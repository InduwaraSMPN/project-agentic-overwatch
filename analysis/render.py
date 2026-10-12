r"""``make analyze``: regenerate every table and figure from raw bundles, and lock the proof.

WHAT THIS MODULE IS FOR
    `docs/protocols/data-management.md` §8 fixes the reproducibility contract: "``make analyze`` on
    a clean checkout + ``runs/`` copy regenerates every table and figure (T-25)", reading "only
    ``runs/`` raw files (never ``metrics.json`` caches, never live services)", with "stats live in
    ``analysis/stats/*.py``, notebooks only render". This module is the entry point that contract
    names. It loads a campaign through :mod:`analysis.stats.loader` (the single door that refuses
    ``metrics.json``), computes every Table 3.4 measure and every ``origin: engineering`` instrument
    through :mod:`analysis.stats.measures`, pools each per scenario and per condition through
    :mod:`analysis.stats.proportions`, forms the RQ2/RQ5 matched-pairs contrasts through
    :mod:`analysis.stats.pairs`, and writes the tables and figures. It holds **no statistic of its
    own**: every number it renders comes from `analysis.stats`, and the descriptive aggregation it
    does for a figure is the minimal per-(scenario, condition) pool those functions already permit,
    never a grand mean.

    `docs/plans/M6-implementation-plan.md` step A9 makes this the second half of T6.6: run over the
    synthetic corpus `runner/synthetic.py` seals, regenerate every artefact, and write
    ``analysis/.synthetic-proof.json``. That sentinel is the pre-registration lock the ``make
    campaign`` preflight reads (§"T6.6 is a preflight gate, not a task that merely happened first"):
    it records both the git commit and a digest of tracked analysis/runner/protocol source bytes, so
    committed, staged, or unstaged changes after real runs exist force the proof to be re-run.

THE PROOF IS ONLY WRITTEN FOR A SYNTHETIC CAMPAIGN
    The campaign_id carries the reserved ``-synthetic`` slug (`runner.campaign.SYNTHETIC_SLUG`), and
    every table and figure stamps it, so an artefact produced from synthetic data says so on its
    face. The proof is written only when the campaign_id ends ``-synthetic``: it is the lock on the
    synthetic pre-registration, not an artefact a real campaign produces. Its ``corpus_digest`` is a
    stable sha256 over the sealed bundles' ``seal.json`` content-hash sets, so two runs of the
    same seed produce the same digest and a tampered corpus does not.

FAIL CLOSED, NEVER FABRICATE
    A measure M1 has not calibrated yet, or that needs a bundle nobody has scored (the SLO
    stabilization window; the researcher-judged and test-retest statistics), is rendered as an
    explicit ``PENDING-...`` status, never as zero and never omitted. The inconclusiveness floor and
    both minimum-detectable-difference figures are no longer in that category: they are GATE-fixed
    (evaluation-protocol.md §4's `gate-constants` block; ADR-080; supervisor rulings 2026-09-13,
    item 3) and every rigorous contrast carries all three -- the pre-registered worst-case MDD, the
    realized MDD computed from this contrast's own observed paired-difference SD, and the floor
    marker (`analysis.stats.gate.FLOOR_MARKER`) -- beside its point estimate and Wilson interval,
    with a support label naming which bar, if either, the observed difference clears. A measure that
    produces no rows on this corpus (a synthetic bundle carries no span timestamps, no end-state
    assertions, no per-phase tokens) writes its empty, correctly-columned table and records why,
    rather than skipping silently.

WHAT BREAKS IF THIS FILE CHANGES
    T-25 (the analysis regenerates every table and figure from bundles) and the ``make campaign``
    preflight gate that reads the synthetic proof. Recomputing a statistic here rather than calling
    `analysis.stats` would breach `data-management.md` §8's "stats live in ``analysis/stats``".
    Giving the proof a numeric floor default, or writing it for a non-synthetic campaign, would void
    the pre-registration lock. ADR-042 (the synthetic corpus and the campaign preflight gate);
    ADR-043 (analysis as a tested component). After the ``v1.0`` freeze any change here is a logged
    hotfix ADR (AGENTS.md iron rule 6).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import matplotlib

matplotlib.use("Agg")  # headless: no display is available on CI or in a test, and none is needed.

import matplotlib.pyplot as plt  # noqa: E402 - the Agg backend must be selected before pyplot loads
import pandas as pd  # noqa: E402 - kept beside pyplot so the third-party block reads together

REPO_ROOT: Final = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from runner.bundle import load_seal  # noqa: E402
from runner.campaign import SYNTHETIC_SLUG  # noqa: E402
from scenarios.schemas import yamlsubset  # noqa: E402

from analysis.stats import (  # noqa: E402 - first-party, reachable only after the sys.path insert
    RQ2_CONTRASTS,
    RQ5_CONTRASTS,
    Bundle,
    EmptyContrastError,
    PendingGateValue,
    PendingInstrumentValue,
    VacuousPredicate,
    containment_eradication_success,
    coordination_cost,
    detection_precision_recall,
    detection_precision_recall_by_scenario,
    framework_restarts,
    full_lifecycle_proportion,
    g2_direct_path,
    grouped_contrast,
    guardrail_effectiveness_by_class,
    injection_success_rate,
    interference,
    load_campaign,
    per_phase_completeness,
    per_phase_outcome_correctness,
    policy_compliant_action_rate,
    pool_binary,
    pool_counts,
    refuse_metrics_json,
    resolve_condition_alias,
    resource_overhead,
    response_latency,
    sealed_bundle_directories,
    vacuous_predicates,
    verified_recovery_claim_fidelity,
)
from analysis.stats.campaign_artefacts import injection_base_rates_document  # noqa: E402
from analysis.stats.gate import inconclusiveness_floor, resolve_stabilization_window  # noqa: E402
from analysis.stats.measures import (  # noqa: E402
    compute_test_retest_agreement,
    time_to_slo_recovery,
)

__all__ = [
    "DEFAULT_PROOF_PATH",
    "EXPECTED_FIGURES",
    "JUDGED_MEASURES",
    "READINESS_STAGES",
    "TABLE_MEASURES",
    "AnalyseResult",
    "MeasureReadiness",
    "ReadinessReport",
    "analyse",
    "analyze",
    "classify_measure_status",
    "collect_treatment_failures",
    "corpus_digest",
    "find_synthetic_campaign",
    "main",
    "proof_matches_tree",
    "read_proof",
    "readiness_gate",
    "readiness_severity",
    "source_surface_digest",
    "write_proof",
]

# The pre-registration lock lives under analysis/, not under runs/: committing it would let the
# preflight gate pass on a tree that never ran the proof, so it is generated and gitignored
# (M6 plan §"T6.6 is a preflight gate"; ADR-042). One home so the gate and the writer agree.
DEFAULT_PROOF_PATH: Final = REPO_ROOT / "analysis" / ".synthetic-proof.json"

# The subdirectory of a campaign the render writes into. It carries no manifest.json, so
# loader.load_campaign skips it and the outputs never masquerade as bundles; runs/ is gitignored, so
# choosing a directory under the campaign needs no new .gitignore entry (unlike the proof sentinel).
_ANALYSIS_SUBDIR: Final = "_analysis"

# The minimal pooling both protected axes require: a figure aggregates a per-seed measure to one
# Wilson interval per (scenario, condition) cell -- coarser than the per-cell tables, but still per
# scenario and per condition, never the grand mean §3 forbids (proportions.POOLED_COLUMNS is exactly
# these two, and pool_binary/pool_counts refuse a grouping that drops either).
_FIGURE_POOL_BY: Final = ["scenario_id", "condition"]

# The figure filenames make_analyze regenerates. Named as a constant so a test asserts the set
# rather than restating it, and so the proof records the same names the renderer wrote.
EXPECTED_FIGURES: Final = (
    "fig_outcome_correctness_by_cell.png",
    "fig_policy_compliant_rate_by_cell.png",
    "fig_rq_contrasts_mdd.png",
)

# Bind the proof to every tracked implementation file that can change the generated corpus, its
# validation, or the resulting analysis, plus the protocols that define those semantics. Tests,
# READMEs and generated files are deliberately outside this executable/protocol source surface.
# Paths come from git's tracked-file index, but bytes always come from the working tree, so an
# unstaged or staged content change invalidates the proof even while HEAD remains unchanged.
_PROOF_SOURCE_PREFIXES: Final = ("analysis/", "runner/", "docs/protocols/")
_PROOF_SOURCE_EXCLUDED_PARTS: Final = frozenset({"tests"})


class RenderError(Exception):
    """The analysis could not be rendered -- an absent campaign, an ambiguous default, a metrics
    cache."""


@dataclass(frozen=True, slots=True)
class AnalyseResult:
    """The outcome of one ``analyse`` over a campaign: what was written, and the corpus it read.

    ``tables`` and ``figures`` are the absolute paths of artefacts regenerated; ``statuses`` maps
    each measure to a one-line status (a cell count, or the ``PENDING-...`` reason it could not be
    computed on this corpus). ``proof_path`` is the sentinel when the campaign was synthetic and the
    proof was written, else ``None``. ``vacuity_warnings`` is the campaign vacuity
    tripwire's own result (ADR-096): every scored predicate that passed in 100% of this campaign's
    real runs, empty when none was flagged. Frozen because a completed render is a record, not a
    scratch space a caller edits.
    """

    campaign_id: str
    campaign_dir: Path
    out_dir: Path
    bundle_count: int
    corpus_digest: str
    tables: tuple[Path, ...]
    figures: tuple[Path, ...]
    statuses: dict[str, str] = field(default_factory=dict)
    proof_path: Path | None = None
    vacuity_warnings: tuple[VacuousPredicate, ...] = field(default_factory=tuple)
    readiness: ReadinessReport | None = None


# ==============================================================================================
# GIT AND CORPUS IDENTITY -- read-only; the proof records what the tree was when it was produced
# ==============================================================================================


def _current_git_commit(repo_root: str | Path = REPO_ROOT) -> str | None:
    """Return the current ``HEAD`` commit, or ``None`` if the tree is not a resolvable git repo.

    A read-only ``git rev-parse HEAD`` (`.agents/rules/30`: inspect freely, never mutate). ``-C
    REPO_ROOT`` so the answer is the artefact's repository regardless of the caller's working
    directory. A detached HEAD still resolves to its commit; a genuine failure (no git, no repo)
    yields ``None`` so the caller records what it can and flags rather than inventing a commit.
    """
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell; git is read-only here
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],  # noqa: S607 - git from PATH
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, ValueError):  # pragma: no cover - git absent from PATH is environment-specific
        return None
    if completed.returncode != 0:
        return None
    commit = completed.stdout.strip()
    return commit or None


def _tracked_proof_source_paths(repo_root: Path = REPO_ROOT) -> tuple[Path, ...] | None:
    """Return the deterministic tracked source/protocol surface, or ``None`` if git fails."""
    try:
        completed = subprocess.run(  # noqa: S603 - fixed read-only git query, no shell
            ["git", "-C", str(repo_root), "ls-files", "--", *_PROOF_SOURCE_PREFIXES],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, ValueError):  # pragma: no cover - git absent is environment-specific
        return None
    if completed.returncode != 0:
        return None
    relative_paths = []
    for raw_path in completed.stdout.splitlines():
        relative = Path(raw_path)
        if relative.parts[0] in {"analysis", "runner"} and relative.suffix != ".py":
            continue
        if relative.parts[:2] == ("docs", "protocols") and relative.suffix != ".md":
            continue
        if any(part in _PROOF_SOURCE_EXCLUDED_PARTS for part in relative.parts):
            continue
        relative_paths.append(relative)
    return tuple(sorted(relative_paths, key=lambda path: path.as_posix()))


def source_surface_digest(repo_root: str | Path = REPO_ROOT) -> str | None:
    """Hash the current bytes of the tracked analysis/runner/protocol source surface.

    The framing includes each POSIX path and content length before its bytes, avoiding ambiguous
    concatenations. Missing tracked files fail closed rather than silently hashing a smaller
    surface. New untracked files are intentionally excluded: they are not part of the implementation
    about to be run, while any staged or unstaged edit to a tracked file changes this digest.
    """
    root = Path(repo_root)
    paths = _tracked_proof_source_paths(root)
    if not paths:
        return None
    digest = hashlib.sha256()
    for relative in paths:
        try:
            content = (root / relative).read_bytes()
        except OSError:
            return None
        encoded_path = relative.as_posix().encode("utf-8")
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def corpus_digest(campaign_dir: str | Path) -> str:
    """Return a stable sha256 over every bundle's ``seal.json`` content-hash set.

    Each sealed bundle's ``seal.json`` records a sha256 over the raw bytes of every file it carries
    (`runner/bundle.py`). This gathers those content hashes across every bundle under the campaign,
    sorts them, and hashes the sorted list -- so the digest is a pure function of the sealed corpus,
    identical across two generations of one seed and different the moment any bundle's bytes change.
    The directory set is exactly :func:`analysis.stats.sealed_bundle_directories` -- the same
    selection :func:`analysis.stats.load_campaign` reads -- so this never opens ``seal.json`` for a
    directory that carries ``manifest.json`` but never reached seal (an invalid attempt kept on
    disk, `data-management.md` §4) or for an original a rerun superseded (ADR-108 bugfix note):
    "not a bundle" here means the same thing it means everywhere else in `analysis/`, not merely
    "has no manifest.json".
    """
    root = Path(refuse_metrics_json(Path(campaign_dir)))
    hashes: list[str] = []
    for child in sealed_bundle_directories(root):
        seal = load_seal(child)
        content_hashes = seal.get("content_hashes", {})
        hashes.extend(sorted(set(content_hashes.values())))
    payload = "\n".join(sorted(hashes)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def find_synthetic_campaign(runs_root: str | Path | None = None) -> Path:
    """Find the sole synthetic campaign directory under ``runs/``, or raise if none/many.

    ``make analyze`` with no ``--campaign`` runs over the synthetic corpus. A synthetic campaign_id
    carries the reserved ``-synthetic`` slug, so its directory matches ``CAMP-*-{SYNTHETIC_SLUG}``.
    Exactly one is expected; zero is an error (generate it with ``runner.synthetic``), and more
    than one is an error too: the default must be unambiguous -- pass ``--campaign`` to pick one.
    """
    root = Path(runs_root) if runs_root is not None else REPO_ROOT / "runs"
    if not root.is_dir():
        raise RenderError(
            f"{root} does not exist; generate the synthetic corpus first "
            "(python -m runner.synthetic --seed <n>) or pass --campaign explicitly"
        )
    matches = sorted(
        child
        for child in root.iterdir()
        if child.is_dir() and child.name.endswith(f"-{SYNTHETIC_SLUG}")
    )
    if not matches:
        raise RenderError(
            f"no synthetic campaign (CAMP-*-{SYNTHETIC_SLUG}) under {root}; generate it with "
            "python -m runner.synthetic --seed <n>, or pass --campaign for a real campaign"
        )
    if len(matches) > 1:
        names = ", ".join(child.name for child in matches)
        raise RenderError(
            f"more than one synthetic campaign under {root} ({names}); the default is ambiguous, "
            "pass --campaign to choose one"
        )
    return matches[0]


# ==============================================================================================
# TABLE AND FIGURE WRITERS -- every artefact is stamped with the campaign_id and the bundle count
# ==============================================================================================


def _stamp(campaign_id: str, bundle_count: int) -> str:
    """The provenance stamp every table and figure carries: campaign_id, bundle count, synthetic
    flag."""
    synthetic = " · SYNTHETIC DATA" if SYNTHETIC_SLUG in campaign_id.split("-") else ""
    return f"campaign_id: {campaign_id} · bundles: {bundle_count}{synthetic}"


def _fmt_cell(value: Any) -> str:
    """Render one table cell: floats to four decimals, everything else as its string, pipes
    escaped."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        if value != value:  # NaN
            return "nan"
        return f"{value:.4f}"
    return str(value).replace("|", r"\|")


def _df_to_markdown(frame: pd.DataFrame) -> str:
    """Render a DataFrame as a GitHub-flavoured Markdown table -- no tabulate dependency."""
    columns = [str(column) for column in frame.columns]
    lines = [
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join("---" for _ in columns) + " |",
    ]
    for _, row in frame.iterrows():
        lines.append("| " + " | ".join(_fmt_cell(row[column]) for column in frame.columns) + " |")
    return "\n".join(lines)


def _write_markdown_table(
    path: Path, frame: pd.DataFrame, *, title: str, campaign_id: str, bundle_count: int
) -> Path:
    """Write a stamped Markdown table. The header block carries the campaign_id and the bundle
    count."""
    body = _df_to_markdown(frame) if not frame.empty else "_(no rows on this corpus)_"
    text = f"# {title}\n\n{_stamp(campaign_id, bundle_count)} · rows: {len(frame)}\n\n{body}\n"
    path.write_bytes(text.encode("utf-8"))
    return path


def _write_csv_table(
    path: Path, frame: pd.DataFrame, *, title: str, campaign_id: str, bundle_count: int
) -> Path:
    """Write a per-seed CSV whose first line stamps the campaign_id and bundle count as a comment.

    The stamp is a leading ``#`` line rather than a column, so provenance is on the file's header
    without widening every row; these are rendered artefacts read by a person or re-imported with a
    comment-aware reader, never fed back into `analysis.stats` (which reads raw bundles only).
    """
    header = (
        f"# campaign_id={campaign_id} bundle_count={bundle_count} "
        f"table={title} rows={len(frame)} generated_by=analysis.render\n"
    )
    csv_text = frame.to_csv(index=False, lineterminator="\n")
    path.write_bytes((header + csv_text).encode("utf-8"))
    return path


def _stamp_title(base: str, campaign_id: str, bundle_count: int) -> str:
    """The two-line figure title: the measure, then the provenance stamp beneath it."""
    return f"{base}\n{_stamp(campaign_id, bundle_count)}"


def _save_figure(
    fig: plt.Figure, path: Path, *, title: str, campaign_id: str, bundle_count: int
) -> Path:
    """Save a figure as PNG, embedding the stamp in the PNG text metadata as well as the visible
    title.

    ``Date`` is set to ``None`` so the PNG carries no wall-clock creation chunk -- a small nod to
    reproducibility. The campaign_id travels in the ``Description`` chunk (stored uncompressed),
    so the provenance is recoverable from the file's bytes and not only from its pixels.
    """
    fig.savefig(
        path,
        format="png",
        dpi=120,
        bbox_inches="tight",
        metadata={
            "Title": title,
            "Description": f"{_stamp(campaign_id, bundle_count)} generated_by=analysis.render",
            "Software": "analysis.render",
            "Date": None,
        },
    )
    plt.close(fig)
    return path


# ==============================================================================================
# POOLING HELPERS -- thin wrappers over analysis.stats poolers; no statistic is defined here
# ==============================================================================================

# The full per-cell pooling keys: both protected axes, the injection condition, and a measure's own
# sub-axis where it has one (phase or injection class). loader.POOL_COLUMNS plus the sub-axis.
_POOL_BY_BASE: Final = ["scenario_id", "condition", "injection_condition"]


def _pool_keys(frame: pd.DataFrame) -> list[str]:
    """The pooling keys for a measure frame: the base cell keys plus its phase/class sub-axis."""
    keys = list(_POOL_BY_BASE)
    for axis in ("phase", "injection_class"):
        if axis in frame.columns:
            keys.append(axis)
    return keys


def _pool_binary_safe(frame: pd.DataFrame, value_column: str, by: list[str]) -> pd.DataFrame:
    """Pool a binary measure, returning an empty frame unchanged rather than pooling nothing."""
    if frame.empty:
        return frame
    return pool_binary(frame, value_column=value_column, by=by)


def _pool_counts_safe(
    frame: pd.DataFrame, k_column: str, n_column: str, by: list[str]
) -> pd.DataFrame:
    """Pool a (k, n) count measure, returning an empty frame unchanged rather than pooling
    nothing."""
    if frame.empty:
        return frame
    return pool_counts(frame, k_column=k_column, n_column=n_column, by=by)


def _delivered_attempts(frame: pd.DataFrame) -> pd.DataFrame:
    """Keep recorded delivery passes; unknown/missed delivery is never evidence of safety."""
    if frame.empty:
        return frame
    return frame.loc[frame["delivered"].eq(True)].copy()  # noqa: E712


# ==============================================================================================
# THE MEASURES -- every Table 3.4 evaluand and every origin:engineering instrument is driven here
# ==============================================================================================


def _split(bundles: list[Bundle]) -> tuple[list[Bundle], list[Bundle]]:
    """Partition a campaign's bundles into framework-on runs and baselines."""
    framework_on = [bundle for bundle in bundles if not bundle.is_baseline]
    baselines = [bundle for bundle in bundles if bundle.is_baseline]
    return framework_on, baselines


def _render_dataframe_measures(
    framework_on: list[Bundle], out_dir: Path, campaign_id: str, bundle_count: int
) -> tuple[list[Path], dict[str, str], dict[str, pd.DataFrame]]:
    """Compute, pool and write every DataFrame-returning measure; return the paths and statuses.

    Each measure's per-seed frame is written as a stamped CSV (`data-management.md` §3: per-seed
    reported alongside pooled). The binary and count measures are additionally pooled per cell into
    a stamped Markdown Wilson-interval table. A continuous measure (completeness) is reported
    per-seed only: §3 summarises continuous measures by medians and IQR, not by a Wilson interval,
    and this module defines no statistic, so it renders the raw per-seed rows and records that. An
    empty frame still writes its columned table so "every table regenerated" holds literally.

    The third return value is the pooled frames themselves, keyed by measure, and it exists for one
    caller: the readiness gate needs each cell's ``n`` to tell a `nan` produced by an under-powered
    cell (n < 2, a WARN) from a `nan` produced by a measure that never ran. Reading them off the
    written Markdown would mean re-parsing the render's own output; recomputing them would mean
    pooling twice. The frames are returned rather than the gate reaching back into this function.
    """
    tables: list[Path] = []
    statuses: dict[str, str] = {}
    pooled_frames: dict[str, pd.DataFrame] = {}

    def _per_seed(name: str, frame: pd.DataFrame) -> None:
        path = out_dir / f"{name}__per_seed.csv"
        tables.append(
            _write_csv_table(
                path,
                frame,
                title=f"{name} (per-seed)",
                campaign_id=campaign_id,
                bundle_count=bundle_count,
            )
        )

    def _pooled(name: str, frame: pd.DataFrame, note: str) -> None:
        path = out_dir / f"{name}__pooled.md"
        tables.append(
            _write_markdown_table(
                path,
                frame,
                title=f"{name} (pooled, Wilson 95%)",
                campaign_id=campaign_id,
                bundle_count=bundle_count,
            )
        )
        statuses[name] = note
        pooled_frames[name] = frame

    # --- binary and count measures: per-seed CSV + pooled Wilson Markdown --------------------
    outcome = per_phase_outcome_correctness(framework_on)
    _per_seed("per_phase_outcome_correctness", outcome)
    _pooled(
        "per_phase_outcome_correctness",
        _pool_binary_safe(outcome, "correct", _pool_keys(outcome)),
        f"computed: {len(outcome)} rows, pooled per (scenario, condition, injection, phase)",
    )

    lifecycle = full_lifecycle_proportion(framework_on)
    _per_seed("full_lifecycle_proportion", lifecycle)
    _pooled(
        "full_lifecycle_proportion",
        _pool_counts_safe(lifecycle, "phases_correct", "n_phases", _pool_keys(lifecycle)),
        f"computed: {len(lifecycle)} per-seed rows, pooled per (scenario, condition, injection)",
    )

    policy = policy_compliant_action_rate(framework_on)
    _per_seed("policy_compliant_action_rate", policy)
    _pooled(
        "policy_compliant_action_rate",
        _pool_counts_safe(policy, "permits", "attempts", _pool_keys(policy)),
        f"computed: {len(policy)} per-seed rows, pooled per (scenario, condition, injection)",
    )

    guardrail = guardrail_effectiveness_by_class(framework_on)
    _per_seed("guardrail_effectiveness_by_class", guardrail)
    _pooled(
        "guardrail_effectiveness_by_class",
        _pool_counts_safe(
            _delivered_attempts(guardrail), "blocked", "attempts", _pool_keys(guardrail)
        ),
        f"computed: {len(guardrail)} raw rows; delivered attempts pooled per cell; "
        "legacy INJ-B excluded under ADR-105/ADR-108",
    )

    contain = containment_eradication_success(framework_on)
    _per_seed("containment_eradication_success", contain)
    _pooled(
        "containment_eradication_success",
        _pool_binary_safe(contain, "success", _pool_keys(contain)),
        f"computed: {len(contain)} rows, pooled per (scenario, condition, injection, phase)",
    )

    injection = injection_success_rate(framework_on)
    _per_seed("injection_success_rate", injection)
    delivered = _delivered_attempts(injection).assign(delivered_attempts=1)
    _pooled(
        "injection_success_rate",
        _pool_counts_safe(delivered, "compromised", "delivered_attempts", _pool_keys(injection)),
        _rows_or_empty(
            delivered,
            f"computed: {len(delivered)}/{len(injection)} delivered attempts; "
            "misses and unknown delivery excluded from denominators; modern INJ-A/B/C/D measured",
            "PENDING-DELIVERY: no recorded delivery passes available for injection-effect rates",
        ),
    )

    for name, frame in (
        ("g2_direct_path", g2_direct_path(framework_on)),
        ("verified_recovery_claim_fidelity", verified_recovery_claim_fidelity(framework_on)),
        ("framework_restarts", framework_restarts(framework_on)),
    ):
        _per_seed(name, frame)
        statuses[name] = f"computed: {len(frame)} raw per-run engineering records"

    base_rates = injection_base_rates_document(framework_on)
    base_frame = pd.DataFrame(
        [
            {"condition": arm, "payload_id": payload, "base_rate": rate}
            for arm, payloads in sorted(base_rates["arms"].items())
            for payload, rate in sorted(payloads.items())
        ],
        columns=["condition", "payload_id", "base_rate"],
    )
    tables.append(
        _write_markdown_table(
            out_dir / "injection_none_same_predicate_base_rates.md",
            base_frame,
            title="INJ-NONE comparison: each registered payload's induced-action predicate per arm",
            campaign_id=campaign_id,
            bundle_count=bundle_count,
        )
    )
    statuses["injection_none_same_predicate_base_rates"] = (
        f"computed: {len(base_frame)} per-arm payload predicates from INJ-NONE executed evidence"
        if not base_frame.empty
        else "PENDING-BASELINE: no real INJ-NONE bundles for same-predicate base rates"
    )

    # --- continuous measures: per-seed only (medians+IQR are §3's summary, not a statistic here) --
    completeness = per_phase_completeness(framework_on)
    _per_seed("per_phase_completeness", completeness)
    statuses["per_phase_completeness"] = _rows_or_empty(
        completeness,
        f"computed: {len(completeness)} per-seed rows (continuous; §3 summarises by median+IQR)",
        "empty: no phase-outcome assertions on this corpus",
    )

    latency = response_latency(framework_on)
    _per_seed("response_latency", latency)
    statuses["response_latency"] = _rows_or_empty(
        latency,
        f"computed: {len(latency)} per-seed rows (continuous; §3 summarises by median+IQR)",
        "empty: synthetic bundles carry no Monitor alert timestamp and no span start times",
    )

    coordination = coordination_cost(framework_on)
    _per_seed("coordination_cost", coordination)
    statuses["coordination_cost"] = _rows_or_empty(
        coordination,
        f"computed: {len(coordination)} per-seed rows (origin: engineering; raw per-phase totals)",
        "empty: synthetic bundles carry no per-phase token block and no span timings",
    )

    return tables, statuses, pooled_frames


def _rows_or_empty(frame: pd.DataFrame, non_empty: str, empty: str) -> str:
    """Pick the status line for a frame that may legitimately be empty on this corpus."""
    return non_empty if not frame.empty else empty


def _render_resource_overhead(
    framework_on: list[Bundle],
    baselines: list[Bundle],
    out_dir: Path,
    campaign_id: str,
    bundle_count: int,
) -> tuple[Path, str]:
    """Render RQ4 resource overhead: each framework-on run against its load-matched baseline.

    ``resource_overhead`` returns medians, IQR and the percentage delta per resource (§3 reports
    those directly, not as a Wilson interval), so its table IS the summary. A framework-on run with
    no matching baseline in this corpus is skipped and counted, not scored on a missing reference.
    """
    baseline_by_id = {baseline.run_id: baseline for baseline in baselines}
    rows: list[dict[str, Any]] = []
    paired = 0
    for bundle in framework_on:
        baseline = baseline_by_id.get(bundle.baseline_run_id or "")
        if baseline is None:
            continue
        try:
            result = resource_overhead(bundle, baseline)
        except ValueError:  # a run without resources.csv cannot form the delta; skip and count
            continue
        paired += 1
        for delta in result.deltas:
            rows.append(
                {
                    "run_id": result.run_id,
                    "baseline_run_id": result.baseline_run_id,
                    "load_profile_id": result.load_profile_id,
                    "resource": delta.resource,
                    "median": delta.median,
                    "iqr": delta.iqr,
                    "baseline_median": delta.baseline_median,
                    "pct_delta": delta.pct_delta,
                    "framework_restarts": result.framework_restarts,
                }
            )
    frame = pd.DataFrame(
        rows,
        columns=[
            "run_id",
            "baseline_run_id",
            "load_profile_id",
            "resource",
            "median",
            "iqr",
            "baseline_median",
            "pct_delta",
            "framework_restarts",
        ],
    )
    path = _write_markdown_table(
        out_dir / "resource_overhead__per_run.md",
        frame,
        title="resource_overhead (RQ4, per run vs baseline: median, IQR, % delta)",
        campaign_id=campaign_id,
        bundle_count=bundle_count,
    )
    status = (
        f"computed: {paired}/{len(framework_on)} framework-on runs paired to a baseline"
        if paired
        else "PENDING-BASELINE: no resource samples paired to a baseline"
    )
    return path, status


def _render_contrasts(
    framework_on: list[Bundle],
    out_dir: Path,
    campaign_id: str,
    bundle_count: int,
    *,
    frame: pd.DataFrame | None = None,
) -> tuple[Path, dict[str, str]]:
    """Render the RQ2 and RQ5 matched-pairs contrasts, each study over its own rigorous evaluand.

    RQ2 is the structure ablation (S1-HIER vs S2-FLAT / S3-SINGLE) and its rigorous measure is
    per-phase outcome correctness (evaluation-protocol.md section 3, "[RQ2 rigorous]"). RQ5 is the
    guardrail ablation (G0-FULL vs the weakened arms) and its two rigorous measures are the
    injection success rate by class and the policy-compliant action rate ("[RQ5 rigorous]"), NOT
    outcome correctness -- reporting the RQ5 guardrail contrast over RQ2's outcome-correctness
    measure was the defect the 2026-09-14 supervisor review named. Each measure resolves the
    ``S1-HIER`` alias to ``G0-FULL`` in one place (`pairs`), pairs cell for cell on its own pairing
    keys, and carries the pre-registered worst-case MDD, the realized MDD from its own observed
    paired-difference SD, the GATE-fixed inconclusiveness floor (row T-34; ADR-080) and the support
    label (supervisor rulings 2026-09-13, item 3, condition 2). The ``measure`` column keeps the two
    RQ5 evaluands distinct in one table. A contrast that formed no pairs is a hard
    :class:`EmptyContrastError`; an arm absent from this campaign is "not in this campaign".
    """
    if frame is None:
        frame = _contrasts_frame(framework_on)
    statuses: dict[str, str] = {}
    for study, pairs_set, measure in (
        ("RQ2", RQ2_CONTRASTS, "per-phase outcome correctness"),
        ("RQ5", RQ5_CONTRASTS, "injection success rate"),
        ("RQ5", RQ5_CONTRASTS, "policy-compliant action rate"),
    ):
        for arm_a, arm_b in pairs_set:
            cells = frame[
                (frame["study"] == study)
                & (frame["measure"] == measure)
                & (frame["arm_a"] == arm_a)
                & (frame["arm_b"] == arm_b)
            ]
            label = f"contrast {study} {measure}: {arm_a} vs {arm_b}"
            statuses[label] = (
                f"computed: {len(cells)} primary cells; MDD worst-case and MDD realized "
                "reported separately for each cell, with its own n, floor and support"
                if not cells.empty
                else "not in this campaign"
            )
    path = _write_markdown_table(
        out_dir / "rq_contrasts.md",
        frame,
        title=(
            "RQ2 (per-phase outcome correctness) and RQ5 (injection-success rate, "
            "policy-compliant action rate) matched-pairs contrasts: mean diff, worst-case MDD, "
            "realized MDD, floor"
        ),
        campaign_id=campaign_id,
        bundle_count=bundle_count,
    )
    return path, statuses


def _render_vacuity_tripwire(
    framework_on: list[Bundle],
    out_dir: Path,
    campaign_id: str,
    bundle_count: int,
    *,
    controls_root: Path | None = None,
) -> tuple[Path, str, tuple[VacuousPredicate, ...]]:
    """Render the campaign vacuity tripwire (ADR-096): a WARNING, never a hard error.

    Computes :func:`~analysis.stats.vacuous_predicates` over ``framework_on`` -- a campaign's real,
    `is_baseline: false` runs, incident runs included -- and writes every flagged predicate to its
    own stamped Markdown table (empty, correctly-columned, when none is flagged: "every table
    regenerated" holds literally here too). When at least one predicate is flagged, a `VACUITY
    WARNING` line is also printed to stderr, on the same pattern this module's other non-fatal
    diagnostic already uses, so a flag is visible in a CI log without opening the table file. This
    never raises and never blocks `make analyze`: the researcher decides what a flagged predicate
    means for the campaign, exactly as the task that added this function specifies.

    Each flagged predicate also carries a `disposition` column:
    `analysis.stats.vacuity.classify_disposition`'s verdict under the supervisor's 2026-09-14
    disposition ruling (`fails-negative-control`, `do-no-harm`, `verified-recovery-check`, or
    `genuinely-vacuous`) -- one table, never a second one, so a reader sees the flag and its
    disposition together. This is still only ever a WARNING: a `genuinely-vacuous` verdict prints
    its own distinct `GENUINELY-VACUOUS` stderr line (naming exactly those predicates, on the same
    pattern the `VACUITY WARNING` line already uses) so it is visible in a CI log without opening
    the table, but `make analyze` still exits 0 and nothing here blocks it -- ADR-096 item 5 and the
    disposition ruling both leave that call to the researcher. ``controls_root`` defaults to
    ``<repo root>/runs/.controls`` (matching `runner/controls.py`'s own layout, resolved against
    :data:`REPO_ROOT` so the default does not depend on the caller's working directory) and is a
    parameter so a test can point it at a fixture directory instead of the tracked
    ``runs/.controls`` tree.
    """
    from analysis.stats.vacuity import GENUINELY_VACUOUS, classify_disposition

    if controls_root is None:
        controls_root = REPO_ROOT / "runs" / ".controls"

    flagged = vacuous_predicates(framework_on)
    scored = [(item, classify_disposition(item, controls_root=controls_root)) for item in flagged]
    rows = [
        {
            "scenario_id": item.scenario_id,
            "kind": item.kind,
            "phase": item.phase if item.phase is not None else "",
            "local_id": item.local_id,
            "pass_count": item.pass_count,
            "total_applicable": item.total_applicable,
            "disposition": disposition,
        }
        for item, disposition in scored
    ]
    frame = pd.DataFrame(
        rows,
        columns=[
            "scenario_id",
            "kind",
            "phase",
            "local_id",
            "pass_count",
            "total_applicable",
            "disposition",
        ],
    )
    path = _write_markdown_table(
        out_dir / "vacuity_tripwire.md",
        frame,
        title=(
            "VACUITY TRIPWIRE -- scored predicates that never failed across real runs (ADR-096)"
        ),
        campaign_id=campaign_id,
        bundle_count=bundle_count,
    )
    if flagged:
        ids = ", ".join(item.identifier for item in flagged)
        print(
            f"analyze: VACUITY WARNING — {len(flagged)} predicate(s) never failed across real "
            f"runs: {ids}",
            file=sys.stderr,
        )
        status = (
            f"VACUITY WARNING: {len(flagged)} predicate(s) passed in 100% of their applicable "
            f"real runs -- {ids}"
        )
        blocking = [item for item, disposition in scored if disposition == GENUINELY_VACUOUS]
        if blocking:
            blocked_ids = ", ".join(item.identifier for item in blocking)
            print(
                f"analyze: GENUINELY-VACUOUS — {len(blocking)} of those classify "
                "genuinely-vacuous under the supervisor's 2026-09-14 disposition ruling and "
                f"block the campaign pending a methodology decision: {blocked_ids}",
                file=sys.stderr,
            )
    else:
        status = "computed: no predicate passed in 100% of its applicable real runs"
    return path, status, tuple(flagged)


def _render_interference_and_detection(
    framework_on: list[Bundle],
    baselines: list[Bundle],
    out_dir: Path,
    campaign_id: str,
    bundle_count: int,
) -> tuple[list[Path], dict[str, str]]:
    """Render the v2 measures from raw evidence using the existing statistical functions."""
    selected = [
        b.run_id
        for b in framework_on
        if b.condition == "G0-FULL" and b.injection_condition == "INJ-NONE"
    ]
    frame = interference(framework_on, baselines, cell_selection=selected)
    identities = {b.run_id: b for b in framework_on}
    for key in ("scenario_id", "condition", "injection_condition"):
        frame[key] = [getattr(identities[run_id], key) for run_id in frame["run_id"]]
    paths = [
        _write_markdown_table(
            out_dir / "interference__per_run.md",
            frame,
            title=(
                "Interference (RQ4): shared G0 INJ-NONE vs load-matched baseline; residual retained"
            ),
            campaign_id=campaign_id,
            bundle_count=bundle_count,
        )
    ]
    statuses = {
        "interference": (
            f"computed: {len(frame)}/{len(selected)} selected runs paired to a baseline"
            if not frame.empty
            else "PENDING-BASELINE: no shared-arm Locust samples paired to a baseline"
        )
    }
    # Empty v2 streams are genuine missed detections. Legacy streams without the structured
    # signal retain ADR-111's limitation; they must not be silently scored as missed detections.
    eligible = [
        b
        for b in framework_on
        if b.fidelity is not None or any("signal_id" in event for event in (b.monitor_events or []))
    ]
    groundtruth = {
        scenario: yamlsubset.parse(
            (REPO_ROOT / "scenarios" / "groundtruth" / f"{scenario}.yaml").read_text(
                encoding="utf-8"
            )
        )
        for scenario in sorted({b.scenario_id for b in eligible if b.scenario_id})
    }
    rows = []
    for bundle in eligible:
        result = detection_precision_recall(bundle, groundtruth[bundle.scenario_id])
        rows.append(
            {
                "run_id": result.run_id,
                "scenario_id": result.scenario_id,
                "condition": bundle.condition,
                "injection_condition": bundle.injection_condition,
                "true_positives": result.true_positives,
                "false_positives": result.false_positives,
                "false_negatives": result.false_negatives,
                "precision": result.precision,
                "recall": result.recall,
            }
        )
    per_run = pd.DataFrame(
        rows,
        columns=[
            "run_id",
            "scenario_id",
            "condition",
            "injection_condition",
            "true_positives",
            "false_positives",
            "false_negatives",
            "precision",
            "recall",
        ],
    )
    groups = []
    for condition in sorted({b.condition for b in eligible if b.condition}):
        grouped = detection_precision_recall_by_scenario(
            [b for b in eligible if b.condition == condition], groundtruth
        )
        grouped.insert(1, "condition", condition)
        groups.append(grouped)
    pooled = (
        pd.concat(groups, ignore_index=True)
        if groups
        else pd.DataFrame(
            columns=[
                "scenario_id",
                "condition",
                "true_positives",
                "false_positives",
                "false_negatives",
                "precision",
                "recall",
            ]
        )
    )
    for name, data in (("per_run", per_run), ("per_scenario_condition", pooled)):
        paths.append(
            _write_markdown_table(
                out_dir / f"detection_precision_recall__{name}.md",
                data,
                title=f"Detection precision/recall ({name}; structured v2 signal IDs)",
                campaign_id=campaign_id,
                bundle_count=bundle_count,
            )
        )
    statuses["detection_precision_recall"] = (
        f"computed: {len(eligible)}/{len(framework_on)} runs with the v2 detection instrument; "
        "legacy runs excluded under ADR-111"
        if eligible
        else "LIMITATION (ADR-111): no v2 structured detection instrument in this corpus"
    )
    return paths, statuses


def _render_pending_measures(framework_on: list[Bundle], baselines: list[Bundle]) -> dict[str, str]:
    """Attempt every fail-closed measure and record the named reason it is not yet computable.

    These depend on the calibrated SLO window and researcher scoring. Capture the fail-closed
    error's own message rather than fabricating a value or omitting the measure.
    """
    statuses: dict[str, str] = {}

    try:
        window = resolve_stabilization_window()
    except PendingInstrumentValue:
        statuses["time_to_slo_recovery"] = (
            "PENDING-M1: the SLO stabilization window is uncalibrated (evaluation-protocol §4)"
        )
    else:  # pragma: no cover - reached only once M1 calibrates the window
        scored = sum(
            1
            for bundle in framework_on
            if bundle.probes is not None
            and time_to_slo_recovery(bundle, stabilization_window_seconds=window) is not None
        )
        statuses["time_to_slo_recovery"] = f"computed: {scored} run(s) recovered within the window"

    try:
        agreement = compute_test_retest_agreement(framework_on)
    except PendingGateValue:
        statuses["researcher_judged_and_test_retest"] = (
            "PENDING-GATE: needs a bundle scored with both an initial and a rescore pass "
            "(evaluation-protocol.md §3/§4; row T-38)"
        )
    else:  # pragma: no cover - reached only once bundles carry both scoring passes
        per_field = ", ".join(
            f"{field}={value:.4f}" for field, value in agreement.per_field_agreement.items()
        )
        statuses["researcher_judged_and_test_retest"] = (
            f"computed: {agreement.n_compared} run(s) compared; exact-tuple agreement "
            f"{agreement.exact_tuple_agreement:.4f}; per-field agreement {per_field}"
        )

    return statuses


# ==============================================================================================
# THE READINESS GATE -- F-AN-01 (plan §5; ADR-133). Per-stage semantics, and why they differ
# ==============================================================================================
#
# F-AN-01 is a CLASS R check (readiness/provenance), and the plan's §2 principle P2 is what gives it
# three different readings at three points in the campaign rather than one verdict used everywhere.
# The class matters as much as the row: a class T failure is a treatment the instrument did not
# deliver, and a class R failure is a measure the instrument cannot yet compute. The first halts a
# campaign; the second would otherwise halt one for a reason that is about the analysis rather than
# about the artefact, which is how a readiness check turns into an incentive to lower the bar.
#
#   pilot gate    every Table 3.3 measure must have a code path that RUNS. A `nan` produced by
#                 n < 2 is a WARN, not a block: a pilot is small by design, and a cell too small to
#                 pool is a fact about the pilot's size rather than about the instrument. A judged
#                 measure is a WARN: the human session cannot have happened yet, by construction.
#   checkpoint    ONLY a missing measure (no code path, or one that raised) or a class-T failure
#                 blocks. Everything else -- a pending judge, a stated LIMITATION, a small-n cell --
#                 is reported and not blocking, because the checkpoint runs after the first
#                 interleave round while scoring is still in progress (D2).
#   final corpus  every measure must be COMPUTED. This is the stage where a judge still pending is a
#                 FAIL, which is the only stage at which it is: the final render is the point the
#                 numbers are read from, and a number that is a placeholder there is a fabricated
#                 one.
#
# "A code path that runs" is checked mechanically rather than by review: a measure is `missing` when
# the render produced no status line for it at all, `pending` when its fail-closed error was
# captured
# (the `PENDING-...` statuses `_render_pending_measures` writes), and `limitation` when it is a
# stated
# instrument gap (the `LIMITATION ...` lines, ADR-111's shape). Nothing here decides whether a
# measure's VALUE is right -- that is every other check's job -- only whether one was produced.

# The three stages F-AN-01 is evaluated at, named as the plan's §5 names them. A closed tuple so a
# caller spelling a fourth stage fails loudly rather than getting the pilot's semantics.
READINESS_STAGES: Final = ("pilot", "checkpoint", "final")

# The campaign-level document F-AN-01 (runner/fidelity/analysis.py) reads. Written into the CAMPAIGN
# directory, not the `_analysis` subdirectory, because the fidelity check opens
# `<campaign>/readiness.json` and a copy under `_analysis/` would leave the check reading a file
# that does not exist. The same name is spelled once in the fidelity package
# (`analysis.READINESS_FILENAME`); a spelling difference would make F-AN-01 report a missing
# producer over a file this renderer had written.
READINESS_DOCUMENT_FILENAME: Final = "readiness.json"

# The eight Table 3.3 dissertation evaluands, by the name `analyse` records each under. This tuple
# is
# the gate's own registry of "every measure that must have a code path", which is why it is a list
# rather than whatever the render happened to produce: a measure that silently stopped being
# computed
# is exactly the failure this check exists to catch, and a registry built from the render's own
# output
# could never report it.
TABLE_MEASURES: Final = (
    "per_phase_outcome_correctness",
    "full_lifecycle_proportion",
    "per_phase_completeness",
    "resource_overhead",
    "interference",
    "policy_compliant_action_rate",
    "injection_success_rate",
    "response_latency",
)

# The researcher-judged measures (Ch.3's "researcher-judged measures"; ADR-134, D2). Labelled rather
# than treated differently by the severity function, because the per-stage table above already gives
# them the only reading that is honest: a WARN while the human session has not happened, a FAIL only
# at the final corpus.
JUDGED_MEASURES: Final = ("researcher_judged_and_test_retest",)

# The four states a measure can be in, plus the two that are conditions on a computed one. Kept as
# module constants because they appear in the written table and a reader comparing the table with
# the
# code needs one spelling of each.
READINESS_COMPUTED: Final = "computed"
READINESS_PENDING: Final = "pending"
READINESS_LIMITATION: Final = "limitation"
READINESS_MISSING: Final = "missing"
READINESS_SMALL_N: Final = "nan-from-n-below-2"

_SEVERITY_PASS: Final = "pass"  # noqa: S105 - status constant, not a secret
_SEVERITY_WARN: Final = "warn"
_SEVERITY_FAIL: Final = "fail"


def classify_measure_status(status: str | None) -> str:
    """Classify one render status line into a readiness state, or ``missing`` for no line at all.

    The classification is on the status PREFIX and nothing else, which is why the two prefixes are
    load-bearing rather than decorative: `_render_pending_measures` writes a fail-closed capture as
    ``PENDING-...`` and a stated instrument gap as ``LIMITATION ...``, and every other status line
      it
    or `_render_dataframe_measures` writes describes a measure that produced rows. A ``None`` -- the
    measure has no status line at all -- is `missing`, the one state that blocks at every stage.
    """
    if status is None:
        return READINESS_MISSING
    text = status.strip()
    if text.startswith("PENDING"):
        return READINESS_PENDING
    if text.startswith("LIMITATION"):
        return READINESS_LIMITATION
    return READINESS_COMPUTED


def readiness_severity(
    *,
    stage: str,
    state: str,
    judged: bool = False,
    small_n: bool = False,
) -> str:
    """Return ``pass``/``warn``/``fail`` for one measure at one stage. F-AN-01's per-stage table.

    Kept a module-level function rather than a branch inside the report builder, because the whole
    claim of this check is that the per-stage semantics are a fixed table and not a judgement made
    while rendering. A test asserts the table cell by cell.

    ``judged`` and ``small_n`` are recorded in the report and change no verdict at any stage -- a
    judged measure's state already says whether it computed, and a small-n cell is still a computed
    one. They are parameters because a reader of the written table asks "was this `nan` a WARN at
    the
    pilot gate?", and the honest answer is that it is a WARN because it computed, not because of the
    small-n flag.
    """
    del judged, small_n  # see the docstring: both are reported, neither changes the verdict
    if stage not in READINESS_STAGES:
        raise ValueError(
            f"unknown readiness stage {stage!r}; expected one of {list(READINESS_STAGES)}"
        )
    if state == READINESS_MISSING:
        # The one state that blocks everywhere: a measure with no code path cannot be reported, and
        # a campaign that omits a measure silently is the v1 failure (V10's interference row) that
        # this check was written for.
        return _SEVERITY_FAIL
    if stage == "final":
        return _SEVERITY_PASS if state == READINESS_COMPUTED else _SEVERITY_FAIL
    # pilot and checkpoint: only `missing` blocks (a class-T failure is handled separately, by
    # `treatment_failures`), so a pending judge or a stated limitation is reported, not fatal.
    return _SEVERITY_PASS if state == READINESS_COMPUTED else _SEVERITY_WARN


def collect_treatment_failures(bundles: list[Bundle]) -> tuple[str, ...]:
    """The class-T fidelity checks that failed anywhere in this corpus (SEAM 2; WS-5's halt rule).

    F-AN-01's checkpoint half says a class-T failure blocks the gate, and this is where the gate
    gets
    that fact: ``fidelity.json``'s ``checks`` entries carry their own ``klass``, so a T failure is
    read rather than re-classified here. A bundle with no ``fidelity.json`` (v1, baseline)
    contributes
    nothing, and the returned tuple is deduplicated and sorted so the report names each failing
    check
    once however many runs saw it.
    """
    failed: set[str] = set()
    for bundle in bundles:
        fidelity = bundle.fidelity
        if not isinstance(fidelity, Mapping):
            continue
        for check in fidelity.get("checks", ()):
            if not isinstance(check, Mapping):
                continue
            if check.get("klass") == "T" and check.get("status") == "fail":
                identifier = check.get("id")
                failed.add(f"{bundle.run_id}:{identifier}" if identifier else bundle.run_id)
    return tuple(sorted(failed))


@dataclass(frozen=True, slots=True)
class MeasureReadiness:
    """One measure's readiness at one stage: what state it is in and what that state means here."""

    measure: str
    stage: str
    state: str
    severity: str
    judged: bool
    small_n: bool
    detail: str

    @property
    def blocking(self) -> bool:
        """``True`` when this entry stops the gate at its stage."""
        return self.severity == _SEVERITY_FAIL


@dataclass(frozen=True, slots=True)
class ReadinessReport:
    """The gate's whole answer for one stage: every measure, and the verdict they imply."""

    stage: str
    entries: tuple[MeasureReadiness, ...]
    treatment_failures: tuple[str, ...] = ()

    @property
    def blocking(self) -> tuple[str, ...]:
        """The measures whose state fails the gate at this stage."""
        return tuple(entry.measure for entry in self.entries if entry.blocking)

    @property
    def warnings(self) -> tuple[str, ...]:
        """The measures reported but not blocking at this stage."""
        return tuple(entry.measure for entry in self.entries if entry.severity == _SEVERITY_WARN)

    @property
    def verdict(self) -> str:
        """``GO`` when nothing blocks, ``NO-GO`` when a measure or a class-T check does.

        ``NO-GO`` is the word the pilot ladder's ``gate_decision.json`` and the campaign checkpoint
        read; it is deliberately not an exception, because a gate that raised would make "the gate
        said no" indistinguishable from "the gate crashed", and the second is not evidence about the
        instrument.
        """
        return "NO-GO" if self.blocking or self.treatment_failures else "GO"


def readiness_gate(
    statuses: Mapping[str, str],
    *,
    stage: str,
    treatment_failures: Sequence[str] = (),
    small_n_measures: Sequence[str] = (),
    measures: Sequence[str] = TABLE_MEASURES + JUDGED_MEASURES,
) -> ReadinessReport:
    """Evaluate F-AN-01 over the status lines a render produced, and return the whole answer.

    ``statuses`` is the mapping `analyse` accumulates -- measure name to its one-line status -- so
      the
    gate reads exactly what the manifest will show a reader and cannot be satisfied by a measure
    that
    was computed and then dropped from the report. ``small_n_measures`` names measures whose pooled
    cells all have n < 2, which is how a `nan` from an under-powered cell is distinguished from a
    `nan` that means the measure did not run: both are `computed`, and only the second is a defect.
    """
    if stage not in READINESS_STAGES:
        raise ValueError(
            f"unknown readiness stage {stage!r}; expected one of {list(READINESS_STAGES)}"
        )
    small_n = set(small_n_measures)
    judged_names = set(JUDGED_MEASURES)
    entries = tuple(
        MeasureReadiness(
            measure=measure,
            stage=stage,
            state=state,
            severity=readiness_severity(
                stage=stage,
                state=state,
                judged=measure in judged_names,
                small_n=measure in small_n,
            ),
            judged=measure in judged_names,
            small_n=measure in small_n,
            detail=statuses.get(measure, ""),
        )
        for measure, state in (
            (measure, classify_measure_status(statuses.get(measure))) for measure in measures
        )
    )
    return ReadinessReport(
        stage=stage, entries=entries, treatment_failures=tuple(sorted(set(treatment_failures)))
    )


def _small_n_measures(pooled: Mapping[str, pd.DataFrame]) -> tuple[str, ...]:
    """Name the measures whose every pooled cell has n < 2, and which therefore pool to `nan`.

    A cell with n < 2 has no paired difference to form, so ``mdd_realized`` is `nan` by design
    (`analysis.stats.pairs`) rather than by defect -- which is why the plan makes it a WARN and not
    a
    block. An EMPTY pooled frame is not small-n: it means the measure produced no rows at all, which
    the measure's own status line already reports.
    """
    return tuple(
        sorted(
            name
            for name, frame in pooled.items()
            if not frame.empty and "n" in frame.columns and bool((frame["n"] < 2).all())
        )
    )


def _render_readiness_gate(
    framework_on: list[Bundle],
    statuses: dict[str, str],
    pooled: Mapping[str, pd.DataFrame],
    out_dir: Path,
    campaign_dir: Path,
    campaign_id: str,
    bundle_count: int,
    *,
    stage: str,
) -> tuple[Path, ReadinessReport]:
    """Write the readiness-gate table (F-AN-01) and return the report it renders.

    One row per registered measure -- the eight Table 3.3 evaluands and the judged measures -- with
    its state, its severity at this stage, and the render's own status line beside them, so a reader
    can see WHY a measure is pending without opening a second file. Class-T fidelity failures
    observed in this corpus are appended as their own rows, because F-AN-01's checkpoint half blocks
    on them and a gate table that omitted them would under-report its own verdict.

    The machine-readable companion, ``<campaign>/readiness.json``, is written here too: F-AN-01
    (``runner/fidelity/analysis.py``) reads that file rather than re-deriving "is this measure
    available", so the renderer's answer -- the one a reader of the dissertation sees -- is the one
    the gate judges. The markdown table is for a human; the JSON is for the check, and writing both
    from the one :class:`ReadinessReport` is what keeps them the same claim.
    """
    treatment = collect_treatment_failures(framework_on)
    report = readiness_gate(
        statuses,
        stage=stage,
        treatment_failures=treatment,
        small_n_measures=_small_n_measures(pooled),
    )
    _write_readiness_document(campaign_dir, report)
    rows: list[dict[str, Any]] = [
        {
            "measure": entry.measure,
            "kind": "judged" if entry.judged else "table",
            "state": entry.state if not entry.small_n else f"{entry.state} ({READINESS_SMALL_N})",
            "severity": entry.severity,
            "detail": entry.detail,
        }
        for entry in report.entries
    ]
    rows.extend(
        {
            "measure": failure,
            "kind": "fidelity-T",
            "state": "fail",
            "severity": _SEVERITY_FAIL,
            "detail": "class-T fidelity check failed in this corpus (F-AN-01 checkpoint half)",
        }
        for failure in treatment
    )
    frame = pd.DataFrame(rows, columns=["measure", "kind", "state", "severity", "detail"])
    path = _write_markdown_table(
        out_dir / "readiness_gate.md",
        frame,
        title=f"READINESS GATE (F-AN-01) -- stage: {stage}; verdict: {report.verdict}",
        campaign_id=campaign_id,
        bundle_count=bundle_count,
    )
    if report.verdict != "GO":
        print(
            f"analyze: READINESS GATE ({stage}) — {report.verdict}: "
            f"{len(report.blocking)} measure(s) blocking, {len(treatment)} class-T failure(s); "
            f"blocking: {', '.join(report.blocking) or 'none'}",
            file=sys.stderr,
        )
    return path, report


def _write_readiness_document(campaign_dir: Path, report: ReadinessReport) -> Path:
    """Write ``<campaign>/readiness.json``, the artefact F-AN-01 reads (ADR-133).

    The render's own readiness report in the shape the check parses: a ``measures`` map of every
    Table 3.3 measure to its state (``computed`` / ``pending`` / ``limitation`` / ``missing``) and a
    ``judged`` map of every judged measure to whether it has been scored. The judged state is
    translated rather than copied -- ``scored`` when the render computed it, ``pending``
    otherwise -- because F-AN-01's rule for a judged measure is ``state != "scored" is pending``,
    and the renderer's ``computed`` vocabulary is about whether a code path ran, not about whether a
    human has scored yet (D2's progressive scoring). The ``stage`` is carried so a reader of the
    sealed artefact can tell which of the three semantics it was produced under.
    """
    measures: dict[str, str] = {}
    judged: dict[str, str] = {}
    for entry in report.entries:
        if entry.judged:
            judged[entry.measure] = "scored" if entry.state == READINESS_COMPUTED else "pending"
        else:
            measures[entry.measure] = entry.state
    document = {"stage": report.stage, "measures": measures, "judged": judged}
    path = Path(campaign_dir) / READINESS_DOCUMENT_FILENAME
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8"
    )
    return path


# ==============================================================================================
# FIGURES -- matplotlib PNGs, each stamped with the campaign_id and bundle count on its face
# ==============================================================================================


def _grouped_bar_figure(
    pooled: pd.DataFrame,
    *,
    value: str,
    title: str,
    ylabel: str,
    campaign_id: str,
    bundle_count: int,
    path: Path,
) -> Path:
    """A grouped bar chart of a pooled per-(scenario, condition) measure, with Wilson CI whiskers.

    Bars are grouped by scenario and coloured by condition; the whiskers are the Wilson interval
    (``ci_low``/``ci_high``) the pooled frame already carries. The title carries the provenance
    stamp, so the figure says on its face the campaign -- and, via the ``-synthetic`` slug, that it
    is synthetic -- it was produced from.
    """
    phases = sorted(pooled["phase"].unique()) if "phase" in pooled.columns else [None]
    fig, axes = plt.subplots(len(phases), 1, figsize=(12, 4 * len(phases)), squeeze=False)
    for axis, phase in zip(axes[:, 0], phases, strict=True):
        panel = pooled[pooled["phase"] == phase] if phase is not None else pooled
        scenarios = sorted(panel["scenario_id"].unique())
        conditions = sorted(panel["condition"].unique())
        width = 0.8 / max(1, len(conditions))
        for index, condition in enumerate(conditions):
            subset = panel[panel["condition"] == condition].set_index("scenario_id")
            # An absent scenario/arm has no bar, rather than a fabricated zero.
            present = [scenario for scenario in scenarios if scenario in subset.index]
            xs = [scenarios.index(scenario) + index * width for scenario in present]
            points = [float(subset.loc[scenario, value]) for scenario in present]
            lower = [
                max(0.0, points[i] - float(subset.loc[scenario, "ci_low"]))
                for i, scenario in enumerate(present)
            ]
            upper = [
                max(0.0, float(subset.loc[scenario, "ci_high"]) - points[i])
                for i, scenario in enumerate(present)
            ]
            axis.bar(xs, points, width=width, label=condition, yerr=[lower, upper], capsize=2)
        axis.set_xticks([position + 0.4 - width / 2 for position in range(len(scenarios))])
        axis.set_xticklabels(scenarios, rotation=30, ha="right")
        axis.set_ylabel(ylabel)
        axis.set_ylim(0.0, 1.05)
        axis.set_title(str(phase) if phase is not None else title, fontsize=9)
        axis.legend(fontsize=7, ncols=3, loc="lower right")
    fig.suptitle(_stamp_title(title, campaign_id, bundle_count), fontsize=9)
    return _save_figure(fig, path, title=title, campaign_id=campaign_id, bundle_count=bundle_count)


def _contrasts_figure(
    contrasts: pd.DataFrame, *, campaign_id: str, bundle_count: int, path: Path
) -> Path:
    """Facet primary cell differences by study, evaluand and arm pair.

    Each dot retains its scenario, injection and phase. Whiskers are the registered worst-case
    and observed realized MDD; singleton cells have no realized MDD. Table rows retain sample
    size and support, while fixed-width facets avoid a canvas whose width grows with every cell.
    """
    keys = ["study", "measure", "arm_a", "arm_b"]
    groups = list(contrasts.groupby(keys, sort=True))
    rows = max(1, (len(groups) + 1) // 2)
    fig, axes = plt.subplots(rows, 2, figsize=(16, 6 * rows), squeeze=False)
    floor = inconclusiveness_floor()
    for axis, (identity, cells) in zip(axes.flat, groups, strict=False):
        labels = [
            f"{r.scenario_id} / {r.injection_condition} / {r.phase if pd.notna(r.phase) else 'run'}"
            for r in cells.itertuples()
        ]
        ys = list(range(len(cells)))
        axis.errorbar(
            cells["mean_difference"],
            ys,
            xerr=cells["mdd_worst_case"],
            fmt="o",
            color="#4C72B0",
            ecolor="#A6B7D6",
            capsize=2,
            label="mean +/- worst-case MDD",
        )
        finite = cells["mdd_realized"].notna()
        axis.errorbar(
            cells.loc[finite, "mean_difference"],
            [y for y, valid in zip(ys, finite, strict=True) if valid],
            xerr=cells.loc[finite, "mdd_realized"],
            fmt="none",
            ecolor="#1B2A4A",
            capsize=1,
            label="realized MDD (n >= 2)",
        )
        axis.axvline(0.0, color="black", linewidth=0.8)
        for boundary in (floor, -floor):
            axis.axvline(boundary, color="#B22222", linewidth=0.8, linestyle="--")
        axis.set_yticks(ys)
        axis.set_yticklabels(labels, fontsize=4)
        axis.invert_yaxis()
        study, measure, arm_a, arm_b = identity
        axis.set_title(f"{study}: {arm_a} vs {arm_b}\n{measure}", fontsize=8)
        axis.set_xlabel("mean matched-pair difference; dashed lines = floor")
        axis.legend(fontsize=6)
    for axis in list(axes.flat)[len(groups) :]:
        axis.set_visible(False)
    title = "Primary cell contrasts: mean difference, worst-case MDD, realized MDD"
    fig.suptitle(_stamp_title(title, campaign_id, bundle_count), fontsize=9)
    return _save_figure(fig, path, title=title, campaign_id=campaign_id, bundle_count=bundle_count)


def _render_figures(
    framework_on: list[Bundle],
    contrasts: pd.DataFrame,
    out_dir: Path,
    campaign_id: str,
    bundle_count: int,
) -> list[Path]:
    """Regenerate every figure from the pooled measures and the contrasts. Returns their paths."""
    outcome = per_phase_outcome_correctness(framework_on)
    policy = policy_compliant_action_rate(framework_on)
    figures = [
        _grouped_bar_figure(
            pool_binary(outcome, value_column="correct", by=[*_FIGURE_POOL_BY, "phase"]),
            value="point",
            title=(
                "Secondary outcome rollup (scenario × condition; "
                "phases separate, injections pooled)"
            ),
            ylabel="correctness (Wilson 95%)",
            campaign_id=campaign_id,
            bundle_count=bundle_count,
            path=out_dir / EXPECTED_FIGURES[0],
        ),
        _grouped_bar_figure(
            pool_counts(policy, k_column="permits", n_column="attempts", by=_FIGURE_POOL_BY),
            value="point",
            title="Secondary policy rollup (scenario × condition; injections pooled)",
            ylabel="permitted / attempted (Wilson 95%)",
            campaign_id=campaign_id,
            bundle_count=bundle_count,
            path=out_dir / EXPECTED_FIGURES[1],
        ),
        _contrasts_figure(
            contrasts,
            campaign_id=campaign_id,
            bundle_count=bundle_count,
            path=out_dir / EXPECTED_FIGURES[2],
        ),
    ]
    return figures


# ==============================================================================================
# THE PROOF SENTINEL -- the pre-registration lock the make campaign preflight reads (ADR-042)
# ==============================================================================================


def write_proof(
    proof_path: str | Path,
    *,
    git_commit: str | None,
    generator_seed: int | None,
    corpus_digest: str,
    source_digest: str | None,
    campaign_id: str,
    bundle_count: int,
    tables: list[str],
    figures: list[str],
) -> Path:
    """Write the proof with commit and current tracked source-surface identities.

    The source digest closes the dirty-tree gap left by an ``HEAD``-only comparison. ``None`` values
    are explicit markers rather than omitted keys, and sorted JSON keeps equivalent proofs
    byte-identical.
    """
    payload = {
        "git_commit": git_commit if git_commit is not None else "UNKNOWN-NO-GIT-HEAD",
        "generator_seed": generator_seed,
        "corpus_digest": corpus_digest,
        "source_surface_digest": (
            source_digest if source_digest is not None else "UNKNOWN-SOURCE-SURFACE"
        ),
        "campaign_id": campaign_id,
        "bundle_count": bundle_count,
        "tables": sorted(tables),
        "figures": sorted(figures),
    }
    path = Path(proof_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    path.write_bytes(text.encode("utf-8"))
    return path


def read_proof(proof_path: str | Path = DEFAULT_PROOF_PATH) -> dict[str, Any]:
    """Read a written proof sentinel into a dict. Raises :class:`FileNotFoundError` if it is
    absent."""
    path = Path(proof_path)
    if not path.is_file():
        raise FileNotFoundError(
            f"{path}: no synthetic proof; run `make analyze` over the synthetic corpus first"
        )
    return json.loads(path.read_bytes().decode("utf-8"))


def proof_matches_tree(
    proof_path: str | Path = DEFAULT_PROOF_PATH, *, repo_root: str | Path = REPO_ROOT
) -> bool:
    """Require both the recorded commit and tracked source digest to match current content.

    This fails closed for absent/malformed proofs, unresolved git state, old proofs without the
    digest, and staged or unstaged changes to the bound analysis/runner/protocol surface.
    """
    path = Path(proof_path)
    if not path.is_file():
        return False
    try:
        proof = read_proof(path)
        recorded_commit = proof.get("git_commit")
        recorded_source_digest = proof.get("source_surface_digest")
    except (OSError, ValueError):
        return False
    current_commit = _current_git_commit(repo_root)
    current_source_digest = source_surface_digest(repo_root)
    return (
        current_commit is not None
        and current_source_digest is not None
        and recorded_commit == current_commit
        and recorded_source_digest == current_source_digest
    )


# ==============================================================================================
# THE ENTRY POINT
# ==============================================================================================


def _enforce_frozen_commit(campaign_path: Path, bundles: list[Bundle]) -> str | None:
    """Gate 2 (supervisor 2026-09-14): every bundle in a frozen campaign names one instrument.

    When the campaign directory carries ``frozen_commit.txt`` -- written by the campaign driver at
    freeze time -- every bundle's ``git_commit`` must equal it, and a bundle produced at a different
    commit is a hard :class:`RenderError`: the analysis refuses to report a campaign whose bundles
    span more than one instrument, the straddle the 2026-09-14 review named. When the file is absent
    (a pilot predating the freeze), a spanning set is a stderr WARNING rather than an error, so an
    accepted, proof-documented straddle still analyses. Returns the frozen commit when enforced.
    """
    pairs = [
        (str(bundle.manifest.get("git_commit", "UNKNOWN")), bundle.run_id) for bundle in bundles
    ]
    distinct = sorted({commit for commit, _ in pairs})
    commit_path = campaign_path / "frozen_commit.txt"
    if commit_path.is_file():
        frozen = commit_path.read_text(encoding="utf-8").strip()
        divergent = sorted(f"{run_id} at {commit}" for commit, run_id in pairs if commit != frozen)
        if divergent:
            raise RenderError(
                f"{campaign_path.name} is frozen at commit {frozen} but {len(divergent)} bundle(s) "
                f"were produced at a different instrument commit: {'; '.join(divergent)}. A frozen "
                "campaign may not span instruments (gate 2, supervisor 2026-09-14)."
            )
        return frozen
    if len(distinct) > 1:
        print(
            f"analyse: PROVENANCE WARNING -- {campaign_path.name} has no frozen_commit.txt and its "
            f"bundles span {len(distinct)} instrument commits: {distinct}. A pre-freeze pilot may "
            "straddle a documented fix; a frozen campaign must not (gate 2).",
            file=sys.stderr,
        )
    return None


def analyse(
    campaign_dir: str | Path,
    *,
    out_dir: str | Path | None = None,
    generator_seed: int | None = None,
    emit_proof: bool = True,
    proof_path: str | Path = DEFAULT_PROOF_PATH,
    readiness_stage: str = "final",
) -> AnalyseResult:
    """Regenerate every table and figure for one campaign, and lock the synthetic proof.

    Reads the campaign through `analysis.stats.loader` only -- never ``metrics.json``, never a live
    service. Computes every Table 3.4 measure and every ``origin: engineering`` instrument, per seed
    and pooled per scenario and per condition (never a grand mean), forms the RQ2/RQ5 contrasts with
    the ``S1-HIER`` alias resolved, writes the tables and figures under ``out_dir`` (default the
    campaign's own gitignored ``_analysis`` directory), evaluates the readiness gate (F-AN-01) at
    ``readiness_stage``, and -- when the campaign_id is synthetic and ``emit_proof`` is set --
      writes
    the proof at ``proof_path`` (default ``analysis/.synthetic-proof.json``; a test redirects it so
    it
    never touches the tracked tree). Returns an :class:`AnalyseResult` recording every artefact,
    every measure's status, and the gate's verdict.

    ``readiness_stage`` defaults to ``final`` because that is the render a reader of the
      dissertation
    tables is looking at, and it is the only stage at which a pending measure or judge is a FAIL.
    The
    pilot gate and the checkpoint call the same function with ``"pilot"`` and ``"checkpoint"``; the
    per-stage semantics are :func:`readiness_severity`'s, and the reason a parameter rather than
    three
    functions is that the three stages differ only in the severity table, not in what is measured.
    """
    campaign_path = Path(refuse_metrics_json(Path(campaign_dir)))
    if not campaign_path.is_dir():
        raise RenderError(f"{campaign_path} is not a campaign directory")

    frame = load_campaign(campaign_path)
    if frame.empty:
        raise RenderError(
            f"{campaign_path} holds no run bundles; nothing to analyse "
            "(a bundle is a subdirectory carrying manifest.json)"
        )
    bundles = list(frame["bundle"])
    campaign_id = str(frame["campaign_id"].iloc[0])
    bundle_count = len(bundles)
    framework_on, baselines = _split(bundles)
    _enforce_frozen_commit(campaign_path, bundles)

    output_dir = Path(out_dir) if out_dir is not None else campaign_path / _ANALYSIS_SUBDIR
    output_dir = Path(refuse_metrics_json(output_dir))
    output_dir.mkdir(parents=True, exist_ok=True)

    statuses: dict[str, str] = {}
    tables, measure_statuses, pooled_frames = _render_dataframe_measures(
        framework_on, output_dir, campaign_id, bundle_count
    )
    statuses.update(measure_statuses)

    fidelity_rows = [
        {
            "run_id": bundle.run_id,
            "condition": bundle.condition,
            "scenario_id": bundle.scenario_id,
            "injection_condition": bundle.injection_condition,
            **{key: check.get(key) for key in ("id", "stage", "klass", "status", "detail")},
        }
        for bundle in framework_on
        for check in (bundle.fidelity or {}).get("checks", [])
    ]
    tables.append(
        _write_markdown_table(
            output_dir / "fidelity_checks__per_run.md",
            pd.DataFrame(
                fidelity_rows,
                columns=[
                    "run_id",
                    "condition",
                    "scenario_id",
                    "injection_condition",
                    "id",
                    "stage",
                    "klass",
                    "status",
                    "detail",
                ],
            ),
            title="Treatment fidelity: raw sealed check verdicts per run",
            campaign_id=campaign_id,
            bundle_count=bundle_count,
        )
    )
    statuses["fidelity_checks"] = f"computed: {len(fidelity_rows)} sealed check records"

    overhead_path, overhead_status = _render_resource_overhead(
        framework_on, baselines, output_dir, campaign_id, bundle_count
    )
    tables.append(overhead_path)
    statuses["resource_overhead"] = overhead_status

    contrasts_frame = _contrasts_frame(framework_on)
    contrasts_path, contrast_statuses = _render_contrasts(
        framework_on,
        output_dir,
        campaign_id,
        bundle_count,
        frame=contrasts_frame,
    )
    tables.append(contrasts_path)
    statuses.update(contrast_statuses)

    vacuity_path, vacuity_status, vacuity_warnings = _render_vacuity_tripwire(
        framework_on, output_dir, campaign_id, bundle_count
    )
    tables.append(vacuity_path)
    statuses["vacuity_tripwire"] = vacuity_status

    diagnostic_tables, diagnostic_statuses = _render_interference_and_detection(
        framework_on, baselines, output_dir, campaign_id, bundle_count
    )
    tables.extend(diagnostic_tables)
    statuses.update(diagnostic_statuses)
    statuses.update(_render_pending_measures(framework_on, baselines))

    # F-AN-01. Last, because it reads the status lines every step above wrote, and before the
    # manifest, so `render_manifest.md` carries the gate's verdict beside the statuses it judged.
    readiness_path, readiness = _render_readiness_gate(
        framework_on,
        statuses,
        pooled_frames,
        output_dir,
        campaign_path,
        campaign_id,
        bundle_count,
        stage=readiness_stage,
    )
    tables.append(readiness_path)
    statuses["readiness_gate"] = (
        f"F-AN-01 ({readiness_stage}): {readiness.verdict}; "
        f"{len(readiness.blocking)} blocking measure(s), {len(readiness.warnings)} warning(s), "
        f"{len(readiness.treatment_failures)} class-T failure(s)"
    )

    figures = _render_figures(framework_on, contrasts_frame, output_dir, campaign_id, bundle_count)

    digest = corpus_digest(campaign_path)
    manifest_path = _write_run_manifest(
        output_dir,
        campaign_id=campaign_id,
        bundle_count=bundle_count,
        digest=digest,
        generator_seed=generator_seed,
        statuses=statuses,
        tables=tables,
        figures=figures,
    )
    tables.append(manifest_path)

    written_proof: Path | None = None
    if emit_proof and campaign_id.endswith(f"-{SYNTHETIC_SLUG}"):
        commit = _current_git_commit()
        source_digest = source_surface_digest()
        if commit is None or source_digest is None:
            print(
                "analyze: WARNING — HEAD or the tracked source surface could not be resolved; "
                "make campaign's preflight will not treat this proof as current",
                file=sys.stderr,
            )
        written_proof = write_proof(
            proof_path,
            git_commit=commit,
            generator_seed=generator_seed,
            corpus_digest=digest,
            source_digest=source_digest,
            campaign_id=campaign_id,
            bundle_count=bundle_count,
            tables=[path.name for path in tables],
            figures=[path.name for path in figures],
        )

    return AnalyseResult(
        campaign_id=campaign_id,
        campaign_dir=campaign_path,
        out_dir=output_dir,
        bundle_count=bundle_count,
        corpus_digest=digest,
        tables=tuple(tables),
        figures=tuple(figures),
        statuses=statuses,
        proof_path=written_proof,
        vacuity_warnings=vacuity_warnings,
        readiness=readiness,
    )


# American spelling alias, because `make analyze` and the DoD both spell it with a 'z'; the British
# spelling is the definition and this is the one-line synonym callers reach for.
analyze = analyse


def _contrasts_frame(framework_on: list[Bundle]) -> pd.DataFrame:
    """Rebuild the contrasts frame the figure reads, from the same measures the table used.

    Mirrors :func:`_render_contrasts` exactly: RQ2 over per-phase outcome correctness, and RQ5's two
    rigorous measures -- injection-success rate (``compromised``) and policy-compliant action rate
    (``rate``) -- each over its own per-run frame. The ``measure`` column is what the figure labels
    each bar with, so two RQ5 bars on the same arm pair stay distinguishable.
    """
    outcome = per_phase_outcome_correctness(framework_on)
    injection = _delivered_attempts(injection_success_rate(framework_on))
    policy = policy_compliant_action_rate(framework_on)
    studies: tuple[tuple[str, tuple[tuple[str, str], ...], str, pd.DataFrame, str], ...] = (
        ("RQ2", RQ2_CONTRASTS, "per-phase outcome correctness", outcome, "correct"),
        ("RQ5", RQ5_CONTRASTS, "injection success rate", injection, "compromised"),
        ("RQ5", RQ5_CONTRASTS, "policy-compliant action rate", policy, "rate"),
    )
    frames: list[pd.DataFrame] = []
    for study, pairs_set, measure, frame_in, value_column in studies:
        present = set(frame_in["condition"]) if "condition" in frame_in.columns else set()
        for arm_a, arm_b in pairs_set:
            if (
                resolve_condition_alias(arm_a) not in present
                or resolve_condition_alias(arm_b) not in present
            ):
                continue
            by = ["scenario_id", "injection_condition"]
            if "phase" in frame_in.columns:
                by.append("phase")
            cells = grouped_contrast(frame_in, arm_a, arm_b, value_column=value_column, by=by)
            cells.insert(0, "measure", measure)
            cells.insert(0, "study", study)
            frames.append(cells)
    columns = [
        "study",
        "measure",
        "scenario_id",
        "injection_condition",
        "phase",
        "arm_a",
        "arm_b",
        "canonical_a",
        "canonical_b",
        "n_pairs",
        "mean_difference",
        "mdd_worst_case",
        "mdd_realized",
        "floor",
        "support",
    ]
    return (
        pd.concat(frames, ignore_index=True).reindex(columns=columns)
        if frames
        else pd.DataFrame(columns=columns)
    )


def _write_run_manifest(
    out_dir: Path,
    *,
    campaign_id: str,
    bundle_count: int,
    digest: str,
    generator_seed: int | None,
    statuses: dict[str, str],
    tables: list[Path],
    figures: list[Path],
) -> Path:
    """Write the render manifest: the corpus identity and every measure's one-line status.

    This is the human-readable index of the render -- what corpus was read, what was computed, and
    for every fail-closed measure, the reason it is pending. It carries the same stamp as every
    other table so its provenance is unambiguous.
    """
    status_frame = pd.DataFrame(sorted(statuses.items()), columns=["measure / contrast", "status"])
    lines = [
        "# analysis render manifest",
        "",
        f"{_stamp(campaign_id, bundle_count)}",
        "",
        f"- corpus_digest: `{digest}`",
        f"- generator_seed: {generator_seed}",
        f"- tables regenerated: {len(tables) + 1}",  # +1: this manifest counts itself
        f"- figures regenerated: {len(figures)}",
        "",
        "## Measure and contrast status",
        "",
        _df_to_markdown(status_frame),
        "",
        "## Figures",
        "",
        *[f"- `{figure.name}`" for figure in figures],
        "",
    ]
    path = out_dir / "render_manifest.md"
    path.write_bytes(("\n".join(lines)).encode("utf-8"))
    return path


def main(argv: list[str] | None = None) -> int:
    """CLI: ``python -m analysis.render [--campaign DIR] [--out-dir DIR] [--generator-seed N]``.

    With no ``--campaign``, the sole synthetic campaign under ``runs/`` is found and analysed, which
    is what ``make analyze`` runs. ``--readiness-stage`` selects which of F-AN-01's three semantics
    the readiness gate is evaluated and recorded under (default ``final``; the pilot ladder passes
    ``pilot``). Prints one summary line to stdout on the pattern the other gates use
    (``analyze: PASS — ...`` / ``analyze: FAIL — ...``) and returns 0/1.
    """
    parser = argparse.ArgumentParser(
        prog="analysis.render",
        description="Regenerate every table and figure from raw bundles, and write the proof.",
    )
    parser.add_argument(
        "--campaign",
        type=Path,
        default=None,
        help="campaign dir; default: the sole synthetic campaign under runs/",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="output dir; default: the campaign's own runs/<CAMP>/_analysis/",
    )
    parser.add_argument(
        "--generator-seed",
        type=int,
        default=None,
        help="the seed the synthetic corpus was generated with, recorded in the proof",
    )
    parser.add_argument("--no-proof", action="store_true", help="do not write the synthetic proof")
    parser.add_argument(
        "--readiness-stage",
        choices=list(READINESS_STAGES),
        default="final",
        help=(
            "the F-AN-01 semantics to evaluate and record in <campaign>/readiness.json "
            "(default: final; the pilot gate and the checkpoint pass their own)"
        ),
    )
    args = parser.parse_args(argv)

    try:
        campaign_dir = args.campaign if args.campaign is not None else find_synthetic_campaign()
        result = analyse(
            campaign_dir,
            out_dir=args.out_dir,
            generator_seed=args.generator_seed,
            emit_proof=not args.no_proof,
            readiness_stage=args.readiness_stage,
        )
    except (RenderError, EmptyContrastError) as error:
        print(f"analyze: FAIL — {error}", file=sys.stderr)
        return 1

    proof = f", proof {result.proof_path}" if result.proof_path is not None else ""
    print(
        f"analyze: PASS — {result.campaign_id}: {len(result.tables)} table(s), "
        f"{len(result.figures)} figure(s) under {result.out_dir}{proof}"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
