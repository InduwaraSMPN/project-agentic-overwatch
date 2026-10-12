r"""Read a sealed run bundle's raw files into a structured record -- and refuse ``metrics.json``.

WHAT THIS MODULE IS FOR
    `docs/protocols/data-management.md` §8 restricts `analysis/` to "only `runs/` raw files (never
    `metrics.json` caches, never live services)", and `.agents/rules/20` binds the same. §1 fixes
    the bundle layout and the two instrument-CSV column schemas (`probes.csv`, `resources.csv`).
    This module is the one door between those files and every measure: :func:`load_bundle` reads one
    `runs/<CAMPAIGN>/<RUN_ID>/` directory into a :class:`Bundle`, and :func:`load_campaign` reads a
    whole campaign directory into a pandas DataFrame -- identity columns plus a `bundle` object per
    row, which is the shape the versions.env header describes ("pandas organises the raw run bundles
    into frames").

    Every raw read routes through :func:`refuse_metrics_json`, so the §8 prohibition is a property
    of the loader rather than a convention each measure has to remember. `evaluation-protocol.md` §3
    states the rule three times over -- per-phase outcome correctness, containment/eradication
    success and the injection end-state assertions are read from `assertions.json`, never from
    `metrics.json` -- and `data-management.md` §3 repeats it, so the refusal is a function, called
    on every path, and `analysis/tests/` proves a `metrics.json` path is refused.

THE SPAN DOCUMENT CONTRACT
    `data-management.md` §1 binds the filename `spans.otel.json`. Its content is one JSON object
    carrying a `spans` array in close order, matching the agent file exporter and the runner sealer.
    The retired `spans.jsonl` producer name and line-delimited format are intentionally not
    accepted: a bundle carrying either cannot have passed the current completeness profile, and
    accepting it here would recreate two contracts for the same evidence.

WHAT BREAKS IF THIS FILE CHANGES
    Making any reader fall through to `metrics.json` would turn §8's "never `metrics.json`" into a
    rule that cannot fire, which is the single most consequential edit to this file. Reading a
    bundle into anything a measure then mutates would let a reported figure diverge from the sealed
    evidence. ADR-043 (analysis as a tested component); after `v1.0` any change here is a logged
    hotfix ADR (AGENTS.md iron rule 6).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final

import pandas as pd

__all__ = [
    "IDENTITY_COLUMNS",
    "INJECTION_CLASSES",
    "INJ_NONE",
    "MATCH_COLUMNS",
    "METRICS_JSON_NAME",
    "PHASES",
    "POOL_COLUMNS",
    "Bundle",
    "BundleError",
    "MetricsJsonRefused",
    "iter_spans",
    "load_bundle",
    "load_campaign",
    "refuse_metrics_json",
    "sealed_bundle_directories",
]

# The four incident-response phases in evaluation-protocol.md §1.6 order, spelled as
# scenarios/schemas/groundtruth.v1.json and guardian/app/models.py's Phase spell them. One spelling,
# so analysis never reconciles two.
PHASES: Final = (
    "detection-and-investigation",
    "containment",
    "eradication",
    "verified-recovery",
)

# The four injection classes RQ5's rigorous contrasts read, and the no-attack coordinate that is the
# baseline the classes are read against rather than a class with a rate of its own
# (evaluation-protocol.md §3; glossary §Scenario & injection IDs).
INJECTION_CLASSES: Final = ("INJ-A", "INJ-B", "INJ-C", "INJ-D")
INJ_NONE: Final = "INJ-NONE"

# The convenience cache §8 forbids analysis from reading. Named so the refusal is greppable.
METRICS_JSON_NAME: Final = "metrics.json"

# The identity coordinates every measure carries through to its output, so a per-cell result is
# self-describing without a join back to the manifest.
IDENTITY_COLUMNS: Final = (
    "run_id",
    "campaign_id",
    "condition",
    "scenario_id",
    "injection_condition",
    "seed",
)

# The matched-pairs key: scenario, injection condition and seed, and NOT condition -- condition is
# the arm a contrast varies over (evaluation-protocol.md §3, row T-39). pairs.py joins two arms on
# exactly these three.
MATCH_COLUMNS: Final = ("scenario_id", "injection_condition", "seed")

# The pooled-cell key: a Wilson interval is computed per (scenario, condition, injection_condition)
# over the seeds. Both scenario_id and condition are present, which is what keeps a pooled result
# per scenario and per condition rather than a grand mean (evaluation-protocol.md §3).
POOL_COLUMNS: Final = ("scenario_id", "condition", "injection_condition")


class BundleError(Exception):
    """A run bundle could not be read as one -- a missing manifest, or an unreadable required
    file."""


class MetricsJsonRefused(BundleError):
    """Raised when a reader is pointed at ``metrics.json``.

    `data-management.md` §8 forbids `analysis/` from reading the per-run metrics cache, and
    `evaluation-protocol.md` §3 names the raw files that replace it. This is the refusal made a
    named error rather than a comment, so the prohibition fires at the call rather than being
    remembered by each measure.
    """


def refuse_metrics_json(path: Path) -> Path:
    """Return ``path`` unchanged, or raise :class:`MetricsJsonRefused` if it names ``metrics.json``.

    Every raw read in this module passes through here first. The check is on the file name, so it
    fires whether the cache is addressed directly or reached by joining a bundle directory with the
    cache's name -- there is no spelling of the forbidden file that slips past.
    """
    if path.name == METRICS_JSON_NAME:
        raise MetricsJsonRefused(
            f"{path}: analysis reads raw bundle files only, never the metrics.json cache "
            "(data-management.md §8; evaluation-protocol.md §3 names the raw files that replace it)"
        )
    return path


def _read_json(path: Path) -> Any:
    """Read one JSON file from a bundle, refusing the metrics cache and tolerating a CRLF
    checkout."""
    refuse_metrics_json(path)
    return json.loads(path.read_bytes().decode("utf-8"))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Read one JSON Lines file into a list of records, tolerating CRLF and ignoring blank lines.

    Bytes-then-decode rather than text mode, and a trailing carriage return stripped per line, for
    the reason `guardian/audit/chain.py` reads its chain the same way: `.gitattributes` normalises
    tracked text to LF in the index, so a fixture checked out on the Windows host arrives with CRLF,
    and a reader that split on a bare '\\n' would keep the '\\r' on every field.
    """
    refuse_metrics_json(path)
    records: list[dict[str, Any]] = []
    text = path.read_bytes().decode("utf-8")
    for raw_line in text.split("\n"):
        line = raw_line[:-1] if raw_line.endswith("\r") else raw_line
        if not line.strip():
            continue
        loaded = json.loads(line)
        if not isinstance(loaded, dict):
            raise BundleError(
                f"{path}: every line must be a JSON object, got {type(loaded).__name__}"
            )
        records.append(loaded)
    return records


def _read_csv(path: Path) -> pd.DataFrame:
    """Read one instrument CSV (`probes.csv`, `resources.csv`, `locust_stats.csv`) into a frame."""
    refuse_metrics_json(path)
    # keep_default_na=False so the empty-string cells data-management.md §1 permits (an empty
    # status_code, an empty error) read back as "" rather than NaN, which would silently change the
    # dtype of the whole column and misrepresent "no response received" as "value missing".
    return pd.read_csv(path, keep_default_na=False)


@dataclass(frozen=True, slots=True)
class Bundle:
    """One sealed run bundle, read into memory from its raw files -- the structured record §8
    permits.

    Every field is the parsed content of one file the `data-management.md` §1 layout names, or
    ``None`` when the bundle's profile does not carry that file (`data-management.md` §3: a baseline
    carries no `assertions.json`, no `guardian_audit.jsonl`, no spans). ``metrics.json`` is
    deliberately absent from this record: §8 forbids reading it, so there is no field that could
    hold it. Frozen, so a measure cannot edit the evidence it reports from.

    The convenience properties read the manifest, which `data-management.md` §2 makes the identity
    of record; a measure keys on these rather than parsing the run id, so the identifier grammar
    stays `runner/`'s concern.
    """

    directory: Path
    manifest: dict[str, Any]
    assertions: dict[str, Any] | None
    results: list[dict[str, Any]] | None
    guardian_audit: list[dict[str, Any]] | None
    monitor_events: list[dict[str, Any]] | None
    monitor_timings: list[dict[str, Any]] | None
    spans: list[dict[str, Any]] | None
    injection_log: list[dict[str, Any]] | None
    tokens: dict[str, Any] | None
    scores: dict[str, Any] | None
    probes: pd.DataFrame | None
    resources: pd.DataFrame | None
    locust_stats: pd.DataFrame | None
    # The two v2 sealed-bundle files the M10 remediation adds (SEAM 2 and SEAM 5). Both are optional
    # at read time, exactly as every other file above: a v1 bundle carries neither, a baseline
    # carries neither, and a framework-on v2 bundle carries both. `fidelity` is fidelity.json's
    # parsed object (the treatment-fidelity summary); `k8s_api_audit` is the API-server audit Event
    # lines the unified executed-action stream reads the direct-path mutations from.
    fidelity: dict[str, Any] | None
    k8s_api_audit: list[dict[str, Any]] | None

    @property
    def run_id(self) -> str:
        return str(self.manifest["run_id"])

    @property
    def campaign_id(self) -> str:
        return str(self.manifest["campaign_id"])

    @property
    def is_baseline(self) -> bool:
        return bool(self.manifest.get("is_baseline", False))

    @property
    def condition(self) -> str | None:
        value = self.manifest.get("condition")
        return None if value is None else str(value)

    @property
    def scenario_id(self) -> str | None:
        value = self.manifest.get("scenario_id")
        return None if value is None else str(value)

    @property
    def injection_condition(self) -> str | None:
        value = self.manifest.get("injection_condition")
        return None if value is None else str(value)

    @property
    def seed(self) -> int | None:
        value = self.manifest.get("seed")
        return None if value is None else int(value)

    @property
    def baseline_run_id(self) -> str | None:
        value = self.manifest.get("baseline_run_id")
        return None if value is None else str(value)

    @property
    def load_profile_id(self) -> str | None:
        value = self.manifest.get("load_profile_id")
        return None if value is None else str(value)

    def identity(self) -> dict[str, Any]:
        """Return the identity columns as a plain mapping, for a DataFrame row or a measure key."""
        return {
            "run_id": self.run_id,
            "campaign_id": self.campaign_id,
            "condition": self.condition,
            "scenario_id": self.scenario_id,
            "injection_condition": self.injection_condition,
            "seed": self.seed,
        }


def _optional(directory: Path, name: str, reader: Any) -> Any:
    """Read ``directory/name`` with ``reader`` if it exists and is non-empty, else return ``None``.

    Absence is expected, not an error: `data-management.md` §3's baseline profile asserts nine
    framework-on artefacts *absent*, so a baseline bundle legitimately has no `assertions.json`. A
    present-but-empty file is treated as absent too, because the completeness check refuses to seal
    one, so it can only appear in a malformed bundle and a measure should see None rather than
    crash.
    """
    path = directory / name
    if not path.exists() or path.stat().st_size == 0:
        return None
    return reader(path)


def load_bundle(path: str | Path) -> Bundle:
    """Read one `runs/<CAMPAIGN>/<RUN_ID>/` directory into a :class:`Bundle`.

    ``manifest.json`` is required -- it is the bundle's identity and a directory without one is not
    a bundle. Every other file is optional at read time: which are present is a property of the
    bundle's profile (`data-management.md` §3), and enforcing the profile is `runner/`'s sealer, not
    this loader's. Spans are read only from the binding `spans.otel.json` JSON document described
    in the module docstring. ``metrics.json`` is never read.
    """
    directory = Path(path)
    manifest_path = directory / "manifest.json"
    if not manifest_path.exists():
        raise BundleError(f"{directory}: no manifest.json; this is not a run bundle")
    manifest = _read_json(manifest_path)
    if not isinstance(manifest, dict):
        raise BundleError(f"{manifest_path}: manifest.json must be a JSON object")

    guardian_audit = _optional(directory, "guardian_audit.jsonl", _read_jsonl)
    monitor_events = _optional(directory, "monitor_events.jsonl", _read_jsonl)
    run_id = str(manifest.get("run_id", ""))
    foreign = [
        record.get("run_id") for record in guardian_audit or [] if record.get("run_id") != run_id
    ]
    if foreign:
        raise BundleError(
            f"{directory}: guardian_audit.jsonl contains foreign run_id {foreign[0]!r}"
        )
    try:
        started = datetime.fromisoformat(str(manifest["started_at"]).replace("Z", "+00:00"))
        # ended_at must parse as well, so a manifest without a usable window still skips the check
        # exactly as before. Only the lower bound is compared: whether the upper one should be is
        # an open question against ADR-054's own clock-lead argument, recorded rather than decided.
        datetime.fromisoformat(str(manifest["ended_at"]).replace("Z", "+00:00"))
    except (KeyError, ValueError):
        started = None
    if started is not None:
        for event in monitor_events or []:
            try:
                stamp = datetime.fromisoformat(str(event["ts"]).replace("Z", "+00:00"))
            except (KeyError, ValueError) as error:
                raise BundleError(f"{directory}: monitor event has no valid timestamp") from error
            if stamp < started:
                raise BundleError(
                    f"{directory}: monitor event {event.get('event_id')!r} is before the run window"
                )

    return Bundle(
        directory=directory,
        manifest=manifest,
        assertions=_optional(directory, "assertions.json", _read_json),
        results=_optional(directory, "results.json", _read_json),
        guardian_audit=guardian_audit,
        monitor_events=monitor_events,
        monitor_timings=_optional(directory, "monitor_timings.jsonl", _read_jsonl),
        spans=_load_spans(directory),
        injection_log=_optional(directory, "injection.log.jsonl", _read_jsonl),
        tokens=_optional(directory, "tokens.json", _read_json),
        scores=_optional(directory, "scores.json", _read_json),
        probes=_optional(directory, "probes.csv", _read_csv),
        resources=_optional(directory, "resources.csv", _read_csv),
        locust_stats=_optional(directory, "locust_stats.csv", _read_csv),
        fidelity=_optional(directory, "fidelity.json", _read_json),
        k8s_api_audit=_optional(directory, "k8s_api_audit.jsonl", _read_jsonl),
    )


def _load_spans(directory: Path) -> list[dict[str, Any]] | None:
    """Read the binding `spans.otel.json` document and enforce its root shape."""
    otel = directory / "spans.otel.json"
    if not otel.exists() or otel.stat().st_size == 0:
        return None
    try:
        loaded = _read_json(otel)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BundleError(f"{otel}: not a valid UTF-8 JSON document: {error}") from error
    if not isinstance(loaded, dict) or not isinstance(loaded.get("spans"), list):
        raise BundleError(f"{otel}: expected a JSON object carrying a 'spans' list")
    spans = loaded["spans"]
    if not all(isinstance(span, dict) for span in spans):
        raise BundleError(f"{otel}: every entry in 'spans' must be a JSON object")
    return spans


def iter_spans(bundle: Bundle) -> Iterator[dict[str, Any]]:
    """Yield each span of a bundle, or nothing when the bundle carries no spans (e.g. a
    baseline)."""
    if bundle.spans is None:
        return
    yield from bundle.spans


def sealed_bundle_directories(campaign_dir: str | Path) -> list[Path]:
    """Return exactly the bundle directories `load_campaign` reads: one per cell, no reruns lost.

    A cell can have more than one attempt directory on disk (`data-management.md` §4: invalid
    originals are retained, never deleted). A directory only counts as its cell's bundle here if it
    carries `manifest.json`, does **not** carry `invalid.json` (a bundle can be sealed and later
    found invalid by a post-seal check -- both files present means it does not count, exactly
    ADR-108's bugfix note and the M7 QA report's "valid sealed bundle" definition), and is not named
    by another candidate's `rerun_of` (the second, belt-and-suspenders check, for a rerun whose
    original was superseded without ever gaining an `invalid.json`). Any caller that needs "the
    sealed corpus" rather than "every directory with a manifest" -- :func:`load_campaign` and
    `analysis.render.corpus_digest` both do -- must filter through this one function, so the two
    can never define "sealed bundle" differently from each other.
    """
    root = Path(campaign_dir)
    candidates = [child for child in sorted(root.iterdir()) if (child / "manifest.json").exists()]
    valid_candidates = [child for child in candidates if not (child / "invalid.json").is_file()]
    reran_originals: set[str] = set()
    for child in valid_candidates:
        try:
            payload = _read_json(child / "manifest.json")
        except (OSError, ValueError, TypeError):
            continue
        rerun_of = payload.get("rerun_of") if isinstance(payload, dict) else None
        if isinstance(rerun_of, str):
            reran_originals.add(rerun_of)
    return [child for child in valid_candidates if child.name not in reran_originals]


def load_campaign(campaign_dir: str | Path) -> pd.DataFrame:
    """Read every bundle under a campaign directory into one identity DataFrame.

    One row per `runs/<CAMPAIGN>/<RUN_ID>/` subdirectory :func:`sealed_bundle_directories` selects:
    the identity columns `data-management.md` §2 fixes, plus `is_baseline`, `baseline_run_id` and
    `load_profile_id` (the RQ4 pairing fields), and a `bundle` column holding the :class:`Bundle`
    itself so a measure can reach the raw files without a second walk of the tree. Rows are sorted
    by `run_id`, so the frame -- and every table computed from it -- is a deterministic function of
    the corpus (rule 20). A directory with no bundles yields an empty, correctly-columned frame
    rather than an error, because "no bundles yet" is the normal state before a campaign runs.
    """
    from runner.bundle import verify_bundle_seal

    bundles: list[Bundle] = []
    for child in sealed_bundle_directories(campaign_dir):
        defects = verify_bundle_seal(child)
        if defects:
            raise BundleError(f"{child}: invalid seal: {'; '.join(defects)}")
        bundles.append(load_bundle(child))
    return bundles_frame(bundles)


def bundles_frame(bundles: Iterable[Bundle]) -> pd.DataFrame:
    """Assemble an identity DataFrame from already-loaded bundles, one row each, sorted by run
    id."""
    columns = [*IDENTITY_COLUMNS, "is_baseline", "baseline_run_id", "load_profile_id", "bundle"]
    rows: list[dict[str, Any]] = []
    for bundle in bundles:
        row = bundle.identity()
        row.update(
            is_baseline=bundle.is_baseline,
            baseline_run_id=bundle.baseline_run_id,
            load_profile_id=bundle.load_profile_id,
            bundle=bundle,
        )
        rows.append(row)
    frame = pd.DataFrame(rows, columns=columns)
    if not frame.empty:
        frame = frame.sort_values("run_id", kind="stable").reset_index(drop=True)
    return frame
