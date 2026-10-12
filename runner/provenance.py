"""Build live run manifests from the checkout and runtime configuration actually in use."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import platform
import subprocess
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from agents.registry.digest import directory_digest, tool_registry_digest
from agents.registry.loader import default_registry_root
from agents.registry.model import (
    DEFAULT_ALIAS,
    MODEL_ALIAS_ENV_VAR,
    MODEL_PROVIDER_STRING_ENV_VAR,
    RUNNER_SCRIPTED_ENV_VAR,
    SCRIPTED_PROVIDER_STRING,
    litellm_config,
    litellm_config_sha256,
)
from agents.tools.registry import TOOL_NAMES, definitions_for
from scripts.versions_env_sha256 import versions_env_sha256

from runner.campaign import PlannedRun
from runner.conditions import flags_for
from runner.freeze import instrument_dirty_paths
from runner.manifest import MANIFEST_FIELDS, RunManifest

REPO_ROOT = Path(__file__).resolve().parents[1]
VERSIONS_ENV = REPO_ROOT / "infra" / "versions.env"

__all__ = (
    "API_AUDIT_FILE",
    "ENVIRONMENT_LOCK",
    "G2_PRINCIPAL",
    "LIVE_PROVENANCE_FILE",
    "ProvenanceError",
    "answered_model_and_fingerprints",
    "api_audit_slice_present",
    "build_run_manifest",
    "environment_lock_sha256",
    "freeze_tag_for",
    "g2_api_audit_requests",
    "guardian_restart_rises",
    "guardian_restarted",
    "head_commit",
    "head_instrument_digest",
    "live_credential_expiries",
    "shared_credential_exercised",
    "working_tree_dirty",
)


class ProvenanceError(RuntimeError):
    """Required live provenance could not be collected without inventing a value."""


# The sealed bundle file that carries the API-server audit slice for one run (SEAM 5; ADR-137). It
# is the evidence `shared_credential_exercised` is now READ FROM, which is the whole point of defect
# V7.
API_AUDIT_FILE: Final = "k8s_api_audit.jsonl"

# The username the API server records for the G2 executor ServiceAccount. Single-homed HERE and
# named verbatim by the interface contract (SEAM 5) and the plan (D1-A):
# `shared_credential_exercised` is "at least one request authenticated as this principal inside the
# window". Guardian-side, the same string is the subject the runner's TokenRequest asks for; the
# cross-check that every non-Guardian mutation's principal is in the expected set (F-GD-03) is
# guardian/audit/k8s_crosscheck.py's, and it reads security-policy §2's set rather than this
# constant, so there is no third copy here.
G2_PRINCIPAL: Final = "system:serviceaccount:agents:g2-executor"


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _command(argv: list[str]) -> str:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed executable and arguments
            argv,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        raise ProvenanceError(f"could not run {' '.join(argv)!r}: {error}") from error
    value = completed.stdout.strip()
    if completed.returncode != 0 or not value:
        detail = completed.stderr.strip() or f"exit {completed.returncode}"
        raise ProvenanceError(f"{' '.join(argv)!r} did not report provenance: {detail}")
    return value


def _optional_command(argv: list[str]) -> str:
    try:
        return _command(argv)
    except ProvenanceError:
        return "unavailable"


def head_commit() -> str:
    """The current ``HEAD`` commit SHA, resolved in the repository root.

    The same value :func:`build_run_manifest` stamps on every bundle. The campaign driver reads it
    once at the start of a run and again before each cell so a tree that moved off the frozen commit
    mid-campaign is refused rather than silently recorded (supervisor gate 2, 2026-09-14).
    """
    return _command(["git", "rev-parse", "HEAD"])


def working_tree_dirty(repo_root: Path = REPO_ROOT) -> bool:
    """Whether any INSTRUMENT path carries an uncommitted change.

    Narrowed from the whole repository on 2026-09-26 (M10 WS-5, ADR-136, defect V14). v1 ran
    ``git status --porcelain`` with no pathspec, so the answer was "the entire checkout is dirty"
    and a reworded doc comment, a scratch file under ``docs/`` or a new note under ``docs/adr/``
    stopped a campaign that was, byte for byte, running the same instrument. M10 plan principle
    **P6** inverts that: only the instrument paths -- ``agents/ guardian/ monitor/ runner/
    scenarios/ analysis/ infra/ scripts/ docs/protocols/ Makefile pyproject.toml`` -- can change
    what a run *does*, and only a change among them is allowed to halt anything.

    The path set, the cleanliness check and the reasoning all live in :mod:`runner.freeze`; this is
    the one-line question-form the campaign driver already calls, kept under its own name because
    ``runner/campaign_cli.py`` imports it from here.

    ``git status --porcelain`` prints nothing for a clean tree, so this cannot reuse
    :func:`_command`, which treats empty output as a provenance failure; here empty output is the
    success case. That is handled inside :func:`runner.freeze.instrument_dirty_paths`.
    """
    try:
        return bool(instrument_dirty_paths(repo_root))
    except Exception as error:  # noqa: BLE001 - re-raise as this module's own provenance failure
        raise ProvenanceError(str(error)) from error


# ==============================================================================================
# shared_credential_exercised: OBSERVED, NOT NAMED (M10 plan §1 V7, §3.1 D1-A, ADR-137, SEAM 5)
# ==============================================================================================
#
# At HEAD this field was `run.condition == "G2-SHAREDCRED"` -- the arm's NAME, written into every G2
# manifest whether or not the arm ever touched the API server. v1 sealed 150 G2 bundles that all
# claimed the alternate credential path was exercised and not one of them was: the TokenRequest file
# was read by nothing, the in-cluster NetworkPolicy targeted a namespace the host-side agent process
# did not live in, and the ServiceAccount could not mutate anything. The field therefore reported
# the treatment the experiment INTENDED and never the one that HAPPENED, which is precisely the
# class of defect the M10 fidelity gate exists to stop (P1: "treatment fidelity is checked, not
# assumed"). The fix is not a better source inside the runner; it is a different source. The
# Guardian never sees the direct path, so its audit chain cannot witness it. The API server can,
# and it is already being captured per run as `k8s_api_audit.jsonl` (SEAM 5, ADR-137).


def api_audit_slice_present(bundle_dir: Path | None) -> bool:
    """Whether ``bundle_dir`` carries an API-server audit slice at all.

    Separate from :func:`shared_credential_exercised` because it answers a different question, and
    F-GD-05 asks both: in G2 the credential must be *exercised* (a request by the G2 principal) and
    in every other arm the same principal must make *zero* requests. A missing slice can only
    support the first half -- so the fidelity check needs to know the slice was there, and this
    predicate is how it asks without re-deriving the filename.
    """
    return bundle_dir is not None and (Path(bundle_dir) / API_AUDIT_FILE).is_file()


def g2_api_audit_requests(bundle_dir: Path | None) -> tuple[Mapping[str, Any], ...]:
    """Every API-server audit record in the slice authenticated as :data:`G2_PRINCIPAL`.

    Raw API-server audit ``Event`` JSON lines, one JSON object per line, exactly as the API server
    emitted them (SEAM 5) -- this function parses and filters, never rewrites, because the slice
    is a sealed evidence file and a "cleaned up" copy of evidence is not evidence.

    Unparseable lines are skipped rather than raised on: a truncated final line is what a sliced log
    looks like when the window closes mid-write, and refusing to read the rest of the slice would
    turn a cosmetic artefact into an unreadable bundle. The count of skipped lines is not reported
    here because the fidelity check owns the slice's completeness profile; this function's contract
    is "the records that are provably the G2 principal's".
    """
    if not api_audit_slice_present(bundle_dir):
        return ()
    records: list[Mapping[str, Any]] = []
    for line in (Path(bundle_dir) / API_AUDIT_FILE).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        username = record.get("user", {})
        if isinstance(username, dict) and username.get("username") == G2_PRINCIPAL:
            records.append(record)
    return tuple(records)


def shared_credential_exercised(bundle_dir: Path | None) -> bool:
    """Whether the alternate credential path was exercised, read from the API-server audit.

    The truth condition, verbatim from the plan (D1-A): "at least one request authenticated as
    ``system:serviceaccount:agents:g2-executor`` inside the window". The window is not re-derived
    here -- the slice handed in is already the window, by construction, which is what the byte
    offset recorded at window open is for (SEAM 5).

    **Absent slice degrades to ``False``, never to the arm's name and never to an exception.** Two
    properties make that the right direction rather than a convenient one:

    * it is fail-CLOSED on the claim. A framework-on run may only assert that a treatment was
      delivered when it can point at the evidence for it (P1, P2: what the framework controls is
      checked; what the agent chose is a finding). Returning the condition name when the evidence
      is missing would re-create V7 in the one case that matters most, and returning ``None``
      would put a null in a field ``data-management.md`` §2 requires to be non-null on every
      framework-on run -- a null the validator would reject, so the run would be discarded rather
      than misread, which is a worse outcome than a truthful ``False`` for a run whose G2
      treatment genuinely never fired.
    * it is SILENT on older bundles. Every v1 bundle predates the slice, so raising would make the
      v1 corpus unreadable for the known-bad replay (P4), and the replay needs to read it in
      order to flag V7. v1's G2 runs were inert -- that is the defect, established by the plan's
      own evidence -- so ``False`` is the correct reading of them, not a convenient one.

    A G2 run whose slice is missing therefore records ``shared_credential_exercised: false`` and is
    caught by F-GD-05, which requires the slice to be present in G2. The failure is loud, at the
    fidelity gate, instead of silent in the manifest.
    """
    return bool(g2_api_audit_requests(bundle_dir))


# ---------------------------------------------------------------------------------------------
# THE BUNDLE-SIDE M10 PROVENANCE (data-management §2's M10 subsection)
#
# Every field below is a fact only the BUNDLE can answer, and every one degrades to its "not
# measured" value rather than raising, for the two reasons :func:`shared_credential_exercised`
# gives: an older bundle must stay readable, and a fabricated value is worse than an honest
# absence. The two token expiries are the exception in one respect -- they exist only INSIDE the
# run, because both bearers are revoked at run end, so they arrive through a relay sidecar the live
# caller writes and this module consumes.
# ---------------------------------------------------------------------------------------------

#: The relay sidecar a LIVE run writes into its own bundle and this module reads back.
#:
#: ``control_plane_token_expiry`` and ``g2_token_expiry`` cannot be re-derived at manifest time: the
#: control-plane bearer lives in a closure and the G2 bearer in a private file that
#: ``_condition_actions.reset`` deletes, both before ``runner/run.py`` builds the manifest. So the
#: live caller writes the two instants here at mint time and this module folds them in -- the same
#: relay idiom as ADR-124's epoch-drop sidecar, and ``runner/bundle.py::seal_bundle`` removes the
#: file once the manifest has been written, so it is never a sealed artefact.
LIVE_PROVENANCE_FILE: Final = "live_provenance.json"

#: The hashed lock ADR-135 makes the evaluated environment reproducible from. Its digest is the
#: ``environment_lock_sha256`` data-management §2 records on every framework-on run.
ENVIRONMENT_LOCK: Final = REPO_ROOT / "requirements.lock"

#: ``resources.csv``'s Guardian workload name, lower-cased. ADR-132's signal is read per-workload
#: from the CSV's own ``workload`` column rather than from a total, "because a restart of ANY
#: workload is interesting and a restart of the GUARDIAN is disqualifying".
_GUARDIAN_WORKLOAD: Final = "guardian"


def _read_object(path: Path) -> dict[str, Any]:
    """A JSON object from ``path``, or ``{}`` when it is absent, unreadable or not an object."""
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _string_or_none(value: object) -> str | None:
    """``value`` when it is a non-empty string, else ``None``."""
    return value if isinstance(value, str) and value else None


def live_credential_expiries(bundle_dir: Path | None) -> tuple[str | None, str | None]:
    """The (control-plane, G2) token expiries a live run relayed, or ``(None, None)``.

    Read from :data:`LIVE_PROVENANCE_FILE`. ``(None, None)`` is the honest answer for a run that
    minted no such credential. For a G2 run it is
    F-GD-05 that turns the absent expiry into a finding rather than a silent null.
    """
    if bundle_dir is None:
        return (None, None)
    relay = _read_object(Path(bundle_dir) / LIVE_PROVENANCE_FILE)
    return (
        _string_or_none(relay.get("control_plane_token_expiry")),
        _string_or_none(relay.get("g2_token_expiry")),
    )


def answered_model_and_fingerprints(bundle_dir: Path | None) -> tuple[str | None, tuple[str, ...]]:
    """The raw answered model and the distinct system fingerprints, from ``tokens.json`` (D10).

    ``answered_model`` is the provider-returned model off the wire (``response_model``), NOT the
    alias the runner asked for: a gateway that echoes the request returns the alias by construction
    (defect V20), so recording only the alias records the one string that cannot go stale. It is
    ``None`` when no call succeeded -- a probe, which forbids ``tokens.json`` altogether, and a run
    whose every call failed -- because "no model answered" is a fact and not a missing one.

    One run is one model (F-AG-04): a run that somehow recorded two is reported as the first in sort
    order, and the finding is F-AG-04's rather than this reader's. ``system_fingerprints`` is the
    distinct set, sorted, so the manifest's bytes are a function of its content alone.
    """
    if bundle_dir is None:
        return (None, ())
    payload: object = None
    try:
        payload = json.loads((Path(bundle_dir) / "tokens.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        payload = None
    rows = [row for row in payload if isinstance(row, dict)] if isinstance(payload, list) else []
    answered = {value for row in rows if (value := _string_or_none(row.get("response_model")))}
    fingerprints = sorted(
        {value for row in rows if (value := _string_or_none(row.get("system_fingerprint")))}
    )
    return (sorted(answered)[0] if answered else None, tuple(fingerprints))


def guardian_restart_rises(rows: Iterable[Mapping[str, Any]]) -> tuple[tuple[str, int, int], ...]:
    """Every tick at which the GUARDIAN workload's ``restarts_total`` ROSE, as ``(tick, from, to)``.

    THE one implementation of ADR-132's signal, so the check and the record cannot disagree:
    ``F-GD-02`` (class T, stage seal) adjudicates it and refuses the seal, and the manifest's
    ``guardian_restarted`` records it so a reader of the manifest alone sees the same fact.

    ``resources.csv``'s rows are (tick, workload) samples. A restart is a RISE between two ticks,
    never a fall: the counter is cumulative per container, so a row from a different pod can show a
    lower number and a decrease is not a restart. Rows are collapsed per tick by their maximum, so a
    multi-container sample cannot report a phantom rise.
    """
    by_tick: dict[str, int] = {}
    for row in rows:
        if str(row.get("workload") or "").lower() != _GUARDIAN_WORKLOAD:
            continue
        raw = row.get("restarts_total")
        try:
            value = int(raw) if raw is not None and raw != "" else 0
        except (TypeError, ValueError):
            continue
        tick = str(row.get("ts") or "")
        by_tick[tick] = max(by_tick.get(tick, 0), value)
    ordered = sorted(by_tick.items())
    if len(ordered) < 2:
        return ()
    rises: list[tuple[str, int, int]] = []
    highest = ordered[0][1]
    for tick, value in ordered[1:]:
        if value > highest:
            rises.append((tick, highest, value))
        highest = max(highest, value)
    return tuple(rises)


def guardian_restarted(bundle_dir: Path | None) -> bool:
    """Whether the Guardian workload restarted inside the run (ADR-132; F-GD-02's record).

    ``False`` for a bundle with no ``resources.csv`` because a run
    whose resource series is absent has not shown a restart, and the completeness profile is what
    refuses the absent file.
    """
    if bundle_dir is None:
        return False
    path = Path(bundle_dir) / "resources.csv"
    try:
        with path.open("r", encoding="utf-8", newline="") as stream:
            rows = list(csv.DictReader(stream))
    except (OSError, UnicodeDecodeError):
        return False
    return bool(guardian_restart_rises(rows))


def environment_lock_sha256(path: Path = ENVIRONMENT_LOCK) -> str | None:
    """The sha256 of the hashed lock (ADR-135), or ``None`` when the lock is absent."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def freeze_tag_for(bundle_dir: Path | None) -> str | None:
    """The freeze tag NAME the bundle's campaign manifest records, or ``None``.

    Read from the campaign manifest beside the bundle (``<out_root>/<campaign>/campaign.json``),
    which is where the tag name lives and where it has to: it is the NAME and never a commit hash
    (ADR-136), because that file is committed in the very commit the tag names. A bundle written by
    an ad-hoc ``make run`` into a directory with no campaign manifest records ``None``, which is the
    honest answer for a run outside a frozen campaign.
    """
    if bundle_dir is None:
        return None
    return _string_or_none(
        _read_object(Path(bundle_dir).parent / "campaign.json").get("freeze_tag")
    )


def head_instrument_digest(repo_root: Path = REPO_ROOT) -> str | None:
    """The P6 instrument digest at HEAD, or ``None`` when it cannot be computed.

    The value F-RN-02 compares across a corpus and ``enforce_freeze`` compares between HEAD and the
    tag (ADR-136). Degrades to ``None`` rather than raising, for the reason the fidelity package's
    own ``_tree_digest`` does: a bundle built on a machine with no ``git`` must still produce a
    manifest, and a null digest says "not computed" instead of naming a tree.
    """
    try:
        from runner.freeze import instrument_digest
    except ImportError:
        return None
    try:
        return instrument_digest(repo_root)
    except Exception:  # noqa: BLE001 - a null digest is a reportable fact, not a crash
        return None


def _versions_values(path: Path = VERSIONS_ENV) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def _model_config(environ: Mapping[str, str], versions: Mapping[str, str]) -> tuple[str, str, str]:
    # A RUNNER_SCRIPTED run answers with a ScriptedClient under SCRIPTED_PROVIDER_STRING and sends
    # no request, so the manifest must pin that string rather than the live provider from
    # versions.env: otherwise the sealed manifest's model_provider_string is custom_openai/... while
    # every tokens.json call reads scripted/none, and F-RN-01/F-AG-04 fail on the mismatch. Forcing
    # it here is what lets a P1a run seal with no operator setting MODEL_PROVIDER_STRING by hand;
    # the alias is left to resolve as usual (the ScriptedClient answers under DEFAULT_ALIAS too).
    scripted = bool(environ.get(RUNNER_SCRIPTED_ENV_VAR))
    provider_default = (
        SCRIPTED_PROVIDER_STRING if scripted else versions.get(MODEL_PROVIDER_STRING_ENV_VAR, "")
    )
    effective = {
        MODEL_ALIAS_ENV_VAR: environ.get(
            MODEL_ALIAS_ENV_VAR, versions.get(MODEL_ALIAS_ENV_VAR, DEFAULT_ALIAS)
        ),
        MODEL_PROVIDER_STRING_ENV_VAR: SCRIPTED_PROVIDER_STRING
        if scripted
        else environ.get(MODEL_PROVIDER_STRING_ENV_VAR, provider_default),
    }
    try:
        config = litellm_config(effective)
    except (ValueError, RuntimeError) as error:
        raise ProvenanceError(
            "MODEL_ALIAS and MODEL_PROVIDER_STRING must resolve from the runtime environment or "
            "infra/versions.env before a live framework-on run can be sealed"
        ) from error
    return config.alias, config.provider_string, litellm_config_sha256(config)


def _host() -> dict[str, str]:
    return {
        "os": platform.platform(),
        "wsl_kernel": platform.release(),
        "docker": _optional_command(["docker", "--version"]),
    }


def build_run_manifest(
    run: PlannedRun,
    campaign_id: str,
    *,
    rerun_of: str | None = None,
    started_at: str | None = None,
    ended_at: str | None = None,
    environ: Mapping[str, str] | None = None,
    bundle_dir: Path | None = None,
) -> RunManifest:
    """Collect a non-synthetic manifest from the current checkout and runtime configuration.

    ``bundle_dir`` is the sealed bundle's own directory, and it is what makes
    ``shared_credential_exercised`` an observation rather than the arm's name (V7). It is optional
    only so that a manifest can still be built before a bundle exists -- the offline/synthetic
    synthetic-proof path, and the caller's own test seams -- and its absence degrades the field to
    ``False`` rather than to the condition name, for the reasons
    :func:`shared_credential_exercised` gives.

    ``runner/run.py`` and ``runner/live_run.py`` MUST pass ``bundle_dir=bundle_dir`` on the live
    path: the API-server audit slice is collated into the bundle by ``execute_live_run`` before this
    function is called, so a live run that omits the keyword records ``False`` for every arm
    including G2 and is then caught by F-GD-05 rather than silently misreported.

    ``bundle_dir`` is also what makes the rest of data-management §2's M10 fields answerable at all.
    Six of them -- ``answered_model``, ``system_fingerprints``, ``guardian_restarted``,
    ``control_plane_token_expiry``, ``g2_token_expiry`` and the ``freeze_tag`` of the campaign
    beside the bundle -- are facts about THIS run, and a manifest built without a bundle records the
    "not measured" value for each. ``fidelity_summary`` is the one M10 field not set here: it copies
    a report ``runner/bundle.py`` writes after this function returns.
    """
    source = os.environ if environ is None else environ
    versions = _versions_values()
    common = {
        "run_id": run.run_id,
        "campaign_id": campaign_id,
        "seed": run.seed,
        "rerun_of": rerun_of,
        "is_baseline": run.is_baseline,
        "load_profile_id": run.load_profile_id,
        "started_at": started_at or _now(),
        "ended_at": ended_at or _now(),
        "git_commit": _command(["git", "rev-parse", "HEAD"]),
        "versions_env_sha256": versions_env_sha256(VERSIONS_ENV),
        "host": _host(),
        "schema_version": "v1",
    }
    if run.is_baseline:
        nulls = {name: None for name in MANIFEST_FIELDS if name not in {*common, "baseline_run_id"}}
        return RunManifest(**common, baseline_run_id=None, **nulls)  # type: ignore[arg-type]

    flags = flags_for(run.condition or "")
    alias, provider, config_digest = _model_config(source, versions)
    # The M10 fields (data-management §2). Six are read from the bundle the run just wrote and two
    # from the checkout; ``fidelity_summary`` is NOT here, because it is a copy of the report
    # ``runner/bundle.py`` writes AFTER this manifest, and that module folds it in before the seal
    # hashes are taken. Every reader degrades rather than raising, so a bundle with no tokens.json,
    # no resources.csv or no relay still produces a manifest -- with ``None`` where the fact was not
    # measured, never a guess.
    control_plane_expiry, g2_expiry = live_credential_expiries(bundle_dir)
    answered_model, fingerprints = answered_model_and_fingerprints(bundle_dir)
    return RunManifest(
        **common,
        condition=run.condition,
        scenario_id=run.scenario_id,
        injection_condition=run.injection_condition,
        baseline_run_id=run.baseline_run_id,
        litellm_config_sha256=config_digest,
        model_alias=alias,
        model_provider_string=provider,
        prompt_registry_sha256=directory_digest(default_registry_root()),
        tool_registry_sha256=tool_registry_digest(definitions_for(TOOL_NAMES)),
        graph_id=flags.graph_id,
        guardian_mode=flags.guardian_mode,
        aggregator_quoting=flags.aggregator_quoting,
        netpol_overlay=flags.netpol_overlay,
        shared_credential_exercised=shared_credential_exercised(bundle_dir),
        freeze_tag=freeze_tag_for(bundle_dir),
        instrument_digest=head_instrument_digest(),
        answered_model=answered_model,
        system_fingerprints=fingerprints,
        guardian_restarted=guardian_restarted(bundle_dir),
        environment_lock_sha256=environment_lock_sha256(),
        control_plane_token_expiry=control_plane_expiry,
        g2_token_expiry=g2_expiry,
    )
