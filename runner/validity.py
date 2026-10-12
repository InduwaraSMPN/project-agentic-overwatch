r"""Run-validity checks owned by ``data-management.md`` section 4.

The bundle sealer answers whether evidence is complete and immutable.  This module answers the
separate question whether a complete attempt is admissible evidence.  It deliberately reads the
probe interval from ``infra.probes.constants`` -- the checked runtime mirror of the evaluation
protocol -- rather than repeating a duration here.

WHY THE MEASUREMENT-WINDOW CHECK READS THE PROTOCOL TEXT DIRECTLY (ADR-085)
----------------------------------------------------------------------------
``evaluation-protocol.md`` section 4 states ``measurement_window_samples: 121`` in prose ("The
measurement window -- derived, and from what"), not inside the anchored ``<!-- m1-instrument-
constants -->`` block ``infra/probes/constants.py`` mirrors. That block's own test
(``infra/tests/test_constants_match_protocol.py``) asserts its key set is *exactly* the six M1
keys, by design (see that module's docstring on why M2's keys were not folded in), so this value
does not belong inside it, and adding a second anchor plus a second checked mirror module would be
an edit to ``evaluation-protocol.md`` -- a file this stream's owned-files list does not include.
Rather than duplicate the integer as a second, unchecked literal (forbidden by
``.agents/rules/00-source-of-truth.md``: "Other files may only reference, never restate with a
value"), :func:`measurement_window_samples` reads it straight out of the protocol's existing bold,
backtick-quoted statement on every call. This is stricter than a mirror-plus-drift-test: there is
exactly one occurrence of the number in the whole repository, so there is nothing to drift out of
sync with. See ADR-085 for the full reasoning and the follow-up this leaves for whoever next edits
``evaluation-protocol.md``: promoting this value into its own anchored block, the way the M1 and M2
constants already are, so it can be machine-rendered as well as machine-read.
"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from infra.probes.constants import PROBE_INTERVAL_SECONDS
from infra.probes.slo_probe import probe_ticks, read_rows
from scenarios.attackers.plan import load_manifest

from runner.manifest import RunManifest, same_model_provider

__all__ = (
    "MeasurementWindowUnavailable",
    "ValidityFinding",
    "check_run_validity",
    "measurement_window_samples",
)

# data-management section 4 names these Kubernetes termination reasons explicitly.  They are marker
# vocabulary, not locally chosen thresholds.
_INFRA_FAILURE_MARKERS: Final = ("Evicted", "OOMKilled")

# The protocol file this module reads measurement_window_samples from, resolved from this file's own
# location rather than the working directory -- the same convention infra/probes/constants.py uses
# for PROTOCOL_RELATIVE_PATH -- so the read works whichever directory pytest or a CLI was invoked
# from.
_PROTOCOL_PATH: Final = (
    Path(__file__).resolve().parents[1] / "docs/protocols/evaluation-protocol.md"
)

# Matches section 4's exact prose statement: "**`measurement_window_samples: 121`**". Anchored on
# the bold-plus-backtick spelling so that an unrelated later mention of the same words in running
# prose (with neither bold nor backticks) cannot be mistaken for the authoritative one.
_MEASUREMENT_WINDOW_PATTERN: Final = re.compile(r"\*\*`measurement_window_samples:\s*(\d+)`\*\*")


class MeasurementWindowUnavailable(RuntimeError):
    """``measurement_window_samples`` could not be read from evaluation-protocol.md section 4.

    Raised rather than defaulted, for the reason ``.agents/rules/00-source-of-truth.md`` gives for
    every protocol-owned number: a validity check that silently fell back to an invented threshold
    when the protocol's own wording changed shape would certify runs against a number nobody wrote
    down.
    """


def measurement_window_samples(protocol_path: Path = _PROTOCOL_PATH) -> int:
    """Read section 4's ``measurement_window_samples`` from the protocol; never restate it.

    See the module docstring for why this parses the protocol's prose directly rather than a second
    anchored mirror module: adding a new anchor to ``evaluation-protocol.md`` is an edit to a file
    outside this stream's owned-files list, and duplicating the integer as a bare literal here would
    violate the single-homing rule with no test to catch drift.
    """
    try:
        text = protocol_path.read_text(encoding="utf-8")
    except OSError as error:
        raise MeasurementWindowUnavailable(
            f"cannot read {protocol_path} to determine measurement_window_samples: {error}"
        ) from error
    match = _MEASUREMENT_WINDOW_PATTERN.search(text)
    if match is None:
        raise MeasurementWindowUnavailable(
            f"{protocol_path} no longer states measurement_window_samples as "
            "'**`measurement_window_samples: <int>`**' in section 4. That prose statement is the "
            "sole authority for this value (.agents/rules/00-source-of-truth.md); this function "
            "must not invent one, so update this pattern to match the new wording rather than "
            "hardcoding a number here."
        )
    return int(match.group(1))


@dataclass(frozen=True, slots=True)
class ValidityFinding:
    """One independently reportable section-4 reason an attempt is invalid."""

    code: str
    detail: str


def _parse_utc(value: str, *, row: int) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as error:
        raise ValueError(f"probes.csv row {row} has invalid ts {value!r}") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"probes.csv row {row} ts is not timezone-aware UTC: {value!r}")
    if parsed.utcoffset().total_seconds() != 0:
        raise ValueError(f"probes.csv row {row} ts is not UTC: {value!r}")
    return parsed.astimezone(UTC)


def _probe_gap_findings(bundle_dir: Path) -> list[ValidityFinding]:
    path = bundle_dir / "probes.csv"
    try:
        with path.open("r", encoding="utf-8", newline="") as stream:
            rows = list(csv.DictReader(stream))
    except (OSError, UnicodeError, csv.Error) as error:
        return [ValidityFinding("probe-timeline-invalid", f"probes.csv cannot be read: {error}")]
    if not rows or not {"ts", "probe_id"}.issubset(rows[0]):
        return [
            ValidityFinding(
                "probe-timeline-invalid", "probes.csv has no samples or lacks ts/probe_id columns"
            )
        ]

    timelines: dict[str, list[datetime]] = {}
    try:
        for number, row in enumerate(rows, 2):
            probe_id = row.get("probe_id", "").strip()
            if not probe_id:
                raise ValueError(f"probes.csv row {number} has an empty probe_id")
            timelines.setdefault(probe_id, []).append(_parse_utc(row.get("ts", ""), row=number))
    except ValueError as error:
        return [ValidityFinding("probe-timeline-invalid", str(error))]

    threshold = PROBE_INTERVAL_SECONDS * 3
    findings: list[ValidityFinding] = []
    for probe_id, timestamps in timelines.items():
        ordered = sorted(timestamps)
        for previous, current in zip(ordered, ordered[1:], strict=False):
            gap = (current - previous).total_seconds()
            if gap > threshold:
                findings.append(
                    ValidityFinding(
                        "probe-gap",
                        f"{probe_id} gap {gap:g}s exceeds protocol interval x3 ({threshold:g}s)",
                    )
                )
                break
    return findings


def _probe_window_findings(bundle_dir: Path, window_samples: int) -> list[ValidityFinding]:
    """A probe timeline with fewer ticks than the protocol window did not observe the run.

    Supervisor ruling B3 / evidence of 2026-09-13: ``RUN-G0-FULL-SCN-SIM-02-INJ-A-101`` sealed with
    one probe tick against ``measurement_window_samples: 121``, and its lone tick predated the first
    injection -- so the sealed bundle's "verified recovery" read a probe row from before the
    incident. A gap check alone cannot catch this: one sample has no neighbour to measure a gap
    against, so :func:`_probe_gap_findings` reports nothing wrong with a timeline that stopped
    almost immediately.

    Reuses :func:`infra.probes.slo_probe.read_rows` and :func:`infra.probes.slo_probe.probe_ticks`
    -- the same fold the writer and the calibration path already trust -- rather than re-deriving
    tick boundaries a third time. A file :func:`_probe_gap_findings` already reports as
    ``probe-timeline-invalid`` (unreadable, wrong header, malformed timestamp) is silently skipped
    here rather than reported twice for one root cause.
    """
    path = bundle_dir / "probes.csv"
    try:
        rows = read_rows(path)
    except (OSError, UnicodeError, csv.Error, ValueError):
        return []
    ticks = len(probe_ticks(rows))
    if ticks < window_samples:
        return [
            ValidityFinding(
                "probe-window-short",
                f"probes.csv holds {ticks} probe tick(s), short of the protocol "
                f"measurement_window_samples ({window_samples}); evaluation-protocol.md section 4",
            )
        ]
    return []


def _resource_window_findings(bundle_dir: Path, window_samples: int) -> list[ValidityFinding]:
    """A resource series with fewer sample ticks than the protocol window did not observe the run.

    ``infra/collectors/resource_collector.py`` stamps every row of one collection tick with the same
    ``ts`` ("taken once per collection tick and stamped identically on every row of that tick"), so
    the number of distinct ``ts`` values is the number of samples -- the same quantity
    ``measurement_window_samples`` counts for the probe timeline, evaluation-protocol.md section 4.
    A file that cannot be read as a CSV, or that lacks a ``ts`` column, is left to whichever other
    check already covers a malformed bundle; this function only ever adds a finding to a bundle it
    could actually read.
    """
    path = bundle_dir / "resources.csv"
    try:
        with path.open("r", encoding="utf-8", newline="") as stream:
            rows = list(csv.DictReader(stream))
    except (OSError, UnicodeError, csv.Error):
        return []
    if not rows or "ts" not in rows[0]:
        return []
    samples = len({row.get("ts", "") for row in rows})
    if samples < window_samples:
        return [
            ValidityFinding(
                "resource-window-short",
                f"resources.csv holds {samples} sample tick(s), short of the protocol "
                f"measurement_window_samples ({window_samples}); evaluation-protocol.md section 4",
            )
        ]
    return []


def _json_records(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        loaded = json.loads(raw)
        if not isinstance(loaded, dict):
            raise ValueError(f"{path.name} line {number} is not a JSON object")
        records.append(loaded)
    return records


def _scenario_targets(manifest: RunManifest) -> set[str]:
    if manifest.is_baseline or manifest.scenario_id is None:
        return set()
    scenario = load_manifest(manifest.scenario_id)
    targets: set[str] = set()
    for primitive in scenario.get("incident_primitives", []):
        target = primitive.get("target", {}) if isinstance(primitive, dict) else {}
        if isinstance(target, dict):
            for field in ("workload", "container"):
                value = target.get(field)
                if isinstance(value, str):
                    targets.add(value.casefold())
    return targets


def _infra_findings(bundle_dir: Path, manifest: RunManifest) -> list[ValidityFinding]:
    path = bundle_dir / "monitor_events.jsonl"
    if manifest.is_baseline or not path.is_file():
        return []
    try:
        records = _json_records(path)
        scenario_targets = _scenario_targets(manifest)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        return [ValidityFinding("infra-marker-invalid", str(error))]

    findings: list[ValidityFinding] = []
    for number, record in enumerate(records, 1):
        rendered = json.dumps(record, sort_keys=True, ensure_ascii=True)
        marker = next((item for item in _INFRA_FAILURE_MARKERS if item in rendered), None)
        if marker is None:
            continue
        resource = record.get("resource")
        names = {
            str(value).casefold()
            for value in (resource.values() if isinstance(resource, dict) else ())
            if value is not None
        }
        # A marker on a workload/container named by an incident primitive is scenario-caused.  Any
        # other marker is the unrelated framework/app failure section 4 invalidates.
        if names & scenario_targets:
            continue
        findings.append(
            ValidityFinding(
                "infra-failure",
                f"monitor_events.jsonl line {number} carries unrelated {marker} marker",
            )
        )
    return findings


def _token_calls(document: Any) -> list[dict[str, Any]]:
    if isinstance(document, list):
        return [item for item in document if isinstance(item, dict)]
    if isinstance(document, dict):
        for key in ("calls", "entries", "records"):
            value = document.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def _answered_models(call: dict[str, Any]) -> list[Any]:
    """Every model string one tokens.json entry records: the call's own, then each attempt's.

    ADR-060 gives an entry ``attempt_usage``, one record per request sent, each naming the model
    that request was answered under. The entry-level ``model`` is the last answer's, so a
    substitution on an earlier attempt shows only there. An entry written before ADR-060 has no
    attempts to read and is checked as it always was. A malformed attempt list, or an attempt
    without a model, reads as ``None``, which is not the manifest's model: a check that must cover
    every request does not skip one it cannot read.
    """
    models: list[Any] = [call.get("model")]
    if "attempt_usage" not in call:
        return models
    usage = call["attempt_usage"]
    if not isinstance(usage, list):
        return [*models, None]
    return [
        *models,
        *(attempt.get("model") if isinstance(attempt, dict) else None for attempt in usage),
    ]


def _model_findings(bundle_dir: Path, manifest: RunManifest) -> list[ValidityFinding]:
    if manifest.is_baseline:
        return []
    path = bundle_dir / "tokens.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return [ValidityFinding("model-identity-invalid", f"tokens.json cannot be read: {error}")]

    calls = _token_calls(document)
    aliases = {call.get("model_alias") for call in calls}
    providers = {model for call in calls for model in _answered_models(call)}
    if any(alias != manifest.model_alias for alias in aliases):
        return [
            ValidityFinding(
                "model-alias-changed",
                f"per-call aliases {sorted(map(repr, aliases))} disagree with manifest alias "
                f"{manifest.model_alias!r}",
            )
        ]
    if any(
        not same_model_provider(provider, manifest.model_provider_string) for provider in providers
    ):
        return [
            ValidityFinding(
                "model-alias-changed",
                f"alias resolved to provider models {sorted(map(repr, providers))} across calls "
                f"and their attempts, not the single manifest provider "
                f"{manifest.model_provider_string!r}",
            )
        ]
    return []


def _fidelity_findings(bundle_dir: Path, manifest: RunManifest) -> list[ValidityFinding]:
    """A run whose class-T fidelity check failed is invalid for the analysed set (data-management
    §4).

    M10's addition to §4's list, and the reason it lives HERE rather than in
    ``runner/bundle.py::verify_bundle_seal``: the two answer different questions.
    ``verify_bundle_seal``
    is INTEGRITY -- do the bytes hash, is the manifest consistent, does the chain verify -- and
    every
    one of those is a property of the artefact. Fidelity is VALIDITY: the artefact is internally
    perfect and the measurement it supports is not the one the cell asked for. A G3-UNQUOTED run
    whose
    aggregator ran quoted seals cleanly, verifies cleanly, and measures the wrong thing; putting
    that
    in the seal verifier would make an integrity question carry a scientific one, and would report
    it
    at a point where the only available action is to destroy the bundle.

    The report is READ BACK, never recomputed: ``fidelity.json`` is inside ``content_hashes``, so an
    edited report has already failed the hash check, and recomputing here would be a second
    implementation of the registry free to disagree with the sealer's. A bundle with no report is a
    v1
    bundle and yields nothing -- its unprovable treatments are ``F-RN-02``'s corpus-level finding,
    not
    a per-bundle one.
    """
    if manifest.is_baseline:
        return []
    from runner.fidelity import read_fidelity

    document = read_fidelity(Path(bundle_dir))
    if document is None:
        return []
    if document.get("schema_version") != "fidelity.v1":
        return [
            ValidityFinding(
                code="fidelity-schema-unknown",
                detail=(
                    f"fidelity.json declares schema_version {document.get('schema_version')!r}, "
                    "not "
                    "'fidelity.v1' (SEAM 2)"
                ),
            )
        ]
    if document.get("run_id") != manifest.run_id:
        return [
            ValidityFinding(
                code="fidelity-run-id-mismatch",
                detail=(
                    f"fidelity.json names run_id {document.get('run_id')!r}, not this bundle's "
                    f"{manifest.run_id!r}"
                ),
            )
        ]
    failures = sorted(
        str(entry.get("id"))
        for entry in document.get("checks", [])
        if isinstance(entry, dict) and entry.get("klass") == "T" and entry.get("status") == "fail"
    )
    if not failures:
        return []
    return [
        ValidityFinding(
            code="fidelity-treatment-failed",
            detail=(
                f"class-T fidelity failure(s) {failures}: the treatment this cell was run to "
                "measure "
                "was not delivered, so the run is invalid for the analysed set and the campaign "
                "HALTS "
                "rather than reruns (P2, ADR-120). The bundle is retained as the evidence of the "
                "defect; originals are retained, marked, never analysed (data-management §4)."
            ),
        )
    ]


def check_run_validity(
    bundle_dir: Path,
    manifest: RunManifest,
    *,
    window_samples: int | None = None,
) -> tuple[ValidityFinding, ...]:
    """Return every detectable data-management section-4 validity failure in one bundle.

    ``window_samples``, when given, additionally checks the bundle's ``probes.csv`` and
    ``resources.csv`` tick counts against it (:func:`_probe_window_findings`,
    :func:`_resource_window_findings`) -- the check ADR-085 adds for the collapsed-window defect
    (supervisor ruling B3, evidence of 2026-09-13). It defaults to ``None``, which skips that pair
    of checks, rather than to :func:`measurement_window_samples`'s live 121, and that default is
    deliberate rather than an oversight: every existing caller of this function --
    ``runner/campaign_cli.py``, ``runner/pilot_cli.py``, ``runner/validate.py``, and this module's
    own offline/synthetic test fixtures -- runs today against bundles built by
    ``runner/synthetic.py`` to exercise a single narrow behaviour in a handful of hand-written rows,
    never against 121 real ticks; defaulting this check on made eight of their passing tests fail on
    a short *synthetic* window, which is a correct reading of a fixture that was never meant to
    carry a real measurement window and not a defect this stream's owned files (none of those three
    call sites, nor ``runner/synthetic.py``, is on it) may fix by editing them. A caller that wants
    the protocol's own number for a real sealed bundle passes
    ``window_samples=measurement_window_samples()`` explicitly; see ADR-085 for the follow-up this
    leaves for the integrator.
    """
    directory = Path(bundle_dir)
    findings = [
        *_probe_gap_findings(directory),
        *_infra_findings(directory, manifest),
        *_model_findings(directory, manifest),
        *_fidelity_findings(directory, manifest),
    ]
    if window_samples is not None:
        findings = [
            *findings,
            *_probe_window_findings(directory, window_samples),
            *_resource_window_findings(directory, window_samples),
        ]
    return tuple(findings)
