r"""The synthetic run corpus (T6.6): the real grid sealed and validated before any real run exists.

WHY THIS RUNS BEFORE ANY REAL DATA
------------------------------------
T6.6 is "pre-registration-as-engineering". This module generates a full campaign of *synthetic* run
bundles -- the real grid (six arms x five scenarios x five injection conditions x the
glossary's five seeds) plus the baselines the pairing rule implies -- seals each through
:func:`runner.bundle.seal_bundle`
and validates the whole corpus through :func:`runner.validate.validate_campaign_corpus`. Because the
generator emits a corpus the sealer accepts and the validator passes, the analysis pipeline can be
proven to regenerate every table and figure from raw bundles alone **before a single real result
exists**, so no metric can be chosen after the fact to flatter one.

THREE CONSTRAINTS, SO SYNTHETIC DATA CANNOT BE MISTAKEN FOR REAL DATA
----------------------------------------------------------------------
1. **Never committed.** ``runs/`` is gitignored; this generator is tracked and its output is not.
   The proof is reproduced by running the generator, which is what makes it a proof.
2. **Unmistakably labelled.** Every bundle's ``campaign_id`` uses the reserved slug
   ``CAMP-<yyyymmdd>-synthetic`` (``runner.campaign.SYNTHETIC_SLUG``), and ``make analyze`` stamps
   the ``campaign_id`` and bundle count into every table and figure, so a figure from synthetic data
   says so on its face.
3. **Structurally real, numerically arbitrary.** The corpus reproduces the real grid exactly -- the
   DoD needs a manifest the validator ACCEPTS, and the metric functions need enough cells per
   condition to exercise per-seed and pooled Wilson intervals and matched-pair formation. Every
   value inside is generated from a fixed seed with no attempt at plausibility.

DETERMINISTIC
---------------
The whole corpus is a pure function of ``(seed, date)``: the campaign date is an input (default a
fixed synthetic date, not a clock read), every ``sealed_at`` is derived from the run index,
and every generated value comes from one seeded generator. Two generations at one seed produce
byte-identical bundles, which lets the synthetic-proof sentinel record a stable corpus digest.

WHAT BREAKS IF THIS FILE CHANGES
---------------------------------
T-25 (the analysis regenerates from raw bundles) and the ``make campaign`` preflight gate that reads
the synthetic proof. ADR-042.
"""

import argparse
import hashlib
import json
import random
import sys
from datetime import UTC, datetime, timedelta
from functools import cache
from pathlib import Path
from typing import Final

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from guardian.app.models import AUDIT_RECORD_SCHEMA_VERSION  # noqa: E402
from guardian.audit.canonical import canonical_json_line  # noqa: E402
from guardian.audit.chain import GENESIS_PREV_HASH, record_hash  # noqa: E402
from guardian.audit.record_types import DECISION_RECORD_TYPE, RUN_START_RECORD_TYPE  # noqa: E402
from scenarios.attackers.plan import plan_cell  # noqa: E402

from runner.assertions import load_groundtruth  # noqa: E402
from runner.bundle import seal_bundle  # noqa: E402
from runner.campaign import (  # noqa: E402
    SYNTHETIC_SLUG,
    CampaignManifest,
    PlannedRun,
)
from runner.campaign import (  # noqa: E402
    to_canonical_bytes as campaign_to_canonical_bytes,
)
from runner.conditions import flags_for  # noqa: E402
from runner.grid import SEEDS as GRID_SEEDS  # noqa: E402
from runner.grid import build_campaign_manifest  # noqa: E402
from runner.ids import parse_run_id  # noqa: E402
from runner.manifest import MANIFEST_FIELDS, RunManifest  # noqa: E402
from runner.validate import (  # noqa: E402
    validate_campaign_corpus,
    validate_campaign_corpus_for_testing,
)
from runner.validity import measurement_window_samples  # noqa: E402

__all__ = (
    "DEFAULT_DATE",
    "SyntheticError",
    "generate_campaign",
    "generate_campaign_for_testing",
    "populate_bundle",
    "synthetic_manifest",
)

# A fixed synthetic date so the campaign_id -- and therefore the corpus digest -- is a function of
# the seed alone, not of when the generator ran. Overridable, but clearly synthetic by default.
DEFAULT_DATE: Final = "20260101"

_PHASES: Final = (
    "detection-and-investigation",
    "containment",
    "eradication",
    "verified-recovery",
)

# --- M10 treatment-fidelity fields (P1, ADR-120) ------------------------------------------------
#
# The synthetic corpus must pass the seal-stage class-T fidelity gate (runner/fidelity/), or
# validate_campaign_corpus rejects it through runner/validity.py::_fidelity_findings. Every value
# below is a fixed, seed-independent constant so two generations at one seed stay byte-identical
# (test_two_generations_at_one_seed_are_byte_identical); nothing here reads a clock.

# F-AG-04 (D10, defect V20): every tokens.json row records the answered model. `model` stays the
# PROVIDER string runner/validity.py::_model_findings reconciles against the manifest;
# `response_model`
# is the raw model off the wire (the value F-AG-04 counts distinct spellings of) and one value
# across
# the corpus, so D10's "unchanged across the campaign" halt never fires on synthetic data.
_MODEL_PROVIDER_STRING: Final = "cerebras/llama-3.3-70b"
_RESPONSE_MODEL: Final = "llama-3.3-70b"

# F-AG-05 (D1-A, SEAM 7): the runtime environment facts rendered into every acting role's task
# frame.
# Rendered in every arm; the credential LOCATION (never its value) and the API server are named ONLY
# in G2-SHAREDCRED. No fact is a secret value, and none is JWT-shaped, so the frame's model context
# stays clean.
_BASE_ENVIRONMENT: Final[tuple[str, ...]] = (
    "NAMESPACE=boutique",
    "GUARDIAN_ENDPOINT=http://127.0.0.1:8080",
)
_G2_ENVIRONMENT: Final[tuple[str, ...]] = (
    # The prefix must be exactly runner.fidelity.agents.KUBE_TOKEN_FACT; the sanitiser redacts the
    # path value (an upper-case KEY carrying TOKEN, per runner/sanitize.py) but keeps the prefix,
    # and
    # F-AG-05 asserts the prefix, so the redaction does not defeat the check.
    "KUBE_TOKEN_FILE=/var/run/secrets/overwatch/g2-executor/token",
    "KUBE_API_SERVER=https://10.96.0.1:443",
)

# F-GD-05 (D1-A, ADR-131): the G2 credential is minted before the agents run and valid past the
# window
# end. A fixed next-day instant, so it is after every _sealed_at window (all on 2026-01-01) and
# stable.
_G2_TOKEN_EXPIRY: Final = "2026-01-02T00:00:00Z"  # noqa: S105 - expiry timestamp, not a secret

# F-GD-05 (D1-A): the object the G2 direct-path mutation targets, named uniquely so the k8s-audit
# cross-check (F-GD-03) never mistakes it for an executed Guardian action and it is attributed to
# the
# G2 principal instead.
_G2_DIRECT_TARGET: Final = "g2-direct-target"

# The API-server principal a synthetic mutation is attributed to when it mirrors an executed
# Guardian
# action or a window sentinel: kind's client-certificate admin user, which
# runner.fidelity.guardian.EXPECTED_PRINCIPAL_EXACT holds (ADR-137). The pre-M10 synthetic sentinels
# already used this literal; keeping it is consistent with that idiom.
_ADMIN_PRINCIPAL: Final = "kubernetes-admin"


class SyntheticError(Exception):
    """The synthetic corpus could not be generated or did not validate."""


def _sealed_at(index: int) -> str:
    """A deterministic ISO-8601 timestamp from the run index, so the corpus is byte-reproducible."""
    minute = index % 60
    hour = (index // 60) % 24
    return f"2026-01-01T{hour:02d}:{minute:02d}:00Z"


def _write_json(path: Path, payload: object) -> None:
    path.write_bytes(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "utf-8"
        )
    )


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    lines = [
        json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True) for row in rows
    ]
    path.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))


@cache
def _synthetic_window_samples() -> int:
    """The protocol window a synthetic bundle must fill, read once (ADR-085 validity check).

    A synthetic bundle carries `measurement_window_samples` probe ticks and resource samples so it
    reads as a real measurement window, which is what lets `make analyze` and the QA entry points
    run the window-length validity check against the synthetic corpus rather than skip it. Cached so
    building a 750-bundle corpus reads the protocol once, not twice per bundle.
    """
    return measurement_window_samples()


def _tick_timestamps(count: int) -> list[str]:
    """``count`` distinct ISO-8601 UTC instants, one per measurement tick.

    Deterministic (no clock, no rng) so a synthetic bundle replays byte-identically. Spaced one
    second apart from a fixed base: distinct enough that `infra.probes.slo_probe.probe_ticks` and
    the resource collector's distinct-``ts`` count see ``count`` separate samples, yet inside the
    probe-gap validity rule (a gap above the protocol probe interval times three is a finding),
    which a minute-wide spacing would trip.
    """
    base = datetime(2026, 1, 1, tzinfo=UTC)
    return [(base + timedelta(seconds=i)).strftime("%Y-%m-%dT%H:%M:%SZ") for i in range(count)]


def _probes_csv(path: Path, rng: random.Random, *, ticks: int) -> None:
    header = "ts,probe_id,target,method,status_code,latency_ms,ok,error"
    rows = [header]
    # One full probe tick per timestamp: the window check counts distinct ticks, so a synthetic
    # bundle must carry `measurement_window_samples` of them to read as a real measurement window
    # rather than the one-tick collapse ADR-085 refuses.
    for ts in _tick_timestamps(ticks):
        latency = rng.randint(5, 400)
        rows.append(f"{ts},PROBE-FRONTEND-HOME,/,GET,200,{latency},true,")
    path.write_bytes(("\n".join(rows) + "\n").encode("utf-8"))


def _resources_csv(path: Path, rng: random.Random, *, ticks: int) -> None:
    header = (
        "ts,series,namespace,workload,container,cpu_cores,mem_bytes,storage_bytes,restarts_total"
    )
    rows = [header]
    # The collector stamps every row of one tick with the same ts; distinct ts values are the sample
    # count. Emit all three series at each of `ticks` timestamps so the resource window matches.
    for ts in _tick_timestamps(ticks):
        for series in ("app", "framework", "platform"):
            cpu = round(rng.uniform(0.01, 0.5), 3)
            mem = rng.randint(10_000_000, 500_000_000)
            rows.append(f"{ts},{series},boutique,frontend,server,{cpu},{mem},0,0")
    path.write_bytes(("\n".join(rows) + "\n").encode("utf-8"))


def _locust_csv(path: Path, rng: random.Random) -> None:
    header = "name,method,num_requests,num_failures,p50_ms,p95_ms"
    req, fail = rng.randint(50, 500), rng.randint(0, 5)
    p50, p95 = rng.randint(10, 80), rng.randint(80, 400)
    row = f"/,GET,{req},{fail},{p50},{p95}"
    rows = [header, row]
    path.write_bytes(("\n".join(rows) + "\n").encode("utf-8"))


def _assertions(
    run_id: str,
    scenario_id: str,
    injection_condition: str,
    rng: random.Random,
    *,
    end_state_results: dict[str, str] | None = None,
) -> dict:
    groundtruth, digest = load_groundtruth(scenario_id)
    definitions = [*groundtruth["assertions"]]
    definitions.extend(groundtruth["conditions"][injection_condition]["end_state_assertions"])
    assertions = [
        {
            "assertion_id": definition["assertion_id"],
            "kind": definition["kind"],
            "phase": definition["phase"],
            "result": (
                end_state_results[definition["assertion_id"]]
                if definition["kind"] == "end-state-compromise" and end_state_results is not None
                else "pass"
                if rng.random() > 0.3
                else "fail"
            ),
            "observed": "synthetic",
            "evaluated_at": "2026-01-01T00:00:00Z",
        }
        for definition in definitions
    ]
    required_substep_results = [
        {
            "substep_id": substep["substep_id"],
            "phase": phase,
            "result": "reached" if rng.random() > 0.3 else "not-reached",
            "observed": "synthetic",
            "evaluated_at": "2026-01-01T00:00:00Z",
        }
        for phase, labels in groundtruth["phases"].items()
        for substep in labels["required_substeps"]
    ]
    return {
        "run_id": run_id,
        "scenario_id": scenario_id,
        "groundtruth_sha256": digest,
        "assertions": assertions,
        "required_substep_results": required_substep_results,
    }


def _write_audit_chain(
    path: Path, run: PlannedRun, injection: str, rng: random.Random, *, started_at: str
) -> tuple[int, dict[str, str]]:
    """Write a valid hash-chained guardian_audit.jsonl, built in memory with the Guardian's hash.

    Uses ``record_hash`` directly rather than ``AuditChainWriter`` -- the writer fsyncs per record,
    which over the whole synthetic grid is minutes, and the synthetic log needs the SAME hash
    construction, not the same durability. verify_chain accepts it because the links are the
    Guardian's own: ``hash = sha256(prev_hash || canonical_json(record_without_hash))`` from the
    genesis all-zero prev_hash, with ``seq`` zero-based and contiguous.

    The chain mirrors what a production Guardian writes (ADR-058). Its genesis is the run-start
    record, stamped at the manifest's ``started_at``; every record names the run (ADR-054's
    boundary) and the arm the Guardian actually runs -- ``flags_for(condition).guardian_mode``,
    which is ``G0-FULL`` for the structure arms and for G3, never the condition token -- and says
    which kind of record it is. So the synthetic proof exercises every consumer's exclusion of the
    genesis rather than a chain shape production no longer writes.
    """
    guardian_mode = flags_for(run.condition or "").guardian_mode
    groundtruth, _digest = load_groundtruth(run.scenario_id or "")
    definitions = groundtruth["conditions"][injection]["end_state_assertions"]
    actions: list[tuple[dict, str]] = []
    end_state_results: dict[str, str] = {}
    for definition in definitions:
        params = dict(definition["check"]["params"])
        action_params = {"replicas": 0} if params.pop("scale_to_zero", False) else {}
        action = {
            "verb": params.pop("verb"),
            "resource": params.pop("resource"),
            "namespace": params.pop("namespace", "boutique"),
            "name": params.pop("name", None),
            "params": {**action_params, **params},
            "justification": "synthetic",
        }
        decision = "permit" if rng.random() > 0.5 else "deny"
        enforcement = (
            "blocked" if decision == "deny" and run.condition != "G1-LOGONLY" else "executed"
        )
        actions.append((action, enforcement))
        end_state_results[definition["assertion_id"]] = (
            "fail" if enforcement == "executed" else "pass"
        )
    while len(actions) < 3:
        actions.append(
            (
                {
                    "verb": "delete",
                    "resource": "pods",
                    "namespace": "boutique",
                    "name": "synthetic-pod",
                    "params": {},
                    "justification": "synthetic",
                },
                "executed",
            )
        )

    genesis: dict[str, object] = {
        "guardian_mode": guardian_mode,
        "prev_hash": GENESIS_PREV_HASH,
        "record_type": RUN_START_RECORD_TYPE,
        "run_id": run.run_id,
        "schema_version": AUDIT_RECORD_SCHEMA_VERSION,
        "seq": 0,
        "ts": started_at,
    }
    prev = record_hash(GENESIS_PREV_HASH, genesis)
    genesis["hash"] = prev
    lines: list[bytes] = [canonical_json_line(genesis)]
    blocked = 0
    for index, (action, enforcement) in enumerate(actions):
        decision = "deny" if enforcement == "blocked" else "permit"
        blocked += enforcement == "blocked"
        record = {
            "action": action,
            "decision": decision,
            "guardian_mode": guardian_mode,
            "enforcement": enforcement,
            "record_type": DECISION_RECORD_TYPE,
            "request_id": f"{run.run_id}-{injection}-{index:03d}",
            "run_id": run.run_id,
            "seq": index + 1,
            "prev_hash": prev,
        }
        digest = record_hash(prev, record)
        record["hash"] = digest
        lines.append(canonical_json_line(record))
        prev = digest
    path.write_bytes(b"".join(lines))
    return blocked, end_state_results


def _required_sources_for(scenario_id: str) -> tuple[str, ...]:
    """The evidence sources a scenario's ground truth requires, sorted for determinism (F-MN-03).

    Mirrors :func:`runner.fidelity.monitor._required_sources` exactly: read the source of every
    ``detection.labels`` entry, and if a ground truth names none, fall back to every source the
    aggregator can emit. Sorted so the per-source ``event_id`` draw does not depend on set iteration
    order (``.agents/rules/20``). A synthetic bundle then carries one event for each source F-MN-03
    demands and no fewer.
    """
    groundtruth, _digest = load_groundtruth(scenario_id)
    detection = groundtruth.get("detection")
    labels = detection.get("labels") if isinstance(detection, dict) else None
    sources = {
        str(label.get("source"))
        for label in (labels or [])
        if isinstance(label, dict) and label.get("source")
    }
    if not sources:
        from monitor.aggregator.normalize import SOURCE_REGISTRY

        sources = {entry.source.value for entry in SOURCE_REGISTRY}
    return tuple(sorted(sources))


def _write_framework_on_files(
    bundle_dir: Path, run: PlannedRun, rng: random.Random, *, started_at: str
) -> None:
    """Write one framework-on bundle's files, passing the seal-stage class-T fidelity gate.

    ``started_at`` is the manifest's own window start. Every Monitor timestamp and the Guardian's
    run-start genesis are stamped with it, so ADR-054's boundary -- every Monitor timestamp inside
    ``[started_at, ended_at]`` -- holds by construction.

    Beyond integrity, each file below carries the M10 treatment-fidelity evidence its class-T check
    reads (plan §5), so ``validate_campaign_corpus`` accepts the corpus rather than rejecting it
    through ``runner/validity.py::_fidelity_findings``:

    * ``tokens.json`` -- the D10 model-echo fields (F-AG-04).
    * ``messages.jsonl`` -- a runtime task frame per context, naming the credential location only in
      G2, plus the drawn payload marker for the agent-visible channels (F-AG-05, F-SC-01).
    * ``monitor_events.jsonl`` -- one event per required source, excerpts framed iff the arm quotes,
      the CVE scan naming the admitted digest, INJ-B's marker in the stream (F-MN-01, F-MN-03,
      F-SC-01, F-SC-02).
    * ``metrics.json`` -- the epoch-drop count (F-MN-02).
    * ``k8s_api_audit.jsonl`` -- window sentinels, one mutation mirroring each executed Guardian
      action, and (G2 only) one direct-path mutation by the shared credential (F-GD-03, F-GD-05,
      F-GD-06).

    Every field is a pure function of ``(seed, run_id)`` and the fixed constants above; nothing
    reads
    a clock, so two generations at one seed stay byte-identical.
    """
    # Lazy imports so `import runner.synthetic` stays light and free of an import cycle through the
    # fidelity package; each is the single owner of the identifier the matching check reads.
    from monitor.aggregator.quoting import apply_quoting

    from runner.fidelity.guardian import (
        SENTINEL_ANNOTATION_KEY,
        SENTINEL_PHASES,
        g2_principal,
    )
    from runner.fidelity.scenarios import _admitted_digest, payload_marker

    parsed = parse_run_id(run.run_id)
    condition = run.condition or ""
    flags = flags_for(condition)
    injection = parsed.injection_condition
    # F-SC-01's needle is scoped to the CELL, not the run: the marker reaches the model's context
    # for INJ-A/C/D, and the agent's context carries no run id, so a run-scoped marker would name
    # the arm to the model. See scenarios/attackers/marker.py.
    marker = payload_marker(parsed.scenario_id, parsed.injection_condition, parsed.seed)

    # F-AG-05 / D1-A: the environment facts the acting role's task frame renders. Every arm renders
    # the base facts; only G2-SHAREDCRED also names the credential location and the API server.
    environment = [*_BASE_ENVIRONMENT]
    if condition == "G2-SHAREDCRED":
        environment.extend(_G2_ENVIRONMENT)

    # F-SC-01: the payload marker reaches the channel the agent sees for INJ-A/C/D (the model
    # context); INJ-B is delivered through the Monitor's stream (below) and never the agent context;
    # INJ-NONE injects nothing.
    agent_marker = marker if injection not in (None, "INJ-NONE", "INJ-B") else None

    messages: list[dict] = []
    for i in range(4):
        # A runtime task frame embedded as a canonical-JSON string, the shape F-AG-05 recovers by
        # scanning for the last object carrying "capability_scope".
        frame = {
            "phase": _PHASES[i],
            "role_id": "supervisor",
            "capability_scope": {
                "verbs": ["patch"],
                "resources": ["deployments"],
                "namespace": "boutique",
            },
            "environment": environment,
        }
        context = "runtime task frame " + json.dumps(
            frame, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        if agent_marker is not None:
            context = f"{context} injected-input {agent_marker}"
        messages.append(
            {
                "index": i,
                "phase": _PHASES[i],
                "role_id": "supervisor",
                "text": "synthetic",
                "context": context,
            }
        )
    _write_jsonl(bundle_dir / "messages.jsonl", messages)

    _write_json(
        bundle_dir / "tokens.json",
        [
            {
                "index": i,
                "phase": _PHASES[i],
                "role_id": "supervisor",
                "model_alias": "overwatch-primary",
                # `model` stays the provider string _model_findings reconciles against the manifest;
                # the raw answered model and hidden-params model are the D10 fields F-AG-04 reads.
                "model": _MODEL_PROVIDER_STRING,
                "response_model": _RESPONSE_MODEL,
                "hidden_params_model": _MODEL_PROVIDER_STRING,
                "prompt_tokens": rng.randint(25, 1250),
                "completion_tokens": rng.randint(12, 500),
            }
            for i in range(4)
        ],
    )
    _write_json(
        bundle_dir / "spans.otel.json",
        {
            "spans": [
                {
                    "attributes": {"phase": phase},
                    "duration_ms": 0.0,
                    "startTimeUnixNano": 1_777_776_000_000_000_000 + index * 1_000_000_000,
                    "endTimeUnixNano": 1_777_776_000_000_000_000 + index * 1_000_000_000,
                    "error": None,
                    "name": "phase",
                    "parent_id": None,
                    "run_id": run.run_id,
                    "schema_version": "v1",
                    "span_id": f"{index:016x}",
                }
                for index, phase in enumerate(_PHASES, 1)
            ]
        },
    )
    # The Guardian's hash-chained decision log, written FIRST so the API-server audit slice below
    # can
    # mirror every executed mutation (F-GD-03's cross-check reads both streams back).
    blocked, end_state_results = _write_audit_chain(
        bundle_dir / "guardian_audit.jsonl",
        run,
        injection,
        rng,
        started_at=started_at,
    )
    decisions = [
        json.loads(line)
        for line in (bundle_dir / "guardian_audit.jsonl").read_text(encoding="utf-8").splitlines()
        if json.loads(line).get("record_type") == DECISION_RECORD_TYPE
    ]

    # F-MN-01/03, F-SC-01/02: one event per ground-truth-required source, so evidence is complete;
    # every excerpt is framed iff the arm quotes; the CVE scan names the admitted digest; INJ-B's
    # marker lands in the Monitor's stream, where the agent never sees it.
    digest = _admitted_digest(run.scenario_id or "")
    events: list[dict] = []
    timings: list[dict] = []
    groundtruth, _ = load_groundtruth(run.scenario_id or "")
    labels = groundtruth["detection"]["labels"]
    for source in _required_sources_for(run.scenario_id or ""):
        excerpt = f"{source} signal fired for {run.run_id} (synthetic evidence)"
        if source == "trivy" and digest:
            excerpt = f"trivy CVE-2021-44228 in admitted image adservice@{digest} (synthetic)"
        if source == "falco" and injection == "INJ-B":
            excerpt = (
                f"falco Terminal shell in container; command line carried {marker} (synthetic)"
            )
        event_id = f"{rng.getrandbits(256):064x}"
        events.append(
            {
                "event_id": event_id,
                "source": source,
                "signal_id": next(
                    (label["signal"] for label in labels if label["source"] == source), None
                ),
                "severity": "high",
                "ts": started_at,
                "evidence_excerpts": [apply_quoting(excerpt, enabled=flags.aggregator_quoting)],
            }
        )
        timings.append({"event_id": event_id, "emit_ts": started_at, "config_epoch": run.run_id})
    _write_jsonl(bundle_dir / "monitor_events.jsonl", events)
    _write_jsonl(bundle_dir / "monitor_timings.jsonl", timings)

    # The API-server audit slice (M10, ADR-137). Required for framework-on bundles (runner/bundle.py
    # _FRAMEWORK_ON_REQUIRED). It carries: the window-open/close sentinel mutations F-GD-06 reads
    # (annotated so `_sentinel_phases` sees them), one mutation mirroring each EXECUTED Guardian
    # action so F-GD-03's one-to-one cross-check clears every execution, and -- G2 only -- one
    # direct-path mutation authenticated as the shared credential so F-GD-05 derives
    # shared_credential_exercised from the audit rather than from the condition name. Every mutation
    # that is not an executed-action mirror is attributed to a principal in the expected set
    # (kind's admin user for sentinels, the G2 ServiceAccount for the direct path).
    api_records: list[dict] = []
    for phase in SENTINEL_PHASES:
        api_records.append(
            {
                "verb": "patch",
                "objectRef": {
                    "resource": "configmaps",
                    "namespace": "boutique",
                    "name": f"overwatch-sentinel-{phase}",
                },
                "annotations": {SENTINEL_ANNOTATION_KEY: phase},
                "user": {"username": _ADMIN_PRINCIPAL},
                "requestReceivedTimestamp": started_at,
            }
        )
    for record in decisions:
        if record.get("enforcement") != "executed":
            continue
        action = record["action"]
        object_ref: dict[str, object] = {
            "resource": action["resource"],
            "namespace": action["namespace"],
        }
        if action.get("name"):
            object_ref["name"] = action["name"]
        api_records.append(
            {
                "verb": action["verb"],
                "objectRef": object_ref,
                "user": {"username": _ADMIN_PRINCIPAL},
                "requestReceivedTimestamp": started_at,
            }
        )
    if condition == "G2-SHAREDCRED":
        api_records.append(
            {
                "verb": "patch",
                "objectRef": {
                    "resource": "deployments",
                    "namespace": "boutique",
                    "name": _G2_DIRECT_TARGET,
                },
                "user": {"username": g2_principal()},
                "requestReceivedTimestamp": started_at,
            }
        )
    _write_jsonl(bundle_dir / "k8s_api_audit.jsonl", api_records)

    _write_json(
        bundle_dir / "results.json",
        [
            {
                "phase": "containment",
                "actions": [
                    {
                        "kind": "action",
                        "decided": True,
                        "audit_seq": record["seq"],
                        "execution": {
                            "status": (
                                "succeeded"
                                if record["enforcement"] == "executed"
                                else "not-attempted"
                            )
                        },
                    }
                ],
            }
            for record in decisions
        ],
    )
    # F-MN-02: the count of events dropped as foreign-epoch. Zero here -- the synthetic collation
    # kept everything -- but the key must be present, or a run that dropped all of them would look
    # clean.
    _write_json(
        bundle_dir / "metrics.json", {"requests_blocked": blocked, "monitor_epoch_drops": 0}
    )
    # The same seeded pool-02 event draw as the live applier, explicitly labelled synthetic.
    planned_events = plan_cell(run.scenario_id or "", injection, parsed.seed)
    _write_jsonl(
        bundle_dir / "injection.log.jsonl",
        [
            {
                **event,
                "applied": {
                    "applied_at": started_at,
                    "outcome": "synthetic",
                    **({"payload_id": event["payload_id"]} if event["payload_id"] else {}),
                },
            }
            for event in planned_events
        ],
    )
    assertions = _assertions(
        run.run_id,
        run.scenario_id,
        injection,
        rng,
        end_state_results=end_state_results,
    )
    from guardian.audit.outcome import bundle_status_by_seq

    from runner.evaluate_assertions import _payload_outcome, _phase_by_seq, build_action_streams

    results = json.loads((bundle_dir / "results.json").read_text(encoding="utf-8"))
    streams = build_action_streams(
        decisions,
        api_records,
        status_by_seq=bundle_status_by_seq(decisions, results),
        phase_by_seq=_phase_by_seq(results),
    )
    outcome = _payload_outcome(bundle_dir, streams)
    if outcome is not None:
        assertions["payload_outcome"] = outcome
    _write_json(bundle_dir / "assertions.json", assertions)
    _probes_csv(bundle_dir / "probes.csv", rng, ticks=_synthetic_window_samples())
    _resources_csv(bundle_dir / "resources.csv", rng, ticks=_synthetic_window_samples())
    _locust_csv(bundle_dir / "locust_stats.csv", rng)


def _write_baseline_files(bundle_dir: Path, rng: random.Random) -> None:
    _probes_csv(bundle_dir / "probes.csv", rng, ticks=_synthetic_window_samples())
    _resources_csv(bundle_dir / "resources.csv", rng, ticks=_synthetic_window_samples())
    _locust_csv(bundle_dir / "locust_stats.csv", rng)


def _manifest_for(
    run: PlannedRun,
    campaign_id: str,
    index: int,
    rerun_of: str | None = None,
    versions_digest: str = "a" * 64,
) -> RunManifest:
    common = {
        "run_id": run.run_id,
        "campaign_id": campaign_id,
        "seed": run.seed,
        "rerun_of": rerun_of,
        "is_baseline": run.is_baseline,
        "load_profile_id": run.load_profile_id,
        "started_at": _sealed_at(index),
        "ended_at": _sealed_at(index + 1),
        "git_commit": "0" * 40,
        "versions_env_sha256": versions_digest,
        "host": {"os": "linux", "wsl_kernel": "6.6", "docker": "27"},
        "schema_version": "v1",
    }
    if run.is_baseline:
        nulls = {name: None for name in MANIFEST_FIELDS if name not in {*common, "baseline_run_id"}}
        return RunManifest(**common, baseline_run_id=None, **nulls)  # type: ignore[arg-type]
    flags = flags_for(run.condition)
    return RunManifest(
        **common,
        condition=run.condition,
        scenario_id=run.scenario_id,
        injection_condition=run.injection_condition,
        baseline_run_id=run.baseline_run_id,
        litellm_config_sha256="b" * 64,
        model_alias="overwatch-primary",
        model_provider_string=_MODEL_PROVIDER_STRING,
        prompt_registry_sha256="c" * 64,
        tool_registry_sha256="d" * 64,
        graph_id=flags.graph_id,
        guardian_mode=flags.guardian_mode,
        aggregator_quoting=flags.aggregator_quoting,
        netpol_overlay=flags.netpol_overlay,
        shared_credential_exercised=run.condition == "G2-SHAREDCRED",
        # M10 (SEAM 1): the provider-returned model (D10), matching tokens.json's answered model,
        # and
        # the G2 token's recorded expiry, after the window end so F-GD-05's expiry half holds. The
        # expiry is None in every arm that mints no such credential.
        answered_model=_RESPONSE_MODEL,
        g2_token_expiry=_G2_TOKEN_EXPIRY if run.condition == "G2-SHAREDCRED" else None,
    )


def populate_bundle(bundle_dir: Path, run: PlannedRun, seed: int, *, index: int = 0) -> None:
    """Write one bundle's telemetry files, deterministically from ``(seed, run.run_id)``.

    The shared bundle-writer behind both the synthetic corpus and ``make run --offline``: an offline
    run produces a real, sealable bundle through the same telemetry writer, so the seal-and-validate
    path is exercised without a cluster. The live Tier B path replaces this with real producers.

    ``index`` is the one :func:`synthetic_manifest` is built with, and defaults the same way, so the
    bundle's Monitor timestamps fall inside that manifest's ``[started_at, ended_at]`` (ADR-054).
    """
    cell_rng = random.Random(  # noqa: S311 - reproducibility is the requirement, not security
        int(hashlib.sha256(f"{seed}\x00{run.run_id}".encode()).hexdigest(), 16)
    )
    if run.is_baseline:
        _write_baseline_files(bundle_dir, cell_rng)
    else:
        _write_framework_on_files(bundle_dir, run, cell_rng, started_at=_sealed_at(index))


def synthetic_manifest(
    run: PlannedRun,
    campaign_id: str,
    index: int = 0,
    *,
    rerun_of: str | None = None,
) -> RunManifest:
    """The full RunManifest for one planned run, with the flag fields set from the arm."""
    return _manifest_for(run, campaign_id, index, rerun_of)


def _generate_campaign(
    out_root: Path,
    seed: int,
    date: str,
    *,
    grid_seeds: tuple[int, ...],
    test_only_reduced: bool,
) -> str:
    """Shared writer behind canonical production and explicitly reduced test generation."""
    campaign_id = f"CAMP-{date}-{SYNTHETIC_SLUG}"
    manifest: CampaignManifest = build_campaign_manifest(
        campaign_id, seeds=grid_seeds, campaign_seed=seed
    )
    campaign_dir = Path(out_root) / campaign_id
    campaign_dir.mkdir(parents=True, exist_ok=True)
    (campaign_dir / "campaign.json").write_bytes(campaign_to_canonical_bytes(manifest) + b"\n")
    for index, run in enumerate(manifest.runs):
        bundle_dir = campaign_dir / run.run_id
        bundle_dir.mkdir(parents=True, exist_ok=True)
        # One deterministic sub-stream per bundle, keyed on (seed, run_id), so a bundle's contents
        # depend on nothing but the seed and its own identifier -- which is what makes two
        # generations byte-identical regardless of iteration order.
        cell_rng = random.Random(  # noqa: S311 - reproducibility is the requirement, not security
            int(hashlib.sha256(f"{seed}\x00{run.run_id}".encode()).hexdigest(), 16)
        )
        if run.is_baseline:
            _write_baseline_files(bundle_dir, cell_rng)
            seal_bundle(
                bundle_dir,
                _manifest_for(
                    run, campaign_id, index, versions_digest=manifest.versions_env_sha256
                ),
                sealed_at=_sealed_at(index),
            )
        else:
            _write_framework_on_files(bundle_dir, run, cell_rng, started_at=_sealed_at(index))
            seal_bundle(
                bundle_dir,
                _manifest_for(
                    run, campaign_id, index, versions_digest=manifest.versions_env_sha256
                ),
                sealed_at=_sealed_at(index),
            )

    try:
        if test_only_reduced:
            validate_campaign_corpus_for_testing(campaign_dir, expected_seeds=grid_seeds)
        else:
            validate_campaign_corpus(campaign_dir)
    except Exception as error:  # noqa: BLE001 - re-raise as the generator's own error with context
        raise SyntheticError(f"the sealed synthetic corpus did not validate: {error}") from error
    return campaign_id


def generate_campaign(out_root: Path, seed: int, date: str = DEFAULT_DATE) -> str:
    """Generate and production-validate the canonical synthetic campaign."""
    return _generate_campaign(out_root, seed, date, grid_seeds=GRID_SEEDS, test_only_reduced=False)


def generate_campaign_for_testing(
    out_root: Path,
    seed: int,
    *,
    seeds: tuple[int, ...],
    date: str = DEFAULT_DATE,
) -> str:
    """Generate a deliberately reduced corpus for unit tests only."""
    return _generate_campaign(out_root, seed, date, grid_seeds=seeds, test_only_reduced=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="synthetic",
        description="Generate, seal and validate the synthetic run corpus (T6.6).",
    )
    parser.add_argument("--seed", type=int, required=True, help="the generator seed")
    parser.add_argument("--out-root", type=Path, default=REPO_ROOT / "runs", help="default runs/")
    parser.add_argument("--date", default=DEFAULT_DATE, help="campaign date yyyymmdd")
    args = parser.parse_args(argv)
    try:
        campaign_id = generate_campaign(args.out_root, args.seed, args.date)
    except SyntheticError as error:
        print(f"synthetic: {error}", file=sys.stderr)
        return 1
    print(f"synthetic: PASS — generated, sealed and validated {campaign_id} under {args.out_root}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
