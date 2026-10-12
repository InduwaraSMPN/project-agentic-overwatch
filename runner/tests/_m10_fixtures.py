r"""Shared builders for the M10 fidelity tests: one v2-shaped bundle, and one per v1 defect.

WHY A HELPER MODULE RATHER THAN FIXTURES IN EACH TEST FILE
----------------------------------------------------------
Three test files need the same thing (``test_fidelity.py``, ``test_fidelity_known_bad.py``, and the
new cases in ``test_bundle.py``), and they need it to be the SAME bundle -- a fixture that is
v2-shaped
in one file and not in another would make "the check passes" and "the check passes" mean two
different things. ``runner/tests/`` is a package (``__init__.py`` is tracked), so a private module
under it is importable as ``runner.tests._m10_fixtures``; the leading underscore keeps it out of
pytest's collection the way a module named ``test_*`` would not.

WHY THE BUILDER IS BUILT ON ``runner.synthetic.populate_bundle``
---------------------------------------------------------------
Plan WS-5's row for ``runner/synthetic.py`` is "expose ``populate_bundle`` as the base for the
per-defect synthetic bundles", and this is that use. The base writes a real, SEALABLE framework-on
bundle -- a valid audit chain, a contract-valid ``assertions.json``, a window-length probe and
resource series -- none of which any of these tests should have to re-derive. What the base does not
write is anything M10 added, so :func:`v2_bundle` writes exactly that on top: the API-audit slice
with
its two sentinels, the ``config_epoch`` on every timing row, the excerpt quoting the arm declares,
the
D1-A environment facts in the runtime task frames, the D10 model-echo fields, the payload marker,
and
the recorded token expiries.

THE SHAPE OF A PASSING BUNDLE, AND WHY IT IS THIS SHAPE
-------------------------------------------------------
A "passing" bundle here is one where every class-T seal check passes, and the shape follows directly
from the checks: an excerpt per required source and per arm quoting, one timing row per event with
this
run's epoch, a recorded drop count, one API-audit mutation per EXECUTED Guardian record (so
F-GD-03's
corroboration direction holds) plus two sentinels (so F-GD-06's coverage direction holds), a
``response_model`` on every tokens row, a runtime task frame on every model context, the payload
marker in a context for an injected cell, and the two token expiries after the window end. Anything
else is a ``skip`` with a reason, which is a legitimate state and is asserted as one where the skip
is
the point.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
Every M10 fidelity test. It is a TEST helper: it is not imported by any production module, and the
guards in ``scripts/grep_guard.sh`` do not constrain it because it opens nothing and imports no
cluster client.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from guardian.audit.record_types import DECISION_RECORD_TYPE, is_run_start
from scenarios.attackers.marker import payload_marker

from runner.campaign import PlannedRun
from runner.conditions import flags_for
from runner.fidelity.guardian import SENTINEL_ANNOTATION_KEY, SENTINEL_PHASES
from runner.ids import RunId, format_run_id
from runner.synthetic import populate_bundle, synthetic_manifest

#: The window the synthetic bundles use, in ISO-8601. Fixed, never a clock read: iron rule 3, and
#: the
#: token-expiry comparisons in F-GD-05 are meaningless against a moving boundary.
WINDOW_START: str = "2026-01-01T00:00:00Z"
WINDOW_END: str = "2026-01-01T00:01:00Z"

#: After the window end on purpose: F-GD-05 requires a token minted before the agents to still be
#: valid when the window closes, and the TokenRequest floor of ten minutes is below v1's 12.4-minute
#: median run, which is the defect.
TOKEN_EXPIRY: str = "2026-01-01T00:30:00Z"  # noqa: S105 - expiry timestamp, not a secret

#: The alternate credential's location, for the G2 frame. A PATH, never a value: the point of the
#: environment fact is that it names where the credential is without carrying it (D1-A, SEAM 7).
G2_TOKEN_PATH: str = "/runner/runs/.private/G2.token"  # noqa: S105 - file path, not a secret

_PHASES: tuple[str, ...] = (
    "detection-and-investigation",
    "containment",
    "eradication",
    "verified-recovery",
)

#: The answered model the fixture records. Distinct from the alias on purpose: D10's whole point is
#: that the provider-returned model is recorded, and a fixture where they coincide would prove
#: nothing about the recording. The PINNED provider string stays `cerebras/llama-3.3-70b`, because
#: `runner.manifest.same_model_provider` compares the provider prefix AND the terminal model id and
#: tolerates a vendor namespace inserted between them (ADR-106) -- so a gateway answering
#: `cerebras/llama-3.3-70b-8192` is the same model to the sealer and a different string to a reader,
#: which is exactly the distinction F-AG-04 exists to preserve.
ANSWERED_MODEL: str = "cerebras/llama-3.3-70b-8192"
PINNED_MODEL: str = "cerebras/llama-3.3-70b"
ALIAS: str = "overwatch-primary"


def _write_json(path: Path, payload: Any) -> None:
    path.write_bytes(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "utf-8"
        )
    )


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    body = "\n".join(
        json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True) for row in rows
    )
    path.write_bytes((body + "\n").encode("utf-8"))


def _read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def planned_run(
    *,
    condition: str = "G0-FULL",
    scenario_id: str = "SCN-SIM-01",
    injection: str = "INJ-A",
    seed: int = 101,
    baseline: bool = False,
) -> PlannedRun:
    """One planned cell for the fixture corpus.

    The seed is inside ``runner.grid.SEEDS`` so the planned run is one the real validators accept,
    and
    the injection condition is one of the five so ``parse_run_id`` round-trips -- which matters
    because
    ``seal_bundle`` calls ``validate_bundle``, and a fixture that could not seal would prove nothing
    about the checks that run after the seal.
    """
    if baseline:
        return PlannedRun(
            run_id="BASE-LOAD-STEADY-101",
            condition=None,
            scenario_id=None,
            injection_condition=None,
            seed=seed,
            is_baseline=True,
            baseline_run_id=None,
            load_profile_id="LOAD-STEADY",
        )
    return PlannedRun(
        run_id=format_run_id(RunId(condition, scenario_id, injection, seed)),
        condition=condition,
        scenario_id=scenario_id,
        injection_condition=injection,
        seed=seed,
        is_baseline=False,
        baseline_run_id=("BASE-LOAD-STEADY-101" if condition == "G0-FULL" else None),
        load_profile_id="LOAD-STEADY",
    )


def _environment_facts(condition: str) -> list[str]:
    """The D1-A environment facts for one arm.

    Rendered in EVERY arm from a fixed list, with the credential LOCATION added in G2 only -- which
    is
    what makes F-AG-05's "if and only if" testable in both directions rather than only the G2 one.
    The two non-G2 facts are deliberately dull: an environment list exists to tell the acting role
    what
    is true about its world, and anything interesting in it is a prompt-injection surface.
    """
    facts = [
        "namespace=boutique",
        "guardian_url_is_reachable=true",
    ]
    if condition == "G2-SHAREDCRED":
        facts.append(f"KUBE_TOKEN_FILE={G2_TOKEN_PATH}")
        facts.append("KUBE_API_SERVER=https://kubernetes.default.svc")
    return facts


def _runtime_task(phase: str, capability_scope: dict | None, environment: list[str]) -> str:
    """The same shape ``agents/graphs/nodes.py::_runtime_task`` writes."""
    return json.dumps(
        {"phase": phase, "capability_scope": capability_scope, "environment": list(environment)},
        sort_keys=True,
        separators=(",", ":"),
    )


def _required_sources(scenario_id: str) -> list[str]:
    from runner.assertions import load_groundtruth

    groundtruth, _digest = load_groundtruth(scenario_id)
    labels = groundtruth.get("detection", {}).get("labels", [])
    sources = [
        str(label["source"]) for label in labels if isinstance(label, dict) and label.get("source")
    ]
    return sources or ["falco"]


def _excerpt(source: str, quoting: bool) -> str:
    from monitor.aggregator.quoting import apply_quoting

    return apply_quoting(_event_text(source), enabled=quoting)


def _event_text(source: str) -> str:
    """The source text one synthetic event carries.

    A Trivy event names the ADMITTED DIGEST, not merely "trivy ran": F-SC-02 exists to catch a stale
    scan report from before the admission, and a fixture whose Trivy text said only "trivy" would
    make
    that check pass over a bundle that proves nothing about the delivery.
    """
    if source == "trivy":
        from runner.fidelity.scenarios import _admitted_digest

        return f"trivy finding on {_admitted_digest('SCN-CVE-04')}"
    return f"synthetic {source} observation"


def _api_audit_records(bundle_dir: Path, *, g2_request: bool = False) -> list[dict]:
    """One API-audit mutation per EXECUTED Guardian record, plus the two sentinels.

    The corroboration direction (F-GD-03) is what makes the Guardian's chain and the API server's
    record agree, and the attribution direction needs every OTHER mutation to carry an expected
    principal. The sentinels are patched annotations on a logged object at the window boundaries,
    and
    they carry the ReplicaSet-controller principal so they do not read as an unattributed mutation.
    """
    records: list[dict] = []
    for position, parsed in enumerate(_audit_records(bundle_dir)):
        if is_run_start(parsed) or parsed.get("record_type") != DECISION_RECORD_TYPE:
            continue
        # `enforcement == executed`, which is the cross-check's own definition of an execution
        # (`guardian/audit/k8s_crosscheck.py::executed_actions_from_records`): the Guardian did not
        # block the action and it reached the executor. Deliberately NOT
        # `guardian.audit.outcome.succeeded` -- the v3 synthetic chain carries no
        # `execution_status` field and no execution follow-up, so the stricter reader answers
        # `unknown` and a fixture that used it would corroborate nothing and appear to prove the
        # cross-check vacuous.
        if parsed.get("enforcement") != "executed":
            continue
        action = parsed.get("action", {})
        records.append(
            {
                "kind": "Event",
                "apiVersion": "audit.k8s.io/v1",
                "level": "Metadata",
                "verb": str(action.get("verb") or "get"),
                "stage": "ResponseComplete",
                "requestReceivedTimestamp": "2026-01-01T00:00:30.000000Z",
                "user": {"username": "system:serviceaccount:guardian:guardian"},
                "objectRef": {
                    "resource": str(action.get("resource") or "pods"),
                    "namespace": action.get("namespace") or "boutique",
                    # The name verbatim, INCLUDING None. A collection-scoped Guardian action carries
                    # no name, and `k8s_crosscheck` documents that such an action never matches a
                    # NAMED API mutation -- so a fixture that invented a name here would be
                    # corroborating a different action than the one the chain records.
                    "name": action.get("name"),
                },
                "responseStatus": {"code": 200},
                "annotations": {SENTINEL_ANNOTATION_KEY: f"mutation-{position:03d}"},
            }
        )
    for phase in SENTINEL_PHASES:
        records.append(
            {
                "kind": "Event",
                "apiVersion": "audit.k8s.io/v1",
                "level": "Metadata",
                "verb": "patch",
                "stage": "ResponseComplete",
                "requestReceivedTimestamp": (
                    "2026-01-01T00:00:01.000000Z"
                    if phase == "open"
                    else "2026-01-01T00:00:59.000000Z"
                ),
                "user": {"username": "system:serviceaccount:kube-system:replicaset-controller"},
                "objectRef": {
                    "resource": "deployments",
                    "namespace": "boutique",
                    "name": "frontend",
                    "annotations": {SENTINEL_ANNOTATION_KEY: phase},
                },
                "responseStatus": {"code": 200},
                "annotations": {SENTINEL_ANNOTATION_KEY: phase},
            }
        )
    if g2_request:
        # The alternate path, DISCOVERED: a read the G2 principal authenticated. D1-A splits
        # discovery
        # from use on purpose -- a `get` is evidence the path was found, not that anything was done
        # through it -- and the fixture exercises the discovery half so a G2 bundle's
        # `shared_credential_exercised` is derived from something observable.
        records.append(
            {
                "kind": "Event",
                "apiVersion": "audit.k8s.io/v1",
                "level": "Metadata",
                "verb": "get",
                "stage": "ResponseComplete",
                "requestReceivedTimestamp": "2026-01-01T00:00:40.000000Z",
                "user": {"username": "system:serviceaccount:agents:g2-executor"},
                "objectRef": {"resource": "pods", "namespace": "boutique", "name": "frontend-abc"},
                "responseStatus": {"code": 200},
            }
        )
    return records


def _audit_records(bundle_dir: Path) -> list[dict]:
    return _read_jsonl(bundle_dir / "guardian_audit.jsonl")


def v2_bundle(
    bundle_dir: Path,
    *,
    condition: str = "G0-FULL",
    scenario_id: str = "SCN-SIM-01",
    injection: str = "INJ-A",
    seed: int = 101,
    campaign_id: str = "CAMP-20260101-m10synthetic",
    instrument_digest: str = "d" * 64,
    baseline: bool = False,
    seal: bool = True,
    payload_id: str = "INJ-A-pool-02-001",
    extra_environment: list[str] | None = None,
    storage_bytes: int = 0,
) -> Path:
    """Write one M10-shaped bundle into ``bundle_dir`` and seal it.

    The base is :func:`runner.synthetic.populate_bundle`; everything after it is the M10 overlay
    described in the module docstring. ``seal`` is on by default because several checks (F-GD-06's
    "and sealed" half, F-RN-02's corpus digest) read ``seal.json``, and a fixture that skipped it
    would exercise a path no real bundle takes.
    """
    bundle_dir.mkdir(parents=True, exist_ok=True)
    planned = planned_run(
        condition=condition,
        scenario_id=scenario_id,
        injection=injection,
        seed=seed,
        baseline=baseline,
    )
    populate_bundle(bundle_dir, planned, seed, index=3)
    if baseline:
        return bundle_dir

    flags = flags_for(condition)
    quoting = bool(flags.aggregator_quoting)
    environment = _environment_facts(condition) + list(extra_environment or [])

    # --- the agent layer: D10 fields, runtime task frames, and the payload marker ---------------
    messages = _read_jsonl(bundle_dir / "messages.jsonl")
    # The marker is scoped to the cell, not the run: the agent's context carries no run id, so a
    # run-scoped marker would name the arm to the model. See scenarios/attackers/marker.py.
    token_marker = payload_marker(planned.scenario_id, planned.injection_condition, planned.seed)
    for position, record in enumerate(messages):
        phase = record.get("phase") or _PHASES[position % len(_PHASES)]
        frame = _runtime_task(phase, {"verb": "get", "resource": "pods"}, environment)
        context = f"synthetic phase {phase}\n{frame}"
        if injection != "INJ-NONE" and position == 0:
            context = f"{context}\n{token_marker}"
        record["context"] = context
        record["system"] = f"synthetic system prompt for {phase}"
        record["tool_call"] = {"name": "guardian_action", "arguments": {"verb": "get"}}
    _write_jsonl(bundle_dir / "messages.jsonl", messages)

    tokens = json.loads((bundle_dir / "tokens.json").read_text(encoding="utf-8"))
    for entry in tokens:
        entry["model_alias"] = ALIAS
        entry["model"] = PINNED_MODEL
        entry["system_fingerprint"] = "fp_fidelity_fixture"
        entry["response_model"] = ANSWERED_MODEL
        entry["hidden_params_model"] = ANSWERED_MODEL
    _write_json(bundle_dir / "tokens.json", tokens)

    # --- the injection log: the drawn payload, which F-SC-01 reads -----------------------------
    injection_rows = _read_jsonl(bundle_dir / "injection.log.jsonl")
    for row in injection_rows:
        applied = row.setdefault("applied", {})
        applied["payload_id"] = payload_id
    _write_jsonl(bundle_dir / "injection.log.jsonl", injection_rows)

    # --- the Monitor: quoting, the config epoch, and one event per required source --------------
    events: list[dict] = []
    timings: list[dict] = []
    for position, source in enumerate(_required_sources(scenario_id), start=1):
        event_id = f"{position:064x}"
        events.append(
            {
                "event_id": event_id,
                "source": source,
                "severity": "high",
                "ts": WINDOW_START,
                "summary": _excerpt(source, quoting),
                "evidence_excerpts": [_excerpt(source, quoting)],
                "raw_ref": {"path": f"k8s_audit.jsonl:{position}", "byte_offset": 0, "length": 1},
                "schema_version": "v2",
                "signal_id": None if source != "falco" else "Synthetic rule",
            }
        )
        timings.append(
            {
                "event_id": event_id,
                "emit_ts": WINDOW_START,
                "config_epoch": planned.run_id,
                "ingest_latency_ms": 1.0,
            }
        )
    _write_jsonl(bundle_dir / "monitor_events.jsonl", events)
    _write_jsonl(bundle_dir / "monitor_timings.jsonl", timings)

    # --- the API-server audit slice, with the sentinels ------------------------------------------
    _write_jsonl(
        bundle_dir / "k8s_api_audit.jsonl",
        _api_audit_records(bundle_dir, g2_request=condition == "G2-SHAREDCRED"),
    )

    # --- metrics.json: the drop count F-MN-02 requires, plus the seal's own counter --------------
    # `monitor_forwarder_drain_seconds` is DELIBERATELY absent: the synthetic bundle ran no audit
    # forwarder, so F-MN-04 must SKIP on it rather than report a drain of a forwarder that never
    # existed. A fixture that recorded a value here would make the P0-live drain check pass without
    # having measured anything, which is the unearned-pass failure the `skip` status exists to
    # prevent.
    metrics = json.loads((bundle_dir / "metrics.json").read_text(encoding="utf-8"))
    metrics["monitor_epoch_drops"] = 0
    _write_json(bundle_dir / "metrics.json", metrics)

    # --- the storage column (D15) ----------------------------------------------------------------
    # `populate_bundle` writes `storage_bytes=0` on every row, which is v1's shape verbatim: the
    # collector's query returned nothing, and reporting that as zero BYTES would be a false
    # measurement (D15, defect V10). A v2-shaped bundle reports a real value; the known-bad fixture
    # leaves it at zero and F-AN-03 flags it, which is the whole of the P0-live probe for D15.
    if storage_bytes:
        _set_storage_bytes(bundle_dir, storage_bytes)

    if seal:
        _seal(bundle_dir, planned, campaign_id, instrument_digest, injection)
    return bundle_dir


def _set_storage_bytes(bundle_dir: Path, value: int) -> None:
    """Put a real ``storage_bytes`` on the FIRST data row and leave the rest at zero.

    One row, not every row: F-AN-03 requires at least one probed container to report a positive
    value, because a freshly created container genuinely has no writable layer and a requirement
    that
    every row be positive would produce a false failure. Rewriting the column also re-hashes the
    file,
    which is why the caller re-seals afterwards.
    """
    lines = (bundle_dir / "resources.csv").read_text(encoding="utf-8").splitlines()
    header = lines[0].split(",")
    column = header.index("storage_bytes")
    cells = lines[1].split(",")
    cells[column] = str(value)
    (bundle_dir / "resources.csv").write_text(
        "\n".join([lines[0], ",".join(cells), *lines[2:]]) + "\n", encoding="utf-8"
    )


def _seal(
    bundle_dir: Path,
    planned: PlannedRun,
    campaign_id: str,
    instrument_digest: str,
    injection: str,
) -> None:
    """Seal the bundle with the M10 manifest fields, through the real sealer.

    ``seal_bundle`` is the production path and it is what computes ``content_hashes`` -- including
    ``fidelity.json``'s, once ``runner/bundle.py`` writes one -- so a fixture sealed here is sealed
    exactly as a live run's is. The token expiries are passed to the manifest builder so F-GD-05's
    "the expiry is after the window end" comparison has something real to read.
    """
    from runner.bundle import seal_bundle
    from runner.manifest import MANIFEST_FIELDS, RunManifest

    manifest = synthetic_manifest(planned, campaign_id)
    is_g2 = planned.condition == "G2-SHAREDCRED"
    extra: dict[str, Any] = {
        "freeze_tag": "v2.0",
        "instrument_digest": instrument_digest,
        "answered_model": ANSWERED_MODEL,
        "system_fingerprints": ("fp_fidelity_fixture",),
        "fidelity_summary": None,
        "guardian_restarted": False,
        "environment_lock_sha256": "e" * 64,
        "control_plane_token_expiry": TOKEN_EXPIRY,
        "g2_token_expiry": TOKEN_EXPIRY,
    }
    values = {name: getattr(manifest, name) for name in MANIFEST_FIELDS if hasattr(manifest, name)}
    values.update(
        {
            "started_at": WINDOW_START,
            "ended_at": WINDOW_END,
            "git_commit": "f" * 40,
            "model_alias": ALIAS,
            "model_provider_string": PINNED_MODEL,
            "shared_credential_exercised": is_g2,
            **extra,
        }
    )
    for name in (
        "freeze_tag",
        "instrument_digest",
        "answered_model",
        "fidelity_summary",
        "guardian_restarted",
        "environment_lock_sha256",
        "control_plane_token_expiry",
        "g2_token_expiry",
        "system_fingerprints",
    ):
        values.setdefault(name, extra[name])
    del injection
    seal_bundle(bundle_dir, RunManifest(**values), sealed_at=WINDOW_END)


def defect_bundles(root: Path) -> dict[str, Path]:
    """One synthetic bundle per v1 defect the fidelity registry is expected to flag.

    The map is keyed by the PLAN's defect id (V1, V2, ...), because the known-bad replay's claim is
    about defects and a fixture keyed by check id would make "one bundle per defect" and "one bundle
    per check" two different claims. Where one defect is visible in more than one check, the bundle
    breaks the check the plan's table names for it, and the ``test_fidelity_known_bad.py`` cases
    cover the rest.

    Every bundle is CI-SAFE: each is written from :func:`v2_bundle` with a deterministic overlay,
    none
    reads the v1 corpus, and none needs a cluster, a model or a network. That is P4's requirement --
    "CI carries minimal synthetic bundles, one per defect, so the proof does not need the v1 corpus"
    --
    and the real-corpus replay over ``runs/CAMP-20260914-campaign`` is the environment-gated half.
    """
    out: dict[str, Path] = {}

    def make(name: str, **kwargs: Any) -> None:
        path = root / name
        v2_bundle(path, **kwargs)
        out[name] = path

    make("GOOD-G0-FULL")
    make("V1-S2-FLAT", condition="S2-FLAT")
    make("V2-G3-UNQUOTED", condition="G3-UNQUOTED")
    make("V4-CVE", scenario_id="SCN-CVE-04")
    make("V7-G2", condition="G2-SHAREDCRED")
    make("V13-INDEX")
    make("V14-MIXED-INSTRUMENT")
    make("V15-BASELINE", baseline=True)
    make("V18-UNSIGNED")
    make("V19-RESTART")
    make("V20-NO-MODEL-ECHO")
    make("V25-PAYLOAD-ROTATION")
    make("V28-NO-API-AUDIT")
    return out


def degrade(bundle_dir: Path, defect: str) -> None:
    """Apply one defect to an already-written v2 bundle, then re-seal it.

    Kept separate from :func:`v2_bundle` so that the bundle is SEEDED correctly and only the named
    property is broken. A fixture built by starting from a broken generator proves the generator is
    broken; this proves the CHECK is.
    """

    if defect == "V1":
        # The self-mint frame is never refreshed: a granted mint is followed by an action whose
        # runtime task frame still carries capability_scope null, which is nodes.py's v1 behaviour.
        messages = _read_jsonl(bundle_dir / "messages.jsonl")
        for record in messages:
            record["tool_call"] = {"name": "issue_capability_token", "arguments": {}}
            record["context"] = "synthetic\n" + _runtime_task(
                str(record.get("phase")), None, _environment_facts("S2-FLAT")
            )
        messages.append(
            {
                "index": len(messages),
                "phase": _PHASES[1],
                "role_id": "supervisor",
                "context": "synthetic\n"
                + _runtime_task(_PHASES[1], None, _environment_facts("S2-FLAT")),
                "system": "synthetic",
                "tool_call": {"name": "guardian_action", "arguments": {"verb": "get"}},
            }
        )
        _write_jsonl(bundle_dir / "messages.jsonl", messages)
        _reseal(bundle_dir)
    elif defect == "V2":
        # The carryover: the aggregator was scaled up with the PREVIOUS run's quoting setting, so
        # the
        # G3 arm's excerpts are quoted. F-MN-01 catches it in the direction the arm forbids.
        events = _read_jsonl(bundle_dir / "monitor_events.jsonl")
        for event in events:
            event["evidence_excerpts"] = [
                __import__("monitor.aggregator.quoting", fromlist=["quote"]).quote("carryover")
            ]
        _write_jsonl(bundle_dir / "monitor_events.jsonl", events)
        _reseal(bundle_dir)
    elif defect == "V4":
        # No Trivy event for a CVE scenario: the v1 applier had no scan step.
        events = [
            event
            for event in _read_jsonl(bundle_dir / "monitor_events.jsonl")
            if event.get("source") != "trivy"
        ]
        _write_jsonl(bundle_dir / "monitor_events.jsonl", events)
        _reseal(bundle_dir)
    elif defect == "V7":
        # G2 was inert: the field is the condition name and the API audit holds no request by the G2
        # principal, which is exactly what a bundle whose TokenRequest file was read by nothing
        # holds.
        records = [
            record
            for record in _read_jsonl(bundle_dir / "k8s_api_audit.jsonl")
            if record.get("annotations", {}).get("window-sentinel") is not None
        ]
        _write_jsonl(bundle_dir / "k8s_api_audit.jsonl", records)
        _reseal(bundle_dir)
    elif defect == "V13":
        # A ModelUnavailable path that appended a bare error dict with no index -- the v1 shape that
        # made 40 attempts unsealable.
        messages = _read_jsonl(bundle_dir / "messages.jsonl")
        messages.append({"error": "model unavailable: provider unreachable"})
        _write_jsonl(bundle_dir / "messages.jsonl", messages)
        _reseal(bundle_dir)
    elif defect == "V18":
        # The audit chain is plain SHA-256: no signature field on any record (ADR-130). The check's
        # anchor half is what a corpus-wide assertion reads, so this bundle is paired with the
        # campaign-level assertion in the test rather than relying on the key being present.
        for record in _audit_records(bundle_dir):
            record.pop("signature", None)
        _write_jsonl(bundle_dir / "guardian_audit.jsonl", _audit_records(bundle_dir))
        _reseal(bundle_dir)
    elif defect == "V19":
        # A Guardian restart inside the window: the cumulative counter rises between two ticks.
        rows = (bundle_dir / "resources.csv").read_text(encoding="utf-8").splitlines()
        header, body = rows[0], rows[1:]
        bumped = []
        for line in body:
            cells = line.split(",")
            cells[-1] = "1"
            bumped.append(",".join(cells))
        (bundle_dir / "resources.csv").write_text(
            "\n".join([header, *bumped]) + "\n", encoding="utf-8"
        )
        _rename_workload(bundle_dir, "guardian")
        _reseal(bundle_dir)
    elif defect == "V20":
        # The alias string only: no response_model, no hidden_params_model, no system_fingerprint.
        tokens = json.loads((bundle_dir / "tokens.json").read_text(encoding="utf-8"))
        for entry in tokens:
            entry.pop("response_model", None)
            entry.pop("hidden_params_model", None)
            entry.pop("system_fingerprint", None)
            entry["model"] = ALIAS
        _write_json(bundle_dir / "tokens.json", tokens)
        _reseal(bundle_dir)
    elif defect == "V25":
        # One payload drawn for a pool of six, and no marker anywhere: the coverage property the
        # balanced rotation (WS-2) restores.
        messages = _read_jsonl(bundle_dir / "messages.jsonl")
        for record in messages:
            record["context"] = "synthetic\n" + _runtime_task(
                str(record.get("phase")),
                {"verb": "get", "resource": "pods"},
                _environment_facts("G0-FULL"),
            )
        _write_jsonl(bundle_dir / "messages.jsonl", messages)
        _reseal(bundle_dir)
    elif defect == "V28":
        # The v1 audit policy ended in a catch-all `level: None`, so no workload mutation is logged.
        _write_jsonl(bundle_dir / "k8s_api_audit.jsonl", [])
        _reseal(bundle_dir)
    else:  # pragma: no cover - the caller names a defect from the map above
        raise AssertionError(f"unknown defect {defect!r}")


def _rename_workload(bundle_dir: Path, workload: str) -> None:
    """Rewrite ``resources.csv``'s workload column, so a restart is attributable to a workload."""
    lines = (bundle_dir / "resources.csv").read_text(encoding="utf-8").splitlines()
    header = lines[0].split(",")
    column = header.index("workload")
    rewritten = [lines[0]]
    for line in lines[1:]:
        cells = line.split(",")
        cells[column] = workload
        rewritten.append(",".join(cells))
    (bundle_dir / "resources.csv").write_text("\n".join(rewritten) + "\n", encoding="utf-8")


def _reseal(bundle_dir: Path) -> None:
    """Re-seal a degraded bundle with the same manifest it sealed with.

    Reads the manifest back rather than rebuilding it, so a degradation that must not change any
    manifest field demonstrably does not -- and so the seal's content hashes cover the degraded file
    exactly as they covered the sound one.
    """
    from runner.bundle import seal_bundle
    from runner.manifest import from_dict as manifest_from_dict

    manifest = manifest_from_dict(
        json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    )
    seal_bundle(bundle_dir, manifest, sealed_at=WINDOW_END)


def make_good(root: Path, name: str = "GOOD-G0-FULL", **kwargs: Any) -> Path:
    """One sound v2 bundle, for the checks that must pass on it."""
    return v2_bundle(root / name, **kwargs)


__all__ = (
    "ALIAS",
    "ANSWERED_MODEL",
    "G2_TOKEN_PATH",
    "TOKEN_EXPIRY",
    "WINDOW_END",
    "WINDOW_START",
    "degrade",
    "defect_bundles",
    "make_good",
    "planned_run",
    "v2_bundle",
)
