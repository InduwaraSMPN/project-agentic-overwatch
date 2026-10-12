"""Live framework-on composition tests using only injected in-process doubles."""

from __future__ import annotations

import base64
import contextlib
import io
import json
import threading
import urllib.error
from datetime import UTC, datetime
from pathlib import Path

import pytest
from agents.scripts import (
    REPLICAS_PARAM,
    SCALE_RESOURCE,
    SCALE_TO_ZERO_REPLICAS,
    SCALE_VERB,
)
from agents.tools.registry import CLUSTER_API_TOOL
from infra.locust.driver import LocustDriver
from scenarios.attackers.apply import ApplicationResult, ClusterAdapter

from runner.campaign import PlannedRun
from runner.conditions import flags_for
from runner.live_baseline import MeasurementWindow
from runner.live_evidence import GUARDIAN_AUDIT_ROOT
from runner.live_run import (
    _GUARDIAN_PHASE_PATH,
    _PHASE_DECLARATION_SCHEMA_VERSION,
    DEFAULT_MONITOR_EVIDENCE_DRAIN_SECONDS,
    MONITOR_EVIDENCE_DRAIN_SECONDS_ENV,
    P1A_EXTENSION_PHASE,
    LiveRunDependencies,
    LiveRunError,
    _audit_export,
    _cluster_api_transport_for,
    _condition_actions,
    _confirm_monitor_config,
    _control_plane_caller_auth,
    _control_plane_identity,
    _control_plane_session,
    _declare_phase_for,
    _GuardianAuditSource,
    _jwt_expiry,
    _monitor_export,
    _p1a_extension_for,
    _run_token_file,
    execute_live_run,
    monitor_drain_seconds,
)
from runner.run import RunError, run_planned
from runner.synthetic import synthetic_manifest

CAMPAIGN = "CAMP-20260101-live"


class FakeCluster(ClusterAdapter):
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls
        self.active = False

    def begin(self, run_id: str) -> None:
        self.calls.append(f"begin:{run_id}")
        self.active = True

    def prepare(self, events, manifest, run_id: str) -> None:
        del events, manifest, run_id
        self.calls.append("prepare")

    def apply_event(self, event, payload_text):
        del event, payload_text
        self.calls.append("event")
        return "applied"

    def teardown(self, manifest, run_id: str) -> None:
        del manifest, run_id
        self.calls.append("teardown")
        self.active = False


class FakeLocust(LocustDriver):
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def drive(self, load_profile_id, out_path, measurement):
        self.calls.append(f"locust-start:{load_profile_id}")
        measurement()
        out_path.write_text(
            "Type,Name,Request Count,Failure Count,50%,95%\n,Aggregated,1,0,1,1\n",
            encoding="utf-8",
        )
        self.calls.append("locust-stop")
        return 1


def _planned(condition: str = "G3-UNQUOTED") -> PlannedRun:
    return PlannedRun(
        run_id=f"RUN-{condition}-SCN-SIM-01-INJ-NONE-101",
        condition=condition,
        scenario_id="SCN-SIM-01",
        injection_condition="INJ-NONE",
        seed=101,
        is_baseline=False,
        baseline_run_id="BASE-LOAD-STEADY-101" if condition == "G0-FULL" else None,
        load_profile_id="LOAD-STEADY",
    )


def _writer(name: str, calls: list[str], barrier: threading.Barrier):
    def write(path: Path, window: MeasurementWindow) -> int:
        assert window.samples == 1
        calls.append(f"{name}-start")
        barrier.wait()
        path.write_text("header\nrow\n", encoding="utf-8")
        calls.append(f"{name}-end")
        return 1

    return write


def test_live_composition_overlaps_instruments_and_responds_before_teardown(tmp_path: Path) -> None:
    calls: list[str] = []
    cluster = FakeCluster(calls)
    barrier = threading.Barrier(3, timeout=1)

    def agents(**kwargs) -> None:
        del kwargs
        assert cluster.active
        calls.append("agents")
        (tmp_path / "messages.jsonl").write_text('{"message":"real"}\n', encoding="utf-8")
        (tmp_path / "tokens.json").write_text('[{"model":"provider/model"}]\n', encoding="utf-8")
        (tmp_path / "spans.otel.json").write_text('{"spans":[{}]}\n', encoding="utf-8")

    def monitor(bundle: Path, planned: PlannedRun) -> None:
        del planned
        assert cluster.active
        calls.append("monitor")
        (bundle / "monitor_events.jsonl").write_text('{"event":"real"}\n', encoding="utf-8")

    def audit(bundle: Path, planned: PlannedRun) -> None:
        del planned
        assert cluster.active
        calls.append("audit")
        (bundle / "guardian_audit.jsonl").write_text('{"record":"real"}\n', encoding="utf-8")

    def assertions(bundle: Path, planned: PlannedRun) -> None:
        del planned
        assert cluster.active
        calls.append("assertions")
        (bundle / "assertions.json").write_text("{}\n", encoding="utf-8")

    def condition(flags, planned) -> None:
        calls.append(
            f"condition:{planned.condition}:{flags.guardian_mode}:{flags.aggregator_quoting}:"
            f"{flags.netpol_overlay}"
        )

    def scenario(events, run_id, *, adapter, before_teardown):
        del events
        adapter.begin(run_id)
        barrier.wait()
        records = ({"event_id": "one", "applied": {"outcome": "applied"}},)
        try:
            before_teardown(records)
        finally:
            adapter.teardown({}, run_id)
        return ApplicationResult(records, None)

    deps = LiveRunDependencies(
        cluster=cluster,
        apply_condition=condition,
        reset_condition=lambda flags, planned: calls.append("reset"),
        drive_agents=agents,
        export_monitor=monitor,
        export_audit=audit,
        evaluate_assertions=assertions,
        probe=_writer("probe", calls, barrier),
        resources=_writer("resources", calls, barrier),
        locust=FakeLocust(calls),
        scenario_driver=scenario,
    )

    count = execute_live_run(
        tmp_path,
        _planned(),
        dependencies=deps,
        guardian_url="http://guardian.test",
        window=MeasurementWindow(samples=1),
    )

    assert count == 4
    assert calls.index("agents") < calls.index("teardown")
    assert calls[0].startswith("condition:G3-UNQUOTED:G0-FULL:False:default-deny")
    assert calls[-1] == "reset"
    assert (tmp_path / "injection.log.jsonl").is_file()


def _metrics_after_live_run(tmp_path: Path, chain: list[dict[str, object]]) -> object:
    """Drive one live composition whose audit export writes ``chain``; return its metrics.json."""
    calls: list[str] = []
    cluster = FakeCluster(calls)
    barrier = threading.Barrier(3, timeout=1)

    def audit(bundle: Path, planned: PlannedRun) -> None:
        del planned
        (bundle / "guardian_audit.jsonl").write_text(
            "".join(json.dumps(record) + "\n" for record in chain), encoding="utf-8"
        )

    def scenario(events, run_id, *, adapter, before_teardown):
        del events
        adapter.begin(run_id)
        barrier.wait()
        records = ({"event_id": "one", "applied": {"outcome": "applied"}},)
        try:
            before_teardown(records)
        finally:
            adapter.teardown({}, run_id)
        return ApplicationResult(records, None)

    deps = LiveRunDependencies(
        cluster=cluster,
        apply_condition=lambda flags, planned: None,
        reset_condition=lambda flags, planned: None,
        drive_agents=lambda **kwargs: None,
        export_monitor=lambda bundle, planned: None,
        export_audit=audit,
        evaluate_assertions=lambda bundle, planned: None,
        probe=_writer("probe", calls, barrier),
        resources=_writer("resources", calls, barrier),
        locust=FakeLocust(calls),
        scenario_driver=scenario,
    )
    execute_live_run(
        tmp_path,
        _planned(),
        dependencies=deps,
        guardian_url="http://guardian.test",
        window=MeasurementWindow(samples=1),
    )
    return json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("chain", "blocked"),
    [
        pytest.param([{"record_type": "run-start", "seq": 0}], 0, id="zero-action"),
        pytest.param(
            [
                {"record_type": "run-start", "seq": 0, "enforcement": "blocked"},
                {"record_type": "decision", "seq": 1, "decision": "deny", "enforcement": "blocked"},
                {
                    "record_type": "decision",
                    "seq": 2,
                    "decision": "permit",
                    "enforcement": "executed",
                },
            ],
            1,
            id="genesis-then-decisions",
        ),
    ],
)
def test_requests_blocked_never_counts_the_guardian_run_start(
    tmp_path: Path, chain: list[dict[str, object]], blocked: int
) -> None:
    """metrics.json counts the requests the Guardian blocked, and its run-start genesis is not one.

    The second case gives the genesis an ``enforcement`` it never carries, so the exclusion is shown
    to be the ADR-058 discriminator rather than an accident of a missing field.
    """
    assert _metrics_after_live_run(tmp_path, chain) == {"requests_blocked": blocked}


def _record_commands(monkeypatch: pytest.MonkeyPatch) -> list[tuple[list[str], dict[str, str]]]:
    """Stand in for every command the condition applier runs, so nothing reaches a cluster."""
    commands: list[tuple[list[str], dict[str, str]]] = []

    def record(argv: list[str], *, environ: object = None) -> None:
        commands.append((list(argv), dict(environ or {})))  # type: ignore[call-overload]

    monkeypatch.setattr("runner.live_run._run_command", record)
    return commands


def _audit_source() -> _GuardianAuditSource:
    return _GuardianAuditSource(
        namespace="guardian",
        workload="deployment/guardian",
        container="guardian",
        kubeconfig=None,
        context=None,
    )


def test_each_attempt_deploys_its_guardian_on_a_chain_of_its_own(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR-058 completing ADR-054: two attempts at one canonical run id, two Guardian chains.

    Each application of the condition draws one attempt suffix, records the chain, and hands the
    deploy script exactly that path. The replay store is not the runner's to move.
    """
    commands = _record_commands(monkeypatch)
    chains: dict[str, str] = {}
    apply, _reset = _condition_actions(
        {"RUNNER_PRIVATE_DIR": str(tmp_path / "private")}, {}, chains, GUARDIAN_AUDIT_ROOT, {}
    )
    planned = _planned("G0-FULL")
    recorded = []
    for _attempt in ("first", "retry"):
        apply(flags_for("G0-FULL"), planned)
        recorded.append(chains[planned.run_id])
    deployed = [
        environ["GUARDIAN_AUDIT_LOG_PATH"]
        for argv, environ in commands
        if argv == ["sh", "scripts/guardian_deploy.sh"]
    ]
    assert deployed == recorded
    assert recorded[0] != recorded[1], "the retry reused the failed attempt's chain"
    for path in recorded:
        assert path.startswith(f"{GUARDIAN_AUDIT_ROOT}/{planned.run_id}-")
        assert path.endswith(".jsonl")
    assert all("GUARDIAN_REPLAY_STORE_PATH" not in environ for _, environ in commands)


def test_extraction_reads_exactly_the_chain_the_attempt_was_deployed_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The exporter reads the recorded chain, and nothing it could derive from the run id."""
    planned = _planned("G0-FULL")
    chain = f"{GUARDIAN_AUDIT_ROOT}/{planned.run_id}-attempt.jsonl"
    seen: dict[str, object] = {}

    def extract(destination: Path, **kwargs: object) -> int:
        seen.update(kwargs)
        destination.write_text('{"record":"extracted"}\n', encoding="utf-8")
        return 1

    monkeypatch.setattr("runner.live_run.extract_guardian_audit", extract)
    source = tmp_path / "staging" / "guardian_audit.jsonl"
    source.parent.mkdir()
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    _audit_export(source, _audit_source(), {planned.run_id: chain})(bundle, planned)
    assert seen["remote_path"] == chain
    copied = (bundle / "guardian_audit.jsonl").read_text(encoding="utf-8")
    assert copied == '{"record":"extracted"}\n'


def test_extraction_refuses_an_attempt_whose_chain_was_never_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail closed: with no recorded chain there is no path to read, and none is guessed."""
    monkeypatch.setattr(
        "runner.live_run.extract_guardian_audit",
        lambda *args, **kwargs: pytest.fail("extraction ran without a recorded chain"),
    )
    with pytest.raises(LiveRunError, match="no Guardian audit chain was recorded"):
        _audit_export(tmp_path / "guardian_audit.jsonl", _audit_source(), {})(
            tmp_path, _planned("G0-FULL")
        )


def test_run_planned_uses_live_producers_and_real_provenance_builder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    planned = _planned("G1-LOGONLY")
    seen: dict[str, object] = {}
    # ADR-087 (Lease stream) nested cluster_lease(run_id) inside runner.run's own file lock, and its
    # default path issues a real `kubectl get/create lease` against whatever context is ambient.
    # This test drives the live branch through a monkeypatched execute_live_run and never touches a
    # cluster anywhere else, so the lease itself is stubbed out the same way -- a no-op context
    # manager -- rather than left to reach a real (and here, unrelated) cluster.
    monkeypatch.setattr("runner.run.cluster_lease", lambda run_id: contextlib.nullcontext())

    def execute(bundle, attempt, **kwargs):
        seen["dependencies"] = kwargs["dependencies"]
        seen["guardian_url"] = kwargs["guardian_url"]
        for name, content in {
            "messages.jsonl": '{"message":"real"}\n',
            "tokens.json": '[{"model":"provider/model"}]\n',
            "spans.otel.json": '{"spans":[{}]}\n',
            "monitor_events.jsonl": '{"event":"real"}\n',
            "guardian_audit.jsonl": '{"record":"real"}\n',
            "injection.log.jsonl": "one\ntwo\nthree\nfour\n",
            "assertions.json": "{}\n",
            "probes.csv": "header\nrow\n",
            "resources.csv": "header\nrow\n",
            "locust_stats.csv": "header\nrow\n",
        }.items():
            (bundle / name).write_text(content, encoding="utf-8")
        return 4

    monkeypatch.setattr("runner.run.execute_live_run", execute)
    monkeypatch.setattr(
        "runner.run.seal_bundle",
        lambda bundle, manifest, **kwargs: seen.update(manifest=manifest, seal=kwargs),
    )
    dependency = object()
    timestamps = iter(("start", "end"))

    def manifest_builder(run, campaign_id, **kwargs):
        seen["provenance"] = kwargs
        return synthetic_manifest(run, campaign_id, rerun_of=kwargs["rerun_of"])

    outcome = run_planned(
        planned,
        campaign_id=CAMPAIGN,
        out_root=tmp_path,
        skip_preflight=True,
        window=MeasurementWindow(samples=1),
        live_dependencies=dependency,  # type: ignore[arg-type]
        guardian_url="http://guardian.test",
        manifest_builder=manifest_builder,
        now=lambda: next(timestamps),
    )

    assert outcome.sealed
    assert seen["dependencies"] is dependency
    assert seen["guardian_url"] == "http://guardian.test"
    # ``bundle_dir`` is the LIVE path's fifth provenance argument, and it is load-bearing: it is
    # what lets the builder derive ``shared_credential_exercised`` from the API-audit slice this run
    # collated (ADR-131, defect V7) instead of recording a constant ``False`` for every arm.
    assert seen["provenance"] == {
        "rerun_of": None,
        "started_at": "start",
        "ended_at": "end",
        "bundle_dir": tmp_path / CAMPAIGN / planned.run_id,
    }
    # The probe flag reaches the seal on every path, so the profile is chosen by the flag and never
    # by which caller happened to seal (runner/bundle.py; M10 plan section 6, WS-5).
    assert seen["seal"] == {"instrument_only": False, "publish_audit_anchor": True}


def test_live_run_fails_clearly_when_runtime_adapters_are_unavailable(tmp_path: Path) -> None:
    with pytest.raises(RunError, match="live run adapters unavailable"):
        run_planned(
            _planned(),
            campaign_id=CAMPAIGN,
            out_root=tmp_path,
            skip_preflight=True,
            window=MeasurementWindow(samples=1),
        )


def test_monitor_export_drains_before_it_scales_the_aggregator_down(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR-063 part B: the drain settle runs after injection and BEFORE the Monitor is quiesced.

    The scenario driver applies the injection before it calls the monitor export (``apply_plan``
    runs ``before_teardown`` only after the last event), so a settle at the top of the export
    closure necessarily lands after injection. This pins the other half: the settle precedes the
    scale-to-0 that detaches the event tree, so the just-appended run-period records have time to
    reach the tree this window collates rather than the next window's -- the SCN-SIM-02 0-byte
    defect. The kubectl commands, the window close and the collation are all stubbed; only their
    order relative to the injected sleep is under test.
    """
    order: list[str] = []

    def fake_run(argv: list[str], *, environ: object = None) -> None:
        del environ
        if "--replicas=0" in argv:
            order.append("scale-down")
        elif "--replicas=1" in argv:
            order.append("scale-up")
        else:
            order.append("cmd")

    def fake_close(events_root: Path, run_id: str) -> Path:
        del run_id
        order.append("close-window")
        return events_root

    def fake_collate(
        closed_root: Path, source: Path, *, started_at: object, required_epoch: object = None
    ) -> int:
        del closed_root, started_at, required_epoch
        order.append("collate")
        source.write_text('{"event_id":"real"}\n', encoding="utf-8")
        source.with_name("monitor_timings.jsonl").write_text(
            '{"emit_ts":"2026-01-01T00:00:00Z","event_id":"real"}\n', encoding="utf-8"
        )
        return 1

    monkeypatch.setattr("runner.live_run._run_command", fake_run)
    monkeypatch.setattr("runner.live_run.close_monitor_window", fake_close)
    monkeypatch.setattr("runner.live_run.collate_monitor_events", fake_collate)

    def fake_sleep(seconds: float) -> None:
        order.append(f"drain:{seconds}")

    planned = _planned()
    events_root = tmp_path / "events"
    events_root.mkdir()
    source = tmp_path / "monitor_events.jsonl"
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    export = _monitor_export(
        source,
        events_root,
        {planned.run_id: datetime.now(UTC)},
        drain_seconds=12.5,
        sleep=fake_sleep,
    )
    export(bundle, planned)

    assert order[0] == "drain:12.5", "the drain must run before anything the export does"
    assert order.index("drain:12.5") < order.index("scale-down")
    assert order.index("scale-down") < order.index("close-window") < order.index("collate")
    assert (bundle / "monitor_events.jsonl").read_text(encoding="utf-8") == (
        '{"event_id":"real"}\n'
    )
    assert (bundle / "monitor_timings.jsonl").is_file()


def test_monitor_drain_seconds_defaults_and_is_overridable_and_fails_closed() -> None:
    """The drain is an operational constant with an env override; junk fails closed (ADR-063)."""
    assert monitor_drain_seconds({}) == DEFAULT_MONITOR_EVIDENCE_DRAIN_SECONDS
    assert monitor_drain_seconds({MONITOR_EVIDENCE_DRAIN_SECONDS_ENV: "  "}) == (
        DEFAULT_MONITOR_EVIDENCE_DRAIN_SECONDS
    )
    assert monitor_drain_seconds({MONITOR_EVIDENCE_DRAIN_SECONDS_ENV: "3"}) == 3.0
    assert monitor_drain_seconds({MONITOR_EVIDENCE_DRAIN_SECONDS_ENV: "0"}) == 0.0
    with pytest.raises(LiveRunError, match="number of seconds"):
        monitor_drain_seconds({MONITOR_EVIDENCE_DRAIN_SECONDS_ENV: "soon"})
    with pytest.raises(LiveRunError, match="must not be negative"):
        monitor_drain_seconds({MONITOR_EVIDENCE_DRAIN_SECONDS_ENV: "-1"})


# --- GAP 3: ADR-124 quoting/epoch set before the aggregator is recreated -------------------------


def _apply_with_monitor_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, condition: str = "G3-UNQUOTED"
) -> tuple[list[tuple[str, object]], PlannedRun]:
    """Drive ``apply`` with a Monitor root, recording every command in order (no cluster touched).

    Every kubectl the applier runs is intercepted and labelled, the epoch/quoting confirm is
    stubbed to report THIS run (so the real ``_confirm_monitor_config`` parses and accepts it), and
    the window open is recorded. The returned list is the exact order the applier issued them in.
    """
    order: list[tuple[str, object]] = []

    def fake_run(argv: list[str], *, environ: object = None) -> None:
        del environ
        if "set" in argv and "env" in argv:
            order.append(("set-env", tuple(argv)))
        elif "--replicas=0" in argv:
            order.append(("scale-down", tuple(argv)))
        elif "--replicas=1" in argv:
            order.append(("scale-up", tuple(argv)))
        elif "rollout" in argv and "deployment/evidence-aggregator" in argv:
            order.append(("rollout-aggregator", tuple(argv)))
        elif "rollout" in argv:
            order.append(("rollout-other", tuple(argv)))
        elif "wait" in argv:
            order.append(("wait", tuple(argv)))
        elif argv[:2] == ["sh", "scripts/guardian_deploy.sh"]:
            order.append(("guardian-deploy", tuple(argv)))
        else:
            order.append(("cmd", tuple(argv)))

    planned = _planned(condition)

    def fake_stdout(argv: list[str], *, environ: object = None) -> str:
        del environ
        order.append(("epoch-confirm", tuple(argv)))
        return json.dumps(
            {"quoting": flags_for(condition).aggregator_quoting, "run_epoch": planned.run_id}
        )

    def fake_begin(events_root: Path, run_id: str) -> Path:
        order.append(("window-open", run_id))
        return events_root

    monkeypatch.setattr("runner.live_run._run_command", fake_run)
    monkeypatch.setattr("runner.live_run._run_command_stdout", fake_stdout)
    monkeypatch.setattr("runner.live_run.begin_monitor_window", fake_begin)

    events_root = tmp_path / "events"
    events_root.mkdir()
    apply, _reset = _condition_actions(
        {
            "MONITOR_EVENTS_ROOT": str(events_root),
            "RUNNER_PRIVATE_DIR": str(tmp_path / "private"),
        },
        {},
        {},
        GUARDIAN_AUDIT_ROOT,
        {},
    )
    apply(flags_for(condition), planned)
    return order, planned


def test_quoting_and_epoch_set_before_the_aggregator_is_recreated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR-124: both flags go on while scaled to zero, one rollout, confirm, then the window opens.

    The V2 defect was the opposite order -- the aggregator was scaled back up on the previous run's
    environment, the window opened, and the quoting was patched with a SECOND rollout. This
    pins the corrected order and, with it, the deletion of that second `set env` + rollout.
    """
    order, planned = _apply_with_monitor_root(tmp_path, monkeypatch, "G3-UNQUOTED")
    labels = [name for name, _ in order]

    # Exactly one `set env`, carrying BOTH the quoting mode and run epoch -- the second is gone.
    set_envs = [detail for name, detail in order if name == "set-env"]
    assert len(set_envs) == 1
    joined = " ".join(set_envs[0])  # type: ignore[arg-type]
    assert "MONITOR_QUOTING_ENABLED=false" in joined
    assert f"MONITOR_RUN_EPOCH={planned.run_id}" in joined

    # A single scale-up and a single aggregator rollout: the aggregator is recreated exactly once.
    assert labels.count("scale-up") == 1
    assert labels.count("rollout-aggregator") == 1

    # The flags go on while the aggregator is at zero (after scale-down, before scale-up); then the
    # single rollout, the exec confirm, and only then the evidence window.
    assert labels.index("scale-down") < labels.index("set-env") < labels.index("scale-up")
    assert labels.index("scale-up") < labels.index("rollout-aggregator")
    assert (
        labels.index("rollout-aggregator")
        < labels.index("epoch-confirm")
        < labels.index("window-open")
    )


def test_window_opens_after_epoch_confirmed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR-124: the evidence window opens only after the one-shot exec confirms the pod's epoch."""
    order, planned = _apply_with_monitor_root(tmp_path, monkeypatch, "G3-UNQUOTED")
    labels = [name for name, _ in order]
    assert "epoch-confirm" in labels and "window-open" in labels
    assert labels.index("epoch-confirm") < labels.index("window-open")
    opened = [detail for name, detail in order if name == "window-open"]
    assert opened == [planned.run_id]


def test_confirm_monitor_config_rejects_a_pod_on_another_epoch_or_quoting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The confirm reads /readyz and refuses to open the window on the wrong epoch or quoting."""
    monkeypatch.setattr(
        "runner.live_run._run_command_stdout",
        lambda argv, *, environ=None: json.dumps({"quoting": False, "run_epoch": "RUN-OTHER-999"}),
    )
    with pytest.raises(LiveRunError, match="run epoch"):
        _confirm_monitor_config("RUN-MINE-101", False)

    monkeypatch.setattr(
        "runner.live_run._run_command_stdout",
        lambda argv, *, environ=None: json.dumps({"quoting": True, "run_epoch": "RUN-MINE-101"}),
    )
    with pytest.raises(LiveRunError, match="quoting"):
        _confirm_monitor_config("RUN-MINE-101", False)

    # Matching epoch AND quoting is accepted with no raise.
    monkeypatch.setattr(
        "runner.live_run._run_command_stdout",
        lambda argv, *, environ=None: json.dumps({"quoting": False, "run_epoch": "RUN-MINE-101"}),
    )
    _confirm_monitor_config("RUN-MINE-101", False)


# --- GAP 6: D1-A / ADR-131 the G2 direct-path transport is wired only under G2 -------------------


def test_g2_sets_cluster_api_transport_and_other_arms_do_not(tmp_path: Path) -> None:
    """The runner builds the transport ONLY under G2-SHAREDCRED; every other arm gets None.

    v1's V7 was that nothing read the g2 token file, so ``cluster_api_request`` refused in every arm
    including G2 and C2 was inert. This asserts the wiring that connects it: a real transport
    and the credential LOCATION facts under G2, and ``(None, ())`` -- which the tool handler turns
    into its no-transport refusal -- everywhere else.
    """
    ca = tmp_path / "cluster-ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n", encoding="utf-8")
    source = {
        "RUNNER_PRIVATE_DIR": str(tmp_path / "private"),
        "KUBE_API_SERVER": "https://127.0.0.1:6443",
        "CLUSTER_CA_CERT": str(ca),
    }

    transport, environment = _cluster_api_transport_for(source, _planned("G2-SHAREDCRED"))
    assert transport is not None
    assert any(fact.startswith("KUBE_TOKEN_FILE=") for fact in environment)
    assert any(fact.startswith("KUBE_API_SERVER=") for fact in environment)
    # The permit the shim reads names THIS run's token path -- the path the applier writes and the
    # shim compares the model's argument against, so "use" of the credential is byte-for-byte the
    # runner's own file.
    permit = json.loads(
        (
            tmp_path / "private" / "RUN-G2-SHAREDCRED-SCN-SIM-01-INJ-NONE-101.g2-transport.json"
        ).read_text(encoding="utf-8")
    )
    assert permit["condition"] == "G2-SHAREDCRED"
    assert permit["token_path"].endswith("RUN-G2-SHAREDCRED-SCN-SIM-01-INJ-NONE-101.token")
    assert permit["api_server"] == "https://127.0.0.1:6443"
    assert permit["ca_cert"] == str(ca)

    for arm in ("G0-FULL", "G1-LOGONLY", "G3-UNQUOTED", "S2-FLAT", "S3-SINGLE"):
        transport, environment = _cluster_api_transport_for(source, _planned(arm))
        assert transport is None, arm
        assert environment == (), arm


def test_g2_transport_fails_closed_when_the_api_path_is_unconfigured(tmp_path: Path) -> None:
    """A G2 run with no API server or cluster CA raises rather than running silently inert (V7)."""
    source = {"RUNNER_PRIVATE_DIR": str(tmp_path / "private")}
    with pytest.raises(LiveRunError, match="KUBE_API_SERVER"):
        _cluster_api_transport_for(source, _planned("G2-SHAREDCRED"))


# --- M10 plan §6: the P1a per-arm extension is built ONLY for G0-FULL and G2-SHAREDCRED ----------


def test_p1a_extension_is_built_for_exactly_the_two_arms(tmp_path: Path) -> None:
    """Plan §6: G0-FULL gets a scale-to-zero and a refused direct path; G2 the transported one.

    The arm NAMES live in the runner, not in ``agents/`` (``.agents/rules/10``, ADR-023):
    ``agents/scripts.py`` carries only the shape of an extension, and this function -- which already
    knows the arm -- decides which arm gets which one. So the assertion is the whole mapping: the
    two arms that make an extra act get an extension, and the four plain arms get ``None``, which is
    the golden traversal with no direct-path call at all.

    The G0 direct-path request names NO credential location (``""``), because no transport is
    injected for G0 -- the handler returns its no-transport refusal before the field is read. G2's
    names the exact file the runner writes the bearer to and the shim compares against, from the one
    derivation both share (``_run_token_file``).
    """
    source = {"RUNNER_PRIVATE_DIR": str(tmp_path / "private")}

    g0 = _p1a_extension_for(_planned("G0-FULL"), "boutique", source)
    assert g0 is not None
    assert g0.phase == P1A_EXTENSION_PHASE
    assert g0.verbs == (SCALE_VERB,)
    assert g0.resources == (SCALE_RESOURCE,)
    assert g0.action is not None
    assert g0.action.arguments["verb"] == SCALE_VERB
    assert g0.action.arguments["params"] == {REPLICAS_PARAM: SCALE_TO_ZERO_REPLICAS}, (
        "the D4-A refusal (ADR-129) is keyed on a zero replica count"
    )
    assert len(g0.calls) == 1
    assert g0.calls[0].name == CLUSTER_API_TOOL.name
    assert g0.calls[0].arguments["bearer_token_file"] == "", (
        "G0 injects no transport, so its environment names no credential location; inventing one "
        "would be the runner supplying a fact the arm does not have"
    )

    g2 = _p1a_extension_for(_planned("G2-SHAREDCRED"), "boutique", source)
    assert g2 is not None
    assert g2.phase == P1A_EXTENSION_PHASE
    assert g2.verbs == () and g2.resources == ()
    assert g2.action is None, "G2's extra act is the direct path, not a scale"
    assert len(g2.calls) == 1
    assert g2.calls[0].name == CLUSTER_API_TOOL.name
    assert g2.calls[0].arguments["bearer_token_file"] == str(
        _run_token_file(source, _planned("G2-SHAREDCRED").run_id)
    )

    for arm in ("G1-LOGONLY", "G3-UNQUOTED", "S2-FLAT", "S3-SINGLE"):
        assert _p1a_extension_for(_planned(arm), "boutique", source) is None, arm


# --- GAP 2: --instrument-only probe mode skips the agent graph -----------------------------------


def test_instrument_only_skips_the_graph(tmp_path: Path) -> None:
    """A P0-live probe runs the scenario and the evidence path but NO agent graph (WS-5).

    The graph, the Guardian audit export and the assertions are the files the probe completeness
    profile forbids, so the mode skips all three while the Monitor evidence and the injection log
    still land and metrics.json is still written.
    """
    calls: list[str] = []
    cluster = FakeCluster(calls)
    barrier = threading.Barrier(3, timeout=1)

    def agents(**kwargs) -> None:
        del kwargs
        calls.append("agents")

    def monitor(bundle: Path, planned: PlannedRun) -> None:
        del planned
        calls.append("monitor")
        (bundle / "monitor_events.jsonl").write_text('{"event":"real"}\n', encoding="utf-8")

    def audit(bundle: Path, planned: PlannedRun) -> None:
        del bundle, planned
        calls.append("audit")

    def assertions(bundle: Path, planned: PlannedRun) -> None:
        del bundle, planned
        calls.append("assertions")

    def scenario(events, run_id, *, adapter, before_teardown):
        del events
        adapter.begin(run_id)
        barrier.wait()
        records = ({"event_id": "one", "applied": {"outcome": "applied"}},)
        try:
            before_teardown(records)
        finally:
            adapter.teardown({}, run_id)
        return ApplicationResult(records, None)

    deps = LiveRunDependencies(
        cluster=cluster,
        apply_condition=lambda flags, planned: None,
        reset_condition=lambda flags, planned: None,
        drive_agents=agents,
        export_monitor=monitor,
        export_audit=audit,
        evaluate_assertions=assertions,
        probe=_writer("probe", calls, barrier),
        resources=_writer("resources", calls, barrier),
        locust=FakeLocust(calls),
        open_api_audit=lambda planned: calls.append("api_audit_open"),
        export_api_audit=lambda bundle_dir, planned: calls.append("api_audit_close"),
        scenario_driver=scenario,
    )

    count = execute_live_run(
        tmp_path,
        _planned(),
        dependencies=deps,
        guardian_url="http://guardian.test",
        window=MeasurementWindow(samples=1),
        instrument_only=True,
    )

    assert count == 4
    assert "monitor" in calls  # the evidence path still runs
    assert "agents" not in calls  # the graph is skipped
    assert "audit" not in calls  # no Guardian chain to export
    assert "assertions" not in calls  # the probe profile forbids assertions.json
    # ADR-137: the API-audit window is opened and sliced in probe mode too, unlike the graph.
    assert "api_audit_open" in calls
    assert "api_audit_close" in calls
    assert (tmp_path / "injection.log.jsonl").is_file()
    metrics = json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8"))
    assert metrics == {"requests_blocked": 0}


# --- GAP 2b: the probe mode is reachable from `make run` / runner.run's CLI ----------------------


def test_run_planned_forwards_the_probe_flag_to_the_live_run_and_the_seal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``instrument_only`` is threaded to BOTH halves: the composition and the seal profile.

    The flag alone is not enough -- ``execute_live_run`` must skip the agent graph AND
    ``seal_bundle`` must select the probe completeness profile. A wiring that reached only one of
    them would either run a probe that still demanded the framework-on files, or seal a graph run
    under the probe profile. This is the boundary ``--instrument-only`` on ``runner.run``'s CLI and
    ``INSTRUMENT_ONLY=1`` on ``scripts/run.sh`` both feed.
    """
    seen: dict[str, object] = {}
    monkeypatch.setattr("runner.run.cluster_lease", lambda run_id: contextlib.nullcontext())

    def execute(bundle, attempt, **kwargs):
        seen["execute"] = kwargs
        return 1

    monkeypatch.setattr("runner.run.execute_live_run", execute)
    monkeypatch.setattr(
        "runner.run.seal_bundle",
        lambda bundle, manifest, **kwargs: seen.update(seal=kwargs),
    )

    outcome = run_planned(
        _planned("G3-UNQUOTED"),
        campaign_id=CAMPAIGN,
        out_root=tmp_path,
        skip_preflight=True,
        instrument_only=True,
        window=MeasurementWindow(samples=1),
        live_dependencies=object(),  # type: ignore[arg-type]
        guardian_url="http://guardian.test",
        manifest_builder=lambda run, campaign_id, **kwargs: synthetic_manifest(
            run, campaign_id, rerun_of=kwargs["rerun_of"]
        ),
        now=lambda: "t",
    )

    assert outcome.sealed
    assert seen["execute"]["instrument_only"] is True
    assert seen["seal"] == {"instrument_only": True, "publish_audit_anchor": True}


def test_instrument_only_is_refused_with_offline(tmp_path: Path) -> None:
    """A probe is a LIVE stage, so the synthetic path must refuse it rather than seal nothing.

    The offline path writes a framework-on bundle, which carries none of the probe profile's
    required evidence and all of the files it forbids; a probe sealed from it would be a probe that
    measured nothing.
    """
    with pytest.raises(RunError, match="cannot be combined with --offline"):
        run_planned(
            _planned("G3-UNQUOTED"),
            campaign_id=CAMPAIGN,
            out_root=tmp_path,
            offline=True,
            instrument_only=True,
        )


def test_run_cli_exposes_the_probe_flag_and_reports_its_illegal_combination(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--instrument-only`` is a CLI flag, and its one illegal combination is a reported refusal.

    ``runner/live_run.py`` carried the mode as a parameter from the start, but nothing on the
    command line could select it, so the P0-live probes had no way in. This is the regression guard
    for that wiring (M10 plan section 6, WS-5).
    """
    from runner.run import main

    code = main(
        [
            "--cond",
            "G3-UNQUOTED",
            "--scn",
            "SCN-SIM-01",
            "--inj",
            "INJ-NONE",
            "--seed",
            "101",
            "--campaign",
            CAMPAIGN,
            "--out-root",
            str(tmp_path),
            "--offline",
            "--instrument-only",
        ]
    )
    assert code == 1
    assert "--instrument-only" in capsys.readouterr().err


# --- SEAM 6 (ADR-128): the runner as the Guardian's control plane --------------------------------


def test_phase_path_and_schema_match_the_guardian() -> None:
    """The runner's copy of the control-plane route and body schema equals the Guardian's own.

    Both are defined in runner/live_run.py rather than imported from guardian/app/main.py so the
    runner declares a phase without the Guardian app's web dependencies; this test keeps the copy
    honest -- the moment guardian/app/main.py moves either value it fails and names both.
    """
    from guardian.app import main as guardian_main

    assert _GUARDIAN_PHASE_PATH == guardian_main.PHASE_PATH
    assert _PHASE_DECLARATION_SCHEMA_VERSION == guardian_main.PHASE_DECLARATION_SCHEMA_VERSION


def test_control_plane_identity_parses_the_subject_and_fails_closed() -> None:
    namespace, service_account, audience = _control_plane_identity(
        {
            "GUARDIAN_CONTROL_PLANE_SUBJECT": "system:serviceaccount:guardian:runner-control-plane",
            "GUARDIAN_CONTROL_PLANE_AUDIENCE": "guardian-control-plane",
        }
    )
    assert (namespace, service_account, audience) == (
        "guardian",
        "runner-control-plane",
        "guardian-control-plane",
    )

    with pytest.raises(LiveRunError, match="GUARDIAN_CONTROL_PLANE_AUDIENCE"):
        _control_plane_identity(
            {
                "GUARDIAN_CONTROL_PLANE_SUBJECT": (
                    "system:serviceaccount:guardian:runner-control-plane"
                )
            }
        )
    with pytest.raises(LiveRunError, match="ServiceAccount subject"):
        _control_plane_identity(
            {
                "GUARDIAN_CONTROL_PLANE_SUBJECT": "runner-control-plane",
                "GUARDIAN_CONTROL_PLANE_AUDIENCE": "guardian-control-plane",
            }
        )


def test_caller_auth_mints_caches_and_refreshes(monkeypatch: pytest.MonkeyPatch) -> None:
    """The bearer is minted once, reused from cache, and re-minted only after the refresh window.

    The value lives only in the closure -- the supplier returns an Authorization header and never
    the token -- and the mint is a ``kubectl create token`` for the audience the Guardian's
    TokenReview requires, so the identity the runner presents is the one the Guardian authenticates
    against.
    """
    minted: list[list[str]] = []
    tokens = iter(("token-A", "token-B"))

    def fake_stdout(argv: list[str], *, environ: object = None) -> str:
        minted.append(argv)
        return next(tokens) + "\n"

    clock = {"t": 0.0}
    monkeypatch.setattr("runner.live_run._run_command_stdout", fake_stdout)
    monkeypatch.setattr("runner.live_run.time.monotonic", lambda: clock["t"])

    supply = _control_plane_caller_auth(
        {
            "GUARDIAN_CONTROL_PLANE_SUBJECT": "system:serviceaccount:guardian:runner-control-plane",
            "GUARDIAN_CONTROL_PLANE_AUDIENCE": "guardian-control-plane",
        },
        {},
        bound_object="test-run-secret",
    )

    assert supply() == {"Authorization": "Bearer token-A"}
    assert supply() == {"Authorization": "Bearer token-A"}  # cached: no second mint
    assert len(minted) == 1
    argv = minted[0]
    assert argv[:6] == ["kubectl", "-n", "guardian", "create", "token", "runner-control-plane"]
    assert "--audience" in argv
    assert "guardian-control-plane" in argv
    assert "--bound-object-kind=Secret" in argv
    assert "--bound-object-name=test-run-secret" in argv

    clock["t"] = 10_000.0  # well past the refresh window
    assert supply() == {"Authorization": "Bearer token-B"}
    assert len(minted) == 2


def test_caller_auth_fails_closed_on_an_empty_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("runner.live_run._run_command_stdout", lambda argv, *, environ=None: "\n")
    supply = _control_plane_caller_auth(
        {
            "GUARDIAN_CONTROL_PLANE_SUBJECT": "system:serviceaccount:guardian:runner-control-plane",
            "GUARDIAN_CONTROL_PLANE_AUDIENCE": "guardian-control-plane",
        },
        {},
        bound_object="test-run-secret",
    )
    with pytest.raises(LiveRunError, match="returned no token"):
        supply()


def test_cached_bearer_restores_expiry_after_attempt_relay_is_cleared(monkeypatch) -> None:
    payload = base64.urlsafe_b64encode(json.dumps({"exp": 2_000_000_000}).encode()).decode()
    bearer = f"header.{payload}.signature"
    calls = []

    def mint(argv, *, environ=None):
        calls.append(argv)
        return bearer

    monkeypatch.setattr("runner.live_run._run_command_stdout", mint)
    expiries = {}
    supply = _control_plane_caller_auth(
        {
            "GUARDIAN_CONTROL_PLANE_SUBJECT": "system:serviceaccount:guardian:runner-control-plane",
            "GUARDIAN_CONTROL_PLANE_AUDIENCE": "guardian-control-plane",
        },
        expiries,
        bound_object="test-run-secret",
    )
    supply()
    expiry = expiries["control_plane_token_expiry"]
    expiries.clear()
    supply()
    assert expiries == {"control_plane_token_expiry": expiry}
    assert len(calls) == 1


@pytest.mark.parametrize("claims", [[], {"exp": True}, {"exp": "1"}, {"exp": 10**30}])
def test_jwt_expiry_does_not_fabricate_an_invalid_claim(claims) -> None:
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode()
    assert _jwt_expiry(f"header.{payload}.signature") is None


def test_declare_phase_posts_the_body_with_the_bearer(monkeypatch: pytest.MonkeyPatch) -> None:
    """declare_phase POSTs {run_id, phase, schema_version} to /v1/phase with the auth header."""
    captured: dict[str, object] = {}

    class _Response:
        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *exc: object) -> bool:
            return False

        def read(self) -> bytes:
            return b""

    def fake_urlopen(request: urllib.request.Request, timeout: object = None) -> _Response:
        captured["url"] = request.full_url
        captured["method"] = request.get_method()
        captured["body"] = request.data
        captured["headers"] = {k.lower(): v for k, v in request.header_items()}
        captured["timeout"] = timeout
        return _Response()

    monkeypatch.setattr("runner.live_run.urllib.request.urlopen", fake_urlopen)

    declare = _declare_phase_for(
        "http://guardian.test/",
        "RUN-X",
        lambda: {"Authorization": "Bearer token-A"},
    )
    declare("containment")

    assert captured["url"] == "http://guardian.test/v1/phase"
    assert captured["method"] == "POST"
    assert json.loads(captured["body"]) == {  # type: ignore[arg-type]
        "run_id": "RUN-X",
        "phase": "containment",
        "schema_version": _PHASE_DECLARATION_SCHEMA_VERSION,
    }
    headers = captured["headers"]
    assert isinstance(headers, dict)
    assert headers["authorization"] == "Bearer token-A"
    assert headers["content-type"] == "application/json"


def test_declare_phase_fails_closed_on_a_guardian_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: urllib.request.Request, timeout: object = None) -> object:
        raise urllib.error.HTTPError(
            request.full_url,
            401,
            "Unauthorized",
            None,
            io.BytesIO(b"no control-plane"),  # type: ignore[arg-type]
        )

    monkeypatch.setattr("runner.live_run.urllib.request.urlopen", fake_urlopen)
    declare = _declare_phase_for(
        "http://guardian.test", "RUN-X", lambda: {"Authorization": "Bearer x"}
    )
    with pytest.raises(LiveRunError, match="HTTP 401"):
        declare("detection-and-investigation")


def test_control_plane_session_revokes_its_bound_secret_when_graph_fails(monkeypatch):
    commands = _record_commands(monkeypatch)
    monkeypatch.setattr("runner.live_run._run_command_stdout", lambda *args, **kwargs: "token")
    source = {
        "GUARDIAN_CONTROL_PLANE_SUBJECT": "system:serviceaccount:guardian:runner-control-plane",
        "GUARDIAN_CONTROL_PLANE_AUDIENCE": "guardian-control-plane",
    }
    with pytest.raises(RuntimeError, match="graph failed"):
        with _control_plane_session(source, {}) as supply:
            assert supply() == {"Authorization": "Bearer token"}
            raise RuntimeError("graph failed")
    create, delete = [argv for argv, _ in commands]
    assert create[:6] == ["kubectl", "-n", "guardian", "create", "secret", "generic"]
    assert delete == [
        "kubectl",
        "-n",
        "guardian",
        "delete",
        "secret",
        create[-1],
        "--ignore-not-found",
    ]
