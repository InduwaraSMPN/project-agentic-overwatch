"""INJ-B end to end, offline: planned payload -> delivered argv -> Falco record -> bundle stream.

ADR-105 found that no INJ-B payload reached ``monitor_events.jsonl`` in any sealed campaign run,
although every delivery was logged ``applied``. Each stage had tests; nothing tested the chain. This
module is that test (ADR-119). It drives the real pieces a live run uses, in the order a live run
uses them, and substitutes only the two things that need a cluster:

1. The planner draws the cell's payload, and ``KubectlClusterAdapter`` delivers it. The fake runners
   record the argv the adapter would hand ``kubectl debug -it``; nothing is executed.
2. The Falco record is the one "Terminal shell in container" emits for that argv. Its shape is the
   JSON a live Falco printed on 2026-09-24 for a debug shell on the campaign cluster, and its
   ``proc.cmdline`` is built from the recorded argv the way Falco builds it: the process name, then
   every later argument, joined by single spaces.
3. The record is POSTed to ``monitor.http_service.AggregatorApplication``, the live aggregator's
   own request handler, once with quoting on (G0-FULL) and once with it off (G3-UNQUOTED), exactly
   as the runner's ``MONITOR_QUOTING_ENABLED`` setting selects. ``runner.live_evidence`` then
   collates the per-request tree into the bundle's ``monitor_events.jsonl``, as
   ``runner/live_run.py`` does.

What stays unproven offline is that Falco sees every such shell. It did not on 2026-09-24: 5 of 7
probe shells were recorded. ADR-119 records that loss and what a run does about it.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from monitor.aggregator.quoting import QUOTE_OPEN, quote, unquote
from monitor.http_service import AggregatorApplication, ServiceConfig
from scenarios.attackers import content
from scenarios.attackers.apply import KubectlClusterAdapter
from scenarios.attackers.plan import load_manifest, plan_cell, resolve_payload_text

from runner.live_evidence import collate_monitor_events

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES = REPO_ROOT / "monitor" / "rules" / "overwatch-rules.yaml"
SCENARIOS = tuple(
    sorted(path.stem for path in (REPO_ROOT / "scenarios" / "manifests").glob("SCN-*.yaml"))
)
# docs/07-glossary-and-ids.md, section Seeds: the pre-registered set, referenced not restated.
SEEDS = (101, 102, 103, 104, 105)
RULE = "Terminal shell in container"
POD_NAMES = ("target-pod-c", "target-pod-a", "target-pod-b")


class _Cluster:
    """Answers the adapter's read-only guards and records every command, running none."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def __call__(
        self, argv: Sequence[str], input_text: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        del input_text
        command = tuple(argv)
        self.calls.append(command)
        if command[-2:] == ("config", "current-context"):
            return subprocess.CompletedProcess(command, 0, "kind-test\n", "")
        if "networkpolicies" in command:
            return subprocess.CompletedProcess(command, 0, "", "")
        if "jsonpath={.spec.replicas}" in command:
            return subprocess.CompletedProcess(command, 0, "3", "")
        if "get" in command and "pods" in command:
            return subprocess.CompletedProcess(command, 0, " ".join(POD_NAMES), "")
        return subprocess.CompletedProcess(command, 0, "", "")

    def pty(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return self(argv)


def _deliver(tmp_path: Path, run_id: str, event: dict[str, Any], payload: str) -> tuple[str, ...]:
    """Deliver through the real adapter; return the argv of the one debug call it made."""
    kubeconfig = tmp_path / "kubeconfig"
    kubeconfig.write_text("apiVersion: v1\n", encoding="utf-8")
    cluster = _Cluster()
    adapter = KubectlClusterAdapter(
        kubeconfig=kubeconfig,
        context="kind-test",
        runner=cluster,
        pty_runner=cluster.pty,
        cleanup_wait_seconds=0,
        cleanup_sleeper=lambda _: None,
    )
    adapter.begin(run_id)
    adapter.apply_event(event, payload)
    (debug,) = [call for call in cluster.calls if "debug" in call]
    assert "-it" in debug, "the terminal-shell rule fires only on a shell with a terminal"
    return debug


def _falco_record(debug: tuple[str, ...], namespace: str) -> dict[str, Any]:
    """The JSON Falco prints for the debug shell ``debug`` starts, as observed live."""
    command = debug[debug.index("--") + 1 :]
    cmdline = " ".join(command)
    pod = debug[debug.index("debug") + 2]
    return {
        "hostname": "kind-worker",
        "output": (
            "01:29:31.241381165: Warning A shell was spawned in a container with an attached "
            "terminal (evt_type=execve user=<NA> user_uid=1000 proc_exepath=/bin/busybox "
            f"proc_cmdline={cmdline}) container_id=9442b899c208 container_name=debugger-kvkpg "
            "container_image_repository=docker.io/library/import-2026-09-13 "
            f"container_image_tag=local k8s_pod_name={pod} k8s_ns_name={namespace}"
        ),
        "output_fields": {
            "container.id": "9442b899c208",
            "container.image.repository": "docker.io/library/import-2026-09-13",
            "container.image.tag": "local",
            "container.name": "debugger-kvkpg",
            "evt.time": 1790213371241381165,
            "evt.type": "execve",
            "k8s.ns.name": namespace,
            "k8s.pod.name": pod,
            "proc.cmdline": cmdline,
            "proc.exepath": "/bin/busybox",
            "user.name": "<NA>",
            "user.uid": 1000,
        },
        "priority": "Warning",
        "rule": RULE,
        "source": "syscall",
        "tags": ["T1059", "container", "mitre_execution", "shell"],
        "time": "2026-09-24T01:29:31.241381165Z",
    }


def _bundle_stream(tmp_path: Path, record: dict[str, Any], *, quoting: bool) -> list[dict]:
    """POST ``record`` to the live aggregator handler, collate, and read the bundle stream back."""
    data_dir = tmp_path / ("g0" if quoting else "g3")
    app = AggregatorApplication(
        ServiceConfig.from_environ(
            {
                "MONITOR_DATA_DIR": str(data_dir),
                "MONITOR_QUOTING_ENABLED": "true" if quoting else "false",
            }
        )
    )
    body = json.dumps(record, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
    response = app.handle("POST", "/v1/falco", body)
    assert response.status.value == 200, response.body
    bundle = data_dir / "bundle" / "monitor_events.jsonl"
    assert collate_monitor_events(data_dir / "events", bundle) == 1
    return [json.loads(line) for line in bundle.read_text(encoding="utf-8").splitlines()]


def _check_arms(tmp_path: Path, debug: tuple[str, ...], namespace: str, payload: str) -> None:
    record = _falco_record(debug, namespace)
    cmdline = record["output_fields"]["proc.cmdline"]
    # NUL is the one character no argument can hold; each becomes the boundary Falco shows as a
    # space. Every other byte of the payload is in the recorded command line unchanged.
    assert payload.replace("\x00", " ") in cmdline

    (g0,) = _bundle_stream(tmp_path, record, quoting=True)
    (g3,) = _bundle_stream(tmp_path, record, quoting=False)
    excerpt = f"proc.cmdline={cmdline}"

    assert quote(excerpt) in g0["evidence_excerpts"], "G0-FULL must carry the payload quoted"
    assert all(text.startswith(QUOTE_OPEN) for text in g0["evidence_excerpts"])
    assert g0["summary"].startswith(QUOTE_OPEN)
    assert cmdline in unquote(g0["summary"])

    assert excerpt in g3["evidence_excerpts"], "G3-UNQUOTED must carry the payload unquoted"
    assert cmdline in g3["summary"]

    # The arms differ in escaping and in nothing else (monitor/tests/test_g3_isolation.py's
    # condition 3, here on the delivered payload rather than on a fixture).
    assert [unquote(text) for text in g0["evidence_excerpts"]] == g3["evidence_excerpts"]
    assert unquote(g0["summary"]) == g3["summary"]
    assert {key: g0[key] for key in g0 if key not in ("summary", "evidence_excerpts")} == {
        key: g3[key] for key in g3 if key not in ("summary", "evidence_excerpts")
    }


def test_the_declared_rule_renders_proc_cmdline() -> None:
    """The record this module models is one the deployed rules actually emit."""
    text = RULES.read_text(encoding="utf-8")
    block = text[text.index(f"- rule: {RULE}") :]
    block = block[: block.index("\n- rule:")]
    assert "proc_cmdline=%proc.cmdline" in block
    assert "proc.tty != 0" in block


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("scenario_id", SCENARIOS)
def test_planned_inj_b_payload_reaches_the_bundle_quoted_under_g0_and_unquoted_under_g3(
    tmp_path: Path, scenario_id: str, seed: int
) -> None:
    """Every INJ-B grid cell: its own payload is in the collated stream, per arm (ADR-119)."""
    (event,) = [e for e in plan_cell(scenario_id, "INJ-B", seed) if e["kind"] == "injection"]
    payload = resolve_payload_text(event)
    assert payload is not None
    assert "proc.cmdline" in event["detail"]["surface"]
    run_id = f"RUN-G0-FULL-{scenario_id}-INJ-B-{seed:03d}"
    debug = _deliver(tmp_path, run_id, event, payload)
    _check_arms(tmp_path, debug, load_manifest(scenario_id)["namespace"], payload)


def test_every_inj_b_pool_instance_survives_the_whole_chain(tmp_path: Path) -> None:
    """The planned cells need not draw every instance; this drives each one through anyway."""
    (event,) = [e for e in plan_cell(SCENARIOS[0], "INJ-B", SEEDS[0]) if e["kind"] == "injection"]
    pool = content.load_pool(event["detail"]["content_pool"])
    assert pool.instances, "the INJ-B pool is empty"
    run_id = f"RUN-G0-FULL-{SCENARIOS[0]}-INJ-B-{SEEDS[0]:03d}"
    namespace = load_manifest(SCENARIOS[0])["namespace"]
    for index, instance in enumerate(pool.instances):
        workdir = tmp_path / str(index)
        workdir.mkdir()
        debug = _deliver(workdir, run_id, event, instance.text)
        _check_arms(workdir, debug, namespace, instance.text)
