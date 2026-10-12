"""A per-run scan report reaches the run's collated Monitor stream; a bring-up one never does.

ADR-118 end to end, offline. The scan Job is the one ``scenarios/attackers/apply.py`` renders for a
CVE run; its uploader container runs ``monitor.trivy_uploader`` with the environment that Job sets,
against a real threaded aggregator (``monitor.http_service``) writing the same per-request fragment
tree the live runner collates. The only substitutions are the ones the cluster makes: the report is
the real live-capture scan retargeted at the admitted image and timestamped inside the window, and
the Service URL resolves to a loopback port.
"""

from __future__ import annotations

import json
import threading
import urllib.parse
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from monitor.http_service import AggregatorApplication, ServiceConfig, build_server
from scenarios.attackers.apply import KubectlClusterAdapter, render_trivy_scan_job
from scenarios.attackers.plan import load_manifest

from monitor import trivy_uploader
from runner.live_evidence import begin_monitor_window, close_monitor_window, collate_monitor_events

REPO_ROOT = Path(__file__).resolve().parents[2]
LIVE_REPORT = REPO_ROOT / "monitor" / "fixtures" / "trivy-live-capture" / "trivy.json"
SCENARIO_ID = "SCN-CVE-04"
RUN_ID = "RUN-G0-FULL-SCN-CVE-04-INJ-NONE-101"


@pytest.fixture
def aggregator(tmp_path: Path) -> Iterator[tuple[Path, int]]:
    data_dir = tmp_path / "monitor-data"
    app = AggregatorApplication(ServiceConfig.from_environ({"MONITOR_DATA_DIR": str(data_dir)}))
    server = build_server(app, ("127.0.0.1", 0))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield data_dir / "events", server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def _admitted_image() -> str:
    manifest = load_manifest(SCENARIO_ID)
    ref = next(p["ref"] for p in manifest["incident_primitives"] if p["mechanism"] == "cve")
    entry = KubectlClusterAdapter._load_cve_entry(ref, SCENARIO_ID)
    return f"{entry['repository']}@{entry['digest']}"


def _run_uploader(job: dict[str, Any], report: Path, port: int, monkeypatch: Any) -> None:
    """Run the Job's uploader container command with the environment the Job gives it."""
    [uploader] = job["spec"]["template"]["spec"]["containers"]
    assert uploader["command"] == ["python", "-m", "monitor.trivy_uploader"]
    env = {item["name"]: item["value"] for item in uploader["env"]}
    service = urllib.parse.urlsplit(env[trivy_uploader.TRIVY_URL_ENV])
    assert service.hostname == "evidence-aggregator.monitor.svc.cluster.local"
    monkeypatch.setenv(trivy_uploader.TRIVY_REPORT_ENV, str(report))
    monkeypatch.setenv(
        trivy_uploader.TRIVY_URL_ENV,
        service._replace(netloc=f"127.0.0.1:{port}").geturl(),
    )
    assert trivy_uploader.main() == 0


def _report(tmp_path: Path, name: str, *, artifact: str | None, created_at: str | None) -> Path:
    document = json.loads(LIVE_REPORT.read_text(encoding="utf-8"))
    if artifact is not None:
        document["ArtifactName"] = artifact
    if created_at is not None:
        document["CreatedAt"] = created_at
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_a_per_run_scan_report_survives_collation_and_a_bring_up_report_does_not(
    tmp_path: Path, aggregator: tuple[Path, int], monkeypatch: Any
) -> None:
    events_root, port = aggregator
    # The Job the cve mechanism renders for this run. Its uploader container is the same program,
    # with the same environment, as the bring-up Job's, so it delivers every report below.
    job = render_trivy_scan_job(RUN_ID, SCENARIO_ID, _admitted_image())

    # Bring-up: the standing Job's frontend report lands before any run, exactly as it does live.
    _run_uploader(job, LIVE_REPORT, port, monkeypatch)
    assert begin_monitor_window(events_root, RUN_ID) is not None  # archived away, not collated
    window_opens = datetime(2026, 9, 24, 10, 0, tzinfo=UTC)

    # A late delivery of an old scan lands inside the tree but carries a pre-window CreatedAt.
    stale = _report(tmp_path, "stale.json", artifact=None, created_at="2026-09-24T09:59:59Z")
    _run_uploader(job, stale, port, monkeypatch)

    # This run's scan: the image the Job was rendered to scan, with the report Trivy writes when
    # the scan finishes -- after the rollout, inside the window.
    [trivy] = job["spec"]["template"]["spec"]["initContainers"]
    target = next(item["value"] for item in trivy["env"] if item["name"] == "TARGET_IMAGE")
    scanned_at = window_opens + timedelta(minutes=2, seconds=13)
    current = _report(
        tmp_path,
        "trivy.json",
        artifact=target,
        created_at=scanned_at.isoformat().replace("+00:00", ".123456789Z"),
    )
    _run_uploader(job, current, port, monkeypatch)

    closed = close_monitor_window(events_root, RUN_ID)
    destination = tmp_path / "bundle" / "monitor_events.jsonl"
    written = collate_monitor_events(closed, destination, started_at=window_opens)

    findings = sum(
        len(result.get("Vulnerabilities") or [])
        for result in json.loads(LIVE_REPORT.read_text(encoding="utf-8"))["Results"]
    )
    events = [json.loads(line) for line in destination.read_bytes().splitlines()]
    assert findings > 0 and written == findings == len(events)
    assert {event["source"] for event in events} == {"trivy"}
    assert {event["resource"]["kind"] for event in events} == {"Image"}
    # Every surviving finding names the admitted image, the join SCN-CVE-05's detection relies on.
    assert {event["resource"]["name"] for event in events} == {target}
    assert {event["ts"] for event in events} == {
        scanned_at.isoformat().replace("+00:00", ".123456Z")
    }
    timings = (destination.parent / "monitor_timings.jsonl").read_bytes().splitlines()
    assert [json.loads(line)["event_id"] for line in timings] == [e["event_id"] for e in events]
