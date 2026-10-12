"""Unit tests for the network-independent HTTP aggregator application, plus two socket-level
regressions for the threaded transport (ADR-091: a single-threaded server starved its own liveness
probe during a multi-megabyte Trivy ingestion and was killed mid-request)."""

import json
import threading
import urllib.request
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from pathlib import Path

from monitor.aggregator.models import EvidenceSource
from monitor.aggregator.normalize import registry_entry
from monitor.http_service import AggregatorApplication, ServiceConfig, build_server
from monitor.tests.test_normalizers import FALCO_RECORD

CAP_ENV = {
    "MONITOR_EVIDENCE_EXCERPT_COUNT_MAX": "8",
    "MONITOR_EVIDENCE_EXCERPT_LENGTH_MAX_CHARS": "512",
    "MONITOR_SUMMARY_LENGTH_MAX_CHARS": "512",
}


def _application(tmp_path: Path, extra: dict[str, str] | None = None) -> AggregatorApplication:
    values = {**CAP_ENV, "MONITOR_DATA_DIR": str(tmp_path)}
    values.update(extra or {})
    return AggregatorApplication(ServiceConfig.from_environ(values))


def _payload(response) -> dict[str, object]:
    return json.loads(response.body)


def test_liveness_and_readiness_use_calibrated_protocol_caps(tmp_path: Path) -> None:
    app = AggregatorApplication(ServiceConfig.from_environ({"MONITOR_DATA_DIR": str(tmp_path)}))

    assert app.handle("GET", "/healthz").status is HTTPStatus.OK
    assert app.handle("GET", "/readyz").status is HTTPStatus.OK


def test_invalid_non_cap_configuration_is_also_not_ready(tmp_path: Path) -> None:
    app = _application(tmp_path, {"MONITOR_QUOTING_ENABLED": "sometimes"})

    assert app.handle("GET", "/healthz").status is HTTPStatus.OK
    assert app.handle("GET", "/readyz").status is HTTPStatus.SERVICE_UNAVAILABLE
    assert app.handle("POST", "/v1/falco", b"{}\n").status is HTTPStatus.SERVICE_UNAVAILABLE


def test_pending_or_partial_caps_reject_ingestion(tmp_path: Path) -> None:
    config = {
        "MONITOR_DATA_DIR": str(tmp_path),
        "MONITOR_EVIDENCE_EXCERPT_COUNT_MAX": "PENDING-M2-FIXTURE-STUDY",
    }
    response = AggregatorApplication(ServiceConfig.from_environ(config)).handle(
        "POST", "/v1/falco", b"{}\n"
    )

    assert response.status is HTTPStatus.SERVICE_UNAVAILABLE
    assert not (tmp_path / "raw").exists()


def test_falco_input_is_persisted_canonically_and_existing_pipeline_emits_event(
    tmp_path: Path,
) -> None:
    body = json.dumps(FALCO_RECORD, separators=(",", ":")).encode("utf-8") + b"\n"
    response = _application(tmp_path).handle("POST", "/v1/falco", body)
    payload = _payload(response)

    assert response.status is HTTPStatus.OK
    assert len(payload["events"]) == 1
    event = payload["events"][0]
    assert event["source"] == "falco"
    assert event["ts"] == "2026-08-26T10:30:00.123456Z"
    raw_path = tmp_path / payload["raw_path"]
    assert raw_path.read_bytes() == body
    assert event["raw_ref"]["path"] == payload["raw_path"]
    assert event["raw_ref"]["offset"] == 0
    assert event["raw_ref"]["length"] == len(body) - 1

    digest_dir = tmp_path / "events" / "falco" / raw_path.parent.name
    emitted = digest_dir / "monitor_events.jsonl"
    assert emitted.is_file()
    assert json.loads(emitted.read_bytes()) == event
    timing = json.loads((digest_dir / "monitor_timings.jsonl").read_bytes())
    assert timing["event_id"] == event["event_id"]
    assert datetime.fromisoformat(timing["emit_ts"].replace("Z", "+00:00")).tzinfo is UTC


def test_readyz_reports_the_run_epoch(tmp_path: Path) -> None:
    """/readyz reports the run epoch and the quoting mode the pod is serving (SEAM 4).

    The runner reads these back from a ready pod before it opens the evidence window, so the
    endpoint
    has to carry both, and an unset epoch has to read as null rather than as a guessed value.
    """
    app = _application(
        tmp_path,
        {"MONITOR_RUN_EPOCH": "RUN-2026-EPOCH-1", "MONITOR_QUOTING_ENABLED": "false"},
    )
    response = app.handle("GET", "/readyz")
    assert response.status is HTTPStatus.OK
    payload = _payload(response)
    assert payload["run_epoch"] == "RUN-2026-EPOCH-1"
    assert payload["quoting"] is False
    assert payload["status"] == "ready"

    # No epoch set: reported as null, never fabricated.
    bare = _payload(_application(tmp_path / "bare").handle("GET", "/readyz"))
    assert bare["run_epoch"] is None
    assert bare["quoting"] is True


def test_timings_carry_the_run_epoch(tmp_path: Path) -> None:
    """Every monitor_timings.jsonl row is stamped with the process's run epoch as config_epoch.

    Defence in depth beside the source-ts filter: the runner drops any collated event whose timing
    row names a different run (SEAM 4), so the epoch has to reach the row for every emitted event.
    """
    body = json.dumps(FALCO_RECORD, separators=(",", ":")).encode("utf-8") + b"\n"
    response = _application(tmp_path, {"MONITOR_RUN_EPOCH": "RUN-2026-EPOCH-7"}).handle(
        "POST", "/v1/falco", body
    )
    assert response.status is HTTPStatus.OK
    payload = _payload(response)
    digest = (tmp_path / payload["raw_path"]).parent.name
    timing = json.loads(
        (tmp_path / "events" / "falco" / digest / "monitor_timings.jsonl").read_bytes()
    )
    assert timing["config_epoch"] == "RUN-2026-EPOCH-7"
    assert timing["event_id"] == payload["events"][0]["event_id"]


def test_every_required_endpoint_routes_through_the_single_source_registry(tmp_path: Path) -> None:
    app = _application(tmp_path)
    expected = {
        "/v1/falco": EvidenceSource.FALCO,
        "/v1/alertmanager": EvidenceSource.PROMETHEUS,
        "/v1/k8s-audit": EvidenceSource.K8S_AUDIT,
        "/v1/trivy": EvidenceSource.TRIVY,
    }

    for route, source in expected.items():
        response = app.handle("POST", route, b"{}\n")
        assert response.status is HTTPStatus.BAD_REQUEST
        assert registry_entry(source).input_filename in (
            "falco.jsonl",
            "prometheus.json",
            "k8s_audit.jsonl",
            "trivy.json",
        )


def test_all_four_endpoints_accept_the_existing_canonical_source_shapes(tmp_path: Path) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "fixtures" / "four-source-incident"
    app = _application(tmp_path)
    cases = {
        "/v1/falco": ("falco.jsonl", "falco"),
        "/v1/alertmanager": ("prometheus.json", "prometheus"),
        "/v1/k8s-audit": ("k8s_audit.jsonl", "k8s_audit"),
        "/v1/trivy": ("trivy.json", "trivy"),
    }

    for route, (filename, expected_source) in cases.items():
        # Exercise HTTP's case-insensitive header contract at the application boundary.
        headers = {"x-monitor-audit-severity": "high"} if expected_source == "k8s_audit" else None
        response = app.handle("POST", route, (fixtures / filename).read_bytes(), headers)
        assert response.status is HTTPStatus.OK, response.body
        events = _payload(response)["events"]
        assert events
        assert {event["source"] for event in events} == {expected_source}


def test_g3_configuration_is_forwarded_without_a_second_quoting_policy(tmp_path: Path) -> None:
    body = json.dumps(FALCO_RECORD, separators=(",", ":")).encode("utf-8") + b"\n"
    quoted = _payload(_application(tmp_path / "on").handle("POST", "/v1/falco", body))
    unquoted = _payload(
        _application(tmp_path / "off", {"MONITOR_QUOTING_ENABLED": "false"}).handle(
            "POST", "/v1/falco", body
        )
    )

    quoted_event = quoted["events"][0]
    unquoted_event = unquoted["events"][0]
    for key in quoted_event:
        if key not in {"summary", "evidence_excerpts"}:
            assert quoted_event[key] == unquoted_event[key]
    assert quoted_event["summary"] != unquoted_event["summary"]


# --------------------------------------------------------------------------------------------
# Transport regressions for the threaded server (ADR-091)
# --------------------------------------------------------------------------------------------


def _serve(server: ThreadingHTTPServer) -> int:
    """Start ``server`` on a daemon thread and return its bound port."""
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server.server_address[1]


def test_build_server_is_threaded_and_serves_healthz_during_an_in_flight_ingestion(
    tmp_path: Path,
) -> None:
    """A held ingestion must not starve ``/healthz``.

    A blocking clock holds one accepted POST inside ``handle()`` (the clock is read once per
    ingestion, after ``emit``). A single-threaded ``HTTPServer`` would then be unable to answer the
    liveness probe for the whole ingestion -- the exact starvation that had the kubelet kill the pod
    mid-request, surfacing to the uploader as ``Remote end closed connection without response``
    (ADR-091). Under ``build_server``'s ``ThreadingHTTPServer`` the probe is answered on another
    thread while the ingestion is blocked.
    """
    entered = threading.Event()
    release = threading.Event()

    def blocking_clock() -> datetime:
        entered.set()
        assert release.wait(timeout=10), "the test never released the held ingestion"
        return datetime(2026, 1, 1, tzinfo=UTC)

    config = ServiceConfig.from_environ({**CAP_ENV, "MONITOR_DATA_DIR": str(tmp_path)})
    server = build_server(AggregatorApplication(config, clock=blocking_clock), ("127.0.0.1", 0))
    assert isinstance(server, ThreadingHTTPServer)  # the fix itself, guarded against regression
    port = _serve(server)
    try:
        body = json.dumps(FALCO_RECORD, separators=(",", ":")).encode("utf-8") + b"\n"
        held = threading.Thread(
            target=lambda: urllib.request.urlopen(
                urllib.request.Request(
                    f"http://127.0.0.1:{port}/v1/falco", data=body, method="POST"
                ),
                timeout=10,
            ).read(),
            daemon=True,
        )
        held.start()
        assert entered.wait(timeout=10), "the ingestion never reached the held clock"
        # The POST is now blocked inside handle(); the liveness probe must still answer promptly.
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=5) as response:
            assert response.status == 200
            assert json.loads(response.read())["status"] == "live"
        release.set()
        held.join(timeout=10)
        assert not held.is_alive(), "the released ingestion did not complete"
    finally:
        release.set()
        server.shutdown()
        server.server_close()


def test_large_multi_megabyte_trivy_report_is_ingested_over_the_socket(tmp_path: Path) -> None:
    """A genuinely multi-megabyte, valid Trivy report is accepted end to end over the real socket.

    The scan-first CVE surface's first evidence IS a full image scan report; this is the size class
    that produced the ADR-091 failure. Every finding is made unique (its own VulnerabilityID,
    PkgName and Target) so the report is valid rather than a duplicate-id rejection.
    """
    fixture = Path(__file__).resolve().parents[1] / "fixtures" / "trivy-live-capture" / "trivy.json"
    document = json.loads(fixture.read_bytes())
    base_results = document.get("Results", [])
    enlarged: list[dict[str, object]] = []
    for copy_index in range(60):
        for result in base_results:
            clone = json.loads(json.dumps(result))
            clone["Target"] = f"{clone.get('Target', 'target')}#copy{copy_index}"
            for vulnerability in clone.get("Vulnerabilities") or []:
                vulnerability["VulnerabilityID"] = (
                    f"{vulnerability.get('VulnerabilityID', 'CVE')}-copy{copy_index}"
                )
                vulnerability["PkgName"] = f"{vulnerability.get('PkgName', 'pkg')}-copy{copy_index}"
            enlarged.append(clone)
    document["Results"] = enlarged
    body = json.dumps(document).encode("utf-8")
    assert len(body) > 3_000_000, "the regression needs a genuinely multi-megabyte report"

    config = ServiceConfig.from_environ({**CAP_ENV, "MONITOR_DATA_DIR": str(tmp_path)})
    server = build_server(AggregatorApplication(config), ("127.0.0.1", 0))
    port = _serve(server)
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/trivy",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - localhost test
            assert response.status == 200, response.read()
            payload = json.loads(response.read())
        assert payload["events"], "a multi-megabyte report must still emit its findings"
        assert (tmp_path / payload["raw_path"]).read_bytes() == body  # persisted byte-for-byte
    finally:
        server.shutdown()
        server.server_close()


def test_trivy_reports_both_package_instances_with_the_same_advisory(tmp_path: Path) -> None:
    from monitor.tests.test_normalizers import TRIVY_CONTEXT, TRIVY_VULNERABILITY

    finding = {k: v for k, v in TRIVY_VULNERABILITY.items() if k != "PkgID"}
    report = {
        **{
            k: v
            for k, v in TRIVY_CONTEXT.items()
            if k in ("CreatedAt", "ArtifactName", "ArtifactType")
        },
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "Java",
                "Class": "lang-pkgs",
                "Type": "jar",
                "Vulnerabilities": [
                    {
                        **finding,
                        "PkgPath": "app/build/install/hipstershop/lib/netty-codec-http2.jar",
                    },
                    {**finding, "PkgPath": "app/build/output/lib/netty-codec-http2.jar"},
                ],
            }
        ],
    }
    body = json.dumps(report).encode()
    app = _application(tmp_path)
    first = app.handle("POST", "/v1/trivy", body)
    assert first.status is HTTPStatus.OK, first.body
    events = _payload(first)["events"]
    assert len(events) == 2
    assert len({event["event_id"] for event in events}) == 2
    assert len({event["raw_ref"]["offset"] for event in events}) == 2
    second = app.handle("POST", "/v1/trivy", body)
    assert second.status is HTTPStatus.OK
    assert _payload(second)["events"] == events
