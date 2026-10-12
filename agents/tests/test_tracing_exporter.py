"""Focused tests for the M4 trace-plane exporter seam.

No test opens a socket. The configured OTLP path receives an exporter double at the final SDK
boundary, while the production class still performs the OpenTelemetry ``ReadableSpan`` translation.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from agents.registry.tracing import (
    OTLP_TRACES_ENDPOINT_KEY,
    SPAN_EXPORTER_KEY,
    FileSpanSink,
    MultiSpanSink,
    OTLPHTTPSpanSink,
    TraceConfigurationError,
    Tracer,
    configured_span_sink,
    read_spans,
)
from opentelemetry.sdk.trace.export import SpanExportResult


class RecordingExporter:
    """An OpenTelemetry exporter double that records batches and performs no I/O."""

    def __init__(self) -> None:
        self.batches: list[tuple[Any, ...]] = []
        self.shutdown_called = False

    def export(self, spans: tuple[Any, ...]) -> SpanExportResult:
        self.batches.append(tuple(spans))
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        self.shutdown_called = True


def test_configuration_defaults_to_the_file_sink(tmp_path: Path) -> None:
    sink = configured_span_sink(tmp_path / "spans.otel.json", {})
    try:
        assert isinstance(sink, FileSpanSink)
    finally:
        sink.close()


def test_file_span_records_injected_absolute_start_time(tmp_path: Path) -> None:
    sink = FileSpanSink(tmp_path / "spans.otel.json")
    ticks = iter((10.0, 10.125))
    wall = iter((1_700_000_000_000_000_000, 1_700_000_000_125_000_000))
    tracer = Tracer(
        run_id="RUN-G0-FULL-SCN-SIM-02-INJ-A-101",
        sink=sink,
        clock_ns=lambda: next(wall),
        timer=lambda: next(ticks),
    )

    with tracer.span("phase", phase="containment"):
        pass

    span = read_spans(sink.path)[0]
    assert span["startTimeUnixNano"] == 1_700_000_000_000_000_000
    assert span["endTimeUnixNano"] == 1_700_000_000_125_000_000
    assert span["duration_ms"] == 125.0


def test_tier_b_configuration_selects_otlp_http_and_preserves_the_bundle(tmp_path: Path) -> None:
    exporter = RecordingExporter()
    endpoint = "http://collector.invalid:4318/v1/traces"

    sink = configured_span_sink(
        tmp_path / "spans.otel.json",
        {
            SPAN_EXPORTER_KEY: "otlp-http",
            OTLP_TRACES_ENDPOINT_KEY: endpoint,
        },
        exporter_factory=lambda resolved: OTLPHTTPSpanSink(resolved, exporter=exporter),
    )
    try:
        assert isinstance(sink, MultiSpanSink)
        assert isinstance(sink.sinks[0], FileSpanSink)
        assert isinstance(sink.sinks[1], OTLPHTTPSpanSink)
        assert sink.sinks[1].endpoint == endpoint
    finally:
        sink.close()
    assert exporter.shutdown_called


def test_node_phase_and_decision_spans_route_through_configured_exporter_without_network(
    tmp_path: Path,
) -> None:
    exporter = RecordingExporter()
    sink = configured_span_sink(
        tmp_path / "spans.otel.json",
        {SPAN_EXPORTER_KEY: "otlp-http"},
        exporter_factory=lambda endpoint: OTLPHTTPSpanSink(endpoint, exporter=exporter),
    )
    tracer = Tracer(run_id="RUN-G0-FULL-SCN01-INJA-S07", sink=sink)

    with tracer.span("phase", phase="containment"):
        with tracer.span("node", phase="containment", role="containment-supervisor"):
            pass
        with tracer.span("decision", phase="containment", reason_code="PERMIT"):
            pass
    sink.close()

    exported = [span for batch in exporter.batches for span in batch]
    assert [span.name for span in exported] == ["node", "decision", "phase"]
    assert exported[0].parent.span_id == exported[2].context.span_id
    assert exported[1].parent.span_id == exported[2].context.span_id
    assert exported[0].attributes["overwatch.phase"] == "containment"
    assert exported[1].attributes["overwatch.reason_code"] == "PERMIT"
    assert all(span.attributes["overwatch.run_id"] == tracer.run_id for span in exported)

    span_path = tmp_path / "spans.otel.json"
    document = json.loads(span_path.read_text(encoding="utf-8"))
    assert list(document) == ["spans"]
    local = read_spans(span_path)
    assert [span["name"] for span in local] == ["node", "decision", "phase"]


def test_unknown_exporter_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(TraceConfigurationError, match=SPAN_EXPORTER_KEY):
        configured_span_sink(
            tmp_path / "spans.otel.json",
            {SPAN_EXPORTER_KEY: "not-an-exporter"},
        )
