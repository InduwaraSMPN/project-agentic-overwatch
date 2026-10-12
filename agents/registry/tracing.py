r"""Spans per node, per phase and per Guardian decision -- to a file at Tier A, to OTLP at Tier B.

WHAT THIS MODULE IS
-------------------
``docs/milestones/M4-agents.md``'s T4.5 asks for "Langfuse logging + OTel spans (node/phase/
decision)", and ``docs/adr/ADR-006-observability-langfuse.md`` chose the technology. The M4 plan
splits the *install shape* by tier: Tier A emits "OTel spans to a file exporter", Tier B runs the
collector and Langfuse compose. This module is the seam that makes one instrumentation call site
serve both. ADR-032.

Traceability row T-05 verifies through "per-phase spans present in run bundle", and FR2.2 makes
that its verification method in so many words -- so a span is evidence rather than a diagnostic,
and the file sink below is the artefact rather than a stand-in for one.

WHY THERE IS A SPAN TYPE HERE AND NOT A DIRECT OPENTELEMETRY DEPENDENCY AT THE CALL SITE
------------------------------------------------------------------------------------------
Two reasons, and the first is the one that decides it.

*The gate must not acquire a dependency.* ``scripts/parity_check.sh`` runs in a CI job that installs
nothing (conflict M4-C1), and it imports the composer, which is imported by the graphs. If a graph
module imported ``opentelemetry`` at module scope, the import chain would reach the gate. So the
backend is resolved lazily, once, on first use, and the default sink is standard library.

*Tier A has to produce a real artefact.* A no-op tracer would make every Tier A assertion about
spans vacuous -- "four phase spans present in order" would pass over a tracer that recorded nothing,
which is the same vacuous-pass shape ``agents/registry/parity.py`` refuses for parity. The file sink
writes the binding ``spans.otel.json`` document as one canonical object with a ``spans`` array, so
``agents/tests/test_golden_path.py`` asserts over bytes that exist.

THE FILE SINK IS DETERMINISTIC, AND THAT COSTS ONE FIELD
----------------------------------------------------------
``.agents/rules/20-parity-and-determinism.md`` requires a replay to produce identical output, and a
span carrying a wall-clock timestamp and a random id could not. So:

*Ids are derived, not generated.* A span's id is a SHA-256 prefix over ``(run id, parent id,
sequence, name)``. Two replays of one run produce the same ids, which is what lets a determinism
check diff two span files rather than two summaries of them.

*Duration and start time are measured.* ``duration_ms`` preserves elapsed cost, while
``startTimeUnixNano`` supplies the phase milestone that ``evaluation-protocol.md`` section 3
requires for response latency. Scenario and Monitor determinism are checked over their own
planned/event streams, not over observational run telemetry; ADR-078 records this correction to
ADR-032.

*Attributes are sorted.* Canonical JSON, sorted keys, minimal separators -- the rule
``monitor/aggregator/models.py`` states once for the event stream, applied here for the same reason.

WHAT A SPAN IS ALLOWED TO CARRY, AND WHAT IT IS NOT
-----------------------------------------------------
A span carries structure and identifiers: the phase, the role, the node kind, the condition, the
tool name, the Guardian's reason code, the token counts, the attempt count. It does **not** carry
prompt text or evidence text.

That is a deliberate boundary rather than a size concern. ``docs/protocols/data-management.md``
section 5's pre-seal sanitizer strips key-shaped strings from a bundle, and
``guardian/app/models.py`` argues at length that the right way to survive that is for the record to
be *born clean*. A span that carried a rendered prompt would carry environment-derived text that an
attacker chose, into a file the sanitizer would then have to rewrite -- and the verbatim messages
T-05 wants belong in ``messages.jsonl``, which is the artefact the data-management protocol already
owns for exactly that. One home for the bytes, one home for the structure.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
``spans.otel.json`` in every run bundle, and the per-phase span assertion T-05 closes on.
"""

import hashlib
import json
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

__all__ = (
    "DEFAULT_OTLP_HTTP_ENDPOINT",
    "FileSpanSink",
    "MultiSpanSink",
    "NullSpanSink",
    "OTLPHTTPSpanSink",
    "OTLP_TRACES_ENDPOINT_KEY",
    "SPAN_EXPORTER_KEY",
    "SPAN_SCHEMA_VERSION",
    "Span",
    "SpanSink",
    "TraceConfigurationError",
    "Tracer",
    "configured_span_sink",
)

# Configuration is deliberately limited to a backend selector and the collector address, supplied
# as a runner-owned mapping rather than read from the process here. The agent sends no authorization
# header: ADR-032 puts Langfuse's credential only on the collector hop.
SPAN_EXPORTER_KEY: Final = "span_exporter"
OTLP_TRACES_ENDPOINT_KEY: Final = "otlp_traces_endpoint"
DEFAULT_OTLP_HTTP_ENDPOINT: Final = "http://127.0.0.1:4318/v1/traces"
_FILE_EXPORTER: Final = "file"
_OTLP_HTTP_EXPORTER: Final = "otlp-http"

# One version token, for monitor/aggregator/models.py's stated reason: a consumer must be able to
# reject a document of a version it does not understand, and a non-numeric token can only be
# compared for membership in a known set -- which is the check a consumer is supposed to perform.
SPAN_SCHEMA_VERSION: Final = "v1"

# The length of a derived span id, in hex characters. Sixteen is 64 bits, which is what
# OpenTelemetry gives a span id, so the value carried here fits the field it will eventually be
# exported into.
_SPAN_ID_CHARS: Final = 16


@dataclass
class Span:
    """One node, phase or decision, with what it was and what it cost.

    Mutable while open and never after: :meth:`Tracer.span` yields it so the body can attach
    attributes as it learns them -- a Guardian reason code is not known until the call returns --
    and the sink receives it once, at close.
    """

    name: str
    span_id: str
    parent_id: str | None
    run_id: str
    attributes: dict[str, Any] = field(default_factory=dict)
    start_time_unix_nano: int = 0
    end_time_unix_nano: int = 0
    duration_ms: float = 0.0
    error: str | None = None

    def set(self, **attributes: Any) -> None:
        """Attach attributes. Values must be scalars; a structure belongs in ``messages.jsonl``."""
        for key, value in attributes.items():
            if value is not None and not isinstance(value, str | int | float | bool):
                raise TypeError(
                    f"span attribute {key!r} is {type(value).__name__}; a span carries structure "
                    "and identifiers, and the verbatim bytes belong in messages.jsonl -- see this "
                    "module's docstring on why a span is born clean"
                )
            self.attributes[key] = value

    def as_record(self) -> dict[str, Any]:
        """Return the canonical mapping the sink serialises."""
        return {
            "name": self.name,
            "span_id": self.span_id,
            "parent_id": self.parent_id,
            "run_id": self.run_id,
            "attributes": dict(self.attributes),
            "startTimeUnixNano": self.start_time_unix_nano,
            "endTimeUnixNano": self.end_time_unix_nano,
            "duration_ms": round(self.duration_ms, 3),
            "error": self.error,
            "schema_version": SPAN_SCHEMA_VERSION,
        }


class SpanSink:
    """Where a closed span goes. One method, so a second backend is a class rather than a branch."""

    def emit(self, span: Span) -> None:
        """Record ``span``. Must not raise for an ordinary failure."""
        raise NotImplementedError

    def close(self) -> None:
        """Release exporter resources. Stateless sinks need no override."""


class NullSpanSink(SpanSink):
    """Discards spans, and exists so that "no tracing configured" is a choice somebody made.

    Not the default. A tracer that silently discarded would make T-05's "per-phase spans present"
    assertion pass over nothing, which is the vacuous pass this repository refuses everywhere else.
    A caller that genuinely wants no trace says so by constructing this.
    """

    def emit(self, span: Span) -> None:
        """Do nothing, deliberately."""


class FileSpanSink(SpanSink):
    """Write the binding ``spans.otel.json`` document used by Tier A and sealed bundles.

    The protocol's ``.json`` suffix is a content contract, not merely a filename: the file is one
    canonical JSON object with a ``spans`` array, rather than a JSON-Lines stream under a misleading
    name. The document is replaced after every closed span so an interrupted run still leaves valid
    JSON containing all spans that closed before it stopped.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._records: list[dict[str, Any]] = []
        self._closed = False
        self._publish()

    def _publish(self) -> None:
        payload = json.dumps(
            {"spans": self._records}, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        temporary = self.path.with_name(f".{self.path.name}.tmp")
        temporary.write_bytes(payload.encode("utf-8") + b"\n")
        temporary.replace(self.path)

    def emit(self, span: Span) -> None:
        """Append one span to the in-memory sequence and publish the complete JSON document."""
        if self._closed:
            raise RuntimeError("cannot emit to a closed span sink")
        self._records.append(span.as_record())
        self._publish()

    def close(self) -> None:
        """Mark the sink closed. Idempotent; every emitted span was already published."""
        self._closed = True


class TraceConfigurationError(ValueError):
    """The configured span exporter is unknown or incomplete."""


class MultiSpanSink(SpanSink):
    """Emits to each configured sink, preserving the local run-bundle artefact."""

    def __init__(self, *sinks: SpanSink) -> None:
        if not sinks:
            raise ValueError("MultiSpanSink requires at least one sink")
        self.sinks = sinks

    def emit(self, span: Span) -> None:
        """Emit in declaration order; each sink owns its ordinary transport failures."""
        for sink in self.sinks:
            sink.emit(span)

    def close(self) -> None:
        """Close every closeable sink."""
        for sink in self.sinks:
            close = getattr(sink, "close", None)
            if close is not None:
                close()


class OTLPHTTPSpanSink(SpanSink):
    """Exports closed spans over OTLP/HTTP to the Tier B collector.

    OpenTelemetry is imported only when this sink is constructed, preserving the dependency-free
    parity path. ``exporter`` is an injection seam for focused tests; production constructs the
    pinned ``OTLPSpanExporter`` without an authorization header because the collector, not an agent,
    owns the Langfuse credential.
    """

    def __init__(self, endpoint: str, *, exporter: Any | None = None) -> None:
        endpoint = endpoint.strip()
        if not endpoint:
            raise TraceConfigurationError("the OTLP/HTTP traces endpoint is empty")
        if exporter is None:
            try:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  # noqa: PLC0415
                    OTLPSpanExporter,
                )
            except ImportError as missing:
                raise TraceConfigurationError(
                    "the OTLP/HTTP exporter is not importable. It is pinned in infra/versions.env "
                    "as OTEL_PYTHON_SDK_VERSION and installed by "
                    "scripts/install_runtime_deps.sh agents"
                ) from missing
            # A non-empty, non-sensitive map prevents the SDK from inheriting OTEL_*_HEADERS from
            # the process. Agents authenticate to nothing on this hop; only the collector
            # authenticates to Langfuse, as ADR-032 requires.
            exporter = OTLPSpanExporter(endpoint=endpoint, headers={"x-overwatch-source": "agents"})
        self.endpoint = endpoint
        self._exporter = exporter

    def emit(self, span: Span) -> None:
        """Translate the clean internal record to one OpenTelemetry SDK span and export it."""
        from opentelemetry.sdk.resources import Resource  # noqa: PLC0415
        from opentelemetry.sdk.trace import ReadableSpan  # noqa: PLC0415
        from opentelemetry.trace import SpanContext, TraceFlags  # noqa: PLC0415
        from opentelemetry.trace.status import Status, StatusCode  # noqa: PLC0415

        trace_id = int(hashlib.sha256(span.run_id.encode("utf-8")).hexdigest()[:32], 16) or 1
        span_context = SpanContext(
            trace_id=trace_id,
            span_id=int(span.span_id, 16) or 1,
            is_remote=False,
            trace_flags=TraceFlags(TraceFlags.SAMPLED),
        )
        parent = None
        if span.parent_id is not None:
            parent = SpanContext(
                trace_id=trace_id,
                span_id=int(span.parent_id, 16) or 1,
                is_remote=False,
                trace_flags=TraceFlags(TraceFlags.SAMPLED),
            )
        start_ns = span.start_time_unix_nano
        end_ns = span.end_time_unix_nano
        attributes = {
            "overwatch.run_id": span.run_id,
            "overwatch.schema_version": SPAN_SCHEMA_VERSION,
            **{
                f"overwatch.{key}": value
                for key, value in span.attributes.items()
                if value is not None
            },
        }
        readable = ReadableSpan(
            name=span.name,
            context=span_context,
            parent=parent,
            resource=Resource.create({"service.name": "agentic-overwatch-agents"}),
            attributes=attributes,
            status=Status(StatusCode.ERROR, span.error) if span.error else Status(StatusCode.UNSET),
            start_time=start_ns,
            end_time=end_ns,
        )
        self._exporter.export((readable,))

    def close(self) -> None:
        """Flush and shut down the SDK exporter."""
        self._exporter.shutdown()


def configured_span_sink(
    path: Path,
    config: Mapping[str, str] | None = None,
    *,
    exporter_factory: Callable[[str], Any] | None = None,
) -> SpanSink:
    """Select the trace backend from configuration.

    The absent/default value is the deterministic Tier A file sink. Tier B selects ``otlp-http``
    and gets both that exporter and the same local file so the run bundle remains self-contained.
    The endpoint defaults to the loopback collector and carries no secret or authorization value.
    """
    source: Mapping[str, str] = {} if config is None else config
    selected = source.get(SPAN_EXPORTER_KEY, _FILE_EXPORTER).strip().lower()
    file_sink = FileSpanSink(path)
    if selected == _FILE_EXPORTER:
        return file_sink
    if selected != _OTLP_HTTP_EXPORTER:
        file_sink.close()
        raise TraceConfigurationError(
            f"{SPAN_EXPORTER_KEY} is {selected!r}; expected {_FILE_EXPORTER!r} or "
            f"{_OTLP_HTTP_EXPORTER!r}"
        )
    endpoint = source.get(OTLP_TRACES_ENDPOINT_KEY, DEFAULT_OTLP_HTTP_ENDPOINT).strip()
    factory = exporter_factory or (lambda resolved: OTLPHTTPSpanSink(resolved))
    try:
        otlp_sink = factory(endpoint)
    except Exception:
        file_sink.close()
        raise
    if not isinstance(otlp_sink, SpanSink):
        otlp_sink = OTLPHTTPSpanSink(endpoint, exporter=otlp_sink)
    return MultiSpanSink(file_sink, otlp_sink)


class Tracer:
    """Opens spans, nests them, and hands each closed one to a sink.

    Nesting is a stack rather than a context variable, because the graph is synchronous -- the
    mediation pipeline it drives has no await point in it, and ``guardian/tests/harness.py`` records
    that threads rather than coroutines are the shape this system's concurrency takes. A stack is
    correct for a synchronous caller and is honest about not being safe for a concurrent one.
    """

    def __init__(
        self,
        *,
        run_id: str,
        sink: SpanSink,
        clock_ns: Callable[[], int] = time.time_ns,
        timer: Callable[[], float] = time.perf_counter,
    ) -> None:
        self.run_id = run_id
        self._sink = sink
        self._clock_ns = clock_ns
        self._timer = timer
        self._stack: list[str] = []
        self._sequence = 0

    @property
    def current_id(self) -> str | None:
        """The innermost open span's id, or ``None`` at the root."""
        return self._stack[-1] if self._stack else None

    def _next_id(self, name: str) -> str:
        """Derive the next span id from the run, the parent, the sequence and the name.

        Derived rather than generated, so two replays of one run produce the same ids. See the
        module docstring: a generated id would make ``spans.otel.json`` undiffable, and the
        byte-level twice-and-diff is how this project proves determinism everywhere else.
        """
        self._sequence += 1
        material = f"{self.run_id}|{self.current_id or ''}|{self._sequence}|{name}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:_SPAN_ID_CHARS]

    @contextmanager
    def span(self, name: str, **attributes: Any) -> Iterator[Span]:
        """Open a span, yield it, and emit it when the body leaves -- including by raising.

        An exception is recorded on the span and re-raised. A span that vanished when its body
        failed would leave a trace in which the failing phase is the one with no evidence, which is
        the opposite of what a trace is for.
        """
        opened = Span(
            name=name,
            span_id=self._next_id(name),
            parent_id=self.current_id,
            run_id=self.run_id,
            start_time_unix_nano=self._clock_ns(),
        )
        opened.set(**attributes)
        self._stack.append(opened.span_id)
        started = self._timer()
        try:
            yield opened
        except Exception as failure:
            opened.error = f"{type(failure).__name__}: {failure}"
            raise
        finally:
            opened.duration_ms = (self._timer() - started) * 1000.0
            opened.end_time_unix_nano = self._clock_ns()
            self._stack.pop()
            self._sink.emit(opened)


def read_spans(path: Path) -> tuple[Mapping[str, Any], ...]:
    """Read the binding ``spans.otel.json`` document back in write order.

    Published for tests and tooling. The filename's ``.json`` contract is enforced here: the root
    must be an object and its ``spans`` member must be a list of objects. There is deliberately no
    JSON-Lines fallback; accepting the retired producer format would preserve the ambiguity this
    contract resolves.
    """
    if not Path(path).exists():
        return ()
    loaded = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(loaded, dict) or not isinstance(loaded.get("spans"), list):
        raise ValueError(f"{path}: expected a JSON object carrying a 'spans' list")
    if not all(isinstance(span, dict) for span in loaded["spans"]):
        raise ValueError(f"{path}: every entry in 'spans' must be a JSON object")
    return tuple(loaded["spans"])
