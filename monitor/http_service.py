"""Standard-library HTTP transport for the deterministic evidence aggregator.

The transport lives outside ``monitor/aggregator`` because that subtree is the pure processing
boundary enforced by ``scripts/monitor_guard.sh``. It persists each accepted request byte-for-byte
under the source registry's canonical input filename, then calls the existing emitter. No parsing,
normalisation, event identity, capping, quoting, or serialisation rule is reimplemented here.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Final

from monitor.aggregator import limits as protocol_limits
from monitor.aggregator.caps import CapConfigurationError, CapLimits
from monitor.aggregator.emit import EmitConfig, SourceInput, emit
from monitor.aggregator.models import EvidenceSeverity, EvidenceSource
from monitor.aggregator.normalize import DuplicateEventId, RecordLayoutError, registry_entry
from monitor.aggregator.sources import NormalisationError, NormaliserOptions
from pydantic import ValidationError

HOST_ENV: Final = "MONITOR_HTTP_HOST"
PORT_ENV: Final = "MONITOR_HTTP_PORT"
DATA_DIR_ENV: Final = "MONITOR_DATA_DIR"
QUOTING_ENV: Final = "MONITOR_QUOTING_ENABLED"
# The run this aggregator process was scaled up for. The runner sets it (value = run_id) in the same
# `set env` that carries MONITOR_QUOTING_ENABLED, before the single rollout, so /readyz can report
# which run's configuration the pod is actually serving and every timing row can be stamped with it.
# Absent (a bare replay, or a process started without a run) means no epoch, reported as null and
# never as a guessed value: the runner's collation drops events whose epoch does not match the run
# it
# expects (SEAM 4), and a fabricated epoch here would defeat exactly that check.
RUN_EPOCH_ENV: Final = "MONITOR_RUN_EPOCH"
AUDIT_SEVERITY_HEADER: Final = "X-Monitor-Audit-Severity"
CAP_ENV_NAMES: Final[dict[str, str]] = {
    "evidence_excerpt_count_max": "MONITOR_EVIDENCE_EXCERPT_COUNT_MAX",
    "evidence_excerpt_length_max_chars": "MONITOR_EVIDENCE_EXCERPT_LENGTH_MAX_CHARS",
    "summary_length_max_chars": "MONITOR_SUMMARY_LENGTH_MAX_CHARS",
}
PENDING_VALUE: Final = protocol_limits.PENDING_FIXTURE_STUDY

_SOURCE_PATHS: Final[dict[str, EvidenceSource]] = {
    "/v1/falco": EvidenceSource.FALCO,
    "/v1/alertmanager": EvidenceSource.PROMETHEUS,
    "/v1/k8s-audit": EvidenceSource.K8S_AUDIT,
    "/v1/trivy": EvidenceSource.TRIVY,
}

_EXPECTED_INGESTION_ERRORS = (
    CapConfigurationError,
    DuplicateEventId,
    NormalisationError,
    RecordLayoutError,
    ValidationError,
)


@dataclass(frozen=True, slots=True)
class ServiceConfig:
    """Service configuration; absent cap environment variables use the checked protocol mirror.

    ``run_epoch`` is the run this process was scaled up for (``MONITOR_RUN_EPOCH``, value = run_id),
    or ``None`` for a process started without one. It is reported by ``/readyz`` and stamped onto
    every ``monitor_timings.jsonl`` row so the runner can confirm the pod is serving the current
    run's configuration before it opens the evidence window, and can drop any event whose timing row
    carries another epoch (SEAM 4). It is carried, never inferred: an absent epoch is ``None``.
    """

    data_dir: Path
    quoting_enabled: bool
    cap_limits: CapLimits | None
    readiness_errors: tuple[str, ...]
    run_epoch: str | None

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> ServiceConfig:
        errors: list[str] = []
        values: dict[str, int] = {}
        mirror = protocol_limits.as_protocol_mapping()
        for key, env_name in CAP_ENV_NAMES.items():
            raw = environ.get(env_name, str(mirror[key]))
            if raw == PENDING_VALUE:
                errors.append(f"{env_name} is {PENDING_VALUE}")
                continue
            try:
                parsed = int(raw)
            except ValueError:
                errors.append(f"{env_name} must be a positive integer")
                continue
            if parsed < 1:
                errors.append(f"{env_name} must be a positive integer")
                continue
            values[key] = parsed

        caps = None
        if not errors:
            caps = CapLimits(**values)

        quote_setting = environ.get(QUOTING_ENV, "true").strip().lower()
        try:
            quote_value = {"true": True, "false": False}[quote_setting]
        except KeyError:
            errors.append(f"{QUOTING_ENV} must be true or false")
            quote_value = True

        return cls(
            data_dir=Path(environ.get(DATA_DIR_ENV, "/var/lib/monitor")),
            quoting_enabled=quote_value,
            cap_limits=caps,
            readiness_errors=tuple(errors),
            # `or None` folds an empty value to absent: a run_id is never the empty string, so an
            # empty variable is an unset one and must not read back as an epoch of "".
            run_epoch=environ.get(RUN_EPOCH_ENV) or None,
        )


@dataclass(frozen=True, slots=True)
class Response:
    status: HTTPStatus
    body: bytes


class AggregatorApplication:
    """Network-independent request application, directly exercised by unit tests."""

    def __init__(
        self,
        config: ServiceConfig,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._config = config
        self._clock = clock

    @staticmethod
    def _json(status: HTTPStatus, payload: object) -> Response:
        return Response(
            status=status,
            body=json.dumps(
                payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
            ).encode("utf-8")
            + b"\n",
        )

    def handle(
        self,
        method: str,
        path: str,
        body: bytes = b"",
        headers: Mapping[str, str] | None = None,
    ) -> Response:
        if method == "GET" and path == "/healthz":
            return self._json(HTTPStatus.OK, {"status": "live"})
        if method == "GET" and path == "/readyz":
            # The runner reads quoting and run_epoch back from a ready pod (a one-shot kubectl exec
            # against this endpoint) to confirm the aggregator is serving the current run's
            # configuration before it opens the evidence window (SEAM 4). Both are reported whether
            # or
            # not the pod is ready, so the runner learns the configuration even from a not-ready
            # pod.
            readiness = {
                "quoting": self._config.quoting_enabled,
                "run_epoch": self._config.run_epoch,
            }
            if self._config.readiness_errors:
                return self._json(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {
                        **readiness,
                        "errors": list(self._config.readiness_errors),
                        "status": "not-ready",
                    },
                )
            return self._json(HTTPStatus.OK, {**readiness, "status": "ready"})
        if method != "POST" or path not in _SOURCE_PATHS:
            return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
        if self._config.readiness_errors or self._config.cap_limits is None:
            return self._json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"errors": list(self._config.readiness_errors), "status": "not-ready"},
            )
        if not body:
            return self._json(HTTPStatus.BAD_REQUEST, {"error": "request body is empty"})

        source = _SOURCE_PATHS[path]
        audit_severity = None
        if source is EvidenceSource.K8S_AUDIT:
            normalized_headers = {name.lower(): value for name, value in (headers or {}).items()}
            severity_text = normalized_headers.get(AUDIT_SEVERITY_HEADER.lower())
            try:
                audit_severity = EvidenceSeverity(severity_text)
            except ValueError:
                return self._json(
                    HTTPStatus.BAD_REQUEST,
                    {
                        "error": "AuditSeverityNotAssigned",
                        "message": (
                            f"{AUDIT_SEVERITY_HEADER} must be one of "
                            + ", ".join(level.value for level in EvidenceSeverity)
                        ),
                    },
                )
        entry = registry_entry(source)
        digest = hashlib.sha256(body).hexdigest()
        raw_relative = Path("raw") / source.value / digest / entry.input_filename
        raw_path = self._config.data_dir / raw_relative
        transaction_dir = self._config.data_dir / "events" / source.value / digest

        try:
            result = emit(
                [SourceInput(entry=entry, raw_path=raw_relative.as_posix(), data=body)],
                out_dir=transaction_dir,
                config=EmitConfig(
                    quoting_enabled=self._config.quoting_enabled,
                    cap_limits=self._config.cap_limits,
                ),
                options=NormaliserOptions(audit_severity=audit_severity),
            )
        except _EXPECTED_INGESTION_ERRORS as failure:
            return self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": type(failure).__name__, "message": str(failure)},
            )

        raw_path.parent.mkdir(parents=True, exist_ok=True)
        if raw_path.exists():
            if raw_path.read_bytes() != body:
                return self._json(HTTPStatus.CONFLICT, {"error": "raw input digest collision"})
        else:
            temporary = raw_path.with_suffix(raw_path.suffix + ".pending")
            temporary.write_bytes(body)
            temporary.replace(raw_path)

        emit_ts = self._clock().astimezone(UTC).isoformat().replace("+00:00", "Z")
        timings = transaction_dir / "monitor_timings.jsonl"
        # Every timing row carries the run epoch this process was scaled up for, so the runner's
        # collation can drop an event whose row names another run (SEAM 4). config_epoch is the
        # process's run_epoch verbatim -- null when the process has none -- never a per-event guess.
        timings.write_text(
            "".join(
                json.dumps(
                    {
                        "event_id": event.event_id,
                        "emit_ts": emit_ts,
                        "config_epoch": self._config.run_epoch,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
                for event in result.events
            ),
            encoding="utf-8",
        )

        return self._json(
            HTTPStatus.OK,
            {
                "events": [event.model_dump(mode="json") for event in result.events],
                "raw_path": raw_relative.as_posix(),
            },
        )


class _RequestHandler(BaseHTTPRequestHandler):
    """Thin HTTP framing adapter; all behavior is in :class:`AggregatorApplication`."""

    app: AggregatorApplication
    protocol_version = "HTTP/1.1"

    def _dispatch(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0:
                raise ValueError
        except ValueError:
            response = self.app._json(HTTPStatus.BAD_REQUEST, {"error": "invalid Content-Length"})
        else:
            response = self.app.handle(
                self.command,
                self.path,
                self.rfile.read(length),
                dict(self.headers.items()),
            )
        self.send_response(response.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response.body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(response.body)

    do_GET = _dispatch
    do_POST = _dispatch

    def log_message(self, format: str, *args: object) -> None:
        print(f"monitor-http: {format % args}", file=sys.stderr)


def build_server(app: AggregatorApplication, address: tuple[str, int]) -> ThreadingHTTPServer:
    """A THREADING HTTP server, so a long ingestion never starves the health probes.

    The aggregator is probed with a 2-second liveness timeout (``monitor/deploy/deployment.yaml``).
    A single-threaded ``HTTPServer`` serialises every request against one thread, so a
    multi-megabyte Trivy report -- the scan-first CVE surface's own first evidence -- blocks
    ``/healthz`` for the whole ingestion; three starved probes in a row have the kubelet kill the
    pod mid-request, which the uploading client sees as ``Remote end closed connection without
    response`` (ADR-091 live diagnosis, 2026-09-13; the failure that leaves the CVE-04 scan Job
    ``Failed`` with
    no first evidence). ``ThreadingHTTPServer`` serves the probe on another thread while the report
    is ingested. Each request writes only to a path derived from its own body digest
    (``raw/<source>/<sha256>/`` and ``events/<source>/<sha256>/``), so two concurrent ingestions of
    different reports share no mutable state, and two of the identical report resolve to the same
    idempotent, atomically-replaced write -- the aggregator holds no other cross-request state. The
    application object is bound onto a fresh handler subclass rather than the module-global handler,
    so a caller (a test) may stand up more than one independent server in one process.
    """
    handler = type("_BoundRequestHandler", (_RequestHandler,), {"app": app})
    return ThreadingHTTPServer(address, handler)


def main() -> int:
    config = ServiceConfig.from_environ(os.environ)
    host = os.environ.get(HOST_ENV, "0.0.0.0")  # noqa: S104 - in-cluster webhook service
    try:
        port = int(os.environ.get(PORT_ENV, "8080"))
    except ValueError:
        print(f"monitor-http: {PORT_ENV} must be an integer", file=sys.stderr)
        return 1
    server = build_server(AggregatorApplication(config), (host, port))
    print(f"monitor-http: listening on {host}:{port}", file=sys.stderr)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
