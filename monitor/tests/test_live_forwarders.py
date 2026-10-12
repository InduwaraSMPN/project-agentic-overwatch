"""Unit tests for the stdlib live-source transports."""

import urllib.error
from io import BytesIO
from pathlib import Path
from urllib.request import Request

import pytest
from monitor.audit_forwarder import (
    configured_severity,
    forward_stream,
    in_v1_scope,
    post_line,
    run,
)
from monitor.trivy_uploader import upload_report


class Response(BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def test_audit_severity_is_explicit_and_never_accepts_audit_level() -> None:
    with pytest.raises(ValueError, match="explicitly set"):
        configured_severity({})
    with pytest.raises(ValueError, match="explicitly set"):
        configured_severity({"MONITOR_AUDIT_SEVERITY": "RequestResponse"})
    assert configured_severity({"MONITOR_AUDIT_SEVERITY": "HIGH"}) == "high"


def test_audit_post_preserves_complete_line_and_explicit_severity() -> None:
    captured: list[Request] = []

    def open_request(request: Request):
        captured.append(request)
        return Response(b"{}")

    body = b'{"level":"Metadata","auditID":"a"}\n'
    post_line(body, url="http://monitor/v1/k8s-audit", severity="high", urlopen=open_request)

    request = captured[0]
    assert request.method == "POST"
    assert request.full_url.endswith("/v1/k8s-audit")
    assert request.data == body
    assert request.get_header("X-monitor-audit-severity") == "high"


def test_audit_stream_sends_only_complete_lines_and_retries_partial_line() -> None:
    stream = BytesIO(b'{"auditID":"one"}\n{"auditID":"two"}')
    posted: list[bytes] = []

    def post(line: bytes, **_kwargs) -> None:
        posted.append(line)

    assert forward_stream(stream, url="unused", severity="high", post=post) == 1
    assert posted == [b'{"auditID":"one"}\n']
    partial_position = stream.tell()
    assert stream.read() == b'{"auditID":"two"}'
    stream.seek(0, 2)
    stream.write(b"\n")
    stream.seek(partial_position)
    assert forward_stream(stream, url="unused", severity="high", post=post) == 1
    assert posted[-1] == b'{"auditID":"two"}\n'


def test_audit_stream_rewinds_a_complete_line_when_delivery_fails() -> None:
    stream = BytesIO(b'{"auditID":"one"}\n')

    def fail(_line: bytes, **_kwargs) -> None:
        raise OSError("temporary delivery failure")

    with pytest.raises(OSError, match="temporary delivery failure"):
        forward_stream(stream, url="unused", severity="high", post=fail)
    assert stream.tell() == 0


def test_audit_stream_skips_a_record_the_aggregator_refuses_and_keeps_going() -> None:
    """One malformed record must not end the audit stream.

    On 2026-09-12 a single interleaved line in 48,738 -- written while the evidence mount was being
    moved -- was retried once a second for hours, so API-plane evidence stopped entirely and an
    audit-first scenario had nothing to detect. A refusal of the record's bytes is permanent, so the
    record is reported and skipped; delivery of every later record continues.
    """
    stream = BytesIO(b'{"auditID":"one"}\n{"auditID":"bad"\n{"auditID":"three"}\n')
    posted: list[bytes] = []

    def post(line: bytes, **_kwargs) -> None:
        if b'"bad"' in line:
            raise urllib.error.HTTPError(
                "http://monitor/v1/k8s-audit", 400, "Bad Request", {}, None
            )
        posted.append(line)

    assert forward_stream(stream, url="unused", severity="high", post=post) == 2
    assert posted == [b'{"auditID":"one"}\n', b'{"auditID":"three"}\n']


def test_forwarder_drops_out_of_scope_records_before_post() -> None:
    """D16-A: only records inside the v1 audit scope are posted; the rest are dropped, not posted.

    The M10 audit policy is widened so the API-plane bundle can record workload mutations (V28), but
    the Monitor must keep its v1 input volume and per-record latency -- one synchronous POST each.
    So
    ``in_v1_scope`` mirrors the v1 policy's rules (RBAC and secret/ServiceAccount mutations; pod
    exec/attach/port-forward creates) and ``forward_stream`` drops everything else before it costs a
    POST. The records are interleaved so an out-of-scope record between two in-scope ones is skipped
    without stalling the stream.
    """
    in_scope = [
        b'{"verb":"create","objectRef":{"apiGroup":"","resource":"secrets",'
        b'"namespace":"boutique","name":"s"}}\n',
        b'{"verb":"patch","objectRef":{"apiGroup":"rbac.authorization.k8s.io",'
        b'"resource":"clusterrolebindings","name":"x"}}\n',
        b'{"verb":"create","objectRef":{"apiGroup":"","resource":"pods","subresource":"exec",'
        b'"namespace":"boutique","name":"p"}}\n',
    ]
    out_of_scope = [
        # A workload mutation the widened M10 policy records but v1 did not.
        b'{"verb":"patch","objectRef":{"apiGroup":"apps","resource":"deployments",'
        b'"namespace":"boutique","name":"frontend"}}\n',
        # A core object outside the credential set.
        b'{"verb":"create","objectRef":{"apiGroup":"","resource":"configmaps",'
        b'"namespace":"boutique","name":"c"}}\n',
        # A pod create -- not a pod exec/attach/portforward subresource.
        b'{"verb":"create","objectRef":{"apiGroup":"","resource":"pods",'
        b'"namespace":"boutique","name":"p"}}\n',
        # Controller churn the v1 policy dropped at Metadata level (ADR-064).
        b'{"verb":"update","objectRef":{"apiGroup":"coordination.k8s.io","resource":"leases",'
        b'"namespace":"kube-system","name":"l"}}\n',
        # serviceaccounts/token is a subresource, never in the v1 bare-serviceaccounts scope.
        b'{"verb":"create","objectRef":{"apiGroup":"","resource":"serviceaccounts",'
        b'"subresource":"token","namespace":"boutique","name":"sa"}}\n',
        # A read of a credential object -- in-scope resource but not a mutating verb.
        b'{"verb":"get","objectRef":{"apiGroup":"","resource":"secrets",'
        b'"namespace":"boutique","name":"s"}}\n',
    ]
    interleaved = [
        out_of_scope[0],
        in_scope[0],
        out_of_scope[1],
        out_of_scope[2],
        in_scope[1],
        out_of_scope[3],
        out_of_scope[4],
        in_scope[2],
        out_of_scope[5],
    ]
    stream = BytesIO(b"".join(interleaved))
    posted: list[bytes] = []

    def post(line: bytes, **_kwargs: object) -> None:
        posted.append(line)

    sent = forward_stream(stream, url="unused", severity="high", post=post, keep=in_v1_scope)
    assert sent == 3
    assert posted == in_scope


def test_audit_stream_retries_a_record_when_the_refusal_is_about_the_moment() -> None:
    """429 and 408 say "come back", not "this record is wrong", so the record is still owed."""
    stream = BytesIO(b'{"auditID":"one"}\n')

    def busy(_line: bytes, **_kwargs) -> None:
        raise urllib.error.HTTPError(
            "http://monitor/v1/k8s-audit", 429, "Too Many Requests", {}, None
        )

    with pytest.raises(urllib.error.HTTPError):
        forward_stream(stream, url="unused", severity="high", post=busy)
    assert stream.tell() == 0


class _StopForwarding(Exception):
    """Break the forwarder's otherwise-infinite poll loop from an injected ``sleep``."""


def test_run_primes_at_end_of_file_and_forwards_only_records_appended_after_start(
    tmp_path: Path,
) -> None:
    """ADR-063: the cumulative pre-run history is skipped; only lines appended after start go out.

    The forwarder is restarted at each run boundary and ``k8s_audit.jsonl`` is the cluster's single
    cumulative audit file, so re-posting it from byte 0 (the prior behaviour) buried the run's own
    records behind hours of backlog. Priming at end-of-file makes the first forwarded record the
    first one appended after start.
    """
    audit = tmp_path / "k8s_audit.jsonl"
    audit.write_bytes(b'{"auditID":"pre-1"}\n{"auditID":"pre-2"}\n')
    posted: list[bytes] = []

    def post(line: bytes, **_kwargs: object) -> None:
        posted.append(line)

    polls = {"n": 0}

    def sleep(_seconds: float) -> None:
        polls["n"] += 1
        if polls["n"] == 1:
            # The primed first pass has seen only end-of-file; now a fresh record is appended.
            with audit.open("ab") as handle:
                handle.write(b'{"auditID":"run-1"}\n')
        else:
            raise _StopForwarding

    with pytest.raises(_StopForwarding):
        run(audit, url="http://monitor/v1/k8s-audit", severity="high", sleep=sleep, post=post)

    assert posted == [b'{"auditID":"run-1"}\n']


def test_run_reads_a_rotated_file_from_the_beginning(tmp_path: Path) -> None:
    """A replacement (new device/inode identity) is a fresh file: read from 0, never re-primed."""
    audit = tmp_path / "k8s_audit.jsonl"
    audit.write_bytes(b'{"auditID":"pre-1"}\n{"auditID":"pre-2"}\n')
    posted: list[bytes] = []

    def post(line: bytes, **_kwargs: object) -> None:
        posted.append(line)

    polls = {"n": 0}

    def sleep(_seconds: float) -> None:
        polls["n"] += 1
        if polls["n"] == 1:
            replacement = tmp_path / "rotated.jsonl"
            replacement.write_bytes(b'{"auditID":"rotated-1"}\n')
            replacement.replace(audit)  # atomic rename: the path now resolves to a new inode
        else:
            raise _StopForwarding

    with pytest.raises(_StopForwarding):
        run(audit, url="http://monitor/v1/k8s-audit", severity="high", sleep=sleep, post=post)

    assert posted == [b'{"auditID":"rotated-1"}\n']


def test_run_rereads_from_zero_after_truncation(tmp_path: Path) -> None:
    """A truncation (size fell below the read position) is a fresh file: read from 0, never EOF."""
    audit = tmp_path / "k8s_audit.jsonl"
    audit.write_bytes(b'{"auditID":"pre-1"}\n{"auditID":"pre-2"}\n')
    posted: list[bytes] = []

    def post(line: bytes, **_kwargs: object) -> None:
        posted.append(line)

    polls = {"n": 0}

    def sleep(_seconds: float) -> None:
        polls["n"] += 1
        if polls["n"] == 1:
            # Rewrite shorter: the new size is below the primed end-of-file position, which is the
            # reopen trigger, and the replacement content must then be read from the beginning.
            audit.write_bytes(b'{"auditID":"fresh"}\n')
        else:
            raise _StopForwarding

    with pytest.raises(_StopForwarding):
        run(audit, url="http://monitor/v1/k8s-audit", severity="high", sleep=sleep, post=post)

    assert posted == [b'{"auditID":"fresh"}\n']


def test_trivy_uploader_posts_the_full_report_unchanged(tmp_path: Path) -> None:
    report = tmp_path / "trivy.json"
    body = b'{"SchemaVersion":2,"Results":[]}\n'
    report.write_bytes(body)
    captured: list[Request] = []

    def open_request(request: Request):
        captured.append(request)
        return Response(b"{}")

    upload_report(report, url="http://monitor/v1/trivy", urlopen=open_request)

    request = captured[0]
    assert request.method == "POST"
    assert request.full_url.endswith("/v1/trivy")
    assert request.data == body
    assert request.get_header("Content-type") == "application/json"


def test_trivy_uploader_rejects_empty_report(tmp_path: Path) -> None:
    report = tmp_path / "trivy.json"
    report.write_bytes(b"")
    with pytest.raises(ValueError, match="empty"):
        upload_report(report, url="http://monitor/v1/trivy")
