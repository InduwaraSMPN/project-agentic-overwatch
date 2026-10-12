"""Tail the kind control-plane audit JSONL file into the Monitor HTTP endpoint.

Kubernetes audit ``level`` is never read or translated: evidence severity must be supplied
explicitly through ``MONITOR_AUDIT_SEVERITY`` and is enforced by the receiving aggregator. The
transport is otherwise deterministic and non-LLM (rule 40); it opens no connection but the one POST
per forwarded record.

THE v1 AUDIT SCOPE FILTER (D16-A)
--------------------------------
At M10 the API-server audit policy (``infra/audit/audit-policy.yaml``) is widened so the API-plane
audit *bundle* can record the workload mutations the executed-action cross-check needs (V28, D1-A).
The Monitor, however, must keep seeing exactly what it saw in v1 -- no more -- or its input volume
and per-event latency, one synchronous POST per record (the ADR-064 bottleneck), would climb with
the widened policy and the campaign's Monitor measurements would no longer be comparable to v1's. So
this forwarder re-applies the v1 policy's own scope, in :func:`in_v1_scope`, **before** each POST:
only the records the v1 policy selected are forwarded, and every widened-policy addition is dropped
before it costs the forwarder a request. The scope is mirrored from the v1 rules of
``infra/audit/audit-policy.yaml`` -- RBAC and secret/ServiceAccount mutations, and pod
exec/attach/port-forward creates -- and ``monitor/tests/test_live_forwarders.py`` checks the mirror
against representative records. The filter reads ``verb`` and ``objectRef`` only; it still never
reads ``level``.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import BinaryIO, Final

AUDIT_PATH_ENV: Final = "MONITOR_AUDIT_PATH"
AUDIT_SEVERITY_ENV: Final = "MONITOR_AUDIT_SEVERITY"
AUDIT_URL_ENV: Final = "MONITOR_AUDIT_URL"
DEFAULT_AUDIT_PATH: Final = "/var/lib/overwatch/evidence/k8s_audit.jsonl"
DEFAULT_AUDIT_URL: Final = "http://evidence-aggregator.monitor.svc.cluster.local:8080/v1/k8s-audit"
VALID_SEVERITIES: Final = frozenset({"critical", "high", "medium", "low", "info"})
# 4xx statuses that are about the moment rather than the record: the aggregator is asking the
# caller to come back, so the record is still owed and is retried. Every other 4xx is a refusal of
# that record's bytes, which no amount of retrying changes.
RETRYABLE_STATUSES: Final = frozenset({408, 429})

# The v1 audit scope, mirrored from infra/audit/audit-policy.yaml's v1 rules (D16-A). Kept here as
# data rather than parsed from the policy file at run time for two reasons: the policy file is
# widened at M10 (V28/D1-A), so parsing the *live* file would track the widening this filter exists
# to undo; and a small explicit table is what monitor/tests/test_live_forwarders.py can mirror-check
# against representative records. If the v1 rules these mirror are ever changed, this table and that
# test change together.
#
# The v1 policy recorded, at RequestResponse level, the mutating verbs on RBAC and credential
# objects:
_V1_MUTATION_VERBS: Final = frozenset({"create", "update", "patch", "delete", "deletecollection"})
_V1_REQUEST_RESPONSE_RESOURCES: Final = frozenset(
    {
        ("rbac.authorization.k8s.io", "clusterrolebindings"),
        ("rbac.authorization.k8s.io", "rolebindings"),
        ("rbac.authorization.k8s.io", "clusterroles"),
        ("rbac.authorization.k8s.io", "roles"),
        ("", "secrets"),
        ("", "serviceaccounts"),
    }
)
# and, at Request level, the create of a pod exec/attach/port-forward subresource:
_V1_POD_SUBRESOURCE_CREATES: Final = frozenset({"exec", "attach", "portforward"})


def in_v1_scope(line: bytes) -> bool:
    """Return whether one audit record is inside the v1 audit-policy scope (D16-A).

    Mirrors the v1 rules of ``infra/audit/audit-policy.yaml``: the mutating verbs on RBAC and
    secret/ServiceAccount objects, and the create of a pod ``exec``/``attach``/``portforward``
    subresource. Everything else -- including every mutation the widened M10 policy adds, and the
    runner's sentinel annotations -- is out of scope and returns ``False`` so it is dropped before
    it
    costs a POST.

    Reads ``verb`` and ``objectRef`` only; ``level`` is never read, exactly as before. A record that
    is not JSON, or not a JSON object, is out of scope: the API server writes well-formed audit
    Events, so a malformed line is not something the v1 policy would have produced, and it is
    dropped
    here rather than posted for the aggregator to reject.
    """
    try:
        record = json.loads(line)
    except (ValueError, TypeError):
        return False
    if not isinstance(record, dict):
        return False
    verb = record.get("verb")
    object_ref = record.get("objectRef")
    object_ref = object_ref if isinstance(object_ref, dict) else {}
    resource = object_ref.get("resource")
    subresource = object_ref.get("subresource")
    group = object_ref.get("apiGroup")
    group = group if isinstance(group, str) else ""
    # A pod exec/attach/port-forward is a subresource create -- objectRef.resource is "pods" and
    # objectRef.subresource names the channel. Request level in v1, create only.
    if group == "" and resource == "pods" and subresource in _V1_POD_SUBRESOURCE_CREATES:
        return verb == "create"
    # RBAC and credential-object writes on the bare resource (no subresource --
    # serviceaccounts/token
    # was never in the v1 scope). RequestResponse level in v1, the five mutating verbs.
    if not subresource and (group, resource) in _V1_REQUEST_RESPONSE_RESOURCES:
        return verb in _V1_MUTATION_VERBS
    return False


def _keep_all(_line: bytes) -> bool:
    """The permissive default filter: forward every complete record.

    ``forward_stream`` and ``run`` default to this so the streaming-mechanics tests exercise line
    framing, rewind and rotation without every synthetic record having to be in the v1 scope. The
    production entry point :func:`main` passes :func:`in_v1_scope` instead, so a live forwarder
    always
    applies the scope; the injection point mirrors the ``post`` parameter's.
    """
    return True


def configured_severity(environ: Mapping[str, str]) -> str:
    """Return an explicit evidence severity, refusing absence and audit verbosity names."""
    severity = environ.get(AUDIT_SEVERITY_ENV, "").strip().lower()
    if severity not in VALID_SEVERITIES:
        allowed = ", ".join(sorted(VALID_SEVERITIES))
        raise ValueError(f"{AUDIT_SEVERITY_ENV} must be explicitly set to one of: {allowed}")
    return severity


def post_line(
    line: bytes,
    *,
    url: str,
    severity: str,
    urlopen: Callable[..., BinaryIO] = urllib.request.urlopen,
) -> None:
    """Post one complete audit record; ``severity`` is explicit and never derived from its body."""
    if not line.endswith(b"\n"):
        raise ValueError("audit record is not newline-terminated")
    if urllib.parse.urlsplit(url).scheme not in {"http", "https"}:
        raise ValueError("audit endpoint must use http or https")
    request = urllib.request.Request(  # noqa: S310 - scheme allowlisted above
        url,
        data=line,
        headers={
            "Content-Type": "application/x-ndjson",
            "X-Monitor-Audit-Severity": severity,
        },
        method="POST",
    )
    with urlopen(request) as response:
        response.read()


def _rejection_detail(rejection: urllib.error.HTTPError) -> str:
    """The aggregator's own reason for refusing a record, for the operator log. Never raises."""
    try:
        return rejection.read()[:200].decode("utf-8", "replace").strip() or rejection.reason
    except Exception:  # noqa: BLE001 - a diagnostic must not mask the rejection it describes
        return str(rejection.reason)


def forward_stream(
    stream: BinaryIO,
    *,
    url: str,
    severity: str,
    post: Callable[..., None] = post_line,
    keep: Callable[[bytes], bool] = _keep_all,
) -> int:
    """Forward every complete, in-scope line currently available, leaving a partial final line
    unread.

    Returns the number of records delivered. ``keep`` decides whether a complete record is in scope
    before it is posted (D16-A): the production caller passes :func:`in_v1_scope`, so a
    widened-policy
    record is dropped before it costs a POST, while the default forwards everything so the mechanics
    tests need not make every synthetic record in-scope. A dropped record is not owed to the
    aggregator and is not reported per-record: out-of-scope records are the expected, high-volume
    case the filter exists for, so a stderr line each would drown the log the rejection branch
    writes
    to. Records the aggregator refuses outright are skipped and reported on stderr rather than
    retried
    forever; see the rejection branch below.
    """
    sent = 0
    rejected = 0
    dropped = 0
    while True:
        position = stream.tell()
        line = stream.readline()
        if not line:
            return sent
        if not line.endswith(b"\n"):
            stream.seek(position)
            return sent
        if not keep(line):
            # Out of the v1 scope: drop it. readline has already advanced past it, which is correct
            # -- a dropped record is never reprocessed and never rewound to.
            dropped += 1
            continue
        try:
            post(line, url=url, severity=severity)
        except urllib.error.HTTPError as rejection:
            # A record the aggregator refuses on its own terms is refused identically forever, so
            # rewinding to it stops the stream at that byte: one malformed record would silently end
            # API-plane evidence for the rest of a campaign, which is what happened on 2026-09-12
            # (one interleaved line in 48,738 stalled ingestion for hours). The line is reported
            # and skipped -- never rewritten, never repaired -- so a reader of the log can see that
            # evidence was dropped rather than delivered. A transient status is not a refusal of
            # the record and still rewinds below.
            if rejection.code in RETRYABLE_STATUSES or not 400 <= rejection.code < 500:
                stream.seek(position)
                raise
            detail = _rejection_detail(rejection)
            print(
                f"audit-forwarder: skipping record the aggregator rejected "
                f"(HTTP {rejection.code}): {detail}",
                file=sys.stderr,
            )
            rejected += 1
            continue
        except Exception:
            stream.seek(position)
            raise
        sent += 1


def run(
    path: Path,
    *,
    url: str,
    severity: str,
    sleep: Callable[[float], None] = time.sleep,
    post: Callable[..., None] = post_line,
    keep: Callable[[bytes], bool] = _keep_all,
) -> None:
    """Follow the audit file from end-of-file on startup, reopening after rotation or replacement.

    On the first open in this process the stream is positioned at end-of-file, so only records
    appended after the forwarder starts are forwarded. ``k8s_audit.jsonl`` is the apiserver's single
    cumulative audit file for the cluster's whole life, and the runner restarts this forwarder at
    each run boundary (ADR-054's ``begin_monitor_window``); starting at end-of-file aligns the
    forwarded stream with that per-run window and skips the pre-run backlog. Nothing is lost by
    doing so: ``runner/live_evidence.collate_monitor_events`` discards every record timestamped
    before the window start anyway, so the skipped history is exactly what collation would drop --
    while re-posting it from byte 0, after a cluster restart, once took long enough that the run's
    own records at the file tail were never reached before the window closed (ADR-063).

    Priming happens only on that first open. A rotation or replacement (the file's device/inode
    identity changed) or a truncation (``st_size`` fell below the read position) is a fresh file and
    is reopened and read from position 0, never re-primed to end-of-file.
    """
    identity: tuple[int, int] | None = None
    position: int | None = None
    while True:
        try:
            # Reopen on every poll so Windows log rotation is not blocked by our read handle. The
            # saved identity and position preserve tail semantics without keeping the file locked.
            with path.open("rb") as stream:
                stat = os.fstat(stream.fileno())
                current_identity = (stat.st_dev, stat.st_ino)
                if position is None:
                    stream.seek(0, os.SEEK_END)
                elif identity == current_identity and stat.st_size >= position:
                    stream.seek(position)
                try:
                    forward_stream(stream, url=url, severity=severity, post=post, keep=keep)
                finally:
                    identity = current_identity
                    position = stream.tell()
        except (FileNotFoundError, urllib.error.URLError, OSError) as failure:
            print(f"audit-forwarder: {failure}", file=sys.stderr)
        sleep(1.0)


def main() -> int:
    try:
        severity = configured_severity(os.environ)
    except ValueError as failure:
        print(f"audit-forwarder: {failure}", file=sys.stderr)
        return 2
    run(
        Path(os.environ.get(AUDIT_PATH_ENV, DEFAULT_AUDIT_PATH)),
        url=os.environ.get(AUDIT_URL_ENV, DEFAULT_AUDIT_URL),
        severity=severity,
        # Production always applies the v1 audit scope (D16-A), so the widened M10 policy does not
        # raise the Monitor's input volume or per-record latency above v1's.
        keep=in_v1_scope,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
