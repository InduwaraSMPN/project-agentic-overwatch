"""Runtime evidence producers for a live run: Monitor collation and Guardian audit extraction.

WHY THIS MODULE EXISTS
----------------------
``runner/live_run.py`` copies three runtime-owned files into the bundle and refuses to synthesise
any of them. Two of the three are not, on a live cluster, single files sitting where the runner can
read them, and this module is the seam that makes them so. It produces nothing: it *relocates* and
*orders* bytes that the Monitor and the Guardian already wrote.

1. ``monitor_events.jsonl``. The live aggregator (``monitor/http_service.py``) is a per-request
   transaction: each accepted POST writes its own ``monitor_events.jsonl`` under
   ``<MONITOR_DATA_DIR>/events/<source>/<sha256-of-the-request-body>/``. That layout is deliberate
   -- it makes ingestion idempotent and content-addressed -- but it means a run's Monitor evidence
   is a *tree of fragments*, not the single stream ``docs/protocols/data-management.md`` section 1
   puts in every bundle. :func:`collate_monitor_events` walks that tree and writes the one stream.

   The collation is not a concatenation. It re-imposes ADR-019's total emission order
   ``(source_ts, source_rank, event_id)`` over the union of the fragments, which is exactly the
   order ``monitor.aggregator.emit`` would have produced had every record arrived in one batch. The
   ordering key is recovered from the emitted JSON itself -- ``ts``, ``source`` and ``event_id`` are
   all fields of the frozen ``EvidenceEvent`` contract -- and ``source_rank`` is read from
   :data:`monitor.aggregator.normalize.SOURCE_REGISTRY` rather than restated here, so a registry
   reorder moves this file's output with it instead of silently disagreeing with the corpus.

   Lines are copied byte for byte. Nothing here re-serialises an event: a re-serialisation would
   put a second canonical-JSON implementation in the repository and the byte diff that
   ``make determinism-check`` rests on would then be testing two encoders against each other.

2. ``guardian_audit.jsonl``. The Guardian writes its hash-chained audit log to a PersistentVolume
   mounted at ``/var/lib/guardian/audit`` *inside its own pod*, and
   ``docs/protocols/security-policy.md`` section 1.2 is why it stays there: the Guardian is the sole
   holder of anything with cluster-mutation rights, and its audit log is the artefact whose custody
   that invariant is about. :func:`extract_guardian_audit` reads it out with the *operator's own*
   kubeconfig -- ``kubectl exec ... -- cat`` -- and never with the Guardian's ServiceAccount token,
   its signing key, or a copy of either. Nothing is written back into the pod.

3. One attempt, one Guardian chain. :func:`guardian_audit_chain_path` names the chain each
   Guardian deployment appends to, ``<audit volume>/<run-id>-<attempt suffix>.jsonl``, with the
   suffix from :func:`attempt_suffix` -- the same runtime token ADR-054 gives the Monitor archive.
   The runner draws it once per attempt when it applies the condition, hands the path to
   ``scripts/guardian_deploy.sh``, which requires it, and extracts exactly that path, so a retry of
   one canonical run id can never reopen, or copy, the failed attempt's chain (ADR-058).

WHY NOT A hostPath FOR THE GUARDIAN AUDIT LOG
---------------------------------------------
The Monitor's evidence directory is a hostPath (``infra/kind-config.yaml`` mounts the repository's
``monitor/runtime/evidence`` into both nodes) and mirroring that for the Guardian would be less
code than this function. It was rejected. A hostPath puts the audit log on a node path that any
other pod with a hostPath mount can also open, which turns the one file whose integrity argument is
"only the Guardian ever appended to it" into a file whose custody is a node-level convention. The
hash chain would still verify -- ``guardian/audit/verify.py`` would catch a rewrite -- but a
detection after the fact is a weaker property than the log never having left the Guardian's
volume, and section 1.2 asks for the stronger one. A read-only extraction performed by the
operator, at a point in the run the runner chooses, keeps the write side single-holder.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
Changing the collation key desynchronises live ``monitor_events.jsonl`` from every golden file in
``monitor/fixtures/``, and the drift would be invisible until a cross-check between a replayed
fixture and a live bundle. Reading the Guardian log by any route that needs the Guardian's own
credential violates ``.agents/rules/10-guardian-first.md``.
"""

from __future__ import annotations

import json
import os
import subprocess
import uuid
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Final

from monitor.aggregator.emit import EVENTS_FILENAME
from monitor.aggregator.normalize import SOURCE_REGISTRY

TIMINGS_FILENAME: Final = "monitor_timings.jsonl"

# The rank of each source family, read from the registry the emitter itself orders by. A dict
# comprehension rather than a written-out table: a fifth family added to the registry gets its rank
# here for free, and cannot get a different one.
_SOURCE_RANK: Final[dict[str, int]] = {entry.source.value: entry.rank for entry in SOURCE_REGISTRY}


# The Guardian's audit volume, as guardian/deploy/deployment.yaml mounts it. Every per-attempt chain
# lives directly on it, beside the replay store; scripts/guardian_deploy.sh refuses a chain anywhere
# else, and runner/tests/test_guardian_deploy.py holds the three spellings equal.
GUARDIAN_AUDIT_ROOT: Final = "/var/lib/guardian/audit"

# ADR-137: the API-server audit slice, k8s_api_audit.jsonl. The runner brackets the measurement
# window with two sentinel mutations so a slice taken from the wrong byte offset is provably empty
# of them (F-GD-06). A sentinel is an annotation patch on the `guardian` Deployment -- the
# framework's own object, present in every run, and a metadata-only annotation, so it starts no pod
# and triggers no rollout (F-GD-02 stays satisfied). The API server logs it at Request level (the
# deployments patch/update rule in infra/audit/audit-policy.yaml, whose own comment names this
# sentinel), so the annotation survives in the record's requestObject; collect_api_audit lifts it to
# the top-level `annotations` F-GD-06 reads. Run with the operator's kubeconfig, so its principal is
# kubernetes-admin, an expected principal (security-policy 2.1), which F-GD-03 attributes without a
# Guardian record. SENTINEL_ANNOTATION_KEY and SENTINEL_PHASES are held equal to the reader's
# (runner/fidelity/guardian.py) by runner/tests/test_api_audit.py; a mismatch would make F-GD-06
# look for a sentinel the writer never wrote.
SENTINEL_ANNOTATION_KEY: Final = "overwatch.io/window-sentinel"
SENTINEL_PHASES: Final[tuple[str, ...]] = ("open", "close")
_SENTINEL_TARGET_NAMESPACE: Final = "guardian"
_SENTINEL_TARGET: Final = "deployment/guardian"


class EvidenceProductionError(RuntimeError):
    """A runtime evidence producer could not deliver its file. Never recovered from silently."""


def attempt_suffix() -> str:
    """ADR-054's unique suffix: one fresh runtime token per use.

    A runtime identifier in the sense a ``jti`` is one, not a draw on a scenario path: nothing a run
    injects, orders or computes depends on its value, which is the line
    ``.agents/rules/20-parity-and-determinism.md`` draws. Its only job is that two attempts at one
    canonical run id -- a quarantined crash and its retry -- never share a path. The Monitor archive
    takes one at each window boundary; the Guardian's chain takes one per attempt, when the runner
    applies the condition (ADR-058).
    """
    return uuid.uuid4().hex


def guardian_audit_chain_path(audit_root: str, run_id: str, suffix: str) -> str:
    """One attempt's Guardian chain: ``<root>/<run-id>-<suffix>.jsonl`` (ADR-054, ADR-058)."""
    return f"{audit_root.rstrip('/')}/{run_id}-{suffix}.jsonl"


def begin_monitor_window(events_root: Path, run_id: str) -> Path | None:
    """Atomically archive the cumulative Monitor tree before one run starts."""
    if not events_root.exists():
        return None
    archive = events_root.parent / "archive" / f"{run_id}-pre-{attempt_suffix()}"
    archive.parent.mkdir(parents=True, exist_ok=True)
    os.replace(events_root, archive)
    return archive


def close_monitor_window(events_root: Path, run_id: str) -> Path:
    """Atomically detach the current run tree so concurrent later ingestion cannot enter it."""
    if not events_root.is_dir():
        raise EvidenceProductionError(f"aggregator event root is absent: {events_root}")
    closed = events_root.parent / "archive" / f"{run_id}-events-{attempt_suffix()}"
    closed.parent.mkdir(parents=True, exist_ok=True)
    os.replace(events_root, closed)
    return closed


def _ordering_key(line: bytes, origin: Path) -> tuple[datetime, int, str]:
    """Recover ADR-019's ``(source_ts, source_rank, event_id)`` from one emitted event line."""
    try:
        event = json.loads(line)
    except json.JSONDecodeError as error:
        raise EvidenceProductionError(f"{origin} holds a line that is not JSON: {error}") from error
    if not isinstance(event, dict):
        raise EvidenceProductionError(f"{origin} holds a line that is not a JSON object")
    try:
        timestamp = datetime.fromisoformat(str(event["ts"]))
        source = str(event["source"])
        event_id = str(event["event_id"])
    except (KeyError, ValueError) as error:
        raise EvidenceProductionError(
            f"{origin} holds a line that is not an EvidenceEvent: {error}"
        ) from error
    try:
        rank = _SOURCE_RANK[source]
    except KeyError:
        raise EvidenceProductionError(
            f"{origin} names source {source!r}, which is not in the aggregator's source registry"
        ) from None
    return (timestamp, rank, event_id)


#: The bundle field the epoch-drop count is recorded under. F-MN-02 (``runner/fidelity/monitor.py``)
#: reads it from ``metrics.json``; :func:`collate_monitor_events` writes it to a sidecar beside the
#: collated stream, and ``runner/live_run.py`` folds it into ``metrics.json`` at run end. The three
#: writers share the name, as ``k8s_api_audit.jsonl`` is shared (bundle.py), so none differs on it.
EPOCH_DROPS_FIELD: Final = "monitor_epoch_drops"
EPOCH_DROPS_FILENAME: Final = "monitor_epoch_drops.json"

#: The bundle field the audit forwarder's worst observed drain is recorded under. F-MN-04
#: (``runner/fidelity/monitor.py``) reads it from ``metrics.json``;
#: :func:`forwarder_drain_seconds` computes it from the two streams
#: :func:`collate_monitor_events` has just written, and ``runner/live_run.py`` folds it into
#: ``metrics.json`` at run end -- the same three-writer arrangement the epoch-drop field uses.
DRAIN_FIELD: Final = "monitor_forwarder_drain_seconds"

#: The one source the audit forwarder transports, and therefore the only one whose records can
#: measure its drain. A Falco record reaches the aggregator over the Falcosidekick webhook, an
#: Alertmanager record over its own receiver, and a Trivy report over the scan Job's upload -- none
#: of the three travels through ``monitor/audit_forwarder.py``, so folding their latency into this
#: number would report a property of a component F-MN-04 is not about.
_DRAIN_SOURCE: Final = "k8s_audit"


def forwarder_drain_seconds(events_path: Path, timings_path: Path) -> float | None:
    """The audit forwarder's worst observed drain, or ``None`` when nothing can measure it.

    A record's drain is the lag between its own timestamp -- for a ``k8s_audit`` record, when the
    API server wrote it -- and the ``emit_ts`` the aggregator stamped on the event it produced from
    it. ``monitor_timings.jsonl`` is where that second timestamp lives, so the two streams are
    joined on the ``event_id`` they already share rather than on a timestamp two records could
    collide on.

    ``None`` rather than ``0.0`` when no pair can be measured: a window that carried no forwarded
    record has not shown the forwarder to be fast, and reporting zero would be the
    fabricated-measurement shape D15's storage defect has (``runner/fidelity/analysis.py``). The
    caller decides what an unmeasured drain means; this function does not manufacture a number.
    """
    emitted: dict[str, datetime] = {}
    for line in timings_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            emitted[str(record["event_id"])] = datetime.fromisoformat(
                str(record["emit_ts"]).replace("Z", "+00:00")
            )
        except (json.JSONDecodeError, KeyError, ValueError) as error:
            raise EvidenceProductionError(
                f"{timings_path} holds a timing row that is not readable: {error}"
            ) from error

    worst: float | None = None
    for line in events_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        if str(event.get("source")) != _DRAIN_SOURCE:
            continue
        emit = emitted.get(str(event.get("event_id")))
        if emit is None:
            continue
        try:
            source_ts = datetime.fromisoformat(str(event["ts"]).replace("Z", "+00:00"))
        except (KeyError, ValueError) as error:
            raise EvidenceProductionError(
                f"{events_path} holds an event with no readable 'ts': {error}"
            ) from error
        drain = (emit - source_ts).total_seconds()
        if worst is None or drain > worst:
            worst = drain
    return worst


def collate_monitor_events(
    events_root: Path,
    destination: Path,
    *,
    started_at: datetime | None = None,
    ended_at: datetime | None = None,
    required_epoch: str | None = None,
) -> int:
    """Collate one run's per-transaction fragments under ``events_root`` into one stream.

    ``events_root`` is ``<MONITOR_DATA_DIR>/events`` as the live aggregator lays it out. Returns the
    number of events written. An absent root is an error rather than an empty file: a live run whose
    Monitor ingested nothing has not produced evidence, and an empty stream would let the bundle
    seal on the claim that it had.

    ``required_epoch`` (ADR-124, SEAM 4) is defence in depth beside the ``started_at`` filter: with
    it set, an event whose timing row names a ``config_epoch`` other than this run's -- a
    Falcosidekick redelivery into a new epoch, the path the ``ts`` filter alone cannot see -- is
    dropped along with its timing row, and the number dropped is written to a
    ``monitor_epoch_drops.json`` sidecar beside ``destination``. The live caller passes
    ``planned.run_id`` and folds the count into ``metrics.json``, where F-MN-02 reads it. ``None``
    (the replay and fixture paths) leaves the collation exactly as it was: no epoch filter, no
    sidecar.
    """
    if not events_root.is_dir():
        raise EvidenceProductionError(
            f"aggregator event root is absent: {events_root}. The evidence aggregator writes it on "
            "its first accepted ingestion; while /readyz reports not-ready it accepts none."
        )
    fragments = sorted(events_root.rglob(EVENTS_FILENAME))
    if not fragments:
        raise EvidenceProductionError(
            f"no {EVENTS_FILENAME} fragment exists under {events_root}; "
            "the Monitor ingested nothing"
        )

    by_event_id: dict[str, bytes] = {}
    keyed: list[tuple[tuple[datetime, int, str], bytes]] = []
    for fragment in fragments:
        for raw in fragment.read_bytes().splitlines():
            if not raw.strip():
                continue
            line = raw + b"\n"
            key = _ordering_key(line, fragment)
            if started_at is not None and key[0] < started_at:
                continue
            if ended_at is not None and key[0] > ended_at:
                raise EvidenceProductionError(
                    f"{fragment} contains event {key[2]} after export time {ended_at.isoformat()}"
                )
            event_id = key[2]
            previous = by_event_id.get(event_id)
            if previous is not None:
                previous_event = json.loads(previous)
                current_event = json.loads(line)
                previous_event.pop("raw_ref", None)
                current_event.pop("raw_ref", None)
                if previous_event != current_event:
                    raise EvidenceProductionError(
                        f"two logically different events share event_id {event_id} "
                        f"under {events_root}"
                    )
                # Repeated Alertmanager notifications have one event identity but different raw
                # locations. Keep one deterministically; the raw files remain available separately.
                by_event_id[event_id] = min(previous, line)
                continue
            by_event_id[event_id] = line

    # The timing rows are read BEFORE the events are written, because with an epoch filter the row's
    # config_epoch is what decides whether its event survives -- so the read that used to sit after
    # the event write now sits before it. Nothing else about the read changes: the same invalid-row
    # refusal, and the same keep-the-earliest-emit_ts dedup for a repeated notification.
    timing_by_event: dict[str, bytes] = {}
    for timing_file in sorted(events_root.rglob(TIMINGS_FILENAME)):
        for raw in timing_file.read_bytes().splitlines():
            if not raw.strip():
                continue
            try:
                record = json.loads(raw)
                event_id = str(record["event_id"])
                datetime.fromisoformat(str(record["emit_ts"]).replace("Z", "+00:00"))
            except (json.JSONDecodeError, KeyError, ValueError) as error:
                raise EvidenceProductionError(
                    f"{timing_file} holds an invalid timing record"
                ) from error
            line = raw + b"\n"
            previous = timing_by_event.get(event_id)
            if previous is None:
                timing_by_event[event_id] = line
            else:
                previous_ts = json.loads(previous)["emit_ts"]
                if str(record["emit_ts"]) < str(previous_ts):
                    timing_by_event[event_id] = line

    # ADR-124 / SEAM 4 epoch filter: an event whose timing row names a config_epoch other than this
    # run's is a stale-epoch event -- a redelivery into a later window -- and it is dropped with its
    # timing row before anything is written, so it can neither enter the stream nor be counted.
    # An event with NO timing row is left for the missing-timings refusal below, exactly as before;
    # only an event WITH a row that disagrees is dropped here. required_epoch of None (replay and
    # fixtures) skips the filter entirely.
    dropped = 0
    if required_epoch is not None:
        for event_id in list(by_event_id):
            timing = timing_by_event.get(event_id)
            if timing is None:
                continue
            config_epoch = json.loads(timing).get("config_epoch")
            if str(config_epoch or "") != required_epoch:
                del by_event_id[event_id]
                del timing_by_event[event_id]
                dropped += 1

    keyed = [(_ordering_key(line, events_root), line) for line in by_event_id.values()]
    keyed.sort(key=lambda item: item[0])
    destination.parent.mkdir(parents=True, exist_ok=True)
    pending = destination.with_suffix(destination.suffix + ".pending")
    pending.write_bytes(b"".join(line for _, line in keyed))
    pending.replace(destination)

    missing = sorted(set(by_event_id) - set(timing_by_event))
    if missing:
        raise EvidenceProductionError(f"Monitor timings missing event_id {missing[0]}")
    timing_destination = destination.with_name(TIMINGS_FILENAME)
    ordered_event_ids = [str(json.loads(line)["event_id"]) for _, line in keyed]
    timing_destination.write_bytes(
        b"".join(timing_by_event[event_id] for event_id in ordered_event_ids)
    )

    # Record the drop count for the caller to fold into metrics.json, where F-MN-02 reads it.
    # Written only when the filter ran, so the replay and fixture paths gain no new artefact and
    # keep byte-for-byte parity with the golden streams.
    if required_epoch is not None:
        drops_sidecar = destination.with_name(EPOCH_DROPS_FILENAME)
        drops_sidecar.write_text(
            json.dumps({EPOCH_DROPS_FIELD: dropped}, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    return len(keyed)


def extract_guardian_audit(
    destination: Path,
    *,
    namespace: str,
    workload: str,
    container: str,
    remote_path: str,
    kubeconfig: str | None = None,
    context: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> int:
    """Copy the Guardian's audit log out of its pod with the operator's own kubeconfig.

    Returns the number of bytes written. Uses ``kubectl exec -- cat`` rather than ``kubectl cp``:
    ``cp`` needs ``tar`` on the container's PATH and rewrites the path through an archive, while a
    single-file read needs neither. No credential belonging to the Guardian is read, copied or
    passed; the Guardian's own volume is never written to.
    """
    argv = ["kubectl"]
    if kubeconfig:
        argv += ["--kubeconfig", kubeconfig]
    if context:
        argv += ["--context", context]
    argv += ["-n", namespace, "exec", workload, "-c", container, "--", "cat", remote_path]
    result = subprocess.run(  # noqa: S603 - argv only, no shell
        argv,
        capture_output=True,
        check=False,
        env=None if environ is None else dict(environ),
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", "replace").strip() or f"exit {result.returncode}"
        raise EvidenceProductionError(
            f"guardian audit log is unreadable at {namespace}/{workload}:{remote_path}: {detail}"
        )
    if not result.stdout:
        raise EvidenceProductionError(
            f"guardian audit log at {namespace}/{workload}:{remote_path} is empty; the Guardian "
            "records a decision for every mediated action, so an empty log means none reached it"
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    pending = destination.with_suffix(destination.suffix + ".pending")
    pending.write_bytes(result.stdout)
    pending.replace(destination)
    return len(result.stdout)


def _kubectl_prefix(kubeconfig: str | None, context: str | None) -> list[str]:
    """The ``kubectl`` argv prefix carrying the operator's kubeconfig and context, or neither."""
    argv = ["kubectl"]
    if kubeconfig:
        argv += ["--kubeconfig", kubeconfig]
    if context:
        argv += ["--context", context]
    return argv


def api_audit_offset(audit_log: Path) -> int:
    """The API-server audit log's byte length at window-open, the start of the slice (ADR-137).

    The kube-apiserver audit log has no rotation (``infra/kind-config.yaml`` pins
    ``audit-log-maxbackup`` and ``audit-log-maxsize`` to 0), so a byte offset recorded when the
    window opens is a stable start for :func:`collect_api_audit` when it closes. An absent log is an
    error, not a zero offset: a framework-on run whose API server logged nothing has not produced
    the corroboration ``k8s_api_audit.jsonl`` is (F-GD-03/F-GD-06), and a zero offset over an absent
    file would let the bundle seal on an empty slice. On a running cluster the file always exists --
    the API server appends to it continuously -- so an ``OSError`` here is a misconfigured mount,
    which fails closed.
    """
    try:
        return audit_log.stat().st_size
    except OSError as error:
        raise EvidenceProductionError(
            f"API-server audit log is unavailable at {audit_log}: {error}. It is the bind-mounted "
            "audit-log-path from infra/kind-config.yaml; a framework-on run cannot corroborate its "
            "executions without it (ADR-137, defect V28)."
        ) from error


def write_api_audit_sentinel(
    phase: str,
    *,
    run_id: str,
    kubeconfig: str | None = None,
    context: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> None:
    """Make the window-``phase`` sentinel mutation (ADR-137, F-GD-06).

    An annotation patch on the ``guardian`` Deployment: metadata-only, so it starts no pod and
    triggers no rollout (F-GD-02 stays satisfied), but the API server logs it at Request level (the
    deployments patch rule in ``infra/audit/audit-policy.yaml``, whose comment names this sentinel),
    so the annotation survives in the record's ``requestObject`` for :func:`collect_api_audit` to
    lift. Run with the operator's own kubeconfig, so its principal is ``kubernetes-admin`` -- in the
    expected-principal set (``security-policy`` section 2.1) -- and F-GD-03 attributes it without a
    Guardian record. An explicit merge patch always carries both the phase and a per-call nonce.
    ``kubectl annotate`` computes a diff and omits an unchanged phase after an interrupted run;
    the nonce alone makes a mutation but leaves its phase absent from the audit request (ADR-176).
    """
    if phase not in SENTINEL_PHASES:
        raise EvidenceProductionError(f"unknown API-audit sentinel phase {phase!r}")
    base = _kubectl_prefix(kubeconfig, context)
    env = None if environ is None else dict(environ)
    nonce = f"{run_id}-{phase}-{uuid.uuid4().hex}"
    patch = json.dumps(
        {
            "metadata": {
                "annotations": {
                    SENTINEL_ANNOTATION_KEY: phase,
                    f"{SENTINEL_ANNOTATION_KEY}-nonce": nonce,
                }
            }
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    patched = subprocess.run(  # noqa: S603 - argv only, no shell
        [
            *base,
            "-n",
            _SENTINEL_TARGET_NAMESPACE,
            "patch",
            _SENTINEL_TARGET,
            "--type=merge",
            "-p",
            patch,
        ],
        capture_output=True,
        check=False,
        env=env,
    )
    if patched.returncode:
        detail = patched.stderr.decode("utf-8", "replace").strip() or f"exit {patched.returncode}"
        raise EvidenceProductionError(
            f"could not write the {phase} API-audit sentinel on "
            f"{_SENTINEL_TARGET_NAMESPACE}/{_SENTINEL_TARGET}: {detail}. Without both window "
            "sentinels the API-audit slice cannot prove its coverage (F-GD-06, ADR-137)."
        )


def _sentinel_phase_of(raw: bytes) -> str | None:
    """The sentinel phase an audit line records, or ``None`` when it is not a sentinel.

    Recognised by the sentinel annotation in the record's ``requestObject.metadata.annotations`` --
    the deployments patch rule logs the sentinel at Request level, so the annotation the writer set
    is in the request body. Reading it from there rather than from ``objectRef.name`` is what lets
    the sentinel ride on a normal Deployment (the ``guardian`` one) instead of a dedicated object.
    Anything unparseable, or any patch without the sentinel annotation, is not a sentinel;
    :func:`collect_api_audit` then copies it byte for byte, so a malformed line reaches the slice
    unchanged for the checks to judge.
    """
    try:
        record = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(record, Mapping):
        return None
    request_object = record.get("requestObject")
    if not isinstance(request_object, Mapping):
        return None
    metadata = request_object.get("metadata")
    annotations = metadata.get("annotations") if isinstance(metadata, Mapping) else None
    value = annotations.get(SENTINEL_ANNOTATION_KEY) if isinstance(annotations, Mapping) else None
    return value if isinstance(value, str) and value in SENTINEL_PHASES else None


def collect_api_audit(audit_log: Path, offset: int, destination: Path) -> int:
    """Slice the API-server audit log from ``offset`` to its end into ``destination`` (ADR-137).

    ``offset`` is :func:`api_audit_offset`'s reading at window-open; the tail is every audit
    ``Event`` the API server logged during the window -- the Guardian's executed mutations (which
    F-GD-03 matches to the Guardian chain), every other mutation (whose principal F-GD-03 requires
    in the expected set), and the two window sentinels. A non-sentinel line is copied byte for byte,
    so no second JSON encoder enters the corpus; a sentinel line (recognised by
    :func:`_sentinel_phase_of`) is the one exception -- its ``annotations`` gain the
    ``overwatch.io/window-sentinel`` key F-GD-06 reads, which the Metadata-level record did not
    carry. Returns the number of lines written.

    An absent log fails closed for the reason :func:`api_audit_offset` gives.
    """
    try:
        with audit_log.open("rb") as handle:
            handle.seek(offset)
            tail = handle.read()
    except OSError as error:
        raise EvidenceProductionError(
            f"API-server audit log is unreadable at {audit_log}: {error} (ADR-137)."
        ) from error
    out: list[bytes] = []
    for raw in tail.splitlines():
        if not raw.strip():
            continue
        phase = _sentinel_phase_of(raw)
        if phase is None:
            out.append(raw)
            continue
        record = json.loads(raw)
        annotations = dict(record.get("annotations") or {})
        annotations[SENTINEL_ANNOTATION_KEY] = phase
        record["annotations"] = annotations
        out.append(json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    destination.parent.mkdir(parents=True, exist_ok=True)
    pending = destination.with_suffix(destination.suffix + ".pending")
    pending.write_bytes(b"".join(line + b"\n" for line in out))
    pending.replace(destination)
    return len(out)
