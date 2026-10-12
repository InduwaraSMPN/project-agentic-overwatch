"""Tests for the two runtime evidence producers a live run needs.

The collation test that matters is the last one: a fixture's golden ``monitor_events.jsonl`` is the
byte-exact output of a single-batch emission, so scattering its lines across per-request fragments
and collating them back must reproduce that file byte for byte. If it does not, live bundles and the
replay corpus disagree about what a Monitor stream is, and nothing else in the tree would notice.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from runner.live_evidence import (
    DRAIN_FIELD,
    GUARDIAN_AUDIT_ROOT,
    EvidenceProductionError,
    attempt_suffix,
    begin_monitor_window,
    close_monitor_window,
    collate_monitor_events,
    extract_guardian_audit,
    forwarder_drain_seconds,
    guardian_audit_chain_path,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = REPO_ROOT / "monitor" / "fixtures"


def _fragment(root: Path, source: str, digest: str, lines: list[bytes]) -> None:
    directory = root / source / digest
    directory.mkdir(parents=True)
    (directory / "monitor_events.jsonl").write_bytes(b"".join(lines))
    timings = []
    for index, line in enumerate(lines):
        event_id = json.loads(line)["event_id"]
        timings.append(f'{{"emit_ts":"2026-08-26T10:31:{index:02d}Z","event_id":"{event_id}"}}\n')
    (directory / "monitor_timings.jsonl").write_text("".join(timings), encoding="utf-8")


def _event(event_id: str, source: str, ts: str) -> bytes:
    return (
        b'{"event_id":"'
        + event_id.encode()
        + b'","source":"'
        + source.encode()
        + b'","ts":"'
        + ts.encode()
        + b'"}\n'
    )


def test_begin_monitor_window_archives_existing_tree_atomically(tmp_path: Path) -> None:
    root = tmp_path / "events"
    _fragment(root, "falco", "aa", [_event("aaaa", "falco", "2026-08-26T10:30:00Z")])

    archive = begin_monitor_window(root, "RUN-G0-FULL-SCN-SIM-01-INJ-NONE-101")

    assert archive is not None and archive.is_dir()
    assert not root.exists()
    assert (archive / "falco" / "aa" / "monitor_events.jsonl").is_file()
    root.joinpath("falco", "bb").mkdir(parents=True)  # next ingestion recreates parents


def test_close_monitor_window_detaches_tree_before_collation(tmp_path: Path) -> None:
    root = tmp_path / "events"
    _fragment(root, "falco", "aa", [_event("aaaa", "falco", "2026-08-26T10:30:00Z")])
    closed = close_monitor_window(root, "RUN-G0-FULL-SCN-SIM-01-INJ-NONE-101")
    assert closed.is_dir()
    assert not root.exists()


def test_collation_filters_events_before_the_run_window(tmp_path: Path) -> None:
    root = tmp_path / "events"
    _fragment(
        root,
        "falco",
        "aa",
        [
            _event("old", "falco", "2026-08-26T10:29:59Z"),
            _event("current", "falco", "2026-08-26T10:30:01Z"),
        ],
    )
    from datetime import UTC, datetime

    destination = tmp_path / "monitor_events.jsonl"
    assert (
        collate_monitor_events(
            root,
            destination,
            started_at=datetime(2026, 8, 26, 10, 30, tzinfo=UTC),
        )
        == 1
    )
    assert b'"event_id":"current"' in destination.read_bytes()
    assert b'"event_id":"old"' not in destination.read_bytes()


def test_absent_root_is_an_error_not_an_empty_stream(tmp_path: Path) -> None:
    with pytest.raises(EvidenceProductionError, match="aggregator event root is absent"):
        collate_monitor_events(tmp_path / "events", tmp_path / "monitor_events.jsonl")


def test_empty_root_is_an_error(tmp_path: Path) -> None:
    (tmp_path / "events").mkdir()
    with pytest.raises(EvidenceProductionError, match="the Monitor ingested nothing"):
        collate_monitor_events(tmp_path / "events", tmp_path / "monitor_events.jsonl")


def test_fragments_collate_into_the_total_emission_order(tmp_path: Path) -> None:
    root = tmp_path / "events"
    # Written in an order that no filesystem walk would produce by accident: the trivy event is
    # earliest by timestamp, and the two falco events tie on timestamp so only rank and event_id
    # separate them from the prometheus one.
    _fragment(root, "prometheus", "dd", [_event("bbbb", "prometheus", "2026-08-26T10:30:00Z")])
    _fragment(
        root,
        "falco",
        "aa",
        [
            _event("cccc", "falco", "2026-08-26T10:30:00Z"),
            _event("aaaa", "falco", "2026-08-26T10:30:00Z"),
        ],
    )
    _fragment(root, "trivy", "cc", [_event("zzzz", "trivy", "2026-08-26T10:29:59.5Z")])

    written = collate_monitor_events(root, tmp_path / "monitor_events.jsonl")
    assert written == 4
    ids = [
        line.split(b'"')[3]
        for line in (tmp_path / "monitor_events.jsonl").read_bytes().splitlines()
    ]
    # trivy first on timestamp; then the two falco events (rank 0) before prometheus (rank 1);
    # event_id breaks the falco tie.
    assert ids == [b"zzzz", b"aaaa", b"cccc", b"bbbb"]


def test_repeated_logical_event_with_different_raw_ref_is_deduplicated(tmp_path: Path) -> None:
    root = tmp_path / "events"
    base = {
        "event_id": "aaaa",
        "source": "prometheus",
        "ts": "2026-08-26T10:30:00Z",
        "summary": "same alert",
    }
    first = (
        json.dumps({**base, "raw_ref": {"path": "a", "offset": 1, "length": 2}}).encode() + b"\n"
    )
    second = (
        json.dumps({**base, "raw_ref": {"path": "b", "offset": 3, "length": 4}}).encode() + b"\n"
    )
    _fragment(root, "prometheus", "aa", [first])
    _fragment(root, "prometheus", "bb", [second])
    assert collate_monitor_events(root, tmp_path / "monitor_events.jsonl") == 1


def test_a_repeated_fragment_is_dropped_and_a_conflicting_one_is_not(tmp_path: Path) -> None:
    root = tmp_path / "events"
    line = _event("aaaa", "falco", "2026-08-26T10:30:00Z")
    _fragment(root, "falco", "aa", [line])
    _fragment(root, "falco", "bb", [line])
    assert collate_monitor_events(root, tmp_path / "one.jsonl") == 1

    _fragment(root, "falco", "cc", [_event("aaaa", "falco", "2026-08-26T10:31:00Z")])
    with pytest.raises(EvidenceProductionError, match="share event_id"):
        collate_monitor_events(root, tmp_path / "two.jsonl")


def test_an_unknown_source_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "events"
    _fragment(root, "nessus", "aa", [_event("aaaa", "nessus", "2026-08-26T10:30:00Z")])
    with pytest.raises(EvidenceProductionError, match="not in the aggregator's source registry"):
        collate_monitor_events(root, tmp_path / "monitor_events.jsonl")


@pytest.mark.parametrize(
    "fixture", ["falco-shell-in-container", "four-source-incident", "trivy-image-report"]
)
def test_collation_reproduces_a_golden_stream_byte_for_byte(tmp_path: Path, fixture: str) -> None:
    """Scatter a golden stream one line per fragment; collating must rebuild it exactly."""
    golden = FIXTURE_ROOT / fixture / "expected" / "monitor_events.jsonl"
    lines = golden.read_bytes().splitlines(keepends=True)
    root = tmp_path / "events"
    for index, line in enumerate(reversed(lines)):
        # One fragment per line, in reverse emission order, under a directory name that sorts the
        # opposite way from the answer: only the ordering key can recover the golden sequence.
        _fragment(root, "scattered", f"{index:04d}", [line])
    assert collate_monitor_events(root, tmp_path / "monitor_events.jsonl") == len(lines)
    assert (tmp_path / "monitor_events.jsonl").read_bytes() == golden.read_bytes()


def _epoch_fragment(
    root: Path, source: str, digest: str, event_id: str, ts: str, epoch: str
) -> None:
    """One fragment whose timing row carries a ``config_epoch`` (SEAM 4), unlike ``_fragment``.

    The timing row is written compact (no spaces after separators), matching ``_fragment`` and the
    live aggregator, so the collated stream the collation copies byte-for-byte is the compact form.
    """
    directory = root / source / digest
    directory.mkdir(parents=True)
    (directory / "monitor_events.jsonl").write_bytes(_event(event_id, source, ts))
    (directory / "monitor_timings.jsonl").write_text(
        f'{{"emit_ts":"{ts}","event_id":"{event_id}","config_epoch":"{epoch}"}}\n',
        encoding="utf-8",
    )


def test_collate_drops_events_from_another_epoch(tmp_path: Path) -> None:
    """ADR-124 / SEAM 4: an event whose timing row names another run's epoch is dropped and counted.

    Defence beside the ``started_at`` filter: a Falcosidekick redelivery into a later window
    carries a within-window timestamp but the PREVIOUS run's ``config_epoch``, so only the epoch
    filter can exclude it. The dropped event leaves the stream AND its timing row; the drop count
    is recorded in the ``monitor_epoch_drops.json`` sidecar the live caller folds into metrics.json.
    """
    run_epoch = "RUN-G3-UNQUOTED-SCN-SIM-01-INJ-NONE-101"
    root = tmp_path / "events"
    _epoch_fragment(root, "falco", "aa", "mine", "2026-08-26T10:30:00Z", run_epoch)
    _epoch_fragment(root, "falco", "bb", "stale", "2026-08-26T10:30:01Z", "RUN-OLD-EPOCH-999")

    destination = tmp_path / "monitor_events.jsonl"
    written = collate_monitor_events(root, destination, required_epoch=run_epoch)

    assert written == 1
    events = destination.read_bytes()
    assert b'"event_id":"mine"' in events
    assert b'"event_id":"stale"' not in events
    # The dropped event's timing row is excluded too, so the two streams stay in lockstep.
    timings = destination.with_name("monitor_timings.jsonl").read_bytes()
    assert b'"event_id":"mine"' in timings
    assert b'"event_id":"stale"' not in timings
    # The drop count is recorded for the caller to fold into metrics.json (where F-MN-02 reads it).
    drops = json.loads(
        destination.with_name("monitor_epoch_drops.json").read_text(encoding="utf-8")
    )
    assert drops == {"monitor_epoch_drops": 1}


def test_collate_without_required_epoch_writes_no_drop_sidecar(tmp_path: Path) -> None:
    """The replay and fixture paths pass no epoch, so they gain no sidecar and drop nothing."""
    root = tmp_path / "events"
    _epoch_fragment(root, "falco", "aa", "mine", "2026-08-26T10:30:00Z", "RUN-OLD-EPOCH-999")
    destination = tmp_path / "monitor_events.jsonl"
    assert collate_monitor_events(root, destination) == 1
    assert b'"event_id":"mine"' in destination.read_bytes()
    assert not destination.with_name("monitor_epoch_drops.json").exists()


def test_guardian_audit_extraction_never_names_a_guardian_credential(tmp_path: Path) -> None:
    """A failed extraction reports where it looked, and the argv carries only operator config."""
    with pytest.raises(EvidenceProductionError, match="guardian audit log is unreadable"):
        extract_guardian_audit(
            tmp_path / "guardian_audit.jsonl",
            namespace="guardian",
            workload="deployment/guardian",
            container="guardian",
            remote_path="/var/lib/guardian/audit/guardian_audit.jsonl",
            kubeconfig=str(tmp_path / "absent-kubeconfig"),
            context="kind-kind",
        )


def test_every_attempt_draws_a_fresh_suffix() -> None:
    """ADR-054's token: distinct per draw, and hex, so it is safe inside a file name."""
    first, second = attempt_suffix(), attempt_suffix()
    assert first != second
    assert set(first + second) <= set("0123456789abcdef")


def test_a_retry_of_one_run_id_gets_a_chain_of_its_own() -> None:
    """Two attempts at one canonical run id: two chains, both on the audit volume, both its own."""
    run_id = "RUN-G0-FULL-SCN-SIM-01-INJ-NONE-102"
    first = guardian_audit_chain_path(GUARDIAN_AUDIT_ROOT, run_id, attempt_suffix())
    retry = guardian_audit_chain_path(f"{GUARDIAN_AUDIT_ROOT}/", run_id, attempt_suffix())
    assert first != retry
    for path in (first, retry):
        assert path.startswith(f"{GUARDIAN_AUDIT_ROOT}/{run_id}-")
        assert path.endswith(".jsonl")
        assert "//" not in path


# ============================================================ the forwarder drain (F-MN-04)


def _drain_bundle(tmp_path: Path, events: list[bytes], emits: list[str]) -> tuple[Path, Path]:
    """One bundle's two streams: the collated events and the timings that join to them."""
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    events_path = bundle / "monitor_events.jsonl"
    events_path.write_bytes(b"".join(events))
    timings_path = bundle / "monitor_timings.jsonl"
    timings_path.write_text(
        "".join(
            json.dumps(
                {
                    "config_epoch": "RUN-G0-FULL-SCN-SIM-01-INJ-NONE-101",
                    "emit_ts": emit,
                    "event_id": json.loads(line)["event_id"],
                },
                separators=(",", ":"),
            )
            + "\n"
            for line, emit in zip(events, emits, strict=True)
        ),
        encoding="utf-8",
    )
    return events_path, timings_path


def test_the_drain_is_the_worst_lag_over_the_forwarded_source(tmp_path: Path) -> None:
    """F-MN-04's number: the largest ``emit_ts - ts`` over the k8s_audit events, and only those.

    A Falco record arrives over the Falcosidekick webhook rather than through the audit forwarder,
    so its (much smaller) latency must not be allowed to stand in for the forwarder's. The fixture
    gives the falco record the LARGER lag on purpose: a predicate that folded every source together
    would return the falco number and this test would catch it.
    """
    events = [
        _event("aaaa", "k8s_audit", "2026-08-26T10:30:00Z"),
        _event("bbbb", "k8s_audit", "2026-08-26T10:30:04Z"),
        _event("cccc", "falco", "2026-08-26T10:30:00Z"),
    ]
    emits = [
        "2026-08-26T10:30:02Z",  # 2.0 s
        "2026-08-26T10:30:09Z",  # 5.0 s -- the worst
        "2026-08-26T10:31:00Z",  # 60 s, but not a forwarded record
    ]
    events_path, timings_path = _drain_bundle(tmp_path, events, emits)

    assert forwarder_drain_seconds(events_path, timings_path) == 5.0


def test_the_drain_is_absent_rather_than_zero_when_nothing_was_forwarded(tmp_path: Path) -> None:
    """A window with no forwarded record has measured nothing, and must not report 0.0.

    Reporting zero would be the fabricated-measurement shape D15's storage defect has: a number that
    reads as a measurement and is in fact an absence.
    """
    events = [_event("cccc", "falco", "2026-08-26T10:30:00Z")]
    events_path, timings_path = _drain_bundle(tmp_path, events, ["2026-08-26T10:30:01Z"])

    assert forwarder_drain_seconds(events_path, timings_path) is None


def test_the_drain_ignores_an_event_with_no_timing_row(tmp_path: Path) -> None:
    """An event the timings stream does not mention cannot be measured, and is skipped.

    The join is on ``event_id``; a missing row is an unmeasured record rather than a zero-second
    one, so it must not pull the worst-case down.
    """
    events = [
        _event("aaaa", "k8s_audit", "2026-08-26T10:30:00Z"),
        _event("bbbb", "k8s_audit", "2026-08-26T10:30:00Z"),
    ]
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    events_path = bundle / "monitor_events.jsonl"
    events_path.write_bytes(b"".join(events))
    timings_path = bundle / "monitor_timings.jsonl"
    timings_path.write_text(
        '{"config_epoch":"RUN-G0-FULL-SCN-SIM-01-INJ-NONE-101",'
        '"emit_ts":"2026-08-26T10:30:03Z","event_id":"aaaa"}\n',
        encoding="utf-8",
    )

    assert forwarder_drain_seconds(events_path, timings_path) == 3.0


def test_the_drain_field_name_is_the_one_the_check_reads() -> None:
    """The producer and the reader agree on the key, or the check skips a field nobody wrote."""
    from runner.fidelity.monitor import f_mn_04_forwarder_drains_within_the_protocol_bound

    assert DRAIN_FIELD == "monitor_forwarder_drain_seconds"
    assert DRAIN_FIELD in f_mn_04_forwarder_drains_within_the_protocol_bound.__doc__
