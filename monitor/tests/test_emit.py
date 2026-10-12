"""Emission: the pipeline order, the total emission order, the output bytes, and latency.json.

WHAT THIS FILE IS PROVING
-------------------------
**That the output bytes are a function of the input and of nothing else.** The determinism proof for
the milestone is ``cmp`` over a fixture corpus (T2.7a); this file proves the same property at unit
scale, over inputs written as literals, so that a regression is localised to a module rather than to
"the corpus changed". Two runs of the same aggregation over the same bytes must produce the same
bytes, and the assertions below compare them directly rather than comparing parsed objects -- a
parsed comparison would pass while key order, separators or the line terminator drifted.

**That the pipeline runs in ADR-019's order.** Capping happens on source text and quoting happens
last. The test that catches a reordering is the one comparing excerpt counts and source-text lengths
across the two G3 arms: escaping lengthens text, so a cap applied after it would truncate the quoted
arm harder and the two arms would stop carrying the same evidence.
``monitor/tests/test_g3_isolation.py`` states that condition over the fixture corpus; this file
states it over literals, so it is covered before the corpus exists.

**That no wall-clock number reaches the event stream.** One such field would make the twice-and-diff
unpassable forever, and it would present as a flaky test rather than as a design error.

WHY THE CLOCK IS A LIST INDEX AND NOT A REAL COUNTER
------------------------------------------------------
``emit.py`` takes an injected nanosecond counter because nothing under ``monitor/aggregator/`` may
read one -- the module docstring there sets out why that is a design decision rather than a way
around ``scripts/monitor_guard.sh`` block (b). This file supplies a counter that returns successive
values from a fixed sequence, which makes the latency figures **exact and asserted** rather than
merely present: a real counter would let this file assert only that a number appeared, and a test
that asserts a number appeared is a test that a hard-coded zero would also pass.

WHAT THIS FILE MAY IMPORT
-------------------------
The standard library, pytest and pydantic, and nothing else. No cluster, no network, no clock, no
fixture on disk beyond the temporary directories pytest itself provides.
"""

import json
import sys
from dataclasses import fields
from inspect import signature
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# quoting.py lands at T2.6 and emit.py imports it lazily so that the aggregator stays importable in
# between. If it is absent, every test here would fail for one reason, so the module skips with that
# reason stated once instead of reporting it a dozen times.
pytest.importorskip(
    "monitor.aggregator.quoting",
    reason="emission applies quoting last; monitor/aggregator/quoting.py lands at M2-T2.6",
)

from monitor.aggregator import emit as emit_module  # noqa: E402
from monitor.aggregator import limits as protocol_limits  # noqa: E402
from monitor.aggregator.caps import CapLimits  # noqa: E402
from monitor.aggregator.emit import (  # noqa: E402
    EVENTS_FILENAME,
    LATENCY_FILENAME,
    EmitConfig,
    FixtureInputError,
    SourceInput,
    _latency_document,
    _percentile,
    emit,
    replay_fixture,
)
from monitor.aggregator.models import (  # noqa: E402
    SCHEMA_VERSION,
    EvidenceSeverity,
    EvidenceSource,
    canonical_json_line,
)
from monitor.aggregator.normalize import SOURCE_REGISTRY, registry_entry  # noqa: E402
from monitor.aggregator.quoting import unquote  # noqa: E402
from monitor.aggregator.sources import NormaliserOptions  # noqa: E402
from monitor.tests.test_normalizers import (  # noqa: E402
    AUDIT_RECORD,
    FALCO_RECORD,
    PROMETHEUS_ALERT,
    TRIVY_VULNERABILITY,
)

# Small, artificial, and not round -- the same test parameters test_caps.py uses, for the same
# reason. They are fixture-corpus parameters and are never evidence about section 4's caps row.
LIMITS = CapLimits(
    evidence_excerpt_count_max=3,
    evidence_excerpt_length_max_chars=40,
    summary_length_max_chars=60,
)

AUDIT_OPTIONS = NormaliserOptions(audit_severity=EvidenceSeverity.HIGH)


class SequenceClock:
    """A nanosecond counter that returns successive values from a fixed list.

    Deterministic by construction, which is what lets the latency assertions below check exact
    figures. It raises rather than repeating its last value when it runs out, so a change to the
    number of readings ``emit`` takes fails here loudly instead of silently reusing a value.
    """

    def __init__(self, values: list[int]) -> None:
        self._values = list(values)
        self.calls = 0

    def __call__(self) -> int:
        if self.calls >= len(self._values):
            raise AssertionError(
                f"the counter was called {self.calls + 1} times but only "
                f"{len(self._values)} readings were supplied"
            )
        value = self._values[self.calls]
        self.calls += 1
        return value


def write_fixture(directory: Path, *, sources: tuple[str, ...] = ("falco",)) -> Path:
    """Write a minimal fixture directory holding one record for each named source.

    Written in **binary** with explicit LF terminators, because a text-mode write on this host would
    put CRLF into the input and the byte offsets in ``raw_ref`` would then describe a file that no
    other machine would produce.
    """
    directory.mkdir(parents=True, exist_ok=True)
    if "falco" in sources:
        (directory / "falco.jsonl").write_bytes(json.dumps(FALCO_RECORD).encode("utf-8") + b"\n")
    if "prometheus" in sources:
        payload = {"version": "4", "status": "firing", "alerts": [PROMETHEUS_ALERT]}
        (directory / "prometheus.json").write_bytes(json.dumps(payload).encode("utf-8"))
    if "k8s_audit" in sources:
        (directory / "k8s_audit.jsonl").write_bytes(
            json.dumps(AUDIT_RECORD).encode("utf-8") + b"\n"
        )
    if "trivy" in sources:
        report = {
            "SchemaVersion": 2,
            "CreatedAt": "2026-08-26T10:33:00Z",
            "ArtifactName": "docker.io/library/vulnerable-app:1.0",
            "ArtifactType": "container_image",
            "Results": [
                {
                    "Target": "docker.io/library/vulnerable-app:1.0 (alpine 3.15.0)",
                    "Class": "os-pkgs",
                    "Type": "alpine",
                    "Vulnerabilities": [TRIVY_VULNERABILITY],
                }
            ],
        }
        (directory / "trivy.json").write_bytes(json.dumps(report).encode("utf-8"))
    return directory


def run(
    fixture: Path,
    out_dir: Path,
    *,
    quoting_enabled: bool = True,
    clock: SequenceClock | None = None,
) -> Any:
    """Replay ``fixture`` into ``out_dir`` through the same path the command line takes."""
    from monitor.aggregator.emit import read_fixture_inputs

    inputs = read_fixture_inputs(fixture, raw_root=fixture.parent)
    return emit(
        inputs,
        out_dir=out_dir,
        config=EmitConfig(quoting_enabled=quoting_enabled, cap_limits=LIMITS),
        options=AUDIT_OPTIONS,
        clock=clock,
    )


# --- the emitted stream --------------------------------------------------------------------------


def test_the_stream_is_canonical_json_lines_terminated_with_lf_and_no_carriage_return(
    tmp_path: Path,
) -> None:
    """One JSON object per line, ASCII, no incidental whitespace, LF only.

    The carriage-return assertion is not pedantry. A text-mode write on Windows would translate
    every terminator, and the resulting bundle would differ from one produced under WSL2 in every
    single line while looking identical in every editor.
    """
    fixture = write_fixture(tmp_path / "fx", sources=("falco", "prometheus", "k8s_audit", "trivy"))
    result = run(fixture, tmp_path / "out")
    data = result.events_path.read_bytes()

    assert b"\r" not in data
    assert data.endswith(b"\n")
    lines = data.split(b"\n")[:-1]
    assert len(lines) == 4
    for line, event in zip(lines, result.events, strict=True):
        assert all(byte < 128 for byte in line)
        # Canonicality is asserted by re-serialising the event and comparing bytes, rather than by
        # looking for ", " and ": " in the line: those sequences occur legitimately inside string
        # values -- a Falco output line is full of them -- so a textual search would be checking
        # the evidence rather than the separators.
        assert canonical_json_line(event) == line + b"\n"
        assert json.loads(line.decode("ascii"))["schema_version"] == SCHEMA_VERSION


def test_no_field_of_any_event_carries_a_latency_or_a_clock_reading(tmp_path: Path) -> None:
    """The event stream has nine fields and none of them is wall-clock-derived.

    One such field makes the byte diff unpassable forever, so the assertion is over the field set
    rather than over a particular name somebody might choose.
    """
    fixture = write_fixture(tmp_path / "fx", sources=("falco",))
    result = run(fixture, tmp_path / "out", clock=SequenceClock(list(range(0, 100, 7))))
    for event in result.events:
        keys = set(event.model_dump().keys())
        assert not any("latency" in key or "elapsed" in key or "emit" in key for key in keys)
    assert "latency" not in result.events_path.read_bytes().decode("ascii")


def test_two_runs_over_the_same_input_produce_identical_bytes(tmp_path: Path) -> None:
    """The unit-scale form of the milestone's ``cmp``. Bytes, not parsed objects."""
    fixture = write_fixture(tmp_path / "fx", sources=("falco", "prometheus", "k8s_audit", "trivy"))
    first = run(fixture, tmp_path / "out-1").events_path.read_bytes()
    second = run(fixture, tmp_path / "out-2").events_path.read_bytes()
    assert first == second


def test_a_run_with_a_counter_and_one_without_produce_identical_bytes(tmp_path: Path) -> None:
    """Measuring must not change what is measured.

    If supplying a counter changed the stream, the latency instrument would be perturbing the
    artefact it exists to characterise -- and the determinism check and the replay would then have
    to be run identically configured forever, which nothing enforces.
    """
    fixture = write_fixture(tmp_path / "fx", sources=("falco", "trivy"))
    untimed = run(fixture, tmp_path / "out-1").events_path.read_bytes()
    timed = run(
        fixture, tmp_path / "out-2", clock=SequenceClock(list(range(0, 1000, 11)))
    ).events_path.read_bytes()
    assert untimed == timed


def test_events_are_emitted_in_timestamp_then_rank_then_id_order(tmp_path: Path) -> None:
    """The explicit total order, over four sources whose fixture timestamps are minutes apart."""
    fixture = write_fixture(tmp_path / "fx", sources=("falco", "prometheus", "k8s_audit", "trivy"))
    result = run(fixture, tmp_path / "out")
    timestamps = [event.ts for event in result.events]
    assert timestamps == sorted(timestamps)
    assert [str(event.source) for event in result.events] == [
        "falco",
        "prometheus",
        "k8s_audit",
        "trivy",
    ]


def test_raw_ref_is_root_relative_and_resolves_to_the_source_record(tmp_path: Path) -> None:
    """An absolute pointer would encode the host; an unresolvable one would prove nothing."""
    fixture = write_fixture(tmp_path / "fx", sources=("falco", "prometheus"))
    result = run(fixture, tmp_path / "out")
    for event in result.events:
        assert not event.raw_ref.path.startswith("/")
        assert ":" not in event.raw_ref.path
        assert event.raw_ref.path.startswith("fx/")
        source_bytes = (fixture.parent / event.raw_ref.path).read_bytes()
        sliced = source_bytes[event.raw_ref.offset : event.raw_ref.offset + event.raw_ref.length]
        assert isinstance(json.loads(sliced.decode("utf-8")), dict)


# --- the pipeline order --------------------------------------------------------------------------


def test_caps_are_applied_to_source_text_and_quoting_comes_last(tmp_path: Path) -> None:
    """Both arms carry identical excerpt counts and identical source-text lengths.

    This is the assertion that fails if anyone reorders the pipeline. Quoting lengthens text, so a
    cap applied after it would truncate the quoted arm harder, and the flag would then change how
    much evidence reaches the Orchestrator as well as how it is escaped -- two properties where
    section 3.5.4 permits one.
    """
    fixture = write_fixture(tmp_path / "fx", sources=("falco", "prometheus", "k8s_audit", "trivy"))
    quoted = run(fixture, tmp_path / "on", quoting_enabled=True).events
    unquoted = run(fixture, tmp_path / "off", quoting_enabled=False).events

    assert len(quoted) == len(unquoted)
    for on, off in zip(quoted, unquoted, strict=True):
        assert on.event_id == off.event_id
        assert len(on.evidence_excerpts) == len(off.evidence_excerpts)
        assert unquote(on.summary) == off.summary
        for excerpt_on, excerpt_off in zip(
            on.evidence_excerpts, off.evidence_excerpts, strict=True
        ):
            assert unquote(excerpt_on) == excerpt_off
            assert len(excerpt_off) <= LIMITS.evidence_excerpt_length_max_chars
        assert len(off.summary) <= LIMITS.summary_length_max_chars
        assert len(off.evidence_excerpts) <= LIMITS.evidence_excerpt_count_max


def test_the_identifier_does_not_change_between_the_two_arms(tmp_path: Path) -> None:
    """The projection is over pre-quoting text, so the one field that must be stable is."""
    fixture = write_fixture(tmp_path / "fx", sources=("falco", "trivy"))
    quoted = run(fixture, tmp_path / "on", quoting_enabled=True).events
    unquoted = run(fixture, tmp_path / "off", quoting_enabled=False).events
    assert [e.event_id for e in quoted] == [e.event_id for e in unquoted]


# --- latency.json --------------------------------------------------------------------------------


def test_latency_is_written_to_its_own_file_and_never_to_the_stream(tmp_path: Path) -> None:
    """Two files, and the diffed one carries none of the wall-clock content."""
    fixture = write_fixture(tmp_path / "fx", sources=("falco",))
    result = run(fixture, tmp_path / "out")
    assert result.events_path.name == EVENTS_FILENAME
    assert result.latency_path.name == LATENCY_FILENAME
    assert result.latency_path.is_file()
    assert result.latency_path.read_bytes().count(b"\r") == 0


def test_without_a_counter_the_document_says_so_rather_than_recording_a_zero(
    tmp_path: Path,
) -> None:
    """A zero is a number and would be read as one. ``measured: false`` cannot be."""
    fixture = write_fixture(tmp_path / "fx", sources=("falco",))
    result = run(fixture, tmp_path / "out")
    document = json.loads(result.latency_path.read_text(encoding="ascii"))
    assert document["measurement"]["measured"] is False
    assert document["per_event_processing_ms"] is None
    assert document["batch_ordering_ms"] is None
    assert "reason" in document["measurement"]
    assert document["event_count"] == 1


def test_with_a_counter_the_figures_are_exact(tmp_path: Path) -> None:
    """The injected counter is a fixed sequence, so the reported figures are asserted, not sampled.

    Two one-record source inputs require two readings around each record, two balanced readings for
    each iterator's exhaustion, two around batch ordering, and two per event around emission --
    fourteen readings in a fixed order. Asserting the call count as well as the figures means that a
    change to *what* is measured shows up here rather than silently redefining the budget-bearing
    quantity.
    """
    fixture = write_fixture(tmp_path / "fx", sources=("falco", "trivy"))
    clock = SequenceClock([0, 5, 6, 7, 10, 25, 26, 27, 100, 103, 200, 260, 300, 330])
    result = run(fixture, tmp_path / "out", clock=clock)
    document = json.loads(result.latency_path.read_text(encoding="ascii"))

    assert clock.calls == 14
    assert document["measurement"]["measured"] is True
    assert document["batch_ordering_ms"] == pytest.approx(3 / 1_000_000)
    per_event = document["per_event_processing_ms"]
    assert per_event["count"] == 2
    # falco: 5 ns locating/normalising + 60 ns emitting; trivy: 15 ns + 30 ns.
    assert per_event["max"] == pytest.approx(65 / 1_000_000)
    assert per_event["min"] == pytest.approx(45 / 1_000_000)
    assert per_event["total"] == pytest.approx(110 / 1_000_000)


def test_counter_wraps_record_parsing_and_location(tmp_path: Path, monkeypatch) -> None:
    """The first per-event interval starts before advancing the lazy record reader."""
    fixture = write_fixture(tmp_path / "fx", sources=("falco",))
    calls: list[str] = []
    real_read_records = emit_module.read_records

    def observed_read_records(data, locator):
        calls.append("reader-created")
        for raw in real_read_records(data, locator):
            calls.append("record-parsed-and-located")
            yield raw
        calls.append("reader-exhausted")

    class ObservedCounter:
        def __init__(self) -> None:
            self.calls = 0

        def __call__(self) -> int:
            calls.append("counter")
            value = self.calls * 10
            self.calls += 1
            return value

    monkeypatch.setattr(emit_module, "read_records", observed_read_records)
    clock = ObservedCounter()
    run(fixture, tmp_path / "out", clock=clock)

    assert calls[:4] == ["counter", "reader-created", "record-parsed-and-located", "counter"]
    assert calls[4:7] == ["counter", "reader-exhausted", "counter"]


def test_injected_counter_does_not_change_event_order_or_bytes(tmp_path: Path) -> None:
    """The broader processing span remains observational only for deterministic evidence."""
    fixture = write_fixture(tmp_path / "fx", sources=("falco", "prometheus", "k8s_audit", "trivy"))
    untimed = run(fixture, tmp_path / "untimed")
    timed = run(fixture, tmp_path / "timed", clock=SequenceClock(list(range(0, 10_000, 10))))

    assert [event.event_id for event in timed.events] == [
        event.event_id for event in untimed.events
    ]
    assert timed.events_path.read_bytes() == untimed.events_path.read_bytes()


def test_the_budget_verdict_is_withheld_while_a_budget_key_is_pending(tmp_path: Path) -> None:
    """No verdict against a number nobody has measured, and the missing keys are named."""
    fixture = write_fixture(tmp_path / "fx", sources=("falco",))
    result = run(fixture, tmp_path / "out")
    budget = json.loads(result.latency_path.read_text(encoding="ascii"))["budget"]
    if budget["pending_keys"]:
        assert budget["verdict"] == "withheld"
        assert "monitor_latency_p95_budget_ms" in budget["pending_keys"]
        assert budget["ci_ceiling_p95_ms"] is None
        assert budget["ci_ceiling_max_ms"] is None


def test_calibrated_latency_budgets_pass_against_the_ci_ceiling(monkeypatch) -> None:
    """A calibrated budget forms an actual pass using budget times the protocol multiplier."""
    calibrated = {
        "monitor_latency_p95_budget_ms": 3.0,
        "monitor_latency_max_budget_ms": 3.0,
        "monitor_latency_ci_ceiling_multiplier": 4,
    }
    monkeypatch.setattr(protocol_limits, "as_protocol_mapping", lambda: calibrated)

    budget = _latency_document(
        event_count=2,
        per_event_ns=(7_000_000, 11_000_000),
        ordering_ns=0,
        reason=None,
    )["budget"]

    assert budget["pending_keys"] == []
    assert budget["ci_ceiling_p95_ms"] == 12.0
    assert budget["ci_ceiling_max_ms"] == 12.0
    assert budget["verdict"] == "pass"


def test_calibrated_latency_budgets_fail_when_either_ci_ceiling_is_exceeded(monkeypatch) -> None:
    """Calibrated values do not merely become available: an exceeded ceiling is a real failure."""
    calibrated = {
        "monitor_latency_p95_budget_ms": 3.0,
        "monitor_latency_max_budget_ms": 2.0,
        "monitor_latency_ci_ceiling_multiplier": 4,
    }
    monkeypatch.setattr(protocol_limits, "as_protocol_mapping", lambda: calibrated)

    budget = _latency_document(
        event_count=2,
        per_event_ns=(7_000_000, 9_000_000),
        ordering_ns=0,
        reason=None,
    )["budget"]

    assert budget["ci_ceiling_p95_ms"] == 12.0
    assert budget["ci_ceiling_max_ms"] == 8.0
    assert budget["verdict"] == "fail"
    assert "max 9 ms exceeds CI ceiling 8 ms" in budget["verdict_reason"]


def test_the_end_to_end_slot_is_present_empty_and_explained(tmp_path: Path) -> None:
    """The obligation stays visible rather than being quietly dropped. See ``emit.py``."""
    fixture = write_fixture(tmp_path / "fx", sources=("falco",))
    result = run(fixture, tmp_path / "out")
    document = json.loads(result.latency_path.read_text(encoding="ascii"))
    assert document["end_to_end_source_ts_to_emit_ts_ms"] is None
    assert "wall-clock" in document["end_to_end_reason"]


@pytest.mark.parametrize(
    ("samples", "expected"),
    [([1], 1), ([1, 2], 2), (list(range(1, 21)), 19), (list(range(1, 101)), 95)],
)
def test_the_percentile_is_nearest_rank(samples: list[int], expected: int) -> None:
    """Nearest rank returns a value some event exhibited; an interpolating variant invents one."""
    assert _percentile(sorted(samples), 0.95) == expected


# --- the fixture entry point --------------------------------------------------------------------


def test_replay_fixture_returns_events_without_writing_anything(tmp_path: Path) -> None:
    """The in-process entry point the G3 isolation test uses; no output directory required."""
    fixture = write_fixture(tmp_path / "fx", sources=("falco", "prometheus"))
    events = replay_fixture(
        fixture,
        quoting_enabled=True,
        cap_limits=LIMITS,
        audit_severity=EvidenceSeverity.HIGH,
    )
    assert len(events) == 2
    assert not list((tmp_path / "fx").glob(EVENTS_FILENAME))


def test_replay_fixture_writes_when_given_an_output_directory(tmp_path: Path) -> None:
    """And what it writes is byte-identical to what ``emit`` writes for the same input."""
    fixture = write_fixture(tmp_path / "fx", sources=("falco", "k8s_audit"))
    replay_fixture(
        fixture,
        quoting_enabled=True,
        cap_limits=LIMITS,
        audit_severity=EvidenceSeverity.HIGH,
        out_dir=tmp_path / "out-1",
    )
    run(fixture, tmp_path / "out-2")
    assert (tmp_path / "out-1" / EVENTS_FILENAME).read_bytes() == (
        tmp_path / "out-2" / EVENTS_FILENAME
    ).read_bytes()


def test_a_directory_with_none_of_the_four_inputs_is_refused(tmp_path: Path) -> None:
    """An empty replay reported as a successful run of nothing survives review. A refusal cannot."""
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "fixture.yaml").write_bytes(b"provenance: synthesised\n")
    with pytest.raises(FixtureInputError) as refusal:
        replay_fixture(empty, quoting_enabled=True, cap_limits=LIMITS)
    assert "falco.jsonl" in str(refusal.value)


def test_a_source_input_outside_the_raw_root_is_refused(tmp_path: Path) -> None:
    """A raw_ref that cannot be made root-relative must not silently become an absolute one."""
    fixture = write_fixture(tmp_path / "fx", sources=("falco",))
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    with pytest.raises(FixtureInputError):
        replay_fixture(fixture, quoting_enabled=True, cap_limits=LIMITS, raw_root=outside)


def test_an_audit_input_without_an_assigned_severity_is_refused(tmp_path: Path) -> None:
    """The fail-closed path reaches all the way out to the replay entry point."""
    fixture = write_fixture(tmp_path / "fx", sources=("k8s_audit",))
    with pytest.raises(Exception) as refusal:
        replay_fixture(fixture, quoting_enabled=True, cap_limits=LIMITS)
    assert "severity" in str(refusal.value)


def test_the_input_filenames_are_the_registry_rows(tmp_path: Path) -> None:
    """The fixture contract is the registry's, so a fixture author has one place to look."""
    fixture = write_fixture(tmp_path / "fx", sources=("falco", "prometheus", "k8s_audit", "trivy"))
    present = {path.name for path in fixture.iterdir()}
    assert present == {entry.input_filename for entry in SOURCE_REGISTRY}


def test_source_input_carries_bytes_so_reading_is_outside_the_measured_span() -> None:
    """A structural assertion: ``emit`` is handed bytes, so it cannot read -- or time -- a file.

    Worth asserting rather than assuming, because the moment the aggregation function takes a path
    the reading moves inside the measured span, and section 4's "excluding source I/O" stops being
    true by construction and starts being a claim.
    """
    entry = registry_entry(EvidenceSource.FALCO)
    source_input = SourceInput(entry=entry, raw_path="fx/falco.jsonl", data=b"{}\n")
    assert isinstance(source_input.data, bytes)
    assert "data" in {field.name for field in fields(SourceInput)}
    assert not any(
        parameter.annotation is Path
        for parameter in signature(SourceInput.__init__).parameters.values()
    )
