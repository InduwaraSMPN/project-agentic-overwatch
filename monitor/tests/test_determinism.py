"""Byte-level determinism over the fixture corpus, as a test rather than as a shell gate.

WHY THIS FILE EXISTS WHEN scripts/monitor_determinism.sh ALREADY DOES THIS
---------------------------------------------------------------------------
Because CI does not run the shell gate. ``.github/workflows/ci.yml`` runs ``python -m pytest
monitor/tests`` on every pull request; ``make determinism-check`` is not a pull-request check, and
the nightly step conventions section 4 declares is armed on the five ``scenarios/`` content
directories, which belong to M5 and do not exist. Left to the shell alone, M2's Definition-of-done
line "same fixture twice -> identical output" would be verified by a human on a laptop and by
nothing else. This file is the same property, in the job that actually runs.

The two are deliberately not one. The shell gate replays in **two separate processes**, which is
what catches state carried between runs in one interpreter; this file replays **in process**, which
is fast enough to sit on a pull request. Each covers what the other cannot, and both compare bytes.

WHAT IS COMPARED, AND WHY ``latency.json`` IS NOT
---------------------------------------------------
A replay writes two files. ``monitor_events.jsonl`` is the deliverable and is compared byte for
byte, twice over: run against run, and run against the golden stream committed beside the fixture.
``latency.json`` is excluded, and the exclusion is the design rather than an oversight -- ADR-019
holds latency figures out of the event stream precisely because they are wall-clock and
machine-dependent, and one of them inside the diffed stream would make the twice-and-diff
unpassable forever while presenting itself as a flaky test.

That exclusion is asserted here in three ways, because "we do not compare that file" is the kind of
claim that quietly stops being true: the harness's own :data:`~monitor.tests.replay_harness.
DIFFED_FILENAMES` names the event stream and not the latency document; the shell gate's ``cmp``
lines never mention the latency document; and no measured figure from ``latency.json`` appears
anywhere in the bytes of the event stream it was measured from.

THE CORPUS CAPS ARE ASSERTED TO BE UNPROMOTABLE, NOT MERELY DOCUMENTED
-----------------------------------------------------------------------
``limits.py`` fails closed while section 4's caps are pending, so every fixture supplies its own cap
values. ADR-019 is explicit that those are test parameters belonging to the corpus and must never be
promoted into the protocol without the fixture study behind them. Two tests here make that
structural: the ``corpus_cap_*`` key names are disjoint from section 4's key names and appear in
neither the protocol nor the mirror, and every fixture carries a sentinel whose absence makes the
fixture unloadable. Promoting one of these numbers therefore means deleting a line that says, in the
file, that it is not a protocol number.

WHAT THIS FILE MAY IMPORT
-------------------------
The standard library, pytest and pydantic, through the harness. No cluster, no network. The only
files it reads are the tracked corpus, the two shell gates, ``limits.py`` and the protocol -- all of
which are in the repository a pull request is being run against.
"""

import json
import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from monitor.aggregator import limits as protocol_limits  # noqa: E402
from monitor.aggregator.emit import EVENTS_FILENAME, LATENCY_FILENAME  # noqa: E402
from monitor.aggregator.models import EvidenceEvent, EvidenceSource  # noqa: E402
from monitor.tests import replay_harness  # noqa: E402
from monitor.tests.replay_harness import (  # noqa: E402
    CORPUS_CAP_KEYS,
    CORPUS_CAP_SENTINEL,
    DIFFED_FILENAMES,
    MANIFEST_FILENAME,
    WRITTEN_FILENAMES,
    FixtureFormatError,
    FixtureSpec,
    StreamValidationError,
    discover,
    latency_figures,
    load_fixture,
    nanosecond_counter,
    replay,
    validate_stream,
)

DETERMINISM_GATE = REPO_ROOT / "scripts" / "monitor_determinism.sh"
REPLAY_GATE = REPO_ROOT / "scripts" / "monitor_replay.sh"

# Architecture section 3's ten field names, spelled out here rather than read off the model, so
# that a field added to the contract and to the model together still fails this file. It is the
# same independence test_schema.py applies for the same reason. signal_id was the tenth, added at
# M10 with the schema_version bump to v2 (ADR-125).
CONTRACT_FIELDS = frozenset(
    {
        "event_id",
        "ts",
        "source",
        "signal_id",
        "severity",
        "resource",
        "summary",
        "evidence_excerpts",
        "raw_ref",
        "schema_version",
    }
)

CORPUS = discover()


def fixture_ids() -> list[str]:
    """The corpus identifiers, used to name the parametrised cases in pytest's output."""
    return [spec.fixture_id for spec in CORPUS]


@pytest.mark.parametrize("spec", CORPUS, ids=fixture_ids())
def test_two_replays_of_one_fixture_produce_identical_bytes(spec: FixtureSpec, tmp_path) -> None:
    """The milestone's ``cmp``, in process: run it twice, compare the bytes, not the objects.

    A parsed comparison would pass while key order, the separators, the line terminator or the
    emission order drifted -- and every one of those would break a sealed run bundle for a consumer
    that was not this interpreter.
    """
    first = tmp_path / "run-1"
    second = tmp_path / "run-2"
    replay(spec, out_dir=first, clock=nanosecond_counter())
    replay(spec, out_dir=second, clock=nanosecond_counter())
    assert (first / EVENTS_FILENAME).read_bytes() == (second / EVENTS_FILENAME).read_bytes()


def test_validate_stream_refuses_a_final_record_without_an_lf(tmp_path: Path) -> None:
    """The validator must not silently discard an unterminated final JSON Lines record."""
    stream = tmp_path / EVENTS_FILENAME
    stream.write_bytes(CORPUS[0].golden_path.read_bytes().rstrip(b"\n"))

    with pytest.raises(StreamValidationError, match="final LF terminator"):
        validate_stream(stream)


@pytest.mark.parametrize("spec", CORPUS, ids=fixture_ids())
def test_the_emitted_stream_equals_the_committed_golden_stream(spec: FixtureSpec, tmp_path) -> None:
    """What the aggregator emits today is what the repository says it emits.

    The golden file is the aggregator's output byte for byte, so a failure here is a change in
    behaviour rather than a stale artefact. The remedy is to read the change, not to regenerate the
    corpus: regeneration is a reviewed diff, and after the ``v1.0`` freeze a logged hotfix ADR.
    """
    replay(spec, out_dir=tmp_path, clock=nanosecond_counter())
    emitted = (tmp_path / EVENTS_FILENAME).read_bytes()
    golden = spec.golden_path.read_bytes()
    assert emitted == golden, (
        f"{spec.fixture_id}: the emitted stream differs from {spec.golden_path.name}. Regenerate "
        "with `python -m monitor.tests.replay_harness --out-root monitor/.replay/update "
        "--update-golden` only after reading what changed."
    )


@pytest.mark.parametrize("spec", CORPUS, ids=fixture_ids())
def test_the_stream_carries_the_ten_contract_fields_and_no_timing(
    spec: FixtureSpec, tmp_path
) -> None:
    """Every emitted event has exactly architecture section 3's ten fields, and none is a clock.

    Stated over the whole field set rather than over a particular name somebody might pick: the
    property that has to hold is that *nothing* wall-clock-derived is in the stream, and a check
    that looked for one name would pass over any other.
    """
    replay(spec, out_dir=tmp_path, clock=nanosecond_counter())
    data = (tmp_path / EVENTS_FILENAME).read_bytes()
    assert data, spec.fixture_id
    for number, line in enumerate(data.split(b"\n")[:-1], start=1):
        event = EvidenceEvent.model_validate_json(line)
        fields = set(event.model_dump().keys())
        assert fields == CONTRACT_FIELDS, f"{spec.fixture_id}:{number}"
    for forbidden in (b"latency", b"elapsed", b"perf_counter", b"emit_ts"):
        assert forbidden not in data, f"{spec.fixture_id}: {forbidden!r} reached the event stream"


@pytest.mark.parametrize("spec", CORPUS, ids=fixture_ids())
def test_no_measured_latency_figure_appears_in_the_event_stream(
    spec: FixtureSpec, tmp_path
) -> None:
    """The figures are really measured, and none of them is in the bytes that get diffed.

    Both halves matter. Asserting only that ``latency.json`` is absent from the stream would pass
    over a run that measured nothing, so the measurement is asserted first: with the counter
    injected, the document must report ``measured`` and carry a p95 and a maximum. Then those exact
    figures are looked for in the event stream, where finding one would mean the diff can never pass
    twice.
    """
    replay(spec, out_dir=tmp_path, clock=nanosecond_counter())
    figures = latency_figures(tmp_path / LATENCY_FILENAME)
    assert figures["measured"] is True, spec.fixture_id
    assert figures["p95_ms"] is not None and figures["max_ms"] is not None
    assert figures["event_count"] > 0

    stream = (tmp_path / EVENTS_FILENAME).read_text(encoding="ascii")
    for key in ("p95_ms", "max_ms"):
        rendered = repr(figures[key])
        assert rendered not in stream, (
            f"{spec.fixture_id}: the measured {key} {rendered} appears in the event stream, which "
            "would make two replays differ in exactly the way ADR-019 holds latency out to prevent"
        )


@pytest.mark.parametrize("spec", CORPUS, ids=fixture_ids())
def test_the_latency_document_is_written_and_reports_a_withheld_budget_verdict(
    spec: FixtureSpec, tmp_path
) -> None:
    """The budget verdict is withheld while section 4's keys are pending, and names what is missing.

    This is the fail-closed posture seen from the reporting side. A replay that formed a verdict
    against an unmeasured budget -- or worse, against a default -- would produce a "within budget"
    line that no measurement supports, which is the shape of failure ADR-016's withheld SLO verdict
    exists to prevent.
    """
    replay(spec, out_dir=tmp_path, clock=nanosecond_counter())
    figures = latency_figures(tmp_path / LATENCY_FILENAME)
    mapping = protocol_limits.as_protocol_mapping()
    pending = {
        key
        for key in ("monitor_latency_p95_budget_ms", "monitor_latency_max_budget_ms")
        if protocol_limits.is_pending(mapping[key])
    }
    if pending:
        assert figures["verdict"] == "withheld", spec.fixture_id
        assert set(figures["pending_keys"]) == pending
    else:
        assert figures["verdict"] in {"pass", "fail"}, spec.fixture_id


def test_replay_harness_keeps_pending_latency_withheld_and_returns_zero(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """The executable harness preserves today's pending state as a successful withheld replay."""
    pending = {
        "monitor_latency_p95_budget_ms": protocol_limits.PENDING_FIXTURE_STUDY,
        "monitor_latency_max_budget_ms": protocol_limits.PENDING_FIXTURE_STUDY,
        "monitor_latency_ci_ceiling_multiplier": 4,
    }
    monkeypatch.setattr(protocol_limits, "as_protocol_mapping", lambda: pending)
    ticks = iter(range(0, 100_000_000, 1_000_000))
    monkeypatch.setattr(replay_harness, "nanosecond_counter", lambda: lambda: next(ticks))

    result = replay_harness.main(["--out-root", str(tmp_path), "--fixture", CORPUS[0].fixture_id])
    captured = capsys.readouterr()

    assert result == 0
    assert "budget=withheld" in captured.out
    assert "LatencyBudgetExceeded" not in captured.err


def test_replay_harness_returns_nonzero_for_a_calibrated_over_budget_result(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """A calibrated fail is a harness failure, not merely a value left in latency.json."""
    calibrated = {
        "monitor_latency_p95_budget_ms": 1e-12,
        "monitor_latency_max_budget_ms": 1e-12,
        "monitor_latency_ci_ceiling_multiplier": 4,
    }
    monkeypatch.setattr(protocol_limits, "as_protocol_mapping", lambda: calibrated)
    ticks = iter(range(0, 100_000_000, 1_000_000))
    monkeypatch.setattr(replay_harness, "nanosecond_counter", lambda: lambda: next(ticks))

    result = replay_harness.main(["--out-root", str(tmp_path), "--fixture", CORPUS[0].fixture_id])
    captured = capsys.readouterr()

    assert result == 1
    assert "budget=fail" in captured.out
    assert "LatencyBudgetExceeded" in captured.err
    assert "CI ceiling" in captured.err


def test_the_diffed_set_is_the_event_stream_and_never_the_latency_document() -> None:
    """``latency.json`` is written by every replay and compared by nothing. Asserted, not assumed.

    Three independent statements of one property, because a comment saying "we do not diff that
    file" is not a check. The harness constant is what the pytest half uses; the ``cmp`` lines are
    what the shell half uses; and both gates must agree, or one of them is comparing a wall clock.
    """
    assert LATENCY_FILENAME in WRITTEN_FILENAMES
    assert DIFFED_FILENAMES == (EVENTS_FILENAME,)
    assert LATENCY_FILENAME not in DIFFED_FILENAMES

    for gate in (DETERMINISM_GATE, REPLAY_GATE):
        compare_lines = [
            line
            for line in gate.read_text(encoding="utf-8").splitlines()
            if "cmp " in line and not line.lstrip().startswith("#")
        ]
        assert compare_lines, f"{gate.name} runs no cmp at all, so it compares nothing"
        for line in compare_lines:
            assert LATENCY_FILENAME not in line, (
                f"{gate.name} compares {LATENCY_FILENAME}, whose figures are wall-clock: "
                f"{line.strip()!r}"
            )


def test_the_corpus_covers_all_four_signal_families_and_is_not_empty() -> None:
    """A non-vacuity check over the corpus itself, which every test above is parametrised on.

    An empty corpus would make every parametrised test above collect zero cases and the file would
    report all-green having asserted nothing. ``discover`` refuses an empty corpus for that reason;
    this states the stronger property the milestone actually needs -- that all four families
    ``docs/02-architecture.md`` section 3 admits are exercised somewhere in it, and that at least
    one fixture exercises more than one family at a time, which is the only way the ordered registry
    is tested *across* sources rather than within one.
    """
    assert CORPUS, "the fixture corpus is empty"
    covered = {source for spec in CORPUS for source in spec.sources}
    assert covered == set(EvidenceSource), sorted(str(source) for source in covered)
    assert any(len(spec.sources) > 1 for spec in CORPUS), (
        "no fixture holds more than one source, so nothing exercises the ordered source registry "
        "across families -- which is where source_rank decides the emission order"
    )


def test_every_fixture_declares_one_complete_provenance_shape() -> None:
    """Provenance is what gates section 4's caps row, so it is checked rather than trusted.

    A fixture that claimed capture without naming a commit and a tool version -- or that claimed
    synthesis without naming a source document -- would let that gate be satisfied by an assertion
    nobody checked. ``load_fixture`` enforces the two shapes; this asserts every fixture in the
    corpus is in exactly one of them.

    Until T2.7b this test asserted the stronger-looking property that the corpus was *entirely*
    synthesised. That was a statement about the corpus's contents at Phase A, not about the
    invariant, and T2.7b ends it by construction: it is the task that adds captured fixtures.
    Replacing it with the shape check loses nothing, because the property it was really defending
    -- that a capture claim is backed by a commit and a version -- is asserted here for every
    fixture, and the companion test below adds the requirement T2.7b actually owes.
    """
    for spec in CORPUS:
        if spec.provenance == "synthesised":
            assert spec.synthesised_from, spec.fixture_id
            assert not spec.capture_commit and not spec.source_tool_version, spec.fixture_id
        else:
            assert spec.provenance == "captured", spec.fixture_id
            assert spec.capture_commit, spec.fixture_id
            assert spec.source_tool_version, spec.fixture_id


def test_every_source_family_has_a_captured_fixture() -> None:
    """T2.7b's obligation, stated as a check rather than as a claim in a milestone log.

    Section 4's caps must be derived from fixtures recorded from the live sources, and a corpus
    that had captured three families out of four would let the T2.5b study be run over a source
    whose real payload shape had never been seen. This fails while any of the four families
    ``docs/02-architecture.md`` section 3 admits is represented only by synthesised bytes.
    """
    captured = {
        source for spec in CORPUS if spec.provenance == "captured" for source in spec.sources
    }
    missing = sorted(str(source) for source in set(EvidenceSource) - captured)
    assert not missing, f"no captured fixture exists for: {missing}"


def test_the_corpus_cap_keys_are_disjoint_from_the_protocol_and_absent_from_it() -> None:
    """A corpus cap can never be read as a section 4 cap, because they share no name.

    The milestone's Definition of done checks that each section 4 value appears only in the protocol
    and in ``limits.py``, with no third occurrence. That check is by value; this one is by name, and
    catches the case the value check cannot -- a corpus number that happens to coincide with a
    protocol number once section 4 is calibrated. Neither the ``corpus_cap_*`` names nor the
    sentinel may appear in the protocol or in the mirror.
    """
    assert not set(CORPUS_CAP_KEYS) & set(protocol_limits.PROTOCOL_KEYS)
    mirror = (REPO_ROOT / "monitor" / "aggregator" / "limits.py").read_text(encoding="utf-8")
    protocol = (REPO_ROOT / protocol_limits.PROTOCOL_RELATIVE_PATH).read_text(encoding="utf-8")
    for text, name in ((mirror, "limits.py"), (protocol, protocol_limits.PROTOCOL_RELATIVE_PATH)):
        for key in CORPUS_CAP_KEYS:
            assert key not in text, f"{name} names the corpus cap key {key!r}"
        assert CORPUS_CAP_SENTINEL not in text, f"{name} carries the corpus cap sentinel"


def test_a_fixture_whose_cap_sentinel_is_altered_will_not_load(tmp_path) -> None:
    """The sentinel is refusable, which is what makes it a guard rather than a comment.

    Promoting a corpus cap into section 4 requires first deleting the line that says it is not a
    section 4 value. This test is the proof that deleting it is not free: the fixture stops loading,
    both gates fail, and the change is visible in the diff rather than in someone's memory.
    """
    original = CORPUS[0]
    copied = tmp_path / original.fixture_id
    shutil.copytree(original.directory, copied)
    manifest = copied / MANIFEST_FILENAME
    manifest.write_bytes(
        manifest.read_text(encoding="utf-8")
        .replace(CORPUS_CAP_SENTINEL, "reviewed and approved for section 4")
        .encode("utf-8")
    )
    with pytest.raises(FixtureFormatError) as refused:
        load_fixture(copied)
    assert "corpus_cap_status" in str(refused.value)


def test_the_golden_streams_are_lf_terminated_ascii_with_no_carriage_return() -> None:
    """A committed corpus must compare equal on Windows and under WSL2, and this is what decides it.

    A text-mode write on the development host would translate every terminator, and the corpus would
    then differ from what CI regenerates on Linux in every single line while looking identical in
    every editor. ASCII because the canonical serialiser escapes non-ASCII, which is what makes the
    bytes independent of the locale of whatever reads or re-encodes them downstream.
    """
    for spec in CORPUS:
        golden = spec.golden_path.read_bytes()
        assert golden, spec.fixture_id
        assert b"\r" not in golden, spec.fixture_id
        assert golden.endswith(b"\n"), spec.fixture_id
        assert all(byte < 128 for byte in golden), spec.fixture_id
        for line in golden.split(b"\n")[:-1]:
            assert json.loads(line.decode("ascii"))["schema_version"]
