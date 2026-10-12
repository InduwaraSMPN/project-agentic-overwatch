"""Schema and behaviour tests for the ``probes.csv`` writer.

WHAT IS UNDER TEST
------------------
``docs/protocols/data-management.md`` section 1 owns the column set and the column order of
``probes.csv``, and ``infra/probes/slo_probe.py`` is the only writer of that file. Everything below
drives the real writer against a temporary file and reads the bytes back, rather than asserting
against the header tuple the module happens to define: a test that compared the module to itself
would pass just as happily if the writer stopped using the header at all.

NO CLUSTER, NO NETWORK, NO SOCKET
---------------------------------
These tests run in CI's ``Unit tests -- infra`` step on a GitHub runner with none of those. The
transport, the clock and the sleep are injected everywhere, so nothing here resolves a name or
opens a connection; the fixtures are defined inline in this file and describe outcomes -- a status
code, or an exception -- rather than servers.

THE UNCALIBRATED GUARD IS TESTED AS BEHAVIOUR, NOT AS DOCUMENTATION
-------------------------------------------------------------------
The most important assertion in this file is that a perfect timeline still does not produce a pass
while a threshold is uncalibrated, and that the process says so on stderr and exits non-zero. That
is the property the whole sentinel design exists for, so it is checked through the command-line
entry point and not merely against the classifier.
"""

import csv
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

# The repository root, from this file's location rather than from the working directory, so the
# import works however pytest was invoked. See the same block in test_constants_match_protocol.py.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from infra.probes import slo_probe  # noqa: E402
from infra.probes.constants import (  # noqa: E402
    PENDING_CALIBRATION,
    SLO_PROBE_SET,
    ProbeSpec,
    as_protocol_mapping,
)
from infra.probes.slo_probe import (  # noqa: E402
    EXIT_THRESHOLDS_PENDING,
    PROBES_CSV_HEADER,
    ProbeResult,
    calibrated_mapping,
    classify,
    dwell_completion_ceiling_seconds,
    false_recovery_curve,
    outage_windows,
    percentile_nearest_rank,
    probe_once,
    probe_ticks,
    read_rows,
    run_timeline,
    settling_seconds,
    stabilization_dwell_seconds,
    steady_state_rows,
    wilson_upper_bound,
    write_rows,
)

# The column order data-management section 1 fixes. Written out as a literal here, rather than
# imported, precisely so that a change to the module's tuple has to be made twice and reviewed
# against the protocol both times.
EXPECTED_HEADER = [
    "ts",
    "probe_id",
    "target",
    "method",
    "status_code",
    "latency_ms",
    "ok",
    "error",
]

FIXTURE_SPECS = (
    ProbeSpec(probe_id="FIXTURE-ONE", target="/fixture-one", method="GET"),
    ProbeSpec(probe_id="FIXTURE-TWO", target="/fixture-two", method="GET"),
)


def scripted_transport(outcomes):
    """Return a transport that replays ``outcomes`` in order, raising any that is an exception.

    An outcome is either an integer status code -- the frontend answered -- or an exception
    instance, which the transport raises to stand for a request that never got a response. Those
    are the only two things a transport can do, and keeping the fixture in exactly those terms is
    what lets these tests describe failure modes without a server to produce them.
    """
    remaining = list(outcomes)

    def transport(url: str, method: str, timeout_seconds: float) -> int:
        outcome = remaining.pop(0) if remaining else 200
        if isinstance(outcome, Exception):
            raise outcome
        return int(outcome)

    return transport


def stepping_clock(step_seconds: float = 1.0, start: datetime | None = None):
    """Return a clock that advances by a fixed step on every call.

    A deterministic clock rather than the real one, so that the elapsed times these tests reason
    about -- the stabilization window in particular -- are exactly what the fixture says and not
    whatever the runner's scheduler produced that day.
    """
    moment = start if start is not None else datetime(2026, 1, 1, tzinfo=UTC)
    state = {"now": moment}

    def clock() -> datetime:
        current = state["now"]
        state["now"] = current + timedelta(seconds=step_seconds)
        return current

    return clock


def read_csv(path: Path) -> list[list[str]]:
    """Return the CSV at ``path`` parsed into rows, header included."""
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.reader(handle))


def drive(tmp_path: Path, outcomes, samples: int = 1, step_seconds: float = 1.0) -> Path:
    """Drive the writer end to end against fakes and return the path it wrote."""
    out = tmp_path / "probes.csv"
    write_rows(
        run_timeline(
            specs=FIXTURE_SPECS,
            base_url="http://fixture.invalid",
            samples=samples,
            transport=scripted_transport(outcomes),
            now=stepping_clock(step_seconds),
            sleep=lambda _seconds: None,
            monotonic=lambda: 0.0,
        ),
        out,
    )
    return out


def test_header_row_is_the_protocol_column_order(tmp_path: Path) -> None:
    """The first line of the file is exactly the columns data-management section 1 declares."""
    rows = read_csv(drive(tmp_path, [200, 200]))
    assert rows[0] == EXPECTED_HEADER
    assert list(PROBES_CSV_HEADER) == EXPECTED_HEADER


def test_one_row_per_probe_per_sample(tmp_path: Path) -> None:
    """A sample is one cycle of the probe set, so N samples write N * len(specs) rows."""
    rows = read_csv(drive(tmp_path, [200] * 6, samples=3))
    assert len(rows) == 1 + 3 * len(FIXTURE_SPECS)
    assert [row[1] for row in rows[1:3]] == ["FIXTURE-ONE", "FIXTURE-TWO"]


def test_ok_column_is_a_lowercase_boolean(tmp_path: Path) -> None:
    """``ok`` is the literal string true or false, never True/False or 1/0.

    Every consumer of a run bundle reads this column, and a per-language boolean spelling is
    exactly the kind of thing that silently parses as truthy in one tool and as a string in
    another.
    """
    rows = read_csv(drive(tmp_path, [200, 500]))
    values = [row[EXPECTED_HEADER.index("ok")] for row in rows[1:]]
    assert values == ["true", "false"]
    assert all(value in {"true", "false"} for value in values)


def test_a_served_error_records_its_status_and_is_not_ok(tmp_path: Path) -> None:
    """A 5xx is a response: the code is recorded, ``ok`` is false, ``error`` stays empty.

    The distinction between a served error and no response at all is what tells a restoration
    curve that the frontend is up and a dependency is not.
    """
    rows = read_csv(drive(tmp_path, [503, 200]))
    failed = rows[1]
    assert failed[EXPECTED_HEADER.index("status_code")] == "503"
    assert failed[EXPECTED_HEADER.index("ok")] == "false"
    assert failed[EXPECTED_HEADER.index("error")] == ""


def test_a_transport_failure_has_no_status_and_carries_the_error(tmp_path: Path) -> None:
    """No response means an empty ``status_code`` and a populated ``error``."""
    rows = read_csv(drive(tmp_path, [TimeoutError("timed out"), 200]))
    failed = rows[1]
    assert failed[EXPECTED_HEADER.index("status_code")] == ""
    assert failed[EXPECTED_HEADER.index("ok")] == "false"
    assert "TimeoutError" in failed[EXPECTED_HEADER.index("error")]


def test_timestamps_are_iso_8601_utc(tmp_path: Path) -> None:
    """``ts`` round-trips through :func:`datetime.fromisoformat` and carries a UTC offset."""
    rows = read_csv(drive(tmp_path, [200, 200]))
    for row in rows[1:]:
        parsed = datetime.fromisoformat(row[EXPECTED_HEADER.index("ts")])
        assert parsed.tzinfo is not None
        assert parsed.utcoffset() == timedelta(0)


def test_the_file_uses_lf_line_endings(tmp_path: Path) -> None:
    """No CR bytes anywhere: a bundle's bytes must not depend on the host that wrote them."""
    assert b"\r" not in drive(tmp_path, [200, 200]).read_bytes()


def test_appending_does_not_repeat_the_header(tmp_path: Path) -> None:
    """A restarted probe extends its timeline; a repeated header would read as a gap."""
    out = tmp_path / "probes.csv"
    for _ in range(2):
        write_rows(
            run_timeline(
                specs=FIXTURE_SPECS,
                base_url="http://fixture.invalid",
                samples=1,
                transport=scripted_transport([200, 200]),
                now=stepping_clock(),
                sleep=lambda _seconds: None,
                monotonic=lambda: 0.0,
            ),
            out,
        )
    rows = read_csv(out)
    assert rows[0] == EXPECTED_HEADER
    assert [row for row in rows[1:] if row[0] == "ts"] == []
    assert len(rows) == 1 + 2 * len(FIXTURE_SPECS)


def test_a_missing_stopping_rule_is_rejected() -> None:
    """Neither stopping rule, or both, is a programming error and not a silent default."""
    with pytest.raises(ValueError):
        list(run_timeline(specs=FIXTURE_SPECS, base_url="http://fixture.invalid"))
    with pytest.raises(ValueError):
        list(
            run_timeline(
                specs=FIXTURE_SPECS,
                base_url="http://fixture.invalid",
                samples=1,
                duration_seconds=1.0,
            )
        )


def test_probe_once_joins_the_base_url_to_the_path() -> None:
    """The target is a path; the base URL supplies the host, with no doubled separator."""
    seen: list[str] = []

    def transport(url: str, method: str, timeout_seconds: float) -> int:
        seen.append(url)
        return 200

    probe_once(
        SLO_PROBE_SET[0],
        base_url="http://fixture.invalid/",
        transport=transport,
        now=stepping_clock(),
    )
    assert seen == ["http://fixture.invalid" + SLO_PROBE_SET[0].target]


def sample(offset_seconds: float, ok: bool, latency_ms: float = 10.0) -> ProbeResult:
    """Build one fixture row at ``offset_seconds`` past a fixed origin."""
    moment = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=offset_seconds)
    return ProbeResult(
        ts=moment.isoformat(),
        probe_id="FIXTURE-ONE",
        target="/fixture-one",
        method="GET",
        status_code=200 if ok else 503,
        latency_ms=latency_ms,
        ok=ok,
        error="" if ok else "fixture failure",
    )


def test_percentile_is_nearest_rank() -> None:
    """No interpolation: the p95 of 1..100 is the 95th ordered value, exactly."""
    assert percentile_nearest_rank(list(range(1, 101)), 0.95) == 95
    assert percentile_nearest_rank([7.0], 0.95) == 7.0
    with pytest.raises(ValueError):
        percentile_nearest_rank([], 0.95)


ORIGIN = datetime(2026, 1, 1, tzinfo=UTC)


def at(offset_seconds: float) -> datetime:
    """Return the repair instant ``offset_seconds`` past the fixture origin."""
    return ORIGIN + timedelta(seconds=offset_seconds)


def test_the_dwell_is_anchored_on_the_systems_own_settling_time() -> None:
    """With a contiguous outage the curve discriminates nothing, so the settling time selects.

    ADR-048: ``premature`` is zero at every candidate when the outage has no green inside it, and
    the completion ceiling is a function of how long the run watched. The settling interval --
    repair to the last failing tick -- is the one bound here that is a property of the system.
    """
    rows = (
        [sample(i, False) for i in range(0, 20)]  # outage; repair applied at t=8
        + [sample(i, True) for i in range(20, 200)]
    )
    repairs = [at(8)]
    curve = false_recovery_curve(rows, repairs, interval_seconds=1.0)
    assert all(p == 0 for _, p, _ in curve)  # the curve alone gives no lower bound
    settling = settling_seconds(rows, repairs, interval_seconds=1.0)
    assert settling == 11  # repair at t=8, last red tick at t=19
    assert stabilization_dwell_seconds(rows, repairs, interval_seconds=1.0) == settling


def test_settling_takes_the_slowest_recovery_not_the_typical_one() -> None:
    """The dwell must survive the slowest recovery observed, so the maximum is taken."""
    rows = (
        [sample(i, False) for i in range(0, 6)]  # cycle 1 outage, repair at t=2 -> lag 5
        + [sample(i, True) for i in range(6, 60)]
        + [sample(i, False) for i in range(60, 80)]  # cycle 2 outage, repair at t=62 -> lag 17
        + [sample(i, True) for i in range(80, 200)]
    )
    assert settling_seconds(rows, [at(2), at(62)], interval_seconds=1.0) == 17


def test_completion_ceiling_is_finite_even_with_no_observed_failure() -> None:
    """Zero observed failures is not evidence of a zero rate, so the ceiling stays finite.

    ADR-048: taking the point estimate here returned no ceiling at all, and the chosen dwell
    became the length of the observation window (290s on a 300s window) rather than a property
    of the system.
    """
    rows = [sample(index, True) for index in range(40)]
    ceiling = dwell_completion_ceiling_seconds(rows, [at(0)], interval_seconds=1.0)
    assert ceiling is not None and ceiling > 0


def test_completion_ceiling_rises_with_a_longer_clean_observation() -> None:
    """More evidence of stability justifies demanding a longer unbroken green run."""
    short = [sample(i, True) for i in range(40)]
    long_ = [sample(i, True) for i in range(400)]
    assert dwell_completion_ceiling_seconds(
        long_, [at(0)], interval_seconds=1.0
    ) > dwell_completion_ceiling_seconds(short, [at(0)], interval_seconds=1.0)


def test_completion_ceiling_shortens_as_the_background_rate_rises() -> None:
    """The ceiling is a function of the measured background rate, and moves with it."""
    light = [sample(i, i % 20 != 0) for i in range(80)]
    heavy = [sample(i, i % 5 != 0) for i in range(80)]
    loose = dwell_completion_ceiling_seconds(light, [at(0)], interval_seconds=1.0)
    tight = dwell_completion_ceiling_seconds(heavy, [at(0)], interval_seconds=1.0)
    assert loose is not None and tight is not None
    assert tight < loose


def test_probe_ticks_folds_a_pass_and_is_red_when_any_probe_is() -> None:
    """A tick is a pass of the probe set, and one red probe makes the whole pass red.

    Same segmentation rule as ADR-050's ``_probe_cycles`` in ``measures.py``: a new pass starts at
    the first row whose ``probe_id`` repeats. Writer and reader agree by construction, which is the
    point -- ADR-050 records what happened when they did not.
    """

    def row(probe_id: str, ok: bool, offset: float) -> ProbeResult:
        base = sample(offset, ok)
        return ProbeResult(
            base.ts, probe_id, "/x", "GET", base.status_code, base.latency_ms, ok, base.error
        )

    rows = [
        row("A", True, 0),
        row("B", True, 0.01),
        row("A", True, 5),
        row("B", False, 5.01),
        row("A", True, 10),
        row("B", True, 10.01),
    ]
    ticks = probe_ticks(rows)
    assert [t.ok for t in ticks] == [True, False, True]


def test_thresholds_are_measured_on_steady_state_not_on_the_induced_outage() -> None:
    """The outage the dwell needs must not inflate the SLO thresholds it is calibrated beside.

    ADR-048: measuring the error rate over the whole calibration timeline produced an 11.7% error
    budget, fitted to the very breaches the budget exists to detect.
    """
    rows = (
        [sample(index, True) for index in range(0, 10)]
        + [sample(index, False) for index in range(10, 20)]  # the induced outage
        + [sample(index, True) for index in range(20, 40)]
    )
    repair = at(15)  # applied while the SLO is broken, as a repair always is
    steady = steady_state_rows(rows, [repair], interval_seconds=1.0)
    assert all(r.ok for r in steady)
    assert len(steady) == 30
    mapping = calibrated_mapping(rows, [repair], interval_seconds=1.0)
    # Wilson upper on 0/30, nowhere near the 10/40 the unfiltered timeline would have given.
    assert mapping["slo_error_rate_max"] < 0.15
    assert mapping["slo_error_rate_max"] == pytest.approx(wilson_upper_bound(0, 30), abs=1e-6)


def test_outage_window_is_empty_when_the_perturbation_never_broke_the_slo() -> None:
    """A repair with no red tick around it yields no window - the previous pilot's silent case."""
    rows = [sample(index, True) for index in range(20)]
    assert outage_windows(probe_ticks(rows), [at(10)]) == []


def test_an_episode_ends_at_the_next_perturbation_not_the_next_repair() -> None:
    """The next cycle's deliberate outage must not retract this cycle's genuine recovery.

    ADR-048: bounding an episode at the next repair leaves the next injection inside it, which
    pinned ``premature`` at one per cycle-with-a-successor on the real run and drove the chosen
    dwell to the resolution floor for a reason unrelated to the system.
    """
    rows = (
        [sample(i, False) for i in range(0, 5)]  # cycle 1 outage (repair lands inside)
        + [sample(i, True) for i in range(5, 40)]  # cycle 1 recovery: clean
        + [sample(i, False) for i in range(40, 45)]  # cycle 2 outage
        + [sample(i, True) for i in range(45, 80)]  # cycle 2 recovery: clean
    )
    repairs = [at(3), at(43)]
    by_dwell = {d: (p, u) for d, p, u in false_recovery_curve(rows, repairs, interval_seconds=1.0)}
    # Cycle 1's recovery is clean; the outage that follows belongs to cycle 2, not to it.
    assert by_dwell[10][0] == 0


def middle_cycle_broke_nothing() -> tuple[list[ProbeResult], list[datetime]]:
    """Three perturbation cycles, the middle one never breaking the SLO (ADR-048 log, 2026-09-11).

    Cycles 1 and 3 are red t=0..9 and t=60..69 and repaired at t=5 and t=65, so each settles 4s
    after its own repair. Cycle 2 is repaired at t=40 inside a green stretch and has no outage
    window; the two windows that exist belong to cycles 1 and 3, whatever their list positions.
    """
    rows = (
        [sample(i, False) for i in range(0, 10)]  # cycle 1 outage, repair at t=5 -> lag 4
        + [sample(i, True) for i in range(10, 60)]  # cycle 2 repair at t=40 breaks nothing
        + [sample(i, False) for i in range(60, 70)]  # cycle 3 outage, repair at t=65 -> lag 4
        + [sample(i, True) for i in range(70, 100)]
    )
    return rows, [at(5), at(40), at(65)]


def test_a_cycle_that_broke_nothing_contributes_no_settling_lag() -> None:
    """Each lag runs from a repair to the end of its own outage, never to a neighbour's.

    ADR-048 log, 2026-09-11: pairing the windows with the sorted repairs by list position handed
    cycle 3's window to cycle 2's repair, and the settling anchor read 29s where both real lags
    are 4s.
    """
    rows, repairs = middle_cycle_broke_nothing()
    # Cycles 1 and 3, each measured on its own, settle 4s after their repairs ...
    assert settling_seconds(rows, [at(5)], interval_seconds=1.0) == 4
    assert settling_seconds(rows, [at(65)], interval_seconds=1.0) == 4
    # ... and cycle 2, which broke nothing, contributes no lag and moves neither of theirs.
    assert settling_seconds(rows, repairs, interval_seconds=1.0) == 4


def test_a_cycle_that_broke_nothing_ends_the_previous_episode_at_its_repair() -> None:
    """Episodes follow ``_episode_bounds``' own rule when a perturbation left no red tick.

    That rule ends an episode where the next outage begins and falls back to the next repair when
    that perturbation broke nothing. Paired by position, cycle 1's episode instead ran on to cycle
    3's outage, and cycle 2's swallowed the start of that outage (ADR-048 log, 2026-09-11).
    """
    rows, repairs = middle_cycle_broke_nothing()
    assert slo_probe._episode_bounds(probe_ticks(rows), repairs) == [
        (at(5), at(40)),  # cycle 2 broke nothing: fall back to its repair
        (at(40), at(60)),  # ends where cycle 3's outage begins
        (at(65), None),  # the last episode is open-ended
    ]


def test_the_calibrated_dwell_reads_each_repairs_own_window() -> None:
    """The calibration path end to end: the dwell and the section 4 block use the fixed pairing.

    Every episode recovers cleanly and neither real lag exceeds 4s, so the smallest clean dwell at
    or above the settling anchor is 4s. Paired by position, cycle 2's episode ran into cycle 3's
    outage and was scored as a retracted recovery, no candidate came out clean, and
    ``calibrated_mapping`` refused the timeline (ADR-048 log, 2026-09-11).
    """
    rows, repairs = middle_cycle_broke_nothing()
    assert stabilization_dwell_seconds(rows, repairs, interval_seconds=1.0) == 4
    mapping = calibrated_mapping(rows, repairs, interval_seconds=1.0)
    assert mapping["stabilization_window_seconds"] == 4


def test_each_outage_window_names_the_repair_it_was_found_from() -> None:
    """The pairing is returned rather than reconstructed, so no consumer can re-pair by position.

    Cycle 2's repair found no window and so has no entry; each of the others carries its own
    repair, and the lags read off the pairs are the two real ones (ADR-048 log, 2026-09-11).
    """
    rows, repairs = middle_cycle_broke_nothing()
    paired = outage_windows(probe_ticks(rows), repairs)
    assert paired == [(at(5), (at(0), at(9))), (at(65), (at(60), at(69)))]
    assert [(end - repair).total_seconds() for repair, (_start, end) in paired] == [4.0, 4.0]


def test_dwell_is_none_without_repair_instants() -> None:
    """A dwell cannot be read off an unlabelled timeline, so none is invented (ADR-048).

    This is the defect ADR-048 records, stated as a test: the old settle reading produced a number
    from any timeline at all, which is exactly why it produced one that meant nothing.
    """
    rows = [sample(index, True) for index in range(10)]
    assert stabilization_dwell_seconds(rows, (), interval_seconds=1.0) is None


def test_dwell_exceeds_a_false_recovery_inside_an_episode() -> None:
    """A green run that the episode itself later retracts must not satisfy the dwell.

    Repair lands at t=0; green for 2s, then red again at t=3, then green from t=4. A 2s dwell
    would declare recovery at t=0 and be retracted; the chosen dwell has to outlast that.
    """
    rows = [
        *[sample(i, False) for i in range(0, 5)],  # the outage; repair applied at t=2
        *[sample(i, True) for i in range(5, 8)],  # a false recovery, spanning t=5..7
        *[sample(i, False) for i in range(8, 10)],  # ... which the system then retracts
        *[sample(i, True) for i in range(10, 60)],  # the genuine recovery
    ]
    repairs = [at(2)]
    by_dwell = {d: (p, u) for d, p, u in false_recovery_curve(rows, repairs, interval_seconds=1.0)}
    # A 2s dwell is satisfied by the false recovery and then retracted; a 3s dwell is not.
    assert by_dwell[2][0] == 1
    assert by_dwell[3][0] == 0
    assert stabilization_dwell_seconds(rows, repairs, interval_seconds=1.0) == 3


def test_dwell_never_reports_below_the_sampling_interval() -> None:
    """A dwell shorter than the sampling interval is not observable by this instrument."""
    rows = [
        *[sample(i, False) for i in range(0, 3)],
        *[sample(i, True) for i in range(3, 80)],
    ]
    assert stabilization_dwell_seconds(rows, [at(1)], interval_seconds=5.0) >= 5


def test_curve_reports_both_failure_modes() -> None:
    """The curve names premature declarations and undeclared episodes, not just one of them.

    The two together are the trade-off the chosen dwell is read off: a dwell long enough that
    nothing retracts it can still be too long for any episode to satisfy.
    """
    rows = [
        sample(0, True),
        sample(1, False),
        *[sample(index, True) for index in range(2, 12)],
    ]
    curve = false_recovery_curve(rows, [at(0)], interval_seconds=1.0)
    assert curve
    assert all(len(entry) == 3 for entry in curve)
    # A dwell longer than the timeline can confirm is undeclared, never a silent success.
    assert curve[-1][2] == 1


def test_classify_is_pending_while_any_threshold_is_uncalibrated() -> None:
    """A flawless timeline is still not a pass while a threshold has never been measured.

    The sentinel mapping is built here rather than read from the real constants: section 4 was
    calibrated at ADR-048, so the live mapping no longer carries a sentinel. The guard this test
    exists for is about what ``classify`` does when one does, and that must stay tested after the
    values are filled -- it is what protects the next uncalibrated environment.
    """
    rows = [sample(index, True) for index in range(6)]
    pending = as_protocol_mapping()
    pending["slo_latency_p95_ms"] = PENDING_CALIBRATION
    verdict = classify(rows, pending)
    assert verdict.state == "PENDING"
    assert verdict.state != "PASS"
    assert [reason for reason in verdict.reasons if "slo_latency_p95_ms" in reason]


def calibrated_fixture(latency_budget: float, error_budget: float, window: int) -> dict:
    """Return a section 4 mapping with fixture thresholds standing in for the pending ones.

    The numbers are fixture values and are not proposals for the protocol; the M1 verification
    greps for each real value appearing in exactly two files, and a plausible number here would be
    a third occurrence.
    """
    mapping = as_protocol_mapping()
    mapping["slo_latency_p95_ms"] = latency_budget
    mapping["slo_error_rate_max"] = error_budget
    mapping["stabilization_window_seconds"] = window
    return mapping


def test_classify_passes_a_timeline_inside_calibrated_budgets() -> None:
    """With thresholds present, a green post-settle timeline passes."""
    rows = [sample(index, True, latency_ms=11.0) for index in range(6)]
    verdict = classify(rows, calibrated_fixture(999.0, 0.5, 2))
    assert verdict.state == "PASS"
    assert verdict.reasons == ()


def test_classify_fails_on_latency_and_names_the_reason() -> None:
    """A breached latency budget is a FAIL whose reason says which budget and by how much."""
    rows = [sample(index, True, latency_ms=888.0) for index in range(6)]
    verdict = classify(rows, calibrated_fixture(1.0, 0.5, 2))
    assert verdict.state == "FAIL"
    assert any("p95 latency" in reason for reason in verdict.reasons)


def test_classify_ignores_the_settle_period() -> None:
    """Failures inside the stabilization window do not count against the SLO."""
    rows = [sample(0, False), sample(1, False), sample(2, True), sample(3, True)]
    verdict = classify(rows, calibrated_fixture(999.0, 0.0001, 2))
    assert verdict.state == "PASS"
    assert verdict.samples == 2


def test_classify_fails_a_timeline_with_no_post_settle_sample() -> None:
    """A run too short to contain a graded sample has not demonstrated anything."""
    rows = [sample(0, True), sample(1, True)]
    verdict = classify(rows, calibrated_fixture(999.0, 0.5, 60))
    assert verdict.state == "FAIL"
    assert any("stabilization window" in reason for reason in verdict.reasons)


def test_calibration_fills_every_measured_key() -> None:
    """``--calibrate`` produces a mapping with no sentinel left in it."""
    rows = [sample(0, False)] + [
        sample(index, True, latency_ms=float(index)) for index in range(1, 8)
    ]
    mapping = calibrated_mapping(rows, [at(0)], interval_seconds=1.0)
    assert PENDING_CALIBRATION not in mapping.values()
    assert mapping["slo_latency_p95_ms"] == 7
    assert mapping["stabilization_window_seconds"] >= 1


def test_calibration_clamps_a_zero_error_rate_to_the_resolution_floor() -> None:
    """With no error observed, the reported bound is one error in n samples, never zero."""
    rows = [
        *[sample(i, False) for i in range(0, 2)],  # the induced outage, removed before measuring
        *[sample(i, True) for i in range(2, 32)],  # steady state: no failure at all
    ]
    mapping = calibrated_mapping(rows, [at(0)], interval_seconds=1.0)
    # Wilson's upper limit for zero failures over the steady-state sample -- the outage rows are
    # not part of it -- and comfortably above that sample's 1/n resolution floor.
    steady = steady_state_rows(rows, [at(0)], interval_seconds=1.0)
    assert all(row.ok for row in steady)
    assert mapping["slo_error_rate_max"] == pytest.approx(
        wilson_upper_bound(0, len(steady)), abs=1e-6
    )
    assert mapping["slo_error_rate_max"] > 1 / len(steady)


def test_read_rows_round_trips_a_written_timeline(tmp_path: Path) -> None:
    """A timeline written and read back yields the same rows, so a bundle re-derives the same block.

    This is the reproducibility claim ``--calibrate-from`` makes: the section 4 values can be
    re-derived from an archived ``probes.csv`` rather than being taken on trust from the run that
    printed them.
    """
    rows = [sample(0, True), sample(1, False), sample(2, True)]
    out = tmp_path / "probes.csv"
    write_rows(rows, out)
    assert read_rows(out) == list(rows)


def test_read_rows_rejects_a_file_that_is_not_a_probes_csv(tmp_path: Path) -> None:
    """A wrong header is named, not silently parsed into a plausible timeline."""
    out = tmp_path / "not-probes.csv"
    out.write_text("a,b\n1,2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not a probes.csv"):
        read_rows(out)


def test_calibration_refuses_a_timeline_with_no_repair_instants() -> None:
    """Without repair instants there is no dwell to measure, and the refusal is explicit.

    ADR-048: the predecessor of this test asserted that an unsettled timeline was refused, which
    it was -- but every *other* timeline got a settle time that the protocol then read as a dwell.
    The refusal that matters is this one.
    """
    rows = [sample(index, True) for index in range(8)]
    with pytest.raises(ValueError, match="no repair instants"):
        calibrated_mapping(rows, interval_seconds=1.0)


def test_calibration_refuses_when_no_dwell_satisfies_every_episode() -> None:
    """A timeline too short to confirm any dwell yields a refusal, not a fallback number."""
    rows = [sample(0, True), sample(1, False)]
    with pytest.raises(ValueError, match="no dwell satisfies"):
        calibrated_mapping(rows, [at(0)], interval_seconds=1.0)


def test_main_writes_the_timeline_and_refuses_to_certify_it(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The end-to-end guard: a perfect run still exits non-zero and says why, loudly.

    ``run_timeline`` is replaced so the entry point never reaches a transport; everything else --
    argument parsing, the CSV write, the verdict, the exit code and the notice -- is the real code
    path an operator runs.
    """

    def fake_timeline(**_kwargs):
        yield from (sample(index, True) for index in range(4))

    monkeypatch.setattr(slo_probe, "run_timeline", fake_timeline)
    # Section 4 is calibrated since ADR-048, so the sentinel is injected to exercise the guard.
    # The guard protects the next environment nobody has measured, so it outlives this calibration.
    pending = as_protocol_mapping()
    pending["slo_latency_p95_ms"] = PENDING_CALIBRATION
    monkeypatch.setattr(slo_probe, "as_protocol_mapping", lambda: dict(pending))
    out = tmp_path / "probes.csv"

    code = slo_probe.main(["--out", str(out), "--samples", "2", "--base-url", "http://x.invalid"])

    assert code == EXIT_THRESHOLDS_PENDING
    assert code != 0
    stderr = capsys.readouterr().err
    assert "SLO VERDICT UNAVAILABLE" in stderr
    assert "uncalibrated" in stderr
    rows = read_csv(out)
    assert rows[0] == EXPECTED_HEADER
    assert len(rows) == 5
