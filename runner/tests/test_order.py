r"""The interleaving order (T-24) and the pilot coverage order (M10 plan §6, ADR-120).

The campaign properties are asserted directly rather than trusted from the construction or frozen
into a golden file: within every scenario block no two consecutive grid runs share an arm or an
injection condition; every cell appears once; no baseline sits at an end; each baseline sits at the
independently computed median of its dependents; and two generations at one seed are identical.
Asserting the median independently is what stops a generator bug being frozen into the fixture that
checks it.

THE PILOT HALF IS A DIFFERENT CLAIM AND IS CHECKED DIFFERENTLY
--------------------------------------------------------------
The P2/P3 coverage passes (below the ``PILOT ORDER`` heading) are not a relabeling of anything and
are not derived from a seed; they are an Eulerian circuit over the complete directed graph on the
six
arms. The properties asserted for them are the ones plan §6 actually states -- every arm of a cell
shares one scenario, the two passes together cover all 30 ordered arm adjacencies, and P3 is P2's
literal reverse -- plus the coverage property the design needs and the plan does not spell out, that
each of the 30 ``(arm, injection condition)`` cells appears exactly once. All five are computed here
from the generated order rather than read off the generator, and none is a recorded golden value.
"""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from runner.grid import (  # noqa: E402
    PILOT_PASS_SEEDS,
    PILOT_SEEDS,
    SEEDS,
    build_campaign_manifest,
    scenario_ids,
)
from runner.ids import (  # noqa: E402
    BASELINE_ID_PATTERN,
    CANONICAL_ARMS,
    INJECTION_CONDITIONS,
    RUN_ID_PATTERN,
    parse_baseline_id,
    parse_run_id,
)
from runner.order import (  # noqa: E402
    OrderError,
    eulerian_circuit,
    generate_order,
    generate_pilot_order,
    pilot_scenario_map,
)

CAMPAIGN = "CAMP-20260827-pilot"


def _order(seed: int = 101) -> tuple[str, ...]:
    return generate_order(build_campaign_manifest(CAMPAIGN), seed)


def _is_run(identifier: str) -> bool:
    return RUN_ID_PATTERN.match(identifier) is not None


def test_no_two_consecutive_grid_runs_share_an_axis_within_a_scenario_block() -> None:
    """Neither arm nor injection condition is ever blocked -- the point of §5.2's interleaving.

    A baseline breaks the adjacency chain (it carries neither axis), so the check resets across one.
    """
    order = _order()
    previous = None
    for identifier in order:
        if not _is_run(identifier):
            previous = None
            continue
        run = parse_run_id(identifier)
        if previous is not None and previous.scenario_id == run.scenario_id:
            assert previous.condition != run.condition, f"blocked arm at {identifier}"
            assert previous.injection_condition != run.injection_condition, (
                f"blocked injection at {identifier}"
            )
        previous = run


def test_every_grid_cell_appears_exactly_once() -> None:
    order = _order()
    grid = [identifier for identifier in order if _is_run(identifier)]
    assert len(grid) == 750
    assert len(set(grid)) == 750


def test_no_baseline_sits_at_either_end() -> None:
    """Blocking baselines at an end is forbidden for the reason blocking an arm is (§5.2)."""
    order = _order()
    assert _is_run(order[0])
    assert _is_run(order[-1])


def test_each_baseline_is_at_the_median_of_its_dependents() -> None:
    """Placement equals an independently computed median, not a recorded golden value."""
    order = _order()
    grid_positions = {identifier: index for index, identifier in enumerate(order)}
    for identifier in order:
        if BASELINE_ID_PATTERN.match(identifier) is None:
            continue
        baseline = parse_baseline_id(identifier)
        dependents = [
            index
            for other, index in grid_positions.items()
            if _is_run(other)
            and parse_run_id(other).condition == "G0-FULL"
            and parse_run_id(other).seed == baseline.seed
        ]
        # the median of the dependents' positions in the FINAL order, computed independently
        pos = order.index(identifier)
        below = sum(1 for d in dependents if d < pos)
        above = sum(1 for d in dependents if d > pos)
        # a true median splits the dependents as evenly as an odd/even count allows
        assert abs(below - above) <= 1, f"{identifier}: {below} before, {above} after"


def test_two_generations_at_one_seed_are_identical() -> None:
    assert _order(101) == _order(101)


def test_two_different_seeds_differ() -> None:
    assert _order(101) != _order(202)


def test_the_reduced_grid_orders_too() -> None:
    """The coprime construction holds for the three-seed reduction path as well as the five."""
    from runner.grid import REDUCTION_SEEDS

    manifest = build_campaign_manifest(CAMPAIGN, seeds=REDUCTION_SEEDS)
    order = generate_order(manifest, 101)
    grid = [identifier for identifier in order if _is_run(identifier)]
    assert len(grid) == 6 * 25 * 3
    previous = None
    for identifier in order:
        if not _is_run(identifier):
            previous = None
            continue
        run = parse_run_id(identifier)
        if previous is not None and previous.scenario_id == run.scenario_id:
            assert previous.condition != run.condition
            assert previous.injection_condition != run.injection_condition
        previous = run


# ================================================================================================
# PILOT ORDER -- the P2/P3 coverage passes (M10 plan §6, ADR-120)
# ================================================================================================
#
# 6 arms x 5 injection conditions = 30 runs per pass, the arm sequence an Eulerian circuit over the
# complete directed graph on the six arms, the scenario a function of the injection condition only,
# and P3 the literal reverse of P2. Everything below is recomputed from the generated order.


def _arms(pass_name: str) -> tuple[str, ...]:
    return tuple(cell.condition for cell in generate_pilot_order(pass_name))


def _adjacencies(arms: tuple[str, ...]) -> set[tuple[str, str]]:
    """The ordered arm pairs two CONSECUTIVE runs exercise: a linear sequence of n has n-1."""
    return {(arms[index], arms[index + 1]) for index in range(len(arms) - 1)}


def test_pilot_cells_share_scenario_across_arms() -> None:
    """Plan §6: "the scenario of a cell is a function of its injection condition only".

    So all six arms of one injection condition share a scenario, and therefore share a matched pair
    -- which is the property the whole coverage pass exists to buy. Checked in both directions: one
    scenario per injection condition, and no scenario shared by two injection conditions (a scenario
    map that collapsed would make "shared" true vacuously).

    The P3 half matters as much as the P2 half: P3 shifts the map by one, so the SAME injection
    condition lands in a DIFFERENT scenario there -- which is the point of the shift (INJ-D has to
    be
    tested against both a containment landing phase and an eradication one).
    """
    p2 = generate_pilot_order("P2")
    p3 = generate_pilot_order("P3")
    for cells in (p2, p3):
        by_injection: dict[str, set[str]] = {}
        for cell in cells:
            by_injection.setdefault(cell.injection_condition, set()).add(cell.scenario_id)
        assert set(by_injection) == set(INJECTION_CONDITIONS)
        for injection, scenarios in by_injection.items():
            assert len(scenarios) == 1, (
                f"{injection} lands in {sorted(scenarios)}, not one scenario"
            )
        # and the map is injective over the five injection conditions
        assert len({next(iter(v)) for v in by_injection.values()}) == len(INJECTION_CONDITIONS)

    # The shift is real: every injection condition changes scenario between the two passes.
    p2_map = {cell.injection_condition: cell.scenario_id for cell in p2}
    p3_map = {cell.injection_condition: cell.scenario_id for cell in p3}
    assert all(p2_map[key] != p3_map[key] for key in p2_map)
    assert set(p2_map.values()) == set(scenario_ids()) == set(p3_map.values())


def test_pilot_order_covers_every_ordered_arm_pair() -> None:
    """Plan §6: "the two passes together cover all 30 ordered arm adjacencies" (P5).

    6 arms give 30 ordered pairs ``(a, b)``, ``a != b``. A linear sequence of 30 runs has 29
    consecutive adjacencies, so P2 alone reaches 29 of them and omits exactly one; P3's sequence is
    the reverse, so it omits the reverse of that one, and no ordered pair equals its own reverse.
    The
    union is therefore the complete set -- asserted here as a set comparison, not as an argument.

    Also asserted, because the plan's sentence is easy to satisfy accidentally: no two consecutive
    runs of EITHER pass share an arm. That is the property the Eulerian circuit was chosen for, and
    it is the one defect V2 (aggregator configuration carrying over between runs) needs tested.
    """
    p2_arms, p3_arms = _arms("P2"), _arms("P3")
    every_pair = {(a, b) for a in CANONICAL_ARMS for b in CANONICAL_ARMS if a != b}
    assert len(every_pair) == 30

    for arms in (p2_arms, p3_arms):
        assert all(arms[index] != arms[index + 1] for index in range(len(arms) - 1)), (
            "two consecutive runs share an arm"
        )

    covered = _adjacencies(p2_arms) | _adjacencies(p3_arms)
    assert covered == every_pair
    # The arithmetic, stated so a reader can see WHY the union is complete rather than assuming it.
    # P2 omits exactly one ordered pair; P3's adjacencies are the reverses of P2's, so P3 omits
    # exactly one too -- and they are NOT the same one, because no ordered pair of two distinct arms
    # equals its own reverse. Two different omissions leave nothing for the union to miss.
    missing_from_p2 = every_pair - _adjacencies(p2_arms)
    missing_from_p3 = every_pair - _adjacencies(p3_arms)
    assert len(missing_from_p2) == len(missing_from_p3) == 1
    assert missing_from_p2 != missing_from_p3
    only_missed = next(iter(missing_from_p2))
    assert (only_missed[1], only_missed[0]) == next(iter(missing_from_p3))
    # Each pass therefore supplies the other's single gap.
    assert only_missed in _adjacencies(p3_arms)
    assert next(iter(missing_from_p3)) in _adjacencies(p2_arms)


def test_p3_reverses_p2s_arm_sequence() -> None:
    """Plan §6: "the arm order is the literal reverse of P2's".

    Literal, not "equivalent up to a relabeling": the two passes must exercise the same adjacencies
    in opposite order, so a carry-over seen in P2 has a mirror in P3. Asserted on the arms, and
    separately on the fact that the two passes differ in everything else the plan says they differ
    in -- the seed and the scenario map -- so the reversal is not an accident of two identical
    passes.
    """
    p2, p3 = generate_pilot_order("P2"), generate_pilot_order("P3")
    assert [cell.condition for cell in p3] == [cell.condition for cell in reversed(p2)]
    assert [cell.step for cell in p3] == list(range(1, len(p3) + 1))

    # Same cells, so the reversal really is of the ARM sequence and not of a re-drawn grid.
    assert {(c.condition, c.injection_condition) for c in p2} == {
        (c.condition, c.injection_condition) for c in p3
    }
    # The seed and the scenario map do differ, as §6 requires.
    assert {cell.seed for cell in p2} == {PILOT_PASS_SEEDS["P2"]}
    assert {cell.seed for cell in p3} == {PILOT_PASS_SEEDS["P3"]}
    assert PILOT_SEEDS[0] not in SEEDS and PILOT_SEEDS[1] not in SEEDS
    assert [c.scenario_id for c in p2] != [c.scenario_id for c in p3]


def test_every_pilot_cell_appears_exactly_once_and_the_pass_is_the_protocols_size() -> None:
    """The coverage property, and the count the protocol fixes -- 6 arms x 5 injections, once each.

    The count is asserted against ``runner.pilot_cli``'s mirrored protocol constant rather than a
    literal, so a change to the arms or the injection conditions fails here and at
    ``coverage_order`` rather than quietly producing a pass one run short.
    """
    from runner.pilot_cli import COVERAGE_PASSES, STAGE_RUNS, coverage_order

    for stage, pass_name in sorted(COVERAGE_PASSES.items()):
        cells = generate_pilot_order(pass_name)
        assert len(cells) == STAGE_RUNS[stage]
        assert len(coverage_order(stage)) == STAGE_RUNS[stage]
        assert len({(c.condition, c.injection_condition) for c in cells}) == len(cells)
        assert {c.condition for c in cells} == set(CANONICAL_ARMS)
        assert {c.injection_condition for c in cells} == set(INJECTION_CONDITIONS)
        # Every cell's run id parses back to the four coordinates the cell carries, so the pilot
        # plan is consumable by the same parser the campaign validator uses.
        for cell in cells:
            parsed = parse_run_id(cell.run_id)
            assert parsed.condition == cell.condition
            assert parsed.scenario_id == cell.scenario_id
            assert parsed.injection_condition == cell.injection_condition
            assert parsed.seed == cell.seed


def test_the_pilot_order_is_reproducible_and_rejects_an_unknown_pass() -> None:
    """No seed, no clock, no container iteration: two calls agree, and a typo is an error.

    Iron rule 3 makes this a requirement rather than a nicety -- the ladder is a pre-registration,
    and
    a pre-registration that regenerated differently on a re-run would be worthless.
    """
    assert generate_pilot_order("P2") == generate_pilot_order("P2")
    assert generate_pilot_order("P3") == generate_pilot_order("P3")
    for bad in ("P1", "p2", "", "P4"):
        with pytest.raises(OrderError):
            generate_pilot_order(bad)
    with pytest.raises(OrderError):
        pilot_scenario_map("INJ-Z", "P2")


def test_eulerian_circuit_is_a_closed_eulerian_walk_over_the_complete_digraph() -> None:
    """The circuit, checked as one: right length, closed, every ordered pair used exactly once.

    Checked on a five-node instance as well as the six arms, so the property is not an accident of
    one graph size, and so the function's contract is stated for "the complete directed graph on n
    nodes" rather than for "six things we happen to have".
    """
    for nodes in (("a", "b", "c", "d", "e", "f"), ("a", "b", "c", "d", "e")):
        walk = eulerian_circuit(nodes)
        assert len(walk) == len(nodes) * (len(nodes) - 1) + 1
        assert walk[0] == walk[-1]
        assert set(walk) == set(nodes)
        edges = [(walk[index], walk[index + 1]) for index in range(len(walk) - 1)]
        assert len(edges) == len(set(edges)) == len(nodes) * (len(nodes) - 1)
        assert set(edges) == {(a, b) for a in nodes for b in nodes if a != b}
        # reproducible: the successor order is positional, never a container's iteration order
        assert eulerian_circuit(nodes) == walk
    with pytest.raises(OrderError):
        eulerian_circuit(("only",))
