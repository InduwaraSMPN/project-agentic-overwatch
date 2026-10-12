r"""The planner is pure, seeded, and produces the injected sequences the determinism gate diffs.

The gate scripts/scenario_determinism.sh proves determinism over the whole matrix in two processes;
these tests prove the properties that make that gate meaningful, in one process, close to the code:
INJ-NONE is non-empty, two conditions at one seed do not share a stream, the planner reads
nothing but its arguments, and the payload rotation (M10 WS-2, D8) gives every pool instance a
cell to be drawn in and gives every cell the same payload in every arm.
"""

import datetime
import inspect
import io
import re
import sys
from contextlib import redirect_stdout
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402

from scenarios.attackers import INJECTION_CLASSES  # noqa: E402
from scenarios.attackers import content as content_registry  # noqa: E402
from scenarios.attackers import plan as planner  # noqa: E402

SCENARIO_IDS = planner.manifest_ids()
# The glossary's fixed set; referenced, not owned. Two of them are enough to prove the properties.
SAMPLE_SEEDS = (101, 105)

# The six arm spellings the campaign grid runs (docs/07-glossary-and-ids.md, conditions). Spelled
# here rather than imported from the runner because the runner owns the ORDER these are run in and
# this test is about the planner's blindness to them; the two lists must agree, and
# `test_the_arm_list_is_the_campaign_six` below is the check that keeps the copy honest.
ARMS = (
    "G0-FULL",
    "G1-LOGONLY",
    "G2-SHAREDCRED",
    "G3-UNQUOTED",
    "S2-FLAT",
    "S3-SINGLE",
)


def _lines(scenario_id: str, condition: str, seed: int) -> list[bytes]:
    events = planner.plan_cell(scenario_id, condition, seed)
    return [planner.canonical_json_line(event) for event in events]


@pytest.mark.parametrize("scenario_id", SCENARIO_IDS)
@pytest.mark.parametrize("seed", SAMPLE_SEEDS)
def test_two_plannings_of_one_cell_are_byte_identical(scenario_id: str, seed: int) -> None:
    """The property traceability row T-17 closes against, at the unit level."""
    first = _lines(scenario_id, "INJ-B", seed)
    second = _lines(scenario_id, "INJ-B", seed)
    assert first == second


@pytest.mark.parametrize("scenario_id", SCENARIO_IDS)
def test_inj_none_plan_is_non_empty_with_no_injection_class_events(scenario_id: str) -> None:
    """T-36: INJ-NONE is a grid coordinate, not an absence. The incident fires; nothing is injected
    at the agent layer."""
    events = planner.plan_cell(scenario_id, "INJ-NONE", 101)
    assert events, f"{scenario_id}: INJ-NONE planned an empty sequence"
    assert all(event["kind"] == "incident" for event in events)
    assert all(event["injection_class"] is None for event in events)


@pytest.mark.parametrize("scenario_id", SCENARIO_IDS)
def test_two_injection_conditions_at_one_seed_do_not_share_a_stream(scenario_id: str) -> None:
    """The seed derivation includes the injection condition, so INJ-B and INJ-D at seed 101 draw
    different jitter, replicas and payloads. Without this the axis RQ5 contrasts on would carry a
    hidden correlation."""
    plan_b = planner.plan_cell(scenario_id, "INJ-B", 101)
    plan_d = planner.plan_cell(scenario_id, "INJ-D", 101)
    incident_b = [e for e in plan_b if e["kind"] == "incident"]
    incident_d = [e for e in plan_d if e["kind"] == "incident"]
    offsets_b = [e["offset_ms"] for e in incident_b]
    offsets_d = [e["offset_ms"] for e in incident_d]
    assert offsets_b != offsets_d, (
        f"{scenario_id}: the incident offsets are identical across INJ-B and INJ-D at one seed, so "
        "the generator is not keyed on the injection condition"
    )


@pytest.mark.parametrize("scenario_id", SCENARIO_IDS)
def test_two_seeds_differ(scenario_id: str) -> None:
    """Different seeds produce different plans; a seed that changed nothing would make the
    multi-seed design pointless."""
    a = _lines(scenario_id, "INJ-B", 101)
    b = _lines(scenario_id, "INJ-B", 105)
    assert a != b


@pytest.mark.parametrize("scenario_id", SCENARIO_IDS)
def test_event_count_is_seed_independent(scenario_id: str) -> None:
    """How many events fire is a property of the manifest, never of the seed -- which is what lets
    data-management.md section 3 compare one bundle's log length to one ground-truth number."""
    manifest = planner.load_manifest(scenario_id)
    for condition in ("INJ-NONE",) + tuple(INJECTION_CLASSES):
        counts = {
            len(planner.plan_cell(scenario_id, condition, seed))
            for seed in (101, 102, 103, 104, 105)
        }
        assert counts == {planner.expected_event_count(manifest, condition)}, (
            f"{scenario_id} {condition}: event count varies with the seed: {counts}"
        )


@pytest.mark.parametrize("scenario_id", SCENARIO_IDS)
def test_every_event_validates_against_the_plan_schema(scenario_id: str) -> None:
    """The planner asserts this itself before writing, but a test makes the guarantee independent of
    the write path."""
    for condition in ("INJ-NONE", "INJ-A", "INJ-B", "INJ-C", "INJ-D"):
        # plan_cell raises PlanError if any event fails the schema; reaching the assert is the pass
        events = planner.plan_cell(scenario_id, condition, 102)
        assert events


@pytest.mark.parametrize("scenario_id", SCENARIO_IDS)
def test_event_ids_are_unique_within_a_plan(scenario_id: str) -> None:
    for condition in ("INJ-NONE", "INJ-A", "INJ-B", "INJ-C", "INJ-D"):
        ids = [event["event_id"] for event in planner.plan_cell(scenario_id, condition, 103)]
        assert len(ids) == len(set(ids))


def test_planner_cli_single_cell_is_deterministic() -> None:
    """The CLI path -- the one the applier and a developer use -- is deterministic too."""
    if not SCENARIO_IDS:
        pytest.skip("no scenarios")
    scenario = SCENARIO_IDS[0]
    outputs = []
    for _ in range(2):
        buffer = io.BytesIO()
        stream = io.TextIOWrapper(buffer, encoding="utf-8", newline="")
        with redirect_stdout(stream):
            code = planner.main(["--scenario", scenario, "--injection", "INJ-A", "--seed", "101"])
        stream.flush()
        assert code == 0
        outputs.append(buffer.getvalue())
    assert outputs[0] == outputs[1]


def test_unknown_injection_condition_is_rejected() -> None:
    if not SCENARIO_IDS:
        pytest.skip("no scenarios")
    with pytest.raises(planner.PlanError):
        planner.plan_cell(SCENARIO_IDS[0], "INJ-Z", 101)


def test_negative_seed_is_rejected() -> None:
    if not SCENARIO_IDS:
        pytest.skip("no scenarios")
    with pytest.raises(planner.PlanError):
        planner.plan_cell(SCENARIO_IDS[0], "INJ-A", -1)


# --- M10 WS-2, D8: the balanced payload rotation, and the coverage guarantee it exists for --------


def _drawn_payload_ids(scenario_id: str, condition: str) -> dict[int, str]:
    """The payload each seed of one ``(scenario, class)`` cell draws, by seed."""
    drawn = {}
    for seed in planner.CANONICAL_SEEDS:
        events = planner.plan_cell(scenario_id, condition, seed)
        injections = [event for event in events if event["kind"] == "injection"]
        assert len(injections) == 1, f"{scenario_id} {condition} seed {seed}: {len(injections)}"
        drawn[seed] = str(injections[0]["payload_id"])
    return drawn


@pytest.mark.parametrize("injection_class", INJECTION_CLASSES)
def test_every_payload_drawn_in_full_grid(injection_class: str) -> None:
    """Every instance of every pool is drawn by some cell of the full grid (defect V25).

    Two properties, and the second is the one that was broken. The v1 draw was one
    ``rng.randrange`` per cell, so across the five seeds of a ``(scenario, class)`` cell a pool of
    six saw three to five of its own instances and the rest were delivered by *no run at all* --
    measured over the v1 campaign as "3-5 of 6 per cell" (plan section 1, V25). A whole-grid
    coverage check alone would NOT have caught that: the hashed draw happened to reach every
    instance across the hundred cells, by luck rather than by construction, which is exactly why
    the guarantee has to be per cell. So this asserts both ends of it:

    1. the union over the grid is the whole pool, and
    2. within one cell the five seeds draw five *different* instances, which is what makes (1) a
       property of the corpus rather than of the draw.

    The rotation gives a scenario's five seeds five consecutive slots, and no pool is smaller than
    five instances (``content.MIN_INSTANCES``), so (2) holds for every pool in the corpus.
    """
    if not SCENARIO_IDS:
        pytest.skip("no scenarios")
    per_cell: dict[str, list[str]] = {}
    for scenario_id in SCENARIO_IDS:
        drawn = _drawn_payload_ids(scenario_id, injection_class)
        assert len(set(drawn.values())) == len(drawn), (
            f"{scenario_id} {injection_class}: five seeds drew {len(set(drawn.values()))} distinct "
            f"payload(s) {sorted(drawn.values())}. A cell that repeats a payload cannot cover its "
            "pool, however many cells the grid has."
        )
        per_cell[scenario_id] = list(drawn.values())

    pool_ids = {
        planner.load_manifest(scenario_id)["injection_points"][injection_class]["content_pool"]
        for scenario_id in SCENARIO_IDS
    }
    assert len(pool_ids) == 1, (
        f"{injection_class}: the corpus names more than one pool {sorted(pool_ids)}; one"
        " class draws from one pool, so a second name means a second rotation nothing checks"
    )
    [pool_id] = pool_ids
    drawn_anywhere = {payload for values in per_cell.values() for payload in values}
    expected = {instance.payload_id for instance in content_registry.load_pool(pool_id).instances}
    assert drawn_anywhere == expected, (
        f"{pool_id}: the full grid never draws {sorted(expected - drawn_anywhere)} and draws "
        f"{sorted(drawn_anywhere - expected)} which the pool does not hold"
    )


def test_the_canonical_seed_set_still_equals_the_glossaries() -> None:
    """``CANONICAL_SEEDS`` is a mirror of docs/07-glossary-and-ids.md's Seeds section.

    The rotation indexes a seed's *position* in that set, so a set edited in the glossary and not
    here would silently re-order which payload every past seed drew -- the same class of silent
    change the pool loader's contiguity check exists to prevent, one level up. Parsed from the
    glossary rather than imported, because the glossary is the single home
    (``.agents/rules/00-source-of-truth.md``).
    """
    text = (REPO_ROOT / "docs" / "07-glossary-and-ids.md").read_text(encoding="utf-8")
    section = text[text.index("## Seeds") :]
    match = re.search(
        r"Kit-canonical fixed seed set \(pre-registered here\):\s*`\{([^}]*)\}`", section
    )
    assert match is not None, "the glossary's Seeds section no longer states the canonical set"
    declared = tuple(int(token) for token in match.group(1).split(","))
    assert planner.CANONICAL_SEEDS == declared, (
        f"planner.CANONICAL_SEEDS {planner.CANONICAL_SEEDS} is not the glossary's {declared}"
    )
    # A pilot seed is disjoint from the campaign set (glossary, M10 ADR-120) and must still take a
    # slot of its own rather than landing on a campaign seed's payload.
    pilot = re.search(r"pilot seed A = `(\d+)`", section)
    assert pilot is not None
    seed = int(pilot.group(1))
    assert seed not in planner.CANONICAL_SEEDS
    assert planner.seed_slot(seed) >= len(planner.CANONICAL_SEEDS)
    assert planner.seed_slot(seed) != planner.seed_slot(seed + 1)


def test_the_arm_list_is_the_campaign_six() -> None:
    """The copy above is checked against the runner's own condition list, not trusted."""
    from runner.conditions import CONDITION_FLAGS  # imported here: not needed at module import

    assert set(ARMS) == set(CONDITION_FLAGS)


def test_draw_is_independent_of_arm() -> None:
    """One cell faces one attack in every arm, so a matched pair's contrast is the arm's.

    The rotation's coordinates are a scenario's index in the canonical manifest list and a seed's
    index in the canonical seed set. None of them is an arm, and the signature makes that structural
    rather than incidental: the draw is handed a pool and three integers, so there is no argument an
    arm could arrive through. The second half is the property itself, checked through the applier,
    which is where an arm first exists as a value: the same cell applied under all six run-id
    spellings produces the same event stream, the same payload, and the same targets, with the
    records differing only in the ``applied`` block the applier stamps per run.
    """
    if not SCENARIO_IDS:
        pytest.skip("no scenarios")
    parameters = inspect.signature(content_registry.draw).parameters
    assert set(parameters) == {"pool", "scenario_index", "seed_index", "seed_count"}, (
        f"draw's signature is {sorted(parameters)}; the rotation takes a pool and three grid "
        "coordinates and nothing else, so no arm can reach it"
    )
    assert not any(
        token in name
        for name in parameters
        for token in ("arm", "condition_id", "run", "run_id", "guardrail")
    )

    from scenarios.attackers import apply as applier  # the applier, not the planner, stamps the run

    scenario_id = SCENARIO_IDS[0]
    streams = {}
    for arm in ARMS:
        run_id = f"RUN-{arm}-{scenario_id}-INJ-A-101"
        events = planner.plan_cell(scenario_id, "INJ-A", 101)
        records = applier.apply_plan(
            events,
            run_id,
            adapter=applier.OfflineAdapter(),
            sleeper=lambda _: None,
            monotonic=lambda: 0.0,
            wall_clock=lambda: datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC),
        ).records
        # Drop the applier's own per-run block: the run id and the wall clock are the only fields a
        # run is allowed to add, and they are exactly what must not change the attack.
        streams[arm] = tuple(
            planner.canonical_json_line({k: v for k, v in record.items() if k != "applied"})
            for record in records
        )
    distinct = set(streams.values())
    assert len(distinct) == 1, (
        f"the same cell planned different event streams under different arms: "
        f"{sorted({arm for arm, stream in streams.items() if stream != streams[ARMS[0]]})}"
    )
