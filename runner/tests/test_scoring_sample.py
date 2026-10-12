"""Prospective D2 sampling from planned cells, before outcomes exist."""

from __future__ import annotations

import json
import sys
from itertools import product
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402
from scripts.scoring_sample import SamplingError, build_sample  # noqa: E402

from runner.ids import CANONICAL_ARMS  # noqa: E402
from scripts import scoring_sample  # noqa: E402

SCENARIOS = ("SCN-SIM-01", "SCN-SIM-02")
INJECTIONS = ("INJ-A", "INJ-NONE")
SEEDS = (101, 102, 103)
CAMPAIGN_ID = "CAMP-TEST-scoring-sample"
CAMPAIGN_SEED = 7


@pytest.fixture(scope="module")
def campaign_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A small planned campaign with no outcome bundles."""
    directory = tmp_path_factory.mktemp("scoring-sample-plan")
    runs = [
        dict(
            scenario_id=scenario,
            injection_condition=injection,
            seed=seed,
            condition=condition,
            is_baseline=False,
            run_id=f"RUN-{condition}-{scenario}-{injection}-{seed}",
        )
        for scenario, injection, seed, condition in product(
            SCENARIOS, INJECTIONS, SEEDS, CANONICAL_ARMS
        )
    ]
    (directory / "campaign.json").write_text(
        json.dumps(dict(campaign_id=CAMPAIGN_ID, campaign_seed=CAMPAIGN_SEED, runs=runs)),
        encoding="utf-8",
    )
    return directory


# This fixture has 2 scenarios x 2 injections = 4 stage-1 strata/tuples. Scaled-down stage-2
# parameters that mirror the production shape (every scenario keeps >= a floor, a seeded subset
# keeps one more): min_per_scenario=1, tuple_count=3 -> floor 2*1=2, extra_needed=1, so one
# scenario (seeded choice) keeps both its tuples and the other keeps exactly one.
_TEST_TUPLE_COUNT = 3
_TEST_MIN_PER_SCENARIO = 1


def test_build_sample_is_deterministic_byte_for_byte(campaign_dir: Path) -> None:
    """Two independent draws from the same sealed corpus, same parameters, serialize
    identically."""
    first = json.dumps(
        build_sample(
            campaign_dir, tuple_count=_TEST_TUPLE_COUNT, min_per_scenario=_TEST_MIN_PER_SCENARIO
        ),
        indent=2,
        sort_keys=True,
    )
    second = json.dumps(
        build_sample(
            campaign_dir, tuple_count=_TEST_TUPLE_COUNT, min_per_scenario=_TEST_MIN_PER_SCENARIO
        ),
        indent=2,
        sort_keys=True,
    )
    assert first == second


def test_build_sample_stage1_draws_exactly_one_seed_per_stratum_with_all_six_arms(
    campaign_dir: Path,
) -> None:
    """Stage 1 (the original D2 mechanism) is unchanged: requesting every stratum back
    (tuple_count == stage1 strata count, min_per_scenario == injections per scenario) recovers
    the full one-seed-per-stratum draw."""
    document = build_sample(
        campaign_dir,
        tuple_count=len(SCENARIOS) * len(INJECTIONS),
        min_per_scenario=len(INJECTIONS),
    )

    assert document["campaign_id"] == CAMPAIGN_ID
    assert document["campaign_seed"] == CAMPAIGN_SEED
    assert document["condition_order"] == sorted(CANONICAL_ARMS)

    tuples = document["tuples"]
    strata_seen = {(t["scenario_id"], t["injection_condition"]) for t in tuples}
    assert strata_seen == set(product(SCENARIOS, INJECTIONS))
    assert len(tuples) == len(SCENARIOS) * len(INJECTIONS)  # one seed per stratum, no duplicates

    for entry in tuples:
        assert entry["seed"] in SEEDS
        assert set(entry["run_ids"]) == set(CANONICAL_ARMS)
        for condition, run_id in entry["run_ids"].items():
            expected = (
                f"RUN-{condition}-{entry['scenario_id']}-"
                f"{entry['injection_condition']}-{entry['seed']}"
            )
            assert run_id == expected

    flat = document["run_ids"]
    assert len(flat) == len(tuples) * len(CANONICAL_ARMS)
    assert len(set(flat)) == len(flat)  # no duplicate run_ids across the sample
    for entry in tuples:
        for condition in document["condition_order"]:
            assert entry["run_ids"][condition] in flat


def test_build_sample_stage2_keeps_a_balanced_per_scenario_subset(campaign_dir: Path) -> None:
    """The revised D2 stage 2: every scenario keeps >= min_per_scenario tuples, a seeded subset
    keeps one more, the total is exactly tuple_count, and every kept tuple's
    (scenario_id, injection_condition, seed, run_ids) is one stage 1 already drew (a genuine
    subset, not a re-draw)."""
    full = build_sample(
        campaign_dir,
        tuple_count=len(SCENARIOS) * len(INJECTIONS),
        min_per_scenario=len(INJECTIONS),
    )
    full_by_key = {(t["scenario_id"], t["injection_condition"]): t for t in full["tuples"]}

    document = build_sample(
        campaign_dir, tuple_count=_TEST_TUPLE_COUNT, min_per_scenario=_TEST_MIN_PER_SCENARIO
    )

    assert document["tuple_sample_count"] == _TEST_TUPLE_COUNT
    assert document["min_tuples_per_scenario"] == _TEST_MIN_PER_SCENARIO
    assert document["strata_count"] == _TEST_TUPLE_COUNT
    assert len(document["tuples"]) == _TEST_TUPLE_COUNT
    assert document["stage1_strata_count"] == len(SCENARIOS) * len(INJECTIONS)
    assert document["matched_tuple_population"] == len(SCENARIOS) * len(INJECTIONS) * len(SEEDS)
    assert document["sample_fraction"] == pytest.approx(
        _TEST_TUPLE_COUNT / (len(SCENARIOS) * len(INJECTIONS) * len(SEEDS))
    )

    extra_scenarios = document["scenarios_with_extra_tuple"]
    assert set(extra_scenarios) <= set(SCENARIOS)
    counts: dict[str, int] = {}
    for entry in document["tuples"]:
        counts[entry["scenario_id"]] = counts.get(entry["scenario_id"], 0) + 1
        # Distinct injection conditions within a scenario (no stratum drawn twice).
    for scenario_id in SCENARIOS:
        expected = _TEST_MIN_PER_SCENARIO + (1 if scenario_id in extra_scenarios else 0)
        assert counts.get(scenario_id, 0) == expected

    for scenario_id in SCENARIOS:
        injections_seen = [
            t["injection_condition"] for t in document["tuples"] if t["scenario_id"] == scenario_id
        ]
        assert len(injections_seen) == len(set(injections_seen))

    # Every kept tuple is byte-identical to its stage-1 counterpart: stage 2 only removes.
    for entry in document["tuples"]:
        key = (entry["scenario_id"], entry["injection_condition"])
        assert entry == full_by_key[key]

    flat = document["run_ids"]
    assert len(flat) == len(document["tuples"]) * len(CANONICAL_ARMS)
    assert len(set(flat)) == len(flat)


def test_build_sample_rejects_a_tuple_count_below_the_per_scenario_floor(
    campaign_dir: Path,
) -> None:
    with pytest.raises(SamplingError, match="cannot satisfy min_per_scenario"):
        build_sample(campaign_dir, tuple_count=1, min_per_scenario=2)


def test_build_sample_rejects_a_tuple_count_above_the_design_maximum(campaign_dir: Path) -> None:
    # 2 scenarios x (min_per_scenario=1 + 1) = 4 is the max; 5 exceeds it.
    with pytest.raises(SamplingError, match="exceeds the maximum"):
        build_sample(campaign_dir, tuple_count=5, min_per_scenario=1)


def test_default_constants_fit_the_production_five_scenario_grid() -> None:
    """The module's default TUPLE_SAMPLE_COUNT/MIN_TUPLES_PER_SCENARIO are the 13-tuple,
    2-per-scenario-floor-plus-3-extra design D2's 2026-09-23 revision specifies, over the real
    campaign's 5 scenarios -- checked as arithmetic here rather than a second, larger sealed
    fixture, since it is exactly the relationship build_sample enforces at runtime (exercised
    against the small fixture above)."""
    production_scenario_count = 5
    assert scoring_sample.TUPLE_SAMPLE_COUNT == 13
    assert scoring_sample.MIN_TUPLES_PER_SCENARIO == 2
    floor_total = scoring_sample.MIN_TUPLES_PER_SCENARIO * production_scenario_count
    extra_needed = scoring_sample.TUPLE_SAMPLE_COUNT - floor_total
    assert floor_total == 10
    assert extra_needed == 3
    assert 0 <= extra_needed <= production_scenario_count
    # 13 / 125 matched tuples = 10.4%, roughly half the original D2 mechanism's ~20%.
    assert scoring_sample.TUPLE_SAMPLE_COUNT / (production_scenario_count * 5 * 5) == pytest.approx(
        0.104
    )


def test_build_sample_refuses_a_corpus_with_no_framework_on_runs(tmp_path: Path) -> None:
    campaign_id = "CAMP-TEST-empty"
    campaign_dir = tmp_path / campaign_id
    campaign_dir.mkdir()
    (campaign_dir / "campaign.json").write_text(
        json.dumps({"campaign_id": campaign_id, "campaign_seed": 0}), encoding="utf-8"
    )
    with pytest.raises(SamplingError, match="no framework-on runs"):
        build_sample(campaign_dir)


def test_build_sample_requires_campaign_seed_in_the_manifest(tmp_path: Path) -> None:
    campaign_dir = tmp_path / "CAMP-TEST-bad-manifest"
    campaign_dir.mkdir()
    (campaign_dir / "campaign.json").write_text(
        json.dumps({"campaign_id": "CAMP-TEST-bad-manifest"}), encoding="utf-8"
    )
    with pytest.raises(SamplingError, match="campaign_seed"):
        build_sample(campaign_dir)


def test_refuses_after_first_seal(tmp_path: Path, campaign_dir: Path) -> None:
    (tmp_path / "campaign.json").write_bytes((campaign_dir / "campaign.json").read_bytes())
    bundle = tmp_path / "RUN-started"
    bundle.mkdir()
    (bundle / "seal.json").write_text("{}", encoding="utf-8")
    with pytest.raises(SamplingError, match="after first seal"):
        build_sample(tmp_path, tuple_count=3, min_per_scenario=1)


def test_production_plan_supports_prospective_draw(tmp_path: Path) -> None:
    (tmp_path / "campaign.json").write_bytes(
        (REPO_ROOT / "runner/CAMP-20260928-campaign-v2.json").read_bytes()
    )
    sample = build_sample(tmp_path)
    assert len(sample["run_ids"]) == scoring_sample.TUPLE_SAMPLE_COUNT * len(CANONICAL_ARMS)
    assert len(set(sample["run_ids"])) == len(sample["run_ids"])
    assert not list(tmp_path.glob("*/seal.json"))


@pytest.mark.parametrize("defect", ["missing-arm", "duplicate-arm", "duplicate-id"])
def test_rejects_incomplete_or_duplicate_plan(
    tmp_path: Path, campaign_dir: Path, defect: str
) -> None:
    payload = json.loads((campaign_dir / "campaign.json").read_text(encoding="utf-8"))
    if defect == "missing-arm":
        payload["runs"].pop()
    elif defect == "duplicate-arm":
        payload["runs"].append(payload["runs"][0])
    else:
        payload["runs"][1]["run_id"] = payload["runs"][0]["run_id"]
    (tmp_path / "campaign.json").write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SamplingError, match="planned"):
        build_sample(tmp_path, tuple_count=3, min_per_scenario=1)
