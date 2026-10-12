r"""The grid closes on 750 both ways; the 875 over-count is the thing guarded against.

evaluation-protocol §2 states that a per-study summation "computes 875 against the real grid ... and
would reject the real 750-run grid". So the 875 figure appears in this suite as an explicit
assertion -- the defect the arithmetic is counted-over-arms to avoid -- rather than only as prose.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from runner.grid import (  # noqa: E402
    REDUCTION_SEEDS,
    SEEDS,
    base_cells,
    build_campaign_manifest,
    expected_total,
    grid_cells,
    per_study_overcount,
    scenario_ids,
)
from runner.ids import CANONICAL_ARMS, INJECTION_CONDITIONS  # noqa: E402


def test_five_scenarios_are_present() -> None:
    """§3.5.6 fixes the count at five; the grid is undefined on a corpus of another size."""
    assert len(scenario_ids()) == 5


def test_base_cells_are_five_by_five() -> None:
    """Five scenarios x five injection-condition values, INJ-NONE counted like a class."""
    assert len(base_cells()) == 5 * len(INJECTION_CONDITIONS)
    assert len(base_cells()) == 25


def test_grid_closes_on_750_over_arms() -> None:
    assert expected_total() == len(CANONICAL_ARMS) * 25 * len(SEEDS)
    assert expected_total() == 750
    assert len(grid_cells()) == 750


def test_study_wise_arithmetic_closes_the_same() -> None:
    """375 + 500 - 125 = 750, the shared full-architecture arm subtracted once."""
    structure = 3 * len(base_cells()) * len(SEEDS)  # G0-FULL, S2-FLAT, S3-SINGLE
    guardrail = 4 * len(base_cells()) * len(SEEDS)  # G0-FULL, G1, G2, G3
    shared = len(base_cells()) * len(SEEDS)
    assert structure == 375
    assert guardrail == 500
    assert structure + guardrail - shared == 750


def test_per_study_summation_reaches_the_rejected_875() -> None:
    """The thing the counted-over-arms arithmetic exists to avoid, asserted not described."""
    assert per_study_overcount() == 875
    assert per_study_overcount() != expected_total()


def test_reduction_path_is_three_seeds() -> None:
    assert expected_total(REDUCTION_SEEDS) == 6 * 25 * 3
    assert len(REDUCTION_SEEDS) == 3


def test_build_campaign_manifest_is_the_real_grid_plus_baselines() -> None:
    """750 grid runs, is_baseline false, plus one baseline per (load, seed): 5 for one profile."""
    manifest = build_campaign_manifest("CAMP-20260827-pilot")
    grid = [run for run in manifest.runs if not run.is_baseline]
    baselines = [run for run in manifest.runs if run.is_baseline]
    assert len(grid) == 750
    assert len(baselines) == len(SEEDS)
    # Only the RQ4 arm names a baseline; every ablated-arm run leaves it null.
    g0 = [run for run in grid if run.condition == "G0-FULL"]
    ablated = [run for run in grid if run.condition != "G0-FULL"]
    assert all(run.baseline_run_id is not None for run in g0)
    assert all(run.baseline_run_id is None for run in ablated)
