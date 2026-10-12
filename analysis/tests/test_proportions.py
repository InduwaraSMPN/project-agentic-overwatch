r"""The Wilson interval is the uncorrected score interval, and pooling never becomes a grand mean.

These guard the two things `evaluation-protocol.md` §3 fixes about proportion uncertainty: the
variant is `'wilson'`, one of `proportion_confint`'s real methods, and a pooled result stays per
scenario and per condition.
"""

import ast
import math
import sys
from pathlib import Path

import pandas as pd
import pytest
from statsmodels.stats.proportion import proportion_confint

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from analysis.stats import (  # noqa: E402
    pool_binary,
    pool_counts,
    proportions,  # noqa: E402
    wilson_interval,
)


def test_wilson_interval_matches_the_known_statsmodels_value_for_eight_of_ten() -> None:
    """wilson_interval(8, 10) reproduces proportion_confint's uncorrected score interval exactly."""
    result = wilson_interval(8, 10)
    expected_low, expected_high = proportion_confint(8, 10, alpha=0.05, method="wilson")
    assert result.point == pytest.approx(0.8)
    assert result.ci_low == pytest.approx(expected_low)
    assert result.ci_high == pytest.approx(expected_high)
    # The published Wilson bounds for 8/10 at 95%, so the test pins a number and not just the
    # wrapper.
    assert result.ci_low == pytest.approx(0.490162, abs=1e-6)
    assert result.ci_high == pytest.approx(0.943318, abs=1e-6)


_STATSMODELS_PROPORTION_METHODS = frozenset(
    {"normal", "agresti_coull", "beta", "wilson", "jeffreys", "binom_test"}
)


def test_the_method_constant_is_a_real_statsmodels_proportion_method() -> None:
    """The one method constant is ``'wilson'``, and it is a method ``proportion_confint`` actually
    offers.

    `proportion_confint` accepts exactly ``normal``, ``agresti_coull``, ``beta``, ``wilson``,
    ``jeffreys`` and ``binom_test`` -- there is no continuity-corrected Wilson variant to choose, so
    the check is that the constant is a real method and is the uncorrected ``'wilson'`` one, not
    that
    some other named token is absent. This also parses the module to prove no string literal the
    code
    evaluates is a method name statsmodels would reject at call time.
    """
    assert proportions.WILSON_METHOD == "wilson"
    assert proportions.WILSON_METHOD in _STATSMODELS_PROPORTION_METHODS
    tree = ast.parse(Path(proportions.__file__).read_text(encoding="utf-8"))
    method_literals = {
        keyword.value.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        for keyword in node.keywords
        if keyword.arg == "method" and isinstance(keyword.value, ast.Constant)
    }
    assert method_literals <= _STATSMODELS_PROPORTION_METHODS, (
        f"a method= literal is not a real proportion_confint method: "
        f"{method_literals - _STATSMODELS_PROPORTION_METHODS}"
    )


def test_wilson_interval_refuses_an_empty_cell_rather_than_dividing_by_zero() -> None:
    """n = 0 is a gap in the campaign, not a proportion of zero, so it raises."""
    with pytest.raises(ValueError, match="undefined for n=0"):
        wilson_interval(0, 0)


def test_pool_binary_returns_one_interval_per_cell_and_never_a_single_grand_mean() -> None:
    """Pooling a per-seed binary measure yields one Wilson row per (scenario, condition) cell."""
    frame = pd.DataFrame(
        {
            "scenario_id": ["SCN-CVE-04"] * 4,
            "condition": ["G0-FULL", "G0-FULL", "S2-FLAT", "S2-FLAT"],
            "injection_condition": ["INJ-A"] * 4,
            "seed": [101, 102, 101, 102],
            "correct": [1, 1, 0, 1],
        }
    )
    pooled = pool_binary(
        frame, value_column="correct", by=["scenario_id", "condition", "injection_condition"]
    )
    assert len(pooled) == 2  # one per condition, not one grand mean
    assert set(pooled["condition"]) == {"G0-FULL", "S2-FLAT"}
    g0 = pooled[pooled["condition"] == "G0-FULL"].iloc[0]
    assert g0["k"] == 2
    assert g0["n"] == 2


def test_pool_binary_refuses_to_collapse_scenario_or_condition() -> None:
    """A pooling that drops scenario_id or condition is the grand mean §3 forbids, so it raises."""
    frame = pd.DataFrame(
        {
            "scenario_id": ["SCN-CVE-04", "SCN-CVE-04"],
            "condition": ["G0-FULL", "S2-FLAT"],
            "injection_condition": ["INJ-A", "INJ-A"],
            "seed": [101, 101],
            "correct": [1, 0],
        }
    )
    with pytest.raises(ValueError, match="scenario_id.*condition|grand mean"):
        pool_binary(frame, value_column="correct", by=["scenario_id"])


def test_pool_binary_rejects_a_non_binary_measure() -> None:
    """Continuous measures use medians and IQR, not Wilson, so a non-0/1 column raises."""
    frame = pd.DataFrame(
        {
            "scenario_id": ["SCN-CVE-04"],
            "condition": ["G0-FULL"],
            "injection_condition": ["INJ-A"],
            "seed": [101],
            "latency": [3.5],
        }
    )
    with pytest.raises(ValueError, match="0/1 measure"):
        pool_binary(
            frame, value_column="latency", by=["scenario_id", "condition", "injection_condition"]
        )


def test_pool_counts_reports_an_empty_cell_as_nan_instead_of_raising() -> None:
    """A pooled cell whose counts sum to n=0 is real data (zero attempts of this kind in every
    run of the cell), not a campaign gap, so pool_counts must report it rather than let
    wilson_interval's n=0 raise take down the whole pipeline (the crash this test guards)."""
    frame = pd.DataFrame(
        {
            "scenario_id": ["SCN-CVE-04", "SCN-CVE-04", "SCN-CVE-07", "SCN-CVE-07"],
            "condition": ["G0-FULL", "G0-FULL", "G0-FULL", "G0-FULL"],
            "successes": [0, 0, 3, 4],
            "attempts": [0, 0, 5, 5],
        }
    )
    pooled = pool_counts(
        frame, k_column="successes", n_column="attempts", by=["scenario_id", "condition"]
    )
    assert len(pooled) == 2

    empty_cell = pooled[pooled["scenario_id"] == "SCN-CVE-04"].iloc[0]
    assert empty_cell["k"] == 0
    assert empty_cell["n"] == 0
    assert math.isnan(empty_cell["point"])
    assert math.isnan(empty_cell["ci_low"])
    assert math.isnan(empty_cell["ci_high"])
    assert empty_cell["method"] == proportions.WILSON_METHOD

    normal_cell = pooled[pooled["scenario_id"] == "SCN-CVE-07"].iloc[0]
    expected_low, expected_high = proportion_confint(7, 10, alpha=0.05, method="wilson")
    assert normal_cell["k"] == 7
    assert normal_cell["n"] == 10
    assert normal_cell["point"] == pytest.approx(0.7)
    assert normal_cell["ci_low"] == pytest.approx(expected_low)
    assert normal_cell["ci_high"] == pytest.approx(expected_high)
