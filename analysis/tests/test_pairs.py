r"""Matched-pairs contrasts resolve the S1-HIER alias, pair on all three keys, never pair nothing.

The RQ2 structure contrasts name the shared arm `S1-HIER` while its bundles carry `G0-FULL`; the
alias is resolved in one place, a zero-pair contrast is a hard error, and every rigorous contrast
carries the GATE-fixed worst-case MDD, the realized MDD from its own observed paired-difference SD,
and the GATE-fixed floor marker (ADR-080).
"""

import math
import sys
from pathlib import Path

import pandas as pd
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from analysis.stats import (  # noqa: E402
    BY_CELL,
    EmptyContrastError,
    contrast,
    grouped_contrast,
    matched_pairs,
    mdd_support_label,
    minimum_detectable_difference,
    per_phase_outcome_correctness,
    realized_minimum_detectable_difference,
    resolve_condition_alias,
)
from analysis.tests._helpers import (  # noqa: E402
    all_phases_pass,
    load,
    phase_outcome_assertions,
    write_bundle,
)


def _two_arm_outcome_frame(tmp_path: Path) -> pd.DataFrame:
    """Build G0-FULL and S2-FLAT bundles over two seeds and return their per-phase outcome frame."""
    bundles = []
    for condition in ("G0-FULL", "S2-FLAT"):
        for seed in (101, 102):
            run_id = f"RUN-{condition}-SCN-CVE-04-INJ-A-{seed}"
            write_bundle(
                tmp_path / run_id,
                run_id=run_id,
                condition=condition,
                scenario_id="SCN-CVE-04",
                injection_condition="INJ-A",
                seed=seed,
                assertions=phase_outcome_assertions(all_phases_pass()),
            )
            bundles.append(load(tmp_path / run_id))
    return per_phase_outcome_correctness(bundles)


def test_resolve_condition_alias_maps_s1_hier_and_leaves_canonical_tokens_untouched() -> None:
    """S1-HIER resolves to the canonical G0-FULL; every other arm token is returned unchanged."""
    assert resolve_condition_alias("S1-HIER") == "G0-FULL"
    assert resolve_condition_alias("G0-FULL") == "G0-FULL"
    assert resolve_condition_alias("S2-FLAT") == "S2-FLAT"


def test_matched_pairs_resolves_s1_hier_to_g0_full_and_pairs_the_bundles(tmp_path: Path) -> None:
    """An RQ2 contrast named against S1-HIER finds the G0-FULL bundles and forms non-empty pairs."""
    frame = _two_arm_outcome_frame(tmp_path)
    pairs = matched_pairs(frame, "S1-HIER", "S2-FLAT", value_column="correct")
    assert not pairs.empty
    # Two seeds x four phases paired between the two arms.
    assert len(pairs) == 8
    assert set(pairs.columns) >= {"value_a", "value_b", "difference"}


def test_matched_pairs_raises_empty_contrast_error_when_an_arm_is_absent(tmp_path: Path) -> None:
    """A contrast against an arm with no bundles is a hard error, never an empty table."""
    frame = _two_arm_outcome_frame(tmp_path)
    with pytest.raises(EmptyContrastError):
        matched_pairs(frame, "S1-HIER", "G3-UNQUOTED", value_column="correct")


def test_matched_pairs_pairs_on_all_three_keys_and_the_phase_sub_axis() -> None:
    """The difference is taken cell for cell on (scenario, injection, seed) and the same phase."""
    frame = pd.DataFrame(
        {
            "scenario_id": ["SCN-CVE-04"] * 4,
            "condition": ["G0-FULL", "G0-FULL", "S2-FLAT", "S2-FLAT"],
            "injection_condition": ["INJ-A"] * 4,
            "seed": [101, 102, 101, 102],
            "phase": ["containment"] * 4,
            "correct": [1, 1, 0, 1],
        }
    )
    pairs = matched_pairs(frame, "G0-FULL", "S2-FLAT", value_column="correct")
    by_seed = dict(zip(pairs["seed"], pairs["difference"], strict=True))
    assert by_seed[101] == 1  # 1 - 0, full-architecture minus ablated
    assert by_seed[102] == 0  # 1 - 1


def test_matched_pairs_refuses_a_contrast_of_an_arm_against_itself() -> None:
    """Two arms that resolve to the same token are not a contrast, so the pairing is refused."""
    frame = pd.DataFrame(
        {
            "scenario_id": ["SCN-CVE-04"],
            "condition": ["G0-FULL"],
            "injection_condition": ["INJ-A"],
            "seed": [101],
            "correct": [1],
        }
    )
    with pytest.raises(ValueError, match="two distinct arms"):
        matched_pairs(frame, "S1-HIER", "G0-FULL", value_column="correct")


# --- grouped_contrast: the D13 primary grain, one row per scenario × injection × phase (ADR-133) --


def test_grouped_contrast_one_row_per_scenario_injection_and_phase(tmp_path: Path) -> None:
    """D13 primary grain: one row per (scenario, injection condition, phase) cell, each with its own
    n = seeds per cell -- never one pooled difference across phases or injection conditions."""
    frame = _two_arm_outcome_frame(tmp_path)  # G0-FULL vs S2-FLAT, seeds 101/102, four phases
    grouped = grouped_contrast(
        frame, "S1-HIER", "S2-FLAT", value_column="correct", by=list(BY_CELL)
    )
    # Four phases × one scenario × one injection condition = four cells, each n = 2 seeds.
    assert len(grouped) == 4
    assert set(grouped.columns) >= {
        "scenario_id",
        "injection_condition",
        "phase",
        "n_pairs",
        "mean_difference",
        "mdd_worst_case",
        "mdd_realized",
        "floor",
        "support",
    }
    assert set(grouped["phase"]) == {
        "detection-and-investigation",
        "containment",
        "eradication",
        "verified-recovery",
    }
    assert set(grouped["n_pairs"]) == {2}
    # Every cell resolved the alias to G0-FULL, so canonical_a is the canonical token, not the
    # alias.
    assert set(grouped["canonical_a"]) == {"G0-FULL"}


def test_grouped_contrast_default_grain_is_by_cell(tmp_path: Path) -> None:
    """The default ``by`` is the D13 primary grain, so a caller need not restate the three
    columns."""
    frame = _two_arm_outcome_frame(tmp_path)
    default = grouped_contrast(frame, "S1-HIER", "S2-FLAT", value_column="correct")
    explicit = grouped_contrast(
        frame, "S1-HIER", "S2-FLAT", value_column="correct", by=list(BY_CELL)
    )
    assert list(default.columns) == list(explicit.columns)
    assert len(default) == len(explicit) == 4


def test_grouped_contrast_marks_realized_mdd_nan_at_one_seed() -> None:
    """A cell with a single matched pair has no sample SD, so its realized MDD is nan by design."""
    frame = pd.DataFrame(
        {
            "scenario_id": ["SCN-CVE-04", "SCN-CVE-04"],
            "condition": ["G0-FULL", "S2-FLAT"],
            "injection_condition": ["INJ-A", "INJ-A"],
            "seed": [101, 101],
            "phase": ["containment", "containment"],
            "correct": [1, 0],
        }
    )
    grouped = grouped_contrast(frame, "G0-FULL", "S2-FLAT", value_column="correct")
    assert len(grouped) == 1
    row = grouped.iloc[0]
    assert row["n_pairs"] == 1
    assert math.isnan(row["mdd_realized"])


def test_grouped_contrast_raises_when_no_cell_pairs(tmp_path: Path) -> None:
    """An arm absent everywhere forms no pair in any cell: a hard error, not an empty table."""
    frame = _two_arm_outcome_frame(tmp_path)
    with pytest.raises(EmptyContrastError):
        grouped_contrast(frame, "S1-HIER", "G3-UNQUOTED", value_column="correct")


def test_minimum_detectable_difference_uses_gate_fixed_parameters() -> None:
    assert minimum_detectable_difference(4) == pytest.approx(1.4007926090564842)


def test_mdd_api_has_no_caller_override_for_unowned_power_or_sd() -> None:
    """A caller cannot bypass protocol ownership by supplying plausible local numeric choices."""
    with pytest.raises(TypeError):
        minimum_detectable_difference(4, power=0.8)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        minimum_detectable_difference(4, sd=1.0)  # type: ignore[call-arg]


def test_contrast_carries_gate_fixed_mdd_and_floor(tmp_path: Path) -> None:
    result = contrast(
        _two_arm_outcome_frame(tmp_path), "S1-HIER", "S2-FLAT", value_column="correct"
    )
    assert result.n_pairs == 8
    assert result.mdd_worst_case == pytest.approx(minimum_detectable_difference(8))
    assert result.mdd_realized == pytest.approx(
        realized_minimum_detectable_difference(result.pairs["difference"])
    )
    assert result.floor == "0.10"
    assert result.support == mdd_support_label(
        result.mean_difference, result.mdd_worst_case, result.mdd_realized
    )


def test_negative_pair_count_is_rejected_before_pending_configuration() -> None:
    with pytest.raises(ValueError, match="positive"):
        minimum_detectable_difference(-1)


# --- realized MDD: same GATE-fixed alpha/power, the contrast's own observed paired-difference SD --


def test_realized_minimum_detectable_difference_matches_the_hand_worked_formula() -> None:
    """(z_alpha/2 + z_power) * sample_sd(differences, ddof=1) / sqrt(n), not the worst-case
    bound."""
    expected = 0.8087479899175992
    assert realized_minimum_detectable_difference([1, 1, 0, 0]) == pytest.approx(expected)


def test_realized_minimum_detectable_difference_is_zero_for_identical_differences() -> None:
    """No observed variance means this sample could detect any nonzero effect: MDD is exactly 0."""
    assert realized_minimum_detectable_difference([2.0, 2.0, 2.0]) == pytest.approx(0.0)


def test_realized_minimum_detectable_difference_is_nan_below_two_differences() -> None:
    """A single difference carries no sample SD; fabricating one would misstate this run's power."""
    assert math.isnan(realized_minimum_detectable_difference([5.0]))


def test_realized_minimum_detectable_difference_rejects_no_differences_at_all() -> None:
    with pytest.raises(ValueError, match="at least one difference"):
        realized_minimum_detectable_difference([])


def test_realized_mdd_api_has_no_caller_override_for_unowned_alpha_or_power() -> None:
    """Alpha and power stay GATE-fixed here too -- no local override, same as the worst-case MDD."""
    with pytest.raises(TypeError):
        realized_minimum_detectable_difference([1, 0], power=0.8)  # type: ignore[call-arg]


# --- mdd_support_label: "clears the conservative bar" vs "clears only the realized bar" (ADR-080) -


def test_support_label_clears_worst_case_when_observed_at_or_above_it() -> None:
    assert mdd_support_label(0.5, 0.3, 0.2) == "clears worst-case MDD: strongly supported"
    # abs(): a negative mean difference (ablated minus full, sign-wise) still compares on magnitude.
    assert mdd_support_label(-0.5, 0.3, 0.2) == "clears worst-case MDD: strongly supported"


def test_support_label_clears_realized_only_below_worst_case() -> None:
    assert mdd_support_label(0.25, 0.5, 0.2) == (
        "clears realized MDD only: reported with caveat, not the conservative bound"
    )


def test_support_label_below_both_figures() -> None:
    assert mdd_support_label(0.1, 0.5, 0.3) == (
        "below both MDD figures: no effect detectable at this design's power"
    )


def test_support_label_names_an_undefined_realized_mdd_explicitly() -> None:
    """A NaN realized MDD (fewer than two pairs) is named, not silently folded into "below both"."""
    assert mdd_support_label(0.05, 0.5, math.nan) == (
        "below worst-case MDD; realized MDD undefined (fewer than two matched pairs)"
    )
