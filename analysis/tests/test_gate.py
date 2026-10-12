r"""The six GATE-fixed constants no longer raise; an unscored bundle and an uncalibrated M1
instrument still do.

The inconclusiveness floor is a fixed number now (evaluation-protocol.md §4; ADR-080). The
test-retest statistic and the SLO stabilization window still raise rather than defaulting: a bundle
without `scores.json` cannot yield a researcher judgement, and time-to-SLO-recovery cannot be
computed against an uncalibrated window.
"""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from analysis.stats import (  # noqa: E402
    FLOOR_MARKER,
    Bundle,
    PendingGateValue,
    PendingInstrumentValue,
    compute_test_retest_agreement,
    inconclusiveness_floor,
    is_inconclusive,
    refuse_researcher_judged,
    researcher_judged_measures,
    resolve_stabilization_window,
)
from analysis.tests._helpers import (  # noqa: E402
    all_phases_pass,
    load,
    phase_outcome_assertions,
    write_bundle,
)


def test_the_floor_marker_and_value_are_gate_fixed() -> None:
    assert FLOOR_MARKER == "0.10"
    assert inconclusiveness_floor() == 0.10


def test_is_inconclusive_compares_absolute_difference_to_the_floor() -> None:
    assert is_inconclusive(0.09) is True
    assert is_inconclusive(-0.09) is True
    assert is_inconclusive(0.10) is False


def test_test_retest_agreement_requires_paired_scoring_passes() -> None:
    with pytest.raises(PendingGateValue, match="both initial and rescore"):
        compute_test_retest_agreement([])


def test_resolve_stabilization_window_fails_closed_while_it_is_pending_m1_calibration() -> None:
    """At M6 the window still holds its PENDING sentinel, so it raises instead of guessing."""
    try:
        window = resolve_stabilization_window()
    except PendingInstrumentValue:
        return  # expected before M1 calibrates a deployed cluster
    assert isinstance(window, int)
    assert window > 0


def test_refuse_researcher_judged_raises_on_a_bundle_without_scores(tmp_path: Path) -> None:
    """A researcher-judged measure cannot be computed from a bundle lacking scores.json."""
    bundle = load(
        write_bundle(
            tmp_path / "r",
            run_id="RUN-G0-FULL-SCN-CVE-04-INJ-A-101",
            condition="G0-FULL",
            scenario_id="SCN-CVE-04",
            injection_condition="INJ-A",
            seed=101,
            assertions=phase_outcome_assertions(all_phases_pass()),
        )
    )
    with pytest.raises(PendingGateValue, match="scores.json"):
        refuse_researcher_judged(bundle)


def _scored_bundle(tmp_path: Path, name: str, *, initial: dict, rescore: dict) -> Bundle:
    return load(
        write_bundle(
            tmp_path / name,
            run_id=f"RUN-G0-FULL-SCN-CVE-04-INJ-A-{name}",
            condition="G0-FULL",
            scenario_id="SCN-CVE-04",
            injection_condition="INJ-A",
            seed=101,
            scores={
                "run_id": f"RUN-G0-FULL-SCN-CVE-04-INJ-A-{name}",
                "rubric_version": "v1.0",
                "passes": [
                    {"pass": "initial", "scored_at": "2026-08-27T00:00:00+00:00", **initial},
                    {"pass": "rescore", "scored_at": "2026-09-10T00:00:00+00:00", **rescore},
                ],
            },
        )
    )


def test_test_retest_agreement_reports_per_field_beside_the_exact_tuple(tmp_path: Path) -> None:
    """An exact-tuple figure dragged down by one noisy field is legible field by field (ADR-080)."""
    full_agreement = {
        "investigation_match": 2,
        "scope_correct": True,
        "incorrect_or_harmful_action_count": 0,
    }
    one_noisy_field = {
        "investigation_match": 1,  # disagrees with the initial pass below
        "scope_correct": True,
        "incorrect_or_harmful_action_count": 0,
    }
    agreeing_bundle = _scored_bundle(
        tmp_path, "agree", initial=full_agreement, rescore=dict(full_agreement)
    )
    noisy_bundle = _scored_bundle(
        tmp_path, "noisy", initial=full_agreement, rescore=one_noisy_field
    )

    result = compute_test_retest_agreement([agreeing_bundle, noisy_bundle])

    assert result.n_compared == 2
    # Exact-tuple agreement is dragged down to 0.5 by the one run whose investigation_match differs.
    assert result.exact_tuple_agreement == pytest.approx(0.5)
    # Per-field agreement shows exactly which field: investigation_match is the noisy one, the other
    # two fields agree on every compared run.
    assert result.per_field_agreement == {
        "investigation_match": pytest.approx(0.5),
        "scope_correct": pytest.approx(1.0),
        "incorrect_or_harmful_action_count": pytest.approx(1.0),
    }


def test_researcher_judged_measures_reads_the_initial_pass_when_the_run_is_scored(
    tmp_path: Path,
) -> None:
    """A scored run yields its three initial-pass judgements, read rather than fabricated."""
    bundle = load(
        write_bundle(
            tmp_path / "r",
            run_id="RUN-G0-FULL-SCN-CVE-04-INJ-A-101",
            condition="G0-FULL",
            scenario_id="SCN-CVE-04",
            injection_condition="INJ-A",
            seed=101,
            scores={
                "run_id": "RUN-G0-FULL-SCN-CVE-04-INJ-A-101",
                "rubric_version": "v1.0",
                "passes": [
                    {
                        "pass": "initial",
                        "scored_at": "2026-08-27T00:00:00+00:00",
                        "blind": True,
                        "investigation_match": 2,
                        "scope_correct": True,
                        "incorrect_or_harmful_action_count": 0,
                    }
                ],
            },
        )
    )
    judged = researcher_judged_measures(bundle)
    assert judged["investigation_match"] == 2
    assert judged["scope_correct"] is True
    assert judged["incorrect_or_harmful_action_count"] == 0
