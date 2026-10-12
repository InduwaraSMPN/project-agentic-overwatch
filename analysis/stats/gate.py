r"""The six GATE-fixed constants (mirroring evaluation-protocol.md section 4), and the fail-closed
sentinels for the values that are still genuinely unset.

WHAT THIS MODULE IS FOR
    `docs/protocols/evaluation-protocol.md` section 4 owns the inconclusiveness floor, the blind
    re-score sample fraction and delay, and the two-sided alpha / target power / worst-case
    paired-difference SD that :mod:`analysis.stats.pairs` needs to compute a minimum detectable
    difference. All six were pre-registered at GATE and confirmed by the supervisor on 2026-09-13
    (the rulings memo, item 3; ADR-080), before any pilot contrast was inspected -- exactly what
    section 7 requires ("fixed in advance"; row T-34). This module is the checked Python mirror of
    that section's `<!-- gate-constants -->` block, on the same pattern ADR-016 establishes for the
    `m1-instrument-constants` / `m2-monitor-limits` blocks: the protocol is the authority, this file
    is a copy, and `analysis/tests/test_gate_constants_match_protocol.py` parses the block and fails
    if the two disagree key for key. That test is the entire justification for the copy being legal
    under `.agents/rules/00-source-of-truth.md`.

    The three researcher-judged measures and the test-retest statistic are a *different* kind of
    pending: not a number GATE has not chosen, but a run that has not been scored yet.
    :func:`~analysis.stats.measures.compute_test_retest_agreement` and
    :func:`~analysis.stats.measures.refuse_researcher_judged` still raise
    :class:`PendingGateValue` for that reason -- a bundle without both an initial and a re-score
    pass in `scores.json` has no test-retest judgement to read, GATE or no GATE -- but that is a
    statement about the corpus, not about an unbound protocol parameter. Nothing in this module
    reads a `PENDING-GATE` placeholder any more: the six constants below are always the fixed
    numbers.

WHY THREE ERROR TYPES AND NOT ONE
    Each names a *different* reason a value is absent, and conflating them would let a caller catch
    one and silently proceed past another. :class:`PendingGateValue` is "a scored run is needed and
    this bundle is not one". :class:`PendingInstrumentValue` is "measured on a deployed cluster at
    M1/M2, not yet"; it is the SLO stabilization window. And :class:`PendingSupervisorDecision` is
    "a measure is not yet *defined*, pending a supervisor decision on a flagged conflict" --
    conflict M6-C1, which `measures.interference` raised until the same 2026-09-13 ruling named the
    framework-on term as the shared arm's `INJ-NONE` cells (see that function's docstring). None of
    the three is a value a default could stand in for.

WHAT BREAKS IF THIS FILE CHANGES
    A value here that drifts from evaluation-protocol.md section 4 without the identical protocol
    edit fails `test_gate_constants_match_protocol.py`, and the protocol is right when that happens,
    never this module (the same direction ADR-016 fixes for the M1/M2 mirrors). Softening
    :func:`resolve_stabilization_window` to return a placeholder would let time-to-SLO-recovery
    report a restoration time measured against a window nobody calibrated. ADR-043 (analysis as a
    tested component); ADR-080 (the GATE constants and the interference term); AGENTS.md iron rule 6
    makes any change here after the `v1.0` freeze a logged hotfix ADR.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

__all__ = [
    "BLIND_RESCORE_DELAY_DAYS",
    "BLIND_RESCORE_SAMPLE_FRACTION",
    "FLOOR_MARKER",
    "INCONCLUSIVENESS_FLOOR",
    "MDD_ALPHA_TWO_SIDED",
    "MDD_TARGET_POWER",
    "MDD_WORST_CASE_PAIRED_DIFF_SD",
    "PROTOCOL_ANCHOR",
    "PROTOCOL_KEYS",
    "PROTOCOL_RELATIVE_PATH",
    "PendingGateValue",
    "PendingInstrumentValue",
    "PendingSupervisorDecision",
    "as_protocol_mapping",
    "inconclusiveness_floor",
    "is_inconclusive",
    "render_protocol_block",
    "resolve_stabilization_window",
]

# The HTML comment that marks the GATE constants block inside evaluation-protocol.md section 4. An
# anchor rather than a heading search, for the reason infra/probes/constants.py gives: headings are
# prose and get retitled, an anchor exists for exactly one purpose.
PROTOCOL_ANCHOR: Final = "<!-- gate-constants -->"

# The path of the owning protocol file, relative to the repository root -- the same file the M1/M2
# blocks live in; GATE owns a different section-4 block within it, not a different document.
PROTOCOL_RELATIVE_PATH: Final = "docs/protocols/evaluation-protocol.md"

# The key set is fixed and total, in the order the block renders them.
PROTOCOL_KEYS: Final[tuple[str, ...]] = (
    "inconclusiveness_floor",
    "blind_rescore_sample_fraction",
    "blind_rescore_delay_days",
    "mdd_alpha_two_sided",
    "mdd_target_power",
    "mdd_worst_case_paired_diff_sd",
)

# ------------------------------------------------------------------------------------------------
# THE SIX GATE-FIXED CONSTANTS -- pre-registered 2026-09-13 (supervisor rulings item 3; ADR-080).
# Rationale for each lives in ADR-080's Decision section and in section 4's surrounding prose; the
# values themselves live exactly once, in this mirror and in the protocol block it is checked
# against. Nothing here is a caller-selectable default: every consumer imports the name.
# ------------------------------------------------------------------------------------------------

# Absolute proportion-difference floor: an ablation contrast smaller than this is reported as
# inconclusive rather than as a small effect, regardless of how tight its Wilson interval is.
INCONCLUSIVENESS_FLOOR: Final[float] = 0.10

# The display string a rendered result prints beside its point estimate. Derived from the constant
# above rather than re-typed, so the two cannot silently diverge within this one file.
FLOOR_MARKER: Final[str] = f"{INCONCLUSIVENESS_FLOOR:.2f}"

# Deterministic, stratified by arm and injection condition (row T-38); the fraction of sealed runs
# blindly re-scored after the delay below.
BLIND_RESCORE_SAMPLE_FRACTION: Final[float] = 0.20

# Days between the initial researcher-judged pass and the blind re-score of the sampled runs.
BLIND_RESCORE_DELAY_DAYS: Final[int] = 14

# Minimum-detectable-difference inputs (section 7, row T-34): two-sided test size, target power, and
# the worst-case paired-difference standard deviation `pairs.minimum_detectable_difference` assumes
# when no sample SD has been observed yet. `pairs.realized_minimum_detectable_difference` uses the
# same alpha and power against the *observed* paired-difference SD instead of this bound.
MDD_ALPHA_TWO_SIDED: Final[float] = 0.05
MDD_TARGET_POWER: Final[float] = 0.80
MDD_WORST_CASE_PAIRED_DIFF_SD: Final[float] = 1.0


def as_protocol_mapping() -> dict[str, object]:
    """Return the mirrored GATE constants in exactly the shape the section 4 block parses to.

    The comparison surface `test_gate_constants_match_protocol.py` uses, and the input
    :func:`render_protocol_block` takes. A fresh dict on every call, so no caller can mutate the
    mirror for everyone else.
    """
    return {
        "inconclusiveness_floor": INCONCLUSIVENESS_FLOOR,
        "blind_rescore_sample_fraction": BLIND_RESCORE_SAMPLE_FRACTION,
        "blind_rescore_delay_days": BLIND_RESCORE_DELAY_DAYS,
        "mdd_alpha_two_sided": MDD_ALPHA_TWO_SIDED,
        "mdd_target_power": MDD_TARGET_POWER,
        "mdd_worst_case_paired_diff_sd": MDD_WORST_CASE_PAIRED_DIFF_SD,
    }


def render_protocol_block(mapping: Mapping[str, object] | None = None) -> str:
    """Return the anchored section 4 block text for the mirrored constants, ending in one newline.

    A reviewer can regenerate the exact block to paste with ``python -m analysis.stats.gate`` rather
    than hand-retyping six numbers, on the same reasoning `infra/probes/constants.py` gives for its
    own renderer.
    """
    source = as_protocol_mapping() if mapping is None else mapping
    lines = [PROTOCOL_ANCHOR, "", "```yaml"]
    lines.extend(f"{key}: {source[key]}" for key in PROTOCOL_KEYS)
    lines.append("```")
    return "\n".join(lines) + "\n"


class PendingGateValue(RuntimeError):
    """Raised when a researcher-judged or test-retest measure is asked of an unscored bundle.

    Not the six constants above -- those are always fixed. This is `data-management.md` §3's
    prohibition on computing the investigation-match rubric, the scope-correct judgement, the
    incorrect/harmful action count, or the test-retest agreement statistic "from a bundle lacking"
    `scores.json`, or lacking both an ``initial`` and a ``rescore`` pass within it. Raising rather
    than returning a default keeps a run that has not been scored from silently contributing an
    invented judgement.
    """


class PendingInstrumentValue(RuntimeError):
    """Raised when an M1/M2 instrument constant a measure needs still holds its PENDING sentinel.

    The stabilization window time-to-SLO-recovery subtracts against is measured on a deployed
    cluster (`infra/probes/constants.py`, `PENDING-M1-CALIBRATION`). A restoration time computed
    against an uncalibrated window would describe the instrument, not the system, so the measure
    fails closed exactly as `slo_probe.py` refuses to form an SLO verdict while the value is
    pending.
    """


class PendingSupervisorDecision(RuntimeError):
    """Raised when a measure is not yet *defined*, pending a supervisor decision on a flagged
    conflict.

    Conflict M6-C1 (`evaluation-protocol.md` §3; `measures.interference`): which runs supply the
    "no incident injected" framework-on term when every grid run is scenario-scoped. The 2026-09-13
    supervisor ruling named the answer -- the shared `G0-FULL` arm's `INJ-NONE` cells, reported with
    the residual that a scenario disturbance remains present (ADR-080) -- so a caller that passes
    that ``cell_selection`` no longer hits this path. It still guards any call that omits a
    selection, so a future conflict of this shape fails closed the same way rather than picking a
    candidate silently.
    """


def inconclusiveness_floor() -> float:
    """Return the GATE-fixed absolute proportion-difference floor (section 4; ADR-080)."""
    return INCONCLUSIVENESS_FLOOR


def is_inconclusive(difference: float) -> bool:
    """Whether an observed absolute contrast falls below the pre-registered floor."""
    return abs(difference) < inconclusiveness_floor()


def resolve_stabilization_window() -> int:
    """Return the calibrated SLO stabilization window in seconds, or fail closed if still pending.

    Reads `infra/probes/constants.py`, which mirrors `evaluation-protocol.md` §4 under an
    ADR-016-style check. The import is local so that importing this module never requires `infra/`
    to be on the path -- only a caller that actually computes time-to-SLO-recovery pays that cost. A
    pending value raises :class:`PendingInstrumentValue`, so a restoration time is never measured
    against a window nobody has calibrated on a deployed cluster.
    """
    from infra.probes import constants

    window = constants.STABILIZATION_WINDOW_SECONDS
    if constants.is_pending(window):
        raise PendingInstrumentValue(
            "stabilization_window_seconds still holds the PENDING-M1-CALIBRATION sentinel "
            "(evaluation-protocol.md §4); time-to-SLO-recovery cannot be computed until it is "
            "measured on a deployed cluster and recorded in §4"
        )
    return int(window)


def main() -> int:
    """Print the section 4 GATE constants block for the currently mirrored values.

    ``python -m analysis.stats.gate`` -- a reviewer can see, without reading Python, exactly what
    this module claims section 4 says. Regenerating a live value from a running campaign is not this
    module's job: these six are pre-registered decisions, not measurements, so there is no
    ``--calibrate`` counterpart.
    """
    print(render_protocol_block(), end="")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
