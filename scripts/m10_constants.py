r"""The M10 human-scoring constants scripts/ reads, mirroring evaluation-protocol.md section 4.

WHAT THIS MODULE IS FOR
    `docs/protocols/evaluation-protocol.md` section 4 carries an `<!-- m10-fidelity-constants -->`
    block owning every quantitative parameter the M10 campaign-v2 remediation adds (ADR-120). Two
    blocks in that one file concern scoring, and both are the authority here:

    * the M10 block's four `scoring_*` keys -- the minimum elapsed time between opening a bundle and
      submitting a judgement, the stratified first-pass sample's tuple count and per-scenario
      minimum, and the whole-tuple re-score's tuple count (D2, ADR-134);
    * the GATE block's `blind_rescore_delay_days`, which the M10 block's own prose says is NOT
      restated there and stays owned by `<!-- gate-constants -->`. That one is not mirrored here:
      `analysis.stats.gate` already mirrors it, `scripts.scoring_sample` already imports from that
      module, and `the source-of-truth iron rule (AGENTS.md 1)` allows a literal to appear
      twice only where the second copy is CHECKED against the first. Copying it into this file
      would be a third home with no mirror test of its own, so this module imports the delay
      instead.

    `scripts/scoring_ui.py` (the minimum elapsed time), `scripts/scoring_sample.py` (the tuple count
    and the per-scenario minimum) and `scripts/scoring_rescore_sample.py` (the re-score tuple count)
    read the names below and nothing else. This module is the same kind of checked copy as
    `analysis/stats/m10.py`, `analysis/stats/gate.py`, `infra/probes/constants.py` and
    `monitor/aggregator/limits.py`: the protocol is the authority, this file is a copy, and
    `scripts/tests/test_m10_constants_match_protocol.py` parses the anchored block and fails CI if
    the two disagree. That test is the entire justification for the copy being legal.

WHY A SUBSET, NOT THE WHOLE BLOCK
    The M10 block also owns the pilot ladder's run counts, the loop-signature length, the lifetime
    attempt cap, the checkpoint size, the clock-skew and forwarder-drain tolerances and the
    PROPOSED-M10-P0LIVE-CALIBRATION sentinel. `runner/` mirrors the ones it consumes (see
    `runner/pilot_cli.py` and, when it lands, `runner/fidelity/`) and `analysis/stats/m10.py`
    mirrors the discrimination ceiling. None of those is scripts/'s to restate: a value a module
    does not use must not live in that module, or the module becomes a second home with no consumer
    -- exactly the duplication the source-of-truth iron rule (AGENTS.md 1) warns against.
    The mirrored sets are disjoint, so no constant has three homes.

    The sentinel matters here more than elsewhere. A PROPOSED value is a value nobody has chosen
    yet, and `infra/probes/constants.py` resolves one by failing closed rather than by inventing a
    number. None of the four keys below carries a sentinel today; if one is ever given it, this
    module must refuse to resolve it rather than return a placeholder, and the consumer must fail
    with it.

WHAT BREAKS IF THIS FILE CHANGES
    A value here that drifts from the protocol block without the identical protocol edit fails the
    mirror test, and the protocol is right when that happens, never this module (the ADR-016
    direction). Inlining a literal at a call site instead of importing the name would put the number
    where the mirror test cannot see it, which is the drift the mirror exists to catch. After the
    `v2.0` freeze any change here is an instrument change that halts the campaign and resets the
    pilot ladder (AGENTS.md iron rule 6; ADR-136).
"""

from __future__ import annotations

from typing import Final

__all__ = [
    "MIRRORED_KEYS",
    "PROTOCOL_ANCHOR",
    "PROTOCOL_RELATIVE_PATH",
    "SCORING_MIN_ELAPSED_SECONDS",
    "SCORING_RESCORE_TUPLE_COUNT",
    "SCORING_SAMPLE_MIN_PER_SCENARIO",
    "SCORING_SAMPLE_TUPLE_COUNT",
    "as_protocol_mapping",
    "render_protocol_block",
]

# The HTML comment that marks the M10 constants block inside evaluation-protocol.md section 4. An
# anchor rather than a heading search, for the reason analysis.stats.m10 gives for the same block: a
# heading is prose and gets retitled, an anchor exists for exactly one purpose.
PROTOCOL_ANCHOR: Final = "<!-- m10-fidelity-constants -->"

# The path of the owning protocol file, relative to the repository root -- the same file the M1, M2,
# GATE and M10 blocks all live in. M10 owns a different block within one document, not a new
# document.
PROTOCOL_RELATIVE_PATH: Final = "docs/protocols/evaluation-protocol.md"

# ------------------------------------------------------------------------------------------------
# THE M10 SCORING CONSTANTS scripts/ CONSUMES -- proposed 2026-09-26 (ADR-120; D2; ADR-134). The
# value lives exactly once beyond this mirror, in the protocol block it is checked against.
# ------------------------------------------------------------------------------------------------

# Minimum seconds between a bundle being opened and its judgement being submitted, in one scoring
# session (ADR-134's provenance control; V12). This is NOT a claim about how long a human needs: at
# the one recorded pace a judgement took 678.8 s, so the bound is a floor beneath any plausible
# honest session, set so that a scripted bulk write -- which opens nothing and submits at once --
# cannot pass it. See scripts/scoring_ui.py for what the control does and, at least as importantly,
# what it does not prove.
SCORING_MIN_ELAPSED_SECONDS: Final[int] = 60

# Matched tuples (scenario_id x injection_condition x seed) in the pre-registered first-pass
# researcher-scoring sample (D2; ADR-134), and the minimum every one of the five scenarios keeps.
# 13 tuples x 6 arms = 78 bundles, the workload the plan's section 3.1 budgets at about 15 h at
# the recorded pace. Both are overridable from the sampler CLI, as parameters rather than buried
# literals, and both DEFAULT to the protocol's value rather than to a number of the sampler's own.
SCORING_SAMPLE_TUPLE_COUNT: Final[int] = 13
SCORING_SAMPLE_MIN_PER_SCENARIO: Final[int] = 2

# Matched tuples drawn WHOLE for the blind re-score: the GATE block's re-score fraction of the 13
# tuples, rounded up (D2; ADR-134). Whole, because the test-retest statistic is exact agreement over
# the three-field judgement tuple, so a re-score of one arm of a tuple measures something other than
# what the first pass recorded for that tuple.
SCORING_RESCORE_TUPLE_COUNT: Final[int] = 3

# The keys this module mirrors, in the order the mirror test reports them. A strict subset of the
# protocol block's own keys, by design (see the module docstring).
MIRRORED_KEYS: Final[tuple[str, ...]] = (
    "scoring_min_elapsed_seconds",
    "scoring_sample_tuple_count",
    "scoring_sample_min_per_scenario",
    "scoring_rescore_tuple_count",
)


def as_protocol_mapping() -> dict[str, object]:
    """Return the mirrored M10 scoring constants in the shape the section 4 block parses to.

    The comparison surface ``scripts/tests/test_m10_constants_match_protocol.py`` uses, and the
    input :func:`render_protocol_block` takes. A fresh dict on every call, so no caller can mutate
    the mirror for everyone else.
    """
    return {
        "scoring_min_elapsed_seconds": SCORING_MIN_ELAPSED_SECONDS,
        "scoring_sample_tuple_count": SCORING_SAMPLE_TUPLE_COUNT,
        "scoring_sample_min_per_scenario": SCORING_SAMPLE_MIN_PER_SCENARIO,
        "scoring_rescore_tuple_count": SCORING_RESCORE_TUPLE_COUNT,
    }


def render_protocol_block(mapping: dict[str, object] | None = None) -> str:
    """Return the anchored section 4 block text for the mirrored constants, ending in one newline.

    A reviewer can regenerate the exact text to paste with ``python -m scripts.m10_constants``
    rather than hand-retyping four numbers, on the same reasoning ``analysis.stats.gate`` gives for
    its own renderer.
    """
    source = as_protocol_mapping() if mapping is None else mapping
    lines = [PROTOCOL_ANCHOR, "", "```yaml"]
    lines.extend(f"{key}: {source[key]}" for key in MIRRORED_KEYS)
    lines.append("```")
    return "\n".join(lines) + "\n"


def main() -> int:
    """Print the section 4 scoring rows this module mirrors.

    ``python -m scripts.m10_constants`` -- a reviewer can see, without reading Python, exactly what
    this module claims section 4 says. These are pre-registered decisions rather than measurements,
    so there is no ``--calibrate`` counterpart, exactly as `analysis.stats.gate` records.
    """
    print(render_protocol_block(), end="")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
