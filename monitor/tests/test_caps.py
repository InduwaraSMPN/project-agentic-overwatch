"""Cap semantics: the unit, the truncation rule, the selection rule, and failing closed.

WHAT THIS FILE IS PROVING
-------------------------
Three things, and the third is the one that would otherwise be invisible.

**The unit.** Section 4 counts source characters before quoting. Every assertion below counts code
points on unquoted text, so a future change that started counting bytes, or counting after escaping,
fails here rather than quietly halving the evidence in one of the two G3 arms.

**The selection rule.** When there are more candidates than the count cap admits, *which* survive
decides what a responder sees. ``caps.py`` writes the rule down in five numbered steps; this file
asserts each of them separately, so a failure names the step rather than the outcome.

**Failing closed.** The offline phase runs with section 4's caps still uncalibrated, so the
interesting behaviour is a refusal -- and a refusal is exactly the kind of behaviour a test suite
quietly stops covering the moment somebody adds a default "just for now". The fail-closed assertions
here and in ``test_limits_match_protocol.py`` are what make that addition a red build.

WHY THE LIMITS IN THIS FILE ARE TINY AND OBVIOUSLY ARTIFICIAL
--------------------------------------------------------------
Every :class:`~monitor.aggregator.caps.CapLimits` below is built from small literals chosen to make
a boundary visible in one line -- three excerpts, twelve characters. They are **test parameters**,
not proposals: ADR-019 is explicit that the values the offline phase passes in are fixture-corpus
parameters and never evidence that section 4's caps row is closed. Deliberately small so that nobody
can mistake one for a measurement, and deliberately not round for the same reason.

WHY EVERY NON-ASCII CHARACTER BELOW IS AN ESCAPE
-------------------------------------------------
The truncation tests are about combining marks and zero-width joiners, which are invisible or
near-invisible when written literally -- a reviewer could not tell a correct test from one whose
character had been silently normalised by an editor, and a diff would show nothing. Written as
``\\u0301`` and ``\\u200d`` they are readable, greppable and cannot be altered without the change
appearing in review. It also keeps this file pure ASCII, which is the same property
``models.canonical_json_bytes`` gives the event stream and for the same reason.
"""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from monitor.aggregator.caps import (  # noqa: E402
    CapConfigurationError,
    CapLimits,
    apply_caps,
    protocol_cap_limits,
    select_excerpts,
    truncate,
)
from monitor.aggregator.limits import (  # noqa: E402
    CAP_KEYS,
    UncalibratedLimit,
    as_protocol_mapping,
    is_pending,
)

# Small, odd numbers, for the reason the module docstring gives.
LIMITS = CapLimits(
    evidence_excerpt_count_max=3,
    evidence_excerpt_length_max_chars=12,
    summary_length_max_chars=17,
)


# --- the limits object itself --------------------------------------------------------------------


@pytest.mark.parametrize("bad", [0, -1, 1.5, True])
def test_a_cap_that_could_not_bound_anything_is_refused_on_construction(bad: object) -> None:
    """Zero, negative, fractional and boolean are each refused, naming the field.

    Zero is the one worth stating: at zero every event would carry an empty summary and no excerpts,
    and a corpus built under it would still go green -- which is the shape of failure the whole
    fail-closed design exists to prevent. ``True`` is refused because ``bool`` is an ``int`` in
    Python, and a cap of ``True`` is a cap of one that nobody wrote on purpose.
    """
    with pytest.raises(CapConfigurationError):
        CapLimits(
            evidence_excerpt_count_max=bad,  # type: ignore[arg-type]
            evidence_excerpt_length_max_chars=12,
            summary_length_max_chars=17,
        )


def test_the_protocol_cap_builder_fails_closed_while_a_cap_is_pending() -> None:
    """No default anywhere between ``limits.resolve`` and ``CapLimits``.

    Skips once the fixture study has landed, at which point the aggregator resolves its caps from
    section 4 and this refusal has nothing left to assert.
    """
    mapping = as_protocol_mapping()
    pending = [key for key in CAP_KEYS if is_pending(mapping[key])]
    if not pending:
        pytest.skip("every cap has been calibrated; there is no refusal left to test")
    with pytest.raises(UncalibratedLimit) as refusal:
        protocol_cap_limits()
    assert refusal.value.key == pending[0]
    assert "no default" in str(refusal.value)


# --- truncation ----------------------------------------------------------------------------------


def test_text_within_the_limit_is_returned_unchanged() -> None:
    """Including its trailing whitespace: this function ends text early, it does not tidy it."""
    assert truncate("abc  ", 12) == "abc  "
    assert truncate("a" * 12, 12) == "a" * 12


def test_truncation_counts_code_points_and_appends_no_marker() -> None:
    """A marker would add characters that are not in the source and break provenance checking."""
    cut = truncate("a" * 40, 12)
    assert cut == "a" * 12
    assert len(cut) == 12
    assert "\u2026" not in cut and "..." not in cut


def test_truncation_never_splits_a_combining_sequence() -> None:
    """The cut retreats past an orphaned combining mark, so the cap is met from below, never above.

    ``e`` followed by U+0301 COMBINING ACUTE ACCENT renders as a single glyph. Cutting between them
    would produce an excerpt that renders differently from the source it claims to quote -- and
    would do it consistently, so no diff would ever flag it.
    """
    text = "abe\u0301cd"
    cut = truncate(text, 3)
    assert cut == "ab"
    assert len(cut) <= 3
    # One more code point of room admits the whole sequence rather than half of it.
    assert truncate(text, 4) == "abe\u0301"


def test_truncation_never_splits_a_zero_width_joiner_sequence() -> None:
    """A cut on either side of U+200D breaks a joined sequence in half.

    In ``ab<ZWJ>cd`` the joined pair is ``b<ZWJ>c``. A cut at two code points would end the text
    between ``b`` and the joiner, so the cut retreats past ``b`` as well -- which is why the answer
    is ``a`` and not ``ab``. Retreating only ever shortens, so the cap is still respected.
    """
    text = "ab\u200dcd"
    assert truncate(text, 2) == "a"
    assert truncate(text, 3) == "a"
    assert truncate(text, 4) == "ab\u200dc"


def test_truncation_is_reproducible_over_repeated_calls() -> None:
    """A pure function of the string and of the character database, with no state between calls."""
    text = "a mark e\u0301 and a joiner x\u200dy inside some padding text" * 3
    assert {truncate(text, 29) for _ in range(5)} == {truncate(text, 29)}


def test_a_limit_below_one_is_refused() -> None:
    """The refusal :class:`CapLimits` makes, for a caller that reached ``truncate`` directly."""
    with pytest.raises(CapConfigurationError):
        truncate("abc", 0)


# --- excerpt selection ---------------------------------------------------------------------------


def test_step_one_drops_candidates_that_carry_no_evidence() -> None:
    """Empty and whitespace-only candidates would spend a scarce slot on nothing."""
    selected = select_excerpts(["", "   ", "\t\n", "real"], summary="s", cap_limits=LIMITS)
    assert selected == ("real",)


def test_step_one_does_not_strip_the_survivors() -> None:
    """Trimming a survivor would alter source text, which this module never does."""
    assert select_excerpts([" padded "], summary="s", cap_limits=LIMITS) == (" padded ",)


def test_step_two_drops_a_candidate_identical_to_the_summary() -> None:
    """The event already carries that text in its own field."""
    selected = select_excerpts(["a summary", "other"], summary="a summary", cap_limits=LIMITS)
    assert selected == ("other",)


def test_step_two_compares_against_the_uncapped_summary() -> None:
    """Comparing against the capped form would keep a candidate whose only difference was cut."""
    long_summary = "x" * 40
    selected = select_excerpts([long_summary, "other"], summary=long_summary, cap_limits=LIMITS)
    assert selected == ("other",)


def test_step_three_deduplicates_keeping_the_first_occurrence() -> None:
    """First occurrence, so the normaliser's ranking decides which copy survives."""
    selected = select_excerpts(["a", "b", "a", "c"], summary="s", cap_limits=LIMITS)
    assert selected == ("a", "b", "c")


def test_step_three_deduplicates_on_the_full_text_not_the_truncated_text() -> None:
    """Two candidates differing only past the cap are two candidates, not one.

    Otherwise the surviving set would depend on the length cap in a way nobody would predict from
    reading the rule.
    """
    first = "x" * 12 + "AAA"
    second = "x" * 12 + "BBB"
    selected = select_excerpts([first, second], summary="s", cap_limits=LIMITS)
    assert len(selected) == 2
    assert selected == ("x" * 12, "x" * 12)


def test_step_four_keeps_the_first_n_in_the_declared_order() -> None:
    """Not the longest, not a sample: the first N, which is what makes the ranking mean anything."""
    selected = select_excerpts(["a", "b", "c", "d", "e"], summary="s", cap_limits=LIMITS)
    assert selected == ("a", "b", "c")


def test_step_five_truncates_each_survivor() -> None:
    """The count cap chooses which; the length cap chooses how much of each."""
    selected = select_excerpts(["y" * 40, "z" * 40], summary="s", cap_limits=LIMITS)
    assert selected == ("y" * 12, "z" * 12)


def test_the_two_cap_axes_are_independent() -> None:
    """Raising the summary cap cannot change which excerpts an event carries, and the reverse.

    Section 4 owns three axes and they have to stay three. A change that made one depend on another
    would leave the fixture study unable to calibrate them separately.
    """
    candidates = ["a" * 40, "b" * 40, "c" * 40, "d" * 40]
    narrow = apply_caps("s" * 40, candidates, cap_limits=LIMITS)
    wider_summary = apply_caps(
        "s" * 40,
        candidates,
        cap_limits=CapLimits(
            evidence_excerpt_count_max=3,
            evidence_excerpt_length_max_chars=12,
            summary_length_max_chars=31,
        ),
    )
    assert narrow.excerpts == wider_summary.excerpts
    assert len(narrow.summary) == 17
    assert len(wider_summary.summary) == 31


def test_apply_caps_bounds_both_fields_and_returns_source_text() -> None:
    """Nothing here is quoted; quoting is the last transformation and lives in ``emit.py``."""
    capped = apply_caps(
        "summary text that is long", ["excerpt one that is long"], cap_limits=LIMITS
    )
    assert capped.summary == "summary text that"
    assert capped.excerpts == ("excerpt one ",)
    assert "\\" not in capped.summary
