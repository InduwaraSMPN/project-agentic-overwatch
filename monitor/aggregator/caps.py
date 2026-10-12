"""Count and length caps, applied to pre-quoting source text -- the ordering the G3 arm depends on.

WHY THE ORDER IS NORMALISE, SELECT, CAP, QUOTE, AND WHY IT IS NOT NEGOTIABLE
-----------------------------------------------------------------------------
Quoting and escaping lengthen text: an escape sequence is longer than the character it replaces, by
construction. So a length cap applied *after* quoting truncates the quoted arm sooner than the
unquoted one, and the two arms end up carrying different amounts of source evidence. The
``G3-UNQUOTED`` flag would then change *how much evidence reaches the Orchestrator* as well as *how
it is escaped* -- two properties, where section 3.5.4 requires each configuration to remove exactly
one. An aggregator ordered the other way does not produce a failing test; it produces an **invalid
arm**, whose results could not support the causal claim the ablation exists to make even with every
test green.

This module therefore runs on source text only. It never sees a quoted string, it must never import
``quoting``, and ``emit.py`` calls it before the single quoting call site. The visible
consequence -- a quoted excerpt whose serialised byte length exceeds the cap -- is stated in
``evaluation-protocol.md`` section 4 beside the value, so that "length cap" cannot be read two ways
after the ``v1.0`` freeze. ADR-019 argues the whole ordering.

THE UNIT IS A UNICODE CODE POINT, AND TRUNCATION WILL NOT SPLIT A COMBINING SEQUENCE
-------------------------------------------------------------------------------------
Section 4's unit is "source characters before quoting or escaping is applied". Here a character is a
Unicode **code point**, which is what ``len`` counts on a ``str`` and what a reader comparing an
excerpt to its source record can count by hand.

Cutting at the code point boundary alone is deterministic but can leave a base character separated
from the combining marks that belong with it, or split a zero-width-joiner sequence in the middle --
producing an excerpt that renders as a different glyph from the source it claims to quote, and doing
it consistently enough that no diff will ever flag it. :func:`truncate` therefore retreats the cut
past any combining mark or joiner that would have been orphaned. The retreat only ever moves the cut
*earlier*, so the cap is never exceeded; it is a pure function of the string and of the Unicode
character database, so it is reproducible; and because the character database is a property of the
interpreter, and the interpreter is pinned in ``infra/versions.env`` under ADR-021, a change to it
arrives as a deliberate version bump rather than as a mystery diff.

Full grapheme-cluster segmentation (UAX #29) would be more correct still -- it also joins regional
indicator pairs and a handful of Indic sequences -- but the standard library does not implement it,
and adding a dependency for it would put a third-party package inside the evidenced artefact for a
case no telemetry source produces. The rule implemented here is written down precisely so that the
gap between it and UAX #29 is a known one rather than an assumed absence.

**No truncation marker is appended.** An ellipsis would add characters that are not in the source,
and ``models.py`` requires an excerpt's provenance to be checkable byte for byte against the raw
record ``raw_ref`` points at. A marker would break that for every truncated excerpt, and it would
have to be counted against the cap or exceed it -- neither of which has an answer that stays right
after the freeze.

THE EXCERPT SELECTION RULE IS PART OF THE CONTRACT, SO IT IS WRITTEN DOWN AND TESTED
--------------------------------------------------------------------------------------
When there are more candidates than the count cap admits, *which* survive decides what a responder
sees. That cannot be an accident of implementation. The rule, in order:

1. **A candidate carrying no evidence is dropped** -- the empty string, or one that is only
   whitespace. It would spend a scarce slot on nothing. Survivors are *not* stripped: trimming a
   survivor would alter source text, and this module does not alter source text, it only ends it
   earlier.
2. **A candidate byte-identical to the summary is dropped.** The event already carries that text in
   its own field, and repeating it costs a slot for no added evidence. Uniform across all four
   sources rather than handled in each normaliser, so there is one rule and one place it can be
   wrong.
3. **Duplicates are dropped, keeping the first occurrence.** Deduplication happens on the *full*
   text, before any truncation, so two candidates that differ only past the cap are still treated as
   two -- the alternative would make the surviving set depend on the cap value in a way nobody would
   predict from reading it.
4. **The first ``evidence_excerpt_count_max`` survivors are kept**, in the normaliser's declared
   order. Not the longest, not the most recent, not a sample: the normalisers rank their candidates
   most-identifying-first for exactly this moment, and "the first N" is the only rule that makes
   that ranking mean something.
5. **Each survivor is truncated** to ``evidence_excerpt_length_max_chars``.

Steps 4 and 5 are in that order because the count cap is about *which* evidence and the length cap
about *how much of it*; truncating first would let two candidates collide after the cut and would
make the selected set depend on the length cap as well as on the count cap.

THERE IS NO DEFAULT LIMIT ANYWHERE IN THIS FILE
------------------------------------------------
:class:`CapLimits` has no default values and :func:`protocol_cap_limits` raises
``limits.UncalibratedLimit`` while section 4's caps are still pending. During the offline phase
that means the replay, the determinism check and the G3 isolation test must pass their limits in
explicitly, and ADR-019 records the consequence plainly: those values are **fixture-corpus test
parameters**, they are never evidence that section 4's row is closed, and they must not be promoted
into the protocol without the fixture study behind them. What the offline corpus proves is ordering,
quoting, cap *semantics* and byte-level determinism. What it does not prove is cap calibration.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
Every golden ``monitor_events.jsonl`` in the corpus was produced under this selection rule and this
truncation rule; changing either invalidates the corpus rather than merely re-running it. Reordering
the pipeline so that quoting precedes capping invalidates the ``G3-UNQUOTED`` arm itself, which is a
result-level failure rather than a test-level one, and ``monitor/tests/test_g3_isolation.py``'s
second condition -- identical per-event excerpt counts across arms -- is what fails loudly if anyone
tries.
"""

import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from monitor.aggregator import limits as protocol_limits

# The zero-width joiner. A cut immediately before or immediately after one splits an emoji or an
# Indic conjunct sequence in half, so the retreat in truncate() treats it like a combining mark.
# Written as an escape rather than as the character itself: it is invisible, and a literal here
# would be indistinguishable from a typo in every diff and every review.
_ZERO_WIDTH_JOINER = "\u200d"

# The Unicode general categories of a mark that attaches to the character before it: non-spacing,
# spacing-combining and enclosing. Read from unicodedata rather than from a hand-written list of
# code points, so the rule follows the character database instead of drifting from it.
_MARK_CATEGORIES = frozenset({"Mn", "Mc", "Me"})


class CapConfigurationError(ValueError):
    """Raised when a cap value exists but could not bound anything: zero, negative, fractional.

    Distinct from ``limits.UncalibratedLimit``, which means the value does not exist yet. This one
    means a value exists and is unusable, which is the shape a half-finished calibration commit
    takes: a zero left behind, a float where a count belongs. Both refuse; only this one indicates
    that somebody has already written a number down.
    """


@dataclass(frozen=True, slots=True)
class CapLimits:
    """The three bounds capping needs, with no defaults and no way to construct a useless one.

    Frozen, because a limit that changed halfway through a batch would produce an event stream that
    no single set of numbers explains. Validated on construction, because the alternative is
    discovering a zero cap by finding an entire corpus of empty excerpts.
    """

    evidence_excerpt_count_max: int
    evidence_excerpt_length_max_chars: int
    summary_length_max_chars: int

    def __post_init__(self) -> None:
        for name in (
            "evidence_excerpt_count_max",
            "evidence_excerpt_length_max_chars",
            "summary_length_max_chars",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise CapConfigurationError(
                    f"{name} is {value!r}; a cap is a whole number of items or characters"
                )
            if value < 1:
                raise CapConfigurationError(
                    f"{name} is {value!r}. A cap below one is not a bound: at zero every event "
                    "would carry an empty summary and no excerpts, and the corpus would still go "
                    "green. If the intent is 'not yet measured', leave the protocol sentinel in "
                    "place and let limits.resolve refuse."
                )


def protocol_cap_limits() -> CapLimits:
    """Build :class:`CapLimits` from the protocol mirror, or raise naming the first pending key.

    The fail-closed path. It resolves the three cap keys in ``limits.CAP_KEYS`` order, so that when
    more than one is pending the key a reader is told about is the first one in the protocol block
    rather than whichever the dictionary happened to yield.
    """
    values = [protocol_limits.resolve(key) for key in protocol_limits.CAP_KEYS]
    return CapLimits(
        evidence_excerpt_count_max=int(values[0]),
        evidence_excerpt_length_max_chars=int(values[1]),
        summary_length_max_chars=int(values[2]),
    )


@dataclass(frozen=True, slots=True)
class CappedText:
    """The two capped text fields of one event, still un-quoted. Quoting is emit.py's last step."""

    summary: str
    excerpts: tuple[str, ...]


def _orphans_a_mark(text: str, cut: int) -> bool:
    """Return True when cutting ``text`` at ``cut`` would split a combining or joined sequence."""
    if cut <= 0 or cut >= len(text):
        return False
    following = text[cut]
    if following == _ZERO_WIDTH_JOINER:
        return True
    if text[cut - 1] == _ZERO_WIDTH_JOINER:
        return True
    return (
        unicodedata.combining(following) != 0 or unicodedata.category(following) in _MARK_CATEGORIES
    )


def truncate(text: str, limit: int) -> str:
    """Return at most ``limit`` code points of ``text``, never splitting a combining sequence.

    Shorter text is returned unchanged, including its trailing whitespace: this function ends text
    early, it does not tidy it. See the module docstring for the retreat rule, for why no marker is
    appended, and for the known gap between this and full UAX #29 segmentation.

    The pathological case -- a string whose first ``limit`` code points are all combining marks, so
    the retreat reaches zero -- yields the empty string. That is the honest answer for text with no
    base character in range, and it cannot arise from any of the four sources' output.
    """
    if limit < 1:
        raise CapConfigurationError(f"limit is {limit!r}; a length cap must be at least one")
    if len(text) <= limit:
        return text
    cut = limit
    while cut > 0 and _orphans_a_mark(text, cut):
        cut -= 1
    return text[:cut]


def select_excerpts(
    candidates: Iterable[str], *, summary: str, cap_limits: CapLimits
) -> tuple[str, ...]:
    """Apply the five-step selection rule to ``candidates``. The rule is in the module docstring.

    ``summary`` is the **un-capped** summary, because step 2 compares a candidate against what the
    normaliser produced rather than against what survived the summary cap -- comparing against the
    capped form would keep a candidate whose only difference from the summary is the part the cap
    removed.
    """
    kept: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate.strip():
            continue
        if candidate == summary:
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        kept.append(candidate)
        if len(kept) == cap_limits.evidence_excerpt_count_max:
            break
    return tuple(truncate(text, cap_limits.evidence_excerpt_length_max_chars) for text in kept)


def apply_caps(summary: str, candidates: Sequence[str], *, cap_limits: CapLimits) -> CappedText:
    """Cap one record's summary and excerpts. The single entry point ``emit.py`` uses.

    Excerpt selection reads the un-capped summary and the summary is capped independently, so the
    two axes section 4 owns stay independent: raising ``summary_length_max_chars`` can never change
    which excerpts an event carries, and raising an excerpt cap can never change its summary.
    """
    return CappedText(
        summary=truncate(summary, cap_limits.summary_length_max_chars),
        excerpts=select_excerpts(candidates, summary=summary, cap_limits=cap_limits),
    )
