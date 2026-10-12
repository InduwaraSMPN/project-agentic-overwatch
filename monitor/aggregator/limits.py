"""Checked copy of the Monitor limits owned by evaluation-protocol section 4, with no defaults.

WHAT THIS MODULE IS, AND WHAT IT IS NOT
---------------------------------------
``docs/protocols/evaluation-protocol.md`` section 4 is the *authority* for every value below. This
module is a mirror of it and never an independent source. Nothing here may be changed on its own:
an edit to a value in this file that is not accompanied by the identical edit to section 4 fails
``monitor/tests/test_limits_match_protocol.py``, which parses the anchored block and asserts the two
sides agree key by key. That test is the entire reason a mirror is permitted at all.
``.agents/rules/00-source-of-truth.md`` allows a literal to repeat only where no second *decision*
exists, and a machine check is what turns "a copy" into "a copy that cannot drift".

The shape is deliberately ``infra/probes/constants.py``'s, key for key and function for function --
:data:`PROTOCOL_ANCHOR`, :func:`as_protocol_mapping`, :func:`pending_keys`,
:func:`render_protocol_block`. ADR-016 settled that pattern for M1's instrument constants and M2
applies it rather than re-deciding it. What differs is the anchor this module mirrors and the one
behavioural refinement recorded below; the mechanism is the same mechanism.

WHY THIS IS A SECOND ANCHOR AND NOT MORE KEYS IN M1'S BLOCK
------------------------------------------------------------
``docs/plans/M2-implementation-plan.md`` proposed adding these keys to M1's
``m1-instrument-constants`` block. The protocol landed the other way and ADR-019 records why: M1's
test asserts that its mirror's key set is *exactly* its block's key set, which is what catches a key
silently deleted from the protocol, and a shared block would have forced that assertion down to
containment. Containment cannot catch a deletion. So section 4 carries two anchors, each owned by
one block, one mirror module and one test, with no shared union for either test to get wrong.

THE ONE REFINEMENT M2 ADDS: NO DEFAULTS, AND FAIL CLOSED
---------------------------------------------------------
Five of the six keys are *measurements*, not choices. The caps came from a study over **captured**
fixtures -- recorded from live Falco, Alertmanager, audit and Trivy output, not synthesised from a
schema -- and the latency figures from a replay on the WSL2 profile. Before that study each carried
:data:`PENDING_FIXTURE_STUDY` here and in section 4, exactly as ADR-016's measured probe constants
carried their own sentinel.

What M2 adds is that **this module publishes no fallback for a pending value and the aggregator
carries no default for one**. :func:`resolve` raises :class:`UncalibratedLimit`, naming the key,
rather than returning a plausible number. The reason is the milestone's phase split: the offline
phase builds and greens a whole fixture corpus before any live source has been captured, and a
default would let the aggregator run, let a replay produce output, and let that corpus go green
against numbers nobody has measured -- with green being the answer everyone wants, so nobody looks
again. It is the same failure shape ADR-016's withheld SLO verdict exists to prevent: a missing
measurement disguised as a satisfied requirement.

The sixth key, ``monitor_latency_ci_ceiling_multiplier``, is a *choice* and is filled. It is not a
second free-standing latency number; it scales the budget so that CI's necessarily looser assertion
cannot be relaxed without the relaxation appearing as a protocol diff, and so that it moves with the
budget instead of drifting away from it.

WHAT EACH KEY MEANS, SINCE A FROZEN NUMBER WITH AN IMPLICIT UNIT CAN BE READ TWO WAYS
-------------------------------------------------------------------------------------
``evidence_excerpt_count_max`` bounds how many excerpts one ``EvidenceEvent`` may carry.
``evidence_excerpt_length_max_chars`` and ``summary_length_max_chars`` bound the length of one
excerpt and of the summary, **counted in source characters before quoting or escaping is applied**.
That unit is section 4's own wording and it is what makes the ``G3-UNQUOTED`` arm valid rather than
confounded: quoting lengthens text, so a cap applied after it would leave the unquoted arm carrying
more source content than the quoted arm, and the flag would then change how much evidence reaches
the Orchestrator as well as how it is escaped. ``caps.py`` implements the ordering; ADR-019 argues
it.

``monitor_latency_p95_budget_ms`` and ``monitor_latency_max_budget_ms`` bound **per-event aggregator
processing time, excluding source I/O and network** -- the property the aggregator controls and the
one a fixture replay reproduces. End-to-end ``source_ts`` to ``emit_ts`` is reported alongside them
and is not the budget-bearing figure. Neither is measured here: nothing under
``monitor/aggregator/`` reads a clock, for the reason ``emit.py`` gives at length.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
``caps.py`` builds its enforcement limits from :func:`resolve`, so every emitted event's summary and
excerpt bounds come from here; the whole fixture corpus is golden output produced under one set of
these values, and changing one invalidates the corpus rather than merely re-running it. The values
freeze at ``v1.0`` with everything else in section 4, after which iron rule 6 makes a change a
logged hotfix ADR. A calibration commit is mechanical: ``python -m monitor.aggregator.limits``
prints the exact block to paste into section 4, and the same edit updates the five module-level
values below.
"""

from collections.abc import Mapping
from typing import Final

# The sentinel that stands in for a value which must be derived from captured fixtures and has not
# been derived yet. It is a string, and deliberately not None or 0: None would read as "this key is
# optional" and 0 would compare as a legitimate bound -- a zero-length cap would truncate every
# excerpt to nothing and a zero-millisecond budget would fail every event -- whereas an unmistakable
# string forces every consumer to decide what to do about it. This module decides by refusing to
# resolve; the test below decides by admitting the sentinel and requiring anything else to parse as
# a positive number.
PENDING_FIXTURE_STUDY: Final = "PENDING-M2-FIXTURE-STUDY"

# The HTML comment that marks this block inside evaluation-protocol.md section 4. An anchor is used
# rather than a heading search because headings are prose and get retitled, whereas an anchor exists
# for exactly one purpose and a reviewer who moves it knows what they are doing. It is deliberately
# not M1's anchor; see the module docstring.
PROTOCOL_ANCHOR: Final = "<!-- m2-monitor-limits -->"

# The path of the owning protocol file, relative to the repository root. Consumers resolve it
# against a root derived from their own __file__, never against the current working directory --
# and nothing in the aggregator resolves it at all at run time, because the aggregator ships as a
# container image with no docs/ tree in it.
PROTOCOL_RELATIVE_PATH: Final = "docs/protocols/evaluation-protocol.md"

# The key set is fixed and total: the section 4 block and as_protocol_mapping() must each carry
# exactly these keys, in this order. Order is part of the contract only for rendering -- the
# equality test compares mappings, not text -- but a stable order keeps the protocol diff readable
# when the calibration commit fills the five measured values.
PROTOCOL_KEYS: Final[tuple[str, ...]] = (
    "evidence_excerpt_count_max",
    "evidence_excerpt_length_max_chars",
    "summary_length_max_chars",
    "monitor_latency_p95_budget_ms",
    "monitor_latency_max_budget_ms",
    "monitor_latency_ci_ceiling_multiplier",
)

# The keys whose values are derived from captured fixtures rather than chosen. These are the five
# that may legally hold PENDING_FIXTURE_STUDY, and the five a calibration commit fills.
MEASURED_KEYS: Final[tuple[str, ...]] = (
    "evidence_excerpt_count_max",
    "evidence_excerpt_length_max_chars",
    "summary_length_max_chars",
    "monitor_latency_p95_budget_ms",
    "monitor_latency_max_budget_ms",
)

# The three keys caps.py needs before it can bound anything, in the order caps.py reports them when
# more than one is missing. Named here rather than spelled again in caps.py so that "which limits
# does capping require" has one answer.
CAP_KEYS: Final[tuple[str, ...]] = (
    "evidence_excerpt_count_max",
    "evidence_excerpt_length_max_chars",
    "summary_length_max_chars",
)

EVIDENCE_EXCERPT_COUNT_MAX: int | str = 36
EVIDENCE_EXCERPT_LENGTH_MAX_CHARS: int | str = 2904
SUMMARY_LENGTH_MAX_CHARS: int | str = 707
MONITOR_LATENCY_P95_BUDGET_MS: int | float | str = 6.169498
MONITOR_LATENCY_MAX_BUDGET_MS: int | float | str = 11.938049
MONITOR_LATENCY_CI_CEILING_MULTIPLIER: int = 4


class UncalibratedLimit(LookupError):
    """Raised when a limit is read that section 4 has not yet been given a measured value for.

    A ``LookupError`` rather than a ``ValueError`` because the failure is "this value does not exist
    yet", not "this value is wrong". The distinction matters at the call site: a caller may
    legitimately catch this one and report that the corpus cannot be bounded, and must never catch
    it and substitute a number of its own.

    The key is carried as an attribute as well as being in the message, so a caller can name the
    missing measurement in its own error without re-parsing English.
    """

    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(
            f"{key} is still {PENDING_FIXTURE_STUDY} in {PROTOCOL_RELATIVE_PATH} section 4 "
            f"(anchor {PROTOCOL_ANCHOR}). The aggregator has no default for it and will not run "
            "against a bound nobody has measured. Either derive the value from captured fixtures "
            "and land it in section 4 and in monitor/aggregator/limits.py in one commit, or pass "
            "an explicit limit at the call site -- which is a fixture-corpus test parameter and is "
            "never evidence that section 4's row is closed (ADR-019)."
        )


def is_pending(value: object) -> bool:
    """Return True when ``value`` is the uncalibrated sentinel rather than a derived number."""
    return value == PENDING_FIXTURE_STUDY


def as_protocol_mapping() -> dict[str, object]:
    """Return the mirrored limits in exactly the shape the section 4 block parses to.

    This is the comparison surface the mirror test uses and the input the section 4 renderer takes.
    A fresh structure is built on every call so that no caller can mutate the mirror for everyone
    else, which is the same reason ``infra/probes/constants.py`` builds its own on every call.
    """
    return {
        "evidence_excerpt_count_max": EVIDENCE_EXCERPT_COUNT_MAX,
        "evidence_excerpt_length_max_chars": EVIDENCE_EXCERPT_LENGTH_MAX_CHARS,
        "summary_length_max_chars": SUMMARY_LENGTH_MAX_CHARS,
        "monitor_latency_p95_budget_ms": MONITOR_LATENCY_P95_BUDGET_MS,
        "monitor_latency_max_budget_ms": MONITOR_LATENCY_MAX_BUDGET_MS,
        "monitor_latency_ci_ceiling_multiplier": MONITOR_LATENCY_CI_CEILING_MULTIPLIER,
    }


def pending_keys(mapping: Mapping[str, object] | None = None) -> tuple[str, ...]:
    """Return the measured keys that still hold the sentinel, in :data:`MEASURED_KEYS` order.

    An empty result means every measured value has been derived and a consumer may bound events and
    form a latency verdict. A non-empty result names exactly what is missing, which is what
    ``emit.py`` writes into ``latency.json`` in place of a verdict: a reader should never have to
    guess which of the five is the absent one.
    """
    source = as_protocol_mapping() if mapping is None else mapping
    return tuple(key for key in MEASURED_KEYS if is_pending(source.get(key)))


def resolve(key: str, mapping: Mapping[str, object] | None = None) -> int | float:
    """Return the numeric value of ``key``, or raise :class:`UncalibratedLimit` naming it.

    This is the fail-closed reader, and it is the only supported way to obtain a limit from the
    protocol mirror. It refuses in two distinct situations and says which: a key that is not in the
    contract at all raises :class:`KeyError`, and a key whose value is still the sentinel raises
    :class:`UncalibratedLimit`. Conflating them would leave a caller unable to tell a typo from an
    unfinished measurement.

    There is deliberately no ``default`` parameter. A default would reintroduce, at the call site,
    exactly the fallback the module refuses to publish -- and it would do so in the one place a
    reviewer is least likely to look, because the call would read as ordinary defensive code.
    """
    source = as_protocol_mapping() if mapping is None else mapping
    if key not in source:
        raise KeyError(
            f"{key!r} is not a Monitor limit; the contract is {', '.join(PROTOCOL_KEYS)}"
        )
    value = source[key]
    if is_pending(value):
        raise UncalibratedLimit(key)
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise TypeError(
            f"{key} is {value!r}, which is neither the {PENDING_FIXTURE_STUDY} sentinel nor a "
            f"number. Fix {PROTOCOL_RELATIVE_PATH} section 4 first, then this mirror."
        )
    return value


def _render_scalar(value: object) -> str:
    """Render one scalar for the section 4 block.

    Values are emitted unquoted. Every value the key set admits is an integer, a float or the
    sentinel, and none of those needs quoting in the block grammar; adding quotes would mean the
    parser has to strip them, which is one more place for the two sides to disagree.
    """
    return str(value)


def render_protocol_block(mapping: Mapping[str, object] | None = None) -> str:
    """Return the exact text of the anchored section 4 limits block, ending in one newline.

    The renderer lives here, beside the mirror, so that the block a calibration run prints and the
    block a reviewer pastes into the protocol are produced by one piece of code rather than by a
    human retyping six lines. ``monitor/tests/test_limits_match_protocol.py`` round-trips this
    function through its own parser, which is what makes "the text this prints is the text that test
    accepts" a checked claim rather than an assumption.

    ``mapping`` defaults to the mirrored limits. The fixture study passes a mapping whose five
    measured keys hold freshly derived numbers in place of the sentinel.
    """
    source = as_protocol_mapping() if mapping is None else mapping
    lines = [PROTOCOL_ANCHOR, "", "```yaml"]
    lines.extend(f"{key}: {_render_scalar(source[key])}" for key in PROTOCOL_KEYS)
    lines.append("```")
    return "\n".join(lines) + "\n"


def main() -> int:
    """Print the section 4 block for the currently mirrored limits; return an exit code.

    ``python -m monitor.aggregator.limits`` exists so that a reviewer can see, without reading
    Python, exactly what this module claims section 4 says. It takes no arguments on purpose: this
    entry point reports the mirror, and deriving new values from a captured corpus is the fixture
    study's job at T2.5b, not this module's.
    """
    print(render_protocol_block(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
