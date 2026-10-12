r"""Checked copy of the parity caps owned by prompt-parity-policy section 3, with no defaults.

WHAT THIS MODULE IS, AND WHAT IT IS NOT
---------------------------------------
``docs/protocols/prompt-parity-policy.md`` section 3 is the *authority* for every value below --
``docs/protocols/evaluation-protocol.md`` section 0's ownership table assigns "Parity tolerance"
there, and section 3 itself says the structural cap is "set at M4 from the first honest
compositions; recorded here, then frozen". This module is a mirror of that section and never an
independent source. An edit to a value here that is not accompanied by the identical edit to
section 3 fails ``agents/tests/test_limits_match_parity_policy.py``, which parses the anchored
block and asserts the two sides agree key by key. That test is the entire reason a mirror is
permitted at all: ``.agents/rules/00-source-of-truth.md`` allows a literal to repeat only where no
second *decision* exists, and a machine check is what turns "a copy" into "a copy that cannot
drift".

The shape is deliberately ``monitor/aggregator/limits.py``'s, key for key and function for function
-- :data:`PROTOCOL_ANCHOR`, :func:`as_protocol_mapping`, :func:`pending_keys`,
:func:`render_protocol_block`, a fail-closed :func:`resolve` -- and that module's shape is
deliberately ``infra/probes/constants.py``'s. ADR-016 settled the pattern for M1's instrument
constants, M2 applied it to the Monitor's caps and added the no-default refinement, and M4 applies
it a third time rather than re-deciding it. What differs is the anchor this module mirrors and the
document that owns it; the mechanism is the same mechanism. ADR-028.

WHY THIS IS A THIRD ANCHOR AND NOT MORE KEYS IN AN EXISTING BLOCK
------------------------------------------------------------------
The two existing blocks live in ``evaluation-protocol.md`` section 4 and are owned by that file.
These values are owned by ``prompt-parity-policy.md`` section 3 -- a different file with a different
owner -- so they could not join either block without moving a value out from under the document
that decides it. ADR-019 records the second half of the argument, which applies unchanged here:
each mirror test asserts that its key set is *exactly* its block's key set, because that is what
catches a key silently deleted from the protocol, and a shared block would force that assertion
down to containment. Containment cannot catch a deletion. So each block has one owning document,
one mirror module and one test.

THE CAP IS A MEASUREMENT AND THE TOLERANCES ARE CHOICES
--------------------------------------------------------
``structural_block_tokens_max`` is not chosen. Section 3 fixes it as "a fixed small cap (set at M4
from the first honest compositions; recorded here, then frozen)", so it is derived from the
compositions the milestone actually writes, in the unit
:data:`agents.registry.tokenizer.REFERENCE_TOKENIZER_ID` names, and it carries
:data:`PENDING_COMPOSITION_STUDY` until those compositions exist. That is ADR-016's measured-value
sentinel, unchanged.

The three tolerances are decisions and are filled from the start:

``condition_token_tolerance_pct`` is section 3's own **±2%** and is stated there in prose as well.
The two live in one file, so there is no cross-file drift to guard against; the block is simply the
machine-readable form of the sentence above it.

``condition_tool_call_tolerance_pct`` and ``condition_turn_tolerance_pct`` are **0**, and the zero
is the substantive decision rather than a placeholder. A prompt-token count is a *measurement* over
text that legitimate wording differences move by a percent or two, which is what a tolerance is for.
A tool-call budget and a turn budget are **declared integers** in a composition manifest -- somebody
wrote them down -- so there is no measurement error for a tolerance to absorb, and a non-zero one
would only ever license an arm quietly receiving more turns than another. Section 3.5.4 of the
dissertation grants the flat arm "every phase the same budget of prompt tokens, tool calls, and
turns as the hierarchical configuration's combined per-phase allocation"; "the same" is an equality,
and this is that equality written as a number the checker reads.

THE MODULE PUBLISHES NO FALLBACK, AND THE CHECKER CARRIES NO DEFAULT
---------------------------------------------------------------------
:func:`resolve` raises :class:`UncalibratedCap`, naming the key, rather than returning a plausible
number. M2 added that refinement to ADR-016's pattern for a reason that applies here with the sign
reversed and the stakes higher.

``scripts/grep_guard.sh`` may pass vacuously because nothing found means nothing violated. Parity
asserts an **equality across conditions**, so nothing found means nothing *proved* -- and a green
check over an absent registry would make deleting the registry the easiest way to pass the gate. A
default cap would be the same failure one layer in: the gate would run, the table would print, and
the structural blocks would be bounded by a number nobody chose, with green being the answer
everyone wants so nobody looks again. :mod:`agents.registry.parity` therefore exits non-zero when a
cap is still pending, when a condition has no composition, or when a declared budget is missing.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
``make parity-check``'s verdict, and therefore whether a pull request touching ``agents/prompts/``
or ``agents/tools/`` can merge. The values freeze at ``v1.0`` with everything else section 3 owns,
after which AGENTS.md iron rule 6 makes a change a logged hotfix ADR. A calibration commit is
mechanical: ``python -m agents.registry.limits`` prints the exact block to paste into section 3, and
the same edit updates the module-level value below.
"""

from collections.abc import Mapping
from typing import Final

__all__ = (
    "CHOSEN_KEYS",
    "MEASURED_KEYS",
    "PENDING_COMPOSITION_STUDY",
    "PROTOCOL_ANCHOR",
    "PROTOCOL_KEYS",
    "PROTOCOL_RELATIVE_PATH",
    "STRUCTURAL_BLOCK_TOKENS_MAX",
    "UncalibratedCap",
    "as_protocol_mapping",
    "is_pending",
    "pending_keys",
    "render_protocol_block",
    "resolve",
)

# The sentinel that stands in for a value which must be derived from the first honest compositions
# and has not been derived yet. A string, and deliberately not None or 0, for
# monitor/aggregator/limits.py's reason: None would read as "this key is optional" and 0 would
# compare as a legitimate bound -- a zero-token cap would reject every structural block that exists
# -- whereas an unmistakable string forces every consumer to decide what to do about it. This
# module decides by refusing to resolve.
PENDING_COMPOSITION_STUDY: Final = "PENDING-M4-COMPOSITION"

# The HTML comment that marks this block inside prompt-parity-policy.md section 3. An anchor rather
# than a heading search, because headings are prose and get retitled, whereas an anchor exists for
# exactly one purpose and a reviewer who moves it knows what they are doing.
PROTOCOL_ANCHOR: Final = "<!-- m4-parity-caps -->"

# The path of the owning protocol file, relative to the repository root. Consumers resolve it
# against a root derived from their own __file__, never against the current working directory --
# and nothing in the agent layer's run-time path resolves it at all, because the agent layer ships
# as a container image with no docs/ tree in it. Only the gate and its test read the protocol.
PROTOCOL_RELATIVE_PATH: Final = "docs/protocols/prompt-parity-policy.md"

# The key set is fixed and total: the section 3 block and as_protocol_mapping() must each carry
# exactly these keys, in this order. Order is part of the contract only for rendering -- the
# equality test compares mappings, not text -- but a stable order keeps the protocol diff readable
# when the calibration commit fills the measured value.
PROTOCOL_KEYS: Final[tuple[str, ...]] = (
    "structural_block_tokens_max",
    "condition_token_tolerance_pct",
    "condition_tool_call_tolerance_pct",
    "condition_turn_tolerance_pct",
)

# The keys derived from the compositions rather than chosen. These are the ones that may legally
# hold PENDING_COMPOSITION_STUDY, and the ones a calibration commit fills.
MEASURED_KEYS: Final[tuple[str, ...]] = ("structural_block_tokens_max",)

# The keys that are decisions and must therefore always carry a usable value. A pending tolerance
# would leave the gate with no bound at all and nothing would say so.
CHOSEN_KEYS: Final[tuple[str, ...]] = (
    "condition_token_tolerance_pct",
    "condition_tool_call_tolerance_pct",
    "condition_turn_tolerance_pct",
)

# Derived at M4 from the first honest compositions, exactly as section 3 requires, and with no
# headroom added: it is the largest structural block the registry actually holds
# (`structural.s3.uncompressed-supervision`, 39 reference tokens), not that number rounded up.
# Headroom would be a second decision -- how much a topology block is allowed to grow into -- taken
# silently, at the moment nobody is looking, by whoever ran the calibration. A structural block that
# needs to grow past this is a design change with an ADR and a supervisor note, which is rule 20's
# posture stated as a number rather than as an intention.
STRUCTURAL_BLOCK_TOKENS_MAX: int | str = 39
CONDITION_TOKEN_TOLERANCE_PCT: int | float = 2
CONDITION_TOOL_CALL_TOLERANCE_PCT: int | float = 0
CONDITION_TURN_TOLERANCE_PCT: int | float = 0


class UncalibratedCap(LookupError):
    """Raised when a cap is read that section 3 has not yet been given a derived value for.

    A ``LookupError`` rather than a ``ValueError`` because the failure is "this value does not exist
    yet", not "this value is wrong". The distinction matters at the call site: the gate may
    legitimately catch this one and report that parity cannot be asserted, and must never catch it
    and substitute a number of its own.

    The key is carried as an attribute as well as in the message, so a caller can name the missing
    value in its own error without re-parsing English.
    """

    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(
            f"{key} is still {PENDING_COMPOSITION_STUDY} in {PROTOCOL_RELATIVE_PATH} section 3 "
            f"(anchor {PROTOCOL_ANCHOR}). The parity gate has no default for it and will not "
            "report green against a bound nobody chose. Derive the value from the composed "
            "registry -- `python -m agents.registry.parity --emit-caps` prints it -- and land it "
            "in section 3 and in agents/registry/limits.py in one commit."
        )


def is_pending(value: object) -> bool:
    """Return True when ``value`` is the uncalibrated sentinel rather than a derived number."""
    return value == PENDING_COMPOSITION_STUDY


def as_protocol_mapping() -> dict[str, object]:
    """Return the mirrored caps in exactly the shape the section 3 block parses to.

    A fresh structure on every call so that no caller can mutate the mirror for everyone else,
    which is the reason ``monitor/aggregator/limits.py`` and ``infra/probes/constants.py`` both
    build their own on every call.
    """
    return {
        "structural_block_tokens_max": STRUCTURAL_BLOCK_TOKENS_MAX,
        "condition_token_tolerance_pct": CONDITION_TOKEN_TOLERANCE_PCT,
        "condition_tool_call_tolerance_pct": CONDITION_TOOL_CALL_TOLERANCE_PCT,
        "condition_turn_tolerance_pct": CONDITION_TURN_TOLERANCE_PCT,
    }


def pending_keys(mapping: Mapping[str, object] | None = None) -> tuple[str, ...]:
    """Return the measured keys that still hold the sentinel, in :data:`MEASURED_KEYS` order.

    An empty result means the cap has been derived and the gate may assert over structural blocks.
    A non-empty result names exactly what is missing, which is what ``scripts/parity_check.sh``
    prints in place of a verdict: a reader should never have to guess which value is absent.
    """
    source = as_protocol_mapping() if mapping is None else mapping
    return tuple(key for key in MEASURED_KEYS if is_pending(source.get(key)))


def resolve(key: str, mapping: Mapping[str, object] | None = None) -> int | float:
    """Return the numeric value of ``key``, or raise :class:`UncalibratedCap` naming it.

    The fail-closed reader, and the only supported way to obtain a cap from the mirror. It refuses
    in two distinct situations and says which: a key that is not in the contract at all raises
    :class:`KeyError`, and a key whose value is still the sentinel raises :class:`UncalibratedCap`.
    Conflating them would leave a caller unable to tell a typo from an unfinished calibration.

    There is deliberately no ``default`` parameter, for ``monitor/aggregator/limits.py``'s reason: a
    default would reintroduce at the call site exactly the fallback the module refuses to publish,
    in the one place a reviewer is least likely to look, because the call would read as ordinary
    defensive code.
    """
    source = as_protocol_mapping() if mapping is None else mapping
    if key not in source:
        raise KeyError(f"{key!r} is not a parity cap; the contract is {', '.join(PROTOCOL_KEYS)}")
    value = source[key]
    if is_pending(value):
        raise UncalibratedCap(key)
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise TypeError(
            f"{key} is {value!r}, which is neither the {PENDING_COMPOSITION_STUDY} sentinel nor a "
            f"number. Fix {PROTOCOL_RELATIVE_PATH} section 3 first, then this mirror."
        )
    return value


def _render_scalar(value: object) -> str:
    """Render one scalar for the section 3 block.

    Values are emitted unquoted. Every value the key set admits is an integer, a float or the
    sentinel, and none needs quoting in the block grammar; adding quotes would mean the parser has
    to strip them, which is one more place for the two sides to disagree.
    """
    return str(value)


def render_protocol_block(mapping: Mapping[str, object] | None = None) -> str:
    """Return the exact text of the anchored section 3 caps block, ending in one newline.

    The renderer lives beside the mirror so that the block a calibration run prints and the block a
    reviewer pastes into the protocol are produced by one piece of code rather than by a human
    retyping four lines. ``agents/tests/test_limits_match_parity_policy.py`` round-trips this
    function through its own parser, which is what makes "the text this prints is the text that
    test accepts" a checked claim rather than an assumption.
    """
    source = as_protocol_mapping() if mapping is None else mapping
    lines = [PROTOCOL_ANCHOR, "", "```yaml"]
    lines.extend(f"{key}: {_render_scalar(source[key])}" for key in PROTOCOL_KEYS)
    lines.append("```")
    return "\n".join(lines) + "\n"


def main() -> int:
    """Print the section 3 block for the currently mirrored caps; return an exit code.

    ``python -m agents.registry.limits`` exists so that a reviewer can see, without reading Python,
    exactly what this module claims section 3 says. It takes no arguments on purpose: this entry
    point reports the mirror, and deriving the cap from the composed registry is
    ``python -m agents.registry.parity --emit-caps``'s job, not this module's.
    """
    print(render_protocol_block(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
