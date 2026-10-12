"""The mirror check: monitor/aggregator/limits.py must agree with evaluation-protocol section 4.

WHAT THIS TEST IS FOR
---------------------
``.agents/rules/00-source-of-truth.md`` allows a literal to appear twice only where no second
*decision* exists. :mod:`monitor.aggregator.limits` is a copy of the numbers
``docs/protocols/evaluation-protocol.md`` section 4 owns under the ``m2-monitor-limits`` anchor, and
this test is the entire justification for that copy being legal: it parses the anchored block out of
the protocol and asserts the two sides agree key by key, so a value changed in one place and not the
other fails CI instead of silently diverging into two sources of truth.

If this test fails with a mismatch, the protocol is right and the module is wrong. That direction is
not negotiable and is not a matter of which was edited last.

WHY THERE ARE TWO ANCHORS AND TWO TESTS, NOT ONE OF EACH
----------------------------------------------------------
``infra/tests/test_constants_match_protocol.py`` does the same job for M1's
``m1-instrument-constants`` block, and asserts that its mirror's key set is **exactly** its block's
key set -- which is what catches a key silently deleted from the protocol. Adding M2's keys to that
block would have forced that assertion down to containment, and containment cannot catch a
deletion. So each block has one mirror module and one test, with no shared union for either to get
wrong. ADR-019 records the decision; this file is the M2 half of it and deliberately mirrors the M1
half's shape.

WHAT THIS FILE ADDS THAT THE M1 TEST DOES NOT
-----------------------------------------------
The fail-closed behaviour, which is M2's one refinement on ADR-016's pattern. The M1 mirror lets a
consumer read a pending value and decide for itself; this one refuses, because during the offline
phase every one of the five measured values is a placeholder and a default would let a whole fixture
corpus go green against numbers nobody has measured. The tests below assert that
:func:`~monitor.aggregator.limits.resolve` raises for each pending key, that the error names the
key, and that the cap builder in ``caps.py`` propagates the refusal rather than substituting
anything.

WHY THERE IS A PARSER HERE AND NOT A YAML DEPENDENCY
-----------------------------------------------------
CI installs ``pytest`` plus whatever ``scripts/install_runtime_deps.sh`` reads from
``infra/versions.env``, which is Pydantic and nothing else. PyYAML is not available and adding it to
run one assertion would put a third-party package on the critical path of the lint job for a grammar
that is a dozen lines of :mod:`re`. This block is flatter than M1's -- six scalars and no list -- so
the parser is correspondingly smaller, and anything outside the grammar raises rather than being
tolerated, because a block this test half-understands is a block this test cannot be trusted about.

WHY THE FIXTURE VALUES ARE OBVIOUSLY FAKE
------------------------------------------
The parser is exercised against a fixture defined inline below, whose values resemble nothing real.
The milestone's Definition of done greps each section 4 value across the repository and requires
exactly two occurrences -- the protocol and the mirror -- so a fixture holding a real number would
be a third home that is not one. The fixture tests the grammar; the protocol test tests values.
"""

import re
import sys
from pathlib import Path

import pytest

# The repository root, derived from this file's own location rather than from the working directory,
# so the test reads the same protocol file whether pytest is invoked from the root, from monitor/,
# or from anywhere else. The same root is prepended to sys.path because `monitor` is only importable
# when the root is on it, and the CI step's working directory is a property of the workflow rather
# than something this file should depend on.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from monitor.aggregator.caps import protocol_cap_limits  # noqa: E402
from monitor.aggregator.limits import (  # noqa: E402
    CAP_KEYS,
    MEASURED_KEYS,
    MONITOR_LATENCY_CI_CEILING_MULTIPLIER,
    PENDING_FIXTURE_STUDY,
    PROTOCOL_ANCHOR,
    PROTOCOL_KEYS,
    PROTOCOL_RELATIVE_PATH,
    UncalibratedLimit,
    as_protocol_mapping,
    is_pending,
    pending_keys,
    render_protocol_block,
    resolve,
)

PROTOCOL_PATH = REPO_ROOT / PROTOCOL_RELATIVE_PATH

FENCE_OPEN = "```yaml"
FENCE_CLOSE = "```"

_SCALAR = re.compile(r"^([a-z_][a-z0-9_]*): (\S+)$")

# A fixture whose values resemble nothing real, for the reason the module docstring gives. It
# exercises every branch of the grammar: an integer scalar, a float scalar and a bare-string scalar.
FIXTURE_BLOCK = """<!-- m2-monitor-limits -->

```yaml
evidence_excerpt_count_max: 907
evidence_excerpt_length_max_chars: 911
summary_length_max_chars: 919
monitor_latency_p95_budget_ms: 929.5
monitor_latency_max_budget_ms: FIXTURE-SENTINEL
monitor_latency_ci_ceiling_multiplier: 937
```
"""

FIXTURE_EXPECTED: dict[str, object] = {
    "evidence_excerpt_count_max": 907,
    "evidence_excerpt_length_max_chars": 911,
    "summary_length_max_chars": 919,
    "monitor_latency_p95_budget_ms": 929.5,
    "monitor_latency_max_budget_ms": "FIXTURE-SENTINEL",
    "monitor_latency_ci_ceiling_multiplier": 937,
}


class AnchorNotFound(LookupError):
    """Raised when the anchor comment is absent from the protocol text."""


class BlockNotFound(LookupError):
    """Raised when the anchor is present but is not followed by a fenced yaml block."""


class BlockSyntaxError(ValueError):
    """Raised when a line inside the block is outside the grammar this parser accepts."""


def find_limits_block(markdown: str) -> str:
    """Return the text inside the fenced yaml block that follows the anchor comment.

    Blank lines between the anchor and the fence are tolerated, because Markdown authors put one
    there and a test that broke over it would be an obstacle rather than a check. Anything else
    between them is not: it would mean the anchor and the block are no longer adjacent, and this
    function would then be reading a block it was not pointed at.
    """
    lines = markdown.splitlines()
    anchor_at = next(
        (index for index, line in enumerate(lines) if line.strip() == PROTOCOL_ANCHOR),
        None,
    )
    if anchor_at is None:
        raise AnchorNotFound(PROTOCOL_ANCHOR)

    cursor = anchor_at + 1
    while cursor < len(lines) and not lines[cursor].strip():
        cursor += 1
    if cursor >= len(lines) or lines[cursor].strip() != FENCE_OPEN:
        raise BlockNotFound(FENCE_OPEN)

    body: list[str] = []
    cursor += 1
    while cursor < len(lines):
        if lines[cursor].strip() == FENCE_CLOSE:
            return "\n".join(body)
        body.append(lines[cursor])
        cursor += 1
    raise BlockNotFound(FENCE_CLOSE)


def _coerce(text: str) -> object:
    """Return ``text`` as an int, else as a float, else as the string itself."""
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        return text


def parse_block(block_text: str) -> dict[str, object]:
    """Parse the block's flat mapping. The grammar is one ``key: value`` per line and nothing else.

    Blank lines and ``#`` comments are skipped. Anything else raises, because a parser that shrugged
    at a line it did not recognise could silently miss the very key it exists to compare. Note that
    this block, unlike M1's, has no nested structure at all -- so an indented line is outside the
    grammar rather than being a list entry, and is refused as such.
    """
    mapping: dict[str, object] = {}
    for number, raw in enumerate(block_text.splitlines(), start=1):
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        scalar = _SCALAR.match(line)
        if scalar is None:
            raise BlockSyntaxError(f"line {number}: not in the block grammar: {raw!r}")
        mapping[scalar.group(1)] = _coerce(scalar.group(2))
    return mapping


def protocol_mapping() -> dict[str, object]:
    """Return the parsed section 4 block, failing with remediation when it is absent.

    Every failure path here names what is missing and what to do about it, because until the section
    4 edit lands this message is the only thing this file reports.
    """
    __tracebackhide__ = True
    if not PROTOCOL_PATH.is_file():
        pytest.fail(f"protocol file not found at {PROTOCOL_PATH}")

    markdown = PROTOCOL_PATH.read_text(encoding="utf-8")
    parsed: dict[str, object] | None = None
    problem: str | None = None

    # The failure is recorded and reported after the handler rather than from inside it. Calling
    # pytest.fail() within an `except` chains the caught exception onto the report, and the sentence
    # that explains what to do is the part that matters.
    try:
        parsed = parse_block(find_limits_block(markdown))
    except AnchorNotFound:
        problem = (
            f"MISSING ANCHOR: {PROTOCOL_ANCHOR} does not appear in {PROTOCOL_RELATIVE_PATH}. "
            "Section 4 of that file must carry the anchor comment on a line of its own, followed "
            "by a fenced yaml block holding the Monitor limits. Run "
            "`python -m monitor.aggregator.limits` to print the exact text to paste."
        )
    except BlockNotFound as missing:
        problem = (
            f"MISSING BLOCK: {PROTOCOL_ANCHOR} was found in {PROTOCOL_RELATIVE_PATH}, but the "
            f"expected {missing.args[0]!r} fence was not. The anchor must be followed, after at "
            "most blank lines, by a fenced yaml block. Run `python -m monitor.aggregator.limits` "
            "to print the exact text to paste."
        )
    except BlockSyntaxError as broken:
        problem = (
            f"MALFORMED BLOCK in {PROTOCOL_RELATIVE_PATH}: {broken}. The block grammar is a flat "
            "key: value mapping; see parse_block in this file."
        )

    if problem is not None:
        pytest.fail(problem)
    assert parsed is not None
    return parsed


def test_parser_accepts_the_inline_fixture() -> None:
    """The grammar round-trips a block whose values resemble nothing real."""
    assert parse_block(find_limits_block(FIXTURE_BLOCK)) == FIXTURE_EXPECTED


def test_parser_names_a_missing_anchor() -> None:
    """A document without the anchor raises the anchor error, not a generic one."""
    with pytest.raises(AnchorNotFound):
        find_limits_block("# A protocol with no anchor in it\n")


def test_parser_names_a_missing_fence() -> None:
    """An anchor with no fenced block after it raises the block error, not the anchor error."""
    with pytest.raises(BlockNotFound):
        find_limits_block(f"{PROTOCOL_ANCHOR}\n\nSome prose, and no fence at all.\n")


def test_parser_rejects_a_line_outside_the_grammar() -> None:
    """A line the grammar does not cover raises instead of being skipped."""
    with pytest.raises(BlockSyntaxError):
        # 907 rather than a real cap, for the reason the module docstring gives about the DoD's
        # two-occurrence grep.
        parse_block("evidence_excerpt_count_max: 907\n  nested: not-in-this-block\n")


def test_renderer_round_trips_through_the_parser() -> None:
    """The text the renderer prints is exactly the text this parser accepts.

    Without this, "paste what the module printed" and "what the mirror check reads" are two claims
    about one string that nothing holds together.
    """
    rendered = render_protocol_block()
    assert parse_block(find_limits_block(rendered)) == as_protocol_mapping()


def test_protocol_block_matches_the_mirror() -> None:
    """Section 4 and monitor/aggregator/limits.py carry the same keys with the same values."""
    from_protocol = protocol_mapping()
    from_module = as_protocol_mapping()

    assert set(from_protocol) == set(PROTOCOL_KEYS), (
        "the section 4 block's key set differs from PROTOCOL_KEYS: "
        f"unexpected {sorted(set(from_protocol) - set(PROTOCOL_KEYS))}, "
        f"missing {sorted(set(PROTOCOL_KEYS) - set(from_protocol))}"
    )
    assert set(from_module) == set(PROTOCOL_KEYS)

    for key in PROTOCOL_KEYS:
        assert from_protocol[key] == from_module[key], (
            f"{key} differs: evaluation-protocol section 4 says {from_protocol[key]!r}, "
            f"monitor/aggregator/limits.py says {from_module[key]!r}. The protocol is the "
            "authority; fix the module, not the protocol, unless the protocol edit is the change "
            "under review."
        )


def test_the_key_order_is_the_same_on_both_sides() -> None:
    """The block's key order matches PROTOCOL_KEYS, so the calibration commit's diff stays readable.

    Not required for correctness -- the equality test above compares mappings -- but a reordered
    block would make the one commit that fills five values at once unreadable in review, which for a
    value frozen at ``v1.0`` is the moment review matters most.
    """
    assert tuple(protocol_mapping()) == PROTOCOL_KEYS


@pytest.mark.parametrize("key", MEASURED_KEYS)
def test_measured_value_is_the_sentinel_or_a_positive_number(key: str) -> None:
    """A measured limit is either still pending, or a number that could have been derived.

    This is the guard on the calibration commit. The five measured values arrive from the fixture
    study in a single protocol edit that is frozen at ``v1.0``, and the failure this catches is a
    value that is neither honest-pending nor usable -- a zero left behind by a half-finished edit, a
    string that was meant to be a number, a negative budget.

    Zero is rejected rather than admitted. A zero cap would truncate every summary to nothing and
    admit no excerpts at all, while a corpus built under it would still go green; a zero budget
    would fail every event. In practice a zero here is an unfilled placeholder wearing a number's
    clothes, which is exactly what this test exists to catch.
    """
    value = as_protocol_mapping()[key]
    if is_pending(value):
        pytest.skip(f"{key} is uncalibrated; nothing to validate until captured fixtures exist")
    assert isinstance(value, int | float) and not isinstance(value, bool), (
        f"{key} is {value!r}, which is neither the pending sentinel nor a number"
    )
    assert value > 0, f"{key} is {value!r}; a derived limit must be positive"
    if key in CAP_KEYS:
        assert isinstance(value, int), f"{key} is {value!r}; a cap counts whole items or characters"


def test_the_ci_ceiling_multiplier_is_a_choice_and_is_filled() -> None:
    """The one key that is a decision rather than a measurement carries a usable value.

    It scales the budget into the looser figure CI asserts against, so it cannot itself be pending:
    a pending multiplier would leave CI with no ceiling at all and nothing would say so.
    """
    assert not is_pending(MONITOR_LATENCY_CI_CEILING_MULTIPLIER)
    assert isinstance(MONITOR_LATENCY_CI_CEILING_MULTIPLIER, int)
    assert MONITOR_LATENCY_CI_CEILING_MULTIPLIER >= 1, (
        "a ceiling multiplier below one would make CI's assertion tighter than the budget it is "
        "supposed to loosen"
    )


def test_pending_keys_names_exactly_the_uncalibrated_measured_keys() -> None:
    """``pending_keys`` agrees with the mirror, in MEASURED_KEYS order."""
    mapping = as_protocol_mapping()
    expected = tuple(key for key in MEASURED_KEYS if is_pending(mapping[key]))
    assert pending_keys() == expected


@pytest.mark.parametrize("key", MEASURED_KEYS)
def test_resolve_fails_closed_on_a_pending_limit(key: str) -> None:
    """Reading a pending limit raises the named error, and the message names the key.

    The fail-closed refinement in one assertion. If this ever starts skipping for every key, the
    fixture study has landed and the aggregator can run against section 4 without an override.
    """
    if not is_pending(as_protocol_mapping()[key]):
        pytest.skip(f"{key} has been calibrated; there is nothing left to refuse")
    with pytest.raises(UncalibratedLimit) as refusal:
        resolve(key)
    assert refusal.value.key == key
    assert key in str(refusal.value)
    assert PENDING_FIXTURE_STUDY in str(refusal.value)


def test_resolve_distinguishes_an_unknown_key_from_an_uncalibrated_one() -> None:
    """A typo raises KeyError; a pending measurement raises UncalibratedLimit. Never the same error.

    Conflating them would leave a caller unable to tell a misspelling from an unfinished
    measurement, and the remedies are opposite.
    """
    with pytest.raises(KeyError):
        resolve("evidence_excerpt_count_maximum")


def test_the_cap_builder_propagates_the_refusal_rather_than_defaulting() -> None:
    """``caps.protocol_cap_limits`` refuses while any cap key is pending, naming the first one.

    This is the assertion that the *aggregator* fails closed, not merely that the mirror can. A
    default anywhere between ``limits.resolve`` and ``caps.CapLimits`` would let a replay run and a
    fixture corpus go green against a bound nobody measured.
    """
    still_pending = [key for key in CAP_KEYS if is_pending(as_protocol_mapping()[key])]
    if not still_pending:
        pytest.skip("every cap has been calibrated; the aggregator no longer needs an override")
    with pytest.raises(UncalibratedLimit) as refusal:
        protocol_cap_limits()
    assert refusal.value.key == still_pending[0]
