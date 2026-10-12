r"""The mirror check: agents/registry/limits.py must agree with prompt-parity-policy section 3.

WHAT THIS TEST IS FOR
---------------------
``.agents/rules/00-source-of-truth.md`` allows a literal to appear twice only where no second
*decision* exists. :mod:`agents.registry.limits` is a copy of the four numbers
``docs/protocols/prompt-parity-policy.md`` section 3 owns under the ``m4-parity-caps`` anchor, and
this test is the entire justification for that copy being legal: it parses the anchored block out of
the protocol and asserts the two sides agree key by key, value by value and type by type, so a
number changed in one place and not the other fails CI instead of silently becoming two sources of
truth.

If this test fails with a mismatch, the protocol is right and the module is wrong. That direction is
not negotiable and is not a matter of which was edited last.

THIS IS ADR-016's PATTERN APPLIED A THIRD TIME, AND THE THIRD ANCHOR IS NOT AN ACCIDENT
----------------------------------------------------------------------------------------
``infra/tests/test_constants_match_protocol.py`` does this job for M1's ``m1-instrument-constants``
block and ``monitor/tests/test_limits_match_protocol.py`` for M2's ``m2-monitor-limits``. Both
assert that the mirror's key set is **exactly** its block's key set, which is what catches a key
silently deleted from the protocol; a shared block would have forced that assertion down to
containment, and containment cannot catch a deletion. ADR-019 records that argument and it applies
unchanged here, with one addition: those two blocks live in ``evaluation-protocol.md`` section 4 and
are owned by that document, whereas these values are owned by ``prompt-parity-policy.md`` section 3
because ``evaluation-protocol.md`` section 0's ownership table assigns "Parity tolerance" there.
Joining them would have moved a value out from under the document that decides it. So: one owning
document, one mirror module, one test, three times over.

WHAT WOULD FAIL SILENTLY WITHOUT THIS FILE
--------------------------------------------
Every consumer of these caps reads the *module*, never the protocol. ``make parity-check`` bounds
structural blocks with :data:`~agents.registry.limits.STRUCTURAL_BLOCK_TOKENS_MAX` and compares
condition token totals against ``condition_token_tolerance_pct``. Nothing in that path opens
``docs/``. So a tolerance loosened in ``limits.py`` alone would widen the gate while the protocol
went on saying the old number, the gate would report green, the pull request would carry a token
table nobody could reconcile with section 3, and the divergence would surface -- if ever -- as a
reviewer noticing two different numbers in two documents. ``.agents/rules/20-parity-and-
determinism.md`` states the prohibition ("the change is wrong -- fix the change, do not adjust the
tolerance"); this file is what makes it a check rather than an instruction.

WHY THERE IS A PARSER HERE AND NOT A YAML DEPENDENCY
-----------------------------------------------------
:mod:`agents.registry` is standard-library only, and that is a gate requirement rather than a
preference: conflict M4-C1 puts ``make parity-check`` in ``.github/workflows/ci.yml``'s
``guardrail-grep`` job, which installs nothing at all. This test must not be the thing that adds
the dependency the package refuses -- a PyYAML import here would make "the parity path needs no
packages" true of the module and false of the check that guards it.

The grammar is therefore a dozen lines of :mod:`re`, and anything outside it **raises** rather than
being tolerated, for the reason ``monitor/tests/test_limits_match_protocol.py`` gives about its own
parser: a parser that shrugs at a line it does not recognise could silently miss the very key it
exists to compare. An indented line is not a nested structure here, it is a refusal; this block is
flat, four scalars and nothing else.

WHY THE FIXTURE VALUES ARE OBVIOUSLY FAKE
------------------------------------------
The grammar is exercised against a fixture defined inline below whose values resemble nothing real.
Section 3's values have exactly two homes -- the protocol and the mirror -- and a fixture holding a
real number would be a third home that is not one, and would defeat any grep that counts them. The
fixture tests the grammar; :func:`test_protocol_block_matches_the_mirror` tests the values.
"""

import inspect
import re
import sys
from pathlib import Path

import pytest

# The repository root, derived from this file's own location rather than from the working directory,
# so the test reads the same protocol file whether pytest is invoked from the root, from agents/ or
# from anywhere else. The same root is prepended to sys.path because `agents` is only importable
# when the root is on it, and the CI step's working directory is a property of the workflow rather
# than something this file should depend on.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agents.registry.limits import (  # noqa: E402
    CHOSEN_KEYS,
    MEASURED_KEYS,
    PENDING_COMPOSITION_STUDY,
    PROTOCOL_ANCHOR,
    PROTOCOL_KEYS,
    PROTOCOL_RELATIVE_PATH,
    UncalibratedCap,
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
FIXTURE_BLOCK = f"""{PROTOCOL_ANCHOR}

{FENCE_OPEN}
structural_block_tokens_max: 941
condition_token_tolerance_pct: 947.5
condition_tool_call_tolerance_pct: FIXTURE-SENTINEL
condition_turn_tolerance_pct: 953
{FENCE_CLOSE}
"""

FIXTURE_EXPECTED: dict[str, object] = {
    "structural_block_tokens_max": 941,
    "condition_token_tolerance_pct": 947.5,
    "condition_tool_call_tolerance_pct": "FIXTURE-SENTINEL",
    "condition_turn_tolerance_pct": 953,
}


class AnchorNotFound(LookupError):
    """Raised when the anchor comment is absent from the protocol text."""


class BlockNotFound(LookupError):
    """Raised when the anchor is present but is not followed by a fenced yaml block."""


class BlockSyntaxError(ValueError):
    """Raised when a line inside the block is outside the grammar this parser accepts."""


def _locate(markdown: str) -> tuple[list[str], int, int, int]:
    """Return the document's lines and the anchor, opening-fence and closing-fence indices.

    One locator with two callers, so that "the mapping this test compares" and "the bytes this test
    compares" are provably the same region of the same file rather than two searches that agree
    today. Blank lines between the anchor and the fence are tolerated, because Markdown authors put
    one there; anything else between them is not, because it would mean the anchor and the block are
    no longer adjacent and this parser would then be reading a block it was not pointed at.
    """
    lines = markdown.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    anchor_at = next(
        (index for index, line in enumerate(lines) if line.strip() == PROTOCOL_ANCHOR),
        None,
    )
    if anchor_at is None:
        raise AnchorNotFound(PROTOCOL_ANCHOR)

    open_at = anchor_at + 1
    while open_at < len(lines) and not lines[open_at].strip():
        open_at += 1
    if open_at >= len(lines) or lines[open_at].strip() != FENCE_OPEN:
        raise BlockNotFound(FENCE_OPEN)

    close_at = open_at + 1
    while close_at < len(lines):
        if lines[close_at].strip() == FENCE_CLOSE:
            return lines, anchor_at, open_at, close_at
        close_at += 1
    raise BlockNotFound(FENCE_CLOSE)


def find_caps_block(markdown: str) -> str:
    """Return the text inside the fenced yaml block that follows the anchor comment."""
    lines, _, open_at, close_at = _locate(markdown)
    return "\n".join(lines[open_at + 1 : close_at])


def extract_block_text(markdown: str) -> str:
    """Return the anchored block verbatim, from the anchor line through the closing fence.

    Verbatim, and deliberately not reassembled from the parsed mapping: this is what
    :func:`test_the_rendered_block_is_the_block_in_the_document` compares against
    :func:`~agents.registry.limits.render_protocol_block`, and a reassembly would compare the
    renderer against itself and call the result a round trip.
    """
    lines, anchor_at, _, close_at = _locate(markdown)
    return "\n".join(lines[anchor_at : close_at + 1]) + "\n"


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
    at a line it did not recognise could silently miss the very key it exists to compare. This block
    has no nested structure at all, so an indented line is outside the grammar rather than being a
    list entry, and is refused as such.
    """
    mapping: dict[str, object] = {}
    for number, raw in enumerate(block_text.splitlines(), start=1):
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        scalar = _SCALAR.match(line)
        if scalar is None:
            raise BlockSyntaxError(f"line {number}: not in the block grammar: {raw!r}")
        key = scalar.group(1)
        if key in mapping:
            raise BlockSyntaxError(f"line {number}: duplicate key {key!r} in the block")
        mapping[key] = _coerce(scalar.group(2))
    return mapping


def protocol_markdown() -> str:
    """Return the protocol document's text, failing with the path when it is not there."""
    __tracebackhide__ = True
    if not PROTOCOL_PATH.is_file():
        pytest.fail(
            f"protocol file not found at {PROTOCOL_PATH}. agents/registry/limits.py names it as "
            f"{PROTOCOL_RELATIVE_PATH!r}, resolved against the repository root rather than the "
            "working directory; a miss here means the constant is stale, not that the test ran "
            "from the wrong place"
        )
    return PROTOCOL_PATH.read_text(encoding="utf-8")


def protocol_mapping() -> dict[str, object]:
    """Return the parsed section 3 block, failing with remediation when it is absent or malformed.

    Every failure path here names what is missing and what to do about it, because when the anchor
    or the block is the thing that broke, this message is the only thing this file reports.
    """
    __tracebackhide__ = True
    markdown = protocol_markdown()
    parsed: dict[str, object] | None = None
    problem: str | None = None

    # The failure is recorded and reported after the handler rather than from inside it. Calling
    # pytest.fail() within an `except` chains the caught exception onto the report, and the sentence
    # that explains what to do is the part that matters.
    try:
        parsed = parse_block(find_caps_block(markdown))
    except AnchorNotFound:
        problem = (
            f"MISSING ANCHOR: {PROTOCOL_ANCHOR} does not appear in {PROTOCOL_RELATIVE_PATH}. "
            "Section 3 of that file must carry the anchor comment on a line of its own, followed "
            "by a fenced yaml block holding the parity caps. Run "
            "`python -m agents.registry.limits` to print the exact text to paste."
        )
    except BlockNotFound as missing:
        problem = (
            f"MISSING BLOCK: {PROTOCOL_ANCHOR} was found in {PROTOCOL_RELATIVE_PATH}, but the "
            f"expected {missing.args[0]!r} fence was not. The anchor must be followed, after at "
            "most blank lines, by a fenced yaml block. Run `python -m agents.registry.limits` to "
            "print the exact text to paste."
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


# ------------------------------------------------------------------------------------------------
# The parser, exercised against a fixture that holds no real value
# ------------------------------------------------------------------------------------------------


def test_parser_accepts_the_inline_fixture() -> None:
    """The grammar round-trips a block whose values resemble nothing real."""
    assert parse_block(find_caps_block(FIXTURE_BLOCK)) == FIXTURE_EXPECTED, (
        "the parser did not reproduce the inline fixture; the grammar and the fixture have "
        "diverged, and until they agree nothing this file says about the protocol is trustworthy"
    )


def test_parser_names_a_missing_anchor() -> None:
    """A document without the anchor raises the anchor error, not a generic one."""
    with pytest.raises(AnchorNotFound):
        find_caps_block("# A protocol with no anchor in it\n")


def test_parser_names_a_missing_fence() -> None:
    """An anchor with no fenced block after it raises the block error, not the anchor error."""
    with pytest.raises(BlockNotFound):
        find_caps_block(f"{PROTOCOL_ANCHOR}\n\nSome prose, and no fence at all.\n")


def test_parser_names_an_unterminated_fence() -> None:
    """An opened fence that never closes raises rather than returning the rest of the document."""
    with pytest.raises(BlockNotFound):
        find_caps_block(f"{PROTOCOL_ANCHOR}\n\n{FENCE_OPEN}\nstructural_block_tokens_max: 941\n")


def test_parser_rejects_a_line_outside_the_grammar() -> None:
    """A line the grammar does not cover raises instead of being skipped.

    This is the assertion that makes every value comparison below mean something. A parser that
    skipped what it did not recognise would read an indented, restructured or mistyped block as a
    *shorter* mapping, and a shorter mapping compares equal on the keys it did manage to read.
    """
    with pytest.raises(BlockSyntaxError):
        # 941 rather than a real cap, for the reason the module docstring gives about the two homes
        # section 3's values are allowed.
        parse_block("structural_block_tokens_max: 941\n  nested: not-in-this-block\n")


def test_parser_rejects_a_repeated_key() -> None:
    """A key written twice raises rather than quietly keeping the last one.

    A silently-deduplicated block is the one shape in which the protocol could say two different
    things about one cap and this test would report agreement with whichever came last.
    """
    with pytest.raises(BlockSyntaxError):
        parse_block("structural_block_tokens_max: 941\nstructural_block_tokens_max: 947\n")


def test_renderer_round_trips_through_the_parser() -> None:
    """The text the renderer prints is exactly the text this parser accepts.

    Without this, "paste what the module printed" and "what the mirror check reads" are two claims
    about one string that nothing holds together.
    """
    rendered = render_protocol_block()
    assert parse_block(find_caps_block(rendered)) == as_protocol_mapping(), (
        "render_protocol_block() emitted a block this parser reads back as something other than "
        "as_protocol_mapping(); the calibration commit's paste and this test's read would disagree"
    )


# ------------------------------------------------------------------------------------------------
# The mirror, against the block the protocol actually carries
# ------------------------------------------------------------------------------------------------


def test_the_anchor_and_the_relative_path_resolve() -> None:
    """PROTOCOL_RELATIVE_PATH points at a real file and PROTOCOL_ANCHOR appears in it exactly once.

    Both constants are strings in a module that never opens the document, so nothing else in the
    repository would notice either of them going stale: a renamed protocol file or a retitled anchor
    would leave ``limits.py`` naming a location that no longer exists, and every error message the
    gate prints would point a reader at it. The occurrence count matters as much as the presence --
    a second copy of the anchor would make "the block" ambiguous, and :func:`_locate` would silently
    read the first one.
    """
    assert PROTOCOL_PATH.is_file(), (
        f"agents/registry/limits.py names {PROTOCOL_RELATIVE_PATH!r} as the owning protocol, and "
        f"there is no file at {PROTOCOL_PATH}"
    )
    occurrences = [
        line for line in protocol_markdown().splitlines() if line.strip() == PROTOCOL_ANCHOR
    ]
    assert len(occurrences) == 1, (
        f"{PROTOCOL_ANCHOR} appears {len(occurrences)} time(s) in {PROTOCOL_RELATIVE_PATH}; the "
        "anchor exists so that exactly one block is addressable by it"
    )


def test_protocol_block_matches_the_mirror() -> None:
    """Section 3 and agents/registry/limits.py carry the same keys with the same values and types.

    The key set is compared for **exact** equality rather than containment, which is the whole of
    ADR-019's argument: containment would pass a protocol block from which a key had been deleted,
    and a deleted cap is precisely the change that leaves the gate bounding nothing.

    Types are compared as well as values because ``2 == 2.0`` in Python and ``0 == False``. A
    tolerance that became a float, or a cap that became a boolean, is a real divergence between the
    two documents that an ``==`` alone would call agreement.
    """
    from_protocol = protocol_mapping()
    from_module = as_protocol_mapping()

    assert set(from_protocol) == set(PROTOCOL_KEYS), (
        "the section 3 block's key set differs from PROTOCOL_KEYS: "
        f"unexpected {sorted(set(from_protocol) - set(PROTOCOL_KEYS))}, "
        f"missing {sorted(set(PROTOCOL_KEYS) - set(from_protocol))}"
    )
    assert set(from_module) == set(PROTOCOL_KEYS), (
        "as_protocol_mapping()'s key set differs from PROTOCOL_KEYS: "
        f"unexpected {sorted(set(from_module) - set(PROTOCOL_KEYS))}, "
        f"missing {sorted(set(PROTOCOL_KEYS) - set(from_module))}"
    )

    for key in PROTOCOL_KEYS:
        assert from_protocol[key] == from_module[key], (
            f"{key} differs: {PROTOCOL_RELATIVE_PATH} section 3 says {from_protocol[key]!r}, "
            "agents/registry/limits.py says "
            f"{from_module[key]!r}. The protocol is the authority; fix the module, not the "
            "protocol, unless the protocol edit is the change under review."
        )
        assert type(from_protocol[key]) is type(from_module[key]), (
            f"{key} agrees in value but not in type: section 3 parses to "
            f"{type(from_protocol[key]).__name__}, the mirror holds "
            f"{type(from_module[key]).__name__}"
        )


def test_the_key_order_is_the_same_on_both_sides() -> None:
    """The block's key order matches PROTOCOL_KEYS, so the calibration commit's diff stays readable.

    Not required for correctness -- the equality test above compares mappings -- but a reordered
    block would make the one commit that fills the measured value unreadable in review, which for a
    number frozen at ``v1.0`` is the moment review matters most.
    """
    assert tuple(protocol_mapping()) == PROTOCOL_KEYS, (
        f"section 3 lists {tuple(protocol_mapping())}, PROTOCOL_KEYS lists {PROTOCOL_KEYS}"
    )


def test_the_rendered_block_is_the_block_in_the_document() -> None:
    """``render_protocol_block()`` reproduces section 3's block byte for byte, after LF folding.

    Stronger than the round trip above, and it is the assertion that makes the calibration procedure
    honest. ``python -m agents.registry.limits`` exists so that a reviewer can paste four lines into
    the protocol without retyping them; if what it prints and what the document holds could differ
    in a blank line, a fence or a space after a colon, "paste this" would be advice rather than a
    procedure. Line endings are folded because ``.gitattributes`` normalises tracked text to LF in
    the index and the Windows development host checks it out with CRLF -- the same reason
    :func:`agents.registry.loader._normalise_body` folds prompt bodies.
    """
    assert extract_block_text(protocol_markdown()) == render_protocol_block(), (
        "the anchored block in "
        f"{PROTOCOL_RELATIVE_PATH} is not byte-for-byte what render_protocol_block() emits. Run "
        "`python -m agents.registry.limits` and paste its output over the block, or fix the mirror "
        "if the protocol is the side that changed."
    )


def test_measured_and_chosen_keys_partition_the_contract() -> None:
    """MEASURED_KEYS and CHOSEN_KEYS together are PROTOCOL_KEYS, exactly and without overlap.

    The split is what decides which caps may legally hold the pending sentinel, so a key in neither
    tuple would be a cap nobody classified: :func:`~agents.registry.limits.pending_keys` iterates
    MEASURED_KEYS, so an unclassified measured cap could sit at the sentinel and never be reported
    as uncalibrated. A key in both would be worse -- a *choice* the calibration procedure is
    entitled to overwrite.
    """
    measured, chosen = set(MEASURED_KEYS), set(CHOSEN_KEYS)
    assert len(measured) == len(MEASURED_KEYS), f"MEASURED_KEYS repeats a key: {MEASURED_KEYS}"
    assert len(chosen) == len(CHOSEN_KEYS), f"CHOSEN_KEYS repeats a key: {CHOSEN_KEYS}"
    assert not measured & chosen, (
        f"{sorted(measured & chosen)} is both measured and chosen; a cap is derived from the "
        "compositions or it is decided, and the two have opposite remedies when they are wrong"
    )
    assert measured | chosen == set(PROTOCOL_KEYS), (
        "MEASURED_KEYS and CHOSEN_KEYS do not partition PROTOCOL_KEYS: "
        f"unclassified {sorted(set(PROTOCOL_KEYS) - (measured | chosen))}, "
        f"not in the contract {sorted((measured | chosen) - set(PROTOCOL_KEYS))}"
    )


@pytest.mark.parametrize("key", MEASURED_KEYS)
def test_a_measured_cap_is_the_sentinel_or_a_positive_whole_number(key: str) -> None:
    """A measured cap is either still pending, or a number that could have been derived.

    This is the guard on the calibration commit. ``structural_block_tokens_max`` is read off the
    first honest compositions in the pinned reference tokenizer's unit and is then frozen, and the
    failure this catches is a value that is neither honest-pending nor usable -- a zero left behind
    by a half-finished edit, a string that was meant to be a number, a negative cap.

    Zero is rejected rather than admitted. A zero cap would reject every structural block that
    exists, so the gate would be red for a reason that has nothing to do with the registry; in
    practice a zero here is an unfilled placeholder wearing a number's clothes.
    """
    value = as_protocol_mapping()[key]
    if is_pending(value):
        pytest.skip(f"{key} is uncalibrated; nothing to validate until honest compositions exist")
    assert isinstance(value, int) and not isinstance(value, bool), (
        f"{key} is {value!r}; a token cap counts whole reference tokens, so it is an int or it is "
        f"the {PENDING_COMPOSITION_STUDY} sentinel"
    )
    assert value > 0, f"{key} is {value!r}; a derived cap must be positive"


@pytest.mark.parametrize("key", CHOSEN_KEYS)
def test_a_chosen_tolerance_is_filled_and_not_negative(key: str) -> None:
    """A tolerance is a decision, so it may never be pending, and it may never be negative.

    A pending tolerance would leave :func:`agents.registry.parity.check_parity` unable to compare
    anything at all -- it catches :class:`~agents.registry.limits.UncalibratedCap` around all three
    and reports that parity was not established -- so the gate would be permanently red with no
    calibration run able to fix it, because nothing measures a choice. A negative tolerance would be
    worse and quieter: every condition would deviate from the mean by more than it, and the gate
    would fail for arithmetic rather than for parity.
    """
    value = as_protocol_mapping()[key]
    assert not is_pending(value), (
        f"{key} carries {PENDING_COMPOSITION_STUDY}, but it is a choice rather than a measurement; "
        "nothing will ever measure it and the gate cannot run without it"
    )
    assert isinstance(value, int | float) and not isinstance(value, bool), (
        f"{key} is {value!r}, which is not a number"
    )
    assert value >= 0, f"{key} is {value!r}; a tolerance below zero admits nothing at all"


def test_pending_keys_names_exactly_the_uncalibrated_measured_keys() -> None:
    """``pending_keys`` agrees with the mirror, in MEASURED_KEYS order."""
    mapping = as_protocol_mapping()
    expected = tuple(key for key in MEASURED_KEYS if is_pending(mapping[key]))
    assert pending_keys() == expected, (
        f"pending_keys() reported {pending_keys()}, the mirror's own measured values imply "
        f"{expected}"
    )


# ------------------------------------------------------------------------------------------------
# The fail-closed reader: M2's refinement to ADR-016's pattern, proved to hold here too
# ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("key", PROTOCOL_KEYS)
def test_resolve_refuses_a_pending_cap_and_names_it(key: str) -> None:
    """A cap sitting at the sentinel raises :class:`UncalibratedCap`, naming the key.

    Driven through ``resolve``'s ``mapping`` parameter rather than by editing the module or skipping
    when the shipped value happens to be filled, and that choice is the point of the test. M2's test
    skips this assertion for every key it has already calibrated, which means the refusal it exists
    to prove goes unexercised the moment the milestone that needed it completes. Supplying the
    mapping keeps the refusal checked for every key, forever, including after the ``v1.0`` freeze.
    """
    mapping = {**as_protocol_mapping(), key: PENDING_COMPOSITION_STUDY}
    with pytest.raises(UncalibratedCap) as refusal:
        resolve(key, mapping)
    assert refusal.value.key == key, (
        f"the refusal carries key {refusal.value.key!r} rather than {key!r}; a caller that reports "
        "the missing value by attribute would name the wrong one"
    )
    assert key in str(refusal.value), "the message does not name the key it refused"
    assert PENDING_COMPOSITION_STUDY in str(refusal.value), (
        "the message does not name the sentinel, so a reader cannot grep the protocol for what to "
        "fill in"
    )


@pytest.mark.parametrize("key", PROTOCOL_KEYS)
def test_resolve_returns_the_number_for_a_calibrated_cap(key: str) -> None:
    """A cap that is set resolves to the number the mirror holds, and to nothing else.

    The other half of the fail-closed contract, and it needs stating: a reader that refused a
    *pending* cap correctly but returned something adjusted, rounded or defaulted for a set one
    would put a number in the gate that neither document contains.
    """
    value = as_protocol_mapping()[key]
    if is_pending(value):
        pytest.skip(f"{key} is uncalibrated; the refusal is asserted above")
    assert resolve(key) == value, (
        f"resolve({key!r}) returned {resolve(key)!r}, while the mirror holds {value!r}"
    )
    assert type(resolve(key)) is type(value), (
        f"resolve({key!r}) changed the type from {type(value).__name__} to "
        f"{type(resolve(key)).__name__}"
    )


def test_resolve_distinguishes_an_unknown_key_from_an_uncalibrated_one() -> None:
    """A typo raises KeyError; a pending measurement raises UncalibratedCap. Never the same error.

    Conflating them would leave a caller unable to tell a misspelling from an unfinished
    calibration, and the remedies are opposite: one is fixed in the caller, the other in section 3.
    """
    with pytest.raises(KeyError):
        resolve("structural_block_tokens_maximum")
    assert not issubclass(UncalibratedCap, KeyError), (
        "UncalibratedCap has become a KeyError subclass, so the two refusals are no longer "
        "distinguishable: an `except KeyError` written to catch a typo would swallow an "
        "uncalibrated cap and the caller would carry on with no bound"
    )


def test_there_is_no_default_and_an_absent_key_is_an_error() -> None:
    """A key the mapping does not carry raises. It never falls back to a number.

    This is the refinement M2 added to ADR-016's pattern, and it has to be proved *here* rather than
    inherited: ``agents/registry/limits.py`` is a third, independently written mirror, and the
    property is one line of code away from being lost. A ``default`` parameter would reintroduce the
    fallback at the call site -- the one place a reviewer is least likely to look, because
    ``resolve("structural_block_tokens_max", default=40)`` reads as ordinary defensive code -- and
    :mod:`agents.registry.parity` would then bound structural blocks with a number nobody chose,
    print a table, and go green. That is exactly the failure the module refuses to publish a
    fallback for, one layer in.
    """
    parameters = inspect.signature(resolve).parameters
    assert "default" not in parameters, (
        "resolve() has grown a `default` parameter. The parity gate has no default for any cap: a "
        "default would let it run, and go green, against a bound nobody set"
    )

    with pytest.raises(KeyError):
        resolve(PROTOCOL_KEYS[0], {})

    partial = {
        key: value for key, value in as_protocol_mapping().items() if key != PROTOCOL_KEYS[0]
    }
    with pytest.raises(KeyError):
        resolve(PROTOCOL_KEYS[0], partial)


def test_resolve_refuses_a_value_that_is_neither_a_number_nor_the_sentinel() -> None:
    """A cap that is prose, or a boolean, raises TypeError rather than being used as a bound.

    ``True`` is the case worth naming: it is an ``int`` in Python, it compares equal to 1, and a
    structural cap of 1 would reject every block in the registry while the gate reported a perfectly
    ordinary cap violation. Refusing it by type is the only place that can be caught.
    """
    with pytest.raises(TypeError):
        resolve(PROTOCOL_KEYS[0], {**as_protocol_mapping(), PROTOCOL_KEYS[0]: "thirty-nine"})
    with pytest.raises(TypeError):
        resolve(PROTOCOL_KEYS[0], {**as_protocol_mapping(), PROTOCOL_KEYS[0]: True})
