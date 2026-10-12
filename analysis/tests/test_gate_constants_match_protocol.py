r"""The mirror check: analysis/stats/gate.py must agree with evaluation-protocol.md section 4.

WHAT THIS TEST IS FOR
    `.agents/rules/00-source-of-truth.md` allows a literal to appear twice only where no second
    *decision* exists. :mod:`analysis.stats.gate` is a copy of the six GATE constants
    `docs/protocols/evaluation-protocol.md` section 4 owns, and this test is the entire
    justification for that copy being legal -- the same role
    `infra/tests/test_constants_match_protocol.py` plays for the M1 instrument constants (ADR-016).
    It parses the anchored `<!-- gate-constants -->` block out of the protocol and asserts the two
    sides agree key for key, so a value changed in one place and not the other fails CI instead of
    silently diverging into two sources of truth.

    If this test fails with a mismatch, the protocol is right and the module is wrong. That
    direction is not negotiable and is not a matter of which was edited last.

HOW THE BLOCK IS FOUND, AND WHY THERE IS A PARSER HERE RATHER THAN A YAML DEPENDENCY
    By the HTML anchor comment :data:`~analysis.stats.gate.PROTOCOL_ANCHOR`, on its own line,
    immediately followed by a fenced ``yaml`` block -- an anchor rather than a heading search,
    because headings are prose and get retitled. The GATE block is flatter than the M1 block (six
    scalars, no list), so the grammar here is smaller still: blank lines and ``#`` comments are
    skipped, and every other line must be a bare ``key: value`` pair. CI installs
    ``pytest==8.4.2`` and nothing else, so this reimplements the few lines of :mod:`re` needed
    rather than adding a YAML dependency for one assertion.

WHY THE FIXTURE VALUES ARE OBVIOUSLY FAKE
    The parser is exercised against a fixture defined inline below, and that fixture deliberately
    holds values that resemble nothing real. A verification pass greps the repository for each real
    GATE constant and expects exactly two occurrences (the protocol block and this module's mirror);
    a fixture containing the real numbers would be a third occurrence and would fail that check for
    no reason. The fixture tests the grammar; the protocol test tests the values.
"""

import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from analysis.stats import m10  # noqa: E402
from analysis.stats.gate import (  # noqa: E402
    PROTOCOL_ANCHOR,
    PROTOCOL_KEYS,
    PROTOCOL_RELATIVE_PATH,
    as_protocol_mapping,
    render_protocol_block,
)

PROTOCOL_PATH = REPO_ROOT / PROTOCOL_RELATIVE_PATH

FENCE_OPEN = "```yaml"
FENCE_CLOSE = "```"

_SCALAR = re.compile(r"^([a-z_][a-z0-9_]*):\s*(.+)$")

# A fixture whose values resemble nothing real, for the reason the module docstring gives.
FIXTURE_BLOCK = """<!-- gate-constants -->

```yaml
inconclusiveness_floor: 0.42
blind_rescore_sample_fraction: 0.37
blind_rescore_delay_days: 999
mdd_alpha_two_sided: 0.13
mdd_target_power: 0.61
mdd_worst_case_paired_diff_sd: 7.0
```
"""

FIXTURE_EXPECTED: dict[str, object] = {
    "inconclusiveness_floor": 0.42,
    "blind_rescore_sample_fraction": 0.37,
    "blind_rescore_delay_days": 999,
    "mdd_alpha_two_sided": 0.13,
    "mdd_target_power": 0.61,
    "mdd_worst_case_paired_diff_sd": 7.0,
}


class AnchorNotFound(LookupError):
    """Raised when the anchor comment is absent from the protocol text."""


class BlockNotFound(LookupError):
    """Raised when the anchor is present but is not followed by a fenced yaml block."""


class BlockSyntaxError(ValueError):
    """Raised when a line inside the block is outside the grammar this parser accepts."""


def find_constants_block(markdown: str) -> str:
    """Return the text inside the fenced yaml block that follows the anchor comment.

    Blank lines between the anchor and the fence are tolerated; anything else is not, because it
    would mean the anchor and the block are no longer adjacent and this function would be reading a
    block it was not pointed at.
    """
    lines = markdown.splitlines()
    anchor_at = next(
        (index for index, line in enumerate(lines) if line.strip() == PROTOCOL_ANCHOR), None
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
    """Return ``text`` as an int, else as a float, else as the stripped string itself."""
    stripped = text.strip()
    try:
        return int(stripped)
    except ValueError:
        pass
    try:
        return float(stripped)
    except ValueError:
        return stripped


def parse_block(block_text: str) -> dict[str, object]:
    """Parse the block's flat ``key: value`` mapping. Anything else raises.

    A parser that shrugged at an unrecognised line could silently miss the very key it exists to
    compare, so every non-blank, non-comment line must match the bare scalar grammar.
    """
    mapping: dict[str, object] = {}
    for number, raw in enumerate(block_text.splitlines(), start=1):
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = _SCALAR.match(line)
        if match is None:
            raise BlockSyntaxError(f"line {number}: not in the block grammar: {raw!r}")
        mapping[match.group(1)] = _coerce(match.group(2))
    return mapping


def protocol_mapping() -> dict[str, object]:
    """Return the parsed section 4 GATE block, failing with remediation when it is absent."""
    __tracebackhide__ = True
    if not PROTOCOL_PATH.is_file():
        pytest.fail(f"protocol file not found at {PROTOCOL_PATH}")

    markdown = PROTOCOL_PATH.read_text(encoding="utf-8")
    parsed: dict[str, object] | None = None
    problem: str | None = None
    try:
        parsed = parse_block(find_constants_block(markdown))
    except AnchorNotFound:
        problem = (
            f"MISSING ANCHOR: {PROTOCOL_ANCHOR} does not appear in {PROTOCOL_RELATIVE_PATH}. "
            "Section 4 must carry the anchor comment on a line of its own, followed by a fenced "
            "yaml block holding the six GATE constants. Run `python -m analysis.stats.gate` to "
            "print the exact text to paste."
        )
    except BlockNotFound as missing:
        problem = (
            f"MISSING BLOCK: {PROTOCOL_ANCHOR} was found in {PROTOCOL_RELATIVE_PATH}, but the "
            f"expected {missing.args[0]!r} fence was not. Run `python -m analysis.stats.gate` to "
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


def test_parser_accepts_the_inline_fixture() -> None:
    """The grammar round-trips a block whose values resemble nothing real."""
    assert parse_block(find_constants_block(FIXTURE_BLOCK)) == FIXTURE_EXPECTED


def test_parser_names_a_missing_anchor() -> None:
    with pytest.raises(AnchorNotFound):
        find_constants_block("# A protocol with no anchor in it\n")


def test_parser_names_a_missing_fence() -> None:
    with pytest.raises(BlockNotFound):
        find_constants_block(f"{PROTOCOL_ANCHOR}\n\nSome prose, and no fence at all.\n")


def test_parser_rejects_a_line_outside_the_grammar() -> None:
    with pytest.raises(BlockSyntaxError):
        parse_block("inconclusiveness_floor: 0.42\n  - not: a-flat-scalar\n")


def test_renderer_round_trips_through_the_parser() -> None:
    """The text the renderer prints is exactly the text this parser accepts."""
    rendered = render_protocol_block()
    assert parse_block(find_constants_block(rendered)) == as_protocol_mapping()


def test_protocol_block_matches_the_mirror() -> None:
    """Section 4's gate-constants block and analysis/stats/gate.py carry the same six values."""
    from_protocol = protocol_mapping()
    from_module = as_protocol_mapping()

    assert set(from_protocol) == set(PROTOCOL_KEYS), (
        "the section 4 gate-constants block's key set differs from PROTOCOL_KEYS: "
        f"unexpected {sorted(set(from_protocol) - set(PROTOCOL_KEYS))}, "
        f"missing {sorted(set(PROTOCOL_KEYS) - set(from_protocol))}"
    )
    assert set(from_module) == set(PROTOCOL_KEYS)

    for key in PROTOCOL_KEYS:
        assert from_protocol[key] == from_module[key], (
            f"{key} differs: evaluation-protocol.md §4 says {from_protocol[key]!r}, "
            f"analysis/stats/gate.py says {from_module[key]!r}. The protocol is the authority; fix "
            "the module, not the protocol, unless the protocol edit is the change under review."
        )


@pytest.mark.parametrize(
    ("key", "low", "high"),
    [
        ("inconclusiveness_floor", 0.0, 1.0),
        ("blind_rescore_sample_fraction", 0.0, 1.0),
        ("mdd_alpha_two_sided", 0.0, 1.0),
        ("mdd_target_power", 0.0, 1.0),
    ],
)
def test_proportion_valued_constants_are_fractions(key: str, low: float, high: float) -> None:
    """Floor, sample fraction, alpha and power are all proportions: strictly between 0 and 1."""
    value = as_protocol_mapping()[key]
    assert low < value < high, f"{key} is {value!r}, which is not a proportion in ({low}, {high})"


def test_delay_and_sd_are_positive() -> None:
    mapping = as_protocol_mapping()
    assert mapping["blind_rescore_delay_days"] > 0
    assert mapping["mdd_worst_case_paired_diff_sd"] > 0


# ================================================================================================
# THE M10 SUBSET -- analysis.stats.m10 mirrors only the M10 constant(s) analysis/ consumes
# ================================================================================================
#
# analysis.stats.m10 mirrors a strict SUBSET of section 4's <!-- m10-fidelity-constants --> block
# (the runner homes the full mirror in runner/fidelity/; see that module's docstring). The check is
# therefore per-mirrored-key, not "the two key sets are equal": the block legitimately owns keys
# this
# module does not mirror, so this reuses the same block grammar but asserts only the keys m10
# claims.


def _find_block_by_anchor(markdown: str, anchor: str) -> str:
    """Return the fenced yaml block following ``anchor`` -- the same walk find_constants_block does,
    parametrised on the anchor so both the GATE and the M10 block can be located by the one
    grammar."""
    lines = markdown.splitlines()
    anchor_at = next((index for index, line in enumerate(lines) if line.strip() == anchor), None)
    if anchor_at is None:
        raise AnchorNotFound(anchor)
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


def _m10_protocol_mapping() -> dict[str, object]:
    """Parse the section-4 M10 block, failing with remediation when it is absent or malformed."""
    __tracebackhide__ = True
    if not PROTOCOL_PATH.is_file():
        pytest.fail(f"protocol file not found at {PROTOCOL_PATH}")
    markdown = PROTOCOL_PATH.read_text(encoding="utf-8")
    try:
        return parse_block(_find_block_by_anchor(markdown, m10.PROTOCOL_ANCHOR))
    except AnchorNotFound:
        pytest.fail(
            f"MISSING ANCHOR: {m10.PROTOCOL_ANCHOR} does not appear in "
            f"{m10.PROTOCOL_RELATIVE_PATH}. "
            "Section 4 must carry the M10 fidelity-constants block on a line of its own, "
            "followed by "
            "a fenced yaml block."
        )
    except BlockNotFound as missing:
        pytest.fail(
            f"MISSING BLOCK: {m10.PROTOCOL_ANCHOR} was found but the expected {missing.args[0]!r} "
            f"fence was not, in {m10.PROTOCOL_RELATIVE_PATH}."
        )
    except BlockSyntaxError as broken:
        pytest.fail(f"MALFORMED M10 BLOCK in {m10.PROTOCOL_RELATIVE_PATH}: {broken}.")


def test_m10_mirror_points_at_the_same_protocol_file() -> None:
    """analysis.stats.m10 and analysis.stats.gate mirror blocks in the one protocol file."""
    assert m10.PROTOCOL_RELATIVE_PATH == PROTOCOL_RELATIVE_PATH


def test_m10_mirrored_keys_match_the_protocol_block() -> None:
    """Every key analysis.stats.m10 mirrors carries the value the M10 block owns.

    A subset check, not an equality of key sets: the block owns runner-side keys this module does
    not
    mirror (see analysis.stats.m10's docstring), so those are not this module's to restate. The
    protocol is the authority; if this fails, fix the module, not the protocol, unless the protocol
    edit is the change under review.
    """
    from_protocol = _m10_protocol_mapping()
    from_module = m10.as_protocol_mapping()
    assert set(from_module) == set(m10.MIRRORED_KEYS)
    for key in m10.MIRRORED_KEYS:
        assert key in from_protocol, (
            f"analysis.stats.m10 mirrors {key!r}, but the section-4 M10 block does not define it"
        )
        assert from_protocol[key] == from_module[key], (
            f"{key} differs: evaluation-protocol.md §4 says {from_protocol[key]!r}, "
            f"analysis/stats/m10.py says {from_module[key]!r}. The protocol is the authority."
        )


def test_m10_discrimination_ceiling_is_a_proportion() -> None:
    """The INJ-NONE discrimination base-rate ceiling is a proportion strictly between 0 and 1."""
    value = m10.INJECTION_DISCRIMINATION_BASE_RATE_MAX
    assert 0.0 < value < 1.0, f"{value!r} is not a proportion in (0, 1)"
