r"""The mirror check: scripts/m10_constants.py must agree with evaluation-protocol.md section 4.

WHAT THIS TEST IS FOR
    `.agents/rules/00-source-of-truth.md` allows a literal to appear twice only where no second
    *decision* exists. :mod:`scripts.m10_constants` is a copy of the four human-scoring constants
    `docs/protocols/evaluation-protocol.md` section 4 owns, and this test is the entire
    justification
    for that copy being legal -- the same role
    `analysis/tests/test_gate_constants_match_protocol.py`
    plays for the GATE block and `infra/tests/test_constants_match_protocol.py` for the M1
    instrument
    constants (ADR-016). It parses the anchored `<!-- m10-fidelity-constants -->` block out of the
    protocol and asserts the two sides agree key for key, so a value changed in one place and not
    the
    other fails CI instead of silently diverging into two sources of truth.

    If this test fails with a mismatch, the protocol is right and the module is wrong. That
    direction
    is not negotiable and is not a matter of which was edited last.

HOW THE BLOCK IS FOUND, AND WHY THERE IS A PARSER HERE RATHER THAN A YAML DEPENDENCY
    By the HTML anchor on its own line, immediately followed by a fenced ``yaml`` block -- an anchor
    rather than a heading search, because headings are prose and get retitled. The M10 block is flat
    (scalars plus comment lines), so the grammar is the smallest one that can reject an unrecognised
    line: blank lines and ``#`` comments are skipped and every other line must be a bare
    ``key: value`` pair. CI installs ``pytest==8.4.2`` and nothing else for this job, so the few
    lines
    of :mod:`re` are reimplemented rather than adding a YAML dependency for one assertion. The same
    grammar, in a different suite, appears in `analysis/tests/test_gate_constants_match_protocol.py`
    and in `runner/tests/test_pilot_constants_match_protocol.py`; the duplication is deliberate for
    the reason those files give -- three suites in three CI jobs, each with only pytest available.

WHY THE FIXTURE VALUES ARE OBVIOUSLY FAKE
    The parser is exercised against a fixture defined inline below, and that fixture deliberately
    holds values that resemble nothing real, so that grepping the repository for each real constant
    still finds exactly two occurrences (the protocol block and the mirror) and a fixture holding
    the
    real numbers would not become a third. The fixture tests the grammar; the protocol test tests
    the
    values.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import m10_constants  # noqa: E402

PROTOCOL_PATH = REPO_ROOT / m10_constants.PROTOCOL_RELATIVE_PATH

FENCE_OPEN = "```yaml"
FENCE_CLOSE = "```"

_SCALAR = re.compile(r"^([a-z_][a-z0-9_]*):\s*(.+)$")

# A fixture whose values resemble nothing real, for the reason the module docstring gives.
FIXTURE_BLOCK = """<!-- m10-fidelity-constants -->

```yaml
# A comment line, which the grammar must skip exactly as the real block's are.
scoring_min_elapsed_seconds: 4242
scoring_sample_tuple_count: 7
scoring_sample_min_per_scenario: 5
scoring_rescore_tuple_count: 2
```
"""

FIXTURE_EXPECTED: dict[str, object] = {
    "scoring_min_elapsed_seconds": 4242,
    "scoring_sample_tuple_count": 7,
    "scoring_sample_min_per_scenario": 5,
    "scoring_rescore_tuple_count": 2,
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
        (
            index
            for index, line in enumerate(lines)
            if line.strip() == m10_constants.PROTOCOL_ANCHOR
        ),
        None,
    )
    if anchor_at is None:
        raise AnchorNotFound(m10_constants.PROTOCOL_ANCHOR)

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
    """Return the parsed section 4 M10 block, failing with remediation when it is absent."""
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
            f"MISSING ANCHOR: {m10_constants.PROTOCOL_ANCHOR} does not appear in "
            f"{m10_constants.PROTOCOL_RELATIVE_PATH}. Section 4 must carry the anchor comment on a "
            "line of its own, followed by a fenced yaml block. Run "
            "`python -m scripts.m10_constants` to print the exact text to paste."
        )
    except BlockNotFound as missing:
        problem = (
            f"MISSING BLOCK: {m10_constants.PROTOCOL_ANCHOR} was found in "
            f"{m10_constants.PROTOCOL_RELATIVE_PATH}, but the expected {missing.args[0]!r} fence "
            "was not. Run `python -m scripts.m10_constants` to print the exact text to paste."
        )
    except BlockSyntaxError as broken:
        problem = (
            f"MALFORMED BLOCK in {m10_constants.PROTOCOL_RELATIVE_PATH}: {broken}. The block "
            "grammar is a flat key: value mapping; see parse_block in this file."
        )

    if problem is not None:
        pytest.fail(problem)
    if parsed is None:  # pragma: no cover - unreachable: `problem` is set whenever parsed is None
        pytest.fail("the protocol block parsed to nothing without a reported problem")
    return parsed


# ------------------------------------------------------------------------------------------------
# The grammar, exercised on a fixture whose values resemble nothing real.
# ------------------------------------------------------------------------------------------------


def _require(condition: bool, message: str) -> None:
    # Bare assert is avoided throughout scripts/tests/ so that this suite needs no S101
    # per-file-ignore entry in pyproject.toml, which this agent does not own; see
    # scripts/tests/__init__.py and the note at the top of test_scoring_ui.py. The pyproject rule
    # is that a per-file-ignore is added one named directory at a time, deliberately, not widened
    # to cover a new directory as a side effect of adding a test to it.
    if not condition:
        raise AssertionError(message)


def test_parser_accepts_the_inline_fixture() -> None:
    """The grammar round-trips a block whose values resemble nothing real."""
    _require(
        parse_block(find_constants_block(FIXTURE_BLOCK)) == FIXTURE_EXPECTED,
        "the fixture block did not parse to the expected mapping",
    )


def test_parser_names_a_missing_anchor() -> None:
    with pytest.raises(AnchorNotFound):
        find_constants_block("# A protocol with no anchor in it\n")


def test_parser_names_a_missing_fence() -> None:
    with pytest.raises(BlockNotFound):
        find_constants_block(f"{m10_constants.PROTOCOL_ANCHOR}\n\nSome prose, and no fence.\n")


def test_parser_rejects_a_line_outside_the_grammar() -> None:
    with pytest.raises(BlockSyntaxError):
        parse_block("scoring_min_elapsed_seconds: 60\n  - not: a-flat-scalar\n")


def test_renderer_round_trips_through_the_parser() -> None:
    """The text the renderer prints is exactly the text this parser accepts."""
    rendered = m10_constants.render_protocol_block()
    _require(
        parse_block(find_constants_block(rendered)) == m10_constants.as_protocol_mapping(),
        "the rendered block did not round-trip through the parser",
    )


# ------------------------------------------------------------------------------------------------
# The values.
# ------------------------------------------------------------------------------------------------


def test_protocol_block_matches_the_mirror() -> None:
    """Section 4's M10 block and scripts/m10_constants.py carry the same four scoring values."""
    from_protocol = protocol_mapping()
    from_module = m10_constants.as_protocol_mapping()

    _require(
        set(from_module) == set(m10_constants.MIRRORED_KEYS),
        f"the mirror's key set differs from MIRRORED_KEYS: {sorted(from_module)}",
    )
    for key in m10_constants.MIRRORED_KEYS:
        _require(
            key in from_protocol,
            f"scripts.m10_constants mirrors {key!r}, but the section-4 M10 block does not "
            "define it",
        )
        _require(
            from_protocol[key] == from_module[key],
            f"{key} differs: evaluation-protocol.md §4 says {from_protocol[key]!r}, "
            f"scripts/m10_constants.py says {from_module[key]!r}. The protocol is the "
            "authority; fix the module, not the protocol, unless the protocol edit is the "
            "change under review.",
        )


def test_the_whole_tuple_rescore_count_does_not_exceed_the_first_pass_sample() -> None:
    """A re-score draws tuples out of the first-pass sample, so it cannot exceed it.

    The arithmetic is the protocol's own: the M10 block states the re-score count is the GATE
    block's
    re-score fraction of the first-pass tuple count, rounded up. This test does not restate the
    fraction (it is mirrored in `analysis.stats.gate`, where `analysis`'s mirror test owns it); it
    asserts only the inequality that makes the draw implementable at all, and would catch a
    transcription that inverted one of the two numbers.
    """
    _require(
        m10_constants.SCORING_RESCORE_TUPLE_COUNT <= m10_constants.SCORING_SAMPLE_TUPLE_COUNT,
        "the re-score tuple count exceeds the first-pass sample it is drawn from",
    )


def test_the_minimum_elapsed_time_is_a_positive_number_of_seconds() -> None:
    """A zero or negative floor would make the open-to-submit control vacuous."""
    _require(
        m10_constants.SCORING_MIN_ELAPSED_SECONDS > 0,
        "scoring_min_elapsed_seconds must be positive for the open-to-submit control to bind",
    )


def test_the_per_scenario_minimum_does_not_exceed_the_tuple_count() -> None:
    """A per-scenario floor above the total would make the sampler's own arithmetic
    unsatisfiable."""
    _require(
        m10_constants.SCORING_SAMPLE_MIN_PER_SCENARIO <= m10_constants.SCORING_SAMPLE_TUPLE_COUNT,
        "the per-scenario minimum exceeds the total tuple count, so no draw can satisfy both",
    )
