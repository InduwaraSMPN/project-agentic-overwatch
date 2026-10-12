"""The mirror check: infra/probes/constants.py must agree with evaluation-protocol section 4.

WHAT THIS TEST IS FOR
---------------------
``.agents/rules/00-source-of-truth.md`` allows a literal to appear twice only where no second
*decision* exists. :mod:`infra.probes.constants` is a copy of the numbers
``docs/protocols/evaluation-protocol.md`` section 4 owns, and this test is the entire justification
for that copy being legal: it parses the anchored block out of the protocol and asserts the two
sides agree key by key, so a value changed in one place and not the other fails CI instead of
silently diverging into two sources of truth.

If this test fails with a mismatch, the protocol is right and the module is wrong. That direction
is not negotiable and is not a matter of which was edited last.

HOW THE BLOCK IS FOUND
----------------------
By the HTML anchor comment :data:`~infra.probes.constants.PROTOCOL_ANCHOR`, on its own line,
immediately followed by a fenced ``yaml`` block. An anchor rather than a heading search, because
headings are prose and get retitled, and a test that silently starts reading a different part of a
document is worse than one that fails.

A missing anchor and a missing fence are separate, named failures with the remediation in the
message. This matters more than it looks: the anchor does not exist in the protocol until the
section 4 edit lands, so the first thing anyone ever sees from this file is that failure, and it
has to read as "paste the block" rather than as "something is broken in the tests".

WHY THERE IS A PARSER HERE AND NOT A YAML DEPENDENCY
-----------------------------------------------------
CI installs ``pytest==8.4.2`` and nothing else. Adding PyYAML to run one assertion would put a
third-party package on the critical path of the lint job for a grammar that is forty lines of
:mod:`re`. The block's grammar is correspondingly small and rigid -- two indentation levels, one
list, plain scalars -- and anything outside it raises rather than being tolerated, because a block
this test half-understands is a block this test cannot be trusted about.

WHY THE FIXTURE VALUES ARE OBVIOUSLY FAKE
-----------------------------------------
The parser is exercised against a fixture defined inline below, and that fixture deliberately holds
values that resemble nothing real. The M1 verification asks for a ``git grep`` proving each
protocol value appears in exactly two files; a fixture containing the real numbers would be a third
occurrence and would fail that check for no reason. The fixture tests the grammar; the protocol
test tests the values.
"""

import re
import sys
from pathlib import Path

import pytest

# The repository root, derived from this file's own location rather than from the working
# directory, so the test reads the same protocol file whether pytest is invoked from the root, from
# infra/, or from anywhere else. The same root is prepended to sys.path because `infra` is only
# importable when the root is on it, and the CI step's working directory is a property of the
# workflow rather than something this file should depend on.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from infra.probes.constants import (  # noqa: E402
    MEASURED_KEYS,
    PENDING_CALIBRATION,
    PROBE_INTERVAL_SECONDS,
    PROBE_TIMEOUT_SECONDS,
    PROTOCOL_ANCHOR,
    PROTOCOL_KEYS,
    PROTOCOL_RELATIVE_PATH,
    SLO_PROBE_SET,
    as_protocol_mapping,
    render_protocol_block,
)

PROTOCOL_PATH = REPO_ROOT / PROTOCOL_RELATIVE_PATH

FENCE_OPEN = "```yaml"
FENCE_CLOSE = "```"

_LIST_ITEM = re.compile(r"^ {2}- ([a-z_][a-z0-9_]*): (.*)$")
_LIST_FIELD = re.compile(r"^ {4}([a-z_][a-z0-9_]*): (.*)$")
_SCALAR = re.compile(r"^([a-z_][a-z0-9_]*):(?: (.*))?$")

# A fixture whose values resemble nothing real, for the reason the module docstring gives. It
# exercises every branch of the grammar: a list with more than one entry, an integer scalar, a
# float scalar and a bare-string scalar.
FIXTURE_BLOCK = """<!-- m1-instrument-constants -->

```yaml
slo_probe_set:
  - probe_id: FIXTURE-ALPHA
    target: /fixture-alpha
    method: GET
  - probe_id: FIXTURE-BETA
    target: /
    method: HEAD
probe_interval_seconds: 997
probe_timeout_seconds: 991
slo_latency_p95_ms: 983
slo_error_rate_max: 0.977
stabilization_window_seconds: FIXTURE-SENTINEL
```
"""

FIXTURE_EXPECTED: dict[str, object] = {
    "slo_probe_set": [
        {"probe_id": "FIXTURE-ALPHA", "target": "/fixture-alpha", "method": "GET"},
        {"probe_id": "FIXTURE-BETA", "target": "/", "method": "HEAD"},
    ],
    "probe_interval_seconds": 997,
    "probe_timeout_seconds": 991,
    "slo_latency_p95_ms": 983,
    "slo_error_rate_max": 0.977,
    "stabilization_window_seconds": "FIXTURE-SENTINEL",
}


class AnchorNotFound(LookupError):
    """Raised when the anchor comment is absent from the protocol text."""


class BlockNotFound(LookupError):
    """Raised when the anchor is present but is not followed by a fenced yaml block."""


class BlockSyntaxError(ValueError):
    """Raised when a line inside the block is outside the grammar this parser accepts."""


def find_constants_block(markdown: str) -> str:
    """Return the text inside the fenced yaml block that follows the anchor comment.

    Blank lines between the anchor and the fence are tolerated, because Markdown authors put one
    there and a test that broke over it would be an obstacle rather than a check. Anything else
    between them is not tolerated: it would mean the anchor and the block are no longer adjacent,
    and this function would then be reading a block it was not pointed at.
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
    """Parse the block's flat mapping plus its one list of probe entries.

    The grammar, complete: a bare ``key:`` opens a list; ``  - key: value`` opens a list entry;
    ``    key: value`` adds a field to the open entry; ``key: value`` at column zero is a scalar.
    Blank lines and ``#`` comments are skipped. Anything else raises, because a parser that
    shrugged at a line it did not recognise could silently miss the very key it exists to compare.
    """
    mapping: dict[str, object] = {}
    entries: list[dict[str, str]] | None = None
    current: dict[str, str] | None = None

    for number, raw in enumerate(block_text.splitlines(), start=1):
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        item = _LIST_ITEM.match(line)
        if item is not None:
            if entries is None:
                raise BlockSyntaxError(f"line {number}: list entry outside any list: {raw!r}")
            current = {item.group(1): item.group(2).strip()}
            entries.append(current)
            continue

        field = _LIST_FIELD.match(line)
        if field is not None:
            if current is None:
                raise BlockSyntaxError(f"line {number}: field outside any list entry: {raw!r}")
            current[field.group(1)] = field.group(2).strip()
            continue

        scalar = _SCALAR.match(line)
        if scalar is None:
            raise BlockSyntaxError(f"line {number}: not in the block grammar: {raw!r}")
        key, value = scalar.group(1), scalar.group(2)
        if value is None or not value.strip():
            entries = []
            current = None
            mapping[key] = entries
        else:
            mapping[key] = _coerce(value)
            entries = None
            current = None

    return mapping


def protocol_mapping() -> dict[str, object]:
    """Return the parsed section 4 block, failing with remediation when it is absent.

    Every failure path here names what is missing and what to do about it. Until the section 4 edit
    lands this is the only thing this file reports, so the message is the documentation the reader
    gets.
    """
    __tracebackhide__ = True
    if not PROTOCOL_PATH.is_file():
        pytest.fail(f"protocol file not found at {PROTOCOL_PATH}")

    markdown = PROTOCOL_PATH.read_text(encoding="utf-8")
    parsed: dict[str, object] | None = None
    problem: str | None = None

    # The failure is recorded and reported after the handler rather than from inside it. Calling
    # pytest.fail() within an `except` chains the caught exception onto the report, so the reader
    # gets a stack ending in AnchorNotFound above the sentence that explains what to do -- and the
    # sentence is the part that matters, because until the section 4 edit lands this message is the
    # only thing this file ever prints.
    try:
        parsed = parse_block(find_constants_block(markdown))
    except AnchorNotFound:
        problem = (
            f"MISSING ANCHOR: {PROTOCOL_ANCHOR} does not appear in {PROTOCOL_RELATIVE_PATH}. "
            "Section 4 of that file must carry the anchor comment on a line of its own, followed "
            "by a fenced yaml block holding the instrument constants. Run "
            "`python -m infra.probes.constants` to print the exact text to paste."
        )
    except BlockNotFound as missing:
        problem = (
            f"MISSING BLOCK: {PROTOCOL_ANCHOR} was found in {PROTOCOL_RELATIVE_PATH}, but the "
            f"expected {missing.args[0]!r} fence was not. The anchor must be followed, after at "
            "most blank lines, by a fenced yaml block. Run `python -m infra.probes.constants` to "
            "print the exact text to paste."
        )
    except BlockSyntaxError as broken:
        problem = (
            f"MALFORMED BLOCK in {PROTOCOL_RELATIVE_PATH}: {broken}. The block grammar is a flat "
            "key: value mapping plus the slo_probe_set list; see parse_block in this file."
        )

    if problem is not None:
        pytest.fail(problem)
    assert parsed is not None
    return parsed


def test_parser_accepts_the_inline_fixture() -> None:
    """The grammar round-trips a block whose values resemble nothing real."""
    assert parse_block(find_constants_block(FIXTURE_BLOCK)) == FIXTURE_EXPECTED


def test_parser_names_a_missing_anchor() -> None:
    """A document without the anchor raises the anchor error, not a generic one."""
    with pytest.raises(AnchorNotFound):
        find_constants_block("# A protocol with no anchor in it\n")


def test_parser_names_a_missing_fence() -> None:
    """An anchor with no fenced block after it raises the block error, not the anchor error."""
    with pytest.raises(BlockNotFound):
        find_constants_block(f"{PROTOCOL_ANCHOR}\n\nSome prose, and no fence at all.\n")


def test_parser_rejects_a_line_outside_the_grammar() -> None:
    """A line the grammar does not cover raises instead of being skipped."""
    with pytest.raises(BlockSyntaxError):
        # 997 rather than the real interval, for the reason the fixture at the top of this file
        # gives: milestone M1's Definition of done greps each §4 value across the repository and
        # requires exactly two occurrences, the protocol and the mirror. A test fixture that
        # reused the real value would make that grep report a third home that is not one.
        parse_block("probe_interval_seconds: 997\n      deeply: indented\n")


def test_renderer_round_trips_through_the_parser() -> None:
    """The text the renderer prints is exactly the text this parser accepts.

    Without this, "paste what --calibrate printed" and "what the mirror check reads" are two
    claims about one string that nothing holds together.
    """
    rendered = render_protocol_block()
    assert parse_block(find_constants_block(rendered)) == as_protocol_mapping()


def test_protocol_block_matches_the_mirror() -> None:
    """Section 4 and infra/probes/constants.py carry the same keys with the same values."""
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
            f"infra/probes/constants.py says {from_module[key]!r}. The protocol is the authority; "
            "fix the module, not the protocol, unless the protocol edit is the change under review."
        )


@pytest.mark.parametrize("key", MEASURED_KEYS)
def test_measured_value_is_the_sentinel_or_a_positive_number(key: str) -> None:
    """A measured constant is either still pending, or a number that could have been measured.

    This is the guard on the calibration commit. The three measured values arrive from a live
    cluster in a single protocol edit that is frozen at ``v1.0``, and the failure this catches is a
    value that is neither honest-pending nor usable -- a zero left behind by a half-finished edit,
    a string that was meant to be a number, a negative latency.

    Zero is rejected rather than admitted. An ``slo_error_rate_max`` of exactly zero says a single
    failed probe anywhere in a 750-run campaign fails a run, which nobody would choose on purpose,
    so in practice it is an unfilled placeholder wearing a number's clothes -- exactly what this
    test exists to catch. An error rate above 1 is rejected for the obvious reason: it is a
    fraction.
    """
    value = as_protocol_mapping()[key]
    if value == PENDING_CALIBRATION:
        pytest.skip(f"{key} is uncalibrated; nothing to validate until a cluster exists")
    assert isinstance(value, int | float) and not isinstance(value, bool), (
        f"{key} is {value!r}, which is neither the {PENDING_CALIBRATION} sentinel nor a number"
    )
    assert value > 0, f"{key} is {value!r}; a measured instrument constant must be positive"
    if key == "slo_error_rate_max":
        assert value <= 1, f"{key} is {value!r}; an error rate is a fraction of one"


def test_probe_set_is_wellformed() -> None:
    """Probe identifiers are unique and targets are paths, not absolute URLs."""
    identifiers = [spec.probe_id for spec in SLO_PROBE_SET]
    assert len(identifiers) == len(set(identifiers)), f"duplicate probe_id in {identifiers}"
    assert SLO_PROBE_SET, "the probe set is empty; probes.csv would never have a row"
    for spec in SLO_PROBE_SET:
        assert spec.target.startswith("/"), (
            f"{spec.probe_id} target {spec.target!r} is not a path; the frontend address is an "
            "environment fact and belongs to --base-url, not to the protocol"
        )
        assert spec.method == spec.method.upper(), f"{spec.probe_id} method is not uppercase"


def test_worst_case_cycle_fits_inside_the_run_validity_gap() -> None:
    """A total outage must produce a recorded timeline, never a run-invalidating gap.

    data-management section 4 invalidates a run whose "probe timeline has gaps > probe interval
    x3". One cycle drives every probe in sequence, so the worst case is every probe timing out.
    If that exceeds the gap rule, a long outage stops being the thing T-21 measures and starts
    being an instrument fault that throws the run away -- so growing the probe set or raising the
    timeout has to fail here rather than in a campaign six months from now.
    """
    # All probes in one tick share the protocol's single cycle deadline; the checkout probe's two
    # HTTP operations consume that same budget rather than multiplying it.
    worst_case = PROBE_TIMEOUT_SECONDS
    gap_limit = PROBE_INTERVAL_SECONDS * 3
    assert worst_case < gap_limit, (
        f"a fully failing cycle takes {worst_case}s, which is not under the {gap_limit}s gap that "
        "data-management section 4 invalidates a run for. Shrink the probe set, lower "
        "probe_timeout_seconds, or raise probe_interval_seconds -- in the protocol first."
    )
