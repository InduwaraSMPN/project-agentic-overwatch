r"""The mirror check: runner/pilot_cli.py must agree with evaluation-protocol.md §4's M10 block.

WHAT THIS TEST IS FOR
    ``docs/protocols/evaluation-protocol.md`` §4 carries an ``<!-- m10-fidelity-constants -->``
    block owning every quantitative parameter the M10 campaign-v2 remediation adds (ADR-120), and
    ``runner/pilot_cli.py`` mirrors the five of them the pilot ladder consumes. Under
    ``.agents/rules/00-source-of-truth.md`` a literal may appear twice only where the second copy is
    *checked* against the first, so this test is the entire justification for that copy being legal.
    It parses the anchored block out of the protocol and asserts the two sides agree key for key.

    It is the same contract, and very nearly the same code, as
    ``analysis/tests/test_gate_constants_match_protocol.py`` for the GATE block and
    ``infra/tests/test_constants_match_protocol.py`` for the M1 instrument constants (ADR-016). The
    duplication is deliberate rather than unfortunate: those suites install and run in three
    different CI jobs, each with only ``pytest`` available, so a shared helper module would be a
    cross-package import for the sake of forty lines of grammar.

    If this test fails with a mismatch, the PROTOCOL IS RIGHT and the module is wrong. That
    direction
    is not negotiable and is not a matter of which was edited last.

WHY THE KEYS ARE A SUBSET, NOT THE WHOLE BLOCK
    ``analysis/stats/m10.py`` mirrors ``injection_discrimination_base_rate_max`` for ``analysis/``;
    the M10 plan homes the FULL mirror in ``runner/fidelity/``, which the Part-B half of WS-5
    creates.
    Until it exists, this file's module carries the pilot ladder's five. The sets are disjoint, so
    no constant has three homes, and the block legitimately owns keys (the class-B thresholds, the
    lifetime attempt cap, the checkpoint size, the scoring and live-timing tolerances) that neither
    mirror may restate until the module that consumes them does.

WHEN THE FULL MIRROR LANDS, THIS TEST IS NOT EDITED
    The repoint is one import inside ``runner/pilot_cli.py`` -- the five ``PILOT_*`` names become
    re-exports of ``runner.fidelity``'s, and ``MIRRORED_KEYS`` / ``PROTOCOL_ANCHOR`` /
    ``PROTOCOL_RELATIVE_PATH`` come with them. Every assertion below reads those names off
    ``runner.pilot_cli`` rather than importing a constants module directly, precisely so the
    repoint is a one-line change in one file and this test keeps checking whatever the mirror's
    current home is. What must survive the repoint is the CONTRACT, not the location: the protocol
    is the authority, a mismatch is fixed in the module, and the two mirrors stay disjoint.


HOW THE BLOCK IS FOUND
    By the HTML anchor on its own line, immediately followed by a fenced ``yaml`` block -- an anchor
    rather than a heading search, because headings are prose and get retitled. The grammar is
    smaller
    than the GATE block's: blank lines and ``#`` comments are skipped and every other line must be a
    bare ``key: value`` pair. The parser is reimplemented here from :mod:`re` rather than adding a
    YAML dependency for one assertion, for the reason
    ``analysis/tests/test_gate_constants_match_protocol.py`` gives.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from runner import pilot_cli  # noqa: E402

PROTOCOL_PATH = REPO_ROOT / pilot_cli.PROTOCOL_RELATIVE_PATH

FENCE_OPEN = "```yaml"
FENCE_CLOSE = "```"

_SCALAR = re.compile(r"^([a-z_][a-z0-9_]*):\s*(.+)$")

# The protocol's M10 block, read once at import so a missing file fails every case with the same
# diagnosis rather than one case per assertion.
_MARKDOWN = PROTOCOL_PATH.read_text(encoding="utf-8")


def _find_block(markdown: str, anchor: str) -> str:
    """Return the text inside the fenced yaml block that follows ``anchor``.

    Blank lines between the anchor and the fence are tolerated; anything else is not, because it
    would mean the anchor and the block are no longer adjacent and this function would be reading a
    block it was not pointed at.
    """
    lines = markdown.splitlines()
    anchor_at = next((index for index, line in enumerate(lines) if line.strip() == anchor), None)
    assert anchor_at is not None, (
        f"MISSING ANCHOR: {anchor} does not appear in {pilot_cli.PROTOCOL_RELATIVE_PATH}. The M10 "
        "fidelity-constants block must carry the anchor comment on a line of its own, followed "
        "by a fenced yaml block."
    )
    cursor = anchor_at + 1
    while cursor < len(lines) and not lines[cursor].strip():
        cursor += 1
    assert cursor < len(lines) and lines[cursor].strip() == FENCE_OPEN, (
        f"MISSING BLOCK: {anchor} was found but the expected {FENCE_OPEN!r} fence was not."
    )
    body: list[str] = []
    cursor += 1
    while cursor < len(lines):
        if lines[cursor].strip() == FENCE_CLOSE:
            return "\n".join(body)
        body.append(lines[cursor])
        cursor += 1
    raise AssertionError(f"MISSING BLOCK: {anchor} has no closing {FENCE_CLOSE!r} fence")


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


def _parse(block_text: str) -> dict[str, object]:
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
        assert match is not None, f"line {number}: not in the block grammar: {raw!r}"
        mapping[match.group(1)] = _coerce(match.group(2))
    return mapping


def test_the_protocol_block_matches_the_pilot_mirror() -> None:
    """§4's M10 block and runner/pilot_cli's mirror carry the same value for every mirrored key.

    A subset check, not an equality of key sets: the block owns runner/fidelity keys that this
    module does not mirror, so those are not this module's to restate.
    """
    from_protocol = _parse(_find_block(_MARKDOWN, pilot_cli.PROTOCOL_ANCHOR))
    from_module = {
        "pilot_p0_live_probes": pilot_cli.PILOT_P0_LIVE_PROBES,
        "pilot_p1a_runs": pilot_cli.PILOT_P1A_RUNS,
        "pilot_p1b_runs": pilot_cli.PILOT_P1B_RUNS,
        "pilot_p2_runs": pilot_cli.PILOT_P2_RUNS,
        "pilot_p3_runs": pilot_cli.PILOT_P3_RUNS,
    }
    assert set(from_module) == set(pilot_cli.MIRRORED_KEYS)
    for key in pilot_cli.MIRRORED_KEYS:
        assert key in from_protocol, (
            f"runner/pilot_cli.py mirrors {key!r}, but the section-4 M10 block does not define it"
        )
        assert from_protocol[key] == from_module[key], (
            f"{key} differs: {pilot_cli.PROTOCOL_RELATIVE_PATH} §4 says {from_protocol[key]!r}, "
            f"runner/pilot_cli.py says {from_module[key]!r}. The protocol is the authority; fix "
            "the module, not the protocol, unless the protocol edit is the change under review."
        )


def test_the_mirrored_keys_exist_in_the_protocol_block_under_those_names() -> None:
    """A renamed protocol key must fail loudly rather than be mirrored from the wrong row.

    Cheap, and it is the failure mode a hand-maintained key list has: the module keeps its name, the
    protocol renames the row, the comparison above finds the module's key ABSENT from the block and
    says so -- but only if someone reads the message. Asserting the intersection explicitly means
    the
    rename is caught as a rename.
    """
    block = _parse(_find_block(_MARKDOWN, pilot_cli.PROTOCOL_ANCHOR))
    assert set(pilot_cli.MIRRORED_KEYS) <= set(block)
    # and the module carries a value for each of them, with the right type
    for key in pilot_cli.MIRRORED_KEYS:
        value = block[key]
        assert isinstance(value, int) and value > 0, f"{key} is {value!r}, not a positive count"


def test_the_two_passes_and_their_stage_sizes_are_consistent() -> None:
    """P2 and P3 are the same design, so the protocol must size them the same way.

    Not a mirror test -- a consistency check between the mirrored numbers and the shape of the
    ladder
    they size. If the two passes ever diverge in size, one of the two assertions above is stale.
    """
    assert pilot_cli.PILOT_P2_RUNS == pilot_cli.PILOT_P3_RUNS
    assert pilot_cli.STAGE_RUNS["p2"] == pilot_cli.STAGE_RUNS["p3"] == pilot_cli.PILOT_P2_RUNS
    assert pilot_cli.STAGE_RUNS["p0"] == 0  # P0-offline runs no bundles
    assert pilot_cli.STAGE_RUNS["p1a"] == pilot_cli.PILOT_P1A_RUNS
    assert pilot_cli.STAGE_RUNS["p1b"] == pilot_cli.PILOT_P1B_RUNS
    assert pilot_cli.STAGE_RUNS["p0-live"] == pilot_cli.PILOT_P0_LIVE_PROBES
    assert set(pilot_cli.STAGE_RUNS) == set(pilot_cli.LADDER_STAGES)


def test_the_mirror_does_not_restate_a_constant_another_module_already_owns() -> None:
    """No key may be mirrored twice, in two runner-side or analysis-side homes.

    ``.agents/rules/00`` allows a second copy only where it is checked, and a THIRD copy is a second
    decision. ``analysis/stats/m10.py`` already owns the discrimination ceiling; this module's keys
    must not overlap it, or the two would be free to diverge. The import is the check.
    """
    analysis_keys = set(__import__("analysis.stats.m10", fromlist=["MIRRORED_KEYS"]).MIRRORED_KEYS)
    assert not analysis_keys & set(pilot_cli.MIRRORED_KEYS)


@pytest.mark.parametrize("stage", ["p2", "p3"])
def test_a_coverage_stage_is_the_size_the_protocol_fixes(stage: str) -> None:
    """The mirrored constant is load-bearing, not decorative: it sizes the generated order.

    M10 principle P5 requires the deterministic parts of every cell to be proven offline, so a
    change
    to the arms or the injection conditions that made a pass the wrong length must fail here and in
    ``runner/tests/test_order.py`` rather than being discovered as a coverage pass one run short.
    """
    from runner.pilot_cli import coverage_order

    assert len(coverage_order(stage)) == pilot_cli.STAGE_RUNS[stage]
