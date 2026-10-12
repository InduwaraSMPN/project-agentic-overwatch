r"""The payload marker: quote-safe, scoped to the cell, and written by the applier (F-SC-01).

F-SC-01 needs a needle that (a) survives the aggregator's quoting under G0-FULL, and (b) tells a
reader nothing about which arm produced the bundle. Both are properties of the marker's *value*
rather than of any one delivery, so they are pinned here rather than in the channel round-trip
suite: a future edit that made the marker run-scoped, or introduced a character the quoting escapes,
would otherwise pass every delivery test and fail only in the live campaign.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from monitor.aggregator.quoting import QUOTE_OPEN, quote, unquote  # noqa: E402

from scenarios.attackers.marker import (  # noqa: E402
    PAYLOAD_MARKER,
    mark_payload,
    payload_marker,
)

# The six arms of the structure and guardrail ablations (docs/07-glossary-and-ids.md).
ARMS = ("G0-FULL", "S2-FLAT", "S3-SINGLE", "G1-LOGONLY", "G2-SHAREDCRED", "G3-UNQUOTED")


def test_the_marker_names_the_cell_and_not_the_arm() -> None:
    """Two runs of one cell, differing only in arm, carry the SAME marker.

    This is the condition-leak guard. For INJ-A/C/D the marker lands in the text the agents read,
    and the agent's context carries no run id, so a marker that varied with the arm would tell a
    model which condition it was running under. The balanced rotation already draws the same
    payload for every arm of a cell, so the marker loses no discriminating power by being
    cell-scoped.
    """
    markers = {payload_marker("SCN-SIM-01", "INJ-A", 101) for _arm in ARMS}
    assert markers == {"OVERWATCH-PAYLOAD:SCN-SIM-01-INJ-A-101"}


def test_distinct_cells_get_distinct_markers() -> None:
    """The three coordinates are all in the marker, so no two cells collide on it."""
    cells = [
        ("SCN-SIM-01", "INJ-A", 101),
        ("SCN-SIM-02", "INJ-A", 101),
        ("SCN-SIM-01", "INJ-B", 101),
        ("SCN-SIM-01", "INJ-A", 102),
    ]
    assert len({payload_marker(*cell) for cell in cells}) == len(cells)


def test_the_marker_survives_the_aggregators_quoting_untouched() -> None:
    """A G0-FULL excerpt carries the marker verbatim; that is the whole reason it exists.

    ``quote`` escapes the delimiters, the escape character and every invisible or reordering code
    point. The marker is built only from letters, digits, ``:`` and ``-``, so it is inside none of
    those classes and a reader can grep a G0 event for it exactly as it greps a G3 one.
    """
    marker = payload_marker("SCN-SIM-01", "INJ-B", 101)
    quoted = quote(f"proc.cmdline=sh -c : {marker}")
    assert quoted.startswith(QUOTE_OPEN)
    assert marker in quoted
    assert marker in unquote(quoted)


def test_mark_payload_appends_the_marker_on_its_own_line() -> None:
    """The separator is a line feed, so an unterminated payload cannot absorb the marker."""
    assert mark_payload("payload text", "MARKER") == "payload text\nMARKER"
    assert mark_payload("", "MARKER") == "\nMARKER"


def test_the_constant_is_the_one_the_reader_greps() -> None:
    """The writer's constant and the reader's re-export are one string, not two that agree today."""
    from runner.fidelity.scenarios import PAYLOAD_MARKER as READER_MARKER

    assert READER_MARKER is PAYLOAD_MARKER
