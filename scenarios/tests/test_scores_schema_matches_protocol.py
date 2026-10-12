r"""scores.v1.json's field names are data-management.md section 3's, asserted rather than eyeballed.

This is the check behind traceability row T-38's "rubric ships with the labels", in the form
ADR-016 fixed for every instrument constant: the protocol document is parsed, the field names are
extracted from its own ``Minimal schema:`` line, and the schema's field set is required to equal
them exactly -- equal, not a superset and not a subset. A reviewer comparing two lists by eye is
exactly what ADR-016 replaced, because the day the two drift is the day scores nobody can join to
the protocol are written under a green check.

The parse is deliberately strict. It locates the one ``Minimal schema:`` line that introduces
``scores.json`` -- there are two such lines in section 3, the other introducing ``assertions.json``
-- and extracts the names from it with a small regex. A protocol edit that reworded the line beyond
what the regex reads would fail here rather than silently matching nothing, which is the ADR-016
property: the mirror breaks loudly when its source moves.
"""

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scenarios.schemas import validate as V  # noqa: E402

PROTOCOL = REPO_ROOT / "docs" / "protocols" / "data-management.md"

# The scores.json schema line in section 3 begins with this exact anchor phrase. assertions.json
# uses the same "Minimal schema:" lead-in, so the anchor is the backticked run_id...rubric_version
# opening, which only the scores line has.
SCORES_ANCHOR = "`run_id, rubric_version, passes[]"


def _extract_scores_field_names() -> set[str]:
    text = PROTOCOL.read_text(encoding="utf-8")
    start = text.find(SCORES_ANCHOR)
    assert start != -1, (  # noqa: S101 - a test
        f"could not find the scores.json schema line in {PROTOCOL.name}; it should begin "
        f"{SCORES_ANCHOR!r}. If the protocol reworded it, update this test deliberately."
    )
    # The schema spans from the opening backtick to the closing one, possibly across wrapped lines.
    opening = text.rfind("`", 0, start + 1)
    closing = text.find("`", start + len(SCORES_ANCHOR))
    literal = text[opening + 1 : closing]
    # Field names are bare identifiers; enum members like `initial`/`rescore` and the set braces are
    # not fields. Strip the `passes[] {...}` nesting braces and the `pass ∈ {...}` enum, then take
    # every identifier token, then remove the ones that are values rather than field names.
    literal = re.sub(r"∈\s*\{[^}]*\}", "", literal)  # drop enum value sets
    tokens = set(re.findall(r"[a-z_][a-z_0-9]*", literal))
    # `passes` is the array field; `pass` inside it is a field too. The tokens that are structural
    # rather than field names:
    tokens.discard("bool")
    return tokens


def test_scores_schema_field_names_are_exactly_the_protocols() -> None:
    """scores.v1.json's top-level and per-pass field names, unioned, equal the protocol's set."""
    protocol_fields = _extract_scores_field_names()

    schema = V.load_schema("scores.v1")
    top_level = set(schema["properties"])
    per_pass = set(schema["$defs"]["scoringPass"]["properties"])
    schema_fields = top_level | per_pass

    assert schema_fields == protocol_fields, (
        "scores.v1.json field names have drifted from data-management.md section 3.\n"
        f"  only in schema:   {sorted(schema_fields - protocol_fields)}\n"
        f"  only in protocol: {sorted(protocol_fields - schema_fields)}\n"
        "The schema is pinned to the protocol by this test (ADR-016); fix the schema, or if the "
        "protocol changed deliberately, change both in one commit."
    )


def test_scores_schema_pins_the_judged_field_ranges() -> None:
    """The three judged fields carry the ranges the rubric fixes, which the protocol defers to M5.

    data-management.md section 3 says 'the value range of each judged field is fixed by the M5
    rubric, not here'. This asserts the schema actually fixes them, so the deferral has a landing
    place rather than being an open promise.
    """
    schema = V.load_schema("scores.v1")
    per_pass = schema["$defs"]["scoringPass"]["properties"]

    assert per_pass["investigation_match"] == {
        "description": per_pass["investigation_match"]["description"],
        "type": "integer",
        "minimum": 0,
        "maximum": 3,
    }
    assert per_pass["scope_correct"]["type"] == "boolean"
    assert per_pass["incorrect_or_harmful_action_count"]["type"] == "integer"
    assert per_pass["incorrect_or_harmful_action_count"]["minimum"] == 0
