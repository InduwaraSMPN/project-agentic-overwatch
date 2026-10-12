r"""The YAML subset reader accepts what the corpus uses and refuses what it does not implement.

The reader's whole safety argument is that it is a subset: a document a real YAML parser would read
differently is refused, never guessed at. So the refusals are as load-bearing as the acceptances,
and both are tested here.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402

from scenarios.schemas import yamlsubset as Y  # noqa: E402


def test_block_mapping_and_scalars() -> None:
    doc = Y.parse("a: 1\nb: hello\nc: true\nd: null\ne: ~\n")
    assert doc == {"a": 1, "b": "hello", "c": True, "d": None, "e": None}


def test_nested_mapping_and_sequence_of_mappings() -> None:
    doc = Y.parse("outer:\n  inner: value\nitems:\n  - id: one\n    n: 1\n  - id: two\n    n: 2\n")
    assert doc == {
        "outer": {"inner": "value"},
        "items": [{"id": "one", "n": 1}, {"id": "two", "n": 2}],
    }


def test_sequence_of_scalars() -> None:
    assert Y.parse("verbs:\n  - get\n  - list\n") == {"verbs": ["get", "list"]}


def test_empty_flow_collections_are_the_one_flow_form_accepted() -> None:
    """`[]` and `{}` are unambiguous and the only way to write an empty collection; populated flow
    style stays refused by the parametrised test below."""
    assert Y.parse("a: []\nb: {}\n") == {"a": [], "b": {}}


def test_literal_and_folded_block_scalars() -> None:
    doc = Y.parse("lit: |\n  one\n  two\nfold: >\n  a\n  b\n")
    assert doc["lit"] == "one\ntwo\n"
    assert doc["fold"] == "a b\n"


def test_quoted_strings_preserve_special_characters() -> None:
    doc = Y.parse("a: \"x: y\"\nb: 'it''s'\n")
    assert doc == {"a": "x: y", "b": "it's"}


def test_comments_are_ignored() -> None:
    assert Y.parse("# lead\na: 1  # trailing\n") == {"a": 1}


@pytest.mark.parametrize(
    "text",
    [
        "a:\tb\n",  # tab
        "a: [1, 2]\n",  # flow sequence
        "a: {x: 1}\n",  # flow mapping
        "a: &anchor 1\n",  # anchor
        "a: 1.5\n",  # float
        "a: 1\n---\nb: 2\n",  # second document
        "a: 1\na: 2\n",  # duplicate key
        "  a: 1\n",  # not starting at column 0
    ],
)
def test_out_of_subset_is_refused_by_line(text: str) -> None:
    with pytest.raises(Y.YamlSubsetError):
        Y.parse(text)


def test_a_key_with_no_value_is_refused() -> None:
    """Empty value is ambiguous between null and an empty mapping; the reader demands it stated."""
    with pytest.raises(Y.YamlSubsetError):
        Y.parse("a:\nb: 1\n")
