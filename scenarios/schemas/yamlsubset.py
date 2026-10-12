r"""A strict-subset YAML reader for the scenario manifests and ground-truth labels.

WHY A PARSER AND NOT PyYAML
-----------------------------
The same reason ``agents/registry/loader.py``, ``infra/locust/registry.py`` and
``monitor/tests/replay_harness.py`` each give: PyYAML is not pinned in ``infra/versions.env``, is
not installed by ``scripts/install_runtime_deps.sh``, and is present in this repository today only
as a LiteLLM transitive -- outside ``versions_env_sha256`` and liable to disappear with a
dependency-set change upstream. ``scenarios/`` is standard-library only for the reason
:mod:`scenarios.schemas.validate` gives at length: a determinism gate that cannot fail for a
dependency reason can only fail for the reason it exists to test. ADR-035.

This reader is larger than ``infra/locust/registry.py``'s because the documents are: a ground-truth
file nests four phase blocks and five condition blocks, each holding lists of mappings. It is still
a subset, and the subset is the point.

THE ACCEPTED SUBSET, IN FULL
------------------------------
* Block mappings. ``key: value`` on one line, or ``key:`` followed by a more-indented block.
* Block sequences. ``- scalar``, ``- key: value`` (a mapping opened on the dash line), or ``-``
  followed by a more-indented block.
* Scalars. Unquoted plain scalars; single-quoted and double-quoted strings; the literals ``true``,
  ``false``, ``null`` and ``~``; and integers. A plain scalar is a string unless it is exactly one
  of those literals or matches an integer.
* Block scalars, ``|`` and ``>``, with the default clip chomping and with ``|-`` / ``>-`` strip.
* Comments: a ``#`` beginning a line, or preceded by whitespace, outside a quoted scalar.
* Indentation in spaces only.

WHAT IS REFUSED, LOUDLY
-------------------------
Tabs, POPULATED flow style (``{a: 1}``/``[1, 2]``), anchors and aliases (``&``/``*``), tags (``!``),
multiple documents (a second ``---``), merge keys, duplicate keys in one mapping, and floats. Every
one raises :class:`YamlSubsetError` naming the line. The rule is the one the sibling parsers state:
a document a conforming YAML parser would read *differently* from this one must be refused, never
guessed at. The single flow form admitted is the EMPTY collection, ``[]`` and ``{}``, because it is
the only way to write an empty list or mapping and every parser reads it identically -- a
ground-truth condition with no end-state assertions writes ``end_state_assertions: []``. Floats are
refused rather than parsed because none of these documents has a use for one and a silently-rounded
label is worse than a rejected file.

WHAT BREAKS IF THIS FILE CHANGES
---------------------------------
Every scenario manifest and ground-truth label file becomes unreadable, which is every M5 check:
the manifest validity test, the ground-truth resolution test behind T-20, and the planner, which
reads the manifest it plans from.
"""

import re
from typing import Any, Final

__all__ = ("YamlSubsetError", "parse")

_INTEGER: Final = re.compile(r"^-?(0|[1-9][0-9]*)$")
_FLOAT: Final = re.compile(r"^-?(0|[1-9][0-9]*)\.[0-9]+([eE][-+]?[0-9]+)?$")
_KEY: Final = re.compile(r"^([A-Za-z_][A-Za-z0-9_.\-]*|\"[^\"]+\"|'[^']+'):(?: (.*))?$")
_BLOCK_HEADER: Final = re.compile(r"^([|>])([-]?)$")

_LITERALS: Final[dict[str, Any]] = {"true": True, "false": False, "null": None, "~": None}


class YamlSubsetError(Exception):
    """The document uses YAML this reader does not implement, or is malformed."""

    def __init__(self, line_number: int, message: str) -> None:
        self.line_number = line_number
        super().__init__(f"line {line_number}: {message}")


class _Line:
    __slots__ = ("indent", "number", "text")

    def __init__(self, number: int, indent: int, text: str) -> None:
        self.number = number
        self.indent = indent
        self.text = text


def _strip_comment(raw: str, number: int) -> str:
    """Remove a trailing comment, respecting quotes. Refuses tabs while it is here."""
    if "\t" in raw:
        raise YamlSubsetError(number, "tabs are not permitted; indent with spaces")
    out: list[str] = []
    quote: str | None = None
    index = 0
    while index < len(raw):
        char = raw[index]
        if quote is None and char == "#" and (index == 0 or raw[index - 1] in " "):
            break
        if quote is None and char in "\"'":
            quote = char
        elif quote is not None and char == quote:
            quote = None
        out.append(char)
        index += 1
    return "".join(out).rstrip()


def _scan(text: str) -> list[_Line]:
    lines: list[_Line] = []
    for number, raw in enumerate(text.replace("\r\n", "\n").replace("\r", "\n").split("\n"), 1):
        stripped = _strip_comment(raw, number)
        if not stripped.strip():
            continue
        if stripped.strip() == "---":
            if lines:
                raise YamlSubsetError(number, "multiple documents are not supported")
            continue
        if stripped.strip() == "...":
            break
        body = stripped.lstrip(" ")
        lines.append(_Line(number, len(stripped) - len(body), body))
    return lines


def _refuse_exotic(line: _Line) -> None:
    text = line.text
    if text.startswith(("&", "*", "!")):
        raise YamlSubsetError(line.number, "anchors, aliases and tags are not supported")
    if text.startswith("<<:"):
        raise YamlSubsetError(line.number, "merge keys are not supported")


def _scalar(raw: str, number: int) -> Any:
    value = raw.strip()
    if not value:
        raise YamlSubsetError(number, "empty scalar; write null explicitly")
    # An EMPTY flow collection is the one flow form accepted, because it is the only way to write an
    # empty list or mapping and it is unambiguous -- every YAML parser reads `[]` and `{}` the same,
    # so admitting them does not break the "read identically to a real parser" contract the way a
    # populated `[1, 2]` would. A ground-truth condition with no end-state assertions is exactly
    # this case: `end_state_assertions: []`.
    if value == "[]":
        return []
    if value == "{}":
        return {}
    if value[0] in "[{":
        raise YamlSubsetError(
            number, "populated flow style is not supported; use block style (`[]`/`{}` for empty)"
        )
    if value[0] in "&*!":
        raise YamlSubsetError(number, "anchors, aliases and tags are not supported")
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        inner = value[1:-1]
        if value[0] == "'":
            return inner.replace("''", "'")
        return _unescape(inner, number)
    if value in _LITERALS:
        return _LITERALS[value]
    if _INTEGER.match(value):
        return int(value)
    if _FLOAT.match(value):
        raise YamlSubsetError(number, f"floats are not supported: {value!r}")
    return value


def _unescape(inner: str, number: int) -> str:
    out: list[str] = []
    index = 0
    simple = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "/": "/", "0": "\0"}
    while index < len(inner):
        char = inner[index]
        if char != "\\":
            out.append(char)
            index += 1
            continue
        index += 1
        if index >= len(inner):
            raise YamlSubsetError(number, "trailing backslash in a double-quoted scalar")
        code = inner[index]
        if code in simple:
            out.append(simple[code])
            index += 1
            continue
        if code in "uU":
            width = 4 if code == "u" else 8
            digits = inner[index + 1 : index + 1 + width]
            if len(digits) != width or any(d not in "0123456789abcdefABCDEF" for d in digits):
                raise YamlSubsetError(number, f"malformed \\{code} escape")
            out.append(chr(int(digits, 16)))
            index += 1 + width
            continue
        raise YamlSubsetError(number, f"unsupported escape \\{code}")
    return "".join(out)


def _block_scalar(
    lines: list[_Line], start: int, style: str, chomp: str, parent: int
) -> tuple[str, int]:
    """Collect a ``|`` or ``>`` block, returning the joined text and the next index."""
    index = start
    body: list[str] = []
    inner_indent: int | None = None
    while index < len(lines) and lines[index].indent > parent:
        line = lines[index]
        if inner_indent is None:
            inner_indent = line.indent
        body.append(" " * (line.indent - inner_indent) + line.text)
        index += 1
    if style == "|":
        text = "\n".join(body)
    else:
        folded: list[str] = []
        for piece in body:
            if folded and piece and not piece.startswith(" ") and not folded[-1].endswith("\n"):
                folded[-1] = folded[-1] + " " + piece
            else:
                folded.append(piece)
        text = "\n".join(folded)
    if chomp != "-":
        text += "\n"
    return text, index


def _parse_block(lines: list[_Line], index: int, indent: int) -> tuple[Any, int]:
    if index >= len(lines):
        raise YamlSubsetError(lines[-1].number if lines else 0, "unexpected end of document")
    if lines[index].text.startswith("- ") or lines[index].text == "-":
        return _parse_sequence(lines, index, indent)
    return _parse_mapping(lines, index, indent)


def _parse_sequence(lines: list[_Line], index: int, indent: int) -> tuple[list[Any], int]:
    items: list[Any] = []
    while index < len(lines) and lines[index].indent == indent:
        line = lines[index]
        if not (line.text.startswith("- ") or line.text == "-"):
            break
        _refuse_exotic(line)
        remainder = line.text[2:] if line.text.startswith("- ") else ""
        if not remainder.strip():
            index += 1
            if index < len(lines) and lines[index].indent > indent:
                value, index = _parse_block(lines, index, lines[index].indent)
                items.append(value)
            else:
                raise YamlSubsetError(line.number, "a dash with no value; write null explicitly")
            continue
        header = _BLOCK_HEADER.match(remainder.strip())
        if header is not None:
            text, index = _block_scalar(lines, index + 1, header.group(1), header.group(2), indent)
            items.append(text)
            continue
        key_match = _KEY.match(remainder)
        if key_match is None:
            items.append(_scalar(remainder, line.number))
            index += 1
            continue
        # A mapping opened on the dash line. Its keys sit at the dash's column plus two, which is
        # where the first key physically starts, so the continuation lines are found by column.
        inner_indent = indent + 2
        synthetic = [_Line(line.number, inner_indent, remainder)]
        cursor = index + 1
        while cursor < len(lines) and lines[cursor].indent >= inner_indent:
            synthetic.append(lines[cursor])
            cursor += 1
        value, consumed = _parse_mapping(synthetic, 0, inner_indent)
        if consumed != len(synthetic):
            raise YamlSubsetError(
                synthetic[consumed].number, "unexpected content in a sequence item"
            )
        items.append(value)
        index = cursor
    return items, index


def _parse_mapping(lines: list[_Line], index: int, indent: int) -> tuple[dict[str, Any], int]:
    mapping: dict[str, Any] = {}
    while index < len(lines) and lines[index].indent == indent:
        line = lines[index]
        if line.text.startswith("- ") or line.text == "-":
            break
        _refuse_exotic(line)
        match = _KEY.match(line.text)
        if match is None:
            raise YamlSubsetError(line.number, f"not a `key: value` line: {line.text!r}")
        key = match.group(1)
        if key[:1] in "\"'":
            key = key[1:-1]
        if key in mapping:
            raise YamlSubsetError(line.number, f"duplicate key {key!r} in one mapping")
        remainder = match.group(2)
        if remainder is None or not remainder.strip():
            index += 1
            if index < len(lines) and lines[index].indent > indent:
                mapping[key], index = _parse_block(lines, index, lines[index].indent)
            else:
                raise YamlSubsetError(line.number, f"{key!r} has no value; write null explicitly")
            continue
        header = _BLOCK_HEADER.match(remainder.strip())
        if header is not None:
            mapping[key], index = _block_scalar(
                lines, index + 1, header.group(1), header.group(2), indent
            )
            continue
        mapping[key] = _scalar(remainder, line.number)
        index += 1
    return mapping, index


def parse(text: str) -> Any:
    """Parse one YAML document written in the accepted subset.

    Raises :class:`YamlSubsetError` on anything outside it, naming the line, so the failure tells
    an author what to change rather than what the reader could not do.
    """
    lines = _scan(text)
    if not lines:
        raise YamlSubsetError(0, "the document is empty")
    base = lines[0].indent
    if base != 0:
        raise YamlSubsetError(lines[0].number, "the document must start at column 0")
    value, consumed = _parse_block(lines, 0, 0)
    if consumed != len(lines):
        raise YamlSubsetError(lines[consumed].number, "unexpected content after the document body")
    return value
