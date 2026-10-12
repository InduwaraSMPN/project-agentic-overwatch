"""The ordered source registry, the raw-record reader, and the identifier every event carries.

WHY THE REGISTRY IS ORDERED, AND WHY THAT IS A DESIGN DECISION RATHER THAN A DETAIL
------------------------------------------------------------------------------------
M2's Definition of Done is a ``cmp``: replaying one fixture twice must produce byte-identical
output. ADR-019 fixes emission order as the explicit total order ``(source_ts, source_rank,
event_id)``, and this module is where ``source_rank`` comes from. The rank is a source's position in
:data:`SOURCE_REGISTRY` -- a tuple, written out once, in ``docs/02-architecture.md`` section 3's own
order -- and never its position in a dictionary, a set, or an alphabetical sort.

Each of those alternatives fails differently and none of them fails loudly. Dictionary iteration
order is insertion order in this interpreter, so it is stable within one process for one input
ordering and changes the moment a fixture directory is walked by a filesystem that returns entries
differently: the diff passes on the machine that wrote the golden file and fails on the next one.
Set iteration order is worse, because it depends on hash values. Alphabetical order over the source
names is stable but wrong for a different reason: adding a fifth family would silently reshuffle
every existing fixture's golden output, whereas a registry makes adding one a deliberate placement
that a reviewer sees in the diff.

The order must be **total**, not merely deterministic in practice. Two events sharing a timestamp
and a source would otherwise fall back to whatever order the input happened to yield, so
``event_id`` is the final tie-break -- and because it is a pure function of content, the tie-break
is a property of the events rather than of the reading.

``event_id``: WHAT THE PROJECTION IS, EXACTLY
----------------------------------------------
``event_id`` is ``sha256`` over :func:`identity_projection`, serialised by ``models.py``'s canonical
JSON. It is never a freshly generated identifier: a generated one differs on every replay and makes
the twice-and-diff unpassable by construction, which is why ``scripts/monitor_guard.sh`` block (b)
treats one under this directory as a failure. Being a digest also makes it *meaningful* -- an
identifier that changes is telling the truth about the content having changed.

The projection is, in full::

    {"schema_version": "v2",
     "source":         <the source family>,
     "signal_id":      <the source's own structured signal, or null>,
     "ts":             <the record's own timestamp, normalised to UTC, ISO-8601>,
     "severity":       <the normalised severity>,
     "resource":       {"ns": ..., "kind": ..., "name": ...},
     "summary":        <summary text, PRE-cap and PRE-quoting>,
     "excerpt_candidates": [<every candidate, in the normaliser's order, PRE-cap, PRE-quoting>],
     "discriminator":  [[<key>, <raw source value>], ...]}

Four properties of that shape are load-bearing:

**The text is pre-cap and pre-quoting.** So the identifier of an event does not change when a cap
value is calibrated, and -- decisively -- it is *identical across the G3 arms*. The isolation test
requires every field except ``summary`` and ``evidence_excerpts`` to be byte-identical between a
quoted and an unquoted run, and an identifier computed over quoted text would fail that on the one
field whose whole job is to be stable. ``signal_id`` (added at M10, ADR-125) is projected here for
the same reason it is captured at the source at all: it is a sensor value, not derived from the
excerpt text, so it enters the digest and stays identical across the two arms.

**``raw_ref`` is excluded.** It is a location, not content. Including it would mean that inserting a
record above another in a fixture, or renaming the file, changes every identifier below it -- so a
one-line fixture edit would churn the entire golden corpus and hide whatever real change was in the
same commit.

**The per-source discriminator carries the source's own natural key, with raw values.** Content
alone does not separate two records that a source considers distinct: two Falco alerts a nanosecond
apart normalise to the same ``ts``, because :class:`~datetime.datetime` resolves microseconds. The
discriminator holds the raw timestamp text, so they separate. Each normaliser declares its own; the
package docstring in ``sources/`` says why the values are raw.

**Two identical records are refused rather than deduplicated.** If two records project identically
the digest collides, and :func:`ordered` raises :class:`DuplicateEventId` naming both byte spans. It
is a real defect either way -- a fixture that repeats a record, or a discriminator too narrow for
its source -- and the alternatives are both worse: emitting two events with one identifier breaks
the contract downstream, and silently dropping the second discards evidence on the strength of a
guess about which duplicate mattered.

THE READER COMPUTES EXACT BYTE SPANS, INCLUDING INSIDE A SINGLE JSON DOCUMENT
------------------------------------------------------------------------------
``raw_ref`` is a pointer -- a path, a byte offset and a byte length -- and ``models.py`` requires it
to be *resolvable*: seek to the offset, read ``length`` bytes, and get exactly the record the event
was derived from. For the two line-oriented families that is the line's own bytes. For Alertmanager
and Trivy, whose records are array elements inside one document, it would have been much easier to
point every record at the whole file, and that is what this module declines to do: a pointer that
resolves to a four-megabyte report does not let anyone check an excerpt's provenance against the
record it claims to come from, which is the one thing the length field exists for.

So :func:`read_records` walks the document with the standard library's own JSON decoder, using
``raw_decode`` to obtain the end position of each value it parses, and converts character positions
to byte offsets with a forward-only cursor. That keeps the spans exact under any UTF-8 content
without a second parser and without a dependency. The element count from the span walk is compared
against the parsed document's own list length, so a scanner that lost its place fails immediately
rather than emitting a plausible offset.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
Reordering :data:`SOURCE_REGISTRY` reorders every golden ``monitor_events.jsonl`` in the corpus.
Changing :func:`identity_projection` changes every ``event_id`` in it. Changing the reader changes
every ``raw_ref`` offset. All three invalidate the corpus wholesale rather than needing it re-run,
and after the ``v1.0`` freeze iron rule 6 makes any of them a logged hotfix ADR.
"""

import hashlib
import json
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Final

from monitor.aggregator.models import (
    SCHEMA_VERSION,
    EvidenceSource,
    RawRef,
    canonical_json_bytes,
)
from monitor.aggregator.sources import (
    NormalisedRecord,
    Normaliser,
    NormaliserOptions,
    RawRecord,
    RecordLayout,
    RecordLocator,
)
from monitor.aggregator.sources import falco as falco_source
from monitor.aggregator.sources import k8s_audit as k8s_audit_source
from monitor.aggregator.sources import prometheus as prometheus_source
from monitor.aggregator.sources import trivy as trivy_source


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build one JSON object, refusing a member name that appears more than once."""
    value: dict[str, Any] = {}
    for key, member in pairs:
        if key in value:
            raise RecordLayoutError(f"duplicate JSON member {key!r}")
        value[key] = member
    return value


# Every parse path uses this decoder so duplicate-member handling cannot differ between the value
# used for normalisation and the span walk used to construct raw_ref.
_DECODER: Final = json.JSONDecoder(object_pairs_hook=_reject_duplicate_members)

# The four characters JSON admits between tokens. Spelled out rather than taken from str.isspace(),
# which accepts a much wider set that JSON does not.
_JSON_WHITESPACE: Final = " \t\n\r"


class RecordLayoutError(ValueError):
    """Raised when a raw input does not have the layout its source's locator declares.

    Always names the byte or character position it stopped at. A reader that shrugged at a shape it
    did not recognise would emit an offset that points at the wrong bytes, and a wrong pointer is
    worse than no pointer: it validates, it resolves, and it produces the wrong evidence.
    """


class DuplicateEventId(ValueError):
    """Raised when two records in one batch project to the same identifier. See the docstring."""


@dataclass(frozen=True, slots=True)
class SourceEntry:
    """One row of the ordered registry: a family, its rank, its normaliser and its input layout.

    ``rank`` is stored rather than computed from the tuple index at each use, so that the value
    which decides emission order is a written-down property of the row a reviewer reads, not
    something derived somewhere else at run time.
    """

    source: EvidenceSource
    rank: int
    normalise: Normaliser
    locator: RecordLocator
    input_filename: str


# The order is docs/02-architecture.md section 3's own, and it is deliberately not re-sorted. See
# the module docstring for why a registry rather than a dictionary, a set or an alphabetical sort.
SOURCE_REGISTRY: Final[tuple[SourceEntry, ...]] = (
    SourceEntry(
        source=EvidenceSource.FALCO,
        rank=0,
        normalise=falco_source.normalise,
        locator=falco_source.LOCATOR,
        input_filename=falco_source.INPUT_FILENAME,
    ),
    SourceEntry(
        source=EvidenceSource.PROMETHEUS,
        rank=1,
        normalise=prometheus_source.normalise,
        locator=prometheus_source.LOCATOR,
        input_filename=prometheus_source.INPUT_FILENAME,
    ),
    SourceEntry(
        source=EvidenceSource.K8S_AUDIT,
        rank=2,
        normalise=k8s_audit_source.normalise,
        locator=k8s_audit_source.LOCATOR,
        input_filename=k8s_audit_source.INPUT_FILENAME,
    ),
    SourceEntry(
        source=EvidenceSource.TRIVY,
        rank=3,
        normalise=trivy_source.normalise,
        locator=trivy_source.LOCATOR,
        input_filename=trivy_source.INPUT_FILENAME,
    ),
)


@dataclass(frozen=True, slots=True)
class AggregatedRecord:
    """A normalised record with the two things only this module can supply: its pointer and its id.

    Carried together because the three are produced in one pass and consumed in one pass, and
    because separating them would let a caller pair a record with another record's pointer -- a
    mistake that would validate, serialise and be undetectable in the output.
    """

    record: NormalisedRecord
    raw_ref: RawRef
    event_id: str
    rank: int


def registry_entry(source: EvidenceSource) -> SourceEntry:
    """Return the registry row for ``source``. Raises :class:`KeyError` for an unregistered one.

    A linear scan of four rows rather than a prebuilt dictionary: the registry is the single home of
    the ordering, and a second, derived mapping is a second thing to keep in step for no measurable
    gain at this size.
    """
    for entry in SOURCE_REGISTRY:
        if entry.source is source:
            return entry
    raise KeyError(f"{source!r} has no row in SOURCE_REGISTRY")


class _ByteCursor:
    """Converts a character index into a UTF-8 byte offset, in amortised linear time overall.

    The JSON decoder works in characters and ``raw_ref`` is specified in bytes, so every span the
    walk produces needs converting. Encoding the whole prefix at each conversion would be quadratic
    in the document size; this keeps the last answer and encodes only the characters since it, which
    is linear across a walk that only ever moves forward. A backward query resets and recomputes,
    which is correct but slow -- and does not happen, because the walk is forward-only.
    """

    __slots__ = ("_byte", "_char", "_text")

    def __init__(self, text: str) -> None:
        self._text = text
        self._char = 0
        self._byte = 0

    def byte_offset(self, char_index: int) -> int:
        if char_index < self._char:
            self._char = 0
            self._byte = 0
        self._byte += len(self._text[self._char : char_index].encode("utf-8"))
        self._char = char_index
        return self._byte


def _skip_whitespace(text: str, index: int) -> int:
    """Return the index of the next non-whitespace character at or after ``index``."""
    while index < len(text) and text[index] in _JSON_WHITESPACE:
        index += 1
    return index


def _array_spans(text: str, start: int) -> list[tuple[Any, int, int]]:
    """Return ``(value, start, end)`` in characters for each element of the array at ``start``.

    ``start`` must be the index of the ``[``. The decoder's ``raw_decode`` reports where each value
    ended, which is what makes the spans exact rather than estimated; everything else here is the
    array's punctuation, checked rather than assumed so that a malformed document raises at the
    character it broke on.
    """
    if start >= len(text) or text[start] != "[":
        raise RecordLayoutError(
            f"expected '[' at character {start}, found {text[start : start + 1]!r}"
        )
    spans: list[tuple[Any, int, int]] = []
    index = _skip_whitespace(text, start + 1)
    if index < len(text) and text[index] == "]":
        return spans
    while True:
        value, end = _DECODER.raw_decode(text, index)
        spans.append((value, index, end))
        index = _skip_whitespace(text, end)
        if index >= len(text):
            raise RecordLayoutError(f"array opening at character {start} is not terminated")
        if text[index] == "]":
            return spans
        if text[index] != ",":
            raise RecordLayoutError(
                f"expected ',' or ']' at character {index}, found {text[index]!r}"
            )
        index = _skip_whitespace(text, index + 1)


def _member_value_start(text: str, start: int, key: str) -> int | None:
    """Return where ``key``'s value begins in the object opening at ``start``, or ``None``.

    ``start`` must be the index of the ``{``. Only the first occurrence of a duplicate key is
    reported, which matches what the decoder itself would have kept, so the span and the parsed
    value describe the same member.
    """
    if start >= len(text) or text[start] != "{":
        raise RecordLayoutError(
            f"expected '{{' at character {start}, found {text[start : start + 1]!r}"
        )
    index = _skip_whitespace(text, start + 1)
    if index < len(text) and text[index] == "}":
        return None
    while True:
        name, end = _DECODER.raw_decode(text, index)
        index = _skip_whitespace(text, end)
        if index >= len(text) or text[index] != ":":
            raise RecordLayoutError(f"expected ':' after an object key at character {index}")
        index = _skip_whitespace(text, index + 1)
        value_start = index
        _, end = _DECODER.raw_decode(text, index)
        if name == key:
            return value_start
        index = _skip_whitespace(text, end)
        if index >= len(text):
            raise RecordLayoutError(f"object opening at character {start} is not terminated")
        if text[index] == "}":
            return None
        if text[index] != ",":
            raise RecordLayoutError(
                f"expected ',' or '}}' at character {index}, found {text[index]!r}"
            )
        index = _skip_whitespace(text, index + 1)


def _records_of(container: Mapping[str, Any], key: str, *, where: str) -> list[Any] | None:
    """Return the list under ``key``, ``None`` for an explicit JSON null, raising when absent.

    The three cases are kept apart deliberately. A key that is present and null is a scan that found
    nothing or a notification with no alerts -- a real, empty result. A key that is absent is a
    document of a shape this reader was not pointed at, and reporting that as "no records" would
    turn a mistyped locator or a changed upstream format into a silently empty replay.
    """
    if key not in container:
        raise RecordLayoutError(f"{where}: no {key!r} member; the document is not of this shape")
    value = container[key]
    if value is None:
        return None
    if not isinstance(value, list):
        raise RecordLayoutError(f"{where}: {key!r} is {type(value).__name__}, expected an array")
    return value


def _decode_complete_json(text: str, *, where: str) -> Any:
    """Decode exactly one JSON value, rejecting duplicate members and trailing non-whitespace."""
    start = _skip_whitespace(text, 0)
    try:
        value, end = _DECODER.raw_decode(text, start)
    except (ValueError, TypeError) as broken:
        raise RecordLayoutError(f"{where}: {broken}") from broken
    trailing = _skip_whitespace(text, end)
    if trailing != len(text):
        raise RecordLayoutError(
            f"{where}: trailing data at character {trailing}; expected only JSON whitespace"
        )
    return value


def _read_json_lines(data: bytes) -> Iterator[RawRecord]:
    """Yield one record per non-blank line, with the line's own byte span.

    The span excludes the line terminator, which is framing rather than part of the record. A
    trailing carriage return is stripped and the span shrinks with it, so a fixture that has passed
    through a Windows checkout still yields records whose pointers resolve to exactly the record.
    """
    offset = 0
    for index, line in enumerate(data.split(b"\n"), start=1):
        span = len(line)
        record_bytes = line[:-1] if line.endswith(b"\r") else line
        if record_bytes.strip():
            try:
                text = record_bytes.decode("utf-8")
            except UnicodeDecodeError as broken:
                raise RecordLayoutError(f"line {index}: {broken}") from broken
            value = _decode_complete_json(text, where=f"line {index}")
            if not isinstance(value, dict):
                raise RecordLayoutError(
                    f"line {index}: a JSON Lines record must be an object, "
                    f"found {type(value).__name__}"
                )
            yield RawRecord(value=value, offset=offset, length=len(record_bytes))
        # +1 for the newline that split() consumed. The final element of split() has no newline
        # after it, so the offset it produces is never used again.
        offset += span + 1


def _group_spans(
    text: str,
    document: Mapping[str, Any],
    document_start: int,
    locator: RecordLocator,
) -> list[tuple[Mapping[str, Any], int]]:
    """Return each group object of a two-level document with the character index it opens at.

    Only Trivy has this shape today -- ``Results[]``, each entry holding its own
    ``Vulnerabilities[]`` -- but it is written as a general level rather than as a Trivy special
    case, because a locator that describes the nesting as data is checkable against a real report
    whereas a hard-coded descent is not.
    """
    if locator.group_key is None:
        raise RecordLayoutError("_group_spans called for a locator with no group_key")
    parsed_groups = _records_of(document, locator.group_key, where="the document")
    if parsed_groups is None:
        return []
    array_start = _member_value_start(text, document_start, locator.group_key)
    if array_start is None:
        raise RecordLayoutError(
            f"the document: {locator.group_key!r} parsed but its span was not found"
        )
    spans = _array_spans(text, array_start)
    if len(spans) != len(parsed_groups):
        raise RecordLayoutError(
            f"the span walk found {len(spans)} {locator.group_key} entries but the parsed "
            f"document has {len(parsed_groups)}"
        )
    groups: list[tuple[Mapping[str, Any], int]] = []
    for value, start, _end in spans:
        if not isinstance(value, dict):
            raise RecordLayoutError(
                f"{locator.group_key} entry at character {start} is "
                f"{type(value).__name__}, expected an object"
            )
        groups.append((value, start))
    return groups


def _read_json_document(data: bytes, locator: RecordLocator) -> Iterator[RawRecord]:
    """Yield one record per array element, with the element's own byte span inside the document."""
    if locator.record_key is None:
        raise RecordLayoutError("a JSON_DOCUMENT locator must name a record_key")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as broken:
        raise RecordLayoutError(f"the document: {broken}") from broken
    cursor = _ByteCursor(text)
    document_start = _skip_whitespace(text, 0)
    document = _decode_complete_json(text, where="the document")
    if not isinstance(document, dict):
        raise RecordLayoutError(f"the document is {type(document).__name__}, expected an object")
    for key, expected in locator.required_document_values:
        actual = document.get(key)
        if actual != expected or type(actual) is not type(expected):
            raise RecordLayoutError(
                f"the document: {key!r} is {actual!r}, expected {expected!r}; "
                "the upstream payload contract is version-specific"
            )

    base_context = {
        key: document[key] for key in locator.document_context if document.get(key) is not None
    }

    if locator.group_key is None:
        groups: list[tuple[Mapping[str, Any], int]] = [(document, document_start)]
        where = "the document"
    else:
        where = locator.group_key
        groups = _group_spans(text, document, document_start, locator)

    for group_value, group_start in groups:
        if locator.group_key is not None and locator.record_key not in group_value:
            # A group with no records at all -- a Trivy target with nothing found -- is a real
            # result rather than a malformed document, so it contributes no records and no error.
            continue
        parsed_records = _records_of(group_value, locator.record_key, where=where)
        if parsed_records is None:
            continue
        array_start = _member_value_start(text, group_start, locator.record_key)
        if array_start is None:
            raise RecordLayoutError(
                f"{where}: {locator.record_key!r} parsed but its span was not found"
            )
        spans = _array_spans(text, array_start)
        if len(spans) != len(parsed_records):
            raise RecordLayoutError(
                f"the span walk found {len(spans)} {locator.record_key} entries but the parsed "
                f"document has {len(parsed_records)}"
            )
        context = dict(base_context)
        context.update(
            {
                key: group_value[key]
                for key in locator.group_context
                if group_value.get(key) is not None
            }
        )
        for value, start, end in spans:
            if not isinstance(value, dict):
                raise RecordLayoutError(
                    f"{locator.record_key} entry at character {start} is "
                    f"{type(value).__name__}, expected an object"
                )
            begin = cursor.byte_offset(start)
            finish = cursor.byte_offset(end)
            yield RawRecord(value=value, offset=begin, length=finish - begin, context=dict(context))


def read_records(data: bytes, locator: RecordLocator) -> Iterator[RawRecord]:
    """Yield the records of one raw input, each with its exact byte span in ``data``."""
    if locator.layout is RecordLayout.JSON_LINES:
        yield from _read_json_lines(data)
    else:
        yield from _read_json_document(data, locator)


def identity_projection(record: NormalisedRecord) -> dict[str, Any]:
    """Return the canonical projection ``event_id`` is the digest of. Spelled out in the docstring.

    A plain dictionary of JSON-native values, because the digest is taken over
    ``models.canonical_json_bytes``, whose sorted keys and fixed separators are what make the
    projection's *serialisation* independent of the order this function happens to build it in.
    ``discriminator`` is a list of two-element lists rather than an object so that the normaliser's
    declared order survives that sort, and so that a source may legitimately repeat a key.
    """
    return {
        "schema_version": SCHEMA_VERSION,
        "source": str(record.source),
        "signal_id": record.signal_id,
        "ts": record.ts.isoformat(),
        "severity": str(record.severity),
        "resource": {
            "ns": record.resource.ns,
            "kind": record.resource.kind,
            "name": record.resource.name,
        },
        "summary": record.summary,
        "excerpt_candidates": list(record.excerpt_candidates),
        "discriminator": [[key, value] for key, value in record.discriminator],
    }


def compute_event_id(record: NormalisedRecord) -> str:
    """Return the SHA-256 digest of :func:`identity_projection`, lowercase hexadecimal.

    Sixty-four lowercase hexadecimal characters, which is what ``models.EVENT_ID_PATTERN`` admits --
    so a change of construct here is rejected at the contract boundary as well as caught by the
    guard.
    """
    return hashlib.sha256(canonical_json_bytes(identity_projection(record))).hexdigest()


def normalise_input(
    entry: SourceEntry,
    data: bytes,
    *,
    raw_path: str,
    options: NormaliserOptions,
) -> list[AggregatedRecord]:
    """Read one source's raw input and normalise every record in it.

    ``raw_path`` is the root-relative path that goes into ``raw_ref`` and is the caller's to
    compute: this module has no notion of where a repository or a run bundle begins, and building a
    filesystem-relative path here would tie the aggregator to a layout it does not ship with.
    """
    aggregated: list[AggregatedRecord] = []
    for raw in read_records(data, entry.locator):
        record = entry.normalise(raw, options)
        aggregated.append(
            AggregatedRecord(
                record=record,
                raw_ref=RawRef(path=raw_path, offset=raw.offset, length=raw.length),
                event_id=compute_event_id(record),
                rank=entry.rank,
            )
        )
    return aggregated


def ordered(records: Iterable[AggregatedRecord]) -> tuple[AggregatedRecord, ...]:
    """Return the records in the total emission order, refusing a duplicate identifier.

    The key is ``(source_ts, source_rank, event_id)`` exactly as ADR-019 fixes it. The duplicate
    check runs after the sort so that the two offending records are reported adjacent to each other
    and in a stable order, which makes the message reproducible as well as the emission.
    """
    ranked = sorted(records, key=lambda item: (item.record.ts, item.rank, item.event_id))
    seen: dict[str, AggregatedRecord] = {}
    for item in ranked:
        previous = seen.get(item.event_id)
        if previous is not None:
            raise DuplicateEventId(
                f"two records project to event_id {item.event_id}: "
                f"{previous.raw_ref.path}@{previous.raw_ref.offset}+{previous.raw_ref.length} and "
                f"{item.raw_ref.path}@{item.raw_ref.offset}+{item.raw_ref.length}. Either the "
                "input repeats a record byte for byte, or that source's discriminator is too "
                "narrow to separate two records it considers distinct. Neither is resolved by "
                "dropping one: see monitor/aggregator/normalize.py."
            )
        seen[item.event_id] = item
    return tuple(ranked)
