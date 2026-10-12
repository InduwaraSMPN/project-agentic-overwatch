"""The contract every source normaliser implements, and the machinery all four of them share.

WHY THIS PACKAGE EXISTS AT ALL
------------------------------
``docs/02-architecture.md`` section 3 admits four signal families and no others, and FR1.1 names
them: Falco runtime events, Prometheus/Alertmanager alerts, the Kubernetes audit stream and Trivy
scan findings. Each speaks its own vocabulary, carries its own timestamp field, identifies its
subject differently, and -- in one case -- has no severity at all. One module per family, each
knowing exactly one payload shape, is what keeps that knowledge from spreading into the dispatcher
as a chain of conditionals that nobody can audit family by family.

What the four modules deliberately do **not** own is the order they are emitted in, the identifier
an event carries, or the bounds on its text. Those are one decision each, and each has one home:
``normalize.py`` for the ordered registry and the identifier projection, ``caps.py`` for the bounds,
``emit.py`` for serialisation. A normaliser's whole job is to turn one raw record of one shape into
:class:`NormalisedRecord`, which is the shape everything downstream understands.

THE PAYLOAD SHAPES ARE RESEARCHED, NOT GUESSED, AND THE SOURCES ARE CITED IN EACH MODULE
-----------------------------------------------------------------------------------------
A normaliser written against a guessed payload is a normaliser that gets rewritten the day real
output arrives -- and worse, the fixture corpus built against it would encode the guess as golden
output, so the rewrite would silently invalidate every expected file at once. Each of the four
modules therefore opens by naming the upstream document or source file its field list was read from,
so a reviewer can check the shape without running a cluster and a later maintainer can re-check it
against a newer release.

THE NORMALISER SIGNATURE IS UNIFORM, AND THAT COSTS ONE FIELD IN THE OPTIONS OBJECT
------------------------------------------------------------------------------------
Every normaliser is ``(RawRecord, NormaliserOptions) -> NormalisedRecord``. Uniformity is what lets
``normalize.py`` dispatch over an ordered registry instead of matching on the source name, and the
registry is what makes emission order a deliberate placement rather than a property of dictionary
iteration.

The cost is :attr:`NormaliserOptions.audit_severity`, which only one of the four reads. That is
accepted deliberately: the alternative is per-source keyword sets, which puts a ``match`` on the
source family back into the dispatcher and re-creates exactly the fan-out the registry exists to
prevent. One unread field in a small frozen options object is cheaper than that, and it is
documented at both ends.

TIMESTAMPS ARE READ FROM THE RECORD, NEVER FROM A CLOCK, AND SUB-MICROSECOND PRECISION IS TRUNCATED
----------------------------------------------------------------------------------------------------
:func:`parse_source_timestamp` is the single entry point for turning a source's own timestamp text
into an aware :class:`~datetime.datetime`. Nothing under ``monitor/aggregator/`` reads a clock, for
the reason ``emit.py`` sets out and ``scripts/monitor_guard.sh`` block (b) trips on.

Two properties of that function are decisions rather than details. A timestamp without an offset is
**rejected**, not assumed to be UTC: assuming is how a timezone bug becomes a silent one, and the
frozen contract requires an aware value anyway. And Falco reports nanoseconds while
:class:`~datetime.datetime` resolves microseconds, so the last three digits are **truncated**, not
rounded -- truncation is total and has no tie-breaking rule to get wrong, whereas rounding does.
Nothing is lost that matters: the raw timestamp text goes into the identifier projection's
per-source discriminator (``normalize.py``), so two records one nanosecond apart still receive
different identifiers even though they share a ``ts``.

ABSENCE IS A FIRST-CLASS CASE, AND THE THREE SPELLINGS OF IT ARE HANDLED IN ONE PLACE
--------------------------------------------------------------------------------------
Real telemetry spells "this field has no value" three ways: the key is missing, the value is
``null``, or the value is the placeholder a formatter substituted -- Falco writes ``<NA>`` into an
output field it could not resolve. :func:`optional_text` collapses all three to ``None`` so that no
normaliser has to remember the third one, and so that ``<NA>`` can never reach an
``EvidenceEvent`` as though it were a namespace or a pod name that somebody created.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
:class:`NormalisedRecord` is the interface between the four normalisers and everything downstream;
changing a field changes all four modules, ``normalize.py``'s identifier projection and therefore
every ``event_id`` in the golden corpus. :class:`RecordLocator` is what tells the reader where a
source's records live inside its file, so a change there re-points the reader at a different part of
the document and invalidates every ``raw_ref`` offset in the corpus.
"""

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final

from monitor.aggregator.models import EvidenceSeverity, EvidenceSource, ResourceRef

# The placeholder Falco substitutes into an output field it could not resolve. Treated as absence
# rather than as text; see the module docstring.
UNRESOLVED_FIELD_PLACEHOLDER: Final = "<NA>"

# A conservative RFC 3339 shape check applied before the interpreter's own ISO-8601 parser runs.
# The parser shipped with the pinned interpreter accepts a good deal more than RFC 3339 -- a space
# in place of the "T", a missing offset -- and every one of the four sources emits RFC 3339, so
# admitting the wider grammar would only mean accepting a malformed fixture quietly. The offset is
# required by the grammar, which is what makes "naive timestamps are rejected" a property of the
# pattern rather than of a later check somebody could remove.
_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$")


class NormalisationError(ValueError):
    """Base class for every way a raw record can fail to become a :class:`NormalisedRecord`.

    One base so that ``normalize.py`` can report "this record could not be normalised" while the
    subclasses stay specific enough to act on. Every subclass names the offending field and the
    source family in its message, because the reader of that message is looking at a fixture file
    and needs to know which line of which document to open.
    """


class MissingSourceField(NormalisationError):
    """A field the source's own contract guarantees is absent, empty, or of the wrong type."""


class SeverityNotRecognised(NormalisationError):
    """A severity token outside the vocabulary ``models.py`` documents for that source.

    Never a guess and never a fallback to ``info``. ``models.py``'s mapping table is the whole
    normalisation, and a token outside it means either the source changed or the fixture is wrong;
    silently ranking it would put a value into Chapter 4 that no rule produced.
    """


class TimestampNotUsable(NormalisationError):
    """A timestamp that is absent, not RFC 3339, or carries no UTC offset."""


class AuditSeverityNotAssigned(NormalisationError):
    """A Kubernetes audit record reached the normaliser with no severity assigned to it.

    The audit stream carries no severity, and its ``level`` field is a verbosity setting rather
    than a ranking -- ``models.py`` sets out at length why reading ``level`` as severity would rank
    a fully recorded ConfigMap read above a metadata-only privilege escalation. Severity for an
    audit event is assigned by the audit rule that selected it, and that rule set is authored at
    T2.4 with the audit policy. Until it exists the assignment must be supplied explicitly, and
    this error is what makes forgetting to supply it impossible rather than merely discouraged.
    """


class RecordLayout(StrEnum):
    """How a source's raw input file is laid out, and therefore how records are located in it.

    Two layouts cover all four families and no third is admitted, because a layout this reader half
    understands is a layout whose ``raw_ref`` offsets cannot be trusted.

    ``JSON_LINES`` -- one complete JSON object per line, which is how Falco writes alerts to a file
    sink and how an audit log file is written. A record's byte span is the line's own bytes.

    ``JSON_DOCUMENT`` -- one JSON document holding an array of records, which is what an
    Alertmanager webhook body and a Trivy report are. A record's byte span is the span of its own
    array element inside that document, computed exactly rather than approximated by pointing every
    record at the whole file.
    """

    JSON_LINES = "json_lines"
    JSON_DOCUMENT = "json_document"


@dataclass(frozen=True, slots=True)
class RecordLocator:
    """Where one source's records live inside its raw input, declared as data rather than as code.

    Data rather than a per-source reader function, because the reading -- byte spans included -- is
    one algorithm that must behave identically for every source, and four hand-written readers would
    be four chances to compute an offset differently.

    ``document_context`` names top-level keys copied onto every record from that document, and
    ``group_context`` names keys copied from the enclosing group element. Both exist because two of
    the four families put facts a normaliser needs *outside* the record: a Trivy vulnerability does
    not carry the name of the image it was found in, nor the time the report was produced, and both
    are needed to build an event. Copying them onto the record is what keeps the normaliser a
    function of one record, rather than of one record plus a document it has to go and find.

    ``group_key`` is for the one source whose records are nested two levels deep -- Trivy's
    ``Results[].Vulnerabilities[]``. Where it is ``None`` the records array sits at the top level.

    ``required_document_values`` declares upstream version discriminators that apply to the whole
    JSON document. Keeping them on the locator makes the reader reject an unsupported document even
    when its records array is empty; checking only in a per-record normaliser would silently accept
    that case.
    """

    layout: RecordLayout
    record_key: str | None = None
    document_context: tuple[str, ...] = ()
    group_key: str | None = None
    group_context: tuple[str, ...] = ()
    required_document_values: tuple[tuple[str, object], ...] = ()


@dataclass(frozen=True, slots=True)
class RawRecord:
    """One raw source record, with the byte span it occupies in the file it was read from.

    ``offset`` and ``length`` are what ``raw_ref`` is built from, and they are byte quantities in
    the file's UTF-8 encoding rather than character positions, because the pointer has to resolve
    with a seek and a read of ``length`` bytes in any language. ``length`` is the span of the record
    itself: for a line-oriented layout it excludes the line terminator, because the terminator is
    framing and not part of the record.

    ``context`` holds whatever :class:`RecordLocator` declared should travel with the record. It is
    empty for the two line-oriented families, whose records are self-contained.
    """

    value: Mapping[str, Any]
    offset: int
    length: int
    context: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class NormalisedRecord:
    """One source record expressed in the target vocabulary: pre-cap, pre-quoting, unordered.

    Every string here is **source text as the source wrote it**, before any cap and before any
    escaping. That is not an implementation convenience; it is the ordering ADR-019 makes
    load-bearing. Caps count source characters, so they have to be applied to exactly this text,
    and quoting has to come after them or the ``G3-UNQUOTED`` arm changes how much evidence reaches
    the Orchestrator as well as how it is escaped -- two properties where section 3.5.4 permits one.

    ``excerpt_candidates`` is an ordered sequence and the order is the normaliser's declared
    significance order, most identifying first. It is not a set and must never be built from one:
    ``caps.py``'s selection rule is "the first N survive", so the order *is* the contract for which
    evidence a reader sees when the count cap binds.

    ``discriminator`` is the source's own natural key -- the fields that make one record of that
    family distinguishable from another. It is a tuple of pairs rather than a mapping so that its
    order is fixed by the normaliser and cannot be reshuffled; ``normalize.py`` folds it into the
    identifier projection. Values are the *raw* source strings, not the normalised ones, so that
    precision the normalisation truncates -- Falco's nanoseconds, most obviously -- still separates
    two records that would otherwise project identically.

    ``signal_id`` is the source's own structured detection signal -- Falco ``rule``, Alertmanager
    ``labels.alertname``, the audit ``verb:objectRef.resource`` pair, Trivy ``VulnerabilityID`` --
    or ``None`` where the source has none (a non-resource Kubernetes audit URL). Each normaliser
    reads it from the one field its family carries it in; ``normalize.py`` folds it into the
    identity
    projection before caps and quoting, and ``models.py`` carries it onto every ``EvidenceEvent``.
    It is the sensor-level identifier detection precision and recall are computed from (V8), and it
    is nullable-with-no-default for the reason the ``EvidenceEvent`` contract states.
    """

    source: EvidenceSource
    ts: datetime
    severity: EvidenceSeverity
    signal_id: str | None
    resource: ResourceRef
    summary: str
    excerpt_candidates: tuple[str, ...]
    discriminator: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class NormaliserOptions:
    """Per-run inputs a normaliser may need that are not in the record.

    Exactly one field today, and the module docstring explains why it lives in a shared object
    rather than in a per-source keyword.

    ``audit_severity`` is the severity assigned to every Kubernetes audit record in this run. It is
    ``None`` by default and the audit normaliser refuses to run without it, which is deliberate:
    the per-rule assignment is authored at T2.4 with the audit policy, and a default here would
    quietly rank every audit event in the corpus at whatever level happened to be convenient.
    """

    audit_severity: EvidenceSeverity | None = None


# The signature every normaliser satisfies. Named so that the registry in normalize.py can be typed
# against one thing rather than against four function objects that merely happen to agree.
Normaliser = Callable[[RawRecord, NormaliserOptions], NormalisedRecord]


def parse_source_timestamp(text: object, *, source: str, field_name: str) -> datetime:
    """Return ``text`` as an aware UTC datetime, or raise :class:`TimestampNotUsable`.

    See the module docstring for why a naive timestamp is rejected rather than assumed to be UTC,
    and why sub-microsecond precision is truncated rather than rounded. ``source`` and
    ``field_name`` appear in the failure message because the reader of that message is holding a
    fixture file open and needs to know which key of which document to look at.
    """
    if not isinstance(text, str) or not text:
        raise TimestampNotUsable(
            f"{source}: {field_name} is {text!r}; a source timestamp must be a non-empty "
            "RFC 3339 string, and the aggregator never substitutes a clock reading for one"
        )
    if _RFC3339.match(text) is None:
        raise TimestampNotUsable(
            f"{source}: {field_name} is {text!r}, which is not RFC 3339 with a UTC offset. A "
            "timestamp without an offset is rejected rather than assumed to be UTC, because "
            "assuming is how a timezone error becomes a silent one."
        )
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None or parsed.tzinfo.utcoffset(parsed) is None:
        raise TimestampNotUsable(f"{source}: {field_name} is {text!r} and carries no UTC offset")
    return parsed.astimezone(UTC)


def optional_text(value: object) -> str | None:
    """Return ``value`` as a non-empty string, or ``None`` for any of the three spellings of absent.

    Absent means: not a string at all (which covers a missing key read through ``.get`` and an
    explicit ``null``), the empty string, a string that is only whitespace, or Falco's ``<NA>``
    placeholder. See the module docstring for why the last one is handled here rather than in the
    one normaliser that meets it.
    """
    if not isinstance(value, str):
        return None
    if not value.strip() or value == UNRESOLVED_FIELD_PLACEHOLDER:
        return None
    return value


def require_text(record: Mapping[str, Any], key: str, *, source: str) -> str:
    """Return ``record[key]`` as a non-empty string, or raise :class:`MissingSourceField`.

    For the fields a source's own contract guarantees. Using it says "the upstream document
    promises this key", so a failure here is a malformed record or a changed upstream shape, and
    either is worth stopping for rather than working around with a placeholder that would then read
    as evidence.
    """
    text = optional_text(record.get(key))
    if text is None:
        raise MissingSourceField(
            f"{source}: required field {key!r} is missing, empty or not a string "
            f"(value {record.get(key)!r})"
        )
    return text


def rendered_pairs(
    mapping: Mapping[str, Any], *, keys: Sequence[str], prefix: str = ""
) -> tuple[str, ...]:
    """Render ``keys`` of ``mapping`` as ``prefix + key=value`` candidates, in the order given.

    In the order given, never in the mapping's own order: dictionary iteration order is an input
    property in Python and a source-format property in JSON, and an emission that depended on it
    would pass the twice-and-diff on the machine that wrote the fixture and fail on the next reader.
    Absent values are skipped rather than rendered as ``key=None``, because an excerpt naming a
    field that had no value spends a capped slot on nothing.

    ``prefix`` exists for the one source that carries two separate string maps -- Alertmanager's
    ``labels`` and ``annotations`` -- where an unprefixed rendering would leave a reader unable to
    tell which map a pair came from, and two maps sharing a key would render identically.
    """
    rendered: list[str] = []
    for key in keys:
        text = optional_text(mapping.get(key))
        if text is not None:
            rendered.append(f"{prefix}{key}={text}")
    return tuple(rendered)


def remaining_pairs(
    mapping: Mapping[str, Any], *, exclude: Sequence[str], prefix: str = ""
) -> tuple[str, ...]:
    """Render every key of ``mapping`` not in ``exclude`` as ``prefix + key=value``, sorted by key.

    Sorted lexicographically, which is an explicit total order over the keys and therefore
    reproducible, rather than the order the JSON parser happened to build the object in. This is
    the tail of a normaliser's candidate list: the fields it does not rank get to compete for
    whatever excerpt slots the ranked ones leave, and they compete in an order a reader can predict.

    A value that is not a string is rendered with ``str`` rather than dropped, so that a numeric
    label or a boolean annotation still becomes evidence; a nested object is rendered the same way
    and is bounded by the length cap like anything else.
    """
    rendered: list[str] = []
    for key in sorted(mapping):
        if key in exclude:
            continue
        value = mapping[key]
        text = optional_text(value) if isinstance(value, str) else str(value)
        if text is not None and text != "":
            rendered.append(f"{prefix}{key}={text}")
    return tuple(rendered)
