r"""The frozen ``EvidenceEvent`` v2 contract -- the only thing the Monitor is allowed to say.

WHAT THIS MODULE IS
-------------------
``docs/02-architecture.md`` section 3 declares the interface contracts of this system schema-first,
and names ``EvidenceEvent`` as the Monitor-to-Orchestrator one. This module is that declaration made
executable. Every fact the agent layer ever learns about the environment arrives as an instance of
:class:`EvidenceEvent` and in no other shape, which is what makes a schema freeze here worth more
than the code that enforces it: M4 builds the agent layer against a fixed contract precisely because
M2 froze it first.

``docs/adr/ADR-019-evidence-event-schema-and-determinism.md`` is the decision record behind this
file and behind the rest of the aggregator's determinism mechanics. Where a paragraph below states
a decision, ADR-019 states the alternatives that were rejected to reach it; the two are meant to be
read together, and any conflict between them is ADR-019's to win, because a decision record outranks
the code that implements it.

THE FIELD LIST IS ARCHITECTURE SECTION 3'S, AND CANNOT BE EXTENDED HERE
-----------------------------------------------------------------------
Section 3 states it in one sentence: ``event_id, ts, source`` in ``{falco, prometheus, k8s_audit,
trivy}``, ``signal_id`` (nullable), ``severity``, ``resource {ns, kind, name}``, ``summary``
(bounded), ``evidence_excerpts[]`` (each quoted/escaped, length-capped), ``raw_ref`` (pointer,
never inline), ``schema_version``. Ten fields, no more and no fewer, and this module implements
exactly that set in exactly that order.

Adding an eleventh field is not a change to this file. ``docs/02-architecture.md`` sits above code
in the precedence order that ``.agents/rules/00-source-of-truth.md`` fixes, so a field this module
carries and section 3 does not is a conflict to be reported, not a convenience to be taken.
``monitor/tests/test_schema.py`` spells section 3's ten names out independently and compares them
to this model, so a field added here without the architecture edit fails a test rather than quietly
widening the contract that four other milestones build against. ``signal_id`` itself was the tenth,
added at M10 alongside the architecture edit and the ``schema_version`` bump to ``v2`` that ADR-125
records -- the worked example of exactly that discipline, an addition to the frozen contract carried
in the architecture first and mirrored here second.

``signal_id`` IS THE SENSOR'S OWN SIGNAL, AND IT IS NULLABLE BECAUSE ONE SOURCE HAS NONE
----------------------------------------------------------------------------------------
Every event already carries ``source`` -- which of the four families produced it -- but not *which
signal within that family* fired. ``signal_id`` is that: the source's own structured detection
identifier, before this module reduces it to prose. It is Falco's ``rule``, Alertmanager's
``labels.alertname``, the Kubernetes audit ``verb:objectRef.resource`` pair, and Trivy's
``VulnerabilityID`` -- read by the per-source normalisers under ``monitor/aggregator/sources/`` and
never composed here. FR-detection (V8) needs a sensor-level identifier per event to compute
detection precision and recall, and a value recovered downstream from the capped, quoted excerpt
would be lossy and arm-dependent; captured at the source, before caps, it is neither.

It is nullable and carries **no default**, which is the same discipline ``resource.ns`` follows and
for the same two reasons. Nullable, because the Kubernetes audit stream's non-resource requests --
``/healthz``, the discovery endpoints -- have no ``verb:resource`` pair to name, and a sentinel
string would read downstream as a signal nobody raised. No default, because the key is required in
the serialised form regardless: a consumer never has to distinguish "absent" from "not applicable",
and an event that reached this boundary without the field set is a normaliser defect to be caught
here rather than three components downstream. ``signal_id`` joins the identity projection
(``normalize.py``) *before* capping and quoting, so it is byte-identical across the G3 arms and does
not disturb the isolation property ``event_id`` exists to hold. It is never rendered into the
agent-visible evidence text; that exclusion is enforced on the agent side (the SEAM-8 renderer).

THE MODEL IS THE SHAPE, NOT THE BOUND -- NO CAP VALUE APPEARS IN THIS FILE
--------------------------------------------------------------------------
Section 3's own note is ``Caps (count/length) owned by evaluation-protocol section 4``, and
``evaluation-protocol.md`` section 0 lists both the evidence caps and the Monitor latency budget as
values "set at M2; recorded here". Under ADR-016's settled pattern the protocol owns them, code
mirrors them in ``monitor/aggregator/limits.py``, a test parses the protocol and asserts the mirror
agrees, and the aggregator carries no default for any of them -- it fails closed with a named error
when one is unset, so that a fixture corpus cannot go green against a number nobody measured.

This module therefore carries no ``max_length``, no ``max_items`` and no default that encodes a
bound. Enforcement is ``caps.py``'s, and it happens *before* an event is constructed rather than
after: the plan's ordering is normalise, select excerpts, apply the count and length caps to the raw
source text, then quote. That ordering exists so that the G3-UNQUOTED arm removes exactly one
property -- escaping -- rather than two, and a cap applied here, to already-quoted text, would break
it. A model that clipped its own fields would be a second, silent enforcement point on an axis the
protocol owns.

The distinction that decides what *may* appear here is ownership of the axis, not the direction of
the inequality. On the three content axes -- summary text, excerpt text, excerpt count -- section 4
owns every bound, so this model states none, not even a floor: an empty summary is a normaliser
defect and is caught there. On the structural axes it states plenty, because no protocol owns them
and they are facts rather than policy: a SHA-256 digest is sixty-four lowercase hex characters, a
byte offset is not negative, a root-relative path has no root. Those constraints are what make
"``event_id`` is a digest, not a generated identifier" and "``raw_ref`` is never absolute" checkable
properties instead of comments.

WHY THE CONTRACT FORBIDS EXTRA KEYS AND WHY INSTANCES ARE FROZEN
----------------------------------------------------------------
``extra="forbid"``: an unknown key is an error, not something silently dropped. A tolerant model
would let a normaliser emit a field that the schema does not describe, that the exported JSON Schema
does not mention and that no consumer reads -- and would let it do so for as long as nobody looked.
For a contract whose whole purpose is to be frozen, "unknown means rejected" is the only setting
that keeps the frozen document and the running code describing the same object.

``frozen=True``: an event is a record of something that happened, and nothing downstream has any
business editing one. The usual objection -- that freezing fights the construction path -- does not
apply, because of the cap ordering above. Caps and quoting are transformations of *source text* and
run before any event exists, so nothing needs to mutate a built event, and no consumer is pushed
towards ``model_copy(update=...)``, which would bypass validation and is exactly the escape hatch a
frozen contract must not offer. ``evidence_excerpts`` is a ``tuple`` rather than a ``list`` for the
same reason: ``frozen=True`` blocks rebinding an attribute but not an in-place ``append``, which
would otherwise leave the one field the G3 isolation test compares across arms mutable by anyone
holding a reference.

``schema_version`` IS REQUIRED, AND ITS SPELLING IS DELIBERATE
--------------------------------------------------------------
A consumer must be able to reject an event of a version it does not understand. A field with a
default defeats that outright: an event serialised by some future writer that omitted the key would
be silently *stamped* with this version on the way in, and the one check that could have caught a
contract mismatch becomes the thing that hides it. So the field is required, it has no default, and
it is typed ``Literal[SCHEMA_VERSION]`` -- which means the rejection is performed by the model
itself, and, because Pydantic exports a single-member ``Literal`` as ``const``, by the exported JSON
Schema too, for consumers that are not written in Python.

The value is the string ``"v2"`` -- the contract's second version, ``signal_id`` being what the
bump records (ADR-125) -- and the spelling was chosen against two alternatives. ``"1"``
invites arithmetic: a reader who sees ``2`` concludes it is newer and probably compatible, which for
an ``extra="forbid"`` contract is false -- there is no such thing as a compatible change to it.
``"1.0"`` is worse, because semantic versioning explicitly promises that a minor bump is compatible.
A non-numeric token can only be compared for membership in a known set, which is precisely the check
a consumer is supposed to perform. It also matches the tracked artefact's filename character for
character -- :data:`SCHEMA_RELATIVE_PATH` is built from :data:`SCHEMA_VERSION`, so a version bump
that does not come with a new schema file fails at the point the tracked file is looked up.

SEVERITY: ONE NORMALISED SCALE, AND THE MAPPING ONTO IT WRITTEN DOWN
--------------------------------------------------------------------
The four sources share no severity vocabulary, and one of them has no severity at all. Section 3
names the field and leaves the vocabulary open, so this module fixes it: five ordered levels,
``critical`` through ``info``, declared most severe first, with the enum's own iteration order being
that order. A normalisation that is not written down is a normalisation nobody can reproduce, so
the mapping from each source's vocabulary onto the scale is stated here, in the file that defines
the target::

    normalised | Falco priority          | Prometheus severity | Trivy    | Kubernetes audit
    -----------+-------------------------+---------------------+----------+------------------
    critical   | emergency, alert,       | critical            | CRITICAL | assigned by the
               | critical                |                     |          | audit rule that
    high       | error                   | --                  | HIGH     | selected the event;
    medium     | warning                 | warning             | MEDIUM   | never read from
    low        | notice                  | --                  | LOW      | the record, for the
    info       | informational, debug    | info                | UNKNOWN  | reason below

Four notes, each of which is a decision and not an observation:

*Falco* uses the eight syslog priorities (``emergency``, ``alert``, ``critical``, ``error``,
``warning``, ``notice``, ``informational``, ``debug``). Eight onto five loses resolution at the top,
where ``emergency``, ``alert`` and ``critical`` all collapse to ``critical``. That is intentional:
the distinction between them is a syslog convention about who gets woken up, and the Orchestrator's
triage does not act on it.

*Prometheus* has no severity in its alerting data model at all -- ``severity`` is a label applied by
convention, and its values are whatever the alert rules say. The rules this project writes are the
authority for what can appear, and they are written at T2.3 to emit only ``critical``, ``warning``
and ``info``; the two blank cells above are blank because those values will not be produced, not
because they were forgotten. A label outside that set is a normalisation failure with a named
error, never a guess. Note that ``warning`` maps to ``medium`` from both Falco and Prometheus: the
same word from two sources must not mean two different things after normalisation, or a
cross-source comparison in Chapter 4 compares vocabulary rather than severity.

*The Kubernetes audit stream carries no severity, and its ``level`` field must not be mistaken for
one.* Audit ``level`` takes ``None``, ``Metadata``, ``Request`` or ``RequestResponse`` and describes
*how much of the request and response was recorded* -- it is a verbosity setting configured in the
audit policy, and it says nothing about danger. Reading it as severity would rank a fully recorded
read of a ConfigMap above a metadata-only privilege escalation, and would do so consistently enough
to look like a finding. Severity for an audit event is therefore assigned by the audit rule that
selected the event, authored at T2.4 with the audit policy itself.

*Trivy* reports ``CRITICAL``, ``HIGH``, ``MEDIUM``, ``LOW`` and ``UNKNOWN``. The first four map
across on the obvious diagonal. ``UNKNOWN`` maps to ``info`` because ``info`` is the floor of this
scale and means "recorded, not ranked as actionable"; a finding the scanner declined to rank must
not be promoted above one it explicitly ranked ``LOW``, and the alternative -- an ``unknown`` member
on the scale -- would put a non-ordinal value into an ordered vocabulary and make every comparison
against it undefined.

The *implementation* of this mapping is ``normalize.py``'s, not this module's. The table is
documented here because this is where the target vocabulary is defined; a second copy of it as code
here would be a second home for one decision, which is the thing
``.agents/rules/00-source-of-truth.md`` exists to prevent.

``raw_ref`` IS A POINTER, AND "NEVER ABSOLUTE" IS ENFORCED RATHER THAN ASSERTED
-------------------------------------------------------------------------------
Section 3 says ``raw_ref (pointer, never inline)``, and the reason is the one FR1.2 gives: the
Monitor emits curated, bounded events rather than raw telemetry, so the raw record stays where it
was captured and the event carries the address of it. :class:`RawRef` is that address -- a path, a
byte offset and a byte length -- and it can carry no content by construction, because it has no
field that could hold any.

The path is *root-relative*: relative to the repository root during fixture replay, and to the run
bundle root in a live run. It carries no root of its own, and the enforcement of that is
:data:`RAW_REF_PATH_PATTERN`, applied as a string constraint so that it appears in the exported JSON
Schema as ``pattern`` and therefore binds consumers written in any language, not only this one. An
absolute path would encode the host that produced it, which breaks the byte diff across machines
while passing perfectly on the machine it was produced on -- the worst failure shape available,
because the milestone's Definition of Done is a ``cmp`` and a green local run would be evidence of
nothing.

The pattern is a positive grammar rather than a list of prohibitions, for a reason worth recording:
Pydantic compiles string patterns with the Rust ``regex`` engine, which does not support lookahead,
so the negative formulation -- "not starting with a slash, not containing a colon, not containing a
dot-dot segment" -- is not expressible either here or, dialect aside, reliably in the exported
schema. A path is instead defined as one or more ``/``-separated segments, each beginning with a
character from ``[A-Za-z0-9_-]`` and continuing over ``[A-Za-z0-9._-]``. That single line rejects,
without a lookahead: a leading ``/``; a Windows drive letter, whether written ``C:\`` or ``C:/``,
because a colon is outside the alphabet; a UNC path and any other backslash, for the same reason;
any URI scheme, again on the colon; an empty segment from ``//`` or a trailing ``/``; whitespace;
and -- because a segment may not *begin* with a dot -- the ``.`` and ``..`` segments that would
otherwise let a relative path escape its root and let two different strings denote one file. The
cost of the leading-dot rule is that a dotfile cannot be referenced. Nothing this pointer may
legitimately address is a dotfile: the raw sources are fixture inputs and run bundle members, all
named by this project's own identifier grammars.

``length`` is the size of the referenced slice, not a bound on it, and has nothing to do with the
excerpt length cap that section 4 owns. It exists because the four sources are not all
line-oriented: an offset alone is a resolvable pointer into a JSONL stream, where the record ends at
the next newline, and an unresolvable one into a Trivy JSON report. With the length present,
"resolve this pointer" is a total operation and an excerpt's provenance can be checked byte for
byte against the raw record it claims to come from.

WHERE ``event_id`` AND ``ts`` COME FROM, SINCE THEY ARE NOT COMPUTED HERE
-------------------------------------------------------------------------
Neither is derived in this module, and a reader should not go hunting.

``event_id`` is a SHA-256 digest over a canonical projection of the source record's own fields,
computed by ``monitor/aggregator/emit.py``. It is never a freshly generated UUID: a generated
identifier differs on every replay and makes the twice-and-diff unpassable by construction, which is
why ``scripts/monitor_guard.sh`` block (b) treats one under this directory as a failure. The digest
shape is pinned here by :data:`EVENT_ID_PATTERN` so that the wrong construct is rejected at the
contract boundary as well as caught by the guard, but the projection -- which fields, in which
order -- belongs with the emitter, because it must be one function and this module must stay free of
anything that could become a second one.

``ts`` is the *source record's* timestamp, read by the per-source normalisers under
``monitor/aggregator/sources/`` and never from a clock. It is required to be timezone-aware and is
converted to UTC on the way in. The conversion is a deliberate normalisation rather than a
convenience: two sources reporting the same instant with different offsets would otherwise serialise
to different bytes, and the offset a source happens to use is a property of the host it runs on,
which is exactly the kind of host-dependence that breaks a cross-machine diff. Nothing is lost --
the instant is preserved exactly -- except the emitter's local offset, which was never evidence. A
naive timestamp is rejected outright rather than assumed to be UTC, because assuming is how a
timezone bug becomes a silent one.

Latency figures are deliberately absent from this contract. They are wall-clock and
machine-dependent, and one such field in ``monitor_events.jsonl`` would make the twice-and-diff
unpassable forever; they are recorded separately in ``latency.json``, which is not diffed.

CANONICAL JSON: THE ONE FUNCTION WHOSE OUTPUT BYTES ARE THE CONTRACT
---------------------------------------------------------------------
``docs/protocols/data-management.md`` section 1 puts ``monitor_events.jsonl`` in every run bundle,
and M2's Definition of Done compares two replays of it with ``cmp``. :func:`canonical_json_line` is
therefore not a formatting helper; its output bytes *are* the deliverable, and each of its choices
exists because the diff would otherwise fail:

``sort_keys=True`` so that key order is a property of the contract rather than of the order in which
a normaliser happened to build a dictionary. ``separators=(",", ":")`` so that no incidental
whitespace enters, and so that the size of a bundle is not inflated by it. ``ensure_ascii=True`` so
that every byte written is ASCII: Falco reports process arguments verbatim and they can hold
arbitrary UTF-8, and escaping it means the file compares identically regardless of the locale or
console encoding of whatever writes, reads or re-encodes it downstream -- which on a project
developed on Windows and run under WSL2 is not a hypothetical. ``allow_nan=False`` so that a
non-finite float raises here rather than emitting ``NaN``, which is not JSON and which no
conforming parser will read back. One trailing ``\n`` and no other whitespace, because the file is
JSON Lines.

The function returns ``bytes`` rather than ``str`` on purpose: the contract is a byte sequence, and
returning text would leave the encoding to the caller. For the same reason the caller must write it
to a file opened in **binary** mode. Python's text mode translates ``\n`` to ``\r\n`` on Windows,
and a bundle written that way differs from one written under WSL2 in every single line while looking
identical in every editor.

The exported schema at :data:`SCHEMA_RELATIVE_PATH` is written by the same canonicalisation but a
different whitespace policy -- indented, one key per line -- because it is one small document read
by humans reviewing a frozen contract, whereas the event stream is machine-diffed at run scale. Both
are deterministic; only their readability requirements differ. Note the consequence of sorting: in
the exported schema it is ``required`` that carries section 3's field order, because a JSON array
keeps its order and an object's keys do not survive the sort.

THE EXPORTED SCHEMA CARRIES THE SHAPE AND NOT THE REASONING
------------------------------------------------------------
Pydantic copies each model's docstring into the generated document as a ``description``, and left
alone that would put every paragraph of rationale on this page into the tracked artefact -- roughly
five kilobytes of English inside a contract that describes nine fields. Two things go wrong if it
does. The frozen document then changes whenever the prose does, so a reworded sentence produces a
forty-line diff in the one file a reviewer is supposed to read character by character, which is how
a reviewer learns to skim it. And after the ``v1.0`` freeze, where iron rule 6 makes a change to
behaviour a logged hotfix ADR, "the contract changed" would stop being a reliable signal, because
sometimes it would mean a typo was fixed.

So :func:`evidence_event_json_schema` applies exactly two transformations to Pydantic's output, and
both are mechanical: it removes every ``description``, and it adds ``$schema`` naming the dialect
plus one short top-level ``description`` naming the authority this contract implements. The
structure -- every type, every constraint, every ``$ref``, the ``required`` array -- is entirely
generated and nothing in it is written by hand. Because the writer and the drift test both call
that one function, the tracked file stays a pure function of the model. The reasoning stays here,
next to the code it explains, which is where a maintainer will look for it; the artefact stays a
contract, which is what a consumer needs from it.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
Everything downstream, which is the point of freezing it. ``monitor/aggregator/`` normalises into
this shape; ``monitor/fixtures/*/expected/monitor_events.jsonl`` are golden files whose bytes were
produced by :func:`canonical_json_line`, so any change to the serialiser invalidates the entire
corpus at once; ``monitor_events.jsonl`` in every sealed run bundle is this format, and
``docs/protocols/data-management.md`` section 3 refuses to seal a bundle without it; and M4's agent
layer parses it. After the pilot gate freeze at ``v1.0``, iron rule 6 makes a change here a logged
hotfix ADR rather than an edit.

``python -m monitor.aggregator.models`` regenerates the tracked JSON Schema from this model. It
writes the file directly instead of printing to standard output, because a shell redirection on a
Windows host would introduce exactly the CRLF translation the paragraph above warns about.
"""

import json
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Final, Literal

from pydantic import AfterValidator, AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints
from pydantic.json_schema import GenerateJsonSchema

# The version token of this contract. See the module docstring for why it is a non-numeric string
# and not "1" or "1.0". It is the sole home of the value: the field type, the tracked schema
# filename and the path constant below are all derived from it, so a bump cannot half-happen. It
# moved from "v1" to "v2" at M10 when signal_id was added (ADR-125).
SCHEMA_VERSION: Final = "v2"

# The tracked export of this model's JSON Schema, and its location relative to the repository root.
# Built from SCHEMA_VERSION rather than spelled out, so that bumping the version points the lookup
# at a file that does not exist yet -- which is the correct, loud failure for a version bump that
# arrives without its artefact.
SCHEMA_FILENAME: Final = f"evidence_event.{SCHEMA_VERSION}.json"
SCHEMA_RELATIVE_PATH: Final = f"monitor/aggregator/schema/{SCHEMA_FILENAME}"

# event_id is a SHA-256 digest rendered as lowercase hexadecimal, computed by emit.py over a
# canonical projection of the source record. The width and the alphabet are properties of SHA-256,
# not a cap: nothing in evaluation-protocol section 4 owns them. Pinning the shape here means the
# wrong construct -- a generated identifier, an upper-case digest, a truncated one -- is rejected at
# the contract boundary rather than only greppable after the fact.
EVENT_ID_PATTERN: Final = r"^[0-9a-f]{64}$"

# A root-relative path: one or more '/'-separated segments, each starting with a character that is
# not a dot and continuing over the same alphabet plus dots. Stated positively because Pydantic
# compiles patterns with an engine that has no lookahead; see the module docstring for the full list
# of what this one line rejects and why the leading-dot rule is the part that kills '.' and '..'.
RAW_REF_PATH_PATTERN: Final = r"^[A-Za-z0-9_-][A-Za-z0-9._-]*(?:/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$"

# The one sentence of prose the exported schema keeps, in place of the model docstrings that are
# stripped from it. It names the authority rather than restating it, so that a consumer holding only
# the JSON file knows which document governs and where the reasoning lives.
SCHEMA_DESCRIPTION: Final = (
    "EvidenceEvent v2 -- the Monitor-to-Orchestrator contract declared in docs/02-architecture.md "
    "section 3. Count and length caps are owned by docs/protocols/evaluation-protocol.md section 4 "
    "and are enforced before an event is constructed, so they are deliberately absent here. "
    "Generated from monitor/aggregator/models.py; regenerate with "
    "`python -m monitor.aggregator.models` rather than editing."
)


def _to_utc(value: datetime) -> datetime:
    """Return ``value`` expressed in UTC, preserving the instant exactly.

    Only ever reached with a timezone-aware value, because :data:`EventTimestamp` composes this with
    Pydantic's aware-datetime type, which rejects a naive one before this runs. See the module
    docstring for why the conversion is deliberate rather than incidental.
    """
    return value.astimezone(UTC)


# The three constrained scalar types, named so that the model body below reads as section 3's
# sentence rather than as a wall of annotations.
EventId = Annotated[str, StringConstraints(pattern=EVENT_ID_PATTERN)]
EventTimestamp = Annotated[AwareDatetime, AfterValidator(_to_utc)]
RawRefPath = Annotated[str, StringConstraints(pattern=RAW_REF_PATH_PATTERN)]


class EvidenceSource(StrEnum):
    """The four signal families section 3 admits, in the order section 3 lists them.

    An enum rather than a ``Literal`` for three reasons. It gives the four names one importable
    home, so the ordered source registry the emitter iterates and the per-source normalisers refer
    to the same definition instead of restating four strings each; the declaration order is stable
    and is what the emitter's ``source_rank`` tie-break is defined against, so the total emission
    order ``(source_ts, source_rank, event_id)`` has somewhere to come from; and Pydantic exports it
    as a named ``$defs`` entry, which documents the closed vocabulary in the frozen schema instead
    of inlining four strings at the use site. Being a ``StrEnum``, members compare equal to their
    values and serialise as plain strings, so the JSON is identical to what a ``Literal`` produces.

    The order is section 3's own and is deliberately not re-sorted: a reader comparing this class to
    the architecture sentence should find them in the same sequence. Which family answers to which
    dissertation signal family is ADR-018's question, not this module's.
    """

    FALCO = "falco"
    PROMETHEUS = "prometheus"
    K8S_AUDIT = "k8s_audit"
    TRIVY = "trivy"


class EvidenceSeverity(StrEnum):
    """The normalised severity scale, declared most severe first.

    Five levels, and the enum's iteration order *is* the ordering -- there is no second constant
    holding a rank, because two homes for one ordering is one home too many. The mapping from each
    source's own vocabulary onto these five is stated in full in the module docstring and
    implemented in ``normalize.py``; this class defines only the target.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class _ContractModel(BaseModel):
    """Shared configuration for every model in the v1 contract.

    One base rather than three copies of ``model_config``, so that "unknown key is an error" and
    "an event cannot be edited after it exists" cannot hold for the outer model and quietly not hold
    for a nested one. The reasoning for both settings is in the module docstring. The class is
    private because it is a configuration detail of this contract and not a base for anything else
    to build on; a model in another component that wants these settings should say so itself.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)


class ResourceRef(_ContractModel):
    """The Kubernetes subject an event is about: section 3's ``resource {ns, kind, name}``.

    ``ns`` is nullable and the other two are not, which is a decision about what the four sources
    can actually supply. A cluster-scoped object -- a ClusterRole or a Node from the audit stream --
    has no namespace, and neither does a Trivy finding that has not been attributed to a workload.
    The key is still required in the serialised form, so a reader never has to distinguish "absent"
    from "not applicable"; the value is ``null``, which forces a consumer to handle the case rather
    than to find the empty string and guess. Nullable now is cheap; nullable after the ``v1.0``
    freeze is impossible, and the alternative -- a sentinel string -- reads as data and would end
    up in Chapter 4 as a namespace nobody created.

    No syntactic constraint is placed on any of the three, and the omission is deliberate. It is
    tempting to require DNS-1123 of ``name`` and ``ns``, but ``kind`` is PascalCase and is not a DNS
    name at all, and a Trivy subject may be an image reference rather than an API object. A pattern
    here would encode an assumption about a field that the four sources fill differently, and would
    reject valid evidence at the one boundary that must never lose it.
    """

    ns: str | None
    kind: str
    name: str


class RawRef(_ContractModel):
    """A pointer to the raw record an event was derived from. Carries no content, by construction.

    See the module docstring for the path grammar, for why "never absolute" is enforced by a pattern
    that reaches the exported JSON Schema, and for why ``length`` is present at all.
    """

    path: RawRefPath
    # ge=0 and ge=1 are domain invariants of a byte range, not caps: an offset before the start of a
    # file is meaningless and a zero-length slice points at nothing. Neither is owned by
    # evaluation-protocol section 4, and neither bounds any evidence content.
    offset: Annotated[int, Field(ge=0)]
    length: Annotated[int, Field(ge=1)]


class EvidenceEvent(_ContractModel):
    """One curated observation, emitted by the Monitor and consumed by the Orchestrator.

    The fields are architecture section 3's ten, in section 3's order. That order is not cosmetic:
    it is what the ``required`` array of the exported JSON Schema carries, so the frozen artefact
    reads back as the architecture sentence it implements. The canonical serialiser sorts keys, so
    declaration order has no effect on the emitted bytes.

    Every field is required. There is no optional field in this contract and no default anywhere in
    it -- ``signal_id`` is nullable but still required, so an event that omits the key is rejected
    rather than stamped with a default -- because an event that is missing part of itself is a
    normaliser defect, and the place to discover that is the boundary rather than three components
    downstream.
    """

    event_id: EventId
    ts: EventTimestamp
    source: EvidenceSource
    # The source's own structured detection signal, placed here -- after source, before severity --
    # in architecture section 3's own order. Nullable and defaulted nowhere: see the module
    # docstring for why one source (a non-resource Kubernetes audit URL) has no signal to name, and
    # why "required but may be null" is the honest shape rather than an optional field. It is folded
    # into the identity projection before capping and quoting, so event_id stays identical across
    # the
    # G3 arms.
    signal_id: str | None
    severity: EvidenceSeverity
    resource: ResourceRef
    # summary and evidence_excerpts carry no length or count constraint here, by rule. Section 4
    # owns both axes; caps.py enforces them on the pre-quoting source text, before an instance of
    # this model exists. A tuple rather than a list so that frozen=True means what it says.
    summary: str
    evidence_excerpts: tuple[str, ...]
    raw_ref: RawRef
    schema_version: Literal[SCHEMA_VERSION]


def canonical_json_bytes(payload: object) -> bytes:
    """Serialise ``payload`` as one canonical JSON line: sorted, minimal, ASCII, LF-terminated.

    This is the repository's single definition of "canonical JSON" for the event stream, and its
    output bytes are what the determinism ``cmp`` compares. Every argument below is load-bearing and
    is justified in the module docstring. The result is ``bytes`` and must be written to a file
    opened in binary mode.
    """
    text = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return text.encode("utf-8") + b"\n"


def canonical_json_line(event: EvidenceEvent) -> bytes:
    """Serialise one :class:`EvidenceEvent` as a line of ``monitor_events.jsonl``.

    ``mode="json"`` first, so that the enum-to-string and datetime-to-ISO-8601 conversions are
    Pydantic's and are decided in one place, and only then the canonicalisation above. Doing it in
    that order is what makes the emitted bytes a function of the event alone: two events that are
    equal serialise identically no matter which keyword order, which source or which normaliser
    produced them.
    """
    return canonical_json_bytes(event.model_dump(mode="json"))


def _without_descriptions(node: Any) -> Any:
    """Return ``node`` with every ``description`` key removed, at every depth.

    Recursive because Pydantic attaches a description wherever a model has a docstring, which for
    this contract means the root object and three entries under ``$defs``. Lists are walked as well
    as dictionaries so that a future ``anyOf`` or ``prefixItems`` branch cannot smuggle one back in.
    See the module docstring for why the exported contract carries no prose.
    """
    if isinstance(node, dict):
        return {
            key: _without_descriptions(value) for key, value in node.items() if key != "description"
        }
    if isinstance(node, list):
        return [_without_descriptions(item) for item in node]
    return node


def evidence_event_json_schema() -> dict[str, Any]:
    """Return the JSON Schema of :class:`EvidenceEvent`, generated -- never hand-written.

    The structure is entirely Pydantic's. Two mechanical transformations are applied on top, and
    the module docstring explains why each is worth the departure from a bare passthrough.

    The model docstrings are stripped, so that the frozen artefact describes the contract and not
    the rationale behind it. In their place the document gains ``$schema``, naming the dialect, and
    a single short ``description`` naming the governing document. The dialect is read from the
    generator that produced the document rather than spelled out here, so that a Pydantic release
    targeting a different dialect updates the artefact instead of leaving it asserting something
    untrue; a frozen schema published without a dialect is ambiguous to every validator that is not
    this one.
    """
    document: dict[str, Any] = {
        "$schema": GenerateJsonSchema.schema_dialect,
        "description": SCHEMA_DESCRIPTION,
    }
    document.update(_without_descriptions(EvidenceEvent.model_json_schema()))
    return document


def schema_json_bytes() -> bytes:
    """Return the exact bytes of the tracked schema export at :data:`SCHEMA_RELATIVE_PATH`.

    Sorted and ASCII like the event stream, but indented and one key per line, because this document
    is read by humans reviewing a freeze rather than diffed at run scale. ``indent`` makes
    :mod:`json` place each item on its own line, so no line carries trailing whitespace; the single
    closing newline is added here for the same reason every text file in this repository has one.
    """
    text = json.dumps(
        evidence_event_json_schema(),
        sort_keys=True,
        indent=2,
        ensure_ascii=True,
        allow_nan=False,
    )
    return text.encode("utf-8") + b"\n"


def repository_root() -> Path:
    """Return the repository root, derived from this file's own location.

    Never from the working directory, so that a caller reaches the same tracked schema whether it
    was invoked from the repository root, from ``monitor/`` or from anywhere else. This is the only
    function in the module that has any notion of a filesystem layout, and nothing calls it at
    import time -- the aggregator ships as a container with no ``docs/`` tree and no repository
    around it, and a module that resolved a repository-relative path on import would fail there.
    """
    return Path(__file__).resolve().parents[2]


def main() -> int:
    """Regenerate the tracked JSON Schema export from this model; return an exit code.

    ``python -m monitor.aggregator.models`` is the one command that produces
    :data:`SCHEMA_RELATIVE_PATH`, and it writes the file rather than printing it so that no shell
    redirection stands between the generator and the artefact -- on a Windows host a redirection
    would translate every newline and the tracked file would differ from what CI regenerates on
    Linux in every line. The file is written in binary mode for the same reason.

    Printing whether the bytes changed makes the common case -- "I edited the model, is the export
    stale?" -- answerable without reading a diff, and makes the command safe to run habitually.
    """
    target = repository_root() / SCHEMA_RELATIVE_PATH
    payload = schema_json_bytes()
    previous = target.read_bytes() if target.exists() else None
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)
    state = "unchanged" if previous == payload else "rewritten"
    print(f"{SCHEMA_RELATIVE_PATH}: {state} ({len(payload)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
