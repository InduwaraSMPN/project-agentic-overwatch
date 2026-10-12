"""Normaliser for Falco runtime alerts -- the syscall-level half of the "system logs" family.

THE PAYLOAD SHAPE, AND WHERE IT WAS READ FROM
----------------------------------------------
Falco with ``json_output: true`` prints one JSON object per alert on one line. The key set was read
from Falco's own emitter, ``userspace/falco/falco_outputs.cpp`` in ``falcosecurity/falco``, where
``handle_msg()`` builds the object with ``output``, ``priority``, ``rule``, ``time``,
``output_fields``, ``hostname`` and ``source``; and cross-checked against the ``FalcoPayload``
struct in ``falcosecurity/falcosidekick``'s ``types/types.go``, which is the receiving end of the
same wire format and adds ``tags`` (omitted when the rule has none) plus an optional
generated-identifier property. That second citation matters for T2.2: Falcosidekick is what will
post these objects to the aggregator, so the shape this module parses is the shape that arrives.

The eight ``priority`` values are the syslog levels Falco documents for a rule's required
``priority`` element -- ``EMERGENCY``, ``ALERT``, ``CRITICAL``, ``ERROR``, ``WARNING``, ``NOTICE``,
``INFORMATIONAL``, ``DEBUG`` (https://falco.org/docs/concepts/rules/basic-elements/). Rules files
spell them in any case and the JSON output capitalises them, so the comparison here is
case-insensitive; a token outside the eight raises rather than being ranked, because
``models.py``'s table is the whole mapping and a ninth value would mean the upstream vocabulary
changed.

``output_fields`` holds one entry per ``%``-templated field in the rule's ``output`` expression. The
field names ranked below are Falco's documented ones
(https://falco.org/docs/reference/rules/supported-fields/): the ``proc``, ``fd``, ``user``,
``container`` and ``k8s`` classes. Falco writes the placeholder ``<NA>`` into a field it could not
resolve, which the package's :func:`~monitor.aggregator.sources.optional_text` treats as absence --
so an unresolvable namespace can never reach an event as though somebody had created a namespace
called ``<NA>``.

WHAT THIS MODULE DECIDES, AND WHY
----------------------------------
**The subject is chosen by a ladder, not by a preference.** A syscall event is observed on a host,
inside a container, which is usually inside a Pod -- and Falco resolves as much of that as its
container engine metadata allows. The ladder takes the most specific subject the record actually
supports: Pod if the pod name resolved, else Container, else the Node the alert names in
``hostname``. Going the other way -- always reporting the Node -- would throw away the attribution
the Orchestrator needs to act, and inventing a Pod name where none resolved would attribute an event
to a workload that may not be the one involved.

**The summary is Falco's own rendered ``output`` string.** Composing a sentence from
``output_fields`` instead would be re-deriving, worse, a string the rule author already wrote for
exactly this purpose -- and it would drift from the rule the moment the rule's output expression
changed.

**The excerpt order is significance order, and it is declared rather than derived.** The rule name
first, because it is what a responder searches for; then the process, file and identity fields that
say what happened; then the container and Kubernetes attribution; then the rule's tags and the host;
then every remaining output field sorted by key. ``caps.py``'s selection rule is "the first N
survive", so this order decides which evidence a reader still sees when the count cap binds, and it
must be a written-down order rather than whatever the JSON parser built.
"""

from typing import Any, Final

from monitor.aggregator.models import EvidenceSeverity, EvidenceSource, ResourceRef
from monitor.aggregator.sources import (
    NormalisedRecord,
    NormaliserOptions,
    RawRecord,
    RecordLayout,
    RecordLocator,
    SeverityNotRecognised,
    optional_text,
    parse_source_timestamp,
    remaining_pairs,
    rendered_pairs,
    require_text,
)

SOURCE: Final = EvidenceSource.FALCO

# One complete alert object per line, which is what a Falco file sink writes and what a capture of
# the Falcosidekick stream serialises to. The record's byte span is the line's own bytes.
LOCATOR: Final = RecordLocator(layout=RecordLayout.JSON_LINES)

# The canonical filename this source's raw input carries inside a fixture directory. Derived
# mechanically from the source identifier so that a fixture author does not have to look it up.
INPUT_FILENAME: Final = "falco.jsonl"

# Falco's eight syslog priorities onto the five normalised levels, exactly as models.py's table
# states it. Eight onto five loses resolution at the top, where emergency, alert and critical all
# collapse: that distinction is a syslog convention about who gets woken up and the Orchestrator's
# triage does not act on it. Keys are lower-cased before lookup.
PRIORITY_TO_SEVERITY: Final[dict[str, EvidenceSeverity]] = {
    "emergency": EvidenceSeverity.CRITICAL,
    "alert": EvidenceSeverity.CRITICAL,
    "critical": EvidenceSeverity.CRITICAL,
    "error": EvidenceSeverity.HIGH,
    "warning": EvidenceSeverity.MEDIUM,
    "notice": EvidenceSeverity.LOW,
    "informational": EvidenceSeverity.INFO,
    "debug": EvidenceSeverity.INFO,
}

# The output fields this normaliser ranks, in significance order. Everything else in output_fields
# still becomes a candidate, sorted by key, after these.
RANKED_OUTPUT_FIELDS: Final[tuple[str, ...]] = (
    "proc.cmdline",
    "proc.exepath",
    "proc.name",
    "proc.pname",
    "fd.name",
    "evt.type",
    "user.name",
    "user.uid",
    "container.image.repository",
    "container.image.tag",
    "container.name",
    "container.id",
    "k8s.pod.name",
    "k8s.ns.name",
)


def _resource(record: dict[str, Any], fields: dict[str, Any]) -> ResourceRef:
    """Return the most specific subject the record supports: Pod, else Container, else Node.

    See the module docstring for why the ladder runs in this direction. ``hostname`` is optional in
    the payload, so the final rung falls back to the literal Falco source name -- an alert that
    resolved neither a workload nor a host still has to name a subject, and naming the collector
    that produced it is the only honest answer left.
    """
    namespace = optional_text(fields.get("k8s.ns.name"))
    pod = optional_text(fields.get("k8s.pod.name"))
    if pod is not None:
        return ResourceRef(ns=namespace, kind="Pod", name=pod)
    container = optional_text(fields.get("container.name")) or optional_text(
        fields.get("container.id")
    )
    if container is not None:
        return ResourceRef(ns=namespace, kind="Container", name=container)
    host = optional_text(record.get("hostname"))
    if host is not None:
        return ResourceRef(ns=None, kind="Node", name=host)
    return ResourceRef(ns=None, kind="Collector", name=str(SOURCE))


def _severity(record: dict[str, Any]) -> EvidenceSeverity:
    """Map Falco's ``priority`` onto the normalised scale, or raise naming the token."""
    priority = require_text(record, "priority", source=str(SOURCE))
    try:
        return PRIORITY_TO_SEVERITY[priority.lower()]
    except KeyError:
        raise SeverityNotRecognised(
            f"{SOURCE}: priority {priority!r} is outside the eight syslog levels Falco documents "
            f"({', '.join(PRIORITY_TO_SEVERITY)}). The mapping in monitor/aggregator/models.py is "
            "the whole normalisation; a value outside it is a changed upstream vocabulary or a "
            "malformed fixture, and is never ranked by guess."
        ) from None


def normalise(raw: RawRecord, options: NormaliserOptions) -> NormalisedRecord:
    """Turn one Falco JSON alert into a :class:`NormalisedRecord`.

    ``options`` is unread here: Falco carries its own severity and its own timestamp, so nothing
    outside the record is needed. The parameter is present because the registry dispatches over one
    uniform signature; the package docstring explains why that is worth one unused argument.
    """
    del options
    record = dict(raw.value)
    fields_value = record.get("output_fields")
    fields: dict[str, Any] = dict(fields_value) if isinstance(fields_value, dict) else {}

    rule = require_text(record, "rule", source=str(SOURCE))
    summary = require_text(record, "output", source=str(SOURCE))
    raw_time = record.get("time")
    ts = parse_source_timestamp(raw_time, source=str(SOURCE), field_name="time")

    tags = record.get("tags")
    trailer: list[str] = []
    if isinstance(tags, list) and tags:
        trailer.append("tags=" + ",".join(str(tag) for tag in tags))
    host = optional_text(record.get("hostname"))
    if host is not None:
        trailer.append(f"hostname={host}")
    falco_source = optional_text(record.get("source"))
    if falco_source is not None:
        trailer.append(f"falco.source={falco_source}")

    candidates = (
        (f"rule={rule}",)
        + rendered_pairs(fields, keys=RANKED_OUTPUT_FIELDS)
        + tuple(trailer)
        + remaining_pairs(fields, exclude=RANKED_OUTPUT_FIELDS)
    )

    return NormalisedRecord(
        source=SOURCE,
        ts=ts,
        severity=_severity(record),
        # The structured detection signal for Falco is the rule name -- the same value ranked first
        # among the excerpts, captured here as its own field so detection precision and recall read
        # a
        # sensor identifier rather than parsing it back out of a capped, quoted excerpt. Always
        # present: `rule` is required above, so Falco's signal_id is never null.
        signal_id=rule,
        resource=_resource(record, fields),
        summary=summary,
        excerpt_candidates=candidates,
        # Falco's natural key. The raw time string is carried verbatim rather than the parsed value
        # because Falco reports nanoseconds and the parsed value resolves microseconds, so two
        # alerts less than a microsecond apart would otherwise project identically.
        discriminator=(
            ("rule", rule),
            ("time", str(raw_time)),
            ("output", summary),
            ("hostname", host or ""),
            ("falco.source", falco_source or ""),
        ),
    )
