"""Normaliser for the Kubernetes audit stream -- the API-server half of the "system logs" family.

THE PAYLOAD SHAPE, AND WHERE IT WAS READ FROM
----------------------------------------------
The API server writes one ``audit.k8s.io/v1`` ``Event`` object per audited request, one per line in
the audit log file. The field list was read from the Kubernetes auditing task page
(https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/) and its linked API reference for
``audit.k8s.io/v1``: ``apiVersion``, ``kind``, ``level``, ``auditID``, ``stage``, ``requestURI``,
``verb``, ``user`` (with ``username`` and ``groups``), ``sourceIPs``, ``userAgent``, ``objectRef``
(with ``resource``, ``namespace``, ``name``, ``apiGroup``, ``apiVersion`` and ``subresource``),
``responseStatus``, ``requestReceivedTimestamp``, ``stageTimestamp`` and ``annotations``.

The ``apiVersion`` is checked rather than assumed. The field set is version-specific and a future
group version could rename or restructure any of it, so a record from another version is refused
here with a message naming what was found -- rather than silently producing an event with several
empty fields, which is the shape of failure that survives review.

Enabling the audit log at all is a ``kube-apiserver`` flag, which is why ``infra/versions.env``
carries no key for this source: it is configured in ``infra/kind-config.yaml`` at T2.4 rather than
installed as a component.

``level`` IS NOT A SEVERITY, AND THIS MODULE WILL NOT INVENT ONE
-----------------------------------------------------------------
The audit stream carries no severity at all. Its ``level`` field takes ``None``, ``Metadata``,
``Request`` or ``RequestResponse`` and describes *how much of the request and response was
recorded* -- it is a verbosity setting configured in the audit policy and it says nothing about
danger. ``models.py`` sets out the consequence of misreading it: a fully recorded read of a
ConfigMap would outrank a metadata-only privilege escalation, consistently enough to look like a
finding.

Severity for an audit event is therefore assigned by the audit rule that selected the event, and
that rule set is authored at T2.4 together with the audit policy. Until it exists, the assignment
reaches this module as :attr:`~monitor.aggregator.sources.NormaliserOptions.audit_severity` and
there is **no default**: a record arriving without one raises
:class:`~monitor.aggregator.sources.AuditSeverityNotAssigned`. That is the same fail-closed
discipline ``limits.py`` applies to an unmeasured cap, and for the same reason -- a default would
rank every audit event in the corpus at whatever level happened to be convenient, and the corpus
would go green.

A rejected alternative, recorded so it is not re-proposed: carrying the assignment in the record's
own ``annotations`` map under a project-specific key. Audit annotations are written by the API
server and its admission plugins, not by the audit policy, so a rule cannot put one there -- the
aggregator's ingestion would have to inject it, which is the same decision taken one layer earlier
and hidden behind a field that looks like source data.

THE SUBJECT KEEPS THE PLURAL RESOURCE NAME, DELIBERATELY
---------------------------------------------------------
``objectRef.resource`` is the plural, lower-case API resource name -- ``pods``, ``endpoints``,
``networkpolicies`` -- and the record does not carry the object's ``Kind``. Deriving ``Pod`` from
``pods`` needs a singularisation table with irregular entries (``endpoints`` is already singular,
``ingresses`` is not a simple strip), and a wrong entry would put a kind into the evidence stream
that no ``kubectl get`` resolves. So the resource name is used as reported. It is unambiguous, it
round-trips against the API, and being visibly plural is a better signal to a reader than a guess
that looks right.

A request with no ``objectRef`` is a non-resource request -- ``/healthz``, ``/metrics``, the
discovery endpoints. Kubernetes has its own name for that category, ``nonResourceURLs`` in RBAC, so
the subject becomes ``kind="NonResourceURL"`` with the request URI as the name. That is a real term
of art rather than a sentinel invented here.

Where a request targets a collection rather than a named object, ``objectRef.name`` is absent and
the request URI is used as the name. It is real data from the record and it identifies the
collection exactly; the alternative -- a placeholder string -- would read as data downstream, which
is the failure ``models.py`` refuses for ``ns`` and refuses here for the same reason.
"""

from typing import Any, Final

from monitor.aggregator.models import EvidenceSource, ResourceRef
from monitor.aggregator.sources import (
    AuditSeverityNotAssigned,
    NormalisationError,
    NormalisedRecord,
    NormaliserOptions,
    RawRecord,
    RecordLayout,
    RecordLocator,
    optional_text,
    parse_source_timestamp,
    remaining_pairs,
    rendered_pairs,
    require_text,
)

SOURCE: Final = EvidenceSource.K8S_AUDIT

# One complete Event object per line, which is how the API server's audit log backend writes them.
LOCATOR: Final = RecordLocator(layout=RecordLayout.JSON_LINES)

# The canonical filename this source's raw input carries inside a fixture directory.
INPUT_FILENAME: Final = "k8s_audit.jsonl"

# The only audit group version this module claims to understand. See the module docstring for why
# a record from another version is refused rather than parsed optimistically.
SUPPORTED_API_VERSION: Final = "audit.k8s.io/v1"
SUPPORTED_KIND: Final = "Event"

# The flattened field names this normaliser ranks as excerpt candidates, in significance order:
# who did what to which object, then how the request arrived, then what the server answered, then
# the record's own bookkeeping.
RANKED_FIELDS: Final[tuple[str, ...]] = (
    "verb",
    "user.username",
    "user.groups",
    "impersonatedUser.username",
    "objectRef.resource",
    "objectRef.subresource",
    "objectRef.namespace",
    "objectRef.name",
    "objectRef.apiGroup",
    "requestURI",
    "sourceIPs",
    "userAgent",
    "responseStatus.code",
    "responseStatus.status",
    "responseStatus.message",
    "stage",
    "level",
    "auditID",
)


def _joined(value: object) -> str | None:
    """Render a JSON list of scalars as comma-separated text; anything else via ``optional_text``.

    ``groups`` and ``sourceIPs`` are lists, and an excerpt has to be text. The separator is a comma
    with no space so that the rendering is compact against the length cap, and the element order is
    the record's own -- the API server writes group membership and source addresses in a meaningful
    order and re-sorting them would destroy it.
    """
    if isinstance(value, list):
        joined = ",".join(str(item) for item in value)
        return joined or None
    return optional_text(value)


def _flatten(record: dict[str, Any]) -> dict[str, Any]:
    """Return the record's nested fields flattened onto the dotted names :data:`RANKED_FIELDS` uses.

    Flattening rather than reaching into nested dictionaries at each use site keeps one description
    of the record's shape, and lets the ranked list above read as the field names a Kubernetes
    operator already knows.
    """
    user = record.get("user") if isinstance(record.get("user"), dict) else {}
    impersonated = (
        record.get("impersonatedUser") if isinstance(record.get("impersonatedUser"), dict) else {}
    )
    object_ref = record.get("objectRef") if isinstance(record.get("objectRef"), dict) else {}
    response = (
        record.get("responseStatus") if isinstance(record.get("responseStatus"), dict) else {}
    )
    flat: dict[str, Any] = {
        "verb": optional_text(record.get("verb")),
        "user.username": optional_text(user.get("username")),
        "user.groups": _joined(user.get("groups")),
        "impersonatedUser.username": optional_text(impersonated.get("username")),
        "objectRef.resource": optional_text(object_ref.get("resource")),
        "objectRef.subresource": optional_text(object_ref.get("subresource")),
        "objectRef.namespace": optional_text(object_ref.get("namespace")),
        "objectRef.name": optional_text(object_ref.get("name")),
        "objectRef.apiGroup": optional_text(object_ref.get("apiGroup")),
        "requestURI": optional_text(record.get("requestURI")),
        "sourceIPs": _joined(record.get("sourceIPs")),
        "userAgent": optional_text(record.get("userAgent")),
        "responseStatus.code": None if response.get("code") is None else str(response.get("code")),
        "responseStatus.status": optional_text(response.get("status")),
        "responseStatus.message": optional_text(response.get("message")),
        "stage": optional_text(record.get("stage")),
        "level": optional_text(record.get("level")),
        "auditID": optional_text(record.get("auditID")),
    }
    return {key: value for key, value in flat.items() if value is not None}


def _resource(flat: dict[str, Any], request_uri: str) -> ResourceRef:
    """Return the audited subject: the API resource it names, else the non-resource URL."""
    resource = flat.get("objectRef.resource")
    if resource is None:
        return ResourceRef(ns=None, kind="NonResourceURL", name=request_uri)
    return ResourceRef(
        ns=flat.get("objectRef.namespace"),
        kind=resource,
        name=flat.get("objectRef.name") or request_uri,
    )


def _summary(flat: dict[str, Any], resource: ResourceRef, request_uri: str) -> str:
    """Compose the one-line summary, from a template fixed here and nowhere else.

    The audit record has no summary field of its own, so one is composed -- and the template is
    written down because a composed string that varies with the composer is not reproducible::

        <verb> <kind>[/<subresource>] <ns>/<name> by <username>[ -> <code> <status>]

    Every part comes from the record; nothing is inferred. The namespace segment is omitted for a
    cluster-scoped subject, and the response clause is omitted for a stage that has not produced
    one, rather than being filled with a placeholder that a reader could mistake for a real answer.
    """
    subject = resource.kind
    subresource = flat.get("objectRef.subresource")
    if subresource is not None:
        subject = f"{subject}/{subresource}"
    name = flat.get("objectRef.name") or request_uri
    qualified = f"{resource.ns}/{name}" if resource.ns is not None else name
    verb = flat.get("verb") or "<unset verb>"
    actor = flat.get("user.username") or "<unset user>"
    line = f"{verb} {subject} {qualified} by {actor}"
    code = flat.get("responseStatus.code")
    if code is None:
        return line
    status = flat.get("responseStatus.status")
    return f"{line} -> {code} {status}" if status is not None else f"{line} -> {code}"


def normalise(raw: RawRecord, options: NormaliserOptions) -> NormalisedRecord:
    """Turn one ``audit.k8s.io/v1`` Event into a normalised record.

    Unlike the other three normalisers this one reads ``options``: the audit stream carries no
    severity and this module will not manufacture one. See the module docstring.
    """
    record = dict(raw.value)
    api_version = optional_text(record.get("apiVersion"))
    if api_version != SUPPORTED_API_VERSION:
        raise NormalisationError(
            f"{SOURCE}: apiVersion is {api_version!r}, and this normaliser understands only "
            f"{SUPPORTED_API_VERSION!r}. The audit Event field set is version-specific, so a "
            "record from another group version is refused rather than parsed optimistically."
        )
    kind = optional_text(record.get("kind"))
    if kind != SUPPORTED_KIND:
        raise NormalisationError(
            f"{SOURCE}: kind is {kind!r}, expected {SUPPORTED_KIND!r}. The audit.k8s.io/v1 "
            "payload contract is an Event object, so another kind is refused."
        )
    if options.audit_severity is None:
        raise AuditSeverityNotAssigned(
            f"{SOURCE}: no severity was assigned to this record. The audit stream carries none of "
            "its own and its 'level' field is a verbosity setting, not a ranking. Severity is "
            "assigned by the audit rule that selected the event (authored at T2.4 with the audit "
            "policy); until that exists, supply it explicitly -- the CLI's --audit-severity flag "
            "does so for a replay. There is deliberately no default."
        )

    request_uri = require_text(record, "requestURI", source=str(SOURCE))
    raw_received = record.get("requestReceivedTimestamp")
    ts = parse_source_timestamp(
        raw_received, source=str(SOURCE), field_name="requestReceivedTimestamp"
    )

    flat = _flatten(record)
    resource = _resource(flat, request_uri)
    # The structured detection signal for the audit stream is the verb-and-resource pair -- what was
    # done to which API resource -- which is what a detection rule keys on. A non-resource request
    # (/healthz, the discovery endpoints) has no objectRef.resource, so it has no such pair and the
    # signal is null: the same case _resource names NonResourceURL, reported honestly rather than
    # with a manufactured pair. Both parts come from the already-flattened record, so this reads no
    # field twice.
    audit_resource = flat.get("objectRef.resource")
    signal_id = None if audit_resource is None else f"{flat.get('verb')}:{audit_resource}"
    annotations_value = record.get("annotations")
    annotations: dict[str, Any] = (
        dict(annotations_value) if isinstance(annotations_value, dict) else {}
    )

    candidates = rendered_pairs(flat, keys=RANKED_FIELDS) + remaining_pairs(
        annotations, exclude=(), prefix="annotation."
    )

    return NormalisedRecord(
        source=SOURCE,
        ts=ts,
        severity=options.audit_severity,
        signal_id=signal_id,
        resource=resource,
        summary=_summary(flat, resource, request_uri),
        excerpt_candidates=candidates,
        # The audit stream's natural key. ``auditID`` is unique per request by the API server's own
        # contract, and the stage separates the several records one long-running request produces.
        discriminator=(
            ("auditID", flat.get("auditID") or ""),
            ("stage", flat.get("stage") or ""),
            ("requestReceivedTimestamp", str(raw_received)),
            ("stageTimestamp", str(record.get("stageTimestamp"))),
        ),
    )
