"""Normaliser for Prometheus alerts as Alertmanager delivers them -- the metric-anomaly path.

THE PAYLOAD SHAPE, AND WHERE IT WAS READ FROM
----------------------------------------------
Prometheus itself never posts to the aggregator. It evaluates alerting rules and hands firing
alerts to Alertmanager, which groups, deduplicates and dispatches them; T2.3 configures a
``webhook_config`` receiver pointing at the aggregator. The body of that POST is the payload this
module parses, and its shape is specified in the Alertmanager configuration reference
(https://prometheus.io/docs/alerting/latest/configuration/, ``webhook_config``): a JSON object with
``version``, ``groupKey``, ``truncatedAlerts``, ``status``, ``receiver``, ``groupLabels``,
``commonLabels``, ``commonAnnotations``, ``externalURL`` and an ``alerts`` array, in which every
entry carries ``status``, ``labels``, ``annotations``, ``startsAt``, ``endsAt``, ``generatorURL``
and ``fingerprint``.

**One record is one entry of ``alerts``, not one webhook body.** A grouped notification carries
several distinct alerts, and collapsing a group into one ``EvidenceEvent`` would merge two different
findings about two different workloads into a single bounded summary -- which is the one thing a
curated event must not do.

SEVERITY IS A LABEL, NOT A FIELD, AND THE PERMITTED SET IS THIS PROJECT'S OWN RULES
------------------------------------------------------------------------------------
Prometheus has no severity in its alerting data model at all. ``severity`` is a label applied by
convention, and its values are whatever the alerting rules say -- which is why ``models.py`` fixes
the vocabulary from the rules side rather than from the protocol side: the rules written at T2.3
emit ``critical``, ``warning`` and ``info`` and nothing else. A label outside that set raises, and
a record with no ``severity`` label at all raises too. Neither is guessed. ``warning`` maps to
``medium`` here and also from Falco, deliberately: the same word from two sources must not mean two
different things after normalisation, or a cross-source comparison in Chapter 4 compares vocabulary
rather than severity.

``startsAt`` IS THE EVENT TIME, AND THE ALTERNATIVES ARE WORSE
---------------------------------------------------------------
``startsAt`` is when the alert began firing, which is the closest thing the payload has to when the
observed condition started. ``endsAt`` is a *future* resolve-by time for a firing alert rather than
a past one, so it is not an event time; and the moment the webhook was delivered is a property of
Alertmanager's grouping timers -- ``group_wait`` and ``group_interval`` -- rather than of the
observation, besides not being in the payload at all. ``endsAt`` and ``status`` are kept as
excerpts, where they are evidence rather than a clock.

THE SUBJECT LADDER READS KUBERNETES LABELS, AND FALLS BACK TO THE ALERT ITSELF
-------------------------------------------------------------------------------
The workload labels a Kubernetes alert carries -- ``namespace``, ``pod``, ``deployment``,
``statefulset``, ``daemonset``, ``service``, ``node`` -- are attached by ``kube-state-metrics`` and
by the relabelling the standard Kubernetes rule sets use, and are the only attribution available.
The ladder takes the most specific one present. Where none is, the subject is the alert itself:
``kind="Alert"`` with the ``alertname`` label as the name. That is honest -- a node-exporter alert
about a filesystem genuinely is not about an API object -- and it keeps the fallback from
manufacturing a workload attribution that the Orchestrator would then act on.

Note that the Prometheus scrape ``job`` label is deliberately **not** a rung. It names the scrape
job that produced the series, which is not a Kubernetes ``Job``, and treating it as one would put a
resource kind into the evidence stream that no ``kubectl get`` can resolve.
"""

from typing import Any, Final

from monitor.aggregator.models import EvidenceSeverity, EvidenceSource, ResourceRef
from monitor.aggregator.sources import (
    MissingSourceField,
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

SOURCE: Final = EvidenceSource.PROMETHEUS

# One webhook body, with the records in its top-level ``alerts`` array. Nothing outside the alert
# entry is copied onto the record: an Alertmanager alert is self-contained, carrying its own
# labels, annotations, times and identity, so there is no document-level fact a normaliser needs.
SUPPORTED_WEBHOOK_VERSION: Final = "4"

LOCATOR: Final = RecordLocator(
    layout=RecordLayout.JSON_DOCUMENT,
    record_key="alerts",
    required_document_values=(("version", SUPPORTED_WEBHOOK_VERSION),),
)

# The canonical filename this source's raw input carries inside a fixture directory. Named after
# the source identifier rather than after Alertmanager, so the four filenames are mechanically
# derivable from the four ``EvidenceSource`` values; the *content* is an Alertmanager webhook body.
INPUT_FILENAME: Final = "prometheus.json"

# The label whose value carries severity by convention. Named as a constant because it is the one
# label this module reads as anything other than evidence.
SEVERITY_LABEL: Final = "severity"

# The three values the alerting rules written at T2.3 may emit, mapped exactly as models.py's table
# states. There is no fourth entry and no default: see the module docstring.
LABEL_TO_SEVERITY: Final[dict[str, EvidenceSeverity]] = {
    "critical": EvidenceSeverity.CRITICAL,
    "warning": EvidenceSeverity.MEDIUM,
    "info": EvidenceSeverity.INFO,
}

# The subject ladder, most specific first: (label name, resource kind). See the module docstring
# for why the Prometheus ``job`` label is absent from it.
SUBJECT_LADDER: Final[tuple[tuple[str, str], ...]] = (
    ("pod", "Pod"),
    ("deployment", "Deployment"),
    ("statefulset", "StatefulSet"),
    ("daemonset", "DaemonSet"),
    ("service", "Service"),
    ("node", "Node"),
)

# The annotation keys a summary may be taken from, in preference order. Alertmanager places no
# constraint on annotation names; these are the conventional ones the Kubernetes rule sets use.
SUMMARY_ANNOTATIONS: Final[tuple[str, ...]] = ("summary", "description", "message")

# Annotations ranked as excerpt candidates, in significance order.
RANKED_ANNOTATIONS: Final[tuple[str, ...]] = ("description", "summary", "runbook_url", "message")

# Alert-level fields ranked as excerpt candidates, in significance order.
RANKED_ALERT_FIELDS: Final[tuple[str, ...]] = (
    "status",
    "startsAt",
    "endsAt",
    "generatorURL",
    "fingerprint",
)


def _severity(labels: dict[str, Any]) -> EvidenceSeverity:
    """Map the ``severity`` label onto the normalised scale, or raise naming what was found."""
    label = optional_text(labels.get(SEVERITY_LABEL))
    if label is None:
        raise MissingSourceField(
            f"{SOURCE}: the alert carries no {SEVERITY_LABEL!r} label. Prometheus has no severity "
            "in its data model, so the label is the only source of one, and the alerting rules "
            "written at T2.3 are required to set it. An alert without it is a rule defect."
        )
    try:
        return LABEL_TO_SEVERITY[label.lower()]
    except KeyError:
        raise SeverityNotRecognised(
            f"{SOURCE}: {SEVERITY_LABEL} label {label!r} is outside the set this project's "
            f"alerting rules may emit ({', '.join(LABEL_TO_SEVERITY)}). Extend the rules and "
            "models.py's mapping table together, or fix the rule; never rank an unknown label."
        ) from None


def _resource(labels: dict[str, Any]) -> ResourceRef:
    """Return the most specific labelled subject, else the alert itself."""
    namespace = optional_text(labels.get("namespace"))
    for label, kind in SUBJECT_LADDER:
        name = optional_text(labels.get(label))
        if name is not None:
            return ResourceRef(ns=namespace, kind=kind, name=name)
    return ResourceRef(
        ns=namespace, kind="Alert", name=require_text(labels, "alertname", source=str(SOURCE))
    )


def _summary(annotations: dict[str, Any], labels: dict[str, Any]) -> tuple[str, str | None]:
    """Return the summary text and the annotation key it came from, if any.

    The key is returned as well as the text so that the caller can leave that annotation out of the
    excerpt candidates. An excerpt repeating the summary word for word spends one of a small number
    of capped slots on text the event already carries.
    """
    for key in SUMMARY_ANNOTATIONS:
        text = optional_text(annotations.get(key))
        if text is not None:
            return text, key
    return require_text(labels, "alertname", source=str(SOURCE)), None


def normalise(raw: RawRecord, options: NormaliserOptions) -> NormalisedRecord:
    """Turn one entry of an Alertmanager webhook's ``alerts`` array into a normalised record.

    ``options`` is unread: an Alertmanager alert carries its own severity label and its own times,
    so nothing outside the record is needed. The parameter is present because the registry
    dispatches over one uniform signature.
    """
    del options
    record = dict(raw.value)
    labels_value = record.get("labels")
    labels: dict[str, Any] = dict(labels_value) if isinstance(labels_value, dict) else {}
    annotations_value = record.get("annotations")
    annotations: dict[str, Any] = (
        dict(annotations_value) if isinstance(annotations_value, dict) else {}
    )

    summary, summary_key = _summary(annotations, labels)
    # The structured detection signal for an Alertmanager alert is its alertname label, read here
    # unconditionally rather than only in the two fallback branches (_resource, _summary) that reach
    # for it when nothing more specific is present. alertname is the alert rule that fired -- the
    # sensor-level identifier detection precision and recall need -- and Alertmanager always sets
    # it,
    # so require_text is right: an alert without it is a rule defect, not a nullable signal.
    signal_id = require_text(labels, "alertname", source=str(SOURCE))
    raw_starts_at = record.get("startsAt")
    ts = parse_source_timestamp(raw_starts_at, source=str(SOURCE), field_name="startsAt")

    used_annotations = (summary_key,) if summary_key is not None else ()
    ranked_annotations = tuple(key for key in RANKED_ANNOTATIONS if key not in used_annotations)

    candidates = (
        rendered_pairs(labels, keys=("alertname",), prefix="label.")
        + rendered_pairs(annotations, keys=ranked_annotations, prefix="annotation.")
        + rendered_pairs(record, keys=RANKED_ALERT_FIELDS)
        + remaining_pairs(labels, exclude=("alertname",), prefix="label.")
        + remaining_pairs(
            annotations, exclude=ranked_annotations + used_annotations, prefix="annotation."
        )
    )

    return NormalisedRecord(
        source=SOURCE,
        ts=ts,
        severity=_severity(labels),
        signal_id=signal_id,
        resource=_resource(labels),
        summary=summary,
        excerpt_candidates=candidates,
        # Alertmanager's natural key. ``fingerprint`` is a hash of the alert's label set, so it
        # identifies the alert but not the firing; ``startsAt`` plus ``status`` separates two
        # firings of the same alert. Both raw times are carried verbatim, for the reason the
        # package docstring gives about truncated precision.
        discriminator=(
            ("fingerprint", optional_text(record.get("fingerprint")) or ""),
            ("startsAt", str(raw_starts_at)),
            ("endsAt", str(record.get("endsAt"))),
            ("status", optional_text(record.get("status")) or ""),
            ("generatorURL", optional_text(record.get("generatorURL")) or ""),
        ),
    )
