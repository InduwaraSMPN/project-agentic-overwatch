"""Per-source normalisation, the raw-record reader's byte spans, and the ordering contract.

WHAT THIS FILE COVERS, AND WHY THE INPUTS ARE MINIMAL
------------------------------------------------------
Each of the four normalisers is exercised against the smallest record its upstream contract calls
well-formed, plus the specific degenerate cases that normaliser decides something about: a priority
outside Falco's eight, an alert with no severity label, an audit record with no severity assigned, a
Trivy report with no creation time. Minimal rather than realistic, because a realistic record makes
a failing assertion hard to localise and tempts the next person to copy a whole capture into a test
file -- which is what ``monitor/fixtures/`` is for, with its provenance recorded.

Nothing here needs a cluster, a network, a clock or a fixture on disk. Every input is a literal in
this file, so a failure is always about the code under test.

WHY THE SEVERITY MAPPINGS ARE SPELLED OUT AGAIN
-------------------------------------------------
The expected mappings below are transcribed from ``models.py``'s documented table, not imported from
the normaliser's own dictionary. A test that asked the module what its mapping is and then checked
the module against the answer would pass for any mapping whatsoever. ``models.py`` is where the
target vocabulary and the mapping are documented, so the table below is that document's side of the
comparison and the normaliser is the code's side.

WHY THE BYTE-SPAN TEST RESOLVES THE POINTER
---------------------------------------------
``raw_ref`` is only worth carrying if it resolves. The reader tests slice the original bytes at the
offset and length the reader reported and parse the slice, asserting it is exactly the record --
which is the operation an examiner checking an excerpt's provenance would perform, done by machine.
Approximating a span, or pointing every record in a document at the whole document, would pass a
weaker test and fail this one.
"""

import sys
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from monitor.aggregator.models import (  # noqa: E402
    EvidenceSeverity,
    EvidenceSource,
    RawRef,
    ResourceRef,
)
from monitor.aggregator.normalize import (  # noqa: E402
    SOURCE_REGISTRY,
    AggregatedRecord,
    DuplicateEventId,
    RecordLayoutError,
    compute_event_id,
    identity_projection,
    ordered,
    read_records,
    registry_entry,
)
from monitor.aggregator.sources import (  # noqa: E402
    AuditSeverityNotAssigned,
    MissingSourceField,
    NormalisationError,
    NormalisedRecord,
    NormaliserOptions,
    RawRecord,
    SeverityNotRecognised,
    TimestampNotUsable,
    parse_source_timestamp,
)
from monitor.aggregator.sources import falco as falco_source  # noqa: E402
from monitor.aggregator.sources import k8s_audit as k8s_audit_source  # noqa: E402
from monitor.aggregator.sources import prometheus as prometheus_source  # noqa: E402
from monitor.aggregator.sources import trivy as trivy_source  # noqa: E402

NO_OPTIONS = NormaliserOptions()

# --- minimal records, one per source ------------------------------------------------------------
# Field sets are the ones each module's docstring cites: Falco's own emitter and the Falcosidekick
# payload struct; Alertmanager's webhook_config reference; the audit.k8s.io/v1 Event; Trivy's JSON
# report. Values are invented; shapes are not.

FALCO_RECORD: dict[str, Any] = {
    "output": "10:30:00.123456789: Warning Shell spawned in a container (user=root)",
    "priority": "Warning",
    "rule": "Terminal shell in container",
    "time": "2026-08-26T10:30:00.123456789Z",
    "source": "syscall",
    "tags": ["container", "shell", "mitre_execution"],
    "hostname": "kind-worker",
    "output_fields": {
        "proc.cmdline": "bash -i",
        "fd.name": "/dev/pts/0",
        "user.name": "root",
        "container.id": "9f2c1b7ae001",
        "k8s.pod.name": "frontend-7d9c-abcde",
        "k8s.ns.name": "boutique",
        "evt.type": "execve",
    },
}

PROMETHEUS_ALERT: dict[str, Any] = {
    "status": "firing",
    "labels": {
        "alertname": "KubePodCrashLooping",
        "severity": "warning",
        "namespace": "boutique",
        "pod": "cartservice-6b5f-zzzzz",
        "job": "kube-state-metrics",
    },
    "annotations": {
        "summary": "Pod is crash looping.",
        "description": "cartservice has restarted 7 times in the last 10 minutes.",
        "runbook_url": "https://runbooks.invalid/KubePodCrashLooping",
    },
    "startsAt": "2026-08-26T10:31:00.000Z",
    "endsAt": "0001-01-01T00:00:00Z",
    "generatorURL": "https://prometheus.invalid/graph?g0.expr=up",
    "fingerprint": "a1b2c3d4e5f60718",
}

AUDIT_RECORD: dict[str, Any] = {
    "apiVersion": "audit.k8s.io/v1",
    "kind": "Event",
    "level": "RequestResponse",
    "auditID": "e6972e08-ead9-4d5c-9c78-2f5290f37541",
    "stage": "ResponseComplete",
    "requestURI": "/api/v1/namespaces/boutique/pods/attacker-pod",
    "verb": "create",
    "user": {"username": "system:anonymous", "groups": ["system:unauthenticated"]},
    "sourceIPs": ["10.244.1.7"],
    "userAgent": "curl/8.5.0",
    "objectRef": {
        "resource": "pods",
        "namespace": "boutique",
        "name": "attacker-pod",
        "apiGroup": "",
        "apiVersion": "v1",
    },
    "responseStatus": {"metadata": {}, "status": "Success", "code": 201},
    "requestReceivedTimestamp": "2026-08-26T10:32:00.123456Z",
    "stageTimestamp": "2026-08-26T10:32:00.234567Z",
    "annotations": {"authorization.k8s.io/decision": "allow"},
}

TRIVY_VULNERABILITY: dict[str, Any] = {
    "VulnerabilityID": "CVE-2026-00001",
    "PkgID": "openssl@3.0.1-r0",
    "PkgName": "openssl",
    "InstalledVersion": "3.0.1-r0",
    "FixedVersion": "3.0.2-r0",
    "Status": "fixed",
    "Severity": "HIGH",
    "Title": "openssl: buffer overflow in the invented parser",
    "PrimaryURL": "https://avd.invalid/CVE-2026-00001",
    "CweIDs": ["CWE-120"],
    "CVSS": {"nvd": {"V3Score": 8.1}},
}

TRIVY_CONTEXT: dict[str, Any] = {
    "ArtifactName": "docker.io/library/vulnerable-app:1.0",
    "ArtifactType": "container_image",
    "CreatedAt": "2026-08-26T10:33:00Z",
    "SchemaVersion": 2,
    "Target": "docker.io/library/vulnerable-app:1.0 (alpine 3.15.0)",
    "Class": "os-pkgs",
    "Type": "alpine",
}


def _raw(value: dict[str, Any], context: dict[str, Any] | None = None) -> RawRecord:
    """Wrap a literal record as a :class:`RawRecord` with a span nothing in this file resolves."""
    return RawRecord(value=value, offset=0, length=len(str(value)), context=context or {})


# --- shared: timestamps -------------------------------------------------------------------------


def test_a_naive_timestamp_is_rejected_rather_than_assumed_to_be_utc() -> None:
    """Assuming an offset is how a timezone error becomes a silent one."""
    with pytest.raises(TimestampNotUsable):
        parse_source_timestamp("2026-08-26T10:30:00", source="test", field_name="ts")


def test_a_non_rfc3339_timestamp_is_rejected() -> None:
    """The interpreter's parser accepts more than RFC 3339; the shape check is what narrows it."""
    with pytest.raises(TimestampNotUsable):
        parse_source_timestamp("2026-08-26 10:30:00+00:00", source="test", field_name="ts")


def test_an_offset_timestamp_is_converted_to_utc_preserving_the_instant() -> None:
    """Two sources reporting one instant with different offsets must serialise to the same bytes."""
    parsed = parse_source_timestamp("2026-08-26T12:30:00+02:00", source="test", field_name="ts")
    assert parsed == datetime(2026, 8, 26, 10, 30, tzinfo=UTC)
    assert parsed.tzinfo == UTC
    assert parsed == datetime(2026, 8, 26, 12, 30, tzinfo=timezone(timedelta(hours=2)))


def test_sub_microsecond_precision_is_truncated_not_rounded() -> None:
    """Truncation is total and has no tie-breaking rule to get wrong; rounding has one."""
    parsed = parse_source_timestamp(
        "2026-08-26T10:30:00.123456789Z", source="test", field_name="ts"
    )
    assert parsed.microsecond == 123456


# --- Falco --------------------------------------------------------------------------------------

# Transcribed from models.py's documented table, not imported from the normaliser.
FALCO_PRIORITY_TABLE = (
    ("emergency", EvidenceSeverity.CRITICAL),
    ("alert", EvidenceSeverity.CRITICAL),
    ("critical", EvidenceSeverity.CRITICAL),
    ("error", EvidenceSeverity.HIGH),
    ("warning", EvidenceSeverity.MEDIUM),
    ("notice", EvidenceSeverity.LOW),
    ("informational", EvidenceSeverity.INFO),
    ("debug", EvidenceSeverity.INFO),
)


@pytest.mark.parametrize(("priority", "expected"), FALCO_PRIORITY_TABLE)
def test_falco_priority_maps_as_models_documents(priority: str, expected: EvidenceSeverity) -> None:
    """All eight syslog levels, in both the spelling a rules file uses and the JSON output's."""
    for spelling in (priority, priority.upper(), priority.capitalize()):
        record = {**FALCO_RECORD, "priority": spelling}
        assert falco_source.normalise(_raw(record), NO_OPTIONS).severity is expected


def test_falco_rejects_a_priority_outside_the_eight() -> None:
    """A ninth value is a changed upstream vocabulary, never something to rank by guess."""
    with pytest.raises(SeverityNotRecognised) as refusal:
        falco_source.normalise(_raw({**FALCO_RECORD, "priority": "severe"}), NO_OPTIONS)
    assert "severe" in str(refusal.value)


def test_falco_normalises_the_minimal_record() -> None:
    """Source, subject, summary and timestamp all come from the record and from nowhere else."""
    normalised = falco_source.normalise(_raw(FALCO_RECORD), NO_OPTIONS)
    assert normalised.source is EvidenceSource.FALCO
    assert normalised.resource == ResourceRef(ns="boutique", kind="Pod", name="frontend-7d9c-abcde")
    assert normalised.summary == FALCO_RECORD["output"]
    assert normalised.ts == datetime(2026, 8, 26, 10, 30, 0, 123456, tzinfo=UTC)
    assert normalised.excerpt_candidates[0] == "rule=Terminal shell in container"
    assert "proc.cmdline=bash -i" in normalised.excerpt_candidates


def test_falco_signal_id_is_the_rule_name() -> None:
    """Falco's structured detection signal is its rule name, captured as its own field (M10)."""
    normalised = falco_source.normalise(_raw(FALCO_RECORD), NO_OPTIONS)
    assert normalised.signal_id == "Terminal shell in container"


def test_falco_subject_ladder_falls_back_from_pod_to_container_to_node() -> None:
    """The most specific subject the record supports, never one it does not."""
    fields = dict(FALCO_RECORD["output_fields"])
    fields.pop("k8s.pod.name")
    container = falco_source.normalise(_raw({**FALCO_RECORD, "output_fields": fields}), NO_OPTIONS)
    assert container.resource == ResourceRef(ns="boutique", kind="Container", name="9f2c1b7ae001")

    bare = {
        key: value for key, value in fields.items() if not key.startswith(("k8s.", "container."))
    }
    node = falco_source.normalise(_raw({**FALCO_RECORD, "output_fields": bare}), NO_OPTIONS)
    assert node.resource == ResourceRef(ns=None, kind="Node", name="kind-worker")


def test_falco_treats_the_unresolved_placeholder_as_absence() -> None:
    """``<NA>`` must never reach an event as though somebody had created a namespace called that."""
    fields = {**FALCO_RECORD["output_fields"], "k8s.ns.name": "<NA>", "k8s.pod.name": "<NA>"}
    normalised = falco_source.normalise(_raw({**FALCO_RECORD, "output_fields": fields}), NO_OPTIONS)
    assert normalised.resource.ns is None
    assert normalised.resource.kind == "Container"
    assert all("<NA>" not in candidate for candidate in normalised.excerpt_candidates)


def test_falco_unranked_output_fields_are_sorted_not_left_in_document_order() -> None:
    """The candidate list's tail is ordered by an explicit rule, not by the parser's order."""
    fields = {"zulu.field": "z", "alpha.field": "a", "proc.cmdline": "bash -i"}
    normalised = falco_source.normalise(_raw({**FALCO_RECORD, "output_fields": fields}), NO_OPTIONS)
    tail = [c for c in normalised.excerpt_candidates if c.startswith(("zulu.", "alpha."))]
    assert tail == ["alpha.field=a", "zulu.field=z"]


# --- Prometheus / Alertmanager --------------------------------------------------------------------

PROMETHEUS_SEVERITY_TABLE = (
    ("critical", EvidenceSeverity.CRITICAL),
    ("warning", EvidenceSeverity.MEDIUM),
    ("info", EvidenceSeverity.INFO),
)


@pytest.mark.parametrize(("label", "expected"), PROMETHEUS_SEVERITY_TABLE)
def test_prometheus_severity_label_maps_as_models_documents(
    label: str, expected: EvidenceSeverity
) -> None:
    """Only the three values this project's own alerting rules may emit."""
    labels = {**PROMETHEUS_ALERT["labels"], "severity": label}
    normalised = prometheus_source.normalise(
        _raw({**PROMETHEUS_ALERT, "labels": labels}), NO_OPTIONS
    )
    assert normalised.severity is expected


def test_prometheus_warning_and_falco_warning_normalise_to_the_same_level() -> None:
    """The same word from two sources must not mean two things after normalisation."""
    from_falco = falco_source.normalise(_raw({**FALCO_RECORD, "priority": "Warning"}), NO_OPTIONS)
    from_alert = prometheus_source.normalise(_raw(PROMETHEUS_ALERT), NO_OPTIONS)
    assert from_falco.severity is from_alert.severity is EvidenceSeverity.MEDIUM


def test_prometheus_rejects_an_unknown_and_a_missing_severity_label() -> None:
    """Both are rule defects; neither is guessed."""
    labels = {**PROMETHEUS_ALERT["labels"], "severity": "page"}
    with pytest.raises(SeverityNotRecognised):
        prometheus_source.normalise(_raw({**PROMETHEUS_ALERT, "labels": labels}), NO_OPTIONS)

    labels = {key: v for key, v in PROMETHEUS_ALERT["labels"].items() if key != "severity"}
    with pytest.raises(MissingSourceField):
        prometheus_source.normalise(_raw({**PROMETHEUS_ALERT, "labels": labels}), NO_OPTIONS)


def test_prometheus_normalises_the_minimal_alert() -> None:
    """``startsAt`` is the event time and the summary comes from the conventional annotation."""
    normalised = prometheus_source.normalise(_raw(PROMETHEUS_ALERT), NO_OPTIONS)
    assert normalised.source is EvidenceSource.PROMETHEUS
    assert normalised.ts == datetime(2026, 8, 26, 10, 31, tzinfo=UTC)
    assert normalised.summary == "Pod is crash looping."
    assert normalised.resource == ResourceRef(
        ns="boutique", kind="Pod", name="cartservice-6b5f-zzzzz"
    )
    # The annotation the summary was taken from does not also appear as an excerpt candidate.
    assert not any(c.startswith("annotation.summary=") for c in normalised.excerpt_candidates)
    assert "annotation.description=" in normalised.excerpt_candidates[1]


def test_prometheus_signal_id_is_the_alertname_even_when_a_workload_is_named() -> None:
    """The signal is the alertname label, read unconditionally (M10).

    The minimal alert resolves a Pod subject, so alertname is *not* reached by either fallback
    branch (_resource, _summary); the signal must still be it, which is what makes the read
    unconditional rather than incidental.
    """
    normalised = prometheus_source.normalise(_raw(PROMETHEUS_ALERT), NO_OPTIONS)
    assert normalised.resource.kind == "Pod"
    assert normalised.signal_id == "KubePodCrashLooping"


def test_prometheus_falls_back_to_the_alert_itself_and_never_to_the_scrape_job() -> None:
    """An alert naming no workload is about the alert; the Prometheus ``job`` label is not a Job."""
    labels = {
        "alertname": "NodeFilesystemAlmostOutOfSpace",
        "severity": "critical",
        "job": "node-exporter",
        "instance": "10.244.1.7:9100",
    }
    normalised = prometheus_source.normalise(
        _raw({**PROMETHEUS_ALERT, "labels": labels}), NO_OPTIONS
    )
    assert normalised.resource == ResourceRef(
        ns=None, kind="Alert", name="NodeFilesystemAlmostOutOfSpace"
    )


# --- Kubernetes audit ---------------------------------------------------------------------------


def test_audit_refuses_a_record_with_no_severity_assigned() -> None:
    """The stream carries none of its own, and this module will not manufacture one."""
    with pytest.raises(AuditSeverityNotAssigned):
        k8s_audit_source.normalise(_raw(AUDIT_RECORD), NO_OPTIONS)


@pytest.mark.parametrize("level", ["None", "Metadata", "Request", "RequestResponse"])
def test_audit_level_never_influences_severity(level: str) -> None:
    """``level`` is a verbosity setting. All four produce the severity the caller assigned.

    This is the assertion that stops a fully recorded ConfigMap read outranking a metadata-only
    privilege escalation -- the specific misreading ``models.py`` warns about.
    """
    options = NormaliserOptions(audit_severity=EvidenceSeverity.LOW)
    normalised = k8s_audit_source.normalise(_raw({**AUDIT_RECORD, "level": level}), options)
    assert normalised.severity is EvidenceSeverity.LOW
    assert f"level={level}" in normalised.excerpt_candidates


def test_audit_refuses_another_group_version() -> None:
    """The field set is version-specific, so a different version is refused rather than guessed."""
    with pytest.raises(NormalisationError) as refusal:
        k8s_audit_source.normalise(
            _raw({**AUDIT_RECORD, "apiVersion": "audit.k8s.io/v2"}),
            NormaliserOptions(audit_severity=EvidenceSeverity.LOW),
        )
    assert "audit.k8s.io/v2" in str(refusal.value)


def test_audit_refuses_a_non_event_kind() -> None:
    """The documented audit.k8s.io/v1 payload is specifically an Event object."""
    with pytest.raises(NormalisationError) as refusal:
        k8s_audit_source.normalise(
            _raw({**AUDIT_RECORD, "kind": "EventList"}),
            NormaliserOptions(audit_severity=EvidenceSeverity.LOW),
        )
    assert "EventList" in str(refusal.value)
    assert "Event" in str(refusal.value)


def test_audit_normalises_the_minimal_record() -> None:
    """Plural resource kept as reported; summary composed from the documented template."""
    options = NormaliserOptions(audit_severity=EvidenceSeverity.HIGH)
    normalised = k8s_audit_source.normalise(_raw(AUDIT_RECORD), options)
    assert normalised.source is EvidenceSource.K8S_AUDIT
    assert normalised.ts == datetime(2026, 8, 26, 10, 32, 0, 123456, tzinfo=UTC)
    assert normalised.resource == ResourceRef(ns="boutique", kind="pods", name="attacker-pod")
    assert normalised.summary == (
        "create pods boutique/attacker-pod by system:anonymous -> 201 Success"
    )
    assert "user.groups=system:unauthenticated" in normalised.excerpt_candidates
    assert "annotation.authorization.k8s.io/decision=allow" in normalised.excerpt_candidates


def test_audit_signal_id_is_verb_and_resource_and_is_null_for_a_non_resource_url() -> None:
    """The audit signal is the ``verb:objectRef.resource`` pair, null when there is no resource
    (M10).

    A resource request pairs the verb with the plural resource name as reported; a non-resource
    request -- /healthz, the discovery endpoints -- has no objectRef.resource and therefore no pair,
    so its signal is null rather than a manufactured one. This is the nullable case the whole
    field is nullable for.
    """
    options = NormaliserOptions(audit_severity=EvidenceSeverity.HIGH)
    resource_request = k8s_audit_source.normalise(_raw(AUDIT_RECORD), options)
    assert resource_request.signal_id == "create:pods"

    non_resource = {key: value for key, value in AUDIT_RECORD.items() if key != "objectRef"}
    non_resource["requestURI"] = "/healthz"
    non_resource["verb"] = "get"
    normalised = k8s_audit_source.normalise(
        _raw(non_resource), NormaliserOptions(audit_severity=EvidenceSeverity.INFO)
    )
    assert normalised.resource.kind == "NonResourceURL"
    assert normalised.signal_id is None


def test_audit_names_a_non_resource_request_by_its_own_kubernetes_term() -> None:
    """No ``objectRef`` means a non-resource URL, which RBAC already has a name for."""
    record = {key: value for key, value in AUDIT_RECORD.items() if key != "objectRef"}
    record["requestURI"] = "/healthz"
    normalised = k8s_audit_source.normalise(
        _raw(record), NormaliserOptions(audit_severity=EvidenceSeverity.INFO)
    )
    assert normalised.resource == ResourceRef(ns=None, kind="NonResourceURL", name="/healthz")


def test_audit_names_a_collection_request_by_its_request_uri() -> None:
    """``objectRef`` with no name is a collection request; the URI identifies it exactly."""
    object_ref = {key: v for key, v in AUDIT_RECORD["objectRef"].items() if key != "name"}
    record = {
        **AUDIT_RECORD,
        "objectRef": object_ref,
        "verb": "list",
        "requestURI": "/api/v1/namespaces/boutique/pods",
    }
    normalised = k8s_audit_source.normalise(
        _raw(record), NormaliserOptions(audit_severity=EvidenceSeverity.INFO)
    )
    assert normalised.resource.name == "/api/v1/namespaces/boutique/pods"
    assert normalised.resource.kind == "pods"


# --- Trivy ----------------------------------------------------------------------------------------

TRIVY_SEVERITY_TABLE = (
    ("CRITICAL", EvidenceSeverity.CRITICAL),
    ("HIGH", EvidenceSeverity.HIGH),
    ("MEDIUM", EvidenceSeverity.MEDIUM),
    ("LOW", EvidenceSeverity.LOW),
    ("UNKNOWN", EvidenceSeverity.INFO),
)


@pytest.mark.parametrize(("severity", "expected"), TRIVY_SEVERITY_TABLE)
def test_trivy_severity_maps_as_models_documents(severity: str, expected: EvidenceSeverity) -> None:
    """UNKNOWN maps to the floor: a finding the scanner declined to rank is not above one it did."""
    record = {**TRIVY_VULNERABILITY, "Severity": severity}
    assert trivy_source.normalise(_raw(record, TRIVY_CONTEXT), NO_OPTIONS).severity is expected


def test_trivy_normalises_the_minimal_finding() -> None:
    """The report's creation time is the event time and the artefact is the subject."""
    normalised = trivy_source.normalise(_raw(TRIVY_VULNERABILITY, TRIVY_CONTEXT), NO_OPTIONS)
    assert normalised.source is EvidenceSource.TRIVY
    assert normalised.ts == datetime(2026, 8, 26, 10, 33, tzinfo=UTC)
    assert normalised.resource == ResourceRef(
        ns=None, kind="Image", name="docker.io/library/vulnerable-app:1.0"
    )
    assert normalised.summary == TRIVY_VULNERABILITY["Title"]
    assert normalised.excerpt_candidates[0] == "VulnerabilityID=CVE-2026-00001"
    assert "CweIDs=CWE-120" in normalised.excerpt_candidates


def test_trivy_signal_id_is_the_vulnerability_id() -> None:
    """Trivy's structured detection signal is the CVE/advisory identifier (M10)."""
    normalised = trivy_source.normalise(_raw(TRIVY_VULNERABILITY, TRIVY_CONTEXT), NO_OPTIONS)
    assert normalised.signal_id == "CVE-2026-00001"


def test_trivy_drops_the_nested_objects_rather_than_rendering_them() -> None:
    """A container repr is a rendering artefact, not source text, and would occupy a capped slot."""
    normalised = trivy_source.normalise(_raw(TRIVY_VULNERABILITY, TRIVY_CONTEXT), NO_OPTIONS)
    assert not any(candidate.startswith("CVSS=") for candidate in normalised.excerpt_candidates)


def test_trivy_composes_a_summary_when_the_report_carries_no_title() -> None:
    """Trivy documents Title as possibly empty; the fallback uses only guaranteed fields."""
    record = {key: v for key, v in TRIVY_VULNERABILITY.items() if key != "Title"}
    normalised = trivy_source.normalise(_raw(record, TRIVY_CONTEXT), NO_OPTIONS)
    assert normalised.summary == "CVE-2026-00001 affects openssl 3.0.1-r0"


def test_trivy_refuses_a_report_with_no_creation_time_rather_than_reading_a_clock() -> None:
    """Substituting a clock reading would make the twice-and-diff unpassable."""
    context = {key: v for key, v in TRIVY_CONTEXT.items() if key != "CreatedAt"}
    with pytest.raises(TimestampNotUsable):
        trivy_source.normalise(_raw(TRIVY_VULNERABILITY, context), NO_OPTIONS)


# --- the reader: byte spans -----------------------------------------------------------------------


def test_json_lines_spans_resolve_to_exactly_the_record() -> None:
    """Slice the original bytes at the reported offset and length; parse; compare."""
    import json

    data = b'{"a": 1}\n\n{"b": "\xc3\xa9\xc3\xa9\xc3\xa9"}\n{"c": 3}\n'
    records = list(read_records(data, k8s_audit_source.LOCATOR))
    assert [record.value for record in records] == [{"a": 1}, {"b": "\u00e9\u00e9\u00e9"}, {"c": 3}]
    for record in records:
        sliced = data[record.offset : record.offset + record.length]
        assert json.loads(sliced.decode("utf-8")) == record.value


def test_json_document_spans_resolve_to_exactly_the_record() -> None:
    """The same, for records nested inside one document rather than framed by newlines."""
    import json

    document = {
        "version": "4",
        "status": "firing",
        "alerts": [
            {"labels": {"alertname": "One"}, "note": "caf\u00e9"},
            {"labels": {"alertname": "Two"}},
        ],
    }
    data = json.dumps(document, indent=2).encode("utf-8")
    records = list(read_records(data, prometheus_source.LOCATOR))
    assert len(records) == 2
    for record, expected in zip(records, document["alerts"], strict=True):
        sliced = data[record.offset : record.offset + record.length]
        assert json.loads(sliced.decode("utf-8")) == expected


def test_trivy_context_travels_down_two_levels_onto_every_record() -> None:
    """Document context and group context both reach the record the normaliser sees."""
    import json

    document = {
        "SchemaVersion": 2,
        "CreatedAt": "2026-08-26T10:33:00Z",
        "ArtifactName": "img:1",
        "ArtifactType": "container_image",
        "Results": [
            {
                "Target": "t1",
                "Class": "os-pkgs",
                "Type": "alpine",
                "Vulnerabilities": [TRIVY_VULNERABILITY],
            },
            {"Target": "t2", "Class": "lang-pkgs", "Type": "gobinary"},
        ],
    }
    data = json.dumps(document).encode("utf-8")
    records = list(read_records(data, trivy_source.LOCATOR))
    assert len(records) == 1
    assert records[0].context["ArtifactName"] == "img:1"
    assert records[0].context["Target"] == "t1"
    sliced = data[records[0].offset : records[0].offset + records[0].length]
    assert json.loads(sliced.decode("utf-8")) == TRIVY_VULNERABILITY


def test_a_missing_records_key_is_an_error_and_an_explicit_null_is_an_empty_result() -> None:
    """A mistyped locator and a scan that found nothing must not report the same thing."""
    with pytest.raises(RecordLayoutError):
        list(read_records(b'{"version": "4"}', prometheus_source.LOCATOR))
    assert list(read_records(b'{"version": "4", "alerts": null}', prometheus_source.LOCATOR)) == []


@pytest.mark.parametrize(
    ("data", "locator"),
    [
        (b'{"version":"4","alerts":[]} garbage', prometheus_source.LOCATOR),
        (b'{"SchemaVersion":2,"Results":[]}{}', trivy_source.LOCATOR),
    ],
)
def test_json_documents_reject_trailing_non_whitespace(data: bytes, locator: Any) -> None:
    """A valid prefix is not a document; accepting it would ignore attacker-controlled bytes."""
    with pytest.raises(RecordLayoutError, match="trailing data"):
        list(read_records(data, locator))


@pytest.mark.parametrize(
    ("data", "locator", "member"),
    [
        (b'{"version":"4","version":"3","alerts":[]}', prometheus_source.LOCATOR, "version"),
        (
            b'{"SchemaVersion":2,"Results":[{"Target":"one","Target":"two"}]}',
            trivy_source.LOCATOR,
            "Target",
        ),
        (
            b'{"version":"4","alerts":[{"labels":{"severity":"warning","severity":"info"}}]}',
            prometheus_source.LOCATOR,
            "severity",
        ),
    ],
)
def test_json_documents_reject_duplicate_members(data: bytes, locator: Any, member: str) -> None:
    """Duplicate names must not acquire the standard decoder's last-wins meaning."""
    with pytest.raises(RecordLayoutError, match=member):
        list(read_records(data, locator))


def test_json_lines_reject_duplicate_members() -> None:
    """Strict member handling applies to line-oriented aggregator inputs too."""
    with pytest.raises(RecordLayoutError, match="kind"):
        list(
            read_records(
                b'{"apiVersion":"audit.k8s.io/v1","kind":"Event","kind":"EventList"}\n',
                k8s_audit_source.LOCATOR,
            )
        )


@pytest.mark.parametrize(
    ("data", "locator", "field"),
    [
        (b'{"version":"3","alerts":[]}', prometheus_source.LOCATOR, "version"),
        (b'{"alerts":[]}', prometheus_source.LOCATOR, "version"),
        (b'{"SchemaVersion":1,"Results":[]}', trivy_source.LOCATOR, "SchemaVersion"),
        (b'{"Results":[]}', trivy_source.LOCATOR, "SchemaVersion"),
    ],
)
def test_json_documents_enforce_upstream_versions_even_when_empty(
    data: bytes, locator: Any, field: str
) -> None:
    """Document contracts are checked before record iteration, including zero-record payloads."""
    with pytest.raises(RecordLayoutError, match=field):
        list(read_records(data, locator))


# --- the registry and the emission order --------------------------------------------------------


def test_the_registry_is_ordered_ranked_and_total_over_the_four_sources() -> None:
    """Ranks are the tuple positions, unique, and in architecture section 3's own order."""
    assert tuple(entry.source for entry in SOURCE_REGISTRY) == tuple(EvidenceSource)
    assert tuple(entry.rank for entry in SOURCE_REGISTRY) == (0, 1, 2, 3)
    assert len({entry.input_filename for entry in SOURCE_REGISTRY}) == len(SOURCE_REGISTRY)
    for source in EvidenceSource:
        assert registry_entry(source).source is source


def test_the_registry_ranks_are_not_alphabetical() -> None:
    """Recorded as an assertion so that "sort the sources" cannot be applied as a tidy-up.

    Alphabetical order would silently reshuffle every existing fixture's golden output the day a
    fifth family is added, whereas a registry makes the placement a line in a diff.
    """
    names = [str(entry.source) for entry in SOURCE_REGISTRY]
    assert names != sorted(names)


def _aggregated(record: NormalisedRecord, rank: int, offset: int = 0) -> AggregatedRecord:
    return AggregatedRecord(
        record=record,
        raw_ref=RawRef(path="monitor/fixtures/x/in.jsonl", offset=offset, length=8),
        event_id=compute_event_id(record),
        rank=rank,
    )


def test_event_id_is_a_pure_function_of_the_projection() -> None:
    """Two computations over one record agree; the digest has the shape the contract admits."""
    normalised = falco_source.normalise(_raw(FALCO_RECORD), NO_OPTIONS)
    first = compute_event_id(normalised)
    second = compute_event_id(falco_source.normalise(_raw(FALCO_RECORD), NO_OPTIONS))
    assert first == second
    assert len(first) == 64
    assert first == first.lower()
    assert all(character in "0123456789abcdef" for character in first)


def test_event_id_changes_when_any_projected_field_changes() -> None:
    """A different source event must not collide with another one."""
    base = falco_source.normalise(_raw(FALCO_RECORD), NO_OPTIONS)
    changed_summary = falco_source.normalise(
        _raw({**FALCO_RECORD, "output": FALCO_RECORD["output"] + "."}), NO_OPTIONS
    )
    changed_rule = falco_source.normalise(
        _raw({**FALCO_RECORD, "rule": "Another rule"}), NO_OPTIONS
    )
    identifiers = {
        compute_event_id(base),
        compute_event_id(changed_summary),
        compute_event_id(changed_rule),
    }
    assert len(identifiers) == 3


def test_event_id_separates_two_records_a_nanosecond_apart() -> None:
    """``ts`` truncates to microseconds; the discriminator holds the raw text, so they differ."""
    first = falco_source.normalise(_raw(FALCO_RECORD), NO_OPTIONS)
    second = falco_source.normalise(
        _raw({**FALCO_RECORD, "time": "2026-08-26T10:30:00.123456788Z"}), NO_OPTIONS
    )
    assert first.ts == second.ts
    assert compute_event_id(first) != compute_event_id(second)


def test_the_projection_carries_pre_cap_pre_quoting_text_and_no_raw_ref() -> None:
    """The two properties the isolation test and the golden corpus both depend on."""
    normalised = falco_source.normalise(_raw(FALCO_RECORD), NO_OPTIONS)
    projection = identity_projection(normalised)
    assert projection["summary"] == FALCO_RECORD["output"]
    assert projection["excerpt_candidates"] == list(normalised.excerpt_candidates)
    assert "raw_ref" not in projection


def test_emission_order_is_timestamp_then_source_rank_then_event_id() -> None:
    """The explicit total order, asserted against records built to tie on the first two keys."""
    audit_options = NormaliserOptions(audit_severity=EvidenceSeverity.HIGH)
    same_instant = "2026-08-26T10:30:00.000000Z"
    falco_a = falco_source.normalise(
        _raw({**FALCO_RECORD, "time": same_instant, "rule": "A"}), NO_OPTIONS
    )
    falco_b = falco_source.normalise(
        _raw({**FALCO_RECORD, "time": same_instant, "rule": "B"}), NO_OPTIONS
    )
    audit = k8s_audit_source.normalise(
        _raw({**AUDIT_RECORD, "requestReceivedTimestamp": same_instant}), audit_options
    )
    earlier = falco_source.normalise(
        _raw({**FALCO_RECORD, "time": "2026-08-26T09:00:00.000000Z"}), NO_OPTIONS
    )

    items = [
        _aggregated(audit, rank=2, offset=1),
        _aggregated(falco_b, rank=0, offset=2),
        _aggregated(falco_a, rank=0, offset=3),
        _aggregated(earlier, rank=0, offset=4),
    ]
    ranked = ordered(items)
    assert ranked[0].record is earlier
    assert ranked[-1].record is audit
    middle = ranked[1:3]
    assert [item.rank for item in middle] == [0, 0]
    assert [item.event_id for item in middle] == sorted(item.event_id for item in middle)


def test_ordering_does_not_depend_on_the_order_records_arrive_in() -> None:
    """A filesystem that lists a fixture directory differently must not change the output."""
    audit_options = NormaliserOptions(audit_severity=EvidenceSeverity.HIGH)
    items = [
        _aggregated(falco_source.normalise(_raw(FALCO_RECORD), NO_OPTIONS), rank=0),
        _aggregated(prometheus_source.normalise(_raw(PROMETHEUS_ALERT), NO_OPTIONS), rank=1),
        _aggregated(k8s_audit_source.normalise(_raw(AUDIT_RECORD), audit_options), rank=2),
        _aggregated(
            trivy_source.normalise(_raw(TRIVY_VULNERABILITY, TRIVY_CONTEXT), NO_OPTIONS), rank=3
        ),
    ]
    forwards = [item.event_id for item in ordered(items)]
    backwards = [item.event_id for item in ordered(list(reversed(items)))]
    assert forwards == backwards


def test_two_records_projecting_identically_are_refused_rather_than_deduplicated() -> None:
    """Two events with one identifier break the contract; dropping one discards evidence."""
    normalised = falco_source.normalise(_raw(FALCO_RECORD), NO_OPTIONS)
    with pytest.raises(DuplicateEventId) as refusal:
        ordered(
            [_aggregated(normalised, rank=0, offset=0), _aggregated(normalised, rank=0, offset=9)]
        )
    assert compute_event_id(normalised) in str(refusal.value)
