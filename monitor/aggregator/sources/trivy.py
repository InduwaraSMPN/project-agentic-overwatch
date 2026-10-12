"""Normaliser for Trivy vulnerability findings -- the CI/CD signal family.

THE PAYLOAD SHAPE, AND WHERE IT WAS READ FROM
----------------------------------------------
``trivy image --format json`` writes one report document per scan. The structure was read from
Trivy's reporting documentation (https://trivy.dev/latest/docs/configuration/reporting/): a
top-level object carrying ``SchemaVersion``, ``CreatedAt``, ``ArtifactName``, ``ArtifactType``,
``Metadata`` and a ``Results`` array, in which each entry carries ``Target``, ``Class``, ``Type``
and a ``Vulnerabilities`` array. The same page states which vulnerability fields are guaranteed:
"VulnerabilityID, PkgName, InstalledVersion, and Severity in Vulnerabilities are always filled with
values, but other fields might be empty." Everything this module treats as required is drawn from
that sentence, and everything it treats as optional is treated as optional because of it.

**One record is one entry of ``Results[].Vulnerabilities``, not one report.** A report on a single
image routinely carries hundreds of findings across several targets, and one bounded
``EvidenceEvent`` per report could not name any of them.

TWO FACTS EVERY FINDING NEEDS LIVE OUTSIDE THE FINDING
--------------------------------------------------------
A vulnerability entry does not carry the name of the artefact it was found in, nor the time the
report was produced, and an ``EvidenceEvent`` needs both. ``ArtifactName``, ``ArtifactType`` and
``CreatedAt`` are therefore declared as document context on :data:`LOCATOR`, and ``Target``,
``Class`` and ``Type`` as group context from the enclosing ``Results`` entry, so that the reader
copies them onto every record before this module ever sees one. The alternative -- a normaliser
that reaches back up into the document -- would make it a function of two things instead of one and
would leave every other normaliser's signature carrying a document it never reads.

``CreatedAt`` IS THE EVENT TIME, AND ITS ABSENCE IS A FAILURE RATHER THAN A CLOCK READ
---------------------------------------------------------------------------------------
A vulnerability has no time of its own that belongs on the event. ``PublishedDate`` and
``LastModifiedDate`` are properties of the CVE record in the upstream database, not of the
observation -- an event stamped with them would sort a finding about today's image among events
from years ago, which is exactly the sort of ordering error a byte diff cannot catch because it is
consistent. The observation's time is when the scan report was produced, which is ``CreatedAt``.

A report without it cannot be normalised, and this module refuses rather than substituting a
reading of the wall clock: substituting one would make the twice-and-diff unpassable, and nothing
under ``monitor/aggregator/`` reads a clock at all. ``CreatedAt`` is present in the schema version 2
report Trivy writes today; a report that lacks it is an older format, and the fixture provenance is
the place to fix that.

THE SUBJECT IS THE ARTEFACT, NOT AN API OBJECT
------------------------------------------------
A scan finding is about an image, a filesystem or a repository -- ``ArtifactType`` says which -- and
none of those is a namespaced Kubernetes object. So ``ns`` is ``null`` and the name is
``ArtifactName``, which for a container image is the image reference. The kind is ``Image`` for
``container_image`` and otherwise the ``ArtifactType`` value as reported: a mapping table covering
every artefact type Trivy will ever add would be a table this repository has to maintain against a
tool it does not own, and reporting the tool's own word is both honest and stable.

Attributing a finding to the workloads running that image is a *join*, not a normalisation. It
needs the cluster's current pod list, which the Monitor's deterministic replay path does not have
and must not acquire; the Orchestrator can perform it through the Guardian when it needs to act.

WHY THE UNRANKED FIELDS ARE DROPPED HERE RATHER THAN SORTED IN
----------------------------------------------------------------
The other three normalisers finish their candidate list with every field they did not rank, sorted
by key, because those fields are scalars. A Trivy vulnerability is not flat: ``CVSS``, ``Layer``,
``VendorSeverity`` and ``DataSource`` are nested objects, and rendering one as text would put a
Python container repr into the evidence stream -- a rendering artefact that is neither the source's
bytes nor anything a responder can act on, occupying a capped excerpt slot. So this module's
candidate list is exactly :data:`RANKED_FIELDS` plus the two list fields rendered explicitly, and
anything else stays in the raw record where ``raw_ref`` points at it.
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
    rendered_pairs,
    require_text,
)

SOURCE: Final = EvidenceSource.TRIVY

# One report document. Records live two levels down, under Results[].Vulnerabilities, and the
# context declarations carry down the six facts a finding needs but does not hold.
SUPPORTED_SCHEMA_VERSION: Final = 2

LOCATOR: Final = RecordLocator(
    layout=RecordLayout.JSON_DOCUMENT,
    record_key="Vulnerabilities",
    document_context=("ArtifactName", "ArtifactType", "CreatedAt", "SchemaVersion"),
    group_key="Results",
    group_context=("Target", "Class", "Type"),
    required_document_values=(("SchemaVersion", SUPPORTED_SCHEMA_VERSION),),
)

# The canonical filename this source's raw input carries inside a fixture directory.
INPUT_FILENAME: Final = "trivy.json"

# Trivy's five severities onto the normalised scale, exactly as models.py's table states. UNKNOWN
# maps to info -- the floor, meaning "recorded, not ranked as actionable" -- because a finding the
# scanner declined to rank must not be promoted above one it explicitly ranked LOW, and adding an
# `unknown` member to an ordered vocabulary would make every comparison against it undefined.
SEVERITY_TO_SEVERITY: Final[dict[str, EvidenceSeverity]] = {
    "critical": EvidenceSeverity.CRITICAL,
    "high": EvidenceSeverity.HIGH,
    "medium": EvidenceSeverity.MEDIUM,
    "low": EvidenceSeverity.LOW,
    "unknown": EvidenceSeverity.INFO,
}

# ArtifactType values with a Kubernetes-legible kind. Anything else is reported as Trivy words it.
ARTIFACT_KIND: Final[dict[str, str]] = {"container_image": "Image"}

# The vulnerability and context fields this normaliser ranks, in significance order: what the
# finding is, which package carries it, whether a fix exists, where to read about it, and finally
# which target and artefact it was found in.
RANKED_FIELDS: Final[tuple[str, ...]] = (
    "VulnerabilityID",
    "PkgName",
    "InstalledVersion",
    "FixedVersion",
    "Status",
    "PkgID",
    "PrimaryURL",
    "SeveritySource",
    "Title",
    "Description",
    "PublishedDate",
    "LastModifiedDate",
    "Target",
    "Class",
    "Type",
    "ArtifactName",
    "ArtifactType",
)

# List-valued fields rendered as comma-joined text after the ranked scalars, in this order.
RANKED_LIST_FIELDS: Final[tuple[str, ...]] = ("CweIDs", "References")


def _severity(record: dict[str, Any]) -> EvidenceSeverity:
    """Map Trivy's ``Severity`` onto the normalised scale, or raise naming the token."""
    severity = require_text(record, "Severity", source=str(SOURCE))
    try:
        return SEVERITY_TO_SEVERITY[severity.lower()]
    except KeyError:
        raise SeverityNotRecognised(
            f"{SOURCE}: Severity {severity!r} is outside Trivy's documented set "
            f"({', '.join(name.upper() for name in SEVERITY_TO_SEVERITY)}). models.py's mapping "
            "table is the whole normalisation and a sixth value is a changed upstream vocabulary."
        ) from None


def _resource(context: dict[str, Any]) -> ResourceRef:
    """Return the scanned artefact as the subject; never a workload. See the module docstring."""
    artefact = require_text(context, "ArtifactName", source=str(SOURCE))
    artefact_type = optional_text(context.get("ArtifactType"))
    kind = ARTIFACT_KIND.get(artefact_type or "", artefact_type or "Artifact")
    return ResourceRef(ns=None, kind=kind, name=artefact)


def _summary(record: dict[str, Any], merged: dict[str, Any]) -> str:
    """Return the finding's ``Title``, or a composed line when the report carries none.

    Trivy's own ``Title`` is the upstream advisory's one-line description and is the right summary
    whenever it is present. It is documented as possibly empty, and when it is, the summary is
    composed from the three fields the same documentation guarantees::

        <VulnerabilityID> affects <PkgName> <InstalledVersion>

    Composed rather than left blank, because a blank summary is a normaliser defect rather than a
    finding with nothing to say, and composed from guaranteed fields so that the fallback cannot
    itself fail on an absent value.
    """
    title = optional_text(record.get("Title"))
    if title is not None:
        return title
    return f"{merged['VulnerabilityID']} affects {merged['PkgName']} {merged['InstalledVersion']}"


def normalise(raw: RawRecord, options: NormaliserOptions) -> NormalisedRecord:
    """Turn one entry of ``Results[].Vulnerabilities`` into a normalised record.

    ``options`` is unread: a Trivy finding carries its own severity, and its time arrives as
    document context. The parameter is present because the registry dispatches over one uniform
    signature.
    """
    del options
    record = dict(raw.value)
    context = dict(raw.context)

    # Guaranteed by Trivy's own documentation; read through require_text so that a fixture which
    # omits one fails here, naming the field, rather than three modules downstream.
    for guaranteed in ("VulnerabilityID", "PkgName", "InstalledVersion"):
        require_text(record, guaranteed, source=str(SOURCE))

    # The structured detection signal for a Trivy finding is the CVE (or advisory) identifier, which
    # is exactly what detection precision and recall are scored against and is ranked first among
    # the
    # excerpts too. Guaranteed present by the loop above, so Trivy's signal_id is never null.
    signal_id = require_text(record, "VulnerabilityID", source=str(SOURCE))

    raw_created_at = context.get("CreatedAt")
    ts = parse_source_timestamp(raw_created_at, source=str(SOURCE), field_name="CreatedAt")

    # Context first so that a vulnerability field of the same name wins; no such collision exists
    # in the shapes above, and this ordering states which side would win if Trivy ever created one.
    merged: dict[str, Any] = {**context, **record}

    candidates = rendered_pairs(merged, keys=RANKED_FIELDS)
    for key in RANKED_LIST_FIELDS:
        value = merged.get(key)
        if isinstance(value, list) and value:
            candidates = (*candidates, f"{key}=" + ",".join(str(item) for item in value))

    return NormalisedRecord(
        source=SOURCE,
        ts=ts,
        severity=_severity(record),
        signal_id=signal_id,
        resource=_resource(context),
        summary=_summary(record, merged),
        excerpt_candidates=candidates,
        # Trivy's natural key. A finding is identified by the artefact, the target within it, the
        # package instance and the advisory; the report's own creation time separates two scans of
        # the same image, which would otherwise project identically.
        discriminator=(
            ("ArtifactName", optional_text(context.get("ArtifactName")) or ""),
            ("Target", optional_text(context.get("Target")) or ""),
            ("PkgID", optional_text(record.get("PkgID")) or ""),
            ("PkgName", optional_text(record.get("PkgName")) or ""),
            ("InstalledVersion", optional_text(record.get("InstalledVersion")) or ""),
            ("VulnerabilityID", optional_text(record.get("VulnerabilityID")) or ""),
            ("CreatedAt", str(raw_created_at)),
        )
        # A package can occur in multiple JARs under one target without PkgID.
        # Preserve old keys when the scanner reports no instance path (ADR-167).
        + ((("PkgPath", path),) if (path := optional_text(record.get("PkgPath"))) else ()),
    )
