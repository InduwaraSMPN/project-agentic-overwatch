"""The freeze check: the ``EvidenceEvent`` v1 contract, its exported schema, and its bytes.

WHAT THIS TEST IS FOR
---------------------
``monitor/aggregator/models.py`` and ``monitor/aggregator/schema/evidence_event.v2.json`` are two
descriptions of one contract, and a repository that holds two descriptions of anything holds a
drift risk. This file is what makes the second copy legal, on exactly the pattern ADR-016 settled
for the instrument constants: regenerate the schema from the model here, in the test, and compare it
to the tracked artefact, so an edit to one that is not accompanied by the other fails CI instead of
diverging quietly. Everything else in this file guards a property of the contract that a reviewer
would otherwise have to take on trust.

If the comparison fails, the model is right and the tracked file is stale. Regenerating it is one
command, ``python -m monitor.aggregator.models``, and the failure message says so. What the message
also says, and means, is that the resulting diff is a change to a frozen contract rather than a
formatting fix: four other milestones build against this shape, every sealed run bundle carries
``monitor_events.jsonl`` in it, and after the pilot gate freeze at ``v1.0`` iron rule 6 makes a
change here a logged hotfix ADR.

WHY THE COMPARISON IS BYTE FOR BYTE AND NOT PARSED EQUALITY
------------------------------------------------------------
Parsed equality would compare the two documents as data and pass while the tracked file's
whitespace, key order or encoding drifted away from what the generator produces. That matters here
more than it usually would, because the tracked file is an artefact this repository *publishes* as
the contract: a consumer fetches those bytes, not this repository's idea of them. The same
reasoning runs through the milestone -- its Definition of Done is a ``cmp`` rather than a judgement
-- so this file holds the schema to the standard the determinism tests hold the event stream to,
and there is one notion of "matches" in the component instead of two.

WHY THE TEN FIELD NAMES ARE SPELLED OUT AGAIN BELOW
------------------------------------------------------
:data:`ARCHITECTURE_SECTION_3_FIELDS` is not imported from the model, and that is the whole point.
A test that asked the model what its fields are and then checked the model against the answer would
pass for any field set whatsoever. The names are transcribed from ``docs/02-architecture.md``
section 3, which sits above code in the precedence order ``.agents/rules/00-source-of-truth.md``
fixes, so this constant is the architecture's side of the comparison and the model is the code's
side. Adding a field to the model without amending the architecture fails here. ``signal_id`` was
added this way at M10 (ADR-125): the architecture sentence gained it first, and it is transcribed
below in the position section 3 lists it -- after ``source``, before ``severity``.

WHAT THIS FILE MAY IMPORT
-------------------------
The standard library, pytest and pydantic, and nothing else, for the reason ``monitor/tests/``'s
package marker gives: those are what CI installs. Note in particular that no timezone is built from
an IANA name anywhere below -- :mod:`zoneinfo` needs the ``tzdata`` package, which is present on the
runner and absent from the Windows development host, so a test written that way would pass in one
place and fail in the other for a reason that has nothing to do with the contract.
"""

import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

# The repository root, derived from this file's own location rather than from the working directory,
# so the tracked schema is read from the same place whether pytest was invoked from the repository
# root, from monitor/, or from anywhere else. The root is prepended to sys.path because `monitor` is
# only importable when it is on there, and the CI step's working directory is a property of the
# workflow rather than something this file should depend on.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from monitor.aggregator.models import (  # noqa: E402
    SCHEMA_RELATIVE_PATH,
    SCHEMA_VERSION,
    EvidenceEvent,
    EvidenceSeverity,
    EvidenceSource,
    RawRef,
    ResourceRef,
    canonical_json_line,
    evidence_event_json_schema,
    schema_json_bytes,
)

# Transcribed from docs/02-architecture.md section 3's EvidenceEvent sentence, in the order it lists
# them. See the module docstring for why this is a literal here and not an import.
ARCHITECTURE_SECTION_3_FIELDS = (
    "event_id",
    "ts",
    "source",
    "signal_id",
    "severity",
    "resource",
    "summary",
    "evidence_excerpts",
    "raw_ref",
    "schema_version",
)

# The four source names architecture section 3 admits, and the nested field names it gives for
# `resource`. Transcribed from the same sentence, for the same reason.
ARCHITECTURE_SECTION_3_SOURCES = ("falco", "prometheus", "k8s_audit", "trivy")
ARCHITECTURE_SECTION_3_RESOURCE_FIELDS = ("ns", "kind", "name")

# A well-formed event_id: the digest of an arbitrary byte string, computed rather than written as a
# literal so that this constant demonstrates the construct emit.py uses instead of a magic string
# that only looks like one.
VALID_EVENT_ID = hashlib.sha256(b"T2.1 fixture event").hexdigest()

TRACKED_SCHEMA = REPO_ROOT / SCHEMA_RELATIVE_PATH


def _payload(**overrides: object) -> dict[str, object]:
    """Return the keyword arguments of one valid event, with ``overrides`` applied.

    Kept as a plain dictionary rather than as a built model so that a test can *remove* a key before
    construction, which is the only way to exercise a required field.
    """
    payload: dict[str, object] = {
        "event_id": VALID_EVENT_ID,
        "ts": datetime(2026, 3, 1, 12, 30, 0, tzinfo=UTC),
        "source": EvidenceSource.FALCO,
        "signal_id": "Terminal shell in container",
        "severity": EvidenceSeverity.HIGH,
        "resource": {"ns": "boutique", "kind": "Pod", "name": "frontend-7d9c8"},
        "summary": "A shell was spawned inside an application container",
        "evidence_excerpts": ("proc.cmdline=sh -c id",),
        "raw_ref": {
            "path": "monitor/fixtures/falco-shell-in-container/falco.jsonl",
            "offset": 0,
            "length": 412,
        },
        "schema_version": SCHEMA_VERSION,
    }
    payload.update(overrides)
    return payload


def _event(**overrides: object) -> EvidenceEvent:
    """Build one valid :class:`EvidenceEvent`, with ``overrides`` applied."""
    return EvidenceEvent(**_payload(**overrides))


def _error_types(excinfo: pytest.ExceptionInfo[ValidationError]) -> list[str]:
    """Return the machine-readable error tags of a validation failure.

    Assertions are made against these rather than against the rendered message, because the message
    is prose that a Pydantic release is free to reword and the tag is the part that is contractual.
    """
    return [error["type"] for error in excinfo.value.errors()]


# --- the drift check itself -----------------------------------------------------------------------


def test_tracked_schema_export_exists() -> None:
    """The artefact the contract is published as must be present and tracked."""
    assert TRACKED_SCHEMA.is_file(), (
        f"The exported JSON Schema is missing from {SCHEMA_RELATIVE_PATH}. It is generated, not "
        "hand-written: run `python -m monitor.aggregator.models` from the repository root."
    )


def test_tracked_schema_is_byte_identical_to_the_model_export() -> None:
    """Regenerating the schema from the model must reproduce the tracked file exactly."""
    generated = schema_json_bytes()
    tracked = TRACKED_SCHEMA.read_bytes()
    assert tracked == generated, (
        f"{SCHEMA_RELATIVE_PATH} no longer matches what monitor/aggregator/models.py exports. "
        "Regenerate it with `python -m monitor.aggregator.models` and read the diff before "
        "committing: this is a change to a frozen contract that M4 and every sealed run bundle "
        "depend on, not a formatting fix."
    )


def test_tracked_schema_has_unix_line_endings_and_one_trailing_newline() -> None:
    """The published artefact is LF-terminated, whatever host wrote it.

    ``.gitattributes`` normalises ``*.json`` through its ``* text=auto eol=lf`` rule, but the file
    is written by :func:`~monitor.aggregator.models.main` in binary mode precisely so the bytes are
    right before Git ever sees them. A CRLF here would differ from what CI regenerates on Linux in
    every single line while looking identical in every editor.
    """
    tracked = TRACKED_SCHEMA.read_bytes()
    assert b"\r" not in tracked
    assert tracked.endswith(b"}\n")


def test_schema_file_name_carries_the_version_constant() -> None:
    """The artefact's name and the value stamped into every event cannot drift apart.

    ``SCHEMA_RELATIVE_PATH`` is built from ``SCHEMA_VERSION``, so this asserts the property that
    construction gives rather than re-deriving it: a version bump that arrives without a new
    artefact fails at the lookup above, and the name on disk always names the version inside.
    """
    assert TRACKED_SCHEMA.name == f"evidence_event.{SCHEMA_VERSION}.json"


# --- the field set is architecture section 3's ----------------------------------------------------


def test_model_fields_are_exactly_architecture_section_3s() -> None:
    """Ten fields, those ten, in that order -- no more and no fewer."""
    assert tuple(EvidenceEvent.model_fields) == ARCHITECTURE_SECTION_3_FIELDS


def test_exported_schema_properties_are_exactly_architecture_section_3s() -> None:
    """The published document describes the same nine fields, and requires all of them.

    ``properties`` is compared as a set because the canonical writer sorts object keys; ``required``
    is compared as a sequence because a JSON array keeps its order, which is what makes the exported
    contract read back as section 3's sentence.
    """
    schema = evidence_event_json_schema()
    assert set(schema["properties"]) == set(ARCHITECTURE_SECTION_3_FIELDS)
    assert schema["required"] == list(ARCHITECTURE_SECTION_3_FIELDS)


def test_resource_fields_are_exactly_architecture_section_3s() -> None:
    """Section 3 gives ``resource`` three sub-fields; the nested model carries those three."""
    assert tuple(ResourceRef.model_fields) == ARCHITECTURE_SECTION_3_RESOURCE_FIELDS


def test_no_field_anywhere_in_the_contract_has_a_default() -> None:
    """Every field of every model in the contract is required.

    Stated as one assertion over all three models because the property is the contract's, not any
    one model's: an event that is missing part of itself is a normaliser defect, and a default
    anywhere would turn that defect into a plausible-looking value three components downstream.
    """
    for model in (EvidenceEvent, ResourceRef, RawRef):
        for name, field in model.model_fields.items():
            assert field.is_required(), (
                f"{model.__name__}.{name} has a default; the contract has none"
            )


def test_signal_id_is_required_and_nullable() -> None:
    """The source's own detection signal: required key, may be null, never defaulted.

    Nullable because a non-resource Kubernetes audit URL has no ``verb:resource`` pair to name, and
    required-without-a-default because the key must always be present so a consumer never has to
    tell
    "absent" from "not applicable" -- the same discipline ``resource.ns`` follows. Added at M10
    (ADR-125); the field sits after ``source`` in section 3's order.
    """
    # Present and null is accepted, and serialises as null rather than as a sentinel string.
    event = _event(signal_id=None)
    assert event.signal_id is None
    assert json.loads(canonical_json_line(event))["signal_id"] is None

    # Present and a non-empty string is accepted and preserved verbatim.
    assert _event(signal_id="Terminal shell in container").signal_id == (
        "Terminal shell in container"
    )

    # Omitting the key is a missing-field error, never a silent default -- the property that makes
    # an
    # event missing its signal a normaliser defect caught here rather than three components later.
    payload = _payload()
    del payload["signal_id"]
    with pytest.raises(ValidationError) as excinfo:
        EvidenceEvent(**payload)
    assert _error_types(excinfo) == ["missing"]


# --- schema_version -------------------------------------------------------------------------------


def test_schema_version_is_required() -> None:
    """Omitting the version is an error, never a silent stamp with the current one."""
    payload = _payload()
    del payload["schema_version"]
    with pytest.raises(ValidationError) as excinfo:
        EvidenceEvent(**payload)
    assert _error_types(excinfo) == ["missing"]


def test_schema_version_rejects_an_unknown_version() -> None:
    """A consumer must be able to reject an event of a version it does not understand.

    ``v3`` is the probe here rather than ``v1``: the contract moved to ``v2`` at M10 (ADR-125), so a
    rejected version has to be one this contract does not name, and the previous version would now
    be
    accepted-as-unknown by nothing -- it would simply fail the ``Literal`` like any other non-``v2``
    string, which is the point, but ``v3`` reads as "a version this code has never seen".
    """
    with pytest.raises(ValidationError) as excinfo:
        _event(schema_version="v3")
    assert _error_types(excinfo) == ["literal_error"]


def test_exported_schema_pins_the_version_as_a_constant() -> None:
    """The rejection above is also expressed to consumers that are not written in Python."""
    schema = evidence_event_json_schema()
    assert schema["properties"]["schema_version"]["const"] == SCHEMA_VERSION


# --- extra="forbid" -------------------------------------------------------------------------------


def test_unknown_key_is_rejected() -> None:
    """An unknown key is an error, not something quietly dropped on the way in."""
    with pytest.raises(ValidationError) as excinfo:
        _event(confidence=0.9)
    assert _error_types(excinfo) == ["extra_forbidden"]


def test_unknown_key_is_rejected_inside_the_nested_models_too() -> None:
    """The nested models carry the same setting, so a stowaway cannot enter one level down."""
    with pytest.raises(ValidationError) as excinfo:
        _event(resource={"ns": "boutique", "kind": "Pod", "name": "frontend-7d9c8", "uid": "x"})
    assert _error_types(excinfo) == ["extra_forbidden"]
    with pytest.raises(ValidationError) as excinfo:
        _event(raw_ref={"path": "a/b.jsonl", "offset": 0, "length": 1, "inline": "the raw record"})
    assert _error_types(excinfo) == ["extra_forbidden"]


def test_exported_schema_forbids_additional_properties() -> None:
    """The published document says the same thing to a validator that never loads this model."""
    schema = evidence_event_json_schema()
    assert schema["additionalProperties"] is False
    for definition in ("ResourceRef", "RawRef"):
        assert schema["$defs"][definition]["additionalProperties"] is False


# --- raw_ref is a pointer, and is never absolute --------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/var/log/falco/events.jsonl",  # POSIX absolute
        "C:/Users/induwara/agentic-overwatch/x.jsonl",  # Windows absolute, forward slashes
        "C:\\Users\\induwara\\x.jsonl",  # Windows absolute, backslashes
        "\\\\fileserver\\share\\x.jsonl",  # UNC
        "file:///var/log/falco/events.jsonl",  # URI with a scheme
        "https://example.invalid/events.jsonl",  # remote URL
        "~/falco/events.jsonl",  # shell-expanded home
        "../../etc/shadow",  # escapes the root
        "monitor/../../etc/shadow",  # escapes it from the middle
        "./events.jsonl",  # single-dot segment
        ".",  # the root itself
        "..",  # its parent
        ".hidden/events.jsonl",  # leading-dot segment, the rule that kills . and ..
        "monitor//events.jsonl",  # empty segment
        "monitor/fixtures/",  # trailing separator
        "monitor/fix tures/x.jsonl",  # whitespace
        "monitor/events.jsonl\n",  # trailing newline
        "",  # empty
    ],
)
def test_raw_ref_rejects_a_path_that_is_absolute_or_not_canonical(path: str) -> None:
    """Being never absolute is a checkable property of the contract, not a comment in the model.

    An absolute path encodes the host that produced it, which breaks the byte diff across machines
    while passing perfectly on the machine that produced it. The non-canonical cases are here for a
    related reason: a ``..`` segment lets two different strings denote one file, so an emitted event
    would compare unequal to a replayed one that named the same record differently.
    """
    with pytest.raises(ValidationError) as excinfo:
        _event(raw_ref={"path": path, "offset": 0, "length": 1})
    assert _error_types(excinfo) == ["string_pattern_mismatch"]


@pytest.mark.parametrize(
    "path",
    [
        "events.jsonl",
        "monitor/fixtures/falco-shell-in-container/falco.jsonl",
        "runs/CAMP-PILOT/RUN-0001/monitor_events.jsonl",
        "monitor/fixtures/k8s-audit_privilege-escalation/audit.log",
    ],
)
def test_raw_ref_accepts_root_relative_paths(path: str) -> None:
    """The grammar must still admit every shape this pointer legitimately needs."""
    assert _event(raw_ref={"path": path, "offset": 0, "length": 1}).raw_ref.path == path


def test_raw_ref_rejects_a_byte_range_that_cannot_exist() -> None:
    """A negative offset and a zero-length slice are not pointers to anything."""
    with pytest.raises(ValidationError) as excinfo:
        _event(raw_ref={"path": "a/b.jsonl", "offset": -1, "length": 1})
    assert _error_types(excinfo) == ["greater_than_equal"]
    with pytest.raises(ValidationError) as excinfo:
        _event(raw_ref={"path": "a/b.jsonl", "offset": 0, "length": 0})
    assert _error_types(excinfo) == ["greater_than_equal"]


def test_exported_schema_carries_the_path_grammar() -> None:
    """The pattern reaches consumers written in other languages, or it binds only this one."""
    schema = evidence_event_json_schema()
    assert "pattern" in schema["$defs"]["RawRef"]["properties"]["path"]


# --- event_id is a digest, not a generated identifier ---------------------------------------------


@pytest.mark.parametrize(
    "event_id",
    [
        "8f14e45f-ceea-467a-9c2b-4b1d0a5f9c31",  # a generated 36-character identifier
        VALID_EVENT_ID.upper(),  # right width, wrong case
        VALID_EVENT_ID[:63],  # truncated digest
        VALID_EVENT_ID + "0",  # over-long
        "not-a-digest",
        "",
    ],
)
def test_event_id_must_be_a_lowercase_sha256_digest(event_id: str) -> None:
    """The determinism rule reaches the contract boundary, not only the static guard.

    ``event_id`` is a SHA-256 digest over a canonical projection of the source record, computed in
    ``emit.py``. An identifier generated fresh at emit time differs on every replay and makes the
    twice-and-diff unpassable by construction, so the shape is pinned at the contract boundary as
    well as being greppable by ``scripts/monitor_guard.sh`` block (b).
    """
    with pytest.raises(ValidationError) as excinfo:
        _event(event_id=event_id)
    assert _error_types(excinfo) == ["string_pattern_mismatch"]


# --- ts comes from the source record, aware, and is normalised to UTC -----------------------------


def test_ts_must_be_timezone_aware() -> None:
    """A naive timestamp is rejected rather than assumed to be UTC."""
    with pytest.raises(ValidationError) as excinfo:
        _event(ts=datetime(2026, 3, 1, 12, 30, 0))  # noqa: DTZ001 -- the point of the test
    assert _error_types(excinfo) == ["timezone_aware"]


def test_ts_is_normalised_to_utc_so_the_offset_is_not_evidence() -> None:
    """The same instant reported with two offsets must serialise to the same bytes.

    Two sources reporting one event with different local offsets would otherwise produce two
    different lines for one fact, and the offset a source happens to use is a property of the host
    it runs on rather than of the incident.
    """
    in_utc = _event(ts=datetime(2026, 3, 1, 12, 30, 0, tzinfo=UTC))
    elsewhere = _event(
        ts=datetime(2026, 3, 1, 18, 0, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    )
    assert canonical_json_line(in_utc) == canonical_json_line(elsewhere)
    assert json.loads(canonical_json_line(in_utc))["ts"] == "2026-03-01T12:30:00Z"


# --- the closed vocabularies ----------------------------------------------------------------------


def test_source_vocabulary_is_architecture_section_3s() -> None:
    """The four families, in section 3's order, because the emitter's tie-break reads that order."""
    assert tuple(member.value for member in EvidenceSource) == ARCHITECTURE_SECTION_3_SOURCES


def test_severity_scale_is_declared_most_severe_first() -> None:
    """The enum's iteration order is the ordering; there is no second constant holding a rank."""
    assert tuple(member.value for member in EvidenceSeverity) == (
        "critical",
        "high",
        "medium",
        "low",
        "info",
    )


def test_a_source_vocabulary_value_from_outside_the_scale_is_rejected() -> None:
    """A source's own severity word must be normalised before it reaches the contract.

    ``warning`` is Falco's and Prometheus's spelling and ``CRITICAL`` is Trivy's; both map onto this
    scale in ``normalize.py``, and neither is admitted raw. ``Metadata`` is in the list because it
    is a Kubernetes audit ``level``, which is a verbosity setting and not a severity at all -- the
    one source vocabulary that must never be mapped across. If any of these is ever accepted, a
    normaliser has been bypassed and a source's own vocabulary has reached the frozen contract.
    """
    for raw in ("warning", "CRITICAL", "emergency", "informational", "UNKNOWN", "Metadata"):
        with pytest.raises(ValidationError):
            _event(severity=raw)
    with pytest.raises(ValidationError):
        _event(source="hubble")


def test_resource_namespace_may_be_null_but_the_key_is_required() -> None:
    """A cluster-scoped subject has no namespace; it does not have a missing one."""
    event = _event(resource={"ns": None, "kind": "ClusterRole", "name": "cluster-admin"})
    assert json.loads(canonical_json_line(event))["resource"]["ns"] is None
    with pytest.raises(ValidationError) as excinfo:
        _event(resource={"kind": "ClusterRole", "name": "cluster-admin"})
    assert _error_types(excinfo) == ["missing"]


# --- immutability ---------------------------------------------------------------------------------


def test_an_event_cannot_be_edited_after_it_exists() -> None:
    """An event is a record of something that happened, and nothing downstream may rewrite it."""
    event = _event()
    with pytest.raises(ValidationError) as excinfo:
        event.severity = EvidenceSeverity.LOW
    assert _error_types(excinfo) == ["frozen_instance"]


def test_the_excerpt_sequence_is_immutable_in_place() -> None:
    """Freezing the model blocks rebinding; the tuple is what blocks an in-place append.

    ``evidence_excerpts`` is the field the G3 isolation test compares across the quoting-on and
    quoting-off arms, so it is exactly the one that must not be editable by anyone holding a
    reference to the event.
    """
    event = _event(evidence_excerpts=["proc.cmdline=sh -c id", "proc.pname=frontend"])
    assert isinstance(event.evidence_excerpts, tuple)
    with pytest.raises(AttributeError):
        event.evidence_excerpts.append("injected after the fact")  # type: ignore[attr-defined]


# --- the canonical serialiser, whose output bytes are the contract --------------------------------


def test_canonical_line_is_stable_across_repeated_serialisation() -> None:
    """Serialising one event twice gives identical bytes. The Definition of Done is a ``cmp``."""
    event = _event()
    assert canonical_json_line(event) == canonical_json_line(event)


def test_canonical_line_does_not_depend_on_construction_order() -> None:
    """Key order is a property of the contract, not of how a normaliser built its dictionary."""
    forwards = EvidenceEvent(**_payload())
    backwards = EvidenceEvent(**dict(reversed(list(_payload().items()))))
    assert canonical_json_line(forwards) == canonical_json_line(backwards)


def test_canonical_line_keys_are_sorted() -> None:
    """Sorted, so that two writers cannot produce two byte sequences for one event."""
    keys = list(json.loads(canonical_json_line(_event())).keys())
    assert keys == sorted(ARCHITECTURE_SECTION_3_FIELDS)


def test_canonical_line_shape_is_one_ascii_json_lines_record() -> None:
    """Exactly one LF, no CR, no trailing whitespace, and every byte inside ASCII.

    The ASCII property is the one that is easy to lose and expensive to lose: Falco reports process
    arguments verbatim and they can carry arbitrary UTF-8, so escaping is what keeps the file
    comparing identically regardless of the locale or console encoding of whatever touches it next.
    """
    line = canonical_json_line(_event(summary="Sh\u00e8ll spawned \u2014 pid 1042"))
    assert line.endswith(b"\n")
    assert line.count(b"\n") == 1
    assert b"\r" not in line
    assert not line[:-1].endswith(b" ")
    line.decode("ascii")  # raises UnicodeDecodeError if any byte escaped the ASCII range
    assert json.loads(line)["summary"] == "Sh\u00e8ll spawned \u2014 pid 1042"


def test_canonical_line_carries_no_incidental_whitespace() -> None:
    """Minimal separators, so a run bundle is not inflated by formatting."""
    assert b", " not in canonical_json_line(_event())
    assert b'": ' not in canonical_json_line(_event())
