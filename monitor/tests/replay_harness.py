"""The fixture-corpus harness: reads ``fixture.yaml``, supplies the clock, drives the replay.

WHAT THIS MODULE IS, AND WHY IT IS NOT UNDER ``monitor/aggregator/``
--------------------------------------------------------------------
Three callers need to replay the corpus and they must all produce the *same bytes*, or the
milestone's ``cmp`` is comparing two implementations rather than two runs:
``scripts/monitor_replay.sh``, ``scripts/monitor_determinism.sh`` and the pytest files beside this
one. This module is the single path all three take. It owns four things the aggregator deliberately
does not:

* **The fixture format.** ``fixture.yaml`` is provenance plus the replay parameters, and this is the
  one Python reader of it. ``monitor/fixtures/README.md`` documents the format for humans and for
  the ``awk`` reader the two shell gates use.
* **The concrete nanosecond counter.** ``emit.py`` declares :data:`~monitor.aggregator.emit.
  NanosecondCounter` as a type and never obtains one -- ADR-019 records that as a design decision
  rather than a way around ``scripts/monitor_guard.sh`` block (b), and names "the replay harness"
  as the caller that supplies it. This file is that caller. :func:`nanosecond_counter` is the only
  place in ``monitor/`` that names a clock function, it sits outside the guarded directory, and the
  emission path stays inside it.
* **The cap limits.** They come from each fixture's own ``fixture.yaml``, under keys that cannot be
  mistaken for section 4's. See the next paragraph, which is the whole point of the arrangement.
* **The repository-relative raw root.** Every caller passes ``REPO_ROOT``, so ``raw_ref.path`` reads
  ``monitor/fixtures/<id>/<input>`` in the golden output and in every replay of it. A default would
  differ between ``replay_fixture`` (whose default is the fixture's parent) and the command line
  (whose default is the repository root), and the two would produce two different golden corpora
  that both looked right.

THE UNCALIBRATED-CAPS RESOLUTION, WHICH IS THE COORDINATION POINT THIS FILE EXISTS TO SETTLE
---------------------------------------------------------------------------------------------
``limits.py`` fails closed: with section 4's caps still ``PENDING-M2-FIXTURE-STUDY``,
``replay_fixture`` with no ``cap_limits`` raises ``UncalibratedLimit``, by design. So the corpus
cannot replay at all unless somebody supplies cap values -- and ADR-019 is explicit that whatever
they supply are "test parameters belonging to the fixture corpus", never section 4 values.

The resolution here is to make that sentence structural instead of remembered:

1. **The values live inside the corpus.** Each fixture declares its own caps in its own
   ``fixture.yaml``. There is no corpus-wide constant, no module-level default, and no value in
   this file -- so there is nothing shaped like "the" cap value for anyone to promote.
2. **The key names are disjoint from the protocol's.** They are ``corpus_cap_*``; section 4's are
   ``evidence_excerpt_count_max``, ``evidence_excerpt_length_max_chars`` and
   ``summary_length_max_chars``. A grep for a protocol key finds section 4 and ``limits.py`` and
   nothing under ``monitor/fixtures/``, which is the form the milestone's Definition of done uses
   to check that a value is single-homed.
3. **Every fixture carries a refusable sentinel.** ``corpus_cap_status`` must read
   :data:`CORPUS_CAP_SENTINEL` or the fixture does not load. Promoting a value into section 4 means
   deleting a line that says, in the file, that the value is not a protocol value.
4. **The values differ between fixtures on purpose.** One fixture caps deliberately tight so that
   truncation and excerpt selection are exercised. A corpus with several disagreeing values has no
   candidate to promote, and the disagreement is visible in the first two files a reader opens.
5. **Both gates print the disclaimer on every run**, so it appears in the log of every replay rather
   than only in a document somebody has to go and find.

``monitor/tests/test_determinism.py`` asserts 2 and 3 mechanically. What the corpus proves is
ordering, quoting, cap *semantics* and byte-level determinism; what it does not prove is cap
calibration, and that stays open until T2.7b captures fixtures from live sources.

WHAT A REPLAY WRITES, AND WHAT IS COMPARED
--------------------------------------------
``replay_fixture`` writes ``monitor_events.jsonl`` and ``latency.json`` into the output directory.
:data:`DIFFED_FILENAMES` names the first and not the second, and that omission is ADR-019's: latency
figures are wall-clock and machine-dependent, so one of them inside the diffed stream would make the
twice-and-diff unpassable forever. ``latency.json`` is checked by :func:`latency_figures` and by
being read, never by ``cmp``.

A MEASUREMENT ARTEFACT T2.5b HAS TO CONTROL FOR, RECORDED HERE RATHER THAN DISCOVERED THERE
---------------------------------------------------------------------------------------------
One invocation replays every selected fixture in one process, and ``emit.py`` imports
``quoting`` lazily on first use -- which also builds its escape table. The first event of the first
fixture in a run therefore pays a one-off cost of roughly an order of magnitude over the rest, and
because fixtures are replayed in sorted order it is always the alphabetically first fixture that
pays it. That is visible in the figures the gates print and it is real: it is work the aggregator
does. It is *not* representative of steady-state per-event cost, and the fixture study at T2.5b must
either discard the first sample or warm the import before it takes one. This harness does neither,
deliberately -- silently warming a cache would be the instrument adjusting the thing it measures,
and there is no budget to compare against yet for the adjustment to matter.

WHY THE EMITTED STREAM IS RE-VALIDATED RATHER THAN TRUSTED
------------------------------------------------------------
The events are built through the frozen contract, so they are valid objects by construction.
:func:`validate_stream` re-reads the emitted *bytes*, parses each line back through
``EvidenceEvent`` -- which forbids unknown keys -- and re-serialises it, requiring the result to be
the same bytes. That is a different claim from "the object validated": it covers the serialiser, the
line framing and the canonical form, which is what a consumer of a run bundle actually receives.

STANDARD LIBRARY, PYDANTIC, AND NOTHING ELSE
----------------------------------------------
No PyYAML: ``fixture.yaml`` is a flat ``key: value`` file precisely so that this reader and an
``awk`` one-liner in a POSIX shell can both parse it without a dependency. No network, and nothing
here opens one -- ``monitor/tests/test_no_inference.py`` runs the whole corpus through this module
with the socket layer denied, which is only positive evidence if this path is the one the gates use.
"""

import argparse
import json
import re
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from monitor.aggregator import limits as protocol_limits  # noqa: E402
from monitor.aggregator.caps import CapLimits  # noqa: E402
from monitor.aggregator.emit import (  # noqa: E402
    EVENTS_FILENAME,
    LATENCY_FILENAME,
    NanosecondCounter,
    replay_fixture,
)
from monitor.aggregator.models import (  # noqa: E402
    EvidenceEvent,
    EvidenceSeverity,
    EvidenceSource,
    canonical_json_line,
)
from monitor.aggregator.normalize import SOURCE_REGISTRY, registry_entry  # noqa: E402

PROGRAM = "replay-harness"

FIXTURES_ROOT = REPO_ROOT / "monitor" / "fixtures"
MANIFEST_FILENAME = "fixture.yaml"
GOLDEN_DIRNAME = "expected"

# The files a replay writes, and the ones the determinism check compares. latency.json is
# deliberately absent from the second tuple; see the module docstring and ADR-019.
WRITTEN_FILENAMES = (EVENTS_FILENAME, LATENCY_FILENAME)
DIFFED_FILENAMES = (EVENTS_FILENAME,)

# The arm the golden output was produced under, spelled with the canonical condition ID from
# AGENTS.md rather than as a boolean, so that "which configuration is this corpus the output of"
# is answered in the vocabulary the rest of the project uses. G0-FULL is full guardrails, which
# includes quoting; G3-UNQUOTED is the arm that removes it.
GOLDEN_ARM = "G0-FULL"
GOLDEN_ARM_QUOTING = True

# The sentinel every fixture must carry beside its cap values. Not a comment, because a comment is
# not refusable: a fixture whose corpus_cap_status is missing or altered does not load at all.
CORPUS_CAP_SENTINEL = "FIXTURE-CORPUS-TEST-PARAMETER"

# The three cap keys a fixture declares, in the order caps.py applies them. Deliberately NOT
# limits.CAP_KEYS: these are corpus parameters and their names must not collide with the protocol's,
# so that a grep for a section 4 key cannot find one of these instead.
CORPUS_CAP_KEYS = (
    "corpus_cap_excerpt_count_max",
    "corpus_cap_excerpt_length_max_chars",
    "corpus_cap_summary_length_max_chars",
)

# The provenance vocabulary. `synthesised` is what the whole M2 offline corpus is; `captured` is
# what T2.7b adds beside it. Exactly two values, because "where did this record shape come from" has
# exactly two answers that matter to section 4, and a third would blur the line the caps wait on.
PROVENANCE_SYNTHESISED = "synthesised"
PROVENANCE_CAPTURED = "captured"
PROVENANCE_VALUES = (PROVENANCE_SYNTHESISED, PROVENANCE_CAPTURED)

# The exact key set of a fixture manifest. Exact rather than a minimum, in the same spirit as
# ADR-016's mirror tests: a missing key and an unexpected key are both defects, and a reader that
# only checked for the ones it needed could not catch a key silently deleted or a key misspelt.
REQUIRED_KEYS = (
    "fixture_id",
    "source",
    "provenance",
    "synthesised_from",
    "capture_commit",
    "source_tool_version",
    "seed",
    "golden_arm",
    "audit_severity",
    "corpus_cap_status",
    *CORPUS_CAP_KEYS,
    "description",
)

# One `key: value` per line, or a bare `key:` for a value that is deliberately empty. Keys are
# lower-case with underscores. The grammar is this narrow so that the awk reader in the two shell
# gates and this one cannot disagree about what a line means.
_MANIFEST_LINE = re.compile(r"^([a-z0-9_]+):(?: (.*))?$")


class FixtureFormatError(ValueError):
    """Raised when a fixture manifest is malformed, incomplete, or inconsistent with its directory.

    Always names the file and what was wrong with it. A harness that shrugged at a manifest it did
    not understand would replay with the wrong caps or the wrong severity and produce a golden file
    that no later reader could account for.
    """


class EmptyCorpus(FileNotFoundError):
    """Raised when the corpus holds no fixture at all.

    Its own class because an empty corpus is the vacuous pass every gate in this repository is
    written to refuse: replaying nothing successfully is byte-identical, in a log, to replaying
    everything successfully.
    """


class StreamValidationError(ValueError):
    """Raised when an emitted line does not read back as a canonical ``EvidenceEvent``."""


@dataclass(frozen=True, slots=True)
class FixtureSpec:
    """One fixture: where it is, what it holds, where it came from, and how it replays.

    Frozen because a replay's parameters are a property of the fixture on disk, and a harness that
    could adjust them between two runs would be able to make the twice-and-diff pass by accident.
    """

    fixture_id: str
    directory: Path
    sources: tuple[EvidenceSource, ...]
    provenance: str
    synthesised_from: str
    capture_commit: str
    source_tool_version: str
    seed: str
    golden_arm: str
    audit_severity: EvidenceSeverity | None
    cap_limits: CapLimits
    description: str

    @property
    def golden_path(self) -> Path:
        """The tracked golden stream this fixture's replay is compared against."""
        return self.directory / GOLDEN_DIRNAME / EVENTS_FILENAME


def nanosecond_counter() -> NanosecondCounter:
    """Return the concrete monotonic nanosecond counter the aggregator is handed.

    This is the one function in ``monitor/`` that names a clock, and it lives here rather than in
    ``monitor/aggregator/`` for the reason ``emit.py`` and ADR-019 both set out at length: nothing
    inside the emission path may obtain a clock, because a clock reading in that path is the most
    reliable way to make the byte diff unpassable. The aggregator declares the counter *type* and
    calls only what its caller hands it; this module is the caller.

    ``perf_counter_ns`` rather than a wall clock: it is monotonic, it has the highest resolution the
    platform offers, and the spans being measured are microseconds. It is not a wall clock and
    cannot be turned into one, which is why ``latency.json``'s end-to-end ``source_ts`` to
    ``emit_ts`` slot stays unfilled and says so rather than being quietly filled with a difference
    of two monotonic readings that share no epoch with anything.
    """
    return time.perf_counter_ns


def read_manifest(path: Path) -> dict[str, str]:
    """Parse one flat ``key: value`` manifest. No nesting, no lists, no dependency.

    Blank lines and lines beginning with ``#`` are ignored. Anything else must match
    :data:`_MANIFEST_LINE`, and a duplicate key is an error rather than a last-one-wins -- two lines
    naming one key is a manifest whose meaning depends on which reader you ask.
    """
    if not path.is_file():
        raise FixtureFormatError(f"{path} does not exist; every fixture directory needs one")
    values: dict[str, str] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        matched = _MANIFEST_LINE.match(line)
        if matched is None:
            raise FixtureFormatError(
                f"{path}:{number}: {line!r} is not 'key: value' or a bare 'key:'. The format is "
                f"flat by contract so that an awk reader and this one cannot disagree; see "
                f"monitor/fixtures/README.md."
            )
        key = matched.group(1)
        if key in values:
            raise FixtureFormatError(f"{path}:{number}: {key!r} appears twice")
        values[key] = matched.group(2) or ""
    return values


def _parse_sources(raw: str, *, path: Path) -> tuple[EvidenceSource, ...]:
    """Parse the comma-separated ``source`` value, requiring registry order and no repeats.

    Registry order is required rather than merely sorted: it is the order events are emitted in
    (``normalize.py``'s ``source_rank``), so a manifest that lists the sources in that order reads
    the same way as the golden file beneath it.
    """
    if not raw:
        raise FixtureFormatError(f"{path}: 'source' is empty; a fixture declares what it holds")
    names = [token.strip() for token in raw.split(",")]
    sources: list[EvidenceSource] = []
    for name in names:
        try:
            source = EvidenceSource(name)
        except ValueError as unknown:
            admitted = ", ".join(str(entry.source) for entry in SOURCE_REGISTRY)
            raise FixtureFormatError(
                f"{path}: source {name!r} is not one of the four families ({admitted})"
            ) from unknown
        if source in sources:
            raise FixtureFormatError(f"{path}: source {name!r} is listed twice")
        sources.append(source)
    ranks = [registry_entry(source).rank for source in sources]
    if ranks != sorted(ranks):
        expected = ",".join(
            str(entry.source) for entry in SOURCE_REGISTRY if entry.source in sources
        )
        raise FixtureFormatError(
            f"{path}: 'source' must list the families in source-registry order, which is the "
            f"emission order: expected {expected!r}, found {raw!r}"
        )
    return tuple(sources)


def _parse_cap(values: dict[str, str], key: str, *, path: Path) -> int:
    """Parse one corpus cap value as a positive integer, or raise naming the key."""
    raw = values[key]
    try:
        return int(raw)
    except ValueError as bad:
        raise FixtureFormatError(
            f"{path}: {key} is {raw!r}; a corpus cap is a whole number of items or characters. "
            f"It is a fixture-corpus test parameter and never a value from "
            f"{protocol_limits.PROTOCOL_RELATIVE_PATH} section 4."
        ) from bad


def _check_provenance(values: dict[str, str], *, path: Path) -> None:
    """Enforce the provenance rules that gate section 4's caps row.

    ``synthesised`` requires the schema or document the record shape was derived from and forbids
    the two capture fields; ``captured`` requires both of them. The asymmetry is the point: the M2
    plan makes provenance the reason the section 4 pull request waits for captured fixtures, so a
    corpus that could not tell the two apart would make that gate unenforceable.
    """
    provenance = values["provenance"]
    if provenance not in PROVENANCE_VALUES:
        raise FixtureFormatError(
            f"{path}: provenance is {provenance!r}; it must be one of {PROVENANCE_VALUES}. "
            f"{PROVENANCE_SYNTHESISED!r} means the record shape was written from a schema or from "
            f"documentation and has never met live output, which is what the whole M2 offline "
            f"corpus is."
        )
    captured_fields = ("capture_commit", "source_tool_version")
    if provenance == PROVENANCE_SYNTHESISED:
        if not values["synthesised_from"]:
            raise FixtureFormatError(
                f"{path}: provenance is {PROVENANCE_SYNTHESISED!r} but 'synthesised_from' is "
                "empty. Name the schema or the documentation the record shape was derived from: "
                "it is what a reviewer checks the shape against without running a cluster."
            )
        for field_name in captured_fields:
            if values[field_name]:
                raise FixtureFormatError(
                    f"{path}: provenance is {PROVENANCE_SYNTHESISED!r} but {field_name!r} is "
                    f"{values[field_name]!r}. A synthesised fixture was never captured, so both "
                    "capture fields stay present and empty until T2.7b fills them."
                )
        return
    for field_name in captured_fields:
        if not values[field_name]:
            raise FixtureFormatError(
                f"{path}: provenance is {PROVENANCE_CAPTURED!r} but {field_name!r} is empty. A "
                "captured fixture records which commit captured it and which version of the "
                "source tool produced it, or it cannot support a calibration claim."
            )


def load_fixture(directory: Path) -> FixtureSpec:
    """Read and validate one fixture directory into a :class:`FixtureSpec`.

    Every check here is one a malformed corpus could otherwise pass silently: caps that are not
    corpus caps, a severity assigned to a source that carries its own, an input file the manifest
    does not declare, a golden file produced under the other ablation arm.
    """
    path = directory / MANIFEST_FILENAME
    values = read_manifest(path)

    missing = [key for key in REQUIRED_KEYS if key not in values]
    unexpected = sorted(key for key in values if key not in REQUIRED_KEYS)
    if missing or unexpected:
        raise FixtureFormatError(
            f"{path}: the manifest key set is exact. Missing: {missing}. Unexpected: {unexpected}. "
            f"The contract is {list(REQUIRED_KEYS)} -- see monitor/fixtures/README.md."
        )

    if values["fixture_id"] != directory.name:
        raise FixtureFormatError(
            f"{path}: fixture_id is {values['fixture_id']!r} but the directory is "
            f"{directory.name!r}. The identifier appears in every gate's output and has to name "
            "the directory a reader will open."
        )
    if not values["description"]:
        raise FixtureFormatError(f"{path}: 'description' is empty")
    if values["golden_arm"] != GOLDEN_ARM:
        raise FixtureFormatError(
            f"{path}: golden_arm is {values['golden_arm']!r}; the tracked golden stream is the "
            f"{GOLDEN_ARM} arm, with quoting applied. The G3-UNQUOTED arm is compared against the "
            "quoted one in monitor/tests/test_g3_isolation.py and is never itself a golden file."
        )
    if values["corpus_cap_status"] != CORPUS_CAP_SENTINEL:
        raise FixtureFormatError(
            f"{path}: corpus_cap_status is {values['corpus_cap_status']!r} and must be "
            f"{CORPUS_CAP_SENTINEL!r}. The three corpus_cap_* values below it are test parameters "
            f"belonging to this corpus. They are NOT the caps "
            f"{protocol_limits.PROTOCOL_RELATIVE_PATH} section 4 owns, they are not evidence that "
            "its caps row is closed, and they must never be promoted into it without the fixture "
            "study over captured fixtures behind them (ADR-019)."
        )

    _check_provenance(values, path=path)
    sources = _parse_sources(values["source"], path=path)

    declared = {registry_entry(source).input_filename for source in sources}
    present = {
        entry.input_filename
        for entry in SOURCE_REGISTRY
        if (directory / entry.input_filename).is_file()
    }
    if declared != present:
        raise FixtureFormatError(
            f"{path}: 'source' declares {sorted(declared)} but the directory holds "
            f"{sorted(present)}. A declared source with no input file replays as nothing, and an "
            "undeclared input file emits events no manifest accounts for."
        )

    audit_declared = values["audit_severity"]
    needs_audit_severity = EvidenceSource.K8S_AUDIT in sources
    if needs_audit_severity and not audit_declared:
        raise FixtureFormatError(
            f"{path}: this fixture holds {EvidenceSource.K8S_AUDIT} records, which carry no "
            "severity of their own -- the audit 'level' field is a verbosity setting, not a "
            "ranking. The per-rule assignment is authored at T2.4; until then the fixture declares "
            "it explicitly. There is deliberately no default."
        )
    if audit_declared and not needs_audit_severity:
        raise FixtureFormatError(
            f"{path}: audit_severity is {audit_declared!r} but this fixture holds no "
            f"{EvidenceSource.K8S_AUDIT} records. The other three families carry their own "
            "severity, so a value here would be read as though it applied to them."
        )
    try:
        audit_severity = EvidenceSeverity(audit_declared) if audit_declared else None
    except ValueError as unknown:
        admitted = ", ".join(str(level) for level in EvidenceSeverity)
        raise FixtureFormatError(
            f"{path}: audit_severity {audit_declared!r} is outside the normalised scale "
            f"({admitted})"
        ) from unknown

    caps = [_parse_cap(values, key, path=path) for key in CORPUS_CAP_KEYS]
    return FixtureSpec(
        fixture_id=values["fixture_id"],
        directory=directory,
        sources=sources,
        provenance=values["provenance"],
        synthesised_from=values["synthesised_from"],
        capture_commit=values["capture_commit"],
        source_tool_version=values["source_tool_version"],
        seed=values["seed"],
        golden_arm=values["golden_arm"],
        audit_severity=audit_severity,
        cap_limits=CapLimits(
            evidence_excerpt_count_max=caps[0],
            evidence_excerpt_length_max_chars=caps[1],
            summary_length_max_chars=caps[2],
        ),
        description=values["description"],
    )


def fixture_directories() -> tuple[Path, ...]:
    """Return every directory under the corpus root that carries a manifest, sorted by name.

    Sorted so that a run's output order is a property of the corpus rather than of the filesystem,
    and filtered on the manifest so that a stray directory is reported as an unloadable fixture by
    :func:`discover` rather than silently skipped here.
    """
    if not FIXTURES_ROOT.is_dir():
        raise EmptyCorpus(
            f"{FIXTURES_ROOT} does not exist. The fixture corpus is the evidence for T-01, T-02 "
            "and T-04; there is nothing to replay without it."
        )
    return tuple(sorted(path for path in FIXTURES_ROOT.iterdir() if path.is_dir()))


def discover(fixture_ids: Sequence[str] | None = None) -> tuple[FixtureSpec, ...]:
    """Load the requested fixtures, or the whole corpus. Refuses an empty result.

    ``fixture_ids`` of ``None`` means every fixture, which is what both shell gates and both pytest
    files use. An unknown identifier is an error naming what the corpus does hold, because a typo
    that silently replayed nothing would report success.
    """
    specs = [load_fixture(directory) for directory in fixture_directories()]
    if not specs:
        raise EmptyCorpus(
            f"{FIXTURES_ROOT} holds no fixture directory. An empty corpus is refused rather than "
            "replayed successfully: a gate that passes over nothing reads exactly like a gate that "
            "passes over everything."
        )
    if fixture_ids is None:
        return tuple(specs)
    by_id = {spec.fixture_id: spec for spec in specs}
    selected: list[FixtureSpec] = []
    for fixture_id in fixture_ids:
        if fixture_id not in by_id:
            raise EmptyCorpus(
                f"no fixture {fixture_id!r} in {FIXTURES_ROOT}. The corpus holds {sorted(by_id)}."
            )
        selected.append(by_id[fixture_id])
    return tuple(selected)


def replay(
    spec: FixtureSpec,
    *,
    out_dir: Path,
    quoting_on: bool = GOLDEN_ARM_QUOTING,
    clock: NanosecondCounter | None = None,
) -> tuple[EvidenceEvent, ...]:
    """Replay one fixture into ``out_dir`` and return its events.

    The single call site of ``replay_fixture`` in the harness, so that every caller passes the same
    raw root, the same caps and the same audit severity. ``quoting_on`` is passed straight through
    as a value and is never tested here: ``quoting.apply_quoting`` is the one place in the
    repository that branches on it.
    """
    return replay_fixture(
        spec.directory,
        quoting_enabled=quoting_on,
        cap_limits=spec.cap_limits,
        raw_root=REPO_ROOT,
        audit_severity=spec.audit_severity,
        out_dir=out_dir,
        clock=clock,
    )


def validate_stream(path: Path) -> int:
    """Parse every emitted line back through the frozen contract; return the event count.

    Round-trip rather than a one-way parse: the line is validated as an ``EvidenceEvent``, which
    forbids unknown keys, and then re-serialised through ``canonical_json_line`` and required to
    equal the bytes it came from. That covers the serialiser, the ASCII policy, the key order and
    the line framing, which "the object validated" does not.
    """
    data = path.read_bytes()
    if not data:
        raise StreamValidationError(f"{path} is empty; a replay that emitted nothing is refused")
    if b"\r" in data:
        raise StreamValidationError(
            f"{path} carries a carriage return. The stream is written in binary mode with LF "
            "terminators so that a bundle written on Windows compares equal to one written under "
            "WSL2; a CRLF stream differs in every single line while looking identical."
        )
    if not data.endswith(b"\n"):
        raise StreamValidationError(
            f"{path} has no final LF terminator. Every JSON Lines record, including the last one, "
            "must be LF-terminated; otherwise the final record would be silently skipped by the "
            "line-framing validation."
        )
    count = 0
    for number, line in enumerate(data.split(b"\n")[:-1], start=1):
        try:
            event = EvidenceEvent.model_validate_json(line)
        except ValueError as invalid:
            raise StreamValidationError(f"{path}:{number}: {invalid}") from invalid
        if canonical_json_line(event) != line + b"\n":
            raise StreamValidationError(
                f"{path}:{number}: the line is a valid event but is not its canonical "
                "serialisation, so the emitted bytes are not a function of the event alone"
            )
        count += 1
    return count


def latency_figures(path: Path) -> dict[str, object]:
    """Read ``latency.json`` and return the figures the gates report.

    A small flat projection rather than the whole document, because the two shell gates print it
    and a shell has no JSON parser here. The budget verdict is reported exactly as ``emit.py``
    formed it -- withheld while any section 4 key is still pending -- and is never replaced with a
    comparison against a placeholder.
    """
    document = json.loads(path.read_text(encoding="utf-8"))
    measurement = document["measurement"]
    per_event = document["per_event_processing_ms"]
    budget = document["budget"]
    return {
        "measured": bool(measurement["measured"]),
        "event_count": int(document["event_count"]),
        "p95_ms": None if per_event is None else per_event["p95"],
        "max_ms": None if per_event is None else per_event["max"],
        "verdict": str(budget["verdict"]),
        "verdict_reason": str(budget["verdict_reason"]),
        "pending_keys": tuple(str(key) for key in budget["pending_keys"]),
    }


def _report(spec: FixtureSpec, out_dir: Path, validated: int) -> str:
    """Format the one machine-readable line per fixture that both shell gates parse."""
    figures = latency_figures(out_dir / LATENCY_FILENAME)
    caps = spec.cap_limits
    return (
        f"{PROGRAM}: {spec.fixture_id}"
        f" sources={','.join(str(source) for source in spec.sources)}"
        f" events={figures['event_count']}"
        f" validated={validated}"
        f" measured={str(figures['measured']).lower()}"
        f" p95_ms={figures['p95_ms']}"
        f" max_ms={figures['max_ms']}"
        f" budget={figures['verdict']}"
        f" corpus_caps={caps.evidence_excerpt_count_max}"
        f"/{caps.evidence_excerpt_length_max_chars}"
        f"/{caps.summary_length_max_chars}"
        f" provenance={spec.provenance}"
    )


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser. Separate from :func:`main` so a test can inspect the surface."""
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description=(
            "Replay the tracked fixture corpus through the aggregator with the clock injected. "
            "Drives scripts/monitor_replay.sh and scripts/monitor_determinism.sh."
        ),
    )
    parser.add_argument(
        "--fixture",
        action="append",
        default=None,
        metavar="ID",
        help="replay only this fixture; repeatable. Omitted, every fixture is replayed.",
    )
    parser.add_argument(
        "--out-root",
        required=True,
        type=Path,
        help="directory to write <id>/monitor_events.jsonl and <id>/latency.json under",
    )
    parser.add_argument(
        "--quoting",
        action=argparse.BooleanOptionalAction,
        default=GOLDEN_ARM_QUOTING,
        help=(
            "quote environment-derived text (default). --no-quoting selects the G3-UNQUOTED arm "
            "for inspection; the golden corpus is always the G0-FULL arm."
        ),
    )
    parser.add_argument(
        "--update-golden",
        action="store_true",
        help=(
            "overwrite each replayed fixture's expected/monitor_events.jsonl with what this run "
            "emitted. A reviewed diff, never a way to make a failing gate green."
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Replay the selected fixtures, print one line each, and return an exit code.

    ``0`` on a completed run, ``1`` on a named failure -- a malformed manifest, an empty corpus, an
    uncalibrated required limit, a stream that does not read back canonically, or a calibrated
    latency CI ceiling breach -- printed on standard error. Pending latency budgets are not a
    failure: their verdict remains withheld. ``2`` is argparse's usage error. Anything else is a
    defect and its stack trace is left alone, because a trace is the right output for one.
    """
    args = build_parser().parse_args(argv)
    # Update mode always emits the golden arm, so that --no-quoting cannot silently rewrite the
    # corpus as the ablation arm. The flag is chosen here, as a value, and tested nowhere.
    quoting_on = GOLDEN_ARM_QUOTING if args.update_golden else args.quoting

    try:
        specs = discover(args.fixture)
        lines: list[str] = []
        latency_failures: list[str] = []
        for spec in specs:
            out_dir = args.out_root / spec.fixture_id
            replay(spec, out_dir=out_dir, quoting_on=quoting_on, clock=nanosecond_counter())
            emitted = out_dir / EVENTS_FILENAME
            validated = validate_stream(emitted)
            figures = latency_figures(out_dir / LATENCY_FILENAME)
            if figures["verdict"] == "fail":
                latency_failures.append(
                    f"{spec.fixture_id}: calibrated latency CI ceiling exceeded: "
                    f"{figures['verdict_reason']}"
                )
            if args.update_golden and figures["verdict"] != "fail":
                spec.golden_path.parent.mkdir(parents=True, exist_ok=True)
                spec.golden_path.write_bytes(emitted.read_bytes())
            lines.append(_report(spec, out_dir, validated))
    except (FixtureFormatError, EmptyCorpus, StreamValidationError) as failure:
        print(f"{PROGRAM}: {type(failure).__name__}: {failure}", file=sys.stderr)
        return 1
    except protocol_limits.UncalibratedLimit as failure:
        print(f"{PROGRAM}: UncalibratedLimit: {failure}", file=sys.stderr)
        return 1

    for line in lines:
        print(line)
    if latency_failures:
        for failure in latency_failures:
            print(f"{PROGRAM}: LatencyBudgetExceeded: {failure}", file=sys.stderr)
        return 1
    pending = protocol_limits.pending_keys()
    print(
        f"{PROGRAM}: {len(specs)} fixture(s); the corpus caps above are fixture-corpus test "
        f"parameters, not evaluation-protocol section 4 values (ADR-019); "
        f"section 4 keys still pending: {','.join(pending) if pending else 'none'}"
    )
    if args.update_golden:
        print(
            f"{PROGRAM}: golden output rewritten for {len(specs)} fixture(s) in the {GOLDEN_ARM} "
            "arm. Review the diff: a change here is a change to what the aggregator emits."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
