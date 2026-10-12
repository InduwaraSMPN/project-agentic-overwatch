"""Deterministic emission: builds events, writes the stream, keeps latency out of it.

WHAT THIS MODULE DOES, IN THE ORDER IT DOES IT
-----------------------------------------------
Given the already-read bytes of each source's raw input, it walks the records, normalises each one
through the registry, computes its identifier, sorts the batch into the total emission order, caps
the summary and excerpts of each event, quotes them, validates the result against the frozen
``EvidenceEvent`` contract, and writes the canonical JSON Lines stream. Then, separately, it writes
``latency.json``.

The pipeline order is ADR-019's and is not an implementation detail: **normalise, select excerpts,
apply the caps to the raw source text, quote.** ``caps.py`` explains at length why putting quoting
before the caps turns ``G3-UNQUOTED`` from a failing test into an invalid arm.

THE ONE BRANCH ON THE G3 FLAG IS NOT IN THIS FILE
---------------------------------------------------
``quoting.apply_quoting`` is the only place in the repository that branches on the flag, and this
module calls it **unconditionally** -- once for the summary and once per excerpt, passing
``enabled=config.quoting_enabled`` straight through. There is deliberately no ``if`` on that value
anywhere here.

That single-branch property is what stops the ablation arm fanning out into scattered conditionals,
each of which would be a second place where the flag could change a second thing --
and section 3.5.4 requires each configuration to remove exactly one property.
``monitor/tests/test_g3_isolation.py`` asserts it, by grep over ``monitor/`` and by comparing the
two arms field by field.

``quoting.py`` is imported lazily rather than at module import, and the reason is sequencing rather
than performance: it lands at T2.6, after this file, and a hard import at the top would make the
whole aggregator unimportable in between. The loader raises :class:`QuotingUnavailable` with
remediation if the module is absent. It does **not** fall back to returning the text unchanged: that
would be a second, silent quoting policy living in the one module whose job is to have none, and it
would produce an entire corpus of unquoted events under a configuration that asked for quoting.

TIMING VERSUS THE DETERMINISM GUARD, AND HOW THE TENSION IS RESOLVED
---------------------------------------------------------------------
FR1.2 requires events to be emitted within the Monitor latency budget, so something has to be
measured. ``scripts/monitor_guard.sh`` block (b) forbids every construct that reads a clock anywhere
under ``monitor/aggregator/`` -- and that prohibition is right, because a clock reading inside the
emission path is the single most reliable way to make the twice-and-diff unpassable.

The resolution here is the third of the three the milestone allows, and it is a design choice rather
than a way around the guard: **the counter is injected by the caller.** :data:`NanosecondCounter` is
a zero-argument callable returning a monotonically non-decreasing integer count of nanoseconds.
Nothing in this package obtains one, constructs one, or names a standard-library function that could
be one; the aggregator only ever *calls* what it was handed. The two other options were available
and were not taken: moving the timing into a module outside the guard's scope would put half the
emission path outside the enforced boundary for the convenience of one measurement, and renaming an
import to slip past the pattern would be defeating the guard rather than satisfying it.

When no counter is supplied -- which is what ``python -m monitor.aggregator.cli`` does today --
``latency.json`` is still written, and it records ``measured: false`` with the reason. It never
records a zero, because a zero is a number and would be read as one. The replay harness at T2.7a and
the runner at M6 are the callers that supply a real counter; both live outside this package.

**Latency figures never enter the event stream.** They are wall-clock and machine-dependent, and one
such field in ``monitor_events.jsonl`` would make the byte diff unpassable forever -- presenting
itself as a flaky determinism test rather than as a design error, which is the expensive way to find
out. They go to ``latency.json``, which the determinism check does not diff. The price is that
``latency.json`` is an output no ``cmp`` covers; it is checked by its own assertions and by being
read.

WHAT THE MEASURED SPAN COVERS, PRECISELY
------------------------------------------
Section 4 defines the budget-bearing figure as **per-event aggregator processing time, excluding
source I/O and network**. This module receives bytes that have already been read, so source I/O is
excluded by construction rather than by a subtraction somebody has to trust. Per event, the measured
span is the sum of two intervals:

* *normalisation* -- locating the record in its input, running the source's normaliser, and
  computing the identifier;
* *emission* -- capping, quoting, validating against the contract, and canonical serialisation.

Two costs are deliberately outside the per-event figure and are reported separately. Sorting the
batch is O(n log n) over the whole batch and cannot be attributed to any one event without inventing
a rule; it is reported as ``batch_ordering_ms``. Writing the output files is I/O and is excluded by
the same clause of section 4 that excludes reading them.

End-to-end ``source_ts`` to ``emit_ts`` is reported by the harness, not here. It needs a wall-clock
reading at emission, and this package takes none -- injected or otherwise, since a monotonic counter
is not a wall clock. ``latency.json`` carries the slot with its reason so the obligation stays
visible rather than being quietly dropped.

WHY ``latency.json`` IS INDENTED AND ``monitor_events.jsonl`` IS NOT
---------------------------------------------------------------------
The event stream is machine-diffed at run scale, so it is canonical and minimal. The latency file is
one small document read by a human asking whether a replay was within budget, so it is indented and
sorted, exactly as ``models.py`` treats the exported JSON Schema. Both are written in **binary**
mode: Python's text mode translates ``\\n`` to ``\\r\\n`` on Windows, and a bundle written that way
differs from one written under WSL2 in every single line while looking identical in every editor.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
Every golden ``monitor_events.jsonl`` in the corpus is this module's output byte for byte.
Reordering the pipeline invalidates the corpus and, worse, the ``G3-UNQUOTED`` arm. Adding a
field to ``latency.json`` is safe; adding one to the event stream changes a frozen contract.
"""

import json
import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from monitor.aggregator import limits as protocol_limits
from monitor.aggregator.caps import CapLimits, apply_caps, protocol_cap_limits
from monitor.aggregator.models import (
    SCHEMA_VERSION,
    EvidenceEvent,
    EvidenceSeverity,
    RawRef,
    canonical_json_line,
)
from monitor.aggregator.normalize import (
    SOURCE_REGISTRY,
    AggregatedRecord,
    SourceEntry,
    compute_event_id,
    ordered,
    read_records,
)
from monitor.aggregator.sources import NormaliserOptions

# The two files a replay writes. Fixed names rather than parameters: the fixture contract names
# monitor_events.jsonl as the golden output, docs/protocols/data-management.md section 1 puts that
# same filename in every run bundle, and a configurable output name would let two bundles disagree
# about what the stream is called.
EVENTS_FILENAME: Final = "monitor_events.jsonl"
LATENCY_FILENAME: Final = "latency.json"

# The version token of the latency document's own shape. Not evidence and not part of the frozen
# EvidenceEvent contract -- but a consumer still has to be able to tell one shape from another, and
# this file is allowed to grow in a way the event stream is not.
LATENCY_SCHEMA: Final = "monitor-latency-v1"

# The percentile section 4 names for the budget-bearing figure, as a fraction.
P95: Final = 0.95

# A zero-argument callable returning a monotonically non-decreasing nanosecond count. The aggregator
# never constructs one; see the module docstring for why the injection is the design rather than a
# workaround.
NanosecondCounter = Callable[[], int]

# Cache for the lazily imported quoting entry point. A module-level cache rather than an import
# inside the loop, so that the per-event measured span does not include a module-table lookup that
# has nothing to do with the aggregator's work.
_APPLY_QUOTING: Callable[..., str] | None = None


class QuotingUnavailable(RuntimeError):
    """Raised when ``monitor.aggregator.quoting`` cannot be imported. Never silently skipped."""


class FixtureInputError(ValueError):
    """Raised when a fixture directory is missing, holds no source input, or is outside the root."""


@dataclass(frozen=True, slots=True)
class EmitConfig:
    """Everything a replay's behaviour depends on, carried as configuration rather than as code.

    ``quoting_enabled`` is the ``G3-UNQUOTED`` toggle. It reaches this object from a command-line
    flag today and from the runner's condition flags at M6, and it is never a code path selected by
    editing ``monitor/`` -- the same discipline rule 10 imposes on ``G1-LOGONLY`` and
    ``G2-SHAREDCRED``. This module passes it straight into ``apply_quoting`` and branches on it
    nowhere.

    ``cap_limits`` has no default, because ``caps.py`` and ``limits.py`` have none: an aggregator
    that ran against an unmeasured bound would let a whole corpus go green against numbers nobody
    has measured.
    """

    quoting_enabled: bool
    cap_limits: CapLimits


@dataclass(frozen=True, slots=True)
class SourceInput:
    """One source's raw input: which registry row reads it, what it is called, and its bytes.

    The bytes are passed in rather than a path, so that reading -- which section 4 excludes from the
    budget -- happens in the caller and cannot accidentally be measured. ``raw_path`` is the
    root-relative string that goes into ``raw_ref``; computing it is the caller's job, because this
    package has no notion of where a repository or a run bundle begins.
    """

    entry: SourceEntry
    raw_path: str
    data: bytes


@dataclass(frozen=True, slots=True)
class EmitResult:
    """What a replay produced: the events, where they were written, and the latency document."""

    events: tuple[EvidenceEvent, ...]
    events_path: Path
    latency_path: Path
    latency: Mapping[str, Any]


def _load_apply_quoting() -> Callable[..., str]:
    """Import and cache ``quoting.apply_quoting``, or raise :class:`QuotingUnavailable`.

    See the module docstring for why the import is lazy and why there is no fallback.
    """
    global _APPLY_QUOTING
    if _APPLY_QUOTING is None:
        try:
            from monitor.aggregator.quoting import apply_quoting
        except ImportError as missing:
            raise QuotingUnavailable(
                "monitor.aggregator.quoting could not be imported, so the summary and excerpts of "
                "every event would be emitted with no quoting policy applied at all. That module "
                "lands at M2-T2.6 and is the single place the G3 flag is read; there is no "
                "fallback here by design. Original import error: " + str(missing)
            ) from missing
        _APPLY_QUOTING = apply_quoting
    return _APPLY_QUOTING


def build_event(item: AggregatedRecord, config: EmitConfig) -> EvidenceEvent:
    """Cap, quote and validate one normalised record into a frozen :class:`EvidenceEvent`.

    The two transformations happen in ADR-019's order and in no other: the caps are applied to the
    source text, and only the capped text is quoted. Both arms of the G3 ablation therefore carry
    identical excerpt counts and identical source-text lengths, and differ only in escaping.
    """
    capped = apply_caps(
        item.record.summary, item.record.excerpt_candidates, cap_limits=config.cap_limits
    )
    apply_quoting = _load_apply_quoting()
    return EvidenceEvent(
        event_id=item.event_id,
        ts=item.record.ts,
        source=item.record.source,
        # Carried straight from the normalised record: signal_id is a sensor value, untouched by
        # caps or quoting, so it is identical across the G3 arms exactly as event_id is.
        signal_id=item.record.signal_id,
        severity=item.record.severity,
        resource=item.record.resource,
        summary=apply_quoting(capped.summary, enabled=config.quoting_enabled),
        evidence_excerpts=tuple(
            apply_quoting(text, enabled=config.quoting_enabled) for text in capped.excerpts
        ),
        raw_ref=item.raw_ref,
        schema_version=SCHEMA_VERSION,
    )


def _percentile(samples: Sequence[int], fraction: float) -> int:
    """Return the nearest-rank percentile of ``samples``, which must be sorted and non-empty.

    Nearest rank rather than an interpolating variant: interpolation invents a value that no event
    exhibited, and a budget is checked against something an event actually took. The rank is
    ``ceil(fraction * n)``, clamped into range, which is the definition NIST calls the nearest-rank
    method and the one a reader can reproduce by counting.
    """
    rank = max(1, math.ceil(fraction * len(samples)))
    return samples[min(rank, len(samples)) - 1]


def _milliseconds(nanoseconds: int) -> float:
    """Convert a nanosecond count to milliseconds, rounded to nanosecond resolution.

    Rounded so that the number written to the file is exactly what the counter reported rather than
    the nearest representable binary fraction of it, which would print differently on a reader that
    formats floats to more places.
    """
    return round(nanoseconds / 1_000_000, 6)


def _latency_document(
    *,
    event_count: int,
    per_event_ns: Sequence[int] | None,
    ordering_ns: int | None,
    reason: str | None,
) -> dict[str, Any]:
    """Assemble ``latency.json``. Reports what was measured, and why, when nothing was.

    The budget section reports section 4's mirrored values without resolving pending values. A
    verdict remains withheld until both latency budgets are calibrated and a measurement exists;
    calibrated budgets are multiplied by the protocol's CI multiplier and yield a real pass or fail.
    """
    mirror = protocol_limits.as_protocol_mapping()
    budget_keys = ("monitor_latency_p95_budget_ms", "monitor_latency_max_budget_ms")
    pending = tuple(key for key in budget_keys if protocol_limits.is_pending(mirror[key]))
    measured = per_event_ns is not None and event_count > 0
    document: dict[str, Any] = {
        "schema": LATENCY_SCHEMA,
        "measurement": {
            "definition": (
                "per-event aggregator processing time, excluding source I/O and network "
                "(docs/protocols/evaluation-protocol.md section 4)"
            ),
            "covers": [
                "record location and per-source normalisation",
                "event_id projection and digest",
                "cap enforcement",
                "quoting",
                "contract validation",
                "canonical serialisation",
            ],
            "excludes": [
                "reading the raw source inputs",
                "writing the output files",
                "batch ordering, reported separately below",
                "anything on the network",
            ],
            "unit": "milliseconds",
            "measured": measured,
        },
        "event_count": event_count,
        "per_event_processing_ms": None,
        "batch_ordering_ms": None if ordering_ns is None else _milliseconds(ordering_ns),
        "end_to_end_source_ts_to_emit_ts_ms": None,
        "end_to_end_reason": (
            "an end-to-end figure needs a wall-clock reading at emission. Nothing under "
            "monitor/aggregator/ reads a clock, and an injected monotonic counter is not a wall "
            "clock, so this figure belongs to the replay harness and to the runner (ADR-019)."
        ),
        "budget": {
            "monitor_latency_p95_budget_ms": mirror["monitor_latency_p95_budget_ms"],
            "monitor_latency_max_budget_ms": mirror["monitor_latency_max_budget_ms"],
            "monitor_latency_ci_ceiling_multiplier": mirror[
                "monitor_latency_ci_ceiling_multiplier"
            ],
            "ci_ceiling_p95_ms": None,
            "ci_ceiling_max_ms": None,
            "pending_keys": list(pending),
            "verdict": "withheld",
            "verdict_reason": (
                "no verdict is formed while a budget key is still PENDING-M2-FIXTURE-STUDY; the "
                "aggregator has no default for one (ADR-016, ADR-019)."
                if pending
                else "both budget keys are calibrated, but no per-event measurement is available."
            ),
        },
    }
    if measured and per_event_ns is not None:
        samples = sorted(per_event_ns)
        p95_ms = _milliseconds(_percentile(samples, P95))
        max_ms = _milliseconds(samples[-1])
        document["per_event_processing_ms"] = {
            "count": len(samples),
            "min": _milliseconds(samples[0]),
            "p95": p95_ms,
            "max": max_ms,
            "total": _milliseconds(sum(samples)),
        }
        if not pending:
            multiplier = protocol_limits.resolve("monitor_latency_ci_ceiling_multiplier", mirror)
            p95_ceiling = (
                protocol_limits.resolve("monitor_latency_p95_budget_ms", mirror) * multiplier
            )
            max_ceiling = (
                protocol_limits.resolve("monitor_latency_max_budget_ms", mirror) * multiplier
            )
            budget = document["budget"]
            budget["ci_ceiling_p95_ms"] = p95_ceiling
            budget["ci_ceiling_max_ms"] = max_ceiling
            breaches: list[str] = []
            if p95_ms > p95_ceiling:
                breaches.append(f"p95 {p95_ms:g} ms exceeds CI ceiling {p95_ceiling:g} ms")
            if max_ms > max_ceiling:
                breaches.append(f"max {max_ms:g} ms exceeds CI ceiling {max_ceiling:g} ms")
            budget["verdict"] = "fail" if breaches else "pass"
            budget["verdict_reason"] = (
                "; ".join(breaches)
                if breaches
                else "measured p95 and max are within their calibrated CI ceilings."
            )
    else:
        document["measurement"]["reason"] = reason or (
            "no nanosecond counter was supplied to emit(), so no processing time was taken. A "
            "zero is not written in its place, because a zero is a number and would be read as "
            "one."
        )
    return document


def _latency_bytes(document: Mapping[str, Any]) -> bytes:
    """Serialise ``latency.json``: sorted, ASCII, indented, one trailing newline, as bytes."""
    text = json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False)
    return text.encode("utf-8") + b"\n"


def read_fixture_inputs(fixture_dir: Path, *, raw_root: Path) -> list[SourceInput]:
    """Read whichever of the four canonical input files a fixture holds, in registry order.

    The one place a fixture directory is turned into inputs, so ``cli.py`` and
    :func:`replay_fixture` cannot drift into two answers about which filenames count. Reading is
    deliberately here, outside :func:`_aggregate`, so that source I/O is excluded from the measured
    span by construction rather than by a subtraction somebody has to trust.

    A source whose file is absent contributes nothing. A directory holding none of the four raises,
    because an empty output that looked like a successful run of nothing is the failure that
    survives review.
    """
    if not fixture_dir.is_dir():
        raise FixtureInputError(f"{fixture_dir} is not a directory")
    collected: list[SourceInput] = []
    for entry in SOURCE_REGISTRY:
        path = fixture_dir / entry.input_filename
        if not path.is_file():
            continue
        try:
            relative = path.resolve().relative_to(raw_root.resolve())
        except ValueError as outside:
            raise FixtureInputError(
                f"{path} is not under the raw root {raw_root}, so no root-relative raw_ref can be "
                "built for it. Point the raw root at a directory the fixture lives under; raw_ref "
                "is never absolute, because an absolute path encodes the host."
            ) from outside
        collected.append(
            SourceInput(entry=entry, raw_path=relative.as_posix(), data=path.read_bytes())
        )
    if not collected:
        expected = ", ".join(entry.input_filename for entry in SOURCE_REGISTRY)
        raise FixtureInputError(
            f"{fixture_dir} holds none of the four canonical source inputs ({expected}). An empty "
            "replay is refused rather than reported as a successful run of nothing."
        )
    return collected


def replay_fixture(
    fixture: Path,
    *,
    quoting_enabled: bool,
    cap_limits: CapLimits | None = None,
    raw_root: Path | None = None,
    audit_severity: EvidenceSeverity | None = None,
    out_dir: Path | None = None,
    clock: NanosecondCounter | None = None,
) -> tuple[EvidenceEvent, ...]:
    """Replay one fixture directory and return its events, optionally writing them out.

    The in-process entry point, for callers that want the events rather than the files --
    ``monitor/tests/test_g3_isolation.py`` replays each fixture twice, once per arm, and compares
    the two field by field, which needs objects and not a path. ``out_dir`` is optional for the
    same reason: a comparison that never reads a file should not be made to write two.

    ``cap_limits`` defaults to the protocol mirror, which means this function **fails closed** while
    section 4's caps are still uncalibrated. That is deliberate and it is ADR-019's recorded cost:
    during the offline phase a caller has to pass the caps in, and the values it passes are
    fixture-corpus test parameters rather than protocol values. Supplying a default here would undo
    the whole fail-closed design at the one call site most likely to be used by a test.

    ``raw_root`` defaults to the fixture's own parent directory, so a fixture replayed from anywhere
    still produces root-relative ``raw_ref`` paths of the form ``<fixture-name>/<input-file>``.
    """
    limits_in_force = protocol_cap_limits() if cap_limits is None else cap_limits
    root = fixture.parent if raw_root is None else raw_root
    inputs = read_fixture_inputs(fixture, raw_root=root)
    config = EmitConfig(quoting_enabled=quoting_enabled, cap_limits=limits_in_force)
    options = NormaliserOptions(audit_severity=audit_severity)
    events, lines, document = _aggregate(inputs, config=config, options=options, clock=clock)
    if out_dir is not None:
        _write(out_dir, lines, document)
    return events


def emit(
    inputs: Sequence[SourceInput],
    *,
    out_dir: Path,
    config: EmitConfig,
    options: NormaliserOptions,
    clock: NanosecondCounter | None = None,
) -> EmitResult:
    """Run the whole aggregation over already-read inputs and write both output files.

    ``inputs`` are processed in the order given; the caller is expected to supply them in registry
    order, but nothing depends on that -- :func:`~monitor.aggregator.normalize.ordered` imposes the
    total emission order afterwards, so the result is the same whichever order they arrive in. That
    independence is deliberate: it means a fixture directory listing that comes back in a different
    order on another filesystem cannot change the output bytes.

    ``clock`` is the injected nanosecond counter. ``None`` means no timing, which is a supported and
    fully functional mode -- see the module docstring.
    """
    events, lines, document = _aggregate(inputs, config=config, options=options, clock=clock)
    events_path, latency_path = _write(out_dir, lines, document)
    return EmitResult(
        events=events,
        events_path=events_path,
        latency_path=latency_path,
        latency=document,
    )


def _write(out_dir: Path, lines: Sequence[bytes], document: Mapping[str, Any]) -> tuple[Path, Path]:
    """Write both output files in binary mode and return their paths. See the module docstring."""
    out_dir.mkdir(parents=True, exist_ok=True)
    events_path = out_dir / EVENTS_FILENAME
    events_path.write_bytes(b"".join(lines))
    latency_path = out_dir / LATENCY_FILENAME
    latency_path.write_bytes(_latency_bytes(document))
    return events_path, latency_path


def _aggregate(
    inputs: Sequence[SourceInput],
    *,
    config: EmitConfig,
    options: NormaliserOptions,
    clock: NanosecondCounter | None,
) -> tuple[tuple[EvidenceEvent, ...], list[bytes], dict[str, Any]]:
    """The whole aggregation, with no file access at all: the part the latency figure measures."""
    per_event_ns: dict[str, int] = {}
    aggregated: list[AggregatedRecord] = []

    for source_input in inputs:
        entry = source_input.entry
        records = iter(read_records(source_input.data, entry.locator))
        while True:
            # Advancing the iterator performs JSON parsing and locates the record's exact byte span,
            # so the reading must precede next(). Starting inside a ``for raw in ...`` body would
            # omit precisely that work while claiming it under latency.json's ``covers`` list.
            started = clock() if clock is not None else 0
            try:
                raw = next(records)
            except StopIteration:
                # Balance the injected counter reads even though iterator exhaustion is not a
                # record and therefore contributes no per-event sample.
                if clock is not None:
                    clock()
                break
            record = entry.normalise(raw, options)
            event_id = compute_event_id(record)
            aggregated.append(
                AggregatedRecord(
                    record=record,
                    raw_ref=RawRef(
                        path=source_input.raw_path, offset=raw.offset, length=raw.length
                    ),
                    event_id=event_id,
                    rank=entry.rank,
                )
            )
            if clock is not None:
                per_event_ns[event_id] = clock() - started

    ordering_started = clock() if clock is not None else 0
    ranked = ordered(aggregated)
    ordering_ns = clock() - ordering_started if clock is not None else None

    events: list[EvidenceEvent] = []
    lines: list[bytes] = []
    for item in ranked:
        started = clock() if clock is not None else 0
        event = build_event(item, config)
        line = canonical_json_line(event)
        if clock is not None:
            per_event_ns[item.event_id] = per_event_ns.get(item.event_id, 0) + (clock() - started)
        events.append(event)
        lines.append(line)

    document = _latency_document(
        event_count=len(events),
        per_event_ns=[per_event_ns[event.event_id] for event in events]
        if clock is not None
        else None,
        ordering_ns=ordering_ns,
        reason=None,
    )
    return tuple(events), lines, document
