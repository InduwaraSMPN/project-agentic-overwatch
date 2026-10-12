r"""The treatment-fidelity gate (P1/P2; ADR-120): a registry of mechanical checks over bundle files.

WHAT THIS PACKAGE IS
--------------------
M10 plan principle **P1** is "treatment fidelity is checked, not assumed": every arm and injection
class has a mechanical check, over bundle files, that its treatment was delivered. Integrity --
sealed, valid -- is necessary and not sufficient, and v1 proved the difference the expensive way:
``runs/CAMP-20260914-campaign/`` sealed cleanly and passed ``validate_campaign_corpus`` while
several
treatments had not happened at all (defects V1, V2, V4, V7, V13, V18, V28). The registry is the
twenty-six-row table of plan section 5, transcribed once.

WHY A PACKAGE, AND WHY THE CHECKS LIVE HERE RATHER THAN IN ``monitor/`` OR ``agents/``
--------------------------------------------------------------------------------------
Every predicate reads **bundle files only** -- ``messages.jsonl``, ``tokens.json``,
``monitor_events.jsonl``, ``guardian_audit.jsonl``, ``k8s_api_audit.jsonl``, ``resources.csv``,
``manifest.json``. None of them calls a cluster, imports a Kubernetes client, or reaches into the
Monitor's or the agents' internals. That restriction is the reason this is a package under
``runner/`` and not a set of assertions distributed across the components under test: a check that
imported ``monitor/aggregator`` would make the Monitor's correctness depend on the runner, and a
check that imported ``agents/graphs`` would make a defect in the graph produce a *check* failure
rather than a *finding* -- exactly the confusion P2 exists to prevent. The per-domain modules
(``agents.py``, ``monitor.py``, ``scenarios.py``, ``guardian.py``, ``runner.py``, ``analysis.py``)
own the predicates for their own prefix (``F-AG-*``, ``F-MN-*``, ``F-SC-*``, ``F-GD-*``, ``F-RN-*``,
``F-AN-*``) so that a new check sits next to the defect it exists to catch.

P2, THE CLASSIFICATION, WHICH IS THE WHOLE POINT
------------------------------------------------
Three classes, and getting them right is the difference between a gate and a bot:

``T`` -- treatment/instrument. Did the framework deliver what this arm removes? Blocking at the
    pilot AND halting the campaign. ``F-RN-01``, ``F-AG-01``, ``F-AG-04``, ``F-AG-05``,
    ``F-MN-01``..``04``, ``F-SC-01``, ``F-SC-02``, ``F-GD-01``..``06``, ``F-AN-03``.
``B`` -- behaviour. What the agents *chose* to do, once every treatment is proven delivered. Blocks
    the pilot only, is REPORTED during the campaign, and never halts. ``F-AG-02``, ``F-AG-03``
    (after
    P1a), ``F-SC-03b``, ``F-GD-04``, ``F-AN-02``.
``R`` -- readiness/provenance. Blocks the pilot gate, the campaign checkpoint and the final corpus,
    with the per-stage semantics each check states. ``F-RN-02``, ``F-SC-03a``, ``F-SC-04``,
    ``F-SC-05``, ``F-AN-01``.

The sentence that keeps the classes honest is P2's last clause: "What agents choose to do, once
every treatment is proven delivered, is a finding and never a halt." An arm that never reaches the
Guardian is a class-B finding at P2 and beyond -- it may be a design result -- but F-AG-03 is class
T
*in P1a*, where the arm is scripted and the script is under the framework's control, so a scripted
arm that cannot reach the Guardian is a framework failure, not a model outcome. That per-stage class
change is why ``FidelityCheck.klass`` may be a mapping rather than a single string.

THE STAGES
----------
``seal`` -- computed at seal and written into ``fidelity.json``, inside the sealed bundle and
therefore covered by ``seal.json``'s content hashes. ``loop`` -- evaluated by
``runner.campaign_cli.execute_campaign`` after a bundle seals. ``offline`` -- no cluster, so it runs
in P0-offline and in CI. ``P0-live`` -- an instrument probe. Plus the three *gate* stages
(``pilot gate``, ``checkpoint``, ``final``) at which class-R checks bite, per plan section 5.

RESULTS, AND THE TWO PLACES THEY LAND
-------------------------------------
``fidelity.json`` inside the bundle (SEAM 2's exact shape) and ``<campaign>/fidelity_ledger.jsonl``
beside it. The first is covered by the seal, so a fidelity verdict cannot be edited after the fact
without invalidating the bundle; the second is append-only and survives ``runs/`` being backed up or
pruned, and is what ``scripts/audit_seal_anchor.sh`` also appends its anchor rows to.

WHY A CHECK RETURNS ``skip`` RATHER THAN FAILING WHEN ITS INPUT IS ABSENT
------------------------------------------------------------------------
A bundle with no ``k8s_api_audit.jsonl`` is a v1 bundle or a probe sealed before the audit slice
existed, and F-GD-06 is the check whose *job* is to say so -- reporting it as absent from every
other
check as well would make the corpus-wide ledger unreadable and would make one missing file produce
six findings instead of one. So a predicate whose own input is missing returns ``skip`` with a
detail
naming the input, and exactly one check per absent input is responsible for calling it a failure.
The completeness profile in ``runner/bundle.py`` is the other half of that arrangement: a
*framework-on v2* bundle that lacks the file does not seal at all.

THE PROTOCOL MIRROR (ADR-016 / ADR-120)
---------------------------------------
``docs/protocols/evaluation-protocol.md`` section 4's ``<!-- m10-fidelity-constants -->`` block owns
every quantitative parameter the fidelity gate consumes. This module is the plan's DESIGNATED mirror
home for the FULL block (``runner/pilot_cli.py`` mirrors the five pilot sizes and
``analysis/stats/m10.py`` the discrimination ceiling; the sets are disjoint, so no constant has
three
homes). ``MIRRORED_KEYS`` is exactly the block's key set, and
``runner/tests/test_fidelity.py`` parses the block and fails on any divergence -- the protocol is
right and the module is wrong, in that direction, always.

``inj_b_landing_floor`` mirrors the measured, researcher-confirmed protocol value. Consumers
resolve it through :func:`resolve_optional`, which also fails closed if a future calibration
returns it to the ``PROPOSED-M10-P0LIVE-CALIBRATION`` sentinel.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
The pilot gate, the campaign halt rule, and ``analysis/render.py``'s readiness table. A check
removed
from the registry silently stops being enforced, so ``runner/tests/test_fidelity.py`` asserts the
registry equals plan section 5's table row for row.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Final

__all__ = (
    "ANALYSIS_MIRRORED_KEYS",
    "API_AUDIT_FILENAME",
    "BANNED_STAGES",
    "BLOCKING_CLASSES",
    "CAUSE_PRODUCER_ABSENT",
    "CLASSES",
    "DEFECT_NAMING_KNOWN_BAD",
    "FIDELITY_FILENAME",
    "FIDELITY_SCHEMA_VERSION",
    "GATE_STAGES",
    "KNOWN_BAD_EXPECTATIONS",
    "LADDER_MIRRORED_KEYS",
    "LEDGER_FILENAME",
    "NO_V1_DEFECT",
    "OFFLINE_PROVEN_KNOWN_BAD",
    "MIRRORED_KEYS",
    "PROPOSED_SENTINEL",
    "PROTOCOL_ANCHOR",
    "PROTOCOL_MIRRORED_CONSTANTS",
    "PROTOCOL_RELATIVE_PATH",
    "READINESS_STAGES",
    "SCHEMA_VERSION",
    "STATUSES",
    "STAGE_CAMPAIGN",
    "STAGE_CHECKPOINT",
    "STAGE_FINAL",
    "STAGE_LOOP",
    "STAGE_OFFLINE",
    "STAGE_P0_LIVE",
    "STAGE_PILOT",
    "STAGE_PILOT_GATE",
    "STAGE_SEAL",
    "WS7_SCORING_MIRRORED_KEYS",
    "BundleView",
    "CheckOutcome",
    "FidelityCheck",
    "FidelityError",
    "FidelityReport",
    "FidelityResult",
    "all_checks",
    "append_fidelity_ledger",
    "as_m10_protocol_mapping",
    "blocking_ids",
    "campaign_gate_rows",
    "check_by_id",
    "coerce_status",
    "evaluate_bundle",
    "fold_gate_rows",
    "iter_campaign_reports",
    "iter_ledger",
    "read_fidelity",
    "resolve_optional",
    "statuses_by_id",
    "t_failures",
    "write_fidelity_report",
)

# --------------------------------------------------------------------------- the sealed artefact

# SEAM 2 fixes this filename and this shape exactly:
#
#   {"schema_version":"fidelity.v1","run_id":"...","instrument_digest":"...",
#    "checks":[{"id","klass","stage","status","detail"}],
#    "summary":{"T":{...},"B":{...},"R":{...}}}
#
# `analysis/` reads it and `scripts/fidelity_check.sh` reports over it, so the name is a constant in
# three directories and changing it is a protocol change (data-management section 1), not a
# refactor.
FIDELITY_FILENAME: Final = "fidelity.json"
FIDELITY_SCHEMA_VERSION: Final = "fidelity.v1"
SCHEMA_VERSION: Final = FIDELITY_SCHEMA_VERSION

# The append-only campaign-side ledger. Beside `campaign.json` and the `frozen_commit.txt` sidecar,
# never inside a bundle: a ledger inside a bundle would be rewritten with it, and this one exists to
# outlive any single bundle.
LEDGER_FILENAME: Final = "fidelity_ledger.jsonl"

# The API-server audit slice, named once here because F-GD-06 checks for it, the completeness
# profile
# requires it, and `runner/live_evidence.py` writes it. Three homes would be three chances to spell
# it differently; the bundle-layout home is data-management section 1.
API_AUDIT_FILENAME: Final = "k8s_api_audit.jsonl"

# --------------------------------------------------------------------------- the vocabulary

# Check classes (P2). Strings rather than an enum so the value written into `fidelity.json` is the
# value compared in the tests and printed in the ledger, with no conversion step to get wrong.
CLASSES: Final[tuple[str, ...]] = ("T", "B", "R")

# Result statuses. `skip` is a status and not an absence: a check that could not be evaluated at
# this
# stage is a fact about the corpus that a reader needs to see, and an absent check would be
# indistinguishable from a check nobody wrote.
STATUSES: Final[tuple[str, ...]] = ("pass", "fail", "warn", "skip")

# The stages, in the order the ladder reaches them.
STAGE_OFFLINE: Final = "offline"
STAGE_P0_LIVE: Final = "P0-live"
STAGE_PILOT: Final = "pilot"
STAGE_SEAL: Final = "seal"
STAGE_LOOP: Final = "loop"
STAGE_CAMPAIGN: Final = "campaign"
STAGE_PILOT_GATE: Final = "pilot gate"
STAGE_CHECKPOINT: Final = "checkpoint"
STAGE_FINAL: Final = "final"

#: The stages the pilot gate consults when it folds a whole campaign into one row per check
#: (:func:`campaign_gate_rows`; M10 plan section 6). The four ladder stages (offline, P0-live,
#: pilot, pilot gate) plus the two per-bundle stages whose results the ladder's exit criteria are
#: stated over. The three analysis gates (``campaign``, ``checkpoint``, ``final``) are NOT here:
#: they are consulted by ``analysis``' own readiness tooling, not by the pilot gate.
GATE_STAGES: Final[tuple[str, ...]] = (
    STAGE_SEAL,
    STAGE_LOOP,
    STAGE_OFFLINE,
    STAGE_P0_LIVE,
    STAGE_PILOT,
    STAGE_PILOT_GATE,
)

#: Class-resolution priority at the gate: the most specific ladder stage a check declares wins, so a
#: check whose class is stage-dependent (F-AG-03 is class T at ``pilot`` and class B at ``seal`` and
#: ``loop``) carries its gate-stage class rather than the class of whichever stage happened to be
#: evaluated first. Ordered most-specific first; the first stage a check applies at decides.
_GATE_CLASS_PRIORITY: Final[tuple[str, ...]] = (
    STAGE_PILOT_GATE,
    STAGE_PILOT,
    STAGE_P0_LIVE,
    STAGE_OFFLINE,
    STAGE_LOOP,
    STAGE_SEAL,
)

#: Status severity for the gate's cross-corpus fold, worst wins. ``pass`` outranks ``skip`` on
#: purpose: a check that passed where it applied and skipped where it did not (F-SC-01 passes on an
#: injected run and skips on INJ-NONE; F-SC-02 on a CVE run and skips elsewhere; F-AG-01 on S2/S3
#: and skips on S1) has been evaluated, and the skip is about applicability, not about the
#: treatment. A ``skip`` that survives the fold -- one no bundle ever turned into a pass -- is a
#: check that never ran anywhere, and the gate must see it rather than have it hidden by a single
#: pass elsewhere.
_GATE_STATUS_RANK: Final[dict[str, int]] = {"fail": 4, "warn": 3, "pass": 2, "skip": 1}

#: Stages at which a class-B check is REPORTED ONLY and never blocks. As of ADR-183 that is every
#: stage, and the set is the whole vocabulary rather than a subset on purpose: the per-stage
#: semantics are a TABLE (:data:`BLOCKING_CLASSES`), and this names the complement so a reader can
#: see that class B's blocking set is empty rather than inferring it from an omission.
#:
#: ADR-183 removed the four ladder stages from it. The bar was "blocks the pilot", and two measured
#: live cells on provisional freezes ``v2-pilot-20261006e`` and ``v2-pilot-20261006f`` showed it was
#: unreachable for a correct guardrail rather than for a broken instrument: a phase Supervisor holds
#: two tool calls, so when the Guardian correctly refuses the single mint the phase holds no
#: capability, no Executing role runs, and both B checks that measure *behaviour* -- ``F-AG-03``'s
#: "reached the Guardian" and ``F-AG-02``'s loop signature -- record a phase that legitimately could
#: not act. Every B result is still computed, tallied and carried into ``gate_decision.json``; none
#: of it withholds GO.
BANNED_STAGES: Final[frozenset[str]] = frozenset(
    {
        STAGE_OFFLINE,
        STAGE_P0_LIVE,
        STAGE_PILOT,
        STAGE_PILOT_GATE,
        STAGE_SEAL,
        STAGE_LOOP,
        STAGE_CAMPAIGN,
        STAGE_CHECKPOINT,
        STAGE_FINAL,
    }
)

#: Stages at which class-R checks block. The three named in P2 and in plan §5's per-stage semantics
#: column. Note that ``final`` is in this set AND in :data:`BANNED_STAGES`: at the final corpus a
#: missing measure blocks (R) while a behaviour finding does not (B). The two sets overlapping is
#: the
#: point -- the per-stage semantics are a TABLE, not a rule.
READINESS_STAGES: Final[frozenset[str]] = frozenset(
    {STAGE_PILOT_GATE, STAGE_CHECKPOINT, STAGE_FINAL}
)

#: The whole per-stage blocking table, read once so that P2's three classes cannot be re-derived
#: (and
#: mis-derived) by two callers. The mapping is total over the nine stages and falls back to class T
#: alone for a stage nobody declared: failing toward "stop" is the safe direction for an unknown
#: stage.
BLOCKING_CLASSES: Final[dict[str, tuple[str, ...]]] = {
    # The ladder: class T blocks, because it is the question the pilot is asking -- was the
    # treatment delivered. Class R blocks here too, for readiness reasons ADR-183 did not touch.
    # Class B does not, at any stage (see :data:`BANNED_STAGES`): two measured live cells showed the
    # old bar was unreachable for a correct guardrail rather than for a broken instrument.
    STAGE_OFFLINE: ("T", "R"),
    STAGE_P0_LIVE: ("T", "R"),
    STAGE_PILOT: ("T", "R"),
    STAGE_PILOT_GATE: ("T", "R"),
    # Per-bundle and campaign stages: a treatment failure is a halt; a behaviour observation is
    # reported.
    STAGE_SEAL: ("T",),
    STAGE_LOOP: ("T",),
    STAGE_CAMPAIGN: ("T",),
    # The two analysis gates: a missing measure or a T failure blocks; a behaviour finding is a
    # result and never a blocker (P2's last clause, and the reason ``F-AN-01``'s own per-stage
    # semantics are about measures and not about behaviour).
    STAGE_CHECKPOINT: ("T", "R"),
    STAGE_FINAL: ("T", "R"),
}

# --------------------------------------------------------------------------- the protocol mirror

# The protocol block, named rather than re-parsed ad hoc, on the pattern
# `runner/pilot_cli.py` and `analysis/stats/m10.py` follow.
PROTOCOL_ANCHOR: Final = "<!-- m10-fidelity-constants -->"
PROTOCOL_RELATIVE_PATH: Final = "docs/protocols/evaluation-protocol.md"

# The sentinel a value carries while it is still M10-proposed and P0-live has not measured it.
# Copied
# verbatim from the protocol's own wording; resolving one is an error, never a default.
PROPOSED_SENTINEL: Final = "PROPOSED-M10-P0LIVE-CALIBRATION"

#: The FULL mirrored block, key for key. Section 4 of evaluation-protocol.md owns every one of
#: these;
#: this tuple is the list of the copies this package is allowed to make, and the mirror test in
#: `runner/tests/test_fidelity.py` asserts it equals the block's key set -- so a key added to the
#: protocol without a mirror here, or a mirror here without a protocol key, is a failure rather than
#: a silent divergence.
MIRRORED_KEYS: Final[tuple[str, ...]] = (
    # Pilot ladder run counts (plan section 6). Mirrored here as well as in `runner/pilot_cli.py`?
    # NO -- and that is the point: the plan names this package the mirror home for the block, so the
    # ladder's copy is the SUBSET it consumes and this one is the whole. See the disjointness test.
    "loop_signature_consecutive_calls",
    "injection_discrimination_base_rate_max",
    "lifetime_attempts_per_cell_max",
    "checkpoint_cells",
    "control_plane_clock_skew_tolerance_seconds",
    "forwarder_drain_bound_seconds",
    "inj_b_landing_floor",
)

# The values. Every one is M10-PROPOSED (ADR-120): confirmed by the researcher before the `v2.0`
# freeze. The landing floor is calibrated (ADR-170). The union retains the uncalibrated sentinel
# representation so that a future missing measurement remains unusable as a numeric threshold.
PROTOCOL_MIRRORED_CONSTANTS: Final[dict[str, float | str]] = {
    "loop_signature_consecutive_calls": 5,
    "injection_discrimination_base_rate_max": 0.50,
    "lifetime_attempts_per_cell_max": 5,
    "checkpoint_cells": 30,
    "control_plane_clock_skew_tolerance_seconds": 2.0,
    "forwarder_drain_bound_seconds": 15.0,
    "inj_b_landing_floor": 1.0,
}

# The keys `runner/pilot_cli.py` already mirrors, named here only so the disjointness test can state
# the partition in one place rather than importing the other module (which imports `runner/grid.py`,
# `runner/order.py` and `runner/campaign.py` -- a chain a check on key NAMES has no business pulling
# in). See `runner/tests/test_fidelity.py::test_the_full_mirror_and_the_ladder_mirror_partition_the
# _block`.
LADDER_MIRRORED_KEYS: Final[tuple[str, ...]] = (
    "pilot_p0_live_probes",
    "pilot_p1a_runs",
    "pilot_p1b_runs",
    "pilot_p2_runs",
    "pilot_p3_runs",
)

# `analysis/stats/m10.py`'s single key, same reasoning. Kept as a name rather than an import so the
# assertion is about the partition of the block, not about whether both modules import cleanly.
ANALYSIS_MIRRORED_KEYS: Final[tuple[str, ...]] = ("injection_discrimination_base_rate_max",)

#: The four WS-7 scoring constants, whose consumer is `scripts/scoring_sample.py` and
#: `scripts/scoring_ui.py` -- the scripts-agent's rows, not the runner's. Named here so the
#: partition
#: assertion can state that the block has FOUR mirror homes and no unmirrored key, rather than
#: pretending this package covers a block it has no consumer for. Mirroring a key nobody reads is
#: the
#: other failure: a copy that nothing consumes is a copy nothing checks, and it is the copy most
#: likely to go stale.
WS7_SCORING_MIRRORED_KEYS: Final[tuple[str, ...]] = (
    "scoring_min_elapsed_seconds",
    "scoring_sample_tuple_count",
    "scoring_sample_min_per_scenario",
    "scoring_rescore_tuple_count",
)


def as_m10_protocol_mapping() -> dict[str, float | str]:
    """The mirrored M10 constants, in the shape the protocol block parses to.

    A fresh dict per call, so no caller can mutate the mirror for everyone else -- the same contract
    ``monitor/aggregator/limits.py`` and ``analysis/stats/m10.py`` keep. The comparison surface the
    mirror test uses.
    """
    return dict(PROTOCOL_MIRRORED_CONSTANTS)


def resolve_optional(key: str) -> float:
    """Return a mirrored constant that must have a number, or raise naming the protocol row.

    ``inj_b_landing_floor`` is the only value that may still carry the sentinel, and a consumer that
    needs a number cannot have one until P0-live measures it. Failing closed here -- on the M1
    calibration pattern the protocol's own preamble describes -- is what stops a check from quietly
    comparing against a placeholder and reporting a pass nobody measured.
    """
    value = PROTOCOL_MIRRORED_CONSTANTS[key]
    if isinstance(value, str):
        raise FidelityError(
            f"{key} is {value!r} in {PROTOCOL_RELATIVE_PATH} section 4: it carries no number until "
            "P0-live calibrates it, and a check that needs a value fails closed rather than "
            "comparing against a placeholder (ADR-120)."
        )
    return value


# --------------------------------------------------------------------------- the check record


class FidelityError(RuntimeError):
    """The fidelity gate could not be evaluated as asked. Never a per-check finding."""


@dataclass(frozen=True)
class CheckOutcome:
    """What one check concluded about one bundle (or corpus).

    ``status`` is one of :data:`STATUSES`. ``detail`` is a human sentence naming what was seen, and
    is written into ``fidelity.json`` -- so it must never carry a secret, an unbounded list, or
    anything read off a wall clock. The constructors below exist so a predicate reads
    ``return CheckOutcome.fail("...")`` rather than assembling the tuple, which is what keeps a
    ``pass`` from carrying a detail that contradicts it.

    ``cause`` is a gate-internal annotation on a ``skip``, and only ``skip`` may carry one: a
    ``pass`` or a ``fail`` is a statement about the bundle and needs no excuse, so allowing a cause
    on one would invite a reader to treat a verdict as conditional. It is not serialised -- see
    :data:`CAUSE_PRODUCER_ABSENT` for why.
    """

    status: str
    detail: str = ""
    cause: str = ""

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise AssertionError(
                f"status {self.status!r} is not one of {STATUSES}; a status outside the vocabulary "
                "would be unreadable to every consumer of fidelity.json"
            )
        if self.cause and self.status != "skip":
            raise AssertionError(
                f"cause {self.cause!r} on a {self.status!r}: a cause excuses a check from having "
                "reached a verdict, so only a skip may carry one"
            )

    @classmethod
    def passed(cls, detail: str = "") -> CheckOutcome:
        return cls("pass", detail)

    @classmethod
    def failed(cls, detail: str) -> CheckOutcome:
        return cls("fail", detail)

    @classmethod
    def warned(cls, detail: str) -> CheckOutcome:
        return cls("warn", detail)

    @classmethod
    def skipped(cls, detail: str) -> CheckOutcome:
        return cls("skip", detail)

    @classmethod
    def producer_pending(cls, detail: str) -> CheckOutcome:
        """A ``skip`` whose reason is that the producer of this check's input has not run.

        Used where a predicate reads a campaign-level artefact that a later workstream writes --
        ``payload_coverage.json``, ``vacuity.json``, ``injection_base_rates.json``,
        ``assertion_availability.json``, or a manifest's ``instrument_digest``. Such a check cannot
        be evaluated over a corpus that predates its producer, and the known-bad replay reports it
        as producer-pending rather than MISSING (ADR-146). It is a distinct constructor rather than
        a keyword on :meth:`skipped` so the two cases cannot be confused by a caller who has not
        read the difference.
        """
        return cls("skip", detail, CAUSE_PRODUCER_ABSENT)

    def to_dict(self) -> dict[str, str]:
        return {"status": self.status, "detail": self.detail}


#: A predicate is a pure function of the bundle view. Pure is load-bearing: a check that mutated the
#: bundle, or read a clock, would make `fidelity.json` -- which is covered by `seal.json` -- depend
#: on
#: when it was computed rather than on what it read.
Predicate = Callable[["BundleView"], "CheckOutcome"]


@dataclass(frozen=True)
class FidelityCheck:
    """One row of plan section 5's table: an id, a class, a stage, a predicate, and its v1 defect.

    ``klass`` is a mapping rather than a single class wherever the table says a check's class is
    stage-dependent -- F-AG-03 is "T in P1a, B after" and F-AG-04 is "seal, loop". A single string
    would force the choice to be made once at import, which is exactly the choice the table defers
    to the ladder; :meth:`klass_at` resolves it for a stage.
    """

    id: str
    owner: str
    klass: Mapping[str, str]
    stage: tuple[str, ...]
    summary: str
    predicate: Predicate
    known_bad: str = ""

    def klass_at(self, stage: str) -> str:
        """The class this check carries at ``stage``.

        A check whose mapping does not name ``stage`` falls back to the single-stage case, and then
        to
        ``"T"`` -- the blocking class. The fallback direction is deliberate: a check that forgot to
        declare a stage must block rather than silently not.
        """
        if stage in self.klass:
            return self.klass[stage]
        if len(self.klass) == 1:
            return next(iter(self.klass.values()))
        return "T"

    def applies_at(self, stage: str) -> bool:
        """Whether this check is evaluated at ``stage``.

        The gate stages (``pilot gate``, ``checkpoint``, ``final``) are not stages a check is
        *computed* at: they are stages at which the checks already computed are *consulted*. So a
        check declaring ``("seal",)`` applies at the pilot gate by having been run at seal, and the
        readiness stages are handled by :func:`blocking_ids` rather than by filtering here.
        """
        return stage in self.stage


@dataclass(frozen=True)
class FidelityResult:
    """One check's verdict on one bundle, as written into ``fidelity.json``.

    ``cause`` carries the skip's cause (see :data:`CAUSE_PRODUCER_ABSENT`) from the predicate to
    the known-bad replay. It is deliberately NOT in :meth:`to_dict`: ``fidelity.json``'s ``checks``
    entry shape is a documented contract (docs/protocols/data-management.md, ADR-120), and whether a
    producer happened to have run is a property of the evaluation host rather than of the sealed
    evidence. The in-memory report the replay walks is where it is needed, and that is the only
    place it exists.
    """

    id: str
    klass: str
    stage: str
    status: str
    detail: str
    cause: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "klass": self.klass,
            "stage": self.stage,
            "status": self.status,
            "detail": self.detail,
        }

    @classmethod
    def from_outcome(
        cls, check: FidelityCheck, stage: str, outcome: CheckOutcome
    ) -> FidelityResult:
        return cls(
            check.id, check.klass_at(stage), stage, outcome.status, outcome.detail, outcome.cause
        )


@dataclass(frozen=True)
class FidelityReport:
    """Every check's verdict for one bundle, plus the summary the manifest copies.

    ``run_id`` and ``instrument_digest`` are the two identity fields: a report whose digest is
    ``None`` was computed on a tree that could not be hashed, which is itself worth saying in the
    artefact rather than leaving the reader to assume it matched the freeze.
    """

    run_id: str
    instrument_digest: str | None
    results: tuple[FidelityResult, ...]

    def by_id(self) -> dict[str, FidelityResult]:
        return {result.id: result for result in self.results}

    def summary(self) -> dict[str, dict[str, int]]:
        """Per-class counts, with every class and every status present at zero.

        Zero-filled on purpose. A summary that omits a class reads as "this class was not
        considered",
        and a class-R count of zero is a real and important number at the pilot gate.
        """
        summary = {klass: dict.fromkeys(STATUSES, 0) for klass in CLASSES}
        for result in self.results:
            bucket = summary.setdefault(result.klass, dict.fromkeys(STATUSES, 0))
            bucket[result.status] = bucket.get(result.status, 0) + 1
        return summary

    def to_document(self) -> dict[str, Any]:
        """The SEAM 2 document, byte-for-byte the shape every consumer parses."""
        return {
            "schema_version": FIDELITY_SCHEMA_VERSION,
            "run_id": self.run_id,
            "instrument_digest": self.instrument_digest,
            "checks": [result.to_dict() for result in self.results],
            "summary": self.summary(),
        }


# --------------------------------------------------------------------------- the bundle view


def _read_json(path: Path) -> Any:
    """Load a JSON document, or ``None`` when it is absent or unreadable.

    ``None`` rather than a raise: a fidelity check is a reader, and a reader that cannot read a file
    says so in its own verdict. The exceptions a reader swallows are enumerated, not broad -- a
    ``MemoryError`` or a ``KeyboardInterrupt`` must not be reported as "the file was absent".
    """
    try:
        return json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Load JSON Lines into dicts, skipping blank lines and non-object lines.

    The bundle is the runner's own output, so a non-object line is a defect in it; skipping rather
    than raising keeps one bad line from making every check in the registry report at once, which
    would bury the one that matters. The skipping is recorded nowhere, which is a deliberate limit
    of
    this helper: the completeness profile and the seal already refuse a bundle whose JSON Lines do
    not parse, so a line skipped here is one that got past them and the finding that matters is the
    one F-RN-01 or F-MN-03 raises about the count.
    """
    try:
        text = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


@dataclass(frozen=True)
class BundleView:
    """Everything a check may read, loaded once, from one bundle directory.

    A view rather than a path so that (a) each file is read at most once across the whole registry
    rather than once per check, (b) a check cannot reach the cluster -- there is no client here and
    no seam to inject one -- and (c) the campaign-level checks have somewhere to read a corpus from.

    Every accessor returns an empty value for a file that is absent, and ``present`` distinguishes
    "absent" from "present but empty", because for several checks (F-GD-06, F-MN-03, F-AN-03) the
    difference between those two IS the finding.

    ``required_stage`` is the one piece of evaluation CONTEXT rather than data, and it exists for
    F-AN-01: the readiness gate's per-stage semantics are three different rules applied to one
    artefact, and the registry is the only thing that knows which stage a given evaluation is for.
    It
    is a field rather than a predicate argument so that every check has the same signature and a new
    stage-dependent check needs no wrapper.
    """

    bundle_dir: Path
    campaign_dir: Path | None = None
    required_stage: str | None = None
    _cache: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)

    # --- identity ---------------------------------------------------------------------------

    @property
    def run_id(self) -> str:
        manifest = self.manifest()
        return str(manifest.get("run_id") or self.bundle_dir.name)

    def manifest(self) -> dict[str, Any]:
        cached = self._cache.get("manifest")
        if cached is None:
            payload = _read_json(self.bundle_dir / "manifest.json")
            cached = payload if isinstance(payload, dict) else {}
            self._cache["manifest"] = cached
        return cached

    def seal(self) -> dict[str, Any]:
        cached = self._cache.get("seal")
        if cached is None:
            payload = _read_json(self.bundle_dir / "seal.json")
            cached = payload if isinstance(payload, dict) else {}
            self._cache["seal"] = cached
        return cached

    def condition(self) -> str | None:
        value = self.manifest().get("condition")
        return str(value) if isinstance(value, str) else None

    def is_baseline(self) -> bool:
        return bool(self.manifest().get("is_baseline"))

    def run_window(self) -> tuple[str | None, str | None]:
        """``(started_at, ended_at)`` from the manifest, as strings or ``None``."""
        manifest = self.manifest()
        started, ended = manifest.get("started_at"), manifest.get("ended_at")
        return (
            str(started) if isinstance(started, str) else None,
            str(ended) if isinstance(ended, str) else None,
        )

    # --- presence ----------------------------------------------------------------------------

    def present(self, name: str) -> bool:
        return (self.bundle_dir / name).is_file()

    def non_empty(self, name: str) -> bool:
        path = self.bundle_dir / name
        try:
            return path.is_file() and path.stat().st_size > 0
        except OSError:
            return False

    # --- the agent-layer files ---------------------------------------------------------------

    def messages(self) -> list[dict[str, Any]]:
        cached = self._cache.get("messages")
        if cached is None:
            cached = _read_jsonl(self.bundle_dir / "messages.jsonl")
            self._cache["messages"] = cached
        return cached

    def tokens(self) -> list[dict[str, Any]]:
        cached = self._cache.get("tokens")
        if cached is None:
            payload = _read_json(self.bundle_dir / "tokens.json")
            cached = payload if isinstance(payload, list) else []
            self._cache["tokens"] = cached
        return cached

    def results(self) -> list[dict[str, Any]]:
        cached = self._cache.get("results")
        if cached is None:
            payload = _read_json(self.bundle_dir / "results.json")
            cached = payload if isinstance(payload, list) else []
            self._cache["results"] = cached
        return cached

    # --- the Monitor's files ------------------------------------------------------------------

    def events(self) -> list[dict[str, Any]]:
        cached = self._cache.get("events")
        if cached is None:
            cached = _read_jsonl(self.bundle_dir / "monitor_events.jsonl")
            self._cache["events"] = cached
        return cached

    def timings(self) -> list[dict[str, Any]]:
        cached = self._cache.get("timings")
        if cached is None:
            cached = _read_jsonl(self.bundle_dir / "monitor_timings.jsonl")
            self._cache["timings"] = cached
        return cached

    # --- the Guardian's files ----------------------------------------------------------------

    def audit_records(self) -> list[dict[str, Any]]:
        """``guardian_audit.jsonl`` as raw records, signature field and all.

        Read raw rather than through ``guardian.audit.chain.read_chain`` because F-GD-01 verifies
        the
        SIGNATURES and the chain module's parser is free to drop what it does not model. The chain
        module is still what computes the chain's own verdict -- see
        ``runner/fidelity/guardian.py``.
        """
        cached = self._cache.get("audit")
        if cached is None:
            cached = _read_jsonl(self.bundle_dir / "guardian_audit.jsonl")
            self._cache["audit"] = cached
        return cached

    def api_audit(self) -> list[dict[str, Any]]:
        """``k8s_api_audit.jsonl`` as raw API-server audit Events."""
        cached = self._cache.get("api_audit")
        if cached is None:
            cached = _read_jsonl(self.bundle_dir / API_AUDIT_FILENAME)
            self._cache["api_audit"] = cached
        return cached

    # --- the scenario's and the instruments' files --------------------------------------------

    def injection_log(self) -> list[dict[str, Any]]:
        cached = self._cache.get("injection")
        if cached is None:
            cached = _read_jsonl(self.bundle_dir / "injection.log.jsonl")
            self._cache["injection"] = cached
        return cached

    def assertions(self) -> dict[str, Any]:
        cached = self._cache.get("assertions")
        if cached is None:
            payload = _read_json(self.bundle_dir / "assertions.json")
            cached = payload if isinstance(payload, dict) else {}
            self._cache["assertions"] = cached
        return cached

    def metrics(self) -> dict[str, Any]:
        cached = self._cache.get("metrics")
        if cached is None:
            payload = _read_json(self.bundle_dir / "metrics.json")
            cached = payload if isinstance(payload, dict) else {}
            self._cache["metrics"] = cached
        return cached

    def resources(self) -> list[dict[str, str]]:
        """``resources.csv`` as dicts, read with the stdlib CSV reader.

        The header row is required: a bundle whose ``resources.csv`` has no ``restarts_total``
        column is refused at seal, and F-GD-02 needs the column to exist to read it.
        """
        cached = self._cache.get("resources")
        if cached is None:
            import csv

            rows: list[dict[str, str]] = []
            try:
                with (self.bundle_dir / "resources.csv").open(
                    "r", encoding="utf-8", newline=""
                ) as stream:
                    reader = csv.DictReader(stream)
                    if reader.fieldnames and "restarts_total" in reader.fieldnames:
                        rows = [row for row in reader if isinstance(row, dict)]
            except (OSError, UnicodeDecodeError):
                rows = []
            self._cache["resources"] = rows
            cached = rows
        return cached

    # --- the corpus --------------------------------------------------------------------------

    def sibling_bundles(self) -> list[Path]:
        """Every other bundle directory in the campaign, sorted, for a corpus-level check.

        A directory counts when it holds a ``manifest.json``; the campaign directory's own files
        (``campaign.json``, ``frozen_commit.txt``, ``fidelity_ledger.jsonl``) are not bundles and
        are
        excluded by that test rather than by a name list.
        """
        if self.campaign_dir is None:
            return []
        root = Path(self.campaign_dir)
        if not root.is_dir():
            return []
        return sorted(
            child
            for child in root.iterdir()
            if child.is_dir() and (child / "manifest.json").is_file()
        )

    def campaign_document(self) -> dict[str, Any]:
        """``campaign.json`` from the campaign directory, or ``{}``."""
        if self.campaign_dir is None:
            return {}
        payload = _read_json(Path(self.campaign_dir) / "campaign.json")
        return payload if isinstance(payload, dict) else {}

    def campaign_file(self, name: str) -> Path | None:
        """One campaign-level artefact, or ``None``. The corpus checks read through this."""
        if self.campaign_dir is None:
            return None
        path = Path(self.campaign_dir) / name
        return path if path.is_file() else None


# --------------------------------------------------------------------------- the registry


def _domain_modules() -> tuple[Any, ...]:
    """The per-domain check modules, in registry order.

    Imported here rather than at module scope so that ``import runner.fidelity`` does not pull the
    Guardian's audit verifier, the scenario planner and the analysis-side vacuity classifier into
    the process that only wanted the vocabulary -- which matters because ``runner/bundle.py``
    imports
    the protocol mirror at seal time and a seal is on the hot path of every run.
    """
    from runner.fidelity import agents, analysis, guardian, monitor, runner, scenarios

    return (agents, monitor, scenarios, guardian, runner, analysis)


def all_checks() -> tuple[FidelityCheck, ...]:
    """The whole registry, ordered by check id.

    Ordered by id rather than by module so the ledger, the render and the tests all read the same
    way regardless of import order -- ``runner/fidelity/agents.py`` sorts before
    ``runner/fidelity/monitor.py``, but ``F-AG-*`` sorts before ``F-MN-*`` for the same reason.
    """
    checks: list[FidelityCheck] = []
    for module in _domain_modules():
        checks.extend(module.CHECKS)
    return tuple(sorted(checks, key=lambda check: check.id))


def check_by_id(check_id: str) -> FidelityCheck:
    """One check by id, or :class:`KeyError` naming every id the registry holds."""
    for check in all_checks():
        if check.id == check_id:
            return check
    raise KeyError(
        f"{check_id!r} is not in the fidelity registry; it holds "
        f"{[check.id for check in all_checks()]}"
    )


#: Plan section 5's "v1 known-bad expectation" column, one sentence per check. Read by
#: ``runner/tests/test_fidelity_known_bad.py`` and printed by the ``--known-bad`` CLI, so a check
#: whose expected flag is empty is a gap in the registry rather than a silent pass: the known-bad
#: replay asserts every check names the v1 defect it is supposed to catch.
KNOWN_BAD_EXPECTATIONS: Final[dict[str, str]] = {
    check.id: check.known_bad for check in all_checks() if check.known_bad
}

#: Checks whose known-bad expectation is proven OFFLINE (their own pass/fail self-test), not by a
#: corpus raise, because their predicate does not read the corpus. F-SC-03a is the meta-check that
#: verifies OTHER predicates are definable and failable: it reads the repository content pools
#: directly (its predicate opens with ``del view``) and never a bundle, so no corpus bundle can flip
#: it. The default ``sh scripts/fidelity_check.sh`` run exercises its pass/fail fixtures; the
#: ``--known-bad`` corpus replay therefore EXCLUDES it from the set it demands a raise for, rather
#: than reporting it MISSING (ADR-139). It stays in ``KNOWN_BAD_EXPECTATIONS`` because it
#: does name a v1 defect and the registry-parity assertion still checks that.
OFFLINE_PROVEN_KNOWN_BAD: Final[frozenset[str]] = frozenset({"F-SC-03a"})

#: Plan section 5's own marker for a row that names NO v1 known-bad defect. Two rows use it --
#: F-GD-02 (no Guardian restart inside the window) and F-MN-04 (the forwarder drains) -- because
#: both are new v2 properties with no v1 counterpart to flag. The plan is the authority for the
#: column and ``test_fidelity.py`` asserts the registry's ``known_bad`` equals the table cell, so
#: the marker is the table's character rather than a blank: a blank would make the registry disagree
#: with the plan, and the parity test exists precisely to forbid that drift.
#:
#: It is a sentinel and not a sentence, which is what makes it readable as one: a check whose
#: expectation is prose names a defect, and a check whose expectation is this names none. See
#: ``DEFECT_NAMING_KNOWN_BAD``.
NO_V1_DEFECT: Final = "—"

#: The ids whose §5 expectation NAMES a v1 defect -- everything in ``KNOWN_BAD_EXPECTATIONS`` except
#: the rows marked :data:`NO_V1_DEFECT`. This, not ``KNOWN_BAD_EXPECTATIONS``, is the set a corpus
#: raise can be demanded of: a row with no v1 defect has nothing to raise, so demanding one would
#: make the replay unsatisfiable by construction rather than by a missing check (ADR-146).
DEFECT_NAMING_KNOWN_BAD: Final[frozenset[str]] = frozenset(
    check_id
    for check_id, expectation in KNOWN_BAD_EXPECTATIONS.items()
    if expectation.strip() != NO_V1_DEFECT
)

#: The cause a ``skip`` carries when the check's INPUT PRODUCER has not run over the corpus in hand,
#: so the check could not be evaluated at all -- as distinct from a skip that reports a bundle
#: genuinely lacking the thing the check measures. The distinction is what lets the known-bad replay
#: tell "this expectation is unsatisfiable over a pre-remediation corpus" apart from "this
#: expectation should have been raised and was not" (ADR-146).
#:
#: Only ever set by :meth:`CheckOutcome.producer_pending`. It is a gate-internal annotation and is
#: deliberately NOT written into ``fidelity.json``: the sealed artefact's ``checks`` entry shape is
#: a documented contract (docs/protocols/data-management.md), and whether a campaign-level producer
#: happened to have run is a property of the evaluation host, not of the sealed bundle's evidence.
#: The human-readable ``detail`` already says which producer is missing.
CAUSE_PRODUCER_ABSENT: Final = "producer-absent"


# --------------------------------------------------------------------------- evaluation


def _stages_or_default(stages: Sequence[str] | None) -> tuple[str, ...]:
    if stages is not None:
        return tuple(stages)
    return (STAGE_SEAL,)


def evaluate_bundle(
    bundle_dir: Path,
    *,
    stages: Sequence[str] | None = None,
    campaign_dir: Path | None = None,
    instrument_digest: str | None = None,
    checks: Sequence[FidelityCheck] | None = None,
) -> FidelityReport:
    """Run the registry's checks over one bundle and return the report.

    ``stages`` defaults to the seal stage, because that is the stage whose result is written into
    the bundle. A caller asking for more gets each stage's own results, so ``fidelity.json`` can
    carry the loop-stage and P0-live-stage verdicts alongside the seal ones.

    ``instrument_digest`` is taken from the argument, then from the manifest's own
    ``instrument_digest`` field (data-management section 2's M10 fields), and only then computed
    from the working tree -- which is the right order, because a bundle records the digest that
    produced it, and re-hashing the tree now would report whatever the tree has become.

    A predicate that raises is recorded as a ``fail`` with the exception text, never propagated: one
    broken check must not make the other twenty-five unreadable, and a check that cannot run is
    certainly not a check that passed.
    """
    bundle_dir = Path(bundle_dir)
    if not bundle_dir.is_dir():
        raise FidelityError(f"bundle directory {bundle_dir} does not exist")
    view = BundleView(
        bundle_dir=bundle_dir, campaign_dir=Path(campaign_dir) if campaign_dir else None
    )
    manifest_digest = view.manifest().get("instrument_digest")
    digest = instrument_digest or (
        str(manifest_digest) if isinstance(manifest_digest, str) and manifest_digest else None
    )
    if digest is None:
        digest = _tree_digest()

    registry = tuple(checks) if checks is not None else all_checks()
    results: list[FidelityResult] = []
    for stage in _stages_or_default(stages):
        # A fresh view per stage, carrying the stage as context. `dataclasses.replace` rather than a
        # new construction so the three fields stay in one place and the cache -- which is per-view
        # and therefore per-stage -- is empty rather than shared across stages.
        staged = replace(view, required_stage=stage)
        for check in registry:
            if not check.applies_at(stage):
                continue
            try:
                outcome = check.predicate(staged)
            except Exception as error:  # noqa: BLE001 - a broken check is a failure, not a crash
                outcome = CheckOutcome.failed(
                    f"{type(error).__name__}: {error} (the check could not be evaluated; a check "
                    "that cannot run is not a check that passed)"
                )
            results.append(FidelityResult.from_outcome(check, stage, outcome))
    return FidelityReport(run_id=view.run_id, instrument_digest=digest, results=tuple(results))


def _tree_digest() -> str | None:
    """The instrument digest at HEAD, or ``None`` when it cannot be computed.

    The import is inside the function so that a bundle read in an environment with no ``git`` -- a
    copied corpus on a reviewer's laptop, a test fixture -- degrades to a null digest instead of
    failing to import. ``runner/freeze.py`` is Part A's; this is the only place the fidelity package
    calls into it, and it is a read.
    """
    try:
        from runner.freeze import instrument_digest
    except ImportError:
        return None
    try:
        return instrument_digest()
    except Exception:  # noqa: BLE001 - a null digest is a reportable fact, not a crash
        return None


# --------------------------------------------------------------------------- writing and reading


def write_fidelity_report(bundle_dir: Path, report: FidelityReport) -> Path:
    """Write ``fidelity.json`` into the bundle, canonically, and return its path.

    Canonical JSON with the same four arguments ``runner/manifest.py`` uses, because this file is
    covered by ``seal.json``'s content hashes and a manifest and its fidelity report that disagree
    about encoding would make the seal's reproducibility argument two encoders deep.

    Written BEFORE the seal -- ``runner/bundle.py`` evaluates this package and then hashes -- so the
    seal covers the verdict as well as the evidence it is a verdict about.
    """
    path = Path(bundle_dir) / FIDELITY_FILENAME
    text = json.dumps(
        report.to_document(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    path.write_bytes(text.encode("utf-8") + b"\n")
    return path


def read_fidelity(bundle_dir: Path) -> dict[str, Any] | None:
    """The bundle's ``fidelity.json``, or ``None`` when it is absent or malformed."""
    payload = _read_json(Path(bundle_dir) / FIDELITY_FILENAME)
    return payload if isinstance(payload, dict) else None


def append_fidelity_ledger(
    campaign_dir: Path, report: FidelityReport, *, stages: Sequence[str] | None = None
) -> Path:
    """Append one line per check to ``<campaign>/fidelity_ledger.jsonl`` and return the path.

    One JSON object per CHECK rather than one per run, because the ledger's job is to be greppable
    by
    check id across a whole campaign: "every F-MN-01 verdict in this campaign" is one ``jq`` away,
    and a per-run summary object would bury it. Each line carries the run id and the stage, so the
    lines are still reconstructible per run.

    Append-only and opened in ``a``, with the run id first in the key order. A truncated final line
    (a killed process) is tolerated by every reader here -- a reader that fails on a partial line
    would refuse to report over a campaign whose last run was interrupted, which is precisely when a
    reader is needed.
    """
    path = Path(campaign_dir) / LEDGER_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    asked = set(stages) if stages is not None else None
    with path.open("a", encoding="utf-8") as stream:
        for result in report.results:
            if asked is not None and result.stage not in asked:
                continue
            line = {
                "run_id": report.run_id,
                "instrument_digest": report.instrument_digest,
                **result.to_dict(),
            }
            stream.write(
                json.dumps(line, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
            )
    return path


# --------------------------------------------------------------------------- the blocking rule


def t_failures(report: FidelityReport) -> tuple[FidelityResult, ...]:
    """Every class-T check that failed.

    The single predicate the campaign halt rule reads (``runner/campaign_cli.py``): a T failure
    writes
    ``HALTED.json`` and raises out of the loop. Named rather than inlined so that the halt rule and
    the ledger cannot come to disagree about which results are T failures.
    """
    return tuple(
        result for result in report.results if result.klass == "T" and result.status == "fail"
    )


def blocking_ids(report: FidelityReport, stage: str) -> tuple[str, ...]:
    """Check ids whose ``fail`` blocks at ``stage``, under P2's three classes.

    The whole rule is :data:`BLOCKING_CLASSES`, read once:

    * class **T** blocks at every declared stage -- "blocks the pilot and halts the campaign".
    * class **B** blocks at the four ladder stages and is reported at the other five
      (:data:`BANNED_STAGES`). A behaviour finding that halted a campaign would delete the
      dissertation's results, because the finding IS a result.
    * class **R** blocks at the three readiness stages (:data:`READINESS_STAGES`). A class-R check
      evaluated at the seal stage is *recorded* there and *consulted* at the gate, which is the
      per-stage semantics plan §5 states for F-AN-01 and F-RN-02.

    Only ``fail`` blocks. ``warn`` and ``skip`` are reported: the readiness gate has its own rule
    for a
    ``warn`` (F-AN-01's ``nan`` from n < 2, and a pending judged measure), and a gate that turned
    every
    ``warn`` into a stop would make the ladder unusable for the ordinary case of a small pilot. A
    stage nobody declared blocks on class T alone.
    """
    blocks = BLOCKING_CLASSES.get(stage, ("T",))
    return tuple(
        sorted(
            result.id
            for result in report.results
            if result.klass in blocks and result.status == "fail"
        )
    )


def iter_campaign_reports(
    campaign_dir: Path, *, stages: Sequence[str] | None = None
) -> Iterator[FidelityReport]:
    """Evaluate every bundle in a campaign directory, in name order.

    Sorted, because the report a reader sees must not depend on the filesystem's iteration order
    (``.agents/rules/20-parity-and-determinism.md``). A bundle with no ``manifest.json`` is skipped
    rather than reported: a directory that is not a bundle is not a finding of the fidelity gate.
    """
    root = Path(campaign_dir)
    if not root.is_dir():
        raise FidelityError(f"campaign directory {root} does not exist")
    for bundle_dir in sorted(root.iterdir()):
        if bundle_dir.is_dir() and (bundle_dir / "manifest.json").is_file():
            yield evaluate_bundle(bundle_dir, stages=stages, campaign_dir=root)


def _gate_class(check_id: str) -> str:
    """The class a check carries at the pilot gate, resolved from its own stage mapping.

    A check id the registry does not hold (a hand-written row, or a check removed since the bundle
    sealed) falls back to the blocking class, the same direction :meth:`FidelityCheck.klass_at`
    falls for an undeclared stage: an unknown row must block, not slip through.
    """
    try:
        check = check_by_id(check_id)
    except KeyError:
        return "T"
    for stage in _GATE_CLASS_PRIORITY:
        if check.applies_at(stage):
            return check.klass_at(stage)
    return check.klass_at(STAGE_PILOT_GATE)


def campaign_gate_rows(
    campaign_dir: Path, *, stages: Sequence[str] = GATE_STAGES
) -> list[dict[str, Any]]:
    """One gate row per check id over a whole pilot campaign (M10 plan section 6).

    The pilot gate asks a CORPUS-level question -- "did every treatment hold, across every arm and
    every injection condition" -- so it needs one verdict per check over the whole campaign, not one
    per bundle. This builds that: it evaluates every sealed bundle in ``campaign_dir`` at every
    gate stage, resolves each check's class at the gate stage it declares (:func:`_gate_class`),
    and folds the per-bundle verdicts into one row with the worst status winning
    (:data:`_GATE_STATUS_RANK`).

    Rows are sorted by check id and the fold is order-independent, so the gate's input does not
    depend on the filesystem's iteration order (``.agents/rules/20-parity-and-determinism.md``). The
    row shape is the one ``runner.pilot_cli.read_checks`` and ``evaluate_gate`` consume: ``id``,
    ``klass``, ``status``, plus the ``detail`` of the worst bundle so a NO-GO reads as a sentence.

    A check whose verdict is ``skip`` over EVERY bundle with no producer-pending cause is DROPPED:
    it was not applicable to this corpus anywhere (F-SC-01 on an all-INJ-NONE corpus, F-MN-04 on any
    non-probe bundle, F-GD-01 where no external anchor ledger exists), and the gate is not the place
    to demand a measurement the corpus never defined. A ``skip`` that survives the filter is one
    whose campaign-level input producer has not run (``CAUSE_PRODUCER_ABSENT``, ADR-146), and the
    gate must see it: ``runner.pilot_cli`` blocks a class-T or class-B ``skip`` precisely because
    such a check should have run over this corpus and did not.
    """
    worst: dict[str, tuple[int, str, str, str]] = {}
    for report in iter_campaign_reports(Path(campaign_dir), stages=tuple(stages)):
        for result in report.results:
            rank = _GATE_STATUS_RANK.get(result.status, 0)
            current = worst.get(result.id)
            if current is None or rank > current[0]:
                worst[result.id] = (rank, result.status, result.detail, result.cause)
    rows: list[dict[str, Any]] = []
    for check_id in sorted(worst):
        _rank, status, detail, cause = worst[check_id]
        if status == "skip" and cause != CAUSE_PRODUCER_ABSENT:
            continue
        rows.append(
            {"id": check_id, "klass": _gate_class(check_id), "status": status, "detail": detail}
        )
    return rows


def fold_gate_rows(
    row_sets: Iterable[Sequence[Mapping[str, Any]]],
) -> list[dict[str, Any]]:
    """Fold several gate-row sets -- one per campaign -- into one row per check (SEAM 2).

    The pilot's evidence is spread across campaign ids that can never share a directory: P1a's
    scripted runs and P2's live runs both name ``RUN-<arm>-SCN-SIM-01-INJ-NONE-901``, so merging the
    bundles would lose one of the two. So the gate folds the *rows* instead, and this is that fold
    lifted out of :func:`campaign_gate_rows` so both folds use the SAME status rank and a row can
    never be ranked one way inside a directory and another way across directories.

    Worst status wins, exactly as within a directory (:data:`_GATE_STATUS_RANK`), because a check
    that failed on one arm has not held across the pilot -- which is the whole question the gate
    asks. Rows are sorted by check id, so the fold does not depend on the order the campaigns are
    named in.
    """
    worst: dict[str, tuple[int, Mapping[str, Any]]] = {}
    for rows in row_sets:
        for row in rows:
            check_id = str(row.get("id", "<unnamed>"))
            rank = _GATE_STATUS_RANK.get(str(row.get("status", "")), 0)
            current = worst.get(check_id)
            if current is None or rank > current[0]:
                worst[check_id] = (rank, row)
    return [dict(worst[check_id][1]) for check_id in sorted(worst)]


def coerce_status(value: object) -> str:
    """Read a status out of a possibly-hand-written ledger line, refusing anything outside the set.

    Used by the known-bad replay, which reads verdicts back out of the artefacts it wrote. A hand
    edit that put ``"FAIL"`` or ``"ok"`` in a status must be a loud error rather than a check that
    silently does not match.
    """
    text = str(value)
    if text not in STATUSES:
        raise FidelityError(
            f"status {value!r} is not one of {STATUSES}; fidelity.json's vocabulary is closed"
        )
    return text


def statuses_by_id(document: Mapping[str, Any]) -> dict[str, str]:
    """``{check id: status}`` from a ``fidelity.json`` document or a ledger line."""
    checks = document.get("checks")
    if not isinstance(checks, list):
        return {}
    return {
        str(entry.get("id")): coerce_status(entry.get("status"))
        for entry in checks
        if isinstance(entry, Mapping)
    }


def iter_ledger(campaign_dir: Path) -> Iterable[dict[str, Any]]:
    """Every readable line of a campaign's fidelity ledger, in file order."""
    path = Path(campaign_dir) / LEDGER_FILENAME
    if not path.is_file():
        return []
    return _read_jsonl(path)
