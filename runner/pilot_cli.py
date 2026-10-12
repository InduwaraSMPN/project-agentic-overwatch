r"""``make pilot-<stage>``: the M10 pilot ladder driver and its gate decision.

(M10 plan §6, ADR-120.)

WHAT THIS IS
------------
The v1 gate pilots ran six G0/G1 runs and nothing else, so four of the six arms were never piloted
and the treatments that were broken in v1 (S2/S3 never reaching the Guardian, G2 inert, G3 quoting
carry-over) were never seen (defect V16). The M10 ladder is the replacement: seven steps, each with
an exit criterion stated in the plan, and a ``decide`` step that turns the accumulated fidelity
results into a single ``gate_decision.json`` the freeze checklist reads before ``v2.0`` is tagged
(plan §7).

    p0        offline: every suite, lint, every guard, parity, determinism, exhaustive offline
              planning of every cell, the known-bad replay. No runs.
    p0-live   instrument-only probes on the live cluster: bring-up, the quoting/epoch chain, every
              pool-02 INJ-B payload, the G2 path, the API-server audit slice.
    p1a       scripted runs, one per arm, no model tokens: mint -> act -> complete through Guardian,
              audit, Monitor, seal and fidelity.
    p1b       live runs: the Ch.3 cost pilot (3 G0 + 3 G1) plus one live S2/S3/G2/G3 that pairs
              with it.
    p2        coverage runs, 6 arms x 5 injection conditions on pilot seed A, in the Eulerian arm
              order (M10 plan §6, ``runner.order.generate_pilot_order``).
    p3        the repeat, on pilot seed B, the injection-to-scenario map shifted by one and the arm
              order the literal reverse of P2's.
    decide    every class-T check at 100%, no class-R failure, no class-B failure withheld from
    the decision but not gating it (ADR-183), no framework-attributable failure, ladder complete
    -> GO.

THE LADDER IS KEYED ON THE INSTRUMENT DIGEST, AND THAT IS THE WHOLE RESTART RULE
---------------------------------------------------------------------------------
Plan §6: "an instrument change resets the ladder to P1a; P0-offline reruns in full and P0-live
reruns for the affected instrument only. A commit outside the instrument paths does not reset the
ladder." So :func:`record_stage` stores the instrument digest (P6, :mod:`runner.freeze`) beside the
completed stages; a *different* digest on the next invocation empties the completed set, counts a
reset, and records :data:`RESET_STAGE` as the stage the ladder resumes at. A docs-only commit
produces an identical digest and therefore changes nothing -- the failure direction the v1
whole-repository dirty check had, in which a reworded comment halted a campaign.

Every stage's *run count* is the protocol's, mirrored in this module and checked by
``runner/tests/test_pilot_constants_match_protocol.py``; none is written here as a literal
(``docs/protocols/evaluation-protocol.md`` §4 owns them, ADR-120).

WHERE THE MIRROR LIVES, AND WHERE IT IS GOING
----------------------------------------------
The M10 plan names ``runner/fidelity/`` as the home of the full ``<!-- m10-fidelity-constants -->``
mirror; that package is the Part-B half of WS-5 and does not exist yet, so the five constants *this*
module consumes are mirrored here, behind the same contract ``analysis/stats/m10.py`` uses for the
one constant ``analysis/`` consumes: the protocol is the authority, this file is a checked copy, and
``runner/tests/test_pilot_constants_match_protocol.py`` is the entire justification for the copy
being legal under ``.agents/rules/00-source-of-truth.md``. The keys are a strict SUBSET of the
block's, disjoint from ``analysis/stats/m10.py``'s, so no constant has three homes. **Part B
repoints by replacing that one section with one import** -- the five constant names,
:data:`MIRRORED_KEYS`, :data:`PROTOCOL_ANCHOR` and :data:`PROTOCOL_RELATIVE_PATH` are the whole
public surface, and the mirror test names them.

WHAT THIS MODULE DELIBERATELY DOES NOT DO
-----------------------------------------
It does not execute anything. Every subcommand is a thin, testable function over the state file; the
cluster work belongs to ``runner/campaign_cli.py`` and the fidelity verdicts to ``runner/fidelity/``
(Part B). A ladder driver that also ran the ladder could not be proven exhaustively offline, and
M10 principle **P5** requires the deterministic parts to be.

DETERMINISM
-----------
No wall-clock, no unseeded randomness, no dict-iteration order in anything written:
``ladder_state.json`` and ``gate_decision.json`` are canonical JSON over sorted keys, so
re-running a completed stage rewrites identical bytes (iron rule 3).

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
``gate_decision.json``, which ``v2.0``'s freeze checklist is gated on, and the ladder-reset rule.
ADR-120, ADR-136.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from runner.freeze import FreezeError, enforce_freeze, instrument_digest
from runner.order import OrderError, generate_pilot_order

__all__ = (
    "GATE_DECISION_FILE",
    "LADDER_STAGES",
    "LADDER_STATE_FILE",
    "MIRRORED_KEYS",
    "PILOT_P0_LIVE_PROBES",
    "PILOT_P1A_RUNS",
    "PILOT_P1B_RUNS",
    "PILOT_P2_RUNS",
    "PILOT_P3_RUNS",
    "PILOT_VALIDATORS",
    "PROTOCOL_ANCHOR",
    "PROTOCOL_RELATIVE_PATH",
    "RESET_STAGE",
    "GateDecision",
    "LadderError",
    "LadderState",
    "evaluate_gate",
    "gate_decision",
    "ladder_complete",
    "load_gate_decision",
    "load_ladder_state",
    "main",
    "next_stage",
    "read_checks",
    "record_stage",
    "write_gate_decision",
    "write_ladder_state",
)

REPO_ROOT: Final = Path(__file__).resolve().parents[1]

# =================================================================================================
# THE MIRRORED M10 CONSTANTS -- docs/protocols/evaluation-protocol.md §4's
# `<!-- m10-fidelity-constants -->` block, key for key, for the five values this module consumes.
# Read the module docstring's "WHERE THE MIRROR LIVES" section for why they are here and not in
# `runner/fidelity/` yet; it also names the exact repoint.
# =================================================================================================

# An HTML anchor rather than a heading search, for the reason `analysis.stats.gate` gives for the
# GATE block: a heading is prose and gets retitled, an anchor exists for exactly one purpose.
PROTOCOL_ANCHOR: Final = "<!-- m10-fidelity-constants -->"

# The owning protocol file, relative to the repository root -- the same file the GATE, M1/M2 and M10
# blocks all live in. M10 owns a different block within one document, not a different document.
PROTOCOL_RELATIVE_PATH: Final = "docs/protocols/evaluation-protocol.md"

# P0-live's probe count. "about 35" in the plan, an integer here because a probe count that is a
# float is not a count; the protocol owns the rounding, this file only the number.
PILOT_P0_LIVE_PROBES: Final[int] = 35
# P1a's six scripted runs, one per arm (plan §6; the only stage that touches every arm once).
PILOT_P1A_RUNS: Final[int] = 6
# P1b's ten live runs: the Ch.3 cost pilot's six plus one live S2/S3/G2/G3 each, paired with it.
PILOT_P1B_RUNS: Final[int] = 10
# P2's and P3's coverage sizes. Equal because the design is: both passes are 6 arms x 5 injection
# conditions on one pilot seed, and the two differ in the seed, the scenario map and the arm order.
PILOT_P2_RUNS: Final[int] = 30
PILOT_P3_RUNS: Final[int] = 30

# The keys this module mirrors, in the order the mirror test reports them. A strict subset of the
# block's own keys, by design: `.agents/rules/00` allows a literal to appear twice only where the
# second copy is checked against the first, and every value a module restates must be a value that
# module uses. The block's class-B, halting-loop, scoring and live-timing keys are Part B's.
MIRRORED_KEYS: Final[tuple[str, ...]] = (
    "pilot_p0_live_probes",
    "pilot_p1a_runs",
    "pilot_p1b_runs",
    "pilot_p2_runs",
    "pilot_p3_runs",
)

# The ladder's stages in execution order. The subcommand names, not the protocol's stage labels, so
# that `python -m runner.pilot_cli p1a` reads as the Makefile target does.
LADDER_STAGES: Final[tuple[str, ...]] = ("p0", "p0-live", "p1a", "p1b", "p2", "p3")

# Where an instrument change sends the ladder (plan §6's restart rule, verbatim: "an instrument
# change resets the ladder to P1a"). P0-offline is re-run in full and P0-live for the affected
# instrument, but neither is a stage the ladder may *skip* on the way back, so the resume point is
# the first stage whose exit criterion involves the instrument that changed.
RESET_STAGE: Final = "p1a"

LADDER_STATE_FILE: Final = "ladder_state.json"
GATE_DECISION_FILE: Final = "gate_decision.json"

# The runs each stage plans, from the mirrored constants above. Used to check a coverage stage's
# generated order against the size the protocol fixes, so a change to the pilot grid cannot quietly
# make a stage under- or over-powered (P5). `p0` is 0 because it runs no bundles at all.
STAGE_RUNS: Final[Mapping[str, int]] = {
    "p0": 0,
    "p0-live": PILOT_P0_LIVE_PROBES,
    "p1a": PILOT_P1A_RUNS,
    "p1b": PILOT_P1B_RUNS,
    "p2": PILOT_P2_RUNS,
    "p3": PILOT_P3_RUNS,
}

# Which coverage pass each 30-run stage is: p2 -> pass "P2", p3 -> pass "P3" (runner/order.py).
COVERAGE_PASSES: Final[Mapping[str, str]] = {"p2": "P2", "p3": "P3"}

# The decision a gate can return. GO is the only value the freeze checklist accepts (plan §7).
GO: Final = "GO"
NO_GO: Final = "NO-GO"

# The three pilot validators, keyed by the KIND an operator names (ADR-136; plan §6). Each value is
# the NAME of a ``runner.validate`` entry point, resolved by :func:`_run_validate` at call time so
# this module does not import the Part-B validator half at module scope. ``cost`` is the default, so
# a bare ``validate`` keeps checking a cost-pilot manifest exactly as it always did -- V16 kept the
# 3+3 plan, it did not retire it -- and P1a's smoke and P2/P3's coverage manifests get their own
# validators by name rather than by hand-editing the subcommand.
PILOT_VALIDATORS: Final[Mapping[str, str]] = {
    "cost": "validate_cost_pilot_manifest",
    "cost-extended": "validate_extended_cost_pilot_manifest",
    "smoke": "validate_smoke_pilot_manifest",
    "coverage": "validate_coverage_pilot_manifest",
}

# Fidelity check classes (plan §5 / ADR-120). T blocks the pilot and halts the campaign; B is
# reported at the pilot gate and in the campaign, and no longer gates (ADR-183); R blocks the pilot
# gate, the checkpoint and the corpus.
CLASS_T: Final = "T"
CLASS_B: Final = "B"
CLASS_R: Final = "R"
FIDELITY_CLASSES: Final[tuple[str, ...]] = (CLASS_T, CLASS_B, CLASS_R)

# The per-check statuses a fidelity row may carry (SEAM 2). `warn` and `skip` are kept distinct from
# `pass` on purpose: a check that did not run has not passed, and for class T that must not read as
# a pass, or the gate would be satisfiable by a check that never executed.
STATUS_PASSING: Final = "pass"
FIDELITY_STATUSES: Final[tuple[str, ...]] = ("pass", "fail", "warn", "skip")

# The state document's own version, so a future field addition is a version bump rather than a
# silent reinterpretation of an old ladder_state.json.
LADDER_SCHEMA_VERSION: Final = "v1"
GATE_SCHEMA_VERSION: Final = "v1"


class LadderError(RuntimeError):
    """The ladder was asked to do something the plan does not define, or its state is unusable."""


# ================================================================================================
# STATE -- the whole ladder, as a small deterministic record
# ================================================================================================


@dataclass(frozen=True)
class LadderState:
    """Where the ladder stands on ONE instrument.

    ``instrument_digest`` is the KEY, not a field of interest: it is what makes "an
    instrument change resets the ladder" mechanical (ADR-136) instead of a rule someone has
    to remember.
    ``resume_stage`` is non-null exactly when the last recorded stage tripped that rule, so the
    record itself says where the ladder restarts rather than the operator having to recall §6.
    """

    instrument_digest: str
    completed: tuple[str, ...]
    freeze_tag: str | None
    frozen_commit: str | None
    resets: int
    resume_stage: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "instrument_digest": self.instrument_digest,
            "completed": list(self.completed),
            "freeze_tag": self.freeze_tag,
            "frozen_commit": self.frozen_commit,
            "resets": self.resets,
            "resume_stage": self.resume_stage,
            "schema_version": LADDER_SCHEMA_VERSION,
        }


def _state_path(state_dir: Path) -> Path:
    return Path(state_dir) / LADDER_STATE_FILE


def _canonical(payload: Mapping[str, Any]) -> bytes:
    """Canonical JSON bytes, the repository's four arguments, with a trailing newline.

    The same shape ``runner/manifest.py`` and ``runner/campaign.py`` use, so a document written by
    this module hashes the same way on any machine -- and, since no timestamp is in the payload, a
    re-run that changes nothing rewrites the identical bytes.
    """
    text = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )
    return text.encode("utf-8") + b"\n"


def load_ladder_state(state_dir: Path) -> LadderState | None:
    """The recorded state, or ``None`` when this campaign has never run a stage."""
    path = _state_path(state_dir)
    if not path.is_file():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    expected = {
        "instrument_digest",
        "completed",
        "freeze_tag",
        "frozen_commit",
        "resets",
        "resume_stage",
        "schema_version",
    }
    if set(payload) != expected:
        raise LadderError(
            f"{path} carries {sorted(payload)}, not the ladder-state shape {sorted(expected)}; "
            "delete it to start the ladder again rather than hand-editing it"
        )
    if payload["schema_version"] != LADDER_SCHEMA_VERSION:
        raise LadderError(
            f"{path} is ladder state schema {payload['schema_version']!r}, not "
            f"{LADDER_SCHEMA_VERSION!r}"
        )
    return LadderState(
        instrument_digest=str(payload["instrument_digest"]),
        completed=tuple(payload["completed"]),
        freeze_tag=payload["freeze_tag"],
        frozen_commit=payload["frozen_commit"],
        resets=int(payload["resets"]),
        resume_stage=payload["resume_stage"],
    )


def write_ladder_state(state_dir: Path, state: LadderState) -> Path:
    """Write the state as canonical JSON and return its path.

    Skips the write when the bytes are already what would be written, so a fix loop that re-records
    a stage leaves the artifact untouched rather than merely identical -- the difference matters
    when
    the file's mtime is what a human glances at to decide whether anything happened.
    """
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    path = _state_path(state_dir)
    payload = _canonical(state.to_dict())
    if not path.is_file() or path.read_bytes() != payload:
        path.write_bytes(payload)
    return path


def _first_unmet(completed: Sequence[str]) -> str:
    """The first stage in ladder order that ``completed`` does not contain."""
    done = set(completed)
    for stage in LADDER_STAGES:
        if stage not in done:
            return stage
    return LADDER_STAGES[-1]


def next_stage(state: LadderState | None) -> str:
    """The stage the ladder expects next: the resume point, else the first unmet stage."""
    if state is None:
        return LADDER_STAGES[0]
    if state.resume_stage is not None:
        return state.resume_stage
    return _first_unmet(state.completed)


def _permitted(state: LadderState) -> tuple[str, ...]:
    """The stages that may be recorded next on ``state``.

    Normally exactly one -- the first unmet stage -- because each stage's exit criterion is a
    precondition for the next. After an instrument reset there are TWO, and the second one is the
    plan's whole restart rule read operationally (M10 plan §6): "an instrument change resets the
    ladder to P1a; P0-offline reruns in full and P0-live reruns for the affected instrument only".

    So P0-offline is recordable (it is re-run in full, and it is the ladder's first unmet stage) AND
    P1a is recordable straight away (the ladder resumes there; nobody has to wait for the offline
    stage to be re-recorded before the live ones restart). Everything between them is still refused.
    """
    first = _first_unmet(state.completed)
    if state.resume_stage is not None and state.resume_stage != first:
        return (state.resume_stage, first)
    return (first,)


def ladder_complete(state: LadderState | None) -> bool:
    """Whether every stage is recorded on the current instrument, with no reset outstanding."""
    if state is None or state.resume_stage is not None:
        return False
    return set(LADDER_STAGES) <= set(state.completed)


def record_stage(
    state_dir: Path,
    stage: str,
    *,
    freeze_tag: str | None = None,
    repo_root: Path = REPO_ROOT,
    enforce: bool = True,
    campaign_dir: Path | None = None,
) -> LadderState:
    """Record ``stage`` as completed on the current instrument, resetting the ladder if it moved.

    This is the freeze's pilot half (ADR-136, "Pilot freeze"), so with ``enforce=True`` -- the
    default, and the only value the CLI uses -- a dirty instrument is refused here exactly as
    ``execute_campaign`` refuses it per cell, through the same
    :func:`runner.freeze.enforce_freeze`. A pilot that routes around the freeze is not frozen.

    The ONE thing the pilot does differently from a campaign is how it answers an instrument move:
    ``enforce_freeze(..., retarget=True)``, so the sidecar is re-pinned instead of the call being
    refused. That is not a hole in the freeze -- the campaign never passes the flag, and with a
    ``freeze_tag`` the tag's digest comparison fires first and the flag is unreachable -- it is plan
    §6's restart rule made executable: an instrument change during the ladder is an expected event
    with a documented response, and the response is recorded in ``resets`` and ``resume_stage``
    where
    a reader can see it.

    Re-recording a stage that is already recorded is deliberately allowed and idempotent: a fix loop
    re-runs a stage without the operator having to know whether it had been recorded, and the state
    is the same either way. Recording a stage that is not the next expected one is refused, because
    each stage's exit criterion is a precondition for the next (plan §6).

    On a DIFFERENT instrument digest the completed set is emptied, ``resets`` is incremented and
    ``resume_stage`` is set to :data:`RESET_STAGE`; every earlier result was produced by an
    instrument that no longer exists, so none of it is evidence about this one.
    """
    if stage not in LADDER_STAGES:
        raise LadderError(
            f"{stage!r} is not a pilot-ladder stage; the ladder is {', '.join(LADDER_STAGES)} "
            "(M10 plan §6)"
        )
    digest = instrument_digest(repo_root)
    previous = load_ladder_state(state_dir)
    moved = previous is not None and previous.instrument_digest != digest
    frozen: str | None = None
    if enforce:
        frozen = enforce_freeze(
            campaign_dir if campaign_dir is not None else Path(state_dir),
            freeze_tag,
            repo_root=repo_root,
            retarget=moved,
        )
    if previous is not None and previous.instrument_digest == digest:
        completed = previous.completed
        resets = previous.resets
        resume = previous.resume_stage
        if stage not in completed and stage not in _permitted(previous):
            expected = next_stage(previous)
            raise LadderError(
                f"stage {stage!r} cannot be recorded before {expected!r}; the ladder is climbed "
                f"in order ({' -> '.join(LADDER_STAGES)}) because each stage's exit criterion is a "
                "precondition for the next (M10 plan §6)"
            )
    else:
        if previous is None and stage != LADDER_STAGES[0]:
            raise LadderError(
                f"a new ladder starts at {LADDER_STAGES[0]!r}, not {stage!r}; the ladder is "
                f"climbed in order ({' -> '.join(LADDER_STAGES)}) (M10 plan §6)"
            )
        completed = ()
        # A reset only happens when there WAS a state to reset. A first-ever record is not a reset:
        # the ladder simply starts at P0, and claiming otherwise would make every new ladder look
        # like a re-iteration and send the operator to P1a instead of P0.
        resets = (previous.resets + 1) if previous is not None else 0
        resume = RESET_STAGE if previous is not None else None
    if stage not in completed:
        completed = (*completed, stage)
    if resume == stage:
        resume = None  # the reset point has been re-reached; the ladder is climbing again
    state = LadderState(
        instrument_digest=digest,
        completed=completed,
        freeze_tag=(
            freeze_tag
            if freeze_tag is not None
            else (previous.freeze_tag if previous is not None else None)
        ),
        frozen_commit=(
            frozen
            if frozen is not None
            else (previous.frozen_commit if previous is not None else None)
        ),
        resets=resets,
        resume_stage=resume,
    )
    write_ladder_state(state_dir, state)
    return state


def coverage_order(stage: str) -> tuple[Any, ...]:
    """The generated run order for a coverage stage, checked against the protocol's run count.

    Deterministic and offline (P5: the deterministic parts of every cell are proven exhaustively
    without a cluster), so a change to the pilot grid is caught by a test rather than by noticing a
    coverage pass came back one run short.
    """
    if stage not in COVERAGE_PASSES:
        raise LadderError(
            f"{stage!r} is not a coverage stage; the coverage passes are "
            f"{', '.join(sorted(COVERAGE_PASSES))} (M10 plan §6)"
        )
    try:
        order = generate_pilot_order(COVERAGE_PASSES[stage])
    except OrderError as error:
        raise LadderError(str(error)) from error
    expected = STAGE_RUNS[stage]
    if len(order) != expected:
        raise LadderError(
            f"the {stage} pass generates {len(order)} runs, not the {expected} "
            "docs/protocols/evaluation-protocol.md §4 fixes (ADR-120); the pilot grid and the "
            "protocol disagree"
        )
    return order


# ================================================================================================
# THE GATE DECISION -- the one file the v2.0 freeze checklist reads
# ================================================================================================


@dataclass(frozen=True)
class GateDecision:
    """``GO`` or ``NO-GO``, with every reason the gate refused spelled out.

    A bare boolean would leave a NO-GO unactionable, and an unactionable gate is the defect this
    whole workstream exists to close (V16: a gate that never looked at the arms it was meant to look
    at). Every non-passing check id appears in ``reasons``, so the fix list IS the file.
    """

    decision: str
    reasons: tuple[str, ...]
    counts: Mapping[str, Mapping[str, int]]
    instrument_digest: str | None
    framework_failures: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reasons": list(self.reasons),
            "counts": {klass: dict(counts) for klass, counts in sorted(self.counts.items())},
            "instrument_digest": self.instrument_digest,
            "framework_failures": self.framework_failures,
            "schema_version": GATE_SCHEMA_VERSION,
        }


def _counts(checks: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, int]]:
    """Per-class status tallies, every status present so the shape does not depend on the input."""
    tally: dict[str, dict[str, int]] = {
        klass: dict.fromkeys(FIDELITY_STATUSES, 0) for klass in FIDELITY_CLASSES
    }
    for check in checks:
        klass = str(check.get("klass", ""))
        status = str(check.get("status", ""))
        if klass in tally and status in tally[klass]:
            tally[klass][status] += 1
    return tally


# The statuses that block, per class, at the PILOT GATE.
#
# **T**: anything short of a pass. A treatment check that did not run has not passed, so `warn` and
# `skip` block too.
#
# **R**: a `fail` only, because F-AN-01's readiness gate carries its own per-stage semantics (at the
# pilot a `nan` from n < 2 is WARN) and duplicating a per-stage rule here would create a second
# place for it to differ.
#
# **B**: nothing (ADR-183). B was "anything short of a pass" here, on the strength of plan §5's
# "B blocks the pilot, reported in the campaign". Two measured live cells on provisional freezes
# `v2-pilot-20261006e` and `v2-pilot-20261006f` showed that bar is unreachable for a correct
# guardrail rather than a broken instrument, and unreachable *by construction*:
#
#   * A phase Supervisor holds `max_tool_calls: 2` -- one mint, one completion. When the Guardian
#     correctly refuses the single mint (`issue_authority_exceeded`, on a scope naming `secrets`
#     and a second namespace), the phase holds no capability, so no Executing role runs, so
#     `F-AG-03` "every arm reaches the Guardian" fails. The refusal is the deny-by-default policy
#     working.
#   * A phase that cannot act then closes terminally, which is `F-AG-02`'s loop signature: five or
#     more consecutive `complete_phase` calls with no successful `guardian_action` between them.
#     Ten and eleven consecutive terminal completions were observed, one per role per remaining
#     phase.
#
# So the two checks that measure *behaviour* were blocking on behaviour the guardrails correctly
# produce. D3's predicate and its threshold of 5 are untouched -- no terminal call is exempted and
# no finding is suppressed -- and every class-B result is still computed, tallied per status in
# `gate_decision.json`'s `counts`, and read per-bundle from the fidelity reports the gate folds.
# What changes is only whether a non-passing B can withhold GO. The pilot gate's bar is now
# treatment delivery: class-T at 100%, class-R not failing, zero framework-attributable failures,
# and a complete ladder.
#
# A `skip` blocking is only meaningful because the gate's INPUT is filtered: `read_checks`'s
# campaign-directory path drops checks that were not applicable to ANY bundle (a `skip` with no
# producer-pending cause -- F-SC-01 on an all-INJ-NONE corpus, F-MN-04 on any non-probe bundle,
# F-GD-01 where no external anchor ledger exists), because those were never this corpus's to
# measure. A check that remains in the input and skips is a check that SHOULD have run here and did
# not, and blocking on it is the whole point. See `runner.fidelity.campaign_gate_rows`.
_BLOCKING_STATUSES: Final[Mapping[str, frozenset[str]]] = {
    CLASS_T: frozenset(FIDELITY_STATUSES) - {STATUS_PASSING},
    CLASS_B: frozenset(),
    CLASS_R: frozenset({"fail"}),
}


def _offending(checks: Sequence[Mapping[str, Any]], klass: str) -> list[str]:
    """The ids of the ``klass`` checks whose status blocks the gate, in a stable order."""
    blocking = _BLOCKING_STATUSES[klass]
    return [
        str(check.get("id", "<unnamed>"))
        for check in sorted(checks, key=lambda item: str(item.get("id", "")))
        if check.get("klass") == klass and check.get("status") in blocking
    ]


def evaluate_gate(
    checks: Sequence[Mapping[str, Any]],
    *,
    ladder_state: LadderState | None = None,
    framework_failures: int = 0,
) -> GateDecision:
    """Turn a set of fidelity check rows into the ladder's gate decision (plan §5, §6; ADR-120).

    The rules, one per class, each restating what the plan states and nothing more:

    * **T** -- "class T checks block the pilot and halt the campaign", and §6 makes every stage's
      exit criterion "T 100%". So a T row must be ``pass``: ``warn`` and ``skip`` block too, because
      a check that did not run has not passed. The gate also refuses a check list containing no T
      row at all -- that is defect V16's shape, a gate that never saw the arms.
    * **B** -- "reported, not gating, at the gate too" (ADR-183; plan §5, revised). A B row is
      computed, tallied per status in the decision's ``counts`` and carried into
      ``gate_decision.json``, but it cannot withhold GO. D3's thresholds (the loop-signature
      length, the discrimination base-rate ceiling) are the fidelity package's to evaluate, because
      that is where the protocol mirror lives; this function consumes the verdict rather than
      restating a number it does not own. The reasoning is on :data:`_BLOCKING_STATUSES`: a
      correct guardrail refusal makes a phase unable to act, and the terminal completions that
      follow are the honest record of that.
    * **R** -- "class R checks block the pilot gate, the campaign checkpoint and the final corpus".
      At the gate a ``fail`` blocks. ``warn`` and ``skip`` are counted but do not block, because
      F-AN-01's readiness gate carries its own per-stage semantics (at the pilot, a ``nan`` from
      n < 2 is WARN) and duplicating a per-stage rule here would create a second place for it to
      differ.
    * **P3's exit criterion** -- "zero framework-attributable failures across P1-P3". The count is
      produced by ``classify_failure`` (the campaign half, Part B) and passed in; requiring it to be
      zero keeps the classification rule in one home.
    * **the ladder itself** must be complete, or the decision is about a ladder nobody climbed.
    """
    rows = list(checks)
    reasons: list[str] = []
    counts = _counts(rows)

    if not any(row.get("klass") == CLASS_T for row in rows):
        reasons.append(
            "no class-T check was reported; a gate that saw no treatment check cannot return GO "
            "(M10 plan §5, §6; defect V16)"
        )
    for klass in FIDELITY_CLASSES:
        offending = _offending(rows, klass)
        if offending:
            reasons.append(
                f"class {klass} checks not at 100%: {', '.join(offending)} "
                "(M10 plan §5, §6; ADR-120)"
            )
    if not ladder_complete(ladder_state):
        done = list(ladder_state.completed) if ladder_state is not None else []
        reasons.append(
            f"the ladder is not complete on one instrument: {', '.join(done) or 'nothing recorded'}"
            f" of {', '.join(LADDER_STAGES)} (M10 plan §6)"
        )
    if framework_failures:
        reasons.append(
            f"{framework_failures} framework-attributable failure(s) across P1-P3; P3's exit "
            "criterion is zero (M10 plan §6)"
        )
    return GateDecision(
        decision=GO if not reasons else NO_GO,
        reasons=tuple(reasons),
        counts=counts,
        instrument_digest=ladder_state.instrument_digest if ladder_state is not None else None,
        framework_failures=framework_failures,
    )


def read_checks(source: Path | Sequence[Path]) -> list[Mapping[str, Any]]:
    """The gate's ``checks`` rows, from one fidelity document, one campaign, or several.

    Three accepted inputs, because the pilot gate is reached three ways:

    * a ``fidelity.json`` FILE (SEAM 2), read as-is -- the shape ``runner/tests/test_pilot_cli.py``
      builds and the shape a hand-assembled aggregate takes;
    * a campaign DIRECTORY. If it carries an explicit ``fidelity.json`` that is read; otherwise the
      campaign is aggregated by ``runner.fidelity.campaign_gate_rows``, which evaluates every sealed
      bundle at the ladder's gate stages and folds them into one row per check (M10 plan section 6).
      This is the path ``FIDELITY=<pilot campaign dir> make pilot-gate`` takes: a pilot campaign
      directory holds one ``fidelity.json`` per bundle and never one at its root, so a gate pointed
      at the directory has to build the corpus-level verdict itself.
    * a SEQUENCE of any of the above, folded into one row per check with the worst status winning
      (``runner.fidelity.fold_gate_rows``). This is the pilot's actual shape: its evidence spans
      P1a, P1b, P2 and P3 as separate campaign ids, and P1a and P2 cannot share a directory at all
      (their run ids collide -- ``RUN-<arm>-SCN-SIM-01-INJ-NONE-901`` is both P1a's scripted cell
      and P2's live one), so the gate folds ROWS rather than merging bundles. The fold is a property
      of the fidelity package, not of this module, so the rank a row gets across campaigns is the
      rank it gets within one.

    A directory whose bundles carry no ``fidelity.json`` at all is refused, not read as an empty
    pass list: a gate that passed over nothing reads, in a log, exactly like a gate that passed over
    everything.
    """
    if isinstance(source, (str, Path)):
        return _read_checks_one(Path(source))
    from runner.fidelity import fold_gate_rows

    sources = [Path(item) for item in source]
    if not sources:
        raise LadderError(
            "the gate was given no fidelity source at all; name a fidelity.json or a campaign "
            "directory (SEAM 2)"
        )
    return fold_gate_rows([_read_checks_one(item) for item in sources])


def _read_checks_one(source: Path) -> list[Mapping[str, Any]]:
    """One source's rows: a fidelity document, or a directory folded by the fidelity package."""
    path = Path(source)
    if path.is_dir():
        explicit = path / "fidelity.json"
        if explicit.is_file():
            path = explicit
        else:
            return _campaign_checks(path)
    if not path.is_file():
        raise LadderError(
            f"no fidelity results at {path}; the gate reads a fidelity.json or a campaign "
            "directory of sealed bundles (SEAM 2)"
        )
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or "checks" not in payload:
        raise LadderError(f"{path} is not a fidelity.json document (no 'checks' key; SEAM 2)")
    return list(payload["checks"])


def _campaign_checks(campaign_dir: Path) -> list[Mapping[str, Any]]:
    """Fold every sealed bundle's verdicts in ``campaign_dir`` into one gate row per check.

    Imported inside the function rather than at module scope: ``runner.fidelity`` is the Part-B half
    of the runner, and a ladder stage must not pay its import cost nor fail to start because it is
    mid-edit -- the same reason :func:`_run_validate` imports ``runner.validate`` lazily.
    """
    from runner.fidelity import FidelityError, campaign_gate_rows

    try:
        rows = campaign_gate_rows(campaign_dir)
    except FidelityError as error:
        raise LadderError(str(error)) from error
    if not rows:
        raise LadderError(
            f"no fidelity results at {campaign_dir}: its bundles carry no fidelity verdict to "
            "fold, and a gate that passed over nothing would read, in a log, exactly like a gate "
            "that passed over everything (SEAM 2)"
        )
    return rows


def write_gate_decision(state_dir: Path, decision: GateDecision) -> Path:
    """Write ``gate_decision.json`` and return its path. Canonical JSON, for the same reason."""
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    path = state_dir / GATE_DECISION_FILE
    path.write_bytes(_canonical(decision.to_dict()))
    return path


def load_gate_decision(state_dir: Path) -> dict[str, Any] | None:
    """The recorded gate decision, or ``None`` when the gate has not been run."""
    path = Path(state_dir) / GATE_DECISION_FILE
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def gate_decision(
    state_dir: Path, fidelity: Path | Sequence[Path], *, framework_failures: int = 0
) -> GateDecision:
    """Read the fidelity rows, evaluate the gate against the recorded ladder, record the result.

    ``fidelity`` is one source or several (see :func:`read_checks`); the pilot's evidence spans
    several campaign ids, so the gate is normally handed the whole list.
    """
    decision = evaluate_gate(
        read_checks(fidelity),
        ladder_state=load_ladder_state(state_dir),
        framework_failures=framework_failures,
    )
    write_gate_decision(state_dir, decision)
    return decision


# ================================================================================================
# THE CLI -- one subcommand per stage, plus `decide` and the pre-M10 manifest validator
# ================================================================================================


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m runner.pilot_cli", description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for stage in LADDER_STAGES:
        stage_parser = subparsers.add_parser(stage, help=f"record ladder stage {stage}")
        stage_parser.add_argument("--state-dir", type=Path, required=True)
        stage_parser.add_argument("--freeze-tag", default=None)
        stage_parser.add_argument(
            "--no-freeze",
            action="store_true",
            help="skip the freeze check (offline proofs and tests only; never for a live stage)",
        )
    decide = subparsers.add_parser(
        "decide", help="write gate_decision.json from the fidelity results"
    )
    decide.add_argument("--state-dir", type=Path, required=True)
    decide.add_argument(
        "--fidelity",
        type=Path,
        action="append",
        required=True,
        help="a fidelity.json or a campaign directory; repeat to fold the pilot's campaigns",
    )
    decide.add_argument("--framework-failures", type=int, default=0)
    # The pre-M10 pilot manifest validator, kept as a subcommand rather than deleted: v1's six-run
    # G0/G1 plan is still something an operator can check a manifest against, and plan §6 adds three
    # validators beside it (`validate_cost_pilot_manifest`, `validate_smoke_pilot_manifest`,
    # `validate_coverage_pilot_manifest`) without retiring this one. `--kind` selects which
    # (``cost`` is the default), so P1a's smoke and P2/P3's coverage manifests validate by name.
    validate = subparsers.add_parser(
        "validate", help="validate a pilot campaign manifest and one bundle"
    )
    validate.add_argument("--manifest", type=Path, required=True)
    validate.add_argument("--bundle", type=Path)
    validate.add_argument(
        "--kind",
        choices=sorted(PILOT_VALIDATORS),
        default="cost",
        help="which pilot validator to apply (default: cost; ADR-136, plan §6)",
    )
    return parser


def _run_validate(args: argparse.Namespace) -> int:
    # Imported here rather than at module scope: `runner.validate`, `runner.bundle` and
    # `runner.validity` are the Part-B half of the runner, and a ladder stage must not pay their
    # import cost -- nor fail to start because one of them is mid-edit.
    from runner import validate as validate_module
    from runner.bundle import verify_bundle_seal
    from runner.campaign import from_dict
    from runner.manifest import from_dict as manifest_from_dict
    from runner.validate import ValidationError
    from runner.validity import check_run_validity, measurement_window_samples

    validator = getattr(validate_module, PILOT_VALIDATORS[args.kind])
    try:
        plan = from_dict(json.loads(args.manifest.read_text(encoding="utf-8")))
        counts = validator(plan)
        if args.bundle is not None:
            defects = verify_bundle_seal(args.bundle)
            manifest = manifest_from_dict(
                json.loads((args.bundle / "manifest.json").read_text(encoding="utf-8"))
            )
            defects.extend(
                f"{finding.code}: {finding.detail}"
                for finding in check_run_validity(
                    args.bundle, manifest, window_samples=measurement_window_samples()
                )
            )
            planned = {run.run_id for run in plan.runs}
            if manifest.run_id not in planned or manifest.campaign_id != plan.campaign_id:
                defects.append("bundle is not one of this pilot manifest's planned runs")
            if defects:
                raise ValidationError("run-invalid", "; ".join(defects))
    except (OSError, ValueError, TypeError, ValidationError) as error:
        print(f"pilot-validator: FAIL — {error}")
        return 1
    detail = f"; bundle {args.bundle.name} sealed, complete, and valid" if args.bundle else ""
    print(f"pilot-validator: PASS — {args.kind} plan {counts}{detail}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "validate":
        return _run_validate(args)
    if args.command == "decide":
        try:
            decision = gate_decision(
                args.state_dir, args.fidelity, framework_failures=args.framework_failures
            )
        except (OSError, ValueError, LadderError) as error:
            print(f"pilot-gate: FAIL — {error}")
            return 1
        if decision.decision == GO:
            print(f"pilot-gate: GO — written to {args.state_dir / GATE_DECISION_FILE}")
            return 0
        print(f"pilot-gate: {NO_GO} — {len(decision.reasons)} reason(s):")
        for reason in decision.reasons:
            print(f"  - {reason}")
        return 1
    try:
        state = record_stage(
            args.state_dir,
            args.command,
            freeze_tag=args.freeze_tag,
            enforce=not args.no_freeze,
        )
        coverage = (
            f", {len(coverage_order(args.command))} planned runs"
            if args.command in COVERAGE_PASSES
            else ""
        )
    except (LadderError, FreezeError) as error:
        print(f"pilot-{args.command}: FAIL — {error}")
        return 1
    print(
        f"pilot-{args.command}: recorded on instrument {state.instrument_digest[:12]} — "
        f"{len(state.completed)}/{len(LADDER_STAGES)} stages complete{coverage}; "
        f"next {next_stage(state)}"
    )
    if STAGE_RUNS[args.command]:
        print(
            f"pilot-{args.command}: exit criterion: {STAGE_RUNS[args.command]} run(s) with every "
            "class-T check at 100%"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
