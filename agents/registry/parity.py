r"""The parity gate: five assertions over the composed registry, and a refusal to pass vacuously.

WHAT THIS MODULE IS
-------------------
``docs/protocols/prompt-parity-policy.md`` section 3 specifies ``make parity-check``, and this
module is it. ``scripts/parity_check.sh`` is the one-line gate script
``docs/04-repo-conventions.md`` section 1 requires, and it delegates here.

Section 1 of that policy says why any of this exists: "The ablation claims are only valid if
conditions differ **solely** in the manipulated variable... this protocol makes that a
machine-checked invariant instead of an intention." Every assertion below is one sentence of
section 2 or 3 turned into a comparison.

THE FIVE ASSERTIONS, AND THE SENTENCE EACH ONE IS
-------------------------------------------------
**1. Shared-block identity.** Section 2 rule 2: role instructions, tool documentation, safety
framing and output-format blocks "are defined once and referenced by every condition's composition
manifest". So a block whose ``parity_class`` is ``shared`` and which *any* condition references must
be referenced by *every* condition, and its bytes must be one set of bytes. The digest comparison is
belt and braces today -- one block id resolves to one file -- and it is the assertion that survives
a future arrangement in which it does not.

This is the assertion that makes ``S3-SINGLE``'s composition honest. Section 2 rule 5 fixes its
parity target as the Supervision layer, "those blocks concatenated, not a fresh authoring", and the
only way to check "concatenated, not re-authored" is to require that the very same block ids appear.
A re-authored variant would be a new block id, and a new shared block id that only one condition
references fails here.

**2. Budget tolerance.** Section 3: total instruction tokens per condition within **±2%** of the
cross-condition mean. The tolerance and the tokenizer are both owned elsewhere and read from there
-- :mod:`agents.registry.limits` mirrors the caps block, and
:data:`agents.registry.tokenizer.REFERENCE_TOKENIZER_ID` names the counting rule. Section 3 is
explicit that the tolerance is never loosened to make a change pass; if a legitimate structural
need exceeds it, that is a design decision needing an ADR and a supervisor note, which is a
different action from editing a number here.

**3. Tool identity.** Section 2 rule 3: the tool registry is identical across conditions and its
hash goes into every bundle manifest. :func:`~agents.registry.digest.tool_registry_digest` explains
why this is a hash over *definitions* rather than a hash over ``agents/tools/``: a directory hash
would be identical across conditions by construction rather than by check, and an assertion that
cannot fail is not an assertion.

**4. The tool-call and turn budgets.** Conflict M4-C4, and traceability row T-37. Section 3 requires
parity over prompt tokens, **tool calls and turns**; tokens are countable from rendered prompts, and
the other two are run-time quantities that no file in the kit declared anywhere -- so as written the
assertion had no artefact to assert over, and ``make parity-check`` could have reported green having
checked one budget of three.

They are declared now, per phase and per role, in each composition manifest, and read twice: here,
and by the graph runtime that enforces them. Section 3.5.4 grants the flat arm "the same budget ...
as the hierarchical configuration's combined per-phase allocation", so the comparison is **per
phase,
summed over roles, across conditions** -- which is exactly what "the combined per-phase allocation"
says, and which does not need the checker to know any role's name. The tolerance is zero, for the
reason :mod:`agents.registry.limits` gives: these are integers somebody wrote down, not measurements
with error to absorb.

**5. Realizable-action parity.** Section 3's M10 bullet, and the reason it exists: equal budgets are
"necessary but not sufficient" for an arm being able to act. See
:func:`_check_realizable_act_paths` and :func:`_check_realizable_actions`.

THE GATE FAILS CLOSED, AND THAT IS THE ASYMMETRY WITH THE GREP GUARDS
----------------------------------------------------------------------
``scripts/grep_guard.sh`` and ``scripts/monitor_guard.sh`` may pass vacuously and say so, because
each is a **prohibition**: nothing found means nothing violated. Parity is an **equality**, so
nothing found means nothing proved -- and a green check over an absent registry would make deleting
the registry the easiest way to pass the gate.

So this module exits non-zero, with a named reason, when any of these holds:

- a condition in :data:`agents.registry.STRUCTURE_CONDITIONS` has no composition manifest;
- the structural-block cap in ``prompt-parity-policy.md`` section 3 is still the pending sentinel;
- the registry holds no block, or a manifest declares no budget for a phase (both refused by
  :mod:`agents.registry.loader` before this module runs).

There is deliberately no ``--allow-empty``, no ``--skip``, and no environment variable that turns an
assertion off. ``.agents/rules/20-parity-and-determinism.md`` states the rule this implements: "If
token budgets across conditions diverge beyond the policy tolerance, the change is wrong -- fix the
change, do not adjust the tolerance."

THE OUTPUT IS THE ARTEFACT
---------------------------
Section 3 requires a "per-condition token table (written into the M4/GATE record)" and section 4
requires every pull request touching ``agents/prompts/`` or ``agents/tools/`` to carry it. The table
names the tokenizer that produced it and the registry digest it was computed over, because a token
count with neither is a number nobody can reproduce -- and reproducing it from a clean checkout with
no credential is traceability row T-45's whole claim.
"""

import argparse
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from agents.registry import PHASES, STRUCTURE_CONDITIONS
from agents.registry.composer import ComposedCondition, compose_condition
from agents.registry.digest import directory_digest, tool_registry_digest
from agents.registry.limits import (
    PROTOCOL_ANCHOR,
    PROTOCOL_RELATIVE_PATH,
    UncalibratedCap,
    pending_keys,
    render_protocol_block,
    resolve,
)
from agents.registry.loader import (
    Composition,
    PromptBlock,
    PromptRegistry,
    RegistryError,
    RoleComposition,
    load_registry,
)
from agents.registry.tokenizer import REFERENCE_TOKENIZER_ID, count_tokens

__all__ = (
    "ParityReport",
    "check_parity",
    "main",
    "render_table",
)

# The column widths of the emitted table. Fixed rather than computed from the data, so that two
# runs over two registries produce tables that line up when a reviewer diffs them -- a table whose
# columns move with the longest value is a table whose every row changes when one value grows.
_CONDITION_WIDTH: Final = 12
_NUMBER_WIDTH: Final = 10


@dataclass
class ParityReport:
    """What one parity run found: the numbers, and every assertion that did not hold.

    ``failures`` is a list of sentences rather than a boolean, because a gate that says only "no"
    sends the reader back to re-derive what the checker already knew. Each entry names the
    assertion, the conditions involved and the two numbers, so a CI log is enough to act on.

    ``blocking`` is separate from ``failures`` and is the fail-closed half: it holds the reasons the
    check could not be *performed* -- a missing manifest, a pending cap -- as distinct from
    assertions that were performed and did not hold. Both exit non-zero. Keeping them apart is what
    lets the summary line distinguish "parity is violated" from "parity was not established", which
    are different findings with different remedies.
    """

    conditions: Mapping[str, ComposedCondition] = field(default_factory=dict)
    registry_digest: str = ""
    tool_digests: Mapping[str, str] = field(default_factory=dict)
    phase_turns: Mapping[str, Mapping[str, int]] = field(default_factory=dict)
    phase_tool_calls: Mapping[str, Mapping[str, int]] = field(default_factory=dict)
    realizable_pairs: Mapping[str, Mapping[str, int]] = field(default_factory=dict)
    structural_tokens: Mapping[str, int] = field(default_factory=dict)
    failures: list[str] = field(default_factory=list)
    blocking: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """``True`` only when every assertion held and every one of them could be made."""
        return not self.failures and not self.blocking


def _mean(values: Sequence[int]) -> float:
    """Return the arithmetic mean. A separate function so the divisor is written exactly once."""
    return sum(values) / len(values)


def _check_shared_blocks(report: ParityReport) -> None:
    """Assertion 1: every shared block is referenced by every condition, with identical bytes."""
    referenced: dict[str, dict[str, str]] = {}
    for condition, composed in report.conditions.items():
        for role in composed.roles.values():
            for block in role.shared_blocks():
                referenced.setdefault(block.block_id, {})[condition] = block.digest

    for block_id in sorted(referenced):
        seen = referenced[block_id]
        missing = sorted(set(report.conditions) - set(seen))
        if missing:
            report.failures.append(
                f"shared-block identity: {block_id!r} is referenced by "
                f"{', '.join(sorted(seen))} but not by {', '.join(missing)}. Parity policy "
                "section 2 rule 2 defines a shared block once and references it from every "
                "condition's manifest; a shared block only one condition carries is a guidance "
                "difference between arms, which is the confound the whole ablation is designed to "
                "exclude"
            )
            continue
        digests = set(seen.values())
        if len(digests) != 1:
            report.failures.append(
                f"shared-block identity: {block_id!r} resolves to {len(digests)} different byte "
                f"sequences across conditions ({sorted(digests)})"
            )


def _check_token_budget(report: ParityReport, tolerance_pct: float) -> None:
    """Assertion 2: each condition's instruction tokens within the tolerance of the mean."""
    totals = {condition: composed.total_tokens for condition, composed in report.conditions.items()}
    mean = _mean(list(totals.values()))
    if mean == 0:
        report.blocking.append(
            "token budget: every condition composed to zero tokens, so the cross-condition mean is "
            "zero and the tolerance is undefined. An equality over nothing is not an equality"
        )
        return
    for condition in sorted(totals):
        deviation = abs(totals[condition] - mean) / mean * 100
        if deviation > tolerance_pct:
            report.failures.append(
                f"token budget: {condition} composes {totals[condition]} instruction tokens, "
                f"{deviation:.2f}% from the cross-condition mean of {mean:.1f}, above the "
                f"{tolerance_pct}% tolerance {PROTOCOL_RELATIVE_PATH} section 3 owns. The "
                "tolerance is never loosened to make a change pass (rule 20); fix the "
                "composition, and if a legitimate structural need really exceeds it that is an ADR "
                "and a supervisor note"
            )


def _check_tool_identity(report: ParityReport) -> None:
    """Assertion 3: the tool-registry digest is identical across conditions."""
    digests = set(report.tool_digests.values())
    if len(digests) > 1:
        rows = ", ".join(
            f"{condition}={report.tool_digests[condition][:12]}"
            for condition in sorted(report.tool_digests)
        )
        report.failures.append(
            "tool identity: the tool-registry digest differs across conditions "
            f"({rows}). Parity policy section 2 rule 3 makes the definitions -- names, schemas, "
            "descriptions -- identical across conditions, and forbids a condition-only tool "
            "outright; what may differ is which node holds which entry"
        )


def _check_declared_budgets(report: ParityReport, turn_tol: float, call_tol: float) -> None:
    """Assertion 4: per phase, the summed turn and tool-call allocations agree across conditions."""
    for label, per_phase, tolerance in (
        ("turn", report.phase_turns, turn_tol),
        ("tool-call", report.phase_tool_calls, call_tol),
    ):
        for phase in PHASES:
            totals = per_phase[phase]
            mean = _mean(list(totals.values()))
            for condition in sorted(totals):
                if mean == 0:
                    deviation = 0.0 if totals[condition] == 0 else float("inf")
                else:
                    deviation = abs(totals[condition] - mean) / mean * 100
                if deviation > tolerance:
                    report.failures.append(
                        f"{label} budget: in phase {phase!r}, {condition} declares "
                        f"{totals[condition]} against a cross-condition mean of {mean:.1f} "
                        f"(tolerance {tolerance}%). Section 3.5.4 grants the flat arm the same "
                        "per-phase budget as the hierarchical configuration's combined per-phase "
                        "allocation, so these are summed over roles and compared phase by phase"
                    )


def _check_budget_coverage(report: ParityReport, registry: PromptRegistry) -> None:
    """Every role has a declared allocation in every phase it can run in. Fail-closed, not a sum.

    WHY THE SUM IS NOT ENOUGH, WHICH IS WHAT THIS ASSERTION EXISTS FOR
    -------------------------------------------------------------------
    :func:`_check_declared_budgets` compares the per-phase **sums** across conditions, because
    section 3.5.4's grant to the flat arm is a statement about a combined per-phase allocation. A
    sum has a blind spot, and it is a real one: delete one role's stanza from a phase and fold the
    same numbers into another role's stanza in that phase, and the sum is unchanged, every
    tolerance holds, and the gate goes green over a manifest in which a role that runs has no
    declared allocation at all.

    That is not a hypothetical. ``agents/graphs/plan.py`` already refuses to build such a plan --
    "role X runs in phase Y but the manifest declares no budget for it there" -- so the property
    does hold across the two readers ADR-028 gives the budgets. But the gate is the thing a
    reviewer reads before merging, and a gate that reports green on a registry the runtime will
    refuse to start is a gate that has to be re-derived by hand. Parity is an equality and this
    check is the fail-closed half of it: a missing declaration means the comparison above was made
    over a number nothing enforced.

    WHY IT IS COMPUTED FROM THE MANIFEST AND NOT FROM A PLAN
    ---------------------------------------------------------
    Which roles run in which phase is a topology's answer and lives in ``agents/graphs/``, which the
    parity path must not import -- this module runs in a CI job that installs nothing, and the
    graphs package imports the runtime. The manifest answers the same question in a weaker but
    sufficient form: a role entry declaring ``phase: <p>`` is scoped to that phase and needs an
    allocation there; a role entry declaring ``phase: null`` spans the phases and needs one in each.
    A topology that ran fewer roles than its manifest declares would be over-declared rather than
    under-declared, which is a manifest defect this reports and never a run that acted unbudgeted.
    """
    for condition in STRUCTURE_CONDITIONS:
        composition = registry.compositions[condition]
        for role in composition.roles:
            wanted = PHASES if role.phase is None else (role.phase,)
            for phase in wanted:
                if role.role_id in composition.budgets.get(phase, {}):
                    continue
                report.blocking.append(
                    f"budget coverage: {condition} declares role {role.role_id!r} for phase "
                    f"{phase!r} but no allocation for it there. Section 3's third and fourth "
                    "budgets are compared as per-phase sums, so an absent stanza is invisible to "
                    "that comparison -- the sum is whatever the remaining roles declare, and a "
                    "role that acts without an allocation is a role the runtime cannot bound and "
                    "the gate cannot compare"
                )


# The two tools a mint-and-act pair is made of, named as strings rather than imported from
# ``agents/tools/registry.py``. The reason is the same one the tool digest gives: this module runs
# in
# a CI job that installs nothing, and importing the tool registry at module scope would put whatever
# that package imports on the parity gate's import path. The names are checked against the registry
# by the assertions below -- a composition naming a different tool is a manifest a reader is looking
# at -- and ``agents/registry/parity.py``'s existing import of ``definitions_for`` stays inside
# :func:`check_parity` for the same reason.
_MINT_TOOL: Final = "issue_capability_token"
_ACTION_TOOL: Final = "guardian_action"

# What one mint-and-act pair costs, in each of the two budgets. Two tool calls is the arithmetic --
# the mediated path spends ``issue_capability_token`` and then ``guardian_action``, and a capability
# is single-use (ADR-075), so a pair is exactly two submissions. Two turns is ADR-028's "a retry is
# a turn": the mint costs one model call and the act costs another, and a retry on either would be a
# third the budget has to carry.
_PAIR_TOOL_CALLS: Final = 2
_PAIR_TURNS: Final = 2


def _roles_running_in(composition: Composition, phase: str) -> tuple[RoleComposition, ...]:
    """Return the roles a condition declares for ``phase``.

    A role entry scoped to a phase runs in that phase; one declaring ``phase: null`` spans them all,
    which is every role in ``S2-FLAT`` and ``S3-SINGLE`` and the Orchestrator in ``S1-HIER``. The
    manifest is the only source, for the reason :func:`_check_budget_coverage` gives: which roles
    run
    in which phase is a topology's answer and lives in ``agents/graphs/``, which the parity path
    must
    not import.
    """
    return tuple(role for role in composition.roles if role.phase in (None, phase))


def _check_realizable_act_paths(report: ParityReport, registry: PromptRegistry) -> None:
    """Assertion 5, first claim: every acting role can obtain the capability it spends.

    An actor is a role that holds ``guardian_action``. It is reachable if it holds
    ``issue_capability_token`` itself -- the self-mint ``S2-FLAT`` and ``S3-SINGLE`` run -- or if
    some
    role declared in the same phase holds it, which is ``S1-HIER``'s Supervisor and the case
    :func:`~agents.graphs.nodes._delegate_phase` shares one ledger for.

    The reading is the runtime's, not a convention invented here: ``_conduct`` computes
    ``hands_off = ACTION_TOOL not in permitted``, and the self-mint path it takes when that is false
    is exactly "this role both mints and acts". So a manifest that leaves an actor with neither
    capability is describing a run that could not have acted, whatever its budgets say -- which is
    the v1 S2/S3 shape at the level this gate can see it, and why the assertion is here at all.

    The manifests are read from ``registry`` rather than from a composed condition because
    :class:`~agents.registry.composer.ComposedCondition` carries the composed *text* and not the
    wiring, and which role holds which tool is wiring.
    """
    for condition in STRUCTURE_CONDITIONS:
        composition = registry.compositions[condition]
        for phase in PHASES:
            roles = _roles_running_in(composition, phase)
            actors = [role for role in roles if _ACTION_TOOL in role.tools]
            if not actors:
                # No role acts on the cluster in this phase. Not a failure: a phase in which nothing
                # is submitted is a legitimate outcome shape, and the budgets are still compared.
                # The
                # control below makes sure the check is not vacuous over a registry where nothing
                # acts anywhere.
                continue
            issuers = [role.role_id for role in roles if _MINT_TOOL in role.tools]
            unreachable = [
                role.role_id for role in actors if _MINT_TOOL not in role.tools and not issuers
            ]
            if unreachable:
                report.failures.append(
                    f"realizable action: in phase {phase!r}, {condition} declares "
                    f"{unreachable} holding {_ACTION_TOOL!r} and no role in the phase holds "
                    f"{_MINT_TOOL!r}. A capability is single-use and a mediated action needs one,"
                    " so "
                    "an acting role with no reachable issuer can hold the action tool and never"
                    " spend "
                    "it -- the shape v1's S2-FLAT and S3-SINGLE ran in (1 of 131 and 11 of 131"
                    " runs "
                    "reached the Guardian) and the one equal budgets cannot detect"
                )


def _check_realizable_actions(report: ParityReport, tolerance_pct: float) -> None:
    """Assertion 5, second claim: equal pairs per phase, and turns that can pay for them.

    Two numbers, and they are not the same number, which is the whole reason this is a separate
    assertion rather than a restatement of the fourth:

    * ``realizable_pairs = min(turns // 2, calls // 2)`` -- what the phase can actually *perform*,
      because a pair needs both halves of both budgets. Held equal across conditions within
      ``condition_tool_call_tolerance_pct``. As long as both assertions read the same per-phase sums
      this equality follows from assertion 4, and this function says so rather than claiming more
      than it has: it is published (:attr:`ParityReport.realizable_pairs`) because it is the number
      a
      reviewer reads to judge a rebalanced budget, and re-derived independently in
      ``agents/tests/test_parity.py`` so a gate computing it some other way is caught.
    * **turn sufficiency**, ``turns >= 2 * (calls // 2)`` -- which is *not* implied by anything
    above
      and is the claim section 3's own words name: "``max_turns`` did not cover a mint-then-act pair
      in one iteration". A phase can declare eight tool calls and seven turns, hold every tool the
      other arms hold, pass every budget equality, and still be unable to turn its own tool-call
      budget into actions -- the calls are there and the turns to make them are not. That is the v1
      S2/S3 outcome with the budgets looking correct, and it is the one thing equal sums cannot see.
    """
    for condition in STRUCTURE_CONDITIONS:
        report.realizable_pairs[condition] = {}
    for phase in PHASES:
        for condition in STRUCTURE_CONDITIONS:
            turns = report.phase_turns[phase][condition]
            calls = report.phase_tool_calls[phase][condition]
            report.realizable_pairs[condition][phase] = min(
                turns // _PAIR_TURNS, calls // _PAIR_TOOL_CALLS
            )
        counts = {
            condition: report.realizable_pairs[condition][phase]
            for condition in STRUCTURE_CONDITIONS
        }
        mean = _mean(list(counts.values()))
        for condition in sorted(counts):
            deviation = (
                0.0
                if mean == 0 and counts[condition] == 0
                else (float("inf") if mean == 0 else abs(counts[condition] - mean) / mean * 100)
            )
            if deviation > tolerance_pct:
                report.failures.append(
                    f"realizable action: in phase {phase!r}, {condition} can realize "
                    f"{counts[condition]} mint-and-act pair(s) against a cross-condition mean of "
                    f"{mean:.1f} (tolerance {tolerance_pct}%). A pair costs "
                    f"{_PAIR_TOOL_CALLS} tool call(s) and {_PAIR_TURNS} turn(s) -- a retry is a"
                    " turn "
                    "(ADR-028) -- and an arm that can perform fewer pairs than another has less "
                    "capacity to act on the same incident, which is the confound section 3.5.4's "
                    "combined per-phase grant is meant to exclude"
                )
    for phase in PHASES:
        for condition in sorted(STRUCTURE_CONDITIONS):
            turns = report.phase_turns[phase][condition]
            needed = (report.phase_tool_calls[phase][condition] // _PAIR_TOOL_CALLS) * _PAIR_TURNS
            if turns < needed:
                report.failures.append(
                    f"realizable action: in phase {phase!r}, {condition} declares {turns} turn(s) "
                    f"against {report.phase_tool_calls[phase][condition]} tool call(s), which is "
                    f"{report.phase_tool_calls[phase][condition] // _PAIR_TOOL_CALLS} mint-and-act "
                    f"pair(s) and therefore needs {needed} turn(s). A mint costs one model call"
                    " and "
                    "the act costs another, so a phase whose turns cannot pay for the pairs its"
                    " tool "
                    "calls would buy ends budget-exhausted holding unspent capability -- the v1"
                    "S2/S3 "
                    "outcome, with every budget equality still holding"
                )


def _check_structural_cap(report: ParityReport, cap: float) -> None:
    """The section 3 cap: each structural block is at most ``cap`` reference tokens."""
    for block_id in sorted(report.structural_tokens):
        size = report.structural_tokens[block_id]
        if size > cap:
            report.failures.append(
                f"structural cap: block {block_id!r} is {size} tokens, above the cap of {int(cap)} "
                f"frozen in {PROTOCOL_RELATIVE_PATH} section 3 (anchor {PROTOCOL_ANCHOR}). A "
                "structural block carries only the topology-necessitated connective text; one that "
                "has grown past the cap is carrying guidance, which is the thing parity exists to "
                "hold equal"
            )


def check_parity(registry: PromptRegistry | None = None) -> ParityReport:
    """Run every assertion and return what was found. Never raises for a parity failure.

    A :class:`~agents.registry.loader.RegistryError` -- a malformed manifest, a dangling block
    reference -- still propagates, because that is a registry that cannot be composed rather than a
    parity verdict, and reporting it as a failed assertion would suggest the numbers below had been
    computed.
    """
    loaded = load_registry() if registry is None else registry
    report = ParityReport()

    missing = [
        condition for condition in STRUCTURE_CONDITIONS if condition not in loaded.compositions
    ]
    if missing:
        report.blocking.append(
            f"no composition manifest for {', '.join(missing)}. Parity asserts an equality across "
            f"{len(STRUCTURE_CONDITIONS)} conditions, so a missing one means nothing was proved -- "
            "and a checker that skipped it would make deleting a manifest the easiest way to pass"
        )
        return report

    report.conditions = {
        condition: compose_condition(loaded, condition) for condition in STRUCTURE_CONDITIONS
    }
    report.registry_digest = directory_digest(loaded.root)

    # Imported here rather than at module scope: agents/tools/ is the tool registry and importing
    # it at the top would make this module -- which scripts/parity_check.sh runs in a job that
    # installs nothing -- depend on whatever that package imports. The registry itself is standard
    # library, and this keeps that a property nobody has to remember.
    from agents.tools.registry import definitions_for

    report.tool_digests = {
        condition: tool_registry_digest(definitions_for(composed.tool_names))
        for condition, composed in report.conditions.items()
    }

    turns: dict[str, dict[str, int]] = {}
    calls: dict[str, dict[str, int]] = {}
    for phase in PHASES:
        turns[phase] = {}
        calls[phase] = {}
        for condition in STRUCTURE_CONDITIONS:
            allocations = loaded.compositions[condition].budgets[phase]
            turns[phase][condition] = sum(budget.max_turns for budget in allocations.values())
            calls[phase][condition] = sum(budget.max_tool_calls for budget in allocations.values())
    report.phase_turns = turns
    report.phase_tool_calls = calls

    report.structural_tokens = _structural_token_counts(
        block
        for composed in report.conditions.values()
        for role in composed.roles.values()
        for block in role.structural_blocks()
    )

    _check_shared_blocks(report)
    _check_tool_identity(report)

    try:
        tolerance = float(resolve("condition_token_tolerance_pct"))
        turn_tolerance = float(resolve("condition_turn_tolerance_pct"))
        call_tolerance = float(resolve("condition_tool_call_tolerance_pct"))
    except UncalibratedCap as uncalibrated:  # pragma: no cover - the tolerances are never pending
        report.blocking.append(str(uncalibrated))
        return report
    _check_token_budget(report, tolerance)
    _check_budget_coverage(report, loaded)
    _check_declared_budgets(report, turn_tolerance, call_tolerance)
    _check_realizable_act_paths(report, loaded)
    _check_realizable_actions(report, call_tolerance)

    try:
        _check_structural_cap(report, float(resolve("structural_block_tokens_max")))
    except UncalibratedCap as uncalibrated:
        report.blocking.append(str(uncalibrated))

    return report


def _structural_token_counts(blocks: Iterable[PromptBlock]) -> dict[str, int]:
    """Return each structural block's own token count, keyed by block id.

    Counted per block rather than derived by subtraction from a role's total, because the cap is a
    statement about one block and a subtraction would attribute a role's whole overage to whichever
    structural block happened to be present. A block held by two roles is counted once: the id is
    the key, and the same id resolves to the same bytes by construction.
    """
    return {block.block_id: count_tokens(block.body) for block in blocks}


def render_table(report: ParityReport) -> str:
    """Return the per-condition token table section 3 requires a pull request to carry."""
    if not report.conditions:
        return "parity: no condition was composed, so there is no table to emit.\n"

    lines = [
        f"tokenizer      : {REFERENCE_TOKENIZER_ID} (pinned; offline; see ADR-028)",
        f"registry sha256: {report.registry_digest}",
        "",
        f"{'condition':<{_CONDITION_WIDTH}} {'tokens':>{_NUMBER_WIDTH}} "
        f"{'turns':>{_NUMBER_WIDTH}} {'toolcalls':>{_NUMBER_WIDTH}}  tool-registry sha256",
    ]
    for condition in STRUCTURE_CONDITIONS:
        composed = report.conditions[condition]
        total_turns = sum(report.phase_turns[phase][condition] for phase in PHASES)
        total_calls = sum(report.phase_tool_calls[phase][condition] for phase in PHASES)
        lines.append(
            f"{condition:<{_CONDITION_WIDTH}} {composed.total_tokens:>{_NUMBER_WIDTH}} "
            f"{total_turns:>{_NUMBER_WIDTH}} {total_calls:>{_NUMBER_WIDTH}}  "
            f"{report.tool_digests[condition]}"
        )

    totals = [composed.total_tokens for composed in report.conditions.values()]
    mean = _mean(totals)
    lines.append("")
    lines.append(f"cross-condition mean: {mean:.1f} tokens")
    for condition in STRUCTURE_CONDITIONS:
        deviation = (report.conditions[condition].total_tokens - mean) / mean * 100 if mean else 0.0
        lines.append(f"  {condition:<{_CONDITION_WIDTH}} {deviation:+.2f}%")

    if report.structural_tokens:
        lines.append("")
        lines.append("structural blocks (parity_class: structural), tokens each:")
        for block_id in sorted(report.structural_tokens):
            lines.append(f"  {block_id:<44} {report.structural_tokens[block_id]:>5}")

    lines.append("")
    lines.append("per-phase declared budgets, summed over roles:")
    lines.append(
        f"  {'phase':<28} " + " ".join(f"{condition:>12}" for condition in STRUCTURE_CONDITIONS)
    )
    for label, per_phase in (
        ("turns", report.phase_turns),
        ("tool calls", report.phase_tool_calls),
    ):
        lines.append(f"  -- {label} --")
        for phase in PHASES:
            row = " ".join(
                f"{per_phase[phase][condition]:>12}" for condition in STRUCTURE_CONDITIONS
            )
            lines.append(f"  {phase:<28} {row}")

    if report.realizable_pairs:
        lines.append("")
        lines.append(
            "realizable mint-and-act pairs per phase (min(turns, tool calls) / 2; a retry is a"
            " turn):"
        )
        lines.append(
            f"  {'phase':<28} " + " ".join(f"{condition:>12}" for condition in STRUCTURE_CONDITIONS)
        )
        for phase in PHASES:
            row = " ".join(
                f"{report.realizable_pairs[condition][phase]:>12}"
                for condition in STRUCTURE_CONDITIONS
            )
            lines.append(f"  {phase:<28} {row}")

    return "\n".join(lines) + "\n"


def _emit_caps(report: ParityReport) -> str:
    """Return the section 3 caps block with the structural cap derived from this registry.

    The calibration helper section 3 promises: "set at M4 from the first honest compositions;
    recorded here, then frozen". It prints the block rather than editing the protocol, because the
    protocol is the authority and a script that wrote into it would make the mirror the source.

    The derived value is the largest structural block, with no headroom added. Headroom would be a
    second decision -- how much slack a topology block is allowed to grow into -- taken by a script,
    silently, at the moment nobody is looking.
    """
    if not report.structural_tokens:
        return "parity: no structural block exists, so no cap can be derived from this registry.\n"
    largest = max(report.structural_tokens.values())
    mapping = {
        "structural_block_tokens_max": largest,
        "condition_token_tolerance_pct": resolve("condition_token_tolerance_pct"),
        "condition_tool_call_tolerance_pct": resolve("condition_tool_call_tolerance_pct"),
        "condition_turn_tolerance_pct": resolve("condition_turn_tolerance_pct"),
    }
    return render_protocol_block(mapping)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the check, print the table, and return the exit code ``make parity-check`` reports."""
    parser = argparse.ArgumentParser(
        prog="python -m agents.registry.parity",
        description=(
            "Prompt and tool parity across the structure conditions, per "
            f"{PROTOCOL_RELATIVE_PATH} section 3. Exits non-zero on any failed assertion and on "
            "any reason the check could not be made at all."
        ),
    )
    parser.add_argument(
        "--registry-root",
        type=Path,
        default=None,
        help="the prompt registry to check (default: agents/prompts/, resolved from this file)",
    )
    parser.add_argument(
        "--emit-caps",
        action="store_true",
        help=(
            "print the section 3 caps block with the structural cap derived from this registry, "
            "for the calibration commit; makes no assertion and changes no file"
        ),
    )
    arguments = parser.parse_args(argv)

    try:
        registry = load_registry(arguments.registry_root)
    except RegistryError as broken:
        print(f"parity: FAIL -- the registry cannot be read: {broken}", file=sys.stderr)
        return 1

    report = check_parity(registry)

    if arguments.emit_caps:
        print(_emit_caps(report), end="")
        return 0

    print(render_table(report), end="")

    if report.blocking:
        print("", file=sys.stderr)
        print(
            f"parity: FAIL -- parity was not established ({len(report.blocking)} reason(s)):",
            file=sys.stderr,
        )
        for reason in report.blocking:
            print(f"  * {reason}", file=sys.stderr)
        print(
            "\nThis is a different finding from a violated assertion. Parity asserts an equality, "
            "so nothing found means nothing proved -- unlike scripts/grep_guard.sh, which may pass "
            "vacuously because nothing found means nothing violated.",
            file=sys.stderr,
        )
    if report.failures:
        print("", file=sys.stderr)
        print(f"parity: FAIL -- {len(report.failures)} assertion(s) did not hold:", file=sys.stderr)
        for failure in report.failures:
            print(f"  * {failure}", file=sys.stderr)

    if not report.passed:
        pending = pending_keys()
        if pending:
            print(
                f"\nStill uncalibrated in {PROTOCOL_RELATIVE_PATH} section 3: "
                f"{', '.join(pending)}. `python -m agents.registry.parity --emit-caps` prints "
                "the block to paste.",
                file=sys.stderr,
            )
        return 1

    # Five assertions, which is section 3's own count once M10's realizable-action bullet is
    # counted,
    # plus the coverage precondition the fourth rests on. Coverage is named separately rather than
    # counted as a sixth because it is not a comparison across conditions: it is what makes the
    # fourth comparison a statement about numbers the runtime will enforce, and a reader counting
    # assertions against section 3 should find five.
    print(
        f"parity: PASS -- {len(report.conditions)} condition(s), 5 assertion(s): shared-block "
        "identity, token budget, tool identity, the tool-call and turn budgets (every role covered "
        "in every phase it runs in), and realizable mint-and-act pairs (a reachable issuer per "
        "acting role, equal counts, and turns sufficient to pay for them)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
