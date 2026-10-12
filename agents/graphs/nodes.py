r"""The node registry: four role behaviours, indexed by behaviour and never by condition.

WHAT THIS MODULE IS
-------------------
``docs/adr/ADR-002-agent-framework-langgraph.md`` fixes the shape -- one node registry, one tool
registry, one prompt registry, with ``agents/graphs/{hier,flat,single}.py`` as thin compositions --
and ADR-027 answers the question that shape leaves open: what "same registry" can mean when
``S2-FLAT`` deletes two role tiers and ``S3-SINGLE`` deletes three.

The answer this module implements is that **the registry is indexed by behaviour**. There are four
behaviours -- global-view coordination, phase planning, bounded execution, and consolidation --
and a graph selects which of them exist and how they are wired. ``S1-HIER`` instantiates
coordination once, phase planning four times and bounded execution per task; ``S2-FLAT``
instantiates one coordination node carrying all four phases' planning blocks and binding the tool
registry directly; ``S3-SINGLE`` instantiates one node carrying the Supervision layer's blocks
concatenated. Three wirings of one behaviour set, which is what makes parity provable by
construction rather than by inspection.

**No function in this module takes a condition parameter, and none ever will.** ADR-027 rejects it
outright: a ``if condition == "S2-FLAT"`` inside a node is the confound the ablation exists to
exclude, and it would be invisible to ``make parity-check``, which compares registries rather than
control flow. What a node knows is its composed prompt, its tools, its budget and its collaborators,
and every one of those arrives from the composition manifest.

WHAT MAKES AN EXECUTOR EPHEMERAL, PRECISELY
---------------------------------------------
FR3.1 has two properties and the M4 plan gives each its own mechanism, because either alone is
weak.

*Lifetime.* A fresh :class:`_NodeTask` is built per task and nothing retains it once the task is
over. ``S1-HIER``'s phase-planning node builds one per delegated task inside its own loop
(:func:`_run_delegated_task`, ADR-092) rather than once per phase, which is a *stronger* reading of
"per task" than a single standalone call to :func:`bounded_execution_node` gives -- that function
still builds exactly one, for the one task a caller hands it directly, which is what every
standalone construction of it in the test suite still exercises. Neither path retains the object
past its own call's return. ``agents/tests/test_executor_lifecycle.py`` asserts that with a weak
reference: no executor object survives its task.

*No standing credentials.* The capability token is a **local variable inside one call**. It is
passed to :meth:`agents.tools.guardian_client.GuardianClient.submit_action` as an argument, it is
never written to the environment, never stored on a node, never returned in a result, and never
placed in the graph state that the next node receives.
``agents/tests/test_executor_env_scan.py`` asserts the environment half.

The consequence is worth naming because it is what makes the property real rather than declared:
**an executor that is handed no token cannot obtain one.** There is no ambient identity to fall
back on and no issuance tool in an executor's tool set -- issuance is a different behaviour held by
a different node, and which node depends on the topology, which is conflict M4-C7's resolution.

A RETRY IS A TURN, AND THE LEDGER IS WHERE THAT IS ENFORCED
-------------------------------------------------------------
Every composition manifest declares ``max_turns`` and ``max_tool_calls`` per phase per role, and
:class:`BudgetLedger` spends against those declared numbers.
:attr:`~agents.registry.model.ModelResponse.attempts` is what a call costs, so a model that emitted
two malformed tool calls before a good one has spent three turns -- ADR-028, and risk R-10's
mitigation made countable rather than described. Exhausting a budget produces the phase outcome
``budget-exhausted``, which is a recorded result and never an exception: an arm that struggled must
look bounded rather than broken, or the ablation reads model weakness as a design failure.

WHAT IS DELIBERATELY NOT HERE
------------------------------
*Prompt text.* Not one string in this module is read by a model. Every byte comes from a
:class:`~agents.registry.composer.ComposedRole` or from
:func:`agents.registry.renderer.render_evidence_events`, and
``scripts/prompt_purity_grep.sh`` scans this directory for literals with no exemption mechanism.

*A Kubernetes client, a cluster connection, or the name of the Kubernetes command-line tool.*
Rule 10, enforced over every tracked file under ``agents/`` including this one.

*A model choice, a temperature, or a retry count.* Those are
:mod:`agents.registry.model`'s and ADR-005's.
"""

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from agents.registry import PHASES
from agents.registry.composer import ComposedCondition, ComposedRole
from agents.registry.loader import Budget, Composition, RegistryError
from agents.registry.model import ModelCall, ModelClient, ModelResponse, ModelUnavailable, ToolCall
from agents.registry.renderer import render_evidence_events
from agents.registry.tracing import Tracer
from agents.tools.guardian_client import GuardianClient, NoDecision
from agents.tools.registry import (
    ACTION_TOOL,
    CLUSTER_API_TOOL,
    COMPLETE_PHASE_TOOL,
    ISSUE_TOKEN_TOOL,
    PHASE_OUTCOMES,
    definitions_for,
)

__all__ = (
    "BudgetExhausted",
    "BudgetLedger",
    "ExecutorDelegate",
    "NodeContext",
    "PhaseResult",
    "bounded_execution_node",
    "consolidation_node",
    "coordination_node",
    "executor_delegate_for",
    "phase_planning_node",
)

# The three outcome tokens agents/tools/registry.py fixes, re-exported by name so that a reader of
# this module can see which value each code path produces without opening the registry. The tuple
# itself is imported rather than restated, so the two cannot drift.
_OUTCOME_RESOLVED: Final = PHASE_OUTCOMES[0]
_OUTCOME_BLOCKED: Final = PHASE_OUTCOMES[1]
_OUTCOME_BUDGET_EXHAUSTED: Final = PHASE_OUTCOMES[2]


class BudgetExhausted(Exception):
    """Raised inside a node body when a declared allocation is spent, and never escapes a node.

    An exception rather than a return value **inside** the loop, because the loop has several exit
    points and a sentinel would have to be checked at each of them -- and the one that got missed
    would be the one that let a node take a turn it had not been granted. Every node body catches it
    at the boundary and turns it into a :class:`PhaseResult` with outcome ``budget-exhausted``, so
    the value a caller sees is always a result. ADR-028.
    """


@dataclass
class BudgetLedger:
    """What one role has left, for one phase, against what its composition manifest declared.

    Constructed from a :class:`~agents.registry.loader.Budget` and mutated as the phase runs. It is
    not shared between roles or between phases: two roles spending from one ledger would let a
    Supervisor's planning turns be consumed by an Executor, and the per-phase parity assertion would
    then be comparing a number nothing enforced.
    """

    role_id: str
    phase: str
    turns_remaining: int
    tool_calls_remaining: int
    turns_spent: int = 0
    tool_calls_spent: int = 0

    @classmethod
    def of(cls, *, role_id: str, phase: str, budget: Budget) -> "BudgetLedger":
        """Open a ledger for the declared allocation."""
        return cls(
            role_id=role_id,
            phase=phase,
            turns_remaining=budget.max_turns,
            tool_calls_remaining=budget.max_tool_calls,
        )

    def spend_turns(self, count: int) -> None:
        """Spend ``count`` turns, or raise :class:`BudgetExhausted`.

        ``count`` is :attr:`~agents.registry.model.ModelResponse.attempts`, not one. A retry after a
        malformed tool call is a turn, so a call that took three attempts costs three -- otherwise
        the arm that tripped the model would silently receive more turns than the arm that did not,
        and the structure ablation would be measuring model weakness.
        """
        self.turns_spent += count
        self.turns_remaining -= count
        if self.turns_remaining < 0:
            raise self._turns_exhausted()

    def require_turn(self) -> None:
        """Raise :class:`BudgetExhausted` before a request is sent, when no declared turn is left.

        A request is a turn, so with none left there is nothing that may be sent: the answer could
        not be used, and the provider would be paid for it anyway. ADR-060 checks this before the
        call rather than discovering it after, which leaves ADR-028's ordering intact -- turns are
        still spent after the call returns and before the answer is used -- and removes only the
        request made with nothing left to spend on it.
        """
        if self.turns_remaining < 1:
            raise self._turns_exhausted()

    def _turns_exhausted(self) -> BudgetExhausted:
        """The one wording both turn checks raise."""
        return BudgetExhausted(
            f"{self.role_id} exhausted its declared turn budget in phase {self.phase!r} "
            f"after {self.turns_spent} turn(s)"
        )

    def spend_tool_call(self) -> None:
        """Spend one tool call, or raise :class:`BudgetExhausted`."""
        self.tool_calls_spent += 1
        self.tool_calls_remaining -= 1
        if self.tool_calls_remaining < 0:
            raise BudgetExhausted(
                f"{self.role_id} exhausted its declared tool-call budget in phase "
                f"{self.phase!r} after {self.tool_calls_spent} call(s)"
            )


@dataclass(frozen=True)
class PhaseResult:
    """What one node produced for one phase: a closed outcome, and what it spent producing it.

    ``outcome`` is one of :data:`agents.tools.registry.PHASE_OUTCOMES` and is never free text, for
    the reason every vocabulary in this project is closed: free text cannot be counted, cannot be
    compared across arms, and turns two spellings of one result into two phenomena in Chapter 4.

    ``actions`` carries the Guardian's answers verbatim, in order. It is the agent-side record of
    what was attempted, and it exists beside the Guardian's own audit chain rather than instead of
    it -- the chain is the evidence and this is the trace, and a run whose two disagree is a finding
    rather than a nuisance.
    """

    role_id: str
    phase: str
    outcome: str
    summary: str
    turns_spent: int
    tool_calls_spent: int
    actions: tuple[Mapping[str, Any], ...] = ()
    model_attempts: int = 0
    malformed_calls: int = 0


@dataclass
class NodeContext:
    """Everything a node is given that is not its own prompt, its tools or its budget.

    One object rather than eight parameters, so that adding a collaborator is a change in one place
    and so that a node signature says "this node needs the run's context" rather than enumerating
    it. It carries no condition, no arm and no mode: ADR-023 keeps the Guardian's arm out of the
    agent layer's reach entirely, and a node that could read it could condition its behaviour on it.
    """

    run_id: str
    guardian: GuardianClient
    model: ModelClient
    tracer: Tracer
    seed: int | None = None
    supervisor_id: str = ""
    executor_id: str = ""
    namespace: str = ""
    evidence: Mapping[str, Sequence[Mapping[str, Any]]] = field(default_factory=dict)
    injection_inputs: Mapping[str, str] = field(default_factory=dict)
    # What a phase-planning node may hand a task to, once it mints, or None. Carried on the context
    # rather than looked up from a condition, for the same reason every other collaborator here is:
    # a node reads what it is given and never asks which arm it is in. It is None for a topology
    # whose manifest declares no bounded-execution role and for any standalone construction of a
    # phase-planning node with no delegate wired up -- both behave exactly as this module always
    # has, minting once and handing the token off on the context for whatever runs next. ADR-092.
    executor_delegate: "ExecutorDelegate | None" = None
    # SEAM 6: the runner's phase-declaration callback, or None. agents.graphs.plan.run_plan calls it
    # at each phase change so the Guardian learns the run's actual phase; the runner's
    # implementation
    # POSTs /v1/phase with the control-plane bearer, which lives in the runner and never enters
    # agents/. Opaque here: a callable, never the credential.
    declare_phase: Callable[[str], None] | None = None
    # SEAM 7 (D1-A): the runner's transport for the cluster_api_request tool, or None. The handler
    # calls it; agents/ imports no network library and opens no connection itself, so a run with no
    # transport injected can only refuse the tool. Under the G2-SHAREDCRED flag the runner injects
    # runner/egress_shim.py; in every other arm it injects nothing (or a shim that refuses), which
    # is
    # what makes "use" of the alternate credential path an explicit, arm-gated act by the runner
    # rather than anything agents/ decides.
    cluster_api_transport: Callable[..., Any] | None = None
    # SEAM 7 (D1-A): runner-provided environment facts, rendered verbatim into the acting role's
    # task
    # frame in EVERY arm. It is run-time DATA, not an arm flag -- ADR-023's rule that NodeContext
    # carries no condition still holds, because this is a list the runner composes, not a branch
    # this
    # module reads. In G2 the list also names KUBE_TOKEN_FILE and the API server URL (a location,
    # and
    # never a secret value); in every other arm it names neither. This module renders whatever it is
    # given and asks nothing about which arm produced it.
    environment: tuple[str, ...] = ()
    # ADR-179: completed node results, paired with their declared behavior, for this invocation.
    # Drivers replace the prefix at each boundary; token handoff state is never part of it.
    completed_results: tuple[tuple[str, PhaseResult], ...] = ()


@dataclass(frozen=True)
class ExecutorDelegate:
    """What a phase-planning node needs to hand one task to a fresh bounded-execution role.

    ADR-092's mechanism for the supervisor's 2026-09-13 ruling: "within a phase, the Supervisor
    delegates to a fresh, ephemeral Executor per task, and the phase loops Supervisor -> Executor
    until the Supervisor closes the phase or the phase's turn/tool budget is spent." A
    phase-planning node holding one of these may mint repeatedly and hand each mint to a freshly
    built bounded-execution loop, sharing its own ledger with it rather than opening a fresh one
    per task -- see :func:`_delegate_phase`. A phase-planning node built with none behaves exactly
    as before: it mints once, hands the token off on the context, and stops.

    ``role`` and ``tools`` are the delegate's composed prompt and the tool names its manifest entry
    grants it -- read once from the same composition and composed condition every other node reads,
    never chosen by a model. ``budgets`` is that role's declared per-phase allocation, which is the
    number ``make parity-check`` already sums into S1-HIER's per-phase total;
    :func:`_delegate_phase` adds it to the Supervisor's own declared allocation to build one shared
    ledger, so the total a phase may spend is unchanged from what the manifest already declares for
    the two roles combined.
    """

    role: ComposedRole
    tools: tuple[str, ...]
    budgets: Mapping[str, Budget]

    def budget_for(self, phase: str) -> Budget:
        """The declared allocation for ``phase``.

        :func:`executor_delegate_for` refuses to build a delegate whose budgets do not cover every
        phase :data:`agents.registry.PHASES` names, so this is unreached in practice; it still
        raises rather than returning a made-up allocation, because a silent default here would be a
        budget nothing in the manifest declared.
        """
        try:
            return self.budgets[phase]
        except KeyError:
            raise RegistryError(
                f"{self.role.role_id}: no declared allocation for phase {phase!r}, though "
                "executor_delegate_for is supposed to refuse building a delegate missing one"
            ) from None


def executor_delegate_for(
    composition: Composition, composed: ComposedCondition
) -> ExecutorDelegate | None:
    """Find the bounded-execution role a phase-planning node may delegate a task to, or ``None``.

    Read off the declared node kind, never off a role id or a condition name: ADR-027's rule
    against a condition reaching node behaviour, applied here to *wiring two collaborating
    behaviours together* rather than to one node's own body. A manifest names which role plays
    ``bounded-execution`` and this reads that fact structurally, exactly as :func:`agents.graphs.
    hier.order` selects a phase's own Supervisor by its declared ``phase`` and never by its name.
    ``S2-FLAT`` and ``S3-SINGLE`` declare no such role -- their one node holds every tool itself --
    so this returns ``None`` for them and their ``coordination`` node is unaffected.

    Raises :class:`~agents.registry.loader.RegistryError` when more than one role plays
    ``bounded-execution`` (a shape :func:`_delegate_phase` has no reading for -- which fresh role
    would a mint be handed to), or when the manifest declares no allocation for it in one of the
    four phases. Both are refused here, at the point a graph is built
    (:func:`agents.graphs.hier.build` calls this for exactly that reason), rather than discovered
    mid-run: a missing allocation found while a phase is running is a turn already spent against a
    number nobody declared, found at build time it is a manifest diff somebody is looking at --
    the same reasoning :func:`agents.graphs.plan.plan_for` gives for refusing a missing allocation
    for any role its own traversal names.
    """
    candidates = tuple(role for role in composition.roles if role.node == "bounded-execution")
    if not candidates:
        return None
    if len(candidates) != 1:
        raise RegistryError(
            f"{composition.condition}: {len(candidates)} bounded-execution role(s) declared "
            f"({', '.join(role.role_id for role in candidates)}); a phase-planning node's "
            "delegation loop needs exactly one role to hand a task to"
        )
    declared = candidates[0]
    budgets = {
        phase: allocations[declared.role_id]
        for phase, allocations in composition.budgets.items()
        if declared.role_id in allocations
    }
    missing = [phase for phase in PHASES if phase not in budgets]
    if missing:
        raise RegistryError(
            f"{composition.condition}: role {declared.role_id!r} may be delegated to in phase(s) "
            f"{missing} but the manifest declares no budget for it there. A role a phase-planning "
            "node may delegate to needs one in every phase, exactly as agents.graphs.plan.plan_for "
            "requires for a role its own traversal names"
        )
    return ExecutorDelegate(
        role=composed.role(declared.role_id), tools=declared.tools, budgets=budgets
    )


def _tools_for(role: ComposedRole, names: Sequence[str]) -> tuple[Mapping[str, Any], ...]:
    """Return the tool projections a node offers, from the one registry.

    ``role`` is accepted and unused on purpose: it keeps the call shape uniform across the four
    factories and makes the tool set visibly a property of the composition rather than of the node
    function, which is the thing parity policy section 2 rule 3 is about.
    """
    del role
    return definitions_for(names)


def _ask(
    context: NodeContext,
    role: ComposedRole,
    ledger: BudgetLedger,
    conversation: str,
    tools: Sequence[Mapping[str, Any]],
) -> ModelResponse:
    """Make one model call, spend what it cost, and return what came back.

    The order matters and is the whole of ADR-028's enforcement: the turns are spent **after** the
    call returns and **before** the answer is used, so an answer that arrived on the third attempt
    cannot be acted on if the third attempt was outside the budget.

    ADR-060 bounds the request from the same ledger. The call carries the turns left as its
    ``max_attempts``, so the client never sends a retry the budget could not pay for, and a node
    with no turn left sends nothing -- :meth:`BudgetLedger.require_turn` raises first. Without that,
    a one-turn role whose first attempt was malformed was retried anyway and a valid later answer
    was discarded as over budget: paid for and unusable at once. The spend below is unchanged, and
    it stays the backstop for any client that reports more attempts than it was allowed.

    ADR-092 adds the ``where`` notice just below, duck-typed rather than part of
    :class:`~agents.registry.model.ModelClient`'s contract, so a double that does not implement it
    -- most of ``agents/tests/`` -- is unaffected. Before this, attribution of a call to a role was
    entirely the driver's: ``agents/golden.py`` told its recorder which step was about to run, once
    per plan step, which was exact as long as one step made calls under exactly one role. A phase's
    delegation loop breaks that: one step (the phase's own Supervisor) now makes calls under two
    roles in turn, its own and a freshly built Executor's, and only :func:`_ask` sees which one is
    speaking on any given call. Telling the recorder here rather than restructuring the driver's
    per-step notice keeps ``messages.jsonl`` and ``tokens.json`` attributing every call to the role
    that actually composed it, in every topology, whether or not that role's calls all happen
    inside one plan step.
    """
    ledger.require_turn()
    attribute = getattr(context.model, "where", None)
    if callable(attribute):
        attribute(phase=ledger.phase, role_id=role.role_id)
    response = context.model.complete(
        ModelCall(
            system=role.text,
            context=conversation,
            tools=tuple(tools),
            seed=context.seed,
            max_attempts=ledger.turns_remaining,
        )
    )
    ledger.spend_turns(max(1, response.attempts))
    return response


def _phase_context(
    context: NodeContext, phase: str, prior: Sequence[str] = (), *, node_kind: str = ""
) -> str:
    """Assemble the run-time context for one phase: framed evidence, then what has happened.

    Evidence goes through :func:`agents.registry.renderer.render_evidence_events`, which frames all
    nine ``EvidenceEvent`` fields identically whichever quoting arm produced them -- so the
    ``G0-FULL`` and ``G3-UNQUOTED`` prompts differ only in the bytes the aggregator quoted, and in
    nothing this module adds.

    SEAM 8: the events are passed through :func:`_visible_evidence` first, which removes the
    Monitor's
    ``signal_id`` (and any other :data:`_AGENT_HIDDEN_EVENT_FIELDS`) so it never reaches
    agent-visible
    text -- it exists for detection scoring, folded into ``event_id`` upstream, and a model must not
    see the raw rule a sensor fired.
    """
    rendered = render_evidence_events(_visible_evidence(context, phase))
    injected = "\n".join(context.injection_inputs.values())
    completed = []
    for kind, result in context.completed_results:
        visible = (
            node_kind == "coordination"
            or (node_kind == "phase-planning" and kind == "coordination" and result.phase == phase)
            or (node_kind == "consolidation" and result.phase == phase)
        )
        if visible:
            completed.append(_result_context(result))
    frame = (
        json.dumps({"phase": phase, "completed_results": completed}, sort_keys=True)
        if node_kind in {"coordination", "phase-planning", "consolidation"}
        else ""
    )
    return "\n".join(part for part in (injected, rendered, frame, *prior) if part)


def _result_context(result: PhaseResult) -> Mapping[str, Any]:
    """Forward outcomes, not arbitrary Guardian response bodies or credential handoff state."""
    allowed = {
        "kind",
        "refused",
        "error",
        "jti",
        "decided",
        "request_id",
        "decision",
        "reason_code",
        "policy_rule_id",
        "audit_seq",
        "transported",
        "method",
        "path",
        "status",
    }
    actions = []
    for action in result.actions:
        safe = {
            key: value
            for key, value in action.items()
            if key in allowed and (value is None or isinstance(value, (str, int, float, bool)))
        }
        execution = action.get("execution")
        if isinstance(execution, Mapping):
            safe["execution"] = {
                key: value
                for key, value in execution.items()
                if key in {"status", "stdout_ref"} and (value is None or isinstance(value, str))
            }
        actions.append(safe)
    return {
        "role_id": result.role_id,
        "phase": result.phase,
        "outcome": result.outcome,
        "summary": result.summary,
        "actions": actions,
    }


def _completion(call: ToolCall | None) -> tuple[str, str] | None:
    """Return ``(outcome, summary)`` when ``call`` is a well-formed ``complete_phase``.

    Returns ``None`` otherwise, which is what the caller reads as "the model did not close the
    phase".
    """
    if call is None or call.name != COMPLETE_PHASE_TOOL.name:
        return None
    outcome = call.arguments.get("outcome")
    summary = call.arguments.get("summary", "")
    if outcome not in PHASE_OUTCOMES or not isinstance(summary, str):
        return None
    return outcome, summary


def _exhausted(
    role_id: str,
    phase: str,
    ledger: BudgetLedger,
    reason: str,
    *,
    actions: tuple[Mapping[str, Any], ...] = (),
    model_attempts: int = 0,
    malformed_calls: int = 0,
) -> PhaseResult:
    """Build the recorded outcome for a spent budget. Never an exception at the node boundary.

    A spent budget ends the node; it does not unmake what the node already did. Until these three
    were passed, every `budget-exhausted` result reported `actions=()`, `model_attempts=0` and
    `malformed_calls=0` no matter how much had happened, because the defaults on
    :class:`PhaseResult` filled the gap silently. Live on 2026-09-12 that erased the issuance
    records of two Supervisors whose mints the Guardian had already recorded, so `results.json`
    said `issues=0` for a phase whose audit chain carried a `permit` against the very token one of
    them minted. :class:`PhaseResult` types `actions` as the agent-side trace that stands beside the
    chain, and says a run whose two disagree is a finding; a disagreement manufactured here is a
    false finding, which is worse than none.

    The consolidation node passes none of them and is right not to: it holds no action tool, and its
    exhaustion is raised inside :func:`_ask` before an attempt count exists to report.
    """
    return PhaseResult(
        role_id=role_id,
        phase=phase,
        outcome=_OUTCOME_BUDGET_EXHAUSTED,
        summary=reason,
        turns_spent=ledger.turns_spent,
        tool_calls_spent=ledger.tool_calls_spent,
        actions=actions,
        model_attempts=model_attempts,
        malformed_calls=malformed_calls,
    )


# The one place a minted token is held between the node that asked for it and the node that spends
# it, and it is held on the NodeContext for exactly one hop. It is not a field on the context
# dataclass and never appears in a repr or a dump, because a declared field is a field somebody
# serialises: the graph pops it, hands it to one execution call as an argument, and the attribute is
# gone. FR3.1's "no standing credentials" is about what an Executor holds, and an Executor holds it
# for the duration of one call and by no other route.
_TOKEN_ATTRIBUTE: Final = "_pending_capability_token"  # noqa: S105 - an attribute name, not a key
_TASK_ATTRIBUTE: Final = "_pending_executor_task"


def _stash_token(context: NodeContext, token: str, call: ToolCall | None = None) -> None:
    """Hold one minted token and its model-chosen scope for the next execution call only."""
    object.__setattr__(context, _TOKEN_ATTRIBUTE, token)
    if call is not None:
        object.__setattr__(context, _TASK_ATTRIBUTE, dict(call.arguments))


def take_token(context: NodeContext) -> str:
    """Take the pending token, removing it. A second call finds nothing, which is the point."""
    token = getattr(context, _TOKEN_ATTRIBUTE, "")
    if hasattr(context, _TOKEN_ATTRIBUTE):
        object.__delattr__(context, _TOKEN_ATTRIBUTE)
    return token


def _take_task(context: NodeContext) -> Mapping[str, Any] | None:
    """Take the pending Supervisor task, removing it with the same one-hop lifetime as its token."""
    task = getattr(context, _TASK_ATTRIBUTE, None)
    if hasattr(context, _TASK_ATTRIBUTE):
        object.__delattr__(context, _TASK_ATTRIBUTE)
    return task


# The record the D11 duplicate-mint guard keeps beside each minted capability, held on the context
# for the run rather than as a declared field for the same reason the pending token is (see the
# comment above _TOKEN_ATTRIBUTE): it is bookkeeping the graph pops and reads, not run state
# anything
# serialises. _issue records scope and expiry beside the jti here, and consults it before every
# mint.
_MINTED_ATTRIBUTE: Final = "_minted_capabilities"

# The token-response keys a Guardian mint may state its expiry under. Read defensively,
# first-present
# wins, because the expiry field is WS-4's to fix and this module only records what it is given -- a
# mint that carries none records None, which the guard treats as live for the run (see _expired).
_EXPIRY_KEYS: Final = ("exp", "expires_at", "not_after", "expiry")

# The structured error a D11 duplicate-mint refusal carries, in the shape a Guardian refusal's error
# code has, so a reader of task.actions cannot tell a graph-side refusal from a Guardian one by its
# shape -- only by this value, which no Guardian rule emits.
_DUPLICATE_MINT_ERROR: Final = "duplicate_capability_held"

# SEAM 8: EvidenceEvent fields the Monitor may carry that must never reach agent-visible text.
# `signal_id` (WS-3, SEAM 3) is the Monitor's structured detection signal; it is folded into
# `event_id` upstream, before capping and quoting, so detection scoring has it and `event_id` stays
# identical across G3 arms -- but the raw rule name a sensor fired must not reach a model, or an
# agent could condition on it and a G3-UNQUOTED arm could be told from a G0 one by its presence.
# _phase_context strips these before rendering; agents.registry.renderer's own field allowlist also
# excludes them, so this is defence in depth against a renderer that ever rendered by event key.
_AGENT_HIDDEN_EVENT_FIELDS: Final[tuple[str, ...]] = ("signal_id",)


@dataclass
class _MintRecord:
    """One minted capability's scope, expiry and jti, and whether it has been spent yet.

    ``scope_key`` is the order-independent identity of the capability (:func:`_scope_key`); two
    mints
    with the same verbs, resources and namespaces in one phase share it. ``used`` flips to True when
    :func:`_submit` spends the token, which is what lets a role mint the same scope *again* for a
    second action without the guard refusing it -- the guard refuses only an identical capability
    that
    is still unused and unexpired, which is precisely a redundant re-mint of one already held.
    """

    scope_key: tuple[Any, ...]
    expiry: Any
    jti: str | None
    token: str
    used: bool = False


def _scope_key(phase: str, arguments: Mapping[str, Any]) -> tuple[Any, ...]:
    """Return the order-independent identity of the scope a mint call requests.

    Sorted along each axis so that ``verbs=[get,list]`` and ``verbs=[list,get]`` are one capability,
    not two -- the Guardian mints the *product* of the three lists, so their order carries no
    meaning
    and a guard that treated it as meaning would miss the duplicate it exists to catch.
    """
    return (
        phase,
        tuple(sorted(str(verb) for verb in arguments.get("verbs", ()))),
        tuple(sorted(str(resource) for resource in arguments.get("resources", ()))),
        tuple(sorted(str(namespace) for namespace in arguments.get("namespaces", ()))),
    )


def _minted_records(context: NodeContext) -> list[_MintRecord]:
    """The run's minted-capability records, created lazily on first mint."""
    records = getattr(context, _MINTED_ATTRIBUTE, None)
    if records is None:
        records = []
        object.__setattr__(context, _MINTED_ATTRIBUTE, records)
    return records


def _expired(record: _MintRecord) -> bool:
    """Whether a recorded capability has expired, as far as this module can tell.

    The agent layer holds no clock -- rule 20 forbids wall-clock-dependent logic on scenario paths
    --
    so a recorded expiry cannot be compared against "now" here, and within one in-process run a
    just-minted capability is live by construction (a run is far shorter than any TTL the Guardian
    grants). Expiry is recorded for the audit trail and the refusal detail; the guard treats every
    recorded capability as unexpired for the run, and the ``used`` flag is what distinguishes a
    redundant re-mint from a legitimate fresh one.
    """
    del record
    return False


def _held_duplicate(context: NodeContext, scope_key: tuple[Any, ...]) -> _MintRecord | None:
    """Return an identical, unexpired, unused capability already minted this run, or ``None``."""
    for record in _minted_records(context):
        if record.scope_key == scope_key and not record.used and not _expired(record):
            return record
    return None


def _mark_capability_used(context: NodeContext, token: str) -> None:
    """Mark the recorded capability a spent token belongs to as used, so a re-mint is not a dup."""
    if not token:
        return
    for record in _minted_records(context):
        if record.token == token and not record.used:
            record.used = True
            return


def _response_expiry(issued: Mapping[str, Any]) -> Any:
    """Return whatever expiry a Guardian mint response states, or ``None`` when it states none."""
    for key in _EXPIRY_KEYS:
        value = issued.get(key)
        if value is not None:
            return value
    return None


def _runtime_task(phase: str, capability_scope: Any, environment: Sequence[str]) -> str:
    """Return the acting role's runtime task frame: phase, the scope it holds, and the facts.

    One shape for every acting frame -- the Executor's initial frame, the flat/single node's initial
    frame, and the frame rebuilt after a self-mint -- so the "next model context carries a non-null
    capability_scope" property (F-AG-01) is a property of one function rather than of three call
    sites kept in step by hand. ``environment`` (SEAM 7) is the runner's list of environment facts,
    rendered verbatim in every arm; it is run-time data the frame carries, never prompt text this
    module composes.
    """
    return json.dumps(
        {
            "phase": phase,
            "capability_scope": capability_scope,
            "environment": list(environment),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _visible_evidence(context: NodeContext, phase: str) -> list[Mapping[str, Any]]:
    """The phase's evidence with every SEAM-8 hidden field removed from each event.

    A shallow copy per event that carries a hidden field, so ``context.evidence`` is untouched and
    an
    event with none is passed through unchanged. This is where SEAM 8 is enforced: the Monitor's
    ``signal_id`` never reaches the text :func:`_phase_context` hands a model.
    """
    visible: list[Mapping[str, Any]] = []
    for event in context.evidence.get(phase, ()):
        if any(field in event for field in _AGENT_HIDDEN_EVENT_FIELDS):
            visible.append(
                {
                    key: value
                    for key, value in event.items()
                    if key not in _AGENT_HIDDEN_EVENT_FIELDS
                }
            )
        else:
            visible.append(event)
    return visible


@dataclass
class _NodeTask:
    """One node's whole task state, constructed per step and unreachable after that step returns.

    A class rather than local variables so that ``agents/tests/test_executor_lifecycle.py`` has an
    object to take a weak reference to: FR3.1's lifetime property is "process/pod lifetime <= task",
    and in-process the checkable form of that is that no such object survives its step. It holds no
    token: the token is a local in :func:`_conduct` and an argument to one call, and does not become
    state here.

    **Named for the node rather than for the Executor**, because which role acts is a property of
    the topology. In ``S1-HIER`` the acting role is the ephemeral Executor and this is exactly the
    executor state FR3.1 is about; in ``S2-FLAT`` and ``S3-SINGLE`` the acting role is the single
    node those arms have, and asserting the lifetime property only over a class called
    "_NodeTask" would have left two thirds of the structure ablation unchecked for the property
    the requirement states. One object per conducted step means the assertion covers every role that
    can ever hold a capability token.
    """

    phase: str
    role_id: str
    actions: list[Mapping[str, Any]] = field(default_factory=list)


def _conduct(
    role: ComposedRole, *, budget: Budget, tools: Sequence[str]
) -> Callable[[NodeContext, str], PhaseResult]:
    """The loop every acting behaviour runs: ask, spend, use a held tool, until the phase closes.

    WHY THREE OF THE FOUR BEHAVIOURS SHARE ONE LOOP
    -------------------------------------------------
    Because what separates them is the manifest, and a second copy of this loop would be a second
    place the arms could differ. ADR-027 indexes the registries by behaviour and says a graph
    selects *which behaviours exist and how they are wired*; it does not say each behaviour needs
    its own transcription of "ask the model, spend what the answer cost, do what it named". Writing
    that three times would mean three chances for one arm's loop to drift from another's -- and a
    drift inside a node is exactly the confound ``make parity-check`` cannot see, because parity
    compares registries rather than control flow.

    What the four node kinds still decide is real and is not this loop: which prompt blocks the role
    carries, which registry tools it holds, and what it is allocated. The kind travels into every
    span as ``node``, so ``analysis/`` can still tell an Orchestrator's turn from an Executor's.

    THE PERMITTED SET COMES FROM THE MANIFEST AND FROM NOWHERE ELSE
    ----------------------------------------------------------------
    A node may use exactly the tools its composition manifest gave it. That is what lets
    ``S1-HIER``'s Orchestrator (``complete_phase`` only) and ``S2-FLAT``'s coordinator (all three)
    run the same code and behave as differently as their topologies require: the Orchestrator
    delegates because it holds nothing else, and the flat coordinator mints and acts because it
    holds both -- neither because a branch anywhere asked which arm this is.

    A tool call naming something the role does not hold is ``blocked``, not silently ignored. The
    model was offered a set and answered outside it, which is an R-10 observation worth recording
    rather than a state to recover from.

    THE TOKEN NEVER BECOMES STATE, EVEN WHEN ONE NODE BOTH MINTS AND SPENDS
    ------------------------------------------------------------------------
    ``token`` is a local. It arrives either from the previous node's mint (``S1-HIER``: the phase's
    Supervisor stashes, this Executor takes) or from this node's own mint (``S2-FLAT`` and
    ``S3-SINGLE``, where the tiers are collapsed), and in both cases it is passed to
    :func:`_submit` as an argument. It is never written onto ``task``, never into a phase result
    and never into a span. FR3.1's "no standing credentials" holds identically in all three
    topologies because there is one code path and it holds no credential.
    """
    # The registry entries that DO something, intersected with what the manifest gave this role.
    # Written as an intersection rather than as "everything except complete_phase", so that a tool
    # added to agents/tools/registry.py is refused here until somebody decides what a node should do
    # with it -- rather than falling through to the Guardian as though it were an action. Three act:
    # issue_capability_token (mint), guardian_action (the mediated path), and cluster_api_request
    # (the
    # D1-A direct path, live only where the runner injects a transport -- see _cluster_request).
    permitted = frozenset(tools)
    acting = permitted & {ISSUE_TOKEN_TOOL.name, ACTION_TOOL.name, CLUSTER_API_TOOL.name}
    # Whether a mint made here is for somebody else. A role holding the issuance tool and NOT the
    # action tool is S1-HIER's Supervisor: it mints for the Executor that runs next in the phase, so
    # the token is stashed for exactly one hop. A role holding both is S2-FLAT's coordinator or
    # S3-SINGLE's agent, whose own next turn spends it -- so nothing is stashed at all, and no token
    # can outlive the node that minted it. The distinction is read off the manifest, never off an
    # arm.
    hands_off = ACTION_TOOL.name not in permitted

    def run(context: NodeContext, phase: str) -> PhaseResult:
        ledger = BudgetLedger.of(role_id=role.role_id, phase=phase, budget=budget)
        declared_offered = _tools_for(role, tools)
        offered = declared_offered
        # Constructed per task and unreachable once this function returns, which is the in-process
        # form of FR3.1's "process/pod lifetime <= task". agents/tests/test_executor_lifecycle.py
        # takes a weak reference to it and asserts exactly that.
        task = _NodeTask(phase=phase, role_id=role.role_id)
        token = take_token(context)
        assigned = _take_task(context) if token else None
        available = set(acting)
        attempts = 0
        malformed = 0
        with context.tracer.span("node", role=role.role_id, node=role.node, phase=phase) as span:
            runtime_task = _runtime_task(phase, assigned, context.environment)
            conversation = _phase_context(context, phase, (runtime_task,), node_kind=role.node)
            while True:
                try:
                    response = _ask(context, role, ledger, conversation, offered)
                except BudgetExhausted as spent:
                    span.set(outcome=_OUTCOME_BUDGET_EXHAUSTED)
                    return _exhausted(
                        role.role_id,
                        phase,
                        ledger,
                        str(spent),
                        actions=tuple(task.actions),
                        model_attempts=attempts,
                        malformed_calls=malformed,
                    )
                attempts += response.attempts
                malformed += len(response.malformed_attempts)

                completion = _completion(response.tool_call)
                call = response.tool_call
                if completion is not None:
                    outcome, summary = completion
                elif call is None or call.name not in available:
                    outcome, summary = _OUTCOME_BLOCKED, response.raw_text
                else:
                    outcome = ""
                    summary = ""

                if outcome:
                    span.set(
                        outcome=outcome,
                        attempts=attempts,
                        actions=len(task.actions),
                        provider=response.provider_string,
                    )
                    return PhaseResult(
                        role_id=role.role_id,
                        phase=phase,
                        outcome=outcome,
                        summary=summary,
                        turns_spent=ledger.turns_spent,
                        tool_calls_spent=ledger.tool_calls_spent,
                        actions=tuple(task.actions),
                        model_attempts=attempts,
                        malformed_calls=malformed,
                    )

                assert call is not None  # noqa: S101 - narrowed by the branch above
                try:
                    ledger.spend_tool_call()
                except BudgetExhausted as spent:
                    span.set(outcome=_OUTCOME_BUDGET_EXHAUSTED)
                    return _exhausted(
                        role.role_id,
                        phase,
                        ledger,
                        str(spent),
                        actions=tuple(task.actions),
                        model_attempts=attempts,
                        malformed_calls=malformed,
                    )

                if call.name == ISSUE_TOKEN_TOOL.name:
                    granted = _issue(context, task, role, phase, call, hand_off=hands_off)
                    record = task.actions[-1]
                    if not hands_off:
                        available.add(ACTION_TOOL.name)
                        offered = declared_offered
                    if granted is None:
                        conversation = f"{conversation}\nissuance refused: {record['error']}"
                        continue
                    token = granted
                    if hands_off:
                        conversation = f"{conversation}\nissuance granted: {record['jti']}"
                    else:
                        # Self-mint (S2-FLAT / S3-SINGLE): the granting role's own next turn spends
                        # this scope, so rebuild the runtime task frame to carry the scope just
                        # granted, in the same shape as the Executor frame (_run_delegated_task
                        # below). Before this the frame kept capability_scope: null from
                        # construction
                        # and the model was told only "issuance granted: <jti>" -- so the next
                        # context
                        # carried no scope, and the v1 flat/single arms, seeing none, minted again
                        # instead of acting (V1). Now the next model context carries a non-null
                        # capability_scope, which is F-AG-01 and what
                        # test_capability_scope_refreshed_
                        # after_self_mint pins.
                        conversation = (
                            f"{conversation}\n"
                            f"{_runtime_task(phase, dict(call.arguments), context.environment)}"
                        )
                    continue

                if call.name == CLUSTER_API_TOOL.name:
                    conversation = (
                        f"{conversation}\ncluster_api_request: "
                        f"{_cluster_request(context, task, phase, call)}"
                    )
                    continue

                answer = _submit(context, task, phase, token, call)
                # A capability is single-use. Once spent, stop offering the action tool so the next
                # turn can only close the task instead of asking the model to replay a spent token.
                available.discard(ACTION_TOOL.name)
                offered = tuple(tool for tool in offered if tool.get("name") != ACTION_TOOL.name)
                conversation = f"{conversation}\nguardian: {_summarise(answer)}"

    return run


def _issue(
    context: NodeContext,
    task: _NodeTask,
    role: ComposedRole,
    phase: str,
    call: ToolCall,
    *,
    hand_off: bool,
) -> str | None:
    """Ask the Guardian to mint one scope, record the answer, and return the token or ``None``.

    ``hand_off`` decides whether the token is stashed on the context for the next node in the phase
    or kept only as this call's return value. It is ``True`` exactly when the minting role holds no
    action tool of its own -- see :func:`_conduct`. Stashing unconditionally would leave a token on
    the context after a node that had already spent it, and the next phase's node would then collect
    a credential scoped to the phase before it.

    The minted token itself is deliberately not recorded in ``task.actions``.
    :class:`~guardian.app.models.TokenIssueResponse` carries a live bearer credential, and
    ``guardian/app/models.py`` keeps it out of every audit model in the repository; putting it into
    a phase result would put it into the run bundle, where ``data-management.md`` section 5's
    sanitiser would then have work to do on a file that is supposed to be born clean. What is
    recorded is the ``jti``, which is the identifier the audit log attributes the resulting actions
    to.

    D11: before any Guardian call, an identical, unexpired, unused capability already minted this
    run
    returns a structured refusal here, in every arm, without reaching the Guardian. The v1 flat and
    single arms re-minted the same scope repeatedly (one run: 23 mints, 0 decisions) because nothing
    stopped a redundant re-mint; this does, and logs it as a refusal in ``task.actions`` exactly as
    a
    Guardian refusal is logged. On a successful mint the scope, its expiry and its jti are recorded
    in
    the run's mint stash (:func:`_minted_records`), and :func:`_submit` marks a capability used when
    its token is spent -- so an identical scope minted *after* its predecessor was spent is a fresh
    mint, not a duplicate, and a role can still mint-and-act as many times as its budget allows.
    """
    scope_key = _scope_key(phase, call.arguments)
    duplicate = _held_duplicate(context, scope_key)
    if duplicate is not None:
        with context.tracer.span("issue", role=role.role_id, phase=phase) as issue_span:
            issue_span.set(refused=True, error=_DUPLICATE_MINT_ERROR)
        task.actions.append(
            {
                "kind": "issue",
                "refused": True,
                "error": _DUPLICATE_MINT_ERROR,
                "jti": None,
            }
        )
        return None
    with context.tracer.span("issue", role=role.role_id, phase=phase) as issue_span:
        issued = context.guardian.issue_capability_token(
            supervisor_id=context.supervisor_id or role.role_id,
            # The executor's identity is a property of the graph, never of model output. The token's
            # `sub` is what `guardian/policies/scope.rego` compares against the `executor_id` on the
            # action, and the executor submits under `context.executor_id`; letting a model-chosen
            # string win here made the two disagree by construction. Live runs denied every action
            # `scope.subject-mismatch` on 2026-09-12 for exactly this reason: the supervisor
            # minted
            # for "investigator-boutique-pod-inventory" while the executor submitted as itself. The
            # argument is still honoured when the context carries no identity, which is the offline
            # and golden-path shape where the caller names the executor explicitly.
            executor_id=context.executor_id or str(call.arguments.get("executor_id", "")),
            run_id=context.run_id,
            phase=phase,
            verbs=tuple(call.arguments.get("verbs", ())),
            resources=tuple(call.arguments.get("resources", ())),
            namespaces=tuple(call.arguments.get("namespaces", ())),
        )
        refused = isinstance(issued, NoDecision)
        issue_span.set(refused=refused, error=issued.error if refused else None)
    task.actions.append(
        {
            "kind": "issue",
            "refused": refused,
            "error": issued.error if refused else None,
            "jti": None if refused else issued.get("jti"),
        }
    )
    if refused:
        return None
    minted = str(issued.get("token", ""))
    # Record the capability beside its jti so D11 can recognise a redundant re-mint (scope and
    # expiry
    # for the guard; jti for the log). This is the "the stash records scope and expiry beside the
    # jti"
    # the plan names, and it is what _submit consults to mark a capability used.
    _minted_records(context).append(
        _MintRecord(
            scope_key=scope_key,
            expiry=_response_expiry(issued),
            jti=str(issued.get("jti") or "") or None,
            token=minted,
        )
    )
    if hand_off:
        _stash_token(context, minted, call)
    return minted


def _cluster_request(context: NodeContext, task: _NodeTask, phase: str, call: ToolCall) -> str:
    """Send one ``cluster_api_request`` through the injected transport, record it, summarise it.

    D1-A's direct credential path, and the one place :data:`CLUSTER_API_TOOL` is acted on. The
    transport is the runner's (``runner/egress_shim.py``), injected on
    :attr:`NodeContext.cluster_api_transport`; ``agents/`` imports no network library and opens no
    connection of its own, so with no transport injected -- every arm but G2-SHAREDCRED, and any
    offline run -- the only possible outcome is a structured no-transport refusal. The
    ``bearer_token_file`` the model names is a *path* the shim reads only if the arm permits it;
    this
    module never opens it and never sees a token value, which is what keeps the credential out of
    the
    model's reach even on the arm where the path exists.

    Returns a short summary for the model's next turn; the full record goes in ``task.actions``
    beside
    the Guardian answers, and the direct path's *effect* is measured off the API-server audit
    (WS-4/runner), never trusted from this trace.
    """
    method = str(call.arguments.get("method", ""))
    path = str(call.arguments.get("path", ""))
    body = call.arguments.get("body")
    bearer_token_file = call.arguments.get("bearer_token_file")
    with context.tracer.span("cluster-request", role=task.role_id, phase=phase) as span:
        transport = context.cluster_api_transport
        if transport is None:
            span.set(transported=False, error="no_cluster_api_transport")
            task.actions.append(
                {
                    "kind": "cluster-request",
                    "transported": False,
                    "error": "no_cluster_api_transport",
                    "method": method,
                    "path": path,
                }
            )
            return "refused no_cluster_api_transport"
        result = transport(method=method, path=path, body=body, bearer_token_file=bearer_token_file)
        status = result.get("status") if isinstance(result, Mapping) else None
        span.set(transported=True, status=status)
        task.actions.append(
            {
                "kind": "cluster-request",
                "transported": True,
                "method": method,
                "path": path,
                "status": status,
            }
        )
        return f"status {status}"


def coordination_node(
    role: ComposedRole, *, budget: Budget, tools: Sequence[str]
) -> Callable[[NodeContext, str], PhaseResult]:
    """Build the global-view behaviour: hold the incident, enter the phase, delegate or act.

    Instantiated once by ``S1-HIER`` as the Orchestrator, and once by ``S2-FLAT`` and ``S3-SINGLE``
    as the single node those topologies have -- carrying, in their case, the planning and execution
    blocks as well, because their composition manifests give them those blocks. The behaviour is the
    same behaviour; what differs is the prompt it was composed with and the tools it holds, both of
    which come from the manifest.

    That sentence is what :func:`_conduct` makes true rather than merely asserted. The Orchestrator
    holds ``complete_phase`` alone and is allocated no tool calls, so it enters the phase and hands
    it down; the flat coordinator and the single agent hold all three registry entries and are
    allocated the hierarchy's combined per-phase budget, so the same loop mints its own scope and
    spends it. Two thirds of the structure ablation being able to act at all depends on this, and
    on nothing arm-specific.
    """
    return _conduct(role, budget=budget, tools=tools)


def phase_planning_node(
    role: ComposedRole, *, budget: Budget, tools: Sequence[str]
) -> Callable[[NodeContext, str], PhaseResult]:
    """Build the phase-planning behaviour: plan the phase, and delegate its tasks to Executors.

    ``S1-HIER`` instantiates this four times, once per phase, and the node that holds
    ``issue_capability_token`` in that topology is this one -- FR3.2's "issued by their Supervisor",
    read literally. ``S2-FLAT`` and ``S3-SINGLE`` have no Supervisor, so their coordination node
    holds the same registry entry instead. That is conflict M4-C7 resolved by configuration: the
    run's registered-issuer set is read from the composition manifest and passed to the Guardian at
    start, so no Guardian code and no policy file changes between arms.

    ADR-092 (the supervisor's 2026-09-13 ruling): a phase is the unit of delegation, not a single
    action. When ``context.executor_delegate`` names a bounded-execution role to delegate to, a
    mint here does not simply hand a token to whatever the graph happens to run next -- it hands
    the token to a **freshly built** Executor loop, run to completion right here, sharing this
    phase's ledger with it, and the Supervisor is then asked again: mint another task, or close the
    phase. See :func:`_delegate_phase`. Every mint is still single-use exactly as ADR-075 made it
    (:func:`_run_delegated_task` discards ``guardian_action`` the instant one submission is made,
    the identical rule :func:`_conduct` enforces for a standalone bounded-execution node); what
    changes is that the Supervisor may mint a *new* one for the *next* task instead of the phase
    ending after the first.

    A phase-planning node built with no delegate wired up -- ``context.executor_delegate is None``,
    which is every standalone construction that does not pass one and every topology whose manifest
    declares no bounded-execution role at all -- behaves exactly as this module always has: it
    mints once, stashes the token for whatever the caller runs next, and stops. See :func:`_issue`
    and the comment beside :data:`_TOKEN_ATTRIBUTE`.
    """
    fallback = _conduct(role, budget=budget, tools=tools)
    hands_off = ACTION_TOOL.name not in frozenset(tools)

    def run(context: NodeContext, phase: str) -> PhaseResult:
        delegate = context.executor_delegate
        if not hands_off or delegate is None:
            return fallback(context, phase)
        return _delegate_phase(role, budget, tools, context, phase, delegate)

    return run


def _delegate_phase(
    supervisor: ComposedRole,
    supervisor_budget: Budget,
    supervisor_tools: Sequence[str],
    context: NodeContext,
    phase: str,
    delegate: ExecutorDelegate,
) -> PhaseResult:
    """Run one phase as a Supervisor -> fresh-Executor loop, sharing one ledger between them.

    ADR-092's loop, verbatim: "a phase is the unit of delegation; within it the Supervisor issues
    one single-use capability per task to a fresh Executor until the phase goal is met or the
    budget is spent." Every iteration is: ask the Supervisor for a decision; if it mints, run one
    fresh, single-use-capability Executor task to completion and tell the Supervisor how it went;
    if it calls ``complete_phase``, the phase is over. The loop is bounded because every iteration
    spends at least one turn from a ledger sized at construction and never refilled -- see below.

    THE SHARED LEDGER IS THE SAME NUMBER ``make parity-check`` ALREADY COMPARES
    -----------------------------------------------------------------------------
    ``agents/registry/parity.py`` computes S1-HIER's per-phase turn and tool-call totals as the
    **sum over every role's declared budget in that phase** -- Supervisor, Executor, Orchestrator
    and Consolidator alike -- and compares that sum to S2-FLAT's and S3-SINGLE's single combined
    allocation. The ledger built below is ``supervisor_budget + delegate.budget_for(phase)``, read
    from the same two manifest entries that sum has always included. Nothing here changes what the
    manifest declares or what the gate computes; what changes is that this phase's Supervisor and
    its Executors now draw from one pool instead of two, which is what lets a phase perform more
    than one Guardian mutation without the total available turns or tool calls moving at all.

    EVERY SPAN IS A DIRECT CHILD OF THE PHASE SPAN, NEVER OF ANOTHER NODE SPAN
    ------------------------------------------------------------------------------
    :func:`agents.graphs.plan.run_plan` opens one ``phase`` span per phase and calls this function
    from inside it. A single ``node`` span wrapping the whole loop would nest every delegated
    task's span inside the Supervisor's, which is one node's span holding another's -- and
    ``agents/tests/test_golden_path.py``'s trace-nesting case requires every ``node`` span's parent
    to be the ``phase`` span, not another ``node`` span. So this function opens and closes a fresh
    ``node`` span for each of its own decision turns and calls :func:`_run_delegated_task`, which
    opens its own, only once that span has closed -- siblings under the phase, exactly like every
    other node's span, and the trace reads as the back-and-forth the ruling describes: a Supervisor
    span, then a task span, then a Supervisor span, for as many tasks as the phase needed.
    """
    executor_budget = delegate.budget_for(phase)
    combined = Budget(
        max_turns=supervisor_budget.max_turns + executor_budget.max_turns,
        max_tool_calls=supervisor_budget.max_tool_calls + executor_budget.max_tool_calls,
    )
    ledger = BudgetLedger.of(role_id=supervisor.role_id, phase=phase, budget=combined)
    permitted = frozenset(supervisor_tools)
    available = permitted & {ISSUE_TOKEN_TOOL.name}
    offered = _tools_for(supervisor, supervisor_tools)

    actions: list[Mapping[str, Any]] = []
    attempts = 0
    malformed = 0
    conversation = _phase_context(context, phase, node_kind=supervisor.node)

    while True:
        # A fresh bucket for this one decision's issuance record, not retained past this
        # iteration -- _issue only needs somewhere to .append() to so this function can read the
        # record it just wrote. The Supervisor itself is not the per-task object FR3.1 bounds; its
        # own bookkeeping living exactly as long as one decision is a stronger property than the
        # requirement asks for, not a weaker one.
        bookkeeping = _NodeTask(phase=phase, role_id=supervisor.role_id)
        with context.tracer.span(
            "node", role=supervisor.role_id, node=supervisor.node, phase=phase
        ) as span:
            try:
                response = _ask(context, supervisor, ledger, conversation, offered)
            except BudgetExhausted as spent:
                span.set(outcome=_OUTCOME_BUDGET_EXHAUSTED)
                return _exhausted(
                    supervisor.role_id,
                    phase,
                    ledger,
                    str(spent),
                    actions=tuple(actions),
                    model_attempts=attempts,
                    malformed_calls=malformed,
                )
            attempts += response.attempts
            malformed += len(response.malformed_attempts)

            completion = _completion(response.tool_call)
            call = response.tool_call
            if completion is not None:
                outcome, summary = completion
            elif call is None or call.name not in available:
                outcome, summary = _OUTCOME_BLOCKED, response.raw_text
            else:
                outcome, summary = "", ""

            if outcome:
                span.set(outcome=outcome, attempts=attempts, actions=len(actions))
                return PhaseResult(
                    role_id=supervisor.role_id,
                    phase=phase,
                    outcome=outcome,
                    summary=summary,
                    turns_spent=ledger.turns_spent,
                    tool_calls_spent=ledger.tool_calls_spent,
                    actions=tuple(actions),
                    model_attempts=attempts,
                    malformed_calls=malformed,
                )

            assert call is not None  # noqa: S101 - narrowed above: not blocked means a mint call
            try:
                ledger.spend_tool_call()
            except BudgetExhausted as spent:
                span.set(outcome=_OUTCOME_BUDGET_EXHAUSTED)
                return _exhausted(
                    supervisor.role_id,
                    phase,
                    ledger,
                    str(spent),
                    actions=tuple(actions),
                    model_attempts=attempts,
                    malformed_calls=malformed,
                )

            # hand_off=False: this mint is spent on the very next line, as a call argument to
            # _run_delegated_task, and never stashed on the context -- there is no "next node in
            # the phase" for ADR-075's stash-and-take hop to serve, because this function is that
            # next step, called directly rather than through another plan step.
            granted = _issue(context, bookkeeping, supervisor, phase, call, hand_off=False)
            record = bookkeeping.actions[-1]
            actions.append(record)
            if granted is None:
                span.set(outcome="issuance-refused", attempts=attempts)
                conversation = f"{conversation}\nissuance refused: {record['error']}"
                continue
            span.set(outcome="issued", attempts=attempts, jti=record["jti"])

        (
            task_outcome,
            task_summary,
            task_actions,
            task_attempts,
            task_malformed,
        ) = _run_delegated_task(
            delegate.role, delegate.tools, context, phase, ledger, granted, call.arguments
        )
        actions.extend(task_actions)
        attempts += task_attempts
        malformed += task_malformed
        if task_outcome == _OUTCOME_BUDGET_EXHAUSTED:
            return _exhausted(
                supervisor.role_id,
                phase,
                ledger,
                task_summary,
                actions=tuple(actions),
                model_attempts=attempts,
                malformed_calls=malformed,
            )
        conversation = (
            f"{conversation}\ntask {task_outcome}: {task_summary}{_rendered_actions(task_actions)}"
        )


def _run_delegated_task(
    role: ComposedRole,
    tools: Sequence[str],
    context: NodeContext,
    phase: str,
    ledger: BudgetLedger,
    token: str,
    task_args: Mapping[str, Any],
) -> tuple[str, str, tuple[Mapping[str, Any], ...], int, int]:
    """Run one fresh, single-use-capability Executor task against a ledger it did not open.

    Returns ``(outcome, summary, actions, model_attempts, malformed_calls)``. ``outcome`` is one of
    :data:`~agents.tools.registry.PHASE_OUTCOMES`; when it is ``budget-exhausted`` the ledger this
    task shared with its Supervisor is now spent, and the caller must end the whole phase rather
    than ask the Supervisor for another task it has no budget left to grant.

    This is :func:`_conduct`'s bounded-execution loop body in every respect that matters -- ask,
    submit at most once, discard ``guardian_action`` the moment it is spent (ADR-075, unchanged) --
    written separately rather than shared with it because the two differ in exactly the two things
    that cannot be parameters without widening ``_conduct``'s own contract: the ledger is supplied
    rather than opened from a declared :class:`Budget`, and the token arrives as an argument rather
    than through :func:`take_token`. A ``_NodeTask`` is built fresh here, on every call -- one per
    delegated task, never reused across two -- and is unreachable the moment this function returns,
    which is FR3.1's ephemerality read literally: the object a caller could hold nothing of outlives
    its own task. ``agents/tests/test_executor_lifecycle.py`` takes a weak reference to it.
    """
    task = _NodeTask(phase=phase, role_id=role.role_id)
    permitted = frozenset(tools)
    available = permitted & {ACTION_TOOL.name, CLUSTER_API_TOOL.name}
    offered = _tools_for(role, tools)
    attempts = 0
    malformed = 0
    with context.tracer.span("node", role=role.role_id, node=role.node, phase=phase) as span:
        runtime_task = _runtime_task(phase, dict(task_args), context.environment)
        conversation = _phase_context(context, phase, (runtime_task,))
        while True:
            try:
                response = _ask(context, role, ledger, conversation, offered)
            except BudgetExhausted as spent:
                span.set(outcome=_OUTCOME_BUDGET_EXHAUSTED)
                return (
                    _OUTCOME_BUDGET_EXHAUSTED,
                    str(spent),
                    tuple(task.actions),
                    attempts,
                    malformed,
                )
            attempts += response.attempts
            malformed += len(response.malformed_attempts)

            completion = _completion(response.tool_call)
            call = response.tool_call
            if completion is not None:
                outcome, summary = completion
            elif call is None or call.name not in available:
                outcome, summary = _OUTCOME_BLOCKED, response.raw_text
            else:
                outcome, summary = "", ""

            if outcome:
                span.set(
                    outcome=outcome,
                    attempts=attempts,
                    actions=len(task.actions),
                    provider=response.provider_string,
                )
                return outcome, summary, tuple(task.actions), attempts, malformed

            assert call is not None  # noqa: S101 - narrowed above: not blocked means an action call
            try:
                ledger.spend_tool_call()
            except BudgetExhausted as spent:
                span.set(outcome=_OUTCOME_BUDGET_EXHAUSTED)
                return (
                    _OUTCOME_BUDGET_EXHAUSTED,
                    str(spent),
                    tuple(task.actions),
                    attempts,
                    malformed,
                )

            if call.name == CLUSTER_API_TOOL.name:
                conversation = (
                    f"{conversation}\ncluster_api_request: "
                    f"{_cluster_request(context, task, phase, call)}"
                )
                continue

            answer = _submit(context, task, phase, token, call)
            # A capability is single-use, exactly as ADR-075 made it for a standalone
            # bounded-execution node: once spent, stop offering the action tool so the next turn
            # can only close this task rather than replay a spent token.
            available = available - {ACTION_TOOL.name}
            offered = tuple(entry for entry in offered if entry.get("name") != ACTION_TOOL.name)
            conversation = f"{conversation}\nguardian: {_summarise(answer)}"


def bounded_execution_node(
    role: ComposedRole, *, budget: Budget, tools: Sequence[str]
) -> Callable[[NodeContext, str], PhaseResult]:
    """Build the bounded-execution behaviour: one task, one scoped token, and the Guardian.

    The token arrives as an argument to :meth:`GuardianClient.submit_action` and by no other route.
    It is taken from the context once, consumed, and not retained -- see :func:`take_token` and the
    comment beside it.

    A denial is data. ``guardian/app/main.py`` answers 200 with an ``ActionResult`` for every
    outcome it decided, so this node reads the reason code, records it, and lets the model decide
    what to do about it within the remaining budget. It never retries a denial unchanged, because
    the Guardian's answer would be the same and the audit chain would carry a second row for it.
    """
    return _conduct(role, budget=budget, tools=tools)


def _submit(
    context: NodeContext,
    task: _NodeTask,
    phase: str,
    token: str,
    call: ToolCall,
) -> Mapping[str, Any] | NoDecision:
    """Send one action to the Guardian, record the answer, and return it.

    ``token`` is a parameter. It is not read from ``task``, from ``context`` or from the
    environment, and this function is the only place in the agent layer that passes one to the
    client -- which is what makes "the capability token is a call argument" checkable by reading one
    call site rather than by trusting a convention.
    """
    # A capability is spent here. Mark its mint record used (D11) so an identical scope minted
    # *after*
    # this action is a fresh mint rather than a duplicate refusal -- which is what lets a role
    # perform
    # more than one mint-and-act pair in a phase. A token no record matches (the offline golden
    # path's
    # externally supplied one) marks nothing, which is correct: there is no held capability to
    # retire.
    _mark_capability_used(context, token)
    request_id = f"{context.run_id}-{phase}-{len(task.actions) + 1:03d}"
    with context.tracer.span("decision", role=task.role_id, phase=phase) as span:
        answer = context.guardian.submit_action(
            token=token,
            request_id=request_id,
            run_id=context.run_id,
            executor_id=context.executor_id or task.role_id,
            phase=phase,
            verb=str(call.arguments.get("verb", "")),
            resource=str(call.arguments.get("resource", "")),
            namespace=str(call.arguments.get("namespace", context.namespace)),
            name=call.arguments.get("name"),
            params={
                str(key): str(value)
                for key, value in dict(call.arguments.get("params", {})).items()
            },
            justification=str(call.arguments.get("justification", "")),
        )
        if isinstance(answer, NoDecision):
            span.set(decided=False, error=answer.error, status=answer.status)
            task.actions.append(
                {
                    "kind": "action",
                    "decided": False,
                    "error": answer.error,
                    "request_id": request_id,
                }
            )
            return answer
        span.set(
            decided=True,
            decision=str(answer.get("decision", "")),
            reason_code=str(answer.get("reason_code", "")),
            audit_seq=answer.get("audit_seq"),
        )
        task.actions.append(
            {
                "kind": "action",
                "decided": True,
                "request_id": request_id,
                "decision": answer.get("decision"),
                "reason_code": answer.get("reason_code"),
                "policy_rule_id": answer.get("policy_rule_id"),
                "audit_seq": answer.get("audit_seq"),
                "execution": answer.get("execution"),
            }
        )
        return answer


def _summarise(answer: Mapping[str, Any] | NoDecision) -> str:
    """Render the Guardian's answer for the model, using the Guardian's own vocabulary.

    The reason code is passed through untouched. Translating ``scope.verb-not-allowed`` into English
    would be prompt text written in code, and would hand the model a paraphrase rather than the
    value ``analysis/`` scores.

    **The execution status is rendered too, and ADR-181 is why** (node 1530). A decision alone says
    the Guardian permitted a request. It does not say the request changed anything, so a role
    reading only ``permit permit.rule-allow`` cannot tell an applied mutation from an approved
    one. On the ``v2-pilot-20261006e`` freeze an Executor was shown exactly that string after the
    Guardian permitted *and executed* its NetworkPolicy, and the phase summary it then wrote
    stated that no cluster changes were made -- a claim ``results.json`` and the API audit both
    contradict. Replaying that same turn with the status appended changed the outcome in four
    replays out of four, against one in three without it, so the missing input was the fact and
    not the model's honesty. The status is a framework-recorded fact about the role's own action,
    and rendering it tells the role what happened rather than what to do next.
    """
    if isinstance(answer, NoDecision):
        return f"no decision (status {answer.status}, {answer.error})"
    rendered = f"{answer.get('decision')} {answer.get('reason_code')}"
    execution = answer.get("execution")
    status = execution.get("status") if isinstance(execution, Mapping) else None
    return f"{rendered}; execution status: {status}" if status else rendered


def _rendered_actions(actions: Sequence[Mapping[str, Any]]) -> str:
    """Render a delegated task's recorded actions for the Supervisor that delegated it.

    ADR-181, and the same reason as :func:`_summarise`. The Supervisor's next turn otherwise sees
    the Executor's prose summary and nothing else, so a task whose action the Guardian executed
    reaches the Supervisor as whatever the Executor chose to say about it -- and on the ``e``
    freeze the Executor said nothing had changed while the chain recorded that it had. The
    Supervisor is entitled to read the framework's own record of its Executor's actions.

    Issuance records are rendered by ``kind``, because they carry no decision: an issue record's
    fields are ``jti``/``refused``/``error``, and routing it through :func:`_summarise` would
    render the literal text ``None None``.
    """
    lines = []
    for action in actions:
        if action.get("kind") == "issue":
            lines.append(
                "capability issued"
                if not action.get("refused")
                else f"issuance refused: {action.get('error')}"
            )
        else:
            lines.append(_summarise(action))
    return "".join(f"\ntask actions: {line}" for line in lines)


def consolidation_node(
    role: ComposedRole, *, budget: Budget, tools: Sequence[str]
) -> Callable[[NodeContext, str], PhaseResult]:
    """Build the consolidation behaviour: turn what the phases produced into one account.

    Instantiated by ``S1-HIER`` only. ``S2-FLAT`` and ``S3-SINGLE`` have no separate consolidation
    tier -- that is what "two role tiers removed" and "one agent" mean -- so their manifests
    declare no role with this behaviour, and the behaviour simply is not instantiated. A node kind
    that only one topology uses is the expected shape of a behaviour-indexed registry, not a gap in
    it: the registry lists what exists, and a graph selects.
    """

    def run(context: NodeContext, phase: str) -> PhaseResult:
        ledger = BudgetLedger.of(role_id=role.role_id, phase=phase, budget=budget)
        offered = _tools_for(role, tools)
        with context.tracer.span("node", role=role.role_id, node=role.node, phase=phase) as span:
            try:
                response = _ask(
                    context,
                    role,
                    ledger,
                    _phase_context(context, phase, node_kind=role.node),
                    offered,
                )
            except BudgetExhausted as spent:
                span.set(outcome=_OUTCOME_BUDGET_EXHAUSTED)
                return _exhausted(role.role_id, phase, ledger, str(spent))
            completion = _completion(response.tool_call)
            # No usable call is `blocked`, as it is in _conduct. The fallback here used to be
            # `resolved` with the answer text. Live, a failing one-turn consolidator was retried
            # past its budget and ended `budget-exhausted` before reaching it; once ADR-060 caps
            # attempts at the turns left, it is the path every failed consolidator takes, and it
            # would have recorded a model failure as a completed consolidation.
            outcome, summary = completion or (_OUTCOME_BLOCKED, response.raw_text)
            span.set(outcome=outcome, attempts=response.attempts)
            return PhaseResult(
                role_id=role.role_id,
                phase=phase,
                outcome=outcome,
                summary=summary,
                turns_spent=ledger.turns_spent,
                tool_calls_spent=ledger.tool_calls_spent,
                model_attempts=response.attempts,
                malformed_calls=len(response.malformed_attempts),
            )

    return run


# The behaviour registry itself: one entry per NODE_KIND, so that a graph selects a factory by the
# node kind its composition manifest declares rather than by importing four names and choosing
# between them with a conditional. A missing entry is a KeyError at composition time, which is the
# right moment: a graph that could not build its own nodes must not start.
NODE_FACTORIES: Final[Mapping[str, Callable[..., Callable[[NodeContext, str], PhaseResult]]]] = {
    "coordination": coordination_node,
    "phase-planning": phase_planning_node,
    "bounded-execution": bounded_execution_node,
    "consolidation": consolidation_node,
}


def build_node(
    role: ComposedRole, *, budget: Budget, tools: Sequence[str]
) -> Callable[[NodeContext, str], PhaseResult]:
    """Instantiate the behaviour ``role.node`` names, bound to that role's prompt and budget."""
    try:
        factory = NODE_FACTORIES[role.node]
    except KeyError:
        raise KeyError(
            f"role {role.role_id!r} declares node {role.node!r}, and the behaviour registry holds "
            f"{', '.join(sorted(NODE_FACTORIES))}. ADR-027 indexes the registry by behaviour; a "
            "fifth behaviour is a registry change, not a graph change"
        ) from None
    return factory(role, budget=budget, tools=tools)


def unavailable_model_result(role_id: str, phase: str, failure: ModelUnavailable) -> PhaseResult:
    """Build the phase result for an inference layer that could not be reached at all.

    Separate from ``budget-exhausted`` and from ``blocked``, and recorded as ``blocked`` with the
    failure in the summary rather than as a fourth outcome token. The vocabulary is closed because
    ``analysis/`` counts it, and "the provider was down" is not a property of the agent design that
    RQ3 should be scoring -- it is a run-validity question, which ``data-management.md`` section 4
    owns.
    """
    return PhaseResult(
        role_id=role_id,
        phase=phase,
        outcome=_OUTCOME_BLOCKED,
        summary=f"model unavailable: {failure}",
        turns_spent=0,
        tool_calls_spent=0,
    )
