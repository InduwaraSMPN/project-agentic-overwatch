r"""FR3.1's first property, *lifetime*: an Executor exists for one task and holds nothing after it.

WHAT THIS FILE PINS
-------------------
``docs/01-requirements.md``'s FR3.1 gives Executors two properties -- they are **ephemeral** and
they hold **no standing credentials** -- and ``docs/plans/M4-implementation-plan.md`` gives each its
own mechanism because either alone is weak. This file is the lifetime half.
``agents/tests/test_executor_env_scan.py`` is the credentials half, and neither is a substitute for
the other: an executor object that survived its phase would be a standing *identity* even with an
empty environment, and an environment carrying a signing key would be a standing *credential* even
if every object died on schedule.

Four claims, and each is here because it would otherwise fail silently.

**One state object per task, and none survives a phase.** ``agents/graphs/nodes.py`` builds a fresh
per-task state object inside the loop every acting behaviour runs, and returns a
:class:`~agents.graphs.nodes.PhaseResult` built from a *copy* of what it accumulated. Nothing in the
module retains the task -- but "nothing retains it" is exactly the kind of claim that a later edit
breaks without changing a single observable value. A node that stashed its task on the
:class:`~agents.graphs.nodes.NodeContext` "so the next phase can see what happened" would pass every
outcome assertion in this suite and would make FR3.1's "process/pod lifetime <= task" false. The
only way to check it is to take a weak reference to the object the node built and assert it is dead
once the step returns, which is what the cases below do, on the shipped class rather than on a
stand-in for it. That class is found by its *shape* and never by its name -- see
:func:`per_task_state_class` -- because the name is private, carries no contract, and a lifetime
assertion that went red for a rename would be an assertion about the wrong thing.

**The capability token is a call argument and nothing else.**
``agents/tools/guardian_client.py`` states it as a property of the type -- the token is a parameter
of :meth:`~agents.tools.guardian_client.GuardianClient.submit_action`, and the client holds a
transport and no credential -- and the failure mode is a client that caches "the last token" for
convenience. Such a client would still pass every decision assertion, because the cached token would
be the right one nearly always; it would fail only on the case the whole architecture exists to
prevent, an Executor acting with a capability it was never handed. So the check here is structural
rather than behavioural: the client's own attributes are enumerated, and the token string is
searched for across everything reachable from it. A scan that cannot fail is not evidence, so a
planted credential is used to show that this one can.

**A token is not reused across phases.** Each phase's Supervisor mints its own scope and hands it to
one execution call; the Guardian's audit chain records which ``jti`` was spent where. A graph that
minted once and reused the token would look identical in every phase result, and the property that
would quietly disappear is the one FR3.2's per-phase scoping is for.

**Retry accounting, which is ADR-028.** A retry is a turn. A call that took three attempts costs
three, exhausting a declared allocation is a **recorded outcome** rather than an exception escaping
the node, and -- the part that is easy to get wrong and impossible to see afterwards -- a node never
*acts* on an answer that arrived outside its budget. :func:`~agents.graphs.nodes._ask` spends the
turns after the call returns and before the answer is used, so an over-budget answer raises before
it can become an action. If the order were reversed, every arm that tripped the model would silently
receive the extra actions its budget did not cover, and the structure ablation would be measuring
model weakness. The audit chain is what makes that checkable: an action taken outside the budget is
a row in it.

WHAT IS DELIBERATELY NOT HERE
------------------------------
*A golden path.* Whether the four phases produce the right outcomes is
``agents/tests/test_golden_path.py``'s. This file drives phases only far enough to observe what an
Executor's existence costs and leaves behind.

*A judgement about the Guardian's decision.* Whether a permit was right is the policy bundle's
business, checked by ``make guardian-test``. Here a decision is evidence that a request was made at
all.

*An arm.* Nothing below builds a condition, a mode or a quoting flag. ADR-023 keeps every condition
flag in the runner's hands, and ``agents/tests/harness.py`` says why no test may reach one.
"""

from __future__ import annotations

import ast  # noqa: E402 - deliberately after the __future__ import, for the syntax scan below
import dataclasses
import gc
import json
import os
import types
import weakref
from collections.abc import Mapping, Sequence
from typing import Any

import pytest
from agents.graphs import hier, nodes
from agents.graphs.nodes import (
    BudgetLedger,
    NodeContext,
    PhaseResult,
    bounded_execution_node,
    executor_delegate_for,
    phase_planning_node,
    take_token,
)
from agents.graphs.plan import run_plan
from agents.registry import PHASES
from agents.registry.composer import compose_condition
from agents.registry.loader import Budget, Composition, PromptRegistry, load_registry
from agents.registry.model import ScriptedClient, ToolCall
from agents.tools.guardian_client import GuardianClient, Transport
from agents.tools.registry import (
    ACTION_TOOL,
    CLUSTER_API_TOOL,
    COMPLETE_PHASE_TOOL,
    ISSUE_TOKEN_TOOL,
    PHASE_OUTCOMES,
)
from harness import (
    EXECUTOR_ID,
    NAMESPACE,
    REPO_ROOT,
    InProcessGuardian,
    RetryingClient,
    asgi_transport,
    control_plane_transport,
    node_context,
)

# The four ways this layer could read a file, named as call targets so the syntax scan below can
# look
# for them by what they *are* rather than by the text near them. Deliberately narrow: a module that
# could open a credential is the thing D1-A forbids, and a broader list (any ``.read*``, any
# ``Path`` construction) would fire on paths that resolve to the registry's own files.
FILE_READING_CALLS = frozenset({"open", "read_text", "read_bytes"})

# The condition this file drives. S1-HIER is the only topology with a *separate* execution tier, so
# it is the only one in which "no executor object survives a phase" is a statement about an object
# rather than about a node that is also doing three other jobs. S2-FLAT and S3-SINGLE inherit the
# property by construction -- their coordination node holds the execution blocks -- and
# agents/tests/test_graphs.py is where their wiring is asserted.
CONDITION = hier.CONDITION

# The three answers a scripted model gives here, built once from the shipped tool registry rather
# than from literals, so that a renamed tool breaks these cases at the name rather than at an
# outcome three assertions later.
ACTION_ANSWER = ToolCall(
    name=ACTION_TOOL.name,
    arguments={
        "verb": "get",
        "resource": "pods",
        "namespace": NAMESPACE,
        "name": None,
        "params": {},
        "justification": "read the workload the evidence names",
    },
)
MINT_ANSWER = ToolCall(
    name=ISSUE_TOKEN_TOOL.name,
    arguments={
        "executor_id": EXECUTOR_ID,
        "verbs": ["get"],
        "resources": ["pods"],
        "namespaces": [NAMESPACE],
    },
)
COMPLETE_ANSWER = ToolCall(
    name=COMPLETE_PHASE_TOOL.name,
    arguments={"outcome": PHASE_OUTCOMES[0], "summary": "the phase reached what it set out to do"},
)

# The phases these cases drive, taken from the closed vocabulary agents/registry/__init__.py fixes
# rather than spelled. The strings travel into an ActionRequest's phase field and into a capability
# token's phase claim, and a second spelling would be a denial under scope.phase-mismatch that
# nothing in the agent layer could explain.
DETECTION = PHASES[0]
CONTAINMENT = PHASES[1]
ERADICATION = PHASES[2]

# The outcome token a spent allocation produces. Taken from the registry tuple rather than spelled,
# for the reason agents/graphs/nodes.py re-exports it: the vocabulary is closed and a test that
# restated a member would be a second home for it.
BUDGET_EXHAUSTED = PHASE_OUTCOMES[2]

# What one conducted step accumulates: the phase it is in, the role conducting it, and what it did.
# Used to identify the per-step state object by shape rather than by its private class name --
# see :func:`per_task_state_class` for why that indirection is the right dependency to take.
PER_TASK_STATE_FIELDS = frozenset({"phase", "role_id", "actions"})

# A bound on the reachability walk below. It is a *termination* guard rather than a tuning knob:
# the walk descends through arbitrary object graphs, and a graph that turned out to be unbounded
# should fail loudly here rather than hang a CI job. The Guardian client's own graph visits some
# fifteen thousand objects, so this is an order of magnitude of headroom.
REACHABILITY_OBJECT_LIMIT = 250_000

# Types the reachability walk records or stops at. Modules and classes are stopped at because
# descending into them reaches the whole interpreter -- every module global of every imported
# package -- which would make the walk a statement about the process rather than about the object
# it started from.
_LEAF_TYPES = (int, float, bool, complex, type(None), types.ModuleType, type)


# --------------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------------


def composed_composition(registry: PromptRegistry) -> Composition:
    """The ``S1-HIER`` composition manifest, which is what :func:`hier.order` selects against."""
    return registry.compositions[CONDITION]


def per_task_state_class() -> tuple[str, type]:
    """Find, by shape, the private dataclass a node builds once per conducted step.

    Found rather than named, and the reason is a rule about what this file is allowed to depend on.
    The claim being made is that an object's *lifetime* is bounded by a step; the object's class
    name is a private implementation detail of :mod:`agents.graphs.nodes` that no contract
    mentions, and a case pinned to it would go red for a rename that changes nothing about
    lifetime. Its *shape* is the part the claim actually rests on -- the state one step accumulates
    is the phase it is in, the role conducting it, and the actions it took -- so that is what is
    matched on.

    Exactly one class must match. Zero means the node module no longer holds per-step state as an
    object at all, in which case this file's whole mechanism is stale and must be reconsidered
    rather than quietly passing; more than one means the shape stopped identifying it, and picking
    the first would be picking whichever the module happened to define earlier.
    """
    matched = [
        (name, value)
        for name, value in vars(nodes).items()
        if isinstance(value, type)
        and name.startswith("_")
        and dataclasses.is_dataclass(value)
        and PER_TASK_STATE_FIELDS <= {field.name for field in dataclasses.fields(value)}
    ]
    assert len(matched) == 1, (
        f"{len(matched)} private dataclass(es) in agents.graphs.nodes carry the fields "
        f"{sorted(PER_TASK_STATE_FIELDS)}: {[name for name, _ in matched]}. This file identifies "
        "the per-step state object by its shape rather than by its name, so that a rename does not "
        "break a lifetime assertion; an ambiguous or empty match means the shape no longer "
        "identifies it and the mechanism below needs rethinking rather than adjusting"
    )
    return matched[0]


def record_executor_objects(monkeypatch: pytest.MonkeyPatch) -> list[weakref.ReferenceType[Any]]:
    """Return a growing list of weak references to every per-task state object a node builds.

    The shipped class is constructed unchanged -- what is substituted is only the *name* the node
    body reaches it through, so that this suite gets a handle on an object it otherwise could not
    name. A subclass or a stand-in would make the assertion a statement about the substitute; a
    weak reference to the real instance is a statement about the real one, and it keeps nothing
    alive, which is the whole point.
    """
    created: list[weakref.ReferenceType[Any]] = []
    attribute, shipped = per_task_state_class()

    def build(**fields: Any) -> Any:
        made = shipped(**fields)
        created.append(weakref.ref(made))
        return made

    monkeypatch.setattr(nodes, attribute, build)
    return created


def surviving(created: Sequence[weakref.ReferenceType[Any]]) -> list[Any]:
    """Collect garbage and return every recorded per-task state object still reachable.

    :func:`gc.collect` rather than a bare refcount check, because a cycle would keep an object
    alive until the collector ran and "alive until the next collection" is not a lifetime property
    anybody could rely on. A collection first makes the answer unambiguous in both directions.
    """
    gc.collect()
    return [alive for alive in (reference() for reference in created) if alive is not None]


def recording_transport(guardian: InProcessGuardian) -> tuple[list[dict[str, Any]], Transport]:
    """Return a request log and a transport that appends to it before driving the real Guardian.

    The log is the bytes the client actually sent, decoded. Asserting over it rather than over what
    a node *says* it did is what makes "the token in the second phase's action is not the first
    phase's" a claim about the wire rather than about a record the graph wrote about itself.

    The inner transport carries SEAM 6's control-plane bearer on ``POST /v1/tokens`` (via
    ``harness.control_plane_transport``), because a client built over this transport mints for real
    --
    ``test_no_capability_token_is_reused_across_phases`` drives two Supervisor mints through it --
    and
    the Guardian now guards that route with an ``HTTPBearer`` dependency (ADR-128). The log still
    records only method, path and body, which is all this file's assertions read; the header is on
    the
    wire, not in the record.
    """
    sent: list[dict[str, Any]] = []
    inner = control_plane_transport(asgi_transport(guardian.assembled.app))

    def transport(method: str, path: str, body: bytes) -> tuple[int, Any]:
        sent.append({"method": method, "path": path, "body": json.loads(body) if body else {}})
        return inner(method, path, body)

    return sent, transport


def reachable_strings(root: Any, *, limit: int = REACHABILITY_OBJECT_LIMIT) -> list[str]:
    """Every string reachable from ``root`` by following references, bounded and cycle-safe.

    :func:`gc.get_referents` rather than a hand-written walk over ``__dict__``, ``__slots__``,
    closures and containers, because the hand-written version is a list of the places somebody
    thought to look -- and a credential kept somewhere nobody thought of is precisely the failure
    this is for. The interpreter's own view of "what does this object refer to" has no such blind
    spot.
    """
    seen: set[int] = set()
    pending: list[Any] = [root]
    found: list[str] = []
    visited = 0
    while pending:
        obj = pending.pop()
        if id(obj) in seen:
            continue
        seen.add(id(obj))
        visited += 1
        if visited > limit:
            raise AssertionError(
                f"the reachability walk from {type(root).__name__} passed {limit} objects without "
                "terminating; it is bounded so that an unexpected graph fails loudly instead of "
                "hanging CI"
            )
        if isinstance(obj, str):
            found.append(obj)
            continue
        if isinstance(obj, (bytes, bytearray)):
            found.append(obj.decode("utf-8", "replace"))
            continue
        if isinstance(obj, _LEAF_TYPES):
            continue
        pending.extend(gc.get_referents(obj))
    return found


def run_one_action_phase(
    guardian: InProcessGuardian,
    registry: PromptRegistry,
    phase: str,
    *,
    context: NodeContext | None = None,
) -> tuple[PhaseResult, PhaseResult, NodeContext]:
    """Mint through the phase's Supervisor, then spend the token through one Executor.

    The two nodes are built from the manifest's own budgets for that phase, so the allocations
    spent here are the allocations ``make parity-check`` compares -- a test that invented its own
    would be exercising a runtime nothing else configures.
    """
    composition = composed_composition(registry)
    composed = compose_condition(registry, CONDITION)
    planner_id = hier.order(composition, phase)[1]
    planner = phase_planning_node(
        composed.role(planner_id),
        budget=composition.budgets[phase][planner_id],
        tools=[ISSUE_TOKEN_TOOL.name, COMPLETE_PHASE_TOOL.name],
    )
    executor = bounded_execution_node(
        composed.role("executor"),
        budget=composition.budgets[phase]["executor"],
        tools=[ACTION_TOOL.name, COMPLETE_PHASE_TOOL.name],
    )
    if context is None:
        context = node_context(
            guardian,
            model=ScriptedClient([MINT_ANSWER, COMPLETE_ANSWER, ACTION_ANSWER, COMPLETE_ANSWER]),
        )
    return planner(context, phase), executor(context, phase), context


# --------------------------------------------------------------------------------------------
# Lifetime: no executor object survives a phase
# --------------------------------------------------------------------------------------------


def test_one_executor_object_is_built_per_task_and_none_survives_its_phase(
    guardian: InProcessGuardian, registry: PromptRegistry, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Drive the whole ``S1-HIER`` plan and assert every per-task state object is unreachable.

    The model is scripted with no answers at all, which is the honest end state of a model that has
    stopped producing usable calls: every node spends one turn, records ``blocked`` or ``resolved``,
    and returns. That is enough to exercise construction and return, which is what lifetime is
    about, and it keeps this case independent of what any particular answer would do.

    The **count** is bounded rather than fixed, and the bounds are the two claims worth making. At
    least one object per phase, so the observation is not vacuous -- a plan that built none would
    make the reachability assertion below true by having nothing to check. At most one per step,
    which is "constructed per task" stated as arithmetic: an object built per model turn instead
    would exceed it. The exact number in between is a fact about how many behaviours share the
    per-task state -- three of the four do, which is a composition decision ADR-027 owns -- and
    pinning it here would make this case fail for a refactor that changes nothing about lifetime.
    """
    created = record_executor_objects(monkeypatch)
    plan = hier.build(registry)
    context = node_context(guardian)

    results = run_plan(plan, context)

    assert len(results) == len(plan.steps), (
        f"run_plan returned {len(results)} result(s) for a plan of {len(plan.steps)} step(s); the "
        "lifetime claim below is about the steps that actually ran"
    )
    assert len(plan.phases()) <= len(created) <= len(plan.steps), (
        f"{len(created)} per-task state object(s) were built across {len(plan.phases())} phase(s) "
        f"and {len(plan.steps)} step(s). Fewer than one per phase means some phase ran no "
        "task-scoped step at all and the lifetime assertion below would be vacuous; more than one "
        "per step means state is being constructed per model turn rather than per task, which is "
        "not the unit FR3.1 bounds"
    )
    assert surviving(created) == [], (
        "a per-task state object is still reachable after the plan returned. FR3.1 types an "
        "Executor's lifetime as at most one task; in-process the checkable form of that is that "
        "nothing retains its state once the step is done. Something now does -- the usual cause is "
        "a convenience reference kept on the NodeContext or accumulated in a module-level list"
    )


def test_the_executor_object_is_dead_before_the_next_step_begins(
    guardian: InProcessGuardian, registry: PromptRegistry, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One node call, checked immediately: the object is gone the moment the call returns.

    The whole-plan case above could in principle pass because a *later* step overwrote a reference
    the earlier one left behind. This one closes that reading: nothing else has run in between, so
    the only thing that could be holding the object is the node itself.
    """
    created = record_executor_objects(monkeypatch)
    composition = composed_composition(registry)
    executor = bounded_execution_node(
        compose_condition(registry, CONDITION).role("executor"),
        budget=composition.budgets[CONTAINMENT]["executor"],
        tools=[ACTION_TOOL.name, COMPLETE_PHASE_TOOL.name],
    )

    context = node_context(guardian, model=ScriptedClient([COMPLETE_ANSWER]))
    result = executor(context, CONTAINMENT)

    assert result.outcome == PHASE_OUTCOMES[0], (
        f"the scripted phase ended {result.outcome!r}; this case needs a step that ran to "
        "completion, because an object that outlived a step which raised would be a different "
        "finding"
    )
    assert len(created) == 1, (
        f"{len(created)} executor object(s) were built for one task; bounded execution constructs "
        "its per-task state once per call"
    )
    assert surviving(created) == [], (
        "the executor object built for this task is still reachable immediately after the call "
        "returned, with nothing else having run in between. The state a node builds for one task "
        "must be unreachable when that task is over -- that is what FR3.1's ephemerality means "
        "in-process"
    )


# --------------------------------------------------------------------------------------------
# ADR-092: a phase delegates more than one task, each under its own fresh single-use capability
# --------------------------------------------------------------------------------------------


def _delegated_planner(registry: PromptRegistry, phase: str) -> tuple[Any, Any]:
    """Build ``phase``'s Supervisor phase-planning node with its delegate wired up.

    Shared by the cases below so each drives the exact node ``agents/golden.py`` builds for a real
    run: the same manifest budgets, the same composed role, the same delegate
    :func:`~agents.graphs.nodes.executor_delegate_for` derives from the shipped registry.
    """
    composition = composed_composition(registry)
    composed = compose_condition(registry, CONDITION)
    planner_id = hier.order(composition, phase)[1]
    delegate = executor_delegate_for(composition, composed)
    assert delegate is not None, "S1-HIER declares no bounded-execution role to delegate to"
    planner = phase_planning_node(
        composed.role(planner_id),
        budget=composition.budgets[phase][planner_id],
        tools=[ISSUE_TOKEN_TOOL.name, COMPLETE_PHASE_TOOL.name],
    )
    return planner, delegate


def _two_task_script() -> list[Any]:
    """Mint, act, close -- twice -- then the Supervisor closes the phase.

    Each cycle is exactly the two-call shape a standalone Executor already uses
    (:data:`ACTION_ANSWER` then :data:`COMPLETE_ANSWER`), preceded by its own mint: three turns per
    task, one for the Supervisor's mint and two for the fresh Executor's action and its own close,
    plus a final turn for the Supervisor to close the phase -- seven turns for two tasks, which is
    what makes ``detection-and-investigation`` (Supervisor 3 + Executor 5 = 8 declared turns) the
    phase this script is driven against below, with one turn to spare. Two fresh capabilities for
    two mutations is the multiplicity ``SCN-SIM-02``'s containment phase needs
    (``create networkpolicies``, ``patch deployments``, per the mutation count the 2026-09-13
    question for the supervisor gives) and which S1-HIER could not previously perform in one phase
    at all -- the structural cap the T-50 confound exists to catch.
    """
    return [
        MINT_ANSWER,
        ACTION_ANSWER,
        COMPLETE_ANSWER,
        MINT_ANSWER,
        ACTION_ANSWER,
        COMPLETE_ANSWER,
        COMPLETE_ANSWER,
    ]


def test_a_phase_delegates_multiple_tasks_each_under_its_own_fresh_single_use_capability(
    guardian: InProcessGuardian, registry: PromptRegistry
) -> None:
    """ADR-092's central claim: several Guardian mutations in one phase, none of them a replay.

    Two tasks, two mints, two submissions. Every jti must be distinct, the Guardian must decide
    each submission exactly once, and none may be denied as a replay of an earlier one -- which is
    what would happen if the single-use rule slipped and the same capability were offered twice.
    Before ADR-092, S1-HIER's phase loop invoked the Executor exactly once, so no scenario whose
    containment phase requires more than one mutation could show a valid completeness score for
    this arm; this is the test that closes that confound (row T-50 in the traceability matrix).
    """
    planner, delegate = _delegated_planner(registry, DETECTION)
    context = node_context(guardian, model=ScriptedClient(_two_task_script()))
    context.executor_delegate = delegate

    result = planner(context, DETECTION)

    assert result.outcome == PHASE_OUTCOMES[0], f"{result.outcome!r}: {result.summary!r}"
    issued = [action for action in result.actions if action.get("kind") == "issue"]
    submitted = [action for action in result.actions if action.get("kind") == "action"]
    assert len(issued) == 2, f"expected two mints for two tasks, recorded {issued!r}"
    assert len(submitted) == 2, f"expected two submitted actions, recorded {submitted!r}"
    assert all(record["refused"] is False for record in issued), f"a mint was refused: {issued!r}"
    assert all(record["decided"] is True for record in submitted), (
        f"the Guardian reached no decision on a submission: {submitted!r}"
    )

    jtis = [record["jti"] for record in issued]
    assert len(set(jtis)) == 2, f"a jti was minted more than once across the two tasks: {jtis!r}"

    records = guardian.audit_records()
    assert len(records) == 2, (
        f"expected exactly one Guardian decision per submitted action, got {len(records)}: "
        f"{records!r}"
    )
    assert all(record["reason_code"] != "replay.jti-spent" for record in records), (
        f"a capability was presented more than once: {records!r}"
    )
    assert [record["token_jti"] for record in records] == jtis, (
        "the audit chain's token_jti order must match the order the Supervisor minted them in: "
        f"chain={[r['token_jti'] for r in records]!r} minted={jtis!r}"
    )


def test_a_delegated_task_cannot_reuse_its_capability_for_a_second_submission(
    guardian: InProcessGuardian, registry: PromptRegistry
) -> None:
    """ADR-075's own case, restated for the loop: one mint still buys exactly one submission.

    The model proposes a second action inside the *same* task, before the Supervisor is ever asked
    again. Exactly as a standalone bounded-execution node already refuses this
    (``test_a_spent_capability_cannot_submit_a_second_action`` above), the fresh Executor a
    delegated task builds must refuse it too: ADR-092 changes how many tasks a phase may run, not
    how many actions one capability may buy.
    """
    planner, delegate = _delegated_planner(registry, CONTAINMENT)
    script = [MINT_ANSWER, ACTION_ANSWER, ACTION_ANSWER, COMPLETE_ANSWER, COMPLETE_ANSWER]
    context = node_context(guardian, model=ScriptedClient(script))
    context.executor_delegate = delegate

    result = planner(context, CONTAINMENT)

    submitted = [action for action in result.actions if action.get("kind") == "action"]
    assert len(submitted) == 1, (
        f"the delegated task submitted {len(submitted)} action(s) with one single-use capability: "
        f"{submitted!r}"
    )
    assert len(guardian.audit_records()) == 1
    assert guardian.audit_records()[0]["reason_code"] != "replay.jti-spent"


def test_each_delegated_task_builds_a_fresh_object_and_none_survive_the_phase(
    guardian: InProcessGuardian, registry: PromptRegistry, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FR3.1 per task, not per phase: two delegated tasks, two fresh objects, all dead by the end.

    The lifetime cases earlier in this file pin the pre-ADR-092 shape: one bounded-execution visit
    per phase, one object. This is the same claim under the new loop -- a fresh per-task state
    object for *every* task the phase delegates, at least one per scripted task, and none of them
    reachable once the whole phase has returned.
    """
    created = record_executor_objects(monkeypatch)
    planner, delegate = _delegated_planner(registry, DETECTION)
    context = node_context(guardian, model=ScriptedClient(_two_task_script()))
    context.executor_delegate = delegate

    result = planner(context, DETECTION)

    assert result.outcome == PHASE_OUTCOMES[0], f"{result.outcome!r}: {result.summary!r}"
    assert len(created) >= 2, (
        f"only {len(created)} per-task state object(s) were built for two delegated tasks; "
        "bounded execution builds one fresh object per task, not one for the whole phase"
    )
    assert surviving(created) == [], (
        "a per-task state object built by a delegated task is still reachable after the phase "
        "returned. Every task's state must be unreachable once the phase is over, exactly as it "
        "already is for a standalone bounded-execution node"
    )


# --------------------------------------------------------------------------------------------
# No standing credential: the token is a call argument
# --------------------------------------------------------------------------------------------


def test_the_client_exposes_no_attribute_holding_a_token_after_a_submission(
    guardian: InProcessGuardian,
) -> None:
    """Enumerate the client's own attributes after a real submission and find only the transport.

    ``guardian_client.py``: "GuardianClient holds a base URL and a transport, and that is the whole
    of its state." Both the instance dictionary and any declared slots are checked, because a class
    that grew ``__slots__`` would hide a cached credential from an inspection of ``__dict__``
    alone -- and the slots check is written to be vacuous today and correct tomorrow rather than
    added on the day it is needed.
    """
    minted = guardian.mint()
    assert isinstance(minted, Mapping), (
        f"the Guardian refused to mint the token this case spends: {minted!r}. Every claim below "
        "is about what the client does with a token, so a failure to obtain one is not this case's "
        "finding -- see test_guardian_seam.py for the issuance seam itself"
    )
    presented = str(minted["token"])
    client = guardian.client

    answer = client.submit_action(
        token=presented,
        request_id=f"{guardian.config.run_id}-containment-001",
        run_id=str(guardian.config.run_id),
        executor_id=EXECUTOR_ID,
        phase=CONTAINMENT,
        verb="get",
        resource="pods",
        namespace=NAMESPACE,
        name=None,
        params={},
        justification="read the workload the evidence names",
    )

    assert isinstance(answer, Mapping), (
        f"the Guardian reached no decision ({answer!r}); this case needs a submission that "
        "completed, because a client that never sent the token could hold none by accident"
    )
    # SEAM 6 widened the client's state by exactly one attribute, and the assertion is widened by
    # exactly as much rather than loosened. `GuardianClient(transport, *, caller_auth=None)` takes
    # an opaque header *supplier* the runner injects for the control-plane routes; it is a callable,
    # never a value, it is requested per call and held nowhere, and the harness injects nothing, so
    # on this client it is None. The set is still an equality rather than a subset: a fourth
    # attribute
    # is a fourth thing this case has never examined, which is the failure mode the test exists for.
    assert set(vars(client)) == {"_transport", "_caller_auth"}, (
        f"GuardianClient's instance state after a submission is {sorted(vars(client))}. It is "
        "supposed to be the transport plus SEAM 6's caller-auth supplier and nothing else: FR3.1 "
        "forbids an Executor a standing credential, and a token cached on the client is exactly "
        "that, held for the lifetime of the client rather than of one call. Any other attribute is"
        " a "
        "field this case has never looked at"
    )
    assert vars(client)["_caller_auth"] is None, (
        f"the harness client's caller-auth supplier is {vars(client)['_caller_auth']!r}. This"
        " suite "
        "injects none -- the credential lives in the runner process and is a bearer header the "
        "Guardian verifies by TokenReview -- so a non-None value here would be a credential this "
        "test's own fixture put on the client"
    )
    declared_slots = tuple(getattr(type(client), "__slots__", ()))
    assert declared_slots == (), (
        f"GuardianClient now declares __slots__ {declared_slots}. That is not forbidden, but the "
        "attribute assertion above reads __dict__ and a slot is invisible to it -- extend this "
        "case to enumerate the slots before adding one"
    )
    assert presented not in str(vars(client)), (
        "the presented capability token appears in the client's instance state after the call that "
        "used it. The token is a parameter of submit_action and must not outlive the call"
    )


def test_no_object_reachable_from_the_client_holds_the_presented_token(
    guardian: InProcessGuardian,
) -> None:
    """Walk everything reachable from the client and find the token nowhere in it.

    The attribute check above is defeated by one indirection -- a token kept inside the transport,
    inside a closure cell, inside a cached request body. This walk has no such blind spot: it
    follows the interpreter's own reference graph, which at Tier A reaches through the ASGI
    transport into the entire in-process Guardian. That the token is absent from *that* graph as
    well is a stronger statement than the one this file needs, and it is the honest one to make:
    neither the client nor the Guardian retains the bearer string once the decision is recorded.
    """
    minted = guardian.mint()
    assert isinstance(minted, Mapping), f"the Guardian refused to mint: {minted!r}"
    presented = str(minted["token"])

    guardian.client.submit_action(
        token=presented,
        request_id=f"{guardian.config.run_id}-containment-001",
        run_id=str(guardian.config.run_id),
        executor_id=EXECUTOR_ID,
        phase=CONTAINMENT,
        verb="get",
        resource="pods",
        namespace=NAMESPACE,
        name=None,
        params={},
        justification="read the workload the evidence names",
    )

    holders = [text for text in reachable_strings(guardian.client) if presented in text]
    assert holders == [], (
        f"{len(holders)} reachable string(s) still contain the presented capability token after "
        "the call that spent it. Nothing downstream of the client may retain a bearer credential: "
        "guardian/app/models.py keeps it out of every audit model in the repository precisely so "
        "that a run bundle is born clean rather than sanitised afterwards"
    )


def test_the_reachability_walk_finds_a_planted_token(guardian: InProcessGuardian) -> None:
    """The adversarial control: a token hidden one closure deep is found, so the walk can fail.

    Without this, the previous case is indistinguishable from a walk that visits nothing. The
    credential is planted where a real one would most plausibly end up -- closed over by the
    transport, which is the one collaborator a client legitimately keeps -- rather than assigned to
    an obvious attribute, so what is demonstrated is that the walk sees past the indirection the
    attribute check cannot.
    """
    minted = guardian.mint()
    assert isinstance(minted, Mapping), f"the Guardian refused to mint: {minted!r}"
    presented = str(minted["token"])

    def leaky_transport(method: str, path: str, body: bytes) -> tuple[int, Any]:
        """A transport that closes over a credential. Never called; the closure is the point."""
        raise AssertionError(f"not for calling: {method} {path} {len(body)} {presented}")

    planted = GuardianClient(leaky_transport)

    holders = [text for text in reachable_strings(planted) if presented in text]
    assert holders != [], (
        "the reachability walk did not find a capability token closed over by the client's own "
        "transport. A scan that cannot fail is not evidence, and the preceding case's empty "
        "result would mean nothing if this one did not show the walk reaching that far"
    )


def test_the_token_reaches_neither_the_environment_nor_module_state(
    guardian: InProcessGuardian, registry: PromptRegistry
) -> None:
    """Run a real mint-then-act phase and find the token in no environment variable and no global.

    ``agents/graphs/nodes.py`` holds a minted token on the context for exactly one hop and deletes
    the attribute when the Executor takes it. All three of the places a credential could
    plausibly be parked are checked here -- the process environment, the node module's globals, and
    the context itself -- because the one that is left out is the one a future convenience will
    reach for.
    """
    planned, acted, context = run_one_action_phase(guardian, registry, CONTAINMENT)

    assert planned.actions, (
        f"the Supervisor minted nothing in this phase ({planned.outcome!r}); with no token issued "
        "there is no credential to look for and the assertions below would pass vacuously"
    )
    issued_jti = planned.actions[0].get("jti")
    assert issued_jti, (
        f"the issuance record carries no jti: {planned.actions[0]!r}. The Guardian refused to "
        "mint, so this case cannot say anything about where a token went"
    )
    assert acted.actions, (
        f"the Executor submitted nothing ({acted.outcome!r}); a token that was never presented "
        "cannot demonstrate that presenting one leaves no trace"
    )

    assert take_token(context) == "", (
        "the minted capability token is still pending on the NodeContext after the Executor ran. "
        "agents/graphs/nodes.py holds it for exactly one hop and take_token removes it; a token "
        "still there is a credential the next node inherits without ever being handed one"
    )
    leaked_env = sorted(key for key, value in os.environ.items() if issued_jti in value)
    assert leaked_env == [], (
        f"the minted token's jti appears in environment variable(s) {leaked_env}. Nothing in the "
        "agent layer may write a credential into the environment: FR3.1's 'no standing "
        "credentials' is about what is visible to executor code, and the environment is the most "
        "visible thing there is"
    )
    globals_holding = sorted(
        name
        for name, value in vars(nodes).items()
        if isinstance(value, str) and issued_jti in value
    )
    assert globals_holding == [], (
        f"agents.graphs.nodes now holds the minted token in module global(s) {globals_holding}. "
        "Module state outlives every phase in the process, so a token parked there is standing by "
        "definition"
    )


def test_a_spent_capability_cannot_submit_a_second_action(
    guardian: InProcessGuardian, registry: PromptRegistry
) -> None:
    """One-shot authority means one Guardian decision, even if the model proposes another action."""
    composition = composed_composition(registry)
    executor = bounded_execution_node(
        compose_condition(registry, CONDITION).role("executor"),
        budget=composition.budgets[CONTAINMENT]["executor"],
        tools=[ACTION_TOOL.name, COMPLETE_PHASE_TOOL.name],
    )
    context = node_context(
        guardian,
        model=ScriptedClient([ACTION_ANSWER, ACTION_ANSWER]),
    )
    minted = guardian.mint(phase=CONTAINMENT, verbs=("get",), resources=("pods",))
    assert isinstance(minted, Mapping)
    nodes._stash_token(context, str(minted["token"]))

    result = executor(context, CONTAINMENT)

    assert len(result.actions) == 1, (
        f"the Executor submitted {len(result.actions)} actions with one single-use capability; "
        "offering guardian_action again turns the next model turn into a replay denial"
    )
    assert len(guardian.audit_records()) == 1
    assert guardian.audit_records()[0]["reason_code"] != "replay.jti-spent"


def test_no_capability_token_is_reused_across_phases(
    guardian: InProcessGuardian, registry: PromptRegistry
) -> None:
    """Two phases, two mints, two distinct bearer strings on the wire and two jti in the chain.

    FR3.2 scopes a capability to one phase, and ``guardian/app/models.py`` makes a token presented
    in another phase ``scope.phase-mismatch``. A graph that minted once and reused the credential
    would therefore be *caught* by the Guardian rather than silently permitted -- but it would be
    caught as a denial in the middle of a run, which is a much worse place to learn it than here.
    The assertions read the bytes the client sent and the ``token_jti`` the audit chain recorded, so
    neither side of the seam is taken on trust.
    """
    sent, transport = recording_transport(guardian)
    context = node_context(
        guardian,
        model=ScriptedClient(
            [
                MINT_ANSWER,
                COMPLETE_ANSWER,
                ACTION_ANSWER,
                COMPLETE_ANSWER,
                MINT_ANSWER,
                COMPLETE_ANSWER,
                ACTION_ANSWER,
                COMPLETE_ANSWER,
            ]
        ),
    )
    context.guardian = GuardianClient(transport)

    minted_jti: list[str] = []
    for phase in (CONTAINMENT, ERADICATION):
        planned, acted, _ = run_one_action_phase(guardian, registry, phase, context=context)
        assert planned.actions and planned.actions[0].get("jti"), (
            f"phase {phase!r} minted nothing: {planned.outcome!r} {planned.actions!r}"
        )
        assert acted.actions, f"phase {phase!r} submitted no action: {acted.outcome!r}"
        minted_jti.append(str(planned.actions[0]["jti"]))

    presented = [
        str(entry["body"]["token"]) for entry in sent if entry["path"].endswith("/actions")
    ]
    assert len(presented) == 2, (
        f"{len(presented)} action request(s) reached the wire across two phases; this case needs "
        "exactly one per phase to compare the credentials they carried"
    )
    assert presented[0] != presented[1], (
        "both phases presented the same bearer string. A capability token is scoped to one phase "
        "(FR3.2), so reuse across phases is not a saving -- it is an Executor acting in one phase "
        "with authority granted for another"
    )
    assert len(set(minted_jti)) == 2, (
        f"the two phases recorded the same issuance identifier {minted_jti}; each phase's "
        "Supervisor mints its own scope"
    )
    spent = [record["token_jti"] for record in guardian.audit_records() if record["token_jti"]]
    assert spent == minted_jti, (
        f"the audit chain records tokens {spent} spent, and the Supervisors minted {minted_jti}. "
        "The chain is the evidence and the phase results are the trace; a run whose two disagree "
        "is a finding rather than a nuisance"
    )


# --------------------------------------------------------------------------------------------
# The ledger is per role and per phase
# --------------------------------------------------------------------------------------------


def test_two_ledgers_opened_for_one_phase_do_not_share_an_allocation(
    registry: PromptRegistry,
) -> None:
    """Open the Supervisor's and the Executor's ledgers for one phase and spend from one only.

    ``BudgetLedger``'s docstring: "two roles spending from one ledger would let a Supervisor's
    planning turns be consumed by an Executor, and the per-phase parity assertion would then be
    comparing a number nothing enforced." Both allocations are the manifest's own, so what is
    checked is the arrangement ``make parity-check`` reads rather than an invented pair.
    """
    composition = composed_composition(registry)
    phase = CONTAINMENT
    planner_id = hier.order(composition, phase)[1]
    planner_budget = composition.budgets[phase][planner_id]
    executor_budget = composition.budgets[phase]["executor"]

    planner_ledger = BudgetLedger.of(role_id=planner_id, phase=phase, budget=planner_budget)
    executor_ledger = BudgetLedger.of(role_id="executor", phase=phase, budget=executor_budget)
    planner_ledger.spend_turns(planner_budget.max_turns)

    assert planner_ledger is not executor_ledger, (
        "one ledger object was handed to both roles; a ledger is opened per role per phase"
    )
    assert planner_ledger.turns_remaining == 0, (
        f"the Supervisor's ledger reports {planner_ledger.turns_remaining} turn(s) left after "
        f"spending its whole allocation of {planner_budget.max_turns}"
    )
    assert executor_ledger.turns_remaining == executor_budget.max_turns, (
        f"the Executor's ledger fell to {executor_ledger.turns_remaining} of "
        f"{executor_budget.max_turns} turn(s) because the *Supervisor* spent its own allocation. "
        "The two roles are budgeted separately by the composition manifest and must be spent "
        "separately, or a phase's parity numbers describe an enforcement that does not exist"
    )
    assert executor_ledger.tool_calls_remaining == executor_budget.max_tool_calls, (
        "the Executor's tool-call allocation moved when only the Supervisor's turns were spent"
    )


def test_a_role_carries_no_ledger_between_phases(
    guardian: InProcessGuardian, registry: PromptRegistry
) -> None:
    """Run one Executor node object through two phases and assert the second starts full.

    The node is a closure built once and called twice, which is the arrangement most likely to leak
    state between phases: a ledger hoisted out of ``run`` into the enclosing scope would be shared
    by every phase that node served, and the symptom would be a late phase reporting
    ``budget-exhausted`` for turns an earlier phase spent.
    """
    composition = composed_composition(registry)
    budget = composition.budgets[CONTAINMENT]["executor"]
    other_budget = composition.budgets[ERADICATION]["executor"]
    executor = bounded_execution_node(
        compose_condition(registry, CONDITION).role("executor"),
        budget=budget,
        tools=[ACTION_TOOL.name, COMPLETE_PHASE_TOOL.name],
    )
    context = node_context(guardian, model=ScriptedClient([COMPLETE_ANSWER, COMPLETE_ANSWER]))

    first = executor(context, CONTAINMENT)
    second = executor(context, ERADICATION)

    assert first.turns_spent == 1, (
        f"the first phase spent {first.turns_spent} turn(s) for one scripted answer; the "
        "arithmetic below compares against this baseline"
    )
    assert second.turns_spent == first.turns_spent, (
        f"the second phase reports {second.turns_spent} turn(s) spent against the first's "
        f"{first.turns_spent}, for the same single answer. A ledger is opened per phase from the "
        "manifest's declared allocation; accumulation across phases means one object is being "
        "reused, and every later phase in a run would be short of the budget it was granted"
    )
    assert second.outcome != BUDGET_EXHAUSTED, (
        f"the second phase ended {second.outcome!r} on its first answer, which is what a carried-"
        f"over ledger looks like when the earlier phase spent an allocation of {budget.max_turns} "
        f"and this phase was granted {other_budget.max_turns}"
    )


# --------------------------------------------------------------------------------------------
# Retry accounting -- ADR-028
# --------------------------------------------------------------------------------------------


def test_a_call_that_took_three_attempts_costs_three_turns(
    guardian: InProcessGuardian, registry: PromptRegistry
) -> None:
    """One expensive call and one cheap one: four turns spent, and both reported.

    ADR-028: "a model that emitted two malformed tool calls before a good one has spent three
    turns". Without this, an arm whose model stumbles would silently receive more turns than an arm
    whose model does not, and the structure ablation would be reading model weakness as a design
    difference -- risk R-10's mitigation made countable rather than described.
    """
    composition = composed_composition(registry)
    executor = bounded_execution_node(
        compose_condition(registry, CONDITION).role("executor"),
        budget=composition.budgets[CONTAINMENT]["executor"],
        tools=[ACTION_TOOL.name, COMPLETE_PHASE_TOOL.name],
    )
    context = node_context(
        guardian,
        model=RetryingClient([ACTION_ANSWER, COMPLETE_ANSWER], attempts=[3, 1]),
    )

    result = executor(context, CONTAINMENT)

    assert result.outcome == PHASE_OUTCOMES[0], (
        f"the phase ended {result.outcome!r} rather than completing; this case is about what a "
        f"completed phase cost. Summary: {result.summary!r}"
    )
    assert result.turns_spent == 4, (
        f"the phase spent {result.turns_spent} turn(s) for a call that took three attempts "
        "followed by one that took one. A retry is a turn (ADR-028): counting the answer rather "
        "than the attempts would report 2 here and would hand every stumbling model a discount "
        "nothing in the budget accounts for"
    )
    assert result.model_attempts == 4, (
        f"the result reports {result.model_attempts} attempt(s); the phase result carries what was "
        "spent so that a run bundle records the retry rate rather than only its consequences"
    )
    assert result.malformed_calls == 2, (
        f"the result reports {result.malformed_calls} malformed call(s) against two malformed "
        "attempts on the first call. That count is R-10's raw measurement and analysis/ reads it"
    )


def test_an_exhausted_turn_budget_is_a_recorded_outcome_and_never_an_exception(
    guardian: InProcessGuardian, registry: PromptRegistry
) -> None:
    """A call that costs more turns than remain returns ``budget-exhausted`` rather than raising.

    ADR-028 again, and the reason is about what an ablation measures: "an arm that struggled must
    look bounded rather than broken, or the ablation reads model weakness as a design failure". An
    escaping :class:`~agents.graphs.nodes.BudgetExhausted` would abort the phase, the run and the
    bundle, and the arm would be recorded as a crash instead of as a bounded refusal.
    """
    executor = bounded_execution_node(
        compose_condition(registry, CONDITION).role("executor"),
        budget=Budget(max_turns=2, max_tool_calls=4),
        tools=[ACTION_TOOL.name, COMPLETE_PHASE_TOOL.name],
    )
    context = node_context(guardian, model=RetryingClient([ACTION_ANSWER], attempts=[3]))

    result = executor(context, CONTAINMENT)

    assert isinstance(result, PhaseResult), (
        f"the node returned {type(result).__name__}; every node boundary turns a spent allocation "
        "into a result"
    )
    assert result.outcome == BUDGET_EXHAUSTED, (
        f"a call costing three turns against an allocation of two ended {result.outcome!r}. The "
        f"outcome vocabulary is closed ({', '.join(PHASE_OUTCOMES)}) and a spent budget has its "
        "own member precisely so that it is countable in Chapter 4 rather than indistinguishable "
        "from a phase that was blocked for a reason of substance"
    )
    assert result.turns_spent == 3, (
        f"the result reports {result.turns_spent} turn(s) spent. The overspend is recorded rather "
        "than clamped: what a run bundle needs to show is that the allocation was exceeded and by "
        "how much, not a number tidied back to the limit"
    )


def test_a_node_never_acts_on_an_answer_that_arrived_outside_its_budget(
    guardian: InProcessGuardian, registry: PromptRegistry
) -> None:
    """The model produced a well-formed action on the attempt that broke the budget; nothing ran.

    This is the ordering claim in :func:`~agents.graphs.nodes._ask` -- turns are spent **after** the
    call returns and **before** the answer is used -- and it is the one part of ADR-028 that leaves
    no trace when it is wrong. A node that used the answer first and charged for it afterwards
    would produce identical phase results, identical turn counts and one extra row in the
    Guardian's audit chain, and the audit chain is what
    ``docs/protocols/evaluation-protocol.md`` section 3 computes both RQ5 measures from. So the
    assertion is on the chain: an action taken outside a declared budget is an action the Guardian
    recorded.
    """
    before = len(guardian.audit_records())
    executor = bounded_execution_node(
        compose_condition(registry, CONDITION).role("executor"),
        budget=Budget(max_turns=2, max_tool_calls=4),
        tools=[ACTION_TOOL.name, COMPLETE_PHASE_TOOL.name],
    )
    context = node_context(guardian, model=RetryingClient([ACTION_ANSWER], attempts=[3]))

    result = executor(context, CONTAINMENT)

    assert result.outcome == BUDGET_EXHAUSTED, (
        f"the phase ended {result.outcome!r}; this case needs the budget to have been exceeded "
        "before it can say anything about what happened to the answer"
    )
    assert result.actions == (), (
        f"the phase recorded {len(result.actions)} action(s) although its turn budget was spent "
        "before the answer could be used. The model's answer arrived on an attempt the budget did "
        "not cover, so it is not an answer the node was entitled to act on"
    )
    assert len(guardian.audit_records()) == before, (
        f"the Guardian's audit chain grew from {before} to {len(guardian.audit_records())} "
        "record(s) during a phase whose budget was spent before any action could be submitted. A "
        "row here means the node acted on an over-budget answer: the turns must be spent after the "
        "call returns and before the answer is used, or a budget bounds nothing"
    )


def test_an_exhausted_tool_call_budget_stops_the_action_before_the_guardian_sees_it(
    guardian: InProcessGuardian, registry: PromptRegistry
) -> None:
    """The second declared allocation, checked the same way: no tool calls left, no request sent.

    ``max_turns`` and ``max_tool_calls`` are separate numbers in every composition manifest and
    ``make parity-check`` compares both. A node that enforced only the first would pass every case
    above while letting a phase make unlimited requests within its turns, which is the allocation
    that actually bounds what reaches the cluster.
    """
    before = len(guardian.audit_records())
    executor = bounded_execution_node(
        compose_condition(registry, CONDITION).role("executor"),
        budget=Budget(max_turns=4, max_tool_calls=0),
        tools=[ACTION_TOOL.name, COMPLETE_PHASE_TOOL.name],
    )
    context = node_context(guardian, model=ScriptedClient([ACTION_ANSWER, COMPLETE_ANSWER]))

    result = executor(context, CONTAINMENT)

    assert result.outcome == BUDGET_EXHAUSTED, (
        f"an action offered against an allocation of zero tool calls ended {result.outcome!r}; a "
        "spent tool-call budget is the same recorded outcome as a spent turn budget"
    )
    assert result.tool_calls_spent == 1, (
        f"the result reports {result.tool_calls_spent} tool call(s) spent; the attempt is recorded "
        "even though it was refused, for the reason the turn overspend is"
    )
    assert len(guardian.audit_records()) == before, (
        f"the audit chain grew from {before} to {len(guardian.audit_records())} record(s) although "
        "the phase had no tool-call allocation left. The Guardian saw a request the composition "
        "manifest did not grant"
    )


# --------------------------------------------------------------------------------------------
# D1-A: the direct credential path is a runner-injected transport, and this layer opens nothing
# --------------------------------------------------------------------------------------------
#
# WHY THIS FILE, AND WHY IT IS ABOUT EXISTENCE
# ---------------------------------------------
# `agents/tools/registry.py` is where the tool is defined; this is where it is shown to *do* only
# what
# it was handed. D1-A admits exactly one alternate mutation path to iron rule 1: the
# `cluster_api_request` tool, whose handler calls a transport the runner injects and which lives
# outside `agents/`. Two properties make that an amendment rather than a loophole, and both are
# properties of the *absence* of code rather than of its presence:
#
# * with no transport injected there is no path at all -- the handler refuses, the refusal is
#   recorded, and the model is told. Every arm but G2-SHAREDCRED, and every offline run, is in this
#   state, so "the tool exists in every arm" (parity) and "the path exists in one arm" (the arm
#   question) are not in tension;
# * nothing under `agents/` opens the credential file. `bearer_token_file` is a *path the model
#   names*; `runner/egress_shim.py` is the layer that reads it, and the last case here asserts at
# the
#   syntax tree that the agent layer has no file-opening call at all for it to use.


CLUSTER_REQUEST = ToolCall(
    name=CLUSTER_API_TOOL.name,
    arguments={
        "method": "GET",
        "path": "/api/v1/namespaces/boutique/pods",
        "body": None,
        "bearer_token_file": "/var/run/secrets/overwatch/g2-executor/token",
    },
)


def test_cluster_api_request_handler_uses_injected_transport_only(
    guardian: InProcessGuardian,
) -> None:
    """The handler calls the transport it was handed, and nothing else, on both the two paths.

    Case (a) is the one that matters for the ablation and it is a *refusal*: no transport injected,
    so the only reachable outcome is a structured ``no_cluster_api_transport``. A registry that
    quietly built a transport of its own -- the obvious way to make the tool work everywhere --
    would
    put a network client inside `agents/`, which is precisely what iron rule 1's amendment forbids
    and
    what `scripts/grep_guard.sh` scans for on every pull request.

    Case (b) is that the injected callable receives the model's four arguments *by keyword*. The
    names are asserted because they are the seam contract: `runner/egress_shim.py` is written
    against them, and a positional call or a renamed keyword would be a transport the runner cannot
    supply. The returned status is read back to the model and recorded in ``task.actions``, so a
    direct-path action is visible in ``results.json`` as a trace -- while its *effect* is measured
    off the API-server audit (WS-4), never trusted from here.
    """
    sent: list[Mapping[str, Any]] = []

    def transport(**request: Any) -> Mapping[str, Any]:
        sent.append(request)
        return {"status": 403, "body": {"kind": "Status"}}

    close = ToolCall(
        name=COMPLETE_PHASE_TOOL.name,
        arguments={"outcome": PHASE_OUTCOMES[0], "summary": "closed"},
    )
    registry = load_registry()
    role = compose_condition(registry, CONDITION).role("executor")

    # (a) nothing injected: a refusal, recorded and reported to the model.
    without = ScriptedClient([CLUSTER_REQUEST, close])
    refused = bounded_execution_node(
        role,
        budget=Budget(max_turns=4, max_tool_calls=4),
        tools=[ACTION_TOOL.name, CLUSTER_API_TOOL.name, COMPLETE_PHASE_TOOL.name],
    )(
        node_context(guardian, model=without, cluster_api_transport=None),
        CONTAINMENT,
    )

    refusals = [action for action in refused.actions if action.get("kind") == "cluster-request"]
    assert refusals == [
        {
            "kind": "cluster-request",
            "transported": False,
            "error": "no_cluster_api_transport",
            "method": CLUSTER_REQUEST.arguments["method"],
            "path": CLUSTER_REQUEST.arguments["path"],
        }
    ], (
        f"with no transport injected the handler recorded {refusals!r}. The only possible outcome "
        "without a runner-injected transport is a structured refusal: a handler that built a "
        "transport of its own would put a network client inside agents/, which is what iron rule "
        "1's D1-A amendment forbids"
    )
    assert "no_cluster_api_transport" in without.calls[1].context, (
        f"the model was not told the request was refused:\n{without.calls[1].context}\nA tool the "
        "model cannot use must say so, or it will call it again"
    )

    # (b) a transport injected: called once, with the four named arguments, and its status reported.
    with_transport = ScriptedClient([CLUSTER_REQUEST, close])
    answered = bounded_execution_node(
        role,
        budget=Budget(max_turns=4, max_tool_calls=4),
        tools=[ACTION_TOOL.name, CLUSTER_API_TOOL.name, COMPLETE_PHASE_TOOL.name],
    )(
        node_context(guardian, model=with_transport, cluster_api_transport=transport),
        CONTAINMENT,
    )

    assert sent == [dict(CLUSTER_REQUEST.arguments)], (
        f"the injected transport received {sent!r}. runner/egress_shim.py is written against these "
        "four keyword names, so a positional call or a renamed keyword is a transport the runner "
        "cannot supply"
    )
    carried = [action for action in answered.actions if action.get("kind") == "cluster-request"]
    assert carried == [
        {
            "kind": "cluster-request",
            "transported": True,
            "method": CLUSTER_REQUEST.arguments["method"],
            "path": CLUSTER_REQUEST.arguments["path"],
            "status": 403,
        }
    ], f"the transported request was recorded as {carried!r}"
    assert "status 403" in with_transport.calls[1].context, (
        f"the transport's status did not reach the model:\n{with_transport.calls[1].context}"
    )


def test_no_shipped_graph_module_opens_the_credential_the_direct_path_names() -> None:
    """Nothing in ``agents/graphs/`` opens a file, so nothing there can read the G2 token.

    D1-A's rule is "the shim reads it, the agent layer never opens it", and an assertion about the
    absence of a call is the only way to hold that. A grep for ``bearer_token_file`` would find the
    schema, the handler's argument pass and the prompt text and prove nothing; what matters is
    whether the module that *receives* the path can read it, and a call to ``open``,
    ``Path.read_text``, ``Path.read_bytes`` or ``Path.open`` is the whole of that ability.

    Scoped to ``agents/graphs/`` rather than to every shipped module, and the scope is the claim
    rather than a convenience: ``agents/registry/loader.py`` and ``agents/registry/digest.py`` read
    the prompt registry, which is what they are for, and ``agents/golden.py`` reads the evidence
    bundle. Those are not places a model-supplied path could reach. The *graph* package is the one
    that builds a tool call's arguments into a request, so it is the one where a file-opening call
    would be a credential read.

    Asserted on the syntax tree rather than on the text, so a name that appears in a docstring does
    not fire it, and paired with a control that plants the call and asserts the scan sees it -- a
    negative result from a scanner that has never matched anything is the disease this file exists
    to
    prevent.
    """
    offenders: list[str] = []
    scanned = 0
    for path in sorted((REPO_ROOT / "agents" / "graphs").rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        scanned += 1
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            name = (
                function.attr
                if isinstance(function, ast.Attribute)
                else function.id
                if isinstance(function, ast.Name)
                else None
            )
            if name in FILE_READING_CALLS:
                offenders.append(f"{path.relative_to(REPO_ROOT).as_posix()}:{node.lineno} {name}()")
    assert scanned, "no module was found under agents/graphs/; this scan would then prove nothing"
    assert not offenders, (
        f"a graph module calls a file-opening function at {offenders}. D1-A's amendment is that "
        "`agents/` never opens the credential the direct-path tool names: the path is a string the "
        "model supplies and runner/egress_shim.py is the layer that reads it, which is what keeps "
        "the token out of the model even on the arm where the path exists"
    )

    # The control: the scan recognises the call it is looking for, so the clean result above is
    # evidence and not an empty list.
    planted = (
        "import pathlib\n\n\ndef read(path: str) -> bytes:\n    return open(path, 'rb').read()\n"
    )
    tree = ast.parse(planted)
    found = [
        node.func.id if isinstance(node.func, ast.Name) else node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
    ]
    assert set(found) & FILE_READING_CALLS, (
        f"the scan found {found} in a source that plainly opens a file, so the clean result above "
        "says nothing about whether the graph layer can read a credential"
    )
