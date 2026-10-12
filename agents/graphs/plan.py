r"""The wiring a topology declares, and the LangGraph it becomes -- separated on purpose.

WHAT THIS MODULE IS
-------------------
A :class:`GraphPlan` is the answer to "which role runs, in which phase, in what order". It is a
value, it is built from a composition manifest and a per-topology ordering rule, and it holds no
LangGraph object at all. :func:`build_state_graph` is what turns one into a runnable graph.

The split exists for two reasons, and the first is a hard constraint.

*The parity gate installs nothing.* ``scripts/parity_check.sh`` runs in ``ci.yml``'s
``guardrail-grep`` job, which has no Python dependency step (conflict M4-C1), and
``agents/registry/`` is standard-library only so that it can. If a topology module reached
LangGraph at import, the import chain from the gate to the composer would eventually reach it too.
A plan is standard library; only :func:`build_state_graph` is not, and nothing on the gate's path
calls it.

*A plan is what a reader checks.* "S1-HIER runs coordination, then this phase's planning node, then
bounded execution, then consolidation -- four times, once per phase" is a claim somebody should be
able to verify by looking at a data structure, not by reading a graph builder's edge calls.
:func:`GraphPlan.describe` prints it, and ``agents/tests/test_graphs.py`` asserts over it without
needing the runtime installed.

WHY THE STEPS ARE FLAT AND NOT NESTED
---------------------------------------
A plan is a flat, ordered tuple of ``(phase, role_id)`` steps rather than a mapping from phase to
roles. Two consequences, both wanted. The traversal order is the tuple's order, so "four phase spans
present **in order**" -- traceability row T-05's actual wording -- is a property of the value rather
than of how a builder happened to iterate. And a topology that ran a role in one phase and not
another needs no special case: it simply emits fewer steps, which is exactly what ``S1-HIER`` does
with its four Supervisors.

WHAT A PLAN IS NOT ALLOWED TO CONTAIN
---------------------------------------
No condition string reaches a node. :func:`plan_for` takes the condition to look the manifest up
and then never passes it on: a :class:`GraphStep` carries a phase and a role id, and
:mod:`agents.graphs.nodes` never sees which arm it is in. ADR-027 rejects a condition parameter
inside node behaviour outright, because the branch would be the confound and it would be invisible
to a gate that compares registries rather than control flow.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Final

from agents.graphs.nodes import NodeContext, PhaseResult, build_node
from agents.registry import PHASES
from agents.registry.composer import ComposedCondition, compose_condition
from agents.registry.loader import Composition, PromptRegistry, RegistryError

__all__ = (
    "GraphPlan",
    "GraphStep",
    "PhaseRoleOrder",
    "build_state_graph",
    "plan_for",
    "run_plan",
)

# A topology's ordering rule: given the composition and a phase, which roles run and in what order.
# A callable rather than a table, because S1-HIER's answer depends on the phase -- only that phase's
# own Supervisor participates -- and a table would have to spell four nearly identical rows.
PhaseRoleOrder = Callable[[Composition, str], Sequence[str]]

# The LangGraph node name for one step. Derived from the step rather than chosen, so that two steps
# can never collide and a span name in a trace can be matched to a graph node by eye.
_NODE_NAME: Final = "{phase}__{role_id}"


@dataclass(frozen=True)
class GraphStep:
    """One role running in one phase. The unit a plan is a sequence of."""

    phase: str
    role_id: str

    @property
    def node_name(self) -> str:
        """The name this step takes as a graph node."""
        return _NODE_NAME.format(phase=self.phase, role_id=self.role_id)


@dataclass(frozen=True)
class GraphPlan:
    """One topology's whole traversal: every step, in order, with the composition behind it.

    ``composed`` is kept because a step's node needs its role's composed prompt and its declared
    budget, and looking both up from one object is what keeps "the graph sends what the gate
    counted" true -- the same :class:`~agents.registry.composer.ComposedCondition` serves both.
    """

    condition: str
    steps: tuple[GraphStep, ...]
    composed: ComposedCondition
    composition: Composition

    def phases(self) -> tuple[str, ...]:
        """The phases this plan traverses, in traversal order, each once.

        Row T-05 closes on four phase spans "present in order", so this is the value that claim is
        checked against.
        """
        seen: list[str] = []
        for step in self.steps:
            if step.phase not in seen:
                seen.append(step.phase)
        return tuple(seen)

    def describe(self) -> str:
        """Return the plan as text, one line per step. For a reader and for a failure message."""
        lines = [f"{self.condition}: {len(self.steps)} step(s)"]
        lines.extend(f"  {step.phase:<28} {step.role_id}" for step in self.steps)
        return "\n".join(lines) + "\n"


def plan_for(registry: PromptRegistry, condition: str, order: PhaseRoleOrder) -> GraphPlan:
    """Build the plan for ``condition``, traversing the four phases in section 1.6's order.

    Every topology traverses all four. FR2.2 requires phase coverage and FR5.1 requires the run to
    progress through them, and neither is a property a topology may opt out of -- what a topology
    decides is how many roles are involved in each phase, which is what ``order`` answers.
    """
    try:
        composition = registry.compositions[condition]
    except KeyError:
        raise RegistryError(
            f"no composition manifest for {condition!r}; the registry declares "
            f"{', '.join(sorted(registry.compositions)) or 'none'}"
        ) from None

    steps: list[GraphStep] = []
    for phase in PHASES:
        for role_id in order(composition, phase):
            composition.role(role_id)  # raises with a useful message if the manifest lacks it
            if phase not in composition.budgets or role_id not in composition.budgets[phase]:
                raise RegistryError(
                    f"{condition}: role {role_id!r} runs in phase {phase!r} but the manifest "
                    "declares no budget for it there. A role that acts without a declared "
                    "allocation is a role make parity-check cannot compare and the runtime cannot "
                    "bound"
                )
            steps.append(GraphStep(phase=phase, role_id=role_id))

    return GraphPlan(
        condition=condition,
        steps=tuple(steps),
        composed=compose_condition(registry, condition),
        composition=composition,
    )


def run_plan(
    plan: GraphPlan,
    context: NodeContext,
    *,
    on_step: Callable[[GraphStep], None] | None = None,
    on_result: Callable[[PhaseResult], None] | None = None,
) -> tuple[PhaseResult, ...]:
    """Execute every step in order and return each result. The runtime-free driver.

    Published beside :func:`build_state_graph` and used by ``agents/tests/`` and by the golden path
    at Tier A, because a driver that needs no runtime installed is what makes "offline, no network,
    no Docker, no credential" an honest description of that tier. The LangGraph build below wires
    the same node callables in the same order over the same context, so a Tier A pass is evidence
    about the thing Tier B runs rather than about a substitute for it.

    The phase span wraps every step of that phase, so a trace carries four phase spans containing
    the node spans beneath them -- which is the nesting row T-05 reads.

    ``on_step`` is called with each step immediately before it runs, and exists for one caller:
    ``agents/golden.py``'s recorder, which has to attribute a model call to the step that made it.
    ``on_result`` is called immediately after a step returns, so that caller can retain the
    genuinely completed prefix if a later model call fails. Both are **notifications**, never
    interceptions --
    neither can change what runs or in what order. A hook that could would be a place a topology's
    traversal could be altered from outside the plan, and the plan being the whole of the traversal
    is what makes :meth:`GraphPlan.describe` a claim a reader can check.

    SEAM 6: at each phase change, before that phase's first node runs, this calls
    :attr:`~agents.graphs.nodes.NodeContext.declare_phase` when the runner has provided one, so the
    Guardian is told the run's *actual* phase and can refuse an issuance whose declared phase is not
    the current one (V17). It is None-safe -- the golden path and every Tier A test leave it None
    and
    the call is skipped -- and the control credential the runner's implementation authenticates that
    POST with lives in the runner: what reaches ``agents/`` is an opaque callable, never the token.
    """
    results: list[PhaseResult] = []
    context.completed_results = ()
    current_phase: str | None = None
    phase_span = None
    stack: list[Any] = []
    try:
        for step in plan.steps:
            if step.phase != current_phase:
                while stack:
                    stack.pop().__exit__(None, None, None)
                current_phase = step.phase
                phase_span = context.tracer.span("phase", phase=step.phase)
                phase_span.__enter__()
                stack.append(phase_span)
                # Announce the phase to the runner's control plane before this phase's first node
                # runs. None-safe by design: no field on NodeContext carries the credential, only
                # this opaque callable, and its absence is the ordinary offline shape.
                if context.declare_phase is not None:
                    context.declare_phase(step.phase)
            if on_step is not None:
                on_step(step)
            node = _node_for(plan, step)
            result = node(context, step.phase)
            results.append(result)
            context.completed_results = _completed_results(plan, results)
            if on_result is not None:
                on_result(result)
    finally:
        while stack:
            stack.pop().__exit__(None, None, None)
    return tuple(results)


def _node_for(plan: GraphPlan, step: GraphStep) -> Callable[[NodeContext, str], PhaseResult]:
    """Instantiate the behaviour one step needs, bound to its composed prompt and its budget."""
    role = plan.composed.role(step.role_id)
    declared = plan.composition.roles
    tools = next(entry.tools for entry in declared if entry.role_id == step.role_id)
    return build_node(role, budget=plan.composition.budgets[step.phase][step.role_id], tools=tools)


def _completed_results(
    plan: GraphPlan, results: Sequence[PhaseResult]
) -> tuple[tuple[str, PhaseResult], ...]:
    return tuple((plan.composed.role(result.role_id).node, result) for result in results)


def build_state_graph(plan: GraphPlan, context: NodeContext) -> Any:
    """Compile ``plan`` into a LangGraph application. Imports LangGraph, and nothing above it does.

    ADR-002 chose LangGraph, and this is where the choice becomes concrete: each step is a graph
    node, the steps are chained in plan order, and the state carries the accumulating results. The
    import is inside the function rather than at module scope for the reason the package docstring
    gives -- the parity gate's import chain must never reach a runtime dependency.

    The graph is deliberately a chain rather than a fan-out. FR5.1 requires the run to *progress*
    through the four phases, containment after detection and eradication after containment, and a
    topology that ran phases concurrently would not be responding to an incident in the order the
    lifecycle defines. Parallelism inside a phase -- ``S1-HIER``'s "spawning parallel Executors" --
    is a scenario-breadth question that M5 opens, and adding it here before there is a scenario that
    needs it would be a graph shape nothing tests.
    """
    from langgraph.graph import END, START, StateGraph  # noqa: PLC0415 - see the docstring

    graph: Any = StateGraph(dict)
    nodes = {step.node_name: _node_for(plan, step) for step in plan.steps}

    def make_step(step: GraphStep) -> Callable[[dict[str, Any]], dict[str, Any]]:
        def run(state: dict[str, Any]) -> dict[str, Any]:
            context.completed_results = _completed_results(plan, state.get("results", []))
            result = nodes[step.node_name](context, step.phase)
            results = [*state.get("results", []), result]
            context.completed_results = _completed_results(plan, results)
            return {"results": results}

        return run

    for step in plan.steps:
        graph.add_node(step.node_name, make_step(step))

    previous = START
    for step in plan.steps:
        graph.add_edge(previous, step.node_name)
        previous = step.node_name
    graph.add_edge(previous, END)
    return graph.compile()
