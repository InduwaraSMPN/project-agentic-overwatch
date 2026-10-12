r"""``S1-HIER`` -- the full hierarchy. Structure arm C1, and the arm ``G0-FULL`` shares.

WHAT THIS MODULE DECIDES
------------------------
One thing: **which roles run in a phase, and in what order**. Everything else -- what each role
says, which tools it holds, what it is allocated -- is read from
``agents/prompts/compositions/S1-HIER.yaml``, and the behaviour each role runs is instantiated from
:data:`agents.graphs.nodes.NODE_FACTORIES` by the ``node`` its manifest entry names. There is no
prompt text here, no tool definition here, and no condition parameter reaching a node: ADR-027
rejects the last outright, because a branch on the arm inside node behaviour would be the confound
and ``make parity-check`` -- which compares registries, not control flow -- could not see it.

THE ORDER, AND WHY IT IS THIS ORDER
-------------------------------------
Per phase: coordination, then that phase's own planning role, then bounded execution, then
consolidation. ``docs/02-architecture.md`` section 1 draws exactly that descent -- Orchestrator over
four phase Supervisors over ephemeral Executors -- and FR2.1 makes the Orchestrator's global view
the thing that enters a phase rather than something consulted afterwards. Consolidation last is
what closes the phase: FR5.1 requires the run to *progress*, and a phase that ended without a
recorded outcome would leave the next one entering on an unstated premise.

ONLY THE PHASE'S OWN SUPERVISOR PARTICIPATES
----------------------------------------------
The other three are absent from the step list rather than present with a zero allocation, and the
manifest agrees: ``budgets.<phase>`` declares an entry for the phase's own Supervisor and for no
other. The distinction is not cosmetic. A role budgeted at zero is a role the runtime would
instantiate, prompt and immediately refuse, spending a turn it was not granted; a role that is
absent never runs. :func:`agents.graphs.plan.plan_for` enforces the agreement in the other
direction -- a step whose ``(phase, role_id)`` has no declared budget is a build-time error, not a
run-time surprise -- so the two descriptions cannot drift apart silently.

THE SUPERVISOR IS FOUND BY ITS DECLARED PHASE, NEVER BY ITS NAME
------------------------------------------------------------------
:func:`order` selects the phase-planning role whose manifest entry declares ``phase: <phase>``. It
does **not** build the id by concatenating a prefix onto the phase string, even though the manifest
happens to name them that way today. A convention about identifiers is not a contract, and a
composition that renamed a Supervisor would then produce a
:class:`~agents.registry.loader.RegistryError` at build time -- which is the right failure -- rather
than a graph that silently skipped a phase's planning step.

THE EXECUTOR IS NO LONGER A STEP OF ITS OWN, AND IS STILL EPHEMERAL
----------------------------------------------------------------------
Before ADR-092 the descent was coordination, this phase's planning role, bounded execution,
consolidation -- four steps, the third always a single Executor visit. The supervisor's
2026-09-13 ruling makes a phase the unit of delegation: the phase's own Supervisor may hand a task
to a fresh Executor, get the result, and hand another -- as many times as the phase's shared budget
allows -- before it closes the phase. A fixed fourth step could express "exactly one visit" and
nothing else, so :func:`order` no longer emits one; the phase-planning step **is** the delegation
loop, and every Executor it builds is built and torn down inside that one step's own call, in
:func:`agents.graphs.nodes._delegate_phase`.

FR3.1's ephemerality is not weakened by moving where the Executor is built. The object is still
constructed when a task starts, still holds its capability token as a call argument for the
duration of one action, and is still unreachable once that task returns --
:func:`agents.graphs.nodes._run_delegated_task` is where this now happens, once per delegated task
rather than once per phase, which is a *more* literal reading of "ephemeral" than a single fixed
step ever gave. ``agents/tests/test_executor_lifecycle.py`` and
``agents/tests/test_executor_env_scan.py`` are what make that checked rather than asserted.
Fan-out to *parallel* Executors inside a phase remains a scenario-breadth question M5 opens; ADR-092
is the sequential loop only.
"""

from typing import Final

from agents.graphs import nodes
from agents.graphs.plan import GraphPlan, plan_for
from agents.registry.loader import Composition, PromptRegistry, RegistryError, load_registry

__all__ = ("CONDITION", "build", "order")

# The condition this module composes. Stated as a constant rather than left implicit in the file
# name so that agents/graphs/__init__.py's CONDITION_MODULES mapping can be checked against the
# modules it names -- agents/tests/test_graphs.py asserts the round trip.
CONDITION: Final = "S1-HIER"

# The node kind whose roles are phase-scoped. Named here because :func:`order` selects on it and a
# bare string literal three lines down would be a magic value in the one place a reader is checking
# the descent against docs/02-architecture.md section 1.
_PHASE_SCOPED_NODE: Final = "phase-planning"


def order(composition: Composition, phase: str) -> tuple[str, ...]:
    """Return the roles that run in ``phase``, in traversal order.

    Three roles, not four: coordination, this phase's own planning role, then consolidation. The
    planning role's own step *is* the phase's delegation loop since ADR-092 -- every Executor it
    hands a task to is built and torn down inside that one call
    (:func:`agents.graphs.nodes._delegate_phase`) rather than run as a separate, fixed step, which
    is what lets the loop mint more than once without a fourth step's fixed allocation capping it
    at one visit. See this module's docstring, "THE EXECUTOR IS NO LONGER A STEP OF ITS OWN".

    Raises :class:`~agents.registry.loader.RegistryError` when the manifest declares no
    phase-planning role for ``phase``. That is a composition defect and it must stop the build: a
    hierarchy missing a phase's Supervisor is not a hierarchy running one fewer role, it is FR2.2's
    "each behind its Supervisor" quietly untrue for one quarter of the run.
    """
    supervisors = tuple(
        role.role_id
        for role in composition.roles
        if role.node == _PHASE_SCOPED_NODE and role.phase == phase
    )
    if len(supervisors) != 1:
        raise RegistryError(
            f"{composition.condition}: phase {phase!r} needs exactly one {_PHASE_SCOPED_NODE} "
            f"role and the manifest declares {len(supervisors)} "
            f"({', '.join(supervisors) or 'none'})"
        )
    return (
        "orchestrator",
        supervisors[0],
        "consolidator",
    )


def build(registry: PromptRegistry | None = None) -> GraphPlan:
    """Build the plan for ``S1-HIER``, loading the registry when one is not supplied.

    The parameter exists for the tests and for the runner, which load the registry once and build
    three plans from it; passing ``None`` is the ordinary case and reads the registry from
    ``agents/prompts/``.

    Also validates, at build time, that the manifest declares a per-phase allocation for the
    bounded-execution role every phase-planning step now delegates to
    (:func:`agents.graphs.nodes.executor_delegate_for`). :func:`~agents.graphs.plan.plan_for`
    already refuses a missing allocation for any role ``order`` names; since ``order`` no longer
    names the Executor, this is the same refusal for the one role it delegates to instead of
    listing -- discovered here, where a manifest diff is being read, rather than mid-phase where an
    allocation nobody declared would otherwise be spent against.
    """
    plan = plan_for(registry if registry is not None else load_registry(), CONDITION, order)
    nodes.executor_delegate_for(plan.composition, plan.composed)
    return plan
