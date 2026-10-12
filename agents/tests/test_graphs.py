r"""The three topologies as *values*: what each traverses, and what no node is ever told.

WHAT THIS FILE PINS, AND WHY EACH PROPERTY WOULD OTHERWISE FAIL SILENTLY
-------------------------------------------------------------------------
``agents/graphs/`` claims to be three thin compositions of one behaviour registry. Four of the five
claims that phrase makes are the kind that a happy-path run confirms without checking, and the fifth
is the validity condition of the entire structure ablation.

*The registry of topologies is complete and self-consistent.*
:data:`~agents.graphs.CONDITION_MODULES` maps a condition id to a module path, and the runner (M6)
resolves an arm through it rather than by importing three modules and choosing between them. A key
whose module does not exist, or a module filed under the wrong key, would surface as a run that
executed the wrong topology under the right label -- and every downstream artefact would carry the
label. So the mapping is asserted to round-trip against each module's own ``CONDITION`` constant and
against :data:`agents.registry.STRUCTURE_CONDITIONS`.

*Every arm traverses the four phases, in order.* Traceability row T-05 closes on "four section 1.6
phase spans present **in order**", so this file asserts order and not membership: a plan whose
phases were the right set in the wrong sequence would satisfy a membership check and would mean the
run had contained before it detected, which FR5.1's "progress through" forbids. It is asserted for
all three arms because it is a property of the traversal rather than of the topology -- deleting two
role tiers does not delete the incident lifecycle.

*``S1-HIER`` descends, and only the phase's own Supervisor is in the phase.* Coordination, then that
phase's planning role, then bounded execution, then consolidation -- ``docs/02-architecture.md``
section 1's descent, four times over. The second half is the one worth a test: the other three
Supervisors are **absent** from a phase rather than present with a zero allocation, and the
difference is not cosmetic. A role budgeted at zero is a role the runtime instantiates, prompts and
immediately refuses, spending a turn it was not granted; a role that is absent never runs.

*Every step has a declared allocation.* A step whose ``(phase, role_id)`` carries no budget is a
role that acts without an allocation ``make parity-check`` can compare or the runtime can bound.
:func:`~agents.graphs.plan.plan_for` refuses one at build time, and the negative case below proves
that refusal over a mutated copy of the shipped registry rather than trusting the code path.

*Each topology's ``order()`` refuses a manifest that has stopped being its shape.* "Flat" is a claim
about role count and "hierarchical" is a claim about a Supervisor per phase; a manifest that grew a
second flat role, or lost a phase's Supervisor, must fail where somebody is reading a diff rather
than in a results table three milestones later.

THE LOAD-BEARING ONE: NO CONDITION STRING REACHES A NODE
----------------------------------------------------------
ADR-027 rejects a ``condition`` parameter inside node behaviour outright, and the reason is not
tidiness. A branch on the arm inside a node **is the confound the ablation exists to exclude** --
and it would be invisible to ``make parity-check``, which compares registries and token counts
rather than control flow. A gate that cannot see a violation cannot report one, so the check has to
be structural, and it is two assertions over the abstract syntax tree:

1. no function in ``agents/graphs/nodes.py`` declares a parameter named ``condition``, ``arm`` or
   ``mode`` -- in any position, including keyword-only and variadic; and
2. none of the three condition ids appears as a **code** string literal anywhere in
   ``agents/graphs/nodes.py`` or ``agents/registry/composer.py``.

"Code literal" excludes a string that stands alone as an expression statement -- a module, class,
function or attribute docstring. The interpreter discards such a value, so it can never reach a
model or a comparison, and both modules argue ADR-027 *by name and by arm* in their own prose. A
scan that failed on documentation would be a scan whose first hits were all false, which is how a
guardrail gets switched off; ``scripts/monitor_guard.sh``'s header makes that argument at length and
this file inherits it rather than relearning it.

WHY LANGGRAPH IS NOT IMPORTED HERE, AND WHY THAT IS ITSELF ASSERTED
---------------------------------------------------------------------
:mod:`agents.graphs.plan` keeps the runtime out of the plan path deliberately: ``scripts/
parity_check.sh`` runs in a CI job that installs nothing (conflict M4-C1), and the import chain from
that gate reaches the composer through the graphs. A test that imported LangGraph in order to build
a plan would stop proving that the plan path is reachable without it, so this file imports the plan
layer and nothing below it -- and then asserts the property directly, by walking the package's
syntax trees and requiring every ``langgraph`` import to sit inside a function body.
"""

import ast
import json
import sys
from dataclasses import replace
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import importlib  # noqa: E402
import shutil  # noqa: E402
from types import ModuleType  # noqa: E402
from typing import Any  # noqa: E402

import pytest  # noqa: E402
from agents.graphs import CONDITION_MODULES, flat, hier, single  # noqa: E402
from agents.graphs.nodes import (  # noqa: E402
    _rendered_actions,
    _summarise,
    bounded_execution_node,
)
from agents.graphs.plan import build_state_graph, run_plan  # noqa: E402
from agents.registry import NODE_KINDS, PHASES, STRUCTURE_CONDITIONS  # noqa: E402
from agents.registry.loader import (  # noqa: E402
    Budget,
    Composition,
    PromptRegistry,
    RegistryError,
    RoleComposition,
    load_registry,
)
from agents.registry.model import ScriptedClient, ToolCall  # noqa: E402
from harness import InProcessGuardian, node_context  # noqa: E402

GRAPHS_ROOT = REPO_ROOT / "agents" / "graphs"
NODES_MODULE_PATH = GRAPHS_ROOT / "nodes.py"
COMPOSER_MODULE_PATH = REPO_ROOT / "agents" / "registry" / "composer.py"
REGISTRY_ROOT = REPO_ROOT / "agents" / "prompts"

# The descent docs/02-architecture.md section 1 draws, expressed in node kinds rather than in role
# ids. Node kinds because the ids are the composition manifest's business and a manifest is allowed
# to rename a Supervisor; the descent is the architecture's and is not.
#
# Three steps, not four, since ADR-092. Before it, "bounded execution" was always the phase's
# fourth and final step: one Executor visit, fixed at build time. The supervisor's 2026-09-13
# ruling makes a phase the unit of delegation -- the phase-planning step now *is* the delegation
# loop, and it builds and tears down as many bounded-execution visits as the phase's shared budget
# lets it, none of them a step of the static plan. "bounded-execution" therefore does not appear in
# this tuple even though it is still a member of NODE_KINDS: it is still a behaviour the registry
# indexes, it is simply reached from inside phase-planning's own call rather than listed as its own
# plan step. See test_s1_hier_delegates_from_inside_the_phase_planning_step below for where it is
# checked instead.
S1_DESCENT: tuple[str, ...] = (
    "coordination",
    "phase-planning",
    "consolidation",
)

# The node kind whose roles are phase-scoped, spelled here so the assertions below read as claims
# about the hierarchy rather than as string comparisons.
PHASE_SCOPED_NODE = "phase-planning"

# The parameter names ADR-027 forbids a node behaviour from taking. Three spellings of one idea,
# because the rule is about the *fact* reaching a node and not about the word chosen for it.
FORBIDDEN_NODE_PARAMETERS = frozenset({"condition", "arm", "mode"})

# The runtime agents/graphs/plan.py keeps off the plan path. Named so the failure message can say
# which import moved rather than only that one did.
RUNTIME_PACKAGE = "langgraph"


@pytest.mark.parametrize("driver", ["plan", "compiled"])
def test_completed_results_follow_role_boundaries_without_credentials(
    driver, guardian, registry, monkeypatch
):
    """Unique outputs reach their consumers in both drivers, rather than only the recorder."""
    if driver == "compiled":
        pytest.importorskip("langgraph.graph")
    plan = hier.build(registry)
    summaries = [f"unique-{index}-{step.phase}" for index, step in enumerate(plan.steps)]
    model = ScriptedClient(
        [
            ToolCall("complete_phase", {"outcome": "resolved", "summary": summary})
            for summary in summaries
        ]
    )
    context = node_context(guardian, model=model, plan=plan)
    canary = "CANARY-CREDENTIAL-MUST-NOT-REACH-MODEL"
    from agents.graphs import plan as driver_module

    original = driver_module._node_for

    def node_for(plan, step):
        node = original(plan, step)

        def run(context, phase):
            result = node(context, phase)
            if plan.composed.role(step.role_id).node == "phase-planning":
                return replace(
                    result,
                    actions=(
                        {
                            "kind": "action",
                            "decision": "permit",
                            "audit_seq": 42,
                            "execution": {
                                "status": "executed",
                                "stdout_ref": "outputs/action.json",
                                "bearer": canary,
                            },
                            "token": canary,
                            "headers": {"Authorization": canary},
                            "body": {"token": canary},
                            "capability": canary,
                        },
                    ),
                )
            return result

        return run

    monkeypatch.setattr(driver_module, "_node_for", node_for)

    def drive():
        if driver == "plan":
            return run_plan(plan, context)
        return tuple(build_state_graph(plan, context).invoke({})["results"])

    results = drive()
    assert [result.summary for result in results] == summaries
    frames = [
        next(
            frame
            for line in call.context.splitlines()
            if "completed_results" in (frame := json.loads(line))
        )
        for call in model.calls
    ]
    for index, step in enumerate(plan.steps):
        frame = frames[index]
        assert frame["phase"] == step.phase
        expected = (
            summaries[:index]
            if index % 3 == 0
            else [summaries[index - 1]]
            if index % 3 == 1
            else summaries[index - 2 : index]
        )
        assert [item["summary"] for item in frame["completed_results"]] == expected
        assert canary not in model.calls[index].context
        if index % 3 == 2:
            action = frame["completed_results"][-1]["actions"][0]
            assert action == {
                "kind": "action",
                "decision": "permit",
                "audit_seq": 42,
                "execution": {"status": "executed", "stdout_ref": "outputs/action.json"},
            }

    # A bounded executor offered the same context must still see only its own task frame.
    executor_model = ScriptedClient(
        [ToolCall("complete_phase", {"outcome": "resolved", "summary": "task-complete"})]
    )
    context.model = executor_model
    executor = bounded_execution_node(
        plan.composed.role("executor"),
        budget=plan.composition.budgets[PHASES[-1]]["executor"],
        tools=("complete_phase",),
    )
    executor(context, PHASES[-1])
    assert all(summary not in executor_model.calls[0].context for summary in summaries)
    assert canary not in executor_model.calls[0].context
    assert "completed_results" not in executor_model.calls[0].context

    # Reusing a context for a fresh driver invocation must not replay a previous run's prefix.
    model = ScriptedClient(
        [
            ToolCall("complete_phase", {"outcome": "resolved", "summary": "fresh"})
            for _ in plan.steps
        ]
    )
    context.model = model
    drive()
    fresh_frame = next(
        frame
        for line in model.calls[0].context.splitlines()
        if "completed_results" in (frame := json.loads(line))
    )
    assert fresh_frame["completed_results"] == []


# --------------------------------------------------------------------------------------------
# Syntax-tree helpers, shared by the three structural scans at the end of the file
# --------------------------------------------------------------------------------------------


def _parse(path: Path) -> ast.Module:
    """Parse one module, naming the file in any SyntaxError the parser raises."""
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _discarded_string_ids(tree: ast.AST) -> frozenset[int]:
    """Return the identities of every string constant that stands alone as a statement.

    That is exactly the set of docstrings -- module, class, function and the attribute docstrings
    :mod:`agents.tools.guardian_client` writes under ``Transport`` -- plus nothing else, because a
    bare string expression is the only construct whose value the interpreter evaluates and throws
    away. Identity rather than value, so that a prose mention of ``S1-HIER`` in a docstring is
    exempt while the same characters in an assignment three lines below are not.
    """
    discarded: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            if isinstance(node.value.value, str):
                discarded.add(id(node.value))
    return frozenset(discarded)


def _code_string_constants(tree: ast.AST) -> tuple[tuple[str, int], ...]:
    """Return every ``(text, line)`` string constant that is not a discarded docstring."""
    discarded = _discarded_string_ids(tree)
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) not in discarded:
                found.append((node.value, node.lineno))
    return tuple(found)


def _parameter_names(
    function: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
) -> tuple[str, ...]:
    """Return every parameter name a function declares, in every position it can declare one."""
    arguments = function.args
    names = [
        argument.arg
        for argument in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs)
    ]
    for variadic in (arguments.vararg, arguments.kwarg):
        if variadic is not None:
            names.append(variadic.arg)
    return tuple(names)


def _functions(tree: ast.AST) -> tuple[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef], ...]:
    """Return every named function in a module, nested ones included, with its own name."""
    return tuple(
        (node.name, node)
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    )


def _graph_modules() -> tuple[Path, ...]:
    """Every Python source file under ``agents/graphs/``, in a stable order."""
    return tuple(
        sorted(path for path in GRAPHS_ROOT.rglob("*.py") if "__pycache__" not in path.parts)
    )


# --------------------------------------------------------------------------------------------
# The registry of topologies
# --------------------------------------------------------------------------------------------


def test_condition_modules_names_exactly_the_structure_arms() -> None:
    """The mapping's keys are the structure conditions the registry declares -- no more, no fewer.

    A fourth key would be an arm ``agents/registry/parity.py`` never compares and the campaign
    manifest never issues; a missing one would be an arm the runner could not resolve at all.
    """
    assert set(CONDITION_MODULES) == set(STRUCTURE_CONDITIONS), (
        "agents/graphs/__init__.py's CONDITION_MODULES and agents/registry's STRUCTURE_CONDITIONS "
        f"disagree about which arms exist: mapping={sorted(CONDITION_MODULES)}, "
        f"registry={sorted(STRUCTURE_CONDITIONS)}"
    )
    assert len(CONDITION_MODULES) == len(STRUCTURE_CONDITIONS), (
        f"CONDITION_MODULES holds {len(CONDITION_MODULES)} entries for "
        f"{len(STRUCTURE_CONDITIONS)} conditions"
    )


def test_every_named_module_imports_and_declares_the_key_it_is_filed_under() -> None:
    """Each module named in the mapping exists, and its ``CONDITION`` is the key it is filed under.

    The round trip is what makes the mapping a list rather than a convention about file names. A
    module filed under the wrong key would produce a run that executed one topology and labelled
    itself another, and nothing downstream could detect it -- every artefact carries the label.
    """
    for condition, module_path in CONDITION_MODULES.items():
        module = importlib.import_module(module_path)
        declared = getattr(module, "CONDITION", None)
        assert declared == condition, (
            f"{module_path} is filed under {condition!r} in CONDITION_MODULES but declares "
            f"CONDITION = {declared!r}"
        )
        for attribute in ("build", "order"):
            assert callable(getattr(module, attribute, None)), (
                f"{module_path} publishes no callable {attribute!r}; every topology module is "
                "a composition rule (order) and a builder (build)"
            )


# --------------------------------------------------------------------------------------------
# The traversal: four phases, in order, in every arm
# --------------------------------------------------------------------------------------------


def test_every_topology_traverses_the_four_phases_in_order(registry: PromptRegistry) -> None:
    """Row T-05's wording is "four phase spans present **in order**", so order is what is asserted.

    Membership would be satisfied by a plan that ran containment before detection, which is FR5.1's
    "progress through the four phases" quietly untrue. It holds for all three arms because the
    phases are a property of the traversal rather than of the topology: S2-FLAT and S3-SINGLE remove
    delegation between tiers, not the incident lifecycle.
    """
    for condition, module_path in CONDITION_MODULES.items():
        plan = importlib.import_module(module_path).build(registry)
        assert plan.condition == condition, (
            f"{module_path}.build() produced a plan labelled {plan.condition!r}"
        )
        assert plan.phases() == PHASES, (
            f"{condition} traverses {plan.phases()}; docs/02-architecture.md section 1.6 fixes "
            f"{PHASES}, and row T-05 closes on those four spans being present in order.\n"
            f"{plan.describe()}"
        )


def test_s1_hier_descends_through_three_steps_in_every_phase(registry: PromptRegistry) -> None:
    """Coordination, this phase's planning role, consolidation -- three steps, three times.

    Asserted in node kinds rather than role ids: the ids belong to the composition manifest, which
    is allowed to rename a Supervisor, while the descent belongs to docs/02-architecture.md section
    1 and is not. FR2.1 makes the Orchestrator's global view the thing that *enters* a phase, and
    consolidation is last because a phase that ended without a recorded outcome would leave the next
    one entering on an unstated premise. Bounded execution is not a fourth step here since ADR-092
    -- it is checked separately, below, as something the phase-planning step reaches internally.
    """
    assert set(S1_DESCENT) < set(NODE_KINDS), (
        "this file's expected descent must be a strict subset of agents/registry's NODE_KINDS: "
        f"descent={sorted(S1_DESCENT)}, registry={sorted(NODE_KINDS)}. 'bounded-execution' is the "
        "one behaviour the registry indexes that this tuple deliberately excludes since ADR-092"
    )
    plan = hier.build(registry)
    node_of = {role.role_id: role.node for role in plan.composition.roles}

    assert len(plan.steps) == len(PHASES) * len(S1_DESCENT), (
        f"S1-HIER emitted {len(plan.steps)} steps; the hierarchy runs {len(S1_DESCENT)} roles in "
        f"each of {len(PHASES)} phases.\n{plan.describe()}"
    )
    for phase in PHASES:
        in_phase = tuple(step.role_id for step in plan.steps if step.phase == phase)
        assert tuple(node_of[role_id] for role_id in in_phase) == S1_DESCENT, (
            f"S1-HIER runs {in_phase} in phase {phase!r}, whose node kinds are "
            f"{tuple(node_of[role_id] for role_id in in_phase)}; the descent is {S1_DESCENT}"
        )


def test_s1_hier_delegates_from_inside_the_phase_planning_step(registry: PromptRegistry) -> None:
    """The one role NODE_KINDS names that S1_DESCENT excludes is reachable, exactly once, by name.

    ADR-092 moves bounded execution from a fourth static step to something the phase-planning step
    reaches internally (:func:`agents.graphs.nodes.executor_delegate_for`). This is the other half
    of the previous case's claim: 'bounded-execution' is excluded from the static descent, but the
    manifest still declares exactly one role playing it, phase-scoped nowhere (so every phase can
    delegate to it) and budgeted in all four phases -- the same coverage
    :func:`agents.graphs.hier.build` already refuses to proceed without.
    """
    from agents.graphs.nodes import executor_delegate_for

    plan = hier.build(registry)
    delegate = executor_delegate_for(plan.composition, plan.composed)
    assert delegate is not None, (
        "S1-HIER's manifest declares no bounded-execution role for a phase-planning step to "
        "delegate to; ADR-092's loop has nothing to build a fresh Executor from"
    )
    assert delegate.role.node == "bounded-execution"
    assert set(delegate.budgets) == set(PHASES), (
        f"the delegate is budgeted in {sorted(delegate.budgets)}, not every phase in {list(PHASES)}"
    )
    assert not any(step.role_id == delegate.role.role_id for step in plan.steps), (
        f"{delegate.role.role_id!r} still appears as its own plan step; ADR-092 builds and tears "
        "it down inside the phase-planning step's own call instead of listing it as a fourth one"
    )


def test_s1_hier_runs_only_the_phases_own_supervisor_in_that_phase(
    registry: PromptRegistry,
) -> None:
    """The other three Supervisors are absent from a phase, not present with a zero allocation.

    FR2.2 puts each phase "behind its Supervisor", and the distinction between absent and budgeted
    at zero decides what the runtime does: a role allocated nothing is still instantiated, prompted
    and refused, spending a turn it was not granted, while a role that is absent never runs. The
    manifest agrees -- ``budgets.<phase>`` declares an entry for the phase's own Supervisor and for
    no other -- and this is the half of that agreement the plan is responsible for.
    """
    plan = hier.build(registry)
    supervisors = {
        role.role_id: role.phase
        for role in plan.composition.roles
        if role.node == PHASE_SCOPED_NODE
    }
    assert set(supervisors.values()) == set(PHASES), (
        f"S1-HIER declares {PHASE_SCOPED_NODE} roles for phases {sorted(supervisors.values())}; "
        f"FR2.2 needs one for each of {sorted(PHASES)}"
    )

    for phase in PHASES:
        in_phase = {step.role_id for step in plan.steps if step.phase == phase}
        present = {role_id for role_id in in_phase if role_id in supervisors}
        assert len(present) == 1, (
            f"phase {phase!r} runs {len(present)} phase-planning role(s) {sorted(present)}; "
            "exactly the phase's own Supervisor participates"
        )
        (only,) = present
        assert supervisors[only] == phase, (
            f"phase {phase!r} is planned by {only!r}, whose manifest entry declares phase "
            f"{supervisors[only]!r}. A Supervisor is selected by its declared phase and never by "
            "its name, so this is a manifest that has stopped saying what the graph does"
        )
        foreign = {role_id for role_id, owns in supervisors.items() if owns != phase} & in_phase
        assert not foreign, (
            f"phase {phase!r} also runs {sorted(foreign)}, which plan other phases. A Supervisor "
            "that is present in a phase it does not own is a role spending that phase's budget on "
            "a plan nobody asked it for"
        )


def test_flat_and_single_run_exactly_one_step_per_phase(registry: PromptRegistry) -> None:
    """One role, once per phase, in both single-node arms -- and still four phases.

    ``docs/07-glossary-and-ids.md`` types S2-FLAT as a flat single coordinator with no
    phase-specific Supervisors and no subordinate Executors, and S3-SINGLE as one agent; a traversal
    of one step per phase is those two sentences as a data structure. What separates the two arms is
    the ``structural`` blocks their manifests name, which is the ``structural`` parity class's
    business and not this file's.
    """
    for module in (flat, single):
        plan = module.build(registry)
        assert tuple(step.phase for step in plan.steps) == PHASES, (
            f"{plan.condition} steps through {tuple(step.phase for step in plan.steps)}; one step "
            f"per phase means exactly {PHASES}.\n{plan.describe()}"
        )
        role_ids = {step.role_id for step in plan.steps}
        assert len(role_ids) == 1, (
            f"{plan.condition} runs {sorted(role_ids)}; both single-node arms run one role in "
            "every phase, and a second role would have made the arm something else"
        )


# --------------------------------------------------------------------------------------------
# Budgets: every step carries a declared allocation, and a manifest missing one cannot build
# --------------------------------------------------------------------------------------------


def test_every_step_in_every_topology_has_a_declared_budget(registry: PromptRegistry) -> None:
    """No step runs on an allocation the manifest did not state.

    A role that acts without a declared allocation is a role ``make parity-check`` cannot compare --
    section 3.5.4's per-phase budget equality is stated over the manifest's numbers -- and one the
    runtime cannot bound, because :class:`~agents.graphs.nodes.BudgetLedger` is opened from exactly
    this value.
    """
    for condition, module_path in CONDITION_MODULES.items():
        plan = importlib.import_module(module_path).build(registry)
        for step in plan.steps:
            allocations = plan.composition.budgets.get(step.phase, {})
            assert step.role_id in allocations, (
                f"{condition}: step {step.node_name} has no declared budget; "
                f"budgets.{step.phase} names {sorted(allocations)}"
            )
            budget = allocations[step.role_id]
            assert isinstance(budget, Budget), (
                f"{condition}: budgets.{step.phase}.{step.role_id} loaded as "
                f"{type(budget).__name__} rather than a Budget"
            )


def _drop_budget_entry(manifest: str, *, phase: str, role_id: str) -> str:
    """Return ``manifest`` with the ``budgets.<phase>.<role_id>`` allocation removed.

    Line-based surgery on the shipped manifest rather than a hand-written stand-in, so that the
    negative case is the real registry with exactly one thing wrong with it. A stand-in would let
    this test pass over a manifest shape nothing else in the repository produces.
    """
    lines = manifest.splitlines(keepends=True)
    out: list[str] = []
    in_budgets = False
    in_phase = False
    dropping_from: int | None = None
    for line in lines:
        stripped = line.rstrip("\n")
        indent = len(stripped) - len(stripped.lstrip(" "))
        if stripped and indent == 0:
            in_budgets = stripped.startswith("budgets:")
            in_phase = False
        elif in_budgets and stripped and indent == 2:
            in_phase = stripped.strip() == f"{phase}:"
        if dropping_from is not None:
            if stripped.strip() and indent > dropping_from:
                continue
            dropping_from = None
        if in_budgets and in_phase and stripped.strip() == f"{role_id}:":
            dropping_from = indent
            continue
        out.append(line)
    changed = "".join(out)
    assert changed != manifest, (
        f"the surgery removed nothing: budgets.{phase}.{role_id} was not found in the manifest, so "
        "this negative case would have proved nothing"
    )
    return changed


def test_a_step_without_a_declared_budget_is_refused_at_build_time(tmp_path: Path) -> None:
    """Remove one allocation from a copy of the shipped registry, and the build must refuse.

    Build time and not run time, and that is the whole point of the check. A missing allocation
    discovered while a phase is running is a turn already spent against a number nobody declared;
    discovered at build time it is a manifest diff somebody is looking at. The mutation is applied
    to a copy under ``tmp_path`` -- nothing under ``agents/prompts/`` is touched -- and the registry
    still *loads*, so the refusal is :func:`~agents.graphs.plan.plan_for`'s and not the loader's.
    """
    root = tmp_path / "prompts"
    shutil.copytree(REGISTRY_ROOT, root)
    manifest_path = root / "compositions" / "S1-HIER.yaml"
    manifest_path.write_text(
        _drop_budget_entry(
            manifest_path.read_text(encoding="utf-8"),
            phase="containment",
            role_id="executor",
        ),
        encoding="utf-8",
    )

    mutated = load_registry(root)
    assert "executor" not in mutated.compositions["S1-HIER"].budgets["containment"], (
        "the mutated registry still declares the allocation this case removes"
    )

    with pytest.raises(RegistryError, match="declares no budget"):
        hier.build(mutated)


# --------------------------------------------------------------------------------------------
# Shape refusals: order() rejects a manifest that has stopped being its topology
# --------------------------------------------------------------------------------------------


def _role(role_id: str, *, node: str, phase: str | None = None) -> RoleComposition:
    """One synthetic manifest role entry. Blocks and tools are irrelevant to ``order()``."""
    return RoleComposition(
        role_id=role_id,
        node=node,
        phase=phase,
        block_ids=("common.mission",),
        tools=(),
    )


def _composition(condition: str, *roles: RoleComposition) -> Composition:
    """A synthetic composition carrying only what ``order()`` reads: the condition and the roles.

    Constructed in memory rather than written to disk because ``order()`` is a pure function of
    those two things, and a manifest on disk would have to satisfy every unrelated rule the loader
    enforces before this case could say anything about the shape rule under test.
    """
    return Composition(
        condition=condition,
        issuance_tool_holder=roles[0].role_id,
        roles=roles,
        budgets={phase: {} for phase in PHASES},
        path=Path("<synthetic>"),
    )


def test_hier_order_refuses_a_manifest_missing_a_phases_supervisor() -> None:
    """A hierarchy with no Supervisor for a phase is FR2.2 untrue for a quarter of the run.

    That is a composition defect and it must stop the build rather than produce a graph that
    silently skipped a phase's planning step -- which is what selecting the Supervisor by name
    would have done, and is why :func:`agents.graphs.hier.order` selects on the declared phase.
    """
    composition = _composition(
        "S1-HIER",
        _role("orchestrator", node="coordination"),
        _role("supervisor-containment", node=PHASE_SCOPED_NODE, phase="containment"),
        _role("executor", node="bounded-execution"),
        _role("consolidator", node="consolidation"),
    )
    with pytest.raises(RegistryError) as refused:
        hier.order(composition, "eradication")
    message = str(refused.value)
    assert "eradication" in message and PHASE_SCOPED_NODE in message, (
        "the refusal must name the phase that lost its Supervisor and the node kind that was "
        f"looked for, so a reader can fix the manifest without reading the code: {message!r}"
    )


def test_hier_order_refuses_two_supervisors_for_one_phase() -> None:
    """Two planning roles for one phase is as broken as none, and for the same reason.

    "Exactly one" is what makes the descent deterministic; two would make the traversal depend on
    manifest declaration order, which ``.agents/rules/20-parity-and-determinism.md`` forbids
    anything a run depends on from resting on.
    """
    composition = _composition(
        "S1-HIER",
        _role("orchestrator", node="coordination"),
        _role("supervisor-containment", node=PHASE_SCOPED_NODE, phase="containment"),
        _role("supervisor-containment-2", node=PHASE_SCOPED_NODE, phase="containment"),
        _role("executor", node="bounded-execution"),
        _role("consolidator", node="consolidation"),
    )
    with pytest.raises(RegistryError) as refused:
        hier.order(composition, "containment")
    message = str(refused.value)
    assert "supervisor-containment" in message and "supervisor-containment-2" in message, (
        f"the refusal must name both candidates so the manifest edit is obvious: {message!r}"
    )


@pytest.mark.parametrize(
    ("module", "condition"),
    [(flat, "S2-FLAT"), (single, "S3-SINGLE")],
    ids=["S2-FLAT", "S3-SINGLE"],
)
def test_single_node_order_refuses_a_manifest_that_grew_a_second_role(
    module: ModuleType, condition: str
) -> None:
    """Flat and single are claims about role count, so a second role is a different arm.

    The failure belongs at build time where somebody is reading a diff. A manifest that quietly grew
    a role would otherwise produce a topology labelled S2-FLAT that was not flat, and 125 runs of
    the campaign would be measuring a structure nobody described.
    """
    composition = _composition(
        condition,
        _role("coordinator", node="coordination"),
        _role("second", node="coordination"),
    )
    with pytest.raises(RegistryError) as refused:
        module.order(composition, PHASES[0])
    message = str(refused.value)
    assert condition in message and "coordinator" in message and "second" in message, (
        f"the refusal must name the condition and every role the manifest declares: {message!r}"
    )


# --------------------------------------------------------------------------------------------
# ADR-027: no condition string reaches a node
# --------------------------------------------------------------------------------------------


def test_the_syntax_scans_actually_read_the_two_modules_they_police() -> None:
    """An empty scan and a clean scan are indistinguishable unless something asserts the difference.

    ``scripts/monitor_guard.sh`` applies the same discipline with its vacuous-pass wording, and it
    matters more here than usual: the three scans below are the only mechanical evidence that
    ADR-027's rejection of a condition parameter holds, so a scan that silently read nothing would
    be the whole proof evaporating without a red line anywhere.
    """
    for path in (NODES_MODULE_PATH, COMPOSER_MODULE_PATH):
        assert path.is_file(), f"{path} is missing; the scan below would pass vacuously"
        tree = _parse(path)
        assert _functions(tree), f"{path} parsed to no functions at all"
        assert _discarded_string_ids(tree), (
            f"{path} parsed to no docstring, which means the exemption rule is not being exercised "
            "and the scan may be reading a tree it does not understand"
        )
    assert len(_graph_modules()) >= len(CONDITION_MODULES) + 2, (
        "agents/graphs/ holds fewer modules than the three topologies plus plan.py and nodes.py; "
        f"the scan saw {[path.name for path in _graph_modules()]}"
    )


def test_no_node_behaviour_takes_a_condition_parameter() -> None:
    """No function in the node registry declares ``condition``, ``arm`` or ``mode``, anywhere.

    Every position is checked -- positional-only, positional, keyword-only, ``*args`` and
    ``**kwargs`` -- because the rule is about the fact reaching a node rather than about the calling
    convention it arrives under. ADR-027 rejects the parameter outright: the branch it would enable
    is the confound the structure ablation exists to exclude, and ``make parity-check`` compares
    registries and token counts rather than control flow, so no gate could see it.
    """
    tree = _parse(NODES_MODULE_PATH)
    offenders = [
        (name, function.lineno, sorted(set(_parameter_names(function)) & FORBIDDEN_NODE_PARAMETERS))
        for name, function in _functions(tree)
        if set(_parameter_names(function)) & FORBIDDEN_NODE_PARAMETERS
    ]
    assert not offenders, (
        f"agents/graphs/nodes.py declares condition-shaped parameter(s): {offenders}. ADR-027: a "
        "node knows its composed prompt, its tools, its budget and its collaborators, and every "
        f"one of those arrives from the composition manifest. Forbidden names: "
        f"{sorted(FORBIDDEN_NODE_PARAMETERS)}"
    )


@pytest.mark.parametrize(
    "module_path",
    [NODES_MODULE_PATH, COMPOSER_MODULE_PATH],
    ids=["nodes", "composer"],
)
def test_no_condition_id_appears_as_a_code_literal(module_path: Path) -> None:
    """Neither the node registry nor the composer names an arm in a value the interpreter keeps.

    Docstrings are exempt and both modules use the exemption heavily -- each argues ADR-027 by
    naming the arms it refuses to branch on. That is documentation, and a guard that failed on it
    would be a guard whose every hit was false from its first run. What is forbidden is the arm as
    a **value**: a literal that can be compared, dispatched on, or interpolated into something a
    model receives.
    """
    tree = _parse(module_path)
    offenders = [
        (text, line, condition)
        for text, line in _code_string_constants(tree)
        for condition in STRUCTURE_CONDITIONS
        if condition in text
    ]
    assert not offenders, (
        f"{module_path.relative_to(REPO_ROOT).as_posix()} carries a condition id in a code string "
        f"literal: {offenders}. A condition selects which composition manifest is loaded, and "
        "nothing below that point learns which arm it is in -- ADR-027 rejects the branch outright "
        "because it would be the confound and no gate that compares registries could see it"
    )


def test_the_plan_path_never_reaches_langgraph_at_module_scope() -> None:
    """Every ``langgraph`` import under ``agents/graphs/`` sits inside a function body.

    ``scripts/parity_check.sh`` runs in ``ci.yml``'s ``guardrail-grep`` job, which installs nothing
    (conflict M4-C1), and its import chain reaches the composer through this package. A module-scope
    import here would make that gate fail for a dependency reason rather than a code reason -- the
    exact shape ADR-025 records for M3's two guards tripping together.

    Asserted over the syntax tree rather than over ``sys.modules``, because a ``sys.modules`` check
    would pass or fail depending on what another test in the same session had already imported, and
    a proof that depends on collection order is not a proof.
    """
    module_scope: list[str] = []
    nested: list[str] = []
    for path in _graph_modules():
        tree = _parse(path)
        inside = {
            id(node)
            for _, function in _functions(tree)
            for node in ast.walk(function)
            if isinstance(node, ast.Import | ast.ImportFrom)
        }
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            if not any(name.split(".")[0] == RUNTIME_PACKAGE for name in names):
                continue
            where = f"{path.relative_to(REPO_ROOT).as_posix()}:{node.lineno}"
            (nested if id(node) in inside else module_scope).append(where)

    assert not module_scope, (
        f"{RUNTIME_PACKAGE} is imported at module scope in {module_scope}. agents/graphs/plan.py "
        "keeps the runtime inside build_state_graph so that a plan is standard library and the "
        "parity gate's import chain never acquires a dependency"
    )
    assert nested, (
        f"no {RUNTIME_PACKAGE} import was found anywhere under agents/graphs/, so this scan proved "
        "nothing about where the runtime is reached. ADR-002 chose LangGraph and "
        "build_state_graph is where the choice becomes concrete"
    )


# --------------------------------------------------------------------------------------------
# SEAM 6: the phase is declared to the control plane before the phase's first node runs
# --------------------------------------------------------------------------------------------
#
# WHAT THIS SECTION IS FOR
# -------------------------
# V17 recorded two defects on the Guardian's side of issuance: `POST /v1/tokens` had no auth
# dependency, and issuance checks the *declared* phase's ceiling while nothing knows the run's
# actual
# phase. WS-4 closes the first with a control-plane bearer and refuses an issuance whose declared
# phase is not the current one; the second needs this side. `NodeContext.declare_phase` is the
# runner-provided callable that POSTs `POST /v1/phase`, and `run_plan` calls it inside the one place
# every topology shares -- `if step.phase != current_phase` -- so the declaration cannot be
# forgotten
# by one arm and remembered by another.
#
# Two properties are asserted and they are different. The ordering one ("before the first node of
# each phase") is what makes the Guardian's check meaningful: a declaration made after the phase's
# first mint would let the very issuance the rule refuses through the window. The opacity one is
# what
# keeps the control credential out of `agents/`: what reaches this layer is a callable taking one
# phase name, and the bearer that implementation authenticates with lives in the runner process.


@pytest.mark.parametrize("condition", sorted(STRUCTURE_CONDITIONS))
def test_phase_declared_before_first_node_of_each_phase(
    condition: str, guardian: InProcessGuardian, registry: PromptRegistry
) -> None:
    """Every phase is announced once, before any of its nodes run, in all three topologies.

    The log is a single interleaving of two event kinds -- ``declare`` from the runner's callback
    and
    ``step`` from the plan's own ``on_step`` -- because the claim is about their *order* and a pair
    of
    separately-checked lists could not say it. The assertion is that, within each phase, the single
    declaration precedes every step of that phase, which is stronger than "there was a declaration
    somewhere in the run" and stronger than "the first declaration happened at some point".

    The count is asserted too. Four phases traversed, four declarations: a driver that announced on
    every *step* would satisfy the ordering half (each phase would still have its announcement
    first) and would be re-announcing the same phase once per node, which is a control-plane write
    per node in a real run and would put four extra requests in every bundle's audit for no reason.
    """
    plan = importlib.import_module(CONDITION_MODULES[condition]).build(registry)
    log: list[tuple[str, str]] = []

    def declare(phase: str) -> None:
        log.append(("declare", phase))

    context = node_context(guardian, model=ScriptedClient([]), declare_phase=declare)

    results = run_plan(plan, context, on_step=lambda step: log.append(("step", step.phase)))

    assert len(results) == len(plan.steps), (
        f"{condition}: run_plan returned {len(results)} result(s) for a plan of "
        f"{len(plan.steps)} step(s); the interleaving below is only meaningful over a complete run"
    )
    declared = [phase for kind, phase in log if kind == "declare"]
    assert declared == list(PHASES), (
        f"{condition}: the phases declared were {declared} and the phases traversed are "
        f"{list(PHASES)}. One declaration per phase change, in traversal order, is what a control "
        "plane recording a run's phase needs; a driver that declared per node would send four"
        " extra "
        "requests per phase for no information"
    )
    for phase in PHASES:
        positions = [index for index, (_, kind_phase) in enumerate(log) if kind_phase == phase]
        first_declare = min(index for index in positions if log[index][0] == "declare")
        first_step = min(index for index in positions if log[index][0] == "step")
        assert first_declare < first_step, (
            f"{condition}: phase {phase!r} was declared at event {first_declare} and its first"
            " node "
            f"ran at event {first_step} of {log!r}. A declaration made after the phase's first"
            " node "
            "is a declaration made after the phase's first mint, which is exactly the window in "
            "which the Guardian's deny_phase_not_current rule would refuse a legitimate issuance"
        )
        assert all(log[index][0] == "step" for index in positions if index > first_declare), (
            f"{condition}: phase {phase!r} was declared more than once: {log!r}"
        )


@pytest.mark.parametrize("condition", sorted(STRUCTURE_CONDITIONS))
def test_the_phase_declaration_receives_a_phase_name_and_nothing_else(
    condition: str, guardian: InProcessGuardian, registry: PromptRegistry
) -> None:
    """The callback is handed one phase string. The control credential never reaches ``agents/``.

    Iron rule 1's amendment and SEAM 6 together: the Guardian's control-plane bearer is minted per
    run by the runner, verified by a TokenReview, and lives in the runner process. What ``agents/``
    receives is a callable, and this asserts the *call shape* -- one positional argument, a member
    of
    the closed phase vocabulary -- because a seam that accepted a token would be a seam that could
    have one.

    The control for that is the second assertion: a phase name that is one of
    :data:`agents.registry.PHASES` cannot be a credential, and every value the callback was handed
    is
    asserted to be exactly such a name. A driver that passed a request body, a header mapping or a
    run identifier alongside would fail here.
    """
    plan = importlib.import_module(CONDITION_MODULES[condition]).build(registry)
    handed: list[tuple[Any, ...]] = []

    def declare(*args: Any, **kwargs: Any) -> None:
        handed.append((*args, *kwargs.values()))

    run_plan(plan, node_context(guardian, model=ScriptedClient([]), declare_phase=declare))

    assert handed, f"{condition}: the callback was never called"
    for call in handed:
        assert len(call) == 1, (
            f"{condition}: the callback was called with {call!r}. It is handed the phase name and "
            "nothing else; a second argument is a second value this layer would have to be trusted "
            "not to put a credential in"
        )
        assert call[0] in PHASES, (
            f"{condition}: the callback was handed {call[0]!r}, which is not one of"
            "{list(PHASES)}. "
            "The value is a phase name from the closed vocabulary, which is how a credential could "
            "not have been among the things passed"
        )
    assert [call[0] for call in handed] == list(PHASES), (
        f"{condition}: the declarations were {[call[0] for call in handed]}; the phases traversed"
        " are "
        f"{list(PHASES)}"
    )


def test_a_context_with_no_declaration_callback_still_runs_every_phase(
    guardian: InProcessGuardian, registry: PromptRegistry
) -> None:
    """``declare_phase is None`` is the ordinary offline shape, and a run must still complete.

    None-safety, and it is asserted rather than assumed because the alternative would be a graph
    that only works when a runner has been wired in: every Tier A test in this suite, the golden
    path
    and the instrument-only P0-live probes all build a context with no control plane. A driver that
    raised here would take the whole offline tier down with the feature.
    """
    for condition in sorted(STRUCTURE_CONDITIONS):
        plan = importlib.import_module(CONDITION_MODULES[condition]).build(registry)

        results = run_plan(plan, node_context(guardian, model=ScriptedClient([])))

        assert len(results) == len(plan.steps), (
            f"{condition}: a run with declare_phase=None returned {len(results)} result(s) for a "
            f"plan of {len(plan.steps)} step(s)"
        )
        assert {result.phase for result in results} == set(PHASES), (
            f"{condition}: the run covered {sorted({result.phase for result in results})}"
        )


def test_an_acting_role_is_told_whether_its_own_action_executed() -> None:
    """The rendered Guardian answer must carry the execution outcome, not only the decision.

    The defect this pins was measured live, not hypothesised. On ``v2-pilot-20261006e`` the
    Executor that had just had a NetworkPolicy permitted **and executed** saw the rendered answer
    ``guardian: permit permit.rule-allow`` and then wrote a phase summary stating that no cluster
    changes were made. ``results.json`` and the API audit both recorded
    ``execution.status: succeeded``. The Supervisor read that summary and repeated it, and the two
    remaining phases acted on the false account -- which is what produced the nine consecutive
    terminal ``complete_phase`` calls that failed ``F-AG-02``.

    A decision is not an outcome. Before ADR-181 this returned only the decision and the reason
    code, so a role could not tell an applied mutation from an approved one, and the permanent
    audit chain and the official phase record could contradict each other. The assertion is on the
    rendering rather than on the model, because the model is the thing being measured: the
    framework owes the acting role the fact about its own action.
    """
    executed = {
        "decision": "permit",
        "reason_code": "permit.rule-allow",
        "execution": {"status": "succeeded", "stdout_ref": "runs/x/raw/out.jsonl"},
    }
    assert _summarise(executed) == "permit permit.rule-allow; execution status: succeeded"

    # A refusal is an outcome too, and it must read as one rather than as a missing field.
    refused = {
        "decision": "deny",
        "reason_code": "scope.verb-not-allowed",
        "execution": {"status": "not-executed"},
    }
    assert _summarise(refused) == "deny scope.verb-not-allowed; execution status: not-executed"

    # An answer carrying no execution block renders exactly as it always did, so a check that
    # never reached execution is not given a fabricated status.
    assert _summarise({"decision": "deny", "reason_code": "scope.namespace"}) == (
        "deny scope.namespace"
    )


def test_a_delegated_tasks_recorded_actions_reach_the_supervisor_that_delegated_it() -> None:
    """The Supervisor reads its Executor's actions, not only the Executor's prose about them.

    The Supervisor's next turn otherwise sees ``task <outcome>: <summary>`` and nothing else, so
    what its Executor did reaches it as whatever the Executor chose to say. That is the second
    half of the ``e`` freeze failure: the Executor understated its executed action and the
    Supervisor wrote that no capability had been issued while its own ledger recorded the mint's
    ``jti``.

    The issuance record is the case that needs its own branch. It carries ``jti``/``refused``/
    ``error`` and no decision, so routed through :func:`_summarise` it would render the literal
    text ``None None`` into a Supervisor's context.
    """
    issued = {"kind": "issue", "jti": "jti-abc", "refused": False, "error": None}
    refused = {"kind": "issue", "jti": None, "refused": True, "error": "issue_authority_exceeded"}
    acted = {
        "decision": "permit",
        "reason_code": "permit.rule-allow",
        "execution": {"status": "succeeded", "stdout_ref": None},
    }

    rendered = _rendered_actions([issued, acted, refused])

    assert rendered == (
        "\ntask actions: capability issued"
        "\ntask actions: permit permit.rule-allow; execution status: succeeded"
        "\ntask actions: issuance refused: issue_authority_exceeded"
    ), rendered
    assert "None" not in rendered, "an issuance record must not render as 'None None'"
    assert _rendered_actions([]) == ""
