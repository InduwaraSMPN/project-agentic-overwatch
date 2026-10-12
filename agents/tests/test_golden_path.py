r"""The golden path, offline: four phases, real Guardian, real audit chain, scripted model.

WHAT THIS MODULE PINS
---------------------
``docs/milestones/M4-agents.md``'s first Definition-of-done item -- "golden path completes;
per-phase spans + verbatim messages captured [T-05, T-14 golden]" -- at **Tier A**. Every
collaborator here is the shipped one except two: the policy engines are canned answers, because a
real one shells out to an ``opa`` binary the offline tier must not require, and the model is a
script. The graph, the plan, the composed prompts, the tool registry, the Guardian client, the
Guardian's mediation pipeline, its token service and its hash-chained audit log are all the real
ones, driven through a real ASGI application.

WHY THIS IS NOT A SUBSTITUTE FOR ``make agents-golden``, AND WHY IT IS STILL LOAD-BEARING
--------------------------------------------------------------------------------------------
``scripts/agents_golden.sh`` is Tier A′/Tier B: it calls the model for real through the LiteLLM
alias, against a Guardian that is a separate process and, at Tier B, one that mutates a cluster.
It refuses rather than degrades when either prerequisite is absent, which is exactly why this file
exists: without it the entire golden-path claim would be unexercised on every machine that has no
provider credential, which today is every machine including CI.

What this file can prove is everything except "the model produced those tool calls": the traversal,
the nesting of the trace, the shape of the artefacts, the audit chain's growth, and that a token
minted by a phase's own Supervisor is accepted for that phase's own action. Risk R-10 -- whether a
free model emits well-formed tool calls at all -- is precisely the part a script cannot measure,
and it is stated as Tier A′'s job rather than quietly simulated here.

WHY THE SCRIPT IS BUILT FROM THE PLAN RATHER THAN WRITTEN OUT
---------------------------------------------------------------
:func:`script_for` walks the plan and emits the answers each step needs, in step order, from the
node kind the manifest declares. Writing twenty-four literal tool calls would have encoded S1-HIER's
current shape into this file, so a manifest change would produce a mystifying mid-run failure
instead of a script that still fits. It also keeps the script honest about one thing: it contains no
decision. Each answer depends on the *node kind* and nothing else -- never on the prompt, never on
what the Guardian just said -- because a double that read either would be a second, much worse
agent, and this file would then be evidence about it. ``guardian/app/policy.py`` states the rule
these doubles obey and :class:`agents.registry.model.ScriptedClient` quotes it.

WHY THE SUPERVISORS ISSUE AS THEMSELVES
-----------------------------------------
``supervisor_id=""`` in the context, and the Guardian is started with the **registered-issuer set
the composition manifest declares** -- all four phase Supervisors, computed by
:func:`agents.golden.registered_issuers`. That is conflict M4-C7's resolution exercised rather than
described: the Guardian denies ``TOKEN_ISSUER_UNKNOWN`` for an ``iss`` it does not know, so a run
that registered only one Supervisor would be denied in three phases out of four, and a test that
configured one would never find out.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from agents.golden import (
    MANIFEST_FILE,
    MESSAGES_FILE,
    RESULTS_FILE,
    SPANS_FILE,
    TOKENS_FILE,
    load_evidence,
    registered_issuers,
    run_golden,
)
from agents.graphs import CONDITION_MODULES
from agents.graphs.plan import build_state_graph
from agents.registry import PHASES
from agents.registry.loader import PromptRegistry
from agents.registry.model import (
    ModelCall,
    ModelResponse,
    ModelUnavailable,
    ScriptedClient,
    ToolCall,
)
from agents.registry.tracing import read_spans
from agents.scripts import action_call, complete_call, issue_call
from agents.scripts import script_for as _script_for
from agents.tools.registry import ISSUE_TOKEN_TOOL, PHASE_OUTCOMES
from harness import (
    EXECUTOR_ID,
    NAMESPACE,
    InProcessGuardian,
    build_in_process_guardian,
    node_context,
)

RESOLVED = PHASE_OUTCOMES[0]

# The mint->act->complete traversal and its ("list", "pods") verb/resource now live in
# agents/scripts.py, the shipped module the live pilot runner drives P1a from (M10 plan section 6).
# This file's wrappers below bind that one generator to this in-process harness's own executor id
# and namespace, so the offline golden test and the live scripted run answer from ONE script
# generator.

# The evidence the golden path reasons over: a real emitted stream from the Monitor's own corpus.
# A fixture rather than a hand-written event, so the renderer is exercised on bytes an aggregator
# actually produced -- including the quoting the G0 arm applies.
GOLDEN_EVIDENCE = (
    Path(__file__).resolve().parents[2]
    / "monitor"
    / "fixtures"
    / "four-source-incident"
    / "expected"
    / "monitor_events.jsonl"
)


# The four thin wrappers below bind agents/scripts.py's generator and helpers to THIS harness's
# executor id and namespace (EXECUTOR_ID / NAMESPACE from harness.py). The shipped helpers require
# executor_id / namespace with no default on purpose -- a live run must name its own
# ``executor-<run-id>`` so the minted token's ``sub`` matches the action's executor_id (ADR-067); a
# default would silently reintroduce the v1 ``scope.subject-mismatch`` defect. The wrappers keep the
# ``_issue(role_id)`` / ``_action(phase)`` / ``_complete(phase, role_id)`` / ``script_for(plan)``
# shapes this file and test_flag_exercise.py already call.
def _issue(role_id: str) -> ToolCall:
    """A well-formed ``issue_capability_token`` call covering the one action the script submits."""
    return issue_call(role_id, executor_id=EXECUTOR_ID, namespace=NAMESPACE)


def _action(phase: str) -> ToolCall:
    """A well-formed ``guardian_action`` call inside the scope the mint above asked for."""
    return action_call(phase, namespace=NAMESPACE)


def _complete(phase: str, role_id: str) -> ToolCall:
    """A well-formed ``complete_phase`` call closing the phase with a recorded outcome."""
    return complete_call(phase, role_id)


def script_for(plan: Any) -> list[ToolCall | None]:
    """The harness-bound scripted answers one traversal of ``plan`` consumes, in step order."""
    return _script_for(plan, executor_id=EXECUTOR_ID, namespace=NAMESPACE)


@pytest.fixture
def hierarchy(tmp_path: Path, registry: PromptRegistry) -> InProcessGuardian:
    """A Guardian configured for an ``S1-HIER`` run: every phase Supervisor a registered issuer."""
    import importlib

    plan = importlib.import_module(CONDITION_MODULES["S1-HIER"]).build(registry)
    return build_in_process_guardian(
        tmp_path, registered_issuers=registered_issuers(plan.composition)
    )


def _run(condition: str, guardian: InProcessGuardian, registry: PromptRegistry, out: Path) -> Any:
    """Drive one condition end to end through the real driver, with a script built from its plan."""
    import importlib

    plan = importlib.import_module(CONDITION_MODULES[condition]).build(registry)
    context = node_context(guardian, supervisor_id="", executor_id=EXECUTOR_ID)
    return run_golden(
        guardian_url="in-process",
        out=out,
        condition=condition,
        run_id=guardian.config.run_id,
        supervisor_id="",
        executor_id=EXECUTOR_ID,
        namespace=NAMESPACE,
        evidence_path=GOLDEN_EVIDENCE,
        client=ScriptedClient(script_for(plan)),
        guardian=context.guardian,
    )


def test_model_unavailable_blocks_only_the_step_that_was_entered(
    hierarchy: InProcessGuardian, registry: PromptRegistry, tmp_path: Path
) -> None:
    """An environment fault must not fabricate results for steps the graph never entered."""
    import importlib

    class UnavailableClient:
        def complete(self, call: ModelCall) -> ModelResponse:
            raise ModelUnavailable("test provider is offline")

    plan = importlib.import_module(CONDITION_MODULES["S1-HIER"]).build(registry)
    context = node_context(hierarchy, supervisor_id="", executor_id=EXECUTOR_ID)
    run = run_golden(
        guardian_url="in-process",
        out=tmp_path / "out",
        condition="S1-HIER",
        run_id=hierarchy.config.run_id,
        supervisor_id="",
        executor_id=EXECUTOR_ID,
        namespace=NAMESPACE,
        evidence_path=GOLDEN_EVIDENCE,
        client=UnavailableClient(),
        guardian=context.guardian,
    )

    assert len(run.results) == 1
    failed = run.results[0]
    assert (failed.role_id, failed.phase, failed.outcome) == (
        plan.steps[0].role_id,
        plan.steps[0].phase,
        "blocked",
    )
    assert "model unavailable" in failed.summary
    assert run.phases_in_order() == (plan.steps[0].phase,)
    assert not any(result.phase in PHASES[1:] for result in run.results)


def test_build_state_graph_compiles_and_invokes_the_installed_runtime(
    hierarchy: InProcessGuardian, registry: PromptRegistry
) -> None:
    """Exercise the installed LangGraph API rather than only inspecting the builder's syntax."""
    import importlib

    pytest.importorskip("langgraph")

    class UnavailableClient:
        def complete(self, call: ModelCall) -> ModelResponse:
            raise ModelUnavailable("stop after entering the compiled graph")

    plan = importlib.import_module(CONDITION_MODULES["S1-HIER"]).build(registry)
    context = node_context(hierarchy, model=UnavailableClient())
    application = build_state_graph(plan, context)

    with pytest.raises(ModelUnavailable, match="stop after entering"):
        application.invoke({"results": []})


def test_the_golden_path_traverses_the_four_phases_in_order(
    hierarchy: InProcessGuardian, registry: PromptRegistry, tmp_path: Path
) -> None:
    """Row T-05's wording is "four phase spans present **in order**", so order is what is asserted.

    A set comparison would pass for a run that entered containment before detection, which is
    FR5.1's progression requirement quietly untrue.
    """
    run = _run("S1-HIER", hierarchy, registry, tmp_path / "out")
    assert run.phases_in_order() == PHASES, (
        f"the run traversed {run.phases_in_order()!r}; docs/02-architecture.md section 1.6 fixes "
        f"the order as {PHASES!r} and FR5.1 requires the run to progress through it"
    )
    assert all(result.outcome == RESOLVED for result in run.results), (
        "every step closed with a recorded outcome; a step that ended otherwise means the golden "
        f"path is not golden: {[(r.role_id, r.phase, r.outcome) for r in run.results]}"
    )


def test_each_executor_receives_its_phase_and_supervisor_minted_task(
    hierarchy: InProcessGuardian, registry: PromptRegistry, tmp_path: Path
) -> None:
    """The Executor's runtime context carries the task its Supervisor chose for this phase."""
    run = _run("S1-HIER", hierarchy, registry, tmp_path / "out")

    for phase in PHASES:
        first_call = next(
            message
            for message in run.recorder.messages
            if message["phase"] == phase and message["role_id"] == "executor"
        )
        runtime_context = first_call["context"]
        assert f'"phase":"{phase}"' in runtime_context, (
            f"the {phase!r} Executor was not told which phase it is executing; without the phase "
            "each Executor receives the same evidence and can repeat investigation work"
        )
        assert '"capability_scope":' in runtime_context, (
            f"the {phase!r} Executor was not given the task its Supervisor minted; without the "
            "scope it must infer a task from the same evidence every phase receives"
        )


def test_a_supervisor_cannot_mint_for_an_executor_the_graph_did_not_name(
    hierarchy: InProcessGuardian, registry: PromptRegistry, tmp_path: Path
) -> None:
    """The executor's identity belongs to the graph, never to the model's tool arguments.

    A live run on 2026-09-12 was denied ``scope.subject-mismatch`` on every single action. The cause
    was not agent behaviour: the mint took ``executor_id`` from the model's arguments while the
    submit took it from the run's own context, so the capability's ``sub`` named a string the
    supervisor had invented ("investigator-boutique-pod-inventory") and the action named the
    executor. They could never agree. This scripts exactly that -- a supervisor minting for an
    invented executor -- and requires the run to complete anyway, which it can only do if the mint
    ignored the argument in favour of the context.
    """
    import importlib

    invented = "executor-a-supervisor-made-up"
    assert invented != EXECUTOR_ID

    plan = importlib.import_module(CONDITION_MODULES["S1-HIER"]).build(registry)
    script = script_for(plan)
    for call in script:
        if call is not None and call.name == ISSUE_TOKEN_TOOL.name:
            call.arguments["executor_id"] = invented

    context = node_context(hierarchy, supervisor_id="", executor_id=EXECUTOR_ID)
    run = run_golden(
        guardian_url="in-process",
        out=tmp_path / "out",
        condition="S1-HIER",
        run_id=hierarchy.config.run_id,
        supervisor_id="",
        executor_id=EXECUTOR_ID,
        namespace=NAMESPACE,
        evidence_path=GOLDEN_EVIDENCE,
        client=ScriptedClient(script),
        guardian=context.guardian,
    )

    assert all(result.outcome == RESOLVED for result in run.results), (
        "a model-supplied executor_id must not reach the token subject; every action was denied: "
        f"{[(r.role_id, r.phase, r.outcome, r.summary) for r in run.results]}"
    )
    reasons = [record.get("reason_code") for record in hierarchy.audit_records()]
    assert "scope.subject-mismatch" not in reasons, (
        "the capability's subject did not match the executor that submitted the action, which is "
        f"the 2026-09-12 defect exactly: {reasons!r}"
    )
    assert all(record["decision"] == "permit" for record in hierarchy.audit_records()), (
        f"every scripted action is inside its minted scope: {reasons!r}"
    )


def test_the_trace_nests_every_node_span_inside_its_phase_span(
    hierarchy: InProcessGuardian, registry: PromptRegistry, tmp_path: Path
) -> None:
    """A flat trace carries the same span names and says nothing about phase membership."""
    out = tmp_path / "out"
    _run("S1-HIER", hierarchy, registry, out)
    assert SPANS_FILE == "spans.otel.json"
    assert (out / SPANS_FILE).is_file()
    assert not (out / "spans.jsonl").exists()
    spans = read_spans(out / SPANS_FILE)
    by_id = {span["span_id"]: span for span in spans}

    phase_spans = [span["attributes"]["phase"] for span in spans if span["name"] == "phase"]
    assert tuple(phase_spans) == PHASES, f"phase spans {phase_spans!r}, expected {list(PHASES)!r}"

    node_spans = [span for span in spans if span["name"] == "node"]
    assert node_spans, (
        "no node span was emitted, so the trace records the phases and nothing inside them"
    )
    for span in node_spans:
        parent = by_id.get(span["parent_id"] or "")
        assert parent is not None and parent["name"] == "phase", (
            f"node span {span['attributes'].get('role')!r} has parent "
            f"{(parent or {}).get('name')!r}; every node runs inside the phase span that wraps it"
        )
        assert parent["attributes"]["phase"] == span["attributes"]["phase"], (
            "a node span is nested inside a phase span for a different phase"
        )


def test_every_model_call_is_recorded_verbatim_with_its_exact_model_string(
    hierarchy: InProcessGuardian, registry: PromptRegistry, tmp_path: Path
) -> None:
    """The Definition of done says "verbatim messages captured" and "the exact model string".

    Verbatim means the bytes that were sent, not a summary and not a digest: the ``G0``/``G3``
    prompt comparison is a comparison of bytes, and a recorded summary could not support it. The
    model string is what the provider **answered** under rather than the alias that was asked for,
    because risk R-01 is the two silently ceasing to be the same thing.
    """
    out = tmp_path / "out"
    run = _run("S1-HIER", hierarchy, registry, out)

    messages = [
        json.loads(line)
        for line in (out / MESSAGES_FILE).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    tokens = json.loads((out / TOKENS_FILE).read_text(encoding="utf-8"))

    assert len(messages) == len(run.recorder.messages) > 0
    assert len(tokens) == len(messages), (
        f"{len(tokens)} tokens entr(y/ies) for {len(messages)} model call(s); every LLM call needs "
        "one, because data-management.md requires the exact model identity per call"
    )

    # Keyed by every composed role, not just the roles that appear as their own plan step: since
    # ADR-092 a phase-planning step's Supervisor calls also share the step with a freshly built
    # Executor's calls, and both must be checked against the composed text of the role that
    # actually spoke -- which agents.graphs.nodes._ask now attributes per call rather than per step.
    composed = {role_id: role.text for role_id, role in run.plan.composed.roles.items()}
    for message in messages:
        assert message["system"] == composed[message["role_id"]], (
            f"the recorded system prompt for {message['role_id']!r} is not the composed prompt "
            "byte for byte, so messages.jsonl is a paraphrase rather than the record"
        )
        assert message["phase"] in PHASES
    for entry in tokens:
        assert entry["model"], "a tokens entry with no model string records nothing about R-01"


def test_every_action_reaches_the_guardian_and_lands_in_the_audit_chain(
    hierarchy: InProcessGuardian, registry: PromptRegistry, tmp_path: Path
) -> None:
    """T-07 and T-09's agent half: the only mutation path is the Guardian, and it audits each one.

    Asserted over the audit **file**, because that is what ``make audit-verify`` reads and what
    ``security-policy.md`` section 1.4 requires to exist. An in-memory count would be asserting over
    the wrong artefact.
    """
    out = tmp_path / "out"
    run = _run("S1-HIER", hierarchy, registry, out)

    submitted = [
        action
        for result in run.results
        for action in result.actions
        if action.get("kind") == "action"
    ]
    assert len(submitted) == len(PHASES), (
        f"{len(submitted)} action(s) submitted across {len(PHASES)} phases; the script submits one "
        "per phase, so a different count means a phase acted twice or not at all"
    )
    for action in submitted:
        assert action["decided"] is True, (
            f"the Guardian reached no decision on {action['request_id']!r} "
            f"({action.get('error')!r})"
        )
        assert action["audit_seq"] is not None

    records = hierarchy.audit_records()
    assert len(records) == len(submitted), (
        f"{len(records)} audit record(s) for {len(submitted)} action(s). security-policy.md "
        "section 1.4 requires exactly one hash-chained record per decision: none is an unaudited "
        "outcome and two is a decision counted twice"
    )
    assert [record["seq"] for record in records] == sorted(record["seq"] for record in records)


def test_a_supervisor_mints_the_scope_its_own_phase_spends(
    hierarchy: InProcessGuardian, registry: PromptRegistry, tmp_path: Path
) -> None:
    """Conflict M4-C7 exercised: four issuers, one Guardian, and no code difference between arms.

    The Guardian denies ``TOKEN_ISSUER_UNKNOWN`` for an ``iss`` it does not know. A run registering
    one Supervisor would be denied in three phases out of four, so this test both proves the
    registered set is read from the manifest and would fail loudly if it stopped being.
    """
    out = tmp_path / "out"
    run = _run("S1-HIER", hierarchy, registry, out)

    issued = [
        record
        for result in run.results
        for record in result.actions
        if record.get("kind") == "issue"
    ]
    assert len(issued) == len(PHASES), f"{len(issued)} mint(s) across {len(PHASES)} phases"
    for record in issued:
        assert record["refused"] is False, (
            f"a mint was refused ({record['error']!r}). Every phase Supervisor is a registered "
            "issuer for this run because agents.golden.registered_issuers reads them from the "
            "composition manifest -- conflict M4-C7's resolution by configuration"
        )
        assert record["jti"], "a granted mint carries the jti the audit log attributes actions to"
        assert "token" not in record, (
            "a phase result must never carry the bearer string: TokenIssueResponse is the one "
            "model in the repository that holds one, and a run bundle is born clean"
        )


def test_the_manifest_ties_the_artefacts_to_the_registry_that_produced_them(
    hierarchy: InProcessGuardian, registry: PromptRegistry, tmp_path: Path
) -> None:
    """``golden.json`` carries both registry digests and the pinned tokenizer's identity.

    Without them the trace is a run of *something*; with them it is a run of a registry somebody can
    check out. ``manifest.json`` requires ``prompt_registry_sha256`` and ``tool_registry_sha256``,
    and ADR-028 adds the tokenizer identity beside them because the parity numbers are only
    reproducible against a named tokenizer.
    """
    out = tmp_path / "out"
    run = _run("S1-HIER", hierarchy, registry, out)
    manifest = json.loads((out / MANIFEST_FILE).read_text(encoding="utf-8"))

    assert manifest == run.manifest
    assert len(manifest["prompt_registry_sha256"]) == 64
    assert len(manifest["tool_registry_sha256"]) == 64
    assert len(manifest["litellm_config_sha256"]) == 64
    assert manifest["model_alias"] == "overwatch-primary"
    assert manifest["model_provider_string"] == "scripted/none"
    assert manifest["parity_tokenizer"]
    assert manifest["phases"] == list(PHASES)
    assert manifest["registered_issuers"] == list(registered_issuers(run.plan.composition))
    assert (out / RESULTS_FILE).exists()


@pytest.mark.parametrize("condition", sorted(CONDITION_MODULES))
def test_every_topology_completes_the_same_four_phases(
    condition: str, registry: PromptRegistry, tmp_path: Path
) -> None:
    """The traversal is a property of the plan, not of the topology -- so all three arms close it.

    Row T-05 is asserted for every arm on the same evidence, which is only possible because deleting
    role tiers deletes delegation and not the incident lifecycle. This is also the test that would
    catch a topology quietly skipping a phase whose Supervisor its manifest forgot.
    """
    import importlib

    plan = importlib.import_module(CONDITION_MODULES[condition]).build(registry)
    guardian = build_in_process_guardian(
        tmp_path / condition, registered_issuers=registered_issuers(plan.composition)
    )
    run = _run(condition, guardian, registry, tmp_path / condition / "out")
    assert run.phases_in_order() == PHASES
    assert all(result.outcome == RESOLVED for result in run.results), (
        f"{condition}: {[(r.role_id, r.phase, r.outcome, r.summary) for r in run.results]}"
    )


def test_the_evidence_a_phase_sees_is_the_monitors_own_emitted_stream(tmp_path: Path) -> None:
    """The driver reads evidence from a path and never imports ``monitor/``.

    Which keeps the agent layer free of a build-time dependency on the Monitor and, more usefully,
    means the golden path consumes the same bytes at Tier A (a fixture) and at Tier B (a live
    aggregator). It also means the ``G3-UNQUOTED`` exercise is a different input file rather than a
    different code path -- ADR-023's discipline, which every arm is held to.
    """
    grouped = load_evidence(GOLDEN_EVIDENCE)
    assert set(grouped) == set(PHASES), (
        "every phase is offered every event: the Monitor triages, it does not plan, and filtering "
        "in the driver would be the driver quietly doing the detection phase's job"
    )
    events = grouped[PHASES[0]]
    assert events, f"{GOLDEN_EVIDENCE} carried no events"
    assert all("summary" in event for event in events)
    assert load_evidence(None) == {phase: [] for phase in PHASES}
