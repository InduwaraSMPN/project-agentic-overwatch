r"""The G1 and G3 exercises: each arm changes its own target and demonstrably nothing else.

WHAT THIS MODULE PINS
---------------------
``docs/milestones/M4-agents.md``'s Definition-of-done item "G1/G3 exercised, each changing only its
target [T-13]", from the **agent layer's** side. The Guardian's own half is already proved by
``guardian/tests/test_flag_isolation.py``, which shows one policy bundle enforced two ways and
bounds the permitted differences to ``guardian_mode``, the enforcement field and the execution
block. What that suite cannot show is that the *agent layer* is unchanged between arms, because it
has no agent layer in it. That is this file's job.

WHY "EXERCISED" IS NOT THE SAME CLAIM AS "DIFFERENT"
------------------------------------------------------
A test that ran G0 and G1 and observed a difference would prove almost nothing: an arm that changed
the enforcement decision *and* the prompt, or the enforcement decision *and* the number of turns,
would pass it. §3.5.4's matched-condition requirement is that the arms differ in the manipulated
variable and in nothing else, so what is asserted here is a **confined** difference — the diff is
computed, and every field outside the permitted set is asserted equal.

HOW THE ARMS ARE REACHED, WHICH IS THE PART ADR-023 CONSTRAINS
----------------------------------------------------------------
Not by a flag in ``agents/``. There is none, there is no field on
:class:`~agents.graphs.nodes.NodeContext` able to hold one, and ``GuardianClient.healthy`` refuses
to report the Guardian's mode for the reason its own docstring gives — an agent that could read
``G1-LOGONLY`` could condition its behaviour on it, and the guardrail ablation would then measure
what an agent does when told enforcement is off.

So:

*G1-LOGONLY* is reached by **starting the Guardian differently**: one configuration mapping with
``GUARDIAN_MODE=G0-FULL``, one with ``GUARDIAN_MODE=G1-LOGONLY``, and the same graph driven against
each. That is exactly what M6's runner will do, so nothing about the mechanism changes when the
runner arrives.

*G3-UNQUOTED* is reached by **handing the renderer differently quoted evidence**. The flag is the
Monitor aggregator's, the arm's whole content is whether ``summary`` and ``evidence_excerpts[]``
arrive escaped, and ``monitor/tests/test_g3_isolation.py`` already proves the two forms are related
by an exact bijection. This file consumes the two forms and asserts what the agent layer does with
them is identical in structure.

THE RENDERER'S ARM-INVARIANCE IS THE LOAD-BEARING G3 CLAIM
------------------------------------------------------------
ADR-019's inherited finding is that the Monitor quotes ``summary`` and ``evidence_excerpts[]`` and
nothing else, while ``resource.ns``, ``resource.kind`` and ``resource.name`` carry attacker-settable
text — a pod name or an image reference is chosen by whoever created the workload. So in G0 **and**
in G3 those reach the Orchestrator unframed unless somebody frames them, and M2 could not fix it
without adding a field to a frozen contract or making G3 remove two properties instead of one.

:mod:`agents.registry.renderer` frames all nine fields, and frames them **identically in both
arms**. If the framing differed between arms, G3 would remove two properties rather than one and
§3.5.4's matched-condition requirement would fail — so the assertion here is that the rendered
prompt diff between G0 and G3 is confined to the bytes the aggregator quoted, and touches no framing
byte.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from agents.golden import registered_issuers, run_golden
from agents.graphs import CONDITION_MODULES
from agents.registry import PHASES
from agents.registry.loader import PromptRegistry
from agents.registry.model import ScriptedClient
from agents.registry.renderer import (
    EVENT_FRAME_CLOSE,
    EVENT_FRAME_OPEN,
    VALUE_FRAME_CLOSE,
    VALUE_FRAME_OPEN,
    render_evidence_events,
)
from guardian.app.models import GuardianMode
from harness import (
    InProcessGuardian,
    ScriptedPolicyEngine,
    build_in_process_guardian,
    counting_jti_factory,
    deny_default_result,
    node_context,
)
from test_golden_path import GOLDEN_EVIDENCE, _action, _complete, script_for

# The two fields ADR-023 assertion 2 permits an audit record to differ in between arms. The
# execution block is the third permitted difference and is not an AuditRecord field at all -- it
# belongs to ActionResult -- so it is asserted separately below, exactly as
# guardian/tests/test_flag_isolation.py splits its own 2a and 2b for the same reason.
PERMITTED_RECORD_DIFFERENCES = frozenset({"guardian_mode", "enforcement"})

# Derived from the record's content, so they differ whenever anything upstream of them differs.
# Excluded from the field-by-field comparison and asserted about separately: comparing them directly
# would report one difference per field that fed them and drown the finding that matters.
CHAIN_FIELDS = frozenset({"hash", "prev_hash"})

# The two quoted properties. monitor/aggregator/quoting.py escapes exactly these and the G3 arm
# disables that escaping; every other EvidenceEvent field is identical between the arms, which is
# what makes "the diff is confined to the quoted bytes" a checkable statement rather than a hope.
QUOTED_PROPERTIES = ("summary", "evidence_excerpts")


def _one_action_script() -> list[Any]:
    """Compatibility script for callers exercising one bounded-execution node."""
    return [_action("containment"), _complete("containment", "executor")]


def _run_one_action(guardian: InProcessGuardian) -> Any:
    """Compatibility driver for the original single-node G1 isolation tests."""
    from agents.graphs.nodes import _stash_token, build_node
    from agents.registry.composer import compose_condition
    from agents.registry.loader import load_registry

    registry = load_registry()
    composition = registry.compositions["S1-HIER"]
    composed = compose_condition(registry, "S1-HIER").role("executor")
    node = build_node(
        composed,
        budget=composition.budgets["containment"]["executor"],
        tools=composition.role("executor").tools,
    )
    context = node_context(guardian, model=ScriptedClient(_one_action_script()))
    issued = guardian.mint(phase="containment", verbs=("list",), resources=("pods",))
    assert not hasattr(issued, "error"), f"the suite could not mint a token: {issued!r}"
    _stash_token(context, str(issued["token"]))
    return node(context, "containment")


def _records_under(mode: GuardianMode, root: Path) -> tuple[list[dict[str, Any]], Any]:
    """Preserve the original one-node helper contract for external and older tests."""
    guardian = build_in_process_guardian(
        root,
        mode=mode,
        engine=ScriptedPolicyEngine(deny_default_result()),
        jti_factory=counting_jti_factory(),
    )
    result = _run_one_action(guardian)
    return [dict(record) for record in guardian.audit_records()], result


def _run_hierarchy(
    root: Path,
    registry: PromptRegistry,
    *,
    mode: GuardianMode = GuardianMode.G0_FULL,
    evidence_path: Path = GOLDEN_EVIDENCE,
) -> tuple[Any, InProcessGuardian]:
    """Drive the complete S1 golden graph with a scripted model and in-process Guardian."""
    import importlib

    plan = importlib.import_module(CONDITION_MODULES["S1-HIER"]).build(registry)
    guardian = build_in_process_guardian(
        root,
        mode=mode,
        engine=ScriptedPolicyEngine(deny_default_result()),
        registered_issuers=registered_issuers(plan.composition),
        jti_factory=counting_jti_factory(),
    )
    context = node_context(guardian, supervisor_id="", executor_id="")
    run = run_golden(
        guardian_url="in-process",
        out=root / "out",
        condition="S1-HIER",
        run_id=guardian.config.run_id,
        supervisor_id="",
        executor_id="",
        namespace=context.namespace,
        evidence_path=evidence_path,
        client=ScriptedClient(script_for(plan)),
        guardian=context.guardian,
    )
    assert run.phases_in_order() == PHASES
    return run, guardian


def _result_without_execution(result: Any) -> dict[str, Any]:
    """Project a PhaseResult while removing only the Guardian execution response field."""
    return {
        "role_id": result.role_id,
        "phase": result.phase,
        "outcome": result.outcome,
        "summary": result.summary,
        "turns_spent": result.turns_spent,
        "tool_calls_spent": result.tool_calls_spent,
        "model_attempts": result.model_attempts,
        "malformed_calls": result.malformed_calls,
        "actions": [
            {field: value for field, value in action.items() if field != "execution"}
            for action in result.actions
        ],
    }


def _executions(run: Any) -> list[Any]:
    """Return every action's execution block in traversal order."""
    return [
        action["execution"]
        for result in run.results
        for action in result.actions
        if action.get("kind") == "action"
    ]


def _messages_without_forwarded_execution(run: Any) -> list[dict[str, Any]]:
    """Remove only causal execution feedback (ADR-179's result frame, ADR-181's rendered status).

    Both are enforcement-dependent and nothing else: G1 executes the action and G0 refuses it, so
    the two runs are *expected* to differ there. Everything else -- system text, evidence, framing,
    the outcome vocabulary, the budgets -- must stay byte-equal, or the guardrail ablation is
    measuring a prompt difference rather than a guardrail.
    """
    messages = json.loads(json.dumps(run.recorder.messages))
    for message in messages:
        lines = []
        for line in message["context"].splitlines():
            if line.startswith('{"completed_results":'):
                frame = json.loads(line)
                for result in frame["completed_results"]:
                    for action in result["actions"]:
                        action.pop("execution", None)
                line = json.dumps(frame, sort_keys=True)
            elif "; execution status: " in line:
                # ADR-181 renders the Guardian's execution outcome into the acting role's own
                # context and into the Supervisor's view of its Executor's actions. G0's refused
                # action and G1's executed one differ here by design.
                line = line.split("; execution status: ")[0]
            lines.append(line)
        message["context"] = "\n".join(lines)
    return messages


def test_g1_complete_golden_graph_diff_is_confined_to_enforcement(
    registry: PromptRegistry, tmp_path: Path
) -> None:
    """Diff all four phases: only mode, enforcement, chain hashes, and execution may change."""
    g0_run, g0_guardian = _run_hierarchy(tmp_path / "g0", registry, mode=GuardianMode.G0_FULL)
    g1_run, g1_guardian = _run_hierarchy(tmp_path / "g1", registry, mode=GuardianMode.G1_LOGONLY)

    assert g0_guardian.assembled.policy_bundle.digest == g1_guardian.assembled.policy_bundle.digest
    # The same wiring now returns real execution outcomes to later nodes; G1's executed
    # action and G0's blocked action must differ there too. Every other byte stays equal.
    assert g0_run.recorder.messages != g1_run.recorder.messages
    assert _messages_without_forwarded_execution(g0_run) == _messages_without_forwarded_execution(
        g1_run
    )
    assert [_result_without_execution(result) for result in g0_run.results] == [
        _result_without_execution(result) for result in g1_run.results
    ]

    g0_records = [dict(record) for record in g0_guardian.audit_records()]
    g1_records = [dict(record) for record in g1_guardian.audit_records()]
    assert len(g0_records) == len(g1_records) == len(PHASES)
    observed: set[str] = set()
    for g0_record, g1_record in zip(g0_records, g1_records, strict=True):
        assert set(g0_record) == set(g1_record)
        differing = {field for field in g0_record if g0_record[field] != g1_record[field]}
        observed.update(differing)
        assert differing <= PERMITTED_RECORD_DIFFERENCES | CHAIN_FIELDS, (
            f"audit seq {g0_record['seq']} differs in {sorted(differing)}; G1 may change only "
            "guardian_mode, enforcement, and hash-chain fields derived from them"
        )
        for field in ("decision", "reason_code", "policy_rule_id", "action", "request_id"):
            assert g0_record[field] == g1_record[field]
    assert PERMITTED_RECORD_DIFFERENCES <= observed

    g0_executions = _executions(g0_run)
    g1_executions = _executions(g1_run)
    assert len(g0_executions) == len(g1_executions) == len(PHASES)
    assert len(g0_guardian.assembled.executor.calls) == 0
    assert len(g1_guardian.assembled.executor.calls) == len(PHASES)
    assert all(left["status"] == "not-attempted" for left in g0_executions)
    assert all(right["status"] == "succeeded" for right in g1_executions)
    assert all(left != right for left, right in zip(g0_executions, g1_executions, strict=True)), (
        "every denied golden-path action must be blocked in G0 and executed in G1; an identical "
        "execution block means the arm was not exercised in that phase"
    )


# ------------------------------------------------------------------------------------------------
# G3-UNQUOTED
# ------------------------------------------------------------------------------------------------


def _events() -> list[dict[str, Any]]:
    """The Monitor's own emitted events for the golden incident, quoted as the G0 arm emits them."""
    lines = GOLDEN_EVIDENCE.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _unquoted(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return the same events as the ``G3-UNQUOTED`` arm emits them: the two properties unescaped.

    Built with ``monitor.aggregator.quoting.unquote``, which
    ``monitor/tests/test_g3_isolation.py`` proves is the exact inverse of what the G0 arm applied.
    Deriving the G3 form rather than shipping a second fixture is what keeps this test honest about
    the arms being one transformation apart: a hand-written "unquoted" fixture could differ in
    anything and this file would not notice.
    """
    from monitor.aggregator.quoting import unquote

    out: list[dict[str, Any]] = []
    for event in events:
        copy = dict(event)
        copy["summary"] = unquote(str(event["summary"]))
        copy["evidence_excerpts"] = [unquote(str(item)) for item in event["evidence_excerpts"]]
        out.append(copy)
    return out


@pytest.fixture
def arms() -> tuple[str, str]:
    """The rendered evidence block under G0 and under G3, from the same events."""
    events = _events()
    return render_evidence_events(events), render_evidence_events(_unquoted(events))


def _write_unquoted_evidence(path: Path) -> Path:
    """Write the exact G3 inverse of the Monitor's quoted golden stream as JSONL."""
    path.write_text(
        "".join(json.dumps(event, sort_keys=True) + "\n" for event in _unquoted(_events())),
        encoding="utf-8",
    )
    return path


def test_g3_complete_golden_graph_prompt_diff_is_confined_to_quoted_evidence(
    registry: PromptRegistry, tmp_path: Path, arms: tuple[str, str]
) -> None:
    """Drive all twelve S1 steps and bound every rendered prompt difference to G3's input bytes."""
    g0_run, g0_guardian = _run_hierarchy(tmp_path / "g0", registry)
    g3_run, g3_guardian = _run_hierarchy(
        tmp_path / "g3",
        registry,
        evidence_path=_write_unquoted_evidence(tmp_path / "g3-evidence.jsonl"),
    )

    # G3 is upstream of Guardian mediation. The complete graph must therefore produce identical
    # results and audit records while every model call differs only by substituting the rendered
    # evidence block derived from the two Monitor forms.
    assert [_result_without_execution(result) for result in g0_run.results] == [
        _result_without_execution(result) for result in g3_run.results
    ]
    assert _executions(g0_run) == _executions(g3_run)
    assert g0_guardian.audit_records() == g3_guardian.audit_records()

    g0_evidence, g3_evidence = arms
    assert len(g0_run.recorder.messages) == len(g3_run.recorder.messages) > len(PHASES)
    for g0_message, g3_message in zip(
        g0_run.recorder.messages, g3_run.recorder.messages, strict=True
    ):
        for field in set(g0_message) - {"context"}:
            assert g0_message[field] == g3_message[field], (
                f"model call {g0_message['index']} differs in {field!r}; G3 may alter only the "
                "rendered evidence bytes inside context"
            )
        assert g0_evidence in g0_message["context"]
        assert g3_evidence in g3_message["context"]
        assert g0_message["context"].replace(g0_evidence, g3_evidence, 1) == g3_message["context"]


def test_the_g0_and_g3_prompts_differ_only_in_the_bytes_the_aggregator_quoted(
    arms: tuple[str, str],
) -> None:
    """The G3 claim, stated as a bound on the difference rather than as its existence.

    The framing structure is byte-identical: the same number of event frames, the same number of
    value frames, the same field labels in the same order. What differs is inside two of the values,
    which is exactly the property the aggregator arm removes.
    """
    g0, g3 = arms
    assert g0 != g3, (
        "the two arms rendered identical prompts, so either the fixture carries nothing the "
        "aggregator escapes or the unquoting did nothing -- and the G3 arm would then be a "
        "condition that changes nothing"
    )
    for delimiter in (EVENT_FRAME_OPEN, EVENT_FRAME_CLOSE, VALUE_FRAME_OPEN, VALUE_FRAME_CLOSE):
        assert g0.count(delimiter) == g3.count(delimiter), (
            f"the arms carry different numbers of {delimiter!r}. The renderer's framing must be "
            "arm-invariant: if it differed, G3 would remove two properties instead of one and "
            "section 3.5.4's matched-condition requirement would fail"
        )

    g0_lines = g0.splitlines()
    g3_lines = g3.splitlines()
    assert len(g0_lines) == len(g3_lines), "the arms rendered different numbers of lines"
    differing = [
        line.split(":", 1)[0].strip()
        for line, other in zip(g0_lines, g3_lines, strict=True)
        if line != other
    ]
    assert differing, "no line differs, so the comparison below asserts nothing"
    assert all(
        any(label.startswith(prop) or prop in label for prop in QUOTED_PROPERTIES)
        for label in differing
    ), (
        f"lines differ at {sorted(set(differing))}, and the aggregator quotes only "
        f"{list(QUOTED_PROPERTIES)}. A difference elsewhere means the arm changed something "
        "besides the escaping of the two properties it is defined by"
    )


def test_attacker_settable_resource_text_is_framed_in_both_arms(arms: tuple[str, str]) -> None:
    """ADR-019's inherited finding, closed on the renderer's side rather than on the Monitor's.

    ``resource.ns``, ``resource.kind`` and ``resource.name`` are chosen by whoever created the
    workload and the Monitor quotes none of them, so in G0 **and** in G3 they would reach the
    Orchestrator unframed if the renderer framed only what the aggregator quoted. Nothing in
    ``monitor/`` is touched and no schema is amended: the renderer frames all nine fields, and this
    asserts it holds in both arms.
    """
    events = _events()
    resource = events[0]["resource"]
    for key in ("ns", "kind", "name"):
        value = resource.get(key)
        if not value:
            continue
        framed = f"{VALUE_FRAME_OPEN}{value}{VALUE_FRAME_CLOSE}"
        for arm, rendered in zip(("G0", "G3"), arms, strict=True):
            assert framed in rendered, (
                f"{arm}: resource.{key} = {value!r} is not framed in the rendered evidence. It is "
                "attacker-settable text the Monitor does not quote, so the renderer is the only "
                "thing standing between it and the instruction stream"
            )


def test_the_arms_are_reached_by_configuration_and_never_by_a_field_in_agents(
    tmp_path: Path,
) -> None:
    """ADR-023 restated as an assertion: there is nowhere in ``agents/`` to put an arm.

    A structural check rather than a behavioural one, and it earns its place because the behavioural
    tests above would keep passing if somebody added the field and simply did not use it yet.
    """
    from agents.graphs.nodes import NodeContext

    fields = set(NodeContext.__dataclass_fields__)
    forbidden = {"mode", "guardian_mode", "arm", "condition", "quoting_enabled", "enforce"}
    assert not (fields & forbidden), (
        f"NodeContext declares {sorted(fields & forbidden)}. ADR-023 keeps every condition flag in "
        "the runner's hands: a node that could read the arm could condition its behaviour on it, "
        "and the ablation would measure the agent's response to being told rather than the effect "
        "of the removal"
    )

    guardian = build_in_process_guardian(tmp_path, mode=GuardianMode.G1_LOGONLY)
    public = {name for name in dir(guardian.client) if not name.startswith("_")}
    assert not (public & {"mode", "guardian_mode", "config"}), (
        "the Guardian client exposes the arm to its caller; healthz reports liveness and nothing "
        "else for exactly this reason"
    )
    assert guardian.client.healthy() is True
