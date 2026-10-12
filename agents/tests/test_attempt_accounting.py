r"""ADR-060 at the node and recorder boundaries: what one call may cost, and what a bundle keeps.

WHAT THIS FILE PINS
-------------------
``agents/tests/test_model_tool_validation.py`` covers the client itself -- the wire object, the
per-attempt record and the client-side cap. This file covers the two places that consume them.

*A node offers the client the turns it has left, and no more.* ADR-028 makes a retry a turn, and the
ledger has always charged for one after the fact. ADR-060 puts the same bound on the request:
:func:`agents.graphs.nodes._ask` passes ``ledger.turns_remaining`` as
:attr:`~agents.registry.model.ModelCall.max_attempts`, and a node with no turn left sends nothing at
all. The overspend path ``agents/tests/test_executor_lifecycle.py`` pins is untouched -- a client
that reports more attempts than it was allowed is still charged for them and still ends the phase
``budget-exhausted`` -- and its doubles ignore the cap precisely so that it stays reachable.

*A consolidator that got no usable answer is blocked, not resolved.* The consolidation fallback used
to be ``resolved`` with the answer text. Live, it was never reached, because a failing one-turn role
was retried past its budget and ended ``budget-exhausted``; once attempts are capped at the turns
left, it would be the path every failed consolidator takes, recording a model failure as a success.

*The recorder adds and never changes.* ``messages.jsonl`` and ``tokens.json`` are read by
``runner/`` and ``analysis/`` code this change does not own, so every key written before ADR-060 is
asserted present with its old meaning, and the new keys are asserted to be exactly ADR-060's.
"""

from __future__ import annotations

import json
from typing import Any

from agents.golden import RecordingClient
from agents.graphs.nodes import bounded_execution_node, consolidation_node
from agents.registry.composer import compose_condition
from agents.registry.loader import Budget, PromptRegistry
from agents.registry.model import (
    TOOL_WIRE_SHAPE,
    AttemptRecord,
    ModelCall,
    ModelResponse,
    ModelUnavailable,
    RawToolCall,
    ScriptedClient,
    ToolCall,
)
from agents.tools.registry import ACTION_TOOL, COMPLETE_PHASE_TOOL, PHASE_OUTCOMES, definitions_for
from harness import NAMESPACE, InProcessGuardian, node_context

CONDITION = "S1-HIER"
PHASE = "containment"
RESOLVED, BLOCKED, BUDGET_EXHAUSTED = PHASE_OUTCOMES

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
COMPLETE_ANSWER = ToolCall(
    name=COMPLETE_PHASE_TOOL.name,
    arguments={"outcome": RESOLVED, "summary": "closed"},
)

# The keys agents/golden.py wrote before ADR-060, which runner/ and analysis/ read today, and the
# keys ADR-060 adds beside them.
PRE_ADR_060_MESSAGE_KEYS = frozenset(
    {
        "index",
        "phase",
        "role_id",
        "system",
        "context",
        "tools",
        "seed",
        "answer_text",
        "tool_call",
        "malformed_attempts",
    }
)
PRE_ADR_060_TOKEN_KEYS = frozenset(
    {
        "index",
        "phase",
        "role_id",
        "model_alias",
        "model",
        "attempts",
        "prompt_tokens",
        "completion_tokens",
    }
)
ADR_060_MESSAGE_KEYS = frozenset({"max_attempts", "tool_wire_shape", "attempt_outcomes"})
ADR_060_TOKEN_KEYS = frozenset({"attempt_usage"})

# M10's additions, and the reason they are additive rather than a change. D10 (V20) records the
# provider-returned model beside the string the call asked for, because LiteLLM's OpenAI-compatible
# transform reports the provider prefix plus whatever the backend echoes -- so a gateway that echoes
# the requested name yields the alias *by construction* and a bundle cannot tell "the provider
# answered under this model" from "the provider said nothing and we recorded what we asked". The
# three fields are nullable and never fall back, so an absent one is a fact rather than a gap.
#
# `tokens.json` gains them as three new top-level keys, on the accepted attempt -- which is what
# SEAM 1's `answered_model` and `system_fingerprints` read -- and inside `attempt_usage`, so a run
# with a mid-call retry is attributable per *request* rather than per call. `messages.jsonl` gains
# no new top-level key: the same three sit inside `attempt_outcomes`, per attempt, which is the
# level
# they describe. So the message-side set is empty and the additions are asserted in the two
# exact-list comparisons below instead -- a new key here would be a second copy of a value the row
# already carries one level down.
M10_D10_TOKEN_KEYS = frozenset({"system_fingerprint", "response_model", "hidden_params_model"})


def _role(registry: PromptRegistry, role_id: str) -> Any:
    """One role of the driven condition, composed from the shipped registry."""
    return compose_condition(registry, CONDITION).role(role_id)


def _budget(registry: PromptRegistry, role_id: str) -> Budget:
    """The allocation the shipped manifest declares for ``role_id`` in the driven phase."""
    return registry.compositions[CONDITION].budgets[PHASE][role_id]


# --------------------------------------------------------------------------------------------
# The node's side of the cap
# --------------------------------------------------------------------------------------------


def test_a_node_offers_the_client_exactly_the_turns_it_has_left(
    guardian: InProcessGuardian, registry: PromptRegistry
) -> None:
    """Each request's cap is what the ledger holds when it is sent, per the manifest's budget."""
    budget = _budget(registry, "executor")
    executor = bounded_execution_node(
        _role(registry, "executor"),
        budget=budget,
        tools=[ACTION_TOOL.name, COMPLETE_PHASE_TOOL.name],
    )
    model = ScriptedClient([ACTION_ANSWER, COMPLETE_ANSWER])

    result = executor(node_context(guardian, model=model), PHASE)

    assert [call.max_attempts for call in model.calls] == [
        budget.max_turns,
        budget.max_turns - 1,
    ], (
        f"the node offered caps {[call.max_attempts for call in model.calls]} against an "
        f"allocation of {budget.max_turns} turn(s). The first request may use the whole "
        "allocation; the second only what the first left, or a retry could spend a turn the "
        "budget never granted"
    )
    assert result.outcome == RESOLVED, f"{result.outcome!r}: {result.summary!r}"
    assert result.turns_spent == len(model.calls)


def test_a_node_with_no_turn_left_sends_no_request(
    guardian: InProcessGuardian, registry: PromptRegistry
) -> None:
    """The action spends the only turn; the loop then needs another and must not ask for one."""
    executor = bounded_execution_node(
        _role(registry, "executor"),
        budget=Budget(max_turns=1, max_tool_calls=4),
        tools=[ACTION_TOOL.name, COMPLETE_PHASE_TOOL.name],
    )
    model = ScriptedClient([ACTION_ANSWER, COMPLETE_ANSWER])

    result = executor(node_context(guardian, model=model), PHASE)

    assert len(model.calls) == 1, (
        f"the node sent {len(model.calls)} request(s) on a one-turn allocation. The second could "
        "only ever be discarded as over budget, so sending it spends provider tokens on an answer "
        "nothing may use"
    )
    assert result.outcome == BUDGET_EXHAUSTED
    assert result.turns_spent == 1, (
        f"the result reports {result.turns_spent} turn(s) spent; no request was made past the "
        "first, so none was charged"
    )


# --------------------------------------------------------------------------------------------
# The consolidation fallback the cap made reachable
# --------------------------------------------------------------------------------------------


def test_a_consolidator_whose_model_produced_no_usable_call_is_blocked(
    guardian: InProcessGuardian, registry: PromptRegistry
) -> None:
    """No usable answer is ``blocked``, as it is for every other node, and never ``resolved``."""
    node = consolidation_node(
        _role(registry, "consolidator"),
        budget=_budget(registry, "consolidator"),
        tools=[COMPLETE_PHASE_TOOL.name],
    )

    result = node(node_context(guardian, model=ScriptedClient([None])), PHASE)

    assert result.outcome == BLOCKED, (
        f"a consolidator whose model produced no usable call ended {result.outcome!r}. "
        "Recording it as resolved would report a model failure as a completed consolidation"
    )
    assert result.turns_spent == 1


def test_a_consolidator_that_closed_the_phase_records_the_outcome_it_chose(
    guardian: InProcessGuardian, registry: PromptRegistry
) -> None:
    """The control for the case above: an answered ``complete_phase`` is recorded as answered."""
    node = consolidation_node(
        _role(registry, "consolidator"),
        budget=_budget(registry, "consolidator"),
        tools=[COMPLETE_PHASE_TOOL.name],
    )
    answer = ToolCall(
        name=COMPLETE_PHASE_TOOL.name,
        arguments={"outcome": BUDGET_EXHAUSTED, "summary": "ran out"},
    )

    result = node(node_context(guardian, model=ScriptedClient([answer])), PHASE)

    assert (result.outcome, result.summary) == (BUDGET_EXHAUSTED, "ran out")


# --------------------------------------------------------------------------------------------
# The recorder: additive only
# --------------------------------------------------------------------------------------------


class _AnsweringClient:
    """Returns one response the test built, attempt log included. Sends nothing, decides nothing."""

    tool_wire_shape = TOOL_WIRE_SHAPE

    def __init__(self, response: ModelResponse) -> None:
        self._response = response

    def complete(self, call: ModelCall) -> ModelResponse:
        """Answer what the test said to answer."""
        del call
        return self._response


def test_the_recorder_adds_attempt_accounting_and_changes_no_existing_field() -> None:
    """Every pre-ADR-060 key keeps its meaning; the additions are ADR-060's and M10's."""
    rejected = AttemptRecord(
        attempt=1,
        model="fake/provider-model",
        finish_reason="tool_calls",
        prompt_tokens=120,
        completion_tokens=30,
        reasoning_tokens=25,
        system_fingerprint="fp_rejected_0001",
        response_model="fake/backend-model-a",
        hidden_params_model="backend-model-a",
        rejected_check="schema-mismatch",
        rejected_detail="required at $.summary",
        tool_calls=(
            RawToolCall(name=COMPLETE_PHASE_TOOL.name, arguments='{"outcome":"resolved"}'),
        ),
    )
    accepted = AttemptRecord(
        attempt=2,
        model="fake/provider-model",
        finish_reason="tool_calls",
        prompt_tokens=121,
        completion_tokens=31,
        reasoning_tokens=None,
        system_fingerprint="fp_accepted_0002",
        response_model="fake/backend-model-a",
        hidden_params_model="backend-model-a",
    )
    response = ModelResponse(
        tool_call=COMPLETE_ANSWER,
        provider_string="fake/provider-model",
        attempts=2,
        prompt_tokens=121,
        completion_tokens=31,
        raw_text="",
        malformed_attempts=("",),
        attempt_log=(rejected, accepted),
        system_fingerprint="fp_accepted_0002",
        response_model="fake/backend-model-a",
        hidden_params_model="backend-model-a",
    )
    recorder = RecordingClient(_AnsweringClient(response))
    recorder.where(phase=PHASE, role_id="consolidator")

    recorder.complete(
        ModelCall(
            system="system",
            context="context",
            tools=definitions_for([COMPLETE_PHASE_TOOL.name]),
            seed=7,
            max_attempts=2,
        )
    )

    (message,) = recorder.messages
    (tokens,) = recorder.tokens
    assert set(message) == PRE_ADR_060_MESSAGE_KEYS | ADR_060_MESSAGE_KEYS
    assert set(tokens) == PRE_ADR_060_TOKEN_KEYS | ADR_060_TOKEN_KEYS | M10_D10_TOKEN_KEYS

    # What already existed means what it meant: the accepted attempt's usage and the retry count.
    assert (tokens["attempts"], tokens["prompt_tokens"], tokens["completion_tokens"]) == (
        2,
        121,
        31,
    )
    assert tokens["model"] == "fake/provider-model"
    assert message["malformed_attempts"] == [""]
    assert message["tool_call"] == {
        "name": COMPLETE_ANSWER.name,
        "arguments": dict(COMPLETE_ANSWER.arguments),
    }

    # What ADR-060 adds.
    assert message["max_attempts"] == 2
    assert message["tool_wire_shape"] == TOOL_WIRE_SHAPE
    assert message["attempt_outcomes"] == [
        {
            "attempt": 1,
            "finish_reason": "tool_calls",
            "accepted": False,
            "rejected_check": "schema-mismatch",
            "rejected_detail": "required at $.summary",
            "system_fingerprint": "fp_rejected_0001",
            "response_model": "fake/backend-model-a",
            "hidden_params_model": "backend-model-a",
            "tool_calls": [
                {"name": COMPLETE_PHASE_TOOL.name, "arguments": '{"outcome":"resolved"}'}
            ],
        },
        {
            "attempt": 2,
            "finish_reason": "tool_calls",
            "accepted": True,
            "rejected_check": None,
            "rejected_detail": None,
            "system_fingerprint": "fp_accepted_0002",
            "response_model": "fake/backend-model-a",
            "hidden_params_model": "backend-model-a",
            "tool_calls": [],
        },
    ]
    assert tokens["attempt_usage"] == [
        {
            "attempt": 1,
            "model": "fake/provider-model",
            "system_fingerprint": "fp_rejected_0001",
            "response_model": "fake/backend-model-a",
            "hidden_params_model": "backend-model-a",
            "prompt_tokens": 120,
            "completion_tokens": 30,
            "reasoning_tokens": 25,
        },
        {
            "attempt": 2,
            "model": "fake/provider-model",
            "system_fingerprint": "fp_accepted_0002",
            "response_model": "fake/backend-model-a",
            "hidden_params_model": "backend-model-a",
            "prompt_tokens": 121,
            "completion_tokens": 31,
            "reasoning_tokens": None,
        },
    ]

    # What M10 adds on the accepted attempt, beside the answered model. D10 records the raw signals
    # so a reader can tell the two apart; here the backend's echo differs from the asked-for string,
    # which is the case V20 says a bundle used to be unable to show. `tokens.json` carries them at
    # the
    # top level (SEAM 1 reads them from there); `messages.jsonl` carries the per-attempt copies
    # inside `attempt_outcomes`, which the exact-list comparison above already holds.
    assert tokens["model"] == "fake/provider-model"
    assert tokens["response_model"] == "fake/backend-model-a"
    assert tokens["system_fingerprint"] == "fp_accepted_0002"
    assert tokens["hidden_params_model"] == "backend-model-a"

    # Both still serialise the way agents/golden.py writes them.
    json.dumps(message, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    json.dumps(tokens, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def test_model_unavailable_record_carries_index() -> None:
    """A model failure is recorded through the same accounting as an answer, never as a bare dict.

    V13, and the defect it names is a seal failure rather than a modelling one. The
    ``ModelUnavailable`` path used to append ``{"error": ...}`` to ``messages`` with no ``index``
    and
    nothing at all to ``tokens``, and ``runner/bundle.py``'s sealer refuses a ``messages.jsonl``
    line
    with "no non-negative integer 'index'". So a run whose provider was unreachable could not be
    sealed at all -- the bundle was invalid for a reason that had nothing to do with the failure it
    was trying to record, and 40 of the v1 campaign's 150 invalid directories carry exactly that
    detail. F-RN-01 states the rule the fix implements: every ``messages.jsonl`` entry, failure
    records included, carries an index matched in ``tokens.json``.

    Three claims, and the last is what stops this being a "non-null index" test:

    * the failure entry carries the **next** index and the tokens entry carries the **same** one, so
      the two files can be joined -- a per-file counter would produce two files that each look
      complete and cannot be paired;
    * it is recorded **after** a successful call rather than instead of it, so an index is a
      position in one call sequence and not a count of successes;
    * the model-echo fields are present and **null**. No request was sent, so there is no answered
      model to read one from, and the alternative -- carrying the alias -- is exactly the V20
      failure
      ADR-123 records: a bundle that cannot distinguish "the provider named no model" from "the
      provider said nothing and we recorded what we asked".
    """
    recorder = RecordingClient(ScriptedClient([COMPLETE_ANSWER]))
    recorder.where(phase=PHASE, role_id="consolidator")
    recorder.complete(
        ModelCall(
            system="system",
            context="context",
            tools=definitions_for([COMPLETE_PHASE_TOOL.name]),
            seed=7,
        )
    )
    recorder.where(phase=PHASE, role_id="consolidator")
    recorder.record_unavailable(ModelUnavailable("the gateway answered 503 for every attempt"))

    assert [entry["index"] for entry in recorder.messages] == [0, 1], (
        f"the recorded indices are {[entry.get('index') for entry in recorder.messages]}."
        " seal_bundle "
        "refuses a messages.jsonl line with no non-negative integer 'index', so a failure record "
        "without one makes the whole bundle invalid for a reason unrelated to the failure (V13)"
    )
    assert [entry["index"] for entry in recorder.tokens] == [0, 1], (
        f"the recorded indices are {[entry.get('index') for entry in recorder.tokens]}. F-RN-01"
        " pairs "
        "every messages.jsonl entry with a tokens.json entry, which is only possible if the two"
        " files "
        "share one counter"
    )

    failure, usage = recorder.messages[1], recorder.tokens[1]
    assert "error" in failure and "model unavailable" in failure["error"], (
        f"the failure entry carries {sorted(failure)}; a reader of messages.jsonl has to be able"
        " to "
        "tell a recorded failure from a recorded answer, and 'error' is the only field that says so"
    )
    assert failure["phase"] == PHASE and failure["role_id"] == "consolidator", (
        f"the failure entry lost the step attribution {failure!r}. It is the only thing that says "
        "which role ran out of provider, and a bundle records the step of every other entry"
    )
    assert usage["model"] is None, (
        f"the failure entry recorded model {usage['model']!r}. No request was sent, so there was"
        " no "
        "answered model; recording the alias is the V20 defect ADR-123 records"
    )
    assert "system_fingerprint" in usage and usage["system_fingerprint"] is None, (
        f"the failure entry's tokens row is {sorted(usage)}. D10's three fields are present and"
        " null "
        "on every row -- a field missing from one row is a schema that has to be read defensively, "
        "and a null is a fact: the provider named nothing"
    )
    # Both rows still serialise, which is what the sealer does first.
    json.dumps(failure, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    json.dumps(usage, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def test_a_scripted_call_records_that_no_request_was_sent() -> None:
    """A double sends nothing, so it has no wire shape and no attempt to account for."""
    recorder = RecordingClient(ScriptedClient([COMPLETE_ANSWER]))
    recorder.where(phase=PHASE, role_id="consolidator")

    recorder.complete(
        ModelCall(
            system="system",
            context="context",
            tools=definitions_for([COMPLETE_PHASE_TOOL.name]),
            seed=7,
        )
    )

    (message,) = recorder.messages
    (tokens,) = recorder.tokens
    assert message["tool_wire_shape"] is None
    assert message["max_attempts"] is None
    assert message["attempt_outcomes"] == []
    assert tokens["attempt_usage"] == []


# --------------------------------------------------------------------------------------------
# A spent budget ends the node; it does not unmake what the node already did
# --------------------------------------------------------------------------------------------


def test_a_budget_exhausted_node_keeps_the_actions_it_already_took(
    guardian: InProcessGuardian, registry: PromptRegistry
) -> None:
    """`budget-exhausted` reports the Guardian answers already recorded, not an empty trace.

    PhaseResult types `actions` as the agent-side trace that stands beside the Guardian's own
    chain, and says a run whose two disagree is a finding. Until `_exhausted` was passed the
    node's own state, every exhausted result reported `actions=()`, `model_attempts=0` and
    `malformed_calls=0` from the dataclass defaults, whatever had happened. Live on 2026-09-12
    that erased two Supervisors' issuance records from
    `runs/CAMP-20260912-gate1/RUN-G0-FULL-SCN-SIM-02-INJ-A-101/results.json` while the bundle's
    `guardian_audit.jsonl` carried a `permit` against the token one of them had minted -- a
    disagreement manufactured by the recorder, which is a false finding rather than no finding.
    """
    budget = Budget(max_turns=1, max_tool_calls=1)
    executor = bounded_execution_node(
        _role(registry, "executor"),
        budget=budget,
        tools=[ACTION_TOOL.name, COMPLETE_PHASE_TOOL.name],
    )
    # The one permitted action spends the only turn; exhaustion on the next loop must retain it.
    model = ScriptedClient([ACTION_ANSWER])

    result = executor(node_context(guardian, model=model), PHASE)

    assert result.outcome == BUDGET_EXHAUSTED, f"{result.outcome!r}: {result.summary!r}"
    assert result.actions, (
        "the node ended budget-exhausted reporting no actions, but it submitted at least one "
        f"action to the Guardian across {len(model.calls)} model call(s). An exhausted budget "
        "ends the node; it does not unmake the decisions the Guardian already recorded"
    )
    assert result.model_attempts >= len(result.actions), (
        f"model_attempts={result.model_attempts} against {len(result.actions)} recorded "
        "action(s); every action cost at least one attempt, so the counter cannot be lower"
    )
