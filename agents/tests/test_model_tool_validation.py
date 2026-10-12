r"""LiteLLM tool calls are accepted only when the shared registry says they are valid.

These are Tier A tests: the fake backend has LiteLLM's narrow ``completion`` shape but performs no
network call. The assertions pin ADR-028's accounting boundary as well as validation: every rejected
provider response remains visible in ``ModelResponse.attempts`` and ``malformed_attempts``.

ADR-060 adds three things pinned at the same boundary: the wire object each registry tool is sent as
(a function whose ``parameters`` is the registry schema, and nothing internal); a per-attempt record
of usage, finish reason and the check that rejected an answer; and the cap a call may place on the
client's attempts, which the graph sets to the turns a node has left.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping, Sequence
from typing import Any

import pytest
from agents.golden import RecordingClient
from agents.graphs.nodes import coordination_node
from agents.registry import STRUCTURE_CONDITIONS
from agents.registry.composer import compose_condition
from agents.registry.loader import PromptRegistry
from agents.registry.model import (
    REASONING_EFFORT,
    REJECTION_CHECKS,
    SUPPORTED_REASONING_EFFORTS,
    TOOL_WIRE_SHAPE,
    LiteLLMClient,
    LiteLLMConfig,
    ModelCall,
    RawToolCall,
    wire_tool,
)
from agents.tools.registry import PHASE_OUTCOMES, TOOL_NAMES, definitions_for, tool_definition
from harness import InProcessGuardian, node_context


class FakeLiteLLM:
    """Return scripted completion mappings and record how many provider attempts were made."""

    def __init__(self, completions: Sequence[Mapping[str, Any]]) -> None:
        self.completions = list(completions)
        self.calls = 0
        self.kwargs: list[dict[str, Any]] = []

    def completion(self, **kwargs: Any) -> Mapping[str, Any]:
        self.calls += 1
        self.kwargs.append(kwargs)
        return self.completions.pop(0)


def completion(
    name: str | None,
    arguments: Any,
    *,
    content: str = "",
    usage: tuple[int, int, int | None] | None = None,
    finish_reason: str | None = None,
) -> dict[str, Any]:
    """A provider response carrying one tool call. ``usage`` is (prompt, completion, reasoning)."""
    return answer(
        [{"function": {"name": name, "arguments": arguments}}],
        content=content,
        usage=usage,
        finish_reason=finish_reason,
    )


def answer(
    tool_calls: list[dict[str, Any]] | None,
    *,
    content: str = "",
    usage: tuple[int, int, int | None] | None = None,
    finish_reason: str | None = None,
) -> dict[str, Any]:
    """A provider response in LiteLLM's mapping shape, with optional usage and finish reason."""
    choice: dict[str, Any] = {"message": {"content": content, "tool_calls": tool_calls}}
    if finish_reason is not None:
        choice["finish_reason"] = finish_reason
    response: dict[str, Any] = {"model": "fake/provider-model", "choices": [choice]}
    if usage is not None:
        prompt, produced, reasoning = usage
        response["usage"] = {
            "prompt_tokens": prompt,
            "completion_tokens": produced,
            "completion_tokens_details": {"reasoning_tokens": reasoning},
        }
    return response


def call(*tool_names: str) -> ModelCall:
    return ModelCall(
        system="system",
        context="context",
        tools=definitions_for(tool_names),
        seed=7,
    )


def client(scripted: Sequence[Mapping[str, Any]]) -> tuple[LiteLLMClient, FakeLiteLLM]:
    backend = FakeLiteLLM(scripted)
    # Bypass __init__ so this Tier A test neither imports the large provider SDK nor lets its global
    # object graph leak into unrelated reachability tests. The constructor's lazy import is covered
    # separately; this test exercises only the completion boundary.
    instance = LiteLLMClient.__new__(LiteLLMClient)
    instance._litellm = backend
    instance.config = LiteLLMConfig({"fake-alias": "fake/requested-model"})
    instance.alias = instance.config.alias
    instance.provider_string = instance.config.provider_string
    instance.max_attempts = len(scripted)
    instance.timeout_seconds = 1.0
    return instance, backend


def test_completion_addresses_the_alias_and_preserves_answered_provider() -> None:
    model, backend = client(
        [completion("complete_phase", {"outcome": "resolved", "summary": "done"})]
    )

    response = model.complete(call("complete_phase"))

    assert backend.kwargs[0]["model"] == "fake-alias"
    assert backend.kwargs[0]["temperature"] == 0.0
    assert backend.kwargs[0]["reasoning_effort"] == REASONING_EFFORT
    assert backend.kwargs[0]["allowed_openai_params"] == ["reasoning_effort"]
    assert backend.kwargs[0]["seed"] == 7
    assert response.provider_string == "fake/provider-model"


def test_reasoning_effort_is_a_value_the_endpoint_accepts() -> None:
    """ADR-005: the provider definition asks for "max"; the endpoint rejects it and lists its own.

    Pinned offline so a silent edit to the constant fails here rather than at the first live call.
    """
    assert REASONING_EFFORT in SUPPORTED_REASONING_EFFORTS
    assert "max" not in SUPPORTED_REASONING_EFFORTS


@pytest.mark.parametrize(
    ("bad_name", "bad_arguments"),
    [
        ("not_in_the_registry", {}),
        ("complete_phase", {"outcome": "resolved"}),
        ("complete_phase", {"outcome": "not-an-outcome", "summary": "done"}),
        ("complete_phase", {"outcome": "resolved", "summary": "done", "extra": True}),
    ],
)
def test_invalid_registry_call_is_malformed_and_retry_is_counted(
    bad_name: str, bad_arguments: Mapping[str, Any]
) -> None:
    model, backend = client(
        [
            completion(bad_name, bad_arguments, content="invalid attempt"),
            completion("complete_phase", {"outcome": "resolved", "summary": "done"}),
        ],
    )

    response = model.complete(call("complete_phase"))

    assert response.tool_call is not None
    assert response.tool_call.name == "complete_phase"
    assert response.attempts == 2
    assert response.malformed_attempts == ("invalid attempt",)
    assert response.provider_string == "fake/provider-model"
    assert backend.calls == 2


def test_nested_registry_schema_is_enforced() -> None:
    invalid_action = {
        "verb": "get",
        "resource": "pods",
        "namespace": "boutique",
        "name": None,
        "params": {"limit": 10},
        "justification": "inspect",
    }
    model, _backend = client(
        [
            completion("guardian_action", invalid_action),
            completion("complete_phase", {"outcome": "blocked", "summary": "bad action"}),
        ],
    )

    response = model.complete(call("guardian_action", "complete_phase"))

    assert response.tool_call is not None
    assert response.tool_call.name == "complete_phase"
    assert response.attempts == 2
    assert len(response.malformed_attempts) == 1


def test_registered_but_unoffered_tool_is_malformed() -> None:
    model, _backend = client(
        [
            completion(
                "guardian_action",
                {
                    "verb": "get",
                    "resource": "pods",
                    "namespace": "boutique",
                    "name": None,
                    "params": {},
                    "justification": "inspect",
                },
            ),
            completion("complete_phase", {"outcome": "blocked", "summary": "no action"}),
        ],
    )

    response = model.complete(call("complete_phase"))

    assert response.tool_call is not None
    assert response.tool_call.name == "complete_phase"
    assert response.attempts == 2
    assert len(response.malformed_attempts) == 1


def test_schema_invalid_calls_exhaust_budget_with_all_attempts_reported() -> None:
    model, backend = client(
        [
            completion("complete_phase", {"outcome": "resolved"}, content="missing summary"),
            completion(
                "complete_phase", {"outcome": "resolved", "summary": 42}, content="wrong type"
            ),
            completion("unknown", {}, content="unknown name"),
        ],
    )

    response = model.complete(call("complete_phase"))

    assert response.tool_call is None
    assert response.attempts == 3
    assert response.malformed_attempts == ("missing summary", "wrong type", "unknown name")
    assert response.raw_text == "unknown name"
    assert backend.calls == 3


# --------------------------------------------------------------------------------------------
# ADR-060: the wire shape
# --------------------------------------------------------------------------------------------

# The registry projection's own keys, none of which an OpenAI-compatible function object defines.
# Sending them in place of `parameters` is the defect ADR-060 records.
INTERNAL_PROJECTION_KEYS = frozenset({"dialect", "doc_block", "schema"})

COMPLETE = '{"outcome": "resolved", "summary": "done"}'


def test_every_offered_tool_goes_on_the_wire_with_the_registry_schema_as_its_parameters() -> None:
    """An OpenAI-compatible endpoint reads ``name`` and ``parameters``, so that is what is sent.

    Until ADR-060 the registry projection itself was the function object: the provider received a
    name, three keys it does not define, and no argument schema. Every offered tool is checked, in
    the order it was offered.
    """
    model, backend = client([completion("complete_phase", COMPLETE)])

    model.complete(call(*TOOL_NAMES))

    sent = backend.kwargs[0]["tools"]
    assert [tool["function"]["name"] for tool in sent] == [
        definition["name"] for definition in definitions_for(TOOL_NAMES)
    ]
    for tool in sent:
        function = tool["function"]
        assert tool == {"type": "function", "function": function}
        assert set(function) == {"name", "parameters"}, (
            f"{function.get('name')!r} went out carrying {sorted(function)}. An OpenAI-compatible "
            "function object is a name and a parameters schema; a description is deliberately "
            "absent because the tool's documentation block is already in the system prompt"
        )
        assert not INTERNAL_PROJECTION_KEYS & set(function)
        assert function["parameters"] == tool_definition(function["name"]).schema


def test_the_wire_mapping_leaves_the_recorded_projection_and_the_registry_untouched() -> None:
    """``tool_registry_sha256`` is computed over the projection, so the projection must not move.

    The parameters object is a deep copy, so nothing a provider library does to a request can reach
    the registry's module-level schema singletons or the projection a bundle records.
    """
    offered = definitions_for(TOOL_NAMES)
    before = copy.deepcopy(offered)
    model, backend = client([completion("complete_phase", COMPLETE)])

    model.complete(ModelCall(system="system", context="context", tools=offered, seed=7))

    assert offered == before
    for definition in offered:
        assert set(definition) == {"name", "dialect", "doc_block", "schema"}
    for tool, definition in zip(backend.kwargs[0]["tools"], offered, strict=True):
        parameters = tool["function"]["parameters"]
        registry_schema = tool_definition(definition["name"]).schema
        assert parameters == definition["schema"] == registry_schema
        assert parameters["properties"] is not registry_schema["properties"], (
            "the wire parameters share nested objects with the registry's schema singleton"
        )


@pytest.mark.parametrize("condition", STRUCTURE_CONDITIONS)
def test_every_role_carries_the_documentation_block_of_every_tool_it_holds(
    registry: PromptRegistry, condition: str
) -> None:
    """Why no ``description`` is sent: each holder already reads the tool's documentation.

    :func:`agents.registry.model.wire_tool` omits ``description`` because every role that holds a
    tool carries that tool's documentation block in its composed system prompt, where
    ``make parity-check`` counts it. That holds only while every manifest keeps it true, so it is
    asserted for every role of every condition. A role holding a tool without its block would be
    offered a tool it was told nothing about, and the fix would be the manifest -- never a
    description written in code, which no parity count would see.
    """
    composed = compose_condition(registry, condition)
    for role in registry.compositions[condition].roles:
        carried = {block.block_id for block in composed.role(role.role_id).blocks}
        for tool in role.tools:
            doc_block = tool_definition(tool).doc_block
            assert doc_block in carried, (
                f"{condition}: role {role.role_id!r} holds {tool!r} but its composed prompt "
                f"carries no {doc_block!r} block, so the tool would reach the model undocumented"
            )


def test_a_recorded_call_reconstructs_the_request_that_went_on_the_wire() -> None:
    """``messages.jsonl`` keeps the projection and a marker; the mapping gives back the request.

    ADR-060 chose a named, documented mapping over recording the wire objects themselves: the
    projection is recorded already and the mapping is a pure function of it. This is the check that
    the choice holds -- the recorded fields, mapped, equal what the backend was handed.
    """
    model, backend = client([completion("complete_phase", COMPLETE)])
    recorder = RecordingClient(model)
    recorder.where(phase="containment", role_id="orchestrator")

    recorder.complete(call(*TOOL_NAMES))

    (record,) = recorder.messages
    sent = backend.kwargs[0]
    assert record["tool_wire_shape"] == TOOL_WIRE_SHAPE
    assert [wire_tool(tool) for tool in record["tools"]] == sent["tools"]
    assert sent["messages"] == [
        {"role": "system", "content": record["system"]},
        {"role": "user", "content": record["context"]},
    ]
    assert sent["seed"] == record["seed"]
    assert sent["model"] == recorder.tokens[0]["model_alias"]


# --------------------------------------------------------------------------------------------
# ADR-060: every attempt is accounted for
# --------------------------------------------------------------------------------------------


def test_a_failed_call_records_what_every_attempt_cost_and_why_it_was_rejected() -> None:
    """The usage of a failed call used to be dropped, and a rejection kept only its text.

    With the dev/pilot provider that text is always empty, so a rejected tool call left no trace.
    Each attempt now keeps its usage, its finish reason, its raw tool calls and the check that
    failed. The two pre-existing usage fields keep their meaning and stay ``None``: no attempt was
    accepted.
    """
    model, backend = client(
        [
            completion(
                "complete_phase",
                '{"outcome": "resolved"}',
                usage=(100, 20, 15),
                finish_reason="tool_calls",
            ),
            completion(
                "complete_phase", "not json", usage=(101, 21, None), finish_reason="tool_calls"
            ),
            answer(None, usage=(102, 22, 0), finish_reason="stop"),
        ]
    )

    response = model.complete(call("complete_phase"))

    assert response.tool_call is None
    assert response.attempts == len(response.attempt_log) == backend.calls == 3
    assert (response.prompt_tokens, response.completion_tokens) == (None, None)
    assert [
        (
            record.attempt,
            record.model,
            record.finish_reason,
            record.prompt_tokens,
            record.completion_tokens,
            record.reasoning_tokens,
        )
        for record in response.attempt_log
    ] == [
        (1, "fake/provider-model", "tool_calls", 100, 20, 15),
        (2, "fake/provider-model", "tool_calls", 101, 21, None),
        (3, "fake/provider-model", "stop", 102, 22, 0),
    ]
    assert [(record.rejected_check, record.rejected_detail) for record in response.attempt_log] == [
        ("schema-mismatch", "required at $.summary"),
        ("tool-call-malformed", "arguments-not-json"),
        ("no-tool-call", None),
    ]
    assert [record.tool_calls for record in response.attempt_log] == [
        (RawToolCall(name="complete_phase", arguments='{"outcome": "resolved"}'),),
        (RawToolCall(name="complete_phase", arguments="not json"),),
        (),
    ]
    assert not any(record.accepted for record in response.attempt_log)


def test_a_successful_call_keeps_the_cost_of_the_attempts_it_rejected() -> None:
    """A success used to report only its own usage, hiding what its rejected attempts cost."""
    model, _backend = client(
        [
            completion(
                "complete_phase",
                '{"outcome": "resolved", "summary": "done", "extra": true}',
                usage=(300, 40, 30),
            ),
            completion("complete_phase", COMPLETE, usage=(301, 41, 31)),
        ]
    )

    response = model.complete(call("complete_phase"))

    assert response.tool_call is not None
    assert response.attempts == 2
    assert (response.prompt_tokens, response.completion_tokens) == (301, 41), (
        "the pre-existing usage fields are the accepted attempt's, as they always were"
    )
    rejected, accepted = response.attempt_log
    assert (rejected.prompt_tokens, rejected.completion_tokens, rejected.reasoning_tokens) == (
        300,
        40,
        30,
    )
    assert (rejected.rejected_check, rejected.rejected_detail) == (
        "schema-mismatch",
        "additionalProperties at $",
    )
    assert accepted.accepted
    assert (accepted.prompt_tokens, accepted.completion_tokens, accepted.reasoning_tokens) == (
        301,
        41,
        31,
    )
    assert accepted.tool_calls == ()


def _args(fields: Mapping[str, Any]) -> str:
    """Tool-call arguments as a provider sends them: one JSON text."""
    return json.dumps(dict(fields))


_VALID_ACTION: dict[str, Any] = {
    "verb": "get",
    "resource": "pods",
    "namespace": "boutique",
    "name": None,
    "params": {},
    "justification": "inspect",
}
_VALID_ISSUE: dict[str, Any] = {
    "executor_id": "executor-01",
    "verbs": ["get"],
    "resources": ["pods"],
    "namespaces": ["boutique"],
}
# Bounds read from the shipped schemas, not restated, so each case sits one past the real bound.
_SUMMARY_MAX = tool_definition("complete_phase").schema["properties"]["summary"]["maxLength"]
_PARAMS_SCHEMA = tool_definition("guardian_action").schema["properties"]["params"]
_PARAM_KEY_MAX = _PARAMS_SCHEMA["propertyNames"]["maxLength"]
_VERBS_MAX = tool_definition("issue_capability_token").schema["properties"]["verbs"]["maxItems"]


@pytest.mark.parametrize(
    ("response", "offered", "check", "detail"),
    [
        pytest.param(answer(None), ("complete_phase",), "no-tool-call", None, id="no-tool-call"),
        pytest.param(
            answer([{"function": {"name": "", "arguments": "{}"}}]),
            ("complete_phase",),
            "tool-call-malformed",
            "name-missing",
            id="name-missing",
        ),
        pytest.param(
            completion("complete_phase", "{"),
            ("complete_phase",),
            "tool-call-malformed",
            "arguments-not-json",
            id="arguments-not-json",
        ),
        pytest.param(
            completion("complete_phase", None),
            ("complete_phase",),
            "tool-call-malformed",
            "arguments-not-json",
            id="arguments-absent",
        ),
        pytest.param(
            completion("complete_phase", "[1, 2]"),
            ("complete_phase",),
            "tool-call-malformed",
            "arguments-not-object",
            id="arguments-not-object",
        ),
        pytest.param(
            completion("guardian_action", _args(_VALID_ACTION)),
            ("complete_phase",),
            "tool-not-offered",
            None,
            id="tool-not-offered",
        ),
        pytest.param(
            completion("complete_phase", _args({"outcome": "done", "summary": "x"})),
            ("complete_phase",),
            "schema-mismatch",
            "enum at $.outcome",
            id="enum",
        ),
        pytest.param(
            completion("complete_phase", _args({"outcome": PHASE_OUTCOMES[0], "summary": 7})),
            ("complete_phase",),
            "schema-mismatch",
            "type at $.summary",
            id="type",
        ),
        pytest.param(
            completion(
                "complete_phase",
                _args({"outcome": PHASE_OUTCOMES[0], "summary": "x" * (_SUMMARY_MAX + 1)}),
            ),
            ("complete_phase",),
            "schema-mismatch",
            "maxLength at $.summary",
            id="maxLength",
        ),
        pytest.param(
            completion("guardian_action", _args({**_VALID_ACTION, "namespace": "Boutique"})),
            ("guardian_action",),
            "schema-mismatch",
            "pattern at $.namespace",
            id="pattern",
        ),
        pytest.param(
            completion("guardian_action", _args({**_VALID_ACTION, "params": {"limit": 10}})),
            ("guardian_action",),
            "schema-mismatch",
            "type at $.params.*",
            id="additional-property-schema",
        ),
        pytest.param(
            completion(
                "guardian_action",
                _args({**_VALID_ACTION, "params": {"k" * (_PARAM_KEY_MAX + 1): "v"}}),
            ),
            ("guardian_action",),
            "schema-mismatch",
            "propertyNames at $.params",
            id="propertyNames",
        ),
        pytest.param(
            completion("issue_capability_token", _args({**_VALID_ISSUE, "verbs": ["GET"]})),
            ("issue_capability_token",),
            "schema-mismatch",
            "pattern at $.verbs[0]",
            id="array-item",
        ),
        pytest.param(
            completion(
                "issue_capability_token",
                _args({**_VALID_ISSUE, "verbs": ["get"] * (_VERBS_MAX + 1)}),
            ),
            ("issue_capability_token",),
            "schema-mismatch",
            "maxItems at $.verbs",
            id="maxItems",
        ),
    ],
)
def test_each_rejected_attempt_names_the_check_that_failed(
    response: Mapping[str, Any], offered: tuple[str, ...], check: str, detail: str | None
) -> None:
    """Every validation check the seam runs is named, and a schema failure says where it failed."""
    model, _backend = client([response])

    result = model.complete(call(*offered))

    assert result.tool_call is None
    (record,) = result.attempt_log
    assert record.rejected_check in REJECTION_CHECKS
    assert (record.rejected_check, record.rejected_detail) == (check, detail)


def test_an_offered_tool_the_registry_does_not_hold_is_rejected_as_unregistered() -> None:
    """Defensive: a hand-built projection can offer a name the shared registry does not define."""
    stranger = {"name": "not_in_the_registry", "schema": {"type": "object"}}
    model, backend = client([completion("not_in_the_registry", "{}")])

    result = model.complete(
        ModelCall(system="system", context="context", tools=(stranger,), seed=7)
    )

    (record,) = result.attempt_log
    assert (record.rejected_check, record.rejected_detail) == ("tool-not-registered", None)
    assert backend.kwargs[0]["tools"] == [
        {
            "type": "function",
            "function": {"name": "not_in_the_registry", "parameters": {"type": "object"}},
        }
    ]


def test_the_rejection_vocabulary_is_the_five_checks_the_seam_runs_in_order() -> None:
    """``analysis/`` can count rejected attempts by cause only while the vocabulary stays closed."""
    assert REJECTION_CHECKS == (
        "no-tool-call",
        "tool-call-malformed",
        "tool-not-offered",
        "tool-not-registered",
        "schema-mismatch",
    )


# --------------------------------------------------------------------------------------------
# ADR-060: a call may lower the client's ceiling, never raise it
# --------------------------------------------------------------------------------------------


def test_the_client_sends_no_more_requests_than_the_call_allows() -> None:
    """A node with one turn left gets one request, whatever the client would otherwise retry."""
    model, backend = client(
        [
            completion("complete_phase", '{"outcome": "resolved"}'),
            completion("complete_phase", COMPLETE),
        ]
    )

    response = model.complete(
        ModelCall(
            system="system",
            context="context",
            tools=definitions_for(["complete_phase"]),
            seed=7,
            max_attempts=1,
        )
    )

    assert backend.calls == 1, (
        f"{backend.calls} request(s) were sent for a call capped at one. The valid answer a second "
        "would have fetched could not have been used, so it must not be paid for"
    )
    assert response.tool_call is None
    assert response.attempts == len(response.attempt_log) == 1


def test_a_call_cannot_raise_the_clients_own_ceiling() -> None:
    """The cap only ever lowers: ADR-032 keeps the client's ceiling a property of the client."""
    model, backend = client(
        [
            completion("complete_phase", '{"outcome": "resolved"}'),
            completion("complete_phase", '{"outcome": "resolved"}'),
        ]
    )
    ceiling = model.max_attempts

    response = model.complete(
        ModelCall(
            system="system",
            context="context",
            tools=definitions_for(["complete_phase"]),
            seed=7,
            max_attempts=ceiling + 1,
        )
    )

    assert backend.calls == ceiling
    assert response.attempts == ceiling


@pytest.mark.parametrize("cap", [0, -1])
def test_a_model_call_refuses_an_attempt_cap_below_one(cap: int) -> None:
    """A node with no turn left sends nothing; it never asks a client for zero attempts."""
    with pytest.raises(ValueError, match="max_attempts"):
        ModelCall(system="system", context="context", tools=(), seed=None, max_attempts=cap)


def test_a_one_turn_role_sends_one_request_and_records_a_failed_answer_as_blocked(
    guardian: InProcessGuardian, registry: PromptRegistry
) -> None:
    """The cap observed end to end, on the S1-HIER orchestrator's own declared allocation.

    Before ADR-060 this role was retried past its one turn: a valid second or third answer arrived
    and was discarded as ``budget-exhausted``, three requests paid for and none usable. Now the one
    request its budget covers is the only one sent, and a failed answer is recorded as ``blocked``.
    """
    composition = registry.compositions["S1-HIER"]
    budget = composition.budgets["containment"]["orchestrator"]
    assert budget.max_turns == 1, (
        f"this case is about a one-turn role; the manifest now allocates {budget.max_turns}"
    )
    node = coordination_node(
        compose_condition(registry, "S1-HIER").role("orchestrator"),
        budget=budget,
        tools=composition.role("orchestrator").tools,
    )
    model, backend = client(
        [
            completion("complete_phase", '{"outcome": "resolved"}'),
            completion("complete_phase", COMPLETE),
            completion("complete_phase", COMPLETE),
        ]
    )

    result = node(node_context(guardian, model=model), "containment")

    assert backend.calls == budget.max_turns, (
        f"{backend.calls} request(s) for a role allocated {budget.max_turns} turn(s)"
    )
    assert result.turns_spent == result.model_attempts == budget.max_turns
    assert result.outcome == PHASE_OUTCOMES[1], f"{result.outcome!r}: {result.summary!r}"
