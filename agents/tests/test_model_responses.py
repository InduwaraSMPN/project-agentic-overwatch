"""ADR-174: Responses changes transport, never controls, identity or attempt accounting."""

import copy
import json
import sys
from types import SimpleNamespace

import pytest
from agents.golden import RecordingClient
from agents.registry.model import REASONING_EFFORT, LiteLLMClient, ModelCall
from agents.tools.registry import definitions_for
from runner.bundle import CompletenessError, _verify_llm_call_accounting


def install_backend(monkeypatch, responses):
    requests, conversions, usage_calls = [], [], []

    def respond(**kwargs):
        requests.append(copy.deepcopy(kwargs))
        return responses.pop(0)

    class Converter:
        def _handle_raw_dict_response_item(self, **kwargs):
            raise AssertionError("the SDK owns output parsing")

        def _convert_response_output_to_choices(self, output_items, handle_raw_dict_callback):
            assert handle_raw_dict_callback == self._handle_raw_dict_response_item
            conversions.append(output_items)
            return output_items[0]["sdk_choices"]

    class UsageConverter:
        @staticmethod
        def _transform_response_api_usage_to_chat_usage(usage):
            usage_calls.append(usage)
            # SDK defaults must never convert missing or malformed provider counts into zero.
            return SimpleNamespace(model_dump=lambda: {"prompt_tokens": 0, "completion_tokens": 0})

    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(responses=respond))
    monkeypatch.setitem(
        sys.modules,
        "litellm.completion_extras.litellm_responses_transformation.transformation",
        SimpleNamespace(LiteLLMResponsesTransformationHandler=Converter),
    )
    monkeypatch.setitem(
        sys.modules,
        "litellm.responses.utils",
        SimpleNamespace(ResponseAPILoggingUtils=UsageConverter),
    )
    monkeypatch.setenv("OPENAI_BASE_URL", "https://provider.invalid/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "test-secret")
    return requests, conversions, usage_calls


def response(arguments='{"outcome":"resolved","summary":"done"}', **fields):
    return SimpleNamespace(
        output=[
            {
                "sdk_choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "content": "",
                            "tool_calls": [
                                {
                                    "function": {
                                        "name": "complete_phase",
                                        "arguments": arguments,
                                    }
                                }
                            ],
                        },
                    }
                ]
            }
        ],
        **fields,
    )


def call():
    return ModelCall(
        system="system", context="context", tools=definitions_for(("complete_phase",)), seed=7
    )


def test_responses_controls_schemas_identity_and_recorder(monkeypatch):
    raw = response(
        model="actual-other-model",
        system_fingerprint="fp-actual",
        _hidden_params={"model": "hidden-actual"},
        usage={
            "input_tokens": 11,
            "output_tokens": 5,
            "output_tokens_details": {"reasoning_tokens": 3},
        },
    )
    requests, conversions, usage_calls = install_backend(monkeypatch, [raw])
    model = LiteLLMClient(provider_string="custom_openai/gpt-5.6-terra", timeout_seconds=9)
    recorder = RecordingClient(model)
    offered = call()
    original = copy.deepcopy(offered.tools)
    result = recorder.complete(offered)
    request = requests[0]
    assert request == {
        "model": "gpt-5.6-terra",
        "custom_llm_provider": "openai",
        "api_base": "https://provider.invalid/v1",
        "api_key": "test-secret",
        "instructions": "system",
        "input": [{"role": "user", "content": "context"}],
        "tools": [
            {
                "type": "function",
                "name": "complete_phase",
                "parameters": original[0]["schema"],
                "strict": False,
            }
        ],
        "reasoning": {"effort": REASONING_EFFORT},
        "extra_body": {"temperature": 0.0, "seed": 7},
        "timeout": 9,
    }
    assert offered.tools == original
    request["tools"][0]["parameters"]["required"].append("invented")
    assert offered.tools == original
    assert conversions == [raw.output] and usage_calls == [raw.usage]
    assert result.tool_call.name == "complete_phase"
    assert result.provider_string == "custom_openai/actual-other-model"
    assert result.response_model == "actual-other-model"
    assert (
        result.hidden_params_model == "hidden-actual" and result.system_fingerprint == "fp-actual"
    )
    assert (result.prompt_tokens, result.completion_tokens) == (11, 5)
    assert result.attempt_log[0].reasoning_tokens == 3
    assert recorder.messages[0]["tool_wire_shape"] == "openai-responses-function-v1"


@pytest.mark.parametrize(
    "usage",
    [
        None,
        {},
        42,
        {
            "input_tokens": None,
            "output_tokens": "5",
            "output_tokens_details": {"reasoning_tokens": True},
        },
    ],
)
def test_responses_missing_or_malformed_usage_stays_unknown(monkeypatch, usage):
    raw = response(usage=usage)
    _, _, usage_calls = install_backend(monkeypatch, [raw])
    result = LiteLLMClient(provider_string="custom_openai/gpt-5.6-terra").complete(call())
    record = result.attempt_log[0]
    assert result.response_model is None and result.provider_string == "custom_openai/gpt-5.6-terra"
    assert record.prompt_tokens is record.completion_tokens is record.reasoning_tokens is None
    assert len(usage_calls) == (0 if usage is None else 1)


def test_responses_rejected_attempt_remains_accounted(monkeypatch):
    install_backend(
        monkeypatch,
        [
            response("not-json", model="first", usage={"input_tokens": 4, "output_tokens": 2}),
            response(model="second", usage={"input_tokens": 9, "output_tokens": 3}),
        ],
    )
    result = LiteLLMClient(provider_string="custom_openai/gpt-5.6-terra").complete(call())
    first, second = result.attempt_log
    assert result.attempts == 2 and result.provider_string == "custom_openai/second"
    assert (first.model, second.model) == ("custom_openai/first", "custom_openai/second")
    assert (first.response_model, second.response_model) == ("first", "second")
    assert (
        first.rejected_check == "tool-call-malformed"
        and first.tool_calls[0].arguments == "not-json"
    )
    assert (first.prompt_tokens, second.prompt_tokens) == (4, 9)
    assert result.prompt_tokens == 9


@pytest.mark.parametrize(
    "echo,qualified,accepted",
    [
        ("gpt-5.6-terra", "custom_openai/gpt-5.6-terra", True),
        ("gpt-5.6-luna", "custom_openai/gpt-5.6-luna", False),
        ("cerebras/gpt-5.6-terra", "cerebras/gpt-5.6-terra", False),
        ("custom_openai/openai/gpt-5.6-terra", "custom_openai/openai/gpt-5.6-terra", True),
        (None, "custom_openai/gpt-5.6-terra", True),
    ],
)
def test_responses_recorder_meets_sealer_identity_contract(
    monkeypatch, tmp_path, echo, qualified, accepted
):
    pin = "custom_openai/gpt-5.6-terra"
    install_backend(monkeypatch, [response(model=echo)])
    recorder = RecordingClient(LiteLLMClient(provider_string=pin))
    result = recorder.complete(call())
    assert result.provider_string == qualified
    assert result.response_model == result.attempt_log[0].response_model == echo
    assert result.attempt_log[0].model == qualified
    assert recorder.tokens[0]["model"] == qualified
    assert recorder.tokens[0]["response_model"] == echo
    (tmp_path / "messages.jsonl").write_text(
        "".join(json.dumps(message) + "\n" for message in recorder.messages), encoding="utf-8"
    )
    (tmp_path / "tokens.json").write_text(json.dumps(recorder.tokens), encoding="utf-8")
    alias = recorder.tokens[0]["model_alias"]
    if accepted:
        _verify_llm_call_accounting(tmp_path, alias, pin)
    else:
        with pytest.raises(CompletenessError, match="exact manifest"):
            _verify_llm_call_accounting(tmp_path, alias, pin)


def test_responses_optional_registry_fields_and_attempt_cap(monkeypatch):
    requests, _, _ = install_backend(
        monkeypatch, [response("not-json", usage={"input_tokens": 0, "output_tokens": 0})]
    )
    offered = ModelCall(
        system="system",
        context="context",
        # A wire-boundary projection with an optional field. The current real registry requires
        # every top-level field; the adapter must still never rewrite a projection's required set.
        tools=copy.deepcopy(definitions_for(("complete_phase",))),
        seed=7,
        max_attempts=1,
    )
    offered.tools[0]["schema"]["required"].remove("summary")
    original = copy.deepcopy(offered.tools)
    result = LiteLLMClient(provider_string="custom_openai/gpt-5.6-terra").complete(offered)
    schema = requests[0]["tools"][0]["parameters"]
    assert set(schema["properties"]) - set(schema["required"])
    assert schema == original[0]["schema"] and offered.tools == original
    assert result.tool_call is None and result.attempts == len(requests) == 1
    assert result.prompt_tokens is None  # no accepted attempt
    assert result.attempt_log[0].prompt_tokens == result.attempt_log[0].completion_tokens == 0
