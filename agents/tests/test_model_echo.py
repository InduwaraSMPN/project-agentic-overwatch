r"""D10: the model a bundle records is the model the provider answered, not the one we asked for.

WHAT THIS FILE PINS, AND WHY A SEPARATE FILE
-------------------------------------------
M10's WS-1 table marks this file *new*, and the reason is V20: a v1 ``tokens.json`` carried
``custom_openai/gpt-5.6-terra`` and nothing else, and that string was not evidence of anything.
``docs/plans/M10-implementation-plan.md`` Appendix A records what the pinned LiteLLM's
OpenAI-compatible transform actually does with ``model`` -- it reports the provider prefix plus the
model **the backend echoed** -- so a gateway that echoes the requested name produces the alias *by
construction*, and a bundle holding only that string cannot distinguish a provider that answered
under the pinned model from one that was never asked.

D10's answer is to record three raw signals beside the answered model, each nullable and **none
falling back**, so a later reader can tell those two cases apart:

* ``system_fingerprint`` -- the OpenAI-documented backend-configuration signal, watched alongside
  ``seed`` for a silent backend change. It is ``deprecated: true`` upstream (Context7, against the
  pinned version), so D10 makes it *advisory* rather than a halt key, and a run that has none is
  ordinary rather than a finding;
* ``response_model`` -- ``completion.model`` with no fallback. ``None`` here means the provider
named
  no model at all, which is precisely the fact :func:`~agents.registry.model._answered_model` hides
  behind the asked-for string;
* ``hidden_params_model`` -- ``completion._hidden_params["model"]``, LiteLLM's fallback home for the
  model when the top-level field carries the prefix only. A value here that differs from
  ``response_model`` is the prefix-versus-echo split Appendix A confirms.

The answered model itself is *not* one of the three and is deliberately left alone: ADR-005 requires
a bundle never to record the bare alias as though it were a model, so ``_answered_model`` falls back
to the asked-for *provider string* rather than to the alias. That fallback is what makes V20
dangerous
rather than visible, which is why these three sit beside it.

WHY THE FIXTURE IS BUILT HERE AND NOT IMPORTED
----------------------------------------------
``test_model_tool_validation.py`` already has a fake backend and a client-construction helper, and
this file does not reuse them. That is not oversight: that file's subject is *which tool calls are
accepted*, and its ``answer()`` helper hard-codes ``"model": "fake/provider-model"`` on every
completion -- a fixture that always names a model is precisely the fixture that cannot exercise
"the provider named none". The two files disagree about a value on purpose, and importing one helper
into the other would have imported the disagreement silently.

Every completion here is a **mapping**, which is the shape ``LiteLLMClient`` receives from
LiteLLM's own transform, and the reader under test (``_attr``) accepts objects and mappings alike
because providers disagree. Asserting against the mapping shape is therefore the stricter of the two
choices: an implementation that reached only for attributes would fail here rather than pass.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agents.registry.model import (  # noqa: E402
    LiteLLMClient,
    LiteLLMConfig,
    ModelCall,
)
from agents.tools.registry import COMPLETE_PHASE_TOOL, definitions_for  # noqa: E402

# The alias the fixture client resolves through, and the provider string behind it. ADR-005's shape:
# the bundle records the resolved string, never the alias, so a run against an unrouted gateway is
# visible in the manifest rather than silent.
ALIAS = "fake-alias"
REQUESTED = "fake/requested-model"

# A well-formed answer, so every case below differs from the others only in the model-echo fields
# under test. The tool call satisfies the registry schema, which matters: an answer the client
# rejects is retried, and the retry would replace the record under test with a different attempt's.
# The arguments are spelled as the wire form -- a JSON *string* -- because that is what a provider
# sends and what the client's parser is strict about.
_WIRE_ARGUMENTS = '{"outcome":"resolved","summary":"done"}'


class _Omitted:
    """The marker for "this case wants the field absent from the completion entirely".

    A distinct type rather than a sentinel *value* because every string a provider could plausibly
    report is one a case here needs to distinguish: ``None`` is "the provider said null", ``""`` is
    "the provider said nothing useful", and a nested structure is "the provider sent something that
    is not a model name". A sentinel drawn from that same set would collapse three of the four
    shapes into one, and the reader's job is exactly to keep them apart.
    """

    __slots__ = ()


_OMITTED = _Omitted()


class FakeLiteLLM:
    """A backend with LiteLLM's ``completion`` shape that returns what the test scripted.

    No network, no provider SDK and no credential: Tier A's three prohibitions, honoured by
    construction rather than by a skip. It records how many requests were made, because one of the
    cases below is about a *single* record existing and a retry would be a second one.
    """

    def __init__(self, completions: Sequence[dict[str, Any]]) -> None:
        self.completions = list(completions)
        self.calls = 0
        self.kwargs: list[dict[str, Any]] = []

    def completion(self, **kwargs: Any) -> dict[str, Any]:
        self.calls += 1
        self.kwargs.append(kwargs)
        return self.completions.pop(0)


def completion(
    *,
    model: Any = _OMITTED,
    system_fingerprint: Any = _OMITTED,
    hidden_model: Any = _OMITTED,
) -> dict[str, Any]:
    """One provider response, with the model-echo fields present only when a case asks for them.

    A field left at :data:`_OMITTED` is not written into the response at all, which is what makes
    "the key is absent" distinguishable from "the key holds ``None``" -- two different facts about
    two different providers, and the second case below needs both.
    """
    response: dict[str, Any] = {
        "choices": [
            {
                "finish_reason": "tool_calls",
                "message": {
                    "content": "",
                    "tool_calls": [
                        {
                            "function": {
                                "name": COMPLETE_PHASE_TOOL.name,
                                "arguments": _WIRE_ARGUMENTS,
                            }
                        }
                    ],
                },
            }
        ],
        "usage": {
            "prompt_tokens": 11,
            "completion_tokens": 5,
            "completion_tokens_details": {"reasoning_tokens": None},
        },
    }
    if model is not _OMITTED:
        response["model"] = model
    if system_fingerprint is not _OMITTED:
        response["system_fingerprint"] = system_fingerprint
    if hidden_model is not _OMITTED:
        response["_hidden_params"] = {"model": hidden_model}
    return response


def client(*completions: dict[str, Any]) -> tuple[LiteLLMClient, FakeLiteLLM]:
    """Return a client over a fake backend, built without importing the provider SDK.

    ``__new__`` rather than the constructor for the reason
    ``test_model_tool_validation.py``'s helper gives: the constructor's lazy ``import litellm``
    pulls
    in a large object graph, and this suite's job is to read three fields off a completion, not to
    prove that LiteLLM is installed. The fields set here are exactly the ones ``complete()`` reads.
    """
    backend = FakeLiteLLM(completions)
    instance = LiteLLMClient.__new__(LiteLLMClient)
    instance._litellm = backend
    instance.config = LiteLLMConfig({ALIAS: REQUESTED})
    instance.alias = instance.config.alias
    instance.provider_string = instance.config.provider_string
    instance.max_attempts = len(completions)
    instance.timeout_seconds = 1.0
    return instance, backend


def call() -> ModelCall:
    """One model call offering the single tool the scripted answer uses."""
    return ModelCall(
        system="system",
        context="context",
        tools=definitions_for([COMPLETE_PHASE_TOOL.name]),
        seed=7,
    )


def test_system_fingerprint_extracted() -> None:
    """A provider that reports a fingerprint has it recorded, on the attempt and on the response.

    The field is the one D10 makes *advisory* rather than a halt key, because OpenAI deprecated it
    (Appendix A, against the pinned version). Advisory does not mean unread: the point of recording
    it is that a backend that changes under a fixed alias shows up as a fingerprint drift, which
    §11 of the plan accepts as a residual risk, rather than as nothing at all.

    Recorded at **both** levels and the distinction is asserted rather than assumed:
    :class:`~agents.registry.model.AttemptRecord` carries it per request, so a run whose middle
    attempt came back under a different backend is attributable to that request, and
    :class:`~agents.registry.model.ModelResponse` carries the accepted attempt's copy, which is what
    ``runner/`` writes into the manifest and what F-AG-04 reads.

    The control for both is that exactly one request was made: a retry would put a second record in
    the log, and reading the accepted one off the end of it would be reading whatever the last
    attempt happened to say.
    """
    model, backend = client(completion(model=REQUESTED, system_fingerprint="fp_abc123"))

    response = model.complete(call())

    assert backend.calls == 1, (
        f"{backend.calls} provider request(s) were made where the script provided one answer that "
        "the registry accepts. A retry would replace the record under test with another attempt's"
    )
    assert response.system_fingerprint == "fp_abc123", (
        f"the response reports system_fingerprint {response.system_fingerprint!r} rather than the "
        "provider's 'fp_abc123'. D10 records the field on the accepted attempt so a backend that "
        "changes under a fixed alias is visible in the manifest"
    )
    (record,) = response.attempt_log
    assert record.system_fingerprint == "fp_abc123", (
        f"the per-attempt record reports {record.system_fingerprint!r}. It is recorded per request "
        "rather than per call so a run whose middle attempt came back under a different backend is "
        "attributable to that request"
    )
    assert record.attempt == 1 and record.accepted, (
        f"the only record is {record!r}; the assertion above is about the accepted attempt and"
        " would "
        "be reading a rejected one"
    )


def test_absent_fingerprint_is_none() -> None:
    """A provider that reports no fingerprint records ``None``: not the asked-for string, not empty.

    The failure mode this forecloses is a *fallback*. ``_answered_model`` substitutes the string the
    call asked for when the provider reports nothing, which is right for the one recorded model and
    wrong here: a bundle whose ``system_fingerprint`` reads ``custom_openai/gpt-5.6-terra`` because
    nothing better was available would be indistinguishable from a bundle whose provider really
    reported it. D10's whole construction is that ``None`` is a *fact* -- "the provider named no
    backend configuration" -- and a fact cannot be manufactured by a default.

    Four shapes are exercised, and the last two are why the reader is written to be strict rather
    than truthy: an absent key, an explicit ``None``, an empty string and a non-string. A reader
    written as ``getattr(completion, "system_fingerprint", None) or fallback`` would pass the first
    three and fail the fourth, and one written as ``str(value)`` would pass all four while recording
    a fabricated signal.
    """
    for label, scripted in (
        ("key absent", completion(model=REQUESTED)),
        ("explicit null", completion(model=REQUESTED, system_fingerprint=None)),
        ("empty string", completion(model=REQUESTED, system_fingerprint="")),
        ("not a string", completion(model=REQUESTED, system_fingerprint={"nested": "fp"})),
    ):
        model, _backend = client(scripted)

        response = model.complete(call())

        assert response.system_fingerprint is None, (
            f"a completion whose fingerprint is {label} recorded {response.system_fingerprint!r}. "
            "None is the honest answer for all four: a provider that reported nothing must not be "
            "recorded as having reported the model we asked for (V20, ADR-123)"
        )
        (record,) = response.attempt_log
        assert record.system_fingerprint is None, (
            f"a completion whose fingerprint is {label} recorded {record.system_fingerprint!r} on "
            "the attempt. The per-request and per-call readers are separate functions and a"
            " fallback "
            "in one of them would be a fallback in half the records a bundle carries"
        )
        # The control: the same call DID record the model the provider named, so the None above is a
        # reading of an absent field and not of a completion the client never looked at.
        assert response.response_model == REQUESTED, (
            f"a completion whose fingerprint is {label} also lost its model: "
            f"{response.response_model!r}"
        )


def test_raw_and_hidden_model_recorded() -> None:
    """The provider's ``model`` and LiteLLM's ``_hidden_params`` are both recorded, un-fallen-back.

    Three shapes, because the interesting case is the one where the two disagree and the case where
    the provider says nothing at all.

    * **Prefix versus echo.** The provider reports ``custom_openai/``-prefixed ``model`` and the
      backend's own name under ``_hidden_params``. Both are recorded, both differ from the requested
      string, and the two are distinguishable from one another -- which is the split Appendix A
      confirms against the pinned LiteLLM and the reason a single field could never have carried it.
    * **The gateway echoes the requested name (V20).** ``response_model`` equals the requested
    string
      *because the provider said so*, and the record is indistinguishable in shape from a provider
      that answered under exactly that model. That is the honest limit D10 and §11 state: a
      provider that echoes the alias yields the alias, and the only defence is that the raw signals
      are recorded so a reader can see the backend's own name disagree (or agree) beside it.
    * **The provider names nothing.** ``model`` falls back to the requested string -- which is
      required, because a bundle may not record the bare alias -- while ``response_model`` is
      ``None``. This is the pair that makes the fallback legible, and asserting only the first half
      would leave the V20 defect in place: the fallback exists in both readings if the second is
      never checked.
    """
    # (a) prefix versus echo.
    model, _ = client(
        completion(model="custom_openai/gpt-5.6-terra", hidden_model="gpt-5.6-terra-2026-09-01")
    )
    echoed = model.complete(call())
    (echo_record,) = echoed.attempt_log
    assert echoed.provider_string == "custom_openai/gpt-5.6-terra", (
        f"the answered model is {echoed.provider_string!r}; the provider reported "
        "'custom_openai/gpt-5.6-terra' and that is what ADR-005 requires a bundle to record"
    )
    assert echoed.response_model == "custom_openai/gpt-5.6-terra", (
        f"the raw response model is {echoed.response_model!r}. With no fallback it is the"
        " provider's "
        "own string, prefix included"
    )
    assert echoed.hidden_params_model == "gpt-5.6-terra-2026-09-01", (
        f"_hidden_params carried {echoed.hidden_params_model!r}. LiteLLM's OpenAI-compatible"
        " transform "
        "records the backend's own name there when the top-level field carries the provider"
        " prefix, "
        "and it is the only one of the three that names a *deployment* rather than a route"
    )
    assert echoed.response_model != echoed.hidden_params_model, (
        "the two model signals agree, so this fixture no longer exercises the prefix-versus-echo "
        "split it was written for"
    )
    assert (echo_record.response_model, echo_record.hidden_params_model) == (
        echoed.response_model,
        echoed.hidden_params_model,
    ), "the per-attempt and per-call copies of the two model signals disagree"

    # (b) the gateway echoes what was requested -- V20 by construction.
    echo_back = client(completion(model=REQUESTED, hidden_model=REQUESTED))[0]
    aliased = echo_back.complete(call())
    assert aliased.response_model == REQUESTED, (
        f"the raw response model is {aliased.response_model!r} where the provider echoed the "
        f"requested name {REQUESTED!r}. That is the honest reading: the provider *did* report"
        " this, "
        "and the record must say so rather than guess"
    )
    assert aliased.response_model == aliased.provider_string, (
        "the raw response model differs from the answered model where the provider echoed the "
        "requested string. They are the same by definition here, which is exactly the V20 shape"
        " this "
        "case exists to make visible"
    )
    assert aliased.system_fingerprint is None, (
        f"the echoed completion reported a fingerprint ({aliased.system_fingerprint!r}) it was"
        " never "
        "given. One of the fixtures has started contaminating the other"
    )

    # (c) the provider names no model at all.
    silent = client(completion(model=None, hidden_model=None))[0]
    unnamed = silent.complete(call())
    assert unnamed.provider_string == REQUESTED, (
        f"a provider that named no model produced answered model {unnamed.provider_string!r}."
        "ADR-005 "
        "requires a bundle never to record the bare alias as though it were a model, so the"
        " fallback "
        "is the requested provider string and not the alias"
    )
    assert unnamed.provider_string != ALIAS, (
        f"the answered model is the alias {ALIAS!r}. A bundle recording that cannot be reproduced "
        "against a named backend at all, which is risk R-01"
    )
    assert unnamed.response_model is None, (
        f"a provider that named no model recorded raw response model {unnamed.response_model!r}."
        "This "
        "is the assertion the fallback exists to be legible against: the two readings together say "
        "'we asked for this and were told nothing', where either alone would be unreadable"
    )
    assert unnamed.hidden_params_model is None, (
        f"a provider with no _hidden_params model recorded {unnamed.hidden_params_model!r}"
    )
