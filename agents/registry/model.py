r"""The inference seam: one alias, one recorded provider string, and a retry that costs a turn.

WHAT THIS MODULE IS
-------------------
``docs/adr/ADR-005-model-strategy.md`` fixes the strategy: "All calls via LiteLLM proxy with a
stable internal alias (``overwatch-primary``)... Exact provider model string + LiteLLM config hash
logged into every bundle... Temperature 0 + provider seed where supported." This module is that
seam. It resolves the alias, makes the call, records what was actually used, and counts what it
spent.

The alias is the whole point and it is worth restating why. Risk R-01 is free-tier model churn --
"provider silently removes/renames the model mid-campaign (observed in the wild, May 2026)" -- and
the mitigation is that every call site names ``overwatch-primary`` and never a provider string, so
switching provider is a change to one configuration value and a note in the campaign log rather
than an edit spread through the agent layer. What must **not** be absorbed by the alias is the
record: ``docs/protocols/data-management.md`` puts the exact provider string in every bundle, so
:class:`ModelResponse` carries the string the provider answered under, per call, rather than the
alias the caller asked for.

THE BACKEND IS IMPORTED LAZILY, AND TIER A NEVER TOUCHES IT
-------------------------------------------------------------
``docs/plans/M4-implementation-plan.md`` splits this milestone's verification three ways and the
split runs straight through this module. Tier A is offline: no network, no Docker, no credential,
no token spent. Tier A' is the tier that exists because deferring it is the expensive mistake --
live dev-tier inference through the alias, with risk R-10 *measured* rather than assumed, because
"a model that cannot tool-call invalidates the agent design, and discovering that at GATE rather
than at M4 costs a milestone".

So :class:`LiteLLMClient` imports ``litellm`` **inside its constructor** rather than at module
scope. Importing this module costs nothing, works on a machine with no provider package installed,
and lets the whole Tier A suite -- the graphs, the executor lifecycle, the golden path against the
in-process Guardian -- run against :class:`ScriptedClient` with the same code above it. That is the
same discipline ``guardian/tests/harness.py`` applies to its policy engine, and for the same stated
reason: a double that returns a canned answer is honest, while a double that *decides* something
would be a second implementation of the thing under test.

A RETRY IS A TURN, AND THIS MODULE IS WHERE THAT BECOMES TRUE
---------------------------------------------------------------
Risk R-10's mitigation is "structured-output prompting; retry policy logged", and a weak free model
retries more in whichever arm happens to trip it. If a retry did not count against the phase's
declared turn budget, the arm that struggled would silently receive more turns, and the structure
ablation would be confounded by model weakness rather than by topology -- an S2-FLAT run that
retried twice as often would look like a topology effect.

:class:`ModelResponse` therefore carries ``attempts``, and every attempt is one turn against the
budget the composition manifest declared. The retry loop is here rather than in the graph because
this is the only place that can see a malformed tool call; what the graph does is spend the turns
this module reports. ADR-028.

The graph also bounds the loop from its side. :attr:`ModelCall.max_attempts` carries the turns the
calling node has left, and the client sends at most the smaller of that and its own ceiling -- so a
request is never sent for an answer the budget could not let the node use. Before ADR-060 a
one-turn role was retried anyway and a valid second answer was discarded as over budget: paid for
and unusable at once.

WHAT GOES ON THE WIRE, AND WHAT A BUNDLE RECORDS ABOUT IT
-----------------------------------------------------------
A tool reaches this module as the registry's projection -- name, dialect, documentation-block id,
schema -- which is what ``tool_registry_sha256`` digests and what ``messages.jsonl`` records. It is
not an OpenAI function object, and until ADR-060 it was sent as one anyway: the provider received a
function name, three keys it does not define, and no argument schema at all. :func:`wire_tool` is
the shared base mapping, applied here and nowhere else. :data:`TOOL_WIRE_SHAPE` names the historical
Chat Completions shape; ADR-174 flattens its function fields and adds ``strict: false`` for
Responses, recorded as :data:`RESPONSES_TOOL_WIRE_SHAPE`. The registry projection stays unchanged.

Every attempt is recorded, not only the one that succeeded: its usage, its finish reason and, when
its answer was rejected, the raw tool calls and which validation check failed
(:class:`AttemptRecord`). The fields that already existed keep their meaning -- ``prompt_tokens``
and ``completion_tokens`` are the accepted attempt's usage and ``None`` when no attempt was
accepted -- and ``attempt_log`` is where what a call actually cost is kept.

DETERMINISM, AS FAR AS A PROVIDER ALLOWS
-----------------------------------------
Temperature is zero and a seed is passed when the provider supports one, per ADR-005.
``.agents/rules/20-parity-and-determinism.md`` requires a run to replay from ``(scenario_id,
seed)``, and the honest limit is stated rather than implied: a hosted model is not a deterministic
function of its input, so temperature and seed reduce variance without eliminating it, and the
determinism this project can actually assert covers the Monitor's replay and the scenario
injection, not the model's sampling. The seed is nevertheless passed and recorded, because a
recorded seed that the provider honoured is evidence and a seed nobody sent is not.

WHAT IS DELIBERATELY NOT HERE
------------------------------
*Prompt text.* This module is handed rendered strings and never composes one.
``scripts/prompt_purity_grep.sh`` scopes its literal scan to ``agents/graphs/`` and
``agents/tools/``; this module is inside ``agents/registry/`` because it is composer-adjacent
machinery, and it holds no prose for the same reason they do not. That is also why a wire tool
carries no ``description``: the tool's documentation is a prompt block, already composed into the
system prompt of every role that holds the tool.

*A model choice.* The alias resolves to whatever ``infra/versions.env``'s ``MODEL_PROVIDER_STRING``
names, and that value is ADR-005's and GATE's. Nothing here prefers a model, falls back to a
second one, or upgrades on a failure -- a fallback chain is configuration in the gateway, which is
where ADR-005 puts it, and a fallback taken silently in code would change which model produced a
run without the bundle recording it.
"""

import copy
import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Final, Protocol, runtime_checkable

from agents.tools.registry import tool_definition

__all__ = (
    "DEFAULT_ALIAS",
    "MODEL_ALIAS_ENV_VAR",
    "MODEL_PROVIDER_STRING_ENV_VAR",
    "REJECTION_CHECKS",
    "AttemptRecord",
    "LiteLLMConfig",
    "ModelCall",
    "ModelClient",
    "ModelResponse",
    "ModelUnavailable",
    "RawToolCall",
    "ScriptedClient",
    "REASONING_EFFORT",
    "RUNNER_SCRIPTED_ENV_VAR",
    "SCRIPTED_PROVIDER_STRING",
    "SUPPORTED_REASONING_EFFORTS",
    "TEMPERATURE",
    "TOOL_WIRE_SHAPE",
    "RESPONSES_TOOL_WIRE_SHAPE",
    "ToolCall",
    "litellm_config",
    "litellm_config_sha256",
    "resolve_provider_string",
    "wire_tool",
    "wire_tools",
)

# ADR-005's alias, spelled as that record spells it. It is a name and never a model: a call site
# that named a provider string would be a call site R-01's churn reaches directly.
DEFAULT_ALIAS: Final = "overwatch-primary"

# The two environment keys the runner sets from infra/versions.env. They are read here rather than
# in the graph because resolving an alias is this module's job, and read from the environment
# rather than from versions.env directly because the agent layer ships as a container image with no
# infra/ tree in it -- scripts/install_runtime_deps.sh and the runner are what bridge the two.
MODEL_ALIAS_ENV_VAR: Final = "MODEL_ALIAS"
MODEL_PROVIDER_STRING_ENV_VAR: Final = "MODEL_PROVIDER_STRING"

# The provider string a ScriptedClient answers under and the runner env var that selects it. A P1a
# scripted run (M10 plan section 6) sends no model request, so its every tokens.json call records
# this string and no usage. It is a constant here, beside ScriptedClient, so that one edit moves
# both the client's default and the manifest pin the runner records: runner/provenance.py forces
# MODEL_PROVIDER_STRING to this value whenever RUNNER_SCRIPTED is set, which is what makes the
# sealed manifest's model_provider_string match tokens.json (F-RN-01 / F-AG-04) without an operator
# setting MODEL_PROVIDER_STRING by hand. The "/none" tail is not a real provider: no litellm route
# resolves it to an endpoint, and nothing tries, because the scripted client never calls out.
SCRIPTED_PROVIDER_STRING: Final = "scripted/none"
RUNNER_SCRIPTED_ENV_VAR: Final = "RUNNER_SCRIPTED"

# Zero, per ADR-005. Not a tunable and not a per-condition parameter: a temperature that differed
# between arms would be a second manipulated variable, and one that differed between runs of one
# arm would put sampling variance into a contrast the reduction lever protects.
TEMPERATURE: Final = 0.0
# The reasoning budget every call asks for, per ADR-005's dev/pilot amendment. It is one constant
# for the same reason TEMPERATURE is: an effort that differed between arms would be a second
# manipulated variable. The owner's provider definition asks for "max"; the endpoint rejects that
# value and enumerates its own vocabulary -- 'none', 'low', 'medium', 'high', 'xhigh' -- so "xhigh"
# is that intent as this endpoint spells it. ADR-174 sends it as Responses reasoning.effort on the
# compatible dev route; other routes retain their Chat Completions allowed_openai_params setting.
REASONING_EFFORT: Final = "xhigh"

# The values the dev/pilot endpoint accepts, recorded so a silent edit to REASONING_EFFORT fails in
# the offline tier rather than at the first live call.
SUPPORTED_REASONING_EFFORTS: Final[frozenset[str]] = frozenset(
    {"none", "low", "medium", "high", "xhigh"}
)

# The mapping from a registry projection to the tool object the endpoint receives, named so that a
# recorded call can say which mapping produced its request. ADR-060 defines it: each projection p in
# ModelCall.tools is sent, in order, as {"type": "function", "function": {"name": p["name"],
# "parameters": p["schema"]}} -- nothing else, and no description (see wire_tool). A messages.jsonl
# record without this marker predates ADR-060, when the projection itself was sent as the function
# object; a record carrying it as null was answered by a double that sent no request at all.
TOOL_WIRE_SHAPE: Final = "openai-function-v1"
RESPONSES_TOOL_WIRE_SHAPE: Final = "openai-responses-function-v1"


@dataclass(frozen=True)
class LiteLLMConfig:
    """The complete secret-free LiteLLM alias mapping used for routing and provenance."""

    model_alias_map: Mapping[str, str]

    def __post_init__(self) -> None:
        configured = dict(self.model_alias_map)
        if len(configured) != 1:
            raise ValueError("the LiteLLM configuration must contain exactly one alias mapping")
        alias, provider = next(iter(configured.items()))
        if not alias.strip() or not provider.strip():
            raise ValueError("the LiteLLM alias and provider string must both be non-empty")
        object.__setattr__(
            self, "model_alias_map", MappingProxyType({alias.strip(): provider.strip()})
        )

    @property
    def alias(self) -> str:
        return next(iter(self.model_alias_map))

    @property
    def provider_string(self) -> str:
        return self.model_alias_map[self.alias]

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            {"model_alias_map": dict(self.model_alias_map)},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


def litellm_config(environ: Mapping[str, str] | None = None) -> LiteLLMConfig:
    """Build the one effective LiteLLM mapping from the two recorded environment values."""
    source = os.environ if environ is None else environ
    alias = source.get(MODEL_ALIAS_ENV_VAR, DEFAULT_ALIAS).strip()
    return LiteLLMConfig({alias: resolve_provider_string(source)})


def litellm_config_sha256(config: LiteLLMConfig) -> str:
    """Return the deterministic SHA-256 of the canonical secret-free mapping."""
    return config.sha256


# The assertion vocabulary used by agents.tools.registry today. Validation fails closed when a tool
# schema grows a keyword this dependency-free evaluator does not yet understand; silently ignoring a
# new constraint would turn an invalid model call back into an apparently valid one.
_TOOL_SCHEMA_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "additionalProperties",
        "enum",
        "items",
        "maxItems",
        "maxLength",
        "maxProperties",
        "pattern",
        "properties",
        "propertyNames",
        "required",
        "type",
    }
)

# Why an attempt's answer was not used: one closed vocabulary, in the order the checks run, so a
# rejected attempt in a bundle can be counted by cause rather than read. ADR-060.
#   no-tool-call          the response carried no tool call at all
#   tool-call-malformed   it carried tool calls, none with a name and a JSON-object argument; the
#                         detail is the first call's defect (one of the three _DEFECT_ values)
#   tool-not-offered      the first well-formed call named a tool this call did not offer
#   tool-not-registered   it named an offered tool the shared registry does not hold
#   schema-mismatch       its arguments fail the registry schema; the detail is
#                         "<keyword> at <path>"
_REJECT_NO_TOOL_CALL: Final = "no-tool-call"
_REJECT_MALFORMED: Final = "tool-call-malformed"
_REJECT_NOT_OFFERED: Final = "tool-not-offered"
_REJECT_NOT_REGISTERED: Final = "tool-not-registered"
_REJECT_SCHEMA: Final = "schema-mismatch"
REJECTION_CHECKS: Final[tuple[str, ...]] = (
    _REJECT_NO_TOOL_CALL,
    _REJECT_MALFORMED,
    _REJECT_NOT_OFFERED,
    _REJECT_NOT_REGISTERED,
    _REJECT_SCHEMA,
)

# The defect that stops one raw tool-call entry being a call. An argument value that is neither a
# string nor a mapping -- absent, a number -- is not JSON text either, and is reported as such.
_DEFECT_NAME_MISSING: Final = "name-missing"
_DEFECT_NOT_JSON: Final = "arguments-not-json"
_DEFECT_NOT_OBJECT: Final = "arguments-not-object"


class ModelUnavailable(RuntimeError):
    """No model call could be made at all -- no client, no credential, no reachable endpoint.

    Distinct from a call that was made and produced something unusable, which is a
    :class:`ModelResponse` with no tool call and a spent attempt. The graph treats the two
    differently: an unusable answer costs a turn and the phase continues, while an unavailable model
    is an environment fault the run must surface rather than absorb into a budget.
    """


@dataclass(frozen=True)
class ToolCall:
    """One tool invocation a model asked for: the registry name, and the arguments it supplied.

    ``arguments`` is a plain mapping. The LiteLLM boundary validates model-produced calls against
    :mod:`agents.tools.registry` before constructing this value; other clients may construct it
    directly because scripted Tier A tests intentionally own their answers.
    """

    name: str
    arguments: Mapping[str, Any]


@dataclass(frozen=True)
class ModelCall:
    """One request to the inference layer: the composed instructions, the context, the tools.

    ``system`` is a :class:`~agents.registry.composer.ComposedRole`'s text, verbatim. ``context`` is
    whatever the phase has accumulated -- rendered evidence from
    :mod:`agents.registry.renderer`, prior tool results -- and it is a separate field so that a
    reader of a trace can tell instruction bytes from environment bytes, which is the distinction
    the whole ``G3-UNQUOTED`` arm turns on.

    ``max_attempts`` bounds how many requests a client may send for this one call, retries
    included. ``None`` leaves the client's own ceiling in force. The graph passes the turns its
    ledger has left, because a retry is a turn (ADR-028) and an attempt the budget cannot cover is a
    request whose answer could never be used; a client sends at most the smaller of the two numbers.
    ADR-060.
    """

    system: str
    context: str
    tools: tuple[Mapping[str, Any], ...]
    seed: int | None
    max_attempts: int | None = None

    def __post_init__(self) -> None:
        if self.max_attempts is not None and self.max_attempts < 1:
            raise ValueError(
                f"max_attempts must be at least one when it is given, not {self.max_attempts}; "
                "a node with no turn left sends no request at all"
            )


@dataclass(frozen=True)
class RawToolCall:
    """One tool call exactly as a rejected attempt returned it: its name and its argument text.

    ``arguments`` is the provider's string verbatim. A provider that returned a structure instead
    is recorded as that structure's canonical JSON, and an absent value as ``None``; LiteLLM's
    OpenAI-compatible responses carry a string, so the verbatim case is the ordinary one. ``name``
    is ``None`` when the entry carried no string name at all.
    """

    name: str | None
    arguments: str | None


@dataclass(frozen=True)
class AttemptRecord:
    """What one request cost, and why its answer was or was not used. ADR-060.

    One per request a client sent, in order, so ``len(attempt_log) == attempts`` for
    :class:`LiteLLMClient`. ``model`` is the string the provider answered that request under. The
    usage figures are the provider's own for that request and ``None`` where it reported none;
    ``reasoning_tokens`` is ``completion_tokens_details.reasoning_tokens``, which ADR-005 records as
    already counted inside ``completion_tokens`` -- a breakdown of that figure, never an addend.

    ``rejected_check`` is one of :data:`REJECTION_CHECKS` for an attempt whose answer was not used,
    with ``rejected_detail`` naming the defect or the failing schema keyword and location, and both
    are ``None`` for the attempt that was used. ``tool_calls`` carries a rejected attempt's raw
    calls and is empty for the accepted one, whose call is :attr:`ModelResponse.tool_call`, parsed.

    THE THREE MODEL-ECHO FIELDS, AND WHY ONE ANSWERED MODEL IS NOT ENOUGH (D10, V20)
    --------------------------------------------------------------------------------
    ``model`` is the *answered* model -- :func:`_answered_model`, which falls back to the string the
    call asked for when the provider reports nothing, so a bundle never records the bare alias as a
    model. That fallback is what makes V20 dangerous rather than visible: LiteLLM's
    OpenAI-compatible
    transform reports the provider prefix plus whatever the backend echoes, so a gateway that echoes
    the requested name yields the alias *by construction* and the answered model then equals the
    asked-for string with nothing wrong-looking about it. D10 records the three raw signals beside
    it,
    each nullable and none falling back, so a later reader can tell "the provider genuinely answered
    under this model" from "the provider reported nothing and we recorded what we asked":

    - ``system_fingerprint`` -- the OpenAI-documented backend-change signal
      (``completion.system_fingerprint``); deprecated upstream, hence advisory rather than a halt
      key.
    - ``response_model`` -- the raw ``completion.model`` with **no** fallback, so ``None`` means the
      provider reported no model at all, which :attr:`model` would have hidden behind the alias.
    - ``hidden_params_model`` -- LiteLLM's ``_hidden_params.get("model")``, the fallback place the
      OpenAI-compatible transform records the model when the top-level field carries the prefix
      only.
    """

    attempt: int
    model: str
    finish_reason: str | None
    prompt_tokens: int | None
    completion_tokens: int | None
    reasoning_tokens: int | None
    system_fingerprint: str | None = None
    response_model: str | None = None
    hidden_params_model: str | None = None
    rejected_check: str | None = None
    rejected_detail: str | None = None
    tool_calls: tuple[RawToolCall, ...] = ()

    @property
    def accepted(self) -> bool:
        """Whether this attempt's answer is the one the call returned."""
        return self.rejected_check is None


@dataclass(frozen=True)
class ModelResponse:
    """What one model call produced, and what it cost in turns.

    ``attempts`` is at least one and counts every request sent, retries included, because ADR-028
    makes a retry a turn. ``provider_string`` is what the provider actually answered under, not the
    alias asked for, because ``data-management.md`` requires the exact model identity per call and
    R-01 is the risk that the two stop being the same thing without anybody noticing.

    ``tool_call`` is ``None`` when the model produced no well-formed call after every permitted
    attempt. That is the R-10 measurement in its raw form, and it is a value rather than an
    exception so that a phase can record it and move on.

    ``prompt_tokens`` and ``completion_tokens`` are the usage of the attempt whose answer was used,
    and ``None`` when none was -- the meaning they have always had. ``attempt_log`` holds every
    attempt, rejected ones included, so what a call cost is the sum over it (ADR-060). A client that
    sends no request -- the Tier A doubles -- leaves it empty.

    ``system_fingerprint``, ``response_model`` and ``hidden_params_model`` are the accepted
    attempt's
    three model-echo signals (D10), carried here beside ``provider_string`` for the same reason
    :class:`AttemptRecord` carries them per attempt: the answered model can equal the alias by
    construction (V20), so the raw signals are what let a run's model provenance be checked rather
    than trusted. They are ``None`` when no attempt was accepted and for a client that sends no
    request.
    """

    tool_call: ToolCall | None
    provider_string: str
    attempts: int
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    raw_text: str = ""
    malformed_attempts: tuple[str, ...] = field(default_factory=tuple)
    attempt_log: tuple[AttemptRecord, ...] = field(default_factory=tuple)
    system_fingerprint: str | None = None
    response_model: str | None = None
    hidden_params_model: str | None = None


@runtime_checkable
class ModelClient(Protocol):
    """One call in, one answer out. The whole inference surface the agent layer has.

    Narrow on purpose. Streaming, function-calling variants, response-format switches and provider
    options are all absent, because each of them is a place where two conditions could be given
    different treatment -- and parity is a claim about what the arms received, which is only
    checkable if there is one way to receive it.
    """

    def complete(self, call: ModelCall) -> ModelResponse:
        """Send ``call`` and return the answer, or raise :class:`ModelUnavailable`."""
        ...


def resolve_provider_string(environ: Mapping[str, str] | None = None) -> str:
    """Return the provider model string the alias resolves to, or raise naming what is missing.

    No default and no fallback. A resolved-to-nothing alias would let a run proceed against whatever
    the gateway happened to route to, and the bundle would record an alias rather than a model --
    which is exactly the state R-01 makes dangerous. The runner sets the key from
    ``infra/versions.env``; a developer sets it in ``.env``.
    """
    source = os.environ if environ is None else environ
    resolved = source.get(MODEL_PROVIDER_STRING_ENV_VAR, "").strip()
    if not resolved:
        raise ModelUnavailable(
            f"{MODEL_PROVIDER_STRING_ENV_VAR} is unset, so the alias "
            f"{source.get(MODEL_ALIAS_ENV_VAR, DEFAULT_ALIAS)!r} resolves to nothing. ADR-005 "
            "requires the exact provider model string to be recorded per call, and a run that "
            "could not name its model would produce a bundle nobody can reproduce (risk R-01). "
            "Set it from infra/versions.env"
        )
    return resolved


def wire_tool(definition: Mapping[str, Any]) -> dict[str, Any]:
    """Return the OpenAI-compatible function tool one registry projection is sent as.

    The projection (:meth:`agents.tools.registry.ToolDefinition.as_projection`) is the registry's
    canonical form, and it is what ``tool_registry_sha256`` digests and what ``messages.jsonl``
    records; it is left exactly as it is. An OpenAI-compatible endpoint reads a function's ``name``
    and its ``parameters`` JSON Schema, so that is what is built from it, at this boundary and
    nowhere else. ADR-060.

    ``parameters`` is the registry schema verbatim, deep-copied so that nothing a provider library
    does to a request can reach the registry's module-level singletons. ``dialect`` and
    ``doc_block`` are not sent: an OpenAI-compatible endpoint defines no field for either. Nor is a
    ``description``, deliberately. Every role that holds a tool carries that tool's documentation
    block in its composed system prompt -- ``agents/tests/test_model_tool_validation.py`` asserts it
    for every role of every condition -- so a description would send the same guidance a second
    time, as instruction text outside the composed prompt that ``make parity-check`` counts.
    """
    name = definition.get("name")
    schema = definition.get("schema")
    if not isinstance(name, str) or not name or not isinstance(schema, Mapping):
        raise ValueError(
            "a tool offered to the model must be a registry projection carrying a non-empty "
            f"'name' and a 'schema' mapping; this one carries {sorted(map(str, definition))}"
        )
    return {
        "type": "function",
        "function": {"name": name, "parameters": copy.deepcopy(dict(schema))},
    }


def wire_tools(definitions: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Map every offered projection with :func:`wire_tool`, in the order it was offered."""
    return [wire_tool(definition) for definition in definitions]


class ScriptedClient:
    """Answers what the test said to answer, and records every call it was handed.

    The Tier A double. It does not decide anything -- ``guardian/app/policy.py`` states the rule
    these obey and it is quoted here because it applies unchanged: "A decision procedure implemented
    twice, once in Rego and once in Python 'for the tests', is two policies whose divergence nobody
    would notice until an evaluation depended on it." The same holds for a model: a double that
    chose a tool by inspecting the prompt would be a second, much worse agent, and the golden path
    would be testing it rather than the graph.

    ``answers`` is consumed in order. When it runs out, the client returns a response with no tool
    call, which is the honest end state -- a model that has stopped producing usable calls -- and is
    what lets a lifecycle test drive a phase to ``budget-exhausted`` without special-casing
    anything.

    It sends no request, so its responses carry no attempt log and it has no ``tool_wire_shape``;
    and it reports its scripted ``attempts`` whatever cap a call carries, which leaves the ledger's
    overspend path reachable by a test that wants it.
    """

    def __init__(
        self,
        answers: Sequence[ToolCall | None],
        *,
        provider_string: str = SCRIPTED_PROVIDER_STRING,
        attempts_per_answer: int = 1,
    ) -> None:
        self._answers = list(answers)
        self._provider_string = provider_string
        self.config = LiteLLMConfig({DEFAULT_ALIAS: provider_string})
        self._attempts_per_answer = attempts_per_answer
        self.calls: list[ModelCall] = []

    def complete(self, call: ModelCall) -> ModelResponse:
        """Record the call and return the next scripted answer."""
        self.calls.append(call)
        answer = self._answers.pop(0) if self._answers else None
        return ModelResponse(
            tool_call=answer,
            provider_string=self._provider_string,
            attempts=self._attempts_per_answer,
        )


class LiteLLMClient:
    """The Tier A' client: one call through the LiteLLM alias, retried on a malformed tool call.

    ``litellm`` is imported in the constructor rather than at module scope, so that importing this
    module costs nothing on a machine that has no provider package and so that the entire Tier A
    suite runs without it. The import failure is reported as :class:`ModelUnavailable` naming the
    pin, because "the package is missing" and "the credential is missing" are different problems
    with different fixes and a caller should not have to read a traceback to tell them apart.

    ``max_attempts`` bounds the retry loop, and every attempt is a turn the caller must spend. The
    default is three: enough for a small model to recover from one malformed emission and a second
    stumble, and small enough that a model which cannot tool-call at all shows up as a measurement
    rather than as a stalled run. That number is a property of this client rather than of the
    protocol, which is why it is a constructor argument and not a value in a protocol file. A call
    may lower it for itself through :attr:`ModelCall.max_attempts`, never raise it.
    """

    # The wire mapping this client applies to ModelCall.tools. agents/golden.py's recorder copies it
    # into every messages.jsonl record, so the request is reconstructible from the bundle.
    @property
    def tool_wire_shape(self) -> str:
        return (
            RESPONSES_TOOL_WIRE_SHAPE
            if self.provider_string.startswith("custom_openai/")
            else TOOL_WIRE_SHAPE
        )

    def __init__(
        self,
        *,
        alias: str = DEFAULT_ALIAS,
        provider_string: str | None = None,
        config: LiteLLMConfig | None = None,
        max_attempts: int = 3,
        timeout_seconds: float = 120.0,
    ) -> None:
        try:
            import litellm  # noqa: PLC0415 - deliberately lazy; see the class docstring
        except ImportError as missing:
            raise ModelUnavailable(
                "litellm is not importable. It is pinned in infra/versions.env as "
                "LITELLM_VERSION and installed by scripts/install_runtime_deps.sh agents; Tier A "
                "does not need it, and Tier A' does"
            ) from missing
        self._litellm = litellm
        if config is not None and (alias != DEFAULT_ALIAS or provider_string is not None):
            raise ValueError("pass config or alias/provider_string, not both")
        effective = config or LiteLLMConfig({alias: provider_string or resolve_provider_string()})
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least one")
        self.config = effective
        self.alias = effective.alias
        self.provider_string = effective.provider_string
        self._litellm.model_alias_map = dict(effective.model_alias_map)
        self.max_attempts = max_attempts
        self.timeout_seconds = timeout_seconds

    def complete(self, call: ModelCall) -> ModelResponse:
        """Send ``call`` through the alias, retrying only a malformed tool call.

        A transport failure is **not** retried here. It is raised as :class:`ModelUnavailable`, on
        the same reasoning :mod:`agents.tools.guardian_client` gives for not retrying a decision: a
        retry policy buried in a client spends a budget nobody can see it spending, and whether to
        try again is a question about the phase's declared turn budget, which the graph owns.

        What *is* retried is an answer that came back and could not be used -- no tool call, an
        unknown tool name, or arguments that are not a JSON object satisfying that tool's shared
        registry schema. That is risk R-10's failure mode, it is cheap to recover from, and every
        attempt is reported so the retry rate is a measurement rather than a hidden cost.

        At most ``min(self.max_attempts, call.max_attempts)`` requests are sent. The graph passes
        the turns its ledger has left, so no request goes out for an answer the node's budget could
        not let it use (ADR-028, ADR-060). Each request carries the tools as :func:`wire_tools`
        maps them, rebuilt per attempt so that nothing a provider library does to one request's
        list can reach the next, and each is recorded in :attr:`ModelResponse.attempt_log`.
        """
        limit = (
            self.max_attempts
            if call.max_attempts is None
            else min(self.max_attempts, call.max_attempts)
        )
        malformed: list[str] = []
        log: list[AttemptRecord] = []
        answered_provider = self.provider_string
        messages = [
            {"role": "system", "content": call.system},
            {"role": "user", "content": call.context},
        ]
        for attempt in range(1, limit + 1):
            # Built outside the try below: a projection that cannot be mapped is a defect in the
            # caller, and reporting it as an unreachable provider would send somebody to the wrong
            # fix.
            tools = wire_tools(call.tools)
            try:
                if self.provider_string.startswith("custom_openai/"):
                    completion = self._responses_completion(call, tools)
                else:
                    completion = self._litellm.completion(
                        model=self.alias,
                        messages=messages,
                        tools=tools,
                        temperature=TEMPERATURE,
                        reasoning_effort=REASONING_EFFORT,
                        allowed_openai_params=["reasoning_effort"],
                        seed=call.seed,
                        timeout=self.timeout_seconds,
                    )
            except Exception as failed:  # noqa: BLE001 - every provider raises its own hierarchy
                raise ModelUnavailable(
                    f"the model call through alias {self.alias!r} "
                    f"({self.provider_string}) did not complete: {failed}"
                ) from failed
            answered_provider = _answered_model(completion, self.provider_string)
            fingerprint = _system_fingerprint(completion)
            response_model = _raw_response_model(completion)
            hidden_model = _hidden_params_model(completion)
            parsed, check, detail = _evaluate_attempt(completion, call.tools)
            log.append(
                AttemptRecord(
                    attempt=attempt,
                    model=answered_provider,
                    finish_reason=_finish_reason(completion),
                    prompt_tokens=_usage(completion, "prompt_tokens"),
                    completion_tokens=_usage(completion, "completion_tokens"),
                    reasoning_tokens=_reasoning_tokens(completion),
                    system_fingerprint=fingerprint,
                    response_model=response_model,
                    hidden_params_model=hidden_model,
                    rejected_check=check,
                    rejected_detail=detail,
                    tool_calls=() if parsed is not None else _raw_tool_calls(completion),
                )
            )
            if parsed is not None:
                return ModelResponse(
                    tool_call=parsed,
                    provider_string=answered_provider,
                    attempts=attempt,
                    prompt_tokens=_usage(completion, "prompt_tokens"),
                    completion_tokens=_usage(completion, "completion_tokens"),
                    raw_text=_text(completion),
                    malformed_attempts=tuple(malformed),
                    attempt_log=tuple(log),
                    system_fingerprint=fingerprint,
                    response_model=response_model,
                    hidden_params_model=hidden_model,
                )
            malformed.append(_text(completion))
        return ModelResponse(
            tool_call=None,
            provider_string=answered_provider,
            attempts=limit,
            raw_text=malformed[-1] if malformed else "",
            malformed_attempts=tuple(malformed),
            attempt_log=tuple(log),
            system_fingerprint=log[-1].system_fingerprint if log else None,
            response_model=log[-1].response_model if log else None,
            hidden_params_model=log[-1].hidden_params_model if log else None,
        )

    def _responses_completion(self, call: ModelCall, tools: list[dict[str, Any]]) -> dict[str, Any]:
        """ADR-174: preserve xhigh function calling on the configured compatible dev route."""
        from litellm.completion_extras.litellm_responses_transformation.transformation import (  # noqa: PLC0415
            LiteLLMResponsesTransformationHandler,
        )
        from litellm.responses.utils import ResponseAPILoggingUtils  # noqa: PLC0415

        raw = self._litellm.responses(
            model=self.provider_string.removeprefix("custom_openai/"),
            custom_llm_provider="openai",
            api_base=os.environ.get("OPENAI_BASE_URL"),
            api_key=os.environ.get("OPENAI_API_KEY"),
            instructions=call.system,
            input=[{"role": "user", "content": call.context}],
            tools=[{"type": "function", **tool["function"], "strict": False} for tool in tools],
            reasoning={"effort": REASONING_EFFORT},
            extra_body={"temperature": TEMPERATURE, "seed": call.seed},
            timeout=self.timeout_seconds,
        )
        converter = LiteLLMResponsesTransformationHandler()
        completion = {
            "choices": converter._convert_response_output_to_choices(
                _attr(raw, "output") or [],
                handle_raw_dict_callback=converter._handle_raw_dict_response_item,
            ),
            # The SDK's full completion transform substitutes the requested model; retain raw
            # identity instead, including absence and deliberate backend mismatches (D10).
            "model": _attr(raw, "model"),
            "system_fingerprint": _attr(raw, "system_fingerprint"),
            "_hidden_params": _attr(raw, "_hidden_params"),
        }
        usage = _attr(raw, "usage")
        if usage is not None:
            try:
                converted = ResponseAPILoggingUtils._transform_response_api_usage_to_chat_usage(
                    usage
                )
                normalized = converted.model_dump()
            except (ValueError, TypeError, AttributeError):
                normalized = {}
            # SDK normalization defaults absent counts to zero and may coerce malformed ones.
            # Attempt accounting must retain unknown instead, while keeping valid explicit zero.
            normalized["prompt_tokens"] = _token_count(_attr(usage, "input_tokens"))
            normalized["completion_tokens"] = _token_count(_attr(usage, "output_tokens"))
            normalized["completion_tokens_details"] = {
                "reasoning_tokens": _token_count(
                    _attr(_attr(usage, "output_tokens_details"), "reasoning_tokens")
                )
            }
            completion["usage"] = normalized
        return completion


def _tool_call_parts(completion: Any) -> list[tuple[Any, Any]]:
    """Return every tool call in a completion as its raw ``(name, arguments)`` pair, in order.

    Deliberately tolerant of the provider's shape: providers disagree about whether a completion is
    an object or a mapping and about where the tool calls hang, so the traversal is defensive and
    nothing is judged here. :func:`_parse_call` is where the judging happens.
    """
    parts: list[tuple[Any, Any]] = []
    for choice in _attr(completion, "choices") or []:
        for raw in _attr(_attr(choice, "message"), "tool_calls") or []:
            function = _attr(raw, "function")
            parts.append((_attr(function, "name"), _attr(function, "arguments")))
    return parts


def _parse_call(name: Any, arguments: Any) -> ToolCall | str:
    """Return the call one raw tool-call entry encodes, or the defect that stops it being one.

    Tolerant of the provider's shape and intolerant of the argument's. Providers agree that the
    arguments are a JSON string, so the parse is strict -- an argument blob that is not a JSON
    object is a malformed call, which is the R-10 measurement, and treating it as an empty call
    would record a model failure as a model success with nothing to do. A mapping is accepted as
    it stands.
    """
    if not isinstance(name, str) or not name:
        return _DEFECT_NAME_MISSING
    if isinstance(arguments, Mapping):
        return ToolCall(name=name, arguments=dict(arguments))
    if not isinstance(arguments, str):
        return _DEFECT_NOT_JSON
    try:
        decoded = json.loads(arguments)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _DEFECT_NOT_JSON
    if not isinstance(decoded, Mapping):
        return _DEFECT_NOT_OBJECT
    return ToolCall(name=name, arguments=dict(decoded))


def _evaluate_attempt(
    completion: Any, offered_tools: Sequence[Mapping[str, Any]]
) -> tuple[ToolCall | None, str | None, str | None]:
    """Return ``(call, None, None)`` for a usable answer, or ``(None, check, detail)`` otherwise.

    The first well-formed tool call is the one judged against the registry; a malformed entry before
    it is skipped, and a well-formed call that then fails the registry rejects the attempt even if a
    later entry would have passed. That is the order this seam has always applied, now with the
    reason for a rejection kept rather than thrown away.
    """
    parts = _tool_call_parts(completion)
    if not parts:
        return None, _REJECT_NO_TOOL_CALL, None
    first_defect: str | None = None
    parsed: ToolCall | None = None
    for name, arguments in parts:
        outcome = _parse_call(name, arguments)
        if isinstance(outcome, ToolCall):
            parsed = outcome
            break
        if first_defect is None:
            first_defect = outcome
    if parsed is None:
        return None, _REJECT_MALFORMED, first_defect
    rejection = _registry_rejection(parsed, offered_tools)
    if rejection is not None:
        return None, rejection[0], rejection[1]
    return parsed, None, None


def _registry_rejection(
    call: ToolCall, offered_tools: Sequence[Mapping[str, Any]]
) -> tuple[str, str | None] | None:
    """Return why ``call`` fails the offered set or the shared registry, or ``None`` if it passes.

    This intentionally reads the schema from the shared registry rather than copying tool shapes
    into the inference seam. The registry currently uses a small, closed JSON Schema 2020-12
    vocabulary; :func:`_schema_violation` implements every assertion keyword present in those
    schemas without adding an unpinned runtime dependency on ``jsonschema``.
    """
    offered_names = {
        name for definition in offered_tools if isinstance((name := definition.get("name")), str)
    }
    if call.name not in offered_names:
        return _REJECT_NOT_OFFERED, None
    try:
        schema = tool_definition(call.name).schema
    except KeyError:
        return _REJECT_NOT_REGISTERED, None
    violation = _schema_violation(call.arguments, schema)
    return None if violation is None else (_REJECT_SCHEMA, violation)


def _schema_violation(value: Any, schema: Mapping[str, Any], path: str = "$") -> str | None:
    """Return the first assertion ``value`` fails as ``"<keyword> at <path>"``, or ``None``.

    Evaluates the assertion vocabulary used by the shared tool registry, in a fixed order, and a
    schema carrying any other keyword fails closed as ``unsupported-keyword``. ``path`` locates the
    failure using the schema's own property names -- ``$.outcome``, ``$.verbs[0]``, and for a
    missing required property the path it should have had. A key the model invented is never
    echoed: an unknown key is ``additionalProperties at`` its object, and a value under an
    additional-property schema is located as ``.*``.
    """
    if set(schema) - _TOOL_SCHEMA_KEYWORDS:
        return f"unsupported-keyword at {path}"

    declared = schema.get("type")
    if declared is not None:
        names = (declared,) if isinstance(declared, str) else tuple(declared)
        if not any(_matches_json_type(value, name) for name in names):
            return f"type at {path}"

    allowed = schema.get("enum")
    if allowed is not None and not any(
        candidate == value and isinstance(candidate, bool) == isinstance(value, bool)
        for candidate in allowed
    ):
        return f"enum at {path}"

    if isinstance(value, str):
        pattern = schema.get("pattern")
        if pattern is not None and re.search(pattern, value) is None:
            return f"pattern at {path}"
        maximum = schema.get("maxLength")
        if maximum is not None and len(value) > maximum:
            return f"maxLength at {path}"

    if isinstance(value, Mapping):
        for name in schema.get("required", ()):
            if name not in value:
                return f"required at {path}.{name}"
        maximum = schema.get("maxProperties")
        if maximum is not None and len(value) > maximum:
            return f"maxProperties at {path}"

        properties = schema.get("properties", {})
        for name, child_schema in properties.items():
            if name in value:
                violation = _schema_violation(value[name], child_schema, f"{path}.{name}")
                if violation is not None:
                    return violation

        names_schema = schema.get("propertyNames")
        if names_schema is not None and any(
            not isinstance(name, str) or _schema_violation(name, names_schema) is not None
            for name in value
        ):
            return f"propertyNames at {path}"

        extra = schema.get("additionalProperties", True)
        # The value's own key order, never a set's: which additional key is reported first must be
        # the same on every replay (rule 20).
        unknown = [name for name in value if name not in properties]
        if extra is False and unknown:
            return f"additionalProperties at {path}"
        if isinstance(extra, Mapping):
            for name in unknown:
                violation = _schema_violation(value[name], extra, f"{path}.*")
                if violation is not None:
                    return violation

    if isinstance(value, list):
        maximum = schema.get("maxItems")
        if maximum is not None and len(value) > maximum:
            return f"maxItems at {path}"
        item_schema = schema.get("items")
        if item_schema is not None:
            for index, item in enumerate(value):
                violation = _schema_violation(item, item_schema, f"{path}[{index}]")
                if violation is not None:
                    return violation

    return None


def _matches_json_type(value: Any, name: str) -> bool:
    """Match JSON types without Python's ``bool``-is-an-``int`` ambiguity."""
    if name == "object":
        return isinstance(value, Mapping)
    if name == "array":
        return isinstance(value, list)
    if name == "string":
        return isinstance(value, str)
    if name == "null":
        return value is None
    if name == "boolean":
        return isinstance(value, bool)
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return False


def _raw_tool_calls(completion: Any) -> tuple[RawToolCall, ...]:
    """Return every tool call in a completion as the provider sent it, for a rejected attempt."""
    return tuple(
        RawToolCall(name=name if isinstance(name, str) else None, arguments=_arguments_text(value))
        for name, value in _tool_call_parts(completion)
    )


def _arguments_text(arguments: Any) -> str | None:
    """Return a tool call's argument text verbatim, or a structure's canonical JSON."""
    if arguments is None or isinstance(arguments, str):
        return arguments
    payload = dict(arguments) if isinstance(arguments, Mapping) else arguments
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=repr
    )


def _attr(node: Any, name: str) -> Any:
    """Read ``name`` off an object or a mapping, returning ``None`` when it is neither."""
    if node is None:
        return None
    if isinstance(node, Mapping):
        return node.get(name)
    return getattr(node, name, None)


def _text(completion: Any) -> str:
    """Return the assistant's text content, or the empty string."""
    for choice in _attr(completion, "choices") or []:
        content = _attr(_attr(choice, "message"), "content")
        if isinstance(content, str):
            return content
    return ""


def _finish_reason(completion: Any) -> str | None:
    """Return the first choice's finish reason, or ``None`` when the provider gave none."""
    for choice in _attr(completion, "choices") or []:
        reason = _attr(choice, "finish_reason")
        return reason if isinstance(reason, str) else None
    return None


def _answered_model(completion: Any, fallback: str) -> str:
    """Return the model string the provider answered under, falling back to what was asked.

    The fallback is the asked-for string rather than the alias, so a bundle never records the alias
    as though it were a model. A provider that reports nothing is recorded as the string it was
    asked for, which is true, and R-01's failure -- a silently substituted model -- shows up as a
    *difference* between the two when the provider does report.
    """
    answered = _attr(completion, "model")
    # ADR-175: qualify a bare echo with the known transport, preserving its actual model.
    # Raw backend identity remains verbatim in _raw_response_model for drift checks.
    if (
        fallback.startswith("custom_openai/")
        and isinstance(answered, str)
        and answered
        and "/" not in answered
    ):
        return f"custom_openai/{answered}"
    return answered if isinstance(answered, str) and answered else fallback


def _raw_response_model(completion: Any) -> str | None:
    """Return the provider's ``model`` verbatim, with **no** fallback to the asked-for string.

    :func:`_answered_model` substitutes the asked-for string when the provider reports nothing,
    which
    is right for the one recorded model but wrong for D10's provenance signal: the whole point of
    recording the raw value is that ``None`` here says the provider named no model, a fact the
    fallback in :func:`_answered_model` hides behind the alias (V20). So this returns exactly what
    the completion carried, or ``None``.
    """
    model = _attr(completion, "model")
    return model if isinstance(model, str) and model else None


def _system_fingerprint(completion: Any) -> str | None:
    """Return ``completion.system_fingerprint``, or ``None`` when the provider reported none.

    OpenAI documents ``system_fingerprint`` as the backend-configuration signal to watch alongside
    ``seed`` for a silent backend change; it is deprecated upstream, so D10 records it as advisory
    rather than as an answered-model halt key.
    """
    fingerprint = _attr(completion, "system_fingerprint")
    return fingerprint if isinstance(fingerprint, str) and fingerprint else None


def _hidden_params_model(completion: Any) -> str | None:
    """Return ``completion._hidden_params['model']``, LiteLLM's fallback home for the model string.

    LiteLLM's OpenAI-compatible transform records the model the backend echoed under
    ``_hidden_params`` when the top-level ``model`` carries the provider prefix only, so this is the
    third D10 signal: a value here that differs from :func:`_raw_response_model` is exactly the
    prefix-versus-echo split Appendix A confirms against the pinned LiteLLM version.
    """
    hidden = _attr(completion, "_hidden_params")
    if not isinstance(hidden, Mapping):
        return None
    model = hidden.get("model")
    return model if isinstance(model, str) and model else None


def _usage(completion: Any, field_name: str) -> int | None:
    """Return one token-usage figure, or ``None`` when the provider reported none."""
    value = _attr(_attr(completion, "usage"), field_name)
    return _token_count(value)


def _token_count(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _reasoning_tokens(completion: Any) -> int | None:
    """Return ``usage.completion_tokens_details.reasoning_tokens``, or ``None`` when unreported."""
    details = _attr(_attr(completion, "usage"), "completion_tokens_details")
    value = _attr(details, "reasoning_tokens")
    return _token_count(value)
