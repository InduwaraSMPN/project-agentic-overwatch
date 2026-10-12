r"""``python -m agents.golden``: drive one condition through the four phases and record everything.

WHAT THIS MODULE IS
-------------------
The golden path's driver. ``make agents-golden`` delegates to ``scripts/agents_golden.sh``, which
delegates here, and what it produces is the evidence ``docs/milestones/M4-agents.md``'s first
Definition-of-done item asks for: four section 1.6 phase spans present **in order**,
``messages.jsonl`` carrying the bytes each call actually sent and received, and a ``tokens.json``
entry for every model call carrying the **exact provider string** rather than the alias.

It is not the runner. ``runner/`` is M6's, it owns condition flags, campaign manifests, seeds drawn
from a run manifest and the sealed bundle format, and none of that is here. What is here is the one
thing M4 owes: a way to run S1-HIER end to end and look at what came out. When M6 lands, its runner
composes the same three pieces this module composes -- a plan, a context, a sink -- and this module
becomes the small worked example rather than a thing to delete.

WHY IT IMPORTS NOTHING FROM ``guardian/``
-------------------------------------------
The Guardian is reached over HTTP through :class:`~agents.tools.guardian_client.UrllibTransport`,
at a base URL this module is told. That is not a stylistic preference: the agent layer ships as its
own container, ``.agents/rules/10-guardian-first.md`` makes the Guardian client the only mutation
path, and a driver that imported the Guardian's composition root would be a driver that could
assemble one -- which would put the sole credential holder's assembly inside the process the threat
model treats as the adversary (position P4). The tests drive the same code against an in-process
ASGI application by handing :class:`~agents.tools.guardian_client.GuardianClient` a different
transport, which is exactly what the ``Transport`` type exists for.

WHY THE EVIDENCE IS A PATH AND NOT AN IMPORT
----------------------------------------------
``--evidence`` names a file of emitted ``EvidenceEvent`` JSON objects -- the Monitor's output
format, one per line, as ``monitor/fixtures/*/expected/monitor_events.jsonl`` holds and as a live
aggregator writes. Reading a file keeps ``agents/`` free of a build-time dependency on ``monitor/``
and, more usefully, means the golden path consumes the **same bytes** at Tier A (a fixture) and at
Tier B (a live Monitor). The ``G3-UNQUOTED`` exercise is then a different input file rather than a
different code path, which is what ADR-023's discipline requires of every arm.

WHY THE MODEL IS EITHER A SCRIPT OR THE ALIAS, AND NEVER A MOCK
-----------------------------------------------------------------
``--script`` names a file of tool calls, consumed in order, and selects
:class:`~agents.registry.model.ScriptedClient`; its absence selects
:class:`~agents.registry.model.LiteLLMClient` against the alias, which is the Tier A′ run that
spends a provider token and measures R-10. There is no third mode, and in particular there is no
"mock that answers plausibly": a double that chose its answer by reading the prompt would be a
second, much worse agent, and the golden path would then be evidence about it.

WHAT IT WRITES
---------------
Into ``--out``: ``spans.otel.json`` (one canonical JSON document containing a ``spans`` array
in close order), ``messages.jsonl`` (one object per model call, verbatim), and ``tokens.json`` (one
entry per call, with the provider string, attempt count and reported usage). ``results.json`` holds
phase results) and ``golden.json`` (what was run: condition, run id, seed, registry digests and the
parity tokenizer's identity, so the artefact can be tied to the registry that produced it).

Since ADR-060 each ``messages.jsonl`` object also carries the call's attempt cap, the wire-shape
marker that makes its request reconstructible, and one outcome per request sent; each
``tokens.json`` entry also carries every request's usage. Those are additions only -- no key that
existed before changes its value or its meaning. See :meth:`RecordingClient.complete`.

Every path is written relative to ``--out`` and nothing is written anywhere else. The bundle format
is M6's and is deliberately not anticipated here: a driver that guessed at it would have to be
unguessed.
"""

from __future__ import annotations

import argparse
import importlib
import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Final

from agents.graphs import CONDITION_MODULES
from agents.graphs.nodes import (
    NodeContext,
    PhaseResult,
    executor_delegate_for,
    unavailable_model_result,
)
from agents.graphs.plan import GraphPlan, GraphStep, run_plan
from agents.registry import PHASES
from agents.registry.digest import directory_digest, tool_registry_digest
from agents.registry.loader import Composition, RegistryError, default_registry_root, load_registry
from agents.registry.model import (
    DEFAULT_ALIAS,
    LiteLLMClient,
    LiteLLMConfig,
    ModelCall,
    ModelClient,
    ModelResponse,
    ModelUnavailable,
    ScriptedClient,
    ToolCall,
    litellm_config,
    litellm_config_sha256,
)
from agents.registry.tokenizer import REFERENCE_TOKENIZER_ID
from agents.registry.tracing import (
    DEFAULT_OTLP_HTTP_ENDPOINT,
    OTLP_TRACES_ENDPOINT_KEY,
    SPAN_EXPORTER_KEY,
    SpanSink,
    Tracer,
    configured_span_sink,
)
from agents.tools.guardian_client import GuardianClient, UrllibTransport
from agents.tools.registry import ISSUE_TOKEN_TOOL, TOOL_NAMES, definitions_for

__all__ = (
    "GoldenRun",
    "RecordingClient",
    "load_evidence",
    "load_script",
    "main",
    "registered_issuers",
    "run_golden",
)

# The default condition. `make agents-golden` runs S1-HIER x G0-FULL and nothing else -- the arm is
# not a parameter on that target, because ADR-023 puts every condition flag in the runner's hands
# and forbids anything under agents/ from reaching one. The flag below exists for the tests, which
# drive all three topologies over the same driver to show the traversal is a property of the plan.
DEFAULT_CONDITION: Final = "S1-HIER"

# The default seed. Rule 20 requires a run to be reproducible from (scenario_id, seed), and a driver
# whose default was "unseeded" would be a place the property was not exercised. M6's runner supplies
# the real one from the run manifest.
DEFAULT_SEED: Final = 7

# How long one HTTP call to the Guardian may take. A driver-level transport bound, not a protocol
# value: `security-policy.md` owns the Guardian's own timeouts and this is the client's patience,
# which is a different quantity and is stated here so it is not silently infinite.
TRANSPORT_TIMEOUT_SECONDS: Final = 30.0

SPANS_FILE: Final = "spans.otel.json"
MESSAGES_FILE: Final = "messages.jsonl"
TOKENS_FILE: Final = "tokens.json"
RESULTS_FILE: Final = "results.json"
MANIFEST_FILE: Final = "golden.json"


class RecordingClient:
    """Wraps a :class:`~agents.registry.model.ModelClient` and records every call verbatim.

    A wrapper rather than a flag on the clients, so that the recording is identical whichever client
    is underneath and so that neither client has a code path that exists only when a trace is
    wanted. The recorded ``system`` and ``context`` are the exact strings that were sent -- not a
    summary, not a hash -- because the Definition of done says "verbatim messages captured" and
    because the ``G0``/``G3`` prompt diff is a comparison of bytes.

    ``tokens`` carries one entry per call with :attr:`~agents.registry.model.ModelResponse`'s
    ``provider_string``, which is what the provider *answered* under rather than the alias that was
    asked for. Risk R-01 is precisely that those two stop being the same thing without anybody
    noticing, so recording the alias here would record the thing that cannot go stale instead of the
    thing that can.
    """

    def __init__(self, inner: ModelClient) -> None:
        self._inner = inner
        config = getattr(inner, "config", None)
        self._model_alias = getattr(config, "alias", None)
        # The wire mapping the inner client applies to the recorded tool projections (ADR-060), or
        # None for a double that sends no request. Read like `config` above: a property of the
        # client, recorded per call so that one messages.jsonl line reconstructs one request.
        self._tool_wire_shape = getattr(inner, "tool_wire_shape", None)
        self.messages: list[dict[str, Any]] = []
        self.tokens: list[dict[str, Any]] = []
        self._phase: str = ""
        self._role_id: str = ""

    def where(self, *, phase: str, role_id: str) -> None:
        """Tell the recorder which step the next calls belong to.

        Set by the driver around each step rather than threaded through
        :class:`~agents.registry.model.ModelCall`, because that dataclass is the inference
        contract -- adding a trace-only field to it would put a recording concern inside the one
        surface parity depends on being identical across arms.
        """
        self._phase = phase
        self._role_id = role_id

    def complete(self, call: ModelCall) -> ModelResponse:
        """Send ``call`` through the wrapped client, record both halves, and return the answer.

        ADR-060 adds four keys and changes none. ``max_attempts`` and ``tool_wire_shape`` complete
        the request: under the marker ``openai-function-v1``, mapping each recorded tool projection
        with :func:`agents.registry.model.wire_tool` gives the tool list that went on the wire.
        ADR-174's ``openai-responses-function-v1`` flattens that function mapping beside
        ``type: function`` and adds ``strict: false``; historical markers retain their meaning.
        ``attempt_outcomes`` says, per request sent, how it finished and which validation check
        rejected it, with a rejected attempt's raw tool calls; ``attempt_usage`` in the tokens entry
        carries every request's usage, so what the call cost is the sum over it. ``prompt_tokens``
        and ``completion_tokens`` keep their meaning -- the accepted attempt's usage, null when no
        attempt was accepted -- which is why they are not the place to total a run's spend.
        """
        response = self._inner.complete(call)
        index = len(self.messages)
        self.messages.append(
            {
                "index": index,
                "phase": self._phase,
                "role_id": self._role_id,
                "system": call.system,
                "context": call.context,
                "tools": [dict(tool) for tool in call.tools],
                "seed": call.seed,
                "answer_text": response.raw_text,
                "tool_call": (
                    None
                    if response.tool_call is None
                    else {
                        "name": response.tool_call.name,
                        "arguments": dict(response.tool_call.arguments),
                    }
                ),
                "malformed_attempts": list(response.malformed_attempts),
                "max_attempts": call.max_attempts,
                "tool_wire_shape": self._tool_wire_shape,
                "attempt_outcomes": [
                    {
                        "attempt": record.attempt,
                        "finish_reason": record.finish_reason,
                        "accepted": record.accepted,
                        "rejected_check": record.rejected_check,
                        "rejected_detail": record.rejected_detail,
                        "system_fingerprint": record.system_fingerprint,
                        "response_model": record.response_model,
                        "hidden_params_model": record.hidden_params_model,
                        "tool_calls": [
                            {"name": raw.name, "arguments": raw.arguments}
                            for raw in record.tool_calls
                        ],
                    }
                    for record in response.attempt_log
                ],
            }
        )
        self.tokens.append(
            {
                "index": index,
                "phase": self._phase,
                "role_id": self._role_id,
                "model_alias": self._model_alias,
                "model": response.provider_string,
                # D10's three model-echo signals for the accepted attempt, beside the answered
                # `model`: the answered model can equal the alias by construction (V20), so these
                # are
                # what let a run's model provenance be checked rather than trusted. `runner/` reads
                # them into the manifest's answered_model / system_fingerprints fields (SEAM 1).
                "system_fingerprint": response.system_fingerprint,
                "response_model": response.response_model,
                "hidden_params_model": response.hidden_params_model,
                "attempts": response.attempts,
                "prompt_tokens": response.prompt_tokens,
                "completion_tokens": response.completion_tokens,
                "attempt_usage": [
                    {
                        "attempt": record.attempt,
                        "model": record.model,
                        "system_fingerprint": record.system_fingerprint,
                        "response_model": record.response_model,
                        "hidden_params_model": record.hidden_params_model,
                        "prompt_tokens": record.prompt_tokens,
                        "completion_tokens": record.completion_tokens,
                        "reasoning_tokens": record.reasoning_tokens,
                    }
                    for record in response.attempt_log
                ],
            }
        )
        return response

    def record_unavailable(self, failure: ModelUnavailable) -> None:
        """Record a model-unavailable failure as an INDEXED entry in both files (V13, F-RN-01).

        The ``ModelUnavailable`` path used to append a bare ``{"error": ...}`` dict to ``messages``
        with no ``index`` and nothing at all to ``tokens`` -- which is V13: ``seal_bundle`` refuses
        a
        ``messages.jsonl`` line with "no non-negative integer 'index'", so a run whose provider was
        unreachable failed to seal for a reason unrelated to the failure it was trying to record.
        This routes the failure through the same accounting :meth:`complete` uses: one message entry
        and one tokens entry, sharing the next index, so F-RN-01 ("every messages.jsonl entry,
        failure records included, carries an index matched in tokens.json") holds for it too.

        No request was sent, so there is no attempt log, no usage and no model-echo to record; the
        two entries carry the failure text and the step attribution :meth:`where` last set. D10's
        three model-echo fields are present and **null** on the tokens row rather than absent, and
        that distinction is load-bearing: ``runner/`` reads them into the manifest's
        ``answered_model`` and ``system_fingerprints`` fields (SEAM 1) and F-AG-04 requires the
        answered model to be recorded for *every* call, so a row whose keys were missing would make
        every consumer read them defensively to tell "this call named no model" from "this row was
        never written by a recorder that knew about the field". A null here is a fact -- the
        provider was never asked.
        """
        index = len(self.messages)
        detail = f"model unavailable: {failure}"
        self.messages.append(
            {
                "index": index,
                "phase": self._phase,
                "role_id": self._role_id,
                "error": detail,
            }
        )
        self.tokens.append(
            {
                "index": index,
                "phase": self._phase,
                "role_id": self._role_id,
                "model_alias": self._model_alias,
                "model": None,
                "system_fingerprint": None,
                "response_model": None,
                "hidden_params_model": None,
                "error": detail,
            }
        )


class GoldenRun:
    """What one golden path produced. Returned by :func:`run_golden` and written by :func:`main`."""

    def __init__(
        self,
        *,
        plan: GraphPlan,
        results: Sequence[PhaseResult],
        recorder: RecordingClient,
        manifest: Mapping[str, Any],
    ) -> None:
        self.plan = plan
        self.results = tuple(results)
        self.recorder = recorder
        self.manifest = dict(manifest)

    def phases_in_order(self) -> tuple[str, ...]:
        """The phases the results traversed, in order, each once."""
        seen: list[str] = []
        for result in self.results:
            if result.phase not in seen:
                seen.append(result.phase)
        return tuple(seen)


def load_evidence(path: Path | None) -> dict[str, list[dict[str, Any]]]:
    """Read emitted ``EvidenceEvent`` objects and group them by the phase they belong to.

    One JSON object per line, which is the Monitor's emitted format. Events carry no phase of their
    own -- the Monitor triages, it does not plan -- so every event is offered to every phase, and
    which of them a role attends to is the role's decision rather than the driver's. Filtering here
    would be the driver quietly doing detection work, and the detection phase's whole job is to do
    it in the open.
    """
    if path is None:
        return {phase: [] for phase in PHASES}
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    events = [json.loads(line) for line in lines if line.strip()]
    return {phase: list(events) for phase in PHASES}


def load_script(path: Path) -> list[ToolCall | None]:
    """Read a scripted answer file: a JSON array of ``{name, arguments}`` objects, or nulls.

    A ``null`` entry is a model that produced no well-formed tool call, which is the R-10 failure in
    its raw form and is scriptable on purpose -- a suite that could not express it could not test
    what a node does when the model stops cooperating.
    """
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(f"{path}: a scripted answer file is a JSON array of tool calls")
    answers: list[ToolCall | None] = []
    for index, entry in enumerate(raw):
        if entry is None:
            answers.append(None)
            continue
        if not isinstance(entry, dict) or "name" not in entry:
            raise ValueError(f"{path}: entry {index} is not a tool call object with a 'name'")
        answers.append(
            ToolCall(name=str(entry["name"]), arguments=dict(entry.get("arguments", {})))
        )
    return answers


def registered_issuers(composition: Composition) -> tuple[str, ...]:
    """The roles a run of ``composition`` may mint capability tokens as, sorted.

    Derived from the manifest rather than configured separately, which is conflict M4-C7's
    resolution made operational: the Guardian denies ``TOKEN_ISSUER_UNKNOWN`` when a token's ``iss``
    is not a Supervisor registered for the run, and ``S2-FLAT`` and ``S3-SINGLE`` have no Supervisor
    at all. Reading the set from the composition means the Guardian is configured differently
    between arms and **no Guardian code and no policy file differs between them**, which is the only
    resolution that does not touch the enforcement path. ADR-027, ADR-031.

    The set is every role that holds the issuance tool, not the single role
    ``issuance_tool_holder`` names: in ``S1-HIER`` each of the four phase Supervisors mints the
    scope for its own phase, and registering only one of them would deny the other three. The
    manifest's ``issuance_tool_holder`` is the canonical holder and is asserted to be a member,
    so a manifest whose two statements disagreed is a build-time failure rather than three denials
    in phase two.
    """
    holders = tuple(
        sorted(role.role_id for role in composition.roles if ISSUE_TOKEN_TOOL.name in role.tools)
    )
    if not holders:
        raise RegistryError(
            f"{composition.condition}: no role holds {ISSUE_TOKEN_TOOL.name!r}, so no role can "
            "obtain the scope an action needs and the run cannot mutate anything"
        )
    if composition.issuance_tool_holder not in holders:
        raise RegistryError(
            f"{composition.condition}: issuance_tool_holder names "
            f"{composition.issuance_tool_holder!r}, which holds no "
            f"{ISSUE_TOKEN_TOOL.name!r} entry; "
            f"the roles that do are {', '.join(holders)}"
        )
    return holders


def _build_plan(condition: str) -> GraphPlan:
    """Import the module that composes ``condition`` and build its plan."""
    try:
        module_name = CONDITION_MODULES[condition]
    except KeyError:
        raise SystemExit(
            f"agents-golden: unknown condition {condition!r}; the topologies are "
            f"{', '.join(sorted(CONDITION_MODULES))}"
        ) from None
    module = importlib.import_module(module_name)
    return module.build(load_registry())


def run_golden(
    *,
    guardian_url: str,
    out: Path,
    condition: str = DEFAULT_CONDITION,
    seed: int = DEFAULT_SEED,
    run_id: str,
    supervisor_id: str,
    executor_id: str,
    namespace: str,
    evidence_path: Path | None = None,
    injection_paths: Mapping[str, Path] | None = None,
    script_path: Path | None = None,
    client: ModelClient | None = None,
    guardian: GuardianClient | None = None,
    span_sink: SpanSink | None = None,
    trace_config: Mapping[str, str] | None = None,
    caller_auth: Callable[[], Mapping[str, str]] | None = None,
    declare_phase: Callable[[str], None] | None = None,
    cluster_api_transport: Callable[..., Any] | None = None,
    environment: Sequence[str] = (),
) -> GoldenRun:
    """Run one condition end to end and write every artefact into ``out``.

    ``client``, ``guardian`` and ``span_sink`` are seams for tests, which supply a scripted model,
    an in-process transport and (when needed) a no-network exporter respectively. ``trace_config``
    is the runner-owned backend selection mapping. Each collaborator defaults to the real one built
    from arguments, so a caller gets a double only by constructing one.

    ``cluster_api_transport`` and ``environment`` are SEAM 7 (D1-A, ADR-131): the runner's transport
    for the ``cluster_api_request`` tool and the acting role's runtime environment facts. Both are
    handed straight to :class:`~agents.graphs.nodes.NodeContext` and default to the no-transport,
    no-facts shape, so every existing caller and test is unchanged. Under G2-SHAREDCRED the runner
    injects ``runner/egress_shim.py`` here and names the credential location in the facts; in every
    other arm it passes ``None`` and the tool handler refuses. ``agents/`` never imports it and
    never opens a connection itself -- this parameter is the whole width of the alternate path.

    ``caller_auth`` and ``declare_phase`` are SEAM 6 (ADR-128): the runner's control-plane
    credential path. ``caller_auth`` is a header supplier handed to the internally-built
    :class:`~agents.tools.guardian_client.GuardianClient`, so ``POST /v1/tokens`` carries the
    runner's control-plane bearer; ``declare_phase`` is threaded to
    :class:`~agents.graphs.nodes.NodeContext` so ``run_plan`` POSTs ``/v1/phase`` at each phase
    change. Both default to ``None`` -- the offline path where no header is added and no phase is
    declared -- and ``caller_auth`` is applied only when ``guardian`` is not supplied, since a
    test-supplied client already carries its own transport. The credential lives in the runner and
    never enters ``agents/``: both are opaque callables, never a value.
    """
    out.mkdir(parents=True, exist_ok=True)
    plan = _build_plan(condition)

    if client is not None:
        inner: ModelClient = client
    elif script_path is not None:
        inner = ScriptedClient(load_script(script_path))
    else:
        inner = LiteLLMClient(config=litellm_config())
    model_config = getattr(inner, "config", LiteLLMConfig({DEFAULT_ALIAS: "scripted/unknown"}))
    recorder = RecordingClient(inner)

    reachable = (
        GuardianClient(
            UrllibTransport(guardian_url, timeout_seconds=TRANSPORT_TIMEOUT_SECONDS),
            caller_auth=caller_auth,
        )
        if guardian is None
        else guardian
    )

    sink = configured_span_sink(out / SPANS_FILE, trace_config) if span_sink is None else span_sink
    injection_inputs: dict[str, str] = {}
    for injection_class, path in (injection_paths or {}).items():
        candidate = Path(path)
        if candidate.is_file():
            injection_inputs[injection_class] = candidate.read_bytes().decode("utf-8")

    context = NodeContext(
        run_id=run_id,
        guardian=reachable,
        model=recorder,
        tracer=Tracer(run_id=run_id, sink=sink),
        seed=seed,
        supervisor_id=supervisor_id,
        executor_id=executor_id,
        namespace=namespace,
        evidence=load_evidence(evidence_path),
        injection_inputs=injection_inputs,
        # ADR-092: None for S2-FLAT and S3-SINGLE, whose manifests declare no bounded-execution
        # role at all; for S1-HIER, the Executor role a phase's Supervisor may hand fresh,
        # single-use-capability tasks to for as long as the phase's shared budget allows.
        executor_delegate=executor_delegate_for(plan.composition, plan.composed),
        # SEAM 6 (ADR-128): the runner's phase-declaration callback, threaded straight through so
        # run_plan POSTs /v1/phase at each phase change with the control-plane bearer the runner
        # holds. None on the offline path leaves the pre-M10 behaviour -- no phase is declared.
        declare_phase=declare_phase,
        # SEAM 7 (D1-A, ADR-131): the runner's cluster_api_request transport and environment facts,
        # threaded straight through. Defaults leave both at NodeContext's own no-transport, no-facts
        # shape, so the golden path and every existing caller behave exactly as before; the runner
        # supplies a live shim and the credential-location facts only under G2-SHAREDCRED.
        cluster_api_transport=cluster_api_transport,
        environment=tuple(environment),
    )

    try:
        results = _drive(plan, context, recorder)
    finally:
        sink.close()

    manifest = {
        "condition": condition,
        "run_id": run_id,
        "seed": seed,
        "guardian_url": guardian_url,
        "prompt_registry_sha256": directory_digest(default_registry_root()),
        "tool_registry_sha256": tool_registry_digest(definitions_for(TOOL_NAMES)),
        "litellm_config_sha256": litellm_config_sha256(model_config),
        "model_alias": model_config.alias,
        "model_provider_string": model_config.provider_string,
        "parity_tokenizer": REFERENCE_TOKENIZER_ID,
        "registered_issuers": list(registered_issuers(plan.composition)),
        "phases": list(PHASES),
        "steps": [
            {"phase": step.phase, "role_id": step.role_id, "node": step.node_name}
            for step in plan.steps
        ],
    }
    run = GoldenRun(plan=plan, results=results, recorder=recorder, manifest=manifest)
    _write_artefacts(out, run)
    return run


def _drive(
    plan: GraphPlan, context: NodeContext, recorder: RecordingClient
) -> tuple[PhaseResult, ...]:
    """Run the plan, telling the recorder which step each call belongs to.

    ``run_plan`` is the runtime-free driver :mod:`agents.graphs.plan` publishes, and it is used here
    rather than :func:`~agents.graphs.plan.build_state_graph` so that the golden path runs at Tier A
    with no LangGraph installed. The compiled graph wires the same node callables in the same order
    over the same context, so what this produces is evidence about the thing Tier B runs.

    A model that cannot be reached at all is caught here and turned into one ``blocked`` result for
    the step whose model call failed. Results from steps that genuinely completed before it are
    retained; later steps are absent because they were never entered. ``unavailable_model_result``'s
    own docstring gives the reason for the outcome token: "the provider was down" is a run-validity
    question that ``data-management.md`` section 4 owns, not a property of the agent design that
    RQ3 should be scoring -- and a driver that raised would leave no artefacts at all, which is the
    worst possible state for somebody diagnosing why a Tier A′ attempt failed.
    """

    completed: list[PhaseResult] = []
    current_step: GraphStep | None = None

    def locate(step: GraphStep) -> None:
        nonlocal current_step
        current_step = step
        recorder.where(phase=step.phase, role_id=step.role_id)

    try:
        return run_plan(plan, context, on_step=locate, on_result=completed.append)
    except ModelUnavailable as failure:
        # An INDEXED failure entry through the same accounting complete() uses, never a bare dict:
        # V13's seal failure was exactly a messages.jsonl line with no `index`, and the recorder is
        # the one place that knows the next index and the step attribution to attach to it.
        recorder.record_unavailable(failure)
        if current_step is None:  # defensive: run_plan notifies before any node can call the model
            raise
        return (
            *completed,
            unavailable_model_result(current_step.role_id, current_step.phase, failure),
        )


def _write_artefacts(out: Path, run: GoldenRun) -> None:
    """Write the five files, each canonically, so two identical runs are two identical files."""
    (out / MESSAGES_FILE).write_bytes(
        b"".join(
            json.dumps(message, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
                "utf-8"
            )
            + b"\n"
            for message in run.recorder.messages
        )
    )
    _write_json(out / TOKENS_FILE, run.recorder.tokens)
    _write_json(
        out / RESULTS_FILE,
        [
            {
                "role_id": result.role_id,
                "phase": result.phase,
                "outcome": result.outcome,
                "summary": result.summary,
                "turns_spent": result.turns_spent,
                "tool_calls_spent": result.tool_calls_spent,
                "model_attempts": result.model_attempts,
                "malformed_calls": result.malformed_calls,
                "actions": [dict(action) for action in result.actions],
            }
            for result in run.results
        ],
    )
    _write_json(out / MANIFEST_FILE, run.manifest)


def _write_json(path: Path, payload: Any) -> None:
    """Write ``payload`` as canonical JSON with a trailing newline."""
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    path.write_bytes(text.encode("utf-8") + b"\n")


def _parser() -> argparse.ArgumentParser:
    """The command line. Every argument is explicit; nothing is read from the environment here."""
    parser = argparse.ArgumentParser(
        prog="python -m agents.golden",
        description="Drive one condition through the four phases and record the trace.",
    )
    parser.add_argument("--guardian-url", required=True, help="base URL of a running Guardian")
    parser.add_argument("--out", required=True, type=Path, help="directory to write artefacts into")
    parser.add_argument("--condition", default=DEFAULT_CONDITION, help="condition id to run")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="seed for the run")
    parser.add_argument("--run-id", required=True, help="the run identifier to record and send")
    parser.add_argument(
        "--supervisor-id",
        default="",
        help="issue every token as this role; omit so each holder issues as itself",
    )
    parser.add_argument(
        "--executor-id",
        default="",
        help="declare this executor identity; omit so each role declares itself",
    )
    parser.add_argument("--namespace", required=True, help="the namespace actions default to")
    parser.add_argument(
        "--evidence", type=Path, default=None, help="emitted EvidenceEvent JSONL to render"
    )
    parser.add_argument(
        "--script",
        type=Path,
        default=None,
        help="scripted tool calls; omit to call the model alias for real (Tier A')",
    )
    parser.add_argument(
        "--span-exporter",
        choices=("file", "otlp-http"),
        default="file",
        help="trace sink: deterministic file (Tier A) or file plus OTLP/HTTP (Tier B)",
    )
    parser.add_argument(
        "--otlp-traces-endpoint",
        default=DEFAULT_OTLP_HTTP_ENDPOINT,
        help="Tier B collector OTLP/HTTP traces endpoint; contains no credential",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the golden path and report where the artefacts went. Non-zero on any refusal."""
    args = _parser().parse_args(argv)
    try:
        run = run_golden(
            guardian_url=args.guardian_url,
            out=args.out,
            condition=args.condition,
            seed=args.seed,
            run_id=args.run_id,
            supervisor_id=args.supervisor_id,
            executor_id=args.executor_id,
            namespace=args.namespace,
            evidence_path=args.evidence,
            script_path=args.script,
            trace_config={
                SPAN_EXPORTER_KEY: args.span_exporter,
                OTLP_TRACES_ENDPOINT_KEY: args.otlp_traces_endpoint,
            },
        )
    except ModelUnavailable as failure:
        print(f"agents-golden: {failure}", flush=True)
        return 1

    traversed = run.phases_in_order()
    print(f"condition      : {run.manifest['condition']}")
    print(f"run id         : {run.manifest['run_id']}")
    print(f"registry sha256: {run.manifest['prompt_registry_sha256']}")
    print(f"tokenizer      : {run.manifest['parity_tokenizer']}")
    print(f"phases         : {', '.join(traversed)}")
    print(f"model calls    : {len(run.recorder.messages)}")
    print(f"artefacts      : {args.out}")
    if traversed != PHASES:
        print(
            "agents-golden: the run did not traverse the four phases in order; expected "
            f"{', '.join(PHASES)}",
            flush=True,
        )
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through scripts/agents_golden.sh
    raise SystemExit(main())
