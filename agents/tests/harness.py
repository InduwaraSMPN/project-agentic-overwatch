r"""What every agent-layer test is given: a real Guardian, a scripted model, and a span sink.

WHAT THIS MODULE IS FOR
-----------------------
Tier A of ``docs/plans/M4-implementation-plan.md`` is defined as "no network, no Docker, no
credential, no token spent", and this module is what makes that description honest rather than
aspirational. Everything below either builds a **real** collaborator that happens to need nothing
outside the process, or a double that answers what the test said and decides nothing.

Two of those distinctions carry the whole weight and are worth stating before the code:

*The Guardian is the real Guardian.* :func:`build_in_process_guardian` calls
:func:`guardian.app.composition.build_guardian` -- the production composition root, the same
function ``python -m guardian.app`` reaches -- and drives its ASGI application directly. The
mediation pipeline, the token verifier, the replay cache, the audit chain and the contract models
are all the shipped ones. What is substituted is the *policy engine*, because a real one shells out
to an ``opa`` binary that the offline tier must not require, and the *executor*, because the
alternative touches a cluster. Both substitutions are named seams
:func:`~guardian.app.composition.build_guardian` publishes for exactly this purpose.

*The model is a script, and it never reads the prompt.* ``guardian/app/policy.py`` states the rule
these doubles obey and :class:`agents.registry.model.ScriptedClient` quotes it: a double that chose
its answer by inspecting its input is a second, much worse implementation of the thing under test,
and the suite would then be measuring the double. So the answers are fixed by the test, consumed in
order, and the client records what it was handed so that a test can assert over the bytes that were
sent.

WHY THIS DUPLICATES A LITTLE OF ``guardian/tests/harness.py``
---------------------------------------------------------------
It duplicates the configuration mapping and the ASGI driver, and it does so because it cannot
import them. ``guardian/tests/`` carries no ``__init__.py`` -- its own ``conftest.py`` explains at
length why adding one would break ``monitor/tests`` collection -- so it is not an importable
package from here.

That is the smaller half of the reason. The larger half is that the agent layer ships as its own
container and must not acquire a build-time dependency on the Guardian's *test* suite; a change
made for a Guardian case would then be able to break an agent case for reasons no reader of either
file could see. ADR-022's precedent applies and is applied with its cost stated rather than hidden:
a copy is legal when a test makes "copy" mean "copy that cannot drift", and
``agents/tests/test_guardian_seam.py`` is that test -- it asserts the configuration keys this module
builds are exactly the keys :class:`guardian.app.config.GuardianConfig` requires, so a key added
there and not here fails here rather than silently configuring a weaker Guardian.

WHAT IS DELIBERATELY NOT HERE
------------------------------
*A credential.* Nothing in this module reads ``os.environ``, and the signing material below is a
synthetic string written in this file. ``.agents/rules/10-guardian-first.md`` forbids copying the
Guardian's real signing key anywhere, tests included, and a suite that needed one could not run on
a fresh clone.

*A decision procedure.* :class:`ScriptedPolicyEngine` returns what it was constructed with. What
the real policy decides is ``opa test``'s to check, through ``make guardian-test``.

*An arm.* No test builds a :class:`~agents.graphs.nodes.NodeContext` carrying a condition, a mode
or a quoting flag, because no such field exists -- ADR-023 keeps every condition flag in the
runner's hands. ``agents/tests/test_flag_exercise.py`` reaches the arms the only way the agent
layer ever will: by starting the Guardian differently and by handing the renderer differently
quoted evidence.
"""

from __future__ import annotations

import asyncio
import itertools
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from agents.graphs.nodes import NodeContext
from agents.registry.model import ModelCall, ModelResponse, ScriptedClient, ToolCall
from agents.registry.tracing import FileSpanSink, SpanSink, Tracer
from agents.tools.guardian_client import TOKENS_PATH, GuardianClient
from guardian.app.composition import AssembledGuardian, build_guardian
from guardian.app.config import GuardianConfig
from guardian.app.models import GuardianMode
from guardian.audit.record_types import is_execution, is_run_start

__all__ = (
    "ALGORITHM",
    "EXECUTOR_ID",
    "InProcessGuardian",
    "NAMESPACE",
    "RUN_ID",
    "RetryingClient",
    "SUPERVISOR_ID",
    "SUITE_EPOCH_SECONDS",
    "ScriptedPolicyEngine",
    "SuiteClock",
    "SYNTHETIC_SIGNING_MATERIAL",
    "asgi_transport",
    "build_in_process_guardian",
    "control_plane_transport",
    "counting_jti_factory",
    "deny_default_result",
    "guardian_environment",
    "node_context",
    "permit_result",
    "recorded_spans",
    "write_stand_in_bundle",
)

REPO_ROOT: Final = Path(__file__).resolve().parents[2]

# --------------------------------------------------------------------------------------------
# Suite parameters. NOT protocol values -- see the note.
# --------------------------------------------------------------------------------------------
#
# Every number below is a test parameter chosen to make a case deterministic and small, and none of
# them is a value docs/protocols/ owns. `.agents/rules/00-source-of-truth.md` fixes exactly one
# home for a quantitative parameter, so restating a protocol number here would create a second;
# what these are instead is the same category as guardian/tests/harness.py's SUITE_* constants,
# which carries the identical note for the identical reason.

SUITE_EPOCH_SECONDS: Final = 1_800_000_000
SUITE_TOKEN_LIFETIME_SECONDS: Final = 60
SUITE_TOKEN_MAX_LIFETIME_SECONDS: Final = 300
SUITE_REPLAY_CACHE_ENTRIES: Final = 64
SUITE_REPLAY_CACHE_WINDOW_SECONDS: Final = 120
SUITE_POLICY_TIMEOUT_SECONDS: Final = 5.0

# HS256 with synthetic material written in this file. `security-policy.md` section 2 owns the
# algorithm the campaign runs; this is the value the Guardian's own suite uses for the same reason,
# and the material is a literal precisely so that no real key is ever near a test.
ALGORITHM: Final = "HS256"
# noqa: S105 below -- ruff reads any string bound to a *_MATERIAL name as a possible credential,
# which is the check working: the value is a literal in a test file precisely so that no real key
# is ever near one, and the rule cannot tell those two cases apart.
#
# THE LENGTH IS LOAD-BEARING. PyJWT refuses an HS256 key shorter than the algorithm's minimum and
# the issuer answers `issue_signing_key_unavailable` rather than signing weakly, so a shortened
# literal here fails every mint in the suite with an operational error that looks like a policy
# refusal. It is padded to be comfortably over the bound rather than exactly at it.
SYNTHETIC_SIGNING_MATERIAL: Final = (  # noqa: S105
    "agents-suite-synthetic-signing-material-not-a-real-credential"
)

# The identifiers a Tier A run uses. RUN_ID is `docs/07-glossary-and-ids.md`'s run-id form, and
# SUPERVISOR_ID is a role id that appears in agents/prompts/compositions/S1-HIER.yaml -- the same
# string the manifest names as that condition's issuance_tool_holder, so a token minted in a test
# is minted by an issuer a real S1-HIER run would register.
RUN_ID: Final = "RUN-G0-FULL-SCN01-INJA-S07"
SUPERVISOR_ID: Final = "supervisor-containment"
EXECUTOR_ID: Final = "executor-containment-01"
NAMESPACE: Final = "boutique"

# The entrypoints guardian/policies/ declares. Spelled here as the Rego packages spell them so that
# the value a test sets and the value a deployment sets are the same string.
POLICY_ENTRYPOINT: Final = "data.guardian.decision"
ISSUANCE_ENTRYPOINT: Final = "data.guardian.issuance.decision"

# The control-plane credential the Guardian authenticates `/v1/tokens` and `/v1/phase` against
# (ADR-128, WS-4). GuardianConfig requires both with no default, because an unauthenticated mint is
# the defect V17 recorded; a suite that builds a Guardian therefore has to state the pair it
# authenticates as. Spelled with the same strings guardian/tests/harness.py uses, so the value a
# test
# sets and the value a deployment sets are the same string. These are *test* values for an
# in-process Guardian: the real control-plane bearer is minted per run by the runner and never
# appears in this repository.
CONTROL_PLANE_SUBJECT: Final = "system:serviceaccount:guardian:runner-control-plane"
CONTROL_PLANE_AUDIENCE: Final = "guardian-control-plane"

# The synthetic control-plane bearer this suite's clients carry on POST /v1/tokens. It stands in for
# the ServiceAccount token the runner presents in a campaign; the value authenticates against
# nothing
# real -- _AcceptingControlPlaneAuthenticator below is what accepts it, and it is written here for
# the
# same reason SYNTHETIC_SIGNING_MATERIAL is: a literal in a test file precisely so that no real
# credential is ever near one. It rides in at the transport layer (`control_plane_transport`) rather
# than through the client's `caller_auth` supplier, so `GuardianClient.caller_auth` stays None on
# this
# suite's client -- which is what agents/tests/test_executor_lifecycle.py asserts, and what
# distinguishes "the suite injected a credential" (it did not) from "the runner's egress carries the
# bearer the Guardian's HTTPBearer dependency requires" (it does). See build_in_process_guardian.
SYNTHETIC_CONTROL_PLANE_BEARER: Final = (  # noqa: S105 - a literal test value, not a real credential
    "agents-suite-synthetic-control-plane-bearer-not-a-real-credential"
)

# Rule ids the scripted engines answer with. They are labels for a canned answer and are not read
# by any policy; the shipped bundle's real rule ids are `opa test`'s business.
PERMIT_RULE_ID: Final = "guardian:permit:agents-suite"
ISSUANCE_PERMIT_RULE_ID: Final = "guardian:issue:within-declared-authority"

# The stand-in bundle's only content, for the same reason guardian/tests/harness.py writes one:
# PolicyBundle.load refuses a directory with no .rego in it, on the ground that an empty bundle
# denies everything while looking configured. It declares a package and no rule, so nothing here
# decides anything even if an engine ever loaded it -- and no engine does, because both are
# scripted.
STAND_IN_BUNDLE_REGO: Final = (
    "# Not a policy. See agents/tests/harness.py: this file exists so PolicyBundle.load has bytes\n"
    "# to digest in a suite whose policy engines are both scripted doubles. It declares a package\n"
    "# and no rule, so nothing here decides anything even if an engine ever loaded it.\n"
    "package agents_tests_stand_in\n"
)


class SuiteClock:
    """One clock read by the token service, the replay cache and the audit record's ``ts``.

    A single clock rather than three, so that "the token expired" and "the cache window elapsed"
    are statements about one timeline. Rule 20's determinism applied to a test suite: nothing in
    this package reads the wall clock.
    """

    def __init__(self, epoch_seconds: int = SUITE_EPOCH_SECONDS) -> None:
        self._epoch = epoch_seconds

    def epoch(self) -> int:
        """Epoch seconds as an integer, the shape the token modules require."""
        return self._epoch

    def instant(self) -> Any:
        """The same moment as an aware UTC datetime, the shape ``AuditRecord.ts`` requires."""
        from datetime import UTC, datetime

        return datetime.fromtimestamp(self._epoch, tz=UTC)

    def advance(self, seconds: int) -> None:
        """Move the timeline forward. Never backwards: nothing in the Guardian expects that."""
        if seconds < 0:
            raise ValueError("the suite clock only moves forward")
        self._epoch += seconds


class ScriptedPolicyEngine:
    """Returns the answer the test fixed, and records every input document it was handed.

    It does not read the document to choose the answer. ``guardian/app/policy.py`` refuses to
    implement a decision procedure in Python "for the tests", because a second policy diverges from
    the Rego and nobody notices until an evaluation depends on it; what ``seen`` is for is the
    other half -- asserting directly which fields did and did not reach the engine.
    """

    def __init__(self, result: Any = None) -> None:
        self.result: Any = permit_result() if result is None else result
        self.seen: list[Mapping[str, Any]] = []

    def evaluate(self, document: Mapping[str, Any], *, timeout_seconds: float) -> Any:
        """Record the document, ignore the bound, and answer what the test said to answer."""
        del timeout_seconds
        self.seen.append(json.loads(json.dumps(document, default=str)))
        return self.result


def permit_result(rule_id: str = PERMIT_RULE_ID) -> dict[str, Any]:
    """The engine result shape the Guardian treats as a permit."""
    return {"allow": True, "rule_id": rule_id}


def deny_default_result() -> dict[str, Any]:
    """The engine result shape for "no explicit permit rule matched" -- deny-by-default."""
    return {"allow": False}


class RetryingClient:
    """A model double whose first ``retries`` attempts are malformed, reported as one response.

    Exists for one assertion and no other: ADR-028 makes a retry a turn, so a call that took three
    attempts must cost three. :class:`~agents.registry.model.ScriptedClient` reports a fixed
    ``attempts`` for every answer, which is the wrong shape for a test that needs the first call to
    be expensive and the rest cheap.

    It ignores :attr:`~agents.registry.model.ModelCall.max_attempts` on purpose. ADR-060 has the
    real client stop at the turns a node has left, so the ledger's overspend path is no longer
    reached through it; that path is still the backstop for any client that reports more attempts
    than it was allowed, and this double is what keeps it tested.
    """

    def __init__(
        self,
        answers: Sequence[ToolCall | None],
        *,
        attempts: Sequence[int],
        provider_string: str = "scripted/retrying",
    ) -> None:
        self._answers = list(answers)
        self._attempts = list(attempts)
        self._provider_string = provider_string
        self.calls: list[ModelCall] = []

    def complete(self, call: ModelCall) -> ModelResponse:
        """Record the call and return the next scripted answer at its scripted cost."""
        self.calls.append(call)
        answer = self._answers.pop(0) if self._answers else None
        attempts = self._attempts.pop(0) if self._attempts else 1
        return ModelResponse(
            tool_call=answer,
            provider_string=self._provider_string,
            attempts=attempts,
            malformed_attempts=tuple(f"attempt-{index}" for index in range(1, attempts)),
        )


# --------------------------------------------------------------------------------------------
# Driving the ASGI application without httpx
# --------------------------------------------------------------------------------------------


def asgi_transport(app: Any) -> Any:
    """Return a :data:`~agents.tools.guardian_client.Transport` that drives ``app`` in-process.

    ``fastapi.testclient.TestClient`` needs httpx, which is not in the pinned runtime set and is
    not being added for a test convenience -- ``monitor/tests/__init__.py`` states the rule and
    ``guardian/tests/harness.py`` follows it for the same reason. The ASGI interface is a
    documented contract, driving it directly exercises exactly the same route handlers, and the
    resulting transport is interchangeable with
    :class:`~agents.tools.guardian_client.UrllibTransport` at Tier B because the client's
    ``Transport`` type is three positional arguments and no configuration.
    """

    def transport(
        method: str, path: str, body: bytes, extra_headers: Mapping[str, str] | None = None
    ) -> tuple[int, Any]:
        headers: list[tuple[bytes, bytes]] = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
        ]
        # SEAM 6: the client attaches the runner's caller-auth header on the control-plane route.
        # Mirrored here so a Tier A test can drive an authenticated mint against the in-process app;
        # the header names carry through as lowercased ASCII, the ASGI convention.
        for name, value in (extra_headers or {}).items():
            headers.append((name.lower().encode("ascii"), value.encode("ascii")))
        scope: dict[str, Any] = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": method,
            "path": path,
            "raw_path": path.encode("ascii"),
            "root_path": "",
            "scheme": "http",
            "query_string": b"",
            "headers": headers,
            "client": ("10.0.0.9", 51234),
            "server": ("guardian", 8080),
        }
        messages: list[Mapping[str, Any]] = []

        async def receive() -> Mapping[str, Any]:
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message: Mapping[str, Any]) -> None:
            messages.append(message)

        async def drive() -> None:
            await app(scope, receive, send)

        asyncio.run(drive())

        starts = [message for message in messages if message["type"] == "http.response.start"]
        if not starts:
            raise AssertionError(f"the application sent no response to {method} {path}")
        payload = b"".join(
            bytes(message.get("body", b""))
            for message in messages
            if message["type"] == "http.response.body"
        )
        decoded: Any = None
        if payload:
            try:
                decoded = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                decoded = None
        return int(starts[0]["status"]), decoded

    return transport


# --------------------------------------------------------------------------------------------
# The control-plane authentication seam (SEAM 6, ADR-128)
# --------------------------------------------------------------------------------------------


class _AcceptingControlPlaneAuthenticator:
    """A permissive ``ControlPlaneVerifier`` for the offline agent suite: any non-empty bearer.

    ``guardian/app/control_auth.py`` publishes the ``ControlPlaneVerifier`` protocol precisely so a
    suite with no cluster can supply a double for the TokenReview the real one performs. The
    Guardian
    guards ``POST /v1/tokens`` and ``POST /v1/phase`` with an ``HTTPBearer`` dependency and answers
    401 without a verified caller, so a Guardian assembled with no authenticator refuses every mint
    --
    which is what left the M10 seam's first landing red.

    This one differs from ``guardian/tests/harness.py``'s ``FakeControlPlaneAuthenticator`` on
    purpose,
    and the purpose is the split of ownership the plan draws. That double accepts *one* synthetic
    string and refuses every other, because the Guardian suite's whole subject is the enforcement --
    a fake that accepted anything would make its 401 cases vacuous. This suite tests the agent layer
    *above* an authenticated Guardian and never the 401 itself
    (``guardian/tests/test_control_auth.py``
    owns that, WS-4), so it accepts any bearer that arrived: the point is that a mint reaches
    issuance,
    not which string got it there. It still refuses a non-string, so the protocol's shape is
    honoured
    rather than bypassed. ``agents/tests/test_guardian_seam.py`` names this "the in-process assembly
    leaves the control-plane verifier optional".
    """

    def authenticate(self, bearer: object) -> bool:
        """Accept any non-empty bearer string; refuse a non-string or an empty one."""
        return isinstance(bearer, str) and bool(bearer)


def control_plane_transport(inner: Any) -> Any:
    """Wrap ``inner`` so control-plane requests carry the suite's synthetic bearer (SEAM 6).

    The header is attached here, at the transport, rather than through
    :class:`~agents.tools.guardian_client.GuardianClient`'s ``caller_auth`` supplier, and the choice
    is the one ``agents/tests/test_executor_lifecycle.py`` pins: this suite's client must report
    ``caller_auth is None`` -- "the suite injects none" -- while every mint it makes still reaches
    an
    authenticated Guardian. In a campaign the runner injects the ``caller_auth`` supplier and its
    egress carries the ServiceAccount token to the Guardian's socket; the in-process analogue of
    "the
    egress carries the bearer" is a transport that adds it, and it adds it to exactly the one route
    the
    client speaks that the Guardian guards -- ``POST /v1/tokens`` -- leaving ``POST /v1/actions``
    the
    unauthenticated body path it is, so a client built over this transport sends the actions route
    the
    same bytes it always did.

    A caller-supplied ``extra_headers`` mapping wins over the injected one (``setdefault``), so a
    case
    that drives its own authenticated client through a wrapper of this transport still sees its own
    header -- the injection is a floor, not an override.
    """

    def transport(
        method: str, path: str, body: bytes, extra_headers: Mapping[str, str] | None = None
    ) -> tuple[int, Any]:
        headers = dict(extra_headers or {})
        if path == TOKENS_PATH:
            headers.setdefault("Authorization", f"Bearer {SYNTHETIC_CONTROL_PLANE_BEARER}")
        return inner(method, path, body, headers or None)

    return transport


# --------------------------------------------------------------------------------------------
# The in-process Guardian
# --------------------------------------------------------------------------------------------


def guardian_environment(
    *,
    mode: GuardianMode,
    bundle_path: Path,
    audit_log_path: Path,
    run_id: str | None = RUN_ID,
    registered_issuers: Sequence[str] = (SUPERVISOR_ID,),
    signing_material: str = SYNTHETIC_SIGNING_MATERIAL,
) -> dict[str, str]:
    """The runner-supplied start-time keys, as a mapping ``GuardianConfig.from_mapping`` accepts.

    Built as a plain dictionary and never written into ``os.environ``: configuration is the only
    route by which an arm reaches the Guardian process, and a suite that mutated the real
    environment would leak one test's arm into the next.

    ``GUARDIAN_EXECUTOR`` is ``fake``, stated rather than assumed. ``ExecutorKind`` has no default,
    so choosing the fake is an explicit act, and writing it here is what makes every Guardian this
    suite builds one that touches nothing.
    """
    environment = {
        "GUARDIAN_MODE": mode.value,
        "GUARDIAN_REGISTERED_ISSUERS": ",".join(registered_issuers),
        "GUARDIAN_SIGNING_KEY": signing_material,
        "GUARDIAN_TOKEN_TTL_SECONDS": str(SUITE_TOKEN_LIFETIME_SECONDS),
        "GUARDIAN_TOKEN_MAX_TTL_SECONDS": str(SUITE_TOKEN_MAX_LIFETIME_SECONDS),
        "GUARDIAN_TOKEN_ALGORITHM": ALGORITHM,
        "GUARDIAN_REPLAY_CACHE_ENTRIES": str(SUITE_REPLAY_CACHE_ENTRIES),
        "GUARDIAN_REPLAY_CACHE_WINDOW_SECONDS": str(SUITE_REPLAY_CACHE_WINDOW_SECONDS),
        "GUARDIAN_REPLAY_STORE_PATH": str(audit_log_path.with_name("guardian_replay.sqlite3")),
        "GUARDIAN_POLICY_BUNDLE_PATH": str(bundle_path),
        "GUARDIAN_POLICY_ENTRYPOINT": POLICY_ENTRYPOINT,
        "GUARDIAN_ISSUANCE_ENTRYPOINT": ISSUANCE_ENTRYPOINT,
        "GUARDIAN_POLICY_TIMEOUT_SECONDS": str(SUITE_POLICY_TIMEOUT_SECONDS),
        "GUARDIAN_AUDIT_LOG_PATH": str(audit_log_path),
        "GUARDIAN_EXECUTOR": "fake",
        "GUARDIAN_CONTROL_PLANE_SUBJECT": CONTROL_PLANE_SUBJECT,
        "GUARDIAN_CONTROL_PLANE_AUDIENCE": CONTROL_PLANE_AUDIENCE,
    }
    if run_id is not None:
        environment["GUARDIAN_RUN_ID"] = run_id
    return environment


def write_stand_in_bundle(path: Path, *, content: str = STAND_IN_BUNDLE_REGO) -> Path:
    """Write the stand-in bundle at ``path`` and return it, creating parents as needed."""
    path.mkdir(parents=True, exist_ok=True)
    (path / "stand_in.rego").write_bytes(content.encode("utf-8"))
    return path


@dataclass
class InProcessGuardian:
    """One assembled Guardian, plus the agent-side client that speaks to it.

    ``client`` is the shipped :class:`~agents.tools.guardian_client.GuardianClient`, constructed
    over an ASGI transport rather than a socket. Nothing about the client differs between the tiers,
    which is what makes a Tier A pass evidence about the thing Tier B runs.
    """

    assembled: AssembledGuardian
    client: GuardianClient
    config: GuardianConfig
    clock: SuiteClock
    audit_log_path: Path
    engine: ScriptedPolicyEngine
    issuance_engine: ScriptedPolicyEngine

    def audit_records(self) -> tuple[Mapping[str, Any], ...]:
        """Every decision record written so far, decoded, in order.

        Read from the file rather than from an in-memory list, because the file is what
        ``make audit-verify`` reads and what ``security-policy.md`` section 1.4 requires to exist.
        A test that asserted over a list would be asserting over the wrong artefact.

        The chain's run-start genesis is left out. ADR-058 makes the Guardian open every per-run
        chain with one ``record_type: "run-start"`` record at ``seq`` 0, and that record is not a
        decision: no agent attempted it and no policy ruled on it. Every count this suite takes is
        a count of decisions, so the record is excluded with
        :func:`guardian.audit.record_types.is_run_start` -- the one spelling ADR-058 gives every
        consumer -- rather than by position or by a field this file would have to know about. The
        file itself is untouched, so a test that verifies the chain still reads all of it.

        ADR-082's execution follow-up records are excluded for the same reason: after every decision
        the Guardian appends one ``record_type: "execution"`` record carrying that decision's
        outcome, so that ``seq`` numbering is identical across arms (a conditional write would let
        an arm change chain position, which ADR-023's isolation proof forbids). It is not itself a
        decision and carries no ``reason_code``; a count or a ``records[-1]`` that included it would
        see two rows per attempted action and a last row with no decision fields. Excluded with
        :func:`~guardian.audit.record_types.is_execution`, the one spelling ADR-082 gives.
        """
        if not self.audit_log_path.exists():
            return ()
        lines = self.audit_log_path.read_text(encoding="utf-8").splitlines()
        decoded = (json.loads(line) for line in lines if line.strip())
        return tuple(
            record for record in decoded if not is_run_start(record) and not is_execution(record)
        )

    def mint(
        self,
        *,
        supervisor_id: str = SUPERVISOR_ID,
        executor_id: str = EXECUTOR_ID,
        phase: str = "containment",
        verbs: tuple[str, ...] = ("get", "list"),
        resources: tuple[str, ...] = ("pods",),
        namespaces: tuple[str, ...] = (NAMESPACE,),
        ttl_seconds: int | None = None,
    ) -> Any:
        """Mint one capability token through the real issuance route. Returns the body or refusal.

        Through ``POST /v1/tokens`` rather than by calling the issuer directly, because the route
        is where the authority bound lives since M4-T4.0d and a test that bypassed it would prove
        nothing about ADR-031.
        """
        return self.client.issue_capability_token(
            supervisor_id=supervisor_id,
            executor_id=executor_id,
            run_id=self.config.run_id,
            phase=phase,
            verbs=verbs,
            resources=resources,
            namespaces=namespaces,
            ttl_seconds=ttl_seconds,
        )


def counting_jti_factory(prefix: str = "jti-agents-suite-") -> Callable[[], str]:
    """A deterministic ``jti`` source: the same sequence for every Guardian built with one.

    Needed by the arm comparison and by nothing else. A minted token's ``jti`` is random by design,
    so two Guardians started in two arms mint two different identifiers for the same action -- and
    a field-by-field diff of their audit records would then report ``token_jti`` as an arm
    difference, which it is not. ``guardian/tests/harness.py`` solves the same problem the same way,
    and the seam is one :func:`~guardian.app.composition.build_guardian` publishes for exactly this.
    """
    counter = itertools.count(1)
    return lambda: f"{prefix}{next(counter):04d}"


def build_in_process_guardian(
    root: Path,
    *,
    mode: GuardianMode = GuardianMode.G0_FULL,
    engine: ScriptedPolicyEngine | None = None,
    issuance_engine: ScriptedPolicyEngine | None = None,
    registered_issuers: Sequence[str] = (SUPERVISOR_ID,),
    run_id: str | None = RUN_ID,
    jti_factory: Callable[[], str] | None = None,
) -> InProcessGuardian:
    """Assemble a Guardian under ``root`` and return it with a client already pointed at it.

    The assembly is :func:`guardian.app.composition.build_guardian`'s, not this function's. What is
    supplied here is a configuration mapping a runner would supply and four of the seams that
    function
    publishes -- the two engines, the clock and (ADR-128) a permissive control-plane authenticator
    --
    each of whose real default is a collaborator this offline suite cannot build: the engines shell
    out
    to ``opa``, and the authenticator's default performs a TokenReview against a cluster. Everything
    not
    named below is what a deployed Guardian gets.
    """
    clock = SuiteClock()
    audit_log_path = root / "guardian_audit.jsonl"
    bundle_path = write_stand_in_bundle(root / "policies")
    action_engine = ScriptedPolicyEngine() if engine is None else engine
    authority_engine = (
        ScriptedPolicyEngine(permit_result(ISSUANCE_PERMIT_RULE_ID))
        if issuance_engine is None
        else issuance_engine
    )
    config = GuardianConfig.from_mapping(
        guardian_environment(
            mode=mode,
            bundle_path=bundle_path,
            audit_log_path=audit_log_path,
            run_id=run_id,
            registered_issuers=registered_issuers,
        )
    )
    assembled = build_guardian(
        config,
        policy_engine=action_engine,
        issuance_engine=authority_engine,
        clock=clock,
        jti_factory=jti_factory,
        # ADR-128: the real default is a TokenReview against a cluster this suite does not have,
        # which
        # would refuse every mint 401. A permissive double keeps the surface authenticated (the mint
        # still reaches issuance through the HTTPBearer dependency) while accepting the synthetic
        # bearer `control_plane_transport` attaches below. Enforcement of *who* is calling is
        # guardian/tests/test_control_auth.py's, not this suite's.
        control_plane_authenticator=_AcceptingControlPlaneAuthenticator(),
    )
    return InProcessGuardian(
        assembled=assembled,
        # The client's transport carries the control-plane bearer on POST /v1/tokens, so its mints
        # authenticate, while the client's own `caller_auth` supplier stays None -- the split
        # test_executor_lifecycle.py asserts. See `control_plane_transport`.
        client=GuardianClient(control_plane_transport(asgi_transport(assembled.app))),
        config=config,
        clock=clock,
        audit_log_path=audit_log_path,
        engine=action_engine,
        issuance_engine=authority_engine,
    )


# --------------------------------------------------------------------------------------------
# The agent side
# --------------------------------------------------------------------------------------------


def node_context(
    guardian: InProcessGuardian,
    *,
    answers: Sequence[ToolCall | None] = (),
    model: Any | None = None,
    sink: SpanSink | None = None,
    evidence: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
    seed: int | None = 7,
    supervisor_id: str = SUPERVISOR_ID,
    executor_id: str = EXECUTOR_ID,
    plan: Any | None = None,
    environment: Sequence[str] = (),
    cluster_api_transport: Callable[..., Any] | None = None,
    declare_phase: Callable[[str], None] | None = None,
) -> NodeContext:
    """Build the context a node runs against, wired to ``guardian`` and a scripted model.

    ``seed`` defaults to a fixed value rather than to ``None`` because rule 20 requires a run to be
    reproducible from ``(scenario_id, seed)``, and a suite whose default was unseeded would be one
    place the property was not exercised.

    ``supervisor_id`` and ``executor_id`` default to this suite's single pair, which is what a
    one-phase case wants. Passing ``""`` for either makes every role issue and declare **as
    itself** -- which is what a real ``S1-HIER`` run does, four Supervisors each minting the scope
    for its own phase, and is what ``test_golden_path.py`` needs in order to exercise the
    registered-issuer set the composition manifest declares rather than a single configured name.

    ``plan``, when given, derives :attr:`~agents.graphs.nodes.NodeContext.executor_delegate` from
    the same :class:`~agents.registry.loader.Composition` and
    :class:`~agents.registry.composer.ComposedCondition` the plan already carries -- exactly what
    ``agents/golden.py`` does for a real run. Omitted (the default), the context carries no
    delegate and a phase-planning node built against it takes ADR-092's fallback: it mints once,
    stashes the token, and stops, which is the pre-ADR-092 shape every case that constructs
    ``phase_planning_node``/``bounded_execution_node`` directly, without a plan, still exercises.

    ``environment``, ``cluster_api_transport`` and ``declare_phase`` are M10's three runner-supplied
    seams (SEAM 6 and SEAM 7). All three default to the pre-M10 shape -- no environment facts, no
    direct-path transport, no phase declaration -- so every case above that does not name one is
    exercising exactly the Tier A arrangement it did before, and each one that does name it is
    exercising the seam rather than a mock of it.
    """
    from agents.graphs.nodes import executor_delegate_for
    from agents.registry.tracing import NullSpanSink

    return NodeContext(
        run_id=guardian.config.run_id,
        guardian=guardian.client,
        model=ScriptedClient(list(answers)) if model is None else model,
        tracer=Tracer(run_id=guardian.config.run_id, sink=NullSpanSink() if sink is None else sink),
        seed=seed,
        supervisor_id=supervisor_id,
        executor_id=executor_id,
        namespace=NAMESPACE,
        evidence={} if evidence is None else evidence,
        executor_delegate=(
            None if plan is None else executor_delegate_for(plan.composition, plan.composed)
        ),
        environment=tuple(environment),
        cluster_api_transport=cluster_api_transport,
        declare_phase=declare_phase,
    )


def recorded_spans(path: Path) -> tuple[Mapping[str, Any], ...]:
    """Open a file span sink at ``path``, and return a reader for what was written to it.

    A file exporter rather than the collector, which is ADR-032's Tier A choice: spans have to be
    assertable with no Docker and no OTLP endpoint, and a file of one JSON object per span is the
    smallest thing that makes "four phase spans present in order" a checkable claim.
    """
    from agents.registry.tracing import read_spans

    return read_spans(path)


def file_sink(path: Path) -> FileSpanSink:
    """A span sink writing to ``path``. Separate from :func:`recorded_spans` so it can be closed."""
    return FileSpanSink(path)
