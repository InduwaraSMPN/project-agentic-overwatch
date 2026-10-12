r"""The Guardian's HTTP surface: four routes, one of which is the only way to change the cluster.

WHAT THIS MODULE IS
-------------------
``docs/plans/M3-implementation-plan.md``'s T3.1 fixes the surface as ``POST /v1/actions``,
``POST /v1/tokens`` and ``GET /healthz``, and M10 (ADR-128) adds ``POST /v1/phase``. This module is
that surface and nothing more. It parses bytes into contracts, hands them to
:mod:`guardian.app.mediation`, and turns what comes back into a response. It makes no decision of
its
own: there is no branch here that permits, denies, executes or skips a step, because a second
decision site would be a second enforcement path and the whole component exists to be the only one.
The one exception is the control-plane gate on two of the four routes, and that is not a decision
about the request -- it is a refusal to answer to a caller the Guardian could not establish, which
is the same posture :class:`~guardian.app.mediation.AuditUnavailable` takes.

The threat model's position P4 is network reach to exactly this surface -- the agent layer must have
it, or it could not be mediated at all -- so everything below is written for a caller that controls
the bytes, the framing, the headers, the ordering and the volume.

WHAT A REQUEST CANNOT DO HERE
-----------------------------
*It cannot influence the arm.* Nothing in this module reads a mode from anything. The
:class:`~guardian.app.mediation.Mediator` is constructed once, from a
:class:`~guardian.app.config.GuardianConfig` that was read at process start, and this module never
sees a mode value at all -- :func:`create_app` has no parameter that could carry one. Three further
mechanisms sit underneath: :class:`~guardian.app.models.ActionRequest` forbids extra keys, so a body
carrying ``guardian_mode`` at top level does not become a request and is denied under
:attr:`~guardian.app.models.ReasonCode.POLICY_REQUEST_MALFORMED`; :mod:`guardian.app.config` rejects
at import any request field *named* or *typed* like a mode; and a mode-shaped key inside ``params``
or ``justification`` parses fine and reaches nothing, because those two fields are excluded from the
OPA input document by a partition checked at import and no code anywhere looks up configuration from
request data.

*It cannot make the Guardian answer without recording.* Every route that produces a decision goes
through :meth:`~guardian.app.mediation.Mediator.decide` or
:meth:`~guardian.app.mediation.Mediator.reject`, both of which audit before they return. When the
audit sink cannot seal a record, :class:`~guardian.app.mediation.AuditUnavailable` reaches the
handler registered below and the caller gets a bare 503 -- **not** a decision. That is the correct
behaviour and it is worth being explicit about why it is not merely conservative: the M3 plan's
threat-model corollary makes an unaudited block worse than an unblocked action, because an unblocked
action at least leaves a trace somewhere.

*It cannot cause a stack trace to be returned.* Every response body this module emits is built from
a fixed set of keys with structured values. Nothing formats an exception into a body, and the
catch-all handler at the bottom answers with a constant. A traceback is a map of the implementation,
and the caller reading it is assumed hostile.

*It cannot exhaust the process with one body.* The oversize gate runs **before** the body is
parsed and before it is fully read: the declared ``Content-Length`` is checked first, and the
stream is then accumulated with a running bound, so that a chunked body which declares nothing
cannot get further than one chunk past the limit. The bound is
:attr:`~guardian.app.mediation.Mediator.max_request_bytes`, which
:class:`~guardian.app.config.GuardianConfig` derives from the request model's own field bounds --
so it can never be *narrower* than what the model would accept, and no legitimate action is ever
refused as oversize.

WHY EVERY ADJUDICATED OUTCOME IS HTTP 200, INCLUDING A DENIAL
--------------------------------------------------------------
``POST /v1/actions`` answers 200 with an :class:`~guardian.app.models.ActionResult` for every
outcome the Guardian reached a decision on: permit, deny, forged token, oversize body, malformed
body, Guardian fault. The status line is not a second copy of the decision.

The alternative -- 403 on a deny, 413 on oversize, 400 on malformed -- is the conventional shape and
it costs three things. It would put the outcome in two places, so a client could act on the status
line and never read the reason code, which is the field the whole evaluation is scored from. It
invites the transport to intervene: proxies and HTTP client libraries retry, transform and swallow
4xx bodies, and a denial that a retry turns into a second denial has just doubled a row in the audit
chain for a reason nobody would find. And it would make oversize the odd case out, because a 413
with no body is the one refusal that could not carry
:attr:`~guardian.app.models.ReasonCode.POLICY_REQUEST_OVERSIZE` to the caller at all.

So 200 means "the Guardian reached a decision, and here it is", and a non-2xx from this route means
the Guardian did not reach one. There is exactly one such case and it is 503.

``POST /v1/tokens`` is deliberately *not* uniform with this, and the asymmetry is the point:
issuance is not an adjudicated action, it produces no
:class:`~guardian.app.models.AuditRecord`, and nothing in the evaluation counts its outcomes. A
refusal there is an ordinary API error and is answered as one -- with the one addition ADR-128 made,
that an unestablished caller is answered 401 there and on ``/v1/phase`` while ``/v1/actions`` stays
the unauthenticated body path the threat model gives the agent layer.

WHAT ``GET /healthz`` DELIBERATELY DOES NOT SAY
------------------------------------------------
It returns liveness and nothing else. Not the Guardian mode, not the policy bundle digest, not the
run id, not the registered issuers, not the configured timeouts.

The mode is the important omission, and the reason is the ablation rather than secrecy. ADR-023's
whole design keeps the arm out of the agent layer's reach, and while an agent that could *read*
``G1-LOGONLY`` could not set it, it could condition its behaviour on it -- which would make the
guardrail ablation a measurement of what the agent does when told enforcement is off, rather than of
what removing enforcement does. That is a different experiment, and it would be running without
anybody choosing it. The bundle digest is withheld on the plainer ground that the isolation suite
reads it from :attr:`~guardian.app.mediation.Mediator.policy_bundle` in-process, so publishing it to
a hostile network buys nothing.

The generated OpenAPI schema and its two documentation UIs are disabled for the same reason the
health check is thin: they are attacker-reachable surface serving a need that is already met
elsewhere. The contracts are ``guardian/app/models.py``, they are readable in the repository, and a
machine-readable schema is one ``model_json_schema()`` call away offline -- which is the shape
ADR-019 already chose for the event stream.

WHAT IS NOT HERE, AND WHY THERE IS NO MODULE-LEVEL ``app``
-----------------------------------------------------------
There is no ``app = create_app()`` at import time, and that is deliberate. A module-level
application would have to read the environment while the module is being imported, which would make
``import guardian.app.main`` fail on any machine without a full Guardian configuration -- CI's lint
job, a developer's editor, and the very test suite whose job is to check that a missing signing key
refuses to start. The composition root is a function, and a server is pointed at it.

There is also no default composition root that assembles real collaborators, because three of the
four do not exist yet: the token service is M3-T3.3, the audit chain's writer is M3-T3.6, the policy
bundle is M3-T3.2, and the real executor is Tier B, gated on M1 delivering a cluster. Writing a
``create_default_app`` today would mean writing one that quietly substitutes fakes, which is the one
way this file could ship a Guardian that looks configured and enforces nothing.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
M4's agent-side Guardian client speaks to these three routes and to the status-code contract above.
Every adversarial case in T3.8 that exercises the transport -- oversize, malformed, mode-shaped keys
-- asserts against the responses built here.
"""

import json
from collections.abc import Mapping
from typing import Any, Final, Literal

from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from guardian.app.control_auth import ControlPlaneVerifier, PhaseState
from guardian.app.mediation import (
    AuditUnavailable,
    MediationError,
    Mediator,
    TokenIssuanceRefused,
    TokenIssuer,
    as_wire_mapping,
)
from guardian.app.models import ActionRequest, Phase, ReasonCode, TokenIssueRequest
from pydantic import BaseModel, ConfigDict, ValidationError

# The routes the Guardian exposes. Named rather than inlined so that the surface is a list a reader
# can
# check against the plan without reading the decorators. M10 (ADR-128) adds POST /v1/phase, the
# control-plane phase channel; it and POST /v1/tokens require the control-plane bearer, while
# POST /v1/actions stays the unauthenticated body path the threat model gives the agent layer.
ACTIONS_PATH: Final = "/v1/actions"
TOKENS_PATH: Final = "/v1/tokens"
PHASE_PATH: Final = "/v1/phase"
HEALTH_PATH: Final = "/healthz"

# The phase-declaration contract's own version, on the same reasoning ActionRequest.schema_version
# has
# one: a channel that could not tell which body shape it was reading would infer it from field
# presence.
PHASE_DECLARATION_SCHEMA_VERSION: Final = "v1"

# The one key every non-decision response body carries, and the closed vocabulary of its values.
# Structured for the reason every reason code in this project is structured: free text cannot be
# counted, cannot be compared across arms, and turns two spellings of one refusal into two
# phenomena. These are not ReasonCodes -- a ReasonCode accompanies an audited decision, and none of
# these is one -- and they are deliberately spelled differently so that the two vocabularies cannot
# be confused in a log or a data frame.
ERROR_KEY: Final = "error"
ERROR_AUDIT_UNAVAILABLE: Final = "guardian_audit_unavailable"
ERROR_INTERNAL: Final = "guardian_internal_error"
ERROR_ISSUANCE_UNAVAILABLE: Final = "issuance_unavailable"
ERROR_PHASE_UNAVAILABLE: Final = "phase_channel_unavailable"
ERROR_REQUEST_MALFORMED: Final = "request_malformed"
ERROR_REQUEST_OVERSIZE: Final = "request_oversize"
# ADR-128: the control-plane caller was not authenticated. Spelled distinctly from the request-shape
# errors so a caller (and a log) can tell "you are not who /v1/tokens serves" from "your body is
# wrong".
ERROR_UNAUTHENTICATED: Final = "control_plane_unauthenticated"

HTTP_OK: Final = 200
HTTP_BAD_REQUEST: Final = 400
HTTP_UNAUTHORIZED: Final = 401
HTTP_FORBIDDEN: Final = 403
HTTP_PAYLOAD_TOO_LARGE: Final = 413
HTTP_INTERNAL_ERROR: Final = 500
HTTP_SERVICE_UNAVAILABLE: Final = 503

CONTENT_LENGTH_HEADER: Final = "content-length"

# The bearer extractor for the two control-plane routes. auto_error=False so this module, not
# FastAPI,
# decides the failure: FastAPI's HTTPBearer answers a missing credential with 403, and ADR-128 wants
# a
# 401 -- "who are you" rather than "you may not" -- so the credential is extracted here and the 401
# is
# produced by _control_plane_denied below.
_control_plane_bearer: Final = HTTPBearer(auto_error=False)


class PhaseDeclaration(BaseModel):
    """The body of ``POST /v1/phase``: the run this Guardian serves has moved into ``phase``
    (ADR-128).
        ``extra="forbid"`` on the same reasoning every Guardian contract carries it -- a stray key
        is a
        malformed body, not a silently ignored one. ``phase`` is typed
        :class:`~guardian.app.models.Phase`
        so a fifth phase never becomes a declaration, and ``schema_version`` is pinned so the
        channel
        reads
        only the shape it understands. It is deliberately small: it declares state, it is not
        adjudicated,
        and it produces no audit record -- the runner is authenticated as the control plane, and
        what it
        declares is which phase issuance should bound the next mint to.
    """

    model_config = ConfigDict(extra="forbid")

    run_id: str
    phase: Phase
    schema_version: Literal[PHASE_DECLARATION_SCHEMA_VERSION]


class _BodyRejected(Exception):
    """The request body was refused before it became a contract, with the reason why.

    Internal to this module and never escapes it: each route catches it and turns it into whatever
    that route's refusal looks like. It carries a :class:`~guardian.app.models.ReasonCode` rather
    than a message because ``POST /v1/actions`` must **audit** the refusal, and an audited refusal
    needs the structured vocabulary the evaluation counts -- not a string that happens to describe
    what went wrong.
    """

    def __init__(self, reason_code: ReasonCode) -> None:
        super().__init__(reason_code.value)
        self.reason_code = reason_code


async def read_bounded_body(request: Request, limit: int) -> bytes:
    """Read at most ``limit`` bytes of ``request``'s body, or raise :class:`_BodyRejected`.

    Two gates, and both are needed. The declared ``Content-Length`` is checked first, so an oversize
    body announced honestly is refused without a byte of it being read. The stream is then
    accumulated with a running total, because ``Content-Length`` is the caller's claim and the
    caller is the attacker: a chunked body declares no length at all, and a dishonest one declares
    the wrong length.

    Refusing mid-stream leaves the remainder of the body unread, which is the intended trade.
    Draining it politely would mean reading exactly the bytes the bound exists to refuse, and threat
    model position P3 is unbounded request volume against this surface.

    A ``Content-Length`` that is not a plain non-negative integer is a *malformed* body rather than
    an oversize one. The distinction reaches the audit chain, and "the framing was wrong" and "the
    body was too big" are different findings about different attacks.
    """
    declared = request.headers.get(CONTENT_LENGTH_HEADER)
    if declared is not None:
        if not declared.strip().isdigit():
            raise _BodyRejected(ReasonCode.POLICY_REQUEST_MALFORMED)
        if int(declared.strip()) > limit:
            raise _BodyRejected(ReasonCode.POLICY_REQUEST_OVERSIZE)
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise _BodyRejected(ReasonCode.POLICY_REQUEST_OVERSIZE)
        chunks.append(chunk)
    return b"".join(chunks)


def parse_json_object(body: bytes) -> Any:
    """Decode ``body`` as JSON, or raise :class:`_BodyRejected` with the malformed reason.

    ``RecursionError`` is caught alongside the decoding errors, and it is the interesting one: a
    body of ten thousand open brackets is well within any sensible size bound and will still exhaust
    the interpreter's stack in the parser. Letting that escape would turn a small request into a
    500, and a 500 is an unaudited outcome on the route where every outcome must be audited.
    """
    try:
        return json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as error:
        raise _BodyRejected(ReasonCode.POLICY_REQUEST_MALFORMED) from error


def _json(payload: Mapping[str, Any], status_code: int) -> Response:
    """Return one JSON response. The single construction site of a response body in this module."""
    return JSONResponse(content=dict(payload), status_code=status_code)


def _error(code: str, status_code: int) -> Response:
    """Return a structured error body carrying nothing but a code from the closed vocabulary."""
    return _json({ERROR_KEY: code}, status_code)


def create_app(
    *,
    mediator: Mediator,
    token_issuer: TokenIssuer | None = None,
    control_plane_authenticator: ControlPlaneVerifier | None = None,
    phase_state: PhaseState | None = None,
) -> FastAPI:
    """Build the Guardian's ASGI application around an already-assembled mediator.

    ``control_plane_authenticator`` and ``phase_state`` are ADR-128's, supplied by
    :func:`guardian.app.composition.build_guardian`. Both default to absent so a caller assembling a
    minimal app is explicit about the control-plane surface: with no authenticator every
    ``/v1/tokens``
    and ``/v1/phase`` request is answered 401, which is the fail-closed reading of "this Guardian
    cannot
    establish who is calling", and with no phase state ``/v1/phase`` answers 503 the way
    ``/v1/tokens``
    does without an issuer -- "this Guardian does not offer the channel" rather than "no such
    route".

    Every collaborator is supplied by the caller. This function reads no environment variable, opens
    no file and constructs no default -- so an application built here enforces exactly what its
    mediator was given, and there is no path by which a missing dependency is silently replaced with
    something weaker. :class:`~guardian.app.config.GuardianConfig` is the only thing in this package
    that reads configuration, and it does so once, at process start, before this function is called.

    Note what the signature does **not** contain: a mode, a policy, an executor, a key, or a
    request. The arm reaches the process through
    :class:`~guardian.app.config.GuardianConfig` and reaches the pipeline through the mediator, and
    there is no parameter here through which anything else could set it.

    ``token_issuer`` is optional and defaults to absent, because M3-T3.3 lands separately and a
    Guardian without an issuer is a Guardian that mediates actions and mints nothing. That is a
    coherent posture; substituting a fake issuer to make the route respond would not be. When it is
    absent the route answers 503 rather than 404, because the difference between "this Guardian does
    not mint tokens" and "this URL does not exist" is a fact a Supervisor needs.
    """
    app = FastAPI(
        title="Agentic Overwatch Guardian",
        version=ActionRequest.model_fields["schema_version"].annotation.__args__[0],
        # See the module docstring: the schema and its two UIs are attacker-reachable surface
        # serving a need that guardian/app/models.py already meets in the repository.
        openapi_url=None,
        docs_url=None,
        redoc_url=None,
    )

    def _control_plane_denied(
        credentials: HTTPAuthorizationCredentials | None,
    ) -> Response | None:
        """Return a 401 response when the control-plane caller is not established, else ``None``.

        Fail closed on every branch: no authenticator wired, no bearer presented, or a bearer the
        authenticator does not accept. The body is one fixed code from the closed vocabulary and
        never
        the authenticator's own message, which -- like every other refusal this module emits -- is
        withheld from a caller the threat model assumes is probing. See
        :class:`ControlPlaneVerifier`.
        """
        if control_plane_authenticator is None:
            return _error(ERROR_UNAUTHENTICATED, HTTP_UNAUTHORIZED)
        if credentials is None or not credentials.credentials:
            return _error(ERROR_UNAUTHENTICATED, HTTP_UNAUTHORIZED)
        if not control_plane_authenticator.authenticate(credentials.credentials):
            return _error(ERROR_UNAUTHENTICATED, HTTP_UNAUTHORIZED)
        return None

    @app.post(ACTIONS_PATH)
    async def submit_action(request: Request) -> Response:
        """Adjudicate one action. Answers 200 with an ActionResult for every decision reached.

        The two refusal paths -- a body too large to accept and a body that is not an
        :class:`~guardian.app.models.ActionRequest` -- are **audited**, not merely returned.
        ``security-policy.md`` section 1.4 requires every decision to be recorded and makes no
        exception for the ones that never reached policy, and
        :meth:`~guardian.app.mediation.Mediator.reject` is what writes them.

        Nothing about a rejected body is recorded beyond its reason code. It did not parse, so there
        is no established request id and no action to record, and copying attacker-authored bytes
        into the chain as though the Guardian had established them is precisely what the null
        attribution fields exist to avoid. The run id the record does carry is this Guardian's own
        configured one, never anything the body said (ADR-058).
        """
        try:
            body = await read_bounded_body(request, mediator.max_request_bytes)
            action_request = ActionRequest.model_validate(parse_json_object(body))
        except _BodyRejected as rejected:
            # Every ValidationError arrives here as POLICY_REQUEST_MALFORMED and none of Pydantic's
            # detail is returned to the caller. The detail names fields, types and constraints,
            # which is a description of the contract's internals handed to the party the threat
            # model assumes is probing it.
            return _json(as_wire_mapping(mediator.reject(rejected.reason_code)), HTTP_OK)
        except ValidationError:
            return _json(
                as_wire_mapping(mediator.reject(ReasonCode.POLICY_REQUEST_MALFORMED)), HTTP_OK
            )
        return _json(as_wire_mapping(mediator.decide(action_request)), HTTP_OK)

    @app.post(TOKENS_PATH)
    async def issue_capability_token(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Depends(_control_plane_bearer),  # noqa: B008 - FastAPI dependency-injection default
    ) -> Response:
        """Mint one capability token for a Supervisor, or refuse with a structured code.

        Not an adjudicated action: it produces no :class:`~guardian.app.models.AuditRecord`, nothing
        in ``evaluation-protocol.md`` section 3 counts its outcomes, and its failures are API errors
        rather than enforcement events. So this route uses ordinary status codes while
        ``POST /v1/actions`` does not -- see the module docstring for why the asymmetry is
        deliberate rather than an inconsistency.

        **This route requires the control-plane bearer** (ADR-128; ``ControlPlaneVerifier``), and
        the
        check is the FIRST thing it does: a request that is not the control plane is answered 401
        whether or not this Guardian was assembled with an issuer, because "you are not who this
        surface serves" is a fact about the caller and not about the Guardian's configuration. The
        ``HTTPBearer`` dependency is declared with ``auto_error=False`` so that the 401 is produced
        here, in one place, with one fixed body -- FastAPI's own is a 403, and who-you-are is not
        you-may-not.

        What that closed, and what it did not, is security-policy.md section 6 and ADR-031 (risk
        R-15): the caller is now the run's runner process, authenticated per run, and the phase is
        runner-declared rather than agent-declared; what remains is that per-node attribution
        *inside*
        that one runner process is not established, because the whole agent graph runs in it.

        The body bound is the action bound, which is generous for this smaller contract. A separate,
        tighter number would be a second unowned bound in a component whose numbers most need a
        single home, and being generous costs nothing while being tight would risk refusing a
        legitimate allow-claim list.
        """
        denied = _control_plane_denied(credentials)
        if denied is not None:
            return denied
        if token_issuer is None:
            return _error(ERROR_ISSUANCE_UNAVAILABLE, HTTP_SERVICE_UNAVAILABLE)
        try:
            body = await read_bounded_body(request, mediator.max_request_bytes)
            issue_request = TokenIssueRequest.model_validate(parse_json_object(body))
        except _BodyRejected as rejected:
            oversize = rejected.reason_code is ReasonCode.POLICY_REQUEST_OVERSIZE
            return _error(
                ERROR_REQUEST_OVERSIZE if oversize else ERROR_REQUEST_MALFORMED,
                HTTP_PAYLOAD_TOO_LARGE if oversize else HTTP_BAD_REQUEST,
            )
        except ValidationError:
            return _error(ERROR_REQUEST_MALFORMED, HTTP_BAD_REQUEST)
        try:
            issued = token_issuer.issue(issue_request)
        except TokenIssuanceRefused as refused:
            # refused.code is bounded and structured by TokenIssuanceRefused; refused.detail is not
            # returned, because it is the issuer's own message and this response goes to a caller
            # the threat model assumes is mapping the implementation.
            return _error(refused.code, HTTP_FORBIDDEN)
        return _json(as_wire_mapping(issued), HTTP_OK)

    @app.post(PHASE_PATH)
    async def declare_phase(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Depends(_control_plane_bearer),  # noqa: B008 - FastAPI dependency-injection default
    ) -> Response:
        """Record that the run this Guardian serves has moved into a phase (ADR-128, V17).

        The channel exists because issuance's phase ceiling was previously checked against a
        *self-declared* phase: ``TokenIssueRequest.phase`` said which phase the caller believed the
        run was in, and nothing knew otherwise. The runner now says it, here, and
        :class:`~guardian.app.control_auth.PhaseState` is what the issuance path reads -- so the
        declaration is state on the Guardian rather than a field on a request.

        Authentication comes first and for the same reason as on ``/v1/tokens``: a channel anybody
        may
        write is worse than no channel, because a forged phase declaration would move the ceiling
        every subsequent mint is bounded by.

        The three refusals, in the order they are reached: 401 when the caller is not established;
        503 when no :class:`~guardian.app.control_auth.PhaseState` was supplied, which is this
        Guardian not offering the channel rather than the URL not existing; 400 or 413 for a body
        that
        is not a :class:`PhaseDeclaration`. A declaration produces **no audit record** -- it is not
        an
        adjudicated action, it authorises nothing by itself, and the caller is authenticated, so
        ``security-policy.md`` section 1.4's "every decision audited" does not reach it.
        """
        denied = _control_plane_denied(credentials)
        if denied is not None:
            return denied
        if phase_state is None:
            return _error(ERROR_PHASE_UNAVAILABLE, HTTP_SERVICE_UNAVAILABLE)
        try:
            body = await read_bounded_body(request, mediator.max_request_bytes)
            declaration = PhaseDeclaration.model_validate(parse_json_object(body))
        except _BodyRejected as rejected:
            oversize = rejected.reason_code is ReasonCode.POLICY_REQUEST_OVERSIZE
            return _error(
                ERROR_REQUEST_OVERSIZE if oversize else ERROR_REQUEST_MALFORMED,
                HTTP_PAYLOAD_TOO_LARGE if oversize else HTTP_BAD_REQUEST,
            )
        except ValidationError:
            return _error(ERROR_REQUEST_MALFORMED, HTTP_BAD_REQUEST)
        phase_state.declare(declaration.run_id, declaration.phase.value)
        return _json(
            {
                "run_id": declaration.run_id,
                "phase": declaration.phase.value,
                "schema_version": PHASE_DECLARATION_SCHEMA_VERSION,
            },
            HTTP_OK,
        )

    @app.get(HEALTH_PATH)
    async def health() -> Response:
        """Report that the process is alive, and report nothing else.

        No mode, no bundle digest, no run id, no configuration of any kind. See the module docstring
        for why the mode in particular is withheld: an agent that could read the arm could condition
        its behaviour on it, which would silently turn the guardrail ablation into a different
        experiment.
        """
        return _json({"status": "ok"}, HTTP_OK)

    @app.exception_handler(AuditUnavailable)
    async def _audit_unavailable(request: Request, exception: AuditUnavailable) -> Response:
        """Answer 503 with no decision when the audit sink could not seal one.

        The one non-2xx outcome ``POST /v1/actions`` can produce, and the only correct one. A
        Guardian that cannot record what it decided has no answer available to it: returning a
        permit would be unrecorded permission, and returning a denial would be the unaudited block
        the M3 plan calls worse than an unblocked action, because an unblocked action at least
        leaves a trace somewhere. 503 says "ask again later", which is true, and says nothing about
        what would have been decided, which is also correct.
        """
        del request, exception
        return _error(ERROR_AUDIT_UNAVAILABLE, HTTP_SERVICE_UNAVAILABLE)

    @app.exception_handler(MediationError)
    async def _mediation_error(request: Request, exception: MediationError) -> Response:
        """Answer 503 for any other refusal to answer from the pipeline.

        Registered after the specific handler so that :class:`AuditUnavailable`, its subclass, still
        reaches the one above. It exists so that a future
        :class:`~guardian.app.mediation.MediationError` added for a new "cannot answer" case starts
        life behaving correctly rather than as a 500 with a traceback.
        """
        del request, exception
        return _error(ERROR_AUDIT_UNAVAILABLE, HTTP_SERVICE_UNAVAILABLE)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exception: Exception) -> Response:
        """Answer 500 with a constant. Never a traceback, never a message, never a field name.

        A defect in this Guardian must not become a description of this Guardian. The body is one
        fixed key with one fixed value, so nothing about what failed, where, or on which field
        crosses the boundary to a caller the threat model assumes is probing for exactly that.

        This handler is the transport's last resort and not the pipeline's. A fault *inside*
        adjudication never reaches here: :meth:`~guardian.app.mediation.Mediator._adjudicate`
        catches it and turns it into an audited denial under
        :attr:`~guardian.app.models.ReasonCode.POLICY_GUARDIAN_FAULT`, because a Guardian defect
        must fail the way an attack fails or the two become distinguishable by their symptoms.
        """
        del request, exception
        return _error(ERROR_INTERNAL, HTTP_INTERNAL_ERROR)

    return app
