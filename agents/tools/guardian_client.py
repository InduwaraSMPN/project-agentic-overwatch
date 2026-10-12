r"""The Guardian client: the only route from the agent layer to the cluster, and it holds nothing.

WHAT THIS MODULE IS
-------------------
``.agents/rules/10-guardian-first.md``: "Code under ``agents/`` must never import a Kubernetes
client, shell out to the Kubernetes command-line client, or open a connection to the cluster API.
The ONLY mutation path is the Guardian client in ``agents/tools/``." This is that client. It speaks
the three routes ``guardian/app/main.py`` fixes -- ``POST /v1/actions``, ``POST /v1/tokens`` and
``GET /healthz`` -- and it does nothing else.

``scripts/grep_guard.sh`` scans every tracked file under ``agents/`` for five patterns, prose
included, with no exemption mechanism, and this module is written so that it never needs one: an
Executor names a ``verb``, a ``resource``, a ``namespace`` and a ``name`` to the Guardian, which is
both sufficient and more accurate than naming a command-line tool it never runs. ADR-029.

A DENIAL IS HTTP 200, AND A CLIENT THAT FORGETS THAT DOUBLES THE AUDIT LOG
---------------------------------------------------------------------------
``guardian/app/main.py`` states the contract at length and it is the single most important thing to
get right here: ``POST /v1/actions`` answers **200 with an ``ActionResult`` for every outcome the
Guardian reached a decision on** -- permit, deny, forged token, oversize body, malformed body,
Guardian fault. "The status line is not a second copy of the decision." A non-2xx from that route
means the Guardian did **not** reach a decision, and there is exactly one such case: 503, when the
audit sink could not seal a record.

The failure mode this module is written against is therefore specific rather than general. A client
built on the ordinary convention -- treat non-2xx as failure, retry it -- would be *correct* here
and still catastrophic, because the ordinary convention also says a 4xx body is an error body worth
discarding. A client that instead treated a *denial* as a transport error would retry it, and every
retry appends a second row to the hash-chained audit log for a decision that was already made. Two
rows for one attempted action is not a cosmetic defect: ``evaluation-protocol.md`` section 3
computes both RQ5 measures by counting those rows.

So: **2xx means read the body, whatever it says.** Non-2xx means no decision was reached, and the
caller is told that as a distinct outcome rather than as a denial.

THE TOKEN IS A CALL ARGUMENT AND NEVER ANYTHING ELSE
------------------------------------------------------
FR3.1 requires Executors to hold **no standing credentials**, and the M4 plan makes that two
mechanisms rather than one. Lifetime is the graph's: an executor node is constructed per task and
its state is unreachable after the task returns. Credentials are this module's, and the rule is
stated as a property of the type: **the capability token is a parameter of
:meth:`GuardianClient.submit_action`.** It is never an environment variable, never module state,
never a field on this object, and never cached between calls. :class:`GuardianClient` holds a base
URL and a transport, and that is the whole of its state --
``agents/tests/test_executor_env_scan.py`` asserts the other half, that the environment visible to
executor code carries no ``GUARDIAN_`` prefixed key and no credential-shaped name.

The consequence worth stating: an executor that is handed no token cannot obtain one. There is no
fallback, no "issue one for me", no ambient identity. Issuance is a different tool held by a
different node (:mod:`agents.tools.registry` explains which node, per topology), and the only way a
token reaches an executor is that a Supervisor passed it in.

THE TRANSPORT IS INJECTABLE, WHICH IS WHAT MAKES TIER A REAL RATHER THAN MOCKED
--------------------------------------------------------------------------------
``docs/plans/M4-implementation-plan.md`` splits M4's verification three ways, and Tier A is
"offline... the Guardian client driven against an in-process ASGI app". That is not a mock of the
Guardian: it is the Guardian, assembled by its own composition root, driven through its own route
handlers, with only the socket removed. ``guardian/tests/harness.py``'s ``call_asgi`` already
established the technique and the reason -- ``fastapi.testclient`` needs ``httpx``, which is not in
the pinned runtime set and is not being added for a test convenience.

So the transport is a callable the caller supplies, defaulting to :class:`UrllibTransport`. Tier A
supplies an ASGI driver, Tier A' and Tier B supply the default, and the client code above them is
the same code in all three -- which is the property that makes a Tier A pass evidence about the
thing Tier B runs.

WHAT THIS MODULE DELIBERATELY DOES NOT DO
------------------------------------------
*It does not retry a decision.* See above. It retries nothing at all, in fact: a 503 is returned to
the caller as :class:`NoDecision`, and whether to try again is a question about the phase's declared
turn budget, which the graph owns and the composition manifest declares. A retry policy buried in a
client would spend a budget nobody could see it spending -- and ADR-028 makes a retry a turn
precisely so that it is visible.

*It does not interpret a reason code.* The Guardian's vocabulary is closed and structured, and this
module passes it through untouched so that the model, the trace and the run bundle all see the same
string. Translating ``scope.verb-not-allowed`` into English here would put prompt text in code and
would give the model a paraphrase rather than the value ``analysis/`` scores.

*It does not read configuration.* The base URL is a constructor argument. Nothing here consults the
environment, which is what lets the env scan assert an empty result rather than an allowlisted one.
"""

import json
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import urlsplit

__all__ = (
    "ACTIONS_PATH",
    "ACTION_REQUEST_SCHEMA_VERSION",
    "GuardianClient",
    "GuardianTransportError",
    "HEALTH_PATH",
    "NoDecision",
    "TOKENS_PATH",
    "TOKEN_ISSUE_SCHEMA_VERSION",
    "Transport",
    "UrllibTransport",
)

# The three routes guardian/app/main.py fixes, named here rather than inlined so that the surface
# this client speaks is a list a reader can check against that module without reading three call
# sites. They are a copy across a component boundary -- agents/ cannot import guardian/, because the
# Guardian ships as its own container and holds the only cluster credential, so the dependency would
# run the wrong way -- and agents/tests/test_guardian_seam.py holds the two sides equal, which is
# ADR-022's rule: a copy is legal when a test makes "copy" mean "copy that cannot drift".
ACTIONS_PATH: Final = "/v1/actions"
TOKENS_PATH: Final = "/v1/tokens"
HEALTH_PATH: Final = "/healthz"

# The contract versions this client speaks, copied across the same boundary and held equal by the
# same test. ActionRequest is at v2 because M4-T4.0c added the presenting identity and the phase --
# the two facts guardian/token/verifier.py needs and architecture section 3's original field list
# did not carry.
ACTION_REQUEST_SCHEMA_VERSION: Final = "v2"
TOKEN_ISSUE_SCHEMA_VERSION: Final = "v1"  # noqa: S105 - a contract version token, not a credential

# The one non-2xx status POST /v1/actions can produce, and it means no decision was reached rather
# than a decision that went against the caller.
_HTTP_SERVICE_UNAVAILABLE: Final = 503

# The schemes this client will open. urllib's opener honours every scheme it knows, `file:` among
# them, and a base URL is operator-supplied -- the finding ADR-026 records ruff's `S` rules
# surfacing in M1's instrument code, fixed there the same way: validate before opening.
_ALLOWED_SCHEMES: Final = frozenset({"http", "https"})

# A response body larger than this is refused unread. The Guardian's own answers are small -- an
# ActionResult is six fields -- and the bound exists because the transport is the one place this
# process reads bytes chosen by something else. It is generous by two orders of magnitude against
# any legitimate answer, so it can only ever fire on something that is not one.
_MAX_RESPONSE_BYTES: Final = 256 * 1024

Transport = Callable[..., tuple[int, Any]]
"""What a transport is: ``(method, path, body[, headers]) -> (status, decoded JSON body)``.

Three positional arguments and, since SEAM 6, an optional fourth ``headers`` mapping, so that an
ASGI driver and an HTTP client stay interchangeable without either learning the other's options. A
transport raises :class:`GuardianTransportError` when it could not obtain a status at all, and
returns whatever it got otherwise -- including a status the caller will treat as a refusal. Deciding
what a status *means* is this module's job and never the transport's.

``headers`` carries the caller-authentication header the runner injects for the control-plane routes
(SEAM 6). It is only ever passed on the one route that needs it, and only when a supplier is,
so a transport with no ``headers`` parameter still serves every other call unchanged.
"""


class GuardianTransportError(RuntimeError):
    """The Guardian could not be reached, so no status and no body exist.

    Distinct from :class:`NoDecision`, which is a status the Guardian *did* return. The difference
    matters to the graph: an unreachable Guardian is an environment fault that the run should
    surface, while a 503 is the Guardian correctly refusing to answer without an audit record, and
    the correct responses are not the same.
    """


@dataclass(frozen=True)
class NoDecision:
    """The Guardian answered, and the answer was that it reached no decision.

    Carries the status and the structured error code from the body's ``error`` key -- one of the
    closed vocabulary ``guardian/app/main.py`` publishes, such as ``guardian_audit_unavailable``.
    Deliberately **not** an ``ActionResult`` with a synthesised denial: a denial is a decision the
    audit chain contains, and manufacturing one here would put a row in a caller's reasoning that
    exists in no log.
    """

    status: int
    error: str


class UrllibTransport:
    """An HTTP transport over the standard library. No third-party client, and no session state.

    ``urllib`` rather than a pinned HTTP client for the reason ``monitor/tests/__init__.py`` states
    about ``httpx``: a dependency added for convenience is a dependency in the evaluated artefact's
    pinned set, recorded in every bundle's ``versions_env_sha256``, and this transport needs
    nothing a session, a connection pool or a retry policy would provide -- it makes one request
    and reads one answer, and every retry decision belongs to the graph's declared turn budget.

    The scheme is validated before the request is built. ``urllib``'s default opener honours every
    scheme it knows, ``file:`` included, and the base URL reaches this class from configuration --
    which is exactly the shape of the four findings ADR-026 records ruff's ``S`` rules surfacing in
    M1's instrument code, fixed there by validating the scheme at the call site.
    """

    def __init__(self, base_url: str, *, timeout_seconds: float) -> None:
        parsed = urlsplit(base_url)
        if parsed.scheme not in _ALLOWED_SCHEMES:
            raise ValueError(
                f"the Guardian base URL {base_url!r} names scheme {parsed.scheme!r}; this "
                f"transport opens {' and '.join(sorted(_ALLOWED_SCHEMES))} and nothing else"
            )
        if not parsed.netloc:
            raise ValueError(f"the Guardian base URL {base_url!r} names no host")
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def __call__(
        self, method: str, path: str, body: bytes, headers: Mapping[str, str] | None = None
    ) -> tuple[int, Any]:
        """Make one request and return ``(status, decoded body)``, or raise.

        ``headers`` is the optional caller-authentication mapping SEAM 6 injects on the
        control-plane
        route. It is merged on top of the fixed ``content-type`` rather than replacing it, and it is
        empty or absent for every route that does not need it, so the ordinary action path is
        byte-for-byte the request it always was.
        """
        request_headers = {"content-type": "application/json"}
        if headers:
            request_headers.update(headers)
        request = urllib.request.Request(  # noqa: S310 - scheme validated in __init__
            url=f"{self.base_url}{path}",
            data=body,
            method=method,
            headers=request_headers,
        )
        try:
            with urllib.request.urlopen(  # noqa: S310 - scheme validated in __init__
                request, timeout=self.timeout_seconds
            ) as response:
                return response.status, _decode(response.read(_MAX_RESPONSE_BYTES + 1))
        except urllib.error.HTTPError as answered:
            # An HTTPError IS an answer: the Guardian returned a status and a body, and both are
            # meaningful. urllib raises rather than returns for any non-2xx, so catching it here is
            # what keeps "a status the Guardian returned" and "no answer at all" apart -- and that
            # distinction is the whole of NoDecision versus GuardianTransportError.
            return answered.code, _decode(answered.read(_MAX_RESPONSE_BYTES + 1))
        except (urllib.error.URLError, TimeoutError, OSError) as unreachable:
            raise GuardianTransportError(
                f"{method} {path} did not reach the Guardian: {unreachable}"
            ) from unreachable


def _decode(payload: bytes) -> Any:
    """Decode a response body, refusing one that is too large or is not JSON."""
    if len(payload) > _MAX_RESPONSE_BYTES:
        raise GuardianTransportError(
            f"the Guardian's answer exceeded {_MAX_RESPONSE_BYTES} bytes and was not read"
        )
    try:
        return json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as malformed:
        raise GuardianTransportError(
            f"the Guardian's answer is not JSON: {malformed}"
        ) from malformed


class GuardianClient:
    """Speaks the Guardian's three routes. Holds a base URL, a transport, and no credential.

    Construction takes the transport rather than building one, so that Tier A drives an in-process
    ASGI application and Tier B drives a socket with the same client code above them. Nothing here
    reads the environment.
    """

    def __init__(
        self,
        transport: Transport,
        *,
        caller_auth: Callable[[], Mapping[str, str]] | None = None,
    ) -> None:
        self._transport = transport
        # SEAM 6: an opaque caller-authentication header supplier the runner injects, so that the
        # control-plane routes the Guardian will guard with an HTTPBearer dependency (POST
        # /v1/tokens
        # now, POST /v1/phase runner-side) carry the runner's control-plane bearer. It is a
        # *supplier* -- a callable the runner owns -- and never a value: the credential lives in the
        # runner process, the client asks for a header each time it needs one and holds nothing
        # between calls, and this attribute is read by no code that composes a model prompt. So it
        # is
        # not the standing credential FR3.1 forbids and it is never exposed to the model; the env
        # scan and test_caller_auth_header_attached_and_not_in_model_context hold both halves. It
        # defaults to None, which is the whole of the pre-SEAM-6 behaviour: no header is ever added.
        self._caller_auth = caller_auth

    def _authenticated(self, method: str, path: str, body: bytes) -> tuple[int, Any]:
        """Send one request on a control-plane route, attaching the caller-auth header if supplied.

        Used only by :meth:`issue_capability_token`. When no supplier is injected, or it returns no
        header, this is exactly ``self._transport(method, path, body)`` -- a three-argument call a
        transport with no ``headers`` parameter serves unchanged. The header is requested per call
        and never retained, so the client still holds no credential between calls.
        """
        if self._caller_auth is None:
            return self._transport(method, path, body)
        headers = dict(self._caller_auth())
        if not headers:
            return self._transport(method, path, body)
        return self._transport(method, path, body, headers)

    def healthy(self) -> bool:
        """Return whether ``GET /healthz`` answered 200.

        Liveness and nothing else, which is all that route reports. It deliberately does not tell a
        caller the Guardian's mode: ADR-023 keeps the arm out of the agent layer's reach, and an
        agent that could *read* ``G1-LOGONLY`` could condition its behaviour on it -- which would
        make the guardrail ablation a measurement of what an agent does when told enforcement is
        off, rather than of what removing enforcement does.
        """
        status, _ = self._transport("GET", HEALTH_PATH, b"")
        return status == 200

    def submit_action(
        self,
        *,
        token: str,
        request_id: str,
        run_id: str,
        executor_id: str,
        phase: str,
        verb: str,
        resource: str,
        namespace: str,
        name: str | None,
        params: Mapping[str, str],
        justification: str,
    ) -> Mapping[str, Any] | NoDecision:
        """Submit one action and return the Guardian's ``ActionResult``, or :class:`NoDecision`.

        ``token`` is first and is keyword-only along with everything else, so that no call site can
        pass it positionally into a different slot. It is used to build one request body and is not
        retained: this method stores nothing, and the object it is called on has no field able to
        hold it.

        ``executor_id`` and ``phase`` are the two fields M4-T4.0c added to the request contract so
        that the Guardian can compare them against the token's ``sub`` and ``phase`` claims. The
        honest limit is worth restating at the point a caller supplies them: with executors as
        in-process nodes both are **agent-declared**, so the Guardian's check is attribution rather
        than authentication -- it records and detects a mismatch rather than preventing one. ADR-030
        states it and Chapter 5 owes the reader the same sentence.

        The returned mapping is the Guardian's body verbatim. A denial is a return value, not an
        exception, for the reason ``guardian/app/mediation.py`` gives about its own outcome types: a
        value the caller must consume is far harder to drop than an exception a caller can catch and
        ignore.
        """
        body = {
            "request_id": request_id,
            "run_id": run_id,
            "token": token,
            "executor_id": executor_id,
            "phase": phase,
            "action": {
                "verb": verb,
                "resource": resource,
                "namespace": namespace,
                "name": name,
                "params": dict(params),
            },
            "justification": justification,
            "schema_version": ACTION_REQUEST_SCHEMA_VERSION,
        }
        status, payload = self._transport("POST", ACTIONS_PATH, _encode(body))
        if status == 200:
            if not isinstance(payload, Mapping):
                raise GuardianTransportError(
                    "the Guardian answered 200 with a body that is not an object; an ActionResult "
                    "is the only 200 body this route produces"
                )
            return payload
        return _no_decision(status, payload)

    def issue_capability_token(
        self,
        *,
        supervisor_id: str,
        executor_id: str,
        run_id: str,
        phase: str,
        verbs: tuple[str, ...],
        resources: tuple[str, ...],
        namespaces: tuple[str, ...],
        ttl_seconds: int | None = None,
    ) -> Mapping[str, Any] | NoDecision:
        """Ask the Guardian to mint one capability token, or report that it refused.

        ``POST /v1/tokens`` is deliberately **not** uniform with the actions route, and
        ``guardian/app/main.py`` explains the asymmetry: issuance is not an adjudicated action, it
        produces no ``AuditRecord``, and nothing in the evaluation counts its outcomes -- so a
        refusal there is an ordinary API error answered with an ordinary status. This method
        therefore returns :class:`NoDecision` for a 403 as well as for a 503, and the ``error`` it
        carries is the structured refusal code, which since M4-T4.0d includes
        ``issue_authority_exceeded``: the Guardian refuses to mint a claim wider than the phase's
        declared authority, evaluated by a rule in the same OPA bundle. ADR-031.

        ``ttl_seconds`` is the per-phase override ``security-policy.md`` section 2 permits, and it
        carries no bound here on purpose: the ceiling is that section's number, it reaches the
        Guardian through configuration, and stating it in this client would be a second home for it.
        An override above the ceiling is **refused rather than truncated**, so a caller that asks
        for too long a lifetime is told so rather than quietly given a shorter one.
        """
        body: dict[str, Any] = {
            "supervisor_id": supervisor_id,
            "executor_id": executor_id,
            "run_id": run_id,
            "phase": phase,
            "allow": {
                "verbs": list(verbs),
                "resources": list(resources),
                "namespaces": list(namespaces),
            },
            "ttl_seconds": ttl_seconds,
            "schema_version": TOKEN_ISSUE_SCHEMA_VERSION,
        }
        # POST /v1/tokens is the one route the agent layer calls that the Guardian guards with an
        # HTTPBearer dependency (SEAM 6), so it goes through _authenticated, which attaches the
        # runner's caller-auth header when a supplier is injected. POST /v1/actions stays the
        # unauthenticated body path and is sent through self._transport directly, below in
        # submit_action, unchanged.
        status, payload = self._authenticated("POST", TOKENS_PATH, _encode(body))
        if status == 200:
            if not isinstance(payload, Mapping):
                raise GuardianTransportError(
                    "the Guardian answered 200 to an issue request with a body that is not an "
                    "object"
                )
            return payload
        return _no_decision(status, payload)


def _encode(body: Mapping[str, Any]) -> bytes:
    """Serialise a request body deterministically.

    Sorted keys and minimal separators, so that two identical requests are two identical byte
    strings. Nothing downstream requires it -- the Guardian parses JSON -- but a run bundle records
    what was sent, and a body whose key order depended on how the mapping was built would make two
    byte-identical runs look different in the trace.
    """
    return json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _no_decision(status: int, payload: Any) -> NoDecision:
    """Build the no-decision outcome from whatever the Guardian returned with a non-2xx status."""
    error = ""
    if isinstance(payload, Mapping):
        candidate = payload.get("error")
        if isinstance(candidate, str):
            error = candidate
    if not error:
        error = "guardian_unreadable_error" if status != _HTTP_SERVICE_UNAVAILABLE else "unknown"
    return NoDecision(status=status, error=error)
