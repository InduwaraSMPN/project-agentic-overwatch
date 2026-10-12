r"""``POST /v1/tokens`` authenticates its caller, and this module is the test of that defence.

WHAT CHANGED, AND WHY THIS FILE IS A REWRITE RATHER THAN AN ADDITION
--------------------------------------------------------------------
This file used to be the *demonstration of an exposure*. It opened by saying so -- "THIS IS NOT A
TEST OF A DEFENCE. IT IS THE EVIDENCE FOR A FINDING" -- and its four headline cases asserted that a
caller presenting no credential of any kind received a signed capability token, that ``iss`` was
whatever the body said, that ``sub``/``run_id``/``phase``/``allow`` were all caller-chosen, and that
a
self-minted token was accepted by the verifier and stopped only by policy.

ADR-031's own tripwire said what had to happen when that was fixed: "whoever authenticates the seam
must rewrite that module into the test of the defence; a green suite describing a system that no
longer exists is the failure mode ADR-031 retires against." M10 (ADR-128) authenticated the seam, so
that is what this file now is. Every one of the four cases is inverted: the same request, without
the
credential, is refused with **401** and produces no token at all.

WHAT THE DEFENCE IS, PRECISELY
------------------------------
``guardian/app/control_auth.py`` verifies a presented bearer with a Kubernetes **TokenReview** and
accepts it only when the API server reports it authenticated, names the subject
``system:serviceaccount:<ns>:runner-control-plane``, and confirms the audience
``guardian-control-plane``. Both values come from ``guardian/app/config.py`` with **no default**, so
  a
Guardian that cannot be told who its control plane is does not start rather than admitting anybody.
The gate covers ``POST /v1/tokens`` and ``POST /v1/phase`` and nothing else: ``POST /v1/actions``
stays the unauthenticated body path the threat model gives the agent layer, and the cases at the
foot
of this file assert that it does.

**The default is 401.** A Guardian assembled without an authenticator answers 401 on both
control-plane
routes, because "this Guardian cannot establish who is calling" is not the same claim as "you are
admitted" -- and the one reading of "I could not check" that does not turn an unverified caller into
an authenticated one is "not authenticated".

WHAT IS STILL OPEN, AND WHERE IT IS WRITTEN DOWN
------------------------------------------------
The caller is now the run's runner process, authenticated per run, and the phase is runner-declared
rather than agent-declared. What remains is that per-node attribution *inside* that one runner
process
is not established, because the whole agent graph runs in it -- ADR-128, security-policy.md section
6,
risk R-15. That residual is a statement about a different thing from the one this file used to
demonstrate, and it is stated there rather than asserted here: the honest test of a defence is the
defence, and a residual is not a test.

THE BOUNDS THE CALLER STILL CANNOT MOVE
---------------------------------------
Three cases are kept almost unchanged, because ADR-128 did not touch them and they are the reason
the
rewrite is not a victory declaration. The authority policy still bounds *what* a minted capability
may
cover, the lifetime ceiling still bounds *how long* it lives, and the request contract still refuses
a
body that is not a ``TokenIssueRequest``. Each now runs as the authenticated control plane, because
that is who the surface is for.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from guardian.app.models import ReasonCode  # noqa: E402
from guardian.tests.harness import (  # noqa: E402
    CONTROL_PLANE_BEARER,
    DEFAULT_ALLOW,
    EXECUTOR_ID,
    PHASE,
    RUN_ID,
    SUITE_TOKEN_MAX_LIFETIME_SECONDS,
    SUPERVISOR_ID,
    GuardianHarness,
    deny_default_result,
    permit_result,
    read_claim,
)

HTTP_OK = 200
HTTP_BAD_REQUEST = 400
HTTP_FORBIDDEN = 403
HTTP_UNAUTHORIZED = 401

# The one code `main.py` returns for an unestablished control-plane caller, from its closed
# vocabulary. Spelled here rather than imported so that a change to the code is a change to this
# file's contract too -- which is the point of a tripwire that fails when the system changes.
UNAUTHENTICATED = "control_plane_unauthenticated"


def _issue_body(**overrides: object) -> dict[str, object]:
    """A well-formed ``POST /v1/tokens`` body, with any field replaced."""
    body: dict[str, object] = {
        "supervisor_id": SUPERVISOR_ID,
        "executor_id": EXECUTOR_ID,
        "run_id": RUN_ID,
        "phase": PHASE,
        "allow": DEFAULT_ALLOW.as_mapping(),
        "ttl_seconds": None,
        "schema_version": "v1",
    }
    body.update(overrides)
    return body


def _assert_refused_unauthenticated(status: int, payload: object, *, what: str) -> None:
    """The triple assertion for a refused mint: 401, the one code, and **no credential at all**.

    The third leg is the one that matters and the one this file was written to get right the other
    way
    round. A 401 that carried a token would be worse than no defence, because the caller would hold
    a
    working capability the Guardian believed it had refused -- the same argument
    ``AuthorityBoundedTokenIssuer`` makes for consulting the policy before signing rather than
    discarding a token afterwards.
    """
    assert status == HTTP_UNAUTHORIZED, (
        f"{what}: the unauthenticated caller was answered HTTP {status} with {payload!r}. "
        f"ADR-128 requires 401 -- who are you, rather than you may not"
    )
    assert isinstance(payload, dict) and payload.get("error") == UNAUTHENTICATED, (
        f"{what}: the refusal body is {payload!r}; the code a caller is told is {UNAUTHENTICATED!r} "  # noqa: E501 - message
        "and nothing else, because every other response this module emits withholds the detail"
    )
    assert "token" not in payload, f"{what}: the refusal carried a token: {payload!r}"
    assert "jti" not in payload, f"{what}: the refusal carried a jti: {payload!r}"


# ------------------------------------------------------------------------------------------------
# The defence (ADR-128): the four cases this file used to demonstrate the opposite of
# ------------------------------------------------------------------------------------------------


def test_the_token_endpoint_refuses_an_unauthenticated_caller(harness: GuardianHarness) -> None:
    """The bare statement of the defence, and the inverse of this file's first case.

    There is no authorization header, no client certificate, no credential of any kind in this
    request -- the ASGI scope carries a client address and a JSON body and nothing else -- and the
    Guardian answers 401 with one structured code and mints nothing. The request body is the *same*
    well-formed body the old case sent, which is what makes this the same case rather than a new
    one.
    """
    _assert_refused_unauthenticated(
        *harness.issue_token(_issue_body(), bearer=None),
        what="unauthenticated mint",
    )


def test_the_token_endpoint_refuses_a_credential_it_cannot_establish(
    harness: GuardianHarness,
) -> None:
    """A bearer the gate does not accept is refused exactly as an absent one is.

    The route cannot tell a forged credential from a missing one, and must not: the difference is
    between the caller being told "that credential is not valid" and being told "credentials are
    checked here", which is a map of the surface handed to whoever is probing it. So the response is
    byte-identical, and the assertion is on the response rather than on which branch produced it.

    ``FakeControlPlaneAuthenticator`` accepts one synthetic string and refuses everything else, so
    "a credential it cannot establish" is exactly what any other string is here. What the *real*
    authenticator refuses -- a wrong subject, a wrong audience, an unauthenticated token -- is
    ``guardian/tests/test_control_auth.py``'s subject, against a fake TokenReview API.
    """
    _assert_refused_unauthenticated(
        *harness.issue_token(_issue_body(), bearer="NOT-A-REAL-KEY some other caller's credential"),
        what="wrong credential",
    )
    _assert_refused_unauthenticated(
        *harness.issue_token(_issue_body(), bearer=""),
        what="empty credential",
    )


def test_the_phase_channel_refuses_an_unauthenticated_caller(harness: GuardianHarness) -> None:
    """``POST /v1/phase`` is behind the same gate, and the gate comes first.

    A phase channel anybody may write would be worse than no channel: the declared phase is what
    issuance's ceiling is checked against, so a forged declaration would move the bound on every
    mint
    after it. The route answers 401 whether or not a phase state was supplied, because "you are not
    who this surface serves" is a fact about the caller and not about the Guardian's configuration.
    """
    _assert_refused_unauthenticated(
        *harness.declare_phase(bearer=None),
        what="unauthenticated phase declaration",
    )
    _assert_refused_unauthenticated(
        *harness.declare_phase(bearer="NOT-A-REAL-KEY some other caller's credential"),
        what="wrong credential, phase declaration",
    )


def test_a_mint_with_the_control_plane_credential_succeeds(harness: GuardianHarness) -> None:
    """The other half of the pair, and the control the 401 cases need.

    Without it the three refusals above would also pass against an application in which the control
    plane cannot mint at all -- which is the failure mode ``guardian/tests/conftest.py`` names as
    M3's, restated for a route. The assertion is the whole three-tuple the old first case asserted
    about the unauthenticated body: 200, a ``jti``, and the two claims the body named.

    **The claims are still caller-chosen, and that is now a property of an authenticated caller
    rather than of anybody at all.** The runner names the Supervisor and the Executor; the authority
    policy bounds what the claim may cover; and the three cases below are what a caller cannot move.
    """
    status, payload = harness.issue_token(_issue_body())
    assert status == HTTP_OK, payload
    assert payload["jti"], payload
    assert read_claim(str(payload["token"]), "iss") == SUPERVISOR_ID
    assert read_claim(str(payload["token"]), "sub") == EXECUTOR_ID
    assert harness.control_plane.seen == [CONTROL_PLANE_BEARER], (
        "the route minted without consulting the control-plane gate at all"
    )


def test_the_action_route_still_needs_no_credential(harness: GuardianHarness) -> None:
    """``POST /v1/actions`` is deliberately unchanged, and this asserts it rather than assuming it.

    ADR-128 gates two routes, not three. The agent layer must reach the action surface without a
    standing credential -- that is FR3.1, and it is the property the whole architecture exists to
    demonstrate -- so adding the gate here would have closed the exposure by making mediation
    impossible. A case that only asserted the 401s could not tell a correct gate from one that had
    been extended to the wrong route, and this is the case that tells them apart.
    """
    harness.engine.result = permit_result()
    token = harness.mint()
    harness.submit(
        harness.action_body(token=token, request_id="req-no-gate"),
        label="an action with no control-plane credential",
    ).assert_permitted()
    assert harness.control_plane.seen == [], (
        "the action route consulted the control-plane gate. ADR-128 gates /v1/tokens and /v1/phase "
        "only; /v1/actions is the agent layer's unauthenticated body path"
    )


# ------------------------------------------------------------------------------------------------
# The bounds an authenticated control plane still cannot move
# ------------------------------------------------------------------------------------------------


def test_a_scope_beyond_the_declared_authority_yields_no_token_at_all(
    harness: GuardianHarness,
) -> None:
    """ADR-031's bound, unchanged by ADR-128: refused with a structured code, and nothing signed.

    Authenticated identity and bounded scope are two different controls, and closing the first did
    not
    touch the second. ``authority.rego`` still declares, per phase, the widest verbs, resources and
    namespaces a capability may ever carry, and ``AuthorityBoundedTokenIssuer`` still consults it
    **before** the inner issuer is called.

    Asserting that the body carries no token is the load-bearing half, for the reason
    :func:`_assert_refused_unauthenticated` gives: a refusal that returned 403 *and* a credential
    would be worse than no bound at all, because the caller would hold a working capability the
    Guardian believed it had refused.

    The engine is scripted here; what the real declaration says is ``opa test``'s to check, and
    ``guardian/tests/test_composition.py`` drives the real bundle where the pinned binary is found.
    See this module's docstring for why a Python authority check in this suite would be the second
    policy ``guardian/app/policy.py`` refuses to have.
    """
    harness.issuance_engine.result = deny_default_result()
    status, payload = harness.issue_token(
        _issue_body(
            phase="containment",
            allow={"verbs": ["delete"], "resources": ["secrets"], "namespaces": ["kube-system"]},
        )
    )
    assert status == HTTP_FORBIDDEN, (status, payload)
    assert payload["error"] == "issue_authority_exceeded", payload
    assert "token" not in payload, payload
    assert "jti" not in payload, payload


def test_the_issue_ceiling_is_the_one_bound_a_caller_cannot_move(
    harness: GuardianHarness,
) -> None:
    """The lifetime ceiling holds against every caller, and is refused rather than clamped.

    Worth stating beside the 401s so the defence is not overstated. The issuer applies
    ``security-policy.md`` section 2's ceiling to every request regardless of who sent it, and
      refuses
    rather than truncating. So even the authenticated control plane chooses *what* a token covers
    and
    *whom* it names, but not how long it lives -- which bounds the blast radius in time and in
    nothing
    else.
    """
    status, payload = harness.issue_token(
        _issue_body(ttl_seconds=SUITE_TOKEN_MAX_LIFETIME_SECONDS + 1)
    )
    assert status == HTTP_FORBIDDEN, (status, payload)
    assert payload["error"] == "issue_ttl_above_ceiling", payload

    status, payload = harness.issue_token(_issue_body(ttl_seconds=SUITE_TOKEN_MAX_LIFETIME_SECONDS))
    assert status == HTTP_OK, payload


def test_the_issue_surface_still_refuses_a_body_that_is_not_a_request(
    harness: GuardianHarness,
) -> None:
    """The contract boundary holds here too: an unknown field or a bad phase is a 400, not a token.

    Authentication and validation are different controls, and a 400 here is the second of them
    rather
    than a weaker version of the first. ``TokenIssueRequest`` forbids extras and holds every
    identifier
    to the bounded grammar, so the authenticated control plane is nonetheless writing into a closed
    contract.
    """
    refused = (
        _issue_body(phase="cleanup"),
        _issue_body(supervisor_id="supervisor/../root"),
        _issue_body(schema_version="v99"),
        _issue_body(guardian_mode="G1-LOGONLY"),
        _issue_body(ttl_seconds=0),
    )
    for body in refused:
        status, payload = harness.issue_token(body)
        assert status in (HTTP_BAD_REQUEST, HTTP_FORBIDDEN), (body, status, payload)
        assert "token" not in payload, payload


def test_a_capability_minted_by_the_control_plane_still_needs_policy_to_act(
    harness: GuardianHarness,
) -> None:
    """The boundary that remains, drawn precisely: identity now holds, policy still decides.

    A token minted by the authenticated control plane naming a registered Supervisor, for the
    presenting Executor, in the expected phase and run, is **accepted by the verifier** -- it passes
    group A, group B, group C's binding checks and group D. That is correct and is not a finding:
    the
    caller is the runner, which is the identity ADR-128 established.

    What is left is unchanged and is the point of the assertion pair: a deny-by-default engine
    refuses
    the action, and the reason code says so. Policy is the last thing between a capability and the
    cluster, and it is the thing the evaluation measures.
    """
    harness.engine.result = deny_default_result()
    status, payload = harness.issue_token(
        _issue_body(allow={"verbs": ["patch"], "resources": ["pods"], "namespaces": ["boutique"]})
    )
    assert status == HTTP_OK, payload

    outcome = harness.submit(
        harness.action_body(
            token=str(payload["token"]),
            request_id="req-authenticated-1",
            verb="patch",
            name="paymentservice-7d9f8c",
        ),
        label="control-plane-minted token, refused by policy alone",
    )
    record = outcome.assert_denied(ReasonCode.POLICY_DENY_DEFAULT)
    assert record.iss == SUPERVISOR_ID, (
        "the audit record must still attribute the action to the Supervisor the token names; that is "  # noqa: E501 - message
        "the bound attribution, and it is what both RQ5 measures are computed from"
    )
    assert record.token_jti == payload["jti"]

    # And with a permitting policy the same token authorises the action outright, which is the
    # counterfactual that shows policy is load-bearing on its own here.
    harness.engine.result = permit_result()
    harness.submit(
        harness.action_body(token=str(harness.mint()), request_id="req-authenticated-2"),
        label="control-plane-minted token under a permitting policy",
    ).assert_permitted()
