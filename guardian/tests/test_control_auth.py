r"""``ControlPlaneAuthenticator``: who may mint a token and declare a phase (ADR-128, M10 WS-4).

WHAT THIS MODULE IS
-------------------
``docs/plans/M10-implementation-plan.md`` section 1 records V17: "Token issuance unauthenticated;
phase self-declared" -- ``POST /v1/tokens`` had no auth dependency at all, and issuance checked the
*declared* phase's ceiling, so anything with network reach to the Guardian could mint a capability
naming any Supervisor. The fix is ``guardian/app/control_auth.py``: a presented bearer is verified
with a Kubernetes **TokenReview** and accepted only when the API server reports it authenticated,
names
the subject ``system:serviceaccount:<ns>:runner-control-plane``, and confirms the audience
``guardian-control-plane``.

This file is that module's test, and it is split the way the mechanism splits:

* **The verification logic** is driven against a fake TokenReview API, so the real
  ``authenticate`` runs -- subject matching, audience matching, and every fail-closed branch -- with
  no cluster, on the same seam ``guardian/app/executor.py`` draws for the same reason.
* **The route gate** is driven through the production ``Mediator``/``create_app`` assembly, because
  the property that matters is about a *route*: ``/v1/tokens`` and ``/v1/phase`` answer 401 to a
  caller it cannot establish, and ``/v1/actions`` does not ask.

``/v1/actions`` BEING UNCHANGED IS ASSERTED, NOT ASSUMED
--------------------------------------------------------
ADR-128 gates two routes, not three. The agent layer must reach the action surface with no standing
credential -- that is FR3.1 and the property the architecture exists to demonstrate -- so extending
the gate to ``/v1/actions`` would have closed the exposure by making mediation impossible. A suite
that
only counted 401s could not tell the correct gate from the over-broad one, so the last case submits
a
real action with no credential anywhere in the request and asserts the full triple (permitted, with
the permit reason code, and present in a chain that still verifies).

THE DEFAULT IS 401, AND THAT IS A SEPARATE CLAIM FROM "A BAD BEARER IS REFUSED"
------------------------------------------------------------------------------
A Guardian assembled **without** an authenticator answers 401 on both control-plane routes, because
"this Guardian cannot establish who is calling" is not the same statement as "you are admitted". The
case is written against ``create_app`` directly with no authenticator named, because that is the
configuration a reader of ``composition.py`` would otherwise assume cannot happen.

NO CLUSTER, NO TOKEN, NO KEY
----------------------------
Nothing here mints, verifies or signs anything. The bearers are obviously synthetic strings,
prefixed
as ``guardian/tests/harness.py``'s ``CONTROL_PLANE_BEARER`` is, and the TokenReview double answers a
question rather than performing an authentication -- exactly as ``ScriptedPolicyEngine`` returns a
canned answer rather than deciding, and for the same stated reason.
"""

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from guardian.app.config import GuardianStartupError  # noqa: E402
from guardian.app.control_auth import (  # noqa: E402
    TOKEN_REVIEW_API_VERSION,
    TOKEN_REVIEW_KIND,
    ControlPlaneAuthenticator,
    PhaseState,
)
from guardian.app.main import (  # noqa: E402
    ERROR_UNAUTHENTICATED,
    PHASE_PATH,
    TOKENS_PATH,
    create_app,
)
from guardian.tests.harness import (  # noqa: E402
    CONTROL_PLANE_AUDIENCE,
    CONTROL_PLANE_BEARER,
    CONTROL_PLANE_SUBJECT,
    DEFAULT_ALLOW,
    EXECUTOR_ID,
    PHASE,
    RUN_ID,
    SUPERVISOR_ID,
    FakeControlPlaneAuthenticator,
    call_asgi,
    make_harness,
    permit_result,
)

HTTP_OK = 200
HTTP_UNAUTHORIZED = 401

# A second synthetic bearer, for the "a credential the gate does not accept" cases. Obviously not a
# credential of any format; the point is only that it is not the one the gate was built for.
OTHER_BEARER = "NOT-A-REAL-KEY a second synthetic control-plane bearer, for the refusal cases"

# A sentinel rather than ``None``: ``username=None`` is a *review* that reports no user (which the
# authenticator must refuse), while omitting ``user`` entirely is a review shaped unlike the real
# one.
_ABSENT = object()


# ------------------------------------------------------------------------------------------------
# The TokenReview double
# ------------------------------------------------------------------------------------------------


@dataclass
class _ReviewUser:
    """The identity block a TokenReview reports back -- the ``UserInfo`` the client models as an
    object with a ``username`` attribute.
    """

    username: str | None = None


@dataclass
class _ReviewStatus:
    """The ``status`` block of a TokenReview, as the generated client models it.

    ``user`` is a nested object rather than a bare ``username``, because that is the shape the
    Kubernetes client builds and the one ``authenticate`` reads: a double that flattened it would
    pass
    this suite and fail against a real API server, which is the failure mode a hand-written double
    has
    by construction.
    """

    authenticated: bool
    user: _ReviewUser | None = None
    audiences: list[str] | None = None


@dataclass
class _Review:
    """A whole TokenReview response."""

    status: _ReviewStatus


@dataclass
class FakeTokenReviewApi:
    """Answers ``create_token_review`` with a fixed review, and records the bodies it was handed.

    Exposes exactly the one method ``ControlPlaneAuthenticator`` calls, and records every request so
    a
    case can assert that the audience was put **in the request** rather than only checked afterwards
    -- the API server is what confirms an audience, so a token minted for another service is refused
    by the API server and never reaches the comparison below.
    """

    review: _Review
    raises: bool = False
    requests: list[Any] = field(default_factory=list)

    def create_token_review(self, body: Any) -> Any:
        """Record ``body`` and return the configured review, or raise when told to."""
        self.requests.append(body)
        if self.raises:
            raise RuntimeError("the API server is unreachable")
        return self.review


def _authenticator(
    *,
    subject: str = CONTROL_PLANE_SUBJECT,
    audience: str = CONTROL_PLANE_AUDIENCE,
    username: object = CONTROL_PLANE_SUBJECT,
    audiences: list[str] | None = None,
    authenticated: bool = True,
    raises: bool = False,
) -> tuple[ControlPlaneAuthenticator, FakeTokenReviewApi]:
    """Build a real authenticator over a fake API, and return both so the request can be
    inspected."""
    api = FakeTokenReviewApi(
        review=_Review(
            status=_ReviewStatus(
                authenticated=authenticated,
                user=None if username is _ABSENT else _ReviewUser(username=username),
                audiences=audiences,
            )
        ),
        raises=raises,
    )
    return (
        ControlPlaneAuthenticator(
            expected_subject=subject, expected_audience=audience, token_review_api=api
        ),
        api,
    )


# ------------------------------------------------------------------------------------------------
# The verification logic
# ------------------------------------------------------------------------------------------------


def test_a_valid_control_plane_bearer_is_accepted() -> None:
    """The positive case, with both conditions satisfied: authenticated, right subject, audience.

    Driven against the real ``authenticate`` over a fake API, so this is the module's own comparison
    and not a restatement of it. The control is load-bearing: every case below is a refusal, and a
    suite of refusals alone is satisfied by an authenticator that refuses everything.
    """
    authenticator, api = _authenticator(audiences=[CONTROL_PLANE_AUDIENCE])
    assert authenticator.authenticate(CONTROL_PLANE_BEARER) is True

    body = api.requests[0]
    assert body["kind"] == TOKEN_REVIEW_KIND
    assert body["apiVersion"] == TOKEN_REVIEW_API_VERSION
    assert body["spec"]["token"] == CONTROL_PLANE_BEARER
    assert body["spec"]["audiences"] == [CONTROL_PLANE_AUDIENCE], (
        "the audience must be asked for in the request: the API server is what confirms it, and a "
        "token minted for another service is refused there rather than here"
    )


def test_a_bearer_naming_the_wrong_subject_is_rejected() -> None:
    """Authenticated, correct audience, wrong subject -- refused.

    The subject is the whole of the control: ``system:serviceaccount:<ns>:runner-control-plane`` is
    the
    one identity security-policy.md section 2.1 names, and a token that authenticates some *other*
    ServiceAccount is a credential this surface must not serve. A reader's objection -- that a
    ServiceAccount
    is a ServiceAccount -- is the answer in the next line: the ServiceAccount carries no RBAC
    bindings
    precisely so that being a ServiceAccount confers nothing.
    """
    authenticator, _api = _authenticator(
        username="system:serviceaccount:boutique:compromised-pod",
        audiences=[CONTROL_PLANE_AUDIENCE],
    )
    assert authenticator.authenticate(CONTROL_PLANE_BEARER) is False


def test_a_bearer_with_the_wrong_audience_is_rejected() -> None:
    """Correct subject, wrong audience -- refused.

    An audience is who the token was minted *for*. A runner token minted for another service
    authenticates the caller perfectly well and still must not drive this surface, which is why the
    audience is both requested and checked: a genuine caller for a different purpose is not a
    control-plane caller.
    """
    authenticator, _api = _authenticator(
        username=CONTROL_PLANE_SUBJECT, audiences=["some-other-guardian-surface"]
    )
    assert authenticator.authenticate(CONTROL_PLANE_BEARER) is False


def test_an_absent_or_non_string_bearer_is_rejected() -> None:
    """Nothing to review, nothing authenticated -- and no TokenReview is even attempted.

    The half that matters is the second: a missing credential must not become a request to the API
    server, or a Guardian under load would be asking its own authenticator to adjudicate the shape
    of
    every unauthenticated probe that arrived.
    """
    authenticator, api = _authenticator()
    for bearer in (None, "", 42, {"token": CONTROL_PLANE_BEARER}, [CONTROL_PLANE_BEARER]):
        assert authenticator.authenticate(bearer) is False, bearer
    assert api.requests == []


@pytest.mark.parametrize(
    ("label", "kwargs"),
    [
        ("not authenticated", {"authenticated": False}),
        ("the review carries no user", {"username": None, "authenticated": True}),
        ("the API server is unreachable", {"raises": True}),
    ],
)
def test_every_unverifiable_path_is_refused(label: str, kwargs: dict[str, Any]) -> None:
    """Fail closed on every path that cannot *establish* the caller, not only on the wrong one.

    The case that matters most is the last. An API server that is unreachable produces no denial and
    no
    evidence -- it produces nothing at all -- and a control-plane surface that admitted a caller it
    could not check is not a control-plane surface. So "I could not check" reads as "not
    authenticated",
    the same posture ``guardian/app/policy.py`` takes when its engine cannot answer.
    """
    authenticator, _api = _authenticator(**kwargs)
    assert authenticator.authenticate(CONTROL_PLANE_BEARER) is False, label


def test_a_review_with_no_audience_list_is_accepted_because_the_request_was_scoped() -> None:
    """``status.audiences`` absent is not a refusal; a populated list without ours is.

    The asymmetry is deliberate and is stated on the method: the review body already carried
    ``spec.audiences``, so the API server refused a token that did not have the audience; a response
    that simply does not echo the list back is older-server behaviour, not a weaker check. Treating
    the absent list as a failure would refuse every caller against such a server, which is a
    fail-closed choice with no security content behind it.
    """
    accepted, _ = _authenticator(audiences=None)
    assert accepted.authenticate(CONTROL_PLANE_BEARER) is True
    refused, _ = _authenticator(audiences=[])
    assert refused.authenticate(CONTROL_PLANE_BEARER) is False


def test_an_authenticator_with_no_expected_identity_refuses_to_be_built() -> None:
    """A blank subject or audience would authenticate the wrong caller, or none -- so it is refused.

    ``GuardianConfig`` requires both settings with no default, so this is unreachable through the
    composition root. It is here because this is the enforcement path: the cost of the check is one
    comparison, and the day a member is added without a branch the failure should be a refusal to
    start rather than an authenticator that compares an empty string to whatever it is handed.
    """
    for subject, audience in (("", CONTROL_PLANE_AUDIENCE), (CONTROL_PLANE_SUBJECT, "")):
        with pytest.raises(GuardianStartupError, match="non-empty expected subject and audience"):
            ControlPlaneAuthenticator(
                expected_subject=subject,
                expected_audience=audience,
                token_review_api=FakeTokenReviewApi(review=_Review(_ReviewStatus(True))),
            )


# ------------------------------------------------------------------------------------------------
# The route gate
# ------------------------------------------------------------------------------------------------


def _issue_body() -> dict[str, Any]:
    """A well-formed ``POST /v1/tokens`` body, built the way the runner builds one."""
    return {
        "supervisor_id": SUPERVISOR_ID,
        "executor_id": EXECUTOR_ID,
        "run_id": RUN_ID,
        "phase": PHASE,
        "allow": DEFAULT_ALLOW.as_mapping(),
        "ttl_seconds": None,
        "schema_version": "v1",
    }


def _post(app, path: str, body: dict[str, Any], *, bearer: str | None) -> tuple[int, Any]:
    """POST ``body`` with an optional control-plane credential, and return ``(status, payload)``."""
    headers = None if bearer is None else {"authorization": f"Bearer {bearer}"}
    return call_asgi(app, path, json.dumps(body).encode("utf-8"), headers=headers)


def _assert_401(status: int, payload: Any, *, what: str) -> None:
    """A control-plane refusal: 401, one structured code, and nothing minted."""
    assert status == HTTP_UNAUTHORIZED, (
        f"{what}: answered HTTP {status} with {payload!r}. ADR-128 requires 401 -- who are you, "
        "rather than you may not"
    )
    assert payload == {"error": ERROR_UNAUTHENTICATED}, (
        f"{what}: the refusal body is {payload!r}. It is one fixed code from the closed vocabulary, "  # noqa: E501 - message
        "because every other response on this surface withholds the detail from a hostile caller"
    )


@pytest.mark.parametrize("path", (TOKENS_PATH, PHASE_PATH))
def test_the_control_plane_routes_answer_401_by_default(tmp_path: Path, path: str) -> None:
    """**The default is 401** -- an app built with no authenticator names, on both routes.

    This is the configuration ``create_app``'s own docstring describes, and the one a reader of the
    composition root would otherwise assume cannot arise. It is the strongest form of the claim: not
    "a bad bearer is refused" but "a Guardian that cannot check anybody refuses everybody", which is
    the only reading of "I could not establish the caller" that does not eventually admit one.
    """
    harness = make_harness(tmp_path)
    app = create_app(mediator=harness.mediator, token_issuer=harness.assembled.token_issuer)
    body = (
        _issue_body()
        if path == TOKENS_PATH
        else {
            "run_id": RUN_ID,
            "phase": PHASE,
            "schema_version": "v1",
        }
    )
    for bearer in (None, OTHER_BEARER):
        _assert_401(
            *_post(app, path, body, bearer=bearer), what=f"default gate, {path}, {bearer!r}"
        )


def test_a_phase_route_without_a_phase_state_is_503_once_the_caller_is_established(
    tmp_path: Path,
) -> None:
    """Authenticated, and this Guardian does not offer the channel: 503, not 401 and not 404.

    The distinction matters to the caller: 401 says "not you", 404 would say "no such URL" and send
    a
    runner looking for a route that exists, and 503 says "ask again later", which is what a Guardian
    assembled without a ``PhaseState`` actually is. And the 401 still comes first, so the order is
    asserted too -- a 503 for an unestablished caller would leak which routes this process has.
    """
    harness = make_harness(tmp_path)
    app = create_app(
        mediator=harness.mediator,
        token_issuer=harness.assembled.token_issuer,
        control_plane_authenticator=FakeControlPlaneAuthenticator(),
    )
    body = {"run_id": RUN_ID, "phase": PHASE, "schema_version": "v1"}
    _assert_401(*_post(app, PHASE_PATH, body, bearer=None), what="no phase state, no credential")
    status, payload = _post(app, PHASE_PATH, body, bearer=CONTROL_PLANE_BEARER)
    assert status == 503, (status, payload)
    assert payload == {"error": "phase_channel_unavailable"}


def test_an_established_caller_may_declare_a_phase_and_the_issuance_path_can_read_it(
    tmp_path: Path,
) -> None:
    """The channel does what it exists for: the declaration becomes readable state.

    Asserted on the ``PhaseState`` object rather than through issuance, because
    ``guardian/policies/issuance.rego``'s ``deny_phase_not_current`` is a Rego behaviour and
    ``guardian/tests/test_composition.py`` plus ``opa test`` own it -- a Python reimplementation of
      the
    rule here would be the second policy ``guardian/app/policy.py`` refuses to have. What is
    testable
    without Rego is the seam: a declared phase is readable, it is the one just declared, and a
    second
    declaration replaces it rather than accumulating.
    """
    harness = make_harness(tmp_path)
    state = PhaseState()
    app = create_app(
        mediator=harness.mediator,
        token_issuer=harness.assembled.token_issuer,
        control_plane_authenticator=harness.control_plane,
        phase_state=state,
    )
    assert state.current_phase is None
    assert state.run_id is None

    for phase in ("containment", "eradication"):
        status, payload = _post(
            app,
            PHASE_PATH,
            {"run_id": RUN_ID, "phase": phase, "schema_version": "v1"},
            bearer=CONTROL_PLANE_BEARER,
        )
        assert status == HTTP_OK, (phase, status, payload)
        assert payload == {"run_id": RUN_ID, "phase": phase, "schema_version": "v1"}
        assert state.current_phase == phase
        assert state.run_id == RUN_ID


def test_a_phase_declaration_that_is_not_a_declaration_is_a_400(tmp_path: Path) -> None:
    """The contract boundary, after the gate: a fifth phase, an extra key, a wrong version.

    Ordered after the gate deliberately. A 400 for a body the caller was not entitled to send would
    be
    a second, weaker answer to the same request, and the weaker one is the one a reader would act
    on.
    """
    harness = make_harness(tmp_path)
    app = create_app(
        mediator=harness.mediator,
        token_issuer=harness.assembled.token_issuer,
        control_plane_authenticator=harness.control_plane,
        phase_state=PhaseState(),
    )
    for body in (
        {"run_id": RUN_ID, "phase": "cleanup", "schema_version": "v1"},
        {"run_id": RUN_ID, "phase": PHASE, "schema_version": "v99"},
        {"run_id": RUN_ID, "phase": PHASE, "schema_version": "v1", "guardian_mode": "G1-LOGONLY"},
        {"phase": PHASE, "schema_version": "v1"},
    ):
        status, payload = _post(app, PHASE_PATH, body, bearer=CONTROL_PLANE_BEARER)
        assert status == 400, (body, status, payload)
        assert payload == {"error": "request_malformed"}, (body, payload)


def test_the_tokens_route_answers_401_to_an_unestablished_caller_and_200_to_the_control_plane(
    tmp_path: Path,
) -> None:
    """The two ends of the gate on ``/v1/tokens``, through the production assembly.

    The 200 half is the control the 401 half needs: an application that minted nothing at all would
    satisfy every refusal case in this file, and the property being defended is that the *right*
    caller can still work.
    """
    harness = make_harness(tmp_path)
    app = harness.app
    _assert_401(*_post(app, TOKENS_PATH, _issue_body(), bearer=None), what="no credential")
    _assert_401(
        *_post(app, TOKENS_PATH, _issue_body(), bearer=OTHER_BEARER), what="wrong credential"
    )
    status, payload = _post(app, TOKENS_PATH, _issue_body(), bearer=CONTROL_PLANE_BEARER)
    assert status == HTTP_OK, (status, payload)
    assert payload["jti"] and payload["token"]


def test_the_action_route_is_unchanged_and_needs_no_credential(tmp_path: Path) -> None:
    """``POST /v1/actions`` asks nobody. Asserted with the full triple, not with a status code.

    The strongest form available without a cluster: a permitted action, a structured permit reason
    code, and a chain that still verifies. A gate extended to this route would fail here; so would a
    gate that merely returned 200 without deciding, which is why the triple is the assertion.
    """
    harness = make_harness(tmp_path)
    harness.engine.result = permit_result()
    token = harness.mint()
    outcome = harness.submit(
        harness.action_body(token=token, request_id="req-control-auth-1"),
        label="an action with no control-plane credential anywhere in the request",
    )
    outcome.assert_permitted()
    assert harness.control_plane.seen == [], (
        "the action route consulted the control-plane gate. ADR-128 gates /v1/tokens and /v1/phase "
        "only; /v1/actions is the agent layer's unauthenticated body path, and gating it would make "  # noqa: E501 - message
        "mediation impossible (FR3.1)"
    )
