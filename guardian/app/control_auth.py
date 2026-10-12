r"""Control-plane authentication: who may mint a token and declare a phase (ADR-128, M10).

WHAT THIS MODULE IS
-------------------
``docs/plans/M10-implementation-plan.md`` V17 records the v1 defect this closes: ``POST /v1/tokens``
had no auth dependency, and nothing knew the run's actual phase, so any party with network reach to
the
Guardian's surface (threat-model position P4) could mint a capability naming any Supervisor, and
issuance checked a *self-declared* phase's ceiling.
``guardian/tests/test_token_issuance_exposure.py``
was written as the demonstration of exactly that.

The M10 answer (ADR-128) is not to authenticate the in-process agent nodes -- FR3.1 forbids the
standing per-node credentials that would take -- but to authenticate the one caller that
legitimately
reaches these two surfaces: the runner's control-plane process. The runner presents a ServiceAccount
token, and this module verifies it with a Kubernetes **TokenReview**
(``AuthenticationV1Api.create_token_review``), accepting it only when the API server reports it
authenticated, names the expected subject ``system:serviceaccount:<ns>:runner-control-plane``, and
was
issued for the audience ``guardian-control-plane``. Both values are ``guardian/app/config.py``
settings
with no default; ``docs/protocols/security-policy.md`` section 2.1 owns them.

What this closes and what it leaves open is stated in full in security-policy.md section 6 and
ADR-128
(risk R-15): the caller is now the run's runner process, authenticated per run, and the phase is
runner-declared rather than agent-declared; what remains is that per-node attribution *inside* that
one
runner process is not established, because the whole agent graph runs in it. This module closes the
first and does not pretend to close the second.

WHY THE KUBERNETES CLIENT IS IMPORTED LAZILY, EXACTLY AS THE EXECUTOR IMPORTS IT
--------------------------------------------------------------------------------
``import guardian.app.control_auth`` must succeed on a host with no Kubernetes package: the lint
  job,
the import-time contract guards and the adversarial suite all import ``guardian.app`` and none of
them
has a cluster. So the client import lives inside :meth:`ControlPlaneAuthenticator.from_config`'s
lazily
built API, and the authenticator otherwise takes an injected ``token_review_api`` -- which is what
lets
``guardian/tests/`` drive the real verification logic with a fake API double that has no cluster, on
  the
same seam ``guardian.app.executor`` draws for the same reason. ``guardian/`` is the sole credential
holder (security-policy.md section 1.2), and creating a TokenReview is the one authentication query
that
requires the ``tokenreviews: create`` grant ``guardian/deploy/rbac.yaml`` adds -- never a mutation.

FAIL CLOSED IS THE PROPERTY THAT MATTERS
-----------------------------------------
Every path that cannot *establish* the caller returns ``False``: a missing or non-string bearer, a
TokenReview that raises (the API server unreachable, the token malformed), a review that reports
``authenticated = false``, a subject that is not the expected one, an audience the review does not
confirm. A control-plane surface that admitted a caller it could not verify would be no surface at
all,
so the only reading of "I could not check" is "not authenticated" -- the same posture
``guardian/app/policy.py`` takes when its engine cannot answer.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any, Final, Protocol, runtime_checkable

from guardian.app.config import GuardianConfig, GuardianStartupError

__all__ = [
    "TOKEN_REVIEW_API_VERSION",
    "TOKEN_REVIEW_KIND",
    "ControlPlaneAuthenticator",
    "ControlPlaneVerifier",
    "PhaseState",
]

# The TokenReview resource's wire identity, named once so the body builder and any reader agree.
TOKEN_REVIEW_API_VERSION: Final = "authentication.k8s.io/v1"  # noqa: S105 - API version string, not a credential
TOKEN_REVIEW_KIND: Final = "TokenReview"  # noqa: S105 - a resource kind, not a credential


@runtime_checkable
class ControlPlaneVerifier(Protocol):
    """The one method ``guardian/app/main.py`` needs to gate ``/v1/tokens`` and ``/v1/phase``.

    A protocol rather than the concrete class, so the adversarial suite injects a fake that accepts
    a
    known synthetic bearer without a cluster, exactly as it injects a scripted policy engine. An
    implementation returns ``True`` only when it has *established* the caller, and ``False`` for
    every
    other case, including every failure it cannot classify.
    """

    def authenticate(self, bearer: object) -> bool:
        """Return ``True`` iff ``bearer`` names the expected control-plane identity and audience."""
        ...


def _dict_review_body(token: str, audience: str) -> dict[str, Any]:
    """Build a TokenReview request body as a plain mapping.

    The default builder, used by the injected-API path and by tests. The real ``from_config`` path
    overrides it with one that constructs the Kubernetes client's own ``V1TokenReview`` model,
    because
    the generated ``AuthenticationV1Api.create_token_review`` expects that model rather than a dict.
    The
    body carries the token and the single audience the caller's token must have been issued for --
    the
    API server confirms the audience, so a token minted for another service does not authenticate
    here.
    """
    return {
        "apiVersion": TOKEN_REVIEW_API_VERSION,
        "kind": TOKEN_REVIEW_KIND,
        "spec": {"token": token, "audiences": [audience]},
    }


class ControlPlaneAuthenticator:
    """Verify a control-plane bearer with a Kubernetes TokenReview, subject- and audience-bound.

    ``expected_subject`` and ``expected_audience`` come from
    :class:`~guardian.app.config.GuardianConfig` and have no default there. ``token_review_api`` is
    any
    object exposing ``create_token_review(body)`` -- the real ``AuthenticationV1Api`` in production,
    a
    fake in the suite -- and ``review_builder`` turns a ``(token, audience)`` pair into whatever
    that
    API expects, defaulting to a plain-dict body.

    :meth:`authenticate` is the whole surface, and it fails closed on every path it cannot turn into
    an
    established identity. See the module docstring.
    """

    def __init__(
        self,
        *,
        expected_subject: str,
        expected_audience: str,
        token_review_api: Any,
        review_builder: Callable[[str, str], Any] = _dict_review_body,
    ) -> None:
        if not expected_subject or not expected_audience:
            # A blank expectation would authenticate the wrong caller or none; config.py forbids it
            # upstream, and this restates the invariant where the value is used.
            raise GuardianStartupError(
                "the control-plane authenticator needs a non-empty expected subject and audience; "
                "security-policy.md section 2.1 owns both and guardian/app/config.py requires them"
            )
        self._expected_subject = expected_subject
        self._expected_audience = expected_audience
        self._token_review_api = token_review_api
        self._review_builder = review_builder

    def authenticate(self, bearer: object) -> bool:
        """Return ``True`` only when the API server authenticates ``bearer`` as the expected
        caller."""
        if not isinstance(bearer, str) or not bearer:
            return False
        body = self._review_builder(bearer, self._expected_audience)
        try:
            reviewed = self._token_review_api.create_token_review(body)
        # Deliberately unselective: the API server unreachable, a transport error, a malformed token
        # the client rejects locally -- every one of them is "could not establish the caller", which
        # is
        # not authenticated. A control-plane surface that admitted an unverifiable caller is not
        # one.
        except Exception:
            return False
        status = getattr(reviewed, "status", None)
        if status is None:
            return False
        if not getattr(status, "authenticated", False):
            return False
        user = getattr(status, "user", None)
        if getattr(user, "username", None) != self._expected_subject:
            return False
        # The audience is confirmed when the review echoes one: a token minted for a different
        # audience
        # must not authenticate here even if it names the right subject. When the review reports no
        # audiences at all the request was still audience-scoped in the body above, so the API
        # server
        # already refused a token that did not carry it; None is therefore accepted rather than
        # treated as a failure, but a populated list that omits the audience is refused.
        audiences = getattr(status, "audiences", None)
        if audiences is not None and self._expected_audience not in audiences:
            return False
        return True

    @classmethod
    def from_config(
        cls, config: GuardianConfig, *, token_review_api: Any | None = None
    ) -> ControlPlaneAuthenticator:
        """Build the production authenticator from ``config``, deferring the cluster client to first
        use.
                ``token_review_api`` is injectable so the suite supplies a fake; when it is absent
                the real
                  API
                is built **lazily**, on the first :meth:`authenticate` call, so assembling a
                Guardian does
                not
                contact a cluster and ``guardian/tests/test_composition.py`` can build one on a host
                with no
                Kubernetes package. The Kubernetes import lives inside the lazy client for the
                reason the
                module
                docstring gives -- the same discipline ``guardian/app/executor.py`` applies to its
                own
                client.
        """
        if token_review_api is not None:
            return cls(
                expected_subject=config.control_plane_subject,
                expected_audience=config.control_plane_audience,
                token_review_api=token_review_api,
            )
        return cls(
            expected_subject=config.control_plane_subject,
            expected_audience=config.control_plane_audience,
            token_review_api=_LazyTokenReviewApi(),
            review_builder=_client_review_body,
        )


class _LazyTokenReviewApi:
    """The real ``AuthenticationV1Api``, imported and configured on first use, then reused.

    Deferring construction is what keeps :meth:`ControlPlaneAuthenticator.from_config` free of any
    cluster contact at assembly time. The first ``create_token_review`` loads the in-cluster
    configuration and builds the client; a failure to do either propagates and is caught by
    :meth:`ControlPlaneAuthenticator.authenticate`, which reads it as "could not establish the
    caller".
    """

    def __init__(self) -> None:
        self._api: Any | None = None
        self._lock = threading.Lock()

    def _resolve(self) -> Any:
        if self._api is None:
            with self._lock:
                if self._api is None:
                    # Function-scoped import, exactly as guardian/app/executor.py imports its
                    # client:
                    # `import guardian.app.control_auth` must succeed with no Kubernetes package.
                    from kubernetes import client
                    from kubernetes import config as kube_config

                    kube_config.load_incluster_config()
                    self._api = client.AuthenticationV1Api()
        return self._api

    def create_token_review(self, body: Any) -> Any:
        return self._resolve().create_token_review(body)


def _client_review_body(token: str, audience: str) -> Any:
    """Build a ``V1TokenReview`` for the real client, importing it lazily.

    Reached only on the production path, after :class:`_LazyTokenReviewApi` has already established
    that
    the Kubernetes package is present, so the import here cannot be the thing that makes an offline
    ``guardian.app`` import fail.
    """
    from kubernetes import client

    return client.V1TokenReview(spec=client.V1TokenReviewSpec(token=token, audiences=[audience]))


class PhaseState:
    """The run's current phase, declared by the control plane and read by the issuance path (V17).

    ``POST /v1/phase`` records the phase the runner has moved the run into; issuance then bounds a
      mint
    to that phase (``guardian/policies/issuance.rego``'s ``deny_phase_not_current``, reading
    ``guardian.declared_phase`` in the input ``guardian/app/policy.py`` builds). Before any phase is
    declared the current phase is ``None``, which constrains nothing -- the same
    development-vs-campaign
    posture a null ``guardian.run_id`` takes -- so a Guardian that no runner has driven still mints
    within the declared authority rather than refusing every request.

    Mutable and lock-guarded because FastAPI serves ``/v1/phase`` and ``/v1/tokens`` concurrently: a
    phase declaration and a mint that read a torn value would be a race on the very state the phase
    channel exists to make authoritative.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._run_id: str | None = None
        self._phase: str | None = None

    def declare(self, run_id: str, phase: str) -> None:
        """Record that the run has moved into ``phase``."""
        with self._lock:
            self._run_id = run_id
            self._phase = phase

    @property
    def current_phase(self) -> str | None:
        """The phase last declared, or ``None`` when none has been."""
        with self._lock:
            return self._phase

    @property
    def run_id(self) -> str | None:
        """The run id of the last declaration, or ``None``."""
        with self._lock:
            return self._run_id
