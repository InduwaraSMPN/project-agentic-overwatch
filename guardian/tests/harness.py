r"""The wiring the adversarial suite runs on: the production composition root, and four doubles.

WHAT THIS MODULE IS, AND THE GAP IT NO LONGER FILLS
----------------------------------------------------
**This module used to be the composition root, and that was the defect it recorded about itself.**
``guardian/app/`` and ``guardian/token/`` were both landed and nothing connected them:
``guardian.app.mediation`` declared four collaborator protocols and
``guardian.app.main.create_app`` took an already-assembled ``Mediator``, which no module in the
repository assembled. The adapters lived here, in a test suite, and this docstring said in as many
words that "**the owed work is a real composition root under ``guardian/app/``**".

That work is done. :mod:`guardian.app.composition` assembles the verifier, the issuer, the policy
bundle, both engines, the audit sink and the executor from a
:class:`~guardian.app.config.GuardianConfig` alone, and :class:`GuardianHarness` now **consumes** it
rather than duplicating it. That inversion is the whole point of the task, and the reason is worth
keeping: a seam described in two places is a seam that can be right in the suite and wrong in the
deployed process, and the adversarial cases would go on passing while production wired something
subtly different. What is left here is what a test suite should own -- parameters, identities, the
doubles, and the means to attack.

The two gaps this file recorded are both settled, and how is kept rather than deleted:

*The two modules speak different reason vocabularies.*
``guardian.token.verifier.DenialReason`` spells ``token_expired``;
``guardian.app.models.ReasonCode`` spells ``temporal.expired``. Neither is a superset of the other.
``DENIAL_REASON_TO_REASON_CODE`` is the translation and it now lives in
:mod:`guardian.app.composition`, still with **no default arm**; ``test_token_contract_seam.py``
asserts it is total against the module that owns it, so a member added to either enum breaks the
build instead of quietly landing in whatever an ``else`` said.

*The verifier needed two facts an ``ActionRequest`` did not carry.*
``TokenVerifier.verify`` requires ``expected_phase`` and ``expected_subject``, and the request
contract had neither. This module resolved that by making both **start-time configuration with no
default** -- fail-closed, and correct for a test, at the cost this docstring stated plainly: a
Guardian configured that way verifies for exactly one Executor in exactly one phase, so a deployment
serving four phases needs four configurations. It also named the fix: "**the architecture section 3
amendment this points at is an executor identity on the request**".

That amendment is what landed. ``ActionRequest`` is at ``v2`` and carries ``executor_id`` and
``phase``; the two expectations are per-request arguments; one Guardian serves a whole run; and
:meth:`GuardianHarness.action_body` emits both, with ``request_phase`` and ``request_executor_id``
naming what *this harness's requests declare* rather than what some Guardian was configured to
expect. The honest limit that arrives with it is
:class:`~guardian.app.models.ActionRequest`'s to state and is not restated here: both fields are
agent-declared, so the check is attribution rather than authentication.

WHAT THE DOUBLES ARE ALLOWED TO DO
-----------------------------------
``guardian/app/policy.py`` states the rule these obey: "A decision procedure implemented twice, once
in Rego and once in Python 'for the tests', is two policies whose divergence nobody would notice
until an evaluation depended on it." So :class:`ScriptedPolicyEngine` does not decide anything. It
returns a canned answer fixed by the test, in the way
``guardian.app.mediation.FakeActionExecutor`` returns a canned execution outcome, and it records the
input documents it was handed so that group E can assert directly on what policy was and was not
shown. It never inspects a document to choose a result. The three failure engines below have no
permit path at all.

**That rule binds the authority entrypoint exactly as it binds the action one, and the consequence
is worth being explicit about.** A Guardian assembled here gets a scripted engine for *both*
questions, so the suite's default answer to "may this capability be minted" is a canned permit and
the pytest cases below assert the **wiring** -- that the policy is consulted before anything is
signed, that a refusal carries ``issue_authority_exceeded``, that a refused mint produces no token.
What ``authority.rego`` actually declares is tested where it lives, by ``opa test`` over
``guardian/policies/issuance_test.rego``, at the 100% pass and 100% coverage floor
``scripts/guardian_test.sh`` holds. Writing a Python authority check here to make the pytest cases
"real" would be the second policy that rule forbids, and it would be the one the suite trusted.

``guardian/tests/test_composition.py`` closes the remaining distance in the one way that does not
create a second policy: where the pinned ``opa`` binary can be located, it drives the **real**
engine over the **real** bundle, and where it cannot it skips with a named reason.

THE NUMBERS, AND WHY ONLY ONE OF THEM MIRRORS THE PROTOCOL
------------------------------------------------------------
``docs/protocols/security-policy.md`` section 2 owns the token lifetime, the per-phase ceiling, the
replay cache's size and its window. ``.agents/rules/00-source-of-truth.md`` allows each exactly one
home, and ``guardian/app/config.py`` carries no default for any of them precisely so that the runner
supplies them from that file. This suite is not the runner and does not restate them: it declares
its own, small and obviously synthetic, beside :data:`SUITE_PARAM_STATUS` -- the same sentinel
``guardian/audit/fixtures/corpus.json`` uses for the identical reason. A three-second token and a
four-entry cache are what make the expiry and eviction cases fast and deterministic, and neither is
a claim about what section 2 says.

The algorithm is the exception, and the exception is principled. It is not a tunable: the ``alg:
none`` and algorithm-confusion cases are *about* the allowlist holding exactly one specific
algorithm, and running them against a substituted value would be running a different test. So
:data:`ALGORITHM` mirrors section 2 -- and ``test_token_contract_seam.py`` parses section 2 and
asserts it still names this value, which is the ``monitor/tests/test_limits_match_protocol.py``
pattern in miniature: the protocol stays the owner and the mirror is proved rather than trusted.

NO REAL-LOOKING CREDENTIAL APPEARS ANYWHERE
--------------------------------------------
:data:`SYNTHETIC_SIGNING_MATERIAL` and :data:`ALTERNATE_SIGNING_MATERIAL` begin by saying what they
are. Neither resembles any credential format: not a base64 blob, not a hex digest, not a vendor
prefix, not a PEM block. That matters twice over. ``.agents/rules/10-guardian-first.md`` forbids the
Guardian's real signing key from being copied into tests at all, so what is here has to be visibly
not it; and ``guardian/audit/chain.py``'s pre-hash scrub redacts high-entropy and credential-shaped
strings, so a realistic-looking fixture value would be silently rewritten inside the audit chain and
the tests reading it would compare against something else than they wrote.
"""

from __future__ import annotations

import asyncio
import base64
import json
import threading
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

import jwt
import pytest
from fastapi import FastAPI
from guardian.app.composition import build_guardian
from guardian.app.config import GuardianConfig
from guardian.app.main import (
    ACTIONS_PATH,
    PHASE_DECLARATION_SCHEMA_VERSION,
    PHASE_PATH,
    TOKENS_PATH,
)
from guardian.app.models import (
    ACTION_REQUEST_SCHEMA_VERSION,
    ActionResult,
    AuditRecord,
    Decision,
    ExecutionRecord,
    GuardianMode,
    ReasonCode,
    RunStartRecord,
)
from guardian.app.policy import PolicyEngineTimeout
from guardian.audit.chain import read_chain
from guardian.audit.record_types import is_execution, is_run_start
from guardian.audit.verify import ChainReport, verify_chain
from guardian.token.issuer import CAPABILITY_TOKEN_SCHEMA_VERSION
from guardian.token.replay import ReplayCache
from guardian.token.verifier import AllowClaim

REPO_ROOT: Final = Path(__file__).resolve().parents[2]

# --------------------------------------------------------------------------------------------
# Suite parameters
#
# The sentinel is guardian/audit/fixtures/corpus.json's and carries its meaning: these are this
# suite's own test parameters and not one of them is a protocol value. See the module docstring.
# --------------------------------------------------------------------------------------------

SUITE_PARAM_STATUS: Final = "adversarial-suite test parameters, NOT protocol values"

# Small enough that an expiry case is one clock advance away, and large enough that a token minted
# at t and presented at t is comfortably live. The ceiling is above the default, which is the one
# relation TokenParameters enforces; the group B ceiling case is written in terms of that relation
# and not in terms of either number.
SUITE_TOKEN_LIFETIME_SECONDS: Final = 3
SUITE_TOKEN_MAX_LIFETIME_SECONDS: Final = 9

# Four entries and an eleven-second window. Both halves are needed: the eviction-replay case floods
# past the size bound and then presents a jti the *window* still covers, which is the only way to
# tell an implementation of section 2's "whichever larger" from a size-only cache that would have
# dropped it. A four-entry cache makes the flood four requests long instead of ten thousand.
SUITE_REPLAY_CACHE_ENTRIES: Final = 4
SUITE_REPLAY_CACHE_WINDOW_SECONDS: Final = 11

# Generous relative to a canned in-process answer, so no case can fail for being slow on a loaded
# CI runner. The timeout cases set their own far smaller bound locally.
SUITE_POLICY_TIMEOUT_SECONDS: Final = 5.0

# An arbitrary fixed instant, so that `ts` in every audit record is a value the suite chose. Not
# "now": a suite whose records carry the wall clock cannot compare two runs field by field, which
# is exactly what the G0-versus-G1 diff has to do.
SUITE_EPOCH_SECONDS: Final = 1_800_000_000

# --------------------------------------------------------------------------------------------
# The one mirrored section 2 value
# --------------------------------------------------------------------------------------------

# security-policy.md section 2: "algorithm HS256". Mirrored rather than parsed because the
# single-algorithm allowlist is the mechanism under test in two group A cases, and proved rather
# than trusted: test_token_contract_seam.py reads section 2 and asserts it still says this.
ALGORITHM: Final = "HS256"

# --------------------------------------------------------------------------------------------
# Identities
# --------------------------------------------------------------------------------------------

RUN_ID: Final = "RUN-G0-FULL-SCN01-INJA-S07"
OTHER_RUN_ID: Final = "RUN-G0-FULL-SCN01-INJA-S08"

SUPERVISOR_ID: Final = "supervisor-containment"
UNREGISTERED_SUPERVISOR_ID: Final = "supervisor-not-registered"

EXECUTOR_ID: Final = "executor-containment-01"
OTHER_EXECUTOR_ID: Final = "executor-containment-02"

PHASE: Final = "containment"
OTHER_PHASE: Final = "eradication"

NAMESPACE: Final = "boutique"

# ADR-128 (M10): the control-plane identity and audience this suite's Guardians expect, and the
# bearer
# the suite presents to reach the authenticated `POST /v1/tokens` and `POST /v1/phase` surfaces. The
# subject spelling matches guardian/deploy/rbac.yaml's runner-control-plane ServiceAccount. The
# bearer
# is obviously synthetic (SYNTHETIC_MARKER-prefixed so test_suite_integrity's credential scan skips
# it)
# and authenticates only through this suite's FakeControlPlaneAuthenticator, never against any
# cluster.
CONTROL_PLANE_SUBJECT: Final = "system:serviceaccount:guardian:runner-control-plane"
CONTROL_PLANE_AUDIENCE: Final = "guardian-control-plane"
CONTROL_PLANE_BEARER: Final = "NOT-A-REAL-KEY synthetic control-plane bearer for this suite only"

DEFAULT_ALLOW: Final = AllowClaim(
    verbs=("get", "list", "patch"),
    resources=("pods", "deployments"),
    namespaces=(NAMESPACE,),
)

# The rule id a scripted permit names. Colon-separated, never dotted: guardian/app/models.py's
# IDENTIFIER_PATTERN admits ':' and refuses '.', so a dotted rule id would be rejected by the audit
# record itself and a permit carrying one could never be written.
PERMIT_RULE_ID: Final = "guardian:read:pods-in-scope"
DENY_RULE_ID: Final = "guardian:deny:delete-outside-scope"

# The rule id the scripted authority engine names when it permits a mint. Spelled the way
# `guardian/policies/issuance.rego` spells its own permit, so a record or a failure message read out
# of this suite names a rule that exists rather than one invented for a fixture.
ISSUANCE_PERMIT_RULE_ID: Final = "guardian:issue:within-declared-authority"

# --------------------------------------------------------------------------------------------
# Synthetic signing material
#
# Both begin with the words that say what they are, both are far longer than HS256's minimum key
# length (RFC 7518 section 3.2, enforced by PyJWT), and neither resembles any credential format.
# See the module docstring for the two separate reasons that matters.
# --------------------------------------------------------------------------------------------

SYNTHETIC_SIGNING_MATERIAL: Final = (
    "NOT-A-REAL-KEY this is synthetic Guardian test material and signs nothing outside this suite"
)
ALTERNATE_SIGNING_MATERIAL: Final = (
    "NOT-A-REAL-KEY this is the other synthetic material, used only to forge a wrong-key signature"
)


# --------------------------------------------------------------------------------------------
# Clock
# --------------------------------------------------------------------------------------------


class SuiteClock:
    """One clock, read by the token service, the replay cache and the audit record's ``ts``.

    A single clock rather than three, so that "the token expired" and "the cache window elapsed"
    are the same statement about the same timeline. Everything that reads time in the Guardian
    takes it by injection, which is what makes the temporal and eviction cases deterministic
    rather than timing-dependent -- rule 20's determinism applied to a test suite.
    """

    def __init__(self, epoch_seconds: int = SUITE_EPOCH_SECONDS) -> None:
        self._epoch = epoch_seconds

    def epoch(self) -> int:
        """Epoch seconds as an integer, the shape the token modules require."""
        return self._epoch

    def instant(self) -> datetime:
        """The same moment as an aware UTC datetime, the shape ``AuditRecord.ts`` requires."""
        return datetime.fromtimestamp(self._epoch, tz=UTC)

    def advance(self, seconds: int) -> None:
        """Move the timeline forward. Never backwards: nothing in the Guardian expects that."""
        if seconds < 0:
            raise ValueError("the suite clock only moves forward")
        self._epoch += seconds


# --------------------------------------------------------------------------------------------
# Policy engine doubles -- canned answers, never a decision procedure
# --------------------------------------------------------------------------------------------


class ScriptedPolicyEngine:
    """Returns the answer the test fixed, and records every input document it was handed.

    It does not read the document to choose the answer, and that restraint is the point:
    ``guardian/app/policy.py`` refuses to implement a decision procedure in Python for the tests,
    because a second policy diverges from the Rego and nobody notices until an evaluation depends on
    it. What this class is for is the other half -- ``seen`` is how group E asserts directly that
    ``justification`` and ``params`` never reached the engine.
    """

    def __init__(self, result: Any = None) -> None:
        self.result: Any = permit_result() if result is None else result
        self.seen: list[Mapping[str, Any]] = []

    def evaluate(self, document: Mapping[str, Any], *, timeout_seconds: float) -> Any:
        """Record the document, ignore the bound, and answer what the test said to answer."""
        del timeout_seconds
        self.seen.append(json.loads(json.dumps(document, default=str)))
        return self.result


class TimingOutPolicyEngine:
    """Raises the timeout the engine contract defines. No permit path."""

    def __init__(self) -> None:
        self.calls = 0

    def evaluate(self, document: Mapping[str, Any], *, timeout_seconds: float) -> Any:
        """Always raise :class:`guardian.app.policy.PolicyEngineTimeout`."""
        del document, timeout_seconds
        self.calls += 1
        raise PolicyEngineTimeout("the scripted engine did not answer within the bound")


class CrashingPolicyEngine:
    """Raises something the engine contract does *not* define. No permit path.

    Separate from :class:`TimingOutPolicyEngine` because the fail-closed claim is only worth
    anything if it also holds for a failure nobody anticipated. ``evaluate_policy`` catches bare
    ``Exception`` and denies; this is what proves it rather than reading it.
    """

    def evaluate(self, document: Mapping[str, Any], *, timeout_seconds: float) -> Any:
        """Always raise a plain ``RuntimeError``."""
        del document, timeout_seconds
        raise RuntimeError("the scripted engine failed in a way the contract does not describe")


class SlowPolicyEngine:
    """Answers *permit*, but only after the configured bound has demonstrably elapsed.

    The one engine whose answer is a permit, and it exists to make the elapsed-time branch of
    ``evaluate_policy`` fail visibly if it is ever removed: if the Guardian did not notice the
    overrun it would return this permit, so the test's denial is evidence the bound was applied.
    The wait is a spin on ``time.monotonic`` rather than a ``sleep`` so it terminates on the clock's
    own advance regardless of its resolution, which on Windows is coarser than on Linux.
    """

    def __init__(self, *, over_by_seconds: float) -> None:
        self.over_by_seconds = over_by_seconds

    def evaluate(self, document: Mapping[str, Any], *, timeout_seconds: float) -> Any:
        """Spin until the bound has been exceeded, then answer permit anyway."""
        del document
        import time

        deadline = time.monotonic() + timeout_seconds + self.over_by_seconds
        while time.monotonic() <= deadline:
            pass
        return permit_result()


class UnavailableReplayCache:
    """A ``jti`` store that cannot answer.

    Fail-closed means an unverifiable single-use claim is not a satisfied one.
    """

    def claim(self, jti: str, *, expires_at: int) -> bool:
        """Always raise, so the verifier denies under ``replay.cache-unavailable``."""
        del jti, expires_at
        raise RuntimeError("the replay cache is unavailable")


class FakeControlPlaneAuthenticator:
    """The suite's stand-in for the TokenReview the real authenticator performs (ADR-128).

    ``guardian/app/control_auth.py`` publishes a ``ControlPlaneVerifier`` protocol precisely so this
    can exist: the real one asks the API server whether a bearer names
    ``system:serviceaccount:<ns>:runner-control-plane`` with audience ``guardian-control-plane``,
      and
    a suite with no cluster cannot ask. So this answers the same one-method question from a fixed
    synthetic string, and -- the property that makes it a double rather than a bypass -- it answers
    **only** that string: every other bearer, and every non-string, is not authenticated. A fake
    that accepted anything would make every 401 case in the suite vacuous, which is the same
    mistake ``guardian/app/mediation.py``'s ``FakeActionExecutor`` avoids by touching nothing.

    ``seen`` records every bearer it was asked about, so a case can assert that a route consulted
      the
    gate at all rather than reaching its handler some other way. ``accepts`` is settable so a case
    can
    make the gate pass or fail independently of the route under test.
    """

    def __init__(self, *, accepts: str = CONTROL_PLANE_BEARER) -> None:
        self.accepts = accepts
        self.seen: list[object] = []

    def authenticate(self, bearer: object) -> bool:
        """Record ``bearer`` and accept it only if it is the one synthetic control-plane string."""
        self.seen.append(bearer)
        return isinstance(bearer, str) and bearer == self.accepts


def permit_result(rule_id: str = PERMIT_RULE_ID) -> dict[str, Any]:
    """The engine result shape ``interpret_policy_result`` treats as a permit."""
    return {"allow": True, "rule_id": rule_id}


def deny_default_result() -> dict[str, Any]:
    """The engine result shape for "no explicit permit rule matched" -- deny-by-default."""
    return {"allow": False}


def explicit_deny_result(rule_id: str = DENY_RULE_ID) -> dict[str, Any]:
    """The engine result shape for an explicit deny rule matching."""
    return {"allow": False, "explicit_deny": True, "rule_id": rule_id}


# --------------------------------------------------------------------------------------------
# Token construction, including the shapes an attacker builds by hand
# --------------------------------------------------------------------------------------------


def claims_payload(**overrides: Any) -> dict[str, Any]:
    """A well-formed, in-scope claim set for this suite, with any claim replaced or removed.

    ``None`` removes a claim rather than setting it to null, because "``exp`` absent" and "``exp``
    is null" are different attacks and group B names the first.
    """
    payload: dict[str, Any] = {
        "iss": SUPERVISOR_ID,
        "sub": EXECUTOR_ID,
        "run_id": RUN_ID,
        "phase": PHASE,
        "allow": DEFAULT_ALLOW.as_mapping(),
        "jti": "jti-suite-0001",
        "iat": SUITE_EPOCH_SECONDS,
        "exp": SUITE_EPOCH_SECONDS + SUITE_TOKEN_LIFETIME_SECONDS,
        "schema_version": CAPABILITY_TOKEN_SCHEMA_VERSION,
    }
    for name, value in overrides.items():
        if value is None:
            payload.pop(name, None)
        else:
            payload[name] = value
    return payload


def sign_claims(payload: Mapping[str, Any], *, material: str = SYNTHETIC_SIGNING_MATERIAL) -> str:
    """Sign ``payload`` with HS256 and the given synthetic material -- the honest mint path."""
    return jwt.encode(dict(payload), material, algorithm=ALGORITHM)


def _b64url(raw: bytes) -> str:
    """Base64url without padding, as RFC 7515 section 2 defines it for a JWS segment."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def craft_compact_jws(
    header: Mapping[str, Any], payload: Mapping[str, Any], signature: bytes = b"forged-signature"
) -> str:
    """Assemble a compact JWS by hand, so a header this repository cannot sign can still be sent.

    Needed for two group A cases that no signing library will produce. ``alg: none`` is unsignable
    by construction, and the algorithm-confusion case needs an ``RS256`` header without an RSA key
    -- ``cryptography`` is not in the pinned runtime set and does not need to be, because the
    attack is defeated by the header allowlist *before* any signature arithmetic happens. Building
    the bytes here is what lets the suite prove that, rather than assuming it.
    """
    segments = [
        _b64url(json.dumps(dict(header), separators=(",", ":")).encode("utf-8")),
        _b64url(json.dumps(dict(payload), separators=(",", ":")).encode("utf-8")),
        _b64url(signature),
    ]
    return ".".join(segments)


# --------------------------------------------------------------------------------------------
# Driving the ASGI application without httpx
# --------------------------------------------------------------------------------------------


def call_asgi(
    app: FastAPI,
    path: str,
    body: bytes,
    *,
    headers: Mapping[str, str] | None = None,
    declare_length: bool = True,
) -> tuple[int, Any]:
    """POST ``body`` to ``path`` on ``app`` and return ``(status, decoded JSON body)``.

    ``fastapi.testclient.TestClient`` needs httpx, which is not in the pinned runtime set and is not
    being added for a test convenience -- ``monitor/tests/__init__.py`` states the rule and the
    reason. The ASGI interface is a documented contract and driving it directly costs twenty lines,
    exercises exactly the same route handlers, and keeps the suite's import surface equal to the
    Guardian's own.

    ``content-length`` is derived from the body unless the caller overrides it, because the oversize
    cases need to send a header that disagrees with what follows it -- and ``declare_length=False``
    omits it entirely, which is the only way to reach ``read_bounded_body``'s streaming bound rather
    than its cheaper declared-length check. Both gates matter: a caller that lies about the length,
    or simply does not state one, must not get further than a caller that tells the truth.
    """
    encoded_headers: list[tuple[bytes, bytes]] = [(b"content-type", b"application/json")]
    supplied = {key.lower(): value for key, value in (headers or {}).items()}
    if declare_length and "content-length" not in supplied:
        encoded_headers.append((b"content-length", str(len(body)).encode("ascii")))
    for key, value in supplied.items():
        encoded_headers.append((key.encode("ascii"), value.encode("ascii")))

    scope: dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "path": path,
        "raw_path": path.encode("ascii"),
        "root_path": "",
        "scheme": "http",
        "query_string": b"",
        "headers": encoded_headers,
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
        raise AssertionError(f"the application sent no response to POST {path}")
    payload = b"".join(
        bytes(message.get("body", b""))
        for message in messages
        if message["type"] == "http.response.body"
    )
    return int(starts[0]["status"]), json.loads(payload.decode("utf-8"))


# --------------------------------------------------------------------------------------------
# One case's outcome, with no way to check only one third of it
# --------------------------------------------------------------------------------------------


class CaseOutcome:
    """What one submitted request produced: the answer, the records it appended, the chain's state.

    The class deliberately publishes no accessor for the decision on its own. Every adversarial case
    in ``docs/milestones/M3-guardian.md``'s Definition of done asserts three things -- denied,
    with a structured reason code, and present in the audit chain -- and the reason all three hold
    is that the third is the one that would be quietly dropped: a denial the audit log does not
    contain fails ``security-policy.md`` section 1.4 and is invisible to T-22's scoring, so an
    unaudited block is worse than an unblocked action, because it is an unblocked action nobody can
    see.

    So :meth:`assert_denied` and :meth:`assert_permitted` are the only exits, each asserts the whole
    triple, and :attr:`record` refuses to answer until one of them has run.
    """

    def __init__(
        self,
        *,
        label: str,
        status: int,
        payload: Any,
        appended: Sequence[AuditRecord],
        report: ChainReport,
    ) -> None:
        self._label = label
        self._status = status
        self._payload = payload
        self._appended = tuple(appended)
        self._report = report
        self._asserted = False

    @property
    def result(self) -> ActionResult:
        """The answered ``ActionResult`` -- only after the triple assertion has run.

        Guarded exactly as :attr:`record` is, and for the same reason. The flag-isolation suite
        needs the ``execution`` block to compare arms, and ADR-023's assertion 2 permits that block
        to differ between G0 and G1; making it reachable only after the triple assertion keeps that
        comparison from becoming a way to inspect an outcome without having checked it.
        """
        return ActionResult.model_validate(self._require_asserted()._payload)

    def _require_asserted(self) -> CaseOutcome:
        """Return ``self``, or raise because nothing has been asserted about this case yet."""
        if not self._asserted:
            raise AssertionError(
                f"{self._label}: the outcome was read before the case asserted anything about it. "
                "Call assert_denied() or assert_permitted() first: every case asserts denied, with "
                "a structured reason code, and present in the audit chain -- all three"
            )
        return self

    @property
    def record(self) -> AuditRecord:
        """The single audit record this case appended -- only after the triple assertion has run."""
        if not self._asserted:
            raise AssertionError(
                f"{self._label}: the audit record was read before the case asserted anything about "
                "it. Call assert_denied() or assert_permitted() first: every case asserts denied, "
                "with a structured reason code, and present in the audit chain -- all three"
            )
        return self._appended[0]

    def _decision(self) -> Decision | None:
        """The answered decision, for :func:`assert_single_winner` only.

        Private, and used from exactly one place in this module. A concurrent case has to *sort* its
        outcomes before it can say which one owes a permit and which owes a denial, and there is no
        way to do that without looking. What there is no way to do is stop after looking: the only
        caller is :func:`assert_single_winner`, which then puts every outcome through the full
        triple assertion, and nothing outside this module can reach it.
        """
        if not isinstance(self._payload, dict) or "decision" not in self._payload:
            return None
        return Decision(self._payload["decision"])

    def assert_denied(self, reason_code: ReasonCode) -> AuditRecord:
        """Assert this case was denied, with ``reason_code``, and audited. Returns the record."""
        return self._assert(Decision.DENY, reason_code)

    def assert_permitted(self, *, rule_id: str = PERMIT_RULE_ID) -> AuditRecord:
        """Assert this case was permitted, naming ``rule_id``, and audited. Returns the record."""
        record = self._assert(Decision.PERMIT, ReasonCode.PERMIT_RULE_ALLOW)
        assert record.policy_rule_id == rule_id, (
            f"{self._label}: permitted by rule {record.policy_rule_id!r}, expected {rule_id!r}"
        )
        return record

    def _assert(self, decision: Decision, reason_code: ReasonCode) -> AuditRecord:
        """The three assertions, in one place so that no case can make fewer than three."""
        assert self._status == 200, (
            f"{self._label}: the Guardian answered HTTP {self._status} with {self._payload!r}. "
            "POST /v1/actions answers 200 with an ActionResult for every decision it reaches; a "
            "different status means no decision was reached and therefore none was audited"
        )
        result = ActionResult.model_validate(self._payload)

        # One: the decision itself.
        assert result.decision is decision, (
            f"{self._label}: decision {result.decision.value!r}, expected {decision.value!r} "
            f"(reason given: {result.reason_code.value!r})"
        )

        # Two: a structured code from the closed vocabulary, never free text. Membership of
        # ReasonCode is guaranteed by ActionResult's own validation above; what is asserted here is
        # that it is the *right* one, and that its threat-model family follows from its own prefix.
        assert result.reason_code is reason_code, (
            f"{self._label}: reason {result.reason_code.value!r}, expected {reason_code.value!r}"
        )
        assert result.reason_code.group is reason_code.group

        # Three: present in the audit chain -- exactly one record, carrying the same decision and
        # the same reason, at the sequence number the answer named, in a chain that still verifies.
        assert len(self._appended) == 1, (
            f"{self._label}: {len(self._appended)} record(s) appended, expected exactly 1. "
            "security-policy.md section 1.4 requires every decision to produce one hash-chained "
            "AuditRecord: none is an unaudited outcome, and two is a decision counted twice"
        )
        record = self._appended[0]
        assert record.decision is decision, f"{self._label}: audited decision {record.decision!r}"
        assert record.reason_code is reason_code, (
            f"{self._label}: audited reason {record.reason_code.value!r}, "
            f"answered reason {result.reason_code.value!r}"
        )
        assert record.seq == result.audit_seq, (
            f"{self._label}: the answer names audit_seq {result.audit_seq} but the record was "
            f"written at seq {record.seq}"
        )
        assert self._report.ok, (
            f"{self._label}: the audit chain does not verify after this case "
            f"({self._report.diagnosis}): {[str(finding) for finding in self._report.findings]}"
        )

        self._asserted = True
        return record


# --------------------------------------------------------------------------------------------
# The harness
# --------------------------------------------------------------------------------------------


class GuardianHarness:
    """One Guardian assembled by the production composition root, and the means to attack it.

    Everything a case needs is reachable from here and nothing is global: each harness owns its own
    audit chain file, its own replay cache and its own clock, so two cases in one pytest session
    cannot see each other's state. That is ``guardian/app/config.py``'s own reason for accepting an
    injectable environment mapping -- the isolation tests build three configurations in one process
    without touching ``os.environ``, which is shared and is the classic source of a test that passes
    alone and fails in a suite.

    **The assembly is :func:`guardian.app.composition.build_guardian`'s, not this class's.**
    Everything below either builds the configuration mapping a runner would supply, or hands the
    composition root one of the five seams it publishes for exactly this purpose: a scripted engine
    for each of the two questions, the suite clock, a small replay cache and a counting ``jti``
    factory. Each of those seams defaults to the real collaborator, so what this harness overrides
    is visible in one constructor and everything it does not override is what a deployed Guardian
    gets.

    Two constructor arguments changed name with ``ActionRequest`` v2 and the rename is the point
    rather than tidying. ``expected_phase`` and ``expected_subject`` used to be what the *Guardian*
    was configured to expect, because the request could not carry them; they are now
    ``request_phase`` and ``request_executor_id``, the values **this harness's requests declare**.
    A case that wants a mismatch states it on the request, which is where a real Executor would
    state it, and no longer needs a differently-configured Guardian to produce one.
    """

    def __init__(
        self,
        *,
        root: Path,
        mode: GuardianMode = GuardianMode.G0_FULL,
        engine: Any = None,
        issuance_engine: Any = None,
        replay_cache: Any = None,
        registered_issuers: Sequence[str] = (SUPERVISOR_ID,),
        request_phase: str = PHASE,
        request_executor_id: str = EXECUTOR_ID,
        run_id: str | None = RUN_ID,
        policy_timeout_seconds: float = SUITE_POLICY_TIMEOUT_SECONDS,
        signing_material: str = SYNTHETIC_SIGNING_MATERIAL,
        control_plane_authenticator: Any = None,
    ) -> None:
        self.root = Path(root)
        self.clock = SuiteClock()
        self.chain_path = self.root / "guardian_audit.jsonl"
        self.bundle_path = write_policy_bundle(self.root / "policies")
        self.request_phase = request_phase
        self.request_executor_id = request_executor_id
        self.engine: Any = ScriptedPolicyEngine() if engine is None else engine
        # The authority entrypoint's double. It answers permit by default, so the issuance surface
        # behaves as it did before the bound existed and every case that is about something else is
        # unaffected; the cases that are about the bound set this attribute. What the real authority
        # policy declares is `opa test`'s to check -- see the module docstring.
        self.issuance_engine: Any = (
            ScriptedPolicyEngine(permit_result(ISSUANCE_PERMIT_RULE_ID))
            if issuance_engine is None
            else issuance_engine
        )
        self.replay_cache: Any = (
            ReplayCache(
                min_entries=SUITE_REPLAY_CACHE_ENTRIES,
                window_seconds=SUITE_REPLAY_CACHE_WINDOW_SECONDS,
                clock=self.clock.epoch,
            )
            if replay_cache is None
            else replay_cache
        )
        # ADR-128. The control-plane gate on POST /v1/tokens and POST /v1/phase is a real
        # collaborator in production (a TokenReview against the API server), so the suite names the
        # double rather than being refused the surface: with no verifier at all `create_app` answers
        # 401 on both, and every case in this suite that mints a token through the route would fail
        # for a reason that is about the machine rather than about the case. The double accepts
        # exactly CONTROL_PLANE_BEARER and nothing else, so the 401 cases are still real.
        self.control_plane: FakeControlPlaneAuthenticator = (
            FakeControlPlaneAuthenticator()
            if control_plane_authenticator is None
            else control_plane_authenticator
        )
        self._minted = 0
        self._lock = threading.Lock()

        self.config = GuardianConfig.from_mapping(
            guardian_environment(
                mode=mode,
                run_id=run_id,
                registered_issuers=registered_issuers,
                bundle_path=self.bundle_path,
                audit_log_path=self.chain_path,
                policy_timeout_seconds=policy_timeout_seconds,
                signing_material=signing_material,
            )
        )
        self.assembled = build_guardian(
            self.config,
            policy_engine=self.engine,
            issuance_engine=self.issuance_engine,
            clock=self.clock,
            replay_cache=self.replay_cache,
            jti_factory=self._next_jti,
            control_plane_authenticator=self.control_plane,
        )
        self.mediator = self.assembled.mediator
        self.app = self.assembled.app
        self.executor = self.assembled.executor
        self.sink = self.assembled.audit_sink
        # The raw JWS issuer, reached through the two wrappers the composition root put around it.
        #
        # `mint` below is a *Supervisor's* mint, standing in for a party that already holds the
        # authority to ask, and the adversarial suite deliberately mints tokens no authority would
        # grant -- a claim for another run, a wildcard scope, a lifetime past the ceiling. Those are
        # attacks on the *verification* path and they have to be constructible. The authority bound
        # sits where an unauthenticated caller reaches it, on `POST /v1/tokens`, which is what
        # `issue_token` drives.
        #
        # Reached rather than rebuilt on purpose. A second JwsTokenIssuer built here from the same
        # configuration would be a second object that could drift from the one the Guardian mints
        # with, which is the duplication moving the composition root out of this file removed.
        self.issuer = self.assembled.token_issuer.inner.issuer
        self.parameters = self.issuer.parameters

    # -- tokens ------------------------------------------------------------------------------

    def _next_jti(self) -> str:
        """A fresh jti per mint, so that the replay cases choose when a jti repeats."""
        with self._lock:
            self._minted += 1
            return f"jti-suite-{self._minted:04d}"

    def mint(
        self,
        *,
        issuer_id: str = SUPERVISOR_ID,
        subject_id: str = EXECUTOR_ID,
        run_id: str = RUN_ID,
        phase: str = PHASE,
        allow: AllowClaim = DEFAULT_ALLOW,
        ttl_seconds: int | None = None,
    ) -> str:
        """Mint a token the honest way -- through the Guardian's own issuer."""
        return self.issuer.issue(
            issuer_id=issuer_id,
            subject_id=subject_id,
            run_id=run_id,
            phase=phase,
            allow=allow,
            ttl_seconds=ttl_seconds,
        ).encoded

    # -- requests ----------------------------------------------------------------------------

    def action_body(
        self,
        *,
        token: str,
        request_id: str = "req-suite-0001",
        run_id: str = RUN_ID,
        executor_id: str | None = None,
        phase: str | None = None,
        verb: str = "get",
        resource: str = "pods",
        namespace: str = NAMESPACE,
        name: str | None = None,
        params: Mapping[str, Any] | None = None,
        justification: str = "reading pod state to establish which replicas are unhealthy",
        **extra: Any,
    ) -> dict[str, Any]:
        """The wire form of one ``ActionRequest`` v2, with room for keys the contract forbids.

        ``executor_id`` and ``phase`` default to this harness's :attr:`request_executor_id` and
        :attr:`request_phase`, which are in turn the identity and phase its tokens are minted for --
        so an ordinary case declares a request that agrees with its capability and says nothing
        about either field. A case that wants a group C binding failure states the disagreeing value
        here, on the request, which is where an Executor states it.

        They default to ``None`` and are resolved from the harness rather than defaulting to the
        module constants directly, so that a harness built with a different declared identity
        produces bodies that match it without every call site having to know.
        """
        body: dict[str, Any] = {
            "request_id": request_id,
            "run_id": run_id,
            "executor_id": self.request_executor_id if executor_id is None else executor_id,
            "phase": self.request_phase if phase is None else phase,
            "token": token,
            "action": {
                "verb": verb,
                "resource": resource,
                "namespace": namespace,
                "name": name,
                "params": dict(params or {}),
            },
            "justification": justification,
            "schema_version": ACTION_REQUEST_SCHEMA_VERSION,
        }
        body.update(extra)
        return body

    def submit(
        self,
        body: Mapping[str, Any] | bytes,
        *,
        label: str,
        headers: Mapping[str, str] | None = None,
        path: str = ACTIONS_PATH,
        declare_length: bool = True,
    ) -> CaseOutcome:
        """Send one request and capture everything the triple assertion needs to check."""
        before = len(self.records())
        raw = body if isinstance(body, bytes) else json.dumps(dict(body)).encode("utf-8")
        status, payload = call_asgi(
            self.app, path, raw, headers=headers, declare_length=declare_length
        )
        after = self.records()
        return CaseOutcome(
            label=label,
            status=status,
            payload=payload,
            appended=after[before:],
            report=self.verify_chain(),
        )

    def race(self, bodies: Sequence[Mapping[str, Any]], *, label: str) -> tuple[CaseOutcome, ...]:
        """Submit several requests genuinely concurrently and return one outcome per request.

        A separate path from :meth:`submit` because that method counts the chain before and after a
        single call, which is meaningless when two calls overlap. Here every request runs on its own
        thread behind a :class:`threading.Barrier`, so they arrive at the replay cache together
        rather than merely in quick succession, and afterwards each answer is paired with the record
        it named through ``audit_seq``. That pairing is what lets a concurrent case still make the
        full triple assertion instead of settling for "one of them was denied".

        Threads and not ``asyncio.gather``: the mediation pipeline is synchronous and has no await
        point in it, so two coroutines would run one after the other and the race would never
        happen. The Guardian is served by a threaded ASGI worker in production, so threads are also
        the shape the concurrency actually takes.
        """
        before = len(self.records())
        barrier = threading.Barrier(len(bodies))
        answers: list[tuple[int, Any] | None] = [None] * len(bodies)

        def drive(index: int, body: Mapping[str, Any]) -> None:
            raw = json.dumps(dict(body)).encode("utf-8")
            barrier.wait()
            answers[index] = call_asgi(self.app, ACTIONS_PATH, raw)

        threads = [
            threading.Thread(target=drive, args=(index, body), name=f"{label}-{index}")
            for index, body in enumerate(bodies)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        assert not any(thread.is_alive() for thread in threads), (
            f"{label}: a request never returned"
        )

        after = self.records()
        assert len(after) - before == len(bodies), (
            f"{label}: {len(bodies)} concurrent request(s) produced {len(after) - before} audit "
            "record(s). Every decision is audited exactly once, concurrency included"
        )
        report = self.verify_chain()
        by_seq = {record.seq: record for record in after}
        outcomes: list[CaseOutcome] = []
        for index, answer in enumerate(answers):
            assert answer is not None, f"{label}: request {index} produced no answer"
            status, payload = answer
            seq = payload.get("audit_seq") if isinstance(payload, dict) else None
            matched = [by_seq[seq]] if seq in by_seq else []
            outcomes.append(
                CaseOutcome(
                    label=f"{label} [request {index}]",
                    status=status,
                    payload=payload,
                    appended=matched,
                    report=report,
                )
            )
        return tuple(outcomes)

    def issue_token(
        self, body: Mapping[str, Any], *, bearer: str | None = CONTROL_PLANE_BEARER
    ) -> tuple[int, Any]:
        """POST to ``/v1/tokens`` as the control plane and return the raw answer.

        ``bearer`` defaults to the suite's synthetic control-plane string and is presented in the
        HTTP authorization scheme ``main.py``'s ``HTTPBearer`` dependency reads, because ADR-128
        made
        this surface authenticated: a case that means to test the gate passes ``bearer=None`` (no
        credential at all) or a different string. No decision is produced, so no audit record is
        expected either way.
        """
        return self._control_plane_call(TOKENS_PATH, body, bearer=bearer)

    def declare_phase(
        self,
        *,
        run_id: str = RUN_ID,
        phase: str = PHASE,
        bearer: str | None = CONTROL_PLANE_BEARER,
        schema_version: str = PHASE_DECLARATION_SCHEMA_VERSION,
    ) -> tuple[int, Any]:
        """POST a phase declaration to ``/v1/phase`` as the control plane and return the answer.

        The shape is the runner's (`runner/` declares the phase at each phase change), asserted here
        so a case cannot drift from the contract by building the body itself.
        """
        body: dict[str, Any] = {"run_id": run_id, "phase": phase, "schema_version": schema_version}
        return self._control_plane_call(PHASE_PATH, body, bearer=bearer)

    def _control_plane_call(
        self, path: str, body: Mapping[str, Any], *, bearer: str | None
    ) -> tuple[int, Any]:
        """POST ``body`` to a control-plane route, with or without a bearer, and return the
        answer."""
        headers = {} if bearer is None else {"authorization": f"Bearer {bearer}"}
        return call_asgi(
            self.app, path, json.dumps(dict(body)).encode("utf-8"), headers=headers or None
        )

    # -- audit -------------------------------------------------------------------------------

    def records(self) -> list[AuditRecord]:
        """Every decision record in this harness's chain, validated against the app's own model.

        Decisions only. The chain's genesis is the run-start record ADR-058 adds, which no request
        produced and no case appends, so it is left out here by its explicit ``record_type`` and
        read through :meth:`run_start_records` instead. ADR-082's execution follow-up is excluded
        for the same reason and read through :meth:`execution_records`: a v4 Guardian appends
        exactly one per decision, so leaving it here would make "the records this request appended"
        -- the third leg of every triple assertion -- count two records for one submitted action.
        """
        if not self.chain_path.exists():
            return []
        return [
            AuditRecord.model_validate(parsed.record)
            for parsed in read_chain(self.chain_path)
            if parsed.defect is None
            and not is_run_start(parsed.record)
            and not is_execution(parsed.record)
        ]

    def run_start_records(self) -> list[RunStartRecord]:
        """Every run-start record in this chain: exactly one, at ``seq`` zero, in a sound one."""
        if not self.chain_path.exists():
            return []
        return [
            RunStartRecord.model_validate(parsed.record)
            for parsed in read_chain(self.chain_path)
            if parsed.defect is None and is_run_start(parsed.record)
        ]

    def execution_records(self) -> list[ExecutionRecord]:
        """Every execution follow-up in this chain (ADR-082), one per decision in a sound one."""
        if not self.chain_path.exists():
            return []
        return [
            ExecutionRecord.model_validate(parsed.record)
            for parsed in read_chain(self.chain_path)
            if parsed.defect is None and is_execution(parsed.record)
        ]

    def verify_chain(self) -> ChainReport:
        """Verify this harness's chain as it stands, with the writer's live head as the anchor."""
        if not self.chain_path.exists():
            return verify_chain([], path=str(self.chain_path))
        return verify_chain(
            read_chain(self.chain_path),
            expected_head=self.sink.writer.head,
            path=str(self.chain_path),
            anchor_source="writer-head",
        )


# --------------------------------------------------------------------------------------------
# Construction helpers
# --------------------------------------------------------------------------------------------


def guardian_environment(
    *,
    mode: GuardianMode,
    run_id: str | None,
    registered_issuers: Sequence[str],
    bundle_path: Path,
    audit_log_path: Path,
    policy_timeout_seconds: float = SUITE_POLICY_TIMEOUT_SECONDS,
    signing_material: str = SYNTHETIC_SIGNING_MATERIAL,
) -> dict[str, str]:
    """The runner-supplied start-time keys, as a mapping ``GuardianConfig.from_mapping`` accepts.

    Built as a plain dictionary and never written into ``os.environ``. Configuration is the only
    route by which the arm reaches the process, so building it in one place keeps every test's
    Guardian configured the same way except in the one respect that test is about.

    Two keys arrived with M4 and both are required with no default, so a suite that omitted either
    would fail to build a Guardian rather than build a weaker one.
    ``GUARDIAN_ISSUANCE_ENTRYPOINT`` names the rule that bounds what may be minted, and it is
    spelled the way ``guardian/policies/issuance.rego`` declares its package so that the value here
    and the value a deployment sets are the same string. ``GUARDIAN_EXECUTOR`` is ``fake``, stated
    rather than assumed: this suite has no cluster, choosing the fake is now an explicit act, and
    writing it here is what makes every Guardian the suite builds one that touches nothing.
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
        "GUARDIAN_POLICY_ENTRYPOINT": "data.guardian.decision",
        "GUARDIAN_ISSUANCE_ENTRYPOINT": "data.guardian.issuance.decision",
        "GUARDIAN_POLICY_TIMEOUT_SECONDS": str(policy_timeout_seconds),
        "GUARDIAN_AUDIT_LOG_PATH": str(audit_log_path),
        "GUARDIAN_EXECUTOR": "fake",
        # ADR-128: required with no default (guardian/app/config.py), so a suite that omitted either
        # would fail to build a Guardian rather than build one that authenticated the wrong caller.
        "GUARDIAN_CONTROL_PLANE_SUBJECT": CONTROL_PLANE_SUBJECT,
        "GUARDIAN_CONTROL_PLANE_AUDIENCE": CONTROL_PLANE_AUDIENCE,
    }
    if run_id is not None:
        environment["GUARDIAN_RUN_ID"] = run_id
    return environment


# The stand-in bundle's only content. It decides nothing and is not policy: `guardian/policies/`
# holds the real bundle and M3-T3.2 owns it. What this file is for is bytes -- PolicyBundle.load
# refuses a directory with no .rego in it, on the ground that an empty bundle denies everything
# while looking configured, and the flag-isolation suite needs a loadable bundle whose digest it can
# compare across three configurations before the real one exists.
STAND_IN_BUNDLE_REGO: Final = (
    "# Not a policy. See guardian/tests/harness.py: this file exists so PolicyBundle.load has\n"
    "# bytes to digest in a suite that runs before guardian/policies/ is authored. It declares\n"
    "# a package and no rule, so nothing here decides anything even if an engine ever loaded it.\n"
    "package guardian_tests_stand_in\n"
)


def write_policy_bundle(path: Path, *, content: str = STAND_IN_BUNDLE_REGO) -> Path:
    """Write the stand-in bundle at ``path`` and return it, creating parents as needed."""
    path.mkdir(parents=True, exist_ok=True)
    (path / "stand_in.rego").write_bytes(content.encode("utf-8"))
    return path


def shipped_policy_bundle() -> Path:
    """The real bundle directory, or skip naming the task that has not landed yet."""
    shipped = REPO_ROOT / "guardian" / "policies"
    rego = sorted(shipped.rglob("*.rego")) if shipped.is_dir() else []
    if not rego:
        pytest.skip(
            "the shipped policy bundle guardian/policies/ holds no .rego file yet (M3-T3.2). The "
            "same assertion runs unconditionally against a stand-in bundle, so the loader's "
            "mode-blindness is proved either way; what waits on T3.2 is proving it over the bytes "
            "the campaign will actually ship"
        )
    return shipped


def policy_purity_script() -> Path:
    """The path to ``scripts/policy_purity_grep.sh``."""
    return REPO_ROOT / "scripts" / "policy_purity_grep.sh"


def find_posix_shell(interpreter_name: str = "sh") -> str | None:
    """Locate a POSIX shell, on ``PATH`` first and then where Git installs one on Windows.

    ``PATH`` alone is enough on ubuntu-latest and inside WSL2. It is not enough on the Windows
    development host, where ``sh.exe`` ships with Git but is only on ``PATH`` for a shell Git
    launched -- so a suite run from PowerShell would skip the two script checks for a reason that
    has nothing to do with the repository. ``docs/04-repo-conventions.md`` already fixes Git for
    Windows as part of the host setup, so looking where it puts its shell is reading the documented
    environment rather than guessing at one.
    """
    import os
    import shutil

    located = shutil.which(interpreter_name)
    if located is not None:
        return located
    roots = (
        os.environ.get("PROGRAMFILES"),
        os.environ.get("PROGRAMFILES(X86)"),
        os.environ.get("LOCALAPPDATA"),
    )
    candidates = [
        Path(root) / part / "Git" / "usr" / "bin" / f"{interpreter_name}.exe"
        for root in roots
        if root
        for part in ("", "Programs")
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


def run_shell_script(
    script: Path,
    interpreter_name: str = "sh",
    *,
    arguments: Sequence[str] = (),
    environment_overrides: Mapping[str, str] | None = None,
) -> tuple[int, str, str]:
    """Run a POSIX shell script and return ``(returncode, stdout, stderr)``, or skip.

    Skips rather than fails when no POSIX shell can be found at all: that is a property of the
    machine the suite happens to be running on, not of the repository.

    ``arguments`` follow the script on its command line and ``environment_overrides`` are laid over
    the inherited environment. Both default to nothing, so every existing caller runs exactly the
    command it always ran. ``scripts/audit_verify.sh`` needs both: the chain to verify, and the
    interpreter this suite is running under, so the gate cannot quietly pick a different Python.
    """
    import os
    import subprocess

    interpreter = find_posix_shell(interpreter_name)
    if interpreter is None:
        pytest.skip(
            f"no {interpreter_name!r} found on PATH or in a Git for Windows installation, so "
            f"{script.name} cannot be executed here. The script is POSIX sh: it runs under dash on "
            "ubuntu-latest and under the shell Git installs on the Windows host"
        )
    # The script calls dirname, git, grep and wc. On a POSIX host they are already on PATH; on the
    # Windows host they live beside the shell itself, in the Git installation's usr/bin, and git.exe
    # one directory up in cmd/. Prepending both is what makes "runs identically from make in WSL2,
    # from Git Bash on the Windows host, and on the CI runner" -- docs/04-repo-conventions.md
    # section 1 -- true when the runner is pytest rather than a shell. It is a no-op on Linux, where
    # the located interpreter's own directory is already on PATH.
    shell_directory = Path(interpreter).parent
    environment = dict(os.environ)
    extra = [str(shell_directory), str(shell_directory.parent.parent / "cmd")]
    environment["PATH"] = os.pathsep.join([*extra, environment.get("PATH", "")])
    environment.update(environment_overrides or {})

    completed = subprocess.run(  # noqa: S603 - argv is a repo-relative script and a resolved shell
        [interpreter, str(script), *arguments],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )
    return completed.returncode, completed.stdout, completed.stderr


def assert_winner_count(
    outcomes: Sequence[CaseOutcome],
    *,
    permitted: int,
    loser_reason: ReasonCode,
) -> tuple[list[AuditRecord], tuple[AuditRecord, ...]]:
    """Assert exactly ``permitted`` outcomes were permitted and every other denied, and say which.

    The concurrent-cap shape, and the generalisation of :func:`assert_single_winner` to a bound
    rather
    than to a winner: a cap is not a race for one prize, it is a budget several may be drawn from,
    so
    the property a concurrent case owes is "never more than the cap" rather than "exactly one". The
    same three reasons apply to both, which is why this is one function with a parameter rather than
    two: every outcome is routed through :meth:`CaseOutcome.assert_permitted` or
    :meth:`CaseOutcome.assert_denied`, so "denied, with a structured reason code, and present in the
    audit chain" holds on both sides of the race and not only on the refused ones. **Counting the
    permitted outcomes is the only way to see a cap that admits more than it should** -- a test that
    looked at one of them, or at the refusals alone, would pass against a lost-update race.
    """
    winners = [outcome for outcome in outcomes if outcome._decision() is Decision.PERMIT]
    denied = [outcome for outcome in outcomes if outcome._decision() is Decision.DENY]
    assert len(winners) == permitted, (
        f"{len(winners)} of {len(outcomes)} concurrent request(s) were permitted, expected exactly "
        f"{permitted}. A cap that admits more than it allows is a check-then-act race: every request "  # noqa: E501 - message
        "read the counter before any of them wrote it back, and that is invisible in any test that "
        "sends the requests in sequence"
    )
    assert len(winners) + len(denied) == len(outcomes), (
        "a concurrent request produced neither a permit nor a deny; every request reaching the "
        "pipeline reaches a decision, and every decision is one of the two"
    )
    winner_records = [outcome.assert_permitted() for outcome in winners]
    loser_records = tuple(outcome.assert_denied(loser_reason) for outcome in denied)
    return winner_records, loser_records


def assert_single_winner(
    outcomes: Sequence[CaseOutcome], *, loser_reason: ReasonCode
) -> tuple[AuditRecord, tuple[AuditRecord, ...]]:
    """Assert exactly one outcome was permitted and every other denied with ``loser_reason``.

    The concurrent-replay shape, expressed once so that a racing case still owes the full triple
    assertion for **every** request rather than for the one it happens to look at. Each outcome is
    routed through :meth:`CaseOutcome.assert_permitted` or :meth:`CaseOutcome.assert_denied`, so
    "denied, with a structured reason code, and present in the audit chain" holds on both sides of
    the race and not just on the losing one.

    A thin wrapper over :func:`assert_winner_count` with the count fixed at one, which is what a
    single-use capability produces: two requests spending one ``jti``, exactly one winner.
    """
    winner_records, loser_records = assert_winner_count(
        outcomes, permitted=1, loser_reason=loser_reason
    )
    return winner_records[0], loser_records


def read_claim(token: str, name: str) -> Any:
    """Read one claim out of a token without verifying it -- for naming what a test just minted.

    Never used to decide anything. The suite mints a token and then needs to say "this ``jti``" in
    an assertion about the replay cache, and the ``jti`` is chosen by the issuer's injected factory
    rather than by the caller. Reading it back is how the test names it.
    """
    return jwt.decode(token, options={"verify_signature": False})[name]


def as_wire(value: Any) -> Any:
    """A JSON round trip, so two structures can be compared as the bytes a bundle would hold."""
    return json.loads(json.dumps(value, sort_keys=True, default=str))


def record_fields(record: AuditRecord | RunStartRecord) -> dict[str, Any]:
    """One audit record -- a decision or the run-start genesis -- as a plain, comparable mapping."""
    return as_wire(record.model_dump(mode="json"))


def make_harness(root: Path, **kwargs: Any) -> GuardianHarness:
    """Build a harness rooted at ``root``. A named function so tests read as one line."""
    return GuardianHarness(root=root, **kwargs)
