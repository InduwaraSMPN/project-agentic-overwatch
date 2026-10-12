r"""The production composition root: the one place the Guardian's halves are wired together.

WHAT THIS MODULE IS
-------------------
``guardian/app/main.py`` says, in the section headed "WHAT IS NOT HERE", that there is no default
composition root "because three of the four do not exist yet: the token service is M3-T3.3, the
audit chain's writer is M3-T3.6, the policy bundle is M3-T3.2, and the real executor is Tier B".
**That sentence is no longer true, and this module is what makes it false.** All four exist:
``guardian/token/`` mints and verifies, ``guardian/audit/chain.py`` seals, ``guardian/policies/``
holds the Rego, and :mod:`guardian.app.executor` holds the Kubernetes client. What was still missing
was anything that assembled them, and until this file the only description anywhere of how the two
halves fit was ``guardian/tests/harness.py`` -- a composition root living in a test suite, which its
own docstring names as owed work in as many words.

So this module is that assembly, moved to where a running Guardian can reach it, and
``guardian/tests/harness.py`` now *consumes* it rather than duplicating it. That inversion is the
point rather than a tidy-up: a seam described in two places is a seam that can be right in the test
and wrong in production, and the adversarial suite would go on passing while the deployed process
wired something subtly different.

NO DEFAULT SUBSTITUTES A FAKE, AND THE SEAMS BELOW DO NOT WEAKEN THAT
-----------------------------------------------------------------------
``main.py``'s refusal to write a composition root was not squeamishness about incompleteness. It was
that "writing a ``create_default_app`` today would mean writing one that quietly substitutes fakes,
which is the one way this file could ship a Guardian that looks configured and enforces nothing."
That constraint is inherited here in full.

:func:`build_guardian` takes a :class:`~guardian.app.config.GuardianConfig` and builds every
collaborator from it. A Guardian that cannot find its signing key does not start; nor does one whose
policy bundle is missing, whose ``opa`` binary cannot be located, or whose executor was not chosen.
Which executor is assembled is :attr:`~guardian.app.config.GuardianConfig.executor`, a **required
setting with no default** -- :class:`~guardian.app.config.ExecutorKind` argues why at length, and
the short form is that a fallback to the fake produces a Guardian that mediates perfectly, records
``executed``, and changes nothing anywhere.

:func:`build_guardian` does carry six keyword seams, and each one's default is **the real
collaborator built from configuration**, never a stand-in. They exist because the adversarial suite
has to drive the real pipeline with a canned policy answer, a frozen clock, a four-entry replay
cache and a chosen ``jti`` -- and the alternative to a seam is the suite assembling its own
Guardian, which is the duplication this module exists to remove. The distinction that matters is
that a fake is reachable only by a caller that names one: there is no configuration, no environment
variable and no absent value that produces one by itself. The fake *executor* is the one exception
and it is not an exception to this rule, because reaching it requires
``GUARDIAN_EXECUTOR=fake`` to have been written down by whoever started the process.

WHY THE ADAPTERS ARE HERE AND NOT IN THE PACKAGES THEY ADAPT
--------------------------------------------------------------
``guardian/app/mediation.py`` declares four collaborator protocols and imports none of the packages
behind them; ``guardian/audit/chain.py`` declares its own ``SupportsModelDump`` so the chain is not
downstream of the contract module's import graph (ADR-022); ``guardian/token/verifier.py`` publishes
its reason vocabulary as strings and says the app layer "must not be import-coupled to the
verifier's internals". Those decisions stand. What they require is that *something* import both
sides, and a composition root is the object whose entire job is to be that something. Every import
below crosses a boundary the modules themselves deliberately do not cross, which is why they are all
in one file that decides nothing.

Three adapters carry a real argument rather than translating shapes:

*The reason vocabularies genuinely differ.* :data:`DENIAL_REASON_TO_REASON_CODE` maps
``guardian.token.verifier.DenialReason`` onto :class:`~guardian.app.models.ReasonCode`, and it has
**no default arm**: an unmapped member raises rather than silently becoming
``TOKEN_MALFORMED``. ``guardian/tests/test_token_contract_seam.py`` asserts the mapping is total, so
a member added to either enum breaks the build instead of landing in whatever an ``else`` said.

*The claim shapes differ by one field.* :class:`CapabilityTokenVerifierAdapter` re-validates the
accepted payload against :class:`~guardian.app.models.CapabilityTokenClaims` rather than projecting
the verifier's eight-claim dataclass, because that dataclass is eight of architecture section 3's
nine and the app's model is those eight plus ``schema_version`` under ``extra="forbid"``.
Projecting would silently drop the ninth and would silently admit a token carrying an ``nbf`` that
``models.py`` says must be refused.

*Issuance has to be bounded before it is signed.* :class:`AuthorityBoundedTokenIssuer` is M4's
conflict M4-C6 answered, and the next section is about it.

THE AUTHORITY BOUND ON ISSUANCE, AND THE GAP IT DOES NOT CLOSE
----------------------------------------------------------------
``POST /v1/tokens`` establishes no caller identity, and ``guardian.rego``'s permit rule grants
exactly what the presented token's allow-claim covers. Put together: any party with network reach to
the issue surface mints a claim, and the permit follows. The mediated arm would not be mediated, and
RQ5's contrast would be measuring nothing.

The answer taken here is deliberately **not** to authenticate the caller. Executors and Supervisors
are in-process graph nodes; authenticating them would need per-node standing credentials, which is
precisely what FR3.1 forbids and what this architecture exists to demonstrate is unnecessary. So
instead :class:`AuthorityBoundedTokenIssuer` consults a deny-by-default authority entrypoint --
``guardian/policies/issuance.rego`` over ``guardian/policies/authority.rego``, in the **same
bundle** so that :attr:`~guardian.app.policy.PolicyBundle.digest` stays ADR-023's machine proof
across every arm -- before anything is signed, and refuses an over-wide request with
:class:`~guardian.app.mediation.TokenIssuanceRefused` carrying ``issue_authority_exceeded``.

**What that buys**: an unauthenticated mint now grants nothing an authorised Supervisor could not
already have obtained, so G0's enforcement claim survives the exposure.

**What it does not**: caller identity is still not established. A party reaching this surface can
still mint *within* the declared authority, can still name any ``iss`` and any ``sub``, and the
audit record's attribution is still the caller's choice rather than an established fact. That is
recorded, not closed -- here, on :class:`guardian.app.mediation.TokenIssuer`, in
``guardian/policies/issuance.rego``'s header, in ADR-031, and in
``guardian/tests/test_token_issuance_exposure.py``, which is written as a demonstration of what
remains open rather than as a test of a defence that exists.

THE ONE RECORD ASSEMBLY WRITES
-------------------------------
:func:`build_guardian` finishes by writing the run-start genesis ADR-058 puts at the head of a new
or empty per-run chain, through :meth:`AuditChainSink.record_run_start`. It is not a decision and
it decides nothing: it records that a Guardian started, for which run and in which arm, so that a
run whose agents never reached the Guardian still leaves the verifiable chain
``data-management.md`` section 3 requires. On a chain that already holds records -- a restart -- it
writes nothing.

WHAT THIS MODULE DELIBERATELY DOES NOT DO
------------------------------------------
*Decide anything.* Not one branch below produces a permit, a denial, a reason code or an
enforcement value. Adjudication is ``guardian/app/mediation.py``'s and policy is the bundle's.

*Read the environment.* :class:`~guardian.app.config.GuardianConfig` does that, once, at process
start, and is handed here already built. The single exception is :func:`resolve_opa_binary`, which
reads ``OPA_BIN`` -- and ``guardian/app/opa.py`` argues why that is a property of the machine rather
than a value a run manifest should be able to set.

*Serve.* :mod:`guardian.app.__main__` is the entry point, and the split is ``main.py``'s reasoning
about module-level state applied one layer up: building an application must not require a server to
be installed.
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Protocol, runtime_checkable
from uuid import uuid4

import jwt
from fastapi import FastAPI
from guardian.app.config import ExecutorKind, GuardianConfig, GuardianStartupError
from guardian.app.control_auth import (
    ControlPlaneAuthenticator,
    ControlPlaneVerifier,
    PhaseState,
)
from guardian.app.executor import KubernetesActionExecutor
from guardian.app.limits import SQLiteActionCapReserver
from guardian.app.main import create_app
from guardian.app.mediation import (
    ActionExecutor,
    AuditDraft,
    FakeActionExecutor,
    Mediator,
    TokenIssuanceRefused,
    TokenVerification,
)
from guardian.app.models import (
    AUDIT_RECORD_SCHEMA_VERSION,
    AUDIT_RECORD_TYPE_RUN_START,
    JUSTIFICATION_MAX_CHARS,
    TOKEN_ISSUE_SCHEMA_VERSION,
    AuditRecord,
    CapabilityTokenClaims,
    Decision,
    ExecutionRecord,
    ExecutionRecordDraft,
    ReasonCode,
    RunStartDraft,
    RunStartRecord,
    TokenIssueRequest,
    TokenIssueResponse,
)
from guardian.app.opa import OpaSubprocessEngine, resolve_opa_binary
from guardian.app.policy import (
    PolicyBundle,
    PolicyEngine,
    build_issuance_input,
    evaluate_policy,
)
from guardian.audit.chain import AuditChainWriter, Ed25519Signer
from guardian.token.issuer import TokenIssuer as JwsTokenIssuer
from guardian.token.issuer import TokenIssueRefused
from guardian.token.persistent_replay import SQLiteReplayStore
from guardian.token.verifier import AllowClaim, DenialReason, TokenParameters
from guardian.token.verifier import TokenVerifier as JwsTokenVerifier

# The structured code a refusal to mint beyond the declared authority carries to the caller.
#
# It satisfies `guardian.app.mediation._is_refusal_code` -- ASCII, non-empty, comfortably inside
# REFUSAL_CODE_MAX_CHARS -- which matters because that predicate is not advisory: a code failing it
# is replaced by the generic `issue_refused`, and the caller would be told less than the Guardian
# knew. The `issue_` prefix is `guardian.token.issuer.IssueRefusalReason`'s convention, kept so that
# no code from the issuance vocabulary can be mistaken for a verification reason in a log or a data
# frame, and the suffix says which of the two bounds on issuance was exceeded -- the other being
# the section 2 lifetime ceiling, which answers `issue_ttl_above_ceiling`.
ISSUE_AUTHORITY_EXCEEDED: Final = "issue_authority_exceeded"

# The prefix on a minted jti. See `_random_jti` for why a nonce is not a determinism question.
JTI_PREFIX: Final = "jti-"


# --------------------------------------------------------------------------------------------
# The reason-vocabulary translation (M3's conflict: two vocabularies, neither a superset)
# --------------------------------------------------------------------------------------------

DENIAL_REASON_TO_REASON_CODE: Final[Mapping[DenialReason, ReasonCode]] = {
    # --- group A, authenticity -------------------------------------------------------------
    DenialReason.MALFORMED: ReasonCode.TOKEN_MALFORMED,
    # A jwk/jku/kid/x5u header is the key-substitution half of the same family the algorithm
    # allowlist defeats: the attacker is telling the verifier which key to trust. It is filed with
    # the algorithm rejection rather than with the malformed bytes because the token is perfectly
    # well formed -- what is refused is the header's attempt to choose the verification key.
    DenialReason.HEADER_PARAMETER_NOT_ALLOWED: ReasonCode.TOKEN_ALGORITHM_REJECTED,
    DenialReason.ALGORITHM_NOT_ALLOWED: ReasonCode.TOKEN_ALGORITHM_REJECTED,
    DenialReason.SIGNATURE_INVALID: ReasonCode.TOKEN_SIGNATURE_INVALID,
    # Not an attack: this Guardian has no key to verify with. POLICY_GUARDIAN_FAULT is the code
    # models.py reserves for "the Guardian's own pipeline" failing, and attributing a missing local
    # key to the presenter would put a configuration fault into the numbers RQ5 reads as attacks.
    DenialReason.VERIFICATION_KEY_UNAVAILABLE: ReasonCode.POLICY_GUARDIAN_FAULT,
    DenialReason.CLAIM_MISSING: ReasonCode.TOKEN_CLAIMS_MALFORMED,
    DenialReason.CLAIM_MALFORMED: ReasonCode.TOKEN_CLAIMS_MALFORMED,
    # --- group B, temporal -------------------------------------------------------------------
    DenialReason.EXP_MISSING: ReasonCode.TOKEN_EXPIRY_MISSING,
    # The app vocabulary has temporal.expiry-missing and no counterpart for a missing `iat`, so a
    # token that cannot say when it was minted is filed as a defective claim set rather than
    # given a temporal code that does not exist. Recorded as a vocabulary gap in the M3 report.
    DenialReason.IAT_MISSING: ReasonCode.TOKEN_CLAIMS_MALFORMED,
    DenialReason.EXPIRED: ReasonCode.TOKEN_EXPIRED,
    DenialReason.ISSUED_IN_FUTURE: ReasonCode.TOKEN_NOT_YET_VALID,
    DenialReason.NOT_YET_VALID: ReasonCode.TOKEN_NOT_YET_VALID,
    # exp <= iat. Not "above the ceiling" -- that code makes a specific claim about which bound was
    # exceeded, and recording a zero-length lifetime as an over-long one would be false in the log.
    # It is an internally inconsistent claim set, which is what claims-malformed means.
    DenialReason.LIFETIME_NOT_POSITIVE: ReasonCode.TOKEN_CLAIMS_MALFORMED,
    DenialReason.LIFETIME_ABOVE_CEILING: ReasonCode.TOKEN_LIFETIME_ABOVE_CEILING,
    # --- group A / C, binding ------------------------------------------------------------------
    DenialReason.ISSUER_UNREGISTERED: ReasonCode.TOKEN_ISSUER_UNKNOWN,
    DenialReason.SUBJECT_MISMATCH: ReasonCode.SCOPE_SUBJECT_MISMATCH,
    DenialReason.RUN_MISMATCH: ReasonCode.SCOPE_RUN_MISMATCH,
    # PHASE_UNKNOWN has two causes in the verifier: a token naming a fifth phase, and a caller
    # naming one. The second cannot arise through this adapter: ActionRequest.phase is typed
    # models.Phase and a body naming a fifth phase never becomes a request at all, so at
    # verification time this can only be the token's own claim.
    DenialReason.PHASE_UNKNOWN: ReasonCode.TOKEN_CLAIMS_MALFORMED,
    DenialReason.PHASE_MISMATCH: ReasonCode.SCOPE_PHASE_MISMATCH,
    # --- group D, replay -----------------------------------------------------------------------
    DenialReason.REPLAYED: ReasonCode.REPLAY_JTI_SPENT,
    DenialReason.REPLAY_CACHE_UNAVAILABLE: ReasonCode.REPLAY_CACHE_UNAVAILABLE,
}


def reason_code_for(denial: DenialReason) -> ReasonCode:
    """Translate one verifier denial into the app's reason vocabulary.

    There is deliberately no default arm. An unmapped member raises here rather than becoming
    ``POLICY_GUARDIAN_FAULT`` or ``TOKEN_MALFORMED``, because a silent fallthrough is how a new
    denial reason would start being recorded as something it is not -- and the audit log is what
    ``docs/protocols/evaluation-protocol.md`` section 3 computes both RQ5 measures from.
    ``guardian/tests/test_token_contract_seam.py`` asserts the mapping is total, so this raise is
    unreachable in a suite that passes; it exists so that the day it becomes reachable, it is loud.
    """
    translated = DENIAL_REASON_TO_REASON_CODE.get(denial)
    if translated is None:
        raise KeyError(
            f"{denial!r} has no ReasonCode. Every guardian.token.verifier.DenialReason must map to "
            "exactly one guardian.app.models.ReasonCode -- add the row to "
            "DENIAL_REASON_TO_REASON_CODE with the reason for the choice, and never a default arm"
        )
    return translated


# --------------------------------------------------------------------------------------------
# The seams, and the clock they share
# --------------------------------------------------------------------------------------------


@runtime_checkable
class GuardianClock(Protocol):
    """One timeline, read in the two shapes the Guardian's collaborators need.

    ``epoch`` is integer seconds, which is what ``guardian/token/`` and the replay cache require --
    RFC 7519's NumericDate, and an integer rather than a float because ADR-013's canonicalisation
    forbids rendering an integer as one. ``instant`` is the aware UTC datetime
    :attr:`~guardian.app.models.AuditRecord.ts` requires.

    One protocol rather than two callables, because "the token expired" and "the audit record was
    written" must be statements about the same timeline. Two independently injected clocks would let
    a Guardian record a denial at an instant its own verifier disagreed with, and the temporal
    adversarial cases would be asserting against whichever of the two the fixture happened to move.
    """

    def epoch(self) -> int:
        """Epoch seconds, as an integer."""
        ...

    def instant(self) -> datetime:
        """The same moment, as an aware UTC datetime."""
        ...


class SystemClock:
    """The real clock: the wall clock, read in both shapes from one call.

    ``instant`` is taken first and ``epoch`` derived from it, rather than the two being read
    independently, so a record and the token check beside it can never straddle a second boundary --
    which would be a one-in-a-thousand off-by-one that only ever appeared under load.
    """

    def instant(self) -> datetime:
        """Now, in UTC."""
        return datetime.now(UTC)

    def epoch(self) -> int:
        """Now, as integer epoch seconds."""
        return int(self.instant().timestamp())


def _random_jti(prefix: str = JTI_PREFIX) -> str:
    """Return a fresh ``jti``, unique per mint.

    ``guardian/token/issuer.py`` requires the factory rather than defaulting one, "so that this
    module imports no random source at all", and this is where the source lives.

    **This is not the unseeded randomness ``.agents/rules/20-parity-and-determinism.md`` forbids,
    and the distinction is worth being exact about.** That rule binds what a scenario *injects*: an
    attacker script, an event sequence, an ordering -- everything a run's behaviour is a function
    of, so that ``(scenario_id, seed)`` replays identically. A ``jti`` is a single-use nonce whose
    only property is that it has not been seen before; nothing in a run depends on its value, no
    measure reads it, and the determinism check diffs injected events rather than credential
    identifiers. A *seeded* ``jti`` would in fact be the defect: two runs of one scenario would mint
    the same identifiers, and a replay cache shared across them would refuse the second run's
    tokens as spent.

    The prefix is not decoration. :data:`~guardian.app.models.IDENTIFIER_PATTERN` requires an
    identifier to begin with an alphanumeric, and a bare hex digest satisfies that only by luck of
    its first character being drawn from ``0-9a-f``; the prefix makes it structural, and it names
    what the value is in an audit record a person reads months later.
    """
    return f"{prefix}{uuid4().hex}"


# --------------------------------------------------------------------------------------------
# Adapters
# --------------------------------------------------------------------------------------------


class CapabilityTokenVerifierAdapter:
    """``guardian.token.verifier.TokenVerifier`` seen through ``mediation.TokenVerifier``.

    Three jobs, and the second is the one M4 changed.

    It **translates the vocabulary**, through :func:`reason_code_for`, which has no default arm.

    It **passes the phase and the Executor identity through per request**. Until ``ActionRequest``
    v2 there was nowhere to get them from and ``guardian/tests/harness.py`` supplied both as
    start-time configuration -- correct for a test, fail-closed, and meaning one Guardian process
    per ``(phase, executor)`` pair, which M4's conflict M4-C5 records as making a four-phase golden
    path unrunnable. The request now carries ``executor_id`` and ``phase``, so this adapter holds
    neither and one Guardian serves a whole run. What that check is worth, and what it is not, is
    argued on :class:`~guardian.app.models.ActionRequest`: it is **attribution, not
    authentication**, because both values are the sender's declaration. It detects a mismatch; it
    does not prevent one.

    It **re-validates the accepted payload against the app's own claim model.** The token module's
    ``CapabilityClaims`` is eight of architecture section 3's nine claims;
    :class:`~guardian.app.models.CapabilityTokenClaims` is those eight plus ``schema_version``, with
    ``extra="forbid"``. Handing the pipeline a claim set built from the eight would silently drop
    the ninth and would silently admit a token carrying an ``nbf`` that ``models.py`` says must be
    refused, so the adapter validates the *decoded payload* instead. The second decode is a
    projection rather than a verification: it runs only after ``TokenVerifier.verify`` has accepted,
    so the bytes are already known authentic, and re-running the signature check here would put a
    second copy of the verifier's option set in an adapter -- the duplication this seam exists to
    avoid.
    """

    def __init__(self, *, verifier: JwsTokenVerifier, registered_issuers: Sequence[str]) -> None:
        self._verifier = verifier
        self._registered_issuers = tuple(registered_issuers)

    def verify(
        self,
        bearer: object,
        *,
        expected_run_id: str | None,
        expected_phase: str,
        expected_subject: str,
    ) -> TokenVerification:
        """Verify ``bearer`` for this run, and for the phase and Executor the request declared."""
        if expected_run_id is None:
            # GuardianConfig permits a null run id as a development posture. A Guardian pinned to
            # no run cannot detect a cross-run token, because ActionRequest.run_id is the
            # attacker's. Refusing is the deny-by-default reading; permitting would make the
            # SCOPE_RUN_MISMATCH case pass by not being asked.
            return TokenVerification.refuse(ReasonCode.POLICY_GUARDIAN_FAULT)
        outcome = self._verifier.verify(
            bearer,
            expected_run_id=expected_run_id,
            expected_phase=expected_phase,
            expected_subject=expected_subject,
            registered_issuers=self._registered_issuers,
        )
        if not outcome.accepted:
            if outcome.reason is None:
                return TokenVerification.refuse(ReasonCode.POLICY_GUARDIAN_FAULT)
            return TokenVerification.refuse(
                reason_code_for(outcome.reason),
                verified_jti=outcome.verified_jti,
                verified_issuer=outcome.verified_issuer,
            )
        return self._as_app_claims(bearer)

    def _as_app_claims(self, bearer: object) -> TokenVerification:
        """Project the already-verified payload onto ``models.CapabilityTokenClaims``."""
        try:
            payload = jwt.decode(str(bearer), options={"verify_signature": False})
            return TokenVerification.accept(CapabilityTokenClaims.model_validate(payload))
        # Deliberately broad. Anything this decode or this validation can raise means the payload
        # is not a claim set this Guardian will act on, and the pipeline's contract here is a
        # verdict rather than an exception -- an escape would reach main.py's catch-all and produce
        # an HTTP 500 with nothing audited, which is the one outcome worse than a denial.
        except Exception:
            return TokenVerification.refuse(ReasonCode.TOKEN_CLAIMS_MALFORMED)


class CapabilityTokenIssuerAdapter:
    """``guardian.token.issuer.TokenIssuer`` seen through ``mediation.TokenIssuer``.

    Translates the wire contract to the minting call and the refusal exception to the app's, and
    does nothing else. In particular it does **not** authenticate the caller and does **not** bound
    what may be minted: the first cannot be done at this seam, and the second is
    :class:`AuthorityBoundedTokenIssuer`'s, wrapped around this one by :func:`build_guardian`.

    Keeping the two apart is deliberate. This class is the shape translation and would be identical
    with or without an authority policy; that one is a policy consultation and would be identical
    whatever the token library. Fused, neither could be read on its own, and a change to either
    would be a change to a class that does both.
    """

    def __init__(self, *, issuer: JwsTokenIssuer) -> None:
        self._issuer = issuer

    @property
    def issuer(self) -> JwsTokenIssuer:
        """The token service this adapter wraps.

        Published rather than private, so that a caller needing the minting object itself reaches
        *this* one instead of building a second from the same configuration. Two issuers built from
        one configuration are two objects that can drift -- a different clock, a different ``jti``
        source, a key read at a different moment -- and the drift would be invisible until a test
        that minted with one and verified with the other disagreed for a reason neither names.
        """
        return self._issuer

    def issue(self, request: TokenIssueRequest) -> TokenIssueResponse:
        """Mint one token for ``request``, or raise ``mediation.TokenIssuanceRefused``."""
        try:
            issued = self._issuer.issue(
                issuer_id=request.supervisor_id,
                subject_id=request.executor_id,
                run_id=request.run_id,
                phase=request.phase.value,
                allow=AllowClaim(
                    verbs=tuple(request.allow.verbs),
                    resources=tuple(request.allow.resources),
                    namespaces=tuple(request.allow.namespaces),
                ),
                ttl_seconds=request.ttl_seconds,
            )
        except TokenIssueRefused as refused:
            raise TokenIssuanceRefused(refused.reason_code, str(refused)) from refused
        return TokenIssueResponse(
            token=issued.encoded,
            jti=issued.claims.jti,
            exp=issued.claims.exp,
            schema_version=TOKEN_ISSUE_SCHEMA_VERSION,
        )


class AuthorityBoundedTokenIssuer:
    """Consult the authority policy, then mint -- or refuse, having minted nothing.

    M4's conflict M4-C6 answered. The module docstring argues why the answer is a bound on what may
    be minted rather than an authentication of who is asking, and states precisely what the bound
    buys and what it leaves open.

    **The order is the whole design.** The policy is consulted *before* the inner issuer is called,
    so a refused request produces no signature, no ``jti``, and nothing for a replay cache to have
    seen. Consulting afterwards and discarding the token would leave a live credential in the
    process's memory for the duration of one function call, minted under the Guardian's own key,
    for a scope the Guardian had just decided it would not grant.

    **A refusal is fail-closed by construction rather than by care.**
    :func:`~guardian.app.policy.evaluate_policy` never raises and never permits on an error path: an
    engine outage, an overrun and an unreadable answer all arrive as denials with their own reason
    codes. This class reads only whether the decision was a permit, so every one of those becomes a
    refusal to mint. A Guardian whose authority policy cannot be evaluated mints nothing, which is
    the same posture ``guardian/app/policy.py`` takes for actions and for the same reason.

    **One structured code, not the policy's rule id.** The caller is told
    ``issue_authority_exceeded`` whichever authority rule refused. The rule id is a value from the
    bundle and would be a description of the policy's internal structure handed to a party the
    threat model assumes is mapping it -- the same reasoning ``guardian/app/main.py`` applies when
    it withholds Pydantic's validation detail from a 400. The rule id is not lost: it is carried in
    the refusal's ``detail``, which ``main.py`` keeps for the Guardian's operational log and never
    returns over the wire.

    **The mint is bounded to the run's declared phase (ADR-128, V17).** ``phase_state`` is the
    :class:`~guardian.app.control_auth.PhaseState` the runner writes through ``POST /v1/phase`` and
    the same object ``guardian/app/main.py`` gates that route with, so the phase this issuer
    bounds a mint against is the run's *actual* phase rather than the ``request.phase`` the caller
    declared.
    The current phase is read at issue time -- a declaration and a mint that read a torn value would
    be the race :class:`PhaseState`'s lock exists to prevent -- and handed to
    :func:`~guardian.app.policy.build_issuance_input` as ``declared_phase``, where
    ``issuance.rego``'s ``deny_phase_not_current`` reads it. It defaults to ``None`` so a Guardian
    assembled without the phase channel (or before any phase is declared) applies no phase-currency
    bound, the development posture :class:`PhaseState` and ``scope.rego`` take for a null run.
    """

    def __init__(
        self,
        *,
        inner: CapabilityTokenIssuerAdapter,
        engine: PolicyEngine,
        guardian_run_id: str | None,
        timeout_seconds: float,
        phase_state: PhaseState | None = None,
    ) -> None:
        self._inner = inner
        self._engine = engine
        self._guardian_run_id = guardian_run_id
        self._timeout_seconds = timeout_seconds
        self._phase_state = phase_state

    @property
    def inner(self) -> CapabilityTokenIssuerAdapter:
        """The unbounded adapter this one guards, published for the reason its ``issuer`` is."""
        return self._inner

    def issue(self, request: TokenIssueRequest) -> TokenIssueResponse:
        """Refuse anything the authority policy does not permit, and otherwise mint."""
        declared_phase = self._phase_state.current_phase if self._phase_state is not None else None
        document = build_issuance_input(
            request=request,
            guardian_run_id=self._guardian_run_id,
            declared_phase=declared_phase,
        )
        outcome = evaluate_policy(self._engine, document, timeout_seconds=self._timeout_seconds)
        if outcome.decision is not Decision.PERMIT:
            raise TokenIssuanceRefused(
                ISSUE_AUTHORITY_EXCEEDED,
                f"the authority policy refused this mint: {outcome.reason_code.value} "
                f"(rule {outcome.rule_id})",
            )
        return self._inner.issue(request)


class AuditChainSink:
    """``guardian.audit.chain.AuditChainWriter`` seen through ``mediation.AuditSink``.

    The two were written not to know about each other -- the chain reaches a record through a
    ``model_dump`` protocol so that the security-critical part cannot be broken by an edit to a
    contract module it never imports (ADR-022) -- so something has to hand the draft to the writer
    and validate what comes back as an :class:`~guardian.app.models.AuditRecord`. Validating the
    returned mapping rather than trusting it is what makes the round trip an assertion: the writer
    scrubs and bounds before hashing, and if what it wrote were not a record the app's own model
    accepts, this raises at the append instead of at some later read of a sealed bundle.
    """

    def __init__(
        self,
        path: Path,
        *,
        max_justification_chars: int = JUSTIFICATION_MAX_CHARS,
        signing_key: Ed25519Signer | None = None,
    ) -> None:
        self.path = Path(path)
        # Re-open and verify an existing chain before appending. Constructing AuditChainWriter
        # directly always starts at the genesis predecessor and seq 0; doing that after a process
        # restart would append a second genesis record to the existing file and corrupt continuity.
        # ADR-130: signing_key is handed straight through to the writer. None writes an unsigned v1
        # chain (offline, Tier A, pre-M10); a key signs every appended record's hash. A chain first
        # written unsigned and reopened here with a key gains signatures on new records only -- the
        # writer's own documented resume behaviour, which the fidelity gate reads as a chain that
        # was signed from the point the key arrived, not retroactively.
        self.writer = AuditChainWriter.open(
            self.path,
            max_justification_chars=max_justification_chars,
            signing_key=signing_key,
        )

    def append(self, draft: AuditDraft) -> AuditRecord:
        """Seal ``draft`` into the chain and return it as a validated record."""
        return AuditRecord.model_validate(self.writer.append(draft))

    def append_execution(self, draft: ExecutionRecordDraft) -> ExecutionRecord:
        """Seal an execution follow-up (ADR-082) and return it as a validated record.

        The same round-trip :meth:`append` performs, over the same writer and the same chain, for
        the same reason: the writer scrubs and bounds before hashing, and validating what comes back
        against :class:`~guardian.app.models.ExecutionRecord` is what makes a shape the writer
        produced but this record's own contract would refuse an append-time failure rather than a
        defect discovered on some later read of a sealed bundle.
        """
        return ExecutionRecord.model_validate(self.writer.append(draft))

    def record_run_start(self, draft: RunStartDraft) -> RunStartRecord | None:
        """Seal ``draft`` as the chain's genesis if, and only if, the chain holds no record yet.

        ADR-058. A Guardian starting on a new or empty per-run chain writes one run-start record at
        ``seq`` zero, so a run whose agents never reached the Guardian still leaves a present,
        verifiable chain for ``data-management.md`` section 3. A Guardian starting on a chain that
        already holds records is a restart -- :meth:`AuditChainWriter.open` walked and verified it
        before this sink existed -- and appends nothing, because a second run-start would claim a
        second genesis inside one run. Returns the sealed record, or ``None`` on a resumed chain.

        The written record is validated as :class:`~guardian.app.models.RunStartRecord` for the
        reason :meth:`append` validates a decision, and that model refuses a run-start anywhere but
        ``seq`` zero -- so a future edit that dropped the position check here would fail loudly at
        the first restart rather than quietly writing a second genesis.
        """
        if self.writer.next_seq != 0:
            return None
        return RunStartRecord.model_validate(self.writer.append(draft))


def _load_audit_signer(path: Path) -> Ed25519Signer:
    """Load the Ed25519 audit-signing key from a PEM file (ADR-130).

    The crypto import is here, in the assembler, and lazy: ``guardian/audit/chain.py`` stays
    standard-library at import (ADR-022) by taking the :class:`~guardian.audit.chain.Ed25519Signer`
    protocol, and ``cryptography``'s ``Ed25519PrivateKey`` satisfies it structurally --
    ``sign(bytes) -> bytes``. The key is *handed in*, built by the operator-managed process that
    holds the file; this never fabricates one. A file that is not a PEM Ed25519 private key is a
    startup failure with a named reason, on config.py's rule that a Guardian told to sign must not
    start unable to.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    try:
        material = path.read_bytes()
    except OSError as error:
        raise GuardianStartupError(
            f"the audit-signing key at {str(path)!r} could not be read: {error}"
        ) from error
    try:
        key = serialization.load_pem_private_key(material, password=None)
    except (ValueError, TypeError) as error:
        raise GuardianStartupError(
            f"the audit-signing key at {str(path)!r} is not a readable PEM private key: {error} "
            "(ADR-130 expects an Ed25519 private key in PEM form)"
        ) from error
    if not isinstance(key, Ed25519PrivateKey):
        raise GuardianStartupError(
            f"the audit-signing key at {str(path)!r} is a {type(key).__name__}, not an Ed25519 "
            "private key; the audit signature scheme is audit-ed25519/v1 (ADR-130)"
        )
    return key


# --------------------------------------------------------------------------------------------
# The assembly
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class AssembledGuardian:
    """Everything :func:`build_guardian` produced, in one frozen value.

    Frozen because a composition root's output is a fact about how one process was built, and a
    caller that could rebind ``mediator`` after the fact would be a second, later composition root
    with none of this file's argument attached to it.

    ``executor`` and ``audit_sink`` are carried alongside the four that a server needs, and both
    additions are deliberate rather than incidental: they are the two collaborators whose *identity*
    a caller most needs to be able to see, and neither is reachable from anything else here.

    ADR-023's isolation assertion 2b is "under ``G1-LOGONLY`` a denied action reaches the executor",
    which is checkable only against the executor instance this root chose. The audit sink holds the
    chain's live head, which is the anchor ``guardian/audit/verify.py`` verifies a chain against and
    is a property of the writer rather than of the file -- a second writer opened on the same path
    would have a head of its own and would answer a different question. Reaching either through a
    private attribute of the mediator would be a caller asserting on an implementation detail, and
    rebuilding one to compare against would be asserting on a different object.
    """

    mediator: Mediator
    token_issuer: AuthorityBoundedTokenIssuer
    app: FastAPI
    policy_bundle: PolicyBundle
    executor: ActionExecutor
    audit_sink: AuditChainSink


def build_guardian(
    config: GuardianConfig,
    *,
    policy_engine: PolicyEngine | None = None,
    issuance_engine: PolicyEngine | None = None,
    clock: GuardianClock | None = None,
    replay_cache: Any | None = None,
    action_caps: Any | None = None,
    jti_factory: Callable[[], str] | None = None,
    control_plane_authenticator: ControlPlaneVerifier | None = None,
) -> AssembledGuardian:
    """Assemble one Guardian from ``config`` alone, or raise a startup error.

    Every collaborator below is built from configuration and nothing is read from the environment
    here. The order is load-then-wire: the policy bundle is loaded and digested first, because a
    Guardian whose policy is missing has no correct behaviour available to it and refusing while
    somebody is watching is cheaper than refusing an entire campaign of requests; then the engines,
    which fail the same way if no ``opa`` binary can be found; then the token service, the sink and
    the executor. The one record assembly itself writes comes last: the run-start genesis ADR-058
    puts at the head of a new or empty per-run chain -- last, so that a Guardian which refuses to
    start has written nothing, and only on an empty chain, so that a restart resumes the run's chain
    rather than beginning a second one inside it.

    **The five keyword seams each default to the real collaborator, built from ``config``.** They
    exist so that ``guardian/tests/harness.py`` can drive *this* assembly with a canned policy
    answer, a frozen clock, a small replay cache and a chosen ``jti`` rather than assembling a
    parallel one -- which is the duplication this module was written to remove, and which the M4
    plan names as the point of the task. Nothing about them weakens the "no default substitutes a
    fake" rule: a fake is reachable only by a caller that names one, and there is no configuration,
    absent value or environment variable that produces one by itself.

    The executor is the deliberate exception to that sentence and is not an exception to the rule.
    It is chosen by :attr:`~guardian.app.config.GuardianConfig.executor`, which has no default at
    all, so ``fake`` is reached only by an operator who wrote it down. See
    :class:`~guardian.app.config.ExecutorKind` for why that is required rather than defaulted.

    ``replay_cache`` is typed loosely because ``guardian.token.verifier.JtiClaimant`` is a
    one-method protocol the token package publishes for exactly this purpose, and importing it here
    to annotate a parameter would couple the composition root to an internal name for no checkable
    gain -- the verifier validates the shape it is handed. When it is absent, production uses the
    Guardian-owned SQLite file from ``config.replay_store_path``; the injectable seam remains for
    deterministic tests (ADR-045).

    ``control_plane_authenticator`` (ADR-128) defaults to the real
    :class:`~guardian.app.control_auth.ControlPlaneAuthenticator` built from configuration, which
    defers its Kubernetes client to the first call and so contacts no cluster at assembly time --
    the
    same discipline the executor applies. A Guardian that cannot establish a control-plane caller
    answers 401 on ``/v1/tokens`` and ``/v1/phase``; that is the fail-closed reading of "no caller
    could be verified here", and it is why the seam exists at all: the suite has no cluster, so it
    names a verifier rather than being refused the surface.

    ``action_caps`` (ADR-129) defaults to the real
    :class:`~guardian.app.limits.SQLiteActionCapReserver` over
    :attr:`~guardian.app.config.GuardianConfig.action_cap_store_path`, beside the audit log. The
    seam
    exists for the reason every seam here exists -- a test that wants to drive a cap boundary in one
    assertion rather than thirty-two may name its own -- and the default is the real store rather
    than
    a no-op, because the failure a no-op default would produce is the exact one this component must
    not have: a Guardian that mediates perfectly, writes a record saying ``action_caps`` is null or
    full, and enforces no budget at all.
    """
    bundle = PolicyBundle.load(config.policy)
    # Resolved once and shared, so a Guardian cannot end up evaluating its actions with one engine
    # binary and its issuance with another -- which would make the bundle digest a statement about
    # bytes two different programs read. Resolved only when at least one engine has to be built,
    # because a caller that supplied both has no use for a binary and should not be refused for the
    # absence of one.
    binary = resolve_opa_binary() if policy_engine is None or issuance_engine is None else None
    action_engine: PolicyEngine = (
        policy_engine
        if policy_engine is not None
        else OpaSubprocessEngine(
            bundle=bundle, entrypoint=config.policy.entrypoint, binary=_required(binary)
        )
    )
    authority_engine: PolicyEngine = (
        issuance_engine
        if issuance_engine is not None
        else OpaSubprocessEngine(
            bundle=bundle, entrypoint=config.issuance_entrypoint, binary=_required(binary)
        )
    )

    timeline: GuardianClock = clock if clock is not None else SystemClock()
    parameters = TokenParameters(
        algorithm=config.token.algorithm,
        default_ttl_seconds=config.token.lifetime_seconds,
        max_ttl_seconds=config.token.max_lifetime_seconds,
    )
    # Read once here and closed over, rather than reached through `config` at every call. The
    # SecretStr is what keeps the value out of a repr, a log line and a model dump; a single
    # explicit `get_secret_value()` is what a reviewer greps for, and thirteen of them would not be.
    material = config.signing_key.get_secret_value()
    cache = (
        replay_cache
        if replay_cache is not None
        else SQLiteReplayStore(
            config.replay_store_path,
            min_entries=config.token.replay_cache_entries,
            window_seconds=config.token.replay_cache_window_seconds,
            clock=timeline.epoch,
        )
    )

    issuer = JwsTokenIssuer(
        parameters=parameters,
        signing_key_provider=lambda: material,
        clock=timeline.epoch,
        jti_factory=jti_factory if jti_factory is not None else _random_jti,
    )
    verifier = CapabilityTokenVerifierAdapter(
        verifier=JwsTokenVerifier(
            parameters=parameters,
            verification_key_provider=lambda: material,
            clock=timeline.epoch,
            replay_cache=cache,
        ),
        registered_issuers=config.registered_issuers,
    )
    # ADR-128. One PhaseState, written by `POST /v1/phase` (gated in `create_app`) and read by the
    # issuer's phase-currency bound below. Created here rather than inside `create_app` so the two
    # share the one object: a declaration the runner makes must be the phase the next mint checks
    # against, and two PhaseState instances would leave the bound reading state nobody wrote. It is
    # process state, not configuration, so it is built here and not carried in `GuardianConfig`.
    phase_state = PhaseState()
    token_issuer = AuthorityBoundedTokenIssuer(
        inner=CapabilityTokenIssuerAdapter(issuer=issuer),
        engine=authority_engine,
        guardian_run_id=config.run_id,
        timeout_seconds=config.policy.evaluation_timeout_seconds,
        phase_state=phase_state,
    )
    executor = build_executor(config)
    # ADR-130. The Guardian signs its audit chain when the deployment supplies an Ed25519 key, and
    # writes an unsigned v1 chain otherwise (Tier A, offline, pre-M10) --
    # config.audit_signing_key_file is None in exactly those cases. The path was proven present and
    # non-empty at config time; here it is parsed into the signer the writer appends with.
    audit_signer = (
        _load_audit_signer(config.audit_signing_key_file)
        if config.audit_signing_key_file is not None
        else None
    )
    audit_sink = AuditChainSink(config.audit_log_path, signing_key=audit_signer)
    caps = (
        action_caps
        if action_caps is not None
        else SQLiteActionCapReserver(config.action_cap_store_path)
    )
    mediator = Mediator(
        config=config,
        policy_bundle=bundle,
        policy_engine=action_engine,
        verifier=verifier,
        executor=executor,
        audit_sink=audit_sink,
        caps=caps,
        clock=timeline.instant,
    )
    app = create_app(
        mediator=mediator,
        token_issuer=token_issuer,
        # ADR-128. The authenticator defaults to the real TokenReview-backed one, built from the
        # two settings config.py requires with no default; `phase_state` is the channel issuance's
        # phase bound is read from, and is process state rather than configuration, so it is created
        # here rather than carried in `GuardianConfig`.
        control_plane_authenticator=(
            ControlPlaneAuthenticator.from_config(config)
            if control_plane_authenticator is None
            else control_plane_authenticator
        ),
        phase_state=phase_state,
    )
    # ADR-058: the chain's genesis. Written last, after every collaborator was built and the
    # Mediator accepted the run id, so a Guardian that refuses to start has written nothing; and a
    # no-op on a resumed chain, so a restart never claims a second genesis inside one run.
    audit_sink.record_run_start(
        RunStartDraft(
            ts=timeline.instant(),
            run_id=config.run_id,
            guardian_mode=config.mode,
            record_type=AUDIT_RECORD_TYPE_RUN_START,
            schema_version=AUDIT_RECORD_SCHEMA_VERSION,
        )
    )
    return AssembledGuardian(
        mediator=mediator,
        token_issuer=token_issuer,
        app=app,
        policy_bundle=bundle,
        executor=executor,
        audit_sink=audit_sink,
    )


def _required(binary: Path | None) -> Path:
    """Return ``binary``, or raise because an engine was about to be built without one.

    Unreachable through :func:`build_guardian`, whose own conditional resolves the binary in exactly
    the cases an engine is constructed. It exists so that the invariant is stated where it is relied
    on rather than left to a reader re-deriving the conditional two screens up -- and so that a
    later edit which separates the two produces a refusal to start instead of a subprocess argv with
    ``None`` in it.
    """
    if binary is None:
        raise GuardianStartupError(
            "a policy engine was about to be built with no resolved opa binary; see "
            "guardian/app/opa.py for how one is located and why the Guardian refuses to start "
            "without it"
        )
    return binary


def build_executor(config: GuardianConfig) -> ActionExecutor:
    """Return the executor ``config`` names, or raise naming the accepted set.

    A separate function because it is the one place in this module where a *choice* is made rather
    than a construction performed, and a choice that decides whether a Guardian can change anything
    at all deserves to be readable on its own. Its failure shape is
    :func:`guardian.app.config._parse_mode`'s: an unrecognised value raises
    :class:`~guardian.app.config.GuardianStartupError` naming what was accepted, never falls back.

    The fallback is unreachable in practice, because
    :class:`~guardian.app.config.ExecutorKind` is a closed enum and configuration parsing already
    refused anything outside it. It is here anyway, for the reason ``guardian/app/policy.py`` gives
    about its own unreachable branches: this is the enforcement path, the cost of the check is one
    comparison, and the day a member is added to the enum without a branch here the failure is a
    refusal to start rather than a Guardian assembled with whichever executor the last line built.
    """
    if config.executor is ExecutorKind.FAKE:
        return FakeActionExecutor()
    if config.executor is ExecutorKind.KUBERNETES:
        # The run id labels every object the executor creates, so that run's teardown can remove
        # it and the next run starts from the baseline (ADR-081).
        return KubernetesActionExecutor(run_id=config.run_id)
    accepted = ", ".join(kind.value for kind in ExecutorKind)
    raise GuardianStartupError(
        f"no executor is built for {config.executor!r}; accepted values are {accepted}"
    )


def create_app_from_config(config: GuardianConfig) -> FastAPI:
    """Build the ASGI application for ``config``. The entry point's one-liner.

    ``guardian/app/main.py``'s :func:`~guardian.app.main.create_app` takes an already-assembled
    mediator and reads no configuration, which is what keeps it free of any path where a missing
    dependency is silently replaced with something weaker. This is the other half: it reads no
    configuration either -- it is *handed* one -- and it assembles the dependencies explicitly.

    Everything :func:`build_guardian` produced other than the application is discarded, which is
    correct for a server and is why the richer function exists beside this one: a test, a
    diagnostic, or a future admin surface needs the mediator and the bundle digest, and a server
    needs neither.
    """
    return build_guardian(config).app
