r"""Capability-token issuance: the only place in the system where a scope becomes a credential.

WHAT THIS MODULE IS
-------------------
``docs/02-architecture.md`` section 2 puts token issuance at one point in the data flow -- phase
Supervisors "spawn Executors with short-TTL tokens" -- and
``docs/adr/ADR-004-capability-tokens-jwt.md`` resolves that into JWTs "signed by the Guardian's
token service at Supervisor request". The
Supervisor asks; the Guardian mints. This module is the minting half, reached through
``POST /v1/tokens`` on the mediation API, and it is deliberately small: it validates an issue
request, stamps ``iat`` and ``exp`` from an injected clock, and signs. It grants nothing on its
own, because a token is not an authorisation -- it is a *claim* about scope that
:mod:`guardian.token.verifier` and then OPA still have to accept.

The dependency runs from here into the verifier and never the other way. Every claim minted below
is constructed by handing a payload to the verifier's own
:meth:`guardian.token.verifier.CapabilityClaims.from_payload`, which is the same validator the
verification path runs on a presented token. That is not code
reuse for its own sake: it is what makes it impossible for this Guardian to mint a token its own
verifier would reject. A separate, more permissive validator on the issue path would produce
credentials that are valid at birth and denied on arrival, and the failure would surface as a
mysterious mid-run denial rather than as a refused issue request.

EVERY PROTOCOL PARAMETER ARRIVES BY CONFIGURATION; NONE IS A LITERAL HERE
-------------------------------------------------------------------------
``docs/protocols/security-policy.md`` section 2 owns the default token lifetime, the per-phase
override ceiling and the signing algorithm, and ``.agents/rules/00-source-of-truth.md`` allows each
to be stated exactly once. None of them appears in this file. They arrive as
:class:`guardian.token.verifier.TokenParameters`, built by the composition root under
``guardian/app/`` from configuration seeded by section 2, and a grep of ``guardian/token/`` for any
section 2 value finds nothing. The clock arrives the same way: this module never imports
:mod:`time`, so ``iat`` and ``exp`` are exactly what the injected clock says and the expiry cases
in the adversarial suite are deterministic rather than timing-dependent.

The ``jti`` arrives from an injected factory for the reason
``.agents/rules/20-parity-and-determinism.md`` gives -- there is no unseeded randomness anywhere in
a path a run depends on -- and for a second reason specific to testing: the replay cases in
``docs/plans/M3-implementation-plan.md``'s adversarial group D need to name a particular ``jti``
and present it twice, which is awkward against a generator the test cannot see. Whatever the
factory returns is validated exactly like a presented claim, so a defective factory produces a
refused issue request rather than an unusable token.

AN OVERRIDE ABOVE THE CEILING IS REFUSED, NEVER TRUNCATED
----------------------------------------------------------
Section 2 permits a per-phase TTL override "up to" a ceiling.
``docs/plans/M3-implementation-plan.md``'s adversarial group B fixes what happens beyond it: an
``exp`` past the ceiling is "rejected rather than silently truncated". This module therefore raises
:class:`TokenIssueRefused` with :attr:`IssueRefusalReason.TTL_ABOVE_CEILING` and mints nothing.

The rejected alternative -- clamp the request to the ceiling and issue -- is the more forgiving
design and is worse in a way that is easy to miss. Clamping returns success. The Supervisor that
asked for a long-lived token is told it got one, plans around a lifetime it does not have, and
discovers the truth as an expired-token denial in the middle of a containment action. Worse, the
control reports that it worked while doing something other than what was asked, which means the
audit record of a clamped issue is indistinguishable from an honest one and the evaluation cannot
see that a ceiling was ever hit. A security control that silently substitutes its own answer is not
a control; it is a source of surprises with a reassuring name. Refusing costs one error path and
buys an accurate record.

The same ceiling is applied a second time on the verification side, to ``exp - iat`` of a presented
token. The redundancy is deliberate: the check here protects a well-behaved Supervisor from asking
for too much, and the check there protects the enforcement path from an issuer that has been
changed, broken or bypassed.

THE CLAIM SET CARRIES A NINTH MEMBER, AND THIS MODULE IS WHY IT IS NEVER ABSENT
------------------------------------------------------------------------------- Architecture
section 3 fixes nine claims, and the ninth is ``schema_version``. It arrived as an addition
``guardian/app/models.py`` made beyond section 3's original eight and was folded into the section
at M4; either way the obligation on this module is the same one that file states as a hard
requirement rather than a suggestion: **the issuer must stamp it into every token it mints, or
verification rejects its own tokens**. That is not a style point.
:class:`guardian.app.models.CapabilityTokenClaims` declares the field as a ``Literal`` with no
default and forbids extras, so a payload without it is not a claim set at all -- an unstamped token
is authentic, live, in scope, unspent, and denied under ``authenticity.claims-malformed`` at the
last step before policy. The failure would present as a Guardian refusing credentials it had just
issued, which is among the harder things to diagnose from an audit log.

So the version is stamped at the point of signing, and it is stamped from a constant that lives in
two files. That duplication is a cost and is recorded as one. The alternative -- importing the
constant from ``guardian.app.models`` -- would contradict the boundary this module already
maintains: :data:`ISSUE_REFUSAL_CODES` above is published precisely "so the app layer can map a
refusal onto its own error contract without importing this module's internals", and the same
sentence in reverse is why nothing here reaches into ``guardian/app/``. ADR-022 fixes the shape for
this exact trade, in the case where two components must agree on one value and must not depend on
each other: state the rule once in prose, allow two homes, and write a cross-check that turns
"these agree today" into "these cannot drift". ``guardian/tests/test_token_contract_seam.py`` holds
the two equal and fails the build the day one moves without the other.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
``POST /v1/tokens`` in ``guardian/app/`` is the only caller, and the AuditRecord records the
``jti`` and ``iss`` this module stamps, so those two claims are the attribution path that
``docs/protocols/security-policy.md`` section 1.4 and NFR6 require. :data:`ISSUE_REFUSAL_CODES` is
published so the app layer can map a refusal onto its own error contract without importing this
module's internals. Changing the claim set is not a change to this file at all: architecture
section 3 owns it, and it outranks code.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

import jwt
from guardian.token.verifier import (
    AllowClaim,
    CapabilityClaims,
    ClaimRejection,
    DenialReason,
    TokenParameters,
    is_plain_int,
    validated_identifier,
)
from jwt.exceptions import InvalidKeyError, PyJWTError


class IssueRefusalReason(StrEnum):
    """The closed set of structured reasons an issue request can be refused for.

    Separate from :class:`guardian.token.verifier.DenialReason` because the two have different
    lifecycles and different audiences. A denial is an adversarial event: it happens on the
    enforcement path, it is audited, and it is scored. A refusal is a *request* that could not be
    honoured -- a Supervisor asking beyond the ceiling, a malformed scope, an unusable signing key
    -- and it is answered to the caller of ``POST /v1/tokens``. Merging them would put
    configuration faults into the same vocabulary the evaluation reads as attacks.

    Values are prefixed ``issue_`` so that no code from this enum can ever be mistaken for a
    verification reason in a log or a data frame.
    """

    TTL_NOT_POSITIVE = "issue_ttl_not_positive"
    TTL_ABOVE_CEILING = "issue_ttl_above_ceiling"
    CLAIM_MALFORMED = "issue_claim_malformed"
    PHASE_UNKNOWN = "issue_phase_unknown"
    SIGNING_KEY_UNAVAILABLE = "issue_signing_key_unavailable"
    ENCODING_FAILED = "issue_encoding_failed"


# Published for the same reason DENIAL_REASON_CODES is: guardian/app/ can assert its own error
# vocabulary covers this one from a test, without either module importing the other.
ISSUE_REFUSAL_CODES: Final[tuple[str, ...]] = tuple(reason.value for reason in IssueRefusalReason)

# The claim-set version stamped into every minted token. See the module docstring section
# "THE CLAIM SET CARRIES A NINTH MEMBER, AND THIS MODULE IS WHY IT IS NEVER ABSENT" for why the
# value has two homes rather than one, and which test holds them equal.
#
# guardian/app/models.py owns it as CAPABILITY_TOKEN_SCHEMA_VERSION. This is a copy, and the copy
# is deliberate: this module's own docstring fixes the decoupling -- guardian/token/ and
# guardian/app/ publish their vocabularies to each other and neither imports the other -- and an
# import taken here to save one literal would repay that decoupling by coupling the token service
# to the contract module it exists to be checkable against. ADR-022 settles the shape for exactly
# this trade: one rule stated once in prose, two homes, and a test that makes "copy" mean "copy
# that cannot drift". guardian/tests/test_token_contract_seam.py is that test.
CAPABILITY_TOKEN_SCHEMA_VERSION: Final = "v1"  # noqa: S105


class TokenIssueRefused(Exception):
    """An issue request that will not be honoured, carrying a structured reason and claim name.

    An exception rather than a returned verdict, which is the opposite of the choice
    :class:`guardian.token.verifier.VerificationOutcome` makes, and the asymmetry is intentional. A
    verification denial must be audited, so it is a value the caller is forced to consume. A
    refusal has nothing to enforce and nothing to hide: the correct behaviour is to abandon the
    request loudly, and the one thing that must never happen -- issuing anyway with an adjusted
    lifetime -- is impossible if the only path out of the failure is a raise.

    ``str(exc)`` is the reason code and the claim name, and nothing else. No free text, no request
    echo, and never any part of the signing key or of a token.
    """

    def __init__(self, reason: IssueRefusalReason, claim: str | None = None) -> None:
        super().__init__(reason.value if claim is None else f"{reason.value}:{claim}")
        self.reason = reason
        self.claim = claim

    @property
    def reason_code(self) -> str:
        """The wire form of :attr:`reason`."""
        return self.reason.value


@dataclass(frozen=True, slots=True)
class IssuedToken:
    """A minted token and the claims inside it.

    ``encoded`` carries ``repr=False``. It is a live bearer credential: anything that can present
    it can act with its scope until it expires or is spent, so a dataclass whose default ``repr``
    printed it would put a working capability into every traceback, every debugger frame and every
    log line that formatted the object. The claims are safe to show and are what the audit chain
    records anyway.
    """

    encoded: str = field(repr=False)
    claims: CapabilityClaims


class TokenIssuer:
    """Mint capability tokens on Supervisor request, within the parameters section 2 fixes.

    Construction takes everything it needs and reads nothing from the environment:

    ``parameters``
        The section 2 values, already resolved by the composition root.
    ``signing_key_provider``
        A zero-argument callable returning the current signing key. Called at each issue rather
        than cached, so "rotated on demand" is a configuration change rather than a restart, and so
        that no key material is ever an attribute of this object and therefore never appears in a
        ``repr``. Returning an empty value refuses the request; there is no default key and no
        environment fallback, because a Guardian that mints tokens under a key nobody configured is
        worse than one that will not start.
    ``clock``
        A zero-argument callable returning integer epoch seconds. The only source of time here.
    ``jti_factory``
        A zero-argument callable returning the ``jti`` for the next token. Required, with no
        default, so that this module imports no random source at all.
    """

    def __init__(
        self,
        *,
        parameters: TokenParameters,
        signing_key_provider: Callable[[], str | bytes | None],
        clock: Callable[[], int],
        jti_factory: Callable[[], str],
    ) -> None:
        self._parameters = parameters
        self._signing_key_provider = signing_key_provider
        self._clock = clock
        self._jti_factory = jti_factory
        # A private codec with RFC 7518 section 3.2's minimum HMAC key length enforced, so that a
        # weak configured key raises InvalidKeyError instead of emitting a warning nobody reads.
        # An instance is used rather than the module-level `jwt.encode` because the option lives on
        # the codec, and rather than a `warnings` filter because filter state is process-global and
        # this Guardian serves concurrent requests. The threshold itself stays inside PyJWT: it is
        # a property of the algorithm, not a parameter for this repository to restate.
        self._codec = jwt.PyJWT(options={"enforce_minimum_key_length": True})

    @property
    def parameters(self) -> TokenParameters:
        """The configured section 2 parameters this issuer was built with."""
        return self._parameters

    def issue(
        self,
        *,
        issuer_id: str,
        subject_id: str,
        run_id: str,
        phase: str,
        allow: AllowClaim | Mapping[str, object],
        ttl_seconds: int | None = None,
    ) -> IssuedToken:
        """Mint one token, or raise :class:`TokenIssueRefused`.

        ``issuer_id`` is the requesting Supervisor and becomes ``iss``; ``subject_id`` is the
        Executor the token is minted for and becomes ``sub``. Both are stamped by the Guardian from
        the authenticated request rather than copied out of anything an Executor supplies -- an
        Executor that could name its own ``sub`` could mint itself another Executor's scope.

        ``ttl_seconds`` of ``None`` means the configured default. Any other value is the per-phase
        override, and it is refused rather than truncated when it exceeds the ceiling.
        """
        ttl = self._parameters.default_ttl_seconds if ttl_seconds is None else ttl_seconds
        if not is_plain_int(ttl) or ttl <= 0:
            raise TokenIssueRefused(IssueRefusalReason.TTL_NOT_POSITIVE, "exp")
        if ttl > self._parameters.max_ttl_seconds:
            # Refused, not clamped. See the module docstring: a control that quietly substitutes
            # its own answer reports success for something other than what was asked.
            raise TokenIssueRefused(IssueRefusalReason.TTL_ABOVE_CEILING, "exp")

        issued_at = self._clock()
        if not is_plain_int(issued_at) or issued_at < 0:
            raise TypeError("clock must return a non-negative integer number of epoch seconds")

        try:
            jti = validated_identifier(self._jti_factory(), "jti")
        except ClaimRejection as rejection:
            raise TokenIssueRefused(IssueRefusalReason.CLAIM_MALFORMED, rejection.claim) from None

        allow_value = allow.as_mapping() if isinstance(allow, AllowClaim) else allow
        payload: dict[str, object] = {
            "iss": issuer_id,
            "sub": subject_id,
            "run_id": run_id,
            "phase": phase,
            "allow": allow_value,
            "jti": jti,
            "iat": issued_at,
            "exp": issued_at + ttl,
        }

        # The verifier's own validator, run on the way out. Anything it would deny on arrival is
        # refused here instead of being signed.
        try:
            claims = CapabilityClaims.from_payload(payload)
        except ClaimRejection as rejection:
            refusal = (
                IssueRefusalReason.PHASE_UNKNOWN
                if rejection.reason is DenialReason.PHASE_UNKNOWN
                else IssueRefusalReason.CLAIM_MALFORMED
            )
            raise TokenIssueRefused(refusal, rejection.claim) from None

        signing_key = self._signing_key_provider()
        if not signing_key:
            raise TokenIssueRefused(IssueRefusalReason.SIGNING_KEY_UNAVAILABLE)

        # The signed payload is the validated claim set plus the one claim architecture section 3's
        # eight do not include. guardian/app/models.py states the obligation in terms this module
        # has to meet: "the issuer must stamp CAPABILITY_TOKEN_SCHEMA_VERSION into every token it
        # mints, or verification rejects its own tokens under TOKEN_CLAIMS_MALFORMED" -- because
        # CapabilityTokenClaims requires the field and forbids extras, so a token without it does
        # not validate as a claim set at all. It is added here rather than inside CapabilityClaims
        # because that dataclass is the *verifier's* eight-claim shape, shared by both paths, and
        # widening it would be an edit to the verification path made from the issue path.
        signed_payload: dict[str, object] = {
            **claims.to_payload(),
            "schema_version": CAPABILITY_TOKEN_SCHEMA_VERSION,
        }

        try:
            encoded = self._codec.encode(
                signed_payload,
                signing_key,
                # Singular, and taken from configuration seeded by security-policy section 2. The
                # verifier's allowlist is built from the same field, so the two cannot drift into a
                # state where this Guardian mints what it will not accept.
                algorithm=self._parameters.algorithm,
            )
        except InvalidKeyError:
            # The configured key is empty or below the algorithm's minimum length. An operational
            # fault, refused loudly rather than signed weakly.
            raise TokenIssueRefused(IssueRefusalReason.SIGNING_KEY_UNAVAILABLE) from None
        except PyJWTError:
            raise TokenIssueRefused(IssueRefusalReason.ENCODING_FAILED) from None

        return IssuedToken(encoded=encoded, claims=claims)
