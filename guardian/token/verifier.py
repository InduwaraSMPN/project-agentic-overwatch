r"""Capability-token verification: the one place a hostile agent layer is told "no" on authenticity.

WHAT THIS MODULE IS
-------------------
``docs/plans/M3-implementation-plan.md`` opens its threat model with the sentence this file is
written against: *the agent layer is the attacker*. The adversary is assumed to hold position P1
(arbitrary ``ActionRequest`` content), P2 (arbitrary token bytes -- minted, mutated, or captured
from another Executor), P3 (unbounded request volume and ordering) and P4 (network reach to the
Guardian's HTTP surface). It does not hold the signing key, and it does not hold the audit file
handle. Everything below follows from that split: this module trusts the configured key and the
injected clock, and it trusts nothing that arrives in a token.

:class:`TokenVerifier` answers exactly one question -- *is this byte string an authentic,
unexpired, unspent capability token minted for this run, this phase and this Executor?* -- and
answers it as a :class:`VerificationOutcome` carrying a structured :class:`DenialReason` rather
than a message. Whether the token's ``allow`` claim covers the *particular* verb, resource and
namespace being requested is a separate question, answered by OPA against
``guardian/policies/``; this module hands those claims over in a validated, typed form and stops.

This module also owns the pieces the issuer must agree with -- :class:`TokenParameters`,
:class:`AllowClaim`, :class:`CapabilityClaims`, the claim validators and :data:`PHASES`. The
dependency direction is deliberate and is the opposite of what module names suggest:
:mod:`guardian.token.issuer` imports this module and never the reverse. The checker defines what
a valid token is and the minter conforms to it, so there is exactly one definition of a
well-formed claim value and the Guardian cannot mint a token its own verifier would reject. It
also means this module imports nothing that can sign, so a verifier-only deployment is possible
and a review of the verification path never has to read minting code.

EVERY PROTOCOL PARAMETER ARRIVES BY CONFIGURATION; NONE IS A LITERAL HERE
-------------------------------------------------------------------------
``docs/protocols/security-policy.md`` section 2 owns the token lifetime, the per-phase override
ceiling, the replay window and size, and the signing algorithm.
``.agents/rules/00-source-of-truth.md`` allows each of those to be written exactly once, and
section 2 is where. This module therefore names none of them: :class:`TokenParameters` requires
``algorithm``, ``default_ttl_seconds`` and ``max_ttl_seconds`` as constructor arguments with no
defaults, and the composition root under ``guardian/app/`` supplies them from configuration seeded
by section 2. A grep of ``guardian/token/`` for any section 2 value returns nothing. The numeric
literals that *do* appear here are of a different kind -- a zero used as a positivity floor, a
DNS-name length bound, a parse-size cap -- and each is documented at its definition as a
structural fact rather than a tuned parameter.

The clock is injected for the same reason and one more. This module never calls :mod:`time`; it
calls the ``clock`` callable given to the constructor, which returns integer epoch seconds. That
makes the temporal cases in ``docs/plans/M3-implementation-plan.md``'s adversarial group B exact
rather than approximate, and it removes the only source of nondeterminism this component would
otherwise have.

THE ALGORITHM ALLOWLIST IS THE SINGLE MOST LOAD-BEARING LINE IN THE FILE
-------------------------------------------------------------------------
Two classic attacks are defeated by the same control. ``alg: none`` presents a token with no
signature and a header asserting that none is required. Algorithm confusion presents a token whose
header claims an asymmetric algorithm -- ``RS256`` -- while its signature is an HMAC computed with
what the attacker hopes the verifier will pass as a "public key", which for a symmetric deployment
is the shared secret itself. Both work only against a verifier that lets the *token* choose how it
will be checked.

:meth:`TokenVerifier.verify` therefore reads the header's ``alg`` before anything else and denies
unless it is exactly ``parameters.algorithm``, then passes that same single-element allowlist to
:func:`jwt.decode`. The check is deliberately made twice, in two different libraries' worth of
code, and the redundancy is the point rather than an oversight: the first check is what produces
the accurate reason code, and the second is what holds if the first is ever refactored away.
PyJWT 2.x does require an ``algorithms`` argument, so this is not compensating for a permissive
default -- it is compensating for the fact that the argument accepts a *list*, and a list is a
thing a future contributor can widen without noticing what they have widened.

WHAT THIS MODULE NORMALISES, AND WHAT IT REFUSES TO NORMALISE
--------------------------------------------------------------
Nothing. No case folding, no Unicode normalisation of any form, no whitespace stripping, no
percent-decoding, no path cleaning, no deduplication. Every comparison is ``==`` on the exact
string that arrived, and the claims stored on :class:`CapabilityClaims` are byte-for-byte the
claims that were signed, so the value the audit chain records is the value that was presented.

The reasoning runs in both directions, and both directions matter. A normalisation that makes two
different strings compare equal is an attack: were this module to apply NFKC before comparing
``run_id`` or ``phase``, a Kelvin sign would fold onto a capital K and a fullwidth letter onto its
ASCII twin, and a value that a human reviewer reads as distinct would authorise the scope of one
it merely resembles. A normalisation that "cleans" a value is the same defect wearing a helpful
face: stripping ``../`` from ``../../kube-system`` produces ``kube-system``, which is to say it
converts a rejected input into an accepted one with a wider scope than either.

What replaces normalisation is *validation that only ever narrows*. Every identifier claim and
every scope entry must be non-empty, within :data:`_MAX_IDENTIFIER_CHARS`, and drawn entirely from
:data:`_IDENTIFIER_ALPHABET` -- ASCII letters, digits, ``.``, ``_``, ``:`` and ``-``. That single
rule disposes of three families at once. Traversal dies because ``/``, ``\`` and the path
separators are simply not in the alphabet, so ``../../kube-system`` is rejected as malformed and
is never rewritten into something acceptable. Homoglyphs die because every codepoint above
U+007F is rejected, so a Cyrillic ``а`` never enters the system at all; this matters less for our
own comparisons, which would treat it as unequal and deny anyway, than for everything downstream
-- OPA, the audit log, a human reading a report -- that might normalise where we did not. And NUL
truncation dies with them, because control characters are outside the alphabet too.

The cost of the rule is real and is accepted deliberately rather than overlooked: Kubernetes
subresources are written ``pods/log``, and a scope entry cannot express one under this alphabet.
No M3 scenario needs a subresource. If one ever does, widening the alphabet is a deliberate change
with an ADR behind it, which is exactly the review the alternative -- an alphabet permissive enough
to be ready for it -- would have skipped.

THE ORDER OF THE CHECKS IS A SECURITY PROPERTY, NOT A STYLE CHOICE
-------------------------------------------------------------------
Cheap, least-trusting checks run first: input shape, then header, then signature, then claim
presence and well-formedness, then time, then the four bindings, and only then the single-use
``jti`` claim. Two orderings inside that sequence are load-bearing.

Signature verification precedes every claim check, so no claim value is ever *used* before it has
been proven to come from the holder of the key. The one thing read before verification is the
header's ``alg``, which must be read early by definition -- and it is used only to decide whether
to continue and which reason to report, never as an input to key selection. The key comes from
configuration and from nowhere else; this module never reads ``kid``, ``jwk``, ``jku`` or ``x5u``,
and denies outright any token carrying one, so that "the token cannot influence which key checks
it" is enforced rather than merely intended.

Spending the ``jti`` runs last, after every other check has passed. The alternative -- claiming
the ``jti`` first, as a cheap early rejection -- hands the attacker a denial-of-service it would
not otherwise have: holding a captured but otherwise valid token, it presents that token once with
a deliberately wrong ``phase``, burns the ``jti`` on a request that was going to be denied anyway,
and the legitimate Executor's token is dead before it is used. Spending only on an otherwise-clean
token means a denial never consumes anything.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
``docs/plans/M3-implementation-plan.md``'s adversarial groups A, B, C and D are the specification
for this file, and each case there names an outcome this module must produce. Every value of
:class:`DenialReason` is part of the Guardian's external contract: it is what
``guardian/app/models.py`` returns as ``ActionResult.reason_code`` and what the AuditRecord
carries, so a code renamed here changes recorded evaluation data and is an ADR-004 log entry
rather than a refactor. :data:`DENIAL_REASON_CODES` is published so the app layer's own reason
enum can be asserted a superset of this one in a test, which is how the two stay aligned without
either module importing the other's definitions.
"""

from __future__ import annotations

import string
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol

import jwt
from jwt.exceptions import (
    DecodeError,
    InvalidAlgorithmError,
    InvalidKeyError,
    InvalidSignatureError,
    PyJWTError,
)

# The four phase names are fixed by docs/02-architecture.md section 1 and restated in AGENTS.md.
# They are a closed vocabulary rather than a tuned parameter -- security-policy section 2 does not
# own them and there is no second decision to drift from -- so mirroring them as a literal tuple is
# what .agents/rules/00-source-of-truth.md permits. A phase claim outside this set is denied, which
# is why the tuple is the *whole* set and not merely the ones M3 exercises.
PHASES: Final[tuple[str, ...]] = (
    "detection-and-investigation",
    "containment",
    "eradication",
    "verified-recovery",
)

# The claim set of docs/02-architecture.md section 3, in the order that document states it. Adding
# a name here is a change to an interface contract that outranks this file, not a local edit.
CLAIM_NAMES: Final[tuple[str, ...]] = (
    "iss",
    "sub",
    "run_id",
    "phase",
    "allow",
    "jti",
    "iat",
    "exp",
)

# The three lists inside the allow claim, again in section 3's order.
SCOPE_KEYS: Final[tuple[str, ...]] = ("verbs", "resources", "namespaces")

# ASCII letters, digits and four separators. See the module docstring for why the set is this
# narrow and why widening it is an ADR rather than an edit. Note what is absent: "/" and "\"
# (traversal), "*" (wildcard scope grants, which section C of the adversarial table requires be
# denied), whitespace, control characters, and every codepoint above U+007F (homoglyphs).
_IDENTIFIER_ALPHABET: Final[frozenset[str]] = frozenset(
    string.ascii_letters + string.digits + "._:-"
)

# 253 is the RFC 1123 limit on a DNS subdomain and therefore the longest a Kubernetes object or
# namespace name can be. It is a structural fact about the protected asset, not a value
# security-policy section 2 owns, and it exists so that a hostile claim cannot push an unbounded
# string into the OPA input document or the audit chain.
_MAX_IDENTIFIER_CHARS: Final[int] = 253

# A scope list long enough for any scenario and short enough to bound the audit record. Same
# category as the length bound above: a parse-time ceiling, not a policy parameter.
_MAX_SCOPE_ENTRIES: Final[int] = 64

# A parse-size ceiling on the encoded token, applied before any decoding is attempted, so that
# position P3's unbounded request volume cannot be turned into unbounded parsing work. A real
# capability token is a small fraction of this.
_DEFAULT_MAX_ENCODED_CHARS: Final[int] = 8192

# JOSE header parameters that select or transport a verification key, plus "crit". None is ever
# emitted by this Guardian's issuer. They are denied rather than ignored so that "the token cannot
# influence which key checks it" is a property the code enforces: if a future contributor adds
# header-driven key resolution, these tokens are already being refused and the change has to
# confront this list first. "crit" is included because RFC 7515 section 4.1.11 requires a verifier
# that does not understand the listed extensions to reject the token, and PyJWT ignores it.
_FORBIDDEN_HEADER_PARAMETERS: Final[frozenset[str]] = frozenset(
    {"jwk", "jku", "kid", "x5u", "x5c", "x5t", "x5t#S256", "crit"}
)


class DenialReason(StrEnum):
    """The closed set of structured reasons this module can refuse a token for.

    Values are the wire form: they travel out as ``ActionResult.reason_code`` and into the
    AuditRecord, so they are stable identifiers rather than descriptions. Member *names* avoid the
    words ruff's ``S105`` treats as password-shaped, which is why the names read ``EXPIRED`` while
    the values read ``token_expired``.
    """

    MALFORMED = "token_malformed"
    HEADER_PARAMETER_NOT_ALLOWED = "token_header_parameter_not_allowed"
    ALGORITHM_NOT_ALLOWED = "token_algorithm_not_allowed"
    SIGNATURE_INVALID = "token_signature_invalid"
    VERIFICATION_KEY_UNAVAILABLE = "token_verification_key_unavailable"
    CLAIM_MISSING = "token_claim_missing"
    CLAIM_MALFORMED = "token_claim_malformed"
    EXP_MISSING = "token_exp_missing"
    IAT_MISSING = "token_iat_missing"
    EXPIRED = "token_expired"
    ISSUED_IN_FUTURE = "token_issued_in_future"
    NOT_YET_VALID = "token_not_yet_valid"
    LIFETIME_NOT_POSITIVE = "token_lifetime_not_positive"
    LIFETIME_ABOVE_CEILING = "token_lifetime_above_ceiling"
    ISSUER_UNREGISTERED = "token_issuer_unregistered"
    SUBJECT_MISMATCH = "token_subject_mismatch"
    RUN_MISMATCH = "token_run_mismatch"
    PHASE_UNKNOWN = "token_phase_unknown"
    PHASE_MISMATCH = "token_phase_mismatch"
    REPLAYED = "token_replayed"
    REPLAY_CACHE_UNAVAILABLE = "token_replay_cache_unavailable"


# Published so that guardian/app/models.py's reason-code enum can be asserted a superset of this
# one from a test, rather than either module importing the other. That is the whole coordination
# mechanism between the two, and it is intentionally this thin: the app layer is a concurrent task
# and must not be import-coupled to the verifier's internals.
DENIAL_REASON_CODES: Final[tuple[str, ...]] = tuple(reason.value for reason in DenialReason)


class ClaimRejection(ValueError):
    """A claim value that is absent, of the wrong type, or outside the permitted alphabet.

    Carries the structured :class:`DenialReason` and the name of the offending claim, which is
    always one of :data:`CLAIM_NAMES` or :data:`SCOPE_KEYS` -- a closed vocabulary, so the pair
    stays machine-readable and no free text reaches a caller. :meth:`TokenVerifier.verify` catches
    this and converts it into a :class:`VerificationOutcome`; the issuer catches it and converts it
    into a refusal to mint.
    """

    def __init__(self, reason: DenialReason, claim: str) -> None:
        super().__init__(f"{reason.value}:{claim}")
        self.reason = reason
        self.claim = claim


@dataclass(frozen=True, slots=True)
class TokenParameters:
    """The section 2 parameters, supplied by the composition root and never defaulted here.

    ``algorithm`` is the single permitted JOSE algorithm name; it becomes the whole allowlist. The
    two TTL values are seconds: ``default_ttl_seconds`` is what the issuer applies when a
    Supervisor asks for no override, and ``max_ttl_seconds`` is the ceiling above which an override
    is refused rather than truncated. The verifier uses the ceiling too, applying it to
    ``exp - iat`` on a presented token, so that a token minted with an over-long lifetime by a
    buggy or compromised issuer is denied on arrival as well as refused at birth.

    Every field is required. There is no default, no ``None`` sentinel and no environment lookup,
    because a fallback here would let the Guardian run on a lifetime nobody chose -- the failure
    ``monitor/aggregator/limits.py`` exists to prevent, in a component where the consequence is a
    credential rather than a metric.
    """

    algorithm: str
    default_ttl_seconds: int
    max_ttl_seconds: int

    def __post_init__(self) -> None:
        if not isinstance(self.algorithm, str) or not self.algorithm:
            raise ValueError("algorithm must be a non-empty string")
        if self.algorithm.strip() != self.algorithm:
            raise ValueError("algorithm must not carry surrounding whitespace")
        for name in ("default_ttl_seconds", "max_ttl_seconds"):
            value = getattr(self, name)
            if not is_plain_int(value) or value <= 0:
                raise ValueError(f"{name} must be a positive integer number of seconds")
        if self.max_ttl_seconds < self.default_ttl_seconds:
            raise ValueError("max_ttl_seconds must not be below default_ttl_seconds")


@dataclass(frozen=True, slots=True)
class AllowClaim:
    """The ``allow {verbs[], resources[], namespaces[]}`` claim of architecture section 3.

    Stored as tuples so an instance is hashable and cannot be mutated after verification, and so
    the object handed to the policy layer cannot be widened by the code that receives it. Each list
    is non-empty by construction: an empty or null scope list is rejected at parse time rather than
    left for OPA to interpret, because "no entries" is exactly the shape a permissive rule is most
    likely to read as "no constraint".
    """

    verbs: tuple[str, ...]
    resources: tuple[str, ...]
    namespaces: tuple[str, ...]

    def as_mapping(self) -> dict[str, list[str]]:
        """Return the claim as the plain JSON shape the wire and the OPA input document use."""
        return {
            "verbs": list(self.verbs),
            "resources": list(self.resources),
            "namespaces": list(self.namespaces),
        }

    @classmethod
    def from_value(cls, value: object) -> AllowClaim:
        """Validate an untrusted ``allow`` value, or raise :class:`ClaimRejection`."""
        if not isinstance(value, Mapping):
            raise ClaimRejection(DenialReason.CLAIM_MALFORMED, "allow")
        if set(value) != set(SCOPE_KEYS):
            # Exactly the three keys: a missing one under-specifies the scope and an extra one is a
            # claim this Guardian does not understand, which is not a thing to shrug at in a
            # credential.
            raise ClaimRejection(DenialReason.CLAIM_MALFORMED, "allow")
        return cls(
            verbs=validated_scope(value["verbs"], "verbs"),
            resources=validated_scope(value["resources"], "resources"),
            namespaces=validated_scope(value["namespaces"], "namespaces"),
        )


@dataclass(frozen=True, slots=True)
class CapabilityClaims:
    """The eight claims this package validates and types.

    Architecture section 3 lists **nine**; the ninth is ``schema_version``, and it is deliberately
    absent from this dataclass. This is the shape both the issue path and the verify path share,
    and ``schema_version`` belongs to neither of them -- it is the wire format's, stamped by the
    issuer on the way out and required by :class:`guardian.app.models.CapabilityTokenClaims` on the
    way in. Widening this class to carry it would put a contract-versioning concern inside the two
    code paths that are supposed to be about authenticity and scope.
    ``guardian/app/composition.py``'s projection is where the nine come back together.

    An instance means "these values were signed by the holder of the configured key and are
    well-formed"; it does *not* mean the token is unexpired, in-scope or unspent. Only
    :class:`VerificationOutcome` with ``accepted`` true carries that meaning.
    """

    iss: str
    sub: str
    run_id: str
    phase: str
    allow: AllowClaim
    jti: str
    iat: int
    exp: int

    def to_payload(self) -> dict[str, object]:
        """Return the JWT payload in :data:`CLAIM_NAMES` order.

        Order is fixed rather than incidental: PyJWT serialises the mapping in insertion order, so
        a fixed order makes the encoded form of a given claim set byte-identical run to run, which
        is what lets the adversarial fixtures be reproducible in the sense
        ``.agents/rules/20-parity-and-determinism.md`` requires.
        """
        return {
            "iss": self.iss,
            "sub": self.sub,
            "run_id": self.run_id,
            "phase": self.phase,
            "allow": self.allow.as_mapping(),
            "jti": self.jti,
            "iat": self.iat,
            "exp": self.exp,
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> CapabilityClaims:
        """Validate a decoded, signature-verified payload, or raise :class:`ClaimRejection`.

        Presence is checked before shape, and ``exp`` and ``iat`` get their own reason codes
        because the adversarial table treats a missing ``exp`` as its own case: a token without an
        expiry must be denied, never read as one that does not expire.
        """
        for name in CLAIM_NAMES:
            if name in payload:
                continue
            if name == "exp":
                raise ClaimRejection(DenialReason.EXP_MISSING, "exp")
            if name == "iat":
                raise ClaimRejection(DenialReason.IAT_MISSING, "iat")
            raise ClaimRejection(DenialReason.CLAIM_MISSING, name)
        return cls(
            iss=validated_identifier(payload["iss"], "iss"),
            sub=validated_identifier(payload["sub"], "sub"),
            run_id=validated_identifier(payload["run_id"], "run_id"),
            phase=validated_phase(payload["phase"]),
            allow=AllowClaim.from_value(payload["allow"]),
            jti=validated_identifier(payload["jti"], "jti"),
            iat=validated_epoch(payload["iat"], "iat"),
            exp=validated_epoch(payload["exp"], "exp"),
        )


@dataclass(frozen=True, slots=True)
class VerificationOutcome:
    """A verdict on one presented token: accepted with claims, or denied with a structured reason.

    Deliberately not an exception. Every denial is a thing the Guardian must *audit*, and the
    plan's threat-model corollary is that an unaudited block is invisible to the evaluation whether
    or not it happened; a value that the caller has to consume is far harder to drop than an
    exception a caller can catch and ignore. The raw encoded token never appears on this object,
    on its ``repr``, or in any exception raised from this module: it is a live bearer credential
    and belongs in no log line.

    ``verified_jti`` and ``verified_issuer`` are an all-or-neither pair present only on subject- and
    phase-mismatch refusals. At those two points the signature, claim shape and issuer registration
    have already been established, so retaining the pair records verified attribution rather than
    attacker-authored payload text. Group-A and malformed-claim refusals must never carry it.
    """

    accepted: bool
    reason: DenialReason | None = None
    claim: str | None = None
    claims: CapabilityClaims | None = None
    verified_jti: str | None = None
    verified_issuer: str | None = None

    def __post_init__(self) -> None:
        attributed = self.verified_jti is not None or self.verified_issuer is not None
        if (self.verified_jti is None) != (self.verified_issuer is None):
            raise ValueError("verified jti and issuer attribution must be present together")
        attributable_reasons = {DenialReason.SUBJECT_MISMATCH, DenialReason.PHASE_MISMATCH}
        if attributed and (self.accepted or self.reason not in attributable_reasons):
            raise ValueError("only subject- or phase-mismatch refusals may carry attribution")

    @property
    def reason_code(self) -> str | None:
        """The wire form of :attr:`reason`, or ``None`` when the token was accepted."""
        return None if self.reason is None else self.reason.value

    @classmethod
    def accept(cls, claims: CapabilityClaims) -> VerificationOutcome:
        """Return an accepting outcome carrying the validated claims."""
        return cls(accepted=True, claims=claims)

    @classmethod
    def deny(
        cls,
        reason: DenialReason,
        claim: str | None = None,
        *,
        verified_jti: str | None = None,
        verified_issuer: str | None = None,
    ) -> VerificationOutcome:
        """Return a denial, retaining verified attribution only where the invariant permits it."""
        return cls(
            accepted=False,
            reason=reason,
            claim=claim,
            verified_jti=verified_jti,
            verified_issuer=verified_issuer,
        )


class JtiClaimant(Protocol):
    """The single-use store the verifier needs, expressed as the narrowest possible surface.

    One method, and it is a *claim* rather than a lookup: implementations must decide membership
    and record the ``jti`` in one indivisible step, returning ``True`` only to the first caller to
    present it. :class:`guardian.token.replay.ReplayCache` satisfies this structurally, so the
    verifier holds no import of it and a deployment that later needs a shared store across
    processes can supply one without touching this file.
    """

    def claim(self, jti: str, *, expires_at: int) -> bool:
        """Record ``jti`` as spent and return ``True``, or return ``False`` if it already was."""
        ...


def is_plain_int(value: object) -> bool:
    """Return whether ``value`` is an ``int`` that is not a ``bool``.

    ``bool`` subclasses ``int`` in Python, so ``True`` would otherwise pass every integer check and
    compare equal to 1. A JSON ``true`` where an ``exp`` belongs is precisely the kind of thing
    position P2 supplies, and it must be malformed rather than an expiry one second after 1970.
    """
    return isinstance(value, int) and not isinstance(value, bool)


def validated_identifier(value: object, claim: str) -> str:
    """Return ``value`` unchanged if it is a well-formed identifier, else raise.

    "Unchanged" is the contract, not an implementation detail. Nothing is stripped, folded,
    decoded or normalised -- see the module docstring for why a cleaning step here would be a
    scope-widening bug rather than a convenience.
    """
    if not isinstance(value, str) or not value:
        raise ClaimRejection(DenialReason.CLAIM_MALFORMED, claim)
    if len(value) > _MAX_IDENTIFIER_CHARS:
        raise ClaimRejection(DenialReason.CLAIM_MALFORMED, claim)
    if not _IDENTIFIER_ALPHABET.issuperset(value):
        raise ClaimRejection(DenialReason.CLAIM_MALFORMED, claim)
    return value


def validated_scope(value: object, claim: str) -> tuple[str, ...]:
    """Return a non-empty tuple of well-formed scope entries, or raise :class:`ClaimRejection`.

    ``str`` and ``bytes`` are rejected explicitly before anything else. Both are iterable, and a
    scope list accidentally given as the string ``"delete"`` would otherwise validate as six
    single-character verbs -- a silent widening produced by nothing more than a missing pair of
    brackets. Duplicates are permitted and are *not* removed: de-duplication would make the stored
    claim differ from the signed claim, and the audit record is supposed to say what was presented.
    """
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, (list, tuple)):
        raise ClaimRejection(DenialReason.CLAIM_MALFORMED, claim)
    if not value or len(value) > _MAX_SCOPE_ENTRIES:
        raise ClaimRejection(DenialReason.CLAIM_MALFORMED, claim)
    return tuple(validated_identifier(entry, claim) for entry in value)


def validated_phase(value: object) -> str:
    """Return ``value`` if it is exactly one of :data:`PHASES`, else raise with the phase reason.

    Exact comparison against a closed set is what makes a homoglyph phase harmless: an attacker's
    Cyrillic lookalike does not match any member and is denied, which it would not be if this
    function folded the value first.
    """
    if not isinstance(value, str) or value not in PHASES:
        raise ClaimRejection(DenialReason.PHASE_UNKNOWN, "phase")
    return value


def validated_epoch(value: object, claim: str) -> int:
    """Return ``value`` as a non-negative integer epoch second, or raise :class:`ClaimRejection`.

    Floats are rejected rather than truncated. JWT's NumericDate permits them, but accepting one
    would put a rounding decision on the expiry path and make ``exp`` comparisons depend on
    IEEE-754 behaviour at the boundary; the Guardian mints integers, so a non-integer is either a
    foreign issuer or a mutation, and both should be denied.
    """
    if not is_plain_int(value) or value < 0:
        raise ClaimRejection(DenialReason.CLAIM_MALFORMED, claim)
    return value


class TokenVerifier:
    """Verify presented capability tokens against configuration, an injected clock and a jti store.

    Construction takes everything it needs and reads nothing from the environment:

    ``parameters``
        The section 2 values, already resolved by the composition root.
    ``verification_key_provider``
        A zero-argument callable returning the current key. Called on every verification rather
        than cached, so that rotating the key is a configuration change and not a restart, and so
        that key bytes never live on this object. Returning an empty value is treated as "the key
        is unavailable" and fails closed with its own reason code.
    ``clock``
        A zero-argument callable returning integer epoch seconds. The only source of time here.
    ``replay_cache``
        Any :class:`JtiClaimant`. Consulted last, and only for an otherwise-clean token.
    ``leeway_seconds``
        Tolerance applied to ``iat`` and ``nbf`` only, never to ``exp``. It defaults to zero
        because in this system the issuer and the verifier are the same process reading the same
        clock, so there is no skew to tolerate and any allowance would be pure attack surface.
        It is a constructor argument rather than a constant so that a future split deployment can
        set it deliberately; note it is never applied to expiry, because leeway on ``exp`` extends
        the life of every token in the system, which is a section 2 parameter being changed by the
        back door.
    ``max_encoded_chars``
        A parse-size ceiling applied before any decoding.
    """

    def __init__(
        self,
        *,
        parameters: TokenParameters,
        verification_key_provider: Callable[[], str | bytes | None],
        clock: Callable[[], int],
        replay_cache: JtiClaimant,
        leeway_seconds: int = 0,
        max_encoded_chars: int = _DEFAULT_MAX_ENCODED_CHARS,
    ) -> None:
        if not is_plain_int(leeway_seconds) or leeway_seconds < 0:
            raise ValueError("leeway_seconds must be a non-negative integer number of seconds")
        if not is_plain_int(max_encoded_chars) or max_encoded_chars <= 0:
            raise ValueError("max_encoded_chars must be a positive integer")
        self._parameters = parameters
        self._verification_key_provider = verification_key_provider
        self._clock = clock
        self._replay_cache = replay_cache
        self._leeway_seconds = leeway_seconds
        self._max_encoded_chars = max_encoded_chars

    @property
    def parameters(self) -> TokenParameters:
        """The configured section 2 parameters this verifier was built with."""
        return self._parameters

    def verify(
        self,
        encoded: object,
        *,
        expected_run_id: str,
        expected_phase: str,
        expected_subject: str,
        registered_issuers: Collection[str],
    ) -> VerificationOutcome:
        """Return a verdict on ``encoded`` for this run, phase and Executor.

        ``encoded`` is typed ``object`` on purpose. It arrives from an HTTP body under position P1
        and may be any JSON value at all; a ``str`` annotation would be a promise the caller cannot
        keep, and this method must never raise on hostile input. Every path below returns a
        :class:`VerificationOutcome`.

        ``expected_subject`` is required rather than optional. An optional identity check is a
        check that is off in production, and "one Executor presenting another's token" is a named
        adversarial case; the caller must therefore name who is presenting, taking the identity
        from the transport rather than from the token.
        """
        # registered_issuers must not be a bare string. "supervisor-1" in "supervisor-12" is True,
        # so a caller who passed one issuer id as a string instead of a one-element collection
        # would turn the registry check into substring matching -- an unregistered issuer whose id
        # is a substring of a registered one would be accepted. Reject the shape rather than trust
        # the caller.
        if isinstance(registered_issuers, (str, bytes, bytearray)) or not isinstance(
            registered_issuers, Collection
        ):
            raise TypeError("registered_issuers must be a collection of issuer ids, not a string")

        if not isinstance(encoded, str) or not encoded:
            return VerificationOutcome.deny(DenialReason.MALFORMED)
        if len(encoded) > self._max_encoded_chars:
            return VerificationOutcome.deny(DenialReason.MALFORMED)

        header_outcome = self._check_header(encoded)
        if header_outcome is not None:
            return header_outcome

        verification_key = self._verification_key_provider()
        if not verification_key:
            return VerificationOutcome.deny(DenialReason.VERIFICATION_KEY_UNAVAILABLE)

        try:
            payload = jwt.decode(
                encoded,
                verification_key,
                # THE ALLOWLIST. Exactly one algorithm, taken from configuration seeded by
                # security-policy section 2. Do not "simplify" this by widening the list, by
                # deriving it from the token header, or by dropping the argument: it is what makes
                # `alg: none` and the RS256-with-the-symmetric-secret confusion attack impossible
                # rather than merely unlikely. The header is checked against the same single value
                # in _check_header above; the redundancy is deliberate.
                algorithms=[self._parameters.algorithm],
                options={
                    "verify_signature": True,
                    # Every temporal and binding check is performed below against the injected
                    # clock and this Guardian's own reason codes. PyJWT's versions are switched off
                    # rather than relied on: they read a wall clock this module is not allowed to
                    # read, and they raise messages instead of structured codes.
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                    "verify_aud": False,
                    "verify_iss": False,
                    "verify_sub": False,
                    "verify_jti": False,
                    "require": [],
                    # RFC 7518 section 3.2 requires an HMAC key at least as long as the hash
                    # output. Enforcing it here means a Guardian configured with a weak key fails
                    # closed on every verification instead of running with a forgeable one, and it
                    # keeps the threshold single-homed in PyJWT rather than copied into this file.
                    "enforce_minimum_key_length": True,
                },
            )
        except InvalidSignatureError:
            # Subclass of DecodeError, so it must be caught before it.
            return VerificationOutcome.deny(DenialReason.SIGNATURE_INVALID)
        except InvalidAlgorithmError:
            return VerificationOutcome.deny(DenialReason.ALGORITHM_NOT_ALLOWED)
        except InvalidKeyError:
            # The *configured* key is unusable -- absent, empty or below the HMAC minimum. Nothing
            # an attacker supplies reaches this path, so it is an operational fault, and it fails
            # closed with a reason the audit chain records.
            return VerificationOutcome.deny(DenialReason.VERIFICATION_KEY_UNAVAILABLE)
        except (DecodeError, PyJWTError, TypeError, ValueError):
            # Non-JWT bytes, a truncated token, a bad base64 segment, a payload that is not a JSON
            # object: all denied cleanly, none allowed to escape as an exception.
            return VerificationOutcome.deny(DenialReason.MALFORMED)

        if not isinstance(payload, Mapping):
            return VerificationOutcome.deny(DenialReason.MALFORMED)

        try:
            claims = CapabilityClaims.from_payload(payload)
        except ClaimRejection as rejection:
            return VerificationOutcome.deny(rejection.reason, rejection.claim)

        temporal_outcome = self._check_temporal(claims, payload)
        if temporal_outcome is not None:
            return temporal_outcome

        binding_outcome = self._check_binding(
            claims,
            expected_run_id=expected_run_id,
            expected_phase=expected_phase,
            expected_subject=expected_subject,
            registered_issuers=registered_issuers,
        )
        if binding_outcome is not None:
            return binding_outcome

        # Last, and only for a token that is clean in every other respect. See the module docstring
        # for why spending the jti earlier would hand the attacker a denial-of-service.
        try:
            claimed = self._replay_cache.claim(claims.jti, expires_at=claims.exp)
        except Exception:
            # A store fault must deny and be audited, never escape as an unhandled 500.
            return VerificationOutcome.deny(DenialReason.REPLAY_CACHE_UNAVAILABLE)
        if not claimed:
            return VerificationOutcome.deny(DenialReason.REPLAYED, "jti")

        return VerificationOutcome.accept(claims)

    def _check_header(self, encoded: str) -> VerificationOutcome | None:
        """Reject on header grounds before any signature work, or return ``None`` to continue.

        The header is unauthenticated data. It is read for exactly two decisions -- which reason
        code an algorithm mismatch deserves, and whether the token is asking us to resolve a key
        from it -- and for nothing else. The verification key is never selected from the header.
        """
        try:
            header = jwt.get_unverified_header(encoded)
        except (PyJWTError, TypeError, ValueError):
            return VerificationOutcome.deny(DenialReason.MALFORMED)
        if not isinstance(header, Mapping):
            return VerificationOutcome.deny(DenialReason.MALFORMED)
        if not _FORBIDDEN_HEADER_PARAMETERS.isdisjoint(header):
            return VerificationOutcome.deny(DenialReason.HEADER_PARAMETER_NOT_ALLOWED)
        # Exact string comparison against the configured algorithm. No case folding: "hs256" and
        # "HS256" are different strings and only the configured one is accepted, which is the
        # correct outcome for a value an attacker chose.
        if header.get("alg") != self._parameters.algorithm:
            return VerificationOutcome.deny(DenialReason.ALGORITHM_NOT_ALLOWED)
        return None

    def _check_temporal(
        self, claims: CapabilityClaims, payload: Mapping[str, object]
    ) -> VerificationOutcome | None:
        """Apply every time-based rule against the injected clock, or return ``None`` to continue.

        ``nbf`` is not one of architecture section 3's claims, so the Guardian never mints one. It
        is still checked when present, because position P2 covers tokens this Guardian did not
        mint and a future-dated ``nbf`` on an otherwise valid token must not be ignored.
        """
        now = self._clock()
        if not is_plain_int(now):
            raise TypeError("clock must return an integer number of epoch seconds")

        if claims.exp <= now:
            return VerificationOutcome.deny(DenialReason.EXPIRED, "exp")
        if claims.iat > now + self._leeway_seconds:
            return VerificationOutcome.deny(DenialReason.ISSUED_IN_FUTURE, "iat")
        if "nbf" in payload:
            not_before = payload["nbf"]
            if not is_plain_int(not_before):
                return VerificationOutcome.deny(DenialReason.CLAIM_MALFORMED, "nbf")
            if not_before > now + self._leeway_seconds:
                return VerificationOutcome.deny(DenialReason.NOT_YET_VALID, "nbf")
        if claims.exp <= claims.iat:
            return VerificationOutcome.deny(DenialReason.LIFETIME_NOT_POSITIVE, "exp")
        # The ceiling applies to a presented token and not only to an issue request. The issuer
        # refuses to mint above it, but "the issuer refuses" is a property of code the attacker may
        # one day be inside; "the verifier refuses" is a property of the enforcement path itself.
        if claims.exp - claims.iat > self._parameters.max_ttl_seconds:
            return VerificationOutcome.deny(DenialReason.LIFETIME_ABOVE_CEILING, "exp")
        return None

    def _check_binding(
        self,
        claims: CapabilityClaims,
        *,
        expected_run_id: str,
        expected_phase: str,
        expected_subject: str,
        registered_issuers: Collection[str],
    ) -> VerificationOutcome | None:
        """Bind the token to this run, phase, Executor and a registered Supervisor.

        Four exact comparisons, each with its own reason code so that the audit chain distinguishes
        a cross-run token from a cross-phase one from a borrowed one. All four are ``==`` or ``in``
        on unmodified strings; see the module docstring on normalisation.
        """
        if claims.iss not in registered_issuers:
            return VerificationOutcome.deny(DenialReason.ISSUER_UNREGISTERED, "iss")
        if claims.sub != expected_subject:
            return VerificationOutcome.deny(
                DenialReason.SUBJECT_MISMATCH,
                "sub",
                verified_jti=claims.jti,
                verified_issuer=claims.iss,
            )
        if claims.run_id != expected_run_id:
            return VerificationOutcome.deny(DenialReason.RUN_MISMATCH, "run_id")
        if expected_phase not in PHASES:
            # The caller, not the token, is wrong. Still a denial rather than an exception: the
            # request must be refused and audited, and a mediation pipeline that raises here would
            # produce an unaudited failure, which the plan's corollary forbids.
            return VerificationOutcome.deny(DenialReason.PHASE_UNKNOWN, "phase")
        if claims.phase != expected_phase:
            return VerificationOutcome.deny(
                DenialReason.PHASE_MISMATCH,
                "phase",
                verified_jti=claims.jti,
                verified_issuer=claims.iss,
            )
        return None
