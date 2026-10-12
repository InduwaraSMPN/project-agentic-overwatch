r"""Group A -- authenticity: is this token one the Guardian issued, to somebody it knows?

``docs/plans/M3-implementation-plan.md``'s group A names five cases: a wrong-key signature,
``alg: none``, algorithm confusion with an RS256 token whose "public key" is the symmetric secret,
an issuer not registered for this run, and malformed or non-JWT bytes.
``docs/milestones/M3-guardian.md``'s Definition of done names two of them again in its own words --
forged, unknown-issuer -- so this module closes the DoD's first row.

Every case here holds threat-model position P2: **arbitrary token bytes**, "including tokens it
minted, mutated, or captured from another Executor". The tokens below are therefore built rather
than obtained. Two of them cannot be produced by any signing library at all -- ``alg: none`` is
unsignable by construction and the confusion case needs an RS256 header without an RSA key -- and
:func:`guardian.tests.harness.craft_compact_jws` assembles those by hand, which is the only way to
show that the header allowlist refuses them *before* any signature arithmetic runs.

WHY TWO SEPARATE REASON CODES FOR WHAT LOOK LIKE THE SAME ATTACK
------------------------------------------------------------------
``guardian/app/models.py`` keeps ``authenticity.algorithm-rejected`` apart from
``authenticity.signature-invalid`` and states why: ``alg: none`` and algorithm confusion "are
defeated by the allowlist, not by the verifier's arithmetic, and an evaluation that could not tell
them apart could not evidence which defence worked". The cases below assert the distinction rather
than merely asserting denial -- a Guardian that rejected an ``alg: none`` token because the empty
signature failed to verify would be one library default away from accepting it, and a test that only
checked for a denial would not notice.

THE CASE THAT IS A REGRESSION GUARD ON THIS COMMIT'S OWN FIX
-------------------------------------------------------------
:func:`test_a6_token_without_the_claim_set_version_is_refused` presents a token that is authentic,
live, in scope and unspent, and differs from an honest one in one respect: it carries no
``schema_version``. ``guardian/app/models.py`` predicted the outcome before either module was
wired -- "the issuer must stamp CAPABILITY_TOKEN_SCHEMA_VERSION into every token it mints, or
verification rejects its own tokens" -- and until this commit ``guardian/token/issuer.py`` did not
stamp it, so *every* token the Guardian minted was one of these. The case is kept because the
failure it guards against is invisible from the outside: a Guardian denying credentials it had
issued seconds earlier, under a reason code that says the claim set was malformed.
"""

import hashlib
import hmac
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from guardian.app.models import BEARER_MAX_CHARS, ReasonCode, ReasonGroup  # noqa: E402
from guardian.tests.harness import (  # noqa: E402
    ALTERNATE_SIGNING_MATERIAL,
    SYNTHETIC_SIGNING_MATERIAL,
    UNREGISTERED_SUPERVISOR_ID,
    GuardianHarness,
    claims_payload,
    craft_compact_jws,
    sign_claims,
)


def test_a1_a_signature_from_another_key_is_refused(harness: GuardianHarness) -> None:
    """A claim set signed with material this Guardian does not hold. The forgery case.

    Everything about the token is right except who signed it: correct shape, correct algorithm,
    correct claims, in-scope action. What refuses it is the signature check and nothing else, which
    is why the code has to be ``signature-invalid`` and not the algorithm rejection -- the two are
    different defences and the log has to say which one held.
    """
    forged = sign_claims(claims_payload(jti="jti-forged-0001"), material=ALTERNATE_SIGNING_MATERIAL)
    outcome = harness.submit(
        harness.action_body(token=forged, request_id="req-a1"), label="A1 wrong-key signature"
    )
    record = outcome.assert_denied(ReasonCode.TOKEN_SIGNATURE_INVALID)
    assert record.reason_code.group is ReasonGroup.AUTHENTICITY
    # No attribution is recorded for a token that never verified. models.py is explicit that
    # copying an unverified claim into token_jti or iss "would record attacker-authored text as
    # though the Guardian had established it", so the honest record is a null plus a group A code.
    assert record.token_jti is None
    assert record.iss is None


def test_a2_alg_none_is_refused_by_the_allowlist(harness: GuardianHarness) -> None:
    """``alg: none`` with an empty signature -- the oldest JWT attack there is.

    Asserted as an *algorithm* rejection rather than as any denial. If this token were refused
    because an empty signature failed to verify, the Guardian would be relying on a library default
    rather than on the single-algorithm allowlist ``security-policy.md`` section 2 fixes, and the
    day that default changed the token would be accepted.
    """
    token = craft_compact_jws(
        {"alg": "none", "typ": "JWT"}, claims_payload(jti="jti-alg-none"), signature=b""
    )
    outcome = harness.submit(
        harness.action_body(token=token, request_id="req-a2"), label="A2 alg: none"
    )
    record = outcome.assert_denied(ReasonCode.TOKEN_ALGORITHM_REJECTED)
    assert record.token_jti is None
    assert record.iss is None


def test_a3_algorithm_confusion_with_the_secret_as_a_public_key(harness: GuardianHarness) -> None:
    """An RS256 header over a signature that is an HMAC taken with the symmetric secret.

    The classical confusion attack in its exact shape: the attacker has obtained what it believes is
    a public key -- here the HMAC secret, which in an asymmetric deployment would be published --
    and presents a token whose header asks the verifier to treat that material as an RSA public key
    while the signature is really a MAC over it. A verifier that selected its algorithm from the
    header would compute the MAC, find it correct, and accept.

    The signature really is a valid HMAC, computed here rather than faked, so the case would pass a
    naive verifier and only the header allowlist stops it. That is what makes the reason code
    load-bearing: rejection happens before any key is chosen and before any arithmetic is done.
    """
    header = craft_compact_jws({"alg": "RS256", "typ": "JWT"}, claims_payload(jti="jti-confused"))
    signing_input = header.rsplit(".", 1)[0].encode("ascii")
    mac = hmac.new(
        SYNTHETIC_SIGNING_MATERIAL.encode("utf-8"), signing_input, hashlib.sha256
    ).digest()
    token = craft_compact_jws(
        {"alg": "RS256", "typ": "JWT"}, claims_payload(jti="jti-confused"), signature=mac
    )
    outcome = harness.submit(
        harness.action_body(token=token, request_id="req-a3"), label="A3 algorithm confusion"
    )
    outcome.assert_denied(ReasonCode.TOKEN_ALGORITHM_REJECTED)


def test_a3b_a_header_that_supplies_its_own_key_is_refused(harness: GuardianHarness) -> None:
    """A ``jwk`` header parameter -- the same family, asking the verifier to trust a supplied key.

    Filed with the algorithm rejection rather than with the malformed bytes, and the adapter's
    mapping table says why: the token is perfectly well formed, and what is refused is the header's
    attempt to choose the verification key. ``jku``, ``kid``, ``x5u``, ``x5c`` and ``crit`` are
    refused by the same rule.
    """
    token = craft_compact_jws(
        {"alg": "HS256", "typ": "JWT", "jwk": {"kty": "oct", "k": "not-a-real-key"}},
        claims_payload(jti="jti-jwk-header"),
    )
    outcome = harness.submit(
        harness.action_body(token=token, request_id="req-a3b"), label="A3b jwk header parameter"
    )
    outcome.assert_denied(ReasonCode.TOKEN_ALGORITHM_REJECTED)


def test_a4_an_issuer_not_registered_for_this_run_is_refused(harness: GuardianHarness) -> None:
    """A correctly signed token from a Supervisor this run does not know.

    Correctly signed matters: the Guardian holds one signing key, so a token minted through its own
    issuer by a caller naming an unregistered Supervisor carries a valid signature. The registration
    check is a separate defence from the signature check, and this is the case that exercises it --
    which is also why ``test_token_issuance_exposure.py`` exists, because that unauthenticated mint
    is how such a token would be obtained in the first place.
    """
    token = harness.mint(issuer_id=UNREGISTERED_SUPERVISOR_ID)
    outcome = harness.submit(
        harness.action_body(token=token, request_id="req-a4"), label="A4 unregistered issuer"
    )
    record = outcome.assert_denied(ReasonCode.TOKEN_ISSUER_UNKNOWN)
    assert record.token_jti is None
    assert record.iss is None


def test_a5_bytes_that_are_not_a_token_are_refused(harness: GuardianHarness) -> None:
    """Five shapes of non-JWT bearer, each denied under the malformed code, none crashing.

    Position P2 does not oblige the attacker to send anything JWT-shaped, and a reference monitor
    that raised on unparseable input would be a reference monitor with an availability bug reachable
    by anyone who can reach its port (position P4). Each of these must produce an ordinary audited
    denial.
    """
    shapes = {
        "req-a5a": "not-a-jwt-at-all",
        "req-a5b": "only.two",
        "req-a5c": "....",
        "req-a5d": "!!!not-base64!!!.!!!not-base64!!!.!!!not-base64!!!",
        "req-a5e": "e" * BEARER_MAX_CHARS,
    }
    for request_id, bearer in shapes.items():
        outcome = harness.submit(
            harness.action_body(token=bearer, request_id=request_id),
            label=f"A5 malformed bearer ({request_id})",
        )
        record = outcome.assert_denied(ReasonCode.TOKEN_MALFORMED)
        assert record.token_jti is None
        assert record.iss is None


def test_a5b_an_oversized_bearer_dies_at_the_contract_boundary(harness: GuardianHarness) -> None:
    """A bearer past ``BEARER_MAX_CHARS`` is refused as a malformed *request*, not a bad token.

    Split from the case above because the reason code differs and the difference is the finding.
    ``guardian/app/models.py`` bounds every string in the request, and a bearer one character past
    the bound never becomes an ``ActionRequest`` -- so the refusal is attributed to the request
    envelope rather than to the token, and the verifier is never asked. That is the correct
    attribution: no token was presented, because no request was formed. It is also the cheaper
    defence, which is the point of putting a bound there at all under threat-model position P3.
    """
    outcome = harness.submit(
        harness.action_body(token="e" * (BEARER_MAX_CHARS + 1), request_id="req-a5f"),
        label="A5b oversized bearer",
    )
    outcome.assert_denied(ReasonCode.POLICY_REQUEST_MALFORMED)


def test_a6_token_without_the_claim_set_version_is_refused(harness: GuardianHarness) -> None:
    """Authentic, live, in scope, unspent -- and carrying no ``schema_version``.

    See the module docstring. This is the outcome ``guardian/app/models.py`` predicted for an issuer
    that did not stamp the version, and it is kept as a regression guard because the failure it
    describes is a Guardian refusing its own freshly minted credentials.
    """
    unstamped = sign_claims(claims_payload(jti="jti-unstamped", schema_version=None))
    outcome = harness.submit(
        harness.action_body(token=unstamped, request_id="req-a6"),
        label="A6 claim set with no schema_version",
    )
    record = outcome.assert_denied(ReasonCode.TOKEN_CLAIMS_MALFORMED)
    assert record.token_jti is None
    assert record.iss is None


def test_a7_token_with_an_unknown_claim_set_version_is_refused(harness: GuardianHarness) -> None:
    """A version this Guardian does not implement is refused rather than interpreted.

    The whole purpose of a required, defaulted-nowhere version field: a consumer must be able to
    reject a document of a version it does not understand. Interpreting a ``v2`` claim set with
    ``v1`` rules would be guessing about a credential.
    """
    future = sign_claims(claims_payload(jti="jti-future-version", schema_version="v2"))
    outcome = harness.submit(
        harness.action_body(token=future, request_id="req-a7"),
        label="A7 unknown claim set version",
    )
    record = outcome.assert_denied(ReasonCode.TOKEN_CLAIMS_MALFORMED)
    assert record.token_jti is None
    assert record.iss is None
