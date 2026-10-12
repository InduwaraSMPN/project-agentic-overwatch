r"""The seam between ``guardian/token/`` and ``guardian/app/``: three copies, and what holds them.

``guardian/token/`` and ``guardian/app/`` are written not to import each other. The token service
publishes :data:`~guardian.token.verifier.DENIAL_REASON_CODES` and
:data:`~guardian.token.issuer.ISSUE_REFUSAL_CODES` so that "guardian/app/ can assert its own error
vocabulary covers this one from a test, **without either module importing the other**", and the app
declares its contracts without knowing how a token is verified. That decoupling is deliberate and
this module is its price: three facts are stated in two places each, and each pair needs a check
that turns "these agree today" into "these cannot drift".

ADR-022 fixed the shape for exactly this trade, in the case where two components must agree on one
value and must not depend on each other -- one rule stated once in prose, two homes, and a
cross-check that fails the build when one moves. What follows applies it three times.

THE THREE PAIRS
---------------
*The claim-set version.* ``guardian/app/models.py`` owns ``CAPABILITY_TOKEN_SCHEMA_VERSION`` and
requires the issuer to stamp it into every token, "or verification rejects its own tokens".
``guardian/token/issuer.py`` carries a copy and stamps it. Until the commit that added it, it
carried neither, so every token the Guardian minted was one its own verification path refused -- see
``test_adversarial_a_authenticity.py``'s case A6, which is that defect kept as a regression guard.

**M4's plan recorded this as still owed, and that reading was stale.** The Inbound table of
``docs/plans/M4-implementation-plan.md`` lists "issuer does not stamp the token schema version" as
work M4 must do, and ``guardian.app.mediation.TokenVerifier`` carried the same claim in its
"reconciliations owed" paragraph. Both were written before the stamping landed. Nothing was changed
to discharge it; what was added is
:func:`test_a_minted_token_validates_as_the_apps_own_claim_model`, which mints through the real
issuer and puts the decoded payload through
:class:`~guardian.app.models.CapabilityTokenClaims` itself -- so the property is held by an
assertion about the model that requires it, not only by a comparison of two constants and a
successful permit.

*The reason vocabulary.* ``DenialReason`` spells ``token_expired``; ``ReasonCode`` spells
``temporal.expired``. Neither is a superset of the other and there is no arithmetic relating them,
so the translation is a table -- and a table with a hole in it is worse than no table, because the
hole becomes a default arm and a default arm records one denial as another in the log that
``docs/protocols/evaluation-protocol.md`` section 3 computes both RQ5 measures from. The totality
assertion below is what makes the hole impossible.

*The signing algorithm.* ``docs/protocols/security-policy.md`` section 2 owns it. The suite mirrors
it, because two group A cases are *about* the allowlist holding one specific algorithm, and the
mirror is proved against the protocol text rather than trusted -- ``monitor/tests/
test_limits_match_protocol.py``'s pattern, in miniature.

AND ONE THING THAT IS NOT A PAIR: THE REASON CODES NOTHING CAN PRODUCE
-----------------------------------------------------------------------
:func:`test_every_reason_code_is_classified` partitions the whole of ``ReasonCode`` into what the
token seam can produce, what the mediation pipeline can produce, and what **nothing can**. Five
codes are in the third set today, and that is a finding rather than an oversight to be quietly left
out of a test: ``models.py`` declares them, the M3 plan's group C expects three of them by name, and
the landed code answers those cases with different codes for reasons argued at each case. Writing
the third set down means a code that becomes reachable -- when the Rego bundle starts naming which
dimension of a scope was exceeded, say -- fails this test until somebody moves it, rather than
sitting unnoticed in a vocabulary nobody has audited since M3.
"""

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import jwt  # noqa: E402
import pytest  # noqa: E402
from guardian.app.composition import (  # noqa: E402
    DENIAL_REASON_TO_REASON_CODE,
    reason_code_for,
)
from guardian.app.mediation import TokenVerification  # noqa: E402
from guardian.app.models import (  # noqa: E402
    CAPABILITY_TOKEN_SCHEMA_VERSION,
    CapabilityTokenClaims,
    ReasonCode,
    ReasonGroup,
)
from guardian.tests.harness import ALGORITHM, GuardianHarness, read_claim  # noqa: E402
from guardian.token.issuer import (  # noqa: E402
    CAPABILITY_TOKEN_SCHEMA_VERSION as ISSUER_SCHEMA_VERSION,
)
from guardian.token.issuer import ISSUE_REFUSAL_CODES  # noqa: E402
from guardian.token.verifier import DENIAL_REASON_CODES, DenialReason  # noqa: E402

SECURITY_POLICY = REPO_ROOT / "docs" / "protocols" / "security-policy.md"


# --------------------------------------------------------------------------------------------
# Pair one: the claim-set version
# --------------------------------------------------------------------------------------------


def test_the_issuers_schema_version_matches_the_contract_that_owns_it() -> None:
    """The two homes of ``CAPABILITY_TOKEN_SCHEMA_VERSION`` hold the same value.

    The cross-check ADR-022's shape requires. If ``guardian/app/models.py`` bumps the claim set to a
    new version and the issuer keeps stamping the old one, every token this Guardian mints becomes
    one it will not accept -- and the symptom is a Guardian refusing credentials it issued seconds
    earlier, which is among the harder things to diagnose from an audit log. This test is what makes
    that a red build instead.
    """
    assert ISSUER_SCHEMA_VERSION == CAPABILITY_TOKEN_SCHEMA_VERSION, (
        f"guardian/token/issuer.py stamps {ISSUER_SCHEMA_VERSION!r} but guardian/app/models.py "
        f"declares {CAPABILITY_TOKEN_SCHEMA_VERSION!r}. models.py owns the value; the copy in the "
        "issuer exists because the two packages do not import each other (see its docstring)"
    )
    declared = CapabilityTokenClaims.model_fields["schema_version"].annotation
    assert CAPABILITY_TOKEN_SCHEMA_VERSION in getattr(declared, "__args__", ()), declared


def test_a_minted_token_carries_the_version_the_contract_requires(
    harness: GuardianHarness,
) -> None:
    """Round trip: what the issuer stamps is what the app's claim model accepts.

    Stronger than comparing the two constants, because it exercises the path rather than the
    values -- an issuer that held the right constant and dropped it before signing would pass the
    test above and fail this one. That was the actual defect: ``CapabilityClaims.to_payload()``
    returns the eight claims ``guardian/token/`` validates -- section 3 lists nine -- so signing its
    output alone silently discarded ``schema_version``.
    """
    token = harness.mint()
    assert read_claim(token, "schema_version") == CAPABILITY_TOKEN_SCHEMA_VERSION
    harness.submit(
        harness.action_body(token=token, request_id="req-seam-1"), label="seam round trip"
    ).assert_permitted()


def test_a_minted_token_validates_as_the_apps_own_claim_model(harness: GuardianHarness) -> None:
    """A token from the real issuer decodes into a ``CapabilityTokenClaims`` with no coaxing.

    The regression guard M4-T4.0b owes, and it is deliberately narrower and stricter than the round
    trip above. That case proves a minted token reaches a permit, which is a statement about the
    whole pipeline and would keep passing if some future adapter learned to repair a claim set on
    the way through. This one takes the decoded payload straight from the token and hands it to the
    model that declares the ninth claim ``Literal`` with no default and forbids extras -- so it
    fails if the claim is absent, if it holds a version this build does not know, or if the issuer
    ever starts stamping something the contract did not ask for.

    Written now because the M4 plan recorded the stamping as still owed and the tree already had it.
    A property that is true, believed to be false, and asserted nowhere directly is a property one
    refactor away from lapsing quietly -- and the symptom would be a Guardian refusing credentials
    it minted seconds earlier.
    """
    payload = jwt.decode(harness.mint(), options={"verify_signature": False})
    assert "schema_version" in payload, (
        "the issuer minted a token with no schema_version. CapabilityTokenClaims requires the "
        "claim and forbids extras, so this Guardian would deny its own credentials under "
        "authenticity.claims-malformed at the last step before policy"
    )
    claims = CapabilityTokenClaims.model_validate(payload)
    assert claims.schema_version == CAPABILITY_TOKEN_SCHEMA_VERSION


# --------------------------------------------------------------------------------------------
# Pair two: the reason vocabulary
# --------------------------------------------------------------------------------------------


def test_the_denial_reason_adapter_is_total() -> None:
    """Every ``DenialReason`` maps to exactly one ``ReasonCode``, and to nothing else.

    Totality in both directions that matter. Every member of the source enum is a key, so no denial
    can fall through; every value is a real ``ReasonCode``, so no denial can be recorded as a string
    the audit record would refuse; and no key is spelled twice, which a plain dict literal would
    otherwise permit silently.
    """
    assert set(DENIAL_REASON_TO_REASON_CODE) == set(DenialReason), "unmapped: " + repr(
        sorted(set(DenialReason) - set(DENIAL_REASON_TO_REASON_CODE))
    )
    assert len(DENIAL_REASON_TO_REASON_CODE) == len(DenialReason)
    for denial, code in DENIAL_REASON_TO_REASON_CODE.items():
        assert isinstance(code, ReasonCode), (
            f"{denial!r} maps to {code!r}, which is not a ReasonCode"
        )
        assert code.group is not ReasonGroup.PERMIT, (
            f"{denial!r} maps to {code.value!r}, which is the permit vocabulary; a refused token "
            "cannot be recorded with a code only a permit may carry"
        )
        assert reason_code_for(denial) is code


def test_refusal_attribution_is_paired_and_limited_to_authentic_binding_mismatches() -> None:
    """The app seam cannot attach attacker-authored attribution to another refusal class."""
    attributed = TokenVerification.refuse(
        ReasonCode.SCOPE_SUBJECT_MISMATCH,
        verified_jti="jti-authentic-mismatch",
        verified_issuer="supervisor-containment",
    )
    assert not attributed.accepted
    assert attributed.claims is None

    with pytest.raises(ValueError, match="present together"):
        TokenVerification.refuse(
            ReasonCode.SCOPE_PHASE_MISMATCH,
            verified_jti="jti-without-issuer",
        )
    with pytest.raises(ValueError, match="only subject- or phase-mismatch"):
        TokenVerification.refuse(
            ReasonCode.TOKEN_SIGNATURE_INVALID,
            verified_jti="attacker-claimed-jti",
            verified_issuer="attacker-claimed-issuer",
        )


def test_the_denial_reason_adapter_has_no_default_arm() -> None:
    """An unmapped value raises rather than becoming something plausible.

    The property that makes the totality assertion above worth having. With a default arm, adding a
    member to ``DenialReason`` would produce a Guardian that denies correctly and records the wrong
    reason -- which passes every test that checks for a denial, and silently corrupts the per-class
    decomposition RQ5 reads.
    """
    with pytest.raises(KeyError) as error:
        reason_code_for("token_something_new")  # type: ignore[arg-type]
    assert "DENIAL_REASON_TO_REASON_CODE" in str(error.value)


def test_the_two_token_vocabularies_do_not_collide() -> None:
    """A verification denial and an issue refusal can never be mistaken for one another.

    ``guardian/token/issuer.py`` states the intent -- refusal codes are prefixed ``issue_`` "so that
    no code from this enum can ever be mistaken for a verification reason in a log or a data frame"
    -- and this is the check. A denial is an adversarial event that is audited and scored; a refusal
    is a request that could not be honoured. Merging them would put configuration faults into the
    vocabulary the evaluation reads as attacks.
    """
    assert set(DENIAL_REASON_CODES).isdisjoint(ISSUE_REFUSAL_CODES)
    assert all(code.startswith("issue_") for code in ISSUE_REFUSAL_CODES)
    assert not any(code.startswith("issue_") for code in DENIAL_REASON_CODES)


# --------------------------------------------------------------------------------------------
# The vocabulary audit: what can be produced, and what cannot
# --------------------------------------------------------------------------------------------

# Codes the mediation pipeline produces without any help from the token seam.
PIPELINE_REASON_CODES = frozenset(
    {
        ReasonCode.PERMIT_RULE_ALLOW,
        ReasonCode.POLICY_DENY_DEFAULT,
        ReasonCode.POLICY_RULE_DENY,
        ReasonCode.POLICY_ENGINE_UNAVAILABLE,
        ReasonCode.POLICY_ENGINE_TIMEOUT,
        ReasonCode.POLICY_ENGINE_MALFORMED_RESULT,
        ReasonCode.POLICY_REQUEST_OVERSIZE,
        ReasonCode.POLICY_REQUEST_MALFORMED,
        # Produced by adjudicate() when a params key is named like a credential, or lies in the
        # Guardian's reserved key namespace. See test_audit_availability.py, which is where the
        # behaviour and the reason for a separate code are argued.
        ReasonCode.POLICY_PARAM_NAME_FORBIDDEN,
        ReasonCode.POLICY_GUARDIAN_FAULT,
        # ADR-129: the action caps, reserved between the token verification and the policy
        # evaluation, so the code is produced by the pipeline and not by the token seam. See
        # test_adversarial_c_scope.py for the boundary it draws and the release rule that keeps a
        # run's refusals from spending the budget its permits draw on.
        ReasonCode.SCOPE_ACTION_CAP_EXCEEDED,
    }
)

# Codes nothing in the landed Guardian can produce. Each is declared in guardian/app/models.py and
# each has a reason it is unreachable, argued at the case that would otherwise produce it.
UNREACHABLE_REASON_CODES = frozenset(
    {
        # The three scope dimensions. Matching an action against an allow-claim is Rego's job, and
        # guardian.app.policy.interpret_policy_result offers an engine result no channel through
        # which to name *which* dimension was exceeded -- an out-of-scope action is answered
        # policy.deny-default. See test_adversarial_c_scope.py's module docstring.
        ReasonCode.SCOPE_VERB_NOT_ALLOWED,
        ReasonCode.SCOPE_RESOURCE_NOT_ALLOWED,
        ReasonCode.SCOPE_NAMESPACE_NOT_ALLOWED,
        # A wildcard, empty or null allow-claim is refused by the token verifier's claim alphabet
        # before policy is consulted, so the refusal is attributed to the claim set rather than to
        # the claim's usability. Deny-by-default holds either way; the attribution is what differs.
        ReasonCode.SCOPE_ALLOW_CLAIM_UNUSABLE,
        # A token with no jti fails as a missing required claim, which the verifier reaches first.
        ReasonCode.REPLAY_JTI_MISSING,
    }
)


def test_every_reason_code_is_classified() -> None:
    """The whole vocabulary is partitioned, and the unreachable part is written down.

    A code that becomes reachable, or one added without a producer, fails here. That is the point:
    ``models.py``'s ``_verify_reason_code_grouping`` already refuses a code whose family is unknown,
    but nothing refuses a code that no code path can ever emit -- and a vocabulary with members
    nothing produces is a vocabulary whose absences an analyst cannot interpret.
    """
    produced = frozenset(DENIAL_REASON_TO_REASON_CODE.values()) | PIPELINE_REASON_CODES
    classified = produced | UNREACHABLE_REASON_CODES

    assert classified == set(ReasonCode), (
        "unclassified reason code(s): "
        f"{sorted(code.value for code in set(ReasonCode) - classified)}. Every member belongs in "
        "exactly one of: produced by the token seam, produced by the pipeline, or unreachable with "
        "the reason written beside it"
    )
    assert produced.isdisjoint(UNREACHABLE_REASON_CODES), (
        "a code is listed as unreachable and is also produced: "
        f"{sorted(code.value for code in produced & UNREACHABLE_REASON_CODES)}"
    )
    # Every threat-model family still has at least one code something can produce. A family that
    # went entirely unreachable would be an adversarial group nothing could be attributed to.
    for group in ReasonGroup:
        assert any(code.group is group for code in produced), (
            f"no producible reason code in the {group.value!r} family; the M3 plan names it as an "
            "adversarial group, so a denial in it would have nothing to be recorded as"
        )


# --------------------------------------------------------------------------------------------
# Pair three: the signing algorithm
# --------------------------------------------------------------------------------------------


def test_the_mirrored_algorithm_still_matches_the_protocol() -> None:
    """``security-policy.md`` section 2 still names the algorithm this suite mirrors.

    The only section 2 value the suite restates, and the reason is that it is not a tunable -- two
    group A cases are about the allowlist holding exactly one specific algorithm, so substituting a
    different one would be running a different test. Everything else section 2 owns reaches the
    Guardian as configuration and the suite supplies its own small values instead.
    """
    text = SECURITY_POLICY.read_text(encoding="utf-8")
    section = re.search(r"^## 2\..*?(?=^## )", text, flags=re.MULTILINE | re.DOTALL)
    assert section is not None, f"{SECURITY_POLICY} has no section 2"
    body = section.group(0)
    assert ALGORITHM in body, (
        f"security-policy.md section 2 no longer names {ALGORITHM!r}, which guardian/tests/"
        "harness.py mirrors. Section 2 owns the value; if it changed, the mirror follows it and "
        "the group A algorithm cases are re-read against the new one"
    )
    assert f"algorithm {ALGORITHM}" in body, body[:400]
