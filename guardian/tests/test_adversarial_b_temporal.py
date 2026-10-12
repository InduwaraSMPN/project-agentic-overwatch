r"""Group B -- temporal: is this token live, and was it minted within its permitted lifetime?

``docs/plans/M3-implementation-plan.md``'s group B: ``exp`` in the past, ``exp`` absent, ``exp``
beyond the per-phase ceiling section 2 permits -- **rejected rather than silently truncated** --
and ``iat`` or ``nbf`` in the future. ``docs/milestones/M3-guardian.md``'s Definition of done names
"expired" among the cases it requires.

Dissertation section 3.4.2 asks for one property here and it is qualitative: every action carries a
"supervisor-issued, **short-lived** capability token traceable to the authorised Supervisor".
``docs/protocols/security-policy.md`` section 2 turns "short-lived" into numbers and owns them
outright. This module therefore tests **relations and not values**: that a token past its ``exp`` is
refused, that one with no ``exp`` is refused rather than treated as eternal, and that one whose
``exp - iat`` exceeds the configured ceiling is refused rather than clamped. Substituting the
suite's own small lifetimes for section 2's changes nothing any of these cases asserts, which is
the test of whether a number was owned or merely used.

THE CLOCK IS INJECTED, SO NOTHING HERE IS TIMING-DEPENDENT
------------------------------------------------------------
``guardian/token/issuer.py`` and ``guardian/token/verifier.py`` both take a clock and neither
imports :mod:`time`. Expiry is produced by moving the suite clock forward, never by sleeping, so
these cases take microseconds and give the same answer on a loaded CI runner as on an idle laptop.
That is ``.agents/rules/20-parity-and-determinism.md`` reaching into a test suite: a security case
that is flaky under load is a security case people learn to re-run.

WHY "REJECTED RATHER THAN TRUNCATED" NEEDS TWO ASSERTIONS AND NOT ONE
----------------------------------------------------------------------
Clamping an over-long lifetime to the ceiling and issuing anyway is the more forgiving design and
the one ``guardian/token/issuer.py``'s docstring argues against at length: it "returns success", so
the Supervisor plans around a lifetime it does not have and the audit record of a clamped issue is
indistinguishable from an honest one. Both halves are checked in
:func:`test_b3_a_lifetime_above_the_ceiling_is_rejected_not_truncated` -- the issuer refuses to mint
one, and the verifier refuses to accept one that was minted elsewhere -- because either half alone
leaves the other free to clamp.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402
from guardian.app.models import ReasonCode, ReasonGroup  # noqa: E402
from guardian.tests.harness import (  # noqa: E402
    SUITE_EPOCH_SECONDS,
    SUITE_TOKEN_LIFETIME_SECONDS,
    SUITE_TOKEN_MAX_LIFETIME_SECONDS,
    GuardianHarness,
    claims_payload,
    sign_claims,
)
from guardian.token.issuer import IssueRefusalReason, TokenIssueRefused  # noqa: E402


def test_b1_a_token_past_its_expiry_is_refused(harness: GuardianHarness) -> None:
    """Minted honestly, live when minted, presented after the clock has passed its ``exp``.

    The token is not forged and nothing about it is malformed: it was valid and it stopped being
    valid. That is what a short-lived capability is *for*, and it is the one group B case where the
    Guardian's own issuer produced the credential it later refuses.
    """
    token = harness.mint()
    harness.clock.advance(SUITE_TOKEN_LIFETIME_SECONDS + 1)
    outcome = harness.submit(
        harness.action_body(token=token, request_id="req-b1"), label="B1 expired token"
    )
    record = outcome.assert_denied(ReasonCode.TOKEN_EXPIRED)
    assert record.reason_code.group is ReasonGroup.TEMPORAL
    assert harness.executor.calls == [], "an expired token must not reach the executor"


def test_b2_a_token_with_no_expiry_is_refused(harness: GuardianHarness) -> None:
    """``exp`` absent is refused, never read as "does not expire".

    The alternative reading is the dangerous one, and ``guardian/app/models.py`` names it: a token
    that cannot expire is not a short-lived capability token, which is the property section 3.4.2
    actually requires. Absent is not the same statement as far in the future, and only one of them
    has its own reason code.
    """
    token = sign_claims(claims_payload(jti="jti-no-exp", exp=None))
    outcome = harness.submit(
        harness.action_body(token=token, request_id="req-b2"), label="B2 exp absent"
    )
    outcome.assert_denied(ReasonCode.TOKEN_EXPIRY_MISSING)


def test_b3_a_lifetime_above_the_ceiling_is_rejected_not_truncated(
    harness: GuardianHarness,
) -> None:
    """Both halves of the ceiling: nothing mints one, and nothing accepts one that was minted.

    The presented token is authentic and live -- it is inside its own ``exp`` -- and is refused
    solely because ``exp - iat`` exceeds the ceiling this Guardian was configured with. Asserting
    that the executor was never called is what distinguishes "rejected" from "truncated": a Guardian
    that clamped the lifetime would have permitted the action and recorded a permit.
    """
    over_ceiling = SUITE_TOKEN_MAX_LIFETIME_SECONDS + 1

    # Half one: the issue path refuses rather than clamping.
    with pytest.raises(TokenIssueRefused) as refusal:
        harness.mint(ttl_seconds=over_ceiling)
    assert refusal.value.reason is IssueRefusalReason.TTL_ABOVE_CEILING

    # Half two: the enforcement path refuses a token minted somewhere the ceiling did not apply.
    token = sign_claims(
        claims_payload(
            jti="jti-over-ceiling",
            iat=SUITE_EPOCH_SECONDS,
            exp=SUITE_EPOCH_SECONDS + over_ceiling,
        )
    )
    outcome = harness.submit(
        harness.action_body(token=token, request_id="req-b3"), label="B3 lifetime above ceiling"
    )
    outcome.assert_denied(ReasonCode.TOKEN_LIFETIME_ABOVE_CEILING)
    assert harness.executor.calls == [], (
        "a lifetime above the ceiling was truncated and the action ran; section 2 permits an "
        "override up to the ceiling and the plan requires anything beyond it to be rejected"
    )


def test_b4_an_issued_at_in_the_future_is_refused(harness: GuardianHarness) -> None:
    """``iat`` ahead of the Guardian's clock: a token that claims not to exist yet.

    Refused rather than held: a reference monitor that queued a not-yet-valid credential would be
    holding attacker-supplied bytes on the enforcement path for an attacker-chosen duration, which
    is threat-model position P3 turned into a resource the attacker allocates.
    """
    token = sign_claims(
        claims_payload(
            jti="jti-future-iat",
            iat=SUITE_EPOCH_SECONDS + 3600,
            exp=SUITE_EPOCH_SECONDS + 3600 + SUITE_TOKEN_LIFETIME_SECONDS,
        )
    )
    outcome = harness.submit(
        harness.action_body(token=token, request_id="req-b4"), label="B4 iat in the future"
    )
    outcome.assert_denied(ReasonCode.TOKEN_NOT_YET_VALID)


def test_b5_a_not_before_in_the_future_is_refused(harness: GuardianHarness) -> None:
    """``nbf`` ahead of the clock, on an otherwise honest claim set.

    ``nbf`` is not one of architecture section 3's nine claims, so a token carrying one is not a
    token this Guardian issued -- but the verifier still checks it *before* rejecting the claim set,
    and that ordering is right. A not-yet-valid token should be refused for being not yet valid,
    which is a temporal finding, rather than for the shape of its claim set.
    """
    token = sign_claims(claims_payload(jti="jti-future-nbf", nbf=SUITE_EPOCH_SECONDS + 3600))
    outcome = harness.submit(
        harness.action_body(token=token, request_id="req-b5"), label="B5 nbf in the future"
    )
    outcome.assert_denied(ReasonCode.TOKEN_NOT_YET_VALID)


def test_b6_a_not_before_in_the_past_still_fails_the_claim_set(harness: GuardianHarness) -> None:
    """The same extra claim, no longer refusable on temporal grounds, is refused on its own.

    The pair with B5, and it is the pair that matters. ``guardian/app/models.py`` fixes the claim
    set at nine members with ``extra="forbid"`` and says exactly what a token carrying ``nbf``
    should get: ``authenticity.claims-malformed``, "because a token with a claim the Guardian never
    issues is not one of the Guardian's tokens". Without this case, a verifier that simply ignored
    unknown claims would pass B5 and nothing would notice.
    """
    token = sign_claims(claims_payload(jti="jti-past-nbf", nbf=SUITE_EPOCH_SECONDS - 3600))
    outcome = harness.submit(
        harness.action_body(token=token, request_id="req-b6"), label="B6 nbf in the past"
    )
    outcome.assert_denied(ReasonCode.TOKEN_CLAIMS_MALFORMED)


def test_b7_a_token_with_no_issued_at_is_refused(harness: GuardianHarness) -> None:
    """``iat`` absent: the lifetime cannot be computed, so the ceiling cannot be applied.

    Denied under the claim-set code rather than a temporal one, and that is a recorded gap rather
    than a preference. ``guardian.token.verifier.DenialReason`` distinguishes ``IAT_MISSING`` from
    ``EXP_MISSING``; ``guardian.app.models.ReasonCode`` has ``temporal.expiry-missing`` and no
    counterpart for the other half, so the adapter files it as a defective claim set. See the
    mapping table in ``harness.py`` and the vocabulary findings in this commit's report.
    """
    token = sign_claims(claims_payload(jti="jti-no-iat", iat=None))
    outcome = harness.submit(
        harness.action_body(token=token, request_id="req-b7"), label="B7 iat absent"
    )
    outcome.assert_denied(ReasonCode.TOKEN_CLAIMS_MALFORMED)
