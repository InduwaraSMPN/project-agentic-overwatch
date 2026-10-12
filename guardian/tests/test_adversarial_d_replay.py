r"""Group D -- replay: has this exact capability already been spent?

``docs/plans/M3-implementation-plan.md``'s group D names three cases and singles out the third:
straight replay of a spent ``jti``; concurrent replay, "two in flight with exactly one winning,
which proves the cache is not read-then-write racy"; and **eviction replay** -- "flood the cache
past its size bound, then replay an older ``jti`` still inside its TTL, which must still be denied.
This is ADR-004's explicit obligation, and it is the only test that proves the 'whichever larger'
clause of ``security-policy.md`` section 2 is implemented rather than merely written down."

WHAT SINGLE USE IS FOR, AND WHY IT IS NOT THE SAME AS EXPIRY
--------------------------------------------------------------
``guardian/token/replay.py`` puts it in one line: single use is "the difference between a
capability and a reusable password". Without it, a token captured from another Executor --
threat-model position P2 -- or simply re-sent by the Executor holding it -- position P3, "replay,
flood, interleave, race" -- authorises the same action again for the rest of its lifetime. Expiry
bounds *how long* a stolen token is useful; single use bounds *how many times*, and only the second
is a capability.

WHY THE EVICTION CASE IS THE ONE THAT CARRIES THE ARGUMENT
------------------------------------------------------------
Section 2 sizes the cache as "the last ``N`` jti **or** one hour, whichever larger". Only the second
half is load-bearing under attack, and only against an attacker who reads the specification: a
size-bounded cache is emptied by anyone who can send ``N`` requests, which position P3 grants
outright, and a Guardian whose cache is size-only would deny a replay in every test written by
somebody who had not thought to flood it first. The size bound alone therefore *looks* correct
until the day it matters. :func:`test_d3_flooding_past_the_size_bound_does_not_open_a_replay_window`
is the case that separates the two implementations, and
:func:`test_d4_an_entry_never_leaves_the_cache_before_its_token_expires` states the property that
makes eviction safe at all: ``guardian/token/replay.py`` retains each entry until
``max(now + window, expires_at, high_water)``, so an entry outlives the token that created it and
there is no interval in which a *live* token is both evicted and replayable.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from guardian.app.models import Decision, ReasonCode, ReasonGroup  # noqa: E402
from guardian.tests.harness import (  # noqa: E402
    SUITE_REPLAY_CACHE_ENTRIES,
    SUITE_REPLAY_CACHE_WINDOW_SECONDS,
    SUITE_TOKEN_LIFETIME_SECONDS,
    GuardianHarness,
    UnavailableReplayCache,
    assert_single_winner,
    claims_payload,
    read_claim,
    sign_claims,
)


def test_d1_a_spent_jti_presented_again_is_denied(harness: GuardianHarness) -> None:
    """The same token, twice. The first use is permitted and the second is refused.

    Both halves are asserted, because only the pair is evidence: a Guardian that denied every
    request would pass the second half alone, and one that never spent a ``jti`` would pass the
    first. Both are audited, and the second record carries the same ``jti`` as the first -- which
    is what lets an analyst see a replay in the log rather than infer it.
    """
    token = harness.mint()
    first = harness.submit(
        harness.action_body(token=token, request_id="req-d1a"), label="D1 first use"
    )
    first_record = first.assert_permitted()

    second = harness.submit(
        harness.action_body(token=token, request_id="req-d1b"), label="D1 straight replay"
    )
    second_record = second.assert_denied(ReasonCode.REPLAY_JTI_SPENT)

    assert second_record.reason_code.group is ReasonGroup.REPLAY
    assert second_record.token_jti is None, (
        "a refused token contributes no attribution: models.py requires token_jti to be null "
        "whenever no claim set was accepted, and a replayed token is one the verifier refused"
    )
    assert first_record.token_jti is not None
    assert len(harness.executor.calls) == 1, "the replayed action reached the executor"


def test_d2_two_concurrent_uses_of_one_token_produce_exactly_one_winner(
    harness: GuardianHarness,
) -> None:
    """Two requests in flight at once, five rounds, exactly one winner each time.

    The property under test is that the cache is not read-then-write racy: an implementation that
    checked membership and then inserted, with anything between the two, would let both requests
    through under precisely this load. Five rounds rather than one because a race that is lost
    reliably is not a race -- a single round could pass by accident on a machine that happened to
    serialise the threads.

    Both outcomes of every round are asserted in full, so the losing side is not merely "not
    permitted" but denied with the replay code and written to the chain.
    """
    for round_index in range(5):
        token = harness.mint()
        bodies = [
            harness.action_body(token=token, request_id=f"req-d2-{round_index}-{side}")
            for side in ("a", "b")
        ]
        outcomes = harness.race(bodies, label=f"D2 concurrent replay round {round_index}")
        winner, losers = assert_single_winner(outcomes, loser_reason=ReasonCode.REPLAY_JTI_SPENT)
        assert len(losers) == 1
        assert winner.decision is Decision.PERMIT
        assert losers[0].reason_code.group is ReasonGroup.REPLAY

    assert len(harness.executor.calls) == 5, (
        f"{len(harness.executor.calls)} action(s) reached the executor across 5 rounds of 2 "
        "concurrent requests; exactly one per round may"
    )


def test_d3_flooding_past_the_size_bound_does_not_open_a_replay_window(
    harness: GuardianHarness,
) -> None:
    """Spend a ``jti``, flood past the cache's size bound, replay the original. Still denied.

    The whole content of section 2's "whichever larger". The cache is configured for four entries
    and the flood spends three times that, so a size-only implementation would have dropped the
    first ``jti`` long before the replay arrives -- and would then permit an action the Guardian has
    already authorised once, which is the exact failure single use exists to prevent.

    The clock does not move, so the window still covers every entry and the two bounds disagree.
    That disagreement is the test: with them in agreement the case cannot tell the two
    implementations apart.
    """
    target = harness.mint()
    harness.submit(
        harness.action_body(token=target, request_id="req-d3-first"), label="D3 first use"
    ).assert_permitted()

    flood = SUITE_REPLAY_CACHE_ENTRIES * 3
    for index in range(flood):
        harness.submit(
            harness.action_body(token=harness.mint(), request_id=f"req-d3-flood-{index:02d}"),
            label=f"D3 flood {index}",
        ).assert_permitted()

    outcome = harness.submit(
        harness.action_body(token=target, request_id="req-d3-replay"),
        label="D3 eviction replay",
    )
    outcome.assert_denied(ReasonCode.REPLAY_JTI_SPENT)
    assert len(harness.executor.calls) == 1 + flood, (
        "the replayed action ran: the cache dropped a jti its window still covers, which is a "
        "size-only bound rather than section 2's 'whichever larger'"
    )


def test_d4_an_entry_never_leaves_the_cache_before_its_token_expires(
    harness: GuardianHarness,
) -> None:
    """Eviction is real, and it never opens a window on a live token. Both halves.

    A cache that merely never evicted would pass D3 and would be an unbounded memory allocation an
    attacker controls -- position P3 again, aimed at the Guardian's own process rather than at its
    decisions. So this case shows the bound working: past the window *and* past the size, the entry
    is gone.

    And it shows why that is safe. ``guardian/token/replay.py`` retains each entry until
    ``max(now + window, expires_at, high_water)``, so a ``jti`` outlives its own token. By the time
    it can be evicted, the token that carried it is expired -- and the replay is refused on temporal
    grounds instead. Denied either way, and never permitted: that pair is the property, and neither
    half states it alone.

    Note what is deliberately *not* asserted -- that the cache never exceeds its entry count. It
    may, and that is the "whichever larger" behaviour rather than a defect: entries whose window has
    not elapsed are retained past the size bound. What the bound guarantees is that an entry both
    past its window and beyond the count is dropped, which is what is checked below.
    """
    target = harness.mint()
    target_jti = read_claim(target, "jti")
    harness.submit(
        harness.action_body(token=target, request_id="req-d4-first"), label="D4 first use"
    ).assert_permitted()
    assert harness.replay_cache.is_spent(target_jti)

    harness.clock.advance(SUITE_REPLAY_CACHE_WINDOW_SECONDS + 1)
    for index in range(SUITE_REPLAY_CACHE_ENTRIES * 2):
        # These tokens are minted at the new time so they are live; the flood is what pushes the
        # cache past its size bound, which is the second condition eviction requires.
        harness.submit(
            harness.action_body(token=harness.mint(), request_id=f"req-d4-flood-{index:02d}"),
            label=f"D4 flood {index}",
        ).assert_permitted()

    assert not harness.replay_cache.is_spent(target_jti), (
        f"{target_jti} is still retained although its window elapsed and the cache is past its "
        f"size bound of {SUITE_REPLAY_CACHE_ENTRIES}. Nothing is being evicted, which makes the "
        "cache an unbounded allocation the request stream controls (threat-model position P3)"
    )

    outcome = harness.submit(
        harness.action_body(token=target, request_id="req-d4-replay"),
        label="D4 replay of an evicted but expired token",
    )
    outcome.assert_denied(ReasonCode.TOKEN_EXPIRED)


def test_d5_a_replay_cache_that_cannot_answer_denies(harness_factory: object) -> None:
    """The cache raises. Fail closed: an unverifiable single-use claim is not a satisfied one.

    The failure mode a cache actually has in production -- a backing store unreachable, a lock not
    acquired -- and the one place where "degrade to permit" is most tempting, because the token
    itself is perfectly good. ``guardian/app/models.py`` fixes the answer: an unverifiable
    single-use claim is not a satisfied one, and the code says so rather than blaming the token.
    """
    build = harness_factory
    harness = build(replay_cache=UnavailableReplayCache())  # type: ignore[operator]
    token = sign_claims(claims_payload(jti="jti-cache-down"))
    outcome = harness.submit(
        harness.action_body(token=token, request_id="req-d5"), label="D5 replay cache unavailable"
    )
    outcome.assert_denied(ReasonCode.REPLAY_CACHE_UNAVAILABLE)
    assert harness.executor.calls == []


def test_d6_a_token_with_no_jti_cannot_be_spent_and_is_denied(harness: GuardianHarness) -> None:
    """No ``jti`` means single use cannot be enforced, so the token is refused.

    ``guardian/app/models.py`` reserves ``replay.jti-missing`` for this and gives the reason -- "a
    capability that cannot be spent is a capability that can be used forever". The landed verifier
    reaches it earlier, as a missing required claim, so the code recorded is
    ``authenticity.claims-malformed`` and ``replay.jti-missing`` is unreachable. Asserted as what
    the Guardian does rather than as what the vocabulary anticipated; the gap is enumerated in
    ``test_token_contract_seam.py``.
    """
    token = sign_claims(claims_payload(jti=None))
    outcome = harness.submit(
        harness.action_body(token=token, request_id="req-d6"), label="D6 no jti"
    )
    outcome.assert_denied(ReasonCode.TOKEN_CLAIMS_MALFORMED)
    assert harness.executor.calls == []


def test_d7_expiry_does_not_substitute_for_single_use(harness: GuardianHarness) -> None:
    """A replay well inside the token's lifetime is still refused. Two bounds, not one.

    The case that stops "the token expires quickly" from being offered as the answer to replay. The
    clock does not move at all here, so the token is as live on the second presentation as on the
    first, and the only thing that refuses it is that the capability has been spent.
    """
    token = harness.mint()
    harness.submit(
        harness.action_body(token=token, request_id="req-d7a"), label="D7 first use"
    ).assert_permitted()
    assert SUITE_TOKEN_LIFETIME_SECONDS > 0
    outcome = harness.submit(
        harness.action_body(token=token, request_id="req-d7b"), label="D7 replay inside lifetime"
    )
    outcome.assert_denied(ReasonCode.REPLAY_JTI_SPENT)
