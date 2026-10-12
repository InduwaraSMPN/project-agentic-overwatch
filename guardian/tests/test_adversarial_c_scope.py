r"""Group C -- scope: the token is genuine and live, but it does not cover this action.

``docs/plans/M3-implementation-plan.md``'s group C: a verb outside ``allow.verbs``; a resource or
namespace outside ``allow``; wildcard, empty and null allow-claims; cross-run, a valid token with
the wrong ``run_id``; cross-phase, a containment token used in eradication; ``sub`` mismatch, one
Executor presenting another's token; and traversal and homoglyph tricks in ``name`` and
``namespace``. ``docs/milestones/M3-guardian.md``'s Definition of done names "out-of-scope".

Three of these cases land somewhere other than where a reader of the plan would expect, and each
displacement is a finding about the landed code rather than a liberty taken here.

**The three allow-claim dimensions are decided by policy, which answers ``policy.deny-default``.**
``guardian/app/models.py`` declares ``scope.verb-not-allowed``, ``scope.resource-not-allowed`` and
``scope.namespace-not-allowed``, and nothing in the landed pipeline can produce them: matching an
action against an allow-claim is Rego's job, and ``guardian.app.policy.interpret_policy_result``
turns an engine answer into exactly three outcomes -- permit, ``policy.rule-deny`` when the engine
sets ``explicit_deny``, and ``policy.deny-default`` otherwise. There is no channel through which a
Rego rule could name which *dimension* of the scope was exceeded. So the cases below assert the code
the Guardian actually produces, and additionally assert that the allow-claim and the action both
reached the policy input document -- because "the engine said no" is worth nothing as evidence
unless the engine was shown what it needed to say no about. The three unreachable codes are
enumerated and reported in ``test_token_contract_seam.py``.

**Wildcard, empty and null allow-claims die at the token verifier, not at policy.**
``guardian/token/verifier.py`` holds every claim string to an alphabet of letters, digits, ``.``,
``_``, ``:`` and ``-``. ``*`` is not in it, an empty scope list is refused outright, and a null
``allow`` is not a mapping -- so all three are ``authenticity.claims-malformed`` and
``scope.allow-claim-unusable`` is likewise unreachable. That is a stronger position than the one
models.py describes, and the deny-by-default outcome is the same; what is lost is the attribution,
which models.py wanted to point at the claim rather than at the action.

**Traversal and homoglyphs die at the contract boundary.** ``guardian/app/models.py`` holds
``namespace`` to a DNS-1123 label and ``name`` to a DNS-1123 subdomain, so ``../``, ``%2e%2e``,
backslashes, control characters and the entire non-ASCII plane are refused before any token is
verified. models.py records the departure from the plan's grouping and gives the reason: a string
that cannot name a Kubernetes object is not a scope question, because no allow-claim could ever
permit it and no executor could ever act on it.

**The two binding cases are now driven from the request, and that is M4's change rather than this
file's convenience.** ``SCOPE_PHASE_MISMATCH`` and ``SCOPE_SUBJECT_MISMATCH`` used to need a
*differently configured Guardian*, because the phase and the presenting identity were start-time
values -- fail-closed, correct, and implying one process per ``(phase, executor)`` pair, which is
M4's conflict M4-C5. ``ActionRequest`` v2 carries ``executor_id`` and ``phase``, so C8 and C9 state
the mismatch on the request, and C14 and C15 assert the property that the codes' producibility was
only ever a proxy for: **one Guardian serves every phase and every Executor of a run, and still
refuses a borrowed or crossed capability**, with the permits and the denials in one audit chain.

What that check is worth is bounded and is stated at each case rather than assumed: both fields are
agent-declared, so the Guardian *detects and records* a mismatch and does not *prevent* one. Genuine
subject binding would need per-executor transport identity, which FR3.1's "no standing credentials"
precludes. ADR-030, and Chapter 5.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from guardian.app.limits import ACTION_CAP_PER_RUN  # noqa: E402
from guardian.app.models import ReasonCode, ReasonGroup  # noqa: E402
from guardian.tests.harness import (  # noqa: E402
    DEFAULT_ALLOW,
    EXECUTOR_ID,
    NAMESPACE,
    OTHER_EXECUTOR_ID,
    OTHER_PHASE,
    OTHER_RUN_ID,
    PHASE,
    SUPERVISOR_ID,
    GuardianHarness,
    assert_winner_count,
    claims_payload,
    deny_default_result,
    permit_result,
    read_claim,
    sign_claims,
)
from guardian.token.verifier import PHASES, AllowClaim  # noqa: E402


def _outside_scope(harness: GuardianHarness, **action: object) -> None:
    """Run one allow-claim case: policy answers deny-default, and saw what it needed to.

    Shared by the three dimension cases because the assertion is the same in each and only the
    field that steps outside the claim differs. The second half -- what reached the engine -- is
    what makes this a scope test rather than a test of the engine double.
    """
    harness.engine.result = deny_default_result()
    token = harness.mint()
    request_id = str(action.pop("request_id"))
    outcome = harness.submit(
        harness.action_body(token=token, request_id=request_id, **action),
        label=f"C1 outside allow ({request_id})",
    )
    record = outcome.assert_denied(ReasonCode.POLICY_DENY_DEFAULT)
    assert record.reason_code.group is ReasonGroup.POLICY
    assert harness.executor.calls == [], "a denied action must not reach the executor"

    document = harness.engine.seen[-1]
    assert document["capability"]["allow"] == {
        "verbs": list(DEFAULT_ALLOW.verbs),
        "resources": list(DEFAULT_ALLOW.resources),
        "namespaces": list(DEFAULT_ALLOW.namespaces),
    }, "policy was asked to decide scope without being given the allow-claim"
    for field in ("verb", "resource", "namespace"):
        assert field in document["action"], f"policy was not shown the action's {field}"


def test_c1_a_verb_outside_the_allow_claim_is_denied(harness: GuardianHarness) -> None:
    """``delete`` presented under a token whose ``allow.verbs`` is get/list/patch."""
    _outside_scope(harness, request_id="req-c1", verb="delete", name="paymentservice-7d9f8c")


def test_c2_a_resource_outside_the_allow_claim_is_denied(harness: GuardianHarness) -> None:
    """``secrets`` presented under a token whose ``allow.resources`` is pods/deployments."""
    _outside_scope(harness, request_id="req-c2", resource="secrets")


def test_c3_a_namespace_outside_the_allow_claim_is_denied(harness: GuardianHarness) -> None:
    """``kube-system`` presented under a token whose ``allow.namespaces`` is the target app only.

    The one dimension where a permit would be a cross-tenant escape rather than a scope slip, which
    is why it is a separate case rather than a parameter of the one above.
    """
    _outside_scope(harness, request_id="req-c3", namespace="kube-system")


def test_c4_a_wildcard_allow_claim_grants_nothing(harness: GuardianHarness) -> None:
    """``allow.verbs = ["*"]`` is refused, and is refused as a claim-set defect.

    Deny-by-default read literally: an allow-claim that cannot be matched grants nothing. The plan
    files this under scope and the landed verifier refuses it earlier, on its claim alphabet; see
    the module docstring. What matters for the security claim is that no wildcard is ever expanded
    -- a Guardian that read ``*`` as "everything" would have a token type that defeats the whole
    mediation path, and it would look like an ordinary permit in the log.
    """
    token = sign_claims(
        claims_payload(
            jti="jti-wildcard",
            allow={"verbs": ["*"], "resources": ["pods"], "namespaces": [NAMESPACE]},
        )
    )
    outcome = harness.submit(
        harness.action_body(token=token, request_id="req-c4"), label="C4 wildcard allow-claim"
    )
    outcome.assert_denied(ReasonCode.TOKEN_CLAIMS_MALFORMED)
    assert harness.engine.seen == [], "a token refused on its claims must never reach policy"


def test_c5_an_empty_allow_claim_grants_nothing(harness: GuardianHarness) -> None:
    """``allow.verbs = []`` is refused rather than treated as an unconstrained scope."""
    token = sign_claims(
        claims_payload(
            jti="jti-empty-allow",
            allow={"verbs": [], "resources": ["pods"], "namespaces": [NAMESPACE]},
        )
    )
    outcome = harness.submit(
        harness.action_body(token=token, request_id="req-c5"), label="C5 empty allow-claim"
    )
    outcome.assert_denied(ReasonCode.TOKEN_CLAIMS_MALFORMED)


def test_c6_a_null_allow_claim_grants_nothing(harness: GuardianHarness) -> None:
    """``allow: null`` is refused. Absent scope is not unlimited scope."""
    # `claims_payload` treats None as "remove the claim", which is a different attack (that is
    # CLAIM_MISSING). A literal JSON null is what group C names, so it is set here directly.
    payload = claims_payload(jti="jti-null-allow")
    payload["allow"] = None
    token = sign_claims(payload)
    outcome = harness.submit(
        harness.action_body(token=token, request_id="req-c6"), label="C6 null allow-claim"
    )
    outcome.assert_denied(ReasonCode.TOKEN_CLAIMS_MALFORMED)


def test_c7_a_token_minted_for_another_run_is_denied(harness: GuardianHarness) -> None:
    """A valid, live, in-scope token whose ``run_id`` belongs to a different run.

    The request declares the *token's* run id, which is the case that matters: ``run_id`` on an
    ``ActionRequest`` is attacker-controlled (position P1), so an Executor holding a token minted
    for another run can make the request agree with the token and pass any self-consistency check.
    What refuses it is ``GuardianConfig.run_id`` -- the run this process was started for -- and this
    case is what proves the check is taken against configuration rather than against the request.
    """
    token = harness.mint(run_id=OTHER_RUN_ID)
    outcome = harness.submit(
        harness.action_body(token=token, request_id="req-c7", run_id=OTHER_RUN_ID),
        label="C7 cross-run token",
    )
    record = outcome.assert_denied(ReasonCode.SCOPE_RUN_MISMATCH)
    assert record.reason_code.group is ReasonGroup.SCOPE


def test_c8_a_containment_token_used_in_eradication_is_denied(harness: GuardianHarness) -> None:
    """A phase mismatch: the request declares one phase and the token was minted for another.

    Driven entirely from the request, on an ordinary harness, because ``ActionRequest`` v2 carries
    ``phase``. Until it did, this case needed a *differently configured Guardian* -- the expectation
    was start-time configuration, which is fail-closed and correct for a test and means one process
    per phase, which is what M4's conflict M4-C5 records as making a four-phase golden path
    unrunnable.

    What the check is worth is stated on :class:`~guardian.app.models.ActionRequest` and is not
    overstated here: ``phase`` is agent-declared, so this detects a mismatch rather than preventing
    one. A node that borrowed a containment token and *also* declared containment would pass. What
    it cannot do is use a containment capability while telling the Guardian it is eradicating, which
    is the shape a Supervisor defect and a confused agent both take.
    """
    token = harness.mint()  # minted for the suite's default phase, containment
    outcome = harness.submit(
        harness.action_body(token=token, request_id="req-c8", phase=OTHER_PHASE),
        label="C8 cross-phase token",
    )
    record = outcome.assert_denied(ReasonCode.SCOPE_PHASE_MISMATCH)
    assert record.token_jti == read_claim(token, "jti")
    assert record.iss == SUPERVISOR_ID
    assert harness.engine.seen == [], "a token refused on its binding must never reach policy"


def test_c9_one_executor_presenting_another_executors_token_is_denied(
    harness: GuardianHarness,
) -> None:
    """A ``sub`` mismatch: the request declares one Executor and the token names another.

    The same structural point as C8 and the same source: ``ActionRequest`` v2 carries
    ``executor_id``, so the presenting identity travels with the request rather than being fixed
    when the process started.

    The plan's phrase for this case is "one Executor presenting another's token", and the honest
    reading of what is caught is worth repeating because the phrase invites a stronger one. The
    Guardian detects that the identity *declared* is not the token's ``sub``. It does not establish
    that the declaration is true, and it cannot: Executors are in-process nodes with no transport
    identity, which is FR3.1's "no standing credentials" holding. ADR-030 records that, and
    ``models.py`` argues it at length.
    """
    token = harness.mint()  # minted for the suite's default Executor
    outcome = harness.submit(
        harness.action_body(token=token, request_id="req-c9", executor_id=OTHER_EXECUTOR_ID),
        label="C9 subject mismatch",
    )
    record = outcome.assert_denied(ReasonCode.SCOPE_SUBJECT_MISMATCH)
    assert record.token_jti == read_claim(token, "jti")
    assert record.iss == SUPERVISOR_ID

    harness.engine.result = permit_result()
    harness.submit(
        harness.action_body(token=token, request_id="req-c9-correct", executor_id=EXECUTOR_ID),
        label="C9 same token with matching subject after mismatch",
    ).assert_permitted()
    assert len(harness.executor.calls) == 1, "a binding mismatch consumed the token's jti"


def test_c10_a_token_naming_a_phase_that_does_not_exist_is_denied(
    harness: GuardianHarness,
) -> None:
    """A fifth phase is not a phase. The vocabulary is closed and the token is refused."""
    token = sign_claims(claims_payload(jti="jti-fifth-phase", phase="cleanup"))
    outcome = harness.submit(
        harness.action_body(token=token, request_id="req-c10"), label="C10 unknown phase"
    )
    outcome.assert_denied(ReasonCode.TOKEN_CLAIMS_MALFORMED)


def test_c11_traversal_in_name_or_namespace_dies_at_the_contract(
    harness: GuardianHarness,
) -> None:
    """Path traversal, separators, escapes and control characters, each refused as malformed.

    Every one of these is a string that cannot name a Kubernetes object, so there is nothing for an
    allow-claim to match and nothing for an executor to act on. Being refused at the contract
    boundary means the token is never even verified, which is also the cheapest place to refuse it.
    """
    tricks = {
        "req-c11a": {"namespace": "../kube-system"},
        "req-c11b": {"namespace": "boutique/../kube-system"},
        "req-c11c": {"namespace": "%2e%2e%2fkube-system"},
        "req-c11d": {"namespace": "boutique\\kube-system"},
        "req-c11e": {"name": "../../etc/passwd"},
        "req-c11f": {"name": "paymentservice\npatched"},
        "req-c11g": {"name": "payment service"},
        "req-c11h": {"namespace": "Boutique"},
    }
    token = harness.mint()
    for request_id, action in tricks.items():
        outcome = harness.submit(
            harness.action_body(token=token, request_id=request_id, **action),
            label=f"C11 traversal ({request_id}: {action})",
        )
        outcome.assert_denied(ReasonCode.POLICY_REQUEST_MALFORMED)


def test_c12_homoglyphs_in_name_or_namespace_die_at_the_contract(
    harness: GuardianHarness,
) -> None:
    """Non-ASCII lookalikes for an in-scope namespace, each refused as malformed.

    The whole non-ASCII plane is outside the DNS-1123 grammar, so a Cyrillic ``о``, a fullwidth
    ``ｂ`` and a zero-width joiner are all refused for the same reason and none of them can reach a
    string comparison against an allow-claim. That is the property worth having: the defence is a
    grammar rather than a blocklist of lookalikes somebody has to keep current.
    """
    homoglyphs = {
        "req-c12a": "bоutique",  # Cyrillic small letter o
        "req-c12b": "ｂoutique",  # fullwidth latin small letter b
        "req-c12c": "bou‍tique",  # zero-width joiner
        "req-c12d": "boutique ",  # non-breaking space
    }
    token = harness.mint()
    for request_id, namespace in homoglyphs.items():
        outcome = harness.submit(
            harness.action_body(token=token, request_id=request_id, namespace=namespace),
            label=f"C12 homoglyph ({request_id}: {namespace!r})",
        )
        outcome.assert_denied(ReasonCode.POLICY_REQUEST_MALFORMED)


def test_c14_one_guardian_serves_two_executors_and_still_refuses_a_borrowed_token(
    harness: GuardianHarness,
) -> None:
    """One process, two Executors: the right one acts, the wrong one is refused, nothing restarted.

    C9 shows the code is producible. This case shows the property M4-C5 was actually about, and the
    two are not the same assertion. Before ``ActionRequest`` v2 the presenting identity was
    start-time configuration, so a Guardian verified for exactly one Executor and the only way to
    produce a subject mismatch was to configure a *second* Guardian -- which meant the deployment
    the golden path needs, one Guardian serving a whole run, was the deployment in which the check
    could not be made at all.

    So this case does both in one harness: the Executor the token names acts and is permitted, and
    another Executor presents the very same shape of capability and is refused. Both assert the full
    triple, and both records land in one chain -- which is what an evaluation reading a sealed
    bundle needs, because a denial and a permit attributed to two different processes cannot be
    compared.
    """
    harness.engine.result = permit_result()
    mine = harness.mint(subject_id=EXECUTOR_ID)
    harness.submit(
        harness.action_body(token=mine, request_id="req-c14a", executor_id=EXECUTOR_ID),
        label="C14 the Executor the token names",
    ).assert_permitted()

    theirs = harness.mint(subject_id=OTHER_EXECUTOR_ID)
    outcome = harness.submit(
        harness.action_body(token=theirs, request_id="req-c14b", executor_id=EXECUTOR_ID),
        label="C14 a borrowed capability",
    )
    outcome.assert_denied(ReasonCode.SCOPE_SUBJECT_MISMATCH)
    assert outcome.record.reason_code.group is ReasonGroup.SCOPE
    assert outcome.record.token_jti == read_claim(theirs, "jti"), (
        "the borrowed capability denial lost its signature-verified jti"
    )
    assert outcome.record.iss == SUPERVISOR_ID, (
        "the borrowed capability denial lost its registered issuer"
    )
    assert len(harness.executor.calls) == 1, (
        "the borrowed capability reached the executor. Exactly one of the two requests was "
        "permitted, so exactly one action may have been attempted"
    )


def test_c15_one_guardian_serves_four_phases_and_still_refuses_a_cross_phase_token(
    harness: GuardianHarness,
) -> None:
    """One process, every phase of a run: the matching pair acts, the crossed pair is refused.

    C14's argument applied to the other binding, and the one the golden path depends on most
    directly. ``docs/protocols/evaluation-protocol.md`` section 1.6 fixes four phases and a run
    traverses all of them; a Guardian that could serve only one would need four processes, four
    audit chains and four configurations per run, and the phase check would be a property of which
    process a request happened to reach rather than of the capability presented.

    Each of the four phases is exercised against a capability minted for it, and then a containment
    capability is presented on an eradication request -- the plan's own phrasing for this case -- in
    the same process that had just permitted the containment action. Every outcome asserts the full
    triple, so the permits are evidence rather than a warm-up.
    """
    harness.engine.result = permit_result()
    for index, phase in enumerate(PHASES):
        token = harness.mint(phase=phase)
        harness.submit(
            harness.action_body(token=token, request_id=f"req-c15-{index}", phase=phase),
            label=f"C15 in-phase action ({phase})",
        ).assert_permitted()

    containment_token = harness.mint(phase=PHASE)
    outcome = harness.submit(
        harness.action_body(token=containment_token, request_id="req-c15-x", phase=OTHER_PHASE),
        label="C15 a containment capability used in eradication",
    )
    outcome.assert_denied(ReasonCode.SCOPE_PHASE_MISMATCH)
    assert outcome.record.reason_code.group is ReasonGroup.SCOPE
    assert outcome.record.token_jti == read_claim(containment_token, "jti")
    assert outcome.record.iss == SUPERVISOR_ID
    assert len(harness.executor.calls) == len(PHASES), (
        "the cross-phase request reached the executor; only the four in-phase actions may have"
    )


def test_c13_an_in_scope_action_is_permitted_so_the_group_is_not_vacuous(
    harness: GuardianHarness,
) -> None:
    """The control. Without it every case above would pass against a Guardian that denied always.

    This is the case that makes group C evidence rather than a tautology: the same harness, the same
    token, an action inside every dimension of the allow-claim, and a permit that names its rule.
    """
    harness.engine.result = {"allow": True, "rule_id": "guardian:read:pods-in-scope"}
    token = harness.mint(
        allow=AllowClaim(verbs=("get",), resources=("pods",), namespaces=(NAMESPACE,))
    )
    outcome = harness.submit(
        harness.action_body(token=token, request_id="req-c13"), label="C13 in-scope control"
    )
    outcome.assert_permitted(rule_id="guardian:read:pods-in-scope")
    assert len(harness.executor.calls) == 1


# ------------------------------------------------------------------------------------------------
# C16 and C17: the action caps (ADR-129; security-policy.md section 2.1)
#
# These two land in group C for the reason models.py gives for the code they produce: the capability
# is authentic, live and entirely within its allow-claim, and what refuses the request is that this
# capability no longer covers one more action. The seventh scope code is the only one in the group
# whose refusal is about the *budget* rather than the claim, which is exactly what the dissertation
# needs to be able to tell apart -- a bounded agent and an over-reaching one produce the same
# evidence if both are recorded as `policy.deny-default`.
# ------------------------------------------------------------------------------------------------


def test_run_action_cap_exceeded_is_denied(harness: GuardianHarness) -> None:
    """A run's thirty-second permitted action is permitted; its thirty-third is refused.

    **The number is the protocol's, not the test's.** ``ACTION_CAP_PER_RUN`` is
    ``docs/protocols/security-policy.md`` section 2.1's, mirrored in :mod:`guardian.app.limits` and
    checked against that section by ``guardian/tests/test_limits_match_security_policy.py``. A case
    that drove a smaller cap would prove the arithmetic works and prove nothing about the bound this
    campaign runs under, and the two differ by a factor of thirty-two in the number of decisions a
    real run has to get right.

    Each request needs its own capability, because a ``jti`` is single-use and every request here is
    a first spend of a fresh one. That is also why the per-token cap cannot be the subject of this
    case: at a per-token cap of 8 and a one-action lifetime, the replay cache always refuses the
    second presentation of a capability first, so the per-token bound is unreachable through this
    surface -- and is proved at the store instead, by
    ``guardian/tests/test_action_caps.py::test_one_capability_cannot_reserve_more_than_the_per_token_cap``.

    The counters on the refused record are asserted, not just the decision, because
    ``security-policy.md`` section 2.1 requires the reserved and consumed counters in *every*
      decision
    record and a cap whose readings are not in the evidence is a cap Chapter 4 cannot read.
    """
    harness.engine.result = permit_result()
    for index in range(ACTION_CAP_PER_RUN):
        token = harness.mint()
        harness.submit(
            harness.action_body(token=token, request_id=f"req-c16-{index:03d}"),
            label=f"C16 in-budget action {index + 1}/{ACTION_CAP_PER_RUN}",
        ).assert_permitted()

    outcome = harness.submit(
        harness.action_body(token=harness.mint(), request_id="req-c16-over"),
        label=f"C16 action {ACTION_CAP_PER_RUN + 1}/{ACTION_CAP_PER_RUN}",
    )
    record = outcome.assert_denied(ReasonCode.SCOPE_ACTION_CAP_EXCEEDED)
    assert record.reason_code.group is ReasonGroup.SCOPE
    assert record.action_caps is not None, (
        "the cap refusal recorded no counters. security-policy.md section 2.1 requires the reserved "  # noqa: E501 - message
        "and consumed counters in every decision record, and a refusal without them is the one "
        "record whose budget reading a reader most needs"
    )
    assert record.action_caps.per_run == ACTION_CAP_PER_RUN
    assert (
        record.action_caps.run_reserved + record.action_caps.run_consumed == ACTION_CAP_PER_RUN
    ), (
        f"the refusal was decided against {record.action_caps.run_reserved} reserved and "
        f"{record.action_caps.run_consumed} consumed run slots, which is not the cap "
        f"({ACTION_CAP_PER_RUN}); the refusal and the budget disagree about which one was reached"
    )
    assert record.action_caps.token_reserved + record.action_caps.token_consumed == 0, (
        "the refused request took a slot against its own capability. The reserve is all-or-nothing "
        f"across both dimensions, so a request refused for the run's budget must leave its own "
        f"cap untouched: got {record.action_caps.token_reserved} reserved and "
        f"{record.action_caps.token_consumed} consumed"
    )
    assert record.action is not None, (
        "the cap refusal dropped the action. What was attempted is what the audit chain exists to "
        "hold, and a bounded agent is measured by what it kept trying"
    )
    assert len(harness.executor.calls) == ACTION_CAP_PER_RUN, (
        f"{len(harness.executor.calls)} action(s) reached the executor, expected exactly "
        f"{ACTION_CAP_PER_RUN}: the refused one must not have"
    )


def test_concurrent_reservations_cannot_exceed_cap(harness: GuardianHarness) -> None:
    """Forty threads, one budget: exactly ``ACTION_CAP_PER_RUN`` are permitted and eight
    are refused.
        **This is the case the cap exists for, and it cannot be written as two sequential
        requests.** A
        read-then-act counter -- read the count, compare, increment -- is correct for every
        sequential
        test in this file and wrong the moment requests overlap, because each reads a value none of
        the
        others has written yet. The plan names that future explicitly ("so the caps hold under any
        worker
        count or asynchronous evaluation"), and a suite that only ever sends requests one at a time
        is a
        suite that would not notice the day mediation became asynchronous. So the requests go
        through
        :meth:`guardian.tests.harness.GuardianHarness.race`, which puts every one of them on its own
        thread behind a :class:`threading.Barrier`: threads rather than coroutines because the
        pipeline
        is
        synchronous with no await point, so two coroutines would run one after the other and the
        race
        would never happen.

        Forty rather than thirty-three so that the refusals contend with each other too: the
        property is
        not that the last eight lose, it is that the total granted is the cap no matter how the
        eight
        interleave with the thirty-two. The assertion is over the *count* of permits, which is the
        only
        place a lost update is visible at all.
    """
    harness.engine.result = permit_result()
    contenders = ACTION_CAP_PER_RUN + 8
    bodies = [
        harness.action_body(token=harness.mint(), request_id=f"req-c17-{index:03d}")
        for index in range(contenders)
    ]
    winners, losers = assert_winner_count(
        harness.race(bodies, label="C17 concurrent reservations"),
        permitted=ACTION_CAP_PER_RUN,
        loser_reason=ReasonCode.SCOPE_ACTION_CAP_EXCEEDED,
    )
    assert len(losers) == 8, (len(losers), f"expected 8 refusals among {contenders} contenders")
    assert len(harness.executor.calls) == ACTION_CAP_PER_RUN, (
        f"{len(harness.executor.calls)} action(s) reached the executor against a cap of "
        f"{ACTION_CAP_PER_RUN}. The permitted count is the cap; the executor is what the cap bounds"
    )
    # Every winner reserved against a budget that was inside the cap, and every loser against one
    # that was exactly full. The winners' readings differ from each other (1..32, in whatever order
    # the threads arrived) and that is the point: the count of winners is bounded by the cap, and
    # each individual record says how much of it was already gone when that request asked.
    claimed = [
        record.action_caps.run_reserved + record.action_caps.run_consumed for record in winners
    ]
    assert max(claimed) == ACTION_CAP_PER_RUN, (
        f"no permitted action saw a full budget, so the cap was never actually reached by the "
        f"requests that were admitted; the readings were {sorted(claimed)}"
    )
    assert all(1 <= value <= ACTION_CAP_PER_RUN for value in claimed), (
        f"a permitted action reserved outside the cap: {sorted(claimed)}"
    )
    assert {
        record.action_caps.run_reserved + record.action_caps.run_consumed for record in losers
    } == {ACTION_CAP_PER_RUN}, (
        "a refused action did not report a budget that was already full, so it was refused for "
        "another reason"
    )


def test_a_refused_action_releases_its_reservation(harness: GuardianHarness) -> None:
    """A run's budget is spent by what it was *allowed* to do, and by nothing else.

    The release rule is the difference between a cap and a ratchet, and getting it wrong is silent:
    a reserver that never released would still pass
    :func:`test_run_action_cap_exceeded_is_denied` -- it would just refuse earlier, on a run that
    had
    done nothing wrong. So this case drives the run with **refusals only** -- far more of them than
    the cap allows -- and then shows a legitimate action is still permitted. A Guardian that spent
    its budget on being asked to stop is a Guardian that stops mediating: past that point every
    refusal it issues would be an artefact of the budget rather than of the policy, and RQ5's
    policy-compliant action rate would be measuring its own accounting.

    The denials are ``policy.deny-default`` rather than cap refusals throughout, which is the
    distinction the case is about: a run that is refused must be *refused by policy* every time, and
    the cap must never be the reason.
    """
    harness.engine.result = deny_default_result()
    for index in range(ACTION_CAP_PER_RUN + 8):
        harness.submit(
            harness.action_body(token=harness.mint(), request_id=f"req-c18-{index:03d}"),
            label=f"C18 policy-refused action {index + 1}",
        ).assert_denied(ReasonCode.POLICY_DENY_DEFAULT)
    assert harness.executor.calls == [], (
        "a policy denial reached the executor under G0-FULL, which is a different defect and is not "  # noqa: E501 - message
        "what this case is about"
    )

    harness.engine.result = permit_result()
    outcome = harness.submit(
        harness.action_body(token=harness.mint(), request_id="req-c18-then-allowed"),
        label="C18 the run's first permitted action, after more refusals than the cap allows",
    )
    record = outcome.assert_permitted()
    assert record.action_caps is not None
    assert record.action_caps.run_reserved + record.action_caps.run_consumed == 1, (
        f"the budget read {record.action_caps.run_reserved} reserved and "
        f"{record.action_caps.run_consumed} consumed run slots after "
        f"{ACTION_CAP_PER_RUN + 8} refusals; every refusal released its reservation, so this run's "
        "first permit should be the first slot anything spent"
    )
    assert len(harness.executor.calls) == 1, (
        "the one permitted action did not reach the executor, so the case proved the budget was "
        "still available without proving the run can still act"
    )
