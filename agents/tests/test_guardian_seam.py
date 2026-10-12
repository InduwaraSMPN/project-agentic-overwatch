r"""The M3/M4 seam, driven from the agent side: what the client sends and what the Guardian answers.

WHAT THIS FILE PINS
-------------------
``docs/plans/M4-implementation-plan.md``'s "Inbound from M3" table lists what the agent layer
inherits from the Guardian, and this file exercises every row of it from the side that consumes it.
The Guardian's own adversarial suite already asserts that the Guardian decides correctly; what it
cannot assert is that :mod:`agents.tools.guardian_client` *reads* those decisions correctly, because
it never runs the client. That gap is the whole subject here, and every case below would leave a
green suite behind if it did not exist.

**A denial is HTTP 200.** ``guardian/app/main.py``: ``POST /v1/actions`` answers 200 with an
``ActionResult`` for every outcome it reached a decision on, and "the status line is not a second
copy of the decision". A client built on the ordinary convention -- non-2xx means failure, retry it
-- would be perfectly idiomatic and catastrophic here, because it would read every denial as a
transport error and retry it, and each retry appends a second row to the hash-chained audit log for
a decision that was already made. Two rows for one attempted action is not cosmetic:
``docs/protocols/evaluation-protocol.md`` section 3 computes both RQ5 measures by counting those
rows, so the arm with the most denials would be the arm whose numbers were most inflated. The case
below therefore asserts three things and not one -- the wire status, the returned type, and that the
chain grew by exactly one.

**The two group-C reason codes are producible through the HTTP seam.** This is conflict M4-C5's
whole point. ``SCOPE_SUBJECT_MISMATCH`` and ``SCOPE_PHASE_MISMATCH`` used to require a *differently
configured Guardian*, because the presenting identity and the phase were start-time values -- which
meant one Guardian process per ``(phase, executor)`` pair and a four-phase golden path that could
not run. ``ActionRequest`` v2 carries ``executor_id`` and ``phase``, and
``agents/tools/guardian_client.py`` sends both, so one Guardian serves a whole run and still refuses
a borrowed or a crossed capability. What that check is worth is bounded and is restated at each
case rather than assumed: both fields are agent-declared under threat-model position P1, so the
Guardian **detects and records** a mismatch and does not **prevent** one. ADR-030, and Chapter 5.

**A minted token verifies.** T4.0b, and it is here because before the fix the Guardian rejected its
own tokens under ``TOKEN_CLAIMS_MALFORMED``: the issuer stamped eight claims and the app's claim
model required nine under ``extra="forbid"``. Every adversarial case still passed -- they all assert
a *denial* -- and the one thing that did not work was the ordinary path. A round trip through the
two real routes is the only case that could have caught it.

**Issuance is bounded by the authority policy.** ADR-031. ``POST /v1/tokens`` establishes no caller
identity, so without a bound on *what* may be minted, any party with reach to that surface mints a
wide claim and the permit follows -- and the mediated arm would not be mediated. The bound is a
deny-by-default authority entrypoint consulted **before** anything is signed, and the case below
asserts the consequence the agent side must be able to observe: a refusal arrives as a
:class:`~agents.tools.guardian_client.NoDecision` carrying the structured code, and **no token comes
back**.

**The client holds no credential and reads no environment.** The type-level half of FR3.1.
``agents/tests/test_executor_lifecycle.py`` asserts the run-time half -- nothing reachable from a
client holds a token after a call -- and this asserts the shape that makes it possible: the
constructor takes a transport and nothing else, and the module never touches ``os.environ``.

**The configuration drift cross-check ``agents/tests/harness.py`` promises.** That module's
docstring justifies duplicating the Guardian's configuration mapping under ADR-022's rule -- "a copy
is legal when a test makes 'copy' mean 'copy that cannot drift'" -- and names this file as the test
that makes it so. The last case is that promise discharged: the required key set is **derived** from
``guardian/app/config.py`` by removing one key at a time and seeing which removals refuse to start,
so a key added there and not here fails here rather than silently configuring a weaker Guardian.

WHAT IS DELIBERATELY NOT HERE
------------------------------
*Whether the Guardian decides correctly.* Both policy engines are scripted doubles;
``agents/tests/harness.py`` gives the reason, which is ``guardian/app/policy.py``'s -- a decision
procedure implemented twice is two policies whose divergence nobody notices. What the real bundle
decides is ``opa test``'s, through ``make guardian-test``.

*The rest of the group A, B, D and E vocabulary.* Forged, expired, replayed and unknown-issuer
tokens are ``guardian/tests/``'s adversarial groups, asserted there against the same pipeline. The
two codes here are the two that were **not producible from the seam** until M4 changed the request
contract, which is why these two and not the others.

*A network.* Nothing below opens a socket. The client is the shipped client and the Guardian is the
real Guardian, assembled by its production composition root and driven through its own ASGI
interface -- see ``agents/tests/harness.py`` for why that is not a mock of anything.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

import pytest
from agents.graphs.nodes import coordination_node
from agents.registry.composer import compose_condition
from agents.registry.loader import PromptRegistry
from agents.registry.model import ScriptedClient, ToolCall
from agents.tools.guardian_client import (
    ACTIONS_PATH,
    TOKENS_PATH,
    GuardianClient,
    NoDecision,
)
from agents.tools.registry import COMPLETE_PHASE_TOOL, PHASE_OUTCOMES
from guardian.app import config as guardian_config
from guardian.app.composition import ISSUE_AUTHORITY_EXCEEDED
from guardian.app.config import GuardianConfig, GuardianStartupError
from guardian.app.models import Decision, GuardianMode, Phase, ReasonCode, ReasonGroup
from harness import (
    EXECUTOR_ID,
    NAMESPACE,
    REPO_ROOT,
    SUPERVISOR_ID,
    InProcessGuardian,
    ScriptedPolicyEngine,
    asgi_transport,
    build_in_process_guardian,
    deny_default_result,
    guardian_environment,
    node_context,
    write_stand_in_bundle,
)

# The status POST /v1/actions answers with for every decision it reached, whatever that decision
# was. Named here because this file's first case is entirely about it: 200 is not "the action was
# allowed", it is "the Guardian decided and the body says what it decided".
HTTP_DECISION_REACHED: Final = 200

# The phase a capability is minted for, and a different one to present it in. Both are members of
# guardian.app.models.Phase; a fifth phase would be refused at the contract boundary and would
# never reach the scope check these cases are about.
MINTED_PHASE: Final = Phase.CONTAINMENT.value
OTHER_PHASE: Final = Phase.ERADICATION.value

# An Executor identity that is not the one a token was minted for. It satisfies the Guardian's
# identifier grammar, because a name that did not would be refused as a malformed request and the
# case would pass for the wrong reason.
OTHER_EXECUTOR_ID: Final = "executor-eradication-02"

# The environment keys guardian/app/config.py declares but does not require, each with the reason
# that module gives for its absence being safe. Written out one key at a time rather than derived,
# because "optional" is a decision somebody took and the derivation below only reports *that* a key
# is optional -- this is where *why* lives, and the assertion holds the two equal.
OPTIONAL_ENVIRONMENT_KEYS: Final[Mapping[str, str]] = {
    guardian_config.MODE_ENV_VAR: (
        "absent means G0-FULL, the arm with the most enforcement, so a configuration mistake "
        "cannot weaken the Guardian -- only leave it strict"
    ),
    guardian_config.RUN_ID_ENV_VAR: (
        "nullable and required as a *field*: a Guardian pinned to no run is a development posture, "
        "and the runner always sets it in a campaign"
    ),
    guardian_config.REGISTERED_ISSUERS_ENV_VAR: (
        "an empty issuer set is meaningful rather than degenerate -- with deny-by-default it means "
        "every token is refused under authenticity.issuer-unknown"
    ),
    guardian_config.SIGNING_KEY_FILE_ENV_VAR: (
        "the projected-Secret half of one requirement satisfiable two ways; this suite supplies "
        "the inline half, so the leave-one-out below reports the inline key required and this one "
        "optional"
    ),
    guardian_config.MAX_REQUEST_BYTES_ENV_VAR: (
        "defaults to ACTION_REQUEST_MAX_BYTES, which is derived from the request model's own field "
        "bounds rather than chosen, so the transport gate can never be narrower than the contract"
    ),
    guardian_config.AUDIT_SIGNING_KEY_FILE_ENV_VAR: (
        "ADR-130: absent means an unsigned v1 chain, the offline/pre-M10 default; the live "
        "deployment sets it to sign. Set-but-unreadable fails closed at config time, so an "
        "unsigned chain that looked configured to sign cannot occur"
    ),
}


# --------------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------------


def recording_transport(guardian: InProcessGuardian) -> tuple[list[tuple[str, int]], Any]:
    """Return a ``(path, status)`` log and a transport that records into it.

    The log is what makes "a denial is HTTP 200" a claim about the wire rather than about how this
    file happened to interpret a return value. The client above it is the shipped client and is
    unaware of the wrapper, which is the point: the status it saw is the status recorded here.
    """
    statuses: list[tuple[str, int]] = []
    inner = asgi_transport(guardian.assembled.app)

    def transport(method: str, path: str, body: bytes) -> tuple[int, Any]:
        status, payload = inner(method, path, body)
        statuses.append((path, status))
        return status, payload

    return statuses, transport


def submit(
    guardian: InProcessGuardian,
    token: str,
    *,
    client: GuardianClient | None = None,
    **overrides: Any,
) -> Mapping[str, Any] | NoDecision:
    """Submit one well-formed action through the real client, with fields overridden by name.

    Everything not overridden is inside the minted scope, so a denial in any case below is
    attributable to the one field that case changed -- which is what makes the reason code evidence
    rather than a coincidence.
    """
    request: dict[str, Any] = {
        "token": token,
        "request_id": f"{guardian.config.run_id}-{MINTED_PHASE}-001",
        "run_id": str(guardian.config.run_id),
        "executor_id": EXECUTOR_ID,
        "phase": MINTED_PHASE,
        "verb": "get",
        "resource": "pods",
        "namespace": NAMESPACE,
        "name": None,
        "params": {},
        "justification": "read the workload the evidence names",
    }
    request.update(overrides)
    return (client or guardian.client).submit_action(**request)


def minted_token(guardian: InProcessGuardian, **overrides: Any) -> Mapping[str, Any]:
    """Mint one capability through ``POST /v1/tokens`` and fail loudly if the Guardian refused."""
    issued = guardian.mint(**overrides)
    assert isinstance(issued, Mapping), (
        f"the Guardian refused to mint the capability this case spends: {issued!r}. Every "
        "assertion that follows is about what happens to a *genuine* token, so a failure to obtain "
        "one is a different finding -- see the issuance cases in this file for that seam"
    )
    return issued


def declared_environment_keys() -> frozenset[str]:
    """Every environment key ``guardian/app/config.py`` names, read out of the module itself.

    That module declares each key as a module-level ``*_ENV_VAR`` constant and its own comment says
    why: "Every key the runner may set, named once." Reading the constants is therefore reading the
    declaration rather than a description of it, and a key added there appears here without anybody
    editing this file.
    """
    return frozenset(
        value
        for name, value in vars(guardian_config).items()
        if name.endswith("_ENV_VAR") and isinstance(value, str)
    )


def required_environment_keys(environment: Mapping[str, str]) -> frozenset[str]:
    """Return the keys of ``environment`` whose removal makes the Guardian refuse to start.

    Derived by leaving one key out at a time and asking
    :meth:`~guardian.app.config.GuardianConfig.from_mapping` -- which is the definition of
    "required" that matters, because it is the one the process itself applies at start. A list of
    required keys written by hand would be a fourth description of the same fact, and the failure
    it would hide is precisely the one this cross-check exists to catch.
    """
    required: set[str] = set()
    for key in environment:
        reduced = {name: value for name, value in environment.items() if name != key}
        try:
            GuardianConfig.from_mapping(reduced)
        except GuardianStartupError:
            required.add(key)
    return frozenset(required)


def environment_accesses(source: str) -> list[int]:
    """Return the lines at which ``source`` reaches the process environment, by any spelling."""
    tree = ast.parse(source)
    accessors = {"environ", "environb", "getenv"}
    imported = {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "os"
        for alias in node.names
        if alias.name in accessors
    }
    return sorted(
        {
            node.lineno
            for node in ast.walk(tree)
            if (isinstance(node, ast.Attribute) and node.attr in accessors)
            or (isinstance(node, ast.Name) and node.id in imported)
        }
    )


# --------------------------------------------------------------------------------------------
# A denial is HTTP 200
# --------------------------------------------------------------------------------------------


def test_a_denial_arrives_as_a_result_over_a_two_hundred_and_is_audited_once(
    tmp_path: Path,
) -> None:
    """A denying policy answers 200 with an ActionResult, and the chain grows by exactly one row.

    The three assertions are the three halves of the same defect, and any one of them alone would
    miss it. A client that treated non-2xx as failure would pass a *type* assertion on a Guardian
    that happened to answer 200; a client that discarded the body would pass a *status* assertion;
    and a client that retried a denial would pass both while writing a second audit row for one
    attempted action. It is the row count that ``evaluation-protocol.md`` section 3 reads, so it is
    the row count this case ends on.
    """
    guardian = build_in_process_guardian(
        tmp_path, engine=ScriptedPolicyEngine(deny_default_result())
    )
    statuses, transport = recording_transport(guardian)
    client = GuardianClient(transport)
    before = len(guardian.audit_records())

    answer = submit(guardian, str(minted_token(guardian)["token"]), client=client)

    action_statuses = [status for path, status in statuses if path == ACTIONS_PATH]
    assert action_statuses == [HTTP_DECISION_REACHED], (
        f"the actions route answered {action_statuses} for a denied action. "
        "guardian/app/main.py answers 200 with an ActionResult for every outcome it reached a "
        "decision on -- the status line is not a second copy of the decision, and a denial is a "
        "decision. A non-2xx here would mean no decision was reached at all"
    )
    assert isinstance(answer, Mapping), (
        f"the client returned {type(answer).__name__} for a denial. A denial is data: "
        "agents/tools/guardian_client.py returns the Guardian's body verbatim, and a NoDecision "
        "means the Guardian could not answer -- a different outcome the graph must treat "
        "differently"
    )
    assert not isinstance(answer, NoDecision), "a denial must never be reported as no decision"
    assert answer["decision"] == Decision.DENY.value, (
        f"the Guardian's answer says {answer['decision']!r}; this case scripted the policy engine "
        "to deny by default"
    )
    reason = ReasonCode(answer["reason_code"])
    assert reason is ReasonCode.POLICY_DENY_DEFAULT, (
        f"the denial carries {reason.value!r} rather than deny-by-default. The vocabulary is "
        "closed and structured because analysis/stats/ counts it; free text or an unexpected code "
        "here means the reason a denial happened is being reported by something other than the "
        "policy result"
    )
    assert reason.group is ReasonGroup.POLICY, (
        f"{reason.value!r} is filed under {reason.group.value!r}; a denial's family is derived "
        "from its own prefix so that a case can be attributed to a threat-model group mechanically"
    )

    records = guardian.audit_records()
    assert len(records) == before + 1, (
        f"the audit chain grew from {before} to {len(records)} record(s) for one denied action. "
        "Exactly one row per attempted action is what evaluation-protocol.md section 3 computes "
        "both RQ5 measures from; a second row is what a client that retried a denial as though it "
        "were a transport error would leave behind, and it would inflate the numbers of whichever "
        "arm was denied most"
    )
    assert records[-1]["reason_code"] == reason.value, (
        f"the chain's last record says {records[-1]['reason_code']!r} and the client was told "
        f"{reason.value!r}. A denial the audit log does not contain is invisible to the evaluation "
        "whether or not it happened"
    )


# --------------------------------------------------------------------------------------------
# The two group-C codes, producible from the seam since M4-C5
# --------------------------------------------------------------------------------------------


def test_an_executor_declaring_another_identity_is_denied_scope_subject_mismatch(
    guardian: InProcessGuardian,
) -> None:
    """One Executor presenting another's capability: denied, recorded, and attributed.

    The policy engine permits in this case, so the denial can only have come from the token check
    -- which is the point. The bound on what this proves is stated here rather than left implied:
    ``executor_id`` is the sender's own declaration under threat-model position P1, so the Guardian
    **detects and records** the mismatch and does not prevent it. Genuine subject binding would need
    per-executor transport identity, which FR3.1's "no standing credentials" precludes. ADR-030.

    What "records" amounts to is asserted rather than assumed. This denial carries a **group C**
    code: the signature verified, the issuer is registered, the token is live, and only the binding
    is wrong. M4-F1 therefore retains the verified ``jti`` and issuer while keeping the refusal's
    claim set unavailable to policy. That is distinct from group-A failures, whose claimed values
    remain null because authenticity or issuer registration was never established.
    """
    before = len(guardian.audit_records())
    minted = minted_token(guardian)

    answer = submit(guardian, str(minted["token"]), executor_id=OTHER_EXECUTOR_ID)

    assert isinstance(answer, Mapping), f"the Guardian reached no decision: {answer!r}"
    reason = ReasonCode(answer["reason_code"])
    assert (
        answer["decision"] == Decision.DENY.value and reason is ReasonCode.SCOPE_SUBJECT_MISMATCH
    ), (
        f"presenting a capability minted for {EXECUTOR_ID!r} while declaring "
        f"{OTHER_EXECUTOR_ID!r} produced {answer['decision']!r} / {reason.value!r}. Until "
        "ActionRequest v2 this code was not producible through the HTTP seam at all -- the "
        "presenting identity was start-time configuration, which meant one Guardian process per "
        "Executor and a golden path that could not run (conflict M4-C5)"
    )
    assert reason.group is ReasonGroup.SCOPE, (
        f"{reason.value!r} is filed under {reason.group.value!r} rather than scope; the token is "
        "genuine and live and simply does not cover this actor, which is what group C means"
    )
    records = guardian.audit_records()
    assert len(records) == before + 1 and records[-1]["reason_code"] == reason.value, (
        f"the chain holds {len(records)} record(s) ending {records[-1]['reason_code']!r}. A "
        "detection that is not recorded is not a detection: attribution is all this check buys, "
        "and it buys nothing at all if the mismatch is not in the log"
    )
    assert records[-1]["token_jti"] == minted["jti"], (
        "the borrowed capability denial lost the jti established by signature verification"
    )
    assert records[-1]["iss"] == SUPERVISOR_ID, (
        "the borrowed capability denial lost its registered issuer attribution"
    )


def test_a_capability_presented_in_another_phase_is_denied_scope_phase_mismatch(
    guardian: InProcessGuardian,
) -> None:
    """A containment capability presented in eradication: denied, attributed, and in the chain.

    The other half of conflict M4-C5, and the same honest limit applies -- ``phase`` is
    agent-declared, so this is detection rather than prevention. What it does establish is that
    **one Guardian serves every phase of a run**: the same process that would permit this action in
    containment refuses it in eradication, with both outcomes in one audit chain.

    As in the subject-mismatch case, the record retains the verified jti and registered issuer:
    refusal prevents policy evaluation, but it does not erase authentic attribution.
    """
    before = len(guardian.audit_records())
    minted = minted_token(guardian, phase=MINTED_PHASE)

    answer = submit(guardian, str(minted["token"]), phase=OTHER_PHASE)

    assert isinstance(answer, Mapping), f"the Guardian reached no decision: {answer!r}"
    reason = ReasonCode(answer["reason_code"])
    assert (
        answer["decision"] == Decision.DENY.value and reason is ReasonCode.SCOPE_PHASE_MISMATCH
    ), (
        f"a capability minted for {MINTED_PHASE!r} and presented in {OTHER_PHASE!r} produced "
        f"{answer['decision']!r} / {reason.value!r}. FR3.2 scopes a capability to one phase, and "
        "the code exists so that a crossed capability is countable separately from an out-of-scope "
        "verb -- RQ5's per-class decomposition reads the distinction"
    )
    records = guardian.audit_records()
    assert len(records) == before + 1 and records[-1]["reason_code"] == reason.value, (
        f"the chain holds {len(records)} record(s) ending {records[-1]['reason_code']!r}"
    )
    assert records[-1]["token_jti"] == minted["jti"], (
        "the cross-phase denial lost the jti established by signature verification"
    )
    assert records[-1]["iss"] == SUPERVISOR_ID, (
        "the cross-phase denial lost its registered issuer attribution"
    )


# --------------------------------------------------------------------------------------------
# A minted token verifies -- T4.0b
# --------------------------------------------------------------------------------------------


def test_a_token_the_guardian_minted_verifies_on_its_own_actions_route(
    guardian: InProcessGuardian,
) -> None:
    """Mint through ``POST /v1/tokens``, spend on ``POST /v1/actions``, and be permitted.

    T4.0b, and the reason it is a case rather than an assumption is that this exact round trip was
    once broken while every adversarial case passed: the issuer stamped architecture section 3's
    eight claims and :class:`~guardian.app.models.CapabilityTokenClaims` required those eight plus
    ``schema_version`` under ``extra="forbid"``, so the Guardian rejected its own tokens under
    ``authenticity.claims-malformed``. Nothing that asserts a denial can see that; only the ordinary
    path can.

    So the assertion is written twice over, deliberately. Once positively -- the decision is a
    permit naming the rule that granted it -- and once against the specific code that regression
    produced, with the reason attached, so that the next occurrence names itself in the failure
    message instead of being read as a policy problem.
    """
    before = len(guardian.audit_records())
    minted = minted_token(guardian)

    answer = submit(guardian, str(minted["token"]))

    assert isinstance(answer, Mapping), f"the Guardian reached no decision: {answer!r}"
    reason = ReasonCode(answer["reason_code"])
    assert reason is not ReasonCode.TOKEN_CLAIMS_MALFORMED, (
        "the Guardian refused a token it had just minted itself under "
        f"{ReasonCode.TOKEN_CLAIMS_MALFORMED.value!r}. That is T4.0b's regression: the issuer and "
        "the app's claim model disagree about the claim set, which no adversarial case can detect "
        "because they all assert a denial and this is one"
    )
    assert answer["decision"] == Decision.PERMIT.value, (
        f"a freshly minted capability spent inside its own scope was {answer['decision']!r} with "
        f"{reason.value!r}. Both engines permit in this configuration, so the only thing that can "
        "deny here is the token pipeline refusing a token the same process issued"
    )
    assert reason.group is ReasonGroup.PERMIT and answer["policy_rule_id"], (
        f"the permit carries {reason.value!r} and rule id {answer['policy_rule_id']!r}. A permit "
        "always names the rule that granted it -- that biconditional is what deny-by-default makes "
        "necessary, and ActionResult enforces it"
    )

    records = guardian.audit_records()
    assert len(records) == before + 1, (
        f"the chain grew from {before} to {len(records)} record(s) for one permitted action"
    )
    assert records[-1]["token_jti"] == minted["jti"], (
        f"the chain attributes the permitted action to {records[-1]['token_jti']!r} and the "
        f"capability minted was {minted['jti']!r}. Matching them is what makes this a *round trip* "
        "rather than two independent calls that both happened to succeed"
    )
    assert answer["audit_seq"] == records[-1]["seq"], (
        f"the result names audit sequence {answer['audit_seq']} and the chain wrote "
        f"{records[-1]['seq']}. A decision cannot be returned without being audited, and the "
        "sequence number is the only evidence the caller has that it was"
    )


# --------------------------------------------------------------------------------------------
# Issuance is bounded by the authority policy -- ADR-031
# --------------------------------------------------------------------------------------------


def test_an_over_wide_mint_is_refused_and_returns_no_capability(tmp_path: Path) -> None:
    """With the authority policy denying, the mint is refused, structured, and empty-handed.

    ``POST /v1/tokens`` is deliberately not uniform with the actions route --
    ``guardian/app/main.py`` explains the asymmetry: issuance is not an adjudicated action, produces
    no audit record, and nothing in the evaluation counts its outcomes, so a refusal is an ordinary
    API error with an ordinary status. The client must therefore report it as
    :class:`~agents.tools.guardian_client.NoDecision`, and the three things worth asserting are that
    it does, that the structured code survives the trip, and -- the one that matters most -- that
    **no token comes back**. ADR-031 makes the policy consultation happen before anything is signed
    precisely so that a refused request leaves no live credential anywhere, and a client that
    returned a partially populated body would put one in the caller's hands.
    """
    guardian = build_in_process_guardian(
        tmp_path, issuance_engine=ScriptedPolicyEngine(deny_default_result())
    )

    refused = guardian.mint(verbs=("delete", "create"), resources=("pods", "deployments"))

    assert isinstance(refused, NoDecision), (
        f"the client returned {type(refused).__name__} for a refused mint. Unlike the actions "
        "route, issuance answers an ordinary status for a refusal, and a caller that read that as "
        "a token would proceed with nothing in its hand"
    )
    assert refused.error == ISSUE_AUTHORITY_EXCEEDED, (
        f"the refusal carries {refused.error!r} rather than the authority code. The caller is told "
        "one structured code whichever authority rule refused, because the rule id would describe "
        "the policy's internal structure to a party the threat model assumes is mapping it -- but "
        "it must be *that* code, or a Supervisor cannot tell an over-wide request from an outage"
    )
    assert refused.status != HTTP_DECISION_REACHED, (
        f"the refusal arrived over {refused.status}; a 200 on this route carries a minted token, "
        "and the asymmetry with the actions route is deliberate rather than an inconsistency"
    )
    assert set(dataclasses.asdict(refused)) == {"status", "error"}, (
        f"the refusal value carries {sorted(dataclasses.asdict(refused))} rather than a status and "
        "a structured error. The authority policy is consulted *before* the inner issuer is "
        "called, so a refused request produces no signature and no jti at all -- there is nothing "
        "for a third field to hold, and a field able to hold one would be a live credential minted "
        "for a scope the Guardian had just decided it would not grant"
    )
    assert guardian.audit_records() == (), (
        f"the audit chain holds {len(guardian.audit_records())} record(s) after a refused mint. "
        "Issuance produces no AuditRecord: it is not an adjudicated action, and a row here would "
        "put an event into the log that evaluation-protocol.md section 3 has no denominator for"
    )


def test_a_mint_within_the_declared_authority_still_succeeds(guardian: InProcessGuardian) -> None:
    """The control for the case above: with the authority policy permitting, a token is returned.

    Without it, the refusal case is satisfied by a Guardian that refuses every mint for any reason
    -- a missing signing key, an unregistered issuer -- and the assertion would be reporting an
    outage as a policy bound.
    """
    issued = guardian.mint()

    assert isinstance(issued, Mapping), (
        f"a mint inside the declared authority was refused: {issued!r}. The refusal case in this "
        "file means nothing unless the same call succeeds when the authority policy permits"
    )
    assert issued["token"] and issued["jti"], (
        f"the mint returned {sorted(issued)} without a usable capability: {issued!r}"
    )


# --------------------------------------------------------------------------------------------
# The client holds no credential and reads no configuration
# --------------------------------------------------------------------------------------------


def test_the_client_constructor_takes_a_transport_and_an_opaque_caller_auth_supplier() -> None:
    """``GuardianClient(transport, *, caller_auth=None)`` -- a transport and one runner-owned seam.

    The type-level statement of FR3.1's second property, updated for SEAM 6. A constructor with a
    ``token`` parameter, or a ``credentials`` one, or one that defaulted a transport built from
    configuration, would make a standing credential possible without any call site looking wrong --
    which is why the signature itself is asserted rather than a behaviour downstream of it.

    ``caller_auth`` does not open that door and is asserted to be the shape that keeps it shut: it
    is
    keyword-only, it defaults to ``None`` (so a client built the old way behaves exactly as before),
    and it is a *supplier* -- a callable the runner injects -- not a credential value. The header it
    yields is requested per call and held nowhere, the credential lives in the runner, and no code
    that composes a model prompt reads it;
    ``test_caller_auth_header_attached_and_not_in_model_context``
    holds the behavioural half. A ``str`` default, or a positional credential parameter, is what
    this
    still forbids.
    """
    parameters = list(inspect.signature(GuardianClient.__init__).parameters)

    assert parameters == ["self", "transport", "caller_auth"], (
        f"GuardianClient.__init__ takes {parameters}. It is supposed to take a transport and,"
        " since "
        "SEAM 6, an opaque caller-auth supplier and nothing else: construction takes the transport "
        "rather than building one so that Tier A drives an in-process application and Tier B"
        " drives a "
        "socket with the same client code above them, and there is still no parameter through"
        " which a "
        "credential *value* could arrive"
    )
    signature = inspect.signature(GuardianClient.__init__)
    transport = signature.parameters["transport"]
    assert transport.default is inspect.Parameter.empty, (
        f"the transport parameter now defaults to {transport.default!r}. A default transport is a "
        "transport built from something -- configuration, an environment variable, a hostname -- "
        "and this module reads none of those by design"
    )
    caller_auth = signature.parameters["caller_auth"]
    assert caller_auth.kind is inspect.Parameter.KEYWORD_ONLY, (
        "caller_auth must be keyword-only, so it can never be passed into the transport's slot by "
        "position and can only ever be named at a call site a reviewer is reading"
    )
    assert caller_auth.default is None, (
        f"caller_auth defaults to {caller_auth.default!r}, not None. Its default is the whole of"
        " the "
        "pre-SEAM-6 behaviour -- no header ever added -- and a non-None default would be a"
        " credential "
        "supplier the client acquired rather than one the runner injected"
    )


def test_the_client_module_never_reaches_the_process_environment() -> None:
    """No ``os.environ`` and no ``os.getenv`` anywhere in the client, by any spelling.

    ``agents/tools/guardian_client.py``: "It does not read configuration. The base URL is a
    constructor argument. Nothing here consults the environment, which is what lets the env scan
    assert an empty result rather than an allowlisted one." This is that sentence checked. The
    parse recognises the aliased spelling as well as the attribute one, for the reason
    ``scripts/grep_guard.sh``'s header gives about import greps: a name bound once at the top of a
    module leaves no later line naming the library.
    """
    source_path = REPO_ROOT / "agents" / "tools" / "guardian_client.py"
    lines = environment_accesses(source_path.read_text(encoding="utf-8"))

    assert lines == [], (
        f"{source_path.relative_to(REPO_ROOT).as_posix()} reaches the process environment at "
        f"line(s) {lines}. The one route from the agent layer to the cluster must be a function of "
        "its arguments alone: a client that read configuration would be a client whose behaviour a "
        "run manifest could not fully describe, and the first thing anybody would read from the "
        "environment there is a credential"
    )


# --------------------------------------------------------------------------------------------
# The configuration drift cross-check harness.py promises
# --------------------------------------------------------------------------------------------


def test_the_suite_configures_exactly_what_the_guardian_requires(tmp_path: Path) -> None:
    """Hold ``harness.guardian_environment`` and ``guardian.app.config`` equal, in both directions.

    ``agents/tests/harness.py`` duplicates the Guardian's configuration mapping and argues that the
    duplication is legal under ADR-022 because "a copy is legal when a test makes 'copy' mean 'copy
    that cannot drift'", naming this case as the test that makes it so. Discharging that promise
    needs both directions, because each hides a different failure.

    *Every key the suite sets is one the Guardian reads.* A misspelled key would otherwise be
    ignored in silence, and the Guardian would run with whatever the corresponding field defaults to
    -- which for a security parameter means a weaker Guardian that every test still passes against.

    *Every key the Guardian requires is one the suite sets.* This direction needs no explicit
    comparison and is the stronger of the two: a required key added to ``config.py`` and not here
    makes :meth:`~guardian.app.config.GuardianConfig.from_mapping` refuse to start, so the
    derivation below cannot even run. That is the failure landing *here*, in the file that promised
    it, rather than as an obscure startup error in whichever case happened to build a Guardian
    first.

    The required set is derived rather than listed, by leaving one key out at a time. The remainder
    -- the keys the Guardian declares and does not require -- is held equal to
    :data:`OPTIONAL_ENVIRONMENT_KEYS`, where each one carries the reason ``config.py`` gives for its
    absence being safe. So a *new* key is caught whichever kind it is: required, and the derivation
    fails; optional, and the remainder no longer matches.
    """
    environment = guardian_environment(
        mode=GuardianMode.G0_FULL,
        bundle_path=write_stand_in_bundle(tmp_path / "policies"),
        audit_log_path=tmp_path / "guardian_audit.jsonl",
    )
    declared = declared_environment_keys()
    supplied = frozenset(environment)

    assert declared, (
        "no *_ENV_VAR constants were found in guardian.app.config, so every comparison below "
        "would be against an empty set. That module names each key once as such a constant; an "
        "empty read means the convention changed and this derivation is now checking nothing"
    )
    try:
        GuardianConfig.from_mapping(environment)
    except GuardianStartupError as refusal:
        raise AssertionError(
            f"the configuration agents/tests/harness.py builds does not start a Guardian: "
            f"{refusal}. This is the drift the harness's docstring promises would fail *here* -- a "
            "key that guardian/app/config.py now requires and this suite does not set. Add it to "
            "harness.guardian_environment with the value a runner would supply; every case in this "
            "directory builds a Guardian and would otherwise fail for a reason none of them names"
        ) from refusal
    assert supplied <= declared, (
        f"the suite sets key(s) {sorted(supplied - declared)} that guardian/app/config.py does not "
        "declare. An unread key is silently ignored, and the Guardian then runs with the default "
        "of whatever field the key was meant to set -- a weaker Guardian that every test in this "
        "directory still passes against, which is the exact failure ADR-022's 'copy that cannot "
        "drift' rule exists to make impossible"
    )

    required = required_environment_keys(environment)
    optional = frozenset(OPTIONAL_ENVIRONMENT_KEYS)

    assert declared - required == optional, (
        f"guardian/app/config.py declares {sorted(declared - required)} without requiring them, "
        f"and this file documents {sorted(optional)} as safely absent. Every difference is a "
        "decision somebody has to write down: a key that became optional needs its reason recorded "
        "in OPTIONAL_ENVIRONMENT_KEYS, and a key that became required needs the suite to set it. "
        "Reasons currently recorded: "
        + "; ".join(f"{key} -- {why}" for key, why in sorted(OPTIONAL_ENVIRONMENT_KEYS.items()))
    )
    assert required == supplied - optional, (
        f"the keys the Guardian refuses to start without are {sorted(required)}, and the keys this "
        f"suite sets beyond the documented-optional ones are {sorted(supplied - optional)}. The "
        "two must be the same set: a key in the first and not the second cannot happen (the "
        "Guardian would not have started), so a difference here means the suite is setting a "
        "required-looking key the Guardian in fact ignores"
    )


def test_the_drift_cross_check_would_notice_a_missing_required_key(tmp_path: Path) -> None:
    """Remove one required key from the suite's mapping and assert the Guardian refuses to start.

    The control for the case above, and the reason it is needed is the same reason every scan in
    this suite carries one: the cross-check's strongest direction is the one that manifests as a
    *failure to build*, so it is worth demonstrating that a build failure is what a missing key
    actually produces -- rather than, say, a Guardian that starts with an empty signing key and
    verifies nothing while looking configured.
    """
    environment = guardian_environment(
        mode=GuardianMode.G0_FULL,
        bundle_path=write_stand_in_bundle(tmp_path / "policies"),
        audit_log_path=tmp_path / "guardian_audit.jsonl",
    )
    withheld = guardian_config.SIGNING_KEY_ENV_VAR
    reduced = {name: value for name, value in environment.items() if name != withheld}

    with pytest.raises(GuardianStartupError) as refusal:
        GuardianConfig.from_mapping(reduced)

    assert withheld in str(refusal.value), (
        f"the Guardian refused to start without {withheld} but the message does not name it: "
        f"{refusal.value}. The person reading it is by definition somebody whose runner flag did "
        "not do what they expected, and 'invalid configuration' would send them to read the source"
    )


# --------------------------------------------------------------------------------------------
# SEAM 6: the caller-authentication header supplier (WS-1's side of ADR-128)
# --------------------------------------------------------------------------------------------
#
# WHY THIS IS AN AGENT-SIDE CLAIM AND NOT A GUARDIAN ONE
# ------------------------------------------------------
# The Guardian half -- `POST /v1/tokens` and `POST /v1/phase` require a control-plane bearer
# verified
# by TokenReview, and an unauthenticated mint is refused -- is `guardian/tests/`, and WS-4 owns it.
# What this file holds is the three properties only the agent layer can break:
#
# * the header reaches the control-plane route and **only** that route. Attaching it everywhere
# would
#   put a control-plane credential on `POST /v1/actions`, which the Guardian deliberately leaves
#   unauthenticated, and would make the action path's wire bytes depend on a credential's lifetime.
# * it is a *supplier*, requested per call and retained nowhere. A client that cached the header
#   would hold a bearer credential for the run, which is exactly what FR3.1's "no standing
#   credentials" forbids and what `test_executor_lifecycle.py` walks the object graph to refute.
# * it never reaches model-visible text. The credential lives in the runner process; what arrives
#   here is a callable, and a callable nothing composes a prompt from cannot be in a prompt.

# A synthetic bearer written here, in a test file, that authenticates against nothing. Deliberately
# not JWT-shaped: the point of the assertions below is that this *string* never appears in a model
# context, and a realistic-looking token would invite a reader to go looking for it in a bundle.
SYNTHETIC_CALLER_BEARER: Final = "caller-auth-supplied-by-the-runner-process-only"


def test_caller_auth_header_attached_and_not_in_model_context(
    tmp_path: Path, registry: PromptRegistry
) -> None:
    """The supplier's header reaches the tokens route only, is retained nowhere, never modelled.

    Three claims, each about a different kind of leak, and the recording transport is what makes the
    first two statements about the wire rather than about a return value: a client that built the
    header and then dropped it would satisfy "the mint worked" and nothing here.

    * **Route discipline.** ``POST /v1/tokens`` goes out with ``Authorization``; ``POST
    /v1/actions``
      goes out with no extra header at all. The second half is the load-bearing one -- the actions
      route is the one route the Guardian leaves unauthenticated, and a control-plane bearer riding
      on it would be a credential in the request-body path whose status ``analysis/`` counts.
    * **No retention.** The supplier is called once per authenticated call and its product is not
      anywhere on the client afterwards. ``vars(client)`` is enumerated rather than trusted, because
      the failure this exists to catch is an attribute somebody added.
    * **No model context.** A real node is driven over the same client and the bearer string is
      searched for in every composed context and system prompt. The model is scripted to close the
      phase immediately, so the run is one call long and the search is over exactly the prompts a
      phase would send.

    The honest limit is stated rather than left implied: the in-process assembly leaves the
    control-plane verifier optional, so this suite's Guardian accepts the mint whether or not the
    header arrived, and the assertions therefore read the recorded request headers rather than the
    outcome. WS-4's `guardian/tests/test_control_auth.py` is what holds the enforcement half; what
    is
    proved here is that the agent layer puts the header where it belongs, and nowhere else.
    """
    guardian = build_in_process_guardian(tmp_path)
    seen: list[tuple[str, Mapping[str, str]]] = []
    inner = asgi_transport(guardian.assembled.app)

    def transport(
        method: str, path: str, body: bytes, headers: Mapping[str, str] | None = None
    ) -> tuple[int, Any]:
        seen.append((path, dict(headers or {})))
        return inner(method, path, body, headers)

    supplier_calls: list[None] = []

    def caller_auth() -> Mapping[str, str]:
        supplier_calls.append(None)
        return {"Authorization": f"Bearer {SYNTHETIC_CALLER_BEARER}"}

    client = GuardianClient(transport, caller_auth=caller_auth)

    minted = client.issue_capability_token(
        supervisor_id=SUPERVISOR_ID,
        executor_id=EXECUTOR_ID,
        run_id=str(guardian.config.run_id),
        phase=MINTED_PHASE,
        verbs=("get", "list"),
        resources=("pods",),
        namespaces=(NAMESPACE,),
    )
    assert isinstance(minted, Mapping), (
        f"the in-process Guardian refused to mint: {minted!r}. Every claim below is about what the "
        "client *sends*, so a run that never obtained a capability is a different finding -- see"
        " the "
        "issuance cases above for the seam itself"
    )

    assert client.submit_action(
        token=str(minted["token"]),
        request_id=f"{guardian.config.run_id}-{MINTED_PHASE}-001",
        run_id=str(guardian.config.run_id),
        executor_id=EXECUTOR_ID,
        phase=MINTED_PHASE,
        verb="get",
        resource="pods",
        namespace=NAMESPACE,
        name=None,
        params={},
        justification="read the workload the evidence names",
    )

    by_path = dict(seen)
    assert TOKENS_PATH in by_path, f"no request was made to {TOKENS_PATH}: {seen!r}"
    assert ACTIONS_PATH in by_path, f"no request was made to {ACTIONS_PATH}: {seen!r}"
    assert by_path[TOKENS_PATH].get("Authorization") == f"Bearer {SYNTHETIC_CALLER_BEARER}", (
        f"the tokens route went out with headers {by_path[TOKENS_PATH]!r}. SEAM 6 puts a bearer "
        "dependency on POST /v1/tokens, and without the header the Guardian answers 401 -- so a "
        "header that stopped being attached would break every mint in the campaign rather than "
        "quietly weaken it"
    )
    assert by_path[ACTIONS_PATH] == {}, (
        f"the actions route went out with headers {by_path[ACTIONS_PATH]!r}. POST /v1/actions is"
        " the "
        "one route the Guardian leaves unauthenticated (WS-4's dependency covers /v1/phase and "
        "/v1/tokens only), and a control-plane bearer on it would be a credential in the request-"
        "body path whose status the analysis counts"
    )
    assert len(supplier_calls) == 1, (
        f"the supplier was called {len(supplier_calls)} time(s) across one authenticated request"
        " and "
        "one unauthenticated one. It is a *supplier* -- asked per call, holding nothing between "
        "calls -- so being asked on the actions route would mean the credential is attached to a "
        "request that does not need it"
    )

    # Nothing retained: the header's product must be unreachable from the client afterwards.
    assert SYNTHETIC_CALLER_BEARER not in str(vars(client)), (
        f"the client's instance state is {vars(client)!r} and carries the bearer value. The "
        "supplier's product is a header for one request; a client that kept it would hold a "
        "credential for the run, which is FR3.1's 'standing credential'"
    )
    assert set(vars(client)) == {"_transport", "_caller_auth"}, (
        f"GuardianClient's instance state grew to {sorted(vars(client))}"
    )

    # Nothing modelled: drive a real node over the same client and search every prompt it composes.
    model = ScriptedClient(
        [
            ToolCall(
                name=COMPLETE_PHASE_TOOL.name,
                arguments={"outcome": PHASE_OUTCOMES[0], "summary": "closed"},
            )
        ]
    )
    composition = registry.compositions["S2-FLAT"]
    node = coordination_node(
        compose_condition(registry, "S2-FLAT").role("coordinator"),
        budget=composition.budgets[MINTED_PHASE]["coordinator"],
        tools=composition.role("coordinator").tools,
    )
    context = node_context(guardian, model=model)
    object.__setattr__(context, "guardian", client)
    node(context, MINTED_PHASE)

    assert model.calls, "the node never called the model, so no prompt was composed to search"
    for index, call in enumerate(model.calls):
        assert SYNTHETIC_CALLER_BEARER not in call.context, (
            f"model call {index}'s context carries the caller-auth bearer value. The credential"
            " lives "
            "in the runner process; what reaches agents/ is a callable, and a callable nothing "
            "composes a prompt from cannot be in a prompt"
        )
        assert SYNTHETIC_CALLER_BEARER not in call.system, (
            f"model call {index}'s system prompt carries the caller-auth bearer value"
        )
        assert "Authorization" not in json.dumps(call.tools), (
            f"model call {index} was offered a tool carrying an Authorization header: "
            f"{json.dumps(call.tools)}"
        )
