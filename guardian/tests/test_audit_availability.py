r"""A credential-shaped ``params`` key is audited and denied, and once produced no record at all.

WHAT THIS MODULE WAS, AND WHY THAT MATTERS TO WHAT IT IS NOW
--------------------------------------------------------------
It was a finding written to fail on being fixed, and it has been fixed. The finding: ``params``
keys are chosen by the attacker (threat model position P1) and ``guardian/app/mediation.py``
projected them verbatim into the audit body, while ``guardian/audit/chain.py`` refuses -- at any
depth, and correctly -- a record body carrying a key whose folded name is in
``FORBIDDEN_RECORD_KEYS``. So ``params: {"api_key": "x"}`` made the append raise,
``Mediator._seal`` turned that into ``AuditUnavailable``, ``main.py`` answered **503**, and the
chain stayed **empty**.

Not an enforcement bypass -- the append precedes execution, so the Guardian failed closed on the
action. What it failed at was the other half of ``docs/protocols/security-policy.md`` section 1.4,
in the direction the M3 plan calls worse than an unblocked action: an unaudited block is invisible
to the evaluation whether or not it happened, and T-22 is scored from that file.

THE FIX, AND WHY THE CHAIN'S GUARD IS UNTOUCHED
------------------------------------------------
``guardian.app.models.recordable_params`` rewrites a credential-shaped key to
``guardian.withheld.<folded name>`` and its value to a constant marker; ``audited_action`` calls it;
``adjudicate`` denies under ``ReasonCode.POLICY_PARAM_NAME_FORBIDDEN``. The chain's guard is not
relaxed by a character -- it still refuses any record body carrying such a key, which is what makes
``data-management.md`` section 5's pre-seal sanitizer a no-op on this file (ADR-022) and what
:func:`test_the_chains_guard_still_refuses_a_guardian_built_body` asserts directly. What changed is
that a key the *Guardian* did not choose no longer reaches that guard wearing the agent's spelling.

WHAT THIS MODULE ASSERTS NOW, IN FOUR LAYERS
----------------------------------------------
1. **The regression guard.** :func:`test_a_credential_shaped_params_key_is_audited_and_denied`
   asserts the two halves of the old defect are gone -- not 503, and not an empty chain -- in the
   terms the old test asserted them in, so a revert is caught by the assertion that was there.
2. **The decision.** Denied, with a structured code, and present in the chain: the same triple
   every ``test_adversarial_*.py`` case makes. This module still sits outside
   ``test_suite_integrity.py``'s scan because its subject is the *availability* of the log rather
   than one adversarial group, but there is no longer any assertion it cannot make.
3. **The evidence.** The withheld key names what the agent tried, the marker says the value was
   removed, and no supplied value survives anywhere in the record.
4. **The cross-check.** ``UNRECORDABLE_PARAM_NAMES`` is a second home for the chain's
   ``FORBIDDEN_RECORD_KEYS`` -- it cannot be an import, for the reasons stated beside it -- so the
   equality is asserted here rather than trusted. Its proper long-term home is
   ``guardian/audit/crosscheck.py``, beside the genesis-sentinel cross-check; it is here because
   ``guardian/audit/`` was not this change's to edit.
"""

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402
from guardian.app.main import ACTIONS_PATH  # noqa: E402
from guardian.app.models import (  # noqa: E402
    UNRECORDABLE_PARAM_NAMES,
    WITHHELD_PARAM_PREFIX,
    WITHHELD_PARAM_VALUE,
    Decision,
    ReasonCode,
    ReasonGroup,
)
from guardian.audit.chain import (  # noqa: E402
    FORBIDDEN_RECORD_KEYS,
    AuditChainWriter,
    AuditRecordRefused,
    scrub_text,
)
from guardian.tests.harness import (  # noqa: E402
    ALTERNATE_SIGNING_MATERIAL,
    GuardianHarness,
    call_asgi,
    claims_payload,
    sign_claims,
)

HTTP_OK = 200
HTTP_SERVICE_UNAVAILABLE = 503

# The value the agent puts under the credential-shaped key. Obviously synthetic and deliberately
# not credential-shaped: `test_suite_integrity.py` scans every literal in this directory, and a
# value the chain's scrubber would rewrite would make "no supplied value survives" untestable --
# the scrubber, not the withholding rule, would be what removed it.
SUPPLIED_VALUE = "supplied-parameter-value-0001"

# The spellings the chain's key normaliser folds together, so this also shows that the
# case-and-separator folding is what an attacker would have to defeat, and does not have to.
CREDENTIAL_SHAPED_KEYS = ("token", "secret", "authorization", "api_key", "API-KEY", "kubeconfig")


def _submit(harness: GuardianHarness, **kwargs: Any) -> tuple[int, Any]:
    """POST one action body built from ``kwargs`` and return the raw status and payload."""
    body = harness.action_body(token=harness.mint(), **kwargs)
    return call_asgi(harness.app, ACTIONS_PATH, json.dumps(body).encode("utf-8"))


# --------------------------------------------------------------------------------------------
# 1 and 2: the regression guard, and the decision
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("key", CREDENTIAL_SHAPED_KEYS)
def test_a_credential_shaped_params_key_is_audited_and_denied(
    key: str, harness: GuardianHarness
) -> None:
    """One extra ``params`` key produces exactly one record and a structured denial.

    The first two assertions are the regression guard and are written against the *old* behaviour
    rather than the new one, on purpose: they fail with the message the finding was reported under
    if the projection ever stops normalising attacker-chosen keys. The rest is the triple every
    adversarial case makes -- denied, with a structured code, present in the chain -- which this
    module could not make before the fix and which was the whole reason it existed.
    """
    status, payload = _submit(harness, request_id="req-audit-deny", params={key: SUPPLIED_VALUE})

    assert status != HTTP_SERVICE_UNAVAILABLE, (
        f"params key {key!r} stops the append again: the Guardian answered 503 rather than a "
        "decision, which is the audit-blindness defect this module was opened for"
    )
    records = harness.records()
    assert len(records) == 1, (
        f"params key {key!r} produced {len(records)} records, not exactly one. Zero is the old "
        "defect -- a request stream that leaves no trace in guardian_audit.jsonl, which "
        "security-policy.md section 1.4 forbids and T-22 is scored from"
    )

    assert status == HTTP_OK, payload
    assert isinstance(payload, dict)
    assert payload["decision"] == Decision.DENY.value, payload
    assert payload["reason_code"] == ReasonCode.POLICY_PARAM_NAME_FORBIDDEN.value, payload
    assert payload["audit_seq"] == records[0].seq

    record = records[0]
    assert record.decision is Decision.DENY
    assert record.reason_code is ReasonCode.POLICY_PARAM_NAME_FORBIDDEN
    assert record.reason_code.group is ReasonGroup.POLICY
    assert harness.verify_chain().ok, "the chain no longer verifies after the withheld record"


def test_the_guardian_still_fails_closed_on_the_action(harness: GuardianHarness) -> None:
    """Nothing reaches the executor. The fix changed what is *recorded*, not what is *run*.

    Before the fix the action was stopped because the append raised. Now it is stopped because it
    is denied and ``G0-FULL`` blocks a denial, which is a strictly better reason for the same
    outcome: there is a decision to read and a reason code to count.
    """
    _submit(harness, request_id="req-audit-deny-2", params={"token": SUPPLIED_VALUE})
    assert harness.executor.calls == [], "an action with a withheld parameter reached the executor"


def test_the_attribution_survives_the_denial(harness: GuardianHarness) -> None:
    """The record still says who sent it, because the token verified before the params were read.

    Ordering assertion, not a formality. If the check ran before token verification, this record
    would carry null ``token_jti`` and ``iss`` -- and an agent could then strip its own attribution
    from the log by adding one key to every request it sent.
    """
    _submit(harness, request_id="req-audit-attrib", params={"api_key": SUPPLIED_VALUE})
    record = harness.records()[0]
    assert record.token_jti is not None, "the denial lost the jti it had already established"
    assert record.iss is not None, "the denial lost the issuer it had already established"


def test_a_forged_token_still_denies_on_authenticity(harness: GuardianHarness) -> None:
    """Adding a credential-shaped key cannot mask a group A finding as a group E one.

    The mirror of the ordering assertion above, from the attacker's side: a token that does not
    verify is an authenticity finding whatever else the request carries, so the reason code is the
    verifier's and the params check never runs.
    """
    forged = sign_claims(
        claims_payload(jti="jti-audit-forged-0001"), material=ALTERNATE_SIGNING_MATERIAL
    )
    body = harness.action_body(
        token=forged,
        request_id="req-audit-forged",
        params={"secret": SUPPLIED_VALUE},
    )
    status, payload = call_asgi(harness.app, ACTIONS_PATH, json.dumps(body).encode("utf-8"))
    assert status == HTTP_OK, payload
    assert isinstance(payload, dict)
    assert payload["decision"] == Decision.DENY.value, payload
    assert ReasonCode(payload["reason_code"]).group is ReasonGroup.AUTHENTICITY, payload
    assert len(harness.records()) == 1


def test_the_same_request_without_the_key_is_audited_normally(harness: GuardianHarness) -> None:
    """The control: one key is the whole difference, and ordinary params are untouched.

    Same token, same action, same free-form ``params`` -- only the key's *name* changes. Without
    the control the cases above would be consistent with the Guardian refusing anything with
    ``params`` in it, which would be a much smaller finding and a much worse fix.
    """
    ordinary = {"harmless": "x", "replicas": 0, "key": "config.yaml", "api.key": "not-folded"}
    status, payload = _submit(harness, request_id="req-audit-ok", params=ordinary)

    assert status == HTTP_OK, payload
    assert isinstance(payload, dict)
    assert payload["reason_code"] == ReasonCode.PERMIT_RULE_ALLOW.value, payload
    records = harness.records()
    assert len(records) == 1
    assert records[0].action is not None
    assert dict(records[0].action.params) == ordinary, (
        "an ordinary params mapping was altered on its way into the record. Bare 'key' and "
        "'api.key' are in this control on purpose: chain.py omits bare 'key' from its forbidden "
        "set because a ConfigMap parameter legitimately names one, and its folding rule keeps '.', "
        "so a wider set or a different fold here would deny a request the chain would have written"
    )


def test_the_executed_spec_is_what_the_caller_asked_for(harness: GuardianHarness) -> None:
    """A permitted action executes exactly the params it was sent. The reverse projection is intact.

    ``executable_action`` hands the executor its output, so a transformation that touched ordinary
    params would silently change what the cluster is asked to do -- a far worse defect than the one
    this module opened with.
    """
    ordinary = {"replicas": 0, "gracePeriodSeconds": 30}
    _submit(harness, request_id="req-audit-exec", verb="patch", params=ordinary)

    assert len(harness.executor.calls) == 1
    _, executed = harness.executor.calls[0]
    assert dict(executed.params) == ordinary


# --------------------------------------------------------------------------------------------
# 3: the evidence
# --------------------------------------------------------------------------------------------


def test_the_withheld_key_survives_into_the_record_and_the_value_does_not(
    harness: GuardianHarness,
) -> None:
    """The record says what the agent tried, and carries nothing the agent supplied under it.

    Both halves are the finding. A record that dropped the key would read exactly like a request
    nobody tampered with, which destroys the signal; a record that kept the value would be the
    born-clean violation ADR-022 exists to prevent.
    """
    _submit(harness, request_id="req-audit-evidence", params={"API-KEY": SUPPLIED_VALUE})

    record = harness.records()[0]
    assert record.action is not None
    params = dict(record.action.params)
    assert params == {f"{WITHHELD_PARAM_PREFIX}apikey": WITHHELD_PARAM_VALUE}, params
    assert SUPPLIED_VALUE not in json.dumps(record.model_dump(mode="json")), (
        "the value supplied under a credential-shaped key reached the record"
    )


def test_the_marker_is_invisible_to_the_pre_seal_sanitizer() -> None:
    """The withheld marker survives ``scrub_text`` unchanged, so the sanitizer stays a no-op.

    ADR-022's resolution of conflict M3-C5 is that the sanitizer finds nothing to change on a
    produced ``guardian_audit.jsonl``. A marker the scrubber rewrote would put a redaction into a
    hashed field on every withheld record, which is the shape of failure that argument exists to
    keep out of the chain.
    """
    assert scrub_text(WITHHELD_PARAM_VALUE, field_path="action.params.x") == WITHHELD_PARAM_VALUE
    assert scrub_text(WITHHELD_PARAM_PREFIX, field_path="action.params.x") == WITHHELD_PARAM_PREFIX


@pytest.mark.parametrize(
    "params",
    [
        pytest.param({"api_key": "a", "API-KEY": "b"}, id="two-spellings"),
        pytest.param({"API-KEY": "b", "api_key": "a"}, id="two-spellings-reversed"),
        pytest.param(
            {"api_key": "a", f"{WITHHELD_PARAM_PREFIX}apikey": "b"}, id="agent-forges-the-marker"
        ),
        pytest.param({f"{WITHHELD_PARAM_PREFIX}apikey": "b", "api_key": "a"}, id="forgery-first"),
        pytest.param(
            {"api_key": "a", "GUARDIAN.WITHHELD.api_key": "b"}, id="forgery-in-another-case"
        ),
    ],
)
def test_a_collision_lands_on_one_entry_whatever_order_it_arrives_in(
    params: dict[str, str], harness: GuardianHarness
) -> None:
    """Every spelling of one finding folds to one key with one value, order-independently.

    The collision case is the one ``.agents/rules/20-parity-and-determinism.md`` binds, because
    this mapping is hashed into the chain. It is resolved by making the colliding entries *equal*
    rather than by ordering them: no last-writer-wins, no counter, no suffix, so the walk order of
    the caller's mapping cannot reach the record. The forgery ids are the second half of the rule
    -- a key already inside the Guardian's reserved namespace is withheld too, so an agent cannot
    plant something in a sealed bundle that reads as the Guardian's own marker.
    """
    _submit(harness, request_id="req-audit-collide", params=params)

    record = harness.records()[0]
    assert record.reason_code is ReasonCode.POLICY_PARAM_NAME_FORBIDDEN
    assert record.action is not None
    assert dict(record.action.params) == {f"{WITHHELD_PARAM_PREFIX}apikey": WITHHELD_PARAM_VALUE}


def test_the_same_request_twice_produces_byte_identical_record_bodies(
    harness_factory: Callable[..., GuardianHarness],
) -> None:
    """Two Guardians, the same colliding request, the same bytes. Determinism, demonstrated.

    Two separate Guardians rather than two requests to one, because a second request to the same
    Guardian differs in ``seq``, ``prev_hash`` and ``hash`` by design. Each chain opens with the
    same run-start genesis (ADR-058), so the request's record sits at the same ``seq`` behind the
    same predecessor in both, and the whole file is comparable, chain fields included.
    """
    lines: list[bytes] = []
    for _ in range(2):
        harness = harness_factory()
        _submit(
            harness,
            request_id="req-audit-determinism",
            params={"api_key": "a", "API-KEY": "b", f"{WITHHELD_PARAM_PREFIX}apikey": "c"},
        )
        lines.append(harness.chain_path.read_bytes())

    assert lines[0] == lines[1], "the same request produced two different records"


# --------------------------------------------------------------------------------------------
# 4: the cross-check, and the guard that must keep firing
# --------------------------------------------------------------------------------------------


def test_the_app_and_the_chain_forbid_exactly_the_same_names() -> None:
    """``UNRECORDABLE_PARAM_NAMES`` is the chain's set, exactly -- not a superset, not a subset.

    A second home for one value, which ADR-022 permits only when a test makes "copy" mean "copy
    that cannot drift". Both directions are asserted because both failures are real and different.
    A name the chain forbids and this set omits is the original defect, reopened for that name. A
    name this set carries and the chain does not is a false positive: the Guardian would deny and
    withhold a parameter the chain would have recorded verbatim, which is the outcome chain.py's
    own comment about bare ``key`` warns against.
    """
    assert UNRECORDABLE_PARAM_NAMES == FORBIDDEN_RECORD_KEYS, {
        "missing here": sorted(FORBIDDEN_RECORD_KEYS - UNRECORDABLE_PARAM_NAMES),
        "extra here": sorted(UNRECORDABLE_PARAM_NAMES - FORBIDDEN_RECORD_KEYS),
    }
    assert len(FORBIDDEN_RECORD_KEYS) >= 15


@pytest.mark.parametrize("name", sorted(FORBIDDEN_RECORD_KEYS))
def test_no_forbidden_name_can_reach_the_chains_key_guard_from_params(
    name: str, harness: GuardianHarness
) -> None:
    """Every name in the chain's own set, sent as a ``params`` key, is recorded rather than refused.

    Parametrised over the chain's set rather than over a hand-written list, so a name added to
    ``FORBIDDEN_RECORD_KEYS`` is covered by this suite the moment it is added rather than the next
    time somebody remembers. The rewritten key is asserted to be outside that set as well, which is
    the property the ``.`` in the prefix guarantees.
    """
    _submit(harness, request_id="req-audit-sweep", params={name: SUPPLIED_VALUE})

    records = harness.records()
    assert len(records) == 1, f"{name!r} left {len(records)} records"
    assert records[0].reason_code is ReasonCode.POLICY_PARAM_NAME_FORBIDDEN
    assert records[0].action is not None
    for key in records[0].action.params:
        folded = key.lower().replace("-", "").replace("_", "")
        assert folded not in FORBIDDEN_RECORD_KEYS, key
        assert key.startswith(WITHHELD_PARAM_PREFIX), key


def test_the_chains_guard_still_refuses_a_guardian_built_body(tmp_path: Path) -> None:
    """The guard the fix did not touch still fires on a body the *Guardian* built wrongly.

    This is the constraint the fix was written under. ``chain.py``'s refusal is correct and is what
    makes ``data-management.md`` section 5's sanitizer a no-op on this file; relaxing it to
    accommodate a caller would have been ``.agents/rules/10``'s "never weaken guardian/policies/ to
    make a test pass" wearing a different filename. So a record body with a credential-named field
    -- which now can only come from a defect in the record builder, never from a caller -- must
    still be refused rather than cleaned.
    """
    writer = AuditChainWriter(tmp_path / "guardian_audit.jsonl", max_justification_chars=64)
    with pytest.raises(AuditRecordRefused):
        writer.append({"decision": "deny", "action": {"params": {"api_key": SUPPLIED_VALUE}}})
    with pytest.raises(AuditRecordRefused):
        writer.append({"decision": "deny", "authorization": SUPPLIED_VALUE})
    assert not (tmp_path / "guardian_audit.jsonl").exists(), "a refused body was written anyway"
