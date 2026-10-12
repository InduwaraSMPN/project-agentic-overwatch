r"""ADR-082: the chain carries every decision's execution outcome, write-ahead kept intact.

WHAT THIS MODULE PINS
----------------------
Supervisor ruling section 3.2, 2026-09-13: "The hash chain carries the execution status: succeeded,
failed or not-attempted. Every ``guardian-executed-*`` predicate counts only ``succeeded``." A
decision is sealed *before* its action is attempted (``guardian/app/mediation.py``'s write-ahead
ordering, which security-policy.md section 1.4 requires and this ADR keeps), so the outcome cannot
be known at the moment the decision's own record is appended -- it can only be added afterwards, in
a record of its own. This suite proves the Guardian writes exactly that record, once per decision,
for every decision, and that ``guardian/audit/outcome.py`` -- already written against this shape --
reads a real Guardian-produced chain the same way it reads its own hand-built fixtures.

WHY EVERY DECISION, NOT ONLY AN EXECUTED ONE
-----------------------------------------------
:class:`~guardian.app.models.ExecutionRecordDraft`'s docstring argues it at length; the short form,
checked here rather than only asserted there, is that ``G1-LOGONLY`` executes what ``G0-FULL``
blocks, so a follow-up written only for executed decisions would append a different number of
records per arm and shift a later decision's ``seq`` differently in each -- putting chain position
on ADR-023's isolation assertion 2's list of things the arm may change, for a reason unrelated to
what that assertion protects. ``test_flag_isolation.py`` is the proof that this suite does not
disturb that assertion; this module is the proof of the mechanism that keeps it undisturbed.
"""

from datetime import UTC, datetime

import pytest
from guardian.app.models import (
    AUDIT_RECORD_SCHEMA_VERSION,
    AUDIT_RECORD_TYPE_EXECUTION,
    ExecutionRecord,
    ExecutionStatus,
    ReasonCode,
)
from guardian.audit import outcome as audit_outcome
from guardian.audit.chain import read_chain
from guardian.audit.record_types import is_execution
from guardian.tests.harness import RUN_ID, GuardianHarness, deny_default_result, permit_result


def test_a_permitted_and_executed_decision_gets_a_succeeded_follow_up(
    harness: GuardianHarness,
) -> None:
    """The ordinary case: a permit, executed, and the chain says the attempt succeeded."""
    harness.engine.result = permit_result()
    decision = harness.submit(
        harness.action_body(token=harness.mint(), request_id="req-exec-succeeded"),
        label="permit",
    ).assert_permitted()

    (execution,) = harness.execution_records()
    assert isinstance(execution, ExecutionRecord)
    assert execution.decision_seq == decision.seq
    assert execution.execution_status is ExecutionStatus.SUCCEEDED
    assert execution.run_id == decision.run_id == RUN_ID
    assert execution.schema_version == AUDIT_RECORD_SCHEMA_VERSION
    assert execution.record_type == AUDIT_RECORD_TYPE_EXECUTION
    assert execution.seq == decision.seq + 1, (
        "the follow-up is the very next record: nothing may be interleaved between a decision and "
        "the outcome it explains"
    )


def test_a_failed_execution_is_recorded_as_failed_not_as_executed(
    harness: GuardianHarness,
) -> None:
    """The defect ADR-082 exists to fix: ``enforcement: executed`` alone cannot say this.

    The Kubernetes API server refusing a ``create networkpolicies`` the Guardian did not block is
    exactly the 2026-09-12 incident the ruling cites. ``FakeActionExecutor.status`` is flipped to
    reproduce it without a cluster: the decision still reads ``enforcement: executed`` -- the
    Guardian did not block it -- and only the follow-up says the attempt itself did not work.
    """
    harness.engine.result = permit_result()
    harness.executor.status = ExecutionStatus.FAILED

    decision = harness.submit(
        harness.action_body(token=harness.mint(), request_id="req-exec-failed"), label="permit"
    ).assert_permitted()
    assert decision.enforcement.value == "executed", (
        "enforcement says the Guardian did not block; it says nothing about whether the cluster "
        "call succeeded, which is precisely the ambiguity this ADR closes"
    )

    (execution,) = harness.execution_records()
    assert execution.decision_seq == decision.seq
    assert execution.execution_status is ExecutionStatus.FAILED

    dumped = decision.model_dump(mode="json")
    assert audit_outcome.execution_status(dumped) != audit_outcome.SUCCEEDED
    assert not audit_outcome.succeeded(dumped)


def test_a_blocked_denial_gets_a_not_attempted_follow_up(harness: GuardianHarness) -> None:
    """A denial the Guardian blocked never reaches the executor, and the chain says so directly."""
    harness.engine.result = deny_default_result()
    decision = harness.submit(
        harness.action_body(token=harness.mint(), request_id="req-exec-blocked", verb="delete"),
        label="blocked denial",
    ).assert_denied(ReasonCode.POLICY_DENY_DEFAULT)

    (execution,) = harness.execution_records()
    assert execution.decision_seq == decision.seq
    assert execution.execution_status is ExecutionStatus.NOT_ATTEMPTED


def test_a_body_that_never_parsed_gets_a_not_attempted_follow_up_too(
    harness: GuardianHarness,
) -> None:
    """``not-applicable`` enforcement (no action was ever formed) still gets its own follow-up.

    Written for uniformity's sake as much as for coverage: every decision gets exactly one, so a
    later decision's ``seq`` is a function of how many decisions preceded it and nothing else,
    identically in every arm (see the module docstring).
    """
    decision = harness.submit(b"{not json", label="malformed body").assert_denied(
        ReasonCode.POLICY_REQUEST_MALFORMED
    )
    assert decision.enforcement.value == "not-applicable"

    (execution,) = harness.execution_records()
    assert execution.decision_seq == decision.seq
    assert execution.execution_status is ExecutionStatus.NOT_ATTEMPTED


def test_execution_records_are_excluded_from_decision_counts(harness: GuardianHarness) -> None:
    """The chain grows by two records per decided action; ``records()`` still counts one.

    This is what keeps ``test_composition.py``'s and ``test_audit_availability.py``'s "exactly one
    record per submitted action" assertions true unmodified: they read through
    :meth:`~guardian.tests.harness.GuardianHarness.records`, which excludes both the run-start
    genesis and this ADR's execution follow-up.
    """
    harness.engine.result = permit_result()
    before = len(harness.records())
    harness.submit(
        harness.action_body(token=harness.mint(), request_id="req-exec-count"), label="permit"
    ).assert_permitted()
    after = harness.records()
    assert len(after) - before == 1

    chain = read_chain(harness.chain_path)
    assert sum(1 for parsed in chain if is_execution(parsed.record)) == 1
    assert len(chain) == 3, "genesis + one decision + its one execution follow-up"


def test_an_execution_record_must_follow_its_own_decision() -> None:
    """The contract-level ordering check: an execution record cannot precede or equal its decision.

    Exercised directly against the model rather than through the pipeline, because the pipeline
    never has an occasion to build a malformed one; the check exists so that a future edit which
    tried to would fail loudly rather than writing a chain nothing downstream could make sense of.
    """
    base = {
        "ts": datetime.now(UTC),
        "run_id": RUN_ID,
        "execution_status": ExecutionStatus.SUCCEEDED,
        "prev_hash": "0" * 64,
        "hash": "1" * 64,
        "record_type": AUDIT_RECORD_TYPE_EXECUTION,
        "schema_version": AUDIT_RECORD_SCHEMA_VERSION,
    }
    with pytest.raises(ValueError, match="genesis"):
        ExecutionRecord.model_validate({**base, "seq": 0, "decision_seq": 0})
    with pytest.raises(ValueError, match="decision_seq"):
        ExecutionRecord.model_validate({**base, "seq": 2, "decision_seq": 2})
    with pytest.raises(ValueError, match="decision_seq"):
        ExecutionRecord.model_validate({**base, "seq": 2, "decision_seq": 3})
    ExecutionRecord.model_validate({**base, "seq": 2, "decision_seq": 1})
