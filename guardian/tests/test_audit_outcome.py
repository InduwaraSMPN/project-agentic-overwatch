"""Execution outcomes: v4 field first, v3 through results.json, never guessed."""

from guardian.audit.outcome import (
    FAILED,
    NOT_ATTEMPTED,
    SUCCEEDED,
    UNKNOWN,
    execution_status,
    results_status_by_seq,
    succeeded,
    succeeded_records,
)


def _decision(seq: int, enforcement: str = "executed", **extra: object) -> dict[str, object]:
    return {"record_type": "decision", "seq": seq, "enforcement": enforcement, **extra}


def test_a_v4_record_is_read_from_its_own_field() -> None:
    assert execution_status(_decision(1, execution_status="failed")) == FAILED
    assert succeeded(_decision(2, execution_status="succeeded"))


def test_a_denial_is_never_an_execution() -> None:
    assert execution_status(_decision(3, enforcement="blocked")) == NOT_ATTEMPTED


def test_a_v3_executed_record_without_a_joinable_result_is_unknown_and_not_counted() -> None:
    record = _decision(4)
    assert execution_status(record) == UNKNOWN
    assert not succeeded(record)


def test_a_v3_record_resolves_through_the_results_join() -> None:
    results = [
        {
            "phase": "containment",
            "actions": [
                {"kind": "issue", "refused": False},
                {
                    "kind": "action",
                    "decided": True,
                    "audit_seq": 2,
                    "execution": {"status": "failed"},
                },
            ],
        },
        {
            "phase": "eradication",
            "actions": [
                {
                    "kind": "action",
                    "decided": True,
                    "audit_seq": 3,
                    "execution": {"status": "succeeded"},
                }
            ],
        },
    ]
    by_seq = results_status_by_seq(results)
    assert by_seq == {2: FAILED, 3: SUCCEEDED}
    chain = [_decision(2), _decision(3)]
    assert [record["seq"] for record in succeeded_records(chain, by_seq)] == [3]


def test_a_malformed_results_file_resolves_nothing() -> None:
    assert results_status_by_seq({"not": "a list"}) == {}
    assert results_status_by_seq([{"actions": [{"kind": "action", "decided": True}]}]) == {}


def test_the_run_start_genesis_is_not_an_execution() -> None:
    genesis = {"record_type": "run-start", "seq": 0, "run_id": "RUN-X"}
    assert execution_status(genesis) == NOT_ATTEMPTED


def test_a_follow_up_execution_record_in_the_chain_resolves_its_decision() -> None:
    from guardian.audit.outcome import bundle_status_by_seq

    chain = [
        {"record_type": "decision", "seq": 1, "enforcement": "executed"},
        {"record_type": "execution", "seq": 2, "decision_seq": 1, "execution_status": "failed"},
    ]
    by_seq = bundle_status_by_seq(chain)
    assert by_seq == {1: FAILED}
    assert execution_status(chain[0], by_seq) == FAILED
    assert execution_status(chain[1], by_seq) == NOT_ATTEMPTED  # the follow-up is not a decision


def test_the_chain_outranks_the_results_copy() -> None:
    from guardian.audit.outcome import bundle_status_by_seq

    chain = [
        {"record_type": "execution", "seq": 3, "decision_seq": 2, "execution_status": "failed"}
    ]
    results = [
        {
            "actions": [
                {
                    "kind": "action",
                    "decided": True,
                    "audit_seq": 2,
                    "execution": {"status": "succeeded"},
                }
            ]
        }
    ]
    assert bundle_status_by_seq(chain, results) == {2: FAILED}
