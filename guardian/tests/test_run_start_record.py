r"""ADR-058's run-start record: the chain's genesis, idempotent across restart, never an attempt.

WHAT THIS MODULE PINS
---------------------
The operator's decision has two halves, and each fails in its own way. A Guardian starting on a
new or empty per-run chain writes exactly one run-start record at ``seq`` zero -- without it, a run
whose agents never reached the Guardian leaves no chain and cannot seal, which is the quarantined
attempt ADR-058 cites. A Guardian restarting on a chain that already holds records writes none --
without that, every pod restart would claim a second genesis inside one run.

Beside it, the property ADR-054 asks of every Guardian record, which refusals used to break: the
record carries the run this Guardian was started for. It is checked here across every record type
the Guardian writes, the genesis included, because a rule stated per record is only as strong as
the record kind nobody thought to check.

And the consumers that live under ``guardian/``: the verifier accepts a chain that begins with a
run-start -- through its module and through ``scripts/audit_verify.sh`` -- replay never counts one
as an attempt, and the pre-seal sanitizer has nothing to change in it.
"""

import sys
from collections.abc import Callable
from pathlib import Path
from typing import get_args

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402
from guardian.app import mediation  # noqa: E402
from guardian.app.mediation import AuditDraft  # noqa: E402
from guardian.app.models import (  # noqa: E402
    AUDIT_RECORD_SCHEMA_VERSION,
    AUDIT_RECORD_TYPE_DECISION,
    AUDIT_RECORD_TYPE_EXECUTION,
    AUDIT_RECORD_TYPE_RUN_START,
    AuditRecord,
    ExecutionRecord,
    ExecutionRecordDraft,
    GuardianMode,
    ReasonCode,
    RunStartDraft,
    RunStartRecord,
)
from guardian.audit import outcome as audit_outcome  # noqa: E402
from guardian.audit import record_types  # noqa: E402
from guardian.audit.chain import GENESIS_PREV_HASH, read_chain, scan_chain_file  # noqa: E402
from guardian.audit.verify import (  # noqa: E402
    DIAGNOSIS_INTACT,
    main,
    replay,
    replay_summary,
    run_start_records,
    verify_file,
)
from guardian.tests.harness import (  # noqa: E402
    RUN_ID,
    UNREGISTERED_SUPERVISOR_ID,
    GuardianHarness,
    deny_default_result,
    make_harness,
    permit_result,
    run_shell_script,
)
from pydantic import ValidationError  # noqa: E402

AUDIT_VERIFY_SCRIPT = REPO_ROOT / "scripts" / "audit_verify.sh"

# Every key a run-start carries. Stated as a set so that a field added to the genesis -- a decision
# field in particular, which would make it countable -- fails here by name.
RUN_START_FIELDS = frozenset(
    {"seq", "ts", "run_id", "guardian_mode", "prev_hash", "hash", "record_type", "schema_version"}
)

ARMS = (GuardianMode.G0_FULL, GuardianMode.G1_LOGONLY, GuardianMode.G2_SHAREDCRED)


# --------------------------------------------------------------------------------------------
# The vocabulary, and the genesis itself
# --------------------------------------------------------------------------------------------


def test_the_record_type_vocabulary_means_one_thing_in_both_homes() -> None:
    """The contract's spelling and the chain readers' spelling are the same three strings.

    ``guardian/app/models.py`` types ``record_type`` on the contracts; ``guardian/audit/
    record_types.py`` is what the verifier, the runner and analysis read it through, because
    ``guardian/audit/`` may not import the app layer (ADR-022). Two homes are legal only when a test
    makes "copy" mean "copy that cannot drift", and this is that test. ADR-082's execution record is
    the third kind, checked here on the same terms as the run-start genesis ADR-058 added; the same
    two-homes argument, and ``guardian/audit/outcome.py`` imports its own copy of the vocabulary's
    third string from ``record_types.py`` rather than restating it, which is the crosscheck's real
    third home closed rather than left open (see that module's own comment).
    """
    assert AUDIT_RECORD_TYPE_DECISION == record_types.DECISION_RECORD_TYPE
    assert AUDIT_RECORD_TYPE_RUN_START == record_types.RUN_START_RECORD_TYPE
    assert AUDIT_RECORD_TYPE_EXECUTION == record_types.EXECUTION_RECORD_TYPE
    assert AUDIT_RECORD_TYPE_EXECUTION == audit_outcome.EXECUTION_RECORD_TYPE
    assert record_types.RECORD_TYPES == {
        AUDIT_RECORD_TYPE_DECISION,
        AUDIT_RECORD_TYPE_RUN_START,
        AUDIT_RECORD_TYPE_EXECUTION,
    }
    typed = (
        (AuditRecord, AUDIT_RECORD_TYPE_DECISION),
        (AuditDraft, AUDIT_RECORD_TYPE_DECISION),
        (RunStartRecord, AUDIT_RECORD_TYPE_RUN_START),
        (RunStartDraft, AUDIT_RECORD_TYPE_RUN_START),
        (ExecutionRecord, AUDIT_RECORD_TYPE_EXECUTION),
        (ExecutionRecordDraft, AUDIT_RECORD_TYPE_EXECUTION),
    )
    for model, expected in typed:
        declared = get_args(model.model_fields[record_types.RECORD_TYPE_FIELD].annotation)
        assert declared == (expected,), f"{model.__name__}.record_type admits {declared}"
        version = get_args(model.model_fields["schema_version"].annotation)
        assert version == (AUDIT_RECORD_SCHEMA_VERSION,), f"{model.__name__} is at {version}"


def test_a_fresh_guardian_writes_exactly_one_run_start_as_the_chain_genesis(
    harness: GuardianHarness,
) -> None:
    """Before any request: one record, at seq 0, carrying the configured run, arm and time.

    The case the quarantined attempt needed. Nothing has been asked of this Guardian, and its chain
    already exists, verifies and names the run it belongs to -- which is what lets a run whose
    agents never act seal as the failure it is instead of vanishing from the data.
    """
    chain = read_chain(harness.chain_path)
    assert len(chain) == 1, f"a fresh chain holds {len(chain)} records; the genesis is one"
    (genesis,) = chain
    assert genesis.defect is None, genesis.defect
    assert record_types.is_run_start(genesis.record)
    assert set(genesis.record) == RUN_START_FIELDS, sorted(set(genesis.record) ^ RUN_START_FIELDS)

    start = RunStartRecord.model_validate(genesis.record)
    assert start.seq == 0
    assert start.prev_hash == GENESIS_PREV_HASH
    assert start.run_id == RUN_ID
    assert start.run_id == harness.config.run_id
    assert start.guardian_mode is GuardianMode.G0_FULL
    assert start.ts == harness.clock.instant()
    assert start.schema_version == AUDIT_RECORD_SCHEMA_VERSION

    # The chain has begun: the writer's head is the genesis, and the next record will be seq 1.
    assert harness.sink.writer.head == start.hash
    assert harness.sink.writer.next_seq == 1
    assert harness.records() == [], "the genesis is not a decision"
    assert harness.run_start_records() == [start]
    report = verify_file(harness.chain_path, expected_head=harness.sink.writer.head)
    assert report.ok, [str(finding) for finding in report.findings]


@pytest.mark.parametrize("arm", ARMS)
def test_the_run_start_names_the_arm_the_guardian_was_started_in(
    arm: GuardianMode, harness_factory: Callable[..., GuardianHarness]
) -> None:
    """A chain states which arm produced it even when it holds no decision at all."""
    harness = harness_factory(mode=arm)
    (start,) = harness.run_start_records()
    assert start.guardian_mode is arm


def test_a_guardian_that_pins_no_run_records_a_null_run(
    harness_factory: Callable[..., GuardianHarness],
) -> None:
    """A Guardian started with no ``GUARDIAN_RUN_ID`` writes a genesis that names no run."""
    harness = harness_factory(run_id=None)
    (start,) = harness.run_start_records()
    assert start.run_id is None


# --------------------------------------------------------------------------------------------
# Idempotence across reopen
# --------------------------------------------------------------------------------------------


def test_a_restart_on_a_non_empty_chain_writes_no_second_run_start(tmp_path: Path) -> None:
    """Three starts on one chain, one genesis.

    Each harness built on the same root is a Guardian process started on the same per-run chain,
    which is exactly what a pod restart is. The first writes the genesis and decides one request;
    the second and third reopen a non-empty chain through ``AuditChainWriter.open`` and must append
    nothing at startup, so the record that follows continues at the recorded head instead of behind
    a second genesis. Each decision carries its own ADR-082 execution follow-up immediately behind
    it, which is why a chain with one decided request already holds three records, not two, and why
    the second decision lands at ``seq`` 3 rather than 2.
    """
    first = make_harness(tmp_path)
    first.submit(
        first.action_body(token=first.mint(), request_id="req-before-restart"),
        label="before restart",
    ).assert_permitted()
    before = [parsed.record for parsed in read_chain(first.chain_path)]
    assert len(before) == 3

    restarted = make_harness(tmp_path)
    assert restarted.chain_path == first.chain_path
    after = [parsed.record for parsed in read_chain(restarted.chain_path)]
    assert after == before, "the restart appended to the chain at startup"
    assert restarted.sink.writer.next_seq == 3
    assert restarted.sink.writer.head == first.sink.writer.head

    record = restarted.submit(
        restarted.action_body(token=restarted.mint(), request_id="req-after-restart"),
        label="after restart",
    ).assert_permitted()
    assert record.seq == 3

    make_harness(tmp_path)  # once more, with nothing asked in between
    chain = read_chain(first.chain_path)
    assert [parsed.seq for parsed in chain] == [0, 1, 2, 3, 4]
    assert [parsed.seq for parsed in run_start_records(chain)] == [0]
    assert verify_file(first.chain_path, use_seal=False).ok


def test_an_existing_empty_chain_file_still_gets_its_genesis(tmp_path: Path) -> None:
    """A zero-byte file at the chain path is an empty chain ("new or empty"), not a resumed one."""
    (tmp_path / "guardian_audit.jsonl").write_bytes(b"")
    harness = make_harness(tmp_path)
    chain = read_chain(harness.chain_path)
    assert [parsed.seq for parsed in chain] == [0]
    assert record_types.is_run_start(chain[0].record)


def test_the_sink_writes_no_run_start_onto_a_chain_that_has_begun(harness: GuardianHarness) -> None:
    """The position rule at the seam itself: a second genesis is a no-op, and nothing is written."""
    draft = RunStartDraft(
        ts=harness.clock.instant(),
        run_id=RUN_ID,
        guardian_mode=GuardianMode.G0_FULL,
        record_type=AUDIT_RECORD_TYPE_RUN_START,
        schema_version=AUDIT_RECORD_SCHEMA_VERSION,
    )
    before = harness.chain_path.read_bytes()
    assert harness.sink.record_run_start(draft) is None
    assert harness.chain_path.read_bytes() == before


def test_the_contract_refuses_a_run_start_anywhere_but_the_genesis(
    harness: GuardianHarness,
) -> None:
    """A ``RunStartRecord`` sits at seq 0 behind the all-zero sentinel, or it is refused."""
    (start,) = harness.run_start_records()
    moved = start.model_dump(mode="json")
    moved["seq"] = 1
    moved["prev_hash"] = start.hash
    with pytest.raises(ValidationError, match="genesis"):
        RunStartRecord.model_validate(moved)
    relinked = start.model_dump(mode="json")
    relinked["prev_hash"] = start.hash
    with pytest.raises(ValidationError, match="genesis"):
        RunStartRecord.model_validate(relinked)


# --------------------------------------------------------------------------------------------
# The verifier, replay and the sanitizer
# --------------------------------------------------------------------------------------------


def test_a_zero_action_chain_verifies_and_replays_no_attempt(
    harness: GuardianHarness, capsys: pytest.CaptureFixture[str]
) -> None:
    """The quarantined attempt's chain as it now exists: one genesis, verified, no attempt."""
    records = read_chain(harness.chain_path)
    report = verify_file(harness.chain_path, expected_head=harness.sink.writer.head)
    assert report.ok, [str(finding) for finding in report.findings]
    assert report.diagnosis == DIAGNOSIS_INTACT
    assert report.record_count == 1
    assert replay(records) == []
    assert set(replay_summary(replay(records)).values()) == {0}
    assert [parsed.seq for parsed in run_start_records(records)] == [0]

    exit_code = main([str(harness.chain_path), "--no-anchor", "--replay"])
    out = capsys.readouterr().out
    assert exit_code == 0, out
    assert "records=1 diagnosis=intact" in out
    assert "run-start at seq=0" in out
    assert "0 attempted action(s)" in out


def test_scripts_audit_verify_passes_a_chain_that_begins_with_run_start(
    harness: GuardianHarness,
) -> None:
    """The gate ``make audit-verify`` runs, over a chain whose first record is the genesis.

    Driven with the interpreter this suite runs under, so the gate cannot pick another Python and
    pass or fail for a reason that has nothing to do with the chain.
    """
    harness.submit(
        harness.action_body(token=harness.mint(), request_id="req-audit-verify"),
        label="one decision behind the genesis",
    ).assert_permitted()
    returncode, stdout, stderr = run_shell_script(
        AUDIT_VERIFY_SCRIPT,
        arguments=(str(harness.chain_path), "--replay"),
        environment_overrides={"PYTHON": sys.executable},
    )
    assert returncode == 0, f"{stdout}\n{stderr}"
    assert "audit-verify: PASS" in stdout, stdout
    # genesis + one decision + its ADR-082 execution follow-up.
    assert "1 chain(s), 3 record(s)" in stdout, stdout
    assert "run-start at seq=0" in stderr, stderr
    assert "1 attempted action(s)" in stderr, stderr


def test_the_pre_seal_sanitizer_finds_nothing_to_change_in_a_run_start_chain(
    harness: GuardianHarness,
) -> None:
    """The genesis is born clean like every record, so data-management section 5 stays a no-op."""
    harness.submit(
        harness.action_body(token=harness.mint(), request_id="req-run-start-scan"),
        label="one decision behind the genesis",
    ).assert_permitted()
    assert scan_chain_file(harness.chain_path) == []
    (start,) = harness.run_start_records()
    assert start.run_id == RUN_ID, "the scrub rewrote the genesis on its way into the chain"


# --------------------------------------------------------------------------------------------
# The run id on every record type (ADR-054, and the defect ADR-058 records)
# --------------------------------------------------------------------------------------------


def test_every_record_type_the_guardian_writes_carries_the_configured_run_id(
    harness: GuardianHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR-054's rule over every kind of record: the genesis, seven decision shapes, and their
    ADR-082 execution follow-ups.

    The refusals are the point. A body that never parsed and a fault inside adjudication used to be
    recorded with a null run id -- the pre-fix sealed bundle ADR-058 cites holds two such
    ``policy.request-malformed`` records -- and analysis rejects any Guardian record not carrying
    its bundle's run id. The run is this Guardian's configuration, never the body's, so stamping it
    records nothing the caller authored. That now has to hold for the execution follow-up too, since
    it also carries the run id (:class:`~guardian.app.models.ExecutionRecordDraft`), and this is the
    one test that walks every record type the Guardian writes rather than one kind at a time.
    """
    harness.engine.result = permit_result()
    harness.submit(
        harness.action_body(token=harness.mint(), request_id="req-run-permit"), label="permit"
    ).assert_permitted()

    harness.engine.result = deny_default_result()
    harness.submit(
        harness.action_body(token=harness.mint(), request_id="req-run-deny", verb="delete"),
        label="policy denial",
    ).assert_denied(ReasonCode.POLICY_DENY_DEFAULT)

    harness.submit(
        harness.action_body(
            token=harness.mint(issuer_id=UNREGISTERED_SUPERVISOR_ID), request_id="req-run-issuer"
        ),
        label="token refusal",
    ).assert_denied(ReasonCode.TOKEN_ISSUER_UNKNOWN)

    harness.submit(
        harness.action_body(
            token=harness.mint(), request_id="req-run-param", params={"api_key": "withheld-value"}
        ),
        label="credential-shaped param",
    ).assert_denied(ReasonCode.POLICY_PARAM_NAME_FORBIDDEN)

    harness.submit(
        b"{}",
        label="declared oversize",
        headers={"content-length": str(harness.mediator.max_request_bytes + 1)},
    ).assert_denied(ReasonCode.POLICY_REQUEST_OVERSIZE)

    harness.submit(b"{not json", label="malformed body").assert_denied(
        ReasonCode.POLICY_REQUEST_MALFORMED
    )

    def _defective_adjudication(*_: object, **__: object) -> None:
        raise RuntimeError("a defect inside adjudication, injected by this case")

    monkeypatch.setattr(mediation, "adjudicate", _defective_adjudication)
    harness.submit(
        harness.action_body(token=harness.mint(), request_id="req-run-fault"),
        label="guardian fault",
    ).assert_denied(ReasonCode.POLICY_GUARDIAN_FAULT)

    chain = read_chain(harness.chain_path)
    # The genesis, seven decisions, and one ADR-082 execution follow-up behind each decision.
    assert len(chain) == 15, "the genesis, seven decisions and seven execution follow-ups"
    unstamped = [
        (parsed.seq, parsed.record.get("record_type"), parsed.record.get("reason_code"))
        for parsed in chain
        if parsed.record.get("run_id") != RUN_ID
    ]
    assert unstamped == [], f"records not carrying the configured run id: {unstamped}"
    assert {parsed.record.get("record_type") for parsed in chain} == record_types.RECORD_TYPES
    decisions = [
        parsed
        for parsed in chain
        if parsed.record.get("record_type") == record_types.DECISION_RECORD_TYPE
    ]
    assert [parsed.record.get("reason_code") for parsed in decisions] == [
        ReasonCode.PERMIT_RULE_ALLOW.value,
        ReasonCode.POLICY_DENY_DEFAULT.value,
        ReasonCode.TOKEN_ISSUER_UNKNOWN.value,
        ReasonCode.POLICY_PARAM_NAME_FORBIDDEN.value,
        ReasonCode.POLICY_REQUEST_OVERSIZE.value,
        ReasonCode.POLICY_REQUEST_MALFORMED.value,
        ReasonCode.POLICY_GUARDIAN_FAULT.value,
    ]
