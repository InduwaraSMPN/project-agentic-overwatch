r"""The tamper suite: a chain that does not fail on tampering is not a chain.

``docs/milestones/M3-guardian.md``'s Verification line asks for it in one clause -- "tamper one
audit line -> verify detects break" -- and its Definition of done asks for the other half: "``make
audit-verify`` passes; replay reconstructs the full attempted-action history, denied actions and G1
denied-but-executed ones included. [T-12]". ``docs/plans/M3-implementation-plan.md`` expands both
into the cases below and adds the requirement that makes them worth running: each break must be
reported **at the correct ``seq``** rather than merely as "invalid". A verifier that says a file is
bad without saying where is a verifier that turns a forensic question into a re-derivation.

THE PAIR THAT IS THE POINT OF THE WHOLE MODULE
------------------------------------------------
``hash = SHA256(prev_hash || canonical_json(record_without_hash))`` detects in-place mutation,
deletion, insertion and reordering, because each breaks the link at a locatable position. It does
**not** detect tail truncation or a whole-chain rewrite: an attacker who can write the file can
recompute every hash forward from the cut, and the result is a perfectly valid chain that is shorter
or different. That is the boundary of an unsigned hash chain, and ADR-022 puts it in the record
rather than leaving it to be discovered at a viva.

The property that closes it already exists -- ``data-management.md`` section 1 puts the chain head
in ``seal.json`` -- so the two truncation cases are asserted **as a pair**: caught with the anchor,
missed without it. ADR-022 states the consequence plainly: "A suite that shows only the first half
would be evidence for a claim stronger than the one this ADR makes." Both halves are in
:func:`test_truncation_and_rewrite_are_caught_with_the_anchor_and_missed_without_it`, and the second
half deliberately asserts a *clean* verification result over a tampered file.

WHERE THE FIXTURES COME FROM
-----------------------------
``guardian/audit/fixtures/`` is a committed corpus built by ``guardian/audit/fixtures/build.py``,
which also re-derives it and compares byte for byte. The tests below read it and never rebuild it:
what is under test here is the verifier, and generating the tampered input from the same module that
verifies it would be a closed loop. The one thing this module does regenerate is a chain of its own,
in :func:`test_a_chain_this_guardian_wrote_verifies_and_replays`, because "the verifier accepts the
committed fixture" and "the verifier accepts what the Guardian actually writes" are two claims and
only the second is about the running system.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from guardian.audit.canonical import canonical_json_line  # noqa: E402
from guardian.audit.chain import (  # noqa: E402
    HASH_FIELD,
    PREV_HASH_FIELD,
    SIGNATURE_FIELD,
    AuditChainWriter,
    read_chain,
    record_hash,
)
from guardian.audit.record_types import is_run_start  # noqa: E402
from guardian.audit.verify import (  # noqa: E402
    DIAGNOSIS_DELETION,
    DIAGNOSIS_HEAD,
    DIAGNOSIS_INSERTION,
    DIAGNOSIS_INTACT,
    DIAGNOSIS_MUTATION,
    DIAGNOSIS_REORDER,
    GENESIS_MISMATCH,
    HEAD_MISMATCH,
    LINK_MISMATCH,
    OUTCOME_DENIED_BLOCKED,
    OUTCOME_DENIED_EXECUTED,
    OUTCOME_PERMITTED,
    RECORD_HASH_MISMATCH,
    SEQ_GAP,
    SEQ_REGRESSION,
    SIGNATURE_INVALID,
    Finding,
    read_seal_head,
    replay,
    replay_summary,
    verify_chain,
    verify_file,
    verify_signature,
)
from guardian.tests.harness import (  # noqa: E402
    GuardianHarness,
    deny_default_result,
    permit_result,
)

FIXTURES = REPO_ROOT / "guardian" / "audit" / "fixtures"
CLEAN = FIXTURES / "clean" / "guardian_audit.jsonl"
SEAL = FIXTURES / "clean" / "seal.json"
CHAIN_FILENAME = "guardian_audit.jsonl"

# One row per tamper class: the fixture directory, the one-word diagnosis the verifier must reach,
# the seq the first finding must name, and the finding kinds that must be present.
#
# The seq values are the load-bearing part. "Detected" is easy; detected at seq 3 rather than "the
# file is invalid" is what lets an incident be reconstructed around the break rather than abandoned
# at it. Each is the position the tamper actually occupies in the corpus, not a value copied from a
# passing run: field-mutation edits record 3, the re-hashed variant leaves record 3 self-consistent
# and breaks record 4's link back to it, record-deletion removes record 4 so the gap is reported at
# the seq that should have followed, and record-insertion forges a second record numbered 3.
TAMPER_CASES = (
    ("field-mutation", DIAGNOSIS_MUTATION, 3, {RECORD_HASH_MISMATCH}),
    ("field-mutation-rehashed", DIAGNOSIS_MUTATION, 4, {LINK_MISMATCH}),
    ("record-deletion", DIAGNOSIS_DELETION, 5, {LINK_MISMATCH, SEQ_GAP}),
    ("record-insertion", DIAGNOSIS_INSERTION, 3, {LINK_MISMATCH, SEQ_REGRESSION}),
    ("reordering", DIAGNOSIS_REORDER, 3, {LINK_MISMATCH, SEQ_GAP, SEQ_REGRESSION}),
)

TRUNCATION_CASES = (("tail-truncation", 6), ("whole-chain-rewrite", 3))


@pytest.fixture(scope="module")
def anchor() -> str:
    """The clean chain's recorded head, read from the fixture's ``seal.json``."""
    assert SEAL.is_file(), f"{SEAL} is missing; the truncation pair cannot be run without an anchor"
    return read_seal_head(SEAL)


def _kinds(findings: tuple[Finding, ...]) -> set[str]:
    return {finding.kind for finding in findings}


def test_the_clean_chain_verifies(anchor: str) -> None:
    """The committed clean chain verifies, with the anchor and without it.

    The control, and it has to come first: every tamper case below is a claim that the verifier can
    tell a broken chain from an intact one, and half of that claim is that it accepts the intact
    one. A verifier that failed everything would pass every other test in this module.
    """
    anchored = verify_file(CLEAN, expected_head=anchor)
    assert anchored.ok, [str(finding) for finding in anchored.findings]
    assert anchored.diagnosis == DIAGNOSIS_INTACT
    assert anchored.anchored

    unanchored = verify_file(CLEAN, use_seal=False)
    assert unanchored.ok and unanchored.diagnosis == DIAGNOSIS_INTACT
    assert not unanchored.anchored


@pytest.mark.parametrize(("name", "diagnosis", "seq", "kinds"), TAMPER_CASES)
def test_structural_tampering_is_detected_at_the_correct_seq(
    name: str, diagnosis: str, seq: int, kinds: set[str], anchor: str
) -> None:
    """Mutation, deletion, insertion and reordering: each detected, each located.

    Three assertions per class and not one. That it fails at all; that the verifier reaches the
    right one-word *diagnosis*, so an operator is told what happened rather than that it did; and
    that the first finding names the right ``seq``, so the break can be located in a file that may
    hold a whole campaign's decisions.

    The re-hashed mutation is the case worth pausing on. An attacker who edits a record and then
    recomputes that record's own hash produces a record that is internally consistent -- so the
    detection has to come from the *next* record's ``prev_hash``, one link later. Without it a
    verifier that only checked each record against its own stored hash would pass the plain mutation
    case and miss the competent version of the same attack.
    """
    path = FIXTURES / "tampered" / name / CHAIN_FILENAME
    assert path.is_file(), f"{path} is missing from the committed corpus"

    report = verify_file(path, expected_head=anchor)
    assert not report.ok, f"{name} was not detected at all"
    assert report.diagnosis == diagnosis, (
        f"{name}: diagnosed {report.diagnosis!r}, expected {diagnosis!r}"
    )
    assert report.first_break_seq == seq, (
        f"{name}: first break reported at seq {report.first_break_seq}, expected {seq}. A verifier "
        "that detects tampering without locating it turns a forensic question into a re-derivation"
    )
    assert kinds <= _kinds(report.findings), (
        f"{name}: findings {sorted(_kinds(report.findings))} do not cover {sorted(kinds)}"
    )

    # The structural classes are detected by the chain rule itself, so the anchor is irrelevant to
    # them -- and saying so is what separates them from the two truncation classes below.
    without_anchor = verify_file(path, use_seal=False)
    assert not without_anchor.ok, (
        f"{name} is only detected with a head anchor. Mutation, deletion, insertion and reordering "
        "each break a link and must be caught by the chain alone"
    )
    assert without_anchor.first_break_seq == seq


@pytest.mark.parametrize(("name", "seq"), TRUNCATION_CASES)
def test_truncation_and_rewrite_are_caught_with_the_anchor_and_missed_without_it(
    name: str, seq: int, anchor: str
) -> None:
    """The pair ADR-022 requires: caught with the recorded head, and demonstrably missed without it.

    The second assertion is the unusual one -- it asserts that a **tampered file verifies clean**.
    That is not a defect being papered over; it is the honest boundary of an unsigned hash chain
    written down as a test. An attacker who can write the file can recompute every hash forward from
    a cut, so what is left is a shorter chain that is internally perfect. Nothing inside the file
    can reveal that, and only something recorded outside it can: ``seal.json``'s head.

    Claiming detection without the anchor would be an unearned security claim, which is the class of
    claim this whole milestone exists to avoid making.
    """
    path = FIXTURES / "tampered" / name / CHAIN_FILENAME
    assert path.is_file(), f"{path} is missing from the committed corpus"

    caught = verify_file(path, expected_head=anchor)
    assert not caught.ok, f"{name} was not caught even with the head anchor"
    assert caught.diagnosis == DIAGNOSIS_HEAD
    assert HEAD_MISMATCH in _kinds(caught.findings)
    assert caught.first_break_seq == seq

    missed = verify_file(path, use_seal=False)
    assert missed.ok, (
        f"{name} was detected without a head anchor. If that is now true the chain has gained a "
        "property it did not have -- a signature, a monotonic counter, an external witness -- and "
        "ADR-022's stated boundary, and Chapter 5's threats section with it, needs rewriting"
    )
    assert missed.diagnosis == DIAGNOSIS_INTACT
    assert not missed.anchored


def test_truncate_and_rehash_passes_the_v1_verifier_and_fails_the_signed_one(
    tmp_path: Path,
) -> None:
    """ADR-130: the rewrite the unsigned chain cannot detect is exactly what the signature catches.

    The pair above shows an anchor is the *only* thing that catches a whole-chain rewrite in an
    unsigned chain. The Ed25519 signature is the second, independent property that catches it
    without
    one: a forger who rewrites the file and recomputes every hash forward leaves each stored
    signature
    covering the hash it was made over, not the new one, so ``verify_signature`` rejects every
    rewritten
    record while ``verify_chain`` -- the v1 verifier -- still accepts the internally consistent
    result.

    The key is ephemeral: the operator's real signing key is out of band (rule 10), and the tests
    generate their own, which is all that is needed to prove the mechanism.
    """
    key = Ed25519PrivateKey.generate()
    path = tmp_path / CHAIN_FILENAME
    writer = AuditChainWriter.open(path, max_justification_chars=2048, signing_key=key)
    for index in range(4):
        writer.append({"n": index, "note": f"record {index}"})

    # Rewrite the body of the record at seq 2 and recompute every hash from there to the tail,
    # leaving
    # the signatures untouched -- the whole-chain rewrite an unsigned chain cannot detect.
    records = [parsed.record for parsed in read_chain(path)]
    for record in records:
        if record.get("seq") == 2:
            record["note"] = "MUTATED after signing"
    head = records[0][PREV_HASH_FIELD]
    for record in records:
        if record.get("seq") is not None and record["seq"] >= 2:
            record[PREV_HASH_FIELD] = head
            body = {k: v for k, v in record.items() if k not in (HASH_FIELD, SIGNATURE_FIELD)}
            record[HASH_FIELD] = record_hash(head, body)
        head = record[HASH_FIELD]
    path.write_bytes(b"".join(canonical_json_line(record) for record in records))

    reparsed = read_chain(path)
    # The v1 verifier is satisfied without an anchor -- the boundary test_truncation... documents.
    assert verify_chain(reparsed).ok, (
        "the rewrite is not internally consistent, so it proves nothing"
    )
    # The signed verifier is not.
    findings = verify_signature(reparsed, key.public_key())
    assert findings, "the whole-chain rewrite passed the signature check"
    assert {finding.kind for finding in findings} == {SIGNATURE_INVALID}
    assert findings[0].seq == 2


def test_an_empty_chain_is_refused_rather_than_passed(tmp_path: Path) -> None:
    """Verifying nothing is a failure, not a success.

    ``guardian/audit/verify.py`` gives the reason in its own message and it is worth keeping under
    test: "a verification that succeeds over nothing reads, in a log, exactly like one that
    succeeded over everything". At M7's daily QA that difference is the difference between a
    healthy campaign and a Guardian that has not written a record in a week.
    """
    empty = tmp_path / CHAIN_FILENAME
    empty.write_bytes(b"")
    report = verify_file(empty, use_seal=False)
    assert not report.ok
    assert report.record_count == 0


def test_a_genesis_record_that_does_not_start_the_chain_is_detected(tmp_path: Path) -> None:
    """A file beginning at a non-zero ``seq`` is a chain with its front removed.

    The deletion case aimed at the one position the link check cannot see: there is no preceding
    record to disagree with, so what catches it is the genesis rule -- the first record of a chain
    carries the all-zero sentinel and a ``seq`` of zero, which makes a chain self-identifying about
    where it begins.
    """
    records = read_chain(CLEAN)
    beheaded = tmp_path / CHAIN_FILENAME
    lines = CLEAN.read_bytes().decode("utf-8").splitlines()
    beheaded.write_bytes(("\n".join(lines[2:]) + "\n").encode("utf-8"))

    report = verify_file(beheaded, use_seal=False)
    assert not report.ok, "a chain missing its first two records verified clean"
    assert GENESIS_MISMATCH in _kinds(report.findings)
    assert report.first_break_seq == 2
    assert len(records) > 2


def test_a_chain_this_guardian_wrote_verifies_and_replays(harness: GuardianHarness) -> None:
    """T-12 over a live chain: the Guardian writes, the verifier accepts, the replay reconstructs.

    The committed fixtures prove the verifier can read a chain of the right shape. This proves the
    Guardian writes one -- which is a different claim, and the one that matters for a sealed run
    bundle. The sequence deliberately includes a permit, a denial that was blocked, a denial that
    was executed under ``G1-LOGONLY``, and a body that never parsed, because the Definition of done
    names the full attempted-action history "denied actions and G1 denied-but-executed ones
    included" and a replay that dropped either would still look complete.
    """
    from guardian.app.models import GuardianMode, ReasonCode

    harness.engine.result = permit_result()
    harness.submit(
        harness.action_body(token=harness.mint(), request_id="req-t12-1"), label="permit"
    ).assert_permitted()

    harness.engine.result = deny_default_result()
    harness.submit(
        harness.action_body(
            token=harness.mint(), request_id="req-t12-2", verb="delete", name="paymentservice"
        ),
        label="blocked denial",
    ).assert_denied(ReasonCode.POLICY_DENY_DEFAULT)

    harness.submit(b"{not json", label="unparsed body").assert_denied(
        ReasonCode.POLICY_REQUEST_MALFORMED
    )

    report = verify_chain(
        read_chain(harness.chain_path),
        expected_head=harness.sink.writer.head,
        path=str(harness.chain_path),
        anchor_source="writer-head",
    )
    assert report.ok, [str(finding) for finding in report.findings]
    assert report.diagnosis == DIAGNOSIS_INTACT
    # The run-start genesis (ADR-058), three decisions, and one ADR-082 execution follow-up behind
    # each decision. The genesis is hash-chained like the rest, which is why the report above
    # covers it, and it is not an attempt, which is why the replay below starts at seq 1; the
    # follow-ups are likewise hash-chained but are not attempts either, which is why each
    # decision's seq is two apart from the last rather than one.
    assert report.record_count == 7
    chain = read_chain(harness.chain_path)
    assert is_run_start(chain[0].record)
    assert chain[0].seq == 0

    attempts = replay(chain)
    assert [attempt.seq for attempt in attempts] == [1, 3, 5]
    assert [attempt.outcome for attempt in attempts] == [
        OUTCOME_PERMITTED,
        OUTCOME_DENIED_BLOCKED,
        OUTCOME_DENIED_BLOCKED,
    ]
    assert attempts[0].target() == "get pods in boutique"
    assert attempts[1].target() == "delete pods/paymentservice in boutique"
    assert attempts[2].verb is None, "a body that never parsed has no action to reconstruct"
    assert all(attempt.guardian_mode == GuardianMode.G0_FULL.value for attempt in attempts)


def test_a_g1_chain_replays_denied_but_executed_actions(harness_factory: object) -> None:
    """The outcome that only exists under ``G1-LOGONLY``, reconstructed from the chain alone.

    ``denied-but-executed`` is the pair that makes a G1 record distinguishable from a G0 deny, and
    conflict M3-C6 records that without it the G0-versus-G1 contrast is uncomputable from the very
    artefact meant to evidence it. This is the replay reading it back out -- which is what
    ``analysis/`` will do months later with nothing but the sealed bundle.
    """
    from guardian.app.models import GuardianMode, ReasonCode

    build = harness_factory
    harness = build(mode=GuardianMode.G1_LOGONLY)  # type: ignore[operator]
    harness.engine.result = deny_default_result()
    harness.submit(
        harness.action_body(token=harness.mint(), request_id="req-g1-replay", verb="delete"),
        label="G1 denied-but-executed",
    ).assert_denied(ReasonCode.POLICY_DENY_DEFAULT)

    attempts = replay(read_chain(harness.chain_path))
    assert [attempt.outcome for attempt in attempts] == [OUTCOME_DENIED_EXECUTED]
    assert replay_summary(attempts)[OUTCOME_DENIED_EXECUTED] == 1
    assert replay_summary(attempts)[OUTCOME_DENIED_BLOCKED] == 0
    assert attempts[0].guardian_mode == GuardianMode.G1_LOGONLY.value


def test_a_planted_secret_is_scrubbed_before_hashing(harness: GuardianHarness) -> None:
    """A credential-shaped string in a justification never reaches the chain unredacted.

    Conflict M3-C5's resolution, checked on a chain this Guardian just wrote.
    ``data-management.md`` section 5 sanitises a bundle before seal and architecture section 3
    hashes the record, so any post-append redaction would break every link after it -- meaning
    ``make audit-verify`` would fail on every sealed bundle *on correct behaviour*. The only
    resolution that keeps both documents true is that the record never carries the secret, and the
    real assertion is not that the sanitizer works but that on this file it has nothing to do.
    """
    from guardian.audit.chain import scan_chain_file

    planted = (
        "the runbook said to export api_key=NOT-A-REAL-KEY-SYNTHETIC-SUITE-VALUE before scaling"
    )
    harness.engine.result = permit_result()
    outcome = harness.submit(
        harness.action_body(token=harness.mint(), request_id="req-scrub", justification=planted),
        label="planted credential-shaped justification",
    )
    record = outcome.assert_permitted()

    text = harness.chain_path.read_bytes().decode("utf-8")
    assert "NOT-A-REAL-KEY-SYNTHETIC-SUITE-VALUE" not in text, (
        "the planted value survived into the chain; the scrub runs before the hash, so a record "
        "needing redaction afterwards would break every link after it"
    )
    assert "[REDACTED-CREDENTIAL-ASSIGNMENT]" in text, (
        "nothing marks the redaction, so the record does not say that something was removed"
    )
    assert scan_chain_file(harness.chain_path) == [], (
        "the pre-seal sanitizer would still find something to change in this chain"
    )
    assert record.action is not None
    assert verify_chain(read_chain(harness.chain_path), expected_head=harness.sink.writer.head).ok
