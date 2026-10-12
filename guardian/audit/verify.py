r"""Verification and replay of a Guardian audit chain, and the command line both are reached by.

WHAT THIS DETECTS, AND WHAT IT HONESTLY DOES NOT
--------------------------------------------------
``hash = SHA256(prev_hash || canonical_json(record_without_hash))`` detects **in-place mutation,
record deletion, record insertion and reordering**, because each breaks a check at a locatable
``seq``. It does **not** detect **tail truncation** or a **whole-chain rewrite**: an attacker who
can write the file recomputes every hash forward from the cut, and the result is a chain that
verifies perfectly and is not the chain that was written. That is the boundary of an *unsigned*
hash chain and no amount of care in the canonicalisation rule moves it. ADR-022 records it, and
this module implements both halves of it rather than only the flattering one.

The property that closes the gap already exists: ``docs/protocols/data-management.md`` section 1
puts the chain head in ``seal.json`` beside the bundle content hashes. So verification takes an
**optional expected head**, and both behaviours are reachable and testable -- truncation is caught
*with* the anchor and demonstrably missed *without* it. The negative half of that pair is the one
that matters. A suite showing only the anchor working leaves a reader to assume the chain detects
truncation on its own, which is exactly the unearned security claim M3 exists not to make.

ONE TAMPERING EVENT PRODUCES ONE OR TWO FINDINGS, NOT A CASCADE
-----------------------------------------------------------------
This is a property of the design rather than of the reporting, and it is what makes "reported at
the correct ``seq``" a meaningful claim instead of a filter over noise:

* **Field mutation** with the stored ``hash`` left alone breaks only that record's self-check, at
  its own ``seq``. Its successor's ``prev_hash`` still equals the untouched stored ``hash``, so
  nothing downstream moves.
* **Field mutation with the hash recomputed** leaves the record self-consistent and breaks exactly
  one link, at the successor's ``seq``, naming the predecessor as the cause.
* **Deletion** of the record at ``seq = k`` leaves a ``seq`` gap and one broken link, both pointing
  at ``k``. Every later link is still sound because the relative order was preserved, and
  :func:`guardian.audit.chain.walk_chain` forms its ``seq`` expectation from the *preceding
  declared* ``seq`` rather than from the file position, so the gap is reported once instead of
  re-reported on every subsequent record.
* **Insertion** of a record spliced between ``k-1`` and ``k`` -- even one the attacker made
  internally self-consistent -- makes the following record's ``seq`` regress and its link fail,
  both at ``k``.
* **Reordering** produces a permutation of the same ``seq`` set in the wrong order, which is
  recognised as such rather than reported as the deletion-plus-insertion it superficially
  resembles.

:func:`verify_chain` therefore returns two layers. ``findings`` is the low-level list, each item
carrying the ``seq``, the one-based file ``line`` and what specifically failed. ``diagnosis`` is a
single classification derived from the findings together with the shape of the declared ``seq``
sequence, so a reader gets "deletion at seq 3" rather than three link errors to interpret.

REPLAY IS THE EVIDENCE FOR TRACEABILITY ROW T-12
---------------------------------------------------
Row T-12 asks for a hash-chained audit that is *replayable*, and the Definition of done asks that
"replay reconstructs the attempted-action history". :func:`replay` does that: every decision record
in the chain becomes one attempt, **including denied ones**, because a denial the history omits is
a denial the evaluation cannot see -- ``docs/protocols/security-policy.md`` section 1.4 and the M3
plan's threat-model corollary both turn on that point.

The one record that is not an attempt is the run-start genesis ADR-058 puts at ``seq`` zero. It
says a Guardian started for this run, and nothing was attempted, permitted, denied or blocked by it,
so :func:`replay` leaves it out -- recognised by its explicit ``record_type``, through
``guardian/audit/record_types.py`` -- and the command line reports it on a line of its own.
Verification is untouched by the distinction: the chain rule covers a run-start exactly as it covers
a decision, so a chain that begins with one verifies like any other.

The outcome of each attempt is classified from two fields rather than one, which is conflict M3-C6:
``decision`` is what policy said and the enforcement field is what the Guardian did. Under
``G0-FULL`` those agree. Under ``G1-LOGONLY`` the Guardian "logs but does not block", so a record
reads ``decision = deny`` and enforcement ``executed`` -- the **denied-but-executed** case, which is
what ``evaluation-protocol.md`` section 3's injection-success and policy-compliance measures are
computed from and what makes the G0-versus-G1 contrast computable at all. A single-field record
would make a G1 denial indistinguishable from a G0 one.

This module reads both fields defensively with ``.get``, because ``02-architecture.md`` section 3's
base field list predates the amendment that adds them and a chain written against the older shape
must still replay rather than crash.

THE HEAD ANCHOR AND ``seal.json``
-----------------------------------
``data-management.md`` section 1 describes ``seal.json`` as "bundle content hashes + chain head +
sealed_at" and fixes no key names, so this module reads :data:`SEAL_HEAD_KEY` and treats a
``seal.json`` that carries no such key as a named error rather than as an absent anchor. That is a
**proposed** contract for M6's sealer, not one found in a protocol, and it is flagged as such here
so the next reader does not mistake it for a citation. Nothing depends on it: ``--head`` supplies
the anchor directly, and ``--no-anchor`` suppresses the lookup, which is how the pair of truncation
tests is driven.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from guardian.audit.canonical import CANONICAL_JSON_RULE_ID
from guardian.audit.chain import (
    GENESIS_PREV_HASH,
    SIGNATURE_FIELD,
    LinkCheck,
    ParsedRecord,
    is_chain_hash,
    read_chain,
    walk_chain,
)
from guardian.audit.outcome import bundle_status_by_seq
from guardian.audit.outcome import execution_status as resolve_execution_status
from guardian.audit.record_types import is_execution, is_run_start

__all__ = [
    "SEAL_HEAD_KEY",
    "SIGNATURE_INVALID",
    "Attempt",
    "ChainReport",
    "Finding",
    "read_seal_head",
    "replay",
    "replay_summary",
    "run_start_records",
    "verify_chain",
    "verify_file",
    "verify_signature",
]

# The key this verifier reads a chain head from. See the module docstring: a proposal for M6's
# sealer rather than a protocol citation, because data-management.md section 1 names the contents
# of seal.json and not its schema.
SEAL_HEAD_KEY: Final = "audit_chain_head"

SEAL_FILENAME: Final = "seal.json"
CHAIN_FILENAME: Final = "guardian_audit.jsonl"

# Finding kinds. Named constants rather than free text so that a report is greppable and a test can
# assert on a kind without matching on a sentence.
MALFORMED_RECORD: Final = "malformed-record"
RECORD_HASH_MISMATCH: Final = "record-hash-mismatch"
LINK_MISMATCH: Final = "link-mismatch"
GENESIS_MISMATCH: Final = "genesis-prev-hash-mismatch"
SEQ_START: Final = "seq-does-not-start-at-zero"
SEQ_GAP: Final = "seq-gap"
SEQ_REGRESSION: Final = "seq-regression"
HEAD_MISMATCH: Final = "head-mismatch"
EMPTY_CHAIN: Final = "empty-chain"

# ADR-130: a record whose Ed25519 signature is absent or does not verify against its hash under the
# operator's public key. This is what :func:`verify_signature` adds on top of the hash-chain checks
# above -- the property that closes the whole-chain-rewrite gap ``verify_chain`` cannot, because a
# forger who rewrites the file and recomputes every hash cannot recompute a signature over a key it
# does not hold.
SIGNATURE_INVALID: Final = "signature-invalid"

# Diagnoses. `head-mismatch` deliberately does not claim to know whether the file was truncated or
# rewritten: from the file alone the two are indistinguishable, and saying so is the point.
DIAGNOSIS_INTACT: Final = "intact"
DIAGNOSIS_EMPTY: Final = "empty"
DIAGNOSIS_MALFORMED: Final = "malformed"
DIAGNOSIS_MUTATION: Final = "mutation"
DIAGNOSIS_DELETION: Final = "deletion"
DIAGNOSIS_INSERTION: Final = "insertion"
DIAGNOSIS_REORDER: Final = "reorder"
DIAGNOSIS_HEAD: Final = "truncation-or-rewrite"
DIAGNOSIS_MIXED: Final = "mixed"


@dataclass(frozen=True)
class Finding:
    """One thing wrong with a chain, located by ``seq`` and by one-based file ``line``.

    Both coordinates are carried because they are not the same number and the reader needs each for
    a different job: ``seq`` is what the chain and every later report speak in, and ``line`` is what
    an editor and a ``sed -n`` speak in. ``seq`` is ``None`` only when the record was too malformed
    to carry one.
    """

    kind: str
    seq: int | None
    line: int
    detail: str

    def __str__(self) -> str:
        where = f"seq={self.seq}" if self.seq is not None else "seq=?"
        return f"{where} line={self.line} {self.kind}: {self.detail}"


@dataclass(frozen=True)
class ChainReport:
    """The result of verifying one chain file: the findings, one diagnosis, and the anchor status.

    ``anchored`` is reported separately from ``expected_head`` so a transcript records *that* the
    run was unanchored, not merely that no mismatch was found. An unanchored pass and an anchored
    pass are different claims and a log that conflated them would be the one place this module's
    honesty about its boundary could be lost.
    """

    path: str
    record_count: int
    findings: tuple[Finding, ...]
    diagnosis: str
    head: str | None
    expected_head: str | None
    anchor_source: str
    rule_id: str = CANONICAL_JSON_RULE_ID

    @property
    def ok(self) -> bool:
        return not self.findings

    @property
    def anchored(self) -> bool:
        return self.expected_head is not None

    @property
    def first_break_seq(self) -> int | None:
        for finding in self.findings:
            if finding.seq is not None:
                return finding.seq
        return None


def _finding_for_malformed(parsed: ParsedRecord) -> Finding:
    return Finding(MALFORMED_RECORD, parsed.seq, parsed.line, str(parsed.defect))


def _findings_for(check: LinkCheck) -> list[Finding]:
    """Every finding one record contributes, in decreasing order of diagnostic weight."""
    parsed = check.parsed
    if parsed.defect is not None:
        return [_finding_for_malformed(parsed)]

    findings: list[Finding] = []
    if not check.hash_ok:
        findings.append(
            Finding(
                RECORD_HASH_MISMATCH,
                parsed.seq,
                parsed.line,
                f"the record hashes to {check.computed_hash} but stores "
                f"{parsed.stored_hash}; its content was altered after it was written",
            )
        )
    if check.link_ok is False:
        kind = GENESIS_MISMATCH if check.index == 0 else LINK_MISMATCH
        detail = (
            f"prev_hash is {parsed.prev_hash} but the first record of a chain must carry the "
            f"genesis value {GENESIS_PREV_HASH}"
            if check.index == 0
            else f"prev_hash is {parsed.prev_hash} but the preceding record hashes to "
            f"{check.expected_prev_hash}; a record was removed, inserted or moved here, or the "
            "preceding record was altered and re-hashed"
        )
        findings.append(Finding(kind, parsed.seq, parsed.line, detail))
    if check.seq_ok is False and parsed.seq is not None and check.expected_seq is not None:
        if check.index == 0:
            findings.append(
                Finding(
                    SEQ_START,
                    parsed.seq,
                    parsed.line,
                    f"the chain begins at seq {parsed.seq}; a complete chain begins at 0, so "
                    f"{parsed.seq} record(s) are missing from the front",
                )
            )
        elif parsed.seq > check.expected_seq:
            missing = parsed.seq - check.expected_seq
            last = parsed.seq - 1
            span = str(check.expected_seq) if missing == 1 else f"{check.expected_seq}..{last}"
            findings.append(
                Finding(
                    SEQ_GAP,
                    check.expected_seq,
                    parsed.line,
                    f"seq {span} is absent: {missing} record(s) were deleted between line "
                    f"{parsed.line - 1} and line {parsed.line}",
                )
            )
        else:
            findings.append(
                Finding(
                    SEQ_REGRESSION,
                    parsed.seq,
                    parsed.line,
                    f"seq {parsed.seq} follows seq {check.expected_seq - 1}; the chain does not "
                    "increase here, which is a record inserted or two records exchanged",
                )
            )
    return findings


def _diagnose(records: Sequence[ParsedRecord], findings: Sequence[Finding]) -> str:
    """Classify a finding list into one word, using the shape of the declared seq sequence.

    Deterministic and total: every input maps to exactly one of the DIAGNOSIS_* constants, and the
    order of the tests below is the classification rule. It is written as a cascade rather than as
    a table because the categories genuinely overlap in their low-level symptoms -- a reorder shows
    both a gap and a regression -- and the cascade is where the precedence is stated.
    """
    if not records:
        return DIAGNOSIS_EMPTY
    kinds = {finding.kind for finding in findings}
    if MALFORMED_RECORD in kinds:
        return DIAGNOSIS_MALFORMED
    structural = kinds - {HEAD_MISMATCH}
    if not structural:
        return DIAGNOSIS_HEAD if HEAD_MISMATCH in kinds else DIAGNOSIS_INTACT

    declared = [record.seq for record in records]
    if all(seq is not None for seq in declared):
        numbers = [int(seq) for seq in declared if seq is not None]
        if sorted(numbers) == list(range(len(numbers))) and numbers != sorted(numbers):
            return DIAGNOSIS_REORDER
        if len(set(numbers)) != len(numbers):
            return DIAGNOSIS_INSERTION
    if SEQ_GAP in kinds or SEQ_START in kinds:
        return DIAGNOSIS_DELETION
    if SEQ_REGRESSION in kinds:
        return DIAGNOSIS_INSERTION
    if kinds & {RECORD_HASH_MISMATCH, LINK_MISMATCH, GENESIS_MISMATCH}:
        return DIAGNOSIS_MUTATION
    return DIAGNOSIS_MIXED


def verify_chain(
    records: Sequence[ParsedRecord],
    *,
    expected_head: str | None = None,
    path: str = "<records>",
    anchor_source: str = "none",
) -> ChainReport:
    """Verify parsed records and return a report. Never raises on tampered input -- it reports it.

    ``expected_head`` is the anchor. Supplying it is what turns tail truncation and whole-chain
    rewrite from undetectable into detected; withholding it is a legitimate mode and the report
    says which one ran.
    """
    findings: list[Finding] = []
    if not records:
        findings.append(
            Finding(
                EMPTY_CHAIN,
                None,
                0,
                f"{path} holds no records. An empty chain is refused rather than passed: a "
                "verification that succeeds over nothing reads, in a log, exactly like one that "
                "succeeded over everything.",
            )
        )
        return ChainReport(
            path, 0, tuple(findings), DIAGNOSIS_EMPTY, None, expected_head, anchor_source
        )

    for check in walk_chain(list(records)):
        findings.extend(_findings_for(check))

    head = records[-1].stored_hash
    if expected_head is not None and head != expected_head:
        findings.append(
            Finding(
                HEAD_MISMATCH,
                records[-1].seq,
                records[-1].line,
                f"the chain ends at {head} but the recorded head is {expected_head}. When the "
                "records themselves verify, this is tail truncation or a whole-chain rewrite -- "
                "an unsigned chain cannot tell those apart, and without this anchor it detects "
                "neither.",
            )
        )

    return ChainReport(
        path=path,
        record_count=len(records),
        findings=tuple(findings),
        diagnosis=_diagnose(records, findings),
        head=head,
        expected_head=expected_head,
        anchor_source=anchor_source,
    )


def read_seal_head(seal_path: Path) -> str:
    """Read the chain head from a ``seal.json``. Raises when the file cannot supply one.

    A ``seal.json`` that exists but carries no usable head is an error rather than a silently
    absent anchor, because "no anchor" and "an anchor I could not read" are different situations
    and only one of them should pass quietly.
    """
    try:
        loaded = json.loads(seal_path.read_bytes().decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"{seal_path}: cannot be read as JSON ({exc})") from exc
    if not isinstance(loaded, dict) or SEAL_HEAD_KEY not in loaded:
        raise ValueError(
            f"{seal_path}: carries no {SEAL_HEAD_KEY!r}. That key is this verifier's proposed "
            "contract for M6's sealer; pass --head explicitly, or --no-anchor to verify without "
            "one and accept that truncation will not be detected."
        )
    head = loaded[SEAL_HEAD_KEY]
    if not is_chain_hash(head):
        raise ValueError(f"{seal_path}: {SEAL_HEAD_KEY} is not 64 lowercase hex characters")
    return str(head)


def verify_file(
    path: Path,
    *,
    expected_head: str | None = None,
    use_seal: bool = True,
) -> ChainReport:
    """Verify one chain file, resolving the anchor from ``--head``, then ``seal.json``, then none.

    The precedence is deliberate. An explicitly supplied head always wins, because that is how the
    ``with anchor`` half of the truncation test pair is driven against a fixture whose sibling
    ``seal.json`` may not exist. ``use_seal=False`` is the ``without anchor`` half.
    """
    path = Path(path)
    anchor_source = "none"
    if expected_head is not None:
        anchor_source = "explicit"
    elif use_seal:
        seal_path = path.parent / SEAL_FILENAME
        if seal_path.is_file():
            expected_head = read_seal_head(seal_path)
            anchor_source = f"{SEAL_FILENAME}"
    return verify_chain(
        read_chain(path),
        expected_head=expected_head,
        path=str(path),
        anchor_source=anchor_source,
    )


# --- signatures (ADR-130) ----------------------------------------------------------------------


def verify_signature(records: Sequence[ParsedRecord], public_key: Any) -> tuple[Finding, ...]:
    """Verify every record's Ed25519 signature against its hash, returning a finding per failure.

    This is the property an unsigned hash chain cannot have, and the reason it is a *separate*
    function
    rather than a branch of :func:`verify_chain`. ``verify_chain`` proves the file is an internally
    consistent chain; a forger who can write the file recomputes every hash forward and produces a
    chain that is internally consistent and is not the one that was written -- tail truncation and
    whole-chain rewrite, which ``verify_chain`` catches only with the ``seal.json`` anchor. A
    signature
    over each record's hash closes it a second, independent way: the forger would have to re-sign
    every
    rewritten record with the operator's private key, which it does not hold. So a
    truncate-and-rehash
    that ``verify_chain`` accepts without the anchor still fails here.

    A record is a :data:`SIGNATURE_INVALID` finding when it carries no signature (an unsigned record
    cannot be told from a rewritten one), when the signature is not hexadecimal, or when
    ``public_key.verify`` rejects it. ``public_key`` is typed ``Any`` and its exception is imported
    lazily so this module -- like the rest of ``guardian/audit/`` -- imports no cryptography library
    at
    module load and stays usable on a host without one (ADR-022); the key is
    :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey`, whose ``verify``
    takes
    ``(signature, data)`` and raises on a bad signature. The data signed is the 64 ASCII hex
      characters
    of ``hash``, exactly what :meth:`guardian.audit.chain.AuditChainWriter.append` signs.

    Malformed records are skipped, not guessed at, on :func:`verify_chain`'s rule: a record that
    failed
    its own parse is not evidence of anything, including of a missing signature.
    """
    from cryptography.exceptions import InvalidSignature

    findings: list[Finding] = []
    for parsed in records:
        if parsed.defect is not None:
            continue
        signature = parsed.record.get(SIGNATURE_FIELD)
        stored_hash = parsed.stored_hash
        if not isinstance(signature, str) or not signature or stored_hash is None:
            findings.append(
                Finding(
                    SIGNATURE_INVALID,
                    parsed.seq,
                    parsed.line,
                    "the record carries no verifiable signature; an unsigned record cannot be "
                    "distinguished from one a rewrite stripped, so it does not pass a signed-chain "
                    "verification",
                )
            )
            continue
        try:
            raw = bytes.fromhex(signature)
        except ValueError:
            findings.append(
                Finding(
                    SIGNATURE_INVALID, parsed.seq, parsed.line, "the signature is not hexadecimal"
                )
            )
            continue
        try:
            public_key.verify(raw, stored_hash.encode("ascii"))
        except InvalidSignature:
            findings.append(
                Finding(
                    SIGNATURE_INVALID,
                    parsed.seq,
                    parsed.line,
                    "the signature does not verify against the record hash under this key; the "
                    "record was rewritten after signing, or signed by a different key",
                )
            )
    return tuple(findings)


# --- replay -----------------------------------------------------------------------------------

OUTCOME_PERMITTED: Final = "permitted-and-executed"
OUTCOME_DENIED_BLOCKED: Final = "denied-and-blocked"
OUTCOME_DENIED_EXECUTED: Final = "denied-but-executed"
OUTCOME_PERMITTED_BLOCKED: Final = "permitted-but-not-executed"
OUTCOME_UNCLASSIFIED: Final = "unclassified"


@dataclass(frozen=True)
class Attempt:
    """One attempted action, reconstructed from one AuditRecord.

    Every record becomes an attempt, denials included. ``outcome`` is derived from ``decision`` and
    ``enforcement`` together rather than from ``decision`` alone; see the module docstring for why
    one field cannot express what G1-LOGONLY does.

    ``execution_status`` is the ADR-082 reading, over and above ``outcome``: ``enforcement`` says
    whether the Guardian let the action reach the executor, and this field says what the executor
    then reported, resolved through :mod:`guardian.audit.outcome` so a v3 chain (joined through a
    ``results.json`` the caller may supply) and a v4 chain (read off its own follow-up records) are
    read the one way that module owns. It is never itself an attempt -- see :func:`is_execution`.
    """

    seq: int | None
    line: int
    ts: str | None
    run_id: str | None
    request_id: str | None
    iss: str | None
    token_jti: str | None
    guardian_mode: str | None
    verb: str | None
    resource: str | None
    namespace: str | None
    name: str | None
    decision: str | None
    reason_code: str | None
    policy_rule_id: str | None
    enforcement: str | None
    outcome: str
    execution_status: str

    def target(self) -> str:
        """``verb resource/name in namespace`` -- the action in one readable phrase."""
        subject = self.resource or "?"
        if self.name:
            subject = f"{subject}/{self.name}"
        where = f" in {self.namespace}" if self.namespace else ""
        return f"{self.verb or '?'} {subject}{where}"


def _classify(decision: str | None, enforcement: str | None) -> str:
    if decision == "deny":
        return OUTCOME_DENIED_EXECUTED if enforcement == "executed" else OUTCOME_DENIED_BLOCKED
    if decision == "permit":
        return OUTCOME_PERMITTED if enforcement in (None, "executed") else OUTCOME_PERMITTED_BLOCKED
    return OUTCOME_UNCLASSIFIED


def _text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def replay(records: Sequence[ParsedRecord]) -> list[Attempt]:
    """Reconstruct the full attempted-action history from a chain, in chain order.

    Malformed records are skipped rather than guessed at; a caller that cares whether any were
    skipped compares ``len(result)`` against the record count, which is what the command line does.
    The run-start genesis (ADR-058) is skipped as well, and for a different reason: it is sound, it
    is simply not an attempt. :func:`run_start_records` is how a caller reads it.

    So is an execution follow-up (ADR-082): it is sound and it names a decision's outcome, but it
    is not itself a second attempt at the same action. What it carries is folded into the
    decision's own ``Attempt.execution_status`` instead, through
    :func:`guardian.audit.outcome.bundle_status_by_seq` computed once over every sound record this
    chain holds -- so a v4 chain's follow-up records
    resolve a decision's status exactly as a v3 bundle's ``results.json`` would, and this function
    does not have to know which shape it was handed.
    """
    sound = [parsed.record for parsed in records if parsed.defect is None]
    status_by_seq = bundle_status_by_seq(sound)
    attempts: list[Attempt] = []
    for parsed in records:
        if parsed.defect is not None:
            continue
        if is_run_start(parsed.record) or is_execution(parsed.record):
            continue
        record: dict[str, Any] = parsed.record
        action = record.get("action")
        action = action if isinstance(action, dict) else {}
        decision = _text(record.get("decision"))
        enforcement = _text(record.get("enforcement"))
        attempts.append(
            Attempt(
                seq=parsed.seq,
                line=parsed.line,
                ts=_text(record.get("ts")),
                run_id=_text(record.get("run_id")),
                request_id=_text(record.get("request_id")),
                iss=_text(record.get("iss")),
                token_jti=_text(record.get("token_jti")),
                guardian_mode=_text(record.get("guardian_mode")),
                verb=_text(action.get("verb")),
                resource=_text(action.get("resource")),
                namespace=_text(action.get("namespace")),
                name=_text(action.get("name")),
                decision=decision,
                reason_code=_text(record.get("reason_code")),
                policy_rule_id=_text(record.get("policy_rule_id")),
                enforcement=enforcement,
                outcome=_classify(decision, enforcement),
                execution_status=resolve_execution_status(record, status_by_seq),
            )
        )
    return attempts


def replay_summary(attempts: Sequence[Attempt]) -> dict[str, int]:
    """Count attempts by outcome, with every outcome present even at zero.

    Present-at-zero matters: ``denied-but-executed: 0`` on a G0 run is a fact the analysis wants to
    read, while a missing key is a question about whether the field was even looked at.
    """
    counts = {
        OUTCOME_PERMITTED: 0,
        OUTCOME_DENIED_BLOCKED: 0,
        OUTCOME_DENIED_EXECUTED: 0,
        OUTCOME_PERMITTED_BLOCKED: 0,
        OUTCOME_UNCLASSIFIED: 0,
    }
    for attempt in attempts:
        counts[attempt.outcome] = counts.get(attempt.outcome, 0) + 1
    return counts


def run_start_records(records: Sequence[ParsedRecord]) -> list[ParsedRecord]:
    """The chain's run-start records (ADR-058), in chain order. A chain the Guardian wrote has one.

    Sound records only, for :func:`replay`'s reason: a record that failed its own parse is not
    evidence of anything, including of a Guardian having started.
    """
    return [parsed for parsed in records if parsed.defect is None and is_run_start(parsed.record)]


# --- command line -------------------------------------------------------------------------------
#
# scripts/audit_verify.sh is the front door; this is where the work happens, on the pattern
# scripts/monitor_replay.sh and monitor/tests/replay_harness.py already set. One machine-readable
# line per chain goes to stdout so the shell can aggregate it with awk; the human detail goes to
# stderr. The two streams are not interchangeable here: the summary line is parsed, the detail is
# read.


def _machine_line(report: ChainReport) -> str:
    first = report.first_break_seq
    return (
        f"audit-chain: {report.path} records={report.record_count} "
        f"diagnosis={report.diagnosis} findings={len(report.findings)} "
        f"anchor={report.anchor_source} head={report.head} "
        f"first_break_seq={'-' if first is None else first} rule={report.rule_id}"
    )


def _print_detail(report: ChainReport, stream: Any) -> None:
    anchor = (
        f"anchored to {report.expected_head} (from {report.anchor_source})"
        if report.anchored
        else "NOT anchored -- tail truncation and whole-chain rewrite are undetectable in this mode"
    )
    print(f"  {report.path}", file=stream)
    print(f"    records={report.record_count} head={report.head}", file=stream)
    print(f"    {anchor}", file=stream)
    print(f"    diagnosis={report.diagnosis}", file=stream)
    for finding in report.findings:
        print(f"    ! {finding}", file=stream)


def _print_replay(report: ChainReport, records: Sequence[ParsedRecord], stream: Any) -> None:
    attempts = replay(records)
    counts = replay_summary(attempts)
    for start in run_start_records(records):
        genesis = start.record
        print(
            f"audit-replay: {report.path} -- run-start at seq={start.seq} "
            f"run_id={genesis.get('run_id') or '-'} mode={genesis.get('guardian_mode') or '-'} "
            f"ts={genesis.get('ts') or '-'}; not an attempt (ADR-058)",
            file=stream,
        )
    print(f"audit-replay: {report.path} -- {len(attempts)} attempted action(s)", file=stream)
    for attempt in attempts:
        mode = attempt.guardian_mode or "-"
        print(
            f"  seq={attempt.seq:<3} {attempt.ts or '-':<20} mode={mode:<12} "
            f"iss={attempt.iss or '-':<28} jti={attempt.token_jti or '-':<36} "
            f"{attempt.decision or '-':<6} {attempt.outcome:<26} "
            f"execution={attempt.execution_status:<13} "
            f"reason={attempt.reason_code or '-':<28} rule={attempt.policy_rule_id or '-':<22} "
            f"{attempt.target()}",
            file=stream,
        )
    print("audit-replay: outcomes", file=stream)
    for outcome, count in counts.items():
        print(f"  {outcome:<28} {count}", file=stream)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m guardian.audit.verify",
        description="Verify Guardian audit chains and replay the attempted-action history.",
    )
    parser.add_argument("paths", nargs="+", help="one or more guardian_audit.jsonl files")
    parser.add_argument(
        "--head",
        default=None,
        help="expected chain head (64 lowercase hex); overrides any sibling seal.json",
    )
    parser.add_argument(
        "--no-anchor",
        action="store_true",
        help="verify without any head anchor, which is how the 'missed without it' half of the "
        "truncation test pair is driven",
    )
    parser.add_argument(
        "--replay",
        action="store_true",
        help="print the attempted-action history of each chain after verifying it",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Verify every named chain. Returns 0 when all pass, 1 otherwise, 2 on a usage error."""
    args = _build_parser().parse_args(argv)
    if args.head is not None and args.no_anchor:
        print("--head and --no-anchor are mutually exclusive", file=sys.stderr)
        return 2
    if args.head is not None and not is_chain_hash(args.head):
        print("--head must be 64 lowercase hexadecimal characters", file=sys.stderr)
        return 2

    failures = 0
    print("audit-verify: per-chain detail", file=sys.stderr)
    for raw_path in args.paths:
        path = Path(raw_path)
        if not path.is_file():
            print(f"  {path}: no such file", file=sys.stderr)
            print(
                f"audit-chain: {path} records=0 diagnosis=missing findings=1 anchor=none "
                f"head=None first_break_seq=- rule={CANONICAL_JSON_RULE_ID}"
            )
            failures += 1
            continue
        try:
            report = verify_file(path, expected_head=args.head, use_seal=not args.no_anchor)
        except ValueError as exc:
            print(f"  {path}: {exc}", file=sys.stderr)
            print(
                f"audit-chain: {path} records=0 diagnosis=anchor-error findings=1 anchor=error "
                f"head=None first_break_seq=- rule={CANONICAL_JSON_RULE_ID}"
            )
            failures += 1
            continue
        print(_machine_line(report))
        _print_detail(report, sys.stderr)
        if not report.ok:
            failures += 1
        if args.replay:
            if report.ok or report.diagnosis == DIAGNOSIS_HEAD:
                _print_replay(report, read_chain(path), sys.stdout)
            else:
                print(
                    f"  {path}: not replayed -- the chain does not verify ({report.diagnosis}), "
                    "and a history reconstructed from records that failed their own integrity "
                    "check is not evidence of anything",
                    file=sys.stderr,
                )
    return 1 if failures else 0


if __name__ == "__main__":  # pragma: no cover - exercised through scripts/audit_verify.sh
    raise SystemExit(main())
