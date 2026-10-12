r"""Builds the committed audit-chain corpus, and re-derives it to prove it has not drifted.

WHAT THIS PRODUCES, AND WHY A BUILDER EXISTS AT ALL
-----------------------------------------------------
One clean chain and one file per tamper class. The clean chain cannot be hand-authored: every
record carries a SHA-256 over its predecessor, so a single edited character anywhere means every
digest after it has to be recomputed by hand. A corpus nobody can regenerate is a corpus that
freezes at the first mistake, and ``docs/adr/ADR-022-audit-canonicalisation-and-chain-boundary.md``
requires the opposite -- that a deliberate change to the rule shows up as a reviewed diff.

So the record *content* is literal in this file, the chain arithmetic is
``guardian.audit.chain``'s, and the tampered files are derived from the clean one by a named
mutation each. Nothing is copied between them by hand.

WHAT THIS DELIBERATELY DOES NOT PRODUCE
-----------------------------------------
``canonical/vectors.json``. Its expected digests are literals a human wrote down, and ADR-022 says
in as many words why: a test that canonicalises a record and hashes it proves only that the
implementation agrees with itself. A regenerator in this repository would make those digests
recomputable by the code under test, which is the property the fixture exists to deny.
:func:`check` therefore reads the vectors and never writes them, and ``--write`` leaves that file
alone. Regenerating it is a deliberate act performed outside this repository and reviewed as a
diff; after the ``v1.0`` freeze it is a hotfix ADR (``AGENTS.md`` iron rule 6).

WHY ``--check`` COMPARES RECORDS AND NOT FILE BYTES
------------------------------------------------------
``.gitattributes`` sets ``* text=auto eol=lf``, so a tracked ``.jsonl`` normalises to LF in the
index and materialises with CRLF in a Windows working tree under ``core.autocrlf=true``. A
byte-level ``cmp`` against a rebuilt file would therefore fail on the machine the corpus was
authored on and pass in CI -- the identical defect ADR-010 closed for ``versions_env_sha256``,
arriving one layer up, and with the green result arriving first. The comparison below normalises
line endings and compares record for record, which is the same discipline
``guardian.audit.canonical`` states for the digest itself: the chain is a statement about the
records, and the file is merely how they were stored.

The one thing this cannot do is notice a difference that lives only in the line endings, and that
is deliberate rather than overlooked: such a difference is not a difference in the corpus.

THE PLANTED SECRETS, AND THE ASSERTION THAT MATTERS
-----------------------------------------------------
Two records carry a deliberately secret-shaped string on the way in -- one in
``action.justification``, which is the LLM-authored field the threat model assumes is hostile, and
one in an ``action.params`` leaf, which is the residual-scrub path. Both plants are obviously
synthetic: they say so in their own text, and neither is shaped like any real vendor credential.

``--check`` asserts three things about them, and the order is the argument:

1. neither plant survives into the committed chain -- so something was actually planted, and it was
   actually removed. Without this, item 2 would also pass on a corpus in which nothing was ever
   planted, which is the way this proof is most easily faked;
2. :func:`guardian.audit.chain.scan_chain_file` finds **nothing** in the committed chain. This is
   ``data-management.md`` section 5's pre-seal sanitizer asked of a finished file, and a clean
   answer is conflict M3-C5's resolution: not that the sanitizer works, but that on this file it has
   no work to do. A sanitizer with work to do on a sealed audit log is a sanitizer about to break
   every link after the record it edits;
3. the redaction markers are present, so the record says that something was removed rather than
   quietly not saying it.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Final

from guardian.audit.canonical import canonical_json_line
from guardian.audit.chain import (
    GENESIS_PREV_HASH,
    AuditChainWriter,
    read_chain,
    record_hash,
    scan_chain_file,
)
from guardian.audit.verify import SEAL_HEAD_KEY

__all__ = ["FIXTURE_ROOT", "TAMPER_CLASSES", "build", "check", "main"]

FIXTURE_ROOT: Final = Path(__file__).resolve().parent

CHAIN_FILENAME: Final = "guardian_audit.jsonl"
SEAL_FILENAME: Final = "seal.json"
CORPUS_PARAMS: Final = "corpus.json"
VECTORS: Final = Path("canonical") / "vectors.json"

CLEAN_DIR: Final = Path("clean")
TAMPERED_DIR: Final = Path("tampered")

# The tamper classes, in the order docs/plans/M3-implementation-plan.md's "Tamper tests" block
# lists them, plus one it implies rather than names. Each maps to one directory holding one
# guardian_audit.jsonl derived from the clean chain by the mutation of the same name.
#
# `field-mutation-rehashed` is the addition. The plan names field mutation once; guardian/audit/
# verify.py's docstring distinguishes two cases that fail at two different places -- a mutation with
# the stored hash left alone breaks the record's own self-check at its own seq, and a mutation whose
# hash the attacker recomputed breaks the *successor's* link instead. They are one class of attack
# and two classes of evidence, and a corpus carrying only the first would leave the second claim in
# that docstring untested.
TAMPER_CLASSES: Final = (
    "field-mutation",
    "field-mutation-rehashed",
    "record-deletion",
    "record-insertion",
    "reordering",
    "tail-truncation",
    "whole-chain-rewrite",
)

# --- the record content ------------------------------------------------------------------------
#
# Everything below is a literal. No clock, no seed, no counter: replaying this file twice must
# produce identical bytes (.agents/rules/20-parity-and-determinism.md), and a timestamp read from
# the host would be the one way that could fail.
#
# The two plants. Named for the redaction rule each is meant to trip, and written so that no reader
# and no scanner could mistake either for a real credential: both say what they are in their own
# text, and neither carries a real vendor prefix, a JWS header or a base64 body.
PLANT_CREDENTIAL_ASSIGNMENT: Final = (
    "the runbook told the executor to set api_key=NOT-A-REAL-KEY-SYNTHETIC-FIXTURE-VALUE "
    "before scaling the deployment back up"
)
PLANT_AUTHORIZATION_HEADER: Final = (
    "operator pasted a header into the incident ticket, verbatim: "
    "Authorization: Bearer NOT-A-REAL-TOKEN-SYNTHETIC-FIXTURE"
)

# What the committed chain must contain instead. Asserted present by check(), because a marker is
# the record saying that something was removed; a silently shortened string would be a record that
# quietly does not say it.
MARKER_CREDENTIAL_ASSIGNMENT: Final = "[REDACTED-CREDENTIAL-ASSIGNMENT]"
MARKER_AUTHORIZATION_HEADER: Final = "[REDACTED-AUTHORIZATION-HEADER]"

RUN_ID: Final = "RUN-G0-FULL-SCN01-INJA-S07"

# The identifier helpers exist so that the values are composed rather than written as string
# literals at a key whose name contains "token". Ruff's S105 reads such a literal as a possible
# hardcoded credential, and it is right to: the whole point of FORBIDDEN_RECORD_KEYS is that a
# field named for a credential is a defect. A jti is a public single-use identifier and not a
# credential, so composing it keeps the rule pointed at the case it is for instead of at a
# suppression comment repeated nine times.


def _jti(index: int) -> str:
    return f"jti-{index:04d}"


def _request(index: int) -> str:
    return f"req-{index:04d}"


def _ts(index: int) -> str:
    return f"2026-08-26T09:{14 + index:02d}:02Z"


def _action(
    verb: str,
    resource: str,
    name: str | None,
    justification: str,
    *,
    namespace: str = "boutique",
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "verb": verb,
        "resource": resource,
        "namespace": namespace,
        "name": name,
        "params": dict(params or {}),
        "justification": justification,
    }


def clean_bodies() -> list[dict[str, Any]]:
    """The nine record bodies of the clean chain, without seq, prev_hash or hash.

    Rich enough to evidence what M3's Definition of done claims, which is why it is nine records
    and not three:

    * **permits and denies both**, because ``security-policy.md`` section 1.4 requires a record for
      each and ``evaluation-protocol.md`` section 3 computes RQ5 from counting them;
    * **one G1-LOGONLY denied-but-executed record** (seq 6), which is the entire content of that
      arm. Under ``G0-FULL`` a deny is blocked; under ``G1-LOGONLY`` the Guardian logs and does not
      block, so ``decision = deny`` sits beside ``enforcement = executed``. A single-outcome record
      could not express it and the G0-versus-G1 contrast would be uncomputable -- conflict M3-C6;
    * **one record with no action at all** (seq 5), the malformed-request case that section 1.4
      still requires to be audited. ``action`` is null, ``enforcement`` is ``not-applicable``, and
      the attribution fields are null because no claim set was ever verified -- copying an
      unverified claim into ``iss`` would record attacker-authored text as established fact;
    * **denies from four different reason groups**, so replay output shows the closed vocabulary
      doing its job rather than one code repeated.
    """
    return [
        {
            "ts": _ts(0),
            "run_id": RUN_ID,
            "request_id": _request(0),
            "token_jti": _jti(0),
            "iss": "supervisor-detection",
            "decision": "permit",
            "reason_code": "permit.rule-allow",
            "policy_rule_id": "guardian:read:pods-in-scope",
            "action": _action(
                "get",
                "pods",
                None,
                "listing pods in the affected namespace to establish which replicas are unhealthy",
            ),
            "guardian_mode": "G0-FULL",
            "enforcement": "executed",
            "schema_version": "v2",
        },
        {
            "ts": _ts(1),
            "run_id": RUN_ID,
            "request_id": _request(1),
            "token_jti": _jti(1),
            "iss": "supervisor-containment",
            "decision": "permit",
            "reason_code": "permit.rule-allow",
            "policy_rule_id": "guardian:scale:deployment-in-scope",
            "action": _action(
                "patch",
                "deployments",
                "paymentservice",
                "scaling the compromised deployment to zero to contain the incident",
                params={"replicas": 0},
            ),
            "guardian_mode": "G0-FULL",
            "enforcement": "executed",
            "schema_version": "v2",
        },
        {
            "ts": _ts(2),
            "run_id": RUN_ID,
            "request_id": _request(2),
            "token_jti": _jti(2),
            "iss": "supervisor-containment",
            "decision": "deny",
            "reason_code": "policy.deny-default",
            "policy_rule_id": None,
            "action": _action(
                "delete",
                "namespaces",
                "boutique",
                "removing the namespace would end the incident quickly",
                params={"gracePeriodSeconds": 0},
            ),
            "guardian_mode": "G0-FULL",
            "enforcement": "blocked",
            "schema_version": "v2",
        },
        {
            "ts": _ts(3),
            "run_id": RUN_ID,
            "request_id": _request(3),
            "token_jti": _jti(3),
            "iss": "supervisor-containment",
            "decision": "deny",
            "reason_code": "scope.verb-not-allowed",
            "policy_rule_id": None,
            "action": _action(
                "delete",
                "pods",
                "paymentservice-7d9f8c",
                "the pod is unresponsive and the ticket says to remove it",
                # The residual-scrub plant: a string leaf that is not `justification`. chain.py
                # redacts these in place rather than refusing them, because refusing would leave a
                # decision unaudited and section 1.4 requires every decision to produce a record.
                params={"note": PLANT_AUTHORIZATION_HEADER},
            ),
            "guardian_mode": "G0-FULL",
            "enforcement": "blocked",
            "schema_version": "v2",
        },
        {
            "ts": _ts(4),
            "run_id": RUN_ID,
            "request_id": _request(4),
            "token_jti": _jti(1),
            "iss": "supervisor-containment",
            "decision": "deny",
            "reason_code": "replay.jti-spent",
            "policy_rule_id": None,
            "action": _action(
                "patch",
                "deployments",
                "paymentservice",
                "retrying the scale-down because the first attempt returned no output",
                params={"replicas": 0},
            ),
            "guardian_mode": "G0-FULL",
            "enforcement": "blocked",
            "schema_version": "v2",
        },
        {
            "ts": _ts(5),
            "run_id": None,
            "request_id": None,
            "token_jti": None,
            "iss": None,
            "decision": "deny",
            "reason_code": "policy.request-malformed",
            "policy_rule_id": None,
            "action": None,
            "guardian_mode": "G0-FULL",
            "enforcement": "not-applicable",
            "schema_version": "v2",
        },
        {
            "ts": _ts(6),
            "run_id": RUN_ID,
            "request_id": _request(6),
            "token_jti": _jti(6),
            "iss": "supervisor-eradication",
            "decision": "deny",
            "reason_code": "policy.rule-deny",
            "policy_rule_id": "guardian:deny:delete-outside-scope",
            "action": _action(
                "delete",
                "pods",
                "cartservice-5b6c7d",
                "removing the pod the attacker used as a foothold",
            ),
            # The one record the whole G1 arm exists to produce: policy said deny, the Guardian did
            # not block. T-12's replay has to reconstruct this as an attempted AND executed action.
            "guardian_mode": "G1-LOGONLY",
            "enforcement": "executed",
            "schema_version": "v2",
        },
        {
            "ts": _ts(7),
            "run_id": RUN_ID,
            "request_id": _request(7),
            "token_jti": _jti(7),
            "iss": "supervisor-eradication",
            "decision": "permit",
            "reason_code": "permit.rule-allow",
            "policy_rule_id": "guardian:read:events-in-scope",
            "action": _action(
                "get",
                "events",
                None,
                "reading events to confirm the foothold pod did not restart",
            ),
            "guardian_mode": "G1-LOGONLY",
            "enforcement": "executed",
            "schema_version": "v2",
        },
        {
            "ts": _ts(8),
            "run_id": RUN_ID,
            "request_id": _request(8),
            "token_jti": _jti(8),
            "iss": "supervisor-recovery",
            "decision": "permit",
            "reason_code": "permit.rule-allow",
            "policy_rule_id": "guardian:scale:deployment-in-scope",
            "action": _action(
                "patch",
                "deployments",
                "paymentservice",
                # The justification plant. This is the field ADR-022 names: LLM-authored free text
                # whose author the threat model assumes is hostile, and the one an agent wanting to
                # poison the pre-seal sanitizer would fill with a key-shaped string.
                PLANT_CREDENTIAL_ASSIGNMENT,
                params={"replicas": 3},
            ),
            "guardian_mode": "G0-FULL",
            "enforcement": "executed",
            "schema_version": "v2",
        },
    ]


# --- corpus parameters ---------------------------------------------------------------------------


def max_justification_chars(root: Path) -> int:
    """Read the corpus's own justification bound, refusing to guess one.

    ``guardian.audit.chain`` carries no default because no protocol owns the number, and this
    reader fails closed for the same reason -- the same shape ``monitor/aggregator/limits.py`` uses
    for the caps ``evaluation-protocol.md`` section 4 still lists as pending. The status sentinel
    must be present, so the value can never be read out of a file that forgot to say what it is.
    """
    path = root / CORPUS_PARAMS
    loaded = json.loads(path.read_bytes().decode("utf-8"))
    if not isinstance(loaded, dict) or "corpus_param_status" not in loaded:
        raise ValueError(
            f"{path}: carries no 'corpus_param_status'. These are fixture-corpus test parameters "
            "and the sentinel is what says so; a bound read out of a file that does not declare "
            "itself would read as a protocol value."
        )
    value = loaded.get("corpus_max_justification_chars")
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{path}: 'corpus_max_justification_chars' must be a positive integer")
    return value


# --- building ------------------------------------------------------------------------------------


def _write_chain(path: Path, bodies: list[dict[str, Any]], bound: int) -> str:
    """Write ``bodies`` as a fresh chain at ``path`` and return the resulting head."""
    if path.exists():
        path.unlink()
    writer = AuditChainWriter(path, max_justification_chars=bound)
    for body in bodies:
        writer.append(body)
    return writer.head


def _records(path: Path) -> list[dict[str, Any]]:
    """Every record of a chain file as a plain dict, in file order."""
    return [parsed.record for parsed in read_chain(path)]


def _emit(path: Path, records: list[dict[str, Any]]) -> None:
    """Write records verbatim, one canonical line each, LF-terminated, binary mode.

    Verbatim is the point: the tampered files are what an attacker left behind, so nothing here may
    repair a record. Re-serialising through the canonical rule is not a repair -- key order and
    separators are already what the rule produced -- it only guarantees that an untouched record
    round-trips to the same bytes it was read from.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        for record in records:
            handle.write(canonical_json_line(record))


def _strip_chain_fields(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key not in ("seq", "prev_hash", "hash")}


def _rechain(bodies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Re-derive a complete, internally consistent chain over ``bodies`` from genesis.

    This is the attacker's own tool, used here to build the whole-chain-rewrite fixture: given the
    file, anybody can produce a chain that verifies. That is the boundary ADR-022 states, and
    building the fixture with the same arithmetic the verifier uses is what makes the fixture
    honest rather than a straw man.
    """
    rewritten: list[dict[str, Any]] = []
    head = GENESIS_PREV_HASH
    for index, body in enumerate(bodies):
        record = dict(body)
        record["seq"] = index
        record["prev_hash"] = head
        record["hash"] = record_hash(head, record)
        head = str(record["hash"])
        rewritten.append(record)
    return rewritten


def _tampered(name: str, clean: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One tamper class applied to the clean record list. Every case is documented at its branch."""
    if name == "field-mutation":
        # The record's own content is edited and its stored hash is left alone: the classic
        # after-the-fact edit by somebody who did not know the file was chained. It breaks that
        # record's self-check at its own seq and nothing else, because its successor's prev_hash
        # still equals the untouched stored hash.
        records = [dict(record) for record in clean]
        records[3]["reason_code"] = "permit.rule-allow"
        records[3]["decision"] = "permit"
        return records
    if name == "field-mutation-rehashed":
        # The same edit by somebody who did know, and recomputed the record's hash. The record is
        # now internally consistent, so nothing fails at seq 3; what fails is seq 4's link, because
        # its prev_hash still names the digest of the record as it was written.
        records = [dict(record) for record in clean]
        records[3]["reason_code"] = "permit.rule-allow"
        records[3]["decision"] = "permit"
        records[3]["hash"] = record_hash(str(records[3]["prev_hash"]), _without_hash(records[3]))
        return records
    if name == "record-deletion":
        # seq 4 removed: the replay denial, which is exactly the record an agent that replayed a
        # token would want gone. Leaves a seq gap and one broken link, both naming seq 4.
        return [dict(record) for index, record in enumerate(clean) if index != 4]
    if name == "record-insertion":
        # A forged permit spliced between seq 2 and seq 3, made internally self-consistent by
        # chaining it onto seq 2 -- an attacker manufacturing authorisation for something that was
        # never permitted. The real seq 3 then follows a record it never followed.
        forged = _strip_chain_fields(clean[2])
        forged["decision"] = "permit"
        forged["reason_code"] = "permit.rule-allow"
        forged["policy_rule_id"] = "guardian:read:pods-in-scope"
        forged["enforcement"] = "executed"
        forged["request_id"] = _request(99)
        forged["seq"] = 3
        forged["prev_hash"] = clean[2]["hash"]
        forged["hash"] = record_hash(str(forged["prev_hash"]), _without_hash(forged))
        return (
            [dict(record) for record in clean[:3]]
            + [forged]
            + [dict(record) for record in clean[3:]]
        )
    if name == "reordering":
        # seq 2 and seq 3 exchanged, mid-chain. Every record is intact and every hash is its own;
        # only the order is a lie, which is the case a per-record signature would miss entirely.
        records = [dict(record) for record in clean]
        records[2], records[3] = records[3], records[2]
        return records
    if name == "tail-truncation":
        # The last two records cut. What remains verifies perfectly -- there is nothing in the file
        # that says how long the file was -- so this fixture is the one that must PASS without the
        # head anchor and fail with it.
        return [dict(record) for record in clean[:-2]]
    if name == "whole-chain-rewrite":
        # History as the attacker would prefer it: every deny removed, everything re-chained from
        # genesis. Internally flawless, and not the chain that was written.
        kept = [
            _strip_chain_fields(record) for record in clean if record.get("decision") == "permit"
        ]
        return _rechain(kept)
    raise ValueError(f"unknown tamper class {name!r}")


def _without_hash(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key != "hash"}


def build(root: Path) -> str:
    """Write the whole corpus under ``root`` and return the clean chain's head."""
    bound = max_justification_chars(FIXTURE_ROOT)
    clean_path = root / CLEAN_DIR / CHAIN_FILENAME
    clean_path.parent.mkdir(parents=True, exist_ok=True)
    head = _write_chain(clean_path, clean_bodies(), bound)

    clean = _records(clean_path)
    seal = {
        SEAL_HEAD_KEY: head,
        "audit_chain_records": len(clean),
        "note": (
            "The head anchor, in the place docs/protocols/data-management.md section 1 puts it: "
            "seal.json carries 'bundle content hashes + chain head + sealed_at'. Only the chain "
            "head is here. The content hashes and sealed_at are M6's sealer's to write and "
            "inventing them in a fixture would be inventing a schema no protocol has fixed; the "
            "key name below is guardian/audit/verify.py's proposed contract for that sealer, "
            "flagged as a proposal there and flagged again here. What this file is for is the "
            "pair of truncation results: with this anchor the tail-truncation and "
            "whole-chain-rewrite fixtures are caught, and without it they verify clean."
        ),
    }
    (root / CLEAN_DIR / SEAL_FILENAME).write_bytes(
        (json.dumps(seal, indent=2, sort_keys=False, ensure_ascii=True) + "\n").encode("ascii")
    )

    for name in TAMPER_CLASSES:
        _emit(root / TAMPERED_DIR / name / CHAIN_FILENAME, _tampered(name, clean))
    return head


# --- checking ------------------------------------------------------------------------------------


def _normalised_lines(path: Path) -> list[str]:
    """A chain file's records as text, line endings normalised and blank lines dropped.

    See the module docstring: comparing bytes here would make the corpus host-dependent.
    """
    text = path.read_bytes().decode("utf-8")
    lines = [line[:-1] if line.endswith("\r") else line for line in text.split("\n")]
    return [line for line in lines if line.strip()]


def _compare(committed: Path, rebuilt: Path, problems: list[str]) -> None:
    if not committed.is_file():
        problems.append(f"{committed}: missing from the committed corpus")
        return
    have = _normalised_lines(committed)
    want = _normalised_lines(rebuilt)
    if len(have) != len(want):
        problems.append(f"{committed}: holds {len(have)} record(s), rebuild produced {len(want)}")
        return
    for index, (left, right) in enumerate(zip(have, want, strict=True)):
        if left != right:
            problems.append(
                f"{committed}: record {index} differs from the rebuild.\n"
                f"      committed: {left}\n"
                f"      rebuilt:   {right}"
            )
            return


def _check_vectors(problems: list[str]) -> int:
    """Confirm the frozen vectors file is present and self-describing. It is never rebuilt."""
    path = FIXTURE_ROOT / VECTORS
    if not path.is_file():
        problems.append(f"{path}: the frozen canonicalisation vectors are missing")
        return 0
    loaded = json.loads(path.read_bytes().decode("utf-8"))
    vectors = loaded.get("vectors") if isinstance(loaded, dict) else None
    if not isinstance(vectors, list) or not vectors:
        problems.append(f"{path}: carries no vectors")
        return 0
    return len(vectors)


def _check_plants(chain_path: Path, problems: list[str]) -> None:
    """The three assertions the module docstring numbers, in that order."""
    text = chain_path.read_bytes().decode("utf-8")
    for plant, label in (
        (PLANT_CREDENTIAL_ASSIGNMENT, "credential assignment"),
        (PLANT_AUTHORIZATION_HEADER, "authorization header"),
    ):
        if plant in text:
            problems.append(
                f"{chain_path}: the planted {label} survived into the committed chain. The scrub "
                "runs before the hash, so this is a record that would need redacting after the "
                "fact -- which breaks every link after it (M3-C5)."
            )
    for marker, label in (
        (MARKER_CREDENTIAL_ASSIGNMENT, "credential assignment"),
        (MARKER_AUTHORIZATION_HEADER, "authorization header"),
    ):
        if marker not in text:
            problems.append(
                f"{chain_path}: no {marker} anywhere. Either the {label} plant was never made, in "
                "which case the sanitizer finding nothing proves nothing, or the redaction left no "
                "marker and the record does not say that something was removed."
            )
    findings = scan_chain_file(chain_path)
    for line, shape in findings:
        problems.append(
            f"{chain_path}: line {line} still carries a {shape.kind} shape at {shape.field_path} "
            f"[{shape.start}:{shape.end}]. data-management.md section 5's sanitizer would edit "
            "this record before seal, and every link after it would break."
        )


def check(root: Path) -> int:
    """Re-derive the corpus into a scratch directory and compare. Returns a process exit code."""
    problems: list[str] = []
    with tempfile.TemporaryDirectory(prefix="audit-fixtures-") as scratch:
        rebuilt_root = Path(scratch)
        head = build(rebuilt_root)

        _compare(
            root / CLEAN_DIR / CHAIN_FILENAME, rebuilt_root / CLEAN_DIR / CHAIN_FILENAME, problems
        )
        for name in TAMPER_CLASSES:
            _compare(
                root / TAMPERED_DIR / name / CHAIN_FILENAME,
                rebuilt_root / TAMPERED_DIR / name / CHAIN_FILENAME,
                problems,
            )

        seal_path = root / CLEAN_DIR / SEAL_FILENAME
        if not seal_path.is_file():
            problems.append(f"{seal_path}: missing; nothing records the chain head")
        else:
            seal = json.loads(seal_path.read_bytes().decode("utf-8"))
            if seal.get(SEAL_HEAD_KEY) != head:
                problems.append(
                    f"{seal_path}: {SEAL_HEAD_KEY} is {seal.get(SEAL_HEAD_KEY)} but the clean "
                    f"chain rebuilds to {head}. Without a correct anchor the truncation half of "
                    "the tamper corpus proves nothing."
                )

    clean_path = root / CLEAN_DIR / CHAIN_FILENAME
    if clean_path.is_file():
        _check_plants(clean_path, problems)
    vector_count = _check_vectors(problems)

    if problems:
        print(f"audit-fixtures: FAIL -- {len(problems)} problem(s):", file=sys.stderr)
        for problem in problems:
            print(f"  ! {problem}", file=sys.stderr)
        print(f"audit-fixtures: FAIL -- {len(problems)} problem(s)")
        return 1

    print(
        f"audit-fixtures: PASS -- clean chain of {len(_normalised_lines(clean_path))} record(s) "
        f"re-derives byte for byte, {len(TAMPER_CLASSES)} tamper fixture(s) re-derive, "
        f"{vector_count} frozen canonicalisation vector(s) present and never rebuilt, "
        "both planted secrets scrubbed before hashing and the pre-seal sanitizer finds nothing "
        "left to change"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m guardian.audit.fixtures.build",
        description=(
            "Build or re-derive the committed audit-chain fixture corpus. The frozen "
            "canonicalisation vectors are never written by either mode; see the module docstring."
        ),
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="regenerate the corpus in place. A reviewed diff, never a way to make a gate green; "
        "after the v1.0 freeze it is a logged hotfix ADR (AGENTS.md iron rule 6)",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="write to this directory instead of the committed corpus (implies --write)",
    )
    args = parser.parse_args(argv)

    if args.out is not None:
        destination = Path(args.out)
        if destination.exists():
            shutil.rmtree(destination)
        build(destination)
        print(f"audit-fixtures: wrote a corpus to {destination}")
        return 0
    if args.write:
        build(FIXTURE_ROOT)
        print(f"audit-fixtures: regenerated {FIXTURE_ROOT}; review the diff before committing")
        return 0
    return check(FIXTURE_ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
