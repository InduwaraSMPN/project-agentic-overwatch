r"""The signed audit chain (ADR-130): the property an unsigned hash chain cannot have.

``guardian/audit/verify.py`` and ``guardian/tests/test_audit_tamper.py`` establish the boundary of
  an
unsigned hash chain: it detects in-place mutation, deletion, insertion and reordering, but a forger
who
can write the file recomputes every hash forward from a cut and produces a chain that verifies and
is
not the one that was written -- caught only by the ``seal.json`` anchor. ADR-130 closes that a
second,
independent way: each record's hash is signed with an operator-held Ed25519 key, so a rewrite would
have
to re-sign every record with a key the forger does not hold.

These cases generate an ephemeral key -- the operator's real key is out of band and rule 10 forbids
it
in a test -- write a chain with it, and prove: an honest signed chain verifies; a rewrite that
``verify_chain`` accepts without an anchor fails signature verification; a different key rejects
  every
record; and an unsigned chain has no signature protection at all.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

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
from guardian.audit.verify import (  # noqa: E402
    SIGNATURE_INVALID,
    verify_chain,
    verify_signature,
)

CHAIN_FILENAME = "guardian_audit.jsonl"
MAX_JUSTIFICATION = 2048


def _write_signed_chain(path: Path, key: Ed25519PrivateKey, *, count: int = 4) -> None:
    """Write ``count`` plain records to ``path``, each signed by ``key``."""
    writer = AuditChainWriter.open(path, max_justification_chars=MAX_JUSTIFICATION, signing_key=key)
    for index in range(count):
        writer.append({"n": index, "note": f"record number {index}"})


def _rewrite_body_and_rehash_forward(path: Path, *, at_seq: int) -> None:
    """Mutate the body of the record at ``at_seq`` and recompute every hash from there to the tail.

    This is the whole-chain-rewrite / truncate-and-rehash attack: the file is left internally
    consistent as a hash chain -- every ``prev_hash`` links, every stored ``hash`` recomputes -- so
    ``verify_chain`` accepts it without a head anchor. The signatures are left exactly as written,
    because a forger cannot produce new ones, which is what ``verify_signature`` catches.
    """
    import json

    records = [parsed.record for parsed in read_chain(path)]
    for record in records:
        if record.get("seq") == at_seq:
            record["note"] = "MUTATED after signing"
    head = records[0][PREV_HASH_FIELD]
    for _, record in enumerate(records):
        if record.get("seq") is not None and record["seq"] >= at_seq:
            record[PREV_HASH_FIELD] = head
            body = {
                key: value
                for key, value in record.items()
                if key not in (HASH_FIELD, SIGNATURE_FIELD)
            }
            record[HASH_FIELD] = record_hash(head, body)
            # The signature is NOT recomputed -- that is the point. It still covers the old hash.
        head = record[HASH_FIELD]
    path.write_bytes(b"".join(canonical_json_line(record) for record in records))
    del json  # imported only to make the byte-rewrite intent explicit; unused otherwise


def test_a_signed_chain_this_guardian_wrote_verifies_by_hash_and_by_signature(
    tmp_path: Path,
) -> None:
    """The control: an honest signed chain passes both the hash-chain check and the signature
    check."""
    key = Ed25519PrivateKey.generate()
    path = tmp_path / CHAIN_FILENAME
    _write_signed_chain(path, key)

    records = read_chain(path)
    assert verify_chain(records).ok, "the honest chain failed the hash-chain check"
    assert verify_signature(records, key.public_key()) == (), (
        "the honest chain failed signature check"
    )

    # Every record actually carries a signature -- otherwise the check above would pass vacuously.
    assert all(SIGNATURE_FIELD in parsed.record for parsed in records)


def test_a_rewrite_that_passes_the_hash_chain_fails_the_signature(tmp_path: Path) -> None:
    """Truncate-and-rehash: accepted by the unsigned verifier, rejected by the signed one.

    This is the whole point of the signature. The rewrite leaves a chain that ``verify_chain`` --
    the
    v1 verifier -- accepts with no anchor, because every hash was recomputed to link. The stored
    signatures still cover the *old* hashes, so ``verify_signature`` rejects every rewritten record.
    """
    key = Ed25519PrivateKey.generate()
    path = tmp_path / CHAIN_FILENAME
    _write_signed_chain(path, key)
    _rewrite_body_and_rehash_forward(path, at_seq=1)

    records = read_chain(path)
    # The v1 verifier is satisfied: the rewritten chain is internally consistent without an anchor.
    assert verify_chain(records).ok, (
        "the rewrite did not produce an internally consistent chain, so this test is not exercising "  # noqa: E501 - message
        "the gap the signature is for"
    )

    # The signed verifier catches it, at the rewritten record and every one after it.
    findings = verify_signature(records, key.public_key())
    assert findings, "a whole-chain rewrite verified clean under the signature check"
    assert {finding.kind for finding in findings} == {SIGNATURE_INVALID}
    assert findings[0].seq == 1


def test_a_different_key_rejects_every_record(tmp_path: Path) -> None:
    """A chain signed by one key does not verify under another's public key."""
    key = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    path = tmp_path / CHAIN_FILENAME
    _write_signed_chain(path, key, count=3)

    records = read_chain(path)
    findings = verify_signature(records, other.public_key())
    assert len(findings) == 3
    assert all(finding.kind == SIGNATURE_INVALID for finding in findings)


def test_an_unsigned_chain_has_no_signature_protection(tmp_path: Path) -> None:
    """A chain written without a key verifies as a hash chain but fails every signature check.

    The honest reading of what signing adds: an unsigned record cannot be distinguished from one a
    rewrite stripped, so a signed-chain verification of an unsigned file reports each record as
    unverifiable rather than passing it. ``verify_chain`` still accepts it, because it is a valid
    hash
    chain -- signing is additive, and the pre-M10 chain shape is unchanged.
    """
    key = Ed25519PrivateKey.generate()
    path = tmp_path / CHAIN_FILENAME
    writer = AuditChainWriter.open(
        path, max_justification_chars=MAX_JUSTIFICATION
    )  # no signing_key
    for index in range(3):
        writer.append({"n": index, "note": f"unsigned record {index}"})

    records = read_chain(path)
    assert verify_chain(records).ok
    assert all(SIGNATURE_FIELD not in parsed.record for parsed in records)
    findings = verify_signature(records, key.public_key())
    assert len(findings) == 3
    assert all(finding.kind == SIGNATURE_INVALID for finding in findings)


def test_the_signature_field_is_not_treated_as_a_planted_secret(tmp_path: Path) -> None:
    """A 128-hex-character signature must not be flagged by the pre-seal secret scan.

    The signature is high-entropy hex by construction, exactly the shape ``scan_record`` redacts in
    a
    justification. It is a writer-assigned field like ``hash``, so the scan skips it; if it did not,
    a
    signed chain would fail the M3-C5 planted-secret seal check on correct behaviour.
    """
    from guardian.audit.chain import scan_chain_file

    key = Ed25519PrivateKey.generate()
    path = tmp_path / CHAIN_FILENAME
    _write_signed_chain(path, key)
    assert scan_chain_file(path) == []
