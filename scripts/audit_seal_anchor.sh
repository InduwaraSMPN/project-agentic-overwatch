#!/bin/sh
# audit_seal_anchor.sh -- append a sealed bundle's audit anchor to the external ledger (ADR-130).
#
# WHAT THIS IS
# At seal, the Guardian audit chain's anchor -- {run_id, head, signature, ts} -- is written OUT of the
# bundle, so that a whole-chain-plus-seal.json rewrite is detectable: an attacker who can rewrite a
# bundle's chain and its seal cannot also reach into an append-only ledger written elsewhere. This
# script writes that anchor to the two homes security-policy §2.1 names:
#   1. the external ledger  runs/.audit-anchor-ledger/anchors.jsonl  (outside any one bundle,
#      gitignored, backed up per the data-management protocol / VM mirror);
#   2. the campaign fidelity ledger  <campaign>/fidelity_ledger.jsonl  (beside the run it anchors).
# Ordinary invocation reads already-sealed facts. ADR-178 live pre-seal invocation verifies the
# supplied head and every Ed25519 signature before appending one JSON line to each ledger.
# It signs nothing -- guardian/audit/ owns the signing
# key and the chain (the key is operator-managed, out of band; ADR-130), and this only records the
# anchor those produced.
#
# WHERE EACH FIELD COMES FROM
#   run_id      <bundle>/manifest.json  "run_id"
#   head        <bundle>/seal.json      "audit_chain_head"  (runner/bundle.py's SEAL_HEAD_KEY)
#   signature   <bundle>/seal.json      "record_signature"/"signature" if present, else the last
#               <bundle>/guardian_audit.jsonl record's "record_signature" (chain.py's SIGNATURE_FIELD),
#               else null -- an unsigned v1-style chain has no signature to anchor, and null records
#               that faithfully rather than inventing one.
#   ts          the moment this anchor was written, UTC ISO-8601.
#
# STREAMS AND EXIT CODES
# One summary line on stdout; diagnostics on stderr. Exit 0 when both ledgers were appended, 1 on a
# missing/malformed bundle or an unwritable ledger. Idempotency is deliberately NOT claimed: the
# ledgers are append-only by design, and a second run appends a second anchor with a later ts -- the
# reader dedupes on (run_id, head). Strict POSIX sh; JSON is read and written by the interpreter, the
# way every other JSON-handling gate in scripts/ does it rather than parsing JSON in the shell.
#
# ARGUMENTS / ENVIRONMENT
#   $1            the sealed bundle directory (required).
#   --verified-head <head>  pre-seal mode; requires GUARDIAN_AUDIT_PUBLIC_KEY (PEM path).
#   ANCHOR_LEDGER=<path>   override the external ledger (default: runs/.audit-anchor-ledger/anchors.jsonl).
#   PYTHON=<path>          the interpreter to use.
#
# WHAT BREAKS IF THIS FILE CHANGES
# The seal-time anchoring security-policy §2.1 and ADR-130 require, and any fidelity check that reads
# the external ledger to confirm the chain head is anchored (F-GD-01). guardian/audit/ owns the chain;
# this owns only the copy of its anchor into the ledgers.

set -eu

LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

if [ -n "${PYTHON:-}" ]; then
    python_bin=$PYTHON
elif [ -x .venv/bin/python ]; then
    python_bin=.venv/bin/python
elif [ -x .venv/Scripts/python.exe ]; then
    python_bin=.venv/Scripts/python.exe
else
    python_bin=python3
fi

bundle=${1:-}
if [ -z "$bundle" ]; then
    echo "usage: sh scripts/audit_seal_anchor.sh <sealed-bundle-dir>" >&2
    exit 2
fi
if [ ! -d "$bundle" ]; then
    echo "audit-seal-anchor: $bundle is not a directory" >&2
    exit 1
fi
verified_head=""
if [ "$#" -gt 1 ]; then
    if [ "$#" -ne 3 ] || [ "$2" != "--verified-head" ] || [ -z "$3" ]; then
        echo "usage: sh scripts/audit_seal_anchor.sh <bundle-dir> [--verified-head <head>]" >&2
        exit 2
    fi
    verified_head=$3
fi

# The external ledger, security-policy §2.1's fixed location, and the campaign fidelity ledger beside
# the run. The campaign directory is the bundle's parent; fidelity_ledger.jsonl is runner.fidelity's
# LEDGER_FILENAME. Both are passed to the interpreter so the shell parses no JSON.
anchor_ledger=${ANCHOR_LEDGER:-runs/.audit-anchor-ledger/anchors.jsonl}
campaign_dir=$(CDPATH= cd -- "$bundle/.." && pwd)
fidelity_ledger="$campaign_dir/fidelity_ledger.jsonl"

# The read-and-append plumbing. No business logic: two JSON files in, one canonical JSON line appended
# to each ledger. Passed as a single-quoted -c program so the shell expands nothing inside it; the
# bundle and ledger paths arrive as argv, never interpolated into the source.
"$python_bin" -c '
import json, os, sys
from datetime import datetime, timezone
from pathlib import Path

bundle = Path(sys.argv[1])
anchor_ledger = Path(sys.argv[2])
fidelity_ledger = Path(sys.argv[3])
verified_head = sys.argv[4]

def load(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        sys.exit(f"audit-seal-anchor: {path}: {error}")

manifest = load(bundle / "manifest.json")
seal = {} if verified_head else load(bundle / "seal.json")

run_id = manifest.get("run_id")
if not isinstance(run_id, str) or not run_id:
    sys.exit(f"audit-seal-anchor: {bundle} manifest.json has no run_id")

head = verified_head or seal.get("audit_chain_head")
if verified_head:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from guardian.audit.chain import read_chain
    from guardian.audit.verify import verify_chain, verify_signature

    records = read_chain(bundle / "guardian_audit.jsonl")
    report = verify_chain(records, expected_head=head)
    if not report.ok or not records:
        sys.exit(f"audit-seal-anchor: chain verification failed: {report.diagnosis}")
    key_path = os.environ.get("GUARDIAN_AUDIT_PUBLIC_KEY")
    if not key_path:
        sys.exit("audit-seal-anchor: GUARDIAN_AUDIT_PUBLIC_KEY is required")
    public_key = serialization.load_pem_public_key(Path(key_path).read_bytes())
    if not isinstance(public_key, Ed25519PublicKey):
        sys.exit("audit-seal-anchor: public key must be Ed25519")
    findings = verify_signature(records, public_key)
    if findings:
        sys.exit(f"audit-seal-anchor: signature verification failed: {findings[0]}")

# The signature, from the seal if the signing path put it there, else from the last audit record, else
# null. "record_signature" is guardian/audit/chain.py SIGNATURE_FIELD; "signature" is a forbidden
# record key there, so it is only read from the seal, never from a chain record.
signature = seal.get("record_signature") or seal.get("signature")
if signature is None:
    audit = bundle / "guardian_audit.jsonl"
    if audit.is_file():
        last = None
        for line in audit.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last = line
        if last is not None:
            try:
                record = json.loads(last)
            except ValueError:
                record = {}
            if isinstance(record, dict):
                signature = record.get("record_signature")

record = {
    "run_id": run_id,
    "head": head,
    "signature": signature,
    "ts": datetime.now(timezone.utc).isoformat(),
}
line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"

for ledger in (anchor_ledger, fidelity_ledger):
    ledger.parent.mkdir(parents=True, exist_ok=True)
    with ledger.open("a", encoding="utf-8") as stream:
        stream.write(line)

note = "" if signature is not None else " (no signature yet: unsigned chain)"
print(f"audit-seal-anchor: PASS — anchored {run_id} head {str(head)[:12]}{note} to {anchor_ledger} and {fidelity_ledger}")
' "$bundle" "$anchor_ledger" "$fidelity_ledger" "$verified_head"
