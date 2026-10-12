#!/bin/sh
# backup_sync.sh — the three-copy backup of sealed run bundles, wired at M6 and operated at M7.
#
# WHAT THIS SCRIPT IS
# data-management.md §7 requires three copies of the sealed bundles -- the working disk (WSL), a
# cloud-drive sync of sealed bundles (nightly), and an external disk (weekly) -- and "Verify restores
# once before GATE". M6-runner.md's risk line says R-09 is wired now; M7-campaign.md T7.4 operates it
# on real bundles. Conflict M6-C5 splits the work without moving ownership: M6 writes this script and
# performs the one required restore verification against the SYNTHETIC corpus, which is free,
# disposable and exists at exactly the right moment (T6.6); M7-T7.4 runs it on real bundles nightly
# and weekly. The restore verification is the load-bearing half -- a backup nobody has ever restored
# from is a hope, not a backup.
#
# WHY IT SYNCS SEALED BUNDLES ONLY
# A bundle is a backup candidate once it carries a seal.json: the seal is what makes its content
# hashes and audit chain verifiable, so a copy can be checked against the original rather than
# trusted. An unsealed bundle is a run in progress, and copying one would back up a moving target.
# This script skips any bundle directory without a seal.json and says how many it skipped.
#
# SCOPE AND EXIT CODES
# Three modes. `--to <dest>` mirrors every sealed bundle under runs/ into <dest> and re-verifies each
# copied seal against its source (the sync-and-check the nightly and weekly copies both use).
# `--verify-restore <copy>` restores a bundle from a backup copy into a scratch directory and asserts
# the restored seal verifies -- the once-before-GATE check §7 names. `--list` reports which bundles
# are sealed and therefore eligible. Exit 0 when every eligible bundle synced or restored and every
# seal re-verified, 1 on any mismatch, missing seal on a copy, or unreadable source. Strict POSIX sh:
# runs under dash on WSL2 Ubuntu, under Git Bash on Windows, and on ubuntu-latest.
#
# PORTABILITY
# Uses cp -R and the existing Python bundle hash verifier,
# no rsync dependency, so it runs the same on a fresh WSL2 install and on the CI runner. The seal
# re-verification reuses guardian/audit/verify.py through scripts/audit_verify.sh rather than
# reimplementing chain verification.

set -eu

LC_ALL=C
export LC_ALL

# Repo root derived from this script's own location, so behaviour is identical whether the script is
# invoked by make, by CI, or by hand from an arbitrary working directory.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

RUNS_DIR="runs"
SEAL="seal.json"

# Use the existing bundle hash verifier with the configured project interpreter.
if [ -n "${PYTHON:-}" ]; then
    python_bin=$PYTHON
elif [ -x "$repo_root/.venv/bin/python" ]; then
    python_bin="$repo_root/.venv/bin/python"
elif [ -x "$repo_root/.venv/Scripts/python.exe" ]; then
    python_bin="$repo_root/.venv/Scripts/python.exe"
else
    python_bin=python3
fi

usage() {
    {
        echo "usage: sh scripts/backup_sync.sh --to <dest>"
        echo "       sh scripts/backup_sync.sh --verify-restore <backup-copy-dir>"
        echo "       sh scripts/backup_sync.sh --list"
    } >&2
    exit 1
}

# List sealed bundle directories under runs/, one per line, relative to runs/.
list_sealed() {
    [ -d "$RUNS_DIR" ] || return 0
    for campaign in "$RUNS_DIR"/*/; do
        [ -d "$campaign" ] || continue
        for bundle in "$campaign"*/; do
            [ -f "$bundle$SEAL" ] || continue
            printf '%s\n' "${bundle#"$RUNS_DIR"/}"
        done
    done
}

# Re-verify a bundle's seal by re-hashing every file the seal records and comparing. Reuses the
# audit-chain verifier for the chain half. Returns non-zero on any mismatch.
verify_seal() {
    verify_dir=$1
    [ -f "$verify_dir/$SEAL" ] || {
        echo "backup-sync: $verify_dir carries no $SEAL" >&2
        return 1
    }
    "$python_bin" - "$verify_dir" <<'PY' || return 1
import sys
from pathlib import Path
from runner.bundle import load_seal, verify_content_hashes
bundle = Path(sys.argv[1])
try:
    hashes = load_seal(bundle).get("content_hashes")
    if not isinstance(hashes, dict) or not hashes:
        raise ValueError("missing content hashes")
    for name, digest in hashes.items():
        if (not isinstance(name, str) or Path(name).is_absolute()
                or ".." in Path(name).parts or not isinstance(digest, str)
                or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)):
            raise ValueError("malformed content hashes")
    mismatches = verify_content_hashes(bundle)
    if mismatches:
        raise ValueError(f"content hash mismatch: {', '.join(mismatches)}")
except (OSError, ValueError, TypeError) as error:
    print(f"backup-sync: {bundle}: {error}", file=sys.stderr)
    sys.exit(1)
PY
    # The chain head, if this is a framework-on bundle with an audit log.
    if [ -f "$verify_dir/guardian_audit.jsonl" ]; then
        sh scripts/audit_verify.sh P="$verify_dir" >/dev/null 2>&1 || {
            echo "backup-sync: $verify_dir audit chain does not verify" >&2
            return 1
        }
    fi
    return 0
}

mode=${1:-}
case "$mode" in
    --list)
        count=0
        while IFS= read -r bundle; do
            [ -n "$bundle" ] || continue
            printf '  %s\n' "$bundle"
            count=$((count + 1))
        done <<EOF
$(list_sealed)
EOF
        printf 'backup-sync: PASS — %s sealed bundle(s) eligible for backup\n' "$count"
        exit 0
        ;;
    --to)
        dest=${2:-}
        [ -n "$dest" ] || usage
        mkdir -p "$dest"
        synced=0
        skipped=0
        problems=0
        # Skip in-progress (unsealed) bundles, but count them, so a run mid-flight does not fail the
        # sync and its exclusion is visible rather than silent.
        if [ -d "$RUNS_DIR" ]; then
            for campaign in "$RUNS_DIR"/*/; do
                [ -d "$campaign" ] || continue
                for bundle in "$campaign"*/; do
                    [ -d "$bundle" ] || continue
                    if [ ! -f "$bundle$SEAL" ]; then
                        skipped=$((skipped + 1))
                        continue
                    fi
                    rel=${bundle#"$RUNS_DIR"/}
                    target="$dest/$rel"
                    mkdir -p "$target"
                    cp -R "$bundle." "$target"
                    if verify_seal "${target%/}"; then
                        synced=$((synced + 1))
                    else
                        problems=$((problems + 1))
                    fi
                done
            done
        fi
        if [ "$problems" -gt 0 ]; then
            printf 'backup-sync: FAIL — %s copied bundle(s) failed re-verification\n' "$problems"
            exit 1
        fi
        printf 'backup-sync: PASS — %s bundle(s) synced to %s and re-verified, %s unsealed skipped\n' \
            "$synced" "$dest" "$skipped"
        exit 0
        ;;
    --verify-restore)
        copy=${2:-}
        [ -n "$copy" ] || usage
        [ -d "$copy" ] || {
            echo "backup-sync: FAIL — $copy is not a directory" >&2
            exit 1
        }
        work=$(mktemp -d)
        trap 'rm -rf "$work"' EXIT HUP INT TERM
        cp -R "$copy/." "$work/restored"
        if verify_seal "$work/restored"; then
            printf 'backup-sync: PASS — restored %s and its seal verifies (the once-before-GATE check)\n' \
                "$copy"
            exit 0
        fi
        printf 'backup-sync: FAIL — restored copy of %s does not verify\n' "$copy"
        exit 1
        ;;
    *)
        usage
        ;;
esac
