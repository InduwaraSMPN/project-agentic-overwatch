#!/bin/sh
# run_quarantine.sh -- move an unsealed, crashed run attempt aside so its cell can be re-run.
#
# WHAT THIS SCRIPT IS
# `runner/run.py` and `runner/baseline.py` allocate a bundle directory with mkdir(exist_ok=False)
# and refuse an existing one: "bundle directory already exists: ...; refusing to reuse or merge
# it". That refusal is a safety property and this script does not touch it. Merging a fresh attempt
# into the leftovers of a crashed one would produce a bundle whose probes.csv came from one attempt
# and whose guardian_audit.jsonl came from another, and it would seal, and nothing downstream could
# tell. The refusal is the only thing standing between a crash and a bundle that lies.
#
# What the refusal does not provide is an operator path, and M7-T7.3 re-runs need one. This script
# is that path:
#
#     sh scripts/run_quarantine.sh runs/CAMP-20260910-x/RUN-G0-FULL-SCN-...-101
#     sh scripts/run_quarantine.sh --campaign CAMP-20260910-x        # every unsealed leftover
#
# WHY QUARANTINE AND NOT DELETE
# A crashed attempt is the only evidence of why it crashed. It is moved to
# `runs/.quarantine/<campaign>/<run-id>-<UTC timestamp>` rather than removed, so the operator can
# read it afterwards and the retry is unblocked in the same step. `runs/.quarantine` is inside the
# gitignored `runs/` tree and is skipped by everything that reads bundles, because a bundle is
# located by campaign and run id and a quarantined directory no longer has that shape.
#
# WHAT IT REFUSES
# A SEALED bundle is never moved. Sealing is what makes a directory evidence, and
# docs/protocols/data-management.md section 4 is explicit that an invalid run's original is
# *retained*, excluded from analysis and counted in the flake rate -- invalidation is a property
# recorded in the manifest, never a directory that vanished. So the presence of `seal.json` stops
# this script cold, and the operator is told to record the rerun with `rerun_of` instead. A path
# outside `runs/` is refused for the same reason `make nuke` refuses a symlinked ancestor.
#
# STREAMS AND EXIT CODES
# One line per directory acted on; exit 0 when every named directory was quarantined or was already
# absent, 1 on a sealed bundle, a path outside runs/, or a failed move. Strict POSIX sh.
#
# WHAT BREAKS IF THIS FILE CHANGES
# The M7-T7.3 rerun loop. It is the only sanctioned way to clear a failed attempt; nothing else in
# the tree removes anything from runs/.

set -eu

LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

runs_root=${RUNS_ROOT:-$repo_root/runs}
quarantine_root=$runs_root/.quarantine
stamp=$(date -u +%Y%m%dT%H%M%SZ)
failures=0

usage() {
    echo "run-quarantine: usage: sh scripts/run_quarantine.sh <bundle-dir>... | --campaign <id>" >&2
    exit 1
}

quarantine_one() {
    _dir=$1
    if [ ! -d "$_dir" ]; then
        printf 'run-quarantine: %s is absent; nothing to clear\n' "$_dir"
        return 0
    fi
    _abs=$(CDPATH= cd -- "$_dir" && pwd -P)
    _runs_abs=$(CDPATH= cd -- "$runs_root" && pwd -P)
    case "$_abs/" in
        "$_runs_abs"/*) ;;
        *)
            printf 'run-quarantine: %s is outside %s; refusing\n' "$_abs" "$_runs_abs" >&2
            failures=$((failures + 1))
            return 0
            ;;
    esac
    case "$_abs/" in
        "$_runs_abs"/.quarantine/*)
            printf 'run-quarantine: %s is already quarantined\n' "$_dir"
            return 0
            ;;
    esac
    if [ -f "$_abs/seal.json" ]; then
        printf 'run-quarantine: %s is SEALED and is evidence; refusing to move it. An invalid run is
  recorded as invalid and re-run with rerun_of set (data-management.md section 4), never deleted.\n' \
            "$_dir" >&2
        failures=$((failures + 1))
        return 0
    fi
    _run_id=$(basename -- "$_abs")
    _campaign=$(basename -- "$(dirname -- "$_abs")")
    _target=$quarantine_root/$_campaign/$_run_id-$stamp
    mkdir -p "$(dirname -- "$_target")"
    if mv -- "$_abs" "$_target"; then
        printf 'run-quarantine: %s -> %s\n' "$_dir" "${_target#"$repo_root"/}"
    else
        printf 'run-quarantine: could not move %s\n' "$_dir" >&2
        failures=$((failures + 1))
    fi
}

[ "$#" -gt 0 ] || usage

if [ "$1" = "--campaign" ]; then
    [ "$#" -eq 2 ] || usage
    campaign_dir=$runs_root/$2
    if [ ! -d "$campaign_dir" ]; then
        printf 'run-quarantine: campaign %s has no directory under %s\n' "$2" "$runs_root"
        exit 0
    fi
    found=0
    for candidate in "$campaign_dir"/*; do
        [ -d "$candidate" ] || continue
        [ -f "$candidate/seal.json" ] && continue
        found=$((found + 1))
        quarantine_one "$candidate"
    done
    [ "$found" -ne 0 ] || printf 'run-quarantine: campaign %s holds no unsealed attempt\n' "$2"
else
    for target in "$@"; do
        case "$target" in --*) usage ;; esac
        quarantine_one "$target"
    done
fi

if [ "$failures" -ne 0 ]; then
    printf 'run-quarantine: FAIL -- %s directory(ies) refused\n' "$failures" >&2
    exit 1
fi
printf 'run-quarantine: PASS -- every named attempt is cleared for re-run\n'
