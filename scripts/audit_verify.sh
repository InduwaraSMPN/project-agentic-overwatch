#!/bin/sh
# audit_verify.sh — verify Guardian hash chains over a path, and say what was NOT checked.
#
# WHAT THIS GATE ASSERTS
# For every guardian_audit.jsonl under P, or for the one file named by P: each record hashes to its
# stored hash, each links to its predecessor, the seq sequence is complete and increasing, and the
# chain begins at the genesis prev_hash. A break is reported at the seq where it happened rather
# than as a bare "invalid", because a break that names its position is a break somebody can
# investigate and a boolean is not. When an expected chain head is supplied, the chain's own head is
# compared against it, which is the only way tail truncation and whole-chain rewrite are visible at
# all.
#
# WHY P IS OPTIONAL AND DEFAULTS TO runs/, WHICH IS A CORRECTION AND NOT A CONVENIENCE
# docs/04-repo-conventions.md section 3 stated the contract as "Guardian hash-chain integrity over
# runs/" and traceability row T-12 verifies through it — but runs/ is gitignored and stays empty
# until M6 seals the first bundle, while docs/milestones/M3-guardian.md's Definition of done
# requires this target to pass at M3, and docs/prompts-playbook.md's verify card already assumes a
# file-level invocation ("tamper with one line in a guardian_audit.jsonl"). As specified, no
# invocation satisfied both. That is conflict M3-C4 in docs/plans/M3-implementation-plan.md, and
# ADR-022's Consequences settle it: the target takes a path, defaulting to runs/. At M3 it is
# exercised against guardian/audit/fixtures/; from M6 onward against runs/, unchanged.
#
# AN EMPTY OR ABSENT PATH FAILS, LOUDLY
# runs/ is empty today, so the default invocation fails today, and that is the correct behaviour
# rather than an inconvenience to be smoothed over. A gate that succeeds over nothing is
# byte-identical, in a log, to one that succeeded over everything — and this particular gate runs at
# M7's daily QA cadence over bundles nobody re-reads by hand. The failure message names the path and
# says what to point it at, which is the difference between a refusal and an obstruction. Same
# discipline as monitor_replay.sh's empty corpus and check_hygiene.sh's problem list.
#
# WHAT AN UNANCHORED PASS DOES NOT MEAN
# An unsigned hash chain detects mutation, deletion, insertion and reordering. It does NOT detect
# tail truncation or a whole-chain rewrite: an attacker who can write the file recomputes every hash
# forward from the cut, and the result verifies perfectly and is not the chain that was written.
# docs/protocols/data-management.md section 1 puts the chain head in seal.json, and HEAD is that
# anchor. Without one, this script says so on the summary line and in the per-chain detail, in those
# words, every run — because a transcript that recorded only "PASS" would let a reader conclude the
# chain detects truncation on its own, which is exactly the unearned security claim ADR-022 exists
# not to make. guardian/audit/fixtures/tampered/tail-truncation/ is the fixture that proves the
# pair: it passes here without the anchor and fails with it.
#
# WHERE THE WORK ACTUALLY HAPPENS
# guardian/audit/verify.py. It parses, recomputes every digest, classifies the findings into one
# diagnosis and prints one machine-readable line per chain. This script resolves the interpreter,
# enumerates the chains, drives that module once, aggregates and reports. Keeping the verification
# in one Python entry point is what makes this gate, guardian/audit/fixtures/build.py and any later
# pytest layer agree about what a record hashes to; three implementations would be comparing
# themselves.
#
# STREAMS AND EXIT CODES
# stdout carries exactly one summary line, in check_hygiene.sh's shape. stderr carries the per-chain
# detail, the replay history when --replay is given, and the failure list. The split is not
# cosmetic: the summary line is parsed, the detail is read. Exit 0 when every chain verified, 1 on
# any failure — including an empty or absent path, which is refused rather than passed.
#
# PORTABILITY
# Strict POSIX sh — no bashisms, no GNU-only options, and no jq, which is not in this toolchain.
# Runs under dash in WSL2 Ubuntu, under Git Bash on Windows, and on ubuntu-latest.

set -eu

# Byte-exact matching and byte-stable tool output whatever the ambient locale.
LC_ALL=C
export LC_ALL

# Repo root from this script's own location, so behaviour is identical from make, from CI, or by
# hand from an arbitrary working directory.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

DEFAULT_PATH="runs/"
CHAIN_FILENAME="guardian_audit.jsonl"
VERIFIER="guardian.audit.verify"

usage() {
    echo "usage: sh scripts/audit_verify.sh [P=<path> | --path <path> | <path>]"
    echo "                                  [HEAD=<sha256> | --head <sha256>]"
    echo "                                  [--no-anchor] [--replay]"
    echo "       with no path given, $DEFAULT_PATH is verified — a directory is walked for every"
    echo "       $CHAIN_FILENAME under it, a file is verified on its own"
    echo "       HEAD is the expected chain head from seal.json; without it, tail truncation and"
    echo "       whole-chain rewrite are NOT detected and the summary line says so"
    echo "       --no-anchor suppresses the sibling seal.json lookup, which is how the 'missed"
    echo "       without it' half of the truncation pair is driven"
}

target=${P:-}
head_anchor=${HEAD:-}
no_anchor=0
replay=0

while [ $# -gt 0 ]; do
    case "$1" in
        --path)
            shift
            [ $# -gt 0 ] || { usage >&2; exit 1; }
            target=$1
            ;;
        --path=*) target=${1#--path=} ;;
        P=*)      target=${1#P=} ;;
        --head)
            shift
            [ $# -gt 0 ] || { usage >&2; exit 1; }
            head_anchor=$1
            ;;
        --head=*) head_anchor=${1#--head=} ;;
        HEAD=*)   head_anchor=${1#HEAD=} ;;
        --no-anchor) no_anchor=1 ;;
        --replay)    replay=1 ;;
        -h|--help)   usage; exit 0 ;;
        -*)
            printf 'audit-verify: unknown option %s\n' "$1" >&2
            usage >&2
            exit 1
            ;;
        *)
            # A bare path, so `sh scripts/audit_verify.sh <file>` reads the way a reader expects.
            target=$1
            ;;
    esac
    shift
done

[ -n "$target" ] || target=$DEFAULT_PATH

if [ -n "$head_anchor" ] && [ "$no_anchor" -eq 1 ]; then
    echo "audit-verify: HEAD and --no-anchor are mutually exclusive: one supplies an anchor and" >&2
    echo "the other suppresses the search for one." >&2
    printf 'audit-verify: FAIL — HEAD and --no-anchor are mutually exclusive\n'
    exit 1
fi

# INTERPRETER RESOLUTION, AND WHY IT DIFFERS FROM install_runtime_deps.sh's
# That script installs, and says that where the packages go is the caller's policy. This one runs
# the artefact, and an interpreter that cannot import the verifier is a failure the caller cannot
# fix by policy. So: $PYTHON if set, else the repository virtualenv if one exists, else python3 —
# which is what CI gets, because .venv/ is gitignored and never exists on a runner. The chosen
# interpreter is printed on every run, so the resolution is never a guess a reader has to make.
#
# ONE WSL2 SUBTLETY, RECORDED BECAUSE IT COULD MASK A REAL FAILURE.
# On WSL2 the repository is reached through /mnt/c, so a virtualenv built on the Windows side is
# visible from the Linux side -- and .venv/Scripts/python.exe is executable there, because WSL2
# registers a binfmt handler for Windows executables. The resolution order below therefore falls
# through to a WINDOWS interpreter when no POSIX .venv/bin/python exists, and the gate passes. It
# is a genuine pass of the chain arithmetic, and the interpreter is printed on the summary line so
# the transcript never hides which one ran. What it is not is evidence about Linux: a
# platform-specific defect -- a path separator, a locale-dependent sort, a filesystem encoding --
# would be invisible. To test the Linux path, build a POSIX virtualenv and name it explicitly:
#   PYTHON=~/.venvs/agentic-overwatch/bin/python make audit-verify
# scripts/install_runtime_deps.sh prints those steps when it refuses an externally managed
# interpreter, which on Ubuntu is the first thing a developer hits.
#
# guardian/audit/ is standard library only, by design: the audit chain is the last thing that
# should acquire a dependency, because every digest in every sealed bundle is a claim about what
# that code did. So the import check below is a check that the repository root is importable, not
# that a package was installed.
if [ -n "${PYTHON:-}" ]; then
    python_bin=$PYTHON
elif [ -x .venv/bin/python ]; then
    python_bin=.venv/bin/python
elif [ -x .venv/Scripts/python.exe ]; then
    python_bin=.venv/Scripts/python.exe
else
    python_bin=python3
fi

if ! "$python_bin" -c "import $VERIFIER" >/dev/null 2>&1; then
    {
        printf 'audit-verify: %s cannot import %s.\n' "$python_bin" "$VERIFIER"
        echo "guardian/audit/ needs no third-party package, so this is a path problem rather than"
        echo "a missing dependency: run the gate from the repository root, or name an interpreter"
        echo "that can see it: PYTHON=<path> sh scripts/audit_verify.sh"
    } >&2
    printf 'audit-verify: FAIL — %s cannot import %s\n' "$python_bin" "$VERIFIER"
    exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
chains="$work/chains"
: > "$chains"

# --- enumerate the chains ----------------------------------------------------------------------
# A directory is walked for every file named guardian_audit.jsonl, which is the name
# docs/protocols/data-management.md section 1 fixes for it inside a run bundle, so pointing this at
# runs/ finds one per bundle and nothing else. A file is taken as given, whatever it is called, so
# that a developer can verify a copy without renaming it.
if [ -f "$target" ]; then
    printf '%s\n' "$target" >> "$chains"
elif [ -d "$target" ]; then
    find "$target" -type f -name "$CHAIN_FILENAME" | sort > "$chains"
else
    {
        printf 'audit-verify: FAIL — %s is neither a file nor a directory.\n' "$target"
        echo "Point the gate at a run bundle tree, a bundle, or one $CHAIN_FILENAME:"
        echo "  make audit-verify P=guardian/audit/fixtures/clean"
        echo "  make audit-verify P=runs/<campaign>/<run-id>/$CHAIN_FILENAME"
        if [ "$target" = "$DEFAULT_PATH" ]; then
            echo
            echo "$DEFAULT_PATH is gitignored and is not created until M6 seals the first bundle,"
            echo "so the default invocation is expected to fail until then. That is the honest"
            echo "answer: the alternative is a target that reports success having verified nothing."
        fi
    } >&2
    printf 'audit-verify: FAIL — no such path %s\n' "$target"
    exit 1
fi

chain_total=$(awk 'END { print NR }' "$chains")

if [ "$chain_total" -eq 0 ]; then
    {
        printf 'audit-verify: FAIL — %s holds no %s.\n' "$target" "$CHAIN_FILENAME"
        echo "An empty path is refused rather than verified successfully. This gate runs at M7's"
        echo "daily QA cadence over bundles nobody re-reads by hand, and a gate that passes over"
        echo "nothing is byte-identical, in a log, to one that passes over everything."
        if [ "$target" = "$DEFAULT_PATH" ]; then
            echo
            echo "$DEFAULT_PATH is gitignored and stays empty until M6 seals the first bundle, so"
            echo "the default invocation is expected to fail until then. At M3 point it at the"
            echo "committed corpus:"
            echo "  make audit-verify P=guardian/audit/fixtures/clean"
        fi
    } >&2
    printf 'audit-verify: FAIL — no %s under %s\n' "$CHAIN_FILENAME" "$target"
    exit 1
fi

# One head anchors one chain. Applying a single HEAD across a walk would compare every bundle's
# chain against one bundle's head and report every other bundle as truncated, which is a false
# alarm manufactured by the gate itself — the exact failure mode ADR-022 spends its Context section
# arguing against.
if [ -n "$head_anchor" ] && [ "$chain_total" -gt 1 ]; then
    {
        printf 'audit-verify: FAIL — HEAD anchors one chain, but %s holds %s.\n' \
            "$target" "$chain_total"
        echo "Each bundle records its own head in its own seal.json, which is found automatically"
        echo "when the walk reaches it. Name a single $CHAIN_FILENAME to use HEAD explicitly."
    } >&2
    printf 'audit-verify: FAIL — HEAD supplied for %s chain(s)\n' "$chain_total"
    exit 1
fi

# --- verify ---------------------------------------------------------------------------------
# The argument list is built with `set --` rather than by interpolating a string, so a path holding
# a space is passed as one argument instead of two. Nothing in this repository has such a path
# today; runs/ will hold operator-chosen campaign names.
set --
if [ -n "$head_anchor" ]; then
    set -- "$@" --head "$head_anchor"
fi
if [ "$no_anchor" -eq 1 ]; then
    set -- "$@" --no-anchor
fi
if [ "$replay" -eq 1 ]; then
    set -- "$@" --replay
fi
while IFS= read -r chain; do
    [ -n "$chain" ] || continue
    set -- "$@" "$chain"
done < "$chains"

machine="$work/machine"
verifier_rc=0
"$python_bin" -m "$VERIFIER" "$@" > "$machine" 2>"$work/detail" || verifier_rc=$?

cat "$work/detail" >&2
# The verifier writes its replay history to stdout, where the machine lines also go. Forward
# everything that is not a machine line to stderr, so stdout keeps to exactly one summary line and
# the history is still shown. awk rather than grep -v, because grep exits 1 when it matches nothing
# and this script runs under set -e.
awk '$1 != "audit-chain:"' "$machine" >&2

figures=$(awk '
    $1 == "audit-chain:" {
        chains++
        records = 0; findings = 0; anchor = ""
        for (i = 2; i <= NF; i++) {
            eq = index($i, "=")
            if (eq <= 0) { continue }
            k = substr($i, 1, eq - 1)
            v = substr($i, eq + 1)
            if (k == "records")  { records  = v + 0 }
            if (k == "findings") { findings = v + 0 }
            if (k == "anchor")   { anchor   = v }
        }
        total_records += records
        if (anchor != "none") { anchored++ }
        if (findings > 0)     { failed++ }
    }
    END { printf "%d %d %d %d", chains, failed, total_records, anchored }' "$machine")

set -- $figures
reported=$1
failed=$2
records=$3
anchored=$4

# The verifier reporting on fewer chains than were handed to it would mean a chain vanished between
# enumeration and verification. It cannot happen through any path this script takes, which is
# exactly why it is worth one line: a silent shortfall here would look like a clean run.
if [ "$reported" -ne "$chain_total" ]; then
    printf 'audit-verify: FAIL — %s chain(s) enumerated but %s reported on\n' \
        "$chain_total" "$reported" >&2
    printf 'audit-verify: FAIL — %s of %s chain(s) reported on\n' "$reported" "$chain_total"
    exit 1
fi

unanchored=$((chain_total - anchored))
if [ "$unanchored" -gt 0 ]; then
    anchor_note=$(printf '%s of %s chain(s) verified WITHOUT a head anchor, so tail truncation and whole-chain rewrite were NOT tested on them' "$unanchored" "$chain_total")
else
    anchor_note=$(printf 'all %s chain(s) anchored to a recorded head, so tail truncation and whole-chain rewrite were tested' "$chain_total")
fi

if [ "$failed" -gt 0 ] || [ "$verifier_rc" -ne 0 ]; then
    {
        echo
        printf 'audit-verify: FAIL — %s of %s chain(s) did not verify.\n\n' "$failed" "$chain_total"
        echo "Each finding above carries the seq where the break is and the one-based file line the"
        echo "record sits on; they are different numbers because seq is zero-based, and both are"
        echo "printed so nobody has to convert. Read the finding before touching the file: an"
        echo "append-only log that stopped verifying is either evidence of tampering or evidence"
        echo "that something wrote to it that should not have, and both are findings."
    } >&2
    printf 'audit-verify: FAIL — %s of %s chain(s) broken over %s record(s) in %s; %s (interpreter %s)\n' \
        "$failed" "$chain_total" "$records" "$target" "$anchor_note" "$python_bin"
    exit 1
fi

printf 'audit-verify: PASS — %s chain(s), %s record(s) verified in %s; %s (interpreter %s)\n' \
    "$chain_total" "$records" "$target" "$anchor_note" "$python_bin"
exit 0
