#!/bin/sh
# fidelity_check.sh -- the CI-safe synthetic treatment-fidelity check (M10 plan P4, §5; ADR-120).
#
# WHAT THIS IS
# The synthetic half of the known-bad proof: it runs the treatment-fidelity registry
# (runner/fidelity/) over a SYNTHETIC corpus, needing no cluster and no v1 run bundles, so P0-offline
# and CI can prove the checks work without the 4 GB v1 campaign. Its sibling scripts/known_bad_replay.sh
# runs the same registry over the real v1 corpus locally. Both wrap `python -m runner.fidelity`, which
# is the gate's without-make entry point (docs/04-repo-conventions.md); the logic is the registry's,
# never this shell's.
#
# WHAT IT ACTUALLY RUNS, AND WHY THAT IS THE SYNTHETIC-DEFECT PROOF
# By default it evaluates the registry at the `offline` stage. The offline-stage checks (F-SC-03a,
# F-SC-04, F-SC-05 and their kin, M10 plan §5) each build their OWN passing and failing synthetic
# fixtures and assert the predicate discriminates -- so a green offline run is exactly "every offline
# check can both pass and fail on a synthetic defect", which is what P4 asks CI to carry. The
# per-defect known-bad REPLAY over synthetic bundles is exercised in full by
# runner/tests/test_fidelity_known_bad.py (the runner suite ci.yml runs); set KNOWN_BAD=1 to run that
# replay through this wrapper -- it builds the per-defect corpus itself (from that test module's
# build_known_bad_corpus) when no CORPUS is given, and evaluates every stage, because the defects are
# spread across stages. Two checks are not provable by any sealable bundle (F-SC-03a, a
# repository-content meta-check; F-SC-03b, vacuous as written), so a KNOWN_BAD=1 run reports exactly
# those two as MISSING and exits non-zero until they are fixed; the DEFAULT (no KNOWN_BAD) gate run is
# the one that is green in CI.
#
# WHERE THE SYNTHETIC CORPUS COMES FROM
# `python -m runner.fidelity` needs a corpus directory to iterate. This script resolves one, in order:
#   1. $CORPUS, if set -- the researcher points it at a specific corpus (a per-defect one for
#      KNOWN_BAD=1, say).
#   2. the newest runs/CAMP-*-synthetic already on disk -- what `make analyze`'s corpus generator
#      (runner.synthetic) leaves behind, reused so a local run costs nothing.
#   3. a fresh synthetic corpus built into a temp directory with `python -m runner.synthetic`
#      (stdlib-only, no cluster), removed on exit -- which is the path CI takes, since runs/ is
#      gitignored and empty on a runner.
#
# STREAMS AND EXIT CODES
# `python -m runner.fidelity` prints one machine-readable summary line on stdout and diagnostics on
# stderr; this script forwards both and its exit code. Exit 0 on a clean verdict, 1 on a blocking one
# (and, under KNOWN_BAD=1, 0 exactly when every expected flag was raised). Strict POSIX sh.
#
# ENVIRONMENT
#   CORPUS=<dir>   evaluate this corpus instead of a synthetic one. Optional under KNOWN_BAD=1: with
#                  no CORPUS the wrapper builds the per-defect known-bad corpus itself; a CLEAN corpus
#                  under KNOWN_BAD=1 flags nothing and fails, so only pass one that carries defects.
#   STAGE=<stage>  the fidelity stage to evaluate (default: offline). Ignored under KNOWN_BAD=1, which
#                  evaluates every stage.
#   KNOWN_BAD=1    run the known-bad replay (exit 0 = every expected flag raised) instead of the gate.
#   SEED=<n>       the seed for a freshly built synthetic corpus (default: a fixed value; the offline
#                  checks are seed-independent, so this only names the generated corpus).
#   PYTHON=<path>  the interpreter to use.
#
# WHAT BREAKS IF THIS FILE CHANGES
# `make fidelity-check` and ci.yml's hygiene synthetic-fidelity step. The registry and its stages are
# runner/fidelity/'s; this file only points them at a corpus. ADR-120.

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

stage=${STAGE:-offline}
seed=${SEED:-20260926}

# Temp directory cleaned on exit; only used when a corpus has to be built (path 3 below).
work=""
cleanup() { [ -n "$work" ] && rm -rf "$work"; return 0; }
trap cleanup EXIT HUP INT TERM

corpus=""
if [ -n "${CORPUS:-}" ]; then
    corpus=$CORPUS
    if [ ! -d "$corpus" ]; then
        echo "fidelity-check: CORPUS=$corpus is not a directory" >&2
        exit 1
    fi
elif [ "${KNOWN_BAD:-0}" = "1" ]; then
    # KNOWN_BAD=1 with no explicit CORPUS: build the PER-DEFECT known-bad corpus -- one minimal
    # bundle per coverable check, each breaking exactly the property that check guards. A clean
    # synthetic corpus (paths 2 and 3 below) would flag nothing and make the replay FAIL, which is the
    # trap the module docstring warns about; the per-defect corpus is the one a known-bad replay needs.
    # The builders live in runner/tests/test_fidelity_known_bad.py (the CI-safe per-defect proof, P4);
    # the registry is still what evaluates. Two registry checks cannot be flipped by any sealable
    # bundle -- F-SC-03a (a repository-content meta-check) and F-SC-03b (vacuous as written: a
    # payload_outcome list/object schema mismatch) -- so this replay reports exactly those two as
    # MISSING until they are fixed. That is the honest state, not a bug in this wrapper.
    work=$(mktemp -d)
    corpus="$work/CAMP-known-bad-synthetic"
    echo "fidelity-check: KNOWN_BAD=1 with no CORPUS; building the per-defect corpus under a temp dir" >&2
    if ! "$python_bin" -c 'import sys; from pathlib import Path; from runner.tests.test_fidelity_known_bad import build_known_bad_corpus; build_known_bad_corpus(Path(sys.argv[1]))' "$corpus" >&2; then
        echo "fidelity-check: FAIL — could not build the per-defect known-bad corpus" >&2
        exit 1
    fi
else
    # Newest existing runs/CAMP-*-synthetic, if any. A for-loop over the glob rather than parsing ls,
    # so a name with an odd character cannot mislead the choice; the date in the id sorts lexically.
    for candidate in runs/CAMP-*-synthetic; do
        [ -d "$candidate" ] && [ -f "$candidate/campaign.json" ] && corpus=$candidate
    done
    if [ -z "$corpus" ]; then
        # Path 3: build one. runner.synthetic is stdlib-only, so this works on a bare CI runner with
        # no runtime dependencies installed and no cluster.
        work=$(mktemp -d)
        echo "fidelity-check: no synthetic corpus on disk; building one under a temp dir" >&2
        if ! "$python_bin" -m runner.synthetic --seed "$seed" --out-root "$work" >&2; then
            echo "fidelity-check: FAIL — could not build a synthetic corpus" >&2
            exit 1
        fi
        for candidate in "$work"/CAMP-*-synthetic; do
            [ -d "$candidate" ] && corpus=$candidate
        done
        if [ -z "$corpus" ]; then
            echo "fidelity-check: FAIL — runner.synthetic wrote no CAMP-*-synthetic corpus" >&2
            exit 1
        fi
    fi
fi

echo "fidelity-check: evaluating stage '$stage' over $corpus" >&2

set -- --campaign-dir "$corpus" --stage "$stage" --no-ledger
if [ "${KNOWN_BAD:-0}" = "1" ]; then
    set -- "$@" --known-bad
fi

exec "$python_bin" -m runner.fidelity "$@"
