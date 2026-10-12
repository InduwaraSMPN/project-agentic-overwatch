#!/bin/sh
# analyze.sh — regenerate every table and figure from raw bundles, and write the synthetic proof.
#
# WHAT THIS GATE IS
# The thin delegator behind `make analyze`, and the executable form of `data-management.md` §8's
# reproducibility line: "`make analyze` on a clean checkout + `runs/` copy regenerates every table
# and figure (T-25)". It runs `python -m analysis.render`, which reads a campaign through
# `analysis/stats/` (raw bundle files only, never `metrics.json`, never a live service), computes
# every Table 3.4 measure and every origin:engineering instrument, pools each per scenario and per
# condition, forms the RQ2/RQ5 matched-pairs contrasts, writes the tables and figures under the
# campaign's own gitignored `runs/<CAMP>/_analysis/`, and — over a synthetic campaign — writes
# `analysis/.synthetic-proof.json`. Logic lives in Python; this script only locates the interpreter
# and forwards its arguments, matching the pattern `docs/04-repo-conventions.md` §1 fixes and every
# prior milestone follows.
#
# WHY THE PROOF MATTERS, AND WHY THIS IS SEPARATE FROM `make campaign`
# The proof sentinel is the pre-registration lock. `make campaign`'s preflight refuses to start when
# it is absent or when its recorded commit no longer matches the tree about to produce real data
# (M6 plan §"T6.6 is a preflight gate, not a task that merely happened first"). This target produces
# that lock; the campaign target consumes it. Keeping them apart means the proof can be regenerated
# — after any change to the analysis — without starting a campaign, which is exactly the discipline
# T6.6 is for.
#
# ARGUMENTS
# Every argument is forwarded verbatim to `python -m analysis.render`: `--campaign <dir>` to analyse
# a named campaign (default: the sole `CAMP-*-synthetic` under `runs/`), `--out-dir <dir>` to
# redirect the output, `--generator-seed <n>` to record the corpus seed in the proof, `--no-proof`
# to skip the sentinel. With no arguments it analyses the synthetic corpus and writes the proof.
#
# STREAMS AND EXIT CODES
# stdout carries one summary line, `analyze: PASS — ...` or `analyze: FAIL — ...`. stderr carries
# any diagnostic from the render (an absent corpus, an empty contrast, an unresolved HEAD). Exit 0
# on success, 1 on any failure — including an empty campaign or a contrast that formed no pairs,
# which are refused rather than passed.
#
# PORTABILITY
# Strict POSIX sh — no bashisms, no GNU-only options, no jq. Runs under dash in WSL2 Ubuntu, under
# Git Bash on Windows, and on ubuntu-latest.
#
# WHAT BREAKS IF THIS FILE CHANGES
# T-25 (the analysis regenerates every table and figure) and the `make campaign` preflight gate that
# reads the proof this target writes. The statistics are not here and must not move here; this file
# is a delegator, and `analysis/stats/` is where a measure is defined and tested. ADR-042 (the
# synthetic corpus and the campaign preflight gate).

set -eu

LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

# Interpreter resolution, identical to scripts/monitor_determinism.sh's and explained there: $PYTHON
# if set, else the repository virtualenv if one exists, else python3 — which is what CI gets, because
# .venv/ is gitignored and never exists on a runner.
if [ -n "${PYTHON:-}" ]; then
    python_bin=$PYTHON
elif [ -x .venv/bin/python ]; then
    python_bin=.venv/bin/python
elif [ -x .venv/Scripts/python.exe ]; then
    python_bin=.venv/Scripts/python.exe
else
    python_bin=python3
fi

if ! "$python_bin" -c 'import analysis.render' >/dev/null 2>&1; then
    {
        printf 'analyze: %s cannot import analysis.render.\n' "$python_bin"
        echo "Install the pinned runtime dependencies with: sh scripts/install_runtime_deps.sh"
        echo "Or: PYTHON=<path> sh scripts/analyze.sh"
    } >&2
    printf 'analyze: FAIL — %s cannot import analysis.render\n' "$python_bin"
    exit 1
fi

# Delegate. The render prints its own PASS/FAIL summary line to stdout and returns 0/1; this script
# forwards both, so the one-line contract is the Python's and there is exactly one place it is set.
if [ -n "${C:-}" ]; then
    set -- --campaign "$C" "$@"
fi
"$python_bin" -m analysis.render "$@"
