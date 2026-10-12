#!/bin/sh
# readiness_gate.sh -- run the analysis readiness gate (F-AN-01) over a campaign (M10 plan §5; ADR-133).
#
# WHAT THIS GATE IS
# The thin delegator behind `make readiness-gate`, and the without-make entry point for F-AN-01: the
# readiness/provenance gate that asks whether every Table 3.3 measure has actually been computed
# before a corpus is read as evidence (M10 plan §5). The gate is a stage of `python -m analysis.render`
# -- render reads a campaign through analysis/stats/ (raw bundle files only, never metrics.json, never
# a live service), computes every measure, and evaluates readiness_gate() over the status lines it
# produced, writing runs/<CAMP>/_analysis/readiness_gate.md with the verdict. The gate LOGIC lives in
# analysis/render.py (readiness_gate / readiness_severity); this script only locates the interpreter
# and forwards arguments, matching the pattern docs/04-repo-conventions.md §1 fixes and scripts/analyze.sh
# follows.
#
# FINAL-CORPUS SEMANTICS, WHICH IS THE DEFAULT
# F-AN-01 has three readings (M10 plan §5): pilot gate, checkpoint, and final corpus. analysis.render
# evaluates at the FINAL-corpus stage by default -- the render a reader of the dissertation tables is
# looking at, and the only stage at which a still-pending judged measure is a FAIL -- which is the
# stage §10's Definition of done means by "`sh scripts/readiness_gate.sh` passes with final-corpus
# semantics". The pilot-gate and checkpoint readings are reached by the pilot ladder and the campaign
# checkpoint, which call the same render machinery with their own stage; this wrapper is the final one.
#
# ARGUMENTS
# C=<campaign> selects a campaign directory (default: the sole synthetic corpus under runs/, as
# scripts/analyze.sh does); STAGE=<pilot|checkpoint|final> selects which of F-AN-01's three
# semantics the gate is evaluated and recorded under (default: final, render's own default); every
# other argument is forwarded verbatim to `python -m analysis.render`.
#
# STREAMS AND EXIT CODES
# render prints its own one-line PASS/FAIL summary to stdout and writes the readiness_gate.md table
# with the verdict in its title; this script forwards render's stdout, stderr and exit code. Exit 0
# when the render (and so the readiness evaluation) completed; the gate's own verdict is recorded in
# readiness_gate.md and the run manifest's status lines. Strict POSIX sh.
#
# WHAT BREAKS IF THIS FILE CHANGES
# `make readiness-gate` and the §10 DoD line. The statistics and the readiness verdict are
# analysis/stats/ and analysis/render.py's and must not move here; this file is a delegator. ADR-133.

set -eu

LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

# Interpreter resolution, identical to scripts/analyze.sh's: $PYTHON if set, else the repository
# virtualenv if one exists, else python3 -- which is what CI gets, because .venv/ is gitignored.
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
        printf 'readiness-gate: %s cannot import analysis.render.\n' "$python_bin"
        echo "Install the pinned runtime dependencies with: sh scripts/install_runtime_deps.sh"
        echo "Or: PYTHON=<path> sh scripts/readiness_gate.sh"
    } >&2
    printf 'readiness-gate: FAIL — %s cannot import analysis.render\n' "$python_bin"
    exit 1
fi

# Delegate. render prints its own PASS/FAIL summary line and returns 0/1; this script forwards both,
# so the one-line contract is the Python's and there is exactly one place it is set. C=<campaign> and
# STAGE=<pilot|checkpoint|final> are spliced ahead of any forwarded arguments, exactly as
# scripts/analyze.sh does it; an unset STAGE leaves render on its own `final` default.
if [ -n "${C:-}" ]; then
    set -- --campaign "$C" "$@"
fi
if [ -n "${STAGE:-}" ]; then
    set -- --readiness-stage "$STAGE" "$@"
fi
exec "$python_bin" -m analysis.render "$@"
