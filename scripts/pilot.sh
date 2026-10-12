#!/bin/sh
# pilot.sh -- `make pilot-<stage>`'s delegator: drive one step of the M10 pilot ladder (§6; ADR-120).
#
# WHAT THIS IS
# The without-make entry point for the pilot ladder. It dispatches
#     sh scripts/pilot.sh <stage>   ->   python -m runner.pilot_cli <stage> ...
# and nothing more: the ladder's state machine, its freeze enforcement and its gate decision all live
# in runner/pilot_cli.py (M10 plan §6). This script only resolves the interpreter, supplies the
# ladder's state directory, and forwards the stage-appropriate flags -- the pattern
# docs/04-repo-conventions.md §1 fixes and every prior gate follows.
#
# STAGES
#   p0 p0-live p1a p1b p2 p3   record a ladder stage on the current instrument (runner.pilot_cli
#                              refuses one out of order, and resets the ladder on an instrument change).
#   gate | decide              write gate_decision.json from the accumulated fidelity results; GO only
#                              when every class-T check is at 100%, no class-B/R failure, the ladder is
#                              complete and there are zero framework-attributable failures (§6). `gate`
#                              is accepted as the readable alias `make pilot-gate` uses; both map to the
#                              CLI's `decide` subcommand.
#   validate                   validate a pilot campaign manifest (and optionally one bundle).
#                              KIND=<cost|smoke|coverage> picks the validator (default: cost, so a
#                              bare `validate` still checks a cost-pilot manifest as it always did;
#                              ADR-136 names the three).
#
# ENVIRONMENT
#   STATE_DIR=<dir>            where ladder_state.json / gate_decision.json live (default: runs/_pilot,
#                              gitignored). One directory per pilot campaign; the ladder is keyed on the
#                              instrument digest inside it, not on this path.
#   FREEZE_TAG=<tag>           the freeze tag a ladder stage records/enforces (e.g. v2.0).
#   NO_FREEZE=1                skip the freeze check -- offline proofs and tests ONLY, never a live stage
#                              (runner.pilot_cli says the same).
#   FIDELITY=<path>            required for gate/decide: the fidelity.json (or a campaign dir holding
#                              one) the gate reads. FIDELITY2..FIDELITY5 name further campaign
#                              directories; the gate folds every source into one row per check with
#                              the worst status winning, because the pilot's evidence spans P1a, P1b,
#                              P2 and P3 as separate campaign ids that cannot share a directory
#                              (their run ids collide).
#   FRAMEWORK_FAILURES=<n>     gate/decide: the count classify_failure produced across P1-P3 (default 0).
#   MANIFEST=<path> BUNDLE=<path>   validate: the pilot manifest and an optional bundle.
#   KIND=<cost|smoke|coverage>      validate: which pilot validator to apply (default: cost).
#   PYTHON=<path>             the interpreter to use.
#
# STREAMS AND EXIT CODES
# runner.pilot_cli prints its own one-line PASS/FAIL (or GO/NO-GO) summary and returns 0/1; this
# script forwards both and its exit code. Strict POSIX sh.
#
# WHAT BREAKS IF THIS FILE CHANGES
# The `make pilot-*` targets. The ladder logic is runner/pilot_cli.py's; this only points it at a state
# directory and forwards flags. ADR-120, ADR-136.

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

stage=${1:-}
if [ -z "$stage" ]; then
    echo "usage: sh scripts/pilot.sh <p0|p0-live|p1a|p1b|p2|p3|gate|decide|validate>" >&2
    exit 2
fi
shift || true

state_dir=${STATE_DIR:-runs/_pilot}

# The gate needs at least one fidelity source, and the pilot's evidence normally spans several
# campaign ids (P1a, P1b, P2, P3), so FIDELITY..FIDELITY5 are all forwarded as repeated --fidelity
# and the gate folds them (runner.pilot_cli.read_checks). Checked here rather than left to argparse
# so the operator gets the variable name to set, not just the flag name.
if [ "${stage}" = "gate" ] || [ "${stage}" = "decide" ]; then
    if [ -z "${FIDELITY:-}" ]; then
        echo "pilot: FIDELITY=<fidelity.json or campaign dir> is required for the gate" \
            "(FIDELITY2..FIDELITY5 add the pilot's further campaign dirs)" >&2
        exit 2
    fi
fi

case "$stage" in
    gate|decide)
        set -- decide --state-dir "$state_dir" \
            --framework-failures "${FRAMEWORK_FAILURES:-0}" "$@"
        if [ -n "${FIDELITY:-}" ]; then set -- "$@" --fidelity "$FIDELITY"; fi
        if [ -n "${FIDELITY2:-}" ]; then set -- "$@" --fidelity "$FIDELITY2"; fi
        if [ -n "${FIDELITY3:-}" ]; then set -- "$@" --fidelity "$FIDELITY3"; fi
        if [ -n "${FIDELITY4:-}" ]; then set -- "$@" --fidelity "$FIDELITY4"; fi
        if [ -n "${FIDELITY5:-}" ]; then set -- "$@" --fidelity "$FIDELITY5"; fi
        ;;
    p0|p0-live|p1a|p1b|p2|p3)
        set -- "$stage" --state-dir "$state_dir" "$@"
        if [ -n "${FREEZE_TAG:-}" ]; then set -- "$@" --freeze-tag "$FREEZE_TAG"; fi
        if [ "${NO_FREEZE:-0}" = "1" ]; then set -- "$@" --no-freeze; fi
        ;;
    validate)
        set -- validate --manifest "${MANIFEST:?MANIFEST=<pilot manifest> is required for validate}" "$@"
        if [ -n "${KIND:-}" ]; then set -- "$@" --kind "$KIND"; fi
        if [ -n "${BUNDLE:-}" ]; then set -- "$@" --bundle "$BUNDLE"; fi
        ;;
    *)
        echo "pilot: unknown stage '$stage'; expected p0, p0-live, p1a, p1b, p2, p3, gate/decide or validate" >&2
        exit 2
        ;;
esac

exec "$python_bin" -m runner.pilot_cli "$@"
