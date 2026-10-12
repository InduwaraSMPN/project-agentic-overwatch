#!/bin/sh
# run.sh — `make run`'s delegator: one grid run to a sealed bundle.
#
# WHAT THIS SCRIPT IS
# The one-line entry point docs/04-repo-conventions.md section 3 contracts for `make run COND=<id>
# SCN=<id> INJ=<id> SEED=<n> CAMP=<id>`. The logic lives in runner/run.py so it is testable without
# make; this script only resolves the interpreter and forwards the four grid coordinates plus the
# campaign id. The four parameters are exactly the four the run identifier carries, so the CLI can
# address all 750 grid cells (T6.1).
#
# TIER B
# The live run path needs M1's cluster and M4's agents. Pass OFFLINE=1 to exercise the pipeline with
# deterministic telemetry and no cluster, which is what proves the seal-and-validate path at Tier A.
#
# THE MEASUREMENT WINDOW
# A live run takes exactly one of DURATION or SAMPLES and refuses without one, exactly as
# scripts/baseline.sh does. runner/run.py builds no default: "no duration exists outside the
# evaluation protocol", so the caller supplies it and this script only forwards it. Until this
# forwarding existed, `make run` could not start a live run at all -- every invocation reached
# runner/run.py with no window and died on "exactly one of samples and duration_seconds must be
# supplied", which reads as a bad coordinate rather than a missing parameter.
#
# THE P0-LIVE PROBE MODE
# INSTRUMENT_ONLY=1 forwards runner/run.py's --instrument-only (M10 plan section 6, WS-5), the mode
# the P0-live instrument probes run in: the condition flags are applied, the scenario and its
# injections execute, the Monitor evidence and the API-server audit are collated, and NO agent graph
# runs, so the bundle seals under the probe completeness profile. It is a LIVE mode and still takes
# DURATION or SAMPLES; runner/run.py refuses it together with --offline.
#
# STREAMS AND EXIT CODES
# runner/run.py prints one summary line and exits 0 on a sealed bundle, 1 on a bad coordinate, a
# failed preflight, or a bundle that would not seal. Strict POSIX sh.
#
# WHAT BREAKS IF THIS FILE CHANGES
# `make run`. The invocation contract is docs/04-repo-conventions.md section 3; ADR-040.

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

offline_flag=""
window_flag=""
window_value=""
instrument_flag=""
if [ "${OFFLINE:-}" = "1" ]; then
    offline_flag="--offline"
elif [ -n "${DURATION:-}" ] && [ -n "${SAMPLES:-}" ]; then
    echo "run: set exactly one of DURATION or SAMPLES for a live run" >&2
    exit 1
elif [ -n "${DURATION:-}" ]; then
    window_flag="--duration"
    window_value=$DURATION
elif [ -n "${SAMPLES:-}" ]; then
    window_flag="--samples"
    window_value=$SAMPLES
else
    echo "run: a live run requires caller-supplied DURATION or SAMPLES" >&2
    exit 1
fi

# INSTRUMENT_ONLY=1 selects the P0-live probe profile (M10 plan section 6, WS-5): the scenario and
# its injections run and the evidence is collated, but NO agent graph runs, and the bundle seals
# under the probe completeness profile. It is a LIVE mode, so it still needs DURATION or SAMPLES --
# runner/run.py refuses it together with --offline rather than sealing a probe that measured nothing.
if [ "${INSTRUMENT_ONLY:-}" = "1" ]; then
    instrument_flag="--instrument-only"
fi

exec "$python_bin" -m runner.run \
    --cond "${COND:?COND is required}" \
    --scn "${SCN:?SCN is required}" \
    --inj "${INJ:?INJ is required}" \
    --seed "${SEED:?SEED is required}" \
    --campaign "${CAMP:?CAMP is required}" \
    $offline_flag $window_flag $window_value $instrument_flag
