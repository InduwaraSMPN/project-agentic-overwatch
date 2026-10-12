#!/bin/sh
# baseline.sh — `make baseline`'s delegator: one framework-off baseline to a sealed bundle.
#
# WHAT THIS SCRIPT IS
# The entry point for `make baseline LOAD=<id> SEED=<n> CAMP=<id>`. A baseline is a separate target
# from `run`, not a mode flag on it, because it occupies no arm, no scenario and no injection
# condition and its parameter set is disjoint (T6.1; the Makefile's own comment). LOAD resolves
# through infra/locust/registry.py and nothing else. The logic lives in runner/baseline.py.
#
# TIER B
# The live path needs M1's cluster (the load driver and the two M1 collectors). Pass OFFLINE=1 to
# write deterministic probe/resource/locust series and seal, exercising the baseline completeness
# profile -- the five required files and the nine asserted absent -- without a cluster.
#
# STREAMS AND EXIT CODES
# One summary line; exit 0 on a sealed baseline, 1 on an unknown load profile or a bundle that would
# not seal. Strict POSIX sh.
#
# WHAT BREAKS IF THIS FILE CHANGES
# `make baseline`. ADR-040.

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
if [ "${OFFLINE:-}" = "1" ]; then
    offline_flag="--offline"
elif [ -n "${DURATION:-}" ] && [ -n "${SAMPLES:-}" ]; then
    echo "baseline: set exactly one of DURATION or SAMPLES for a live baseline" >&2
    exit 1
elif [ -n "${DURATION:-}" ]; then
    window_flag="--duration"
    window_value=$DURATION
elif [ -n "${SAMPLES:-}" ]; then
    window_flag="--samples"
    window_value=$SAMPLES
else
    echo "baseline: a live baseline requires caller-supplied DURATION or SAMPLES" >&2
    exit 1
fi

exec "$python_bin" -m runner.baseline \
    --load "${LOAD:?LOAD is required}" \
    --seed "${SEED:?SEED is required}" \
    --campaign "${CAMP:?CAMP is required}" \
    $offline_flag $window_flag $window_value
