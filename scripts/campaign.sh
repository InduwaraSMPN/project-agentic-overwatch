#!/bin/sh
# campaign.sh — `make campaign`'s delegator: validate the grid, order it, gate the start.
#
# WHAT THIS SCRIPT IS
# The entry point for `make campaign M=<campaign-manifest>`. The logic lives in
# runner/campaign_cli.py, which validates the manifest against the §2 grid arithmetic, runs the
# preflight -- `make status`, `make parity-check`, `make determinism-check` and the synthetic-proof
# gate (ADR-042) -- and produces the interleaved run order. It refuses to start the campaign when any
# preflight gate fails, because a campaign is the dissertation's evidence and M6 freezes behaviour at
# v1.0-rc.
#
# THE MEASUREMENT WINDOW
# A live campaign takes exactly one of DURATION or SAMPLES and refuses without one, exactly as
# scripts/run.sh and scripts/baseline.sh require for a single run. runner/campaign_cli.py's live
# branch builds MeasurementWindow(samples=args.samples, duration_seconds=args.duration) straight from
# --samples/--duration, and that class's own contract is "exactly one form is required and neither
# has a default" (runner/live_baseline.py) -- so the caller supplies it and this script only forwards
# it. Until this forwarding existed, `make campaign` could not start a live campaign at all: every
# invocation reached that check with neither flag and died on "exactly one of samples and
# duration_seconds must be supplied", which main() re-raises as "live campaign execution requires
# exactly one of --samples or --duration" -- a bad-coordinate reading, not a missing-parameter one.
# OFFLINE=1 ignores DURATION and SAMPLES the same way scripts/run.sh's offline branch does --
# silently, not a refusal -- because an offline campaign never reaches the live branch that needs a
# window; forwarding them anyway would only trip runner/campaign_cli.py's own offline check
# ("--samples/--duration apply only to live campaign execution").
#
# STREAMS AND EXIT CODES
# One summary line; exit 0 when the manifest validated, the preflight cleared and the order was
# generated, 1 otherwise. Strict POSIX sh.
#
# WHAT BREAKS IF THIS FILE CHANGES
# `make campaign`. ADR-041, ADR-042.

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

set -- --manifest "${M:?M=<campaign-manifest> is required}" --execute
if [ -n "${PILOT_KIND:-}" ]; then set -- "$@" --pilot-kind "$PILOT_KIND"; fi
if [ "${OFFLINE:-0}" = "1" ]; then
    # DURATION/SAMPLES are silently unused here, the same way scripts/run.sh's offline branch
    # never examines them: an offline campaign never reaches the live branch that needs a window.
    set -- "$@" --offline --skip-preflight
elif [ -n "${DURATION:-}" ] && [ -n "${SAMPLES:-}" ]; then
    echo "campaign: set exactly one of DURATION or SAMPLES for a live campaign" >&2
    exit 1
elif [ -n "${DURATION:-}" ]; then
    set -- "$@" --duration "$DURATION"
elif [ -n "${SAMPLES:-}" ]; then
    set -- "$@" --samples "$SAMPLES"
else
    echo "campaign: a live campaign requires caller-supplied DURATION or SAMPLES" >&2
    exit 1
fi
if [ -n "${TIMEOUT:-}" ]; then set -- "$@" --timeout "$TIMEOUT"; fi
if [ -n "${MAX_ATTEMPTS:-}" ]; then set -- "$@" --max-attempts "$MAX_ATTEMPTS"; fi
exec "$python_bin" -m runner.campaign_cli "$@"
