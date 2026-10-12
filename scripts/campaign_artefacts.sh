#!/bin/sh
# campaign_artefacts.sh -- write the WS-6 campaign-level fidelity artefacts (M10 plan §5; ADR-150).
#
# WHAT THIS WRITES
# The four campaign-level roll-ups the fidelity checks read but no bundle carries:
#   vacuity.json                F-AN-02   the symmetric vacuity tripwire over the campaign's runs
#   injection_base_rates.json   F-SC-03b  the per-arm INJ-NONE base rate of each payload's induced action
#   payload_coverage.json       F-SC-04   per-class payload coverage (offline round trip + live INJ-B)
#   assertion_availability.json F-SC-05   the assertion-failability audit over the ground truth
# The producer LOGIC lives in analysis/stats/campaign_artefacts.py; this script only locates the
# interpreter and forwards the campaign directories, matching the pattern
# docs/04-repo-conventions.md §1 fixes and scripts/readiness_gate.sh follows. readiness.json
# (F-AN-01) is NOT written here: it is a stage of `python -m analysis.render` (see
# scripts/readiness_gate.sh), which already computes the readiness report.
#
# WHY SEVERAL CAMPAIGNS
# The pilot's evidence is spread across campaign ids -- P0-live probes, P2, P3 -- and these artefacts
# are properties of the PILOT, so the bundles of every named directory are unioned, the four
# documents are computed once over the union, and the same documents are written into each directory.
# That is what lets the pilot gate point at whichever pilot campaign directory it was given and still
# read the whole pilot's verdict (INJ-B's coverage comes from P0-live; INJ-A/C/D's from the offline
# round trip; the vacuity and base-rate roll-ups are stated "across the pilot").
#
# ARGUMENTS AND ENVIRONMENT
# C=<campaign>       the campaign directory the gate will read; required.
# C2=<campaign>      C3= C4= C5=   optional further pilot campaign directories to union in (the
#                    pilot's evidence spans P0-live, P1a, P1b, P2 and P3).
# PYTHON=<path>      the interpreter to use.
#
# STREAMS AND EXIT CODES
# python -m analysis.stats.campaign_artefacts prints one line per file written and returns 0/1; this
# script forwards both and its exit code. Strict POSIX sh.
#
# WHAT BREAKS IF THIS FILE CHANGES
# `make campaign-artefacts` and the pilot gate's input. The roll-ups are analysis/stats/'s and must
# not move here; this file is a delegator. ADR-150, ADR-146.

set -eu

LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

# Interpreter resolution, identical to scripts/readiness_gate.sh's: $PYTHON if set, else the
# repository virtualenv if one exists, else python3 -- which is what CI gets (.venv/ is gitignored).
if [ -n "${PYTHON:-}" ]; then
    python_bin=$PYTHON
elif [ -x .venv/bin/python ]; then
    python_bin=.venv/bin/python
elif [ -x .venv/Scripts/python.exe ]; then
    python_bin=.venv/Scripts/python.exe
else
    python_bin=python3
fi

if ! "$python_bin" -c 'import analysis.stats.campaign_artefacts' >/dev/null 2>&1; then
    {
        printf 'campaign-artefacts: %s cannot import analysis.stats.campaign_artefacts.\n' "$python_bin"
        echo "Install the pinned runtime dependencies with: sh scripts/install_runtime_deps.sh"
        echo "Or: PYTHON=<path> sh scripts/campaign_artefacts.sh"
    } >&2
    printf 'campaign-artefacts: FAIL — %s cannot import the producer\n' "$python_bin"
    exit 1
fi

if [ -z "${C:-}" ]; then
    echo "usage: C=<campaign> [C2=<campaign> C3=<campaign>] sh scripts/campaign_artefacts.sh" >&2
    exit 2
fi

# Build the --campaign list: C is required, C2..C5 are the optional extra pilot corpora. The order is
# fixed (C, C2, C3, C4, C5) so the invocation is reproducible.
set -- --campaign "$C"
if [ -n "${C2:-}" ]; then set -- "$@" --campaign "$C2"; fi
if [ -n "${C3:-}" ]; then set -- "$@" --campaign "$C3"; fi
if [ -n "${C4:-}" ]; then set -- "$@" --campaign "$C4"; fi
if [ -n "${C5:-}" ]; then set -- "$@" --campaign "$C5"; fi

exec "$python_bin" -m analysis.stats.campaign_artefacts "$@"
