#!/bin/sh
# parity_check.sh — the CI-blocking prompt and tool parity gate (`make parity-check`).
#
# WHAT THIS GATE IS
# docs/protocols/prompt-parity-policy.md section 1 states the reason it exists: "The ablation claims
# are only valid if conditions differ solely in the manipulated variable (topology, or guardrail
# arm). Prompts, tools, and instruction budgets must be matched; this protocol makes that a
# machine-checked invariant instead of an intention." Section 3 specifies the check, and
# agents/registry/parity.py implements it. This script is the one-line delegator
# docs/04-repo-conventions.md section 1 requires — "every gate's logic lives in scripts/" — and
# `make parity-check` delegates to it, as does .github/workflows/ci.yml's guardrail-grep job.
#
# WHY THE CHECKER IS NOT UNDER analysis/, WHICH ITS OWN SPEC HEADING NAMES
# Section 3 heads itself "spec for `analysis/stats/parity_check.py`", and that home contradicts two
# other binding documents. docs/protocols/data-management.md section 8 binds analysis/ to read
# "only runs/ raw files (never metrics.json caches, never live services)" — a parity check reads
# agents/ and no bundle at all, so it would be the first breach of that section in the repository.
# And the deciding argument is neither of those: the check must count exactly the bytes the graph
# sends, so the composer is agent-layer code shared by the gate and the runtime, and a checker with
# its own rendering path would measure a prompt no run ever used. That is conflict M4-C2; ADR-027
# records it and section 3's path is corrected to name agents/registry/.
#
# WHY THIS SCRIPT INSTALLS NOTHING, AND WHY THAT IS A REQUIREMENT RATHER THAN A PREFERENCE
# ci.yml runs this inside the `guardrail-grep` job, which checks out the repository, runs shell
# scripts, and installs nothing at all. Conflict M4-C1: a parity checker with a third-party
# dependency would fail there for a dependency reason before it could fail for a code reason —
# exactly the shape ADR-025 records for M3's two guards tripping together. ADR-025's own resolution
# was "a gate script acquires what it needs", and that alternative is rejected here: a `pip install`
# inside a grep job puts a package index on the critical path of a check that should take a second,
# and makes the verdict depend on network reachability. So agents/registry/ is standard-library only
# — no YAML parser, no validation library, no tokenizer distribution — and this script needs a
# Python interpreter and nothing else. ADR-028.
#
# THE GATE FAILS CLOSED, WHICH IS THE ASYMMETRY WITH THE TWO GREP GUARDS BESIDE IT
# scripts/grep_guard.sh and scripts/monitor_guard.sh may pass vacuously and say so, because each is
# a prohibition: nothing found means nothing violated. Parity is an equality, so nothing found means
# nothing PROVED — and a green check over an absent registry would make deleting the registry the
# easiest way to pass the gate. agents/registry/parity.py therefore exits non-zero, with a named
# reason, when a condition has no composition manifest, when the structural-block cap in section 3
# is still the PENDING sentinel, or when a declared budget is missing. There is deliberately no
# --allow-empty and no environment variable that turns an assertion off.
#
# THE TOLERANCE IS NEVER LOOSENED TO MAKE A CHANGE PASS
# the prompt-parity iron rule (AGENTS.md 2): "If token budgets across conditions diverge beyond the
# policy tolerance, the change is wrong — fix the change, do not adjust the tolerance." The numbers
# live in prompt-parity-policy.md section 3 behind the `m4-parity-caps` anchor,
# agents/registry/limits.py mirrors that block key for key, and
# agents/tests/test_limits_match_parity_policy.py parses it and fails on drift — ADR-016's pattern
# applied a third time, after M1's probe constants and M2's Monitor limits.
#
# OUTPUT
# stdout carries the per-condition token table section 3 requires a pull request to carry, naming
# the pinned reference tokenizer and the registry digest it was computed over. stderr carries every
# failed assertion and every reason the check could not be made. Exit 0 only when all four
# assertions held and all four could be made.
#
# INTERPRETER SELECTION
# $PYTHON if set, else python3, else python. The last fallback is what makes this work on the
# Windows development host, where Git for Windows provides sh but the interpreter on PATH is
# `python`. scripts/install_runtime_deps.sh reads $PYTHON the same way and for the same reason.
#
# PORTABILITY
# Strict POSIX sh — no bashisms, no GNU-only options — so it runs under dash in WSL2 Ubuntu, under
# Git Bash on the Windows host, and on ubuntu-latest.

set -eu

LC_ALL=C
export LC_ALL

# Repo root derived from this script's own location, so behaviour is identical whether the script is
# invoked by make, by CI, or by hand from an arbitrary working directory.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

interpreter=""
if [ -n "${PYTHON-}" ]; then
    interpreter=$PYTHON
elif command -v python3 >/dev/null 2>&1; then
    interpreter=python3
elif command -v python >/dev/null 2>&1; then
    interpreter=python
fi

if [ -z "$interpreter" ]; then
    echo "parity-check: no Python interpreter found. Set PYTHON to the interpreter to use." >&2
    echo "parity-check: this gate needs an interpreter and nothing else — agents/registry/ is" >&2
    echo "parity-check: standard-library only, so that it can run in a CI job that installs" >&2
    echo "parity-check: nothing (conflict M4-C1, ADR-028)." >&2
    exit 1
fi

if [ ! -d agents/prompts ]; then
    echo "parity-check: FAIL — agents/prompts/ does not exist, so no condition was composed." >&2
    echo "parity-check: Parity asserts an equality across conditions, so an absent registry" >&2
    echo "parity-check: proves nothing rather than nothing being wrong. Unlike a grep guard," >&2
    echo "parity-check: this check cannot pass vacuously — see this script's header." >&2
    exit 1
fi

# PYTHONIOENCODING is set because the emitted table and the failure messages carry the block
# delimiters and the condition identifiers as UTF-8, and the Windows console's default code page
# cannot encode them — a gate that failed while printing its own verdict would be the least useful
# failure in the repository.
PYTHONIOENCODING=utf-8
export PYTHONIOENCODING

# PYTHONPATH puts the repository root on the import path so that `agents` resolves without the
# package being installed. Nothing in this project is ever pip-installed: pyproject.toml's header
# says so, and the per-component pytest steps rely on the same arrangement.
PYTHONPATH="$repo_root${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONPATH

exec "$interpreter" -m agents.registry.parity "$@"
