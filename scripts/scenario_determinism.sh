#!/bin/sh
# scenario_determinism.sh — plan every grid cell twice and prove the two runs are the same bytes.
#
# WHAT THIS GATE IS
# The scenario half of `make determinism-check`, and the machine form of M5's Definition-of-done
# line "same seed twice → identical injected sequence". That wording is a `cmp`, not a judgement:
# two planner runs over one cell must produce byte-identical output, and a comparison of parsed
# objects would pass while key order, separators, the line terminator or the emission order drifted.
# It is the check traceability row T-17 closes against, and NFR2 and
# the prompt-parity iron rule (AGENTS.md 2) are what require the property.
#
# WHY IT LANDS IN THE SAME COMMIT AS THE FIRST FILE UNDER scenarios/
# Conflict M5-C1. Before M5, `make determinism-check`'s second line was an @echo reporting the
# scenario half not-implemented, and it returned 0. .github/workflows/ci.yml's nightly step arms on
# hashFiles() over the five scenarios/ content directories — chaosmesh, cve, attackers, groundtruth,
# manifests. So the first commit putting any file under any of those five arms a nightly run of a
# target whose scenario half asserted nothing and reported green. That is a sharper obligation than
# "implement the target or CI goes red": it is "implement the target or CI goes green while proving
# nothing". This script and the first corpus file are therefore one commit.
#
# WHAT IS COMPARED, AND WHY NOTHING HAS TO BE HELD OUT OF IT
# plan.jsonl, in full, for every cell. The Monitor half of this target has to exclude latency.json
# because its figures are wall-clock (ADR-019); this half excludes nothing, because a plan has no
# wall-clock quantity to exclude. The planner has no t0 to read — offsets are integers in
# milliseconds from a t0 that exists only in scenarios/attackers/apply.py — so the absence is
# structural rather than arranged. A gate that compares whole files is a stronger claim than one
# that compares files minus a field, and this half can make it.
#
# THE UNIT IS A CELL, NOT A FIXTURE
# The corpus is (scenario_id, injection_condition, seed): the scenarios under scenarios/manifests/,
# times the five injection-condition values, times the seed set given on the command line. One
# planner invocation per run plans the whole matrix, so the two runs are two processes however many
# cells there are.
#
# THE TWO RUNS ARE NOT ALLOWED TO SHARE A DIRECTORY
# Each writes into its own tree under scenarios/.replay/determinism/, which is gitignored. Writing
# both into one directory would make the second overwrite the first and the comparison would be a
# file against itself — the shape of vacuous pass this repository refuses everywhere else.
#
# WHY THE SECOND RUN IS A SECOND PROCESS
# The planner is invoked twice, so the two runs share no interpreter state: no warm module cache
# entry, no memoised table, no dictionary that happened to be built in one order, and no generator
# carried over. A determinism check that ran twice inside one process would be blind to exactly the
# class of defect that makes the second machine disagree with the first.
#
# WHY THERE IS NO INTERPRETER-IMPORT PRECONDITION HERE
# scripts/monitor_determinism.sh opens with a branch that exits 1 when the interpreter cannot
# import the aggregator, because the aggregator needs pydantic. Nothing under scenarios/ imports
# anything outside the standard library — the JSON Schema subset validator and the YAML subset
# reader under scenarios/schemas/ exist for that reason (ADR-035) — so this gate has no such branch
# and cannot fail for a dependency reason. It can only fail for the reason it exists to test.
#
# THE SEED SET IS THE CALLER'S, NEVER THIS SCRIPT'S
# SEEDS defaults to the fixed set docs/07-glossary-and-ids.md section Seeds pre-registers. That is
# a reference, not a second home: the source-of-truth iron rule (AGENTS.md 1) single-homes the integers
# there, and the default below is the one place in scenarios/ that names them, so a change to the
# set is one edit. Override with SEEDS=101,102,103 to run the reduction path.
#
# STREAMS AND EXIT CODES
# stdout carries one summary line. stderr carries the per-cell detail, the empty diff on success,
# and the first differing bytes on failure. Exit 0 when every cell matches itself, 1 otherwise —
# including an empty corpus, which is refused rather than passed.
#
# PORTABILITY
# Strict POSIX sh — no bashisms, no GNU-only options, no jq. Runs under dash in WSL2 Ubuntu, under
# Git Bash on Windows, and on ubuntu-latest.

set -eu

LC_ALL=C
export LC_ALL

# Repo root derived from this script's own location, so behaviour is identical whether the script
# is invoked by make, by CI, or by hand from an arbitrary working directory.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

CORPUS_DIR="scenarios/manifests"
PLAN="plan.jsonl"
RUN_ROOT="scenarios/.replay/determinism"
PLANNER="scenarios.attackers.plan"
CONDITIONS="INJ-NONE INJ-A INJ-B INJ-C INJ-D"

# The fixed seed set of docs/07-glossary-and-ids.md section Seeds, referenced here and owned there.
SEEDS=${SEEDS:-101,102,103,104,105}

# Interpreter resolution, identical to scripts/monitor_determinism.sh's and explained there: $PYTHON
# if set, else the repository virtualenv if one exists, else python3 — which is what CI gets,
# because .venv/ is gitignored and never exists on a runner.
if [ -n "${PYTHON:-}" ]; then
    python_bin=$PYTHON
elif [ -x .venv/bin/python ]; then
    python_bin=.venv/bin/python
elif [ -x .venv/Scripts/python.exe ]; then
    python_bin=.venv/Scripts/python.exe
else
    python_bin=python3
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
problems="$work/problems"
: > "$problems"

# --- the corpus -----------------------------------------------------------------------------
scenarios="$work/scenarios"
: > "$scenarios"
if [ -d "$CORPUS_DIR" ]; then
    for manifest in "$CORPUS_DIR"/SCN-*.yaml; do
        [ -f "$manifest" ] || continue
        base=${manifest##*/}
        printf '%s\n' "${base%.yaml}" >> "$scenarios"
    done
fi
scenario_count=$(wc -l < "$scenarios" | tr -d ' ')

seed_list=$(printf '%s' "$SEEDS" | tr ',' ' ')
seed_count=0
for seed in $seed_list; do
    seed_count=$((seed_count + 1))
done

if [ "$scenario_count" -eq 0 ] || [ "$seed_count" -eq 0 ]; then
    {
        printf 'determinism-check: FAIL — %s holds no scenario manifest, or the seed set is empty.\n' \
            "$CORPUS_DIR"
        echo "Planning nothing twice produces two empty results that compare equal, which is a"
        echo "vacuous pass. The corpus is the evidence behind traceability row T-17, and the"
        echo "nightly step in .github/workflows/ci.yml arms on the first file under any of the five"
        echo "scenarios/ content directories — so a green run over an empty corpus is exactly the"
        echo "failure conflict M5-C1 exists to prevent."
    } >&2
    printf 'determinism-check: scenario half: FAIL — empty corpus\n'
    exit 1
fi

condition_count=0
for condition in $CONDITIONS; do
    condition_count=$((condition_count + 1))
done
total=$((scenario_count * condition_count * seed_count))

# --- two runs, two trees, two processes -----------------------------------------------------
rm -rf "$RUN_ROOT"
run=1
while [ "$run" -le 2 ]; do
    rc=0
    "$python_bin" -m "$PLANNER" --seeds "$SEEDS" --out-root "$RUN_ROOT/run-$run" \
        > "$work/planner-$run.out" 2> "$work/planner-$run.err" || rc=$?
    if [ "$rc" -ne 0 ]; then
        {
            printf 'determinism-check: FAIL — planner run %s exited %s\n' "$run" "$rc"
            cat "$work/planner-$run.err"
        } >&2
        printf 'determinism-check: scenario half: FAIL — planner run %s exited %s\n' "$run" "$rc"
        exit 1
    fi
    run=$((run + 1))
done

# --- the diff -------------------------------------------------------------------------------
echo "determinism-check: scenario half — per-cell byte comparison of two independent plannings" >&2
compared=0
while IFS= read -r scenario; do
    [ -n "$scenario" ] || continue
    for condition in $CONDITIONS; do
        for seed in $seed_list; do
            cell="$scenario/$condition/$seed"
            first="$RUN_ROOT/run-1/$cell/$PLAN"
            second="$RUN_ROOT/run-2/$cell/$PLAN"
            if [ ! -f "$first" ] || [ ! -f "$second" ]; then
                printf 'cell %s: one of the two plannings wrote no %s\n' "$cell" "$PLAN" >> "$problems"
                continue
            fi
            compared=$((compared + 1))
            bytes=$(wc -c < "$first" | tr -d ' ')
            if [ "$bytes" -eq 0 ]; then
                printf 'cell %s: planned an empty sequence; INJ-NONE is a grid coordinate, not an absence\n' \
                    "$cell" >> "$problems"
                continue
            fi
            if cmp -s "$first" "$second"; then
                printf '  %-38s %s bytes   diff: (empty)\n' "$cell" "$bytes" >&2
            else
                printf '  %-38s %s bytes   diff: DIFFERS\n' "$cell" "$bytes" >&2
                # One line per problem, because the count below is a line count. `cmp` names the
                # first differing byte and line, which is what localises a non-determinism; both
                # output trees are left in place under scenarios/.replay/determinism/.
                detail=$(cmp "$first" "$second" 2>&1 | head -n 1)
                printf 'cell %s: two plannings produced different bytes -- %s (run 1 %s, run 2 %s)\n' \
                    "$cell" "$detail" "$first" "$second" >> "$problems"
            fi
        done
    done
done < "$scenarios"

problem_count=$(awk 'END { print NR }' "$problems")

if [ "$problem_count" -gt 0 ]; then
    {
        printf '\ndeterminism-check: FAIL — %s problem(s):\n\n' "$problem_count"
        cat "$problems"
        echo
        echo "A plan must be a function of (scenario_id, injection_condition, seed) and of nothing"
        echo "else. The usual causes are a clock read where an offset should be an integer from t0,"
        echo "a generator seeded from the bare seed rather than from the whole cell key, a draw"
        echo "taken from a set or a dict rather than from an ordered pool, or an emission order"
        echo "taken from insertion rather than from the explicit total order"
        echo "(offset_ms, event_rank, event_id). ADR-035 and"
        echo "the prompt-parity iron rule (AGENTS.md 2) fix all four, and"
        echo "scripts/scenario_guard.sh greps for the first of them."
    } >&2
    printf 'determinism-check: scenario half: FAIL — %s of %s cell(s) differed\n' \
        "$problem_count" "$total"
    exit 1
fi

{
    echo
    echo "determinism-check: scenario half — every diff above is empty. Unlike the Monitor half, no"
    echo "file and no field is held out of this comparison: a plan carries no absolute time, because"
    echo "the planner has no t0 to read. The wall clock enters only in"
    echo "scenarios/attackers/apply.py, whose output is injection.log.jsonl rather than a plan."
} >&2

printf 'determinism-check: scenario half: PASS — %s cell(s) planned twice in two processes, %s byte-identical, 0 differing (interpreter %s)\n' \
    "$total" "$compared" "$python_bin"
exit 0
