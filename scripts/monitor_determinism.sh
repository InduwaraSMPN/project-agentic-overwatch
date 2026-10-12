#!/bin/sh
# monitor_determinism.sh — replay every fixture twice and prove the two runs are the same bytes.
#
# WHAT THIS GATE IS
# The Monitor half of `make determinism-check`, and the machine form of M2's Definition-of-done line
# "same fixture twice → identical output". That wording is a `cmp`, not a judgement: two runs of the
# aggregator over one fixture must produce byte-identical output, and a comparison of parsed objects
# would pass while key order, separators, the line terminator or the emission order drifted. It is
# also the check traceability row T-04 closes against, and NFR2 and
# the prompt-parity iron rule (AGENTS.md 2) are what require the property.
#
# WHY IT IS A SEPARATE GATE FROM monitor_replay.sh RATHER THAN A FLAG ON IT
# They answer different questions and can fail independently. The replay gate compares one run
# against the golden stream committed in the repository, which catches a change in *behaviour*. This
# gate compares two runs against each other, which catches a *non-determinism* — a generated
# identifier, a clock read, a set iteration, a dictionary order — that the replay gate cannot see,
# because a non-deterministic aggregator can still agree with a golden file produced by one of its
# own runs. A single target with a flag would let one of the two be skipped without the log saying
# which.
#
# WHAT IS COMPARED, AND WHAT DELIBERATELY IS NOT
# monitor_events.jsonl only. A replay also writes latency.json, and that file is excluded by design:
# latency figures are wall-clock and machine-dependent, so a `cmp` over them would fail on every
# second run and would present itself as a flaky determinism test rather than as the design error it
# would actually be. ADR-019 records the decision and its price — latency.json is an output no `cmp`
# covers, checked instead by its own assertions and by being read.
#
# THE TWO RUNS ARE NOT ALLOWED TO SHARE A DIRECTORY
# Each writes into its own tree under monitor/.replay/determinism/, which is gitignored. Writing
# both into one directory would make the second overwrite the first and the comparison would be a
# file against itself — the shape of vacuous pass this repository refuses everywhere else.
#
# WHY THE SECOND RUN IS A SECOND PROCESS
# The harness is invoked twice, so the two runs share no interpreter state: no warm module cache
# entry, no memoised table, no dictionary that happened to be built in one order. A determinism
# check that ran twice inside one process would be blind to exactly the class of defect that makes
# the second machine disagree with the first.
#
# STREAMS AND EXIT CODES
# stdout carries one summary line. stderr carries the per-fixture detail, the empty diff on success,
# and the first differing bytes on failure. Exit 0 when every fixture matches itself, 1 otherwise —
# including an empty corpus, which is refused rather than passed.
#
# PORTABILITY
# Strict POSIX sh — no bashisms, no GNU-only options, no jq. Runs under dash in WSL2 Ubuntu, under
# Git Bash on Windows, and on ubuntu-latest.

set -eu

LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

CORPUS_DIR="monitor/fixtures"
MANIFEST="fixture.yaml"
EVENTS="monitor_events.jsonl"
RUN_ROOT="monitor/.replay/determinism"
HARNESS="monitor.tests.replay_harness"

# Interpreter resolution, identical to scripts/monitor_replay.sh's and explained there: $PYTHON if
# set, else the repository virtualenv if one exists, else python3 — which is what CI gets, because
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

if ! "$python_bin" -c 'import monitor.aggregator.models' >/dev/null 2>&1; then
    {
        printf 'determinism-check: %s cannot import the aggregator.\n' "$python_bin"
        echo "Install the pinned runtime dependency with: sh scripts/install_runtime_deps.sh"
        echo "Or: PYTHON=<path> sh scripts/monitor_determinism.sh"
    } >&2
    exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
problems="$work/problems"
: > "$problems"

ids="$work/ids"
: > "$ids"
if [ -d "$CORPUS_DIR" ]; then
    for dir in "$CORPUS_DIR"/*/; do
        [ -f "$dir$MANIFEST" ] || continue
        id=${dir#"$CORPUS_DIR"/}
        printf '%s\n' "${id%/}" >> "$ids"
    done
fi
total=$(wc -l < "$ids" | tr -d ' ')

if [ "$total" -eq 0 ]; then
    {
        printf 'determinism-check: FAIL — %s holds no fixture directory carrying a %s.\n' \
            "$CORPUS_DIR" "$MANIFEST"
        echo "Replaying nothing twice produces two empty results that compare equal, which is a"
        echo "vacuous pass. The corpus is the evidence behind traceability row T-04."
    } >&2
    printf 'determinism-check: monitor half: FAIL — empty corpus\n'
    exit 1
fi

# --- two runs, two trees, two processes -----------------------------------------------------
rm -rf "$RUN_ROOT"
run=1
while [ "$run" -le 2 ]; do
    rc=0
    "$python_bin" -m "$HARNESS" --out-root "$RUN_ROOT/run-$run" \
        > "$work/harness-$run.out" 2> "$work/harness-$run.err" || rc=$?
    if [ "$rc" -ne 0 ]; then
        {
            printf 'determinism-check: FAIL — replay %s exited %s\n' "$run" "$rc"
            cat "$work/harness-$run.err"
        } >&2
        printf 'determinism-check: monitor half: FAIL — replay %s exited %s\n' "$run" "$rc"
        exit 1
    fi
    run=$((run + 1))
done

# --- the diff -------------------------------------------------------------------------------
echo "determinism-check: monitor half — per-fixture byte comparison of two independent replays" >&2
compared=0
while IFS= read -r id; do
    [ -n "$id" ] || continue
    first="$RUN_ROOT/run-1/$id/$EVENTS"
    second="$RUN_ROOT/run-2/$id/$EVENTS"
    if [ ! -f "$first" ] || [ ! -f "$second" ]; then
        printf 'fixture %s: one of the two replays wrote no %s\n' "$id" "$EVENTS" >> "$problems"
        continue
    fi
    compared=$((compared + 1))
    bytes=$(wc -c < "$first" | tr -d ' ')
    if cmp -s "$first" "$second"; then
        printf '  %-32s %s bytes   diff: (empty)\n' "$id" "$bytes" >&2
    else
        printf '  %-32s %s bytes   diff: DIFFERS\n' "$id" "$bytes" >&2
        # One line per problem, because the count below is a line count. `cmp` names the first
        # differing byte and line, which is what localises a non-determinism; both output trees are
        # left in place under monitor/.replay/determinism/ for a full diff.
        detail=$(cmp "$first" "$second" 2>&1 | head -n 1)
        printf 'fixture %s: two replays produced different bytes -- %s (run 1 %s, run 2 %s)\n' \
            "$id" "$detail" "$first" "$second" >> "$problems"
    fi
done < "$ids"

problem_count=$(awk 'END { print NR }' "$problems")

if [ "$problem_count" -gt 0 ]; then
    {
        printf '\ndeterminism-check: FAIL — %s problem(s):\n\n' "$problem_count"
        cat "$problems"
        echo
        echo "The aggregator's output must be a function of its input and of nothing else. The"
        echo "usual causes are a generated identifier where event_id should be a sha256 over the"
        echo "source record, a clock read where ts should come from the record's own timestamp,"
        echo "an unseeded draw, or an emission order taken from a dict or a set rather than from"
        echo "the explicit total order (source_ts, source_rank, event_id). ADR-019 and"
        echo "the prompt-parity iron rule (AGENTS.md 2) fix all four."
    } >&2
    printf 'determinism-check: monitor half: FAIL — %s of %s fixture(s) differed\n' \
        "$problem_count" "$total"
    exit 1
fi

{
    echo
    echo "determinism-check: monitor half — every diff above is empty. latency.json is written by"
    echo "both runs and is deliberately NOT compared: its figures are wall-clock and would fail"
    echo "every second run, which is why they are held out of the event stream entirely (ADR-019)."
} >&2

printf 'determinism-check: monitor half: PASS — %s fixture(s) replayed twice in two processes, %s byte-identical, 0 differing (interpreter %s)\n' \
    "$total" "$compared" "$python_bin"
exit 0
