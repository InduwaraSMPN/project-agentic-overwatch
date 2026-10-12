#!/bin/sh
# monitor_replay.sh — replay the tracked fixture corpus and check what came out.
#
# WHAT THIS GATE ASSERTS
# For every fixture under monitor/fixtures/, or for the one named by F: the aggregator replays it,
# every emitted line reads back as a schema-valid EvidenceEvent, and the emitted stream is
# byte-identical to the golden stream committed beside the fixture. That last comparison is a `cmp`
# rather than a judgement, for the reason M2's Definition of done gives: a parsed comparison would
# pass while key order, separators or the line terminator drifted.
#
# WHY F IS OPTIONAL, WHICH IS A CORRECTION AND NOT A CONVENIENCE
# docs/04-repo-conventions.md section 3 used to fix the signature as `make monitor-replay F=<fixture>`
# as though F were required, while docs/milestones/M2-monitor.md's Definition of done asks for a
# replay "over all fixtures" and docs/prompts-playbook.md's verify card for one "against every
# fixture". As written, no invocation satisfied the DoD — conflict M2-C2 in
# docs/plans/M2-implementation-plan.md. So: with no F this replays the whole corpus, which is what
# the DoD asks for; with F=<id> it replays that one, which is what a developer iterating on a single
# normaliser wants. Both spellings work — `F=<id>` in the environment, which is how `make` passes a
# command-line variable through, and `--fixture <id>` for a direct call.
#
# THE LATENCY VERDICT IS WITHHELD UNTIL CALIBRATION, THEN ENFORCED
# evaluation-protocol.md section 4 owns the Monitor latency budgets and CI ceiling multiplier. While
# either budget remains PENDING-M2-FIXTURE-STUDY, the harness withholds the verdict and this script
# reports measured figures without comparing them. Once calibrated, the harness compares p95 and max
# against budget times multiplier; this gate fails if either CI ceiling is exceeded. It never inserts
# a placeholder value, which would manufacture a green result unsupported by measurement.
#
# WHY THE CAPS COME FROM EACH FIXTURE AND WHY THE DISCLAIMER IS PRINTED EVERY RUN
# monitor/aggregator/limits.py fails closed while section 4's caps are pending, so the corpus cannot
# replay at all unless cap values are supplied. Each fixture supplies its own, in its own
# fixture.yaml, under corpus_cap_* keys that are deliberately not section 4's key names and beside a
# corpus_cap_status sentinel that the reader refuses to load without. They are fixture-corpus test
# parameters. The summary below says so on every run, so the sentence is in the log of every replay
# rather than only in monitor/fixtures/README.md.
#
# WHERE THE WORK ACTUALLY HAPPENS
# monitor/tests/replay_harness.py. It reads fixture.yaml, supplies the injected nanosecond counter
# that nothing under monitor/aggregator/ may obtain (ADR-019), calls emit.replay_fixture, and prints
# one machine-readable line per fixture. This script drives it, does the cmp, and reports. Keeping
# the replay in one Python entry point is what makes the shell gate, the determinism gate and the
# pytest files produce the same bytes: three implementations would be comparing themselves.
#
# STREAMS AND EXIT CODES
# stdout carries one summary line, in check_hygiene.sh's shape. stderr carries the per-fixture
# detail and the failure list. Exit 0 on a clean run, 1 on any failure — including an empty corpus,
# which is refused rather than passed: a gate that succeeds over nothing reads, in a log, exactly
# like a gate that succeeds over everything.
#
# PORTABILITY
# Strict POSIX sh — no bashisms, no GNU-only options, and no jq, which is not in this toolchain.
# fixture.yaml is a flat `key: value` file precisely so that the awk reader below and the Python one
# in the harness can both parse it. Runs under dash in WSL2 Ubuntu, under Git Bash on Windows, and
# on ubuntu-latest.

set -eu

# Byte-exact matching and byte-stable tool output whatever the ambient locale.
LC_ALL=C
export LC_ALL

# Repo root from this script's own location, so behaviour is identical from make, from CI, or by
# hand from an arbitrary working directory.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

CORPUS_DIR="monitor/fixtures"
MANIFEST="fixture.yaml"
EVENTS="monitor_events.jsonl"
OUT_ROOT="monitor/.replay/emitted"
HARNESS="monitor.tests.replay_harness"

usage() {
    echo "usage: sh scripts/monitor_replay.sh [F=<fixture-id> | --fixture <fixture-id>]"
    echo "       with no fixture named, every fixture in $CORPUS_DIR is replayed"
}

selection=${F:-}
while [ $# -gt 0 ]; do
    case "$1" in
        --fixture)
            shift
            [ $# -gt 0 ] || { usage >&2; exit 1; }
            selection=$1
            ;;
        --fixture=*) selection=${1#--fixture=} ;;
        F=*)         selection=${1#F=} ;;
        -h|--help)   usage; exit 0 ;;
        *)
            printf 'monitor-replay: unknown argument %s\n' "$1" >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

# INTERPRETER RESOLUTION, AND WHY IT DIFFERS FROM install_runtime_deps.sh's
# That script installs, and says that where the packages go is the caller's policy. This one runs
# the artefact, and an interpreter without the pinned dependency is a failure the caller cannot fix
# by policy. So: $PYTHON if set, else the repository virtualenv if one exists, else python3 — which
# is what CI gets, because .venv/ is gitignored and never exists on a runner. The chosen interpreter
# is printed on every run, so the resolution is never a guess a reader has to make.
#
# ONE WSL2 SUBTLETY, RECORDED BECAUSE IT COULD MASK A REAL FAILURE.
# On WSL2 the repository is reached through /mnt/c, so a virtualenv built on the Windows side is
# visible from the Linux side -- and .venv/Scripts/python.exe is executable there, because WSL2
# registers a binfmt handler for Windows executables. The resolution order above therefore falls
# through to a WINDOWS interpreter when no POSIX .venv/bin/python exists, and the gate passes. It
# is a genuine pass of the aggregator's logic, and the interpreter is printed on the summary line
# so the transcript never hides which one ran. What it is not is evidence about Linux: a
# platform-specific defect -- a path separator, a locale-dependent sort, a filesystem encoding --
# would be invisible. To test the Linux path, build a POSIX virtualenv and name it explicitly:
#   PYTHON=~/.venvs/agentic-overwatch/bin/python make monitor-replay
# scripts/install_runtime_deps.sh prints those steps when it refuses an externally managed
# interpreter, which on Ubuntu is the first thing a developer hits.
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
        printf 'monitor-replay: %s cannot import the aggregator.\n' "$python_bin"
        echo "The evidence aggregator needs the runtime dependency pinned in infra/versions.env."
        echo "Install it with: sh scripts/install_runtime_deps.sh"
        echo "Or point this gate at an interpreter that already has it: PYTHON=<path> sh scripts/monitor_replay.sh"
    } >&2
    exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
problems="$work/problems"
: > "$problems"

# --- enumerate the corpus ------------------------------------------------------------------
# A directory counts as a fixture when it holds a manifest. A glob rather than `find` so the walk
# is one level deep by construction, and a directory that is not a fixture is skipped here and
# reported by the harness rather than replayed as an empty one.
ids="$work/ids"
: > "$ids"
if [ -d "$CORPUS_DIR" ]; then
    for dir in "$CORPUS_DIR"/*/; do
        [ -f "$dir$MANIFEST" ] || continue
        id=${dir#"$CORPUS_DIR"/}
        printf '%s\n' "${id%/}" >> "$ids"
    done
fi
corpus_total=$(wc -l < "$ids" | tr -d ' ')

if [ "$corpus_total" -eq 0 ]; then
    {
        printf 'monitor-replay: FAIL — %s holds no fixture directory carrying a %s.\n' \
            "$CORPUS_DIR" "$MANIFEST"
        echo "An empty corpus is refused rather than replayed successfully. The corpus is the"
        echo "evidence behind traceability rows T-01, T-02 and T-04, and a gate that passes over"
        echo "nothing is byte-identical, in a log, to one that passes over everything."
    } >&2
    printf 'monitor-replay: FAIL — empty corpus\n'
    exit 1
fi

selected="$work/selected"
if [ -n "$selection" ]; then
    if ! awk -v want="$selection" '$0 == want { found = 1 } END { exit !found }' "$ids"; then
        {
            printf 'monitor-replay: FAIL — no fixture %s in %s. The corpus holds:\n' \
                "$selection" "$CORPUS_DIR"
            sed 's/^/  /' "$ids"
        } >&2
        printf 'monitor-replay: FAIL — unknown fixture %s\n' "$selection"
        exit 1
    fi
    printf '%s\n' "$selection" > "$selected"
else
    cp "$ids" "$selected"
fi
selected_total=$(wc -l < "$selected" | tr -d ' ')

# --- replay ---------------------------------------------------------------------------------
rm -rf "$OUT_ROOT"
harness_out="$work/harness.out"
harness_rc=0
if [ -n "$selection" ]; then
    "$python_bin" -m "$HARNESS" --out-root "$OUT_ROOT" --fixture "$selection" \
        > "$harness_out" 2> "$work/harness.err" || harness_rc=$?
else
    "$python_bin" -m "$HARNESS" --out-root "$OUT_ROOT" \
        > "$harness_out" 2> "$work/harness.err" || harness_rc=$?
fi

if [ "$harness_rc" -ne 0 ]; then
    {
        printf 'monitor-replay: FAIL — the replay harness exited %s\n' "$harness_rc"
        cat "$work/harness.err"
    } >&2
    printf 'monitor-replay: FAIL — harness exited %s\n' "$harness_rc"
    exit 1
fi

# report_field <fixture-id> <key>
# One token of the harness's per-fixture line, which is `replay-harness: <id> k=v k=v ...`.
report_field() {
    awk -v id="$1" -v key="$2" '
        $1 == "replay-harness:" && $2 == id {
            for (i = 3; i <= NF; i++) {
                eq = index($i, "=")
                if (eq > 0 && substr($i, 1, eq - 1) == key) { print substr($i, eq + 1); exit }
            }
        }' "$harness_out"
}

# manifest_field <manifest-path> <key>
# The awk half of the fixture.yaml contract: `key: value`, or a bare `key:` for an empty value.
# The Python half is monitor/tests/replay_harness.py; both read the same file, and the format is
# flat so that neither needs a parser.
manifest_field() {
    awk -v key="$2" '
        index($0, key ":") == 1 {
            value = substr($0, length(key) + 2)
            sub(/^ /, "", value)
            print value
            exit
        }' "$1"
}

# --- per fixture: schema validity, then the byte diff ---------------------------------------
echo "monitor-replay: per-fixture detail" >&2
compared=0
while IFS= read -r id; do
    [ -n "$id" ] || continue
    emitted="$OUT_ROOT/$id/$EVENTS"
    golden="$CORPUS_DIR/$id/expected/$EVENTS"
    events=$(report_field "$id" events)
    validated=$(report_field "$id" validated)
    p95=$(report_field "$id" p95_ms)
    worst=$(report_field "$id" max_ms)
    caps=$(report_field "$id" corpus_caps)
    budget=$(report_field "$id" budget)
    provenance=$(manifest_field "$CORPUS_DIR/$id/$MANIFEST" provenance)
    sources=$(manifest_field "$CORPUS_DIR/$id/$MANIFEST" source)

    if [ -z "$events" ]; then
        printf 'the harness reported no result for fixture %s\n' "$id" >> "$problems"
        continue
    fi
    if [ "$events" = "0" ]; then
        printf 'fixture %s emitted no events; a replay of nothing is not a pass\n' "$id" \
            >> "$problems"
    fi
    if [ "$events" != "$validated" ]; then
        printf 'fixture %s: %s event(s) emitted but %s validated against the frozen contract\n' \
            "$id" "$events" "$validated" >> "$problems"
    fi
    if [ "$budget" = "fail" ]; then
        printf 'fixture %s: calibrated latency budget CI ceiling was exceeded\n' "$id" >> "$problems"
    elif [ "$budget" != "withheld" ] && [ "$budget" != "pass" ]; then
        printf 'fixture %s: harness reported unknown latency budget verdict %s\n' \
            "$id" "$budget" >> "$problems"
    fi
    if [ ! -f "$emitted" ]; then
        printf 'fixture %s: nothing was written to %s\n' "$id" "$emitted" >> "$problems"
        continue
    fi
    if [ ! -f "$golden" ]; then
        printf 'fixture %s: no golden stream at %s. Generate it with `python -m %s --out-root monitor/.replay/update --update-golden` and review the diff\n' \
            "$id" "$golden" "$HARNESS" >> "$problems"
        continue
    fi

    compared=$((compared + 1))
    if cmp -s "$emitted" "$golden"; then
        printf '  %-32s %s source(s)=%-38s events=%-3s p95=%sms max=%sms caps=%s golden=identical\n' \
            "$id" "$provenance" "$sources" "$events" "$p95" "$worst" "$caps" >&2
    else
        printf '  %-32s %s source(s)=%-38s events=%-3s p95=%sms max=%sms caps=%s golden=DIFFERS\n' \
            "$id" "$provenance" "$sources" "$events" "$p95" "$worst" "$caps" >&2
        # One line per problem, because the count below is a line count -- the same contract
        # check_hygiene.sh's problem list keeps. `cmp` reports the first difference only, which is
        # what a reader needs to locate the change; the whole diff is available from the two paths.
        detail=$(cmp "$emitted" "$golden" 2>&1 | head -n 1)
        printf 'fixture %s: emitted stream differs from its golden stream -- %s\n' "$id" "$detail" \
            >> "$problems"
    fi
done < "$selected"

# The worst figures across everything replayed. Nearest-rank p95 over a handful of events is the
# maximum, so on a small fixture the two columns agree; that is arithmetic, not a bug.
figures=$(awk '
    $1 == "replay-harness:" {
        for (i = 3; i <= NF; i++) {
            eq = index($i, "=")
            if (eq <= 0) { continue }
            k = substr($i, 1, eq - 1)
            v = substr($i, eq + 1)
            if (v == "None") { continue }
            if (k == "p95_ms" && v + 0 > p95) { p95 = v + 0 }
            if (k == "max_ms" && v + 0 > mx)  { mx  = v + 0 }
        }
    }
    END { printf "%.4f %.4f", p95, mx }' "$harness_out")
worst_p95=${figures% *}
worst_max=${figures#* }

problem_count=$(awk 'END { print NR }' "$problems")

if [ "$problem_count" -gt 0 ]; then
    {
        printf '\nmonitor-replay: FAIL — %s problem(s):\n\n' "$problem_count"
        cat "$problems"
        echo
        echo "A golden stream is the aggregator's output byte for byte, so a difference means the"
        echo "aggregator's behaviour changed. Read the change first. Regenerating the corpus with"
        echo "--update-golden is a reviewed diff, never a way to make this gate green; after the"
        echo "v1.0 freeze it is a logged hotfix ADR (AGENTS.md iron rule 6)."
    } >&2
    printf 'monitor-replay: FAIL — %s problem(s) over %s fixture(s)\n' "$problem_count" \
        "$selected_total"
    exit 1
fi

budget_status=$(awk '
    $1 == "replay-harness:" {
        for (i = 3; i <= NF; i++) {
            if ($i == "budget=withheld") { withheld = 1 }
        }
    }
    END { print withheld ? "uncalibrated" : "within calibrated CI ceiling" }' "$harness_out")

{
    echo
    echo "monitor-replay: the caps above are per-fixture corpus_cap_* values from each fixture.yaml."
    echo "They are fixture-corpus test parameters. They are NOT the caps"
    echo "docs/protocols/evaluation-protocol.md section 4 owns, and they are not evidence that its"
    echo "caps row is closed: that row waits on fixtures captured from live sources at T2.7b and the"
    echo "study that derives the values at T2.5b (ADR-019)."
    if [ "$budget_status" = "uncalibrated" ]; then
        echo "monitor-replay: the latency budget is UNCALIBRATED. The figures above are measured and"
        echo "reported; they are compared against nothing, because section 4's budget keys still read"
        echo "PENDING-M2-FIXTURE-STUDY and a placeholder ceiling would produce a 'within budget' line"
        echo "that no measurement supports."
    else
        echo "monitor-replay: each measured p95 and max is within its section 4 budget multiplied by"
        echo "monitor_latency_ci_ceiling_multiplier. An exceeded ceiling is a gate failure."
    fi
} >&2

printf 'monitor-replay: PASS — %s of %s fixture(s) replayed, %s schema-validated and byte-identical to golden; worst p95 %sms, worst max %sms; latency budget %s (interpreter %s)\n' \
    "$selected_total" "$corpus_total" "$compared" "$worst_p95" "$worst_max" "$budget_status" "$python_bin"
exit 0
