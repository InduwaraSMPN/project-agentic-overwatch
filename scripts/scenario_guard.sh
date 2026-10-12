#!/bin/sh
# scenario_guard.sh — the three boundaries the injection harness is built on, as a static check.
#
# WHAT THIS GUARD ANSWERS TO
# docs/plans/M5-implementation-plan.md section D11, which asks for the same treatment
# the guardian-first iron rule (AGENTS.md 1) and the monitor-non-LLM iron rule (AGENTS.md 7) each already earned:
# a boundary stated in prose is a boundary until someone forgets it, and a boundary a grep enforces
# is one the repository can still assert about itself after the person who wrote it has moved on.
#
# THREE BLOCKS, THREE DIFFERENT CLAIMS
#   (a) The planner reads no clock and takes no unseeded draw. This is the static half of NFR2 for
#       scenarios/. An offset derived from time.monotonic(), an identifier from uuid4(), or a draw
#       from the `random` module rather than from the seeded generator would each make
#       (scenario_id, seed) stop determining a plan.
#   (b) The planner does not reach the cluster; only the applier does. Section D1's plan/apply split
#       is what makes determinism checkable with no cluster at M5, and a split that lives only in a
#       docstring is not a split.
#   (c) There is no import edge between agents/ and scenarios/, in either direction.
#       docs/02-architecture.md section 5 draws the injection harness in its own subgraph,
#       perturbing the environment so telemetry reaches the Monitor. An agent that could import the
#       harness could read the ground truth it is being scored against; a harness that could import
#       the agent layer would be inside the trust boundary it exists outside of.
#
# BLOCK (b) NAMES ONE EXCLUDED FILE, AND CHECKS THAT IT EXISTS
# scenarios/attackers/apply.py is the one file the split permits to hold cluster access, and it is
# named in this script rather than carried in a list somewhere. That naming is a SCOPE decision and
# not an exemption, and the difference is what the block is built to keep: the exclusion is a single
# named file, not a glob, not an allowlist file, not an inline sentinel; the negative scan below
# still covers every OTHER file under scenarios/, so moving cluster access into the planner or adding
# a second cluster-touching file both fire; and the one excluded file is checked to exist, so the
# exclusion cannot dangle over a deleted applier. What it does NOT do is grep the applier for a
# cluster pattern to prove it earns the exclusion: at Tier A the applier's cluster seam is an
# authored stub with no `import kubernetes` yet, so that positive grep would pass only on a prose
# mention of the credential and a docstring reword could trip it. The negative scan is the robust
# invariant; the presence check is the anti-dangle.
#
# THERE IS DELIBERATELY NO EXEMPTION MECHANISM
# No allowlist file, no inline `# noqa`-style sentinel, no per-path skip. Blocks (a) and (b) are
# scoped positively — every tracked .py and .sh file under scenarios/, minus the one applier named
# above — and every file in that scope is scanned whatever it holds. Block (c) applies no file-class
# filter at all: every tracked file under agents/ and under scenarios/ is scanned, prose included,
# because its patterns are anchored import statements that prose does not produce. The reasoning is
# rule 10's and rule 40's, unchanged: an exemption mechanism added before the first true positive is
# an exemption mechanism sized to convenience rather than to risk, and a file-class filter is that
# same hole under a tidier name, because it drops whole classes of file from the scan without ever
# reporting what it dropped. A genuine false positive is an ADR at the milestone that produces the
# evidence, not a hole punched at M5 against false positives nobody has seen.
#
# THIS GUARD IS A TRIPWIRE. IT IS NOT THE PROOF OF DETERMINISM.
# Block (a) can only see the constructs it spells. The proof is
# scripts/scenario_determinism.sh's byte-level twice-and-diff, which catches a non-determinism this
# grep has no pattern for. Both run; neither substitutes for the other. ADR-020's wording, kept.
#
# SCOPE AND EXIT CODES
# Tracked files only (git ls-files), so an untracked local scratch file cannot fail CI and the check
# sees exactly what a fresh clone contains. Each block reports independently, so a failure names
# which invariant broke rather than leaving the reader to infer it from the pattern tag. Exit 0 on a
# clean scan or a vacuous pass — vacuous meaning the block's scope is absent, or holds no tracked
# files at all — exit 1 on any hit in any block. Strict POSIX sh, GNU-ERE patterns (`\b` and `\w`,
# the dialect grep_guard.sh already established): this runs under dash on WSL2 Ubuntu, under Git
# Bash on Windows, and on ubuntu-latest.

set -eu

LC_ALL=C
export LC_ALL

# Repo root derived from this script's own location, so behaviour is identical whether the script
# is invoked by make, by CI, or by hand from an arbitrary working directory.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

APPLIER="scenarios/attackers/apply.py"

# Patterns are spelled exactly once, here, and the failure report below prints these same variables.
# grep_guard.sh spells its patterns twice — once to scan, once to report — which is a drift risk
# this script declines to inherit, for the reason monitor_guard.sh gives: a pattern tightened in one
# place and not the other produces a failure message that does not describe the check that failed.

# (a1) Wall-clock reads, call-shaped. The trailing `\(` is what keeps this from matching prose: a
#      docstring saying "no clock" does not match, a call to time.monotonic() does.
PAT_CLOCK='\b(time\.(time|monotonic|perf_counter|process_time|time_ns|monotonic_ns|perf_counter_ns)|datetime\.(now|utcnow|today)|date\.today)[[:space:]]*\('

# (a2) Generated identifiers. A plan's event_id is a digest over the event's own fields; anything
#      drawn from entropy would differ between two runs by construction.
PAT_UUID='^[[:space:]]*(import|from)[[:space:]]+uuid\b|\buuid[0-9]\b|\bos\.urandom[[:space:]]*\(|\bsecrets\.[a-z_]+[[:space:]]*\(|\bSystemRandom\b'

# (a3) Draws taken from the `random` MODULE rather than from a seeded random.Random instance. The
#      constructor random.Random(...) is deliberately not matched: seeding one generator once at
#      entry is exactly what rule 20 requires, and it is spelled that way.
PAT_MODULE_RANDOM='\brandom\.(random|randint|randrange|randbytes|choice|choices|shuffle|sample|uniform|getrandbits|seed|gauss|normalvariate|betavariate|triangular|expovariate)[[:space:]]*\('

# (b1) Kubernetes clients, in an import statement. The anchored prefix keeps this call-shaped:
#      prose naming the library does not match, an import of it does.
PAT_K8S_IMPORT='^[[:space:]]*(import|from)[[:space:]]+kubernetes(_asyncio)?\b'

# (b2) Shelling out to the cluster, and the environment variable that points at one.
PAT_KUBECTL='\bkubectl\b|\bKUBECONFIG\b'

# (b3) Kubeconfig and in-cluster credential loading by any route.
PAT_K8S_CONFIG='\bkubernetes\.config\.load_|\bincluster_config\b|\bkube_config\b|\bload_incluster_config\b'

# (b4) Raw network reach. A planner that can open a socket can reach an API server without naming
#      one, which is the hole (b1) to (b3) would otherwise leave.
PAT_NETWORK='^[[:space:]]*(import|from)[[:space:]]+(socket|ssl|http\.client|http\.server|urllib|requests|httpx|aiohttp)\b'

# (c1) The import edge, both directions. scripts/grep_guard.sh already scans agents/ for the
#      Kubernetes patterns and needs no change; this is the direction M5 adds.
PAT_AGENTS_IMPORTS_SCENARIOS='^[[:space:]]*(import|from)[[:space:]]+scenarios\b'
PAT_SCENARIOS_IMPORTS_AGENTS='^[[:space:]]*(import|from)[[:space:]]+agents\b'

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

files_planner="$work/files_planner"
files_scenarios="$work/files_scenarios"
files_agents="$work/files_agents"
hits_a="$work/hits_a"
hits_b="$work/hits_b"
hits_c="$work/hits_c"
: > "$hits_a"
: > "$hits_b"
: > "$hits_c"

lt_count=0
list_tracked() {
    lt_out=$1
    lt_spec=$2
    git ls-files -z -- "$lt_spec" | tr '\0' '\n' > "$lt_out"
    lt_count=$(wc -l < "$lt_out" | tr -d ' ')
    lt_plain=$(git ls-files -- "$lt_spec" | wc -l | tr -d ' ')
    if [ "$lt_count" != "$lt_plain" ]; then
        printf 'scenario-guard: refusing to run — a tracked path under %s contains a newline\n' \
            "$lt_spec" >&2
        exit 1
    fi
}

SCAN_LIST=""
SCAN_HITS=""

# scan <pattern-name> <extended-regex>
# Appends one line per hit to $SCAN_HITS, formatted path:line: <matching line>, tagged with the
# pattern that fired. -I skips binary files; -E is required because the patterns are extended
# regexes.
scan() {
    scan_name=$1
    scan_pattern=$2
    while IFS= read -r scan_file; do
        [ -n "$scan_file" ] || continue
        grep -nEI -e "$scan_pattern" -- "$scan_file" | while IFS= read -r scan_hit; do
            scan_lineno=${scan_hit%%:*}
            scan_text=${scan_hit#*:}
            printf '%s:%s: %s   <-- [%s]\n' \
                "$scan_file" "$scan_lineno" "$scan_text" "$scan_name"
        done >> "$SCAN_HITS"
    done < "$SCAN_LIST"
}

# --- the planner's scope: every tracked .py and .sh under scenarios/, minus the one applier -----
list_tracked "$work/all_code" 'scenarios/*.py'
cp "$work/all_code" "$files_planner"
list_tracked "$work/sh_code" 'scenarios/*.sh'
cat "$work/sh_code" >> "$files_planner"
grep -v -x -F "$APPLIER" "$files_planner" > "$work/planner_filtered" || true
mv "$work/planner_filtered" "$files_planner"
planner_count=$(awk 'END { print NR }' "$files_planner")

# --- (a) no clock, no unseeded draw, in the planner --------------------------------------------
if [ "$planner_count" -eq 0 ]; then
    state_a="vacuous — scenarios/ holds no tracked .py or .sh outside the applier (pre-M5)"
else
    state_a="scanned $planner_count planner file(s) against 3 pattern families"
    SCAN_LIST=$files_planner
    SCAN_HITS=$hits_a
    scan wall-clock     "$PAT_CLOCK"
    scan generated-id   "$PAT_UUID"
    scan module-random  "$PAT_MODULE_RANDOM"
fi

# --- (b) no cluster reach from the planner, and the applier must be one -------------------------
if [ "$planner_count" -eq 0 ]; then
    state_b="vacuous — no planner files to scan (pre-M5)"
else
    state_b="scanned $planner_count planner file(s) against 4 pattern families"
    SCAN_LIST=$files_planner
    SCAN_HITS=$hits_b
    scan k8s-import     "$PAT_K8S_IMPORT"
    scan kubectl        "$PAT_KUBECTL"
    scan kubeconfig     "$PAT_K8S_CONFIG"
    scan raw-network    "$PAT_NETWORK"

    # The one excluded file must EXIST, so the exclusion cannot dangle. This is what keeps a single
    # named exclusion a scope rather than an exemption: the file scripts name is checked to be
    # present, so deleting the applier and leaving the exclusion behind -- which would silently drop
    # its future cluster code from the negative scan -- fails here. The exclusion is not proven by
    # grepping the applier for a cluster pattern, deliberately: at Tier A the applier's cluster seam
    # is an authored stub with no `import kubernetes` yet, and a positive grep would pass only on a
    # prose mention of the credential, so a reviewer rewording a docstring could trip it. What makes
    # the split checkable is the negative scan above, which covers every file under scenarios/ except
    # this one -- so moving cluster access into the planner, or adding a second cluster-touching
    # file, both fire regardless of what the applier contains.
    if git ls-files --error-unmatch -- "$APPLIER" >/dev/null 2>&1; then
        state_b="$state_b; the one excluded file ($APPLIER) is present"
    elif [ -f "$APPLIER" ]; then
        state_b="$state_b; the one excluded file ($APPLIER) exists but is untracked (pre-commit)"
    else
        printf '%s:0: the file scoped out of the cluster scan does not exist, so the exclusion is dangling   <-- [applier-absent]\n' \
            "$APPLIER" >> "$hits_b"
    fi
fi

# --- (c) no import edge between agents/ and scenarios/, either direction ------------------------
edge_scanned=0
if [ -d agents ]; then
    list_tracked "$files_agents" 'agents/*'
    agents_count=$lt_count
else
    : > "$files_agents"
    agents_count=0
fi
if [ -d scenarios ]; then
    list_tracked "$files_scenarios" 'scenarios/*'
    scenarios_count=$lt_count
else
    : > "$files_scenarios"
    scenarios_count=0
fi

if [ "$agents_count" -eq 0 ] && [ "$scenarios_count" -eq 0 ]; then
    state_c="vacuous — neither agents/ nor scenarios/ holds a tracked file"
else
    if [ "$agents_count" -gt 0 ]; then
        SCAN_LIST=$files_agents
        SCAN_HITS=$hits_c
        scan agents-imports-scenarios "$PAT_AGENTS_IMPORTS_SCENARIOS"
        edge_scanned=$((edge_scanned + agents_count))
    fi
    if [ "$scenarios_count" -gt 0 ]; then
        SCAN_LIST=$files_scenarios
        SCAN_HITS=$hits_c
        scan scenarios-imports-agents "$PAT_SCENARIOS_IMPORTS_AGENTS"
        edge_scanned=$((edge_scanned + scenarios_count))
    fi
    state_c="scanned $edge_scanned tracked file(s) under agents/ and scenarios/ in both directions"
fi

# --- report ------------------------------------------------------------------------------------
count_a=$(awk 'END { print NR }' "$hits_a")
count_b=$(awk 'END { print NR }' "$hits_b")
count_c=$(awk 'END { print NR }' "$hits_c")
total=$((count_a + count_b + count_c))

if [ "$total" -gt 0 ]; then
    {
        printf 'scenario-guard: FAIL — %s hit(s): block (a) %s, block (b) %s, block (c) %s\n\n' \
            "$total" "$count_a" "$count_b" "$count_c"
        if [ "$count_a" -gt 0 ]; then
            echo "(a) determinism — the planner reads a clock or takes an unseeded draw:"
            cat "$hits_a"
            echo
            printf '  wall-clock      %s\n' "$PAT_CLOCK"
            printf '  generated-id    %s\n' "$PAT_UUID"
            printf '  module-random   %s\n' "$PAT_MODULE_RANDOM"
            echo
            echo "  Fix the code: offsets are integers from t0 and t0 lives only in the applier;"
            echo "  event_id is a digest over the event's own fields; every draw comes from the one"
            echo "  random.Random seeded at entry from the whole cell key."
            echo
        fi
        if [ "$count_b" -gt 0 ]; then
            echo "(b) plan/apply split — the planner reaches the cluster, or the applier does not:"
            cat "$hits_b"
            echo
            printf '  k8s-import      %s\n' "$PAT_K8S_IMPORT"
            printf '  kubectl         %s\n' "$PAT_KUBECTL"
            printf '  kubeconfig      %s\n' "$PAT_K8S_CONFIG"
            printf '  raw-network     %s\n' "$PAT_NETWORK"
            echo
            echo "  Fix the code: cluster access belongs in $APPLIER and nowhere else under"
            echo "  scenarios/. A planner that can reach a cluster cannot be replayed without one,"
            echo "  and traceability row T-17's evidence would then need M1."
            echo
        fi
        if [ "$count_c" -gt 0 ]; then
            echo "(c) trust boundary — an import edge between agents/ and scenarios/:"
            cat "$hits_c"
            echo
            printf '  agents-imports-scenarios   %s\n' "$PAT_AGENTS_IMPORTS_SCENARIOS"
            printf '  scenarios-imports-agents   %s\n' "$PAT_SCENARIOS_IMPORTS_AGENTS"
            echo
            echo "  Fix the code: the injection harness sits outside the trust boundary"
            echo "  docs/02-architecture.md section 5 draws it outside. An agent that can import"
            echo "  scenarios/ can read the ground truth it is scored against."
            echo
        fi
        echo "There is no exemption mechanism by design — see this script's header."
    } >&2
    exit 1
fi

printf 'scenario-guard: PASS — block (a) determinism tripwire: %s; block (b) plan/apply split: %s; block (c) trust boundary: %s; no hits\n' \
    "$state_a" "$state_b" "$state_c"
exit 0
