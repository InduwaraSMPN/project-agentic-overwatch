#!/bin/sh
# grep_guard.sh — machine enforcement of the guardian-first iron rule (AGENTS.md 1) (rule 10).
#
# WHAT RULE 10 SAYS
# Code under agents/ never imports a Kubernetes client, never shells out to kubectl, and never
# opens a connection to the cluster API. The only mutation path from an agent to the cluster is
# the Guardian client in agents/tools/, so that every mutation passes the Guardian's
# deny-by-default reference monitor and is recorded in its audit log. One direct client call
# under agents/ silently voids that guarantee for the whole study: the mediated arm would no
# longer be mediated, and the security results would describe a system that is not the one built.
#
# WHY FIVE PATTERNS AND NOT ONE
# The first two are the literal rule: an import of the Kubernetes client library, and a shell-out
# to kubectl. The last three are defence in depth, because a plain import grep is trivially
# defeated — `import kubernetes as k8s` aliased once at the top of a module leaves no later line
# that names the library, and every call site afterwards reads as `k8s.…`. So the guard also looks
# for what such code must do regardless of how the import was spelled: pattern 3 names the
# generated API client classes, pattern 4 names the three loaders a client must call before it can
# reach a cluster (kubeconfig or in-cluster service account), and pattern 5 names the environment
# variable that points a client at a cluster. Between them they cover the config-load and call
# sites even when the import itself has been renamed out of sight.
#
# THERE IS DELIBERATELY NO EXEMPTION MECHANISM
# No allowlist file, no inline `# noqa`-style sentinel, no per-path skip, and no file-class
# filter: every tracked file under agents/ is scanned, whatever its extension, prose included.
# If M4 produces a legitimate false positive — the likely one being prompt registry text that
# names kubectl while describing what an Executor may ask the Guardian to do on its behalf —
# that is a decision about how the guardrail is scoped and worded, and it is taken at M4 with an
# ADR recording the alternatives. It is not a hole punched into the guard at M0, where there is
# no evidence yet about what the real false positives look like and any exemption would be
# written blind. An exemption mechanism added before the first true positive is an exemption
# mechanism sized to convenience rather than to risk, and a file-class filter is that same hole
# under a tidier name: it silently drops whole classes of file from the scan without ever
# reporting what it dropped.
#
# UNTIL THAT ADR EXISTS, THE PROSE MOVES, NOT THE CHECK
# Prose under agents/ that needs to describe rule 10 states the constraint without naming the
# binary — agents/README.md's rule-10 paragraph names the Kubernetes command-line client
# descriptively for exactly this reason. That costs one sentence today and keeps the guard
# honest about what it has actually read. Whether M4's prompt registry can live under the same
# discipline, or needs the scope narrowed, is the open question the M0 plan reserves for an M4
# ADR; nothing here pre-empts it.
#
# SCOPE AND EXIT CODES
# Tracked files only (git ls-files), so an untracked local scratch file cannot fail CI and the
# check sees exactly what a fresh clone contains. Exit 0 on a clean scan or a vacuous pass —
# vacuous meaning agents/ is absent, or holds no tracked files at all, both of which are the
# expected pre-M4 state — exit 1 on any hit. Strict POSIX sh: this runs under dash on WSL2
# Ubuntu and on ubuntu-latest.

set -eu

# Repo root derived from this script's own location, so behaviour is identical whether the script
# is invoked by make, by CI, or by hand from an arbitrary working directory.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

# agents/ is created at M4. A guard that goes red on every pull request from M0 to M4 is a guard
# nobody is still reading by the time it has something to say, so the pre-M4 state is an explicit
# vacuous pass rather than a failure.
if [ ! -d agents ]; then
    echo "grep-guard: agents/ absent (pre-M4) — rule 10 guard vacuously passes"
    exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
files="$work/files"
hits="$work/hits"
: > "$hits"

git ls-files -z -- 'agents/*' | tr '\0' '\n' > "$files"

# `tr` is the POSIX-portable way to consume -z output; `read -d ''` is a bashism. The only case in
# which that conversion is ambiguous is a tracked path containing a literal newline, so compare
# the two encodings and prove it rather than assume it. git quotes such a path on the non-z path,
# which collapses it to one line, so the counts diverge exactly when the assumption breaks.
z_lines=$(wc -l < "$files" | tr -d ' ')
nl_lines=$(git ls-files -- 'agents/*' | wc -l | tr -d ' ')
if [ "$z_lines" != "$nl_lines" ]; then
    echo "grep-guard: refusing to run — a tracked path under agents/ contains a newline" >&2
    exit 1
fi

if [ "$z_lines" -eq 0 ]; then
    echo "grep-guard: agents/ absent-or-empty — no tracked files at all (pre-M4); rule 10 guard vacuously passes"
    exit 0
fi

# Every tracked path under agents/ is a candidate; there is no filtering step between the
# candidate list and the scan.
scan_count=$z_lines

# scan <pattern-name> <extended-regex>
# Appends one line per hit to $hits, formatted path:line: <matching line>, tagged with the pattern
# that fired. -I skips binary files; -E is required because the patterns are extended regexes.
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
        done >> "$hits"
    done < "$files"
}

scan k8s-import       '^[[:space:]]*(import|from)[[:space:]]+kubernetes(_asyncio)?\b'
scan kubectl-shellout '\bkubectl\b'
scan k8s-api-class    '\bclient\.(Core|Apps|Batch|Rbac)V1(beta1)?Api\b'
scan k8s-config-load  '\bkubernetes\.config\.load_|\bincluster_config\b|\bkube_config\b'
scan kubeconfig-env   '\bKUBECONFIG\b'

hit_count=$(wc -l < "$hits" | tr -d ' ')

if [ "$hit_count" -gt 0 ]; then
    {
        echo "grep-guard: FAIL — the guardian-first iron rule (AGENTS.md 1) violated ($hit_count hit(s))"
        echo
        cat "$hits"
        echo
        echo "Patterns:"
        echo "  k8s-import        ^[[:space:]]*(import|from)[[:space:]]+kubernetes(_asyncio)?\b"
        echo "  kubectl-shellout  \bkubectl\b"
        echo "  k8s-api-class     \bclient\.(Core|Apps|Batch|Rbac)V1(beta1)?Api\b"
        echo "  k8s-config-load   \bkubernetes\.config\.load_|\bincluster_config\b|\bkube_config\b"
        echo "  kubeconfig-env    \bKUBECONFIG\b"
        echo
        echo "Fix the code: route the action through the Guardian client in agents/tools/."
        echo "There is no exemption mechanism by design — see this script's header."
    } >&2
    exit 1
fi

# RULE 10 AMENDMENT (ADR-131, D1-A): ONLY runner/ MAY IMPORT runner.egress_shim
# D1-A gives the agent layer exactly one alternate mutation path, the cluster_api_request tool,
# transported by runner/egress_shim.py and live only under G2-SHAREDCRED. The shim is the entire
# width of that exception, so its dependency arrow must point ONE way: the runner injects the
# transport into agents/ as a callable on NodeContext.cluster_api_transport, and nothing under
# agents/ ever imports the shim (which would make the agent layer depend on the runner and, worse,
# give it an in-process handle to the module that opens the socket). guardian/ and monitor/ never
# touch it either, for the reason iron rule 1 applies to them: the alternate path is a property of
# the ARM's condition flags, and the flags are the only thing that may set it. The shim's own
# docstring REPORTS this check; it is IMPLEMENTED here because CI runs this script.
#
# IMPORTS, not mentions. A docstring that names the module — agents/graphs/nodes.py names it where a
# reader learns what the transport is, correctly — is not a violation; an import line is. So the
# pattern is anchored to an import/from statement, exactly as runner/tests/test_egress_shim.py's two
# guard cases assert. runner/ itself is the one permitted importer and is excluded from the scan.
egress_hits="$work/egress_hits"
: > "$egress_hits"
egress_files="$work/egress_files"
git ls-files -- '*.py' > "$egress_files"
egress_scanned=0
while IFS= read -r egress_file; do
    [ -n "$egress_file" ] || continue
    case "$egress_file" in
        runner/*) continue ;;
    esac
    egress_scanned=$((egress_scanned + 1))
    grep -nEI -e '^[[:space:]]*(import|from)[[:space:]].*egress_shim' -- "$egress_file" 2>/dev/null \
        | while IFS= read -r egress_hit; do
            printf '%s:%s   <-- [egress-shim-import]\n' "$egress_file" "$egress_hit"
        done >> "$egress_hits"
done < "$egress_files"

egress_count=$(wc -l < "$egress_hits" | tr -d ' ')
if [ "$egress_count" -gt 0 ]; then
    {
        echo "grep-guard: FAIL — runner.egress_shim imported outside runner/ ($egress_count hit(s))"
        echo
        cat "$egress_hits"
        echo
        echo "Only runner/ may import runner.egress_shim (iron rule 1 as amended by ADR-131, D1-A)."
        echo "agents/ receives the transport as an injected callable on"
        echo "NodeContext.cluster_api_transport and imports no network library and never the shim;"
        echo "guardian/ and monitor/ never touch it. The direct API path is a property of the arm's"
        echo "condition flags, which are the only thing that may set it."
    } >&2
    exit 1
fi

echo "grep-guard: PASS — scanned $scan_count tracked file(s) under agents/ against 5 rule-10 patterns; no hits"
echo "grep-guard: PASS — scanned $egress_scanned non-runner python file(s) for a runner.egress_shim import; no hits"
exit 0
