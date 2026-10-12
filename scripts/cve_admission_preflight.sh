#!/bin/sh
# scripts/cve_admission_preflight.sh -- fail closed before a CVE scenario's injection t0 unless
# every image its incident admits is already on every kind node and its target Deployment is fully
# Ready on the UNPATCHED (patched-pin) baseline. Backs supervisor ruling B1's second sentence: "an
# admission preflight (image present and rollout Ready) before injection t0."
#
# WHY THIS CHECK EXISTS
#   2026-09-13: an uncached image pull observed inside a timed run took 4m58s -- a `kubectl debug`
#   or Deployment patch that has to pull a multi-hundred-megabyte image from a registry mid-run
#   contaminates every latency and wall-clock figure the run measures, exactly as
#   docs/protocols/data-management.md section 4 already treats a probe-timeline gap as a validity
#   defect and not merely a slow sample. Preloading every scenario image into the kind nodes at
#   bring-up (this stream's other change, wired into scripts/up.sh) is the fix; this script is what
#   makes "preloaded" a checked fact rather than an assumption a run's first injected primitive
#   discovers the hard way, 30 seconds into its own timed window.
#
# WHAT THIS SCRIPT CHECKS, AND WHAT IT DELIBERATELY DOES NOT
#   For the named scenario's images.yaml entry: the vulnerable image is resolvable in every kind
#   node's containerd image store (`crictl inspecti`, run inside the node container via `docker
#   exec`, the same node-introspection shape scripts/netpol_proof.sh already uses to discover node
#   names rather than hard-coding them). And: the entry's `component` Deployment (adservice, for both
#   entries this corpus holds today, but this script reads the field rather than hard-coding the
#   name) is fully Ready in the `boutique` namespace on ITS OWN current image -- i.e. the baseline
#   BEFORE any incident primitive has patched it, so a preflight that passed on an already-
#   compromised Deployment left over from an aborted run cannot be mistaken for a clean environment.
#   It does not check NetworkPolicies (apply.py's own `_verify_clean_start`, ADR-081, already owns
#   that), and it makes no cluster mutation of any kind: every check below is a read.
#
#   It refuses to run at all while either digest is the PENDING sentinel (empty), rather than
#   reporting a vacuous pass or a confusing "image not found": an unpinned entry has no image
#   reference to check presence for yet, and scenarios/cve/images.yaml's own header already commits
#   this corpus to failing an unpinned entry closed rather than skipping it (the same discipline
#   scripts/cve_mirror.sh --verify keeps).
#
# WHY THIS LIVES UNDER scripts/, NOT scenarios/cve/
#   It was first written at scenarios/cve/admission_preflight.sh, beside the catalog it reads, on the
#   principle that keeps scenarios/attackers/apply.py's own `_verify_clean_start` beside the applier.
#   scripts/scenario_guard.sh's own block (b) proved that placement wrong: that guard enforces
#   "the planner does not reach the cluster; only the applier does" by scanning every tracked .py and
#   .sh under scenarios/ EXCEPT the one named applier (scenarios/attackers/apply.py) for `kubectl`,
#   `KUBECONFIG`, a Kubernetes client import or a raw socket -- with no exemption mechanism, by
#   design (its header: "Adding ... a second cluster-touching file ... fires"). This script reads
#   `kubectl` and `docker exec` extensively, by its own design; leaving it under scenarios/ therefore
#   makes `sh scripts/scenario_guard.sh` fail every future run, which is the same failure mode the
#   guard exists to catch. scripts/ is where this repository's other cluster-reading, CVE-adjacent
#   tooling already lives (scripts/cve_mirror.sh, scripts/chaos_preflight.sh, scripts/up.sh, all of
#   which read or would read cluster state freely, because none of them is the planner
#   scenario_guard.sh protects). Moving here is therefore not a convenience relocation; it is what
#   the guard's own boundary requires of any file that reads the cluster and is not the one named
#   exception.
#
# WHAT THIS SCRIPT DOES NOT DO
#   It never mutates the cluster and never builds, pulls or loads an image itself -- that is
#   scripts/cve_mirror.sh's and scenarios/cve/adservice/build_and_pin.sh's job, at Tier B, by an
#   operator who reads the commands first. This script only reads state that Tier B step already
#   produced and reports whether it is present.
#
# USAGE
#   sh scripts/cve_admission_preflight.sh <SCENARIO_ID>
#   e.g. sh scripts/cve_admission_preflight.sh SCN-CVE-04
#
# ENVIRONMENT
#   CVE_IMAGES_FILE     default scenarios/cve/images.yaml, matching scripts/cve_mirror.sh's own
#                       default and the same override reason: a test can drive this script over a
#                       fixture corpus without editing the real one.
#   KUBE_CONTEXT        default the kubeconfig's current context, matching
#                       scripts/chaos_preflight.sh's own convention.
#   BOUTIQUE_NAMESPACE  default boutique, the namespace every scenario manifest's `namespace` field
#                       already names for the CVE arm.
#
# EXIT CODES
#   0   the vulnerable image is present on every node and the target Deployment fully Ready.
#   1   named entry not found, an entry unpinned, the image absent from a node, or the Deployment
#       not fully Ready. The offending fact is named on stderr; stdout carries exactly one summary
#       line, in scripts/cve_mirror.sh's own shape, so a caller can capture the verdict without
#       parsing the report.
#
# PORTABILITY
#   Strict POSIX sh -- no bashisms, no GNU-only options -- matching scripts/cve_mirror.sh and
#   scripts/chaos_preflight.sh. Needs kubectl and docker (for `docker exec <node> crictl ...`,
#   the same node-introspection path scripts/netpol_proof.sh already relies on for a kind cluster).

set -eu
LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

IMAGES_FILE=${CVE_IMAGES_FILE:-scenarios/cve/images.yaml}
NAMESPACE=${BOUTIQUE_NAMESPACE:-boutique}
KUBE_CONTEXT=${KUBE_CONTEXT:-}

usage() {
    echo "usage: sh scripts/cve_admission_preflight.sh <SCENARIO_ID>" >&2
    echo "  e.g.  sh scripts/cve_admission_preflight.sh SCN-CVE-04" >&2
}

scenario_id=${1:-}
if [ -z "$scenario_id" ]; then
    usage
    printf 'cve-admission-preflight: FAIL -- no scenario_id given\n'
    exit 1
fi

if [ -z "$KUBE_CONTEXT" ]; then
    KUBE_CONTEXT=$(kubectl config current-context 2>/dev/null || true)
fi
if [ -z "$KUBE_CONTEXT" ]; then
    printf 'cve-admission-preflight: FAIL -- no kubectl context\n'
    exit 1
fi
kc() { kubectl --context "$KUBE_CONTEXT" "$@"; }

if [ ! -f "$IMAGES_FILE" ]; then
    printf 'cve-admission-preflight: FAIL -- %s not found\n' "$IMAGES_FILE"
    exit 1
fi

# --- read the one entry this scenario_id names, with the same column-anchored parser
# scripts/cve_mirror.sh uses, so the two readers of this file can never disagree about a field's
# value. Duplicated rather than shared for the same reason scripts/up.sh gives for its own copy of
# scripts/status.sh's parser: the file set this task creates is fixed, and a shared parser module
# would be a new cross-script dependency for a few dozen lines of awk.
row=$(awk -v want="$scenario_id" '
    function emit() {
        if (id == "" || scenario_id != want) return
        printf "%s|%s|%s|%s|%s\n", id, component, repository, digest, patched_digest
    }
    {
        line = $0
        sub(/\r$/, "", line)
        indent = line
        sub(/[^ ].*$/, "", indent)
        col = length(indent)
        body = substr(line, col + 1)
        if (body == "" || substr(body, 1, 1) == "#") next
        isnew = 0
        if (substr(body, 1, 2) == "- ") { isnew = 1; body = substr(body, 3); col = col + 2 }
        ci = index(body, ":")
        if (ci == 0) next
        k = substr(body, 1, ci - 1)
        if (k !~ /^[A-Za-z_][A-Za-z0-9_]*$/) next
        if (isnew) {
            emit()
            field_col = col
            id = ""; scenario_id = ""; component = ""; repository = ""
            digest = ""; patched_digest = ""
        } else {
            if (id == "") next
            if (col != field_col) next
        }
        v = substr(body, ci + 1)
        sub(/^ +/, "", v); sub(/ +$/, "", v); sub(/^"/, "", v); sub(/"$/, "", v)
        if (k == "id") id = v
        else if (k == "scenario_id") scenario_id = v
        else if (k == "component") component = v
        else if (k == "repository") repository = v
        else if (k == "digest") digest = v
        else if (k == "patched_digest") patched_digest = v
    }
    END { emit() }
' "$IMAGES_FILE")

if [ -z "$row" ]; then
    printf 'cve-admission-preflight: FAIL -- %s declares no entry for scenario_id %s\n' \
        "$IMAGES_FILE" "$scenario_id" >&2
    printf 'cve-admission-preflight: FAIL -- no entry for %s\n' "$scenario_id"
    exit 1
fi

IFS='|' read -r e_id e_component e_repo e_digest e_patched_digest <<EOF
$row
EOF

if [ -z "$e_digest" ] || [ -z "$e_patched_digest" ]; then
    printf 'cve-admission-preflight: FAIL -- %s (%s): vulnerable or patched digest is empty\n' \
        "$e_id" "$scenario_id" >&2
    printf 'cve-admission-preflight: FAIL -- %s unpinned\n' "$e_id"
    printf '  fails closed, not skipped -- same discipline as scripts/cve_mirror.sh --verify\n' >&2
    exit 1
fi

case "$e_digest" in
    sha256:*) digest_hex=${e_digest#sha256:} ;;
    *) digest_hex="" ;;
esac
case "$digest_hex" in
    *[!0-9a-f]*) digest_hex="" ;;
esac
if [ "${#digest_hex}" -ne 64 ]; then
    printf 'cve-admission-preflight: FAIL -- %s: digest %s is not sha256:<64 hex>\n' \
        "$e_id" "$e_digest" >&2
    printf 'cve-admission-preflight: FAIL -- %s malformed digest\n' "$e_id"
    exit 1
fi

vulnerable_ref="${e_repo}@${e_digest}"
# Only the vulnerable image's presence is checked against the nodes below. That is the one the cve
# mechanism ADMITS mid-run, so it is the one a slow first-time pull would stall a timed run on; the
# patched image is not re-checked here because it is the exact image adservice already runs
# everywhere the CVE arm is not exercising it, kept present by the fleet's own ordinary bring-up
# rather than by anything this script or scripts/cve_mirror.sh loads. e_patched_digest is read above
# only so a malformed or empty patched_digest is caught by the unpinned-entry check, alongside its
# vulnerable-half sibling.

nodes=$(kc get nodes -o name 2>/dev/null | sed 's|^node/||')
if [ -z "$nodes" ]; then
    printf 'cve-admission-preflight: FAIL -- no nodes visible on context %s\n' "$KUBE_CONTEXT" >&2
    printf 'cve-admission-preflight: FAIL -- no nodes\n'
    exit 1
fi

missing=""
for node in $nodes; do
    if ! docker exec "$node" crictl inspecti "$vulnerable_ref" >/dev/null 2>&1; then
        missing="$missing $node"
    fi
done
if [ -n "$missing" ]; then
    printf 'cve-admission-preflight: FAIL -- %s absent from node(s):%s\n' "$vulnerable_ref" "$missing" >&2
    printf '  preload it: sh scripts/cve_mirror.sh --load (after --save and a recorded tarball_sha256)\n' >&2
    printf 'cve-admission-preflight: FAIL -- vulnerable image not preloaded on%s\n' "$missing"
    exit 1
fi

ready=$(kc -n "$NAMESPACE" get deployment "$e_component" \
    -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)
desired=$(kc -n "$NAMESPACE" get deployment "$e_component" \
    -o jsonpath='{.spec.replicas}' 2>/dev/null || true)
if [ -z "$desired" ]; then
    printf 'cve-admission-preflight: FAIL -- deployment/%s not found in namespace %s\n' \
        "$e_component" "$NAMESPACE" >&2
    printf 'cve-admission-preflight: FAIL -- deployment/%s absent\n' "$e_component"
    exit 1
fi
ready=${ready:-0}
if [ "$ready" -lt "$desired" ]; then
    printf 'cve-admission-preflight: FAIL -- deployment/%s is %s/%s ready in %s\n' \
        "$e_component" "$ready" "$desired" "$NAMESPACE" >&2
    printf 'cve-admission-preflight: FAIL -- deployment/%s not fully Ready (%s/%s)\n' \
        "$e_component" "$ready" "$desired"
    exit 1
fi

printf 'cve-admission-preflight: PASS -- %s preloaded on %s node(s); deployment/%s %s/%s Ready\n' \
    "$vulnerable_ref" "$(printf '%s\n' "$nodes" | wc -l | tr -d ' ')" "$e_component" "$ready" "$desired"
exit 0
