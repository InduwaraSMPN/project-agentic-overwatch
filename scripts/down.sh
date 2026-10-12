#!/bin/sh
#
# down.sh -- tear the M1 environment down, leaving volumes intact. Backs `make down`, whose
# contract is docs/04-repo-conventions.md section 3: the row reads "full env from
# infra/versions.env on clean machine / teardown / destroy incl. volumes" across up, down and
# nuke, so "incl. volumes" is what distinguishes nuke, and down is the teardown that does not.
#
# WHAT "LEAVING VOLUMES INTACT" HAS TO MEAN ON A KIND CLUSTER, AND WHY
# On kind there is no volume layer that survives the cluster. The nodes are Docker containers; a
# PersistentVolume provisioned by the default local-path provisioner is a directory inside a node
# container's filesystem, and the container image cache lives in the same place. `kind delete
# cluster` removes those containers together with their anonymous volumes. So on this substrate,
# deleting the cluster IS deleting the volumes, and any reading of `down` that deletes the cluster
# makes section 3's three-way distinction collapse into two: down and nuke would differ only in
# whether they also removed the Docker network.
#
# The reading taken here is therefore the one that keeps the three targets genuinely distinct:
#
#   down  removes the workloads -- the application, the load generator and the observability
#         stack -- and leaves the cluster, its nodes, its CNI, its image cache, its namespaces and
#         every PersistentVolumeClaim exactly where they are.
#   nuke  deletes the cluster, and with it the node containers and everything inside them.
#
# The operational difference is the point of having both. After `down`, `up` is a re-apply against
# a warm cluster: no cluster creation, no image pulls, tens of seconds. After `nuke`, `up` is a
# cold bring-up: a new cluster, a full pull of every pinned digest, minutes. `down` is what you run
# between experiments on one machine; `nuke` is what you run to prove the pins reproduce the
# environment from nothing, which is what T-16 and NFR1 actually assert.
#
# WHY CILIUM STAYS
# Cilium is not a workload this environment runs, it is the datapath the cluster runs on. Removing
# it leaves a cluster whose nodes are NotReady and in which nothing can schedule -- a state that is
# neither up nor down, and that no target in section 3 names. It also has no uninstall contract:
# infra/cilium/install.sh is specified as an idempotent installer and nothing more. Leaving it is
# what makes `down` followed by `up` a fast re-apply rather than a slow rebuild.
#
# THE ONE CASE WHERE A VOLUME STILL GOES
# `helm uninstall` deletes the resources a chart templated. A PersistentVolumeClaim created from a
# StatefulSet volumeClaimTemplate survives that, because Kubernetes does not garbage-collect those;
# a PVC that the chart itself templates, as charts with a `persistence.enabled` switch do, does
# not. Grafana is installed with persistence off per the M1 plan, so this does not bite today, but
# it is recorded here rather than discovered later: if a future values file turns persistence on
# for any observability release, that release's PVC is deleted by `down` and this header's promise
# stops being true for it. The fix at that point is to uninstall that release with its PVC
# retained, not to widen the promise.
#
# IDEMPOTENCE
# Running against a machine with no cluster is a success, not an error: there is nothing to tear
# down and the post-condition already holds. Every deletion is --ignore-not-found for the same
# reason. Running `down` twice must be indistinguishable from running it once.
#
# ENVIRONMENT
#   KIND_CLUSTER_NAME  overrides the cluster name; the default derivation is scripts/up.sh's
#   COMPONENTS_FILE    declared component set, default infra/status/components.yaml
#
# STREAMS
#   stdout carries exactly one summary line; progress, detail and failures go to stderr. Exit 0
#   when the environment is down (or was never up), 1 naming the layer that would not go.
#
# PORTABILITY
#   Strict POSIX sh, as with every other script in this directory.

set -eu

LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

COMPONENTS_FILE=${COMPONENTS_FILE:-infra/status/components.yaml}
KIND_CONFIG=infra/kind-config.yaml
BOUTIQUE_OVERLAY=infra/boutique
LOCUST_MANIFEST=infra/locust/deployment.yaml
MONITOR_OVERLAY=monitor/deploy
GUARDIAN_MANIFEST=guardian/deploy/deployment.yaml
G2_RBAC=guardian/deploy/g2-rbac.yaml

LAYER_TOTAL=6
layer_index=0

progress() {
    layer_index=$((layer_index + 1))
    printf 'down: [%s/%s] %s\n' "$layer_index" "$LAYER_TOTAL" "$1" >&2
}

detail() {
    printf 'down:       %s\n' "$1" >&2
}

die() {
    printf 'down: FAILED while removing %s\n' "$1" >&2
    printf '%s\n' "$2" >&2
    printf 'down: FAIL — %s\n' "$1"
    exit 1
}

# Same fourteen lines of awk as scripts/up.sh and scripts/status.sh; see the note in up.sh for why
# the parser is duplicated rather than extracted into a sixth script.
component_field() {
    awk -v want="$1" -v key="$2" '
        {
            line = $0
            sub(/\r$/, "", line)
            sub(/^[ \t]+/, "", line)
            if (line == "" || substr(line, 1, 1) == "#") next
            isnew = 0
            if (substr(line, 1, 2) == "- ") {
                isnew = 1
                line = substr(line, 3)
                sub(/^[ \t]+/, "", line)
            }
            ci = index(line, ":")
            if (ci == 0) next
            k = substr(line, 1, ci - 1)
            v = substr(line, ci + 1)
            sub(/^[ \t]+/, "", v)
            sub(/[ \t]+$/, "", v)
            sub(/^"/, "", v)
            sub(/"$/, "", v)
            if (k !~ /^[A-Za-z_][A-Za-z0-9_]*$/) next
            if (isnew) { inrec = (k == "id" && v == want) }
            else if (inrec && k == key) { print v; exit }
        }' "$COMPONENTS_FILE"
}

if [ ! -f "$COMPONENTS_FILE" ]; then
    printf 'down: FAIL — declared component set not found at %s\n' "$COMPONENTS_FILE" >&2
    printf 'down: FAIL — component set missing\n'
    exit 1
fi

OBSERVABILITY_NS=$(component_field prometheus namespace)
[ -n "$OBSERVABILITY_NS" ] || OBSERVABILITY_NS=observability
FALCO_NS=$(component_field falco namespace)
[ -n "$FALCO_NS" ] || FALCO_NS=monitor

cluster_name=${KIND_CLUSTER_NAME:-}
if [ -z "$cluster_name" ] && [ -f "$KIND_CONFIG" ]; then
    cluster_name=$(awk '/^name:[ \t]/ {
                       v = $2
                       sub(/\r$/, "", v)
                       gsub(/"/, "", v)
                       print v
                       exit
                   }' "$KIND_CONFIG")
fi
[ -n "$cluster_name" ] || cluster_name=kind
kube_context="kind-${cluster_name}"

if ! command -v kubectl >/dev/null 2>&1; then
    printf 'down: FAIL — kubectl is not on PATH, so nothing can be removed\n' >&2
    printf 'down: FAIL — kubectl absent\n'
    exit 1
fi

# Nothing to tear down is the post-condition, not an error. Reported explicitly so that a caller
# who expected a cluster to be there finds out from this line rather than from a silent success.
if ! kubectl --context "$kube_context" get --raw=/version >/dev/null 2>&1; then
    printf 'down: no reachable cluster on context %s — nothing to tear down\n' "$kube_context" >&2
    printf 'down: PASS — nothing to tear down (no cluster on context %s)\n' "$kube_context"
    exit 0
fi

kubectl_ctx() {
    kubectl --context "$kube_context" "$@"
}

# --- layer 1: Guardian ---------------------------------------------------------------------------

progress "Guardian"
if [ -f "$G2_RBAC" ]; then
    kubectl_ctx delete -f "$G2_RBAC" --ignore-not-found >/dev/null || \
        die "Guardian G2 identity" "failed to remove the scoped G2 identity"
fi
if [ -f "$GUARDIAN_MANIFEST" ]; then
    # Delete the workload and Service, but retain the audit PVC and signing Secret. Deleting the
    # multi-document file would remove the PVC and violate this target's volume-retention contract.
    kubectl_ctx -n guardian delete deployment guardian service guardian --ignore-not-found || \
        die "Guardian" "failed to remove the Guardian workload"
    kubectl_ctx -n guardian delete configmap guardian-runtime --ignore-not-found >/dev/null || \
        die "Guardian" "failed to remove Guardian runtime configuration"
fi

# --- layer 2: Falco -----------------------------------------------------------------------------

progress "Falco releases in namespace $FALCO_NS"
if ! command -v helm >/dev/null 2>&1; then
    detail "helm is not on PATH — skipping Falco releases"
else
    releases=$(helm --kube-context "$kube_context" list -n "$FALCO_NS" -q 2>/dev/null || true)
    if [ -z "$releases" ]; then
        detail "no helm releases in $FALCO_NS"
    else
        for release in $releases; do
            detail "helm uninstall $release"
            if ! helm --kube-context "$kube_context" uninstall "$release" \
                 -n "$FALCO_NS" --wait >/dev/null; then
                die "Falco" "helm uninstall $release failed; see its output above"
            fi
        done
    fi
fi

# --- layer 3: evidence aggregator ---------------------------------------------------------------

progress "Monitor evidence aggregator"
if [ ! -f "$MONITOR_OVERLAY/kustomization.yaml" ]; then
    detail "$MONITOR_OVERLAY/kustomization.yaml is absent — nothing applied from it to remove"
else
    # Retain the evidence PVC just as the Guardian and observability layers retain their data.
    if ! kubectl_ctx -n monitor delete deployment evidence-aggregator service evidence-aggregator \
         configmap evidence-aggregator-config --ignore-not-found; then
        die "Monitor evidence aggregator" "failed to remove the Monitor workload without deleting its evidence PVC"
    fi
fi

# --- layer 4: observability ---------------------------------------------------------------------

# Releases are enumerated with `helm list -q` rather than uninstalled by name, so that this script
# holds no copy of the release names infra/observability/install.sh chooses. A name written down
# in two places is a name that will disagree in one of them.
progress "observability releases in namespace $OBSERVABILITY_NS"
if ! command -v helm >/dev/null 2>&1; then
    detail "helm is not on PATH — skipping the observability releases"
else
    releases=$(helm --kube-context "$kube_context" list -n "$OBSERVABILITY_NS" -q 2>/dev/null || true)
    if [ -z "$releases" ]; then
        detail "no helm releases in $OBSERVABILITY_NS"
    else
        for release in $releases; do
            detail "helm uninstall $release"
            if ! helm --kube-context "$kube_context" uninstall "$release" \
                 -n "$OBSERVABILITY_NS" --wait >/dev/null; then
                die "observability" "helm uninstall $release failed; see its output above"
            fi
        done
    fi
fi

# The namespace itself is deliberately left standing. Deleting a namespace deletes every
# PersistentVolumeClaim in it, which is the one thing this target promises not to do.
detail "namespace $OBSERVABILITY_NS retained, with any PersistentVolumeClaims in it"

# --- layer 5: Locust ---------------------------------------------------------------------------

progress "Locust"
if [ ! -f "$LOCUST_MANIFEST" ]; then
    detail "$LOCUST_MANIFEST is absent — nothing applied from it to remove"
else
    if ! kubectl_ctx delete -f "$LOCUST_MANIFEST" --ignore-not-found; then
        die "Locust" "kubectl delete -f $LOCUST_MANIFEST failed; see its output above"
    fi
fi

# --- layer 6: Online Boutique --------------------------------------------------------------------

progress "Online Boutique"
if [ ! -f "$BOUTIQUE_OVERLAY/kustomization.yaml" ]; then
    detail "$BOUTIQUE_OVERLAY/kustomization.yaml is absent — nothing applied from it to remove"
else
    # Deleting through the same overlay that created it is what keeps this exact: it removes what
    # the overlay declares and nothing else, so a workload somebody added to the namespace by hand
    # is left alone rather than silently swept up by a namespace deletion.
    if ! kubectl_ctx delete -k "$BOUTIQUE_OVERLAY" --ignore-not-found; then
        die "Online Boutique" "kubectl delete -k $BOUTIQUE_OVERLAY failed; see its output above"
    fi
fi

# --- report --------------------------------------------------------------------------------------

# The retained-claim count is printed as evidence rather than asserted in prose. "Volumes intact"
# is a promise, and a promise that prints its own count is one a reader can check against the
# cluster in one command.
pvc_count=$(kubectl_ctx get pvc --all-namespaces --no-headers 2>/dev/null | awk 'END { print NR }')
node_count=$(kubectl_ctx get nodes --no-headers 2>/dev/null | awk 'END { print NR }')

printf 'down: PASS — workloads removed on context %s; cluster kept (%s node(s)), %s PersistentVolumeClaim(s) retained; run `make nuke` to destroy the cluster and its volumes\n' \
    "$kube_context" "$node_count" "$pvc_count"
exit 0
