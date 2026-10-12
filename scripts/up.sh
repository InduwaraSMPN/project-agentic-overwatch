#!/bin/sh
#
# up.sh -- bring the full M1 environment up from a clean machine, in the only order that works,
# and refuse to report success over a partial one. Backs `make up`, whose contract is
# docs/04-repo-conventions.md section 3: "full env from infra/versions.env on clean machine".
#
# WHY THE ORDER IS NOT NEGOTIABLE
#   preflight   Everything below mutates the host. Discovering an absent `kind` binary or an empty
#               chart pin after a cluster exists means tearing that cluster down again.
#   cluster     Nothing schedules without nodes.
#   Cilium      infra/kind-config.yaml sets disableDefaultCNI, so the nodes come up NotReady and
#               stay NotReady until a CNI is installed. Every workload below waits on node
#               readiness, so every workload below waits on this.
#   Boutique    The application under test, and the thing the load generator and the scrape
#               configuration are pointed at.
#   Locust      Deployed idle, at zero users, and driven per run. It is applied after the
#               application so that its target exists before it is asked to reach it.
#   observability  Last, because a scrape configuration is only verifiable against workloads that
#               already exist, and because the container-restart series kube-state-metrics
#               supplies has nothing to count on an empty cluster.
#   CVE preload Last of all, after Guardian, because it depends on nothing this bring-up installs
#               and nothing downstream depends on it: it is the CVE arm's own image mirror, loaded
#               into every kind node so a scenario's `cve`-mechanism admission never pulls from a
#               registry mid-run. ADR-091 (supervisor ruling B1, 2026-09-13): "a 4m58s uncached
#               pull inside a timed run contaminates latency/wall-clock" -- observed 2026-09-13.
#               Non-fatal when the CVE arm is not yet pinned at Tier B (scenarios/cve/images.yaml's
#               own PENDING-sentinel discipline): the three SIM scenarios need none of this, and a
#               fresh Tier-A checkout must still bring up a fully usable cluster for them.
#
# WHY IT FAILS AT THE FIRST LAYER THAT DOES NOT COME UP
# A `make up` that brings up half the environment and exits 0 is the precise false green the M0
# stub-honesty argument exists to prevent, and it is worse here than a stub would be: every run is
# preflighted by `make status` (docs/protocols/evaluation-protocol.md section 5 rule 1), so a
# half-built environment that reported success would be caught only if status happened to cover
# the missing piece. Each layer therefore has a bounded wait and a named failure, and no layer
# starts before the one beneath it is ready.
#
# IDEMPOTENCE, AND WHAT "CONVERGES" MEANS HERE
# Re-running against a healthy environment must not error. An existing cluster is reported and
# reused rather than recreated -- recreating it would destroy the node containers, their image
# cache and every volume inside them, which is `make nuke`'s job and not this one's. Every apply
# below is a `kubectl apply`, which is declarative and repeatable, and the two installer scripts
# this delegates to are idempotent by their own contract. A second run against a healthy
# environment therefore re-asserts the desired state and re-verifies readiness, which is exactly
# what an operator who is unsure of the state of a machine wants it to do.
#
# WHAT THIS SCRIPT DOES NOT DO
#   It does not run scripts/netpol_proof.sh. Proving that Cilium enforces NetworkPolicy is a
#   separate target with its own bounded runtime, and folding a four-part proof with two node
#   placements into every bring-up would make `make up` slower for a property that does not change
#   between bring-ups of the same pinned stack.
#   It does not author any manifest. T1.1, T1.2 and T1.3 own infra/kind-config.yaml,
#   infra/cilium/install.sh, infra/boutique/, infra/locust/ and infra/observability/. This script
#   composes them. When one of them is missing it says which path is missing and which task owns
#   it, and stops -- it never improvises a substitute, because an environment assembled from
#   improvised parts is not the environment infra/versions.env pins.
#   It does not install tooling. preflight requires the tools; T1.7's fresh-clone workflow is what
#   proves a clean machine can install them from the versions.env pins.
#
# THE CLUSTER NAME
# infra/kind-config.yaml declares no `name:`, and its header documents the by-hand invocation as
# `kind create cluster --config infra/kind-config.yaml --image "$KIND_NODE_IMAGE"`, which produces
# kind's default cluster name. This script passes --name explicitly, because down.sh, nuke.sh and
# the status context assertion all have to be able to say which cluster they are acting on, but it
# defaults to that same kind default so that the scripted and the by-hand cluster are one cluster
# and not two. If infra/kind-config.yaml ever gains a top-level `name:`, that value wins; the
# KIND_CLUSTER_NAME environment variable wins over both.
#
# Overriding it has a consequence worth stating once. kind derives its node names from the cluster
# name, so a non-default name gives nodes called something other than kind-control-plane and
# kind-worker. scripts/netpol_proof.sh discovers node names rather than writing them down, so it
# survives that; scripts/status.sh asserts only that the context begins with `kind-`, so it does
# too. What does not survive is a second cluster: create one under an override and the by-hand
# invocation in infra/kind-config.yaml's header will build a different cluster beside it, and the
# two will compete for the same host memory budget that ADR-001 sizes for one.
#
# THE TIMEOUTS ARE OPERATIONAL, NOT PROTOCOL CONSTANTS
# docs/protocols/evaluation-protocol.md owns every quantity that parameterises the experiment --
# run counts, seeds, budgets, thresholds, the stabilization window. The waits below are none of
# those. They change only how long a broken bring-up takes to admit it is broken; no measurement,
# no bundle field and no analysis depends on them, and a run whose environment came up in 90
# seconds is not different from one whose environment came up in 300. Putting them in section 4
# would add two numbers to a frozen protocol that no result is ever computed from.
#
# ENVIRONMENT
#   KIND_CLUSTER_NAME   overrides the cluster name; see THE CLUSTER NAME above.
#   UP_CLUSTER_TIMEOUT  seconds to wait for the API server and for node registration (default 300)
#   UP_WAIT_TIMEOUT     seconds to wait for each workload layer to become ready (default 600)
#   UP_POLL_INTERVAL    seconds between readiness polls (default 5)
#   VERSIONS_FILE       pins file, default infra/versions.env; passed through to preflight
#   COMPONENTS_FILE     declared component set, default infra/status/components.yaml
#   UP_PROFILE          which components this bring-up is required to raise, default `full` (every
#                       declared component). `substrate` omits the components whose deployment needs
#                       operator-supplied material no ephemeral machine has -- today the Guardian
#                       alone, whose `guardian-signing-key` is operator-supplied out of band and
#                       which ADR-114 forbids any path in this repository from creating. The skip is
#                       derived from the `required_in` field of infra/status/components.yaml, not
#                       restated here, so up.sh and status.sh cannot disagree about the same
#                       environment. A CAMPAIGN OR PILOT BRING-UP MUST USE THE DEFAULT PROFILE:
#                       evaluation-protocol section 5 rule 1 gates every run on a `make status` that
#                       sees the Guardian.
#
# STREAMS
#   stdout carries exactly one summary line, so that a caller can capture the result without
#   parsing progress. Every per-layer progress line, every detail and every failure goes to
#   stderr. Exit 0 only when every layer is up and ready; exit 1 naming the layer otherwise.
#
# PORTABILITY
#   Strict POSIX sh -- no bashisms, no GNU-only options -- so it runs identically under Git Bash on
#   Windows, under dash in WSL2 Ubuntu, and on ubuntu-latest in CI.

set -eu

LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

VERSIONS_FILE=${VERSIONS_FILE:-infra/versions.env}
COMPONENTS_FILE=${COMPONENTS_FILE:-infra/status/components.yaml}
UP_CLUSTER_TIMEOUT=${UP_CLUSTER_TIMEOUT:-300}
UP_WAIT_TIMEOUT=${UP_WAIT_TIMEOUT:-600}
UP_POLL_INTERVAL=${UP_POLL_INTERVAL:-5}
UP_PROFILE=${UP_PROFILE:-full}

case "$UP_PROFILE" in
    full|substrate) ;;
    *)
        printf 'up: FAIL — UP_PROFILE is %s, not one of full, substrate\n' "$UP_PROFILE" >&2
        printf 'up: FAIL — unknown bring-up profile\n'
        exit 1
        ;;
esac

KIND_CONFIG=infra/kind-config.yaml
CILIUM_INSTALL=infra/cilium/install.sh
# Env-overridable (M10, ADR-135) so a CI bring-up can select a resource-request overlay
# (infra/boutique/overlays/ci-bringup: requests only, never replicas, never used by a campaign) that
# sizes Online Boutique to a hosted runner's envelope. The default is unchanged, so a plain `make up`
# and every campaign bring-up applies the same base overlay they always did (V21).
BOUTIQUE_OVERLAY=${BOUTIQUE_OVERLAY:-infra/boutique}
LOCUST_MANIFEST=infra/locust/deployment.yaml
OBSERVABILITY_INSTALL=infra/observability/install.sh
CHAOS_MESH_INSTALL=infra/chaosmesh/install.sh
MONITOR_OVERLAY=monitor/deploy
MONITOR_IMAGE=scripts/monitor_image.sh
MONITOR_INSTALL=infra/monitor/install.sh
GUARDIAN_DEPLOY=scripts/guardian_deploy.sh

# Scenario/run prerequisites (layer 12; ADR-142). Paths, not protocol quantities, so they live here
# with every other layer's path constant rather than in docs/protocols/evaluation-protocol.md.
AGENTS_NETPOL=infra/netpol/agents-default-deny.yaml
PROBE_BUILD=infra/probes/deploy/build.sh
PROBE_NAMESPACE_MANIFEST=infra/probes/deploy/namespace.yaml
# The namespace infra/probes/deploy/namespace.yaml declares, named here so layer 12 can create it
# ahead of the apply (apply_namespace_manifest) rather than racing the ServiceAccount controller.
# It must move with that manifest and with PROBE_NAMESPACE in runner/live_baseline.py, which the
# manifest's own WHAT BREAKS note also says.
PROBE_NAMESPACE=slo-probe
# scenarios/attackers/apply.py::_DEBUG_SHELL_IMAGE is the single source of this tag; this layer's
# job is only to make sure the tag it names exists in every kind node, built from this exact
# pinned upstream digest.
ATTACKER_DEBUG_UPSTREAM_IMAGE=curlimages/curl@sha256:ce8e655b562cf387752de7d2076ec3f81a4383c908f386b6724ec3571ce08b4a
ATTACKER_DEBUG_LOCAL_TAG=overwatch-attacker/curl:local

LAYER_TOTAL=12

# --- output helpers ---------------------------------------------------------------------------

layer_index=0

progress() {
    layer_index=$((layer_index + 1))
    printf 'up: [%s/%s] %s\n' "$layer_index" "$LAYER_TOTAL" "$1" >&2
}

detail() {
    printf 'up:       %s\n' "$1" >&2
}

# Every failure path goes through here, so every failure names a layer and every failure writes
# the same single summary line to stdout that a success writes.
die() {
    printf 'up: FAILED at layer %s/%s (%s)\n' "$layer_index" "$LAYER_TOTAL" "$1" >&2
    printf '%s\n' "$2" >&2
    printf 'up: FAIL — layer %s/%s (%s)\n' "$layer_index" "$LAYER_TOTAL" "$1"
    exit 1
}

# A missing manifest is never improvised around. The message names the path and the task that owns
# it, because "no such file or directory" from three calls deeper tells a reader nothing about
# whether the file is meant to exist yet.
require_path() {
    if [ ! -e "$1" ]; then
        die "$3" "missing $1 — owned by $2, which has not landed it yet"
    fi
}

# --- readers ----------------------------------------------------------------------------------

# One value out of infra/versions.env. index($0, k "=") == 1 anchors the match at column 1, so
# KIND_VERSION cannot answer a lookup for KIND_NODE_IMAGE and a commented-out line cannot answer
# anything.
versions_value() {
    awk -v k="$1" 'index($0, k "=") == 1 {
               v = substr($0, length(k) + 2)
               sub(/\r$/, "", v)
               sub(/[ \t]+$/, "", v)
               print v
               exit
           }' "$VERSIONS_FILE"
}

# One field out of one record of infra/status/components.yaml. The parser is deliberately the same
# shape as the one in scripts/status.sh: strip the CR a Windows checkout may carry, drop blank and
# comment lines, treat a leading "- " as the start of a record, split on the first colon, and strip
# one layer of double quotes. It is duplicated rather than shared because the file set this task
# creates is fixed and a sixth script would be a new entry in the section 1 folder map, a new core
# path in the hygiene EOL list and a new thing to keep in step -- for fourteen lines of awk.
component_field() {
    awk -v want="$1" -v key="$2" '
        {
            line = $0
            sub(/\r$/, "", line)
            sub(/^[ \t]+/, "", line)
            if (line == "" || substr(line, 1, 1) == "#") next
            isnew = 0
            if (substr(line, 1, 2) == "- ") { isnew = 1; line = substr(line, 3); sub(/^[ \t]+/, "", line) }
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

# --- readiness ---------------------------------------------------------------------------------

now_seconds() {
    date +%s
}

# One line per workload in a namespace, as "kind/name|desired|ready", across the three workload
# kinds that carry a replica or scheduling count. jsonpath is used rather than table output
# because column headers and widths are presentation and have changed between kubectl releases,
# whereas these field paths are API. A field that is absent prints empty, which the caller reads
# as zero -- that is deliberate: .status.readyReplicas is simply absent, not zero, on a Deployment
# that has never had a ready pod.
ns_workload_rows() {
    ns_rows_target=$1
    kubectl -n "$ns_rows_target" get deployments -o \
        'jsonpath={range .items[*]}{"deployment/"}{.metadata.name}{"|"}{.spec.replicas}{"|"}{.status.readyReplicas}{"\n"}{end}' \
        2>/dev/null || true
    kubectl -n "$ns_rows_target" get statefulsets -o \
        'jsonpath={range .items[*]}{"statefulset/"}{.metadata.name}{"|"}{.spec.replicas}{"|"}{.status.readyReplicas}{"\n"}{end}' \
        2>/dev/null || true
    kubectl -n "$ns_rows_target" get daemonsets -o \
        'jsonpath={range .items[*]}{"daemonset/"}{.metadata.name}{"|"}{.status.desiredNumberScheduled}{"|"}{.status.numberReady}{"\n"}{end}' \
        2>/dev/null || true
}

# Poll until every workload in the namespace is ready AND at least $2 workloads exist. The second
# half is not redundant: a namespace that is empty, or that has been created but never applied
# into, produces zero rows and therefore zero unready rows, and an all-clear over nothing reads
# exactly like an all-clear over everything. The floor is what makes this a check.
wait_ns_ready() {
    wait_ns=$1
    wait_floor=$2
    wait_label=$3
    wait_deadline=$(( $(now_seconds) + UP_WAIT_TIMEOUT ))
    while : ; do
        wait_rows=$(ns_workload_rows "$wait_ns")
        wait_count=$(printf '%s\n' "$wait_rows" | awk 'NF { n++ } END { print n + 0 }')
        wait_bad=$(printf '%s\n' "$wait_rows" | awk -F'|' 'NF >= 3 {
                       want = ($2 == "" ? 0 : $2 + 0)
                       have = ($3 == "" ? 0 : $3 + 0)
                       if (have < want) { printf "  %s not ready (%d/%d)\n", $1, have, want }
                       else if (index($1, "daemonset/") == 1 && want == 0) {
                           printf "  %s scheduled onto no node (0 desired)\n", $1
                       }
                   }')
        if [ "$wait_count" -ge "$wait_floor" ] && [ -z "$wait_bad" ]; then
            detail "$wait_label ready — $wait_count workload(s) in namespace $wait_ns"
            return 0
        fi
        if [ "$(now_seconds)" -ge "$wait_deadline" ]; then
            {
                printf 'namespace %s did not become ready within %ss\n' "$wait_ns" "$UP_WAIT_TIMEOUT"
                printf '  workloads found: %s (floor %s)\n' "$wait_count" "$wait_floor"
                if [ -n "$wait_bad" ]; then printf '%s\n' "$wait_bad"; fi
                printf '  inspect with: kubectl -n %s get pods\n' "$wait_ns"
            } >&2
            return 1
        fi
        sleep "$UP_POLL_INTERVAL"
    done
}

# Node registration and node readiness are two different waits, and the difference is the whole
# reason this script exists in this order. With disableDefaultCNI the kubelets register and then
# sit NotReady until Cilium is installed, so waiting for Ready before installing Cilium would
# always time out, and `kind create cluster --wait` -- the obvious thing to reach for -- does
# exactly that. Registration is therefore the gate before Cilium and readiness is the gate after.
wait_nodes() {
    wait_nodes_floor=$1
    wait_nodes_want_ready=$2
    wait_nodes_deadline=$(( $(now_seconds) + UP_CLUSTER_TIMEOUT ))
    while : ; do
        wait_nodes_rows=$(kubectl get nodes -o \
            'jsonpath={range .items[*]}{.metadata.name}{"|"}{range @.status.conditions[?(@.type=="Ready")]}{.status}{end}{"\n"}{end}' \
            2>/dev/null || true)
        wait_nodes_total=$(printf '%s\n' "$wait_nodes_rows" | awk 'NF { n++ } END { print n + 0 }')
        wait_nodes_ready=$(printf '%s\n' "$wait_nodes_rows" | awk -F'|' '$2 == "True" { n++ } END { print n + 0 }')
        if [ "$wait_nodes_total" -ge "$wait_nodes_floor" ]; then
            if [ "$wait_nodes_want_ready" -eq 0 ]; then
                detail "$wait_nodes_total node(s) registered"
                return 0
            fi
            if [ "$wait_nodes_ready" -ge "$wait_nodes_floor" ] && \
               [ "$wait_nodes_ready" -eq "$wait_nodes_total" ]; then
                detail "$wait_nodes_ready/$wait_nodes_total node(s) Ready"
                return 0
            fi
        fi
        if [ "$(now_seconds)" -ge "$wait_nodes_deadline" ]; then
            printf 'nodes did not settle within %ss: %s registered, %s Ready, floor %s\n' \
                "$UP_CLUSTER_TIMEOUT" "$wait_nodes_total" "$wait_nodes_ready" "$wait_nodes_floor" >&2
            printf '  inspect with: kubectl get nodes -o wide\n' >&2
            return 1
        fi
        sleep "$UP_POLL_INTERVAL"
    done
}

# The Boutique overlay sets `namespace: boutique` but declares no Namespace object, and the
# upstream base it builds on declares none either, so somebody has to create it. Composition is
# this script's job, and creating a target namespace is composition rather than authorship: no
# manifest changes, and if T1.2 later adds a Namespace object to the overlay the apply simply
# finds the namespace already present.
#
# The namespace is created THROUGH apply rather than with `kubectl create`, so that a manifest
# which also declares the Namespace -- infra/locust/deployment.yaml does -- applies over it
# cleanly instead of warning that the object it is patching was created imperatively and carries
# no last-applied annotation. A warning in a bring-up log that is otherwise silent gets read as a
# problem, and this one is not.
ensure_namespace() {
    if kubectl get namespace "$1" >/dev/null 2>&1; then
        return 0
    fi
    detail "creating namespace $1"
    kubectl create namespace "$1" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
}

# Apply a manifest that declares a Namespace together with that namespace's `default`
# ServiceAccount, without losing the race layer 12's header describes.
#
# Creating a Namespace starts the control plane's serviceaccount controller creating the namespace's
# `default` ServiceAccount asynchronously. A single `kubectl apply -f` of a file that also declares
# that same ServiceAccount does a GET-then-CREATE, and when the controller's CREATE lands first
# apply's own CREATE returns 409 -- observed as
# `Error from server (AlreadyExists): serviceaccounts "default" already exists`. The window only
# opens on a namespace that does not exist yet, which is why it appears on a cold cluster's first
# bring-up and never on a warm one: the CI runner meets it every run, a developer's second `make up`
# never does.
#
# So: create the namespace first through ensure_namespace (apply-based, so a warm run is a no-op),
# wait for the controller's own ServiceAccount to land, and only then apply the whole file. Every
# object it touches then already exists or is not racing anything, so apply only ever PATCHes.
#
# This is one helper and not two inline copies because BOTH namespace manifests in this layer have
# the shape -- agents-default-deny.yaml and infra/probes/deploy/namespace.yaml -- and ADR-142's
# original text fixed only the first while believing the second was safe. A third one should not
# have to rediscover the race.
apply_namespace_manifest() {
    apply_manifest=$1
    apply_namespace=$2
    apply_label=$3
    ensure_namespace "$apply_namespace"
    detail "waiting for the control plane to provision $apply_namespace/default (ServiceAccount)"
    apply_sa_deadline=$(( $(now_seconds) + 30 ))
    while ! kubectl -n "$apply_namespace" get serviceaccount default >/dev/null 2>&1; do
        if [ "$(now_seconds)" -ge "$apply_sa_deadline" ]; then
            die "$apply_label" "$apply_namespace/default ServiceAccount did not appear within 30s of the $apply_namespace namespace existing"
        fi
        sleep 1
    done
    detail "applying $apply_manifest (namespace and default SA already present, so this only patches)"
    if ! kubectl apply -f "$apply_manifest"; then
        die "$apply_label" "kubectl apply -f $apply_manifest failed; see its output above"
    fi
}

# Bounded retry for a network call this script makes directly rather than through one of the
# infra/*/install.sh delegates -- those wrap their own helm calls with their own retry_helm (same
# shape, same OPA-fetch-loop ancestry in guardian/deploy/Dockerfile). Three attempts, short sleep
# between, operational retry knob rather than a protocol quantity
# (the source-of-truth iron rule (AGENTS.md 1)). A failed attempt's own error is left to print straight to
# stderr, so a command that still fails after retrying shows every attempt's real reason.
retry_cmd() {
    retry_cmd_attempt=1
    while :; do
        if "$@"; then
            return 0
        fi
        if [ "$retry_cmd_attempt" -ge 3 ]; then
            return 1
        fi
        detail "command failed (attempt $retry_cmd_attempt/3); retrying in 5s: $*"
        sleep 5
        retry_cmd_attempt=$((retry_cmd_attempt + 1))
    done
}

# --- resolve the declared values ---------------------------------------------------------------

if [ ! -f "$COMPONENTS_FILE" ]; then
    printf 'up: FAIL — declared component set not found at %s\n' "$COMPONENTS_FILE" >&2
    printf 'up: FAIL — component set missing\n'
    exit 1
fi

# Namespaces and readiness floors come from the declared component set rather than from literals
# here, so that `make up` waits for exactly what `make status` will later check. A layer that came
# up but is not declared would pass status vacuously; a layer that is declared but that up did not
# wait for would fail status intermittently, which is worse than failing it reliably.
BOUTIQUE_NS=$(component_field boutique-services namespace)
BOUTIQUE_FLOOR=$(component_field boutique-services min_count)
LOCUST_NS=$(component_field locust namespace)
LOCUST_FLOOR=$(component_field locust min_count)
OBSERVABILITY_NS=$(component_field prometheus namespace)
MONITOR_NS=$(component_field evidence-aggregator namespace)
MONITOR_FLOOR=$(component_field evidence-aggregator min_count)
FALCO_NS=$(component_field falco namespace)
FALCO_FLOOR=$(component_field falco min_count)
FALCOSIDEKICK_FLOOR=$(component_field falcosidekick min_count)
NODE_FLOOR=$(component_field cluster-nodes min_count)

# The observability floor is the number of components the declared set places in that namespace,
# counted from the file rather than restated as a literal. The Prometheus chart also brings a
# node-exporter DaemonSet, which takes no versions.env key and no component row of its own, so the
# real workload count is higher than the floor -- a floor is a floor, not an equality.
OBSERVABILITY_FLOOR=$(grep -c -E "^[ \t]*namespace:[ \t]*\"?${OBSERVABILITY_NS}\"?[ \t]*$" \
    "$COMPONENTS_FILE" || true)

for declared in BOUTIQUE_NS:"$BOUTIQUE_NS" BOUTIQUE_FLOOR:"$BOUTIQUE_FLOOR" \
                LOCUST_NS:"$LOCUST_NS" LOCUST_FLOOR:"$LOCUST_FLOOR" \
                OBSERVABILITY_NS:"$OBSERVABILITY_NS" MONITOR_NS:"$MONITOR_NS" \
                MONITOR_FLOOR:"$MONITOR_FLOOR" FALCO_NS:"$FALCO_NS" \
                FALCO_FLOOR:"$FALCO_FLOOR" FALCOSIDEKICK_FLOOR:"$FALCOSIDEKICK_FLOOR" \
                NODE_FLOOR:"$NODE_FLOOR" OBSERVABILITY_FLOOR:"$OBSERVABILITY_FLOOR"; do
    case "$declared" in
        *:) printf 'up: FAIL — %s resolved to nothing in %s\n' "${declared%:}" "$COMPONENTS_FILE" >&2
            printf 'up: FAIL — component set incomplete\n'
            exit 1 ;;
    esac
done

# The cluster name: KIND_CLUSTER_NAME, else a top-level `name:` in the kind config, else kind's own
# default. See THE CLUSTER NAME in the header for why the fallback is kind's default and not a
# project-specific string.
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

# --- layer 1: preflight -------------------------------------------------------------------------

progress "preflight — host tooling, Docker daemon, versions.env pins"
if ! VERSIONS_FILE="$VERSIONS_FILE" sh "$script_dir/preflight.sh" >/dev/null; then
    die "preflight" "the host is not ready; scripts/preflight.sh printed the reasons above"
fi
detail "host ready"

# --- layer 2: the kind cluster ------------------------------------------------------------------

progress "kind cluster '$cluster_name' — $NODE_FLOOR node(s), no default CNI"
require_path "$KIND_CONFIG" "M1-T1.1" "kind cluster"

if kind get clusters 2>/dev/null | awk -v want="$cluster_name" '$0 == want { f = 1 } END { exit !f }'
then
    detail "cluster '$cluster_name' already exists — reusing it, not recreating it"
else
    node_image=$(versions_value KIND_NODE_IMAGE)
    if [ -z "$node_image" ]; then
        die "kind cluster" "KIND_NODE_IMAGE is empty in $VERSIONS_FILE"
    fi
    # The Monitor evidence directory is mounted into both nodes and every ingested request writes
    # into it, so its filesystem sets the aggregator's throughput. On the WSL2 profile a checkout
    # under /mnt/c reaches Docker Desktop through the 9p bridge, where one small write measured
    # ~115 ms from inside a node against ~5 ms on WSL's own ext4: the aggregator fell behind its
    # ingestion rate under load and was liveness-killed. OVERWATCH_EVIDENCE_DIR moves the mount to
    # a native path; unset, it stays at the repository path the kind config names.
    evidence_dir=${OVERWATCH_EVIDENCE_DIR:-$repo_root/monitor/runtime/evidence}
    case "$evidence_dir" in
        /mnt/*) detail "WARNING: evidence directory $evidence_dir is on the Windows 9p bridge; set OVERWATCH_EVIDENCE_DIR to a WSL ext4 path" ;;
    esac
    mkdir -p "$evidence_dir" || die "kind cluster" "cannot create evidence directory $evidence_dir"
    rendered_config=$(mktemp)
    sed "s|hostPath: monitor/runtime/evidence|hostPath: $evidence_dir|" "$KIND_CONFIG" > "$rendered_config"
    detail "creating cluster from $KIND_CONFIG at $node_image, evidence mounted from $evidence_dir"
    # No --wait. With disableDefaultCNI the nodes never reach Ready before Cilium, so --wait would
    # spend its whole budget and then fail on a cluster that is behaving exactly as designed.
    if ! kind create cluster --name "$cluster_name" --config "$rendered_config" --image "$node_image"; then
        rm -f "$rendered_config"
        die "kind cluster" "kind create cluster failed; see its output above"
    fi
    rm -f "$rendered_config"
    # Record what this cluster actually mounts. scripts/live_env.sh reads it, so the runner collates
    # from the directory the aggregator writes to rather than from a second guess at it.
    mkdir -p "$repo_root/runs"
    printf '%s\n' "$evidence_dir" > "$repo_root/runs/.cluster-evidence-dir"
fi

if ! kubectl config use-context "$kube_context" >/dev/null 2>&1; then
    die "kind cluster" "no kubectl context named $kube_context after cluster creation"
fi

api_deadline=$(( $(now_seconds) + UP_CLUSTER_TIMEOUT ))
while ! kubectl get --raw=/version >/dev/null 2>&1; do
    if [ "$(now_seconds)" -ge "$api_deadline" ]; then
        die "kind cluster" "the API server did not answer within ${UP_CLUSTER_TIMEOUT}s on context $kube_context"
    fi
    sleep "$UP_POLL_INTERVAL"
done
detail "API server answering on context $kube_context"

if ! wait_nodes "$NODE_FLOOR" 0; then
    die "kind cluster" "not every node registered; the cluster is incomplete"
fi

# --- layer 3: Cilium ----------------------------------------------------------------------------

progress "Cilium — the sole CNI and the NetworkPolicy enforcement point"
require_path "$CILIUM_INSTALL" "M1-T1.1" "Cilium"

# No arguments and no exported pins. infra/cilium/install.sh reads CILIUM_CHART_VERSION from
# infra/versions.env itself and is idempotent by its own contract, so passing the value in from
# here would create a second path by which the chart version could be chosen -- and the one that
# is easier to get wrong.
if ! sh "$CILIUM_INSTALL"; then
    die "Cilium" "infra/cilium/install.sh failed; see its output above"
fi

if ! wait_nodes "$NODE_FLOOR" 1; then
    die "Cilium" "nodes did not reach Ready after the CNI install, so no workload can schedule"
fi

# --- layer 4: Online Boutique -------------------------------------------------------------------

progress "Online Boutique — application under test, at pinned digests"
require_path "$BOUTIQUE_OVERLAY/kustomization.yaml" "M1-T1.2" "Online Boutique"

ensure_namespace "$BOUTIQUE_NS"
detail "applying the overlay at $BOUTIQUE_OVERLAY"
if ! kubectl apply -k "$BOUTIQUE_OVERLAY"; then
    die "Online Boutique" "kubectl apply -k $BOUTIQUE_OVERLAY failed; see its output above"
fi

if ! wait_ns_ready "$BOUTIQUE_NS" "$BOUTIQUE_FLOOR" "Online Boutique"; then
    die "Online Boutique" "the application did not become ready"
fi

# --- layer 5: Chaos Mesh -------------------------------------------------------------------------

progress "Chaos Mesh — experimenter-controlled fault injection"
require_path "$CHAOS_MESH_INSTALL" "M5-Tier-B1" "Chaos Mesh"
if ! sh "$CHAOS_MESH_INSTALL"; then
    die "Chaos Mesh" "infra/chaosmesh/install.sh failed; see its output above"
fi

# --- layer 6: Locust ----------------------------------------------------------------------------

progress "Locust — load generator, deployed idle and driven per run"
require_path "$LOCUST_MANIFEST" "M1-T1.2" "Locust"

ensure_namespace "$LOCUST_NS"
detail "applying $LOCUST_MANIFEST"
if ! kubectl apply -f "$LOCUST_MANIFEST"; then
    die "Locust" "kubectl apply -f $LOCUST_MANIFEST failed; see its output above"
fi

if ! wait_ns_ready "$LOCUST_NS" "$LOCUST_FLOOR" "Locust"; then
    die "Locust" "the load generator did not become ready"
fi

# --- layer 7: observability ---------------------------------------------------------------------

progress "observability — Prometheus, kube-state-metrics and Grafana"
require_path "$OBSERVABILITY_INSTALL" "M1-T1.3" "observability"

ensure_namespace "$OBSERVABILITY_NS"
if ! sh "$OBSERVABILITY_INSTALL"; then
    die "observability" "infra/observability/install.sh failed; see its output above"
fi

if ! wait_ns_ready "$OBSERVABILITY_NS" "$OBSERVABILITY_FLOOR" "observability"; then
    die "observability" "the observability stack did not become ready"
fi

# --- layer 8: evidence aggregator ---------------------------------------------------------------

progress "Monitor evidence aggregator — bounded EvidenceEvent ingress"
require_path "$MONITOR_OVERLAY/kustomization.yaml" "M2" "Monitor evidence aggregator"
require_path "$MONITOR_IMAGE" "M2" "Monitor evidence aggregator"
ensure_namespace "$MONITOR_NS"
if ! sh "$MONITOR_IMAGE"; then
    die "Monitor evidence aggregator" "scripts/monitor_image.sh failed; see its output above"
fi
detail "applying the Monitor overlay at $MONITOR_OVERLAY"
if ! kubectl apply -k "$MONITOR_OVERLAY"; then
    die "Monitor evidence aggregator" "kubectl apply -k $MONITOR_OVERLAY failed; see its output above"
fi
# The local image tag is intentionally stable; restart both consumers so a rebuild cannot leave
# yesterday's image running behind today's manifests (ADR-046).
kubectl rollout restart -n "$MONITOR_NS" deployment/evidence-aggregator deployment/audit-forwarder
kubectl rollout status -n "$MONITOR_NS" deployment/evidence-aggregator --timeout="${UP_WAIT_TIMEOUT}s"
kubectl rollout status -n "$MONITOR_NS" deployment/audit-forwarder --timeout="${UP_WAIT_TIMEOUT}s"
if ! wait_ns_ready "$MONITOR_NS" "$MONITOR_FLOOR" "Monitor evidence aggregator"; then
    die "Monitor evidence aggregator" "the evidence aggregator did not become ready"
fi

# --- layer 9: Falco and Falcosidekick -----------------------------------------------------------

progress "Monitor sources — Falco, Falcosidekick, Alertmanager and Trivy"
require_path "$MONITOR_INSTALL" "M2" "Monitor sources"
if ! sh "$MONITOR_INSTALL"; then
    die "Monitor sources" "infra/monitor/install.sh failed; see its output above"
fi
FALCO_WORKLOAD_FLOOR=$((FALCO_FLOOR + FALCOSIDEKICK_FLOOR))
if ! wait_ns_ready "$FALCO_NS" "$FALCO_WORKLOAD_FLOOR" "Falco and Falcosidekick"; then
    die "Falco" "Falco and Falcosidekick did not become ready"
fi

# --- layer 10: Guardian ------------------------------------------------------------------------

# Guardian is redeployed per RUN by the runner (runner/live_run.py), which sets GUARDIAN_RUN_ID, the
# run's registered issuers and the attempt's audit chain. Bring-up has no run, so it deploys a
# BOOTSTRAP Guardian: a valid, ready mediation service that `make status` sees green and that the
# campaign preflight (runner/campaign_cli.py; evaluation-protocol section 5 rule 1) requires BEFORE the
# first run redeploys over it. Without it, `make up` cannot reach a green `make status` and no campaign
# can start -- the chicken-and-egg guardian_deploy.sh's lease comment refers to when it names `make up`
# a direct invoker of that script.
#
# The bootstrap's settings are real, not stubs. The token parameters come from the protocol via
# scripts/security_params.py -- the single source scripts/live_env.sh reads too, never a second copy
# (rule 00). The registered issuers are S1-HIER's own set, the richest of the three topologies. The
# control-plane identities (ADR-128) match guardian/deploy/rbac.yaml and default exactly as
# scripts/live_env.sh defaults them. The audit chain is this bring-up's own BOOTSTRAP-bringup.jsonl on
# the Guardian's audit volume. Deriving the first two needs the project's Python -- a prerequisite of
# the environment this brings up anyway -- resolved venv-first, exactly as scripts/live_env.sh does.
bring_up_guardian() {
    progress "Guardian — sole credential holder and mediation service"
    require_path "$GUARDIAN_DEPLOY" "M3-Tier-B" "Guardian"

    # Resolve a Python that can actually IMPORT agents.golden, not merely the first that exists. A
    # repository .venv synced from another OS (the VM mirror carries a Windows-built one that cannot
    # run on Linux) exists and is executable but cannot import the project, so an existence-only
    # check would pick it and fail the bootstrap deriving issuers. Probe the import and fall through
    # -- the same check scripts/agents_golden.sh makes before it trusts an interpreter. An explicit
    # PYTHON is honoured as given (the operator's choice), and only the auto-resolution candidates
    # are probed.
    bootstrap_pythonpath="$repo_root${PYTHONPATH:+:$PYTHONPATH}"
    bootstrap_python=${PYTHON:-}
    if [ -z "$bootstrap_python" ]; then
        for bootstrap_candidate in "$repo_root/.venv/bin/python" \
            "$HOME/.venvs/agentic-overwatch/bin/python" python3 python; do
            command -v "$bootstrap_candidate" >/dev/null 2>&1 || continue
            if PYTHONPATH="$bootstrap_pythonpath" "$bootstrap_candidate" -c "import agents.golden" \
                >/dev/null 2>&1; then
                bootstrap_python="$bootstrap_candidate"
                break
            fi
        done
    fi
    if [ -z "$bootstrap_python" ]; then
        die "Guardian" "no Python can import agents.golden (tried .venv, ~/.venvs/agentic-overwatch, python3, python); set PYTHON to the project's interpreter"
    fi
    if ! bootstrap_params=$(PYTHONPATH="$bootstrap_pythonpath" "$bootstrap_python" scripts/security_params.py); then
        die "Guardian" "could not read token parameters from the protocol (scripts/security_params.py)"
    fi
    if ! bootstrap_issuers=$(PYTHONPATH="$bootstrap_pythonpath" "$bootstrap_python" -c "from agents.golden import registered_issuers; from agents.registry.loader import load_registry; print(','.join(registered_issuers(load_registry().compositions['S1-HIER'])))"); then
        die "Guardian" "could not derive the bootstrap registered-issuer set (agents.golden.registered_issuers)"
    fi
    # The token parameters are NAME='value' lines; eval and export them so the deploy's child shell
    # sees them, then set the per-run-shaped keys as a prefix on the one call that consumes them.
    eval "$bootstrap_params"
    export GUARDIAN_TOKEN_TTL_SECONDS GUARDIAN_TOKEN_MAX_TTL_SECONDS GUARDIAN_TOKEN_ALGORITHM \
        GUARDIAN_REPLAY_CACHE_ENTRIES GUARDIAN_REPLAY_CACHE_WINDOW_SECONDS
    bootstrap_run_id=${GUARDIAN_BOOTSTRAP_RUN_ID:-BOOTSTRAP}
    if ! GUARDIAN_MODE="${GUARDIAN_MODE:-G0-FULL}" \
        GUARDIAN_RUN_ID="$bootstrap_run_id" \
        GUARDIAN_REGISTERED_ISSUERS="$bootstrap_issuers" \
        GUARDIAN_AUDIT_LOG_PATH="/var/lib/guardian/audit/${bootstrap_run_id}-bringup.jsonl" \
        GUARDIAN_CONTROL_PLANE_SUBJECT="${GUARDIAN_CONTROL_PLANE_SUBJECT:-system:serviceaccount:guardian:runner-control-plane}" \
        GUARDIAN_CONTROL_PLANE_AUDIENCE="${GUARDIAN_CONTROL_PLANE_AUDIENCE:-guardian-control-plane}" \
        sh "$GUARDIAN_DEPLOY"; then
        die "Guardian" "Guardian deployment failed; no cluster verification is claimed"
    fi
    if ! wait_ns_ready guardian 1 "Guardian"; then
        die "Guardian" "the mediation service did not become ready"
    fi
}

# THE PROFILE GATE. `required_in` on the guardian row of infra/status/components.yaml is the single
# home for "which profiles require this component"; the gate below reads it rather than restating a
# second list, so a profile edit cannot leave up.sh and status.sh disagreeing about the same
# environment. An absent key means every profile, the fail-closed reading. The `substrate` profile
# omits the Guardian because guardian-signing-key is operator-supplied out of band and ADR-114
# forbids any chart value, ESO ExternalSecret or installer script in this repository from creating
# it -- which an ephemeral CI runner cannot do. Layers 11 and 12 do not depend on the Guardian, and
# a campaign or pilot bring-up must use the default profile.
guardian_required_in=$(component_field guardian required_in)
if [ -z "$guardian_required_in" ]; then
    guardian_required=1
else
    case ",$guardian_required_in," in
        *",$UP_PROFILE,"*) guardian_required=1 ;;
        *) guardian_required=0 ;;
    esac
fi

if [ "$guardian_required" -eq 1 ]; then
    bring_up_guardian
else
    progress "Guardian — SKIPPED: not required in profile $UP_PROFILE"
    detail "profile $UP_PROFILE omits the Guardian, whose signing key is operator-supplied out of band (ADR-114); layers 11-12 do not depend on it"
fi

# --- layer 11: CVE arm image preload -------------------------------------------------------------
#
# Loads scenarios/cve/images.yaml's vulnerable image(s) into every kind node from the local mirror
# tarball, so a live CVE scenario's admission primitive (`_set_image`) patches a Deployment onto an
# image the node's containerd already has rather than one it must pull from a registry mid-run.
# ADR-091 owns this layer (stream V; supervisor ruling B1's second sentence). It reuses
# scripts/cve_mirror.sh's own record -- the same digest and tarball_sha256 fields, read here rather
# than through that script, because cve_mirror.sh deliberately never runs `kind load` itself (an
# operator-approved side effect it prints instead, for a script that must also stay runnable with no
# cluster or network); this bring-up script is already the place every other real, host-mutating
# action in this list happens, so running the load here is consistent with what up.sh already is.
#
# An entry with an empty digest or tarball_sha256 is UNPINNED, not broken: that is the correct state
# before an operator completes Tier B (scenarios/cve/adservice/build_and_pin.sh, then
# scripts/cve_mirror.sh --save/--load), and the three SIM scenarios need none of this, so an
# unpinned CVE arm never fails this bring-up. A present pin whose `kind load` itself fails is a real
# defect (a corrupted tarball, a wrong cluster name, exhausted disk) and does fail it, on the same
# "fails at the first layer that does not come up" rule every layer above keeps.
progress "CVE arm image preload — vulnerable image(s) loaded into kind nodes ahead of injection t0"
CVE_IMAGES_FILE=${CVE_IMAGES_FILE:-scenarios/cve/images.yaml}
CVE_TARBALL_DIR=${CVE_TARBALL_DIR:-scenarios/cve/tarballs}

if [ ! -f "$CVE_IMAGES_FILE" ]; then
    detail "no $CVE_IMAGES_FILE — CVE arm preload skipped (not a failure: SIM scenarios need none of it)"
else
    # The same column-anchored reader scripts/cve_mirror.sh and scripts/cve_admission_preflight.sh
    # use, duplicated rather than shared for the reason scripts/up.sh already gives for its own copy
    # of scripts/status.sh's parser: a few dozen lines of awk is not worth a new shared module.
    cve_rows=$(awk '
        function emit() {
            if (id == "") return
            printf "%s|%s|%s|%s|%s\n", id, repository, digest, tarball, tarball_sha256
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
                id = ""; repository = ""; digest = ""; tarball = ""; tarball_sha256 = ""
            } else {
                if (id == "") next
                if (col != field_col) next
            }
            v = substr(body, ci + 1)
            sub(/^ +/, "", v); sub(/ +$/, "", v); sub(/^"/, "", v); sub(/"$/, "", v)
            if (k == "id") id = v
            else if (k == "repository") repository = v
            else if (k == "digest") digest = v
            else if (k == "tarball") tarball = v
            else if (k == "tarball_sha256") tarball_sha256 = v
        }
        END { emit() }
    ' "$CVE_IMAGES_FILE")

    if [ -z "$cve_rows" ]; then
        detail "$CVE_IMAGES_FILE declares no entries — CVE arm preload skipped"
    else
        cve_loaded=0
        cve_pending=0
        while IFS='|' read -r cve_id cve_repo cve_digest cve_tar cve_sha; do
            [ -n "$cve_id" ] || continue
            if [ -z "$cve_digest" ] || [ -z "$cve_sha" ]; then
                detail "$cve_id unpinned (Tier B not yet run) — not a bring-up failure"
                cve_pending=$((cve_pending + 1))
                continue
            fi
            cve_tar_path="$CVE_TARBALL_DIR/$cve_tar"
            if [ ! -f "$cve_tar_path" ]; then
                detail "$cve_id pinned but $cve_tar_path is absent — run: sh scripts/cve_mirror.sh --save"
                cve_pending=$((cve_pending + 1))
                continue
            fi
            detail "loading $cve_id ($cve_repo@$cve_digest) into cluster '$cluster_name'"
            if ! kind load image-archive --name "$cluster_name" "$cve_tar_path"; then
                die "CVE arm image preload" "kind load image-archive failed for $cve_tar_path ($cve_id)"
            fi
            cve_loaded=$((cve_loaded + 1))
        done <<CVE_ROWS
$cve_rows
CVE_ROWS
        detail "$cve_loaded CVE image(s) preloaded, $cve_pending entry(ies) not yet pinned at Tier B"

        # Admission preflight: image present in every node's containerd AND the target Deployment
        # fully Ready on its own current (patched-baseline) image, for each scenario whose entry was
        # actually loaded above. Skipped, not failed, for a scenario still unpinned at Tier B.
        # ADR-091's Integration section reports that a full "before every run's injection t0"
        # guarantee also needs a per-run re-check from the runner, which is outside this stream's
        # ownership; this bring-up-time check is the part scripts/up.sh can make true on its own,
        # consistent with evaluation-protocol.md section 5 rule 1 gating every run on a green
        # preflight taken once the environment is up.
        if [ "$cve_loaded" -gt 0 ]; then
            for cve_scenario in SCN-CVE-04 SCN-CVE-05; do
                if sh scripts/cve_admission_preflight.sh "$cve_scenario" >&2; then
                    detail "admission preflight green for $cve_scenario"
                else
                    detail "admission preflight did not pass for $cve_scenario (see above) — not a bring-up failure by itself, but a live run of it will not clear its own preflight"
                fi
            done
        fi
    fi
fi

# --- layer 12: scenario and run prerequisites ----------------------------------------------------
#
# `make up` brings up the substrate; a live `make run`/`make campaign` additionally needs three
# things that nothing above this line establishes and that, until now, the FIRST run against a
# fresh cluster discovered missing: the `agents` namespace and its default-deny NetworkPolicy pair
# (a), the in-cluster SLO probe's image and namespace (b), and the attacker debug image
# scenarios/attackers/apply.py's `kubectl debug` primitive names (c). ADR-142 records the decision
# to fold all three into bring-up rather than leaving them for an operator, or a run, to discover
# missing.
#
# AGENTS NAMESPACE, AND THE RACE THIS LAYER CLOSES. infra/netpol/agents-default-deny.yaml declares,
# in one file, the `agents` Namespace, its `default` ServiceAccount (automountServiceAccountToken
# turned off) and the NetworkPolicy/CiliumNetworkPolicy pair that closes its egress -- see that
# file's own header for why all four objects ship together. runner/live_run.py applies this same
# file at the start of every run (or agents-g2-open.yaml under the G2 arm, which replaces only the
# CiliumNetworkPolicy and assumes the namespace it lives in already exists). Applying the whole
# file in one `kubectl apply -f` against a namespace that does not exist yet loses a race every
# time: creating the Namespace starts the control plane's own serviceaccount controller creating
# that namespace's `default` ServiceAccount asynchronously, and if it wins against apply's own
# GET-then-CREATE for that SAME object, the CREATE returns 409 and apply fails -- observed as
# `Error from server (AlreadyExists): serviceaccounts "default" already exists` the first time a
# run applied this file against a cluster nothing had provisioned ahead of it.
#
# The fix is to never let apply's GET race the controller: create the namespace first (through
# ensure_namespace, the same apply-based helper layers 4 and 6 already use, so a second run finds
# it present and does nothing), wait for the controller's own `default` ServiceAccount to land, and
# only then apply the full file. Every object that file touches then already exists or is not
# racing anything that creates one behind apply's back, so apply always PATCHes rather than
# CREATEs and the AlreadyExists window never opens -- on this run or the next. Re-applying the
# whole file this way stays idempotent for the same reason: the second and every later `make up`
# finds the namespace and the ServiceAccount already there and PATCHes every object again.
#
# THE RACE IS A PROPERTY OF THE FILE'S SHAPE, NOT OF THE `agents` FILE. ADR-142 wrote this section
# for agents-default-deny.yaml and left (b) applying infra/probes/deploy/namespace.yaml bare, on the
# assumption that a manifest with no NetworkPolicy in it was safe. It is not: that file has the same
# Namespace-plus-`default`-ServiceAccount shape, so it opens the same window, and the first
# bring-up to reach this layer on a cold cluster -- the CI runner, once ADR-147 and ADR-148 let it
# get this far -- failed with the identical message against `slo-probe`. Both now go through the one
# helper apply_namespace_manifest, so a third such file inherits the fix instead of rediscovering
# the race. ADR-142 carries the correction as an amendment.
progress "scenario/run prerequisites — agents namespace+netpol, SLO probe, attacker debug image"

# --- (a) agents namespace and default-deny NetworkPolicy -----------------------------------------

require_path "$AGENTS_NETPOL" "M3-T3.5" "scenario/run prerequisites"
apply_namespace_manifest "$AGENTS_NETPOL" agents "scenario/run prerequisites"

# --- (b) in-cluster SLO probe: image and namespace --------------------------------------------
#
# infra/probes/deploy/pod.yaml is applied per attempt by the runner, not here (its own header's
# LIFECYCLE note), but it sets imagePullPolicy: Never -- a kind cluster has no registry of its own
# -- so the image has to already be sitting in every node's containerd, and its dedicated namespace
# (infra/probes/deploy/namespace.yaml's own WHY A DEDICATED NAMESPACE note) has to already exist,
# or the runner's first per-attempt apply is what discovers either is missing.
require_path "$PROBE_BUILD" "ADR-085" "scenario/run prerequisites"
require_path "$PROBE_NAMESPACE_MANIFEST" "ADR-085" "scenario/run prerequisites"

detail "building and loading the SLO probe image ($PROBE_BUILD)"
if ! KIND_CLUSTER_NAME="$cluster_name" sh "$PROBE_BUILD"; then
    die "scenario/run prerequisites" "$PROBE_BUILD failed; see its output above"
fi

apply_namespace_manifest "$PROBE_NAMESPACE_MANIFEST" "$PROBE_NAMESPACE" "scenario/run prerequisites"

# --- (c) attacker debug image -------------------------------------------------------------------
#
# scenarios/attackers/apply.py runs its shell/exec/egress primitives through `kubectl debug --image
# overwatch-attacker/curl:local` rather than `kubectl exec`, because no Boutique target image
# carries a shell (that module's own comment records the operator-verified evidence). The image is
# a re-tag of a pinned upstream digest, not a local Dockerfile build, so establishing it is pull,
# tag, then load into every kind node. The pull is retried like the helm calls in infra/*/install.sh
# are (Task 1): it is a new network round trip this layer adds to bring-up, against the same class
# of transient failure those retries exist for.
detail "pulling $ATTACKER_DEBUG_UPSTREAM_IMAGE"
if ! retry_cmd docker pull "$ATTACKER_DEBUG_UPSTREAM_IMAGE"; then
    die "scenario/run prerequisites" "docker pull $ATTACKER_DEBUG_UPSTREAM_IMAGE failed after 3 attempts"
fi

detail "tagging it $ATTACKER_DEBUG_LOCAL_TAG"
if ! docker tag "$ATTACKER_DEBUG_UPSTREAM_IMAGE" "$ATTACKER_DEBUG_LOCAL_TAG"; then
    die "scenario/run prerequisites" "docker tag $ATTACKER_DEBUG_LOCAL_TAG failed"
fi

detail "loading $ATTACKER_DEBUG_LOCAL_TAG into cluster '$cluster_name'"
if ! kind load docker-image --name "$cluster_name" "$ATTACKER_DEBUG_LOCAL_TAG"; then
    die "scenario/run prerequisites" "kind load docker-image failed for $ATTACKER_DEBUG_LOCAL_TAG"
fi

# --- report ---------------------------------------------------------------------------------

# The closing line is a statement about what came up, not a claim that the environment is healthy
# now: readiness was true at the moment each layer was waited on, and a workload can crash a second
# later. `make status` is the check that answers "is it healthy now", and it is what
# docs/protocols/evaluation-protocol.md section 5 rule 1 gates a run on -- so up points at it
# rather than pretending to have replaced it.
printf 'up: PASS — %s layer(s) up on context %s; run `make status` to gate a run on it\n' \
    "$LAYER_TOTAL" "$kube_context"
exit 0
