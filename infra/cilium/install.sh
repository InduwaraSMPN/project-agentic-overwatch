#!/bin/sh
#
# infra/cilium/install.sh -- install or upgrade Cilium into the kind cluster created from
# infra/kind-config.yaml, at the chart version pinned as CILIUM_CHART_VERSION in
# infra/versions.env and with the values in infra/cilium/values.yaml. Because that kind config
# sets `disableDefaultCNI: true`, nothing schedules on the cluster until this script has run
# successfully: the nodes stay NotReady and every pod stays Pending. This is therefore the second
# step of a bring-up and the first one that can fail for a reason specific to this host.
#
# WHY A SCRIPT AND NOT A MAKE RECIPE OR A README INSTRUCTION
#   The M0 convention that logic lives in scripts rather than in recipes applies here for the usual
#   reason -- the Windows development host has no make, so behaviour written into a recipe is
#   unrunnable where most of the authoring happens -- and for one specific to this file: the
#   .github/workflows/env-bringup.yml job and a developer bringing up a cluster by hand must
#   execute the same bytes, or the "reconstructs from a clean machine" claim in NFR1 and
#   traceability row T-16 is a claim about two different procedures. A README instruction is worse
#   still, because prose cannot be executed and therefore cannot be verified.
#
# WHY THE PIN IS READ FROM versions.env RATHER THAN WRITTEN HERE
#   docs/03-tech-stack.md section 5 makes infra/versions.env the single home for every version and
#   digest, and docs/protocols/data-management.md section 2 records that file's normalised hash in
#   every run manifest as the identity of the stack the run was produced on. A literal chart
#   version in this script would be a version the run manifest does not describe, so a bundle could
#   name one Cilium while the cluster ran another. The script therefore reads the pin, and refuses
#   to proceed when it is empty rather than letting Helm resolve whatever is newest today: an
#   unpinned install is not reproducible, and a bring-up that quietly floats is a worse outcome
#   than one that stops with a message naming the key to fill in.
#
# WHY DOT-SOURCING versions.env IS SAFE
#   The file is read with a dot rather than parsed line by line. That is only defensible because
#   infra/versions.env's own header states its contract in its first numbered rule: values only,
#   no logic, no command substitution, no shell expansion, no conditionals and no secrets. Every
#   line is a plain key and value, so sourcing it executes nothing but assignments. The contract is
#   what makes the shortcut legal, and it is load-bearing in both directions: if anyone ever adds
#   shell logic to that file, this script becomes an arbitrary-code path and the read has to become
#   a parse. Sourcing also means the key set arrives whole, so a later edit here can reference
#   another pin without touching the reading code.
#
# IDEMPOTENCE
#   The upgrade-install form is the same command whether or not a release exists, so a second run
#   over an already-installed Cilium is an upgrade to the same version with the same values, which
#   converges rather than conflicts. Adding the chart repository with --force-update overwrites an
#   existing entry instead of failing on the name, which is what makes a re-run survive a
#   repository list that already has a cilium entry pointing somewhere else. The readiness waits at
#   the end are pure observation. Running this script twice in a row is expected to be uneventful,
#   and the composed bring-up depends on that being true.
#
# WHAT THIS SCRIPT DOES NOT DO
#   It does not create the cluster; that is a kind create cluster invocation against
#   infra/kind-config.yaml, and scripts/up.sh composes the two once M1-T1.6 lands. It does not
#   prove that Cilium enforces anything -- installation and enforcement are different claims, and
#   conflating them is exactly the error scripts/netpol_proof.sh exists to prevent. It writes
#   nothing to version control and reads no credentials.
#
# TIMEOUTS ARE INSTALL-TIME BOUNDS, NOT EXPERIMENT PARAMETERS
#   The two durations below bound how long this script waits for images to pull and for a
#   DaemonSet to roll out on a cold cluster. They are generous on purpose: a bound that fires
#   during an image pull reports a broken install for a slow network. They are not thresholds,
#   budgets or service-level objectives, none of which may live under infra/ -- those belong to
#   docs/protocols/evaluation-protocol.md, per .agents/rules/00-source-of-truth.md.
#
# HELM 3 AND HELM 4 BOTH RUN THIS FILE UNCHANGED
#   Worth stating because one of the flags below changed shape between the two majors. In Helm 4
#   --wait is no longer a boolean but a wait-strategy value, and a bare --wait selects the watcher
#   strategy through the flag's no-option default; supplying it bare, immediately followed by
#   another flag as it is below, is therefore parsed identically by both majors. --install,
#   --timeout, --version, --values, --namespace, helm repo add --force-update and helm repo update
#   all exist in both. Each was checked against the Helm version pinned in versions.env rather than
#   assumed, because a flag that silently changes meaning across a major is exactly the kind of
#   thing that turns a reproducible install into an irreproducible one.
#
# PORTABILITY
#   Strict POSIX sh -- no bashisms, no GNU-only options -- so it runs identically under Git Bash on
#   Windows, under dash in WSL2 Ubuntu, and on ubuntu-latest in CI.

set -eu

# Byte-stable tool output regardless of the ambient locale.
LC_ALL=C
export LC_ALL

# Repo root derived from this script's own location, never hardcoded, so the script behaves the
# same whether it is invoked by make, by CI, or by hand from an arbitrary working directory. This
# script sits one level deeper than scripts/, hence the two parent steps.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
cd "$repo_root"

versions_file="infra/versions.env"
values_file="infra/cilium/values.yaml"

# How long Helm may wait for every rendered resource to become ready, and how long the explicit
# DaemonSet wait afterwards may take. See TIMEOUTS above.
HELM_TIMEOUT="10m"
ROLLOUT_TIMEOUT="5m"

# Bounded retry for a helm call that reaches a chart repository over the network: repo add,
# repo update, or an upgrade --install that has to pull the chart archive itself. Operational
# retry knobs, not protocol quantities (.agents/rules/00-source-of-truth.md) -- literals here
# exactly as the two timeouts above are.
HELM_RETRY_ATTEMPTS=3
HELM_RETRY_SLEEP_SECONDS=5

fail() {
    echo "cilium-install: $1" >&2
    exit 1
}

# Mirrors the OPA-binary fetch loop in guardian/deploy/Dockerfile: a fixed number of attempts,
# break on the first success. A short sleep between attempts is added here because the failure
# this recovers from -- "connection reset by peer", "not a valid chart repository or cannot be
# reached" against helm.cilium.io -- is a transient reset on the link, not a configuration error,
# and it routinely clears within a few seconds. A failed attempt's own helm/network error is left
# to print straight to stderr, so a run that still fails after retrying shows every attempt's real
# reason, not just the last one.
retry_helm() {
    retry_helm_attempt=1
    while :; do
        if "$@"; then
            return 0
        fi
        if [ "$retry_helm_attempt" -ge "$HELM_RETRY_ATTEMPTS" ]; then
            return 1
        fi
        echo "cilium-install: helm command failed (attempt $retry_helm_attempt/$HELM_RETRY_ATTEMPTS); retrying in ${HELM_RETRY_SLEEP_SECONDS}s" >&2
        sleep "$HELM_RETRY_SLEEP_SECONDS"
        retry_helm_attempt=$((retry_helm_attempt + 1))
    done
}

for tool in helm kubectl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "cilium-install: $tool is not on PATH. Install the version pinned in" >&2
        echo "cilium-install: $versions_file; scripts/install_cluster_tools.sh is the shared" >&2
        echo "cilium-install: installer that CI and docs/04-repo-conventions.md section 2 use." >&2
        exit 1
    fi
done

[ -f "$versions_file" ] || fail "$versions_file is missing; the chart version has no source."
[ -f "$values_file" ] || fail "$values_file is missing; refusing to install with chart defaults."

# Values only, by that file's own contract. See WHY DOT-SOURCING versions.env IS SAFE above.
. "./$versions_file"

# The default keeps set -u from aborting with a bare unbound-variable message if the key is ever
# removed from versions.env, so the diagnosis below is what a reader sees instead.
CILIUM_CHART_VERSION=${CILIUM_CHART_VERSION:-}
if [ -z "$CILIUM_CHART_VERSION" ]; then
    echo "cilium-install: CILIUM_CHART_VERSION is empty in $versions_file." >&2
    echo "cilium-install: An unpinned chart resolves to whatever is newest at install" >&2
    echo "cilium-install: time, so two bring-ups a week apart would produce two different" >&2
    echo "cilium-install: clusters while every run manifest recorded the same versions.env" >&2
    echo "cilium-install: digest. Populate the key (M1-T1.1 is the task that does so) and" >&2
    echo "cilium-install: re-run." >&2
    exit 1
fi

if ! kubectl cluster-info >/dev/null 2>&1; then
    echo "cilium-install: no reachable cluster. Create it first with:" >&2
    echo "cilium-install:   kind create cluster --config infra/kind-config.yaml \\" >&2
    echo "cilium-install:     --image <the KIND_NODE_IMAGE value from infra/versions.env>" >&2
    echo "cilium-install: Nodes report NotReady until this script completes; that is expected," >&2
    echo "cilium-install: because infra/kind-config.yaml disables the default CNI." >&2
    exit 1
fi

# THE CONTEXT GUARD, AND WHY IT REFUSES RATHER THAN WARNS
#   This script installs a CNI into whatever cluster kubectl currently points at, and on a
#   developer machine that is very often not the cluster the operator has in mind -- a stale
#   context from an unrelated project takes the install, silently and successfully. That is not
#   hypothetical: during M1-T1.3 a sibling installer was run for a syntax check and began
#   installing into an unrelated live cluster before it was stopped, which is the incident this
#   guard exists to prevent. Installing a CNI is strictly worse than installing a chart, because
#   it replaces the datapath of whatever it lands on.
#
#   `make up` selects the kind context before it calls this script, so the guard never fires on
#   the supported path; it fires only on a by-hand invocation, which is the only way the accident
#   can happen. The assertion is on the `kind-` prefix rather than on a cluster name, so it is not
#   a second copy of a name owned elsewhere -- kubectl writes that prefix for every kind cluster,
#   whatever it is called. scripts/status.sh already asserts exactly this, with no relaxation
#   knob, and none is offered here for the same reason: a guard with an override is a guard
#   somebody sets once in a shell profile and never sees again.
current_context=$(kubectl config current-context 2>/dev/null || echo "")
case "$current_context" in
    kind-*) : ;;
    *)
        echo "cilium-install: REFUSING -- the current kubectl context is '${current_context:-<none>}'," >&2
        echo "cilium-install: which is not a kind cluster (kubectl names those 'kind-<cluster>')." >&2
        echo "cilium-install: This script replaces the CNI of whatever it installs into, so it will" >&2
        echo "cilium-install: not act on a context it cannot identify as this project's." >&2
        echo "cilium-install: Select the cluster first, or use 'make up', which does it for you." >&2
        exit 1
        ;;
esac

echo "cilium-install: target context $current_context"
echo "cilium-install: chart cilium/cilium version $CILIUM_CHART_VERSION, values $values_file"

# --force-update overwrites an existing cilium entry rather than failing on the name, which is what
# makes a re-run idempotent on a machine whose repository list is already populated. The refresh
# that follows is the unqualified form, which updates every configured repository: the
# per-repository form is a newer Helm feature and this file has no reason to require it.
retry_helm helm repo add cilium https://helm.cilium.io/ --force-update \
    || fail "helm repo add cilium failed after $HELM_RETRY_ATTEMPTS attempts; see the connection errors above"
retry_helm helm repo update \
    || fail "helm repo update failed after $HELM_RETRY_ATTEMPTS attempts; see the connection errors above"

retry_helm helm upgrade --install cilium cilium/cilium \
    --version "$CILIUM_CHART_VERSION" \
    --namespace kube-system \
    --values "$values_file" \
    --wait \
    --timeout "$HELM_TIMEOUT" \
    || fail "helm upgrade --install cilium failed after $HELM_RETRY_ATTEMPTS attempts; see Helm's own output above"

# Helm's --wait already blocks on the rendered resources, so this is a second, narrower assertion
# rather than the first one: it names the DaemonSet whose readiness is the property that actually
# matters, so a failure here reads as "the agent did not roll out" instead of "the release timed
# out".
echo "cilium-install: waiting for the cilium agent DaemonSet"
kubectl -n kube-system rollout status daemonset/cilium --timeout="$ROLLOUT_TIMEOUT"

# The cilium CLI reports connectivity, endpoint management and operator health in one place, which
# is strictly more than a DaemonSet rollout can tell you. It is an optional extra rather than a
# requirement: the rollout wait above is the fallback, and it has already run, so a host without
# the CLI still gets a real readiness assertion and not merely a skipped step.
if command -v cilium >/dev/null 2>&1; then
    echo "cilium-install: cilium status --wait"
    cilium status --wait
else
    echo "cilium-install: the cilium CLI is not on PATH; the DaemonSet rollout above is this run's"
    echo "cilium-install: readiness evidence. Install the version pinned as CILIUM_CLI_VERSION in"
    echo "cilium-install: $versions_file for the fuller report."
fi

printf 'cilium-install: PASS — cilium/cilium %s installed, agent DaemonSet ready\n' \
    "$CILIUM_CHART_VERSION"
