#!/bin/sh
# Install M2 Phase B source-side components. The evidence-aggregator workload is
# deliberately out of scope; these values target its architecture-owned Service.
# Every version is read from infra/versions.env, the repository's sole pin surface.
set -eu

LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
cd "$repo_root"

fail() {
    printf 'monitor sources install: FAIL -- %s\n' "$*" >&2
    exit 1
}

pin() {
    awk -F= -v key="$1" '$1 == key { sub(/\r$/, "", $2); print $2; exit }' infra/versions.env
}

# Bounded retry for a helm call that reaches a chart repository over the network: repo add/update,
# an upgrade --install that pulls the chart archive, or a show/template that has to fetch an
# archive not already in the local cache. Operational retry knobs, not protocol quantities
# (.agents/rules/00-source-of-truth.md).
HELM_RETRY_ATTEMPTS=3
HELM_RETRY_SLEEP_SECONDS=5

# Mirrors the OPA-binary fetch loop in guardian/deploy/Dockerfile: a fixed number of attempts,
# break on the first success. A short sleep between attempts is added here because the failures
# this recovers from -- "connection reset by peer", "not a valid chart repository or cannot be
# reached" against falcosecurity.github.io and prometheus-community.github.io -- are transient
# resets on the link, not configuration errors, and they routinely clear within a few seconds. A
# failed attempt's own helm error is left to print straight to stderr.
retry_helm() {
    retry_helm_attempt=1
    while :; do
        if "$@"; then
            return 0
        fi
        if [ "$retry_helm_attempt" -ge "$HELM_RETRY_ATTEMPTS" ]; then
            return 1
        fi
        printf 'monitor sources install: helm command failed (attempt %s/%s); retrying in %ss\n' \
            "$retry_helm_attempt" "$HELM_RETRY_ATTEMPTS" "$HELM_RETRY_SLEEP_SECONDS" >&2
        sleep "$HELM_RETRY_SLEEP_SECONDS"
        retry_helm_attempt=$((retry_helm_attempt + 1))
    done
}

FALCO_CHART_VERSION=$(pin FALCO_CHART_VERSION)
FALCO_DRIVER=$(pin FALCO_DRIVER)
FALCOSIDEKICK_CHART_VERSION=$(pin FALCOSIDEKICK_VERSION)
ALERTMANAGER_CHART_VERSION=$(pin ALERTMANAGER_VERSION)
TRIVY_IMAGE_VERSION=$(pin TRIVY_VERSION)
for value in "$FALCO_CHART_VERSION" "$FALCO_DRIVER" "$FALCOSIDEKICK_CHART_VERSION" \
             "$ALERTMANAGER_CHART_VERSION" "$TRIVY_IMAGE_VERSION"; do
    [ -n "$value" ] || fail "a required Monitor pin is empty in infra/versions.env"
done
[ "$FALCO_DRIVER" = modern_ebpf ] \
    || fail "FALCO_DRIVER must be modern_ebpf, found $FALCO_DRIVER"

for tool in helm kubectl; do
    command -v "$tool" >/dev/null 2>&1 || fail "$tool is not on PATH"
done

current_context=$(kubectl config current-context 2>/dev/null || true)
case "$current_context" in
    kind-*) : ;;
    *) fail "current kubectl context '${current_context:-<none>}' is not a kind cluster" ;;
esac

retry_helm helm repo add falcosecurity https://falcosecurity.github.io/charts --force-update >/dev/null \
    || fail "helm repo add falcosecurity failed after $HELM_RETRY_ATTEMPTS attempts"
retry_helm helm repo add prometheus-community https://prometheus-community.github.io/helm-charts --force-update >/dev/null \
    || fail "helm repo add prometheus-community failed after $HELM_RETRY_ATTEMPTS attempts"
retry_helm helm repo update falcosecurity prometheus-community >/dev/null \
    || fail "helm repo update failed after $HELM_RETRY_ATTEMPTS attempts"

# Resolve the application tag from the exact Sidekick chart selected by the
# versions.env chart pin. This avoids a literal app version in values while also
# avoiding chart 0.12.1's inconsistent default image tag.
#
# Retried as a whole rather than through retry_helm: a pipeline's exit status under plain sh is the
# LAST command's (awk's, which exits 0 even when helm produced nothing), so the retry condition is
# the same non-empty-result check the fail guard below already made -- just tried up to
# HELM_RETRY_ATTEMPTS times, with the same sleep between attempts, before it is allowed to fail.
retry_helm_attempt=1
while :; do
    FALCOSIDEKICK_APP_VERSION=$(helm show chart falcosecurity/falcosidekick \
        --version "$FALCOSIDEKICK_CHART_VERSION" \
        | awk '$1 == "appVersion:" { print $2; exit }')
    [ -n "$FALCOSIDEKICK_APP_VERSION" ] && break
    [ "$retry_helm_attempt" -ge "$HELM_RETRY_ATTEMPTS" ] && break
    printf 'monitor sources install: helm show chart falcosecurity/falcosidekick returned nothing (attempt %s/%s); retrying in %ss\n' \
        "$retry_helm_attempt" "$HELM_RETRY_ATTEMPTS" "$HELM_RETRY_SLEEP_SECONDS" >&2
    sleep "$HELM_RETRY_SLEEP_SECONDS"
    retry_helm_attempt=$((retry_helm_attempt + 1))
done
[ -n "$FALCOSIDEKICK_APP_VERSION" ] \
    || fail "Falcosidekick chart $FALCOSIDEKICK_CHART_VERSION has no appVersion"
retry_helm helm template falcosidekick-pin-check falcosecurity/falcosidekick \
    --namespace monitor \
    --version "$FALCOSIDEKICK_CHART_VERSION" \
    --values infra/monitor/falcosidekick-values.yaml \
    --set "image.tag=$FALCOSIDEKICK_APP_VERSION" >/dev/null \
    || fail "helm template falcosidekick-pin-check failed after $HELM_RETRY_ATTEMPTS attempts"

kubectl create namespace monitor --dry-run=client -o yaml | kubectl apply -f - >/dev/null

retry_helm helm upgrade --install falco falcosecurity/falco \
    --namespace monitor \
    --version "$FALCO_CHART_VERSION" \
    --values infra/monitor/falco-values.yaml \
    --set "driver.kind=$FALCO_DRIVER" \
    --set "falcosidekick.image.tag=$FALCOSIDEKICK_APP_VERSION" \
    --set-file 'customRules.overwatch-rules\.yaml=monitor/rules/overwatch-rules.yaml' \
    --wait --timeout 10m \
    || fail "helm upgrade --install falco failed after $HELM_RETRY_ATTEMPTS attempts"

retry_helm helm upgrade --install alertmanager prometheus-community/alertmanager \
    --namespace observability \
    --create-namespace \
    --version "$ALERTMANAGER_CHART_VERSION" \
    --values infra/monitor/alertmanager-values.yaml \
    --wait --timeout 10m \
    || fail "helm upgrade --install alertmanager failed after $HELM_RETRY_ATTEMPTS attempts"

# Re-assert Prometheus values so its generated prometheus.yml contains the
# standalone Alertmanager target and the project-owned alerting rules.
prometheus_version=$(awk -F= '$1 == "PROMETHEUS_CHART_VERSION" { sub(/\r$/, "", $2); print $2; exit }' infra/versions.env)
[ -n "$prometheus_version" ] || fail "PROMETHEUS_CHART_VERSION is empty in infra/versions.env"
retry_helm helm upgrade --install prometheus prometheus-community/prometheus \
    --namespace observability \
    --version "$prometheus_version" \
    --values infra/observability/prometheus-values.yaml \
    --wait --timeout 10m \
    || fail "helm upgrade --install prometheus failed after $HELM_RETRY_ATTEMPTS attempts"

# The manifest carries a token rather than a second copy of the version. Render into a temporary
# file and apply that exact build product so versions.env remains the sole pinning surface.
trivy_job=$(mktemp)
trap 'rm -f "$trivy_job"' EXIT HUP INT TERM
sed "s|TRIVY_IMAGE_VERSION|$TRIVY_IMAGE_VERSION|g" \
    infra/monitor/trivy-kubernetes-job.yaml > "$trivy_job"
kubectl apply -f "$trivy_job"

printf 'monitor sources install: PASS -- Falco %s (%s), Falcosidekick chart %s/app %s, Alertmanager %s, Trivy %s\n' \
    "$FALCO_CHART_VERSION" "$FALCO_DRIVER" "$FALCOSIDEKICK_CHART_VERSION" \
    "$FALCOSIDEKICK_APP_VERSION" "$ALERTMANAGER_CHART_VERSION" "$TRIVY_IMAGE_VERSION"
