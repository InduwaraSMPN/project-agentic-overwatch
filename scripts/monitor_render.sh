#!/bin/sh
# Render every build-controlled M2 Phase B manifest without contacting a cluster.
set -eu
LC_ALL=C
export LC_ALL
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

fail() {
    printf 'monitor-render: FAIL -- %s\n' "$*" >&2
    exit 1
}
pin() {
    awk -F= -v key="$1" '$1 == key { sub(/\r$/, "", $2); print $2; exit }' infra/versions.env
}
for tool in helm kubectl; do
    command -v "$tool" >/dev/null 2>&1 || fail "$tool is not on PATH"
done
falco=$(pin FALCO_CHART_VERSION)
sidekick=$(pin FALCOSIDEKICK_VERSION)
alertmanager=$(pin ALERTMANAGER_VERSION)
prometheus=$(pin PROMETHEUS_CHART_VERSION)
trivy=$(pin TRIVY_VERSION)
driver=$(pin FALCO_DRIVER)
for value in "$falco" "$sidekick" "$alertmanager" "$prometheus" "$trivy" "$driver"; do
    [ -n "$value" ] || fail "a required Monitor pin is empty in infra/versions.env"
done
[ "$driver" = modern_ebpf ] || fail "FALCO_DRIVER must be modern_ebpf, found $driver"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
helm repo add falcosecurity https://falcosecurity.github.io/charts --force-update >/dev/null
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts --force-update >/dev/null
helm repo update falcosecurity prometheus-community >/dev/null
sidekick_app=$(helm show chart falcosecurity/falcosidekick --version "$sidekick" \
    | awk '$1 == "appVersion:" { print $2; exit }')
[ -n "$sidekick_app" ] || fail "Falcosidekick chart $sidekick has no appVersion"
helm template falco falcosecurity/falco --namespace monitor --version "$falco" \
    --values infra/monitor/falco-values.yaml \
    --set "driver.kind=$driver" \
    --set "falcosidekick.image.tag=$sidekick_app" \
    --set-file 'customRules.overwatch-rules\.yaml=monitor/rules/overwatch-rules.yaml' \
    > "$work/falco.yaml"
helm template falcosidekick-pin-check falcosecurity/falcosidekick --namespace monitor \
    --version "$sidekick" --values infra/monitor/falcosidekick-values.yaml \
    --set "image.tag=$sidekick_app" > "$work/falcosidekick.yaml"
helm template alertmanager prometheus-community/alertmanager --namespace observability \
    --version "$alertmanager" --values infra/monitor/alertmanager-values.yaml \
    > "$work/alertmanager.yaml"
helm template prometheus prometheus-community/prometheus --namespace observability \
    --version "$prometheus" --values infra/observability/prometheus-values.yaml \
    > "$work/prometheus.yaml"
kubectl kustomize monitor/deploy > "$work/aggregator.yaml"
sed "s|TRIVY_IMAGE_VERSION|$trivy|g" infra/monitor/trivy-kubernetes-job.yaml \
    > "$work/trivy.yaml"

# Assert the rendered output carries the load-bearing wiring rather than accepting an empty render.
grep -q 'kind: DaemonSet' "$work/falco.yaml" || fail "Falco chart rendered no DaemonSet"
grep -q 'kind: Deployment' "$work/falcosidekick.yaml" \
    || fail "Falcosidekick chart rendered no Deployment"
grep -q 'kind: StatefulSet' "$work/alertmanager.yaml" \
    || fail "Alertmanager chart rendered no StatefulSet"
grep -q 'alerting_rules.yml' "$work/prometheus.yaml" \
    || fail "Prometheus render contains no alert rules"
grep -q 'name: evidence-aggregator' "$work/aggregator.yaml" \
    || fail "aggregator render is absent"
grep -q "image: docker.io/aquasec/trivy:$trivy" "$work/trivy.yaml" \
    || fail "Trivy render did not apply its pin"

printf 'monitor-render: PASS -- Falco %s/%s, Falcosidekick %s, Alertmanager %s, Prometheus %s, Trivy %s and aggregator manifests rendered\n' \
    "$falco" "$driver" "$sidekick" "$alertmanager" "$prometheus" "$trivy"
