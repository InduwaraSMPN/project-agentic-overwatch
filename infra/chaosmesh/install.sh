#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_root"

fail() { printf 'chaos-mesh install: FAIL -- %s\n' "$*" >&2; exit 1; }
pin() { awk -F= -v key="$1" '$1 == key { sub(/\r$/, "", $2); print $2; exit }' infra/versions.env; }

# Bounded retry for a helm call that reaches charts.chaos-mesh.org over the network: 3 attempts,
# short sleep between, mirroring the OPA-fetch loop in guardian/deploy/Dockerfile. Operational
# retry knob, not a protocol quantity (.agents/rules/00-source-of-truth.md).
retry_helm() {
  retry_helm_attempt=1
  while :; do
    if "$@"; then return 0; fi
    [ "$retry_helm_attempt" -ge 3 ] && return 1
    printf 'chaos-mesh install: helm command failed (attempt %s/3); retrying in 5s\n' "$retry_helm_attempt" >&2
    sleep 5
    retry_helm_attempt=$((retry_helm_attempt + 1))
  done
}

version=$(pin CHAOS_MESH_CHART_VERSION)
[ -n "$version" ] || fail "CHAOS_MESH_CHART_VERSION is empty in infra/versions.env"
for tool in helm kubectl; do command -v "$tool" >/dev/null 2>&1 || fail "$tool is not on PATH"; done
[ "$(kubectl config current-context 2>/dev/null || true)" = kind-kind ] \
  || fail "current kubectl context must be kind-kind"

retry_helm helm repo add chaos-mesh https://charts.chaos-mesh.org --force-update >/dev/null \
  || fail "helm repo add chaos-mesh failed after 3 attempts"
retry_helm helm repo update chaos-mesh >/dev/null \
  || fail "helm repo update chaos-mesh failed after 3 attempts"
retry_helm helm upgrade --install chaos-mesh chaos-mesh/chaos-mesh \
  --namespace chaos-mesh --create-namespace --version "$version" \
  --set chaosDaemon.runtime=containerd \
  --set chaosDaemon.socketPath=/run/containerd/containerd.sock \
  --set controllerManager.replicaCount=1 \
  --set dashboard.create=false \
  --set dnsServer.create=false \
  --wait --timeout 10m \
  || fail "helm upgrade --install chaos-mesh failed after 3 attempts"

printf 'chaos-mesh install: PASS -- chart %s, containerd socket, one controller, dashboard/dns disabled\n' "$version"
