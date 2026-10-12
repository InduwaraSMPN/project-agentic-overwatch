#!/bin/sh
# Consume a runner-owned G2 TokenRequest bearer without printing it. This proves the scoped identity
# can read pods in boutique and cannot mutate them; it is live-cluster evidence only when executed.
set -eu
LC_ALL=C
export LC_ALL

: "${G2_TOKEN_FILE:?G2_TOKEN_FILE must name the private bearer file}"
[ -s "$G2_TOKEN_FILE" ] || { echo "g2-probe: bearer file is absent or empty" >&2; exit 1; }

token=$(cat "$G2_TOKEN_FILE")
server=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
ca=$(mktemp)
trap 'rm -f "$ca"' EXIT HUP INT TERM
kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > "$ca"

scoped() {
    kubectl --server="$server" --certificate-authority="$ca" --token="$token" "$@"
}

scoped auth can-i list pods -n boutique | grep -qx yes || {
    echo "g2-probe: scoped bearer cannot perform its declared read" >&2
    exit 1
}
scoped auth can-i delete pods -n boutique | grep -qx no || {
    echo "g2-probe: scoped bearer unexpectedly permits pod deletion" >&2
    exit 1
}
scoped auth can-i get secrets -n boutique | grep -qx no || {
    echo "g2-probe: scoped bearer unexpectedly permits secret reads" >&2
    exit 1
}
scoped -n boutique get pods --request-timeout=10s >/dev/null
printf 'g2-probe: PASS — scoped bearer read pods and forbidden operations remained denied\n'
