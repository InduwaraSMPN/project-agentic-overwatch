#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL
context=${KUBE_CONTEXT:-$(kubectl config current-context 2>/dev/null || true)}
[ -n "$context" ] || { echo "chaos-preflight: FAIL -- no kubectl context" >&2; exit 1; }

parents=$(kubectl --context "$context" get httpchaos,networkchaos,podchaos,stresschaos -A --no-headers 2>/dev/null || true)
if [ -n "$parents" ]; then
    printf 'chaos-preflight: FAIL -- active parent chaos resources:\n%s\n' "$parents" >&2
    exit 1
fi

subordinates=$(kubectl --context "$context" get podhttpchaos,podnetworkchaos -A -o json 2>/dev/null \
    | python3 -c 'import json,sys; print("\n".join("{}/{}".format(x["metadata"].get("namespace", "-"), x["metadata"]["name"]) for x in json.load(sys.stdin).get("items", []) if x.get("spec")))' \
    || true)
if [ -n "$subordinates" ]; then
    printf 'chaos-preflight: FAIL -- subordinate chaos resources with non-empty specs:\n%s\n' "$subordinates" >&2
    exit 1
fi

for node in $(kubectl --context "$context" get nodes -o name | sed 's|^node/||'); do
    if docker exec "$node" sh -c "ps -eo args | grep '[t]proxy'" >/dev/null 2>&1; then
        printf 'chaos-preflight: FAIL -- tproxy is still running on node %s\n' "$node" >&2
        exit 1
    fi
    qdiscs=$(docker exec "$node" sh -c 'for p in /proc/[0-9]*/ns/net; do nsexec -n "$p" -- tc qdisc show 2>/dev/null; done' \
        | grep -E 'qdisc (netem|tbf) ' || true)
    if [ -n "$qdiscs" ]; then
        printf 'chaos-preflight: FAIL -- netem/tbf qdisc remains on node %s:\n%s\n' "$node" "$qdiscs" >&2
        exit 1
    fi
done

echo "chaos-preflight: PASS -- no parent faults, configured subordinate faults, tproxy processes, or netem/tbf qdiscs"
