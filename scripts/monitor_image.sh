#!/bin/sh
# Build the pinned evidence-aggregator image and load it into the selected kind cluster.
set -eu
LC_ALL=C
export LC_ALL
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"
versions_file=${VERSIONS_FILE:-infra/versions.env}
cluster_name=${KIND_CLUSTER_NAME:-kind}
value() {
    awk -F= -v key="$1" '$1 == key { sub(/\r$/, "", $2); print substr($0, length(key) + 2); exit }' "$versions_file"
}
for tool in docker kind; do
    command -v "$tool" >/dev/null 2>&1 \
        || { echo "monitor-image: $tool is not on PATH" >&2; exit 1; }
done
image=$(value MONITOR_IMAGE)
base=$(value MONITOR_PYTHON_BASE_IMAGE)
pydantic=$(value PYDANTIC_VERSION)
[ -n "$image" ] && [ -n "$base" ] && [ -n "$pydantic" ] \
    || { echo "monitor-image: Monitor image pins are absent" >&2; exit 1; }
docker build --pull=false -f monitor/Dockerfile -t "$image" \
    --build-arg "PYTHON_BASE_IMAGE=$base" \
    --build-arg "PYDANTIC_VERSION=$pydantic" .
kind load docker-image --name "$cluster_name" "$image"
printf 'monitor-image: PASS — built and loaded %s into kind-%s\n' "$image" "$cluster_name"
