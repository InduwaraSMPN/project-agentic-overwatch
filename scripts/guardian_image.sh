#!/bin/sh
# Build the Guardian image from the immutable inputs in infra/versions.env and load it into kind.
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
    command -v "$tool" >/dev/null 2>&1 || { echo "guardian-image: $tool is not on PATH" >&2; exit 1; }
done

image=$(value GUARDIAN_IMAGE)
base=$(value GUARDIAN_PYTHON_BASE_IMAGE)
[ -n "$image" ] && [ -n "$base" ] || { echo "guardian-image: Guardian image pins are absent" >&2; exit 1; }

docker build --pull=false -f guardian/deploy/Dockerfile -t "$image" \
  --build-arg "PYTHON_BASE_IMAGE=$base" \
  --build-arg "FASTAPI_VERSION=$(value FASTAPI_VERSION)" \
  --build-arg "PYJWT_VERSION=$(value PYJWT_VERSION)" \
  --build-arg "PYDANTIC_VERSION=$(value PYDANTIC_VERSION)" \
  --build-arg "KUBERNETES_CLIENT_VERSION=$(value KUBERNETES_CLIENT_VERSION)" \
  --build-arg "UVICORN_VERSION=$(value UVICORN_VERSION)" \
  --build-arg "OPA_VERSION=$(value OPA_VERSION)" \
  --build-arg "OPA_LINUX_AMD64_SHA256=c9f985ce0d345f5484006ade2c695ed9e3f308e4441139e46695c5c182ac0839" \
  .
kind load docker-image --name "$cluster_name" "$image"
printf 'guardian-image: PASS — built and loaded %s into kind-%s\n' "$image" "$cluster_name"
