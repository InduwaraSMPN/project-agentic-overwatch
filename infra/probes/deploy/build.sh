#!/bin/sh
# infra/probes/deploy/build.sh -- build the in-cluster SLO probe image and load it into kind.
#
# Mirrors scripts/guardian_image.sh's shape for the reason that script is the established pattern
# in this repository for "build a local image and load it into kind", not because this image is
# pinned in infra/versions.env the way the Guardian's is -- see the Dockerfile in this directory for
# why it deliberately is not. This script lives under infra/probes/ rather than scripts/ because it
# builds and loads exactly one thing this stream owns end to end (ADR-085); scripts/ is a directory
# shared by every milestone's own deploy helper and is not touched here.
#
#     sh infra/probes/deploy/build.sh
#
# Override the image name/tag or the cluster name with SLO_PROBE_IMAGE / KIND_CLUSTER_NAME; both
# must then also change in runner/live_baseline.py's PROBE_IMAGE, or the runner will apply a Pod
# naming an image the cluster never loaded.
set -eu
LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
cd "$repo_root"

image=${SLO_PROBE_IMAGE:-agentic-overwatch/slo-probe:local}
cluster_name=${KIND_CLUSTER_NAME:-kind}

for tool in docker kind; do
    command -v "$tool" >/dev/null 2>&1 || { echo "slo-probe-image: $tool is not on PATH" >&2; exit 1; }
done

docker build --pull=false -f infra/probes/deploy/Dockerfile -t "$image" .
kind load docker-image --name "$cluster_name" "$image"
printf 'slo-probe-image: PASS — built and loaded %s into kind-%s\n' "$image" "$cluster_name"
