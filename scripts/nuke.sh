#!/bin/sh
#
# nuke.sh -- destroy the M1 environment including its volumes. Backs `make nuke`, whose contract
# is docs/04-repo-conventions.md section 3: "destroy incl. volumes". It is the counterpart to
# scripts/down.sh, which removes the workloads and keeps the cluster; see that script's header for
# the reasoning that makes the two genuinely different targets on a kind substrate.
#
# WHAT IT DESTROYS, AND WHY THAT IS EVERYTHING
# `kind delete cluster` removes the node containers. On kind the node container IS the storage
# layer: a PersistentVolume from the default local-path provisioner is a directory inside it, the
# pulled image layers are inside it, and its anonymous Docker volumes go with it. There is no
# separate step that "also removes the volumes" and no way to keep them; deleting the cluster is
# the volume deletion. The remaining cluster items are Docker volumes still carrying its label and
# the shared `kind` bridge network once no container is attached to it.
#
# Langfuse is deliberately outside kind, and its Postgres, ClickHouse, Redis and MinIO state is bind
# mounted into four repository-owned directories. Those four directories are therefore an explicit
# part of this destruction contract. They are named individually below rather than deleting a
# generic `volumes/` tree, and every path component above them is rejected if it is a symlink. A
# datastore entry that is itself a symlink is unlinked by rm, never followed. This makes the fixed
# repository boundary executable rather than relying on the current working directory or user input.
#
# WHY IT ASKS, AND WHY IT ACCEPTS THREE ANSWERS
# Everything above is irreversible, and the plausible mistake is not malice but muscle memory --
# `make nuke` reads like `make clean` and it is one character from `make up` on a keyboard. So the
# script prints the exact list first and then requires one of:
#
#   --yes / -y   the explicit form, for a human who has read the list, and for any caller that can
#                pass an argument.
#   FORCE=1      the environment form, for callers that cannot. `make nuke` runs a fixed recipe
#                with no argument of its own, so `FORCE=1 make nuke` is how the Makefile path and
#                a CI job drive this non-interactively. Without it, a Makefile recipe would need
#                conditional logic, and docs/04-repo-conventions.md section 1 requires recipes to
#                be one-line delegators with no logic in them.
#   a typed y    for an interactive terminal, which is where the muscle-memory mistake happens.
#
# When stdin is not a terminal and neither --yes nor FORCE=1 was given, the script REFUSES rather
# than proceeding or hanging. A non-interactive caller that did not say yes did not say yes, and
# reading end-of-file from a closed stdin is not consent.
#
# --dry-run prints the same list and stops. It exists so that the "print exactly what is about to
# be deleted" half of this contract can be exercised on its own, including in a review, without
# anybody having to trust that the confirmation prompt would have been honoured.
#
# WHAT IT DOES NOT DO
#   It does not prune dangling Docker volumes generally. `docker volume prune` would remove
#   volumes belonging to every other project on the machine, and this script's remit is one
#   cluster. Volumes are removed only when they carry this cluster's own label.
#   It does not remove the `kind` Docker network while any container is still attached, because
#   that network is shared by every kind cluster on the host and a second cluster may be using it.
#   It does not delete Langfuse's whole parent directory, accept a state path from the environment,
#   or follow symlinks on the path to that state. Only the four fixed datastore directories go.
#   It does not touch infra/versions.env, any other repository content, or anything under runs/.
#   Run bundles are data (docs/protocols/data-management.md), not environment.
#
# ENVIRONMENT
#   FORCE              set to 1 to skip the confirmation; see above
#   KIND_CLUSTER_NAME  overrides the cluster name; the default derivation is scripts/up.sh's
#
# STREAMS
#   stdout carries exactly one summary line; the deletion plan, the prompt and every detail go to
#   stderr. Exit 0 when the environment is gone (or was already gone), 1 on refusal or failure.
#
# PORTABILITY
#   Strict POSIX sh, as with every other script in this directory.

set -eu

LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

KIND_CONFIG=infra/kind-config.yaml
KIND_NETWORK=kind
LANGFUSE_ROOT=infra/observability/langfuse
LANGFUSE_VOLUMES=$LANGFUSE_ROOT/volumes
LANGFUSE_STATE_DIRS="postgres clickhouse redis minio"

assume_yes=0
dry_run=0
[ "${FORCE:-0}" = "1" ] && assume_yes=1

usage() {
    cat >&2 <<'USAGE'
usage: sh scripts/nuke.sh [--yes|-y] [--dry-run] [--help]

Destroys the kind cluster and all repo-owned Langfuse datastore state, including volumes.

  --yes, -y   proceed without asking; equivalent to FORCE=1
  --dry-run   print the deletion plan and stop
  --help      print this text

FORCE=1 is the form to use from make, whose recipes take no arguments of their own.
USAGE
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --yes|-y) assume_yes=1 ;;
        --dry-run) dry_run=1 ;;
        --help|-h) usage; exit 0 ;;
        *)
            printf 'nuke: unknown argument: %s\n' "$1" >&2
            usage
            printf 'nuke: FAIL — unknown argument\n'
            exit 1
            ;;
    esac
    shift
done

detail() {
    printf 'nuke:   %s\n' "$1" >&2
}

if ! command -v kind >/dev/null 2>&1; then
    printf 'nuke: FAIL — kind is not on PATH, so the cluster cannot be deleted\n' >&2
    printf 'nuke: FAIL — kind absent\n'
    exit 1
fi

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

# --- validate and enumerate what would go --------------------------------------------------------

# The path is intentionally not configurable: accepting an override would turn FORCE=1 into an
# arbitrary recursive-delete primitive. Refuse symlinked ancestors before even printing a plan;
# otherwise `volumes/postgres`, for example, could resolve outside the checkout. The datastore leaf
# may itself be a symlink because `rm -rf` unlinks that leaf without traversing its target.
for component in infra infra/observability "$LANGFUSE_ROOT" "$LANGFUSE_VOLUMES"; do
    if [ -L "$component" ]; then
        printf 'nuke: REFUSING — Langfuse state ancestor is a symlink: %s\n' "$component" >&2
        printf 'nuke: FAIL — unsafe Langfuse state path\n'
        exit 1
    fi
    if [ -d "$component" ]; then
        component_real=$(CDPATH= cd -- "$component" && pwd -P)
        component_expected=$repo_root/$component
        if [ "$component_real" != "$component_expected" ]; then
            printf 'nuke: REFUSING — Langfuse state ancestor escapes the repository: %s\n' \
                "$component" >&2
            printf 'nuke: FAIL — unsafe Langfuse state path\n'
            exit 1
        fi
    fi
done

langfuse_state_present=0
for datastore in $LANGFUSE_STATE_DIRS; do
    state_path=$LANGFUSE_VOLUMES/$datastore
    if [ -e "$state_path" ] || [ -L "$state_path" ]; then
        langfuse_state_present=$((langfuse_state_present + 1))
    fi
done

cluster_present=0
if kind get clusters 2>/dev/null | awk -v want="$cluster_name" '$0 == want { f = 1 } END { exit !f }'
then
    cluster_present=1
fi

docker_present=0
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    docker_present=1
fi

# kind labels every node container and every volume it creates with the cluster name, which is what
# makes this enumeration specific rather than a guess at a naming convention.
cluster_label="io.x-k8s.io/cluster=$cluster_name"
node_containers=""
cluster_volumes=""
network_attached=""
if [ "$docker_present" -eq 1 ]; then
    node_containers=$(docker ps -a --filter "label=$cluster_label" --format '{{.Names}}' 2>/dev/null || true)
    cluster_volumes=$(docker volume ls -q --filter "label=$cluster_label" 2>/dev/null || true)
    network_attached=$(docker network inspect "$KIND_NETWORK" -f '{{len .Containers}}' 2>/dev/null || true)
fi

count_lines() {
    printf '%s\n' "$1" | awk 'NF { n++ } END { print n + 0 }'
}

node_count=$(count_lines "$node_containers")
volume_count=$(count_lines "$cluster_volumes")

if [ "$cluster_present" -eq 0 ] && [ "$node_count" -eq 0 ] && [ "$volume_count" -eq 0 ] && \
   [ "$langfuse_state_present" -eq 0 ]; then
    printf 'nuke: no kind cluster named %s, nothing labelled for it, and no Langfuse state — already destroyed\n' \
        "$cluster_name" >&2
    printf 'nuke: PASS — nothing to destroy (no cluster named %s or Langfuse state)\n' "$cluster_name"
    exit 0
fi

# --- print the plan ------------------------------------------------------------------------------

{
    echo "nuke: about to DESTROY the following, irreversibly:"
    echo
    if [ "$cluster_present" -eq 1 ]; then
        echo "  kind cluster:  $cluster_name  (and the kubectl context kind-$cluster_name)"
    else
        echo "  kind cluster:  $cluster_name  — not present"
    fi
    if [ "$docker_present" -eq 0 ]; then
        echo "  docker:        daemon not reachable, so containers, volumes and the network"
        echo "                 attached to this cluster could not be enumerated"
    else
        if [ "$node_count" -gt 0 ]; then
            echo "  node containers ($node_count), with every image layer and every"
            echo "  PersistentVolume directory inside them:"
            printf '%s\n' "$node_containers" | awk 'NF { print "      " $0 }'
        else
            echo "  node containers: none labelled $cluster_label"
        fi
        if [ "$volume_count" -gt 0 ]; then
            echo "  docker volumes ($volume_count) labelled for this cluster:"
            printf '%s\n' "$cluster_volumes" | awk 'NF { print "      " $0 }'
        else
            echo "  docker volumes: none labelled $cluster_label"
        fi
        if [ "$network_attached" = "0" ]; then
            echo "  docker network $KIND_NETWORK: currently has no attached container and will be removed"
        elif [ -n "$network_attached" ]; then
            echo "  docker network $KIND_NETWORK: $network_attached container(s) still attached — KEPT"
        else
            echo "  docker network $KIND_NETWORK: not present"
        fi
    fi
    if [ "$langfuse_state_present" -gt 0 ]; then
        echo "  Langfuse bind-mounted datastore state ($langfuse_state_present present):"
        for datastore in $LANGFUSE_STATE_DIRS; do
            state_path=$LANGFUSE_VOLUMES/$datastore
            if [ -e "$state_path" ] || [ -L "$state_path" ]; then
                echo "      $state_path"
            else
                echo "      $state_path — not present"
            fi
        done
    else
        echo "  Langfuse bind-mounted datastore state: none present"
    fi
    echo
    echo "  NOT touched: all other repository content, infra/versions.env, and anything under runs/."
    echo
} >&2

if [ "$dry_run" -eq 1 ]; then
    printf 'nuke: PASS — dry run, nothing destroyed\n'
    exit 0
fi

# --- confirm -------------------------------------------------------------------------------------

if [ "$assume_yes" -eq 0 ]; then
    if [ ! -t 0 ]; then
        {
            echo "nuke: REFUSING — stdin is not a terminal and neither --yes nor FORCE=1 was given."
            echo "A caller that cannot be asked has not answered. Re-run as one of:"
            echo "    sh scripts/nuke.sh --yes"
            echo "    FORCE=1 make nuke"
        } >&2
        printf 'nuke: FAIL — refused, no confirmation and no terminal to ask on\n'
        exit 1
    fi
    printf 'nuke: type y to destroy everything listed above, anything else to abort: ' >&2
    read -r answer || answer=""
    case "$answer" in
        y|Y|yes|YES) ;;
        *)
            printf 'nuke: aborted at the prompt — nothing destroyed\n' >&2
            printf 'nuke: FAIL — aborted at the prompt\n'
            exit 1
            ;;
    esac
fi

# --- destroy ---------------------------------------------------------------------------------------

langfuse_removed=0
for datastore in $LANGFUSE_STATE_DIRS; do
    state_path=$LANGFUSE_VOLUMES/$datastore
    if [ -e "$state_path" ] || [ -L "$state_path" ]; then
        detail "rm -rf $state_path"
        if rm -rf "$state_path"; then
            langfuse_removed=$((langfuse_removed + 1))
        else
            printf 'nuke: FAIL — could not remove Langfuse datastore state: %s\n' "$state_path" >&2
            printf 'nuke: FAIL — Langfuse state deletion failed\n'
            exit 1
        fi
    fi
done

if [ "$cluster_present" -eq 1 ]; then
    detail "kind delete cluster --name $cluster_name"
    if ! kind delete cluster --name "$cluster_name"; then
        printf 'nuke: FAIL — kind delete cluster failed; see its output above\n' >&2
        printf 'nuke: FAIL — cluster deletion failed\n'
        exit 1
    fi
fi

volumes_removed=0
if [ "$docker_present" -eq 1 ] && [ "$volume_count" -gt 0 ]; then
    # Re-enumerated rather than reusing the list from before the delete: kind removes the volumes
    # it owns along with the containers, so what is left here is the residue, and deleting a name
    # that is already gone would be a spurious failure.
    remaining=$(docker volume ls -q --filter "label=$cluster_label" 2>/dev/null || true)
    for volume in $remaining; do
        detail "docker volume rm $volume"
        if docker volume rm "$volume" >/dev/null 2>&1; then
            volumes_removed=$((volumes_removed + 1))
        else
            printf 'nuke: WARNING — could not remove docker volume %s; it may still be in use\n' \
                "$volume" >&2
        fi
    done
fi

network_removed=0
if [ "$docker_present" -eq 1 ]; then
    # Re-checked after the cluster went, because the count that mattered is the one AFTER its nodes
    # detached. The network is shared by every kind cluster on this host, so it is removed only
    # when nothing at all is attached to it.
    attached_now=$(docker network inspect "$KIND_NETWORK" -f '{{len .Containers}}' 2>/dev/null || true)
    if [ "$attached_now" = "0" ]; then
        detail "docker network rm $KIND_NETWORK"
        if docker network rm "$KIND_NETWORK" >/dev/null 2>&1; then
            network_removed=1
        else
            printf 'nuke: WARNING — could not remove docker network %s\n' "$KIND_NETWORK" >&2
        fi
    elif [ -n "$attached_now" ]; then
        detail "docker network $KIND_NETWORK kept — $attached_now container(s) still attached"
    fi
fi

if [ "$network_removed" -eq 1 ]; then
    network_note="the $KIND_NETWORK network removed"
else
    network_note="the $KIND_NETWORK network kept"
fi

printf 'nuke: PASS — cluster %s destroyed with its volumes, %s residual volume(s) removed, %s, %s Langfuse datastore path(s) removed\n' \
    "$cluster_name" "$volumes_removed" "$network_note" "$langfuse_removed"
exit 0
