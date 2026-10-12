#!/bin/sh
#
# preflight.sh -- prove that this host can build the M1 environment BEFORE anything starts
# mutating it. Called first by scripts/up.sh, and runnable on its own by anyone setting a machine
# up for the first time.
#
# WHY A SEPARATE SCRIPT AND NOT THE FIRST TEN LINES OF up.sh
# The failures this catches are almost all environmental rather than repository defects:
# docs/04-repo-conventions.md section 2 step 1 asks for Docker Desktop's WSL2 integration to be
# enabled for the Ubuntu distro, step 2 asks for six tools to be installed inside it, and the M1
# plan's host table records that on the development machine neither was true when the milestone
# opened. Those are R-03 data points, and ADR-001's log is where they belong. A check that names
# exactly which tool is absent and exactly which pin is empty is a thirty-second fix; the same
# condition discovered by `kind create cluster` half a minute into a bring-up is a stack trace and
# a half-built cluster. Keeping it separate also means it can be run before, and independently of,
# any decision to change the machine.
#
# WHAT IT CHECKS, AND WHY EACH ITEM IS ON THE LIST
#   Tools. docker, kind, kubectl, helm and kustomize are required; the cilium CLI is optional.
#   The five are conventions section 2 step 2's list minus opa, which belongs to the Guardian at
#   M3 and is not on the bring-up path, and minus python3, which no layer of `make up` invokes.
#   The cilium CLI is optional because infra/cilium/install.sh installs the chart through helm;
#   the CLI is what scripts/netpol_proof.sh uses to attribute a drop to the policy engine, which
#   is a separate target with its own prerequisites. kustomize is required even though up.sh
#   applies the Boutique overlay with `kubectl apply -k`, i.e. through kubectl's embedded
#   kustomize rather than the standalone binary: conventions section 2 names it, T1.2 authors an
#   overlay against it, and a host that cannot render the overlay standalone cannot debug it.
#
#   The Docker daemon. Having the `docker` client on PATH proves nothing about whether a daemon
#   will answer, and the exact failure the M1 plan recorded on this host -- the client resolving
#   to the /mnt/c interop shim inside WSL2 while the daemon is unreachable from the distro -- is
#   invisible to a PATH check and fatal to every layer above it.
#
#   versions.env keys. `make up` consumes eight of them; docs/04-repo-conventions.md section 3
#   contracts `up` as building the full environment "from infra/versions.env", so an empty pin is
#   not a missing convenience but a missing input. infra/versions.env's own rule 2 keeps every key
#   present even while empty, so a key that is merely absent is a different and worse defect than
#   one that is empty, and the two are reported differently.
#
# NAMING THE EMPTY KEY RATHER THAN FAILING GENERICALLY
# "versions.env is not populated" sends a reader to a forty-key file to diff it against their
# memory of what `make up` reads. Naming CILIUM_CHART_VERSION sends them to one line. The
# distinction matters most at T1.1 through T1.3, which populate these keys one group at a time, so
# a partially populated file is the normal intermediate state of this milestone rather than an
# exceptional one.
#
# WHAT IS DELIBERATELY NOT CHECKED
#   Tool VERSIONS against their versions.env pins. KIND_VERSION, KUBECTL_VERSION, HELM_VERSION,
#   KUSTOMIZE_VERSION and CILIUM_CLI_VERSION pin how the tooling is INSTALLED, and the milestone
#   that proves a clean machine can install from them is T1.7's fresh-clone workflow, which does
#   the installing. `make up` requires the tools to be present, not to have been installed by it.
#   Asserting the versions here would turn every local minor-version drift into a failed bring-up
#   on a host where the environment is otherwise fine, and would duplicate T1.7's assertion in the
#   one place that cannot act on it.
#
#   Free memory. The M1 plan sizes the steady state and prescribes a .wslconfig, but that file
#   lives in %USERPROFILE% outside the repository and the number is a plan-level estimate rather
#   than a protocol constant. A hard memory gate here would encode an estimate as a threshold, and
#   docs/protocols/evaluation-protocol.md owns thresholds. The layer waits in up.sh surface memory
#   starvation as what it is -- a workload that does not become ready -- and name the workload.
#
# ENVIRONMENT
#   VERSIONS_FILE -- path to the pins file, default infra/versions.env, repo-root relative. It
#   exists so that a caller can check a candidate file before it replaces the tracked one; nothing
#   in make or CI sets it.
#
# STREAMS
#   stdout carries exactly one summary line. stderr carries the per-item findings, any warnings,
#   and the remediation. Exit 0 when the host is ready, 1 with every problem named otherwise. A
#   warning never changes the exit status.
#
# PORTABILITY
#   Strict POSIX sh -- no bashisms, no GNU-only options -- so it runs identically under Git Bash
#   on Windows, under dash in WSL2 Ubuntu, and on ubuntu-latest in CI.

set -eu

# Byte-stable tool output regardless of the ambient locale.
LC_ALL=C
export LC_ALL

# Repo root is derived from the script's own location, never hardcoded, so the script works from
# any working directory and from any clone path.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

VERSIONS_FILE=${VERSIONS_FILE:-infra/versions.env}

work=$(mktemp -d) || exit 1
trap 'rm -rf "$work"' EXIT HUP INT TERM
problems="$work/problems"
: > "$problems"

problem() {
    printf '%s\n' "$1" >> "$problems"
}

warn() {
    printf 'preflight: WARNING — %s\n' "$1" >&2
}

# --- (a) required and optional tools ----------------------------------------------------------

# Space-separated words rather than arrays, because dash has no arrays; every loop below relies on
# default word splitting over these two variables and on nothing else.
REQUIRED_TOOLS="docker kind kubectl helm kustomize"
OPTIONAL_TOOLS="cilium"

tools_total=0
tools_present=0
for tool in $REQUIRED_TOOLS; do
    tools_total=$((tools_total + 1))
    if command -v "$tool" >/dev/null 2>&1; then
        tools_present=$((tools_present + 1))
    else
        problem "required tool not on PATH: $tool (docs/04-repo-conventions.md section 2 step 2)"
    fi
done

for tool in $OPTIONAL_TOOLS; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        msg="optional tool not on PATH: $tool — make up does not need it, but"
        msg="$msg scripts/netpol_proof.sh uses it to attribute a dropped packet to Cilium's"
        msg="$msg policy engine rather than merely observing that a connection failed"
        warn "$msg"
    fi
done

# --- (b) the Docker daemon actually answers ---------------------------------------------------

daemon_reachable=0
if command -v docker >/dev/null 2>&1; then
    if docker info >/dev/null 2>&1; then
        daemon_reachable=1
    else
        msg="the Docker daemon is not reachable from this shell -- 'docker info' failed."
        msg="$msg On Windows that is usually Docker Desktop not running, or its WSL2 integration"
        msg="$msg not enabled for the Ubuntu distro (docs/04-repo-conventions.md section 2 step 1)"
        problem "$msg"
    fi
else
    # The missing binary is already on the problem list and saying it twice would only pad the
    # failure output. The daemon must not be reported as reachable either, hence the explicit 0.
    daemon_reachable=0
fi

# The cluster runs inside Docker, so the kernel that matters is the daemon's rather than this
# shell's, and driving that daemon from Git Bash on the Windows host does work. It is still worth
# one warning, because conventions section 2 asks for cluster work to be done from WSL2 and
# because the two shells do not see the same PATH, the same filesystem performance or necessarily
# the same Docker context -- a bring-up that succeeds in one and fails in the other is confusing
# at exactly the moment it happens.
kernel_name=$(uname -s 2>/dev/null || echo unknown)
case "$kernel_name" in
    Linux) ;;
    *)
        msg="running under '$kernel_name' rather than Linux — docs/04-repo-conventions.md"
        msg="$msg section 2 asks for cluster work to be driven from a WSL2 shell"
        warn "$msg"
        ;;
esac

# --- (c) the versions.env keys make up consumes ------------------------------------------------

# The eight keys below are the pins `make up` reads, directly or through the per-layer installers
# it calls. Each is named here rather than derived from the file, for the reason
# scripts/check_hygiene.sh states about its own core list: a set derived from the thing it guards
# moves whenever that thing moves, and therefore guards nothing. Adding a layer to up.sh means
# adding its key here in the same commit.
#
#   KIND_NODE_IMAGE             infra/kind-config.yaml deliberately carries no node image, so
#                               `kind create cluster --image` is the only place the pin is applied
#                               and an empty value silently gets whatever image the local kind
#                               binary defaults to -- the exact opposite of a reproducible cluster
#   CILIUM_CHART_VERSION        read by infra/cilium/install.sh
#   BOUTIQUE_MANIFEST_REF       the upstream ref the Boutique overlay's base resolves against
#   BOUTIQUE_IMAGE_DIGESTS_FILE the per-service sha256 list the overlay's images transformer reads
#   LOCUST_IMAGE_DIGEST         the image the Locust deployment runs
#   PROMETHEUS_CHART_VERSION    read by infra/observability/install.sh
#   KUBE_STATE_METRICS_VERSION  read by infra/observability/install.sh
#   GRAFANA_VERSION             read by infra/observability/install.sh
#   ALERTMANAGER_VERSION        read by infra/observability/install.sh
#   FALCO_CHART_VERSION         read by monitor/falco/install.sh
#   FALCO_DRIVER                required to equal modern_ebpf by M2 and monitor/falco/install.sh
#   FALCOSIDEKICK_VERSION       checked against the Falco chart dependency lock
#   TRIVY_VERSION               applied to the image used by the Trivy scan Job
#   MONITOR_PYTHON_BASE_IMAGE   immutable base used by scripts/monitor_image.sh
#   MONITOR_IMAGE               local image name loaded into kind by scripts/monitor_image.sh
UP_REQUIRED_KEYS="KIND_NODE_IMAGE CILIUM_CHART_VERSION BOUTIQUE_MANIFEST_REF"
UP_REQUIRED_KEYS="$UP_REQUIRED_KEYS BOUTIQUE_IMAGE_DIGESTS_FILE LOCUST_IMAGE_DIGEST"
UP_REQUIRED_KEYS="$UP_REQUIRED_KEYS PROMETHEUS_CHART_VERSION KUBE_STATE_METRICS_VERSION"
UP_REQUIRED_KEYS="$UP_REQUIRED_KEYS GRAFANA_VERSION ALERTMANAGER_VERSION"
UP_REQUIRED_KEYS="$UP_REQUIRED_KEYS FALCO_CHART_VERSION FALCO_DRIVER FALCOSIDEKICK_VERSION"
UP_REQUIRED_KEYS="$UP_REQUIRED_KEYS TRIVY_VERSION MONITOR_PYTHON_BASE_IMAGE MONITOR_IMAGE PYDANTIC_VERSION"

keys_total=0
keys_populated=0
if [ ! -f "$VERSIONS_FILE" ]; then
    msg="pins file not found: $VERSIONS_FILE — docs/04-repo-conventions.md section 3 contracts"
    msg="$msg make up as building the full environment from it"
    problem "$msg"
    for key in $UP_REQUIRED_KEYS; do
        keys_total=$((keys_total + 1))
    done
else
    for key in $UP_REQUIRED_KEYS; do
        keys_total=$((keys_total + 1))
        if ! grep -q "^${key}=" "$VERSIONS_FILE"; then
            # A key that is absent rather than empty is the worse defect: infra/versions.env's own
            # rule 2 keeps every key present even while empty, precisely so that a consumer may
            # rely on the key existing before anyone has decided what it holds.
            msg="$VERSIONS_FILE has no '$key=' line at all. Rule 2 of that file's header"
            msg="$msg requires every key to stay present even when its value is empty"
            problem "$msg"
            continue
        fi
        value=$(awk -v k="$key" 'index($0, k "=") == 1 {
                   v = substr($0, length(k) + 2)
                   sub(/\r$/, "", v)
                   sub(/[ \t]+$/, "", v)
                   print v
                   exit
               }' "$VERSIONS_FILE")
        if [ -n "$value" ]; then
            keys_populated=$((keys_populated + 1))
        else
            problem "$VERSIONS_FILE key is empty and make up consumes it: $key"
        fi
    done
fi

# --- report -------------------------------------------------------------------------------------

problem_count=$(awk 'END { print NR }' "$problems")

if [ "$problem_count" -gt 0 ]; then
    {
        echo "preflight: FAIL — $problem_count problem(s):"
        echo
        cat "$problems"
        echo
        echo "Each item above is a property of this host or of infra/versions.env, not of the"
        echo "check. Install the missing tooling per docs/04-repo-conventions.md section 2, start"
        echo "or expose the Docker daemon, and populate the named pins in the milestone task that"
        echo "owns them. Record any WSL2 or eBPF workaround in ADR-001's log -- that log is the"
        echo "mitigation risk R-03 asks for, and it is dissertation material later."
    } >&2
    printf 'preflight: FAIL — %s problem(s)\n' "$problem_count"
    exit 1
fi

printf 'preflight: PASS — %s/%s required tool(s) on PATH, Docker daemon reachable (%s), %s/%s versions.env key(s) populated\n' \
    "$tools_present" "$tools_total" "$daemon_reachable" "$keys_populated" "$keys_total"
exit 0
