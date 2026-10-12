#!/bin/sh
#
# install_cluster_tools.sh -- install the cluster toolchain at exactly the versions
# infra/versions.env pins, into a directory on PATH.
#
# WHY THIS FILE EXISTS, AND WHY IT IS A SCRIPT RATHER THAN WORKFLOW STEPS
#   docs/04-repo-conventions.md section 1 states the rule without qualification: every gate's
#   logic lives in scripts/, the Makefile is a table of one-line delegators, and the workflow
#   files invoke the same scripts directly rather than reimplementing them, "so each gate is
#   defined once and runs identically from `make` in WSL2, from Git Bash on the Windows host
#   ... and on the CI runner". A tool-install sequence written as a dozen `run:` steps inside
#   .github/workflows/env-bringup.yml would be logic in a workflow file, and -- worse -- it
#   would be logic that a developer setting up their own WSL2 distro could not run. The two
#   audiences are the same audience: docs/04-repo-conventions.md section 2 step 2 asks a
#   developer to install this exact list, and docs/plans/M1-implementation-plan.md's "Step 0 --
#   prerequisites" asks for it "at the versions T1.1 is about to pin". One script serves both,
#   and because it is the same script, a green bring-up workflow is evidence about the
#   developer's setup path and not merely about the runner's.
#
# WHY THE VERSIONS COME FROM infra/versions.env AND NOT FROM LITERALS HERE
#   This is the deliberate exception to ADR-011, which fixes CI *tool* pins -- ruff, pytest --
#   as literals in the workflow so they stay upgradable without touching a pin frozen at v1.0
#   or invalidating the versions_env_sha256 digest every sealed bundle carries. That reasoning
#   turns on those tools not being part of the evaluated artefact. kind, kubectl, helm,
#   kustomize and the cilium CLI are part of it: they are the substrate the experiment runs on,
#   NFR1 asserts the environment reproduces from a clean machine, and traceability row T-16's
#   verifying check is a fresh-clone bring-up. Reading the versions from infra/versions.env is
#   therefore not a convenience -- it is the thing under test. A literal here would prove that
#   some toolchain can bring the environment up, which is not the claim.
#
# CONTRACT
#   Reads infra/versions.env. Fails, naming the key, if any version it needs is empty: an
#   unpinned install is not reproducible and would make a green run meaningless. Installs into
#   $BIN_DIR (default /usr/local/bin), using sudo only when that directory is not writable, so
#   the script works unprivileged on a developer's machine and privileged on a CI runner
#   without branching on which it is.
#
#   Idempotent. A tool already present at the pinned version is left alone and reported as
#   already-current; a tool present at a different version is replaced, because the pin is the
#   contract and a stale binary that merely exists is the failure mode this script prevents.
#
#   Linux amd64 only, and it says so rather than guessing: WSL2 Ubuntu and ubuntu-latest are
#   both linux/amd64, and every download URL below is architecture-specific. An arm64 host is
#   a real case for a future contributor, so the check fails with a message naming the gap
#   instead of downloading a binary that cannot execute.
#
# WHAT THIS SCRIPT DOES NOT DO
#   It does not install Docker, and it does not enable Docker Desktop's WSL2 integration.
#   Docker is a host prerequisite (docs/04-repo-conventions.md section 2 step 1); on a Windows
#   host the integration toggle lives in Docker Desktop's own settings, outside any repository.
#   scripts/preflight.sh is what reports its absence at the point it matters.
#
# STREAMS
#   stdout carries one line per tool plus a final summary line. stderr carries failures.
#
# PORTABILITY
#   Strict POSIX sh -- no bashisms, no GNU-only options -- so it runs under dash in WSL2
#   Ubuntu, under Git Bash on the Windows host, and on ubuntu-latest.

set -eu

LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

versions_file="infra/versions.env"
BIN_DIR=${BIN_DIR:-/usr/local/bin}

if [ ! -f "$versions_file" ]; then
    echo "install-cluster-tools: $versions_file not found; run from a full checkout" >&2
    exit 1
fi

os=$(uname -s)
arch=$(uname -m)
if [ "$os" != "Linux" ] || { [ "$arch" != "x86_64" ] && [ "$arch" != "amd64" ]; }; then
    echo "install-cluster-tools: this script installs linux/amd64 binaries only; this host reports $os/$arch." >&2
    echo "install-cluster-tools: install the pinned versions by hand, or extend the URLs below for this architecture." >&2
    exit 1
fi

# infra/versions.env is contractually values-only -- its header rule 1 forbids logic, command
# substitution, shell expansion and conditionals -- which is exactly what makes dot-sourcing it
# safe rather than an arbitrary-code hazard.
# shellcheck disable=SC1090
. "./$versions_file"

require_pin() {
    # $1 key name, $2 value
    if [ -z "${2:-}" ]; then
        echo "install-cluster-tools: $1 is empty in $versions_file." >&2
        echo "install-cluster-tools: an unpinned install is not reproducible, so this is a hard failure rather than a default." >&2
        exit 1
    fi
}

require_pin KIND_VERSION "${KIND_VERSION:-}"
require_pin KUBECTL_VERSION "${KUBECTL_VERSION:-}"
require_pin HELM_VERSION "${HELM_VERSION:-}"
require_pin KUSTOMIZE_VERSION "${KUSTOMIZE_VERSION:-}"
require_pin CILIUM_CLI_VERSION "${CILIUM_CLI_VERSION:-}"

work=$(mktemp -d) || exit 1
trap 'rm -rf "$work"' EXIT HUP INT TERM

# sudo only when $BIN_DIR is not writable. Resolved once rather than per-tool so the whole run
# is consistent, and reported so a reader of the log knows which mode it was.
if [ -w "$BIN_DIR" ] || [ ! -e "$BIN_DIR" ]; then
    SUDO=""
else
    SUDO="sudo"
fi

install_binary() {
    # $1 source path, $2 installed name
    $SUDO install -m 0755 "$1" "$BIN_DIR/$2"
}

fetch() {
    # $1 url, $2 destination. --fail so an HTML error page never lands on disk as a "binary",
    # --location because every release URL below redirects at least once.
    curl -sSfL --retry 3 --retry-delay 2 -o "$2" "$1"
}

installed=0
skipped=0

report_current() {
    printf 'install-cluster-tools: %-10s already at %s\n' "$1" "$2"
    skipped=$((skipped + 1))
}

report_installed() {
    printf 'install-cluster-tools: %-10s installed %s\n' "$1" "$2"
    installed=$((installed + 1))
}

# --- kind -----------------------------------------------------------------------------
# `kind version` prints "kind vX.Y.Z go... ", so field 2 is the version.
kind_have=""
if command -v kind >/dev/null 2>&1; then
    kind_have=$(kind version 2>/dev/null | awk '{ print $2 }')
fi
if [ "$kind_have" = "$KIND_VERSION" ]; then
    report_current kind "$KIND_VERSION"
else
    fetch "https://kind.sigs.k8s.io/dl/$KIND_VERSION/kind-linux-amd64" "$work/kind"
    install_binary "$work/kind" kind
    report_installed kind "$KIND_VERSION"
fi

# --- kubectl --------------------------------------------------------------------------
kubectl_have=""
if command -v kubectl >/dev/null 2>&1; then
    kubectl_have=$(kubectl version --client -o json 2>/dev/null \
        | awk -F\" '/gitVersion/ { print $4; exit }')
fi
if [ "$kubectl_have" = "$KUBECTL_VERSION" ]; then
    report_current kubectl "$KUBECTL_VERSION"
else
    fetch "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl" "$work/kubectl"
    install_binary "$work/kubectl" kubectl
    report_installed kubectl "$KUBECTL_VERSION"
fi

# --- helm -----------------------------------------------------------------------------
helm_have=""
if command -v helm >/dev/null 2>&1; then
    helm_have=$(helm version --template '{{.Version}}' 2>/dev/null)
fi
if [ "$helm_have" = "$HELM_VERSION" ]; then
    report_current helm "$HELM_VERSION"
else
    fetch "https://get.helm.sh/helm-$HELM_VERSION-linux-amd64.tar.gz" "$work/helm.tgz"
    tar -xzf "$work/helm.tgz" -C "$work"
    install_binary "$work/linux-amd64/helm" helm
    report_installed helm "$HELM_VERSION"
fi

# --- kustomize ------------------------------------------------------------------------
# The release asset is tagged kustomize/vX.Y.Z upstream; the archive name carries the bare
# version without the leading v, so both forms are derived from the single pinned value.
kustomize_bare=${KUSTOMIZE_VERSION#v}
kustomize_have=""
if command -v kustomize >/dev/null 2>&1; then
    kustomize_have=$(kustomize version 2>/dev/null | awk '{ print $1 }')
fi
if [ "$kustomize_have" = "$KUSTOMIZE_VERSION" ] || [ "$kustomize_have" = "$kustomize_bare" ]; then
    report_current kustomize "$KUSTOMIZE_VERSION"
else
    fetch "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2F$KUSTOMIZE_VERSION/kustomize_${KUSTOMIZE_VERSION}_linux_amd64.tar.gz" \
        "$work/kustomize.tgz"
    tar -xzf "$work/kustomize.tgz" -C "$work"
    install_binary "$work/kustomize" kustomize
    report_installed kustomize "$KUSTOMIZE_VERSION"
fi

# --- cilium CLI -----------------------------------------------------------------------
# The CLI is a diagnostic tool -- `cilium status` is part of the enforcement proof in
# scripts/netpol_proof.sh -- and is versioned independently of the Cilium chart, which is why
# infra/versions.env carries CILIUM_CLI_VERSION and CILIUM_CHART_VERSION as separate keys.
cilium_have=""
if command -v cilium >/dev/null 2>&1; then
    cilium_have=$(cilium version --client 2>/dev/null | awk '/cilium-cli/ { print $2; exit }')
fi
if [ "$cilium_have" = "$CILIUM_CLI_VERSION" ]; then
    report_current cilium "$CILIUM_CLI_VERSION"
else
    fetch "https://github.com/cilium/cilium-cli/releases/download/$CILIUM_CLI_VERSION/cilium-linux-amd64.tar.gz" \
        "$work/cilium.tgz"
    tar -xzf "$work/cilium.tgz" -C "$work"
    install_binary "$work/cilium" cilium
    report_installed cilium "$CILIUM_CLI_VERSION"
fi

printf 'install-cluster-tools: PASS — %s installed, %s already current, into %s (pins from %s)\n' \
    "$installed" "$skipped" "$BIN_DIR" "$versions_file"
exit 0
