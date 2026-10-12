#!/bin/sh
#
# self_scan.sh -- SBOM generation and a Trivy vulnerability self-scan of OUR OWN container
# images (M8-T8.4; docs/milestones/M8-hardening.md; design record: docs/adr/ADR-115-sbom-and-
# self-scan.md; operator-facing detail: docs/ops/sbom.md).
#
# THIS IS PACKAGING/OPS TOOLING ONLY. It builds images and reads them with a scanner; it never
# touches a live Kubernetes cluster or a registry, runs no `kubectl` or `helm`, and edits nothing
# under agents/, guardian/, monitor/, scenarios/, runner/ or analysis/ -- so there is no v1.0
# behavior to log a hotfix ADR for (AGENTS.md iron rule 6).
#
# WHAT THIS SCANS, AND WHY
#   Every image this repository actually builds today: the evidence aggregator
#   (monitor/Dockerfile, MONITOR_IMAGE), the Guardian (guardian/deploy/Dockerfile,
#   GUARDIAN_IMAGE), and the SLO probe (infra/probes/deploy/Dockerfile). The probe is measurement
#   apparatus, not evaluated artefact -- that Dockerfile's own header draws the line -- but it is
#   still an image WE build and ship, so a supply-chain self-scan covers it too.
#
#   agents/ ships no container image. ADR-113 records why: the agent layer is a host-side graph
#   the runner drives for the duration of a run, not a standing cluster workload, so there is no
#   agents Dockerfile to build. When one exists, add a build_agents() function beside the three
#   below and one more scan_image call in "main" -- the shape is built to extend that way.
#
# WHY THIS SCRIPT BUILDS WITHOUT `kind load`
#   scripts/monitor_image.sh and scripts/guardian_image.sh both build AND
#   `kind load docker-image` into a running kind cluster, because that is what a campaign run
#   needs next. A CI self-scan runner has no cluster and must not need one to answer "does our
#   image have a CRITICAL CVE" -- the same argument ADR-017 makes against putting a 15-minute
#   cluster bring-up in a per-change check applies harder to a scan that only needs a local
#   Docker daemon. This script therefore re-issues each Dockerfile's `docker build` (same
#   Dockerfile, same infra/versions.env build args) and stops there; it never calls `kind`.
#
#   The Guardian build also needs OPA_LINUX_AMD64_SHA256, a checksum literal that lives only in
#   scripts/guardian_image.sh (it is a build-time argument for one Dockerfile, not one of
#   infra/versions.env's pins). It is duplicated below with a pointer back to that script, rather
#   than invented a fourth time, so the two do not drift unnoticed -- see this file's own
#   GUARDIAN_OPA_LINUX_AMD64_SHA256 line and ADR-115's Consequences for the follow-up this leaves
#   open (moving the literal to one shared home).
#
# SBOM + SCANNER: TRIVY, FOR BOTH, AT infra/versions.env's TRIVY_VERSION
#   `trivy image --format cyclonedx` emits the SBOM and `trivy image` (vulnerability mode) scans
#   it, so both halves of T8.4 share one binary already reasoned about elsewhere in this project
#   (ADR-007/ADR-018 pin the same tool as the Monitor's own CVE signal source, and
#   docs/ops/runbook.md's prerequisites table already states this self-scan runs Trivy at
#   TRIVY_VERSION). This script reads that same key rather than inventing a second, disagreeing
#   home for Trivy's version -- see ADR-115 for why a separate CI-tool literal (the ADR-011
#   shape ruff and pytest use) was considered and rejected once that runbook line existed.
#
# EXIT-CODE POLICY (the CI gate)
#   Every image gets a full vulnerability report at every severity (UNKNOWN..CRITICAL), written
#   in full regardless of any accepted-risk entry: the report is never suppressed. Separately, a
#   gate pass at SELF_SCAN_FAIL_SEVERITY (default CRITICAL) decides pass/fail for that one image,
#   and an optional ignore file (SELF_SCAN_TRIVYIGNORE, unset by default -- fail-closed, no
#   suppression) may drop specific, individually-accepted findings from THAT decision only.
#   docs/ops/sbom.md documents the ignore-file format (one entry per accepted CVE, each carrying
#   a reason, an owner and an `expires` date) and the review an accepted finding needs before it
#   is added. This script's own exit code is 0 only when every image's gate passed.
#
# STREAMS
#   stdout carries the per-image progress lines and the final summary (also written to
#   <output_dir>/summary.txt). stderr carries failures and the gate's own findings on a FAIL.
#
# PORTABILITY
#   Strict POSIX sh -- no bashisms, no GNU-only options. The parts that fetch a binary are
#   linux/amd64 only, matching scripts/install_cluster_tools.sh's own scope decision: WSL2
#   Ubuntu and ubuntu-latest are both linux/amd64, and an arm64 host is asked to supply its own
#   trivy via TRIVY_BIN rather than have this script guess at an asset name for it.
#
# WHAT THIS SCRIPT DOES NOT DO
#   It does not push an image anywhere, does not run `helm` or `kubectl`, and does not require a
#   kind cluster. It does not install Docker -- Docker is a host prerequisite exactly as
#   scripts/install_cluster_tools.sh already states for the cluster toolchain.

set -eu

LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

usage() {
    echo "usage: sh scripts/self_scan.sh"
    echo "  SELF_SCAN_OUTPUT_DIR=<dir>     SBOM/scan report output (default: self-scan-out)"
    echo "  SELF_SCAN_FAIL_SEVERITY=<sev>  comma list gating CI, e.g. CRITICAL or CRITICAL,HIGH"
    echo "                                 (default: CRITICAL)"
    echo "  SELF_SCAN_TRIVYIGNORE=<path>   residual-findings ignore file (default: unset, i.e."
    echo "                                 no suppression -- see docs/ops/sbom.md)"
    echo "  SELF_SCAN_FORCE_BUILD=1        rebuild every image even if already present locally"
    echo "  SLO_PROBE_IMAGE=<ref>          override the SLO probe image tag"
    echo "                                 (default: agentic-overwatch/slo-probe:local)"
    echo "  TRIVY_BIN=<path>               use this trivy binary (version still checked)"
    echo "  TRIVY_CACHE_HOME=<dir>         where a fetched trivy is cached"
    echo "  VERSIONS_FILE=<path>           default infra/versions.env"
}

case "${1:-}" in
    "") ;;
    -h|--help) usage; exit 0 ;;
    *)
        printf 'self-scan: unknown argument %s\n' "$1" >&2
        usage >&2
        exit 1
        ;;
esac

# --- pins: infra/versions.env is contractually values-only (its header rule 1: no logic, no ----
# command substitution, no shell expansion, no conditionals), which is what makes dot-sourcing it
# safe rather than an arbitrary-code hazard -- the same reasoning
# scripts/install_cluster_tools.sh and scripts/guardian_test.sh give for the identical line.
versions_file=${VERSIONS_FILE:-infra/versions.env}
if [ ! -f "$versions_file" ]; then
    echo "self-scan: $versions_file not found; run from a full checkout" >&2
    exit 1
fi
# shellcheck disable=SC1090
. "./$versions_file"

require_pin() {
    # $1 key name, $2 value
    if [ -z "${2:-}" ]; then
        echo "self-scan: $1 is empty in $versions_file." >&2
        echo "self-scan: an unpinned image is not reproducible, so this is a hard failure." >&2
        exit 1
    fi
}
require_pin MONITOR_IMAGE "${MONITOR_IMAGE:-}"
require_pin MONITOR_PYTHON_BASE_IMAGE "${MONITOR_PYTHON_BASE_IMAGE:-}"
require_pin PYDANTIC_VERSION "${PYDANTIC_VERSION:-}"
require_pin GUARDIAN_IMAGE "${GUARDIAN_IMAGE:-}"
require_pin GUARDIAN_PYTHON_BASE_IMAGE "${GUARDIAN_PYTHON_BASE_IMAGE:-}"
require_pin FASTAPI_VERSION "${FASTAPI_VERSION:-}"
require_pin PYJWT_VERSION "${PYJWT_VERSION:-}"
require_pin KUBERNETES_CLIENT_VERSION "${KUBERNETES_CLIENT_VERSION:-}"
require_pin UVICORN_VERSION "${UVICORN_VERSION:-}"
require_pin OPA_VERSION "${OPA_VERSION:-}"
require_pin TRIVY_VERSION "${TRIVY_VERSION:-}"

for tool in docker curl python3 tar; do
    command -v "$tool" >/dev/null 2>&1 || { echo "self-scan: $tool is not on PATH" >&2; exit 1; }
done

output_dir=${SELF_SCAN_OUTPUT_DIR:-self-scan-out}
fail_severity=${SELF_SCAN_FAIL_SEVERITY:-CRITICAL}
report_severities="UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
trivyignore=${SELF_SCAN_TRIVYIGNORE:-}
force_build=${SELF_SCAN_FORCE_BUILD:-0}
slo_probe_image=${SLO_PROBE_IMAGE:-agentic-overwatch/slo-probe:local}

if [ -n "$trivyignore" ] && [ ! -f "$trivyignore" ]; then
    printf 'self-scan: SELF_SCAN_TRIVYIGNORE=%s does not exist.\n' "$trivyignore" >&2
    echo "self-scan: a configured ignore file that is missing fails closed rather than scanning" >&2
    echo "with no suppressions applied silently, which would read as a choice nobody made." >&2
    exit 1
fi

mkdir -p "$output_dir"
work=$(mktemp -d) || exit 1
trap 'rm -rf "$work"' EXIT HUP INT TERM

sha256_of() {
    # One digest, lower-case hex, no filename. Two implementations, matching
    # scripts/guardian_test.sh's sha256_of: coreutils and the perl tool are what this project's
    # hosts actually offer.
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        return 1
    fi
}

# --- resolve trivy: TRIVY_BIN -> PATH (skip-if-pinned) -> cache -> fetch + verify --------------
RELEASE_BASE="https://github.com/aquasecurity/trivy/releases/download"
TRIVY_ASSET="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
TRIVY_CHECKSUMS="trivy_${TRIVY_VERSION}_checksums.txt"

trivy_version_of() {
    # `trivy --version` prints "Version: 0.69.3" on its first line.
    "$1" --version 2>/dev/null | awk '$1 == "Version:" { print $2; exit }'
}

trivy_bin=""
trivy_source=""

if [ -n "${TRIVY_BIN:-}" ]; then
    [ -x "$TRIVY_BIN" ] || { echo "self-scan: TRIVY_BIN=$TRIVY_BIN is not an executable file" >&2; exit 1; }
    found=$(trivy_version_of "$TRIVY_BIN" || true)
    [ "$found" = "$TRIVY_VERSION" ] || {
        printf 'self-scan: TRIVY_BIN=%s reports version %s, but %s pins TRIVY_VERSION=%s\n' \
            "$TRIVY_BIN" "${found:-unknown}" "$versions_file" "$TRIVY_VERSION" >&2
        exit 1
    }
    trivy_bin=$TRIVY_BIN
    trivy_source="TRIVY_BIN (version checked, bytes not)"
elif command -v trivy >/dev/null 2>&1 && [ "$(trivy_version_of trivy || true)" = "$TRIVY_VERSION" ]; then
    # A developer with the pinned version already installed pays nothing, same as ADR-025's
    # skip-if-present branch for OPA.
    trivy_bin=trivy
    trivy_source="PATH (version checked, bytes not)"
else
    host_platform="$(uname -s)/$(uname -m)"
    case "$host_platform" in
        Linux/x86_64|Linux/amd64) ;;
        *)
            printf 'self-scan: no trivy %s on PATH, and this script fetches linux/amd64 assets only (host reports %s).\n' \
                "$TRIVY_VERSION" "$host_platform" >&2
            echo "self-scan: install Trivy $TRIVY_VERSION by hand and re-run with TRIVY_BIN=<path>." >&2
            exit 1
            ;;
    esac

    cache_dir=${TRIVY_CACHE_HOME:-"${XDG_CACHE_HOME:-$HOME/.cache}/agentic-overwatch/trivy"}/$TRIVY_VERSION
    cached_bin="$cache_dir/trivy"

    if [ ! -x "$cached_bin" ]; then
        mkdir -p "$cache_dir"
        printf 'self-scan: fetching trivy %s (%s)\n' "$TRIVY_VERSION" "$host_platform" >&2
        curl -sSfL --retry 3 --retry-delay 2 -o "$work/$TRIVY_ASSET" \
            "$RELEASE_BASE/v$TRIVY_VERSION/$TRIVY_ASSET"
        curl -sSfL --retry 3 --retry-delay 2 -o "$work/$TRIVY_CHECKSUMS" \
            "$RELEASE_BASE/v$TRIVY_VERSION/$TRIVY_CHECKSUMS"

        # VERIFICATION STRENGTH, STATED RATHER THAN ASSUMED. This checks the tarball against
        # Trivy's own published checksums manifest, fetched over TLS from the same release --
        # real protection against transport corruption and a renamed/substituted asset, but not
        # the stronger guarantee scripts/guardian_test.sh gives OPA, where the expected digest is
        # a literal a reviewer read from the release's .sha256 sidecar and committed to the
        # repository independently of the fetch it verifies (ADR-025). No reviewer has done that
        # for Trivy here yet; ADR-115's Consequences names tightening this to a committed literal
        # as follow-up, not silently assumed done.
        expected=$(awk -v f="$TRIVY_ASSET" '$2 == f { print $1 }' "$work/$TRIVY_CHECKSUMS")
        if [ -z "$expected" ]; then
            printf 'self-scan: %s not listed in %s\n' "$TRIVY_ASSET" "$TRIVY_CHECKSUMS" >&2
            exit 1
        fi
        actual=$(sha256_of "$work/$TRIVY_ASSET") || {
            echo "self-scan: no sha256 tool available to verify the fetched trivy binary" >&2
            exit 1
        }
        if [ "$actual" != "$expected" ]; then
            printf 'self-scan: checksum mismatch for %s\n  expected %s\n  actual   %s\n' \
                "$TRIVY_ASSET" "$expected" "$actual" >&2
            exit 1
        fi

        tar -xzf "$work/$TRIVY_ASSET" -C "$work" trivy
        install -m 0755 "$work/trivy" "$cached_bin"
        trivy_source="fetched and verified against the release's own checksums manifest"
    else
        trivy_source="cache (version checked at acquisition time)"
    fi
    trivy_bin=$cached_bin
fi

trivy_reported=$(trivy_version_of "$trivy_bin" || true)
[ -n "$trivy_reported" ] || { echo "self-scan: $trivy_bin does not report a usable trivy version" >&2; exit 1; }
printf 'self-scan: using trivy %s (%s)\n' "$trivy_reported" "$trivy_source"

# --- image build functions, mirroring each Dockerfile's own build script minus `kind load` -----

# guardian/deploy/Dockerfile's OPA download build-arg. Duplicated from
# scripts/guardian_image.sh:26 rather than a fourth home in infra/versions.env, because this is a
# build-time checksum for one Dockerfile, not one of that file's version pins. If
# scripts/guardian_image.sh's value ever changes, this one must move with it (ADR-115).
GUARDIAN_OPA_LINUX_AMD64_SHA256=c9f985ce0d345f5484006ade2c695ed9e3f308e4441139e46695c5c182ac0839

build_monitor() {
    printf 'self-scan: building %s from monitor/Dockerfile\n' "$MONITOR_IMAGE" >&2
    docker build --pull=false -f monitor/Dockerfile -t "$MONITOR_IMAGE" \
        --build-arg "PYTHON_BASE_IMAGE=$MONITOR_PYTHON_BASE_IMAGE" \
        --build-arg "PYDANTIC_VERSION=$PYDANTIC_VERSION" \
        .
}

build_guardian() {
    printf 'self-scan: building %s from guardian/deploy/Dockerfile\n' "$GUARDIAN_IMAGE" >&2
    docker build --pull=false -f guardian/deploy/Dockerfile -t "$GUARDIAN_IMAGE" \
        --build-arg "PYTHON_BASE_IMAGE=$GUARDIAN_PYTHON_BASE_IMAGE" \
        --build-arg "FASTAPI_VERSION=$FASTAPI_VERSION" \
        --build-arg "PYJWT_VERSION=$PYJWT_VERSION" \
        --build-arg "PYDANTIC_VERSION=$PYDANTIC_VERSION" \
        --build-arg "KUBERNETES_CLIENT_VERSION=$KUBERNETES_CLIENT_VERSION" \
        --build-arg "UVICORN_VERSION=$UVICORN_VERSION" \
        --build-arg "OPA_VERSION=$OPA_VERSION" \
        --build-arg "OPA_LINUX_AMD64_SHA256=$GUARDIAN_OPA_LINUX_AMD64_SHA256" \
        .
}

build_slo_probe() {
    printf 'self-scan: building %s from infra/probes/deploy/Dockerfile\n' "$slo_probe_image" >&2
    docker build --pull=false -f infra/probes/deploy/Dockerfile -t "$slo_probe_image" .
}

# --- scan one image: locate-or-build, SBOM, full report, gate ----------------------------------
results=""
overall_rc=0

scan_image() {
    # $1 short name (used in filenames), $2 image ref, $3 build function name
    img_name=$1
    img_ref=$2
    build_fn=$3

    printf '\nself-scan: === %s (%s) ===\n' "$img_name" "$img_ref"

    if [ "$force_build" = "1" ] || ! docker image inspect "$img_ref" >/dev/null 2>&1; then
        "$build_fn"
    else
        printf 'self-scan: %s already present locally; not rebuilding (SELF_SCAN_FORCE_BUILD=1 to force)\n' \
            "$img_ref"
    fi

    sbom_file="$output_dir/$img_name.cyclonedx.json"
    full_report="$output_dir/$img_name.trivy-full.json"
    gate_report="$output_dir/$img_name.trivy-gate.txt"

    printf 'self-scan: SBOM (CycloneDX) -> %s\n' "$sbom_file"
    "$trivy_bin" image --format cyclonedx --output "$sbom_file" "$img_ref"

    printf 'self-scan: full vulnerability report (%s, never suppressed) -> %s\n' \
        "$report_severities" "$full_report"
    "$trivy_bin" image --scanners vuln --format json --severity "$report_severities" \
        --exit-code 0 --output "$full_report" "$img_ref"

    printf 'self-scan: gate at %s%s\n' "$fail_severity" "${trivyignore:+ (ignore file: $trivyignore)}"
    gate_rc=0
    if [ -n "$trivyignore" ]; then
        "$trivy_bin" image --scanners vuln --severity "$fail_severity" --exit-code 1 \
            --ignorefile "$trivyignore" --format table "$img_ref" > "$gate_report" 2>&1 || gate_rc=$?
    else
        "$trivy_bin" image --scanners vuln --severity "$fail_severity" --exit-code 1 \
            --format table "$img_ref" > "$gate_report" 2>&1 || gate_rc=$?
    fi

    # A per-severity count from the FULL (unsuppressed) report, so the summary line is honest
    # about what exists even on a gate that passed because of an ignore-file entry.
    counts=$(python3 - "$full_report" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        data = json.load(handle)
except Exception as exc:  # noqa: BLE001 -- a summary line must never abort the scan
    print(f"unparseable ({exc})")
    raise SystemExit(0)

counts = {}
for result in data.get("Results") or []:
    for vuln in result.get("Vulnerabilities") or []:
        severity = vuln.get("Severity", "UNKNOWN")
        counts[severity] = counts.get(severity, 0) + 1

order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
print(" ".join(f"{sev}={counts.get(sev, 0)}" for sev in order))
PY
)

    if [ "$gate_rc" -eq 0 ]; then
        printf 'self-scan: %-10s PASS  [%s]\n' "$img_name" "$counts"
        results="$results $img_name:PASS"
    else
        printf 'self-scan: %-10s FAIL  [%s] (trivy exit %s)\n' "$img_name" "$counts" "$gate_rc" >&2
        sed 's/^/  /' "$gate_report" >&2
        results="$results $img_name:FAIL"
        overall_rc=1
    fi
}

# --- main: every image this repository builds today ---------------------------------------------
scan_image monitor "$MONITOR_IMAGE" build_monitor
scan_image guardian "$GUARDIAN_IMAGE" build_guardian
scan_image slo-probe "$slo_probe_image" build_slo_probe

image_count=$(printf '%s\n' "$results" | wc -w | tr -d ' ')

{
    printf 'self-scan summary -- %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'trivy %s via %s\n' "$trivy_reported" "$trivy_source"
    printf 'fail-severity gate: %s%s\n' "$fail_severity" "${trivyignore:+ (ignore file: $trivyignore)}"
    for pair in $results; do printf '  %s\n' "$pair"; done
} > "$output_dir/summary.txt"
cat "$output_dir/summary.txt"

if [ "$overall_rc" -ne 0 ]; then
    printf 'self-scan: FAIL — one or more images have an unignored finding at or above %s. Reports in %s\n' \
        "$fail_severity" "$output_dir" >&2
else
    printf 'self-scan: PASS — SBOM + scan reports for %s image(s) written to %s\n' \
        "$image_count" "$output_dir"
fi
exit "$overall_rc"
