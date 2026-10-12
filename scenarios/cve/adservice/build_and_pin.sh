#!/bin/sh
# scenarios/cve/adservice/build_and_pin.sh -- build the CVE arm's vulnerable adservice image (and,
# optionally, a reference-patched rebuild) from adservice's own pinned upstream source, and print --
# never run -- the steps that turn a local build into a pinned scenarios/cve/images.yaml entry.
#
# WHAT THIS SCRIPT IS, AND WHY IT EXISTS
#   ADR-091 supersedes ADR-079's sidecar design with "a vulnerable build of the SAME service": the
#   scenario admits adservice's own real, serving container, rebuilt with log4j-core forced to the
#   Log4Shell-unpatched 2.14.1, rather than a decoration beside it that never ran. That build does
#   not exist anywhere until an operator produces it -- it is not a tag any registry already serves,
#   unlike ADR-079's Solr entries, which at least named a real (if unpinned) upstream repository. This
#   script is that build recipe, and it fetches adservice's OWN Dockerfile and build.gradle from the
#   upstream ref this project already pins (infra/versions.env's BOUTIQUE_MANIFEST_REF) rather than
#   forking a parallel copy of either into this repository -- the same reason
#   infra/boutique/kustomization.yaml consumes the upstream base by reference instead of vendoring it:
#   every fix upstream ships to adservice's Dockerfile or dependency set is inherited by this recipe
#   automatically, and the artefact under test stays auditable against a public commit rather than
#   against a private fork only this repository maintains.
#
# WHY THE PATCH IS ONE SED, TOUCHING ONE VERSION LITERAL
#   `src/adservice/build.gradle` at the pinned ref declares
#   `"org.apache.logging.log4j:log4j-core:2.26.1"` as a direct compile dependency (read from the tree
#   at https://github.com/GoogleCloudPlatform/microservices-demo/blob/v0.10.6/src/adservice/build.gradle
#   on 2026-09-13). `--vulnerable` rewrites only that version literal to
#   `$VULNERABLE_LOG4J_VERSION` (2.14.1 by default, the version CVE-2021-44228 is unpatched in) and
#   verifies the rewrite took before building, so the vulnerability is a property of one dependency
#   coordinate and nothing else about the service changes: same gRPC contract, same port 9555, same
#   grpc-native readiness and liveness probes (unmodified from the upstream Deployment; this script
#   never touches Kubernetes manifests), same entrypoint. `--patched` builds the SAME fetched source
#   with NO patch applied at all -- see WHY --patched EXISTS below for what it is and is not for.
#
# WHY --patched EXISTS, AND WHY IT IS NOT THE RECOMMENDED SOURCE OF THE "PATCHED" PIN
#   scenarios/cve/images.yaml's `patched_repository` / `patched_digest` are, by default, a CHECKED
#   MIRROR of infra/boutique/images.yaml's own adservice pin -- the exact image this cluster already
#   runs -- not a fresh build from this script. That is the recommended path: eradication rolls the
#   Deployment back onto the artefact every other Boutique run in this project already deploys, not
#   onto a second, separately-built "known good" image that could drift from it in ways unrelated to
#   log4j-core (a different JDK point release, a different Alpine base layer, a different build date).
#   `--patched` is offered anyway, for the operator who wants build-parity verification: it runs the
#   IDENTICAL fetch-and-build path as `--vulnerable`, with the sed skipped, so a reviewer can diff its
#   output against the fleet's own image if they want independent evidence the two differ only in the
#   dependency this recipe patches. It resolves whatever log4j-core version the pinned ref's own
#   build.gradle names at build time (2.26.1 as read above) rather than a version this script assumes
#   or invents -- Gradle is the authority on what its own dependency graph resolves, not this script.
#
# WHY THIS SCRIPT NEVER TOUCHES A REGISTRY
#   `scripts/cve_mirror.sh --save` and `--load` print `docker pull` / `docker save` / `kind load`
#   commands to stderr and never run one, for two reasons its own header states: landing a
#   known-vulnerable image on a host is a decision that belongs to the operator, taken from a command
#   they read first; and a script that must reach a registry to run cannot be exercised on a machine
#   with no network, which is what CI and a reviewer's laptop may be. Both apply here with equal
#   force, plus a third: THIS image has no registry to pull from at all until the operator chooses one
#   and pushes to it, so "push" and "resolve the digest" are inescapably manual, operator-owned steps.
#   This script builds and tags the image locally -- building is unavoidably this script's job, since
#   nothing else in the repository can produce these bytes -- then prints the push and digest-resolve
#   commands to stderr and stops. It never runs `docker push`, `docker login` or any command that
#   reaches a registry.
#
# WHAT TO DO WITH THE OUTPUT
#   1. Run `sh scenarios/cve/adservice/build_and_pin.sh --vulnerable`. Read the printed next steps.
#   2. Push the built image to a registry you control (Docker Hub under your own namespace, GHCR, a
#      private registry -- this project has no registry of its own to push to, and none should be
#      invented here). Resolve the pushed manifest's digest.
#   3. Paste the resolved repository and digest into BOTH scenarios/cve/images.yaml entries'
#      `repository` / `digest` fields (CVE-SCN-04-adservice and CVE-SCN-05-adservice: they pin the
#      SAME image, by researcher/supervisor decision 2026-09-13 -- see that file's header).
#   4. Follow scenarios/cve/README.md's existing mirror procedure verbatim from here:
#      `sh scripts/cve_mirror.sh --save` prints the `docker pull`/`docker save` commands for the now-
#      pinned digest; `sha256sum` the resulting tarball into `tarball_sha256`; `sh
#      scripts/cve_mirror.sh --load` prints the `kind load image-archive` command; `sh
#      scripts/cve_mirror.sh --verify` confirms the mirror. This script's own job ends at step 3 --
#      it does not re-implement cve_mirror.sh's save/load/verify, which already exist and are generic
#      over whatever this entry's fields say.
#
# ENVIRONMENT
#   VERSIONS_FILE                default infra/versions.env; where BOUTIQUE_MANIFEST_REF is read from,
#                                 so this script tracks a re-pin of the upstream ref automatically
#                                 rather than carrying a second copy of that value.
#   ADSERVICE_UPSTREAM_URL        default the public microservices-demo repository; override for a
#                                 mirror or a fork.
#   VULNERABLE_LOG4J_VERSION      default 2.14.1 (CVE-2021-44228's unpatched version). Overridable so
#                                 a later Log4Shell-family CVE with a different vulnerable floor does
#                                 not require an edit here.
#   ADSERVICE_IMAGE_TAG           default agentic-overwatch/adservice-log4shell:v0.10.6-log4j-2.14.1;
#                                 the local tag `--vulnerable` builds.
#   ADSERVICE_PATCHED_IMAGE_TAG   default agentic-overwatch/adservice-log4shell:v0.10.6-patched-reference;
#                                 the local tag `--patched` builds.
#   ADSERVICE_BUILD_WORKDIR       default a fresh mktemp -d; where the upstream source is cloned.
#
# PORTABILITY
#   POSIX sh, no GNU-only sed flags (no `-i`; the patch is written to a new file and moved into place,
#   which works identically under BSD and GNU sed). Needs git, docker and network -- Tier B tools this
#   script does not attempt to substitute for, on the same principle scripts/cve_mirror.sh states for
#   itself: a check or a build that silently degrades when a tool is missing is worse than one that
#   says which tool is missing and stops.

set -eu
LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
cd "$repo_root"

VERSIONS_FILE=${VERSIONS_FILE:-infra/versions.env}
UPSTREAM_URL=${ADSERVICE_UPSTREAM_URL:-https://github.com/GoogleCloudPlatform/microservices-demo.git}
VULNERABLE_LOG4J_VERSION=${VULNERABLE_LOG4J_VERSION:-2.14.1}
IMAGE_TAG=${ADSERVICE_IMAGE_TAG:-agentic-overwatch/adservice-log4shell:v0.10.6-log4j-2.14.1}
PATCHED_IMAGE_TAG=${ADSERVICE_PATCHED_IMAGE_TAG:-agentic-overwatch/adservice-log4shell:v0.10.6-patched-reference}

usage() {
    echo "usage: sh scenarios/cve/adservice/build_and_pin.sh --vulnerable | --patched" >&2
    echo "  --vulnerable  build adservice's pinned source with log4j-core forced to" >&2
    echo "                \$VULNERABLE_LOG4J_VERSION (default 2.14.1). This is the image both" >&2
    echo "                scenarios/cve/images.yaml entries pin." >&2
    echo "  --patched     build adservice's pinned source UNPATCHED, for build-parity" >&2
    echo "                verification only. images.yaml's recommended patched pin is a mirror" >&2
    echo "                of infra/boutique/images.yaml's own adservice pin, not this output --" >&2
    echo "                see this script's header, WHY --patched EXISTS." >&2
    echo "  never pushes and never resolves a digest; see WHAT TO DO WITH THE OUTPUT" >&2
}

if [ ! -f "$VERSIONS_FILE" ]; then
    printf 'build_and_pin: FAIL -- %s not found\n' "$VERSIONS_FILE" >&2
    exit 1
fi

for tool in git docker sed awk; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'build_and_pin: FAIL -- %s is not on PATH\n' "$tool" >&2
        exit 1
    }
done

mode=""
case "${1:-}" in
    --vulnerable|--patched) mode=$1 ;;
    -h|--help) usage; exit 0 ;;
    "") usage; printf 'build_and_pin: FAIL -- no mode given\n' >&2; exit 1 ;;
    *)  printf 'build_and_pin: FAIL -- unknown argument %s\n' "$1" >&2; usage; exit 1 ;;
esac

ref=$(awk -F= '$1 == "BOUTIQUE_MANIFEST_REF" { sub(/\r$/, "", $2); print $2; exit }' "$VERSIONS_FILE")
if [ -z "$ref" ]; then
    printf 'build_and_pin: FAIL -- BOUTIQUE_MANIFEST_REF is empty in %s\n' "$VERSIONS_FILE" >&2
    exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

printf 'build_and_pin: cloning %s at %s into %s\n' "$UPSTREAM_URL" "$ref" "$work" >&2
git clone --quiet --depth 1 --branch "$ref" "$UPSTREAM_URL" "$work/microservices-demo" >&2

src="$work/microservices-demo/src/adservice"
if [ ! -d "$src" ]; then
    printf 'build_and_pin: FAIL -- no src/adservice under the fetched tree at ref %s\n' "$ref" >&2
    exit 1
fi
if [ ! -f "$src/Dockerfile" ] || [ ! -f "$src/build.gradle" ]; then
    printf 'build_and_pin: FAIL -- src/adservice is missing its Dockerfile or build.gradle at %s\n' \
        "$ref" >&2
    exit 1
fi

if [ "$mode" = "--vulnerable" ]; then
    printf 'build_and_pin: patching build.gradle: log4j-core -> %s\n' "$VULNERABLE_LOG4J_VERSION" >&2
    sed -E "s/(org\.apache\.logging\.log4j:log4j-core:)[0-9][0-9.]*/\\1${VULNERABLE_LOG4J_VERSION}/" \
        "$src/build.gradle" > "$src/build.gradle.patched"
    mv "$src/build.gradle.patched" "$src/build.gradle"
    if ! grep -q "log4j-core:${VULNERABLE_LOG4J_VERSION}" "$src/build.gradle"; then
        printf 'build_and_pin: FAIL -- the log4j-core patch did not take.\n' >&2
        printf '  src/adservice/build.gradle may have moved the dependency line upstream;\n' >&2
        printf '  inspect it by hand rather than trusting an unverified build.\n' >&2
        exit 1
    fi
    tag=$IMAGE_TAG
else
    printf 'build_and_pin: building the UNPATCHED pinned source (build-parity reference only)\n' >&2
    printf '  the RECOMMENDED "patched" pin is the fleet'"'"'s own image in\n' >&2
    printf '  infra/boutique/images.yaml, not this output -- see this script'"'"'s header.\n' >&2
    tag=$PATCHED_IMAGE_TAG
fi

printf 'build_and_pin: docker build -t %s %s\n' "$tag" "$src" >&2
docker build -t "$tag" "$src"

{
    echo
    printf 'build_and_pin: PASS -- built %s locally (mode %s)\n' "$tag" "$mode"
    echo
    echo "This script never pushes and never resolves a digest. Next steps, run by you:"
    echo "  1. docker tag $tag <your-registry>/<your-namespace>/adservice-log4shell:<tag>"
    echo "  2. docker push <your-registry>/<your-namespace>/adservice-log4shell:<tag>"
    echo "  3. docker buildx imagetools inspect <your-registry>/<your-namespace>/adservice-log4shell:<tag>"
    echo "     (or a registry HEAD request per infra/boutique/images.yaml's own re-pinning note)"
    echo "     and read the Docker-Content-Digest / manifest digest it reports."
    if [ "$mode" = "--vulnerable" ]; then
        echo "  4. Paste that repository + digest into scenarios/cve/images.yaml's repository/digest"
        echo "     fields on BOTH CVE-SCN-04-adservice and CVE-SCN-05-adservice -- they pin one image."
    else
        echo "  4. This build is for comparison only; images.yaml's patched pin does not change."
    fi
    echo "  5. Continue with scenarios/cve/README.md's existing mirror procedure verbatim:"
    echo "     sh scripts/cve_mirror.sh --save / sha256sum the tarball / --load / --verify."
} >&2

exit 0
