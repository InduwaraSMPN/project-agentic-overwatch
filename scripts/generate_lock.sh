#!/bin/sh
# generate_lock.sh -- compile the hashed, universal runtime lock from infra/versions.env pins.
#
# WHAT THIS IS
# The single command that turns the runtime pins infra/versions.env owns into requirements.lock: a
# fully resolved, hash-pinned, platform-independent lock (ADR-135, superseding ADR-021's rejection of
# uv and pip-tools). guardian/deploy/Dockerfile, monitor/Dockerfile and scripts/install_runtime_deps.sh
# all install FROM this lock with --require-hashes, so the evaluated artefact's whole transitive
# dependency closure -- not just the dozen packages this repository names -- is pinned by digest and
# recorded in the environment freeze every sealed bundle carries (V23).
#
# versions.env STAYS THE OWNER
# This script never invents a version. It reads each runtime pin out of infra/versions.env (the
# single pinning surface, docs/03-tech-stack.md section 5) and asks uv to resolve the transitive
# closure around those exact pins. infra/tests/test_lock_matches_versions_env.py then asserts every
# pinned runtime dependency appears in the lock at its versions.env version, so the lock cannot drift
# from the owner without a red test. The package list below mirrors scripts/install_runtime_deps.sh's
# pinned set, key for key -- keep the two in step; the test is what makes "in step" mechanical.
#
# REPRODUCIBILITY, AND WHY THE lock-drift CHECK IS STABLE
# The lock is written with --no-annotate (so no per-package "# via <path>" line embeds this run's
# temporary input path) and a fixed UV_CUSTOM_COMPILE_COMMAND header, so two machines that resolve
# the same index state on the same day produce byte-identical files. uv, like pip-tools, reads an
# existing requirements.lock as resolution PREFERENCES, so re-running this script keeps the already
# pinned transitive versions unless a versions.env pin changed -- which is what lets ci.yml's hygiene
# job run `sh scripts/generate_lock.sh` then `git diff --exit-code requirements.lock` and have the
# diff be empty except when the lock genuinely needs regenerating.
#
# --universal, AND WHY
# Hashes are platform-specific unless the resolution is universal; --universal for Python 3.12 gives
# one lock that installs on the WSL2 host, the CI runner and both container images (Appendix A, uv).
#
# STREAMS AND EXIT CODES
# One summary line on stdout; diagnostics on stderr. Exit 0 when requirements.lock was written, 1 on a
# missing pin, a missing uv, or a resolution failure. If uv cannot reach an index (an offline host),
# it fails here rather than writing a partial lock -- the lock is only meaningful when every hash
# resolved.
#
# PORTABILITY
# Strict POSIX sh -- no bashisms, no GNU-only options. Runs under dash in WSL2 Ubuntu, under Git Bash
# on the Windows host, and on ubuntu-latest.
#
# WHAT BREAKS IF THIS FILE CHANGES
# requirements.lock's reproducibility, the two Dockerfiles and scripts/install_runtime_deps.sh that
# install from it, and ci.yml's lock-drift step. ADR-135.

set -eu

LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

versions_file="infra/versions.env"
lock_file="requirements.lock"

if ! command -v uv >/dev/null 2>&1; then
    echo "generate-lock: uv is not on PATH. It is the resolver ADR-135 pins for this lock; install it" >&2
    echo "generate-lock: (https://docs.astral.sh/uv/) and re-run, or set PATH to reach it." >&2
    exit 1
fi

if [ ! -f "$versions_file" ]; then
    echo "generate-lock: $versions_file not found; run from a full checkout" >&2
    exit 1
fi

# Read one pin, failing closed on an empty or absent value -- an unpinned runtime dependency is the
# defect this lock exists to remove, so it must never resolve to whatever the index serves today.
# grep+cut, not dot-sourcing, and \r stripped, exactly as scripts/install_runtime_deps.sh reads it.
read_pin() {
    read_pin_value=$(grep -E "^$1=" "$versions_file" | head -n 1 | cut -d= -f2- | tr -d '\r')
    if [ -z "$read_pin_value" ]; then
        echo "generate-lock: $1 is empty or absent in $versions_file; populate it before locking" >&2
        exit 1
    fi
}

# The Python minor the lock is resolved for. Single-homed in versions.env (PYTHON_VERSION=3.12); the
# lock is universal, but the resolver still needs the interpreter version to pick markers.
read_pin PYTHON_VERSION
python_version=$read_pin_value

# The requirements input, DERIVED from versions.env -- never a committed second pinning surface. Each
# line mirrors one scripts/install_runtime_deps.sh entry; OTEL_PYTHON_SDK_VERSION covers two
# distributions, exactly as it does there. Written to a temporary file that is removed on exit, so the
# only durable artefact is the lock.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
req_in="$work/requirements.in"

{
    read_pin PYDANTIC_VERSION;               printf 'pydantic==%s\n' "$read_pin_value"
    read_pin FASTAPI_VERSION;                printf 'fastapi==%s\n' "$read_pin_value"
    read_pin PYJWT_VERSION;                  printf 'PyJWT==%s\n' "$read_pin_value"
    read_pin KUBERNETES_CLIENT_VERSION;      printf 'kubernetes==%s\n' "$read_pin_value"
    read_pin UVICORN_VERSION;                printf 'uvicorn==%s\n' "$read_pin_value"
    read_pin CRYPTOGRAPHY_VERSION;           printf 'cryptography==%s\n' "$read_pin_value"
    read_pin LANGGRAPH_VERSION;              printf 'langgraph==%s\n' "$read_pin_value"
    read_pin LITELLM_VERSION;                printf 'litellm==%s\n' "$read_pin_value"
    read_pin OTEL_PYTHON_SDK_VERSION;        printf 'opentelemetry-sdk==%s\n' "$read_pin_value"
    read_pin OTEL_PYTHON_SDK_VERSION;        printf 'opentelemetry-exporter-otlp-proto-http==%s\n' "$read_pin_value"
    read_pin PANDAS_VERSION;                 printf 'pandas==%s\n' "$read_pin_value"
    read_pin STATSMODELS_VERSION;            printf 'statsmodels==%s\n' "$read_pin_value"
    read_pin MATPLOTLIB_VERSION;             printf 'matplotlib==%s\n' "$read_pin_value"
} > "$req_in"

# A stable header instead of the temp input path, so the lock is reproducible and says how to
# regenerate it. --no-annotate drops the per-package "# via <path>" lines that would otherwise embed
# this run's temp directory. -o requirements.lock is also read by uv as resolution preferences when it
# already exists, keeping transitive pins stable across regenerations (see the header).
UV_CUSTOM_COMPILE_COMMAND="sh scripts/generate_lock.sh"
export UV_CUSTOM_COMPILE_COMMAND

if ! uv pip compile \
        --universal \
        --python-version "$python_version" \
        --generate-hashes \
        --no-annotate \
        "$req_in" \
        -o "$lock_file" >&2; then
    echo "generate-lock: FAIL — uv could not resolve the runtime closure. If this host is offline," >&2
    echo "generate-lock: run it where an index is reachable; the lock is only valid when every hash" >&2
    echo "generate-lock: resolved. requirements.lock left unchanged." >&2
    exit 1
fi

package_count=$(grep -cE '^[A-Za-z0-9].*==' "$lock_file" || true)
printf 'generate-lock: PASS — wrote %s (%s pinned packages, hashed, universal, Python %s) from %s\n' \
    "$lock_file" "$package_count" "$python_version" "$versions_file"
