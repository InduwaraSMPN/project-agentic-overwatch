r"""requirements.lock is consistent with infra/versions.env: every runtime pin, at its version.

WHAT THIS GUARDS (ADR-135, V23)
    infra/versions.env is the single owner of every runtime dependency's version
    (docs/03-tech-stack.md section 5); requirements.lock is the hashed, universal, fully-resolved
    lock that guardian/deploy/Dockerfile, monitor/Dockerfile and scripts/install_runtime_deps.sh
    install from with --require-hashes. The lock is GENERATED from versions.env by
    scripts/generate_lock.sh, so the two can only diverge if the lock was regenerated from a
    different
    versions.env or hand-edited. This test makes that divergence a red check: every runtime
    dependency
    versions.env pins must appear in the lock at exactly that version. It is the ADR-016 mirror
    pattern
    applied to the lock -- the owner is versions.env, the lock is the checked copy.

WHY A SEPARATE HOME FOR THE PACKAGE MAP, AND WHY THAT IS ALLOWED
    The versions.env-key -> pip-name map below mirrors the one in scripts/generate_lock.sh and
    scripts/install_runtime_deps.sh. Three homes for a map is normally the duplication
    .agents/rules/00 warns against -- but the rule permits a copy where a test makes the copy unable
    to drift, and this IS that test: generate_lock.sh's output and versions.env are checked against
    each other HERE, so a key added to versions.env (and to generate_lock.sh) but not the lock, or
    vice versa, fails. OTEL_PYTHON_SDK_VERSION maps to two distributions, as it does in both
    scripts.

INFRA/TESTS CONTRACT (infra/tests/__init__.py)
    Standard library and pytest only -- no PyYAML, no third-party parser -- because CI's infra step
    installs nothing but pytest. versions.env is a values-only key=value file and requirements.lock
    is
    a pip requirements file; both are read with str operations here, no dependency required.
"""

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

VERSIONS_ENV = ROOT / "infra" / "versions.env"
LOCK = ROOT / "requirements.lock"

# versions.env key -> the canonical pip distribution name(s) it pins. Mirrors
# scripts/generate_lock.sh
# and scripts/install_runtime_deps.sh, key for key. Names are stored already canonicalised (PEP 503:
# lower-case, runs of -_. collapsed to a single -), which is how uv writes them into the lock, so
# the
# comparison never turns on "PyJWT" vs "pyjwt".
RUNTIME_PINS: dict[str, tuple[str, ...]] = {
    "PYDANTIC_VERSION": ("pydantic",),
    "FASTAPI_VERSION": ("fastapi",),
    "PYJWT_VERSION": ("pyjwt",),
    "KUBERNETES_CLIENT_VERSION": ("kubernetes",),
    "UVICORN_VERSION": ("uvicorn",),
    "CRYPTOGRAPHY_VERSION": ("cryptography",),
    "LANGGRAPH_VERSION": ("langgraph",),
    "LITELLM_VERSION": ("litellm",),
    "OTEL_PYTHON_SDK_VERSION": (
        "opentelemetry-sdk",
        "opentelemetry-exporter-otlp-proto-http",
    ),
    "PANDAS_VERSION": ("pandas",),
    "STATSMODELS_VERSION": ("statsmodels",),
    "MATPLOTLIB_VERSION": ("matplotlib",),
}


def _canonical(name: str) -> str:
    """PEP 503 canonical name: lower-case, runs of -_. collapsed to a single -."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _read_versions_env() -> dict[str, str]:
    """The key=value pairs of versions.env, with \\r stripped (the CRLF gotcha its header notes)."""
    pins: dict[str, str] = {}
    for raw in VERSIONS_ENV.read_text(encoding="utf-8").splitlines():
        line = raw.strip().lstrip("﻿")
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        pins[key.strip()] = value.strip().replace("\r", "")
    return pins


def _read_lock() -> dict[str, str]:
    """Canonical distribution name -> pinned version, from requirements.lock.

    A pin line looks like ``pydantic==2.13.4 \\`` -- name at column 0, ``==`` version, then a
    trailing
    backslash before the hash block. Hash lines are indented and start with ``--hash``, so anchoring
    the pattern to the line start excludes them.
    """
    if not LOCK.is_file():
        pytest.fail(
            f"{LOCK} does not exist. It is generated from infra/versions.env by "
            "`sh scripts/generate_lock.sh` (ADR-135); generate it and commit it."
        )
    pins: dict[str, str] = {}
    pattern = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\;]+)")
    for raw in LOCK.read_text(encoding="utf-8").splitlines():
        match = pattern.match(raw)
        if match:
            pins[_canonical(match.group(1))] = match.group(2)
    return pins


def test_every_runtime_pin_is_in_the_lock_at_its_version() -> None:
    """Each versions.env runtime dependency appears in requirements.lock at exactly that version."""
    env = _read_versions_env()
    lock = _read_lock()
    mismatches: list[str] = []
    for key, dists in RUNTIME_PINS.items():
        version = env.get(key)
        if not version:
            mismatches.append(f"{key}: absent or empty in versions.env")
            continue
        for dist in dists:
            locked = lock.get(dist)
            if locked is None:
                mismatches.append(f"{dist} ({key}={version}) is not pinned in requirements.lock")
            elif locked != version:
                mismatches.append(
                    f"{dist} is {locked} in the lock but {version} in versions.env ({key})"
                )
    assert mismatches == [], (
        "requirements.lock is out of step with infra/versions.env; regenerate it with "
        "`sh scripts/generate_lock.sh`:\n  " + "\n  ".join(mismatches)
    )


def test_the_lock_is_hashed_so_require_hashes_installs_work() -> None:
    """The lock carries --hash lines; the Dockerfiles and installer use --require-hashes."""
    text = LOCK.read_text(encoding="utf-8") if LOCK.is_file() else ""
    assert "--hash=sha256:" in text, (
        "requirements.lock carries no sha256 hashes; --require-hashes installs (guardian/monitor "
        "Dockerfiles, scripts/install_runtime_deps.sh) need them. Regenerate with "
        "`sh scripts/generate_lock.sh`, whose --generate-hashes produces them."
    )


def test_the_pin_map_is_not_vacuous() -> None:
    """The runtime-pin map names real versions.env keys, so the coverage test checks something."""
    env = _read_versions_env()
    unknown = [key for key in RUNTIME_PINS if key not in env]
    assert unknown == [], (
        f"these RUNTIME_PINS keys are not in versions.env, so the map has drifted: {unknown}"
    )
    assert len(RUNTIME_PINS) >= 12
