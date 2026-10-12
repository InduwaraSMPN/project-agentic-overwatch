# The Guardian image is built locally by scripts/guardian_image.sh from pins in infra/versions.env.
# No credential is copied into the image; the signing key and Kubernetes credential are mounted.
ARG PYTHON_BASE_IMAGE=python:3.12-slim-bookworm
FROM ${PYTHON_BASE_IMAGE}

ARG FASTAPI_VERSION
ARG PYJWT_VERSION
ARG PYDANTIC_VERSION
ARG KUBERNETES_CLIENT_VERSION
ARG UVICORN_VERSION
# ADR-130: the Ed25519 audit-signing library. Pinned once in infra/versions.env (CRYPTOGRAPHY_VERSION);
# referenced here only, never restated. guardian/audit/ signs each record hash with the operator's key,
# which is mounted, never built into the image (no key material appears here).
ARG CRYPTOGRAPHY_VERSION
ARG OPA_VERSION
ARG OPA_LINUX_AMD64_SHA256
# ADR-182: the OS-level security update the base image's own layer still needs. Three CRITICAL
# CVEs in perl-base 5.36.0-7+deb12u3 (CVE-2026-8376 heap overflow on regex compilation,
# CVE-2026-13221 incorrect regex processing, CVE-2026-42496 archive-tar path traversal) are fixed
# by Debian in 7+deb12u4, which the archive already serves. The base digest does not have to move
# for that, and moving it would: the `python:3.12-slim-bookworm` tag has switched distro to Ubuntu
# noble, and the bookworm-pinned `3.12.11` image would downgrade the interpreter from 3.12.14.
# One targeted, version-pinned upgrade fixes the three and changes nothing else in the image.
#
# The pin is read from infra/versions.env rather than passed as a build arg, and that asymmetry is
# deliberate. Every other pin here is an ARG forwarded by a builder script, which means each
# builder must repeat the list; `scripts/self_scan.sh` builds this image too, and when ADR-182 first
# added the pin as an ARG the self-scan build failed at apt because that script had not been given
# it -- the image the security gate scans was not the image the VM runs. A pin that a builder can
# forget is a pin that will be forgotten, so this one is read from its single home in the build
# itself and the copy is removed afterwards.

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/opa/bin:${PATH}

WORKDIR /app

# The Python runtime is installed from the hashed lock (ADR-135, M10) rather than from the per-package
# pins above: requirements.lock is generated from infra/versions.env by scripts/generate_lock.sh, so
# cryptography (ADR-130) and every other runtime pin stay consistent with versions.env -- checked by
# infra/tests/test_lock_matches_versions_env.py -- now with the whole transitive closure frozen by
# digest and refused by --require-hashes if an archive's hash is not in the lock. The version ARGs above
# remain the build controller's inputs and the documented pins. pip cannot install a hashed SUBSET of one
# universal lock, so the Guardian image installs the full closure; the Guardian has no non-LLM constraint
# (that is the Monitor's, rule 40), so this is heavier than the six pins but not a boundary violation.
# The OPA binary is not a Python package and is still fetched and checksum-verified below.
COPY requirements.lock /app/requirements.lock
COPY infra/versions.env /tmp/versions.env
RUN perl_base=$(grep -E '^PERL_BASE_VERSION=' /tmp/versions.env | head -n 1 | cut -d= -f2- | tr -d '\r') \
 && [ -n "$perl_base" ] || { echo 'PERL_BASE_VERSION is absent or empty in infra/versions.env' >&2; exit 1; } \
 && apt-get update \
 && apt-get install -y --no-install-recommends "perl-base=$perl_base" \
 && rm -rf /var/lib/apt/lists/* /tmp/versions.env \
 && dpkg-query -W -f='${Version}\n' perl-base | grep -qx "$perl_base" \
 && python -m pip install --no-cache-dir --require-hashes -r /app/requirements.lock \
 && for attempt in 1 2 3; do \
      python -c "import pathlib,urllib.request; u='https://github.com/open-policy-agent/opa/releases/download/${OPA_VERSION}/opa_linux_amd64_static'; pathlib.Path('/tmp/opa').write_bytes(urllib.request.urlopen(u, timeout=120).read())" \
      && break; \
      rm -f /tmp/opa; \
      [ "$attempt" -lt 3 ] || exit 1; \
    done \
 && python -c "import hashlib,pathlib; p=pathlib.Path('/tmp/opa'); h=hashlib.sha256(p.read_bytes()).hexdigest(); assert h == '${OPA_LINUX_AMD64_SHA256}', (h, '${OPA_LINUX_AMD64_SHA256}')" \
 && mkdir -p /opt/opa/bin \
 && cp /tmp/opa /opt/opa/bin/opa \
 && chmod 0555 /opt/opa/bin/opa \
 && rm /tmp/opa

COPY guardian /app/guardian
COPY scenarios/__init__.py /app/scenarios/__init__.py
COPY scenarios/schemas/__init__.py scenarios/schemas/yamlsubset.py /app/scenarios/schemas/
COPY scenarios/cve/images.yaml /app/scenarios/cve/images.yaml

RUN groupadd --system --gid 65532 guardian \
 && useradd --system --uid 65532 --gid guardian --home-dir /nonexistent --shell /usr/sbin/nologin guardian \
 && mkdir -p /var/lib/guardian/audit \
 && chown -R 65532:65532 /var/lib/guardian

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python", "-m", "guardian.app"]
