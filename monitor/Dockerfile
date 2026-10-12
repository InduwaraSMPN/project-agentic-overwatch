# Build inputs are supplied from infra/versions.env by the build controller; no version is duplicated here.
ARG PYTHON_BASE_IMAGE
FROM ${PYTHON_BASE_IMAGE}

ARG PYDANTIC_VERSION
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MONITOR_HTTP_HOST=0.0.0.0 \
    MONITOR_HTTP_PORT=8080 \
    MONITOR_DATA_DIR=/var/lib/monitor

WORKDIR /app
# The Monitor installs its ONE runtime dependency, pydantic, pinned from PYDANTIC_VERSION
# (infra/versions.env, the single source the hashed requirements.lock is also derived from). It does
# NOT install from requirements.lock: rule 40 (.agents/rules/40) types the Monitor deterministic and
# non-LLM end to end, the universal lock carries LiteLLM and LangGraph, and pip cannot install a hashed
# SUBSET of one lock (constraint files do not hand hashes to CLI requirements), so a lock install here
# would drag an inference SDK into the Monitor image. Keeping the version pin from versions.env is the
# rule-40-clean choice (ADR-135's lock covers the Guardian image and the whole-environment install);
# infra/tests/test_lock_matches_versions_env.py keeps pydantic's lock version equal to PYDANTIC_VERSION,
# so reproducibility is preserved transitively. See infra/tests/test_monitor_http_static.py.
RUN python -m pip install --no-cache-dir "pydantic==${PYDANTIC_VERSION}" \
 && groupadd --system --gid 65532 monitor \
 && useradd --system --uid 65532 --gid monitor --home-dir /nonexistent --shell /usr/sbin/nologin monitor \
 && mkdir -p /var/lib/monitor \
 && chown 65532:65532 /var/lib/monitor

COPY monitor /app/monitor

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python", "-m", "monitor.http_service"]
