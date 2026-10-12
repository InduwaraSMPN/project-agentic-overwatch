# infra/probes/deploy/Dockerfile -- the in-cluster SLO probe image. ADR-085; supervisor ruling B3.
#
# WHY THIS IMAGE HAS NO THIRD-PARTY DEPENDENCY
#   infra/probes/slo_probe.py's own module docstring already establishes why: it is exercised end to
#   end by CI's "Unit tests -- infra" step, which installs pytest and nothing else, so the writer's
#   own imports are standard library only (argparse, csv, http.cookiejar, math, urllib, ...). The
#   same property makes the runtime image trivial: a bare Python base image plus this repository's
#   infra/ package is a complete, runnable probe, with nothing to pin a version for beyond Python
#   itself.
#
# WHY NOT REUSE guardian/deploy/Dockerfile's PINNED BASE-IMAGE DIGEST
#   guardian/deploy/Dockerfile builds FROM GUARDIAN_PYTHON_BASE_IMAGE, pinned by digest in
#   infra/versions.env, because the Guardian is a measured, evaluated component of the artefact.
#   This image is measurement apparatus in exactly the sense infra/collectors/resource_collector.py
#   already gives its `platform` series (Prometheus, Locust, kube-state-metrics): it never runs in
#   an experimental condition, computes no evaluated result, and appears in no run bundle by name.
#   infra/netpol/probe/server.yaml records the identical distinction for its own fixture image and
#   pins its tag in the manifest rather than in infra/versions.env, "in the same category as a unit
#   test's fixture data". If the supervisor decides fixture and apparatus images belong in
#   infra/versions.env too, the move is a versions.env key plus an ADR, and nothing here changes but
#   this comment -- the same forward note that file leaves for itself.
#
# WHY imagePullPolicy: Never (infra/probes/deploy/pod.yaml)
#   Matches guardian/deploy/deployment.yaml: a kind cluster has no image registry of its own, so the
#   image is built here and loaded directly into the kind nodes (`kind load docker-image`) before
#   any pod can reference it. See ADR-085's deployment steps for the exact commands, or run
#   infra/probes/deploy/build.sh.
#
# WHY A NON-ROOT, READ-ONLY-ROOTFS-COMPATIBLE IMAGE
#   infra/probes/deploy/pod.yaml sets runAsNonRoot, runAsUser/runAsGroup 65532,
#   readOnlyRootFilesystem and drops every capability -- the same posture
#   guardian/deploy/deployment.yaml gives the Guardian's own container. The probe writes only to its
#   /data emptyDir mount, so a read-only root filesystem costs it nothing.
#
# WHAT BREAKS IF THIS FILE CHANGES
#   Renaming the image away from agentic-overwatch/slo-probe:local must move in the same commit as
#   PROBE_IMAGE in runner/live_baseline.py, infra/probes/deploy/build.sh, and the
#   SLO_PROBE_IMAGE_PLACEHOLDER default an operator substitutes by hand in
#   infra/probes/deploy/pod.yaml.
FROM python:3.12-slim-bookworm

WORKDIR /app

# Only the two files infra.probes.slo_probe actually imports: the package marker and the probes
# package itself (infra/probes/constants.py and infra/probes/slo_probe.py). Not `COPY infra /app/
# infra`: infra/ also holds the boutique, cilium, monitor and observability trees and, on a
# developer's checkout, the langfuse data volumes under infra/observability/ -- none of it wanted in
# an image that speaks only HTTP to one Service.
COPY infra/__init__.py /app/infra/__init__.py
COPY infra/probes /app/infra/probes

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system --gid 65532 slo-probe \
 && useradd --system --uid 65532 --gid slo-probe --home-dir /nonexistent \
      --shell /usr/sbin/nologin slo-probe

USER 65532:65532

# Overridden by infra/probes/deploy/pod.yaml's own command/args (a Pod's command+args fully replace
# an image's ENTRYPOINT/CMD); kept so `docker run agentic-overwatch/slo-probe:local --out ... --base
# -url ... --samples 1` is a usable manual smoke test on its own.
ENTRYPOINT ["python", "-m", "infra.probes.slo_probe"]
