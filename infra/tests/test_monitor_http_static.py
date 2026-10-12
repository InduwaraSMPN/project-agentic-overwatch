"""Static deployment and boundary checks for the M2 HTTP aggregator service."""

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SERVICE = REPO_ROOT / "monitor" / "http_service.py"
DEPLOY = REPO_ROOT / "monitor" / "deploy"
VERSIONS = REPO_ROOT / "infra" / "versions.env"
IMAGE_SCRIPT = REPO_ROOT / "scripts" / "monitor_image.sh"


def test_http_transport_is_outside_the_guarded_aggregator_subtree() -> None:
    assert SERVICE.is_file()
    assert SERVICE.parent == REPO_ROOT / "monitor"
    assert SERVICE.parent != REPO_ROOT / "monitor" / "aggregator"
    tree = ast.parse(SERVICE.read_text(encoding="utf-8"))
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom))
    assert "subprocess" not in imports
    assert "socket" not in imports


def test_service_reuses_emitter_and_declares_all_required_routes() -> None:
    text = SERVICE.read_text(encoding="utf-8")
    assert "from monitor.aggregator.emit import EmitConfig, SourceInput, emit" in text
    assert "entry.normalise(" not in text
    assert "EvidenceEvent(" not in text
    for route in (
        '"/healthz"',
        '"/readyz"',
        '"/v1/falco"',
        '"/v1/alertmanager"',
        '"/v1/k8s-audit"',
        '"/v1/trivy"',
    ):
        assert route in text


def test_kustomization_is_complete_and_readiness_checks_ingestion() -> None:
    kustomization = (DEPLOY / "kustomization.yaml").read_text(encoding="utf-8")
    for name in (
        "namespace.yaml",
        "config.yaml",
        "deployment.yaml",
        "service.yaml",
    ):
        assert f"  - {name}" in kustomization
        assert (DEPLOY / name).is_file()

    config = (DEPLOY / "config.yaml").read_text(encoding="utf-8")
    assert "PENDING-M2-FIXTURE-STUDY" not in config
    deployment = (DEPLOY / "deployment.yaml").read_text(encoding="utf-8")
    assert deployment.count("path: /healthz") == 1
    assert deployment.count("path: /readyz") == 1
    assert "readOnlyRootFilesystem: true" in deployment
    assert "automountServiceAccountToken: false" in deployment


def test_dockerfile_build_arguments_have_digest_pinned_consumers() -> None:
    text = (REPO_ROOT / "monitor" / "Dockerfile").read_text(encoding="utf-8")
    versions = dict(
        line.split("=", 1)
        for line in VERSIONS.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    )
    controller = IMAGE_SCRIPT.read_text(encoding="utf-8")

    assert "ARG PYTHON_BASE_IMAGE" in text
    assert "ARG PYDANTIC_VERSION" in text
    assert "FROM ${PYTHON_BASE_IMAGE}" in text
    assert "pydantic==${PYDANTIC_VERSION}" in text
    assert "python:3." not in text
    assert versions["MONITOR_PYTHON_BASE_IMAGE"].startswith("python:3.12-slim-bookworm@sha256:")
    assert len(versions["MONITOR_PYTHON_BASE_IMAGE"].rsplit(":", 1)[1]) == 64
    assert versions["MONITOR_IMAGE"] == "agentic-overwatch/evidence-aggregator:local"
    for key in ("MONITOR_IMAGE", "MONITOR_PYTHON_BASE_IMAGE", "PYDANTIC_VERSION"):
        assert f"value {key}" in controller
    assert 'docker build --pull=false -f monitor/Dockerfile -t "$image"' in controller
    assert 'kind load docker-image --name "$cluster_name" "$image"' in controller


def test_bringup_builds_the_image_before_rendered_deployment_is_applied() -> None:
    text = (REPO_ROOT / "scripts" / "up.sh").read_text(encoding="utf-8")
    build = 'if ! sh "$MONITOR_IMAGE"; then'
    apply = 'if ! kubectl apply -k "$MONITOR_OVERLAY"; then'
    restart = (
        'kubectl rollout restart -n "$MONITOR_NS" '
        "deployment/evidence-aggregator deployment/audit-forwarder"
    )
    assert build in text
    assert apply in text
    assert restart in text
    assert text.index(build) < text.index(apply) < text.index(restart)


def test_calibrated_caps_are_not_duplicated_in_the_deployment() -> None:
    config = (DEPLOY / "config.yaml").read_text(encoding="utf-8")
    deployment = (DEPLOY / "deployment.yaml").read_text(encoding="utf-8")
    assert "MONITOR_EVIDENCE_EXCERPT" not in config
    assert "MONITOR_SUMMARY_LENGTH_MAX_CHARS" not in config
    assert deployment.count("path: /healthz") == 1
    assert deployment.count("path: /readyz") == 1
