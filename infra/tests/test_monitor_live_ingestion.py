"""Static contracts for live Kubernetes audit and Trivy ingestion wiring."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
AUDIT_FORWARDER = ROOT / "monitor" / "deploy" / "audit-forwarder.yaml"
KUSTOMIZATION = ROOT / "monitor" / "deploy" / "kustomization.yaml"
TRIVY_JOB = ROOT / "infra" / "monitor" / "trivy-kubernetes-job.yaml"
DOCKERFILE = ROOT / "monitor" / "Dockerfile"


def load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def env(container: dict) -> dict[str, str]:
    return {item["name"]: item["value"] for item in container.get("env", [])}


def test_audit_forwarder_is_control_plane_local_and_explicitly_ranked() -> None:
    deployment = load(AUDIT_FORWARDER)
    pod = deployment["spec"]["template"]["spec"]
    assert pod["nodeSelector"] == {"node-role.kubernetes.io/control-plane": ""}
    assert pod["automountServiceAccountToken"] is False
    container = pod["containers"][0]
    assert container["image"] == "agentic-overwatch/evidence-aggregator:local"
    assert container["command"] == ["python", "-m", "monitor.audit_forwarder"]
    values = env(container)
    assert values["MONITOR_AUDIT_PATH"] == "/var/lib/overwatch/evidence/k8s_audit.jsonl"
    # The manifest carried `PENDING-M2-AUDIT-RULE` while the selecting policy rule's severity was
    # undecided, and this assertion pinned that sentinel. Build control has since assigned the
    # value -- audit-forwarder.yaml records `high` with its rationale -- so pinning the sentinel now
    # asserts the opposite of what it was written to protect. What the test owes the manifest is
    # that a real severity was assigned before live ingestion, and that Kubernetes audit `level`
    # (`RequestResponse` and friends) never leaks into a field that means severity;
    # monitor/tests/test_live_forwarders.py owns that second rule at the parser.
    assert values["MONITOR_AUDIT_SEVERITY"] == "high"
    assert not values["MONITOR_AUDIT_SEVERITY"].startswith("PENDING-")
    assert values["MONITOR_AUDIT_URL"].endswith("/v1/k8s-audit")
    assert pod["volumes"] == [
        {
            "name": "evidence",
            "hostPath": {"path": "/var/lib/overwatch/evidence", "type": "Directory"},
        }
    ]
    assert container["volumeMounts"][0]["readOnly"] is True
    assert "audit-forwarder.yaml" in load(KUSTOMIZATION)["resources"]


def test_trivy_job_scans_one_explicit_image_then_uploads_full_report() -> None:
    job = load(TRIVY_JOB)
    pod = job["spec"]["template"]["spec"]
    assert pod["automountServiceAccountToken"] is False
    assert "serviceAccountName" not in pod
    scanner = pod["initContainers"][0]
    assert scanner["image"] == "docker.io/aquasec/trivy:TRIVY_IMAGE_VERSION"
    assert scanner["args"] == [
        "image",
        "--format",
        "json",
        "--output",
        "/work/trivy.json",
        "$(TARGET_IMAGE)",
    ]
    target = env(scanner)["TARGET_IMAGE"]
    assert "@sha256:" in target
    uploader = pod["containers"][0]
    assert uploader["image"] == "agentic-overwatch/evidence-aggregator:local"
    assert uploader["command"] == ["python", "-m", "monitor.trivy_uploader"]
    assert env(uploader)["MONITOR_TRIVY_URL"].endswith("/v1/trivy")
    assert pod["volumes"] == [{"name": "report", "emptyDir": {}}]
    serialized = TRIVY_JOB.read_text(encoding="utf-8")
    assert "ClusterRole" not in serialized
    assert "ClusterRoleBinding" not in serialized
    assert "kubernetes\n" not in serialized


def test_monitor_image_contains_both_stdlib_transport_modules() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "COPY monitor /app/monitor" in text
    assert (ROOT / "monitor" / "audit_forwarder.py").is_file()
    assert (ROOT / "monitor" / "trivy_uploader.py").is_file()
