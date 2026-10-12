"""Static proofs for M2 Phase B source artifacts (not live-source evidence)."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
FALCO_VALUES = ROOT / "infra" / "monitor" / "falco-values.yaml"
FALCO_RULES = ROOT / "monitor" / "rules" / "overwatch-rules.yaml"
ALERTMANAGER_VALUES = ROOT / "infra" / "monitor" / "alertmanager-values.yaml"
PROMETHEUS_VALUES = ROOT / "infra" / "observability" / "prometheus-values.yaml"
AUDIT_POLICY = ROOT / "infra" / "audit" / "audit-policy.yaml"
KIND_CONFIG = ROOT / "infra" / "kind-config.yaml"
TRIVY_JOB = ROOT / "infra" / "monitor" / "trivy-kubernetes-job.yaml"
AUDIT_FORWARDER = ROOT / "monitor" / "deploy" / "audit-forwarder.yaml"
HTTP_SERVICE = ROOT / "monitor" / "http_service.py"
AUDIT_FORWARDER_SOURCE = ROOT / "monitor" / "audit_forwarder.py"
TRIVY_UPLOADER_SOURCE = ROOT / "monitor" / "trivy_uploader.py"
INSTALL = ROOT / "infra" / "monitor" / "install.sh"

AGGREGATOR_BASE = "http://evidence-aggregator.monitor.svc.cluster.local:8080"
EXPECTED_ROUTES = {
    "falco": "/v1/falco",
    "alertmanager": "/v1/alertmanager",
    "k8s-audit": "/v1/k8s-audit",
    "trivy": "/v1/trivy",
}


def load(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def documents(path: Path) -> list[dict]:
    return [item for item in yaml.safe_load_all(path.read_text(encoding="utf-8")) if item]


def test_falco_uses_modern_ebpf_and_forwards_all_priorities() -> None:
    values = load(FALCO_VALUES)
    install = INSTALL.read_text(encoding="utf-8")
    assert '--set "driver.kind=$FALCO_DRIVER"' in install
    assert '[ "$FALCO_DRIVER" = modern_ebpf ]' in install
    assert "kind" not in values["driver"]
    assert values["driver"]["modernEbpf"]["sysfsMount"] is True
    assert values["falco"]["json_output"] is True
    sidekick = values["falcosidekick"]
    assert sidekick["enabled"] is True
    assert "image" not in sidekick
    assert '--set "falcosidekick.image.tag=$FALCOSIDEKICK_APP_VERSION"' in install
    webhook = sidekick["config"]["webhook"]
    assert webhook["address"] == (
        "http://evidence-aggregator.monitor.svc.cluster.local:8080/v1/falco"
    )
    assert webhook["method"] == "POST"
    assert webhook["minimumpriority"] == "debug"


def test_falco_rules_cover_scenario_detection_labels() -> None:
    entries = load(FALCO_RULES)
    rules = {item["rule"]: item for item in entries if "rule" in item}
    assert {
        "Terminal shell in container",
        "Read sensitive file untrusted",
        "Launch Privileged Container",
        "Unexpected outbound connection destination",
    } <= rules.keys()
    for rule in rules.values():
        assert rule["condition"].strip()
        assert rule["output"].strip()
        assert rule["priority"].lower() in {
            "emergency",
            "alert",
            "critical",
            "error",
            "warning",
            "notice",
            "informational",
            "debug",
        }


def test_alertmanager_is_standalone_and_routes_to_aggregator() -> None:
    prometheus = load(PROMETHEUS_VALUES)
    assert prometheus["alertmanager"]["enabled"] is False
    assert prometheus["server"]["alertmanagers"] == [
        {"static_configs": [{"targets": ["alertmanager.observability.svc.cluster.local:9093"]}]}
    ]
    alertmanager = load(ALERTMANAGER_VALUES)["config"]
    assert alertmanager["route"]["receiver"] == "evidence-aggregator"
    receiver = next(
        item for item in alertmanager["receivers"] if item["name"] == "evidence-aggregator"
    )
    assert receiver["webhook_configs"] == [
        {
            "url": "http://evidence-aggregator.monitor.svc.cluster.local:8080/v1/alertmanager",
            "send_resolved": True,
        }
    ]


def test_prometheus_rules_use_only_closed_severity_and_engineering_origin() -> None:
    groups = load(PROMETHEUS_VALUES)["serverFiles"]["alerting_rules.yml"]["groups"]
    rules = [rule for group in groups for rule in group["rules"]]
    assert {rule["alert"] for rule in rules} >= {
        "KubeDeploymentReplicasMismatch",
        "KubePodCrashLooping",
        "CartServiceErrorRateHigh",
    }
    assert {rule["labels"]["severity"] for rule in rules} == {"critical", "warning", "info"}
    assert all(rule["labels"]["origin"] == "engineering" for rule in rules)
    assert all(rule["expr"] and rule["annotations"]["summary"] for rule in rules)


def test_kind_audit_paths_are_consistent_and_policy_is_selective() -> None:
    config = load(KIND_CONFIG)
    control = next(node for node in config["nodes"] if node["role"] == "control-plane")
    mounts = {item["containerPath"]: item for item in control["extraMounts"]}
    # ADR-095: the audit policy is mounted as a DIRECTORY, not a file -- a host-file bind mount
    # does not survive a Docker Desktop restart on the WSL2 profile. The directory mount is what
    # keeps the control-plane startable across restarts, so pin the directory shape, not a path.
    audit_dir = "/etc/kubernetes/overwatch-audit"
    assert mounts[audit_dir]["readOnly"] is True
    assert mounts[audit_dir]["hostPath"] == "infra/audit"
    assert "/etc/kubernetes/audit-policy.yaml" not in mounts  # never remount the bare file
    assert "/var/lib/overwatch/evidence" in mounts
    patch = yaml.safe_load(control["kubeadmConfigPatches"][0])
    args = patch["apiServer"]["extraArgs"]
    assert args["audit-policy-file"] == f"{audit_dir}/audit-policy.yaml"
    assert args["audit-log-path"] == "/var/lib/overwatch/evidence/k8s_audit.jsonl"
    volumes = {item["name"]: item for item in patch["apiServer"]["extraVolumes"]}
    assert volumes["overwatch-audit-policy"]["mountPath"] == audit_dir
    assert volumes["overwatch-audit-policy"]["pathType"] == "Directory"
    assert args["audit-policy-file"].startswith(audit_dir + "/")  # the file lives in the dir mount
    assert volumes["overwatch-evidence"]["mountPath"] == "/var/lib/overwatch/evidence"

    policy = load(AUDIT_POLICY)
    assert policy["apiVersion"] == "audit.k8s.io/v1"
    assert policy["kind"] == "Policy"
    assert policy["rules"][-1] == {"level": "None"}
    serialized = AUDIT_POLICY.read_text(encoding="utf-8")
    for resource in ("pods/exec", "clusterrolebindings", "secrets"):
        assert resource in serialized


def test_trivy_image_scan_posts_schema_v2_report_to_the_existing_route() -> None:
    docs = documents(TRIVY_JOB)
    job = next(item for item in docs if item["kind"] == "Job")
    assert job["spec"]["backoffLimit"] == 0
    pod = job["spec"]["template"]["spec"]
    assert pod["restartPolicy"] == "Never"
    assert pod["automountServiceAccountToken"] is False
    scanner = pod["initContainers"][0]
    assert scanner["image"] == "docker.io/aquasec/trivy:TRIVY_IMAGE_VERSION"
    assert scanner["args"][0:5] == ["image", "--format", "json", "--output", "/work/trivy.json"]
    assert "@sha256:" in scanner["env"][0]["value"]
    uploader = pod["containers"][0]
    assert uploader["command"] == ["python", "-m", "monitor.trivy_uploader"]
    env = {item["name"]: item["value"] for item in uploader["env"]}
    assert env["MONITOR_TRIVY_URL"].endswith("/v1/trivy")
    assert env["MONITOR_TRIVY_URL"] == AGGREGATOR_BASE + EXPECTED_ROUTES["trivy"]
    assert pod["volumes"] == [{"name": "report", "emptyDir": {}}]


def test_every_source_wires_exactly_to_the_http_service_route() -> None:
    """Keep all four transports locked to the routes the server actually dispatches."""
    service_text = HTTP_SERVICE.read_text(encoding="utf-8")
    assert {route for route in EXPECTED_ROUTES.values()} == {
        route for route in EXPECTED_ROUTES.values() if f'"{route}"' in service_text
    }

    falco = load(FALCO_VALUES)["falcosidekick"]["config"]["webhook"]["address"]
    alertmanager = load(ALERTMANAGER_VALUES)["config"]["receivers"][0]["webhook_configs"][0]["url"]
    audit_doc = load(AUDIT_FORWARDER)
    audit_env = {
        item["name"]: item["value"]
        for item in audit_doc["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    trivy_job = next(item for item in documents(TRIVY_JOB) if item["kind"] == "Job")
    trivy_env = {
        item["name"]: item["value"]
        for item in trivy_job["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert falco == AGGREGATOR_BASE + EXPECTED_ROUTES["falco"]
    assert alertmanager == AGGREGATOR_BASE + EXPECTED_ROUTES["alertmanager"]
    assert audit_env["MONITOR_AUDIT_URL"] == AGGREGATOR_BASE + EXPECTED_ROUTES["k8s-audit"]
    assert trivy_env["MONITOR_TRIVY_URL"] == AGGREGATOR_BASE + EXPECTED_ROUTES["trivy"]

    assert EXPECTED_ROUTES["k8s-audit"] in AUDIT_FORWARDER_SOURCE.read_text(encoding="utf-8")
    assert EXPECTED_ROUTES["trivy"] in TRIVY_UPLOADER_SOURCE.read_text(encoding="utf-8")

    wired_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            FALCO_VALUES,
            ROOT / "infra" / "monitor" / "falcosidekick-values.yaml",
            ALERTMANAGER_VALUES,
            AUDIT_FORWARDER,
            AUDIT_FORWARDER_SOURCE,
            TRIVY_JOB,
            TRIVY_UPLOADER_SOURCE,
        )
    )
    assert "/ingest/" not in wired_text


def test_install_surface_reads_every_verified_version_from_versions_env() -> None:
    text = INSTALL.read_text(encoding="utf-8")
    for key in (
        "FALCO_CHART_VERSION",
        "FALCO_DRIVER",
        "FALCOSIDEKICK_VERSION",
        "ALERTMANAGER_VERSION",
        "TRIVY_VERSION",
    ):
        assert f"$(pin {key})" in text
    assert "FALCO_CHART_VERSION=8.0.1" not in text
    assert "TRIVY_IMAGE_VERSION=0.69.3" not in text
    assert "s|TRIVY_IMAGE_VERSION|$TRIVY_IMAGE_VERSION|g" in text
    assert "FALCOSIDEKICK_APP_VERSION=$(helm show chart" in text
    assert '--set "driver.kind=$FALCO_DRIVER"' in text
    assert '--set "falcosidekick.image.tag=$FALCOSIDEKICK_APP_VERSION"' in text
    assert (
        "--set-file 'customRules.overwatch-rules\\.yaml=monitor/rules/overwatch-rules.yaml'" in text
    )
