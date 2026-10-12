"""Static deployment proofs. These validate authored intent; they are not live-cluster evidence."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "guardian" / "deploy"


def documents(name: str) -> list[dict]:
    return [doc for doc in yaml.safe_load_all((DEPLOY / name).read_text(encoding="utf-8")) if doc]


def by_kind(name: str) -> dict[str, dict]:
    return {doc["kind"]: doc for doc in documents(name)}


def test_guardian_image_packages_only_the_trusted_cve_catalog_reader() -> None:
    dockerfile = (DEPLOY / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY scenarios/cve/images.yaml /app/scenarios/cve/images.yaml" in dockerfile
    assert "yamlsubset.py" in dockerfile
    assert "scenarios/cve/tarballs" not in dockerfile


def test_workload_attaches_sole_service_account_and_persistent_audit() -> None:
    docs = by_kind("deployment.yaml")
    assert set(docs) == {"Deployment", "Service", "PersistentVolumeClaim"}
    deployment = docs["Deployment"]
    pod = deployment["spec"]["template"]["spec"]
    assert pod["serviceAccountName"] == "guardian"
    assert pod["automountServiceAccountToken"] is True
    assert pod["securityContext"]["runAsNonRoot"] is True
    assert pod["securityContext"]["fsGroup"] == 65532
    signing_volume = next(volume for volume in pod["volumes"] if volume["name"] == "signing-key")
    assert signing_volume["secret"]["defaultMode"] == 0o440
    container = pod["containers"][0]
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["securityContext"]["allowPrivilegeEscalation"] is False
    assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
    assert {v["name"] for v in pod["volumes"]} == {"signing-key", "audit-signing-key", "audit"}
    assert docs["Service"]["spec"]["ports"] == [
        {"name": "http", "port": 8080, "targetPort": "http", "protocol": "TCP"}
    ]


def test_workload_mounts_the_ed25519_audit_signing_key_and_points_config_at_it() -> None:
    """ADR-130: the live Guardian is wired to sign its audit chain.

    The env names the mounted key, the volume mount is read-only, and the volume is a projected
    Secret -- ``guardian-audit-signing-key``, referenced and never declared, created out of band
    like the token key. Config refuses to start if the path names no readable key, so this wiring is
    what makes the campaign's chains signed rather than an unsigned v1 chain that merely looked
    configured.
    """
    pod = by_kind("deployment.yaml")["Deployment"]["spec"]["template"]["spec"]
    container = pod["containers"][0]
    env = {var["name"]: var["value"] for var in container["env"]}
    key_path = "/var/run/guardian-audit-key/audit-signing-key"
    assert env["GUARDIAN_AUDIT_SIGNING_KEY_FILE"] == key_path
    mount = next(m for m in container["volumeMounts"] if m["name"] == "audit-signing-key")
    assert mount["mountPath"] == "/var/run/guardian-audit-key"
    assert mount["readOnly"] is True
    # The env path is the mount path plus the item's path, so the key the code reads is the key the
    # Secret projects -- a drift between the two would read an absent file and fail closed at start.
    assert key_path == f"{mount['mountPath']}/audit-signing-key"
    volume = next(v for v in pod["volumes"] if v["name"] == "audit-signing-key")
    assert volume["secret"]["secretName"] == "guardian-audit-signing-key"
    assert volume["secret"]["defaultMode"] == 0o440
    assert volume["secret"]["items"] == [{"key": "audit-signing-key", "path": "audit-signing-key"}]


def test_guardian_deploy_requires_the_audit_signing_key_secret_out_of_band() -> None:
    """ADR-130: deploy fails fast on an absent audit key rather than hanging the pod Pending.

    deployment.yaml mounts guardian-audit-signing-key as a required volume, so the script checks it
    exists and prints the out-of-band creation recipe -- the same posture the token key already has,
    keeping both private keys out of source control (rule 4, rule 10).
    """
    script = (ROOT / "scripts" / "guardian_deploy.sh").read_text(encoding="utf-8")
    assert "get secret guardian-audit-signing-key" in script
    assert "guardian/guardian-audit-signing-key is absent" in script
    # The token key's own check stays, and the audit check does not replace it.
    assert "get secret guardian-signing-key" in script


def test_guardian_rbac_is_namespaced_for_every_mutation_and_has_one_subject() -> None:
    docs = documents("rbac.yaml")
    mutating = {"create", "update", "patch", "delete", "deletecollection"}
    forbidden = {"secrets", "pods/exec", "pods/portforward", "serviceaccounts/token"}
    for doc in docs:
        if doc["kind"] in {"Role", "ClusterRole"}:
            for rule in doc.get("rules", []):
                resources = set(rule["resources"])
                verbs = set(rule["verbs"])
                assert "*" not in resources | verbs | set(rule["apiGroups"])
                assert not resources & forbidden
                if "bind" in verbs:
                    assert doc["kind"] == "Role"
                    assert rule.get("resourceNames") == ["boutique-escalation"]
                    assert resources == {"roles"}
                if doc["kind"] == "ClusterRole":
                    # ADR-128: creating a TokenReview is an authentication query, not a cluster
                    # mutation -- it writes and stores nothing -- so this one `create` is the single
                    # carve-out from "no ClusterRole holds a mutating verb". It names only
                    # `tokenreviews` in `authentication.k8s.io` and nothing else.
                    if resources == {"tokenreviews"}:
                        assert verbs == {"create"}
                        assert rule["apiGroups"] == ["authentication.k8s.io"]
                    else:
                        assert not verbs & mutating
        if doc["kind"] in {"RoleBinding", "ClusterRoleBinding"}:
            assert doc["subjects"] == [
                {"kind": "ServiceAccount", "name": "guardian", "namespace": "guardian"}
            ]
    role = next(doc for doc in docs if doc["kind"] == "Role")
    assert role["metadata"]["namespace"] == "boutique"
    bind_rules = [rule for rule in role["rules"] if "bind" in rule["verbs"]]
    assert bind_rules == [
        {
            "apiGroups": ["rbac.authorization.k8s.io"],
            "resources": ["roles"],
            "resourceNames": ["boutique-escalation"],
            "verbs": ["bind"],
        }
    ]


def test_g2_role_mirrors_guardian_role() -> None:
    """ADR-131 / D17-A: in G2-SHAREDCRED the g2-executor Role equals the Guardian's own Role.

    C2 removes the "sole credentials" invariant by design: the agents hold, through g2-executor,
    exactly
    the Guardian's cluster-mutation rights, so a direct path can execute what the Guardian could. In
    v1
    this Role was read-only pods (V7), which made G2 inert -- indistinguishable from G0. The two
    rule
    lists are compared field for field, so a widening or narrowing of either drifts them apart and
    fails
    here.
    """
    g2 = by_kind("g2-rbac.yaml")
    assert set(g2) == {"ServiceAccount", "Role", "RoleBinding"}
    assert g2["ServiceAccount"]["automountServiceAccountToken"] is False
    assert g2["Role"]["metadata"]["namespace"] == "boutique"
    assert g2["RoleBinding"]["subjects"] == [
        {"kind": "ServiceAccount", "name": "g2-executor", "namespace": "agents"}
    ]

    guardian_role = next(doc for doc in documents("rbac.yaml") if doc["kind"] == "Role")
    assert g2["Role"]["rules"] == guardian_role["rules"], (
        "the g2-executor Role no longer mirrors the Guardian's incident-response Role; D17-A requires "  # noqa: E501 - message
        "them byte-for-byte equal so G2 holds credentials equivalent to the Guardian's"
    )
    # And the mirror is a real mutation grant now, not a read-only leftover -- the property V7
    # lacked.
    all_verbs = {verb for rule in g2["Role"]["rules"] for verb in rule["verbs"]}
    assert {"patch", "create", "delete"} <= all_verbs


def test_the_guardian_creates_tokenreviews_for_control_plane_authentication() -> None:
    """ADR-128: the Guardian holds `create` on tokenreviews, bound to its sole ServiceAccount.

    That verb is what lets ControlPlaneAuthenticator verify the runner's token with a TokenReview.
    It is
    an authentication query, not a cluster mutation, and it is the Guardian's alone.
    """
    docs = documents("rbac.yaml")
    tokenreview_roles = [
        doc
        for doc in docs
        if doc["kind"] == "ClusterRole"
        and any("tokenreviews" in rule["resources"] for rule in doc.get("rules", []))
    ]
    assert len(tokenreview_roles) == 1, "exactly one ClusterRole grants the TokenReview verb"
    rules = tokenreview_roles[0]["rules"]
    assert rules == [
        {
            "apiGroups": ["authentication.k8s.io"],
            "resources": ["tokenreviews"],
            "verbs": ["create"],
        }
    ]
    name = tokenreview_roles[0]["metadata"]["name"]
    binding = next(
        doc
        for doc in docs
        if doc["kind"] == "ClusterRoleBinding" and doc["roleRef"]["name"] == name
    )
    assert binding["subjects"] == [
        {"kind": "ServiceAccount", "name": "guardian", "namespace": "guardian"}
    ]


def test_the_control_plane_serviceaccount_exists_and_holds_no_rbac() -> None:
    """ADR-128: `runner-control-plane` is a verifiable identity with no permission of any kind.

    The runner authenticates AS this ServiceAccount at the control-plane surface. It carries no RBAC
    binding, so a token minted for it grants nothing on the cluster -- it exists only to be
    recognised.
    """
    docs = documents("rbac.yaml")
    accounts = [
        doc
        for doc in docs
        if doc["kind"] == "ServiceAccount" and doc["metadata"]["name"] == "runner-control-plane"
    ]
    assert len(accounts) == 1, (
        "the runner-control-plane ServiceAccount must be declared exactly once"
    )
    assert accounts[0]["metadata"]["namespace"] == "guardian"

    for doc in docs:
        if doc["kind"] in {"RoleBinding", "ClusterRoleBinding"}:
            names = {subject["name"] for subject in doc["subjects"]}
            assert "runner-control-plane" not in names, (
                "a Role or ClusterRole is bound to runner-control-plane; it must hold no permission"
            )


def test_g2_script_uses_tokenrequest_and_restores_default_deny() -> None:
    script = (ROOT / "scripts" / "g2_credential.sh").read_text(encoding="utf-8")
    # The bearer is minted before the window opens and must still be
    # valid when it closes, or F-GD-05's expiry half cannot hold and the direct path lapses mid-run
    # (ADR-157, amending ADR-103). Measured framework-on runs reach 1578s (n=1687).
    assert "create token g2-executor --duration=3600s" in script
    assert "--bound-object-kind=Secret" in script
    assert '--bound-object-name="$bound_secret"' in script
    assert 'delete secret "$bound_secret" --ignore-not-found' in script
    assert "guardian/deploy/g2-rbac.yaml" in script
    assert "infra/netpol/agents-g2-open.yaml" in script
    assert "infra/netpol/agents-default-deny.yaml" in script
    assert "cat $" not in script


def test_guardian_ingress_admits_only_the_agent_namespace_on_the_mediation_port() -> None:
    """ADR-076: nothing but `agents` may open a connection to the issue surface (T-44 reach)."""
    policy_path = ROOT / "infra" / "netpol" / "guardian-ingress.yaml"
    docs = [doc for doc in yaml.safe_load_all(policy_path.read_text(encoding="utf-8")) if doc]
    assert len(docs) == 1
    policy = docs[0]
    assert policy["kind"] == "NetworkPolicy"
    assert policy["metadata"]["namespace"] == "guardian"
    spec = policy["spec"]
    assert spec["podSelector"] == {"matchLabels": {"app.kubernetes.io/name": "guardian"}}
    # Without policyTypes the object would not isolate ingress and would still read as a boundary.
    assert spec["policyTypes"] == ["Ingress"]
    assert spec["ingress"] == [
        {
            "from": [
                {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "agents"}}}
            ],
            "ports": [{"protocol": "TCP", "port": 8080}],
        }
    ]
    service_ports = by_kind("deployment.yaml")["Service"]["spec"]["ports"]
    assert [port["port"] for port in service_ports] == [8080]


def test_every_guardian_deploy_applies_the_ingress_boundary() -> None:
    """Applied on every deploy, which the runner performs per attempt in every arm."""
    script = (ROOT / "scripts" / "guardian_deploy.sh").read_text(encoding="utf-8")
    apply_rbac = script.index("kubectl apply -f guardian/deploy/rbac.yaml")
    apply_ingress = script.index("kubectl apply -f infra/netpol/guardian-ingress.yaml")
    rollout = script.index("kubectl apply -f guardian/deploy/deployment.yaml")
    assert apply_rbac < apply_ingress < rollout
    assert "GUARDIAN_MODE" not in script[apply_ingress - 200 : apply_ingress + 60]
