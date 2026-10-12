r"""V28 / D1-A: the API-server audit policy logs every mutation the Guardian's Role can make.

In v1 the audit policy ended in a catch-all ``level: None`` that recorded no workload mutation, so
an
executed Guardian action and a direct G2 action were equally invisible to the API-plane record
(V28).
``guardian/audit/k8s_crosscheck.py`` (ADR-137) needs that independent record, and G2's
``shared_credential_exercised`` is derived from it. The remediation widens
``infra/audit/audit-policy.yaml`` to log exactly the (resource, verb) pairs the Guardian's
incident-response Role in ``boutique`` grants -- which the ``g2-executor`` Role mirrors (D17-A).

These cases derive the Role's pairs from ``guardian/deploy/rbac.yaml`` and assert the audit policy's
first matching rule logs each of them (never falls through to the catch-all ``None``), that
``patch``
and ``update`` on ``apps/deployments`` are captured at ``Request`` level so the replica count is in
the
body (D4-A), and that the policy still ends in a catch-all ``None`` so unrelated controller churn is
not
logged.
"""

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

AUDIT_POLICY = ROOT / "infra" / "audit" / "audit-policy.yaml"
GUARDIAN_RBAC = ROOT / "guardian" / "deploy" / "rbac.yaml"

# The audit-verb vocabulary. `bind` (on roles/boutique-escalation) is an authorization check
# embedded in
# a rolebindings write, not an object mutation the API server audits under its own name, so the
# pairs it
# produces are excluded from the coverage assertion -- the rolebindings create/update/patch that
# carry
# it are logged by the RBAC rule.
AUDITED_VERBS = frozenset(
    {"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"}
)

# rbac apiGroup spelling -> audit-policy group spelling. Both use "" for core and the group name
# otherwise, so the mapping is the identity; it is written out so a future divergence is a named
# change.
_GROUP = {
    "": "",
    "apps": "apps",
    "batch": "batch",
    "discovery.k8s.io": "discovery.k8s.io",
    "networking.k8s.io": "networking.k8s.io",
    "rbac.authorization.k8s.io": "rbac.authorization.k8s.io",
}


def _documents(path: Path) -> list[dict]:
    return [doc for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")) if doc]


def _guardian_role_pairs() -> set[tuple[str, str, str]]:
    """Every (group, resource, verb) the Guardian's incident-response Role grants, bind excluded."""
    role = next(
        doc
        for doc in _documents(GUARDIAN_RBAC)
        if doc["kind"] == "Role" and doc["metadata"]["namespace"] == "boutique"
    )
    pairs: set[tuple[str, str, str]] = set()
    for rule in role["rules"]:
        for group in rule["apiGroups"]:
            for resource in rule["resources"]:
                for verb in rule["verbs"]:
                    if verb in AUDITED_VERBS:
                        pairs.add((_GROUP[group], resource, verb))
    return pairs


def _rule_matches(rule: dict, *, verb: str, group: str, resource: str) -> bool:
    """Whether one audit-policy rule matches a generic user's (verb, group, resource) request.

    A generic user is used deliberately: the ``system:nodes`` exclusion rule carries ``userGroups``
    and
    so does not match an ordinary caller, which is the runner, the operator or a direct-path agent.
    """
    if "nonResourceURLs" in rule:
        return False
    if rule.get("userGroups") or rule.get("users"):
        return False  # not this generic caller
    verbs = rule.get("verbs")
    if verbs is not None and verb not in verbs:
        return False
    resources = rule.get("resources")
    if resources is None:
        return True  # every resource
    for entry in resources:
        if entry.get("group", "") == group and resource in entry.get("resources", []):
            return True
    return False


def _first_matching_level(rules: list[dict], *, verb: str, group: str, resource: str) -> str:
    """The level of the first rule that matches, which is the level the API server would apply."""
    for rule in rules:
        if _rule_matches(rule, verb=verb, group=group, resource=resource):
            return rule["level"]
    return "None"  # no rule matched at all


def test_every_guardian_role_pair_is_logged_not_dropped() -> None:
    """Each (resource, verb) the Guardian Role grants is logged at Metadata or higher, never
    None."""
    policy = _documents(AUDIT_POLICY)[0]
    rules = policy["rules"]
    uncovered = []
    for group, resource, verb in sorted(_guardian_role_pairs()):
        level = _first_matching_level(rules, verb=verb, group=group, resource=resource)
        if level == "None":
            uncovered.append(f"{verb} {resource} (group {group!r})")
    assert uncovered == [], (
        "these Guardian-Role (resource, verb) pairs fall through to the catch-all None and would leave "  # noqa: E501 - message
        f"no API-server audit record for the cross-check: {uncovered}"
    )


def test_deployment_patch_and_update_are_logged_at_request_level() -> None:
    """Replica counts must be in the body for both verbs (D4-A scale-to-zero, sentinel patches)."""
    rules = _documents(AUDIT_POLICY)[0]["rules"]
    for verb in ("patch", "update"):
        level = _first_matching_level(rules, verb=verb, group="apps", resource="deployments")
        assert level == "Request", (
            f"{verb} on apps/deployments is logged at {level!r}, not Request; the replica count is in "  # noqa: E501 - message
            "the request body and the cross-check and D4-A detection need to see it"
        )


def test_the_mutating_pairs_are_actually_present_so_the_scan_is_not_vacuous() -> None:
    """The Role grants real write verbs, so the coverage test above is checking something."""
    write_verbs = {"create", "update", "patch", "delete", "deletecollection"}
    mutating = {
        (group, resource, verb)
        for group, resource, verb in _guardian_role_pairs()
        if verb in write_verbs
    }
    # pods patch/delete, deployments patch, networkpolicies create/delete, rolebindings
    # patch/delete,
    # jobs/cronjobs delete -- at least these.
    assert ("", "pods", "patch") in mutating
    assert ("", "pods", "delete") in mutating
    assert ("apps", "deployments", "patch") in mutating
    assert ("networking.k8s.io", "networkpolicies", "create") in mutating
    assert len(mutating) >= 6


def test_the_policy_still_ends_in_a_catch_all_none() -> None:
    """Unrelated controller churn is still dropped (ADR-064): the last rule is an unscoped None."""
    rules = _documents(AUDIT_POLICY)[0]["rules"]
    last = rules[-1]
    assert last["level"] == "None"
    assert "verbs" not in last and "resources" not in last and "nonResourceURLs" not in last, (
        "the final rule must be an unscoped catch-all, or some mutations would be logged that the "
        "ADR-064 throughput argument relies on dropping"
    )
