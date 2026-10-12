"""Audit resource spelling is stable across legitimate Kubernetes wire forms (ADR-097)."""

from guardian.app.executor import _bare_resource as executor_bare_resource
from guardian.audit.resource import bare_resource


def test_bare_resource_strips_api_group() -> None:
    assert bare_resource("deployments.apps") == "deployments"
    assert bare_resource("networkpolicies.networking.k8s.io") == "networkpolicies"


def test_bare_resource_preserves_bare_spelling() -> None:
    assert bare_resource("pods") == "pods"


def test_audit_and_executor_resource_normalisation_do_not_drift() -> None:
    spellings = ("pods", "deployments.apps", "networkpolicies.networking.k8s.io")
    assert [bare_resource(value) for value in spellings] == [
        executor_bare_resource(value) for value in spellings
    ]
