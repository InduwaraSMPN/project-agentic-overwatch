"""Canonical Kubernetes resource spelling for audit consumers (ADR-097).

Guardian audit records legitimately carry either a bare resource (``deployments``) or the same
resource qualified by its API group (``deployments.apps``). Scoring compares their bare spellings
so wire-format choice cannot hide a matching action.
"""

from __future__ import annotations

__all__ = ("bare_resource",)


def bare_resource(resource: str) -> str:
    """Return the Kubernetes resource name without its optional API-group suffix."""
    return resource.split(".", 1)[0]
