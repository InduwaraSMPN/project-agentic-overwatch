"""Layer 12's namespace applies must not race the ServiceAccount controller.

ADR-142 decision (a) fixed the ``AlreadyExists`` race for ``agents-default-deny.yaml`` and believed
``infra/probes/deploy/namespace.yaml`` was safe. It is not: the race is a property of any manifest
that declares a Namespace together with that namespace's ``default`` ServiceAccount, and both files
have that shape. The first cold-cluster bring-up to reach layer 12 failed on the probe namespace
with the identical message, so this test pins both files to the one helper that closes the window.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UP = (ROOT / "scripts" / "up.sh").read_text(encoding="utf-8")
PROBE_MANIFEST = (ROOT / "infra" / "probes" / "deploy" / "namespace.yaml").read_text(
    encoding="utf-8"
)
LIVE_BASELINE = (ROOT / "runner" / "live_baseline.py").read_text(encoding="utf-8")


def test_both_namespace_manifests_go_through_the_race_tolerant_helper() -> None:
    """One helper, called by (a) and (b); neither manifest is applied bare any more."""
    assert "apply_namespace_manifest()" in UP
    assert 'apply_namespace_manifest "$AGENTS_NETPOL" agents "scenario/run prerequisites"' in UP
    assert (
        'apply_namespace_manifest "$PROBE_NAMESPACE_MANIFEST" "$PROBE_NAMESPACE" '
        '"scenario/run prerequisites"' in UP
    )


def test_no_bare_apply_of_either_namespace_manifest_remains() -> None:
    """The exact regression: a bare `kubectl apply -f` of a Namespace-plus-`default`-SA file."""
    assert 'kubectl apply -f "$AGENTS_NETPOL"' not in UP
    assert 'kubectl apply -f "$PROBE_NAMESPACE_MANIFEST"' not in UP


def test_the_helper_creates_the_namespace_then_waits_before_applying() -> None:
    """Order matters: create, wait for the controller's `default` SA, then apply."""
    helper = UP.split("apply_namespace_manifest()", 1)[1].split("\n}", 1)[0]
    assert 'ensure_namespace "$apply_namespace"' in helper
    assert 'kubectl -n "$apply_namespace" get serviceaccount default' in helper
    apply_line = 'kubectl apply -f "$apply_manifest"'
    assert apply_line in helper
    # The wait must come before the apply, or the window is open again.
    assert helper.index("serviceaccount default") < helper.index(apply_line)


def test_probe_namespace_is_named_identically_wherever_it_is_spelled() -> None:
    """The manifest, the layer-12 constant and live_baseline must agree on the name."""
    assert "name: slo-probe" in PROBE_MANIFEST
    assert "PROBE_NAMESPACE=slo-probe" in UP
    assert 'PROBE_NAMESPACE: Final = "slo-probe"' in LIVE_BASELINE
