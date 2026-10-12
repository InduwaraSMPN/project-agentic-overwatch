"""Static checks on netpol_proof.sh's drop monitor.

Two defects found while unblocking env-bringup, both about the monitor rather than about Cilium's
policy engine:

1. The readiness gate matched only ``Listening for events``. That line is not printed by the FIRST
   ``cilium-dbg monitor`` to attach since the agent last started -- the first prints only
   ``Press Ctrl-C to quit``, and later ones print the longer line first (measured on kind, Cilium
   1.20.1). The same-node case is always first, so it always failed while the cross-node case
   passed on the strength of the first case's attach.
2. ``stop_monitor`` killed only the local ``kubectl exec`` client, leaving the monitor running
   inside the pod; a proof leaked one per case per node.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (ROOT / "scripts" / "netpol_proof.sh").read_text(encoding="utf-8")


def _function(name: str) -> str:
    return SCRIPT.split(f"{name}()", 1)[1].split("\n}", 1)[0]


def test_readiness_gate_accepts_either_cilium_banner() -> None:
    """The first attach after an agent start omits the long line; both wordings must match."""
    body = _function("start_drop_monitor")
    assert "'Listening for events'" in body
    assert "'Press Ctrl-C to quit'" in body


def test_stop_monitor_ends_the_monitor_inside_the_pod_too() -> None:
    """Killing the local kubectl client does not stop `cilium-dbg monitor` in the container."""
    body = _function("stop_monitor")
    assert 'kill "$monitor_pid"' in body
    assert "pkill -f" in body
    assert "monitor --type drop" in body


def test_the_remote_monitor_is_only_killed_when_one_was_started() -> None:
    """A proof that never started a monitor must not pkill anything."""
    assert 'monitor_remote_pod=""' in SCRIPT
    assert 'monitor_remote_bin=""' in SCRIPT
    body = _function("stop_monitor")
    assert '[ -n "$monitor_remote_pod" ] && [ -n "$monitor_remote_bin" ]' in body
