"""Operational tests for the explicit component landed-state gate in ``make status``."""

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
STATUS = REPO_ROOT / "scripts" / "status.sh"
COMPONENTS = REPO_ROOT / "infra" / "status" / "components.yaml"


@pytest.fixture
def fake_kubectl(tmp_path: Path) -> Path:
    """Provide healthy answers for every landed check without requiring a cluster."""
    shell = shutil.which("sh")
    if shell is None:
        pytest.skip("status.sh requires a POSIX shell")

    binary = tmp_path / "kubectl"
    binary.write_text(
        """#!/bin/sh
case "$*" in
  "config current-context") printf '%s\\n' kind-test ;;
  *"get --raw=/version"*) printf '%s\\n' '{"gitVersion":"v1"}' ;;
  *"get nodes"*) printf 'control-plane|True\\nworker|True\\n' ;;
  *"get deployments"*)
    i=1
    while [ "$i" -le 11 ]; do printf 'workload-%s|1|1\\n' "$i"; i=$((i + 1)); done
    ;;
  *"get daemonset cilium"*|*"get daemonset falco"*|*"get deployment "*) printf '1|1' ;;
  *"get statefulset alertmanager"*) printf '1|1' ;;
  *) printf 'unexpected kubectl invocation: %s\\n' "$*" >&2; exit 1 ;;
esac
""",
        encoding="utf-8",
        newline="\n",
    )
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    return binary


def run_status(
    fake_kubectl: Path,
    components: Path = COMPONENTS,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PATH"] = f"{fake_kubectl.parent}{os.pathsep}{env['PATH']}"
    env["COMPONENTS_FILE"] = str(components)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(  # noqa: S603 - fixed test shell and repository script
        [shutil.which("sh") or "sh", str(STATUS)],  # noqa: S607 - POSIX test shell
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_landed_monitor_and_guardian_workloads_are_required(fake_kubectl: Path) -> None:
    """All four M2 rows and the unrelated Guardian row are checked as landed workloads."""
    result = run_status(fake_kubectl)

    assert result.returncode == 0, result.stderr
    assert "status: PASS" in result.stdout
    assert "daemonset monitor/falco 1/1 ready" in result.stderr
    assert "deployment monitor/falco-falcosidekick 1/1 ready" in result.stderr
    assert "statefulset observability/alertmanager 1/1 ready" in result.stderr
    assert "deployment monitor/evidence-aggregator 1/1 ready" in result.stderr
    assert "deployment guardian/guardian 1/1 ready" in result.stderr
    assert "not-deployed" not in result.stderr


def test_invalid_landed_state_fails_closed(fake_kubectl: Path, tmp_path: Path) -> None:
    registry = tmp_path / "components.yaml"
    registry.write_text(
        COMPONENTS.read_text(encoding="utf-8").replace(
            "    milestone: M2\n    landed: true",
            "    milestone: M2\n    landed: maybe",
            1,
        ),
        encoding="utf-8",
        newline="\n",
    )

    result = run_status(fake_kubectl, registry)

    assert result.returncode == 1
    assert "invalid landed value 'maybe'" in result.stderr


def test_substrate_profile_omits_the_guardian_and_names_the_profile(fake_kubectl: Path) -> None:
    """ADR-148: `UP_PROFILE=substrate` reports the Guardian `not-required`, not `absent`."""
    result = run_status(fake_kubectl, extra_env={"UP_PROFILE": "substrate"})

    assert result.returncode == 0, result.stderr
    assert "status: PASS" in result.stdout
    # The Guardian is reported and skipped -- never queried, so never able to fail the gate.
    assert "not-required" in result.stderr
    assert "deployment guardian/guardian" not in result.stderr
    # A weakened gate must not read as a full one: the summary line names the profile.
    assert "not required in profile substrate" in result.stdout


def test_full_profile_still_requires_the_guardian(fake_kubectl: Path) -> None:
    """The default profile is unchanged: the Guardian is a landed workload that must be ready."""
    result = run_status(fake_kubectl, extra_env={"UP_PROFILE": "full"})

    assert result.returncode == 0, result.stderr
    assert "deployment guardian/guardian 1/1 ready" in result.stderr
    assert "not-required" not in result.stderr
    assert "not required in profile" not in result.stdout


def test_unknown_required_in_value_fails_closed(fake_kubectl: Path, tmp_path: Path) -> None:
    """A `required_in` naming a profile the script does not know is a FAILURE, not a silent skip."""
    registry = tmp_path / "components.yaml"
    registry.write_text(
        COMPONENTS.read_text(encoding="utf-8").replace(
            "    required_in: full",
            "    required_in: staging",
            1,
        ),
        encoding="utf-8",
        newline="\n",
    )

    result = run_status(fake_kubectl, registry)

    assert result.returncode == 1
    assert "invalid required_in value 'staging'" in result.stderr


def test_unknown_up_profile_fails_closed(fake_kubectl: Path) -> None:
    """An unrecognised `UP_PROFILE` is refused before any component is reported."""
    result = run_status(fake_kubectl, extra_env={"UP_PROFILE": "staging"})

    assert result.returncode == 1
    assert "UP_PROFILE is staging, not one of full, substrate" in result.stderr
