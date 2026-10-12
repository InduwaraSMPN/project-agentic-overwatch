"""scripts/guardian_deploy.sh requires each attempt's own audit chain, and refuses before kubectl.

ADR-058 completes ADR-054 on the Guardian side: the runner names one attempt-unique chain per
attempt and passes it as ``GUARDIAN_AUDIT_LOG_PATH``; the deploy script requires it, with no
default, and refuses any value that is not a ``.jsonl`` chain for this run directly on the
Guardian's audit volume. Every refusal must happen before the script touches the cluster, so each
case runs the script with a stand-in ``kubectl`` first on ``PATH`` that records its argv and fails
-- and with ``KUBECONFIG`` and ``HOME`` pointed at nothing, so no real configuration could be
reached even if the stand-in were bypassed. The accepted case proves the check lets a valid path
through: the first thing it reaches is the stand-in, asked about the run lock lease and then to
apply the RBAC manifest.

The run lock lease (ADR-087, supervisor ruling B6) is checked between those two: the stand-in
answers ``kubectl get lease`` from ``STAND_IN_LEASE_LINE`` when the test sets one (the same
``holderIdentity|renewTime|leaseDurationSeconds`` line real jsonpath would print), and otherwise
reports the lease absent, which is what lets every audit-path test below reach the same "no lease"
branch as ``make up`` bring-up without having to say so.
"""

import os
import re
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from runner.live_evidence import GUARDIAN_AUDIT_ROOT, attempt_suffix, guardian_audit_chain_path
from runner.run_lock import LEASE_DURATION_SECONDS

REPO_ROOT = Path(__file__).resolve().parents[2]
DEPLOY_SCRIPT = REPO_ROOT / "scripts" / "guardian_deploy.sh"
DEPLOYMENT_MANIFEST = REPO_ROOT / "guardian" / "deploy" / "deployment.yaml"
RUN_ID = "RUN-G0-FULL-SCN-SIM-01-INJ-NONE-102"
OTHER_RUN_ID = "RUN-G1-LOGONLY-SCN-SIM-01-INJ-NONE-102"

# The settings the script requires besides the audit path. Placeholders: none is parsed before the
# first kubectl call, and none is shaped like the protocol value it stands in for. The control-plane
# identity pair (ADR-128) is in the required-settings loop too, so it must be present here or the
# script would refuse on it before ever reaching the audit-path check or the cluster.
_OTHER_SETTINGS = {
    "GUARDIAN_RUN_ID": RUN_ID,
    "GUARDIAN_REGISTERED_ISSUERS": "supervisor-containment",
    "GUARDIAN_TOKEN_TTL_SECONDS": "placeholder",
    "GUARDIAN_TOKEN_MAX_TTL_SECONDS": "placeholder",
    "GUARDIAN_TOKEN_ALGORITHM": "placeholder",
    "GUARDIAN_REPLAY_CACHE_ENTRIES": "placeholder",
    "GUARDIAN_REPLAY_CACHE_WINDOW_SECONDS": "placeholder",
    "GUARDIAN_CONTROL_PLANE_SUBJECT": "placeholder",
    "GUARDIAN_CONTROL_PLANE_AUDIENCE": "placeholder",
}

# Every argv the real script issues is logged; only `get lease` is ever answered with success, and
# only when the test asks for it, so the default behaviour for every pre-existing test below is
# unchanged: "no lease" (a NotFound on stderr), then fail on the very next call, exactly as before
# this row existed.
_STAND_IN_KUBECTL = """#!/bin/sh
printf '%s\\n' "$*" >> "$STAND_IN_KUBECTL_LOG"
case "$*" in
    *"get lease"*)
        if [ -n "${STAND_IN_LEASE_LINE:-}" ]; then
            printf '%s' "$STAND_IN_LEASE_LINE"
            exit 0
        fi
        echo 'Error from server (NotFound): leases.coordination.k8s.io "x" not found' >&2
        exit 1
        ;;
esac
exit 1
"""


def _lease_line(holder_run_id: str, renew_time: datetime, duration: int = 3600) -> str:
    """A canned ``kubectl get lease -o jsonpath=...`` line naming one holder, for the stand-in."""
    renewed = renew_time.astimezone(UTC).isoformat().replace("+00:00", "Z")
    return f"{holder_run_id}/2026-09-13T00:00:00Z/test-host/1|{renewed}|{duration}"


def _run_deploy(
    tmp_path: Path,
    audit_log_path: str | None,
    *,
    lease_line: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    """Run the deploy script against the stand-in kubectl; return the result and kubectl's calls."""
    shell = shutil.which("sh")
    if shell is None:
        pytest.skip("no POSIX sh on PATH; scripts/guardian_deploy.sh is strict POSIX sh")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stand_in = bin_dir / "kubectl"
    stand_in.write_text(_STAND_IN_KUBECTL, encoding="utf-8")
    stand_in.chmod(0o755)
    log = tmp_path / "kubectl-calls.log"
    environment = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        "HOME": str(tmp_path),
        "KUBECONFIG": str(tmp_path / "no-such-kubeconfig"),
        "STAND_IN_KUBECTL_LOG": str(log),
        **_OTHER_SETTINGS,
    }
    if audit_log_path is not None:
        environment["GUARDIAN_AUDIT_LOG_PATH"] = audit_log_path
    if lease_line is not None:
        environment["STAND_IN_LEASE_LINE"] = lease_line
    if extra_env:
        environment.update(extra_env)
    completed = subprocess.run(  # noqa: S603 - the repository's own script under a resolved sh
        [shell, str(DEPLOY_SCRIPT)],
        cwd=str(REPO_ROOT),
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return completed, calls


@pytest.mark.parametrize(
    "audit_log_path",
    [
        pytest.param(None, id="unset"),
        pytest.param("", id="empty"),
        pytest.param(f"{GUARDIAN_AUDIT_ROOT}/{RUN_ID}.jsonl", id="run-id-only"),
        pytest.param(f"/var/lib/guardian/{RUN_ID}-attempt.jsonl", id="above-the-volume"),
        pytest.param(f"{GUARDIAN_AUDIT_ROOT}/../{RUN_ID}-attempt.jsonl", id="traversal"),
        pytest.param(f"{GUARDIAN_AUDIT_ROOT}/nested/{RUN_ID}-attempt.jsonl", id="nested"),
        pytest.param(f"{GUARDIAN_AUDIT_ROOT}/{OTHER_RUN_ID}-attempt.jsonl", id="another-run"),
        pytest.param(f"{GUARDIAN_AUDIT_ROOT}/{RUN_ID}-.jsonl", id="empty-suffix"),
        pytest.param(f"{GUARDIAN_AUDIT_ROOT}/{RUN_ID}-attempt.log", id="not-a-chain"),
        pytest.param(f"{GUARDIAN_AUDIT_ROOT}/guardian_replay.sqlite3", id="the-replay-store"),
    ],
)
def test_the_deploy_script_refuses_anything_but_this_attempts_chain_before_kubectl(
    tmp_path: Path, audit_log_path: str | None
) -> None:
    """Fail closed, name the setting, and never reach the cluster."""
    completed, calls = _run_deploy(tmp_path, audit_log_path)
    assert completed.returncode != 0
    assert "GUARDIAN_AUDIT_LOG_PATH" in completed.stderr, completed.stderr
    assert calls == [], f"the script reached kubectl before refusing: {calls}"


def test_a_chain_the_runner_named_for_this_attempt_is_let_through(tmp_path: Path) -> None:
    """The path the runner builds passes the check; the next real call is the RBAC manifest.

    No ``STAND_IN_LEASE_LINE`` is set, so the stand-in reports the run lock lease absent -- the
    same "no lease" branch ``make up`` bring-up relies on -- and the script proceeds past it.
    """
    path = guardian_audit_chain_path(GUARDIAN_AUDIT_ROOT, RUN_ID, attempt_suffix())
    completed, calls = _run_deploy(tmp_path, path)
    assert "GUARDIAN_AUDIT_LOG_PATH" not in completed.stderr, completed.stderr
    assert calls[0].startswith("-n guardian get lease live-run-lock"), calls
    assert calls[1:2] == ["apply -f guardian/deploy/rbac.yaml"], calls
    assert completed.returncode != 0, "the stand-in fails the first cluster call, by design"


# --------------------------------------------------------------------------------------------
# The run lock lease (ADR-087, supervisor ruling B6): refuse a fresh foreign holder before
# touching the ConfigMap -- indeed before touching anything -- and let every other case through.
# --------------------------------------------------------------------------------------------


def test_refuses_a_fresh_foreign_holder_before_touching_the_cluster(tmp_path: Path) -> None:
    path = guardian_audit_chain_path(GUARDIAN_AUDIT_ROOT, RUN_ID, attempt_suffix())
    line = _lease_line(OTHER_RUN_ID, datetime.now(UTC))
    completed, calls = _run_deploy(tmp_path, path, lease_line=line)
    assert completed.returncode != 0
    assert OTHER_RUN_ID in completed.stderr, completed.stderr
    assert RUN_ID in completed.stderr, completed.stderr
    assert calls == [
        "-n guardian get lease live-run-lock "
        "-o jsonpath={.spec.holderIdentity}|{.spec.renewTime}|{.spec.leaseDurationSeconds}"
    ], "must refuse without reaching rbac.yaml or anything else"


def test_allows_a_stale_foreign_holder(tmp_path: Path) -> None:
    path = guardian_audit_chain_path(GUARDIAN_AUDIT_ROOT, RUN_ID, attempt_suffix())
    stale = datetime.now(UTC) - timedelta(seconds=LEASE_DURATION_SECONDS + 100)
    line = _lease_line(OTHER_RUN_ID, stale)
    completed, calls = _run_deploy(tmp_path, path, lease_line=line)
    assert calls[1:2] == ["apply -f guardian/deploy/rbac.yaml"], calls
    assert completed.returncode != 0, "the stand-in fails the first cluster call, by design"


def test_allows_a_fresh_lease_already_held_by_this_run(tmp_path: Path) -> None:
    """The normal case: the runner acquired the lease under GUARDIAN_RUN_ID moments earlier."""
    path = guardian_audit_chain_path(GUARDIAN_AUDIT_ROOT, RUN_ID, attempt_suffix())
    line = _lease_line(RUN_ID, datetime.now(UTC))
    completed, calls = _run_deploy(tmp_path, path, lease_line=line)
    assert calls[1:2] == ["apply -f guardian/deploy/rbac.yaml"], calls
    assert completed.returncode != 0, "the stand-in fails the first cluster call, by design"


def test_allows_a_fresh_lease_held_by_the_campaign_this_attempt_runs_under(tmp_path: Path) -> None:
    """ADR-101/ADR-104: a campaign-span holder is not foreign to an attempt it drives."""
    path = guardian_audit_chain_path(GUARDIAN_AUDIT_ROOT, RUN_ID, attempt_suffix())
    line = _lease_line("CAMP-20260914-campaign", datetime.now(UTC))
    holder = line.split("|", 1)[0]
    completed, calls = _run_deploy(
        tmp_path, path, lease_line=line, extra_env={"RUNNER_CAMPAIGN_LEASE_HOLDER": holder}
    )
    assert calls[1:2] == ["apply -f guardian/deploy/rbac.yaml"], calls
    assert completed.returncode != 0, "the stand-in fails the first cluster call, by design"


def test_refuses_a_fresh_campaign_holder_this_attempt_does_not_run_under(tmp_path: Path) -> None:
    """Only an exact holder-identity match is accepted; another campaign is still foreign."""
    path = guardian_audit_chain_path(GUARDIAN_AUDIT_ROOT, RUN_ID, attempt_suffix())
    line = _lease_line("CAMP-20260914-campaign", datetime.now(UTC))
    other = "CAMP-20260101-other/2026-09-13T00:00:00Z/test-host/2"
    completed, calls = _run_deploy(
        tmp_path, path, lease_line=line, extra_env={"RUNNER_CAMPAIGN_LEASE_HOLDER": other}
    )
    assert completed.returncode != 0
    assert "CAMP-20260914-campaign" in completed.stderr, completed.stderr
    assert len(calls) == 1, "must refuse without reaching rbac.yaml or anything else"


def test_the_audit_volume_has_one_spelling_across_manifest_script_and_runner() -> None:
    """deployment.yaml's mount, the script's check and the runner's root name one directory."""
    manifest = DEPLOYMENT_MANIFEST.read_text(encoding="utf-8")
    mount = re.search(r"-\s*name:\s*audit\s*\n\s*mountPath:\s*(\S+)", manifest)
    assert mount is not None, "guardian/deploy/deployment.yaml mounts no volume named audit"
    declared = re.search(
        r"^audit_dir=(\S+)\s*$", DEPLOY_SCRIPT.read_text(encoding="utf-8"), re.MULTILINE
    )
    assert declared is not None, "scripts/guardian_deploy.sh declares no audit_dir"
    assert mount.group(1) == declared.group(1) == GUARDIAN_AUDIT_ROOT
