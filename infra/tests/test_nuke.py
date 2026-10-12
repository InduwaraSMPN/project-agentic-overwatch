"""Offline contract tests for scripts/nuke.sh.

The tests execute a copied script in a disposable repository skeleton with fake ``kind``
and no Docker daemon. They exercise host filesystem deletion without touching the real
checkout, a cluster, Docker, or the network.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX shell contract runs on Linux/WSL")

REPO_ROOT = Path(__file__).resolve().parents[2]
NUKE_SCRIPT = REPO_ROOT / "scripts" / "nuke.sh"
STATE_NAMES = ("postgres", "clickhouse", "redis", "minio")


def _sandbox(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    repo = tmp_path / "repo"
    scripts = repo / "scripts"
    scripts.mkdir(parents=True)
    shutil.copyfile(NUKE_SCRIPT, scripts / "nuke.sh")

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    kind = fake_bin / "kind"
    kind.write_text(
        "#!/bin/sh\n"
        'if [ "${1:-}" = get ] && [ "${2:-}" = clusters ]; then exit 0; fi\n'
        'if [ "${1:-}" = delete ]; then exit 0; fi\n'
        "exit 2\n",
        encoding="utf-8",
    )
    kind.chmod(0o755)

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"
    env.pop("FORCE", None)
    return repo, env


def _run(repo: Path, env: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    shell = shutil.which("sh")
    assert shell is not None
    return subprocess.run(  # noqa: S603 - fixed local shell and disposable copied script
        [shell, str(repo / "scripts" / "nuke.sh"), *args],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        stdin=subprocess.DEVNULL,
    )


def _populate_state(repo: Path) -> Path:
    volumes = repo / "infra" / "observability" / "langfuse" / "volumes"
    for name in STATE_NAMES:
        directory = volumes / name
        directory.mkdir(parents=True)
        (directory / "state.bin").write_bytes(name.encode())
    return volumes


def test_force_removes_only_the_four_langfuse_datastore_directories(tmp_path: Path) -> None:
    repo, env = _sandbox(tmp_path)
    volumes = _populate_state(repo)
    keep = volumes / "operator-notes"
    keep.mkdir()
    (keep / "keep.txt").write_text("not datastore state", encoding="utf-8")
    repo_keep = repo / "runs" / "keep.json"
    repo_keep.parent.mkdir()
    repo_keep.write_text("keep", encoding="utf-8")

    env["FORCE"] = "1"
    result = _run(repo, env)

    assert result.returncode == 0, result.stderr
    assert all(not (volumes / name).exists() for name in STATE_NAMES)
    assert (keep / "keep.txt").read_text(encoding="utf-8") == "not datastore state"
    assert repo_keep.read_text(encoding="utf-8") == "keep"
    assert "4 Langfuse datastore path(s) removed" in result.stdout


def test_noninteractive_run_without_force_refuses_and_preserves_state(tmp_path: Path) -> None:
    repo, env = _sandbox(tmp_path)
    volumes = _populate_state(repo)

    result = _run(repo, env)

    assert result.returncode == 1
    assert "REFUSING" in result.stderr
    assert all((volumes / name / "state.bin").is_file() for name in STATE_NAMES)


def test_datastore_symlink_is_unlinked_without_touching_external_target(tmp_path: Path) -> None:
    repo, env = _sandbox(tmp_path)
    volumes = repo / "infra" / "observability" / "langfuse" / "volumes"
    volumes.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("must survive", encoding="utf-8")
    try:
        (volumes / "postgres").symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")

    env["FORCE"] = "1"
    result = _run(repo, env)

    assert result.returncode == 0, result.stderr
    assert not (volumes / "postgres").exists()
    assert sentinel.read_text(encoding="utf-8") == "must survive"


def test_symlinked_state_ancestor_is_rejected_before_any_deletion(tmp_path: Path) -> None:
    repo, env = _sandbox(tmp_path)
    langfuse_parent = repo / "infra" / "observability"
    langfuse_parent.mkdir(parents=True)
    outside = tmp_path / "outside-langfuse"
    volumes = outside / "volumes"
    volumes.mkdir(parents=True)
    sentinel = volumes / "postgres" / "sentinel.txt"
    sentinel.parent.mkdir()
    sentinel.write_text("must survive", encoding="utf-8")
    try:
        (langfuse_parent / "langfuse").symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")

    env["FORCE"] = "1"
    result = _run(repo, env)

    assert result.returncode == 1
    assert "unsafe Langfuse state path" in result.stdout
    assert sentinel.read_text(encoding="utf-8") == "must survive"
