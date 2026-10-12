"""Backup restores must verify raw file hashes, including baseline bundles."""

# ruff: noqa: S101, S603 - assertions and controlled subprocesses exercise the shell entrypoint
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_restore_rejects_corrupted_raw_file(tmp_path: Path) -> None:
    shell = shutil.which("bash")
    if sys.platform == "win32":
        shell = r"C:\Program Files\Git\bin\bash.exe"
    if not shell or not Path(shell).is_file():
        pytest.skip("POSIX shell unavailable")
    copy = tmp_path / "baseline-copy"
    copy.mkdir()
    raw = copy / "resource_usage.csv"
    raw.write_bytes(b"timestamp,storage_bytes\n0,123\n")
    (copy / "seal.json").write_text(
        json.dumps({"content_hashes": {raw.name: hashlib.sha256(raw.read_bytes()).hexdigest()}}),
        encoding="utf-8",
    )
    env = dict(os.environ, PYTHON=Path(sys.executable).as_posix())
    command = [shell, "scripts/backup_sync.sh", "--verify-restore", copy.as_posix()]
    good = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True)
    assert good.returncode == 0, good.stdout + good.stderr
    raw.write_bytes(b"corrupted")
    bad = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True)
    assert bad.returncode != 0
    assert "content hash mismatch" in bad.stderr
