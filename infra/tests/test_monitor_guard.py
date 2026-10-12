"""Black-box regression tests for the Monitor's static non-inference boundary.

These tests live outside ``monitor/`` deliberately: rule 40 scans that entire tree with no test
exemption, so a test fixture containing the forbidden process-launch constructs belongs outside the
boundary it attacks. A tiny read-only ``git`` double supplies the tracked-file listing; no temporary
repository or index mutation is needed.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GUARD = REPO_ROOT / "scripts" / "monitor_guard.sh"
SH = shutil.which("sh")
if os.name == "nt":
    git = shutil.which("git")
    if git is not None:
        git_bash = Path(git).resolve().parents[1] / "bin" / "bash.exe"
        if git_bash.is_file():
            SH = str(git_bash)


@pytest.fixture
def guard_repo(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    """Return an isolated guard checkout and environment with one tracked Monitor file."""
    scripts = tmp_path / "scripts"
    monitor = tmp_path / "monitor"
    bin_dir = tmp_path / "bin"
    scripts.mkdir()
    monitor.mkdir()
    bin_dir.mkdir()
    shutil.copyfile(GUARD, scripts / GUARD.name)

    fake_git = bin_dir / "git"
    fake_git.write_bytes(
        b"#!/bin/sh\n"
        b'case " $* " in\n'
        b"  *\" -z \"*) printf 'monitor/candidate.py\\0' ;;\n"
        b"  *) printf 'monitor/candidate.py\\n' ;;\n"
        b"esac\n"
    )
    fake_git.chmod(0o755)

    env = os.environ.copy()
    if os.name == "nt":
        drive, tail = bin_dir.as_posix().split(":", 1)
        shell_bin_dir = f"/{drive.lower()}{tail}"
        env["GUARD_TEST_BIN"] = shell_bin_dir
    else:
        env["GUARD_TEST_BIN"] = str(bin_dir)
    return tmp_path, env


def run_guard(repo: Path, env: dict[str, str], source: str) -> subprocess.CompletedProcess[str]:
    """Write the sole tracked Monitor file and run the real guard against it."""
    assert SH is not None, "the repository's POSIX shell guards require sh on PATH"
    (repo / "monitor" / "candidate.py").write_text(source, encoding="utf-8")
    return subprocess.run(  # noqa: S603 - resolved shell and repo-local copied script
        [SH, "-c", f'PATH="$GUARD_TEST_BIN:$PATH" exec sh scripts/{GUARD.name}'],
        cwd=repo,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize(
    "source",
    (
        "import subprocess\nsubprocess.run(['claude', '-p', 'triage'])\n",
        "from subprocess import check_output\ncheck_output(['ollama', 'run', 'model'])\n",
        "import os\nos.system('openai api chat.completions.create')\n",
        "from os import spawnvp\nspawnvp(0, 'gemini', ['gemini', '-p', 'triage'])\n",
        "#!/bin/sh\nollama run model\n",
        "#!/bin/sh\nexec claude --print triage\n",
    ),
)
def test_monitor_guard_rejects_process_and_provider_cli_routes(
    guard_repo: tuple[Path, dict[str, str]], source: str
) -> None:
    repo, env = guard_repo
    result = run_guard(repo, env, source)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "process-execution" in result.stderr or "provider-cli" in result.stderr


@pytest.mark.parametrize(
    "source",
    (
        "import os\nHERE = os.path.dirname(__file__)\n",
        "# Claude is named here as documentation, not executed.\n",
        "provider = 'internal'\ncommand = ['printf', provider]\n",
    ),
)
def test_monitor_guard_allows_non_launch_os_use_and_provider_prose(
    guard_repo: tuple[Path, dict[str, str]], source: str
) -> None:
    repo, env = guard_repo
    result = run_guard(repo, env, source)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "monitor-guard: PASS" in result.stdout
    assert "against 7 pattern families" in result.stdout
