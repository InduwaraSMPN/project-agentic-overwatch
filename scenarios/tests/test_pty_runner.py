"""Terminal failures retain the diagnostics required by live delivery triage."""

import os
import sys

import pytest

from scenarios.attackers.apply import _pty_subprocess_runner


@pytest.mark.skipif(os.name != "posix", reason="the live terminal runner is Linux-only")
def test_terminal_failure_keeps_exit_status_and_diagnostic() -> None:
    result = _pty_subprocess_runner(
        [
            sys.executable,
            "-c",
            "import sys; print('target container unavailable',file=sys.stderr); sys.exit(7)",
        ]
    )
    assert result.returncode == 7
    assert "target container unavailable" in result.stdout
