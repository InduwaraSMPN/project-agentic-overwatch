r"""Shared fixtures for the agent layer's suite (M4-T4.1 to T4.7).

WHAT THE FIRST FILE IN THIS DIRECTORY DOES
-------------------------------------------
``.github/workflows/ci.yml``'s ``Unit tests -- agents`` step is guarded by
``hashFiles('agents/tests/**')``, so it arms itself on the first tracked file here. So does the
``Install the pinned runtime dependencies`` step above it, whose guard M4 extended to the union of
``monitor/tests/**``, ``guardian/tests/**`` and ``agents/tests/**`` -- and
``scripts/install_runtime_deps.sh`` gained the ``agents`` component in the same commit, installing
LangGraph, LiteLLM and the two OpenTelemetry distributions from ``infra/versions.env``.
``pyproject.toml`` gained ``"agents/tests/**" = ["S101"]`` there too, so ``make lint`` does not
redden on the first bare ``assert``.

That ordering is the whole content of the M4 plan's conflict M4-C1: three guards fire on the first
tracked file under ``agents/prompts/`` and ``agents/tests/``, and each would otherwise fail for a
**dependency** reason before it could fail for a code one. Everything they need landed in the four
commits before this directory, which is M3's lesson applied -- acquisition and guards land before
the file that arms them.

THE THREE CONTRACTS THIS SUITE INHERITS
-----------------------------------------
``monitor/tests/__init__.py`` states them and they apply here unchanged, so they are not re-argued:
nothing may need a cluster, a network, Docker or a running service; nothing may import a package
outside pytest plus the pinned runtime set (**httpx is not in it**, so the Guardian's ASGI
application is driven directly rather than through ``fastapi.testclient``); and nothing may depend
on the working directory.

There is a fourth, and it belongs to this component alone: **nothing here may spend a provider
token.** Tier A is defined as "no network, no Docker, no credential, no token spent", and every
model in this suite is a script. The live-inference measurements are Tier A′, they need a
credential in ``.env`` that no CI runner has, and they live behind an explicit skip rather than
behind a mock that would let a green suite mean less than it appears to.

WHY THIS DIRECTORY HAS NO ``__init__.py``
--------------------------------------------
The same reason ``guardian/tests/`` has none, and its ``conftest.py`` gives the argument in full:
no component root carries an ``__init__.py``, so pytest's prepend import mode would import every
component's ``tests/`` package under the same top-level name. ``agents/tests/`` follows
``guardian/tests/`` exactly -- a ``conftest.py``, no package marker, and module basenames that are
unique across the repository so that no two suites collide by file name.

WHAT THIS SUITE IS FOR
------------------------
``docs/milestones/M4-agents.md``'s Definition of done asks for six things, and five of them are
properties an ordinary happy-path suite would pass without checking:

1. the golden path completes with per-phase spans and verbatim messages captured [T-05, T-14];
2. ``make parity-check`` passes and emits the token table [T-06];
3. the check asserts **all three** budgets -- prompt tokens, tool calls and turns [T-37];
4. Executors hold no standing credentials and every mutation goes through the Guardian [T-07, T-09];
5. the G1 and G3 arms are exercised, each changing only its target [T-13];
6. the whole-repository gates stay green.

Items 3, 4 and 5 are the ones that need adversarial cases rather than coverage. A parity check can
report green having compared one budget of three; an executor can hold a credential that nothing
looks for; and an arm can change something besides its target without any single-arm test noticing.
So ``test_parity_negative.py`` carries a negative fixture per budget, ``test_executor_env_scan.py``
scans rather than trusts, and ``test_flag_exercise.py`` asserts a *confined* difference rather than
a difference.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# The repository root, put on the import path before anything under `agents` is imported. Derived
# from this file rather than from the caller, because the third contract above is that nothing here
# may depend on the working directory -- and `python -m pytest` puts the *current directory* on
# sys.path, so a suite without these lines passes from the repository root and fails from anywhere
# else with `No module named 'agents'`. guardian/tests/conftest.py carries the same lines for the
# same reason, and a conftest is imported before any test module, so no test file can supply it.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agents.registry.loader import PromptRegistry, load_registry  # noqa: E402 - see above
from harness import InProcessGuardian, build_in_process_guardian  # noqa: E402 - see above


@pytest.fixture(scope="session")
def registry() -> PromptRegistry:
    """The shipped prompt registry, loaded once for the session.

    Session-scoped because loading it reads every block file and every manifest, it is immutable
    once loaded (every dataclass in :mod:`agents.registry.loader` is frozen), and the parity tests
    would otherwise re-read the same forty files a dozen times.
    """
    return load_registry()


@pytest.fixture
def guardian(tmp_path: Path) -> InProcessGuardian:
    """A real Guardian assembled by the production composition root, under a per-test directory.

    Function-scoped and rooted at ``tmp_path``, so each test owns its own audit chain, its own
    replay cache and its own clock. Two tests in one session cannot see each other's state, which
    is what keeps a suite from containing the classic test that passes alone and fails in company.

    Nothing is torn down afterwards, and that is deliberate rather than an omission:
    :class:`~guardian.app.composition.AuditChainSink` publishes ``append`` and nothing else, because
    the chain writer opens and closes the file per record so that a Guardian killed mid-run leaves a
    verifiable chain rather than a truncated buffer. There is no handle here to release.
    """
    return build_in_process_guardian(tmp_path)
