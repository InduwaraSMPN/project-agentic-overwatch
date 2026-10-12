r"""Shared fixtures for the Guardian's adversarial and flag-isolation suite (M3-T3.7, M3-T3.8).

WHAT THE FIRST FILE IN THIS DIRECTORY DOES
-------------------------------------------
``.github/workflows/ci.yml``'s ``Unit tests -- guardian`` step is guarded by
``hashFiles('guardian/tests/**')``, so it arms itself on the first tracked file here. So does the
``Install the pinned runtime dependencies`` step above it, guarded on the union of
``monitor/tests/**`` and ``guardian/tests/**``, which installs FastAPI, PyJWT and Pydantic from
``infra/versions.env`` through ``scripts/install_runtime_deps.sh``. That ordering is the whole
content of the M3 plan's conflict M3-C3: the dependency install had to land *before* the first test
file, or this suite would fail on ``import fastapi`` in the commit that introduced it. It has
landed, so arming here is deliberate and the suite is expected green from this commit onward.

The three contracts ``monitor/tests/__init__.py`` states apply here unchanged and are not
re-argued: nothing may need a cluster, a network, Docker or a running service; nothing may import a
package outside pytest plus the pinned runtime set (FastAPI, PyJWT, Pydantic -- **httpx is not in
it**, so the ASGI application is driven directly rather than through ``fastapi.testclient``); and
nothing may depend on the working directory.

WHY THIS DIRECTORY HAS NO ``__init__.py`` WHEN ``monitor/tests/`` AND ``infra/tests/`` DO
------------------------------------------------------------------------------------------
Deliberate, and worth stating because the obvious tidy-up breaks something. Neither ``monitor/`` nor
``infra/`` nor ``guardian/`` carries an ``__init__.py``, so pytest's prepend import mode walks up
from a test file only as far as the last directory that has one -- which means every component's
``tests/`` package is imported under the *same* top-level name, ``tests``. ``infra`` and ``monitor``
coexist today because neither holds a ``conftest.py``; adding one here binds ``tests`` to
``guardian/tests`` at collection time, and every ``monitor/tests`` module then fails to import.
CI is unaffected -- it runs each component's suite in its own ``python -m pytest <dir>`` step -- but
a bare ``pytest`` at the repository root would report nine collection errors that all point at the
Monitor, which is the worst possible place for them to appear.

So this directory carries a ``conftest.py`` and no package marker, and the CI-arming note that
would have lived in the marker lives above. The proper fix is a ``guardian/__init__.py``, which
would make these modules ``guardian.tests.<name>`` and remove the collision outright; that is a file
outside this task's scope and is recorded as owed rather than taken quietly. Until it lands, do not
add ``guardian/tests/__init__.py``.

WHAT THIS SUITE IS FOR, WHICH IS NOT WHAT MOST SUITES ARE FOR
--------------------------------------------------------------
``docs/milestones/M3-guardian.md``'s Definition of done asks for one thing here, and it is a
security claim rather than a coverage number: every adversarial case **denied**, with a
**structured reason code** rather than a free-text message, and **present in the audit chain**. All
three, per case. The M3 plan gives the reason in one sentence -- a denial the audit log does not
contain fails ``docs/protocols/security-policy.md`` section 1.4, and T-22's scoring reads that log,
so an unaudited block is invisible to the evaluation whether or not it happened.

M3's failure mode is silent. A Guardian that permits what it should deny passes every test that
only asks whether the happy path works, and the audit log of a run it mishandled looks exactly like
the audit log of a run it handled correctly. So the suite is written from
``docs/plans/M3-implementation-plan.md``'s threat model rather than from the code: the adversary is
the LLM layer, it holds arbitrary request content (P1), arbitrary token bytes (P2), unbounded
volume and ordering (P3) and network reach to this HTTP surface (P4), and every case is one of
those positions exercised.

HOW "ALL THREE, PER CASE" IS MADE STRUCTURAL RATHER THAN REMEMBERED
--------------------------------------------------------------------
Three mechanisms, because a convention that depends on the next person reading this paragraph is
not a mechanism.

1. Every case runs through :meth:`guardian.tests.harness.GuardianHarness.submit`, which returns a
   :class:`~guardian.tests.harness.CaseOutcome`. That object exposes no accessor for the decision
   alone. The only ways out of it are :meth:`~guardian.tests.harness.CaseOutcome.assert_denied` and
   :meth:`~guardian.tests.harness.CaseOutcome.assert_permitted`, and each asserts all three
   properties before returning anything.
2. :attr:`~guardian.tests.harness.CaseOutcome.record` and
   :attr:`~guardian.tests.harness.CaseOutcome.result` raise until one of those has run, so a test
   that wants to inspect the outcome cannot get at it without having made the full assertion first.
3. ``test_suite_integrity.py`` walks the abstract syntax tree of every ``test_adversarial_*.py``
   module and fails if any test function does not call one of them. A case added later without the
   triple assertion breaks the build rather than passing quietly.

WHAT IS DELIBERATELY NOT HERE
------------------------------
*A policy.* ``guardian/app/policy.py`` refuses to implement a decision procedure in Python "for the
tests", because two policies diverge and nobody notices until an evaluation depends on it. The
engine doubles in ``harness.py`` therefore return **canned answers**, in the way
``guardian.app.mediation.FakeActionExecutor`` returns a canned execution outcome. None of them
looks at the input document to decide.

*Any ``security-policy.md`` section 2 value except the algorithm.* The token lifetime, the ceiling
and the replay cache's two bounds reach the Guardian as configuration and the suite supplies its
own -- small, obviously synthetic, and labelled as suite parameters exactly as
``guardian/audit/fixtures/corpus.json`` labels its own. The one mirrored value is the JWS
algorithm, which is not a tunable: the ``alg: none`` and algorithm-confusion cases are *about* the
allowlist holding exactly one specific algorithm. It is mirrored beside a check that section 2
still names it.

*Any real-looking credential.* The signing material in ``harness.py`` is a synthetic string that
begins by saying so. ``pyproject.toml`` grants this directory ``S101`` and nothing else, so ruff's
security rules still apply here in full -- which is the right way round, since the Guardian's
adversarial suite is where a fixture carrying a real-looking secret would be most tempting and most
damaging.
"""

import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

# The repository root, derived from this file rather than from the working directory, so that a
# bare `pytest guardian/tests` and CI's `python -m pytest guardian/tests` resolve imports the same
# way. The `-m` form happens to put the working directory on the path; the bare form does not, and
# a suite whose imports depend on which one was typed is a suite that fails for the wrong reason.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from guardian.tests.harness import GuardianHarness, make_harness  # noqa: E402


@pytest.fixture
def harness(tmp_path: Path) -> GuardianHarness:
    """One Guardian in the default arm, with its own chain file, cache and clock.

    Function-scoped and rooted at ``tmp_path`` deliberately: an adversarial case that shared a
    replay cache or an audit chain with the case before it would pass or fail depending on
    collection order, and a suite whose result depends on collection order is not evidence.
    """
    return make_harness(tmp_path)


@pytest.fixture
def harness_factory(tmp_path: Path) -> Callable[..., GuardianHarness]:
    """Build differently-configured Guardians inside one test, each with its own directory.

    Needed wherever a case is *about* the configuration -- the mode diff, the engine-failure cases,
    the run-id and phase bindings. Each call gets its own subdirectory so two Guardians in one test
    never share an audit chain.
    """
    built: list[GuardianHarness] = []

    def build(**kwargs: Any) -> GuardianHarness:
        root = tmp_path / f"guardian-{len(built):02d}"
        root.mkdir(parents=True, exist_ok=True)
        instance = make_harness(root, **kwargs)
        built.append(instance)
        return instance

    return build
