"""Package marker for the Monitor's unit tests.

WHAT PLACING A FILE HERE DOES
-----------------------------
``.github/workflows/ci.yml``'s ``Unit tests -- monitor`` step is guarded by
``hashFiles('monitor/tests/**')``, so it arms itself on the first tracked file under this directory
-- this one. From that commit onward every file here runs on ``ubuntu-latest``, on every push and
every pull request, and a failure here is a red pull request for whoever pushed next. The guard is
not a convention that can be quietly ignored; it is the reason M2's implementation plan records
M2-C4 as a conflict and sequences the CI dependency install *before* the first test file lands.

Three contracts follow, and each is a property of the runner rather than a preference:

**Nothing here may need a cluster, a network, Docker or a running aggregator.** The runner has none
of them. These are unit tests over this repository's own files and its own Python. A test that
reaches for a Kubernetes API, an image registry or a Falco socket is a test that fails in CI for a
reason unrelated to the change under review, and the second time that happens people start ignoring
the job. Verification that genuinely needs a cluster belongs to the bring-up workflow M1 builds.

**Nothing here may import a third-party package beyond pytest and the Monitor's pinned runtime
dependencies.** CI installs ``pytest==8.4.2`` as a literal -- it is development tooling, per ADR-011
-- and then runs ``scripts/install_runtime_deps.sh``, which reads the pins from
``infra/versions.env``, because Pydantic validates every ``EvidenceEvent`` the campaign produces and
is therefore software under study rather than tooling. That set is what is available. In particular
PyYAML is not, and neither is anything that would have to be added to make one assertion convenient.
A test importing a package that merely happens to be installed on a developer's machine passes there
and fails on the runner, which is the failure mode this note exists to prevent.

Two consequences of the same rule are easy to trip over and are worth naming. :mod:`zoneinfo` needs
the ``tzdata`` package on Windows and finds it in the system database on Linux, so a test that
builds a timezone from an IANA name passes in CI and fails on the development host; build fixed
offsets from :class:`datetime.timezone` instead. And the pinned Pydantic version is part of the
contract under test: the exported JSON Schema is a function of the model *and* of the generator that
rendered it, so the drift test in ``test_schema.py`` will also catch a Pydantic upgrade that changes
the export. That is intended -- an upgrade that changes the frozen contract is a contract change and
must be seen -- and the remedy is to regenerate the artefact deliberately, never to loosen the test.

**Nothing here may depend on the working directory.** Each module derives the repository root from
its own ``__file__``, because the step's working directory is a property of the workflow rather than
something a test should assert about.

The marker also makes these modules importable as ``monitor.tests.<module>`` rather than as
top-level modules whose names must be globally unique across every component's test directory. With
five components each owning a ``tests/`` directory, two of them are free to name a file the same
thing without colliding in pytest's module table.
"""
