"""Package marker for infra/'s unit tests.

docs/04-repo-conventions.md section 1 places each component's tests inside that component and
requires them to be runnable standalone, and .github/workflows/ci.yml gives infra/ its own pytest
step, guarded by ``hashFiles('infra/tests/**')``. That guard arms on the first tracked file placed
here, so from this milestone onward every file under infra/tests/ runs on ubuntu-latest.

Two consequences follow, and both are contracts rather than preferences:

Nothing here may need a cluster, a network, Docker or Locust. The CI runner has none of them. The
tests are unit tests over this repository's own files -- the load-profile registry, the pinned
manifests, versions.env -- and a test that reaches for a Kubernetes API is a test that will fail in
CI for a reason unrelated to the change under review. Verification that genuinely needs a running
environment belongs to the fresh-clone bring-up workflow planned at M1-T1.7, which builds one.

Nothing here may import a third-party package other than pytest. CI's test step installs
``pytest==8.4.2`` and nothing else, so PyYAML in particular is unavailable; anything that needs to
read YAML in this tree reads it through the standard-library subset parser in
infra/locust/registry.py. A test that imports PyYAML passes on a developer machine that happens to
have it and fails on the runner, which is the failure mode this note exists to prevent.

The marker itself is what makes the test modules importable as ``infra.tests.<module>`` rather than
as top-level modules whose names must be globally unique across every component's test directory.
Once monitor/, guardian/, agents/ and runner/ have tests of their own, two components are free to
name a test file the same thing without colliding in pytest's module table.
"""
