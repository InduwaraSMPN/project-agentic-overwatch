"""The single-run lock: one live run at a time, refused loudly rather than corrupting two."""

from __future__ import annotations

import json
import os
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from runner import run_lock
from runner.run_lock import (
    LOCK_NAME,
    ClusterLeaseError,
    RunLockHeld,
    cluster_lease,
    cluster_run_lock,
)


def test_a_second_run_is_refused_while_the_first_holds_the_cluster(tmp_path: Path) -> None:
    with cluster_run_lock(tmp_path, "RUN-A"):
        with pytest.raises(RunLockHeld, match="RUN-A"):
            with cluster_run_lock(tmp_path, "RUN-B"):
                pytest.fail("the second run must not acquire the lock")


def test_the_lock_is_released_so_the_next_run_can_take_it(tmp_path: Path) -> None:
    with cluster_run_lock(tmp_path, "RUN-A"):
        pass
    assert not (tmp_path / LOCK_NAME).exists()
    with cluster_run_lock(tmp_path, "RUN-B") as held:
        assert json.loads(held.read_text(encoding="utf-8"))["run_id"] == "RUN-B"


def test_the_lock_is_released_even_when_the_run_raises(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="run failed"):
        with cluster_run_lock(tmp_path, "RUN-A"):
            raise ValueError("run failed")
    assert not (tmp_path / LOCK_NAME).exists()


@pytest.mark.skipif(os.name != "posix", reason="liveness is only decidable on POSIX")
def test_a_lock_left_by_a_dead_process_is_taken_over(tmp_path: Path) -> None:
    """A runner killed hard leaves its lock behind; the next run must not be blocked forever."""
    lock = tmp_path / LOCK_NAME
    lock.write_text(
        json.dumps({"pid": 2**22, "run_id": "RUN-DEAD", "host": "x", "started_at": "now"}),
        encoding="utf-8",
    )
    with cluster_run_lock(tmp_path, "RUN-B") as held:
        assert json.loads(held.read_text(encoding="utf-8"))["run_id"] == "RUN-B"


def test_an_unreadable_lock_does_not_wedge_the_runner(tmp_path: Path) -> None:
    """A truncated or half-written lock names no live holder, so it is taken over, not obeyed."""
    (tmp_path / LOCK_NAME).write_text("{not json", encoding="utf-8")
    with cluster_run_lock(tmp_path, "RUN-B") as held:
        assert json.loads(held.read_text(encoding="utf-8"))["run_id"] == "RUN-B"


# --------------------------------------------------------------------------------------------
# The cluster Lease (ADR-087, supervisor ruling B6): the same guarantee, visible across
# checkouts. Fakes are a small in-memory Lease store rather than a scripted call transcript, so
# a test describes cluster *state* -- a lease held by X, or none -- and gets the API server's
# real compare-and-swap behaviour (an AlreadyExists on a second create, a Conflict on a second
# replace) for free, exactly as the real object would.
# --------------------------------------------------------------------------------------------

_NOT_FOUND = 'Error from server (NotFound): leases.coordination.k8s.io "live-run-lock" not found\n'
_CONFLICT = (
    "Error from server (Conflict): the object has been modified; please apply your changes to "
    "the latest version and try again\n"
)
_ALREADY_EXISTS = (
    'Error from server (AlreadyExists): leases.coordination.k8s.io "live-run-lock" already exists\n'
)


class _FakeLeaseCluster:
    """A working fake of the one Lease object this module reads and writes.

    ``initial``, when given, is a ``(holder_identity, renew_time, lease_duration_seconds)`` triple
    describing the lease as it stands before the test's ``cluster_lease`` call runs.
    """

    def __init__(
        self,
        initial: tuple[str, datetime, int] | None = None,
        *,
        race_winner: tuple[str, datetime, int] | None = None,
        resource_version: int = 1,
    ) -> None:
        self._resource_version = resource_version
        self._lease: dict[str, object] | None = None
        if initial is not None:
            self._lease = self._lease_body(*initial)
        # Consumed on the first `create` only, and only when no lease is otherwise present: models
        # a second writer's create landing in the gap between this process's own `get` and
        # `create`, exactly the race _acquire_lease retries against.
        self._race_winner = race_winner
        self.calls: list[list[str]] = []

    def _lease_body(self, holder: str, renew_time: datetime, duration: int) -> dict[str, object]:
        return {
            "metadata": {
                "name": run_lock.LEASE_NAME,
                "namespace": run_lock.LEASE_NAMESPACE,
                "resourceVersion": str(self._resource_version),
            },
            "spec": {
                "holderIdentity": holder,
                "renewTime": run_lock._format_rfc3339(renew_time),
                "leaseDurationSeconds": duration,
            },
        }

    def __call__(
        self, argv: list[str], *, stdin: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        assert argv[:2] == ["-n", run_lock.LEASE_NAMESPACE], argv
        verb = argv[2]
        if verb == "get":
            if self._lease is None:
                return subprocess.CompletedProcess(argv, 1, "", _NOT_FOUND)
            return subprocess.CompletedProcess(argv, 0, json.dumps(self._lease), "")
        if verb == "create":
            if self._lease is not None:
                return subprocess.CompletedProcess(argv, 1, "", _ALREADY_EXISTS)
            if self._race_winner is not None:
                self._resource_version += 1
                self._lease = self._lease_body(*self._race_winner)
                self._race_winner = None
                return subprocess.CompletedProcess(argv, 1, "", _ALREADY_EXISTS)
            self._write(json.loads(stdin or "{}"))
            return subprocess.CompletedProcess(argv, 0, "", "")
        if verb == "replace":
            body = json.loads(stdin or "{}")
            current_rv = None if self._lease is None else self._lease["metadata"]["resourceVersion"]
            if current_rv != body.get("metadata", {}).get("resourceVersion"):
                return subprocess.CompletedProcess(argv, 1, "", _CONFLICT)
            self._write(body)
            return subprocess.CompletedProcess(argv, 0, "", "")
        if verb == "delete":
            self._lease = None
            return subprocess.CompletedProcess(argv, 0, "", "")
        raise AssertionError(f"unscripted kubectl verb {verb!r} in {argv}")  # pragma: no cover

    def _write(self, body: dict[str, object]) -> None:
        self._resource_version += 1
        body["metadata"]["resourceVersion"] = str(self._resource_version)
        self._lease = body

    def holder(self) -> str | None:
        return None if self._lease is None else str(self._lease["spec"]["holderIdentity"])


def test_holder_identity_leads_with_the_run_id_for_the_shell_side_to_parse() -> None:
    """``scripts/guardian_deploy.sh`` reads the run id back out with ``${x%%/*}`` alone."""
    identity = run_lock._holder_identity("RUN-G0-FULL-SCN-SIM-02-INJ-A-101")
    assert identity.startswith("RUN-G0-FULL-SCN-SIM-02-INJ-A-101/")
    assert identity.count("/") == 3  # run_id/started_at/host/pid, and no field may swallow "/"


def test_cluster_lease_is_acquired_when_the_cluster_holds_none() -> None:
    fake = _FakeLeaseCluster(initial=None)
    with cluster_lease("RUN-A", run_kubectl=fake):
        assert fake.holder() is not None and fake.holder().startswith("RUN-A/")
    assert fake.holder() is None, "the lease must be released when the attempt ends cleanly"
    assert [call[2] for call in fake.calls] == ["get", "create", "get", "delete"]


def test_cluster_lease_refuses_a_fresh_foreign_holder() -> None:
    now = datetime(2026, 9, 13, 12, 0, 0, tzinfo=UTC)
    fake = _FakeLeaseCluster(initial=("RUN-OTHER/2026-09-13T11:59:00Z/host/1", now, 3600))
    with pytest.raises(RunLockHeld, match="RUN-OTHER"):
        with cluster_lease("RUN-A", run_kubectl=fake, now=lambda: now):
            pytest.fail("a fresh foreign lease must refuse before the body ever runs")
    assert [call[2] for call in fake.calls] == ["get"], "must refuse without writing anything"
    assert fake.holder() == "RUN-OTHER/2026-09-13T11:59:00Z/host/1", "the foreign lease is intact"


def test_cluster_lease_takes_over_a_stale_holder() -> None:
    now = datetime(2026, 9, 13, 12, 0, 0, tzinfo=UTC)
    stale_renew = now - timedelta(seconds=run_lock.LEASE_DURATION_SECONDS + 100)
    fake = _FakeLeaseCluster(initial=("RUN-DEAD/2026-01-01T00:00:00Z/host/1", stale_renew, 3600))
    with cluster_lease("RUN-B", run_kubectl=fake, now=lambda: now):
        assert fake.holder().startswith("RUN-B/")
    assert fake.holder() is None
    assert [call[2] for call in fake.calls] == ["get", "replace", "get", "delete"]


def test_cluster_lease_is_released_even_when_the_attempt_raises() -> None:
    fake = _FakeLeaseCluster(initial=None)
    with pytest.raises(ValueError, match="attempt failed"):
        with cluster_lease("RUN-A", run_kubectl=fake):
            raise ValueError("attempt failed")
    assert fake.holder() is None


def test_cluster_lease_release_does_not_delete_a_takeover_by_a_later_holder() -> None:
    """A runner that overran ``LEASE_DURATION_SECONDS`` must not delete its successor's lease."""
    fake = _FakeLeaseCluster(initial=None)
    with cluster_lease("RUN-A", run_kubectl=fake):
        # Simulate a second runner declaring RUN-A stale and taking over mid-attempt: exactly
        # what a runner that overran the lease duration would find on release.
        fake._write(
            {
                "metadata": {"name": run_lock.LEASE_NAME, "namespace": run_lock.LEASE_NAMESPACE},
                "spec": {
                    "holderIdentity": "RUN-LATER/2026-09-13T12:00:00Z/host/2",
                    "renewTime": "2026-09-13T12:00:00Z",
                    "leaseDurationSeconds": run_lock.LEASE_DURATION_SECONDS,
                },
            }
        )
    assert fake.holder() == "RUN-LATER/2026-09-13T12:00:00Z/host/2"


def test_cluster_lease_error_on_a_read_failure_that_is_not_notfound() -> None:
    """A cluster this process cannot read from is not evidence that no one else holds the lock."""

    def broken(argv: list[str], *, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
        del stdin
        return subprocess.CompletedProcess(argv, 1, "", "Unable to connect to the server\n")

    with pytest.raises(ClusterLeaseError, match="Unable to connect"):
        with cluster_lease("RUN-A", run_kubectl=broken):
            pytest.fail("an unreadable lease must never be treated as an absent one")


def test_cluster_lease_retries_a_create_race_against_the_eventual_winner() -> None:
    """Two runners can both read "no lease"; the API server's AlreadyExists resolves it here.

    The winner's lease is seeded already stale, so after losing the create race this process's
    retry finds a takeover-able lease rather than a fresh one -- exercising the retry loop without
    needing a second concurrent thread to lose a real race against.
    """
    now = datetime(2026, 9, 13, 12, 0, 0, tzinfo=UTC)
    stale_renew = now - timedelta(seconds=run_lock.LEASE_DURATION_SECONDS + 1)
    fake = _FakeLeaseCluster(
        initial=None,
        race_winner=("RUN-WINNER/2026-01-01T00:00:00Z/host/9", stale_renew, 3600),
    )
    with cluster_lease("RUN-A", run_kubectl=fake, now=lambda: now):
        assert fake.holder().startswith("RUN-A/")
    assert fake.holder() is None, "our own release must still run normally after the retry"
    assert [call[2] for call in fake.calls] == ["get", "create", "get", "replace", "get", "delete"]


# --------------------------------------------------------------------------------------------
# The campaign-span hold (supervisor resumability gate, 2026-09-14, before the 750-run pilot):
# the same Lease held once for a whole campaign instead of reacquired per attempt, and the
# re-entrancy check in cluster_lease above that makes that safe.
# --------------------------------------------------------------------------------------------


def test_cluster_lease_is_a_reentrant_noop_when_a_campaign_already_holds_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A campaign holds this Lease for its whole span via ``campaign_cluster_lease``; a nested
    per-attempt ``cluster_lease`` call in the same process tree -- deep inside ``runner/run.py`` /
    ``runner/baseline.py``, unchanged -- must not re-acquire it under a different holder identity,
    which would see the campaign's own fresh lease as foreign and refuse itself."""
    monkeypatch.setenv(run_lock.CAMPAIGN_LEASE_HOLDER_ENV_VAR, "CAMP-X/2026-01-01T00:00:00Z/host/1")

    def must_not_be_called(argv: list[str], *, stdin: str | None = None):
        raise AssertionError(f"kubectl must not be invoked while a campaign lease is held: {argv}")

    with cluster_lease("RUN-A", run_kubectl=must_not_be_called) as holder:
        assert holder == "CAMP-X/2026-01-01T00:00:00Z/host/1"


def test_campaign_cluster_lease_holds_once_and_makes_nested_acquires_free() -> None:
    """The campaign-span hold acquires the object once; a nested per-attempt ``cluster_lease`` call
    made while it is held -- exactly what each grid or baseline attempt's own driver does -- touches
    kubectl not at all, and the marker is gone once the campaign-span hold exits cleanly."""
    fake = _FakeLeaseCluster(initial=None)
    with run_lock.campaign_cluster_lease("CAMP-20260101-pilot", run_kubectl=fake) as holder:
        assert holder.startswith("CAMP-20260101-pilot/")
        assert fake.holder() == holder
        with cluster_lease("RUN-A", run_kubectl=fake) as nested_holder:
            assert nested_holder == holder
        # the nested call above touched kubectl not at all
        assert [call[2] for call in fake.calls] == ["get", "create"]
    assert fake.holder() is None
    assert os.environ.get(run_lock.CAMPAIGN_LEASE_HOLDER_ENV_VAR) is None


def test_campaign_cluster_lease_cleans_up_on_error_too() -> None:
    """The lease and the re-entrancy marker are both released when the campaign body raises, not
    only on a clean exit -- mirrors ``test_cluster_lease_is_released_even_when_the_attempt_raises``
    above for the per-attempt lease."""
    fake = _FakeLeaseCluster(initial=None)
    with pytest.raises(ValueError, match="campaign failed"):
        with run_lock.campaign_cluster_lease("CAMP-X", run_kubectl=fake):
            raise ValueError("campaign failed")
    assert fake.holder() is None
    assert os.environ.get(run_lock.CAMPAIGN_LEASE_HOLDER_ENV_VAR) is None
