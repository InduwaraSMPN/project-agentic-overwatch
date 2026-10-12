"""One live run at a time, because the cluster and the Guardian are singletons.

WHY THIS EXISTS
---------------
`scripts/guardian_deploy.sh` reconfigures and restarts the *one* Guardian for every run: it writes
`GUARDIAN_RUN_ID` and `GUARDIAN_AUDIT_LOG_PATH` into the `guardian-runtime` ConfigMap and waits for
the rollout. That is correct for runs that follow one another and catastrophic for runs that
overlap, because the Guardian stamps `run_id` from its own configuration rather than from the
request. Two runners therefore produce, silently:

* **refused tokens.** `guardian/policies/issuance.rego` requires
  `input.guardian.run_id == input.issue.run_id`. A supervisor of run A asking the Guardian that run
  B just reconfigured is refused `issue_authority_exceeded` — a policy denial that looks exactly
  like an agent overreaching.
* **a cascade that hides the cause.** An executor handed no token submits an empty one, the
  Guardian rejects the body as `policy.request-malformed`, and the run's `results.json` reports
  agents that tried and were denied. Nothing in the bundle says "another run was in flight".
* **misattributed audit.** Run A's decisions are appended to run B's per-run chain and carry run
  B's `run_id`, so ADR-058's per-run chain stops being per-run and ADR-054's isolation proof would
  pass while the evidence was mixed.

This was not hypothetical: it happened on 2026-09-12, and the resulting bundle looked like an
agent-behaviour finding rather than an operator error. The lock exists so that the second runner is
refused loudly, before it touches the cluster, instead of quietly corrupting both runs.

The campaign runner is sequential by construction (`runner/campaign.py` drives one cell at a time),
so in normal operation this lock is never contended. It is contended exactly when a human or an
agent starts a second run by hand, which is the case it is written for.

WHAT IT DOES NOT DO
-------------------
It is a lock over *this checkout's* runs, not a distributed lease over the cluster: a second
checkout, or a second machine pointed at the same kind cluster, is outside what a file can see.
`GUARDIAN_RUN_ID` in the live ConfigMap is the cluster-side truth, and a mismatch there is what the
issuance policy already refuses on.

THE CLUSTER LEASE CLOSES THAT GAP (ADR-087, supervisor ruling B6)
-------------------------------------------------------------------
The limit above was reached on 2026-09-12 (ADR-077): a spawned task session runs in its own git
worktree, hence its own `runs/` and its own copy of this file lock, so a second live run started
from it is exactly the "second checkout" the file lock cannot see. :func:`cluster_lease` is the
fix -- a `coordination.k8s.io/v1` Lease held in the cluster itself, read and written through the
operator's own kubeconfig by every checkout alike, regardless of which `runs/` each has on disk.
`scripts/guardian_deploy.sh` re-checks the same Lease immediately before it rewrites the one
Guardian's identity, which is the actual dangerous action; that second, independent check is what
catches a direct or manual invocation of the deploy script that never went through this module at
all (exactly what `make up` bring-up does, which is why an absent or stale Lease must still let it
through), and the small window between this module acquiring the Lease and the deploy script
actually running deep inside `runner/live_run.py`.

The file lock above is kept, not subsumed. It costs nothing extra -- no network round trip, no
cluster dependency -- and it still catches the common case (two invocations from one checkout) the
instant it happens, before anything reaches the network. The Lease is the authoritative guard for
exactly what the file lock was always documented above as unable to see; the two are complementary,
cheapest check first, not redundant.

`LEASE_DURATION_SECONDS` reuses :data:`STALE_AFTER_SECONDS` rather than inventing a second number
for the same judgement call (`.agents/rules/00-source-of-truth.md` allows an operational bound to
live in code with a comment, the way `scripts/guardian_deploy.sh`'s own rollout timeout does, but
not a second experiment-shaped constant for a quantity this file already owns). That constant was
already chosen to exceed any single run's wall-clock length with margin, so a Lease going stale
while a run is still making progress and a file lock doing the same are the same fact observed
twice, not two facts. Nothing renews it early: at the measured run length the margin is wide, and
an attempt that somehow outlives it has already overrun badly enough that takeover is the correct
behaviour, exactly as it already is for the file lock above.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final, Protocol

LOCK_NAME: Final = ".run.lock"
# A lock whose holder cannot be proven alive is taken over after this long. It bounds the damage of
# a runner killed hard enough to skip its own release (SIGKILL, a closed laptop, a crashed shell),
# and it is deliberately longer than any single run: at the measured ~900 s per run plus teardown,
# an hour cannot be reached by a run that is still making progress.
STALE_AFTER_SECONDS: Final = 3600.0


class RunLockHeld(RuntimeError):
    """Another live run holds the cluster. Never recovered from silently."""


def _process_alive(pid: int) -> bool:
    """Whether ``pid`` is running, answered conservatively.

    POSIX answers exactly, through signal 0. Windows has no cheap equivalent that does not risk
    terminating the process, so it answers "alive" and lets :data:`STALE_AFTER_SECONDS` decide. The
    conservative direction is the safe one here: claiming a live holder is dead would let a second
    runner proceed, which is the failure this module exists to prevent.
    """
    if os.name != "posix":
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _holder_record(run_id: str) -> dict[str, object]:
    """The four fields that identify one attempt: run id, host, pid, and when it started.

    Shared by the file lock below and the cluster Lease further down, so "who holds this" is one
    fact described two ways -- JSON for the file, a delimited string for the Lease -- rather than
    two facts that could drift apart.
    """
    return {
        "pid": os.getpid(),
        "run_id": run_id,
        "host": os.uname().nodename if hasattr(os, "uname") else os.environ.get("COMPUTERNAME", ""),
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def _holder_description(record: dict[str, object], path: Path) -> str:
    return (
        f"run {record.get('run_id')!r} (pid {record.get('pid')}, host {record.get('host')!r}, "
        f"started {record.get('started_at')}) holds {path}"
    )


@contextmanager
def cluster_run_lock(out_root: Path, run_id: str) -> Iterator[Path]:
    """Hold the single-run lock for the duration of one live run.

    Raises :class:`RunLockHeld` when another runner holds it and that runner can still be running.
    A lock left behind by a dead process, or one older than :data:`STALE_AFTER_SECONDS`, is taken
    over and the takeover is reported on stderr -- silently reusing it would hide the crash that
    left it.
    """
    path = Path(out_root) / LOCK_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    record = _holder_record(run_id)
    payload = json.dumps(record, sort_keys=True).encode("utf-8") + b"\n"

    while True:
        try:
            handle = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            existing: dict[str, object] = {}
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                existing = {}
            pid = existing.get("pid")
            age = time.time() - path.stat().st_mtime if path.exists() else 0.0
            alive = isinstance(pid, int) and _process_alive(pid)
            if alive and age < STALE_AFTER_SECONDS:
                raise RunLockHeld(
                    "another live run holds the cluster: "
                    + _holder_description(existing, path)
                    + ". One run at a time: the Guardian is reconfigured and restarted per run, so "
                    "overlapping runs refuse each other's tokens and mix their audit chains."
                ) from None
            print(
                f"runner: taking over a stale run lock ({_holder_description(existing, path)}; "
                f"age {age:.0f}s)",
                file=sys.stderr,
            )
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            continue
        try:
            os.write(handle, payload)
        finally:
            os.close(handle)
        break

    try:
        yield path
    finally:
        try:
            held = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            held = {}
        # Only the holder removes it: a runner that took over a stale lock must not delete the lock
        # a later runner has since created.
        if held.get("pid") == record["pid"] and held.get("run_id") == record["run_id"]:
            try:
                path.unlink()
            except FileNotFoundError:
                pass


# --------------------------------------------------------------------------------------------
# The cluster Lease (ADR-087, supervisor ruling B6): the same lock, visible to every checkout.
# See the module docstring's "THE CLUSTER LEASE CLOSES THAT GAP" section for why this exists
# beside cluster_run_lock above rather than instead of it.
# --------------------------------------------------------------------------------------------

# `guardian` already exists before any attempt can reach this code: every deploy applies
# guardian/deploy/rbac.yaml first (scripts/guardian_deploy.sh), including the one `make up` runs at
# bring-up, and `make status` -- required by both runner/run.py's and runner/baseline.py's preflight
# -- would not be green without it. Naming the Lease's home here, rather than provisioning a
# namespace of its own, keeps this a lock with no cluster footprint beyond one object. It does not
# make the Lease a Guardian resource: guardian/deploy/rbac.yaml -- owned by a different stream --
# grants the Guardian's own ServiceAccount no verb on leases.coordination.k8s.io, and must not: this
# lease is acquired with the operator's kubeconfig, never the Guardian's.
LEASE_NAMESPACE: Final = "guardian"

# One Lease per cluster, not per run: the object is reused across attempts (created once, replaced
# on takeover, deleted on release), exactly as the file lock above reuses one path.
LEASE_NAME: Final = "live-run-lock"

# Reused, not invented (.agents/rules/00-source-of-truth.md) -- see the module docstring.
LEASE_DURATION_SECONDS: Final = int(STALE_AFTER_SECONDS)

# A concurrent create or takeover resolves as a 409/AlreadyExists from the API server; this bounds
# how many times this process re-reads and retries before giving up. Generous, not tuned: every
# contender here is a human-triggered run or scripts/guardian_deploy.sh, not a tight loop, so real
# contention resolves on the first or second attempt and this bound only guards a wedged retry loop
# in case it somehow does not.
_MAX_LEASE_ATTEMPTS: Final = 5


class ClusterLeaseError(RuntimeError):
    """The cluster Lease could not be read, created, taken over, or released.

    Distinct from :class:`RunLockHeld`: that is the expected refusal when another live run holds
    the cluster. This is the unexpected case -- kubectl missing, the cluster unreachable, the Lease
    object not shaped like one this module wrote -- and it must never be read as "no lease", which
    is why :func:`_read_lease` raises it rather than returning ``None`` for anything but a genuine
    ``NotFound``.
    """


class _KubectlRunner(Protocol):
    def __call__(
        self, argv: list[str], *, stdin: str | None = None
    ) -> subprocess.CompletedProcess[str]: ...


def _run_kubectl(argv: list[str], *, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    """Run one kubectl call against whatever cluster the ambient kubeconfig names.

    No explicit ``--kubeconfig``/``--context``: every other bare ``kubectl`` call this codebase
    makes from Python (``runner/live_run.py``'s ``_run_command``) relies on the same ambient
    environment, and ``runner/baseline.py`` -- one of this module's two live callers -- has no
    kubeconfig or context of its own to pass down.
    """
    return subprocess.run(  # noqa: S603 - argv fixed by this module, no shell
        ["kubectl", *argv],  # noqa: S607 - kubectl is expected on PATH, like every caller here
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
    )


def _utc_now() -> datetime:
    """Wrapped so callers can substitute a deterministic clock; see infra/probes/slo_probe.py."""
    return datetime.now(UTC)


def _format_rfc3339(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_rfc3339(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _holder_identity(run_id: str) -> str:
    """The Lease's ``holderIdentity``: the same four fields :func:`_holder_record` gives the file
    lock, rendered as ``run_id/started_at/host/pid`` rather than JSON.

    Plain and delimited, not JSON, because the only other reader of this string is
    ``scripts/guardian_deploy.sh`` -- strict POSIX sh, no ``jq`` -- which reads the run id back out
    with ``${holder_identity%%/*}`` alone. A JSON blob would make that script's half of this lock a
    second JSON parser in a language that does not have one.
    """
    record = _holder_record(run_id)
    return f"{record['run_id']}/{record['started_at']}/{record['host']}/{record['pid']}"


@dataclass(frozen=True, slots=True)
class _LeaseState:
    """What one ``kubectl get lease -o json`` told us: who holds it, and until when."""

    holder_identity: str
    renew_time: datetime
    lease_duration_seconds: int
    resource_version: str

    def fresh_at(self, moment: datetime) -> bool:
        return self.renew_time + timedelta(seconds=self.lease_duration_seconds) > moment


def _lease_manifest(
    *,
    holder_identity: str,
    lease_duration_seconds: int,
    acquired_at: str,
    resource_version: str | None,
) -> dict[str, object]:
    """The Lease object body for a create (no ``resourceVersion``) or a takeover (with one).

    Passing ``resourceVersion`` back on a takeover is what makes it a compare-and-swap: the API
    server refuses the ``replace`` with a 409 if the object changed since this process read it,
    which is exactly the race between two runners that both found the same stale lease.
    """
    metadata: dict[str, object] = {"name": LEASE_NAME, "namespace": LEASE_NAMESPACE}
    if resource_version is not None:
        metadata["resourceVersion"] = resource_version
    return {
        "apiVersion": "coordination.k8s.io/v1",
        "kind": "Lease",
        "metadata": metadata,
        "spec": {
            "holderIdentity": holder_identity,
            "leaseDurationSeconds": lease_duration_seconds,
            "acquireTime": acquired_at,
            "renewTime": acquired_at,
        },
    }


def _read_lease(run_kubectl: _KubectlRunner) -> _LeaseState | None:
    """Return the current Lease, or None if it does not exist yet.

    None is returned only for a ``NotFound`` from the API server -- an absent Lease and an absent
    ``guardian`` namespace read the same way, which is what lets a fresh cluster's first-ever
    ``make up`` and first-ever run proceed. Any other failure is :class:`ClusterLeaseError`: a
    cluster this process cannot even read from is not evidence that no one else holds the lock.
    """
    result = run_kubectl(["-n", LEASE_NAMESPACE, "get", "lease", LEASE_NAME, "-o", "json"])
    if result.returncode != 0:
        if "notfound" in result.stderr.lower():
            return None
        raise ClusterLeaseError(
            f"could not read lease {LEASE_NAMESPACE}/{LEASE_NAME}: {result.stderr.strip()}"
        )
    try:
        payload = json.loads(result.stdout)
        spec = payload["spec"]
        return _LeaseState(
            holder_identity=str(spec["holderIdentity"]),
            renew_time=_parse_rfc3339(str(spec["renewTime"])),
            lease_duration_seconds=int(spec["leaseDurationSeconds"]),
            resource_version=str(payload["metadata"]["resourceVersion"]),
        )
    except (KeyError, ValueError, json.JSONDecodeError) as error:
        raise ClusterLeaseError(
            f"lease {LEASE_NAMESPACE}/{LEASE_NAME} is not a well-formed Lease: {error}"
        ) from error


def _acquire_lease(
    run_id: str,
    holder_identity: str,
    run_kubectl: _KubectlRunner,
    now: Callable[[], datetime],
) -> None:
    """Create the Lease if none exists, take it over if stale, or refuse if it is fresh.

    Raises :class:`RunLockHeld` for a fresh foreign holder and :class:`ClusterLeaseError` if the
    Lease cannot be acquired after :data:`_MAX_LEASE_ATTEMPTS` retries against concurrent writers.
    """
    for _attempt in range(_MAX_LEASE_ATTEMPTS):
        state = _read_lease(run_kubectl)
        moment = now()
        if state is None:
            manifest = _lease_manifest(
                holder_identity=holder_identity,
                lease_duration_seconds=LEASE_DURATION_SECONDS,
                acquired_at=_format_rfc3339(moment),
                resource_version=None,
            )
            result = run_kubectl(
                ["-n", LEASE_NAMESPACE, "create", "-f", "-"], stdin=json.dumps(manifest)
            )
            if result.returncode == 0:
                return
            if "alreadyexists" in result.stderr.lower():
                continue  # someone else created it between our read and our create; re-read
            raise ClusterLeaseError(
                f"could not create lease {LEASE_NAMESPACE}/{LEASE_NAME}: {result.stderr.strip()}"
            )
        if state.fresh_at(moment):
            raise RunLockHeld(
                "another live run holds the cluster: lease "
                f"{LEASE_NAMESPACE}/{LEASE_NAME} is held by {state.holder_identity!r} "
                f"(renewed {state.renew_time.isoformat()}; this run is {run_id!r}). One run at a "
                "time: the Guardian is reconfigured and restarted per run, so overlapping runs "
                "refuse each other's tokens and mix their audit chains."
            )
        print(
            f"runner: taking over a stale cluster lease {LEASE_NAMESPACE}/{LEASE_NAME} "
            f"(held by {state.holder_identity!r}, last renewed {state.renew_time.isoformat()})",
            file=sys.stderr,
        )
        manifest = _lease_manifest(
            holder_identity=holder_identity,
            lease_duration_seconds=LEASE_DURATION_SECONDS,
            acquired_at=_format_rfc3339(moment),
            resource_version=state.resource_version,
        )
        result = run_kubectl(
            ["-n", LEASE_NAMESPACE, "replace", "-f", "-"], stdin=json.dumps(manifest)
        )
        if result.returncode == 0:
            return
        if "conflict" in result.stderr.lower():
            continue  # someone else took it over first; re-read and re-evaluate
        raise ClusterLeaseError(
            f"could not take over lease {LEASE_NAMESPACE}/{LEASE_NAME}: {result.stderr.strip()}"
        )
    raise ClusterLeaseError(
        f"could not acquire lease {LEASE_NAMESPACE}/{LEASE_NAME} after "
        f"{_MAX_LEASE_ATTEMPTS} attempts: repeated concurrent modification"
    )


def _release_lease(holder_identity: str, run_kubectl: _KubectlRunner) -> None:
    """Delete the Lease, but only while it still names this holder.

    The same care :func:`cluster_run_lock`'s own release takes above: a runner that took over a
    stale lease must not delete the lease a later runner has since taken over from *this* one
    after it overran :data:`LEASE_DURATION_SECONDS`. Reading immediately before deleting narrows
    that race without closing it -- an accepted trade-off, not an ignored one, exactly as above.
    """
    state = _read_lease(run_kubectl)
    if state is None or state.holder_identity != holder_identity:
        return
    result = run_kubectl(["-n", LEASE_NAMESPACE, "delete", "lease", LEASE_NAME])
    if result.returncode != 0 and "notfound" not in result.stderr.lower():
        raise ClusterLeaseError(
            f"could not release lease {LEASE_NAMESPACE}/{LEASE_NAME}: {result.stderr.strip()}"
        )


@contextmanager
def cluster_lease(
    run_id: str,
    *,
    run_kubectl: _KubectlRunner = _run_kubectl,
    now: Callable[[], datetime] = _utc_now,
) -> Iterator[str]:
    """Hold the cluster-wide Lease for the duration of one live attempt.

    See the module docstring's "THE CLUSTER LEASE CLOSES THAT GAP" section for why this exists
    beside :func:`cluster_run_lock` rather than instead of it. Raises :class:`RunLockHeld` when a
    fresh Lease names another holder -- the same exception the file lock raises, so a caller
    already handling that from :func:`cluster_run_lock` handles this for free -- and
    :class:`ClusterLeaseError` when the Lease itself could not be read, acquired or released, which
    a caller must handle separately since it is not a contended lock but a broken check.

    Yields the holder identity this call is acting under -- either one it just acquired, or, when
    :data:`CAMPAIGN_LEASE_HOLDER_ENV_VAR` names a holder already, the campaign's own (see
    :func:`campaign_cluster_lease`): a campaign holding this Lease across its whole span sets that
    variable so every attempt's own per-run acquire -- `runner/run.py` and `runner/baseline.py`,
    unchanged, still call this function once per attempt -- becomes a re-entrant no-op instead of a
    second acquire that would see the campaign's fresh Lease as a foreign holder and refuse itself.
    A second checkout has no reason to see that variable in its own environment, so it still
    acquires, and is still refused, exactly as before this existed: re-entrancy is scoped to one
    process tree, not a weakening of the lock itself.
    """
    campaign_holder = os.environ.get(CAMPAIGN_LEASE_HOLDER_ENV_VAR)
    if campaign_holder:
        yield campaign_holder
        return
    holder_identity = _holder_identity(run_id)
    _acquire_lease(run_id, holder_identity, run_kubectl, now)
    try:
        yield holder_identity
    finally:
        _release_lease(holder_identity, run_kubectl)


# --------------------------------------------------------------------------------------------
# The campaign-span hold (supervisor resumability gate, 2026-09-14, before the 750-run pilot):
# the same Lease and the same object, held once for an entire campaign rather than reacquired
# per attempt, so no second checkout can touch the cluster for the whole span -- not only for
# whichever one attempt happens to be running at a given moment.
# --------------------------------------------------------------------------------------------

# Set for the lifetime of a campaign-span hold (see :func:`campaign_cluster_lease`), to the exact
# holder identity the campaign itself acquired. Read back by :func:`cluster_lease` above -- see its
# docstring for why a nested per-attempt acquire must become a no-op rather than a second acquire.
CAMPAIGN_LEASE_HOLDER_ENV_VAR: Final = "RUNNER_CAMPAIGN_LEASE_HOLDER"


@contextmanager
def campaign_cluster_lease(
    campaign_id: str,
    *,
    run_kubectl: _KubectlRunner = _run_kubectl,
    now: Callable[[], datetime] = _utc_now,
) -> Iterator[str]:
    """Hold the cluster Lease for an entire campaign rather than one attempt.

    Identical object, identical holder-identity shape to :func:`cluster_lease` -- a campaign is
    simply the coarsest attempt this lock already knows how to hold, identified by ``campaign_id``
    in place of a run id, so ``holderIdentity`` reads ``<campaign_id>/<started_at>/<host>/<pid>``.
    Raises :class:`RunLockHeld` when a fresh Lease already names another holder -- a live run or
    another campaign already has the cluster -- and :class:`ClusterLeaseError` when the Lease
    itself could not be read, acquired or released.

    While held, :data:`CAMPAIGN_LEASE_HOLDER_ENV_VAR` names this holder for the duration of the
    ``with`` block, restored to whatever it held before (usually unset) on the way out, so nesting
    two campaign-span holds in the same process is exactly as safe as nesting a per-attempt
    :func:`cluster_lease` inside one. Every attempt this campaign drives -- one grid or baseline run
    at a time, each in its own spawned child process that inherits this process's environment --
    calls :func:`cluster_lease` unchanged deep inside `runner/run.py` / `runner/baseline.py`; that
    call reads this variable back and, finding it set, yields without touching the cluster again.
    """
    previous = os.environ.get(CAMPAIGN_LEASE_HOLDER_ENV_VAR)
    with cluster_lease(campaign_id, run_kubectl=run_kubectl, now=now) as holder_identity:
        os.environ[CAMPAIGN_LEASE_HOLDER_ENV_VAR] = holder_identity
        try:
            yield holder_identity
        finally:
            if previous is None:
                os.environ.pop(CAMPAIGN_LEASE_HOLDER_ENV_VAR, None)
            else:
                os.environ[CAMPAIGN_LEASE_HOLDER_ENV_VAR] = previous
