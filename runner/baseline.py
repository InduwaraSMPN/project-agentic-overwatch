r"""``make baseline`` (T6.1): one framework-off baseline to a sealed bundle.

WHY A SEPARATE TARGET, NOT A MODE FLAG ON ``run``
---------------------------------------------------
``make baseline LOAD=<id> SEED=<n>``. A baseline occupies no arm, no scenario and no injection
condition; its parameter set is disjoint from a grid run's rather than a subset, so it is a separate
target rather than a mode on ``run`` (``M6-runner.md`` T6.1, and the Makefile's own comment).
``LOAD`` resolves through ``infra.locust.registry`` and nothing else; ``SEED`` is a seed.

THE SHALLOWER HALF, WHICH UNBLOCKS FIRST
------------------------------------------
A baseline needs only the load-profile registry, the SLO probe and the resource collector -- all
of which landed at M1 -- so ``make baseline`` can be finished and proven in Tier A, ahead of ``make
run`` which needs M4's agents and M5's scenarios. The live seam is the load driver plus the two M1
collectors; the ``--offline`` path writes deterministic probe/resource/locust series and
seals, exercising the baseline completeness profile (the five required files, the nine asserted
absent) without a cluster.

WHAT BREAKS IF THIS FILE CHANGES
---------------------------------
The baseline bundle every RQ4 delta reads against (T-15), and the "a baseline carrying a
framework-on artefact refuses to seal" check the sealer enforces.
"""

import argparse
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from infra.locust.driver import Transport, urllib_transport  # noqa: E402
from infra.locust.registry import UnknownLoadProfile, resolve  # noqa: E402

from runner.bundle import SealError, seal_bundle  # noqa: E402
from runner.campaign import PlannedRun  # noqa: E402
from runner.grid import SEEDS  # noqa: E402
from runner.ids import BaselineId, format_baseline_id  # noqa: E402
from runner.live_baseline import (  # noqa: E402
    DEFAULT_FRONTEND_URL,
    DEFAULT_LOCUST_URL,
    DEFAULT_PROMETHEUS_URL,
    LiveMeasurementError,
    MeasurementWindow,
    Writer,
    execute,
    probe_writer,
    resource_writer,
)
from runner.manifest import RunManifest  # noqa: E402
from runner.provenance import build_run_manifest  # noqa: E402
from runner.run_lock import (  # noqa: E402
    ClusterLeaseError,
    RunLockHeld,
    cluster_lease,
    cluster_run_lock,
)
from runner.synthetic import populate_bundle, synthetic_manifest  # noqa: E402

__all__ = (
    "BaselineError",
    "BaselineOutcome",
    "MeasurementWindow",
    "run_baseline",
    "run_planned_baseline",
)

ManifestBuilder = Callable[..., RunManifest]
Now = Callable[[], str]


class BaselineError(Exception):
    """A baseline could not be dispatched -- an unknown load profile, or preflight failed."""


@dataclass(frozen=True)
class BaselineOutcome:
    run_id: str
    sealed: bool
    detail: str


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _preflight(skip: bool) -> None:
    """Require a green ``make status`` before collecting a live baseline."""
    if skip:
        return
    result = subprocess.run(  # noqa: S603 - argv fixed, no shell
        ["make", "status"],  # noqa: S607 - make is on PATH by design
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise BaselineError(
            "preflight `make status` is not green; a baseline on an unhealthy environment is "
            "invalid by construction (data-management §4). Bring the environment up before "
            "running."
        )


def run_planned_baseline(
    planned: PlannedRun,
    *,
    campaign_id: str,
    out_root: Path,
    offline: bool = False,
    skip_preflight: bool = False,
    rerun_of: str | None = None,
    window: MeasurementWindow | None = None,
    locust_url: str = DEFAULT_LOCUST_URL,
    locust_transport: Transport = urllib_transport,
    frontend_url: str = DEFAULT_FRONTEND_URL,
    prometheus_url: str = DEFAULT_PROMETHEUS_URL,
    probe: Writer | None = None,
    resources: Writer | None = None,
    manifest_builder: ManifestBuilder = build_run_manifest,
    now: Now = _now,
) -> BaselineOutcome:
    """Dispatch the exact planned baseline attempt supplied by campaign orchestration."""
    if not planned.is_baseline:
        raise BaselineError(f"{planned.run_id} is not a baseline planned run")
    if planned.seed not in SEEDS:
        raise BaselineError(
            f"SEED {planned.seed} is not in the canonical protocol seed set {SEEDS}"
        )
    try:
        resolve(planned.load_profile_id)
    except UnknownLoadProfile as error:
        raise BaselineError(str(error)) from None
    if not offline and window is None:
        raise BaselineError(
            f"the live baseline path for {planned.run_id} requires a caller-supplied "
            "measurement window; no duration exists outside the evaluation protocol"
        )
    _preflight(skip_preflight or offline)

    bundle_dir = Path(out_root) / campaign_id / planned.run_id
    try:
        bundle_dir.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        raise BaselineError(
            f"bundle directory already exists: {bundle_dir}; refusing to reuse or merge it"
        ) from None
    if offline:
        populate_bundle(bundle_dir, planned, planned.seed)
        manifest = synthetic_manifest(planned, campaign_id, rerun_of=rerun_of)
    else:
        if window is None:  # defensive: checked before preflight and bundle allocation
            raise BaselineError("live baseline requires a measurement window")
        started_at = now()
        try:
            # One cluster, one lock (supervisor ruling B6, ADR-087). A baseline shares the cluster,
            # the frontend and the Prometheus/Locust instruments with every other live attempt, so
            # it needs the same singleton discipline runner/run.py holds around its own live call,
            # even though a baseline never touches the Guardian: two live measurements running at
            # once would interleave one probes.csv/resources.csv/locust_stats.csv, which is exactly
            # the cross-attempt contamination this lock exists to prevent, not only the Guardian
            # redeploy race. See runner/run_lock.py for why both the file lock and the Lease are
            # held together.
            with cluster_run_lock(Path(out_root), planned.run_id):
                with cluster_lease(planned.run_id):
                    execute(
                        bundle_dir,
                        planned.load_profile_id,
                        window,
                        locust_url=locust_url,
                        locust_transport=locust_transport,
                        probe=probe or probe_writer(frontend_url),
                        resources=resources or resource_writer(prometheus_url),
                    )
        except RunLockHeld as error:
            raise BaselineError(str(error)) from None
        except ClusterLeaseError as error:
            raise BaselineError(str(error)) from None
        except LiveMeasurementError as error:
            raise BaselineError(str(error)) from None
        manifest = manifest_builder(
            planned,
            campaign_id,
            rerun_of=rerun_of,
            started_at=started_at,
            ended_at=now(),
        )
    try:
        seal_bundle(bundle_dir, manifest)
    except SealError as error:
        return BaselineOutcome(planned.run_id, sealed=False, detail=str(error))
    return BaselineOutcome(planned.run_id, sealed=True, detail="sealed")


def run_baseline(
    load_profile_id: str,
    seed: int,
    *,
    campaign_id: str,
    out_root: Path,
    offline: bool = False,
    skip_preflight: bool = False,
    **live_options: object,
) -> BaselineOutcome:
    """Dispatch one first-attempt baseline under the baseline completeness profile."""
    run_id = format_baseline_id(BaselineId(load_profile_id, seed))
    return run_planned_baseline(
        PlannedRun(
            run_id=run_id,
            condition=None,
            scenario_id=None,
            injection_condition=None,
            seed=seed,
            is_baseline=True,
            baseline_run_id=None,
            load_profile_id=load_profile_id,
        ),
        campaign_id=campaign_id,
        out_root=out_root,
        offline=offline,
        skip_preflight=skip_preflight,
        **live_options,  # type: ignore[arg-type]
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="baseline", description="One framework-off baseline to a sealed bundle (T6.1)."
    )
    parser.add_argument("--load", required=True, help="the load profile id, LOAD-<slug>")
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--campaign", required=True)
    parser.add_argument("--out-root", type=Path, default=REPO_ROOT / "runs")
    parser.add_argument("--offline", action="store_true")
    stop = parser.add_mutually_exclusive_group()
    stop.add_argument("--duration", type=float, metavar="SECONDS")
    stop.add_argument("--samples", type=int, metavar="N")
    args = parser.parse_args(argv)

    try:
        window = None
        if not args.offline:
            window = MeasurementWindow(samples=args.samples, duration_seconds=args.duration)
        elif args.samples is not None or args.duration is not None:
            raise BaselineError("--samples/--duration apply only to a live baseline")
        outcome = run_baseline(
            args.load,
            args.seed,
            campaign_id=args.campaign,
            out_root=args.out_root,
            offline=args.offline,
            window=window,
        )
    except (BaselineError, ValueError) as error:
        print(f"baseline: {error}", file=sys.stderr)
        return 1
    if not outcome.sealed:
        print(f"baseline: {outcome.run_id} did not seal: {outcome.detail}", file=sys.stderr)
        return 1
    print(f"baseline: PASS — {outcome.run_id} sealed under {args.out_root}/{args.campaign}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
