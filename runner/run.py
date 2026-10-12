r"""``make run`` (T6.1): one grid run to a sealed bundle, condition flags set here and only here.

THE INVOCATION CONTRACT
-------------------------
``make run COND=<id> SCN=<id> INJ=<id> SEED=<n>`` -- four parameters, exactly the four grid
coordinates the run identifier carries, so the CLI addresses all 750 cells. ``COND`` is one of the
six canonical arms, ``SCN`` a scenario, ``INJ`` one of the five injection-condition values, ``SEED``
a seed. A framework-off baseline is a different target (``runner/baseline.py``), because a baseline
occupies no arm, no scenario and no injection condition and its parameter set is disjoint.

WHERE THE CONDITION FLAGS COME FROM
-------------------------------------
From ``runner/conditions.py``'s table, keyed on ``COND``, and from nowhere else -- which is T6.1's
whole content and the obligation ``.agents/rules/10-guardian-first.md`` states for the Guardian arms
and ADR-040 extends to all six, G3 included. The flag fields written into the sealed manifest are
the runner's *selection*, and ``runner.validate.validate_bundle`` asserts the manifest agrees with
its identifier, so a run whose environment was tampered with cannot seal as a clean arm.

TWO TIERS
-----------
The live path -- drive the agent graph (M4), inject the scenario (M5), collect the four telemetry
families, apply the G2 netpol overlay and the Monitor quoting flag -- is :func:`_execute_live`, the
Tier B seam that needs M1's cluster. It is authored here and raises until a cluster exists. The
``--offline`` path writes deterministic telemetry through ``runner.synthetic.populate_bundle`` and
seals, so the whole pipeline from coordinates to a validated bundle is exercisable now, the same
shape ``scenarios/attackers/apply.py``'s offline mode takes at M5.

CONTINUE ON FAILURE
---------------------
A nightly batch survives one bad run: :func:`run_cell` returns an outcome rather than raising on a
run-validity failure (data-management §4), so a caller can log it, mark the cell for rerun with a
``-R<n>`` suffix, and go on. The preflight gate (``make status`` green, §5 rule 1) is the one thing
that stops the batch, because a run on an unhealthy environment is invalid by construction.

THE P0-LIVE PROBE MODE
------------------------
``--instrument-only`` drives the same coordinates to a sealed bundle but runs NO agent graph: the
condition flags are applied, the scenario and its injections execute, the Monitor evidence and the
API-server audit are collated, and the bundle seals under the probe completeness profile
(``runner/bundle.py``) instead of the framework-on one. It exists for the P0-live instrument probes
(M10 plan section 6, WS-5), which measure the framework around the agent -- the quoting and epoch
chain, the forwarder drain, the audit policy, the egress shim -- and for which a graph running
inside the probe would make the probed instrument the thing under test. The flag is refused with
``--offline``: a probe is a live stage, and the synthetic path would seal a probe that ran nothing.

WHAT BREAKS IF THIS FILE CHANGES
---------------------------------
The framework-on bundle every grid cell seals (T-15); condition-flag isolation (T-13, ADR-040);
the probe profile's boundary, since this is the only CLI that selects it.
"""

import argparse
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scenarios.attackers.plan import PlanError, load_manifest  # noqa: E402

from runner.bundle import SealError, seal_bundle  # noqa: E402
from runner.campaign import CampaignManifest, PlannedRun  # noqa: E402
from runner.conditions import flags_for  # noqa: E402
from runner.grid import PILOT_SEEDS, SEEDS  # noqa: E402
from runner.ids import (  # noqa: E402
    CANONICAL_ARMS,
    INJECTION_CONDITIONS,
    BaselineId,
    RunId,
    format_baseline_id,
    format_run_id,
)
from runner.live_baseline import MeasurementWindow  # noqa: E402
from runner.live_run import (  # noqa: E402
    LiveRunDependencies,
    LiveRunError,
    dependencies_from_environment,
    execute_live_run,
)
from runner.manifest import requires_baseline_pairing  # noqa: E402
from runner.provenance import build_run_manifest  # noqa: E402
from runner.run_lock import (  # noqa: E402
    ClusterLeaseError,
    RunLockHeld,
    cluster_lease,
    cluster_run_lock,
)
from runner.synthetic import populate_bundle, synthetic_manifest  # noqa: E402

__all__ = ("RunError", "RunOutcome", "run_cell", "run_planned")

ManifestBuilder = Callable[..., object]
Now = Callable[[], str]


def _now() -> str:
    return datetime.now(UTC).isoformat()


class RunError(Exception):
    """A run could not be dispatched -- a coordinate is invalid, or preflight failed."""


@dataclass(frozen=True)
class RunOutcome:
    """What one run produced: its identifier, whether it sealed, and why not if it did not."""

    run_id: str
    sealed: bool
    detail: str


def _validate_coordinates(
    condition: str, scenario_id: str, injection: str, seed: int, *, instrument_only: bool = False
) -> None:
    """Refuse a coordinate the protocol does not define, before any cluster work starts.

    ``instrument_only`` widens the accepted seed set by exactly the PILOT seeds, and by nothing
    else. P0-live's probes are the only instrument-only runs (WS-5, ``--instrument-only``), and they
    seal into a pilot campaign directory, so they belong to the pilot seed space the glossary fixes
    ("The pilot ladder uses seeds disjoint from the campaign set, so no pilot bundle can be mistaken
    for a campaign bundle", docs/07-glossary-and-ids.md section Seeds). Without this the probe mode
    had no seed it could legally be given: the campaign seeds are the campaign's, and the pilot
    seeds were refused. A full experimental run is still campaign-seed-only, so a stray pilot-seed
    run cannot be manufactured outside the pilot manifests.
    """
    if condition not in CANONICAL_ARMS:
        raise RunError(
            f"COND {condition!r} is not one of the six canonical arms {sorted(CANONICAL_ARMS)}; "
            "S1-HIER is an alias of G0-FULL, not a separate arm"
        )
    if injection not in INJECTION_CONDITIONS:
        raise RunError(f"INJ {injection!r} is not one of {INJECTION_CONDITIONS}")
    allowed = (*SEEDS, *PILOT_SEEDS) if instrument_only else SEEDS
    if seed not in allowed:
        raise RunError(f"SEED {seed} is not in the canonical protocol seed set {allowed}")
    # Formatting checks the identifier grammar; loading checks that the named scenario actually
    # exists and is schema-valid. This is unconditional so --offline cannot manufacture a bundle
    # for a scenario absent from the registered corpus.
    try:
        load_manifest(scenario_id)
    except PlanError as error:
        raise RunError(str(error)) from None


def _preflight(skip: bool) -> None:
    """`make status` green gates every run (evaluation-protocol §5 rule 1). Skipped only offline."""
    if skip:
        return
    for command, failure in (
        (
            ["make", "status"],
            "preflight `make status` is not green; a run on an unhealthy environment is invalid "
            "by construction (data-management §4). Bring the environment up before running.",
        ),
        (
            ["sh", "scripts/chaos_preflight.sh"],
            "Chaos preflight is not green; a previous run may still be perturbing the cluster.",
        ),
    ):
        result = subprocess.run(  # noqa: S603 - argv fixed, no shell
            command,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise RunError(f"{failure} {detail}".strip())


def run_planned(
    planned: PlannedRun,
    *,
    campaign_id: str,
    out_root: Path,
    offline: bool = False,
    skip_preflight: bool = False,
    instrument_only: bool = False,
    rerun_of: str | None = None,
    window: MeasurementWindow | None = None,
    live_dependencies: LiveRunDependencies | None = None,
    guardian_url: str | None = None,
    manifest_builder: ManifestBuilder = build_run_manifest,
    now: Now = _now,
    pilot: tuple[str, CampaignManifest] | None = None,
) -> RunOutcome:
    """Dispatch the exact planned grid attempt supplied by campaign orchestration.

    ``instrument_only`` is the P0-live probe mode (``--instrument-only``, WS-5): it is forwarded to
    :func:`runner.live_run.execute_live_run`, which runs the scenario and the evidence path but no
    agent graph, and to :func:`runner.bundle.seal_bundle`, which then selects the probe completeness
    profile. It is refused together with ``offline`` because a probe is a LIVE instrument stage --
    the synthetic path writes a framework-on bundle and would seal a probe-labelled bundle that ran
    nothing (data-management section 3).
    """
    if offline and instrument_only:
        raise RunError(
            "--instrument-only is a live probe mode and cannot be combined with --offline: the "
            "synthetic path writes a framework-on bundle, so the probe profile's required files "
            "would be absent and the seal would fail on a probe that measured nothing"
        )
    if planned.is_baseline or planned.condition is None or planned.scenario_id is None:
        raise RunError(f"{planned.run_id} is not a framework-on planned run")
    if planned.injection_condition is None:
        raise RunError(f"{planned.run_id} has no injection condition")
    pilot_validated = False
    if pilot is not None:
        from runner import validate as validation
        from runner.pilot_cli import PILOT_VALIDATORS

        kind, pilot_plan = pilot
        if kind not in PILOT_VALIDATORS:
            raise RunError(f"unknown pilot kind {kind!r}")
        getattr(validation, PILOT_VALIDATORS[kind])(pilot_plan)
        canonical = replace(planned, run_id=planned.run_id.rsplit("-R", 1)[0])
        if pilot_plan.campaign_id != campaign_id or canonical not in pilot_plan.runs:
            raise RunError("the run is not an exact member of its validated pilot manifest")
        if planned.seed not in PILOT_SEEDS:
            raise RunError("a formal pilot requires a registered pilot seed")
        pilot_validated = True
    _validate_coordinates(
        planned.condition,
        planned.scenario_id,
        planned.injection_condition,
        planned.seed,
        instrument_only=instrument_only or pilot_validated,
    )
    flags_for(planned.condition)
    if not offline and window is None:
        raise RunError(
            f"the live run path for {planned.run_id} requires a caller-supplied measurement "
            "window; no duration exists outside the evaluation protocol"
        )
    _preflight(skip_preflight or offline)

    bundle_dir = Path(out_root) / campaign_id / planned.run_id
    try:
        bundle_dir.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        raise RunError(
            f"bundle directory already exists: {bundle_dir}; refusing to reuse or merge it"
        ) from None
    if offline:
        populate_bundle(bundle_dir, planned, planned.seed)
        manifest = synthetic_manifest(planned, campaign_id, rerun_of=rerun_of)
    else:
        if window is None:  # defensive: checked before preflight and bundle allocation
            raise RunError("live run requires a measurement window")
        try:
            dependencies, configured_guardian_url = (
                dependencies_from_environment()
                if live_dependencies is None
                else (live_dependencies, guardian_url)
            )
        except LiveRunError as error:
            raise RunError(str(error)) from None
        effective_guardian_url = guardian_url or configured_guardian_url
        if not effective_guardian_url:
            raise RunError("the live run requires an explicit Guardian URL")
        started_at = now()
        try:
            # One cluster, one lock (supervisor ruling B6, ADR-087). The cluster and the Guardian
            # are singletons and the Guardian is reconfigured per run, so a second concurrent
            # runner refuses this one's tokens and mixes its audit chain -- and a worktree's own
            # runs/ hides that from the file lock alone (ADR-077), which is why the Lease is held
            # alongside it rather than in its place. Both are held only around the cluster-touching
            # call, exactly the scope scripts/guardian_deploy.sh's own lease check re-verifies
            # immediately before it reconfigures the Guardian, deep inside execute_live_run.
            with cluster_run_lock(Path(out_root), planned.run_id):
                with cluster_lease(planned.run_id):
                    execute_live_run(
                        bundle_dir,
                        planned,
                        dependencies=dependencies,
                        guardian_url=effective_guardian_url,
                        window=window,
                        instrument_only=instrument_only,
                    )
        except RunLockHeld as error:
            raise RunError(str(error)) from None
        except ClusterLeaseError as error:
            raise RunError(str(error)) from None
        except LiveRunError as error:
            raise RunError(str(error)) from None
        # ``bundle_dir`` is what makes ``shared_credential_exercised`` an OBSERVATION rather than a
        # copy of the arm's name (M10 plan §3.1 D1-A, ADR-131, defect V7): the builder reads the
        # API-audit slice this run just collated into the bundle and derives the field from it. A
        # live run that omitted it recorded ``False`` for every arm -- including G2 -- and was then
        # caught by F-GD-05 instead of measured, which is exactly the wiring
        # ``runner/provenance.py::build_run_manifest`` documents as mandatory on the live path.
        manifest = manifest_builder(
            planned,
            campaign_id,
            rerun_of=rerun_of,
            started_at=started_at,
            ended_at=now(),
            bundle_dir=bundle_dir,
        )
    try:
        seal_bundle(
            bundle_dir, manifest, instrument_only=instrument_only, publish_audit_anchor=not offline
        )  # type: ignore[arg-type]
    except SealError as error:
        return RunOutcome(planned.run_id, sealed=False, detail=str(error))
    return RunOutcome(planned.run_id, sealed=True, detail="sealed")


def run_cell(
    condition: str,
    scenario_id: str,
    injection: str,
    seed: int,
    *,
    campaign_id: str,
    out_root: Path,
    offline: bool = False,
    skip_preflight: bool = False,
    instrument_only: bool = False,
    **live_options: object,
) -> RunOutcome:
    """Dispatch one first-attempt grid run and seal its bundle."""
    _validate_coordinates(condition, scenario_id, injection, seed, instrument_only=instrument_only)
    run_id = format_run_id(RunId(condition, scenario_id, injection, seed))
    baseline_id = (
        format_baseline_id(BaselineId("LOAD-STEADY", seed))
        if requires_baseline_pairing(condition)
        else None
    )
    return run_planned(
        PlannedRun(
            run_id=run_id,
            condition=condition,
            scenario_id=scenario_id,
            injection_condition=injection,
            seed=seed,
            is_baseline=False,
            baseline_run_id=baseline_id,
            load_profile_id="LOAD-STEADY",
        ),
        campaign_id=campaign_id,
        out_root=out_root,
        offline=offline,
        skip_preflight=skip_preflight,
        instrument_only=instrument_only,
        **live_options,  # type: ignore[arg-type]
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="run", description="One grid run to a sealed bundle (T6.1)."
    )
    parser.add_argument("--cond", required=True, help="the arm token (one of six canonical arms)")
    parser.add_argument("--scn", required=True, help="the scenario id, SCN-<CLASS>-<nn>")
    parser.add_argument("--inj", required=True, help="the injection condition")
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--campaign", required=True, help="the campaign id, CAMP-<yyyymmdd>-<slug>")
    parser.add_argument("--out-root", type=Path, default=REPO_ROOT / "runs")
    parser.add_argument("--offline", action="store_true", help="deterministic telemetry")
    parser.add_argument("--skip-preflight", action="store_true")
    parser.add_argument(
        "--instrument-only",
        action="store_true",
        help=(
            "P0-live probe mode: apply the condition flags, run the scenario and its "
            "injections and collate the evidence, but run NO agent graph and seal under "
            "the probe profile (WS-5)"
        ),
    )
    stop = parser.add_mutually_exclusive_group()
    stop.add_argument("--duration", type=float, metavar="SECONDS")
    stop.add_argument("--samples", type=int, metavar="N")
    args = parser.parse_args(argv)

    try:
        window = None
        if not args.offline:
            window = MeasurementWindow(samples=args.samples, duration_seconds=args.duration)
        elif args.samples is not None or args.duration is not None:
            raise RunError("--samples/--duration apply only to a live run")
        outcome = run_cell(
            args.cond,
            args.scn,
            args.inj,
            args.seed,
            campaign_id=args.campaign,
            out_root=args.out_root,
            offline=args.offline,
            skip_preflight=args.skip_preflight,
            instrument_only=args.instrument_only,
            window=window,
        )
    except (RunError, ValueError) as error:
        print(f"run: {error}", file=sys.stderr)
        return 1
    if not outcome.sealed:
        print(f"run: {outcome.run_id} did not seal: {outcome.detail}", file=sys.stderr)
        return 1
    print(f"run: PASS — {outcome.run_id} sealed under {args.out_root}/{args.campaign}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
