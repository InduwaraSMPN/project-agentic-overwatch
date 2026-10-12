r"""make campaign: validate the grid, order it, and refuse to start on an invalid manifest.

The preflight (make status / parity-check / determinism-check / synthetic-proof) needs a live tree
and is Tier B, so these tests use ``skip_preflight`` to exercise the validate-and-order half -- the
part that is checkable offline. The order returned is the T-24 interleaving, produced and countable
now.
"""

import sys
from dataclasses import replace
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import json  # noqa: E402

import pytest  # noqa: E402

from runner.bundle import seal_bundle  # noqa: E402
from runner.campaign import CampaignManifest, to_canonical_bytes  # noqa: E402
from runner.campaign_cli import (  # noqa: E402
    AttemptResult,
    CampaignExecution,
    CampaignHaltError,
    CampaignRunError,
    _DefaultDriver,
    _invoke_driver,
    classify_failure,
    execute_campaign,
    main,
    run_campaign,
)
from runner.grid import build_campaign_manifest  # noqa: E402
from runner.synthetic import populate_bundle, synthetic_manifest  # noqa: E402


def _write(manifest: CampaignManifest, path: Path) -> Path:
    path.write_bytes(to_canonical_bytes(manifest))
    return path


def test_a_valid_campaign_validates_and_orders(tmp_path: Path) -> None:
    manifest = build_campaign_manifest("CAMP-20260101-pilot", campaign_seed=101)
    path = _write(manifest, tmp_path / "campaign.json")
    order = run_campaign(path, campaign_seed=101, skip_preflight=True)
    assert len(order) == 755  # 750 grid + 5 baselines


def test_the_order_is_deterministic_from_the_campaign_seed(tmp_path: Path) -> None:
    path = _write(
        build_campaign_manifest("CAMP-20260101-pilot", campaign_seed=101), tmp_path / "c.json"
    )
    assert run_campaign(path, 101, skip_preflight=True) == run_campaign(
        path, 101, skip_preflight=True
    )
    with pytest.raises(CampaignRunError, match="does not match frozen manifest seed"):
        run_campaign(path, 202, skip_preflight=True)


def test_an_invalid_manifest_is_refused_before_ordering(tmp_path: Path) -> None:
    manifest = build_campaign_manifest("CAMP-20260101-pilot", campaign_seed=101)
    short = replace(manifest, runs=manifest.runs[:-10])
    path = _write(short, tmp_path / "bad.json")
    with pytest.raises(CampaignRunError):
        run_campaign(path, 101, skip_preflight=True)


def test_a_malformed_manifest_file_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "junk.json"
    path.write_text(json.dumps({"not": "a campaign"}), encoding="utf-8")
    with pytest.raises(Exception):  # noqa: B017 - CampaignError or JSON error, both are refusals
        run_campaign(path, 101, skip_preflight=True)


def test_resume_skips_sealed_cells_and_keeps_the_regenerated_order(tmp_path: Path) -> None:
    """M7-C8: a resumed campaign regenerates the order and skips cells that already sealed."""
    from runner.campaign_cli import resume_order

    manifest = build_campaign_manifest("CAMP-20260101-pilot", campaign_seed=101)
    order = run_campaign(_write(manifest, tmp_path / "c.json"), 101, skip_preflight=True)
    campaign_dir = tmp_path / manifest.campaign_id
    # nothing sealed yet: resume is the whole order, in order
    assert resume_order(order, campaign_dir) == order
    # Seal the first ten cells through the real sealer; existence alone is not completion.
    planned_by_id = {run.run_id: run for run in manifest.runs}
    for index, run_id in enumerate(order[:10]):
        planned = planned_by_id[run_id]
        bundle = campaign_dir / run_id
        bundle.mkdir(parents=True, exist_ok=True)
        populate_bundle(bundle, planned, seed=101)
        seal_bundle(
            bundle,
            synthetic_manifest(planned, manifest.campaign_id, index),
            sealed_at="2026-01-01T00:00:00Z",
        )
    remaining = resume_order(order, campaign_dir)
    assert remaining == order[10:]  # exactly the un-sealed tail, order preserved
    assert len(remaining) == len(order) - 10


def test_resume_is_a_pure_suffix_never_a_reshuffle(tmp_path: Path) -> None:
    """Skipping done cells must not reorder the rest -- T-24 survives an interruption."""
    from runner.campaign_cli import resume_order

    manifest = build_campaign_manifest("CAMP-20260101-pilot", campaign_seed=101)
    order = run_campaign(_write(manifest, tmp_path / "c.json"), 101, skip_preflight=True)
    campaign_dir = tmp_path / manifest.campaign_id
    # Seal a scattered subset through the real sealer.
    planned_by_id = {run.run_id: run for run in manifest.runs}
    sealed_ids = (order[3], order[17], order[100])
    for index, run_id in enumerate(sealed_ids):
        planned = planned_by_id[run_id]
        bundle = campaign_dir / run_id
        bundle.mkdir(parents=True, exist_ok=True)
        populate_bundle(bundle, planned, seed=101)
        seal_bundle(
            bundle,
            synthetic_manifest(planned, manifest.campaign_id, index),
            sealed_at="2026-01-01T00:00:00Z",
        )
    remaining = resume_order(order, campaign_dir)
    # every remaining id keeps its relative order from the original
    positions = [order.index(r) for r in remaining]
    assert positions == sorted(positions)
    assert set(remaining) == set(order) - set(sealed_ids)


def test_resume_retries_a_bundle_with_only_a_malformed_seal(tmp_path: Path) -> None:
    """A crash-created seal.json is not completion unless the whole bundle verifies."""
    from runner.campaign_cli import resume_order

    run_id = "RUN-G0-FULL-SCN-CVE-03-INJ-A-101"
    bundle = tmp_path / run_id
    bundle.mkdir()
    (bundle / "seal.json").write_text("{}", encoding="utf-8")
    assert resume_order((run_id,), tmp_path) == (run_id,)


def test_resume_retries_a_tampered_sealed_bundle(tmp_path: Path) -> None:
    """A sealed bundle whose recorded content changed must be rerun, not skipped."""
    from runner.campaign_cli import resume_order

    manifest = build_campaign_manifest("CAMP-20260101-pilot", campaign_seed=101)
    planned = next(run for run in manifest.runs if not run.is_baseline)
    bundle = tmp_path / planned.run_id
    bundle.mkdir()
    populate_bundle(bundle, planned, seed=101)
    seal_bundle(
        bundle,
        synthetic_manifest(planned, manifest.campaign_id),
        sealed_at="2026-01-01T00:00:00Z",
    )
    assert resume_order((planned.run_id,), tmp_path) == ()
    (bundle / "probes.csv").write_text("tampered\n", encoding="utf-8")
    assert resume_order((planned.run_id,), tmp_path) == (planned.run_id,)


def _small_manifest() -> CampaignManifest:
    manifest = build_campaign_manifest("CAMP-20260101-pilot", campaign_seed=101)
    return replace(
        manifest,
        runs=(manifest.runs[0], manifest.runs[-1]),
        generated_order=(manifest.runs[0].run_id, manifest.runs[-1].run_id),
    )


def test_execution_uses_injected_drivers_and_continues_after_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _small_manifest()
    order = tuple(run.run_id for run in manifest.runs)
    monkeypatch.setattr("runner.campaign_cli.validate_campaign_manifest", lambda _manifest: {})
    monkeypatch.setattr("runner.campaign_cli.generate_order", lambda _manifest, _seed: order)
    seen: list[str] = []

    class Outcome:
        def __init__(self, run_id: str, sealed: bool) -> None:
            self.run_id = run_id
            self.sealed = sealed
            self.detail = "sealed" if sealed else "boom"

    def driver(planned, rerun_of):
        seen.append(planned.run_id)
        bundle = tmp_path / manifest.campaign_id / planned.run_id
        bundle.mkdir(parents=True, exist_ok=True)
        if len(seen) == 1:
            return Outcome(planned.run_id, False)
        populate_bundle(bundle, planned, planned.seed)
        seal_bundle(
            bundle,
            synthetic_manifest(planned, manifest.campaign_id, rerun_of=rerun_of),
            sealed_at="2026-01-01T00:00:00Z",
        )
        return Outcome(planned.run_id, True)

    result = execute_campaign(
        manifest,
        manifest.campaign_seed,
        out_root=tmp_path,
        run_driver=driver,
        baseline_driver=driver,
        max_attempts_per_cell=1,
        enforce_freeze=False,
        hold_lease=False,
    )
    assert seen == list(order)
    assert result.attempted[0].invalid
    assert (tmp_path / manifest.campaign_id / order[0] / "invalid.json").is_file()
    assert result.attempted[1].sealed


def test_execution_reruns_corrupt_attempt_with_suffix_and_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _small_manifest()
    planned = manifest.runs[0]
    manifest = replace(manifest, runs=(planned,), generated_order=(planned.run_id,))
    monkeypatch.setattr("runner.campaign_cli.validate_campaign_manifest", lambda _manifest: {})
    monkeypatch.setattr(
        "runner.campaign_cli.generate_order", lambda _manifest, _seed: (planned.run_id,)
    )
    corrupt = tmp_path / manifest.campaign_id / planned.run_id
    corrupt.mkdir(parents=True)
    (corrupt / "seal.json").write_text("{}", encoding="utf-8")
    calls: list[tuple[str, str | None]] = []

    class Outcome:
        sealed = True
        detail = "sealed"

        def __init__(self, run_id: str) -> None:
            self.run_id = run_id

    def driver(attempt, rerun_of):
        calls.append((attempt.run_id, rerun_of))
        bundle = tmp_path / manifest.campaign_id / attempt.run_id
        bundle.mkdir(parents=True)
        populate_bundle(bundle, attempt, attempt.seed)
        seal_bundle(
            bundle,
            synthetic_manifest(attempt, manifest.campaign_id, rerun_of=rerun_of),
            sealed_at="2026-01-01T00:00:00Z",
        )
        return Outcome(attempt.run_id)

    result = execute_campaign(
        manifest,
        manifest.campaign_seed,
        out_root=tmp_path,
        run_driver=driver,
        baseline_driver=driver,
        max_attempts_per_cell=1,
        enforce_freeze=False,
        hold_lease=False,
    )
    assert calls == [(planned.run_id + "-R2", planned.run_id)]
    assert result.attempted[0].rerun_of == planned.run_id
    assert (corrupt / "seal.json").read_text(encoding="utf-8") == "{}"
    assert (corrupt / "invalid.json").is_file()


def test_successful_retry_completes_and_retains_flake_count() -> None:
    execution = CampaignExecution(
        "CAMP-20260101-pilot",
        (
            AttemptResult("RUN-A", "CELL-A", False, True, "failed"),
            AttemptResult("RUN-A-R2", "CELL-A", True, False, "sealed", "RUN-A"),
        ),
        (),
    )
    assert execution.complete
    assert execution.flake_count == 1


def test_cli_returns_success_for_complete_campaign_with_retained_invalid_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = _small_manifest()
    path = _write(manifest, tmp_path / "campaign.json")
    execution = CampaignExecution(
        manifest.campaign_id,
        (
            AttemptResult("RUN-A", "CELL-A", False, True, "failed"),
            AttemptResult("RUN-A-R2", "CELL-A", True, False, "sealed", "RUN-A"),
        ),
        (),
    )
    monkeypatch.setattr("runner.campaign_cli.run_campaign", lambda *_args, **_kwargs: ())
    monkeypatch.setattr("runner.campaign_cli.execute_campaign", lambda *_args, **_kwargs: execution)
    assert main(["--manifest", str(path), "--seed", "101", "--execute", "--offline"]) == 0
    output = capsys.readouterr().out
    assert "PASS" in output
    assert "1 invalid attempts, 1 flakes" in output


def test_live_cli_requires_window_and_reports_adapter_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = _small_manifest()
    path = _write(manifest, tmp_path / "campaign.json")
    monkeypatch.setattr("runner.campaign_cli.run_campaign", lambda *_args, **_kwargs: ())
    monkeypatch.setattr("runner.live_run.dependencies_from_environment", lambda: (object(), "url"))
    assert main(["--manifest", str(path), "--seed", "101", "--execute"]) == 1
    assert "requires exactly one of --samples or --duration" in capsys.readouterr().err


def test_live_cli_wires_default_run_and_baseline_adapters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _small_manifest()
    path = _write(manifest, tmp_path / "campaign.json")
    captured: dict[str, object] = {}
    execution = CampaignExecution(
        manifest.campaign_id, (), tuple(run.run_id for run in manifest.runs)
    )
    monkeypatch.setattr("runner.campaign_cli.run_campaign", lambda *_args, **_kwargs: ())
    monkeypatch.setattr("runner.live_run.dependencies_from_environment", lambda: (object(), "url"))

    def capture(*_args, **kwargs):
        captured.update(kwargs)
        return execution

    monkeypatch.setattr("runner.campaign_cli.execute_campaign", capture)
    assert (
        main(
            [
                "--manifest",
                str(path),
                "--seed",
                "101",
                "--execute",
                "--samples",
                "2",
            ]
        )
        == 0
    )
    run_driver = captured["run_driver"]
    baseline_driver = captured["baseline_driver"]
    assert not run_driver.offline and not run_driver.baseline
    assert not baseline_driver.offline and baseline_driver.baseline
    assert run_driver.window.samples == 2


def test_default_driver_timeout_terminates_and_joins_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[object] = []

    class Queue:
        def close(self) -> None:
            events.append("queue-closed")

    class Process:
        exitcode = None

        def start(self) -> None:
            events.append("started")

        def join(self, timeout=None) -> None:
            events.append(("joined", timeout))

        def is_alive(self) -> bool:
            return True

        def terminate(self) -> None:
            events.append("terminated")

    class Context:
        def Queue(self):
            return Queue()

        def Process(self, **_kwargs):
            return Process()

    monkeypatch.setattr("runner.campaign_cli.multiprocessing.get_context", lambda _mode: Context())
    planned = _small_manifest().runs[0]
    driver = _DefaultDriver("CAMP-20260101-pilot", tmp_path, True, None, False)
    with pytest.raises(TimeoutError, match="runner timeout"):
        _invoke_driver(driver, planned, None, 0.01)
    assert events == ["started", ("joined", 0.01), "terminated", ("joined", None), "queue-closed"]


def test_execution_timeout_marks_invalid_and_continues(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _small_manifest()
    order = tuple(run.run_id for run in manifest.runs)
    monkeypatch.setattr("runner.campaign_cli.validate_campaign_manifest", lambda _manifest: {})
    monkeypatch.setattr("runner.campaign_cli.generate_order", lambda _manifest, _seed: order)

    mutations: list[str] = []

    def driver(planned, rerun_of):
        import time

        time.sleep(0.05)
        mutations.append(planned.run_id)
        raise AssertionError("late result must not count")

    result = execute_campaign(
        manifest,
        manifest.campaign_seed,
        out_root=tmp_path,
        run_driver=driver,
        baseline_driver=driver,
        timeout_seconds=0.001,
        max_attempts_per_cell=1,
        enforce_freeze=False,
        hold_lease=False,
    )
    assert len(result.attempted) == len(order)
    assert all(item.invalid and "timeout" in item.detail for item in result.attempted)
    assert mutations == list(
        order
    )  # timeout joins injected drivers before campaign mutation resumes


class _Sealed:
    """A driver outcome for a sealed run: the small surface execute_campaign reads."""

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.sealed = True
        self.detail = "sealed"


def _make_sealing_driver(out_root: Path, campaign_id: str):
    """A driver that writes and seals a healthy synthetic bundle for whatever attempt it is given.

    Shared by the M10 halt-loop tests: each seals a real, integrity-sound bundle through the real
    ``seal_bundle`` (so ``fidelity.json`` is written and the loop's post-seal reads run), and
    reports ``sealed=True``.
    """

    def driver(attempt, rerun_of):
        bundle = out_root / campaign_id / attempt.run_id
        bundle.mkdir(parents=True, exist_ok=True)
        populate_bundle(bundle, attempt, attempt.seed)
        seal_bundle(
            bundle,
            synthetic_manifest(attempt, campaign_id, rerun_of=rerun_of),
            sealed_at="2026-01-01T00:00:00Z",
        )
        return _Sealed(attempt.run_id)

    return driver


def _two_grid_manifest() -> CampaignManifest:
    """A two-cell manifest whose cells are BOTH framework-on grid runs (no baseline).

    The halt-loop tests read ``fidelity.json`` and ``answered_model`` from sealed cells; a baseline
    carries neither, so these tests use two grid runs, not the grid+baseline ``_small_manifest``.
    """
    full = build_campaign_manifest("CAMP-20260101-pilot", campaign_seed=101)
    grid = tuple(run for run in full.runs if not run.is_baseline)[:2]
    return replace(full, runs=grid, generated_order=tuple(run.run_id for run in grid))


def test_freeze_refuses_a_dirty_instrument(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """P6/ADR-136: the per-cell freeze calls runner.freeze.enforce_freeze; a dirty instrument (a
    FreezeError) refuses the campaign as a CampaignRunError, and no cell runs. This replaces the v1
    whole-repository dirty check (defect V14) -- a docs-only edit no longer halts, an instrument one
    does."""
    from runner.freeze import FreezeError

    manifest = _small_manifest()
    order = tuple(run.run_id for run in manifest.runs)
    monkeypatch.setattr("runner.campaign_cli.validate_campaign_manifest", lambda _manifest: {})
    monkeypatch.setattr("runner.campaign_cli.generate_order", lambda _manifest, _seed: order)

    def refuse(campaign_dir, freeze_tag=None, **kwargs):
        raise FreezeError("the instrument has uncommitted changes at runner/x.py")

    monkeypatch.setattr("runner.freeze.enforce_freeze", refuse)

    def driver(_attempt, _rerun_of):  # pragma: no cover - must never run
        raise AssertionError("a cell ran despite a dirty instrument")

    with pytest.raises(CampaignRunError, match="uncommitted changes"):
        execute_campaign(
            manifest,
            manifest.campaign_seed,
            out_root=tmp_path,
            run_driver=driver,
            baseline_driver=driver,
            max_attempts_per_cell=1,
            hold_lease=False,
        )


def test_freeze_refuses_instrument_drift_after_the_first_cell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """P6/ADR-136: enforce_freeze runs before EVERY cell, so an instrument that moves after the
    first cell (a FreezeError on the second call) refuses the next cell -- no session may change the
    instrument while the campaign runs."""
    from runner.freeze import FreezeError

    manifest = _small_manifest()
    order = tuple(run.run_id for run in manifest.runs)
    monkeypatch.setattr("runner.campaign_cli.validate_campaign_manifest", lambda _manifest: {})
    monkeypatch.setattr("runner.campaign_cli.generate_order", lambda _manifest, _seed: order)
    calls: list[object] = []

    def enforce(campaign_dir, freeze_tag=None, **kwargs):
        calls.append(freeze_tag)
        if len(calls) >= 2:
            raise FreezeError(
                "the instrument digest at HEAD is not the digest at freeze tag 'v2.0'; "
                "the instrument moved after the freeze"
            )
        return "frozen-commit"

    monkeypatch.setattr("runner.freeze.enforce_freeze", enforce)
    driver = _make_sealing_driver(tmp_path, manifest.campaign_id)

    with pytest.raises(CampaignRunError, match="instrument moved"):
        execute_campaign(
            manifest,
            manifest.campaign_seed,
            out_root=tmp_path,
            run_driver=driver,
            baseline_driver=driver,
            max_attempts_per_cell=1,
            hold_lease=False,
        )
    # The freeze was consulted before each cell: the first passed, the second refused.
    assert len(calls) == 2
    # The first cell sealed on the frozen instrument before the drift was caught.
    assert (tmp_path / manifest.campaign_id / order[0] / "seal.json").is_file()


# --------------------------------------------------------------------------------------------
# M10 fidelity-gated halting loop (WS-5; ADR-120 halt/failure-classes/lifetime-cap, ADR-123
# answered-model halt, ADR-133 checkpoint readiness gate). The campaign loop now READS each sealed
# bundle's fidelity.json and halts on a class-T failure; classifies unsealed attempts; persists a
# lifetime attempt cap across invocations; halts on an answered-model change; and runs the readiness
# gate once after the first interleave round.
# --------------------------------------------------------------------------------------------


def test_campaign_halts_on_sealed_t_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A sealed, integrity-sound bundle whose fidelity.json carries a class-T failure HALTS the
    campaign (ADR-120): HALTED.json is written and CampaignHaltError is raised out of the loop, and
    the treatment failure is never rerun. The second cell is never reached."""
    manifest = _two_grid_manifest()
    order = manifest.generated_order
    monkeypatch.setattr("runner.campaign_cli.validate_campaign_manifest", lambda _manifest: {})
    monkeypatch.setattr("runner.campaign_cli.generate_order", lambda _manifest, _seed: order)

    def fake_read_fidelity(bundle_dir):
        # every sealed bundle reports a class-T fidelity failure
        return {
            "schema_version": "fidelity.v1",
            "run_id": Path(bundle_dir).name,
            "instrument_digest": None,
            "checks": [
                {
                    "id": "F-MN-01",
                    "klass": "T",
                    "stage": "seal",
                    "status": "fail",
                    "detail": "quoting carryover",
                }
            ],
            "summary": {},
        }

    monkeypatch.setattr("runner.campaign_cli.read_fidelity", fake_read_fidelity)
    driven: list[str] = []
    seal = _make_sealing_driver(tmp_path, manifest.campaign_id)

    def driver(attempt, rerun_of):
        driven.append(attempt.run_id)
        return seal(attempt, rerun_of)

    with pytest.raises(CampaignHaltError, match="F-MN-01"):
        execute_campaign(
            manifest,
            manifest.campaign_seed,
            out_root=tmp_path,
            run_driver=driver,
            baseline_driver=driver,
            max_attempts_per_cell=1,
            enforce_freeze=False,
            hold_lease=False,
        )
    halted = tmp_path / manifest.campaign_id / "HALTED.json"
    assert halted.is_file()
    payload = json.loads(halted.read_text(encoding="utf-8"))
    assert payload["reason"] == "treatment-fidelity"
    assert "F-MN-01" in payload["failures"]
    assert driven == [order[0]]  # halted at the first sealed cell, never reached the second


def test_campaign_halts_on_native_missing_open_sentinel_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real sealer records the failure before hashes; the native loop reads it and halts."""
    manifest = _two_grid_manifest()
    monkeypatch.setattr("runner.campaign_cli.validate_campaign_manifest", lambda _manifest: {})
    monkeypatch.setattr(
        "runner.campaign_cli.generate_order", lambda _manifest, _seed: manifest.generated_order
    )
    driven = []

    def driver(attempt, rerun_of):
        driven.append(attempt.run_id)
        bundle = tmp_path / manifest.campaign_id / attempt.run_id
        bundle.mkdir(parents=True)
        populate_bundle(bundle, attempt, attempt.seed)
        audit = bundle / "k8s_api_audit.jsonl"
        records = [json.loads(line) for line in audit.read_text().splitlines()]
        audit.write_text(
            "".join(
                json.dumps(record) + "\n"
                for record in records
                if record.get("annotations", {}).get("overwatch.io/window-sentinel") != "open"
            ),
            encoding="utf-8",
        )
        seal_bundle(
            bundle,
            synthetic_manifest(attempt, manifest.campaign_id, rerun_of=rerun_of),
            sealed_at="2026-01-01T00:00:00Z",
        )
        return _Sealed(attempt.run_id)

    with pytest.raises(CampaignHaltError, match="F-GD-06"):
        execute_campaign(
            manifest,
            manifest.campaign_seed,
            out_root=tmp_path,
            run_driver=driver,
            baseline_driver=driver,
            max_attempts_per_cell=1,
            enforce_freeze=False,
            hold_lease=False,
        )
    assert driven == [manifest.generated_order[0]]
    campaign = tmp_path / manifest.campaign_id
    halted = json.loads((campaign / "HALTED.json").read_text())
    assert halted["reason"] == "treatment-fidelity" and "F-GD-06" in halted["failures"]
    report = json.loads((campaign / driven[0] / "fidelity.json").read_text())
    assert any(check["id"] == "F-GD-06" and check["status"] == "fail" for check in report["checks"])


def test_infra_failure_reruns_on_same_instrument_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """classify_failure sorts unsealed attempts: infra and delivery-miss rerun on the same
    instrument, an instrument failure halts (ADR-120). An infra failure is retried as -R2 and seals;
    an instrument failure writes HALTED.json and is never rerun."""
    # The classification contract, asserted directly.
    assert classify_failure(detail="attempt exceeded 5s runner timeout", timed_out=True) == "infra"
    assert (
        classify_failure(detail="driver failed: provider unreachable", timed_out=False) == "infra"
    )
    assert (
        classify_failure(detail="INJ-B payload did not land in monitor_events", timed_out=False)
        == "delivery-miss"
    )
    assert (
        classify_failure(
            detail="messages.jsonl entry 3 has no non-negative integer 'index'", timed_out=False
        )
        == "instrument"
    )

    manifest = _two_grid_manifest()
    order = manifest.generated_order
    monkeypatch.setattr("runner.campaign_cli.validate_campaign_manifest", lambda _manifest: {})
    monkeypatch.setattr("runner.campaign_cli.generate_order", lambda _manifest, _seed: order)

    # Infra: the first attempt fails transiently; the rerun (-R2) on the same instrument seals.
    seen: list[str] = []
    seal = _make_sealing_driver(tmp_path, manifest.campaign_id)

    def infra_then_seal(attempt, rerun_of):
        seen.append(attempt.run_id)
        if len(seen) == 1:
            outcome = _Sealed(attempt.run_id)
            outcome.sealed = False
            outcome.detail = "driver failed: provider unreachable"
            return outcome
        return seal(attempt, rerun_of)

    result = execute_campaign(
        manifest,
        manifest.campaign_seed,
        out_root=tmp_path,
        run_driver=infra_then_seal,
        baseline_driver=infra_then_seal,
        max_attempts_per_cell=2,
        enforce_freeze=False,
        hold_lease=False,
    )
    assert seen[:2] == [order[0], order[0] + "-R2"]  # infra reran on the same cell's instrument
    assert result.complete
    assert not (tmp_path / manifest.campaign_id / "HALTED.json").exists()

    # Instrument: a deterministic defect a rerun cannot fix halts on the first attempt (no -R2).
    other = tmp_path / "instrument"
    attempts: list[str] = []

    def instrument_fail(attempt, _rerun_of):
        attempts.append(attempt.run_id)
        raise RuntimeError("messages.jsonl entry 3 has no non-negative integer 'index'")

    with pytest.raises(CampaignHaltError, match="instrument"):
        execute_campaign(
            manifest,
            manifest.campaign_seed,
            out_root=other,
            run_driver=instrument_fail,
            baseline_driver=instrument_fail,
            max_attempts_per_cell=3,
            enforce_freeze=False,
            hold_lease=False,
        )
    assert attempts == [order[0]]  # halted on the first attempt, not rerun
    halted = other / manifest.campaign_id / "HALTED.json"
    assert halted.is_file()
    assert json.loads(halted.read_text(encoding="utf-8"))["reason"] == "instrument"


def test_lifetime_attempt_cap_survives_reinvocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The per-cell attempt count is a LIFETIME counter persisted in attempts.json (defect V15). It
    accumulates across separate execute_campaign invocations, never exceeds the cap, and a cell that
    reaches the cap without sealing halts; a further invocation refuses the halted campaign."""
    full = build_campaign_manifest("CAMP-20260101-pilot", campaign_seed=101)
    planned = next(run for run in full.runs if not run.is_baseline)
    manifest = replace(full, runs=(planned,), generated_order=(planned.run_id,))
    order = (planned.run_id,)
    monkeypatch.setattr("runner.campaign_cli.validate_campaign_manifest", lambda _manifest: {})
    monkeypatch.setattr("runner.campaign_cli.generate_order", lambda _manifest, _seed: order)
    calls: list[str] = []

    def always_infra(attempt, _rerun_of):
        calls.append(attempt.run_id)
        outcome = _Sealed(attempt.run_id)
        outcome.sealed = False
        outcome.detail = "driver failed: provider unreachable"
        return outcome

    cap = 3
    attempts_path = tmp_path / manifest.campaign_id / "attempts.json"

    # The first cap-1 invocations each spend one attempt and stay below the cap without halting.
    for _ in range(cap - 1):
        result = execute_campaign(
            manifest,
            manifest.campaign_seed,
            out_root=tmp_path,
            run_driver=always_infra,
            baseline_driver=always_infra,
            max_attempts_per_cell=1,
            lifetime_attempts_cap=cap,
            enforce_freeze=False,
            hold_lease=False,
        )
        assert not result.complete
    assert json.loads(attempts_path.read_text(encoding="utf-8"))[order[0]] == cap - 1

    # The invocation that reaches the cap halts.
    with pytest.raises(CampaignHaltError, match="lifetime attempt cap"):
        execute_campaign(
            manifest,
            manifest.campaign_seed,
            out_root=tmp_path,
            run_driver=always_infra,
            baseline_driver=always_infra,
            max_attempts_per_cell=1,
            lifetime_attempts_cap=cap,
            enforce_freeze=False,
            hold_lease=False,
        )
    assert json.loads(attempts_path.read_text(encoding="utf-8"))[order[0]] == cap
    assert (tmp_path / manifest.campaign_id / "HALTED.json").is_file()

    # A further invocation refuses to resume the halted campaign and drives nothing more.
    with pytest.raises(CampaignHaltError, match="halted"):
        execute_campaign(
            manifest,
            manifest.campaign_seed,
            out_root=tmp_path,
            run_driver=always_infra,
            baseline_driver=always_infra,
            max_attempts_per_cell=1,
            lifetime_attempts_cap=cap,
            enforce_freeze=False,
            hold_lease=False,
        )
    assert json.loads(attempts_path.read_text(encoding="utf-8"))[order[0]] == cap
    assert len(calls) == cap  # cap attempts total; the halted-resume invocation drove nothing


def test_answered_model_change_halts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A change of the provider-returned answered model across runs HALTS the campaign (ADR-123):
    the first sealed run fixes the campaign's answered model and a later run reporting a different
    one writes HALTED.json and raises."""
    manifest = _two_grid_manifest()
    order = manifest.generated_order
    monkeypatch.setattr("runner.campaign_cli.validate_campaign_manifest", lambda _manifest: {})
    monkeypatch.setattr("runner.campaign_cli.generate_order", lambda _manifest, _seed: order)
    models = {order[0]: "llama-3.3-70b", order[1]: "gpt-5.6-terra"}
    monkeypatch.setattr(
        "runner.campaign_cli._bundle_answered_model",
        lambda bundle_dir: models.get(Path(bundle_dir).name),
    )
    driver = _make_sealing_driver(tmp_path, manifest.campaign_id)

    with pytest.raises(CampaignHaltError, match="answered model changed"):
        execute_campaign(
            manifest,
            manifest.campaign_seed,
            out_root=tmp_path,
            run_driver=driver,
            baseline_driver=driver,
            max_attempts_per_cell=1,
            enforce_freeze=False,
            hold_lease=False,
        )
    halted = tmp_path / manifest.campaign_id / "HALTED.json"
    assert halted.is_file()
    payload = json.loads(halted.read_text(encoding="utf-8"))
    assert payload["reason"] == "answered-model-change"
    assert payload["prior"] == "llama-3.3-70b"
    assert payload["current"] == "gpt-5.6-terra"
    # The first run fixed the campaign's answered model before the second changed it.
    recorded = json.loads(
        (tmp_path / manifest.campaign_id / "answered_model.json").read_text(encoding="utf-8")
    )
    assert recorded["answered_model"] == "llama-3.3-70b"


def test_checkpoint_after_first_interleave_round(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """After the first interleave round (checkpoint_cells completed cells) the readiness gate runs
    ONCE with checkpoint semantics (F-AN-01, ADR-133). A GO lets the campaign finish and records the
    checkpoint; a NO-GO writes HALTED.json and halts."""
    manifest = _two_grid_manifest()
    order = manifest.generated_order
    monkeypatch.setattr("runner.campaign_cli.validate_campaign_manifest", lambda _manifest: {})
    monkeypatch.setattr("runner.campaign_cli.generate_order", lambda _manifest, _seed: order)
    driver = _make_sealing_driver(tmp_path, manifest.campaign_id)
    calls: list[Path] = []

    def gate(campaign_dir):
        calls.append(Path(campaign_dir))
        return "GO"

    result = execute_campaign(
        manifest,
        manifest.campaign_seed,
        out_root=tmp_path,
        run_driver=driver,
        baseline_driver=driver,
        max_attempts_per_cell=1,
        checkpoint_cells=2,
        checkpoint_gate=gate,
        enforce_freeze=False,
        hold_lease=False,
    )
    assert result.complete
    # The gate ran exactly once, after the first interleave round of two cells completed.
    assert calls == [tmp_path / manifest.campaign_id]
    state = json.loads(
        (tmp_path / manifest.campaign_id / "checkpoint.json").read_text(encoding="utf-8")
    )
    assert state["ran"] is True
    assert state["verdict"] == "GO"
    assert state["completed"] == 2

    # A NO-GO verdict at the checkpoint halts the campaign.
    other = tmp_path / "nogo"
    nogo_driver = _make_sealing_driver(other, manifest.campaign_id)
    with pytest.raises(CampaignHaltError, match="checkpoint"):
        execute_campaign(
            manifest,
            manifest.campaign_seed,
            out_root=other,
            run_driver=nogo_driver,
            baseline_driver=nogo_driver,
            max_attempts_per_cell=1,
            checkpoint_cells=2,
            checkpoint_gate=lambda _campaign_dir: "NO-GO",
            enforce_freeze=False,
            hold_lease=False,
        )
    assert (other / manifest.campaign_id / "HALTED.json").is_file()


# --------------------------------------------------------------------------------------------
# Supervisor resumability gate (2026-09-14, before the 750-run pilot): the cluster Lease held
# across the whole campaign span, per-cell quarantine-and-retry proven within one invocation (not
# only across separate ones), and checkpoint-and-resume proven end to end through execute_campaign
# itself rather than only through resume_order in isolation.
# --------------------------------------------------------------------------------------------


def test_a_failed_attempt_is_retried_within_one_invocation_up_to_max_attempts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Per-cell quarantine-and-retry: a cell whose first attempt fails is retried automatically
    inside the same execute_campaign call, not only across separate invocations -- the existing
    retry coverage above only ever exercised max_attempts_per_cell=1."""
    manifest = _small_manifest()
    order = tuple(run.run_id for run in manifest.runs)
    monkeypatch.setattr("runner.campaign_cli.validate_campaign_manifest", lambda _manifest: {})
    monkeypatch.setattr("runner.campaign_cli.generate_order", lambda _manifest, _seed: order)
    attempts_seen: list[str] = []

    class Outcome:
        def __init__(self, run_id: str, sealed: bool) -> None:
            self.run_id = run_id
            self.sealed = sealed
            self.detail = "sealed" if sealed else "boom"

    def driver(attempt, rerun_of):
        attempts_seen.append(attempt.run_id)
        bundle = tmp_path / manifest.campaign_id / attempt.run_id
        bundle.mkdir(parents=True, exist_ok=True)
        if len(attempts_seen) == 1:  # only the campaign's very first attempt fails
            return Outcome(attempt.run_id, False)
        populate_bundle(bundle, attempt, attempt.seed)
        seal_bundle(
            bundle,
            synthetic_manifest(attempt, manifest.campaign_id, rerun_of=rerun_of),
            sealed_at="2026-01-01T00:00:00Z",
        )
        return Outcome(attempt.run_id, True)

    result = execute_campaign(
        manifest,
        manifest.campaign_seed,
        out_root=tmp_path,
        run_driver=driver,
        baseline_driver=driver,
        max_attempts_per_cell=2,
        enforce_freeze=False,
        hold_lease=False,
    )
    assert attempts_seen == [order[0], order[0] + "-R2", order[1]]
    assert result.complete
    assert result.flake_count == 1
    first_cell = [a for a in result.attempted if a.cell_id == order[0]]
    assert [a.sealed for a in first_cell] == [False, True]
    assert (tmp_path / manifest.campaign_id / order[0] / "invalid.json").is_file()
    assert (tmp_path / manifest.campaign_id / (order[0] + "-R2") / "seal.json").is_file()


def test_execute_campaign_holds_the_lease_once_across_the_whole_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cluster Lease is acquired once at campaign start and released once at the end, not
    reacquired per cell -- proven against a multi-cell order via kubectl call counts on a fake
    lease cluster (the same fake ``runner/tests/test_run_lock.py`` uses for ``cluster_lease``
    itself)."""
    from runner.tests.test_run_lock import _FakeLeaseCluster

    manifest = _small_manifest()
    order = tuple(run.run_id for run in manifest.runs)
    monkeypatch.setattr("runner.campaign_cli.validate_campaign_manifest", lambda _manifest: {})
    monkeypatch.setattr("runner.campaign_cli.generate_order", lambda _manifest, _seed: order)
    assert len(order) > 1  # a real multi-cell order, or "once, not per cell" proves nothing
    fake = _FakeLeaseCluster(initial=None)

    class Outcome:
        def __init__(self, run_id: str) -> None:
            self.run_id = run_id
            self.sealed = True
            self.detail = "sealed"

    def driver(attempt, rerun_of):
        bundle = tmp_path / manifest.campaign_id / attempt.run_id
        bundle.mkdir(parents=True, exist_ok=True)
        populate_bundle(bundle, attempt, attempt.seed)
        seal_bundle(
            bundle,
            synthetic_manifest(attempt, manifest.campaign_id, rerun_of=rerun_of),
            sealed_at="2026-01-01T00:00:00Z",
        )
        return Outcome(attempt.run_id)

    result = execute_campaign(
        manifest,
        manifest.campaign_seed,
        out_root=tmp_path,
        run_driver=driver,
        baseline_driver=driver,
        max_attempts_per_cell=1,
        enforce_freeze=False,
        hold_lease=True,
        run_kubectl=fake,
    )
    assert result.complete
    assert [call[2] for call in fake.calls] == ["get", "create", "get", "delete"]
    assert fake.holder() is None


def test_execute_campaign_refuses_a_foreign_held_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A campaign must not start at all -- let alone drive a single cell -- while another live run
    or campaign already holds the cluster Lease (ADR-087)."""
    from datetime import UTC, datetime

    from runner.tests.test_run_lock import _FakeLeaseCluster

    manifest = _small_manifest()
    order = tuple(run.run_id for run in manifest.runs)
    monkeypatch.setattr("runner.campaign_cli.validate_campaign_manifest", lambda _manifest: {})
    monkeypatch.setattr("runner.campaign_cli.generate_order", lambda _manifest, _seed: order)
    now = datetime.now(UTC)
    fake = _FakeLeaseCluster(initial=("RUN-OTHER/2026-09-13T11:59:00Z/host/1", now, 3600))

    def driver(_attempt, _rerun_of):  # pragma: no cover - must never run
        raise AssertionError("a cell ran despite a foreign lease holder")

    with pytest.raises(CampaignRunError, match="RUN-OTHER"):
        execute_campaign(
            manifest,
            manifest.campaign_seed,
            out_root=tmp_path,
            run_driver=driver,
            baseline_driver=driver,
            max_attempts_per_cell=1,
            enforce_freeze=False,
            hold_lease=True,
            run_kubectl=fake,
        )


def test_an_interrupted_campaign_resumes_without_rerunning_sealed_cells(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """M7-C8 end to end: a campaign that dies partway through -- some cells sealed, one mid-attempt
    failure stops the batch -- resumes on a fresh execute_campaign call and never redrives a cell
    that already sealed. resume_order's own unit tests above cover the pure function in isolation;
    this covers execute_campaign actually driving it across two invocations, the checkpoint-and-
    resume proof the resumability gate (2026-09-14) asks for."""
    full = build_campaign_manifest("CAMP-20260101-pilot", campaign_seed=101)
    manifest = replace(
        full,
        runs=full.runs[:6],
        generated_order=tuple(run.run_id for run in full.runs[:6]),
    )
    order = tuple(run.run_id for run in manifest.runs)
    monkeypatch.setattr("runner.campaign_cli.validate_campaign_manifest", lambda _manifest: {})
    monkeypatch.setattr("runner.campaign_cli.generate_order", lambda _manifest, _seed: order)

    def seal(attempt, rerun_of):
        bundle = tmp_path / manifest.campaign_id / attempt.run_id
        bundle.mkdir(parents=True, exist_ok=True)
        populate_bundle(bundle, attempt, attempt.seed)
        seal_bundle(
            bundle,
            synthetic_manifest(attempt, manifest.campaign_id, rerun_of=rerun_of),
            sealed_at="2026-01-01T00:00:00Z",
        )

    class Outcome:
        def __init__(self, run_id: str, sealed: bool) -> None:
            self.run_id = run_id
            self.sealed = sealed
            self.detail = "sealed" if sealed else "boom"

    seen_first: list[str] = []

    def crashes_on_the_fourth_cell(attempt, rerun_of):
        seen_first.append(attempt.run_id)
        if len(seen_first) > 3:
            raise RuntimeError("simulated interruption: the campaign process died here")
        seal(attempt, rerun_of)
        return Outcome(attempt.run_id, True)

    with pytest.raises(CampaignRunError, match="invalid"):
        execute_campaign(
            manifest,
            manifest.campaign_seed,
            out_root=tmp_path,
            run_driver=crashes_on_the_fourth_cell,
            baseline_driver=crashes_on_the_fourth_cell,
            max_attempts_per_cell=1,
            continue_on_failure=False,
            enforce_freeze=False,
            hold_lease=False,
        )
    assert seen_first == list(order[:4])  # three sealed; the fourth's failure stopped the batch

    seen_second: list[str] = []

    def always_succeeds(attempt, rerun_of):
        seen_second.append(attempt.run_id)
        seal(attempt, rerun_of)
        return Outcome(attempt.run_id, True)

    result = execute_campaign(
        manifest,
        manifest.campaign_seed,
        out_root=tmp_path,
        run_driver=always_succeeds,
        baseline_driver=always_succeeds,
        max_attempts_per_cell=1,
        enforce_freeze=False,
        hold_lease=False,
    )
    # The resumed invocation never redrives the three cells that sealed before the interruption.
    assert len(seen_second) == 3
    assert set(result.skipped) == set(order[:3])
    assert [a.cell_id for a in result.attempted] == list(order[3:])
    assert result.complete
    for cell_id in order[:3]:
        assert not (tmp_path / manifest.campaign_id / f"{cell_id}-R2").exists()
