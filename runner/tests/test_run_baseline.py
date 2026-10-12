r"""make run and make baseline: coordinates to a sealed bundle, offline, with the arm flags correct.

These exercise the T6.1 contract without a cluster: a grid run seals a framework-on bundle whose
manifest carries the arm's flags from ``runner/conditions.py``; a baseline seals a framework-off
bundle under the baseline profile; a non-canonical arm and an unknown load profile are refused; and
a G0-FULL run names a baseline while an ablated arm does not.
"""

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402

from runner.baseline import BaselineError, run_baseline  # noqa: E402
from runner.conditions import flags_for  # noqa: E402
from runner.grid import PILOT_SEEDS  # noqa: E402
from runner.run import RunError, _validate_coordinates, run_cell  # noqa: E402
from runner.validate import validate_bundle  # noqa: E402

CAMPAIGN = "CAMP-20260101-synthetic"


def _manifest(bundle_dir: Path) -> dict:
    return json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))


def test_a_grid_run_seals_with_the_arms_flags(tmp_path: Path) -> None:
    """The sealed manifest's flag fields are the arm's, from the condition table, and validate."""
    outcome = run_cell(
        "G3-UNQUOTED",
        "SCN-CVE-04",
        "INJ-A",
        101,
        campaign_id=CAMPAIGN,
        out_root=tmp_path,
        offline=True,
    )
    assert outcome.sealed, outcome.detail
    bundle = tmp_path / CAMPAIGN / outcome.run_id
    manifest = _manifest(bundle)
    flags = flags_for("G3-UNQUOTED")
    assert manifest["graph_id"] == flags.graph_id
    assert manifest["guardian_mode"] == flags.guardian_mode == "G0-FULL"  # G3 routes to the Monitor
    assert manifest["aggregator_quoting"] is False


def test_a_g0_run_names_a_baseline_and_an_ablated_arm_does_not(tmp_path: Path) -> None:
    g0 = run_cell(
        "G0-FULL",
        "SCN-SIM-01",
        "INJ-B",
        102,
        campaign_id=CAMPAIGN,
        out_root=tmp_path,
        offline=True,
    )
    s2 = run_cell(
        "S2-FLAT",
        "SCN-SIM-01",
        "INJ-B",
        102,
        campaign_id=CAMPAIGN,
        out_root=tmp_path,
        offline=True,
    )
    assert _manifest(tmp_path / CAMPAIGN / g0.run_id)["baseline_run_id"] is not None
    assert _manifest(tmp_path / CAMPAIGN / s2.run_id)["baseline_run_id"] is None


def test_a_baseline_seals_under_the_baseline_profile(tmp_path: Path) -> None:
    outcome = run_baseline(
        "LOAD-STEADY", 101, campaign_id=CAMPAIGN, out_root=tmp_path, offline=True
    )
    assert outcome.sealed, outcome.detail
    bundle = tmp_path / CAMPAIGN / outcome.run_id
    manifest = _manifest(bundle)
    assert manifest["is_baseline"] is True
    assert manifest["condition"] is None
    # the nine framework-on artefacts are absent
    for forbidden in ("guardian_audit.jsonl", "assertions.json", "injection.log.jsonl"):
        assert not (bundle / forbidden).exists()


def test_a_sealed_grid_bundle_passes_validate_bundle(tmp_path: Path) -> None:
    from runner.manifest import from_dict

    outcome = run_cell(
        "G1-LOGONLY",
        "SCN-CVE-05",
        "INJ-D",
        103,
        campaign_id=CAMPAIGN,
        out_root=tmp_path,
        offline=True,
    )
    manifest = from_dict(_manifest(tmp_path / CAMPAIGN / outcome.run_id))
    validate_bundle(manifest)  # does not raise


def test_a_non_canonical_arm_is_refused(tmp_path: Path) -> None:
    with pytest.raises(RunError):
        run_cell(
            "S1-HIER",
            "SCN-CVE-04",
            "INJ-A",
            101,
            campaign_id=CAMPAIGN,
            out_root=tmp_path,
            offline=True,
        )


def test_an_unknown_load_profile_is_refused(tmp_path: Path) -> None:
    with pytest.raises(BaselineError):
        run_baseline("LOAD-BOGUS", 101, campaign_id=CAMPAIGN, out_root=tmp_path, offline=True)


@pytest.mark.parametrize(
    ("runner", "error"),
    [
        (
            lambda root: run_cell(
                "G1-LOGONLY",
                "SCN-SIM-01",
                "INJ-NONE",
                999,
                campaign_id=CAMPAIGN,
                out_root=root,
                offline=True,
            ),
            RunError,
        ),
        (
            lambda root: run_baseline(
                "LOAD-STEADY", 999, campaign_id=CAMPAIGN, out_root=root, offline=True
            ),
            BaselineError,
        ),
    ],
)
def test_direct_runners_refuse_seeds_outside_the_canonical_set(
    tmp_path: Path, runner, error: type[Exception]
) -> None:
    with pytest.raises(error, match="canonical protocol seed set"):
        runner(tmp_path)


def test_a_pilot_seed_is_accepted_only_for_an_instrument_only_probe() -> None:
    """A pilot seed is legal exactly when the run is a probe, and illegal for every other run.

    P0-live's probes seal into a pilot campaign directory, so they belong to the pilot seed space
    (docs/07-glossary-and-ids.md section Seeds); before this widening the probe mode had no seed it
    could legally be given, because the campaign seeds are the campaign's and the pilot seeds were
    refused outright. The widening is scoped to ``instrument_only``, so an ordinary grid run still
    cannot carry a pilot seed and a stray pilot-seed bundle cannot be manufactured outside the
    pilot manifests.
    """
    with pytest.raises(RunError, match="canonical protocol seed set"):
        _validate_coordinates("G0-FULL", "SCN-SIM-01", "INJ-NONE", PILOT_SEEDS[0])
    # The same coordinate is legal once the run declares itself a probe.
    _validate_coordinates("G0-FULL", "SCN-SIM-01", "INJ-NONE", PILOT_SEEDS[0], instrument_only=True)
    # A campaign seed stays legal in probe mode too: the widening only ever adds.
    _validate_coordinates("G0-FULL", "SCN-SIM-01", "INJ-NONE", 101, instrument_only=True)


def test_offline_run_refuses_a_missing_scenario_manifest(tmp_path: Path) -> None:
    with pytest.raises(RunError, match="no scenario manifest"):
        run_cell(
            "G1-LOGONLY",
            "SCN-SIM-99",
            "INJ-NONE",
            101,
            campaign_id=CAMPAIGN,
            out_root=tmp_path,
            offline=True,
        )


@pytest.mark.parametrize("kind", ["run", "baseline"])
def test_direct_runners_refuse_an_existing_bundle_directory(tmp_path: Path, kind: str) -> None:
    if kind == "run":

        def first():
            return run_cell(
                "G1-LOGONLY",
                "SCN-SIM-01",
                "INJ-NONE",
                101,
                campaign_id=CAMPAIGN,
                out_root=tmp_path,
                offline=True,
            )

        error = RunError
    else:

        def first():
            return run_baseline(
                "LOAD-STEADY", 101, campaign_id=CAMPAIGN, out_root=tmp_path, offline=True
            )

        error = BaselineError

    assert first().sealed
    with pytest.raises(error, match="refusing to reuse or merge"):
        first()


def test_live_baseline_runs_make_status_before_bundle_allocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[object, ...]] = []

    def failed_status(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 1)

    monkeypatch.setattr("runner.baseline.subprocess.run", failed_status)
    with pytest.raises(BaselineError, match=r"preflight `make status` is not green"):
        run_baseline(
            "LOAD-STEADY",
            101,
            campaign_id=CAMPAIGN,
            out_root=tmp_path,
            window=object(),  # type: ignore[arg-type]
        )

    assert calls[0][0] == ["make", "status"]
    assert not (tmp_path / CAMPAIGN).exists()


def test_offline_baseline_skips_make_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "runner.baseline.subprocess.run",
        lambda *_args, **_kwargs: pytest.fail("offline baseline invoked make status"),
    )
    assert run_baseline(
        "LOAD-STEADY", 101, campaign_id=CAMPAIGN, out_root=tmp_path, offline=True
    ).sealed
