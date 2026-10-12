r"""The loader reads raw bundle files and refuses the ``metrics.json`` cache (data-mgmt §8)."""

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from analysis.stats import (  # noqa: E402
    BundleError,
    MetricsJsonRefused,
    load_bundle,
    load_campaign,
    refuse_metrics_json,
    sealed_bundle_directories,
)
from analysis.tests._helpers import (  # noqa: E402
    all_phases_pass,
    phase_outcome_assertions,
    write_bundle,
)


def test_refuse_metrics_json_raises_on_a_metrics_json_path() -> None:
    """The refusal fires on the file name, whichever directory the cache is addressed under."""
    with pytest.raises(MetricsJsonRefused):
        refuse_metrics_json(Path("runs/CAMP-x/RUN-y/metrics.json"))


def test_refuse_metrics_json_passes_through_any_other_bundle_file() -> None:
    """A legitimate raw file is returned unchanged, so only the cache is blocked."""
    path = Path("runs/CAMP-x/RUN-y/assertions.json")
    assert refuse_metrics_json(path) == path


def test_load_bundle_reads_the_manifest_and_assertions_and_ignores_metrics_json(
    tmp_path: Path,
) -> None:
    """A bundle carrying a garbage metrics.json still loads, because the loader never reads it."""
    directory = write_bundle(
        tmp_path / "RUN-G0-FULL-SCN-CVE-04-INJ-A-101",
        run_id="RUN-G0-FULL-SCN-CVE-04-INJ-A-101",
        condition="G0-FULL",
        scenario_id="SCN-CVE-04",
        injection_condition="INJ-A",
        seed=101,
        assertions=phase_outcome_assertions(all_phases_pass()),
        write_metrics_json=True,
    )
    bundle = load_bundle(directory)
    assert bundle.run_id == "RUN-G0-FULL-SCN-CVE-04-INJ-A-101"
    assert bundle.condition == "G0-FULL"
    assert bundle.seed == 101
    assert bundle.assertions is not None
    assert len(bundle.assertions["assertions"]) == 4


def test_load_bundle_refuses_foreign_guardian_run_id(tmp_path: Path) -> None:
    run_id = "RUN-G0-FULL-SCN-CVE-04-INJ-A-101"
    directory = write_bundle(
        tmp_path / run_id,
        run_id=run_id,
        condition="G0-FULL",
        scenario_id="SCN-CVE-04",
        injection_condition="INJ-A",
        seed=101,
        guardian_audit=[{"run_id": "RUN-G0-FULL-SCN-CVE-04-INJ-A-102"}],
    )
    with pytest.raises(BundleError, match="foreign run_id"):
        load_bundle(directory)


def test_load_bundle_refuses_monitor_event_outside_manifest_window(tmp_path: Path) -> None:
    run_id = "RUN-G0-FULL-SCN-CVE-04-INJ-A-101"
    directory = write_bundle(
        tmp_path / run_id,
        run_id=run_id,
        condition="G0-FULL",
        scenario_id="SCN-CVE-04",
        injection_condition="INJ-A",
        seed=101,
        monitor_events=[{"event_id": "old", "ts": "2026-08-26T09:59:59Z"}],
    )
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.update(started_at="2026-08-26T10:00:00Z", ended_at="2026-08-26T10:01:00Z")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(BundleError, match="before the run window"):
        load_bundle(directory)


def test_load_bundle_reads_only_the_binding_span_document_in_close_order(tmp_path: Path) -> None:
    directory = write_bundle(
        tmp_path / "RUN-G0-FULL-SCN-CVE-04-INJ-A-101",
        run_id="RUN-G0-FULL-SCN-CVE-04-INJ-A-101",
        condition="G0-FULL",
        scenario_id="SCN-CVE-04",
        injection_condition="INJ-A",
        seed=101,
        assertions=phase_outcome_assertions(all_phases_pass()),
    )
    spans = [
        {"name": "node", "attributes": {"phase": "containment"}},
        {"name": "phase", "attributes": {"phase": "containment"}},
    ]
    (directory / "spans.otel.json").write_text(
        json.dumps({"spans": spans}, sort_keys=True) + "\n", encoding="utf-8"
    )
    (directory / "spans.jsonl").write_text('{"name":"legacy"}\n', encoding="utf-8")

    assert load_bundle(directory).spans == spans


def test_load_bundle_rejects_obsolete_json_lines_under_the_binding_name(tmp_path: Path) -> None:
    directory = write_bundle(
        tmp_path / "RUN-G0-FULL-SCN-CVE-04-INJ-A-101",
        run_id="RUN-G0-FULL-SCN-CVE-04-INJ-A-101",
        condition="G0-FULL",
        scenario_id="SCN-CVE-04",
        injection_condition="INJ-A",
        seed=101,
        assertions=phase_outcome_assertions(all_phases_pass()),
    )
    (directory / "spans.otel.json").write_text(
        '{"name":"first"}\n{"name":"second"}\n', encoding="utf-8"
    )

    with pytest.raises(BundleError, match="spans.otel.json"):
        load_bundle(directory)


def test_load_bundle_ignores_a_legacy_only_span_filename(tmp_path: Path) -> None:
    directory = write_bundle(
        tmp_path / "RUN-G0-FULL-SCN-CVE-04-INJ-A-101",
        run_id="RUN-G0-FULL-SCN-CVE-04-INJ-A-101",
        condition="G0-FULL",
        scenario_id="SCN-CVE-04",
        injection_condition="INJ-A",
        seed=101,
        assertions=phase_outcome_assertions(all_phases_pass()),
    )
    (directory / "spans.jsonl").write_text('{"name":"legacy"}\n', encoding="utf-8")

    assert load_bundle(directory).spans is None


def test_load_bundle_raises_when_a_directory_has_no_manifest(tmp_path: Path) -> None:
    """A directory without manifest.json is not a bundle, and is refused rather than half-read."""
    empty = tmp_path / "not-a-bundle"
    empty.mkdir()
    with pytest.raises(Exception, match="manifest"):
        load_bundle(empty)


def test_load_campaign_returns_only_verified_valid_bundles_sorted_by_run_id(
    tmp_path: Path,
) -> None:
    """Campaign ingestion excludes invalid attempts and verifies every included seal."""
    from runner.run import run_cell

    campaign_id = "CAMP-20260827-synthetic"
    outcomes = [
        run_cell(
            "G1-LOGONLY",
            "SCN-CVE-04",
            "INJ-A",
            seed,
            campaign_id=campaign_id,
            out_root=tmp_path,
            offline=True,
        )
        for seed in (102, 101)
    ]
    campaign = tmp_path / campaign_id
    (campaign / outcomes[0].run_id / "invalid.json").write_text(
        '{"invalid":true}\n', encoding="utf-8"
    )

    frame = load_campaign(campaign)
    assert list(frame["run_id"]) == [outcomes[1].run_id]
    assert frame["bundle"].iloc[0].condition == "G1-LOGONLY"


def test_load_campaign_rejects_an_unsealed_attempt(tmp_path: Path) -> None:
    campaign = tmp_path / "CAMP-20260827-synthetic"
    write_bundle(
        campaign / "RUN-G1-LOGONLY-SCN-CVE-04-INJ-A-101",
        run_id="RUN-G1-LOGONLY-SCN-CVE-04-INJ-A-101",
        condition="G1-LOGONLY",
        scenario_id="SCN-CVE-04",
        injection_condition="INJ-A",
        seed=101,
        assertions=phase_outcome_assertions(all_phases_pass()),
    )
    with pytest.raises(BundleError, match="invalid seal"):
        load_campaign(campaign)


def test_sealed_bundle_directories_excludes_a_manifest_that_never_reached_seal(
    tmp_path: Path,
) -> None:
    """A directory carrying both ``manifest.json`` and ``invalid.json`` but no ``seal.json`` --
    the real CAMP-20260914-campaign pattern (ADR-108's corpus_digest bugfix note) -- is excluded,
    the same as it is from :func:`load_campaign`, so a caller that only needs the directory set
    (e.g. ``analysis.render.corpus_digest``) never opens a ``seal.json`` that does not exist.
    """
    campaign = tmp_path / "CAMP-20260827-synthetic"
    write_bundle(
        campaign / "RUN-G1-LOGONLY-SCN-CVE-04-INJ-A-101",
        run_id="RUN-G1-LOGONLY-SCN-CVE-04-INJ-A-101",
        condition="G1-LOGONLY",
        scenario_id="SCN-CVE-04",
        injection_condition="INJ-A",
        seed=101,
        assertions=phase_outcome_assertions(all_phases_pass()),
    )
    (campaign / "RUN-G1-LOGONLY-SCN-CVE-04-INJ-A-101" / "invalid.json").write_text(
        '{"invalid":true,"reason":"probe-gap"}\n', encoding="utf-8"
    )
    assert sealed_bundle_directories(campaign) == []
