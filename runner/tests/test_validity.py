"""Offline checks for the remaining data-management section 4 validity rules."""

import csv
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from infra.probes.constants import PROBE_INTERVAL_SECONDS  # noqa: E402
from infra.probes.slo_probe import PROBES_CSV_HEADER  # noqa: E402

from runner.grid import build_campaign_manifest  # noqa: E402
from runner.synthetic import populate_bundle, synthetic_manifest  # noqa: E402
from runner.validity import (  # noqa: E402
    MeasurementWindowUnavailable,
    check_run_validity,
    measurement_window_samples,
)


def _framework_bundle(tmp_path: Path):
    campaign = build_campaign_manifest("CAMP-20260101-pilot")
    planned = next(
        run
        for run in campaign.runs
        if run.condition == "G1-LOGONLY" and run.scenario_id == "SCN-CVE-04"
    )
    bundle = tmp_path / planned.run_id
    bundle.mkdir()
    populate_bundle(bundle, planned, planned.seed)
    return bundle, synthetic_manifest(planned, campaign.campaign_id)


def _write_probes(path: Path, seconds: tuple[float, ...]) -> None:
    fields = ("ts", "probe_id", "target", "method", "status_code", "latency_ms", "ok", "error")
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for second in seconds:
            writer.writerow(
                {
                    "ts": f"2026-01-01T00:00:{second:06.3f}Z",
                    "probe_id": "PROBE-FRONTEND-HEALTHZ",
                    "target": "/_healthz",
                    "method": "GET",
                    "status_code": 200,
                    "latency_ms": 1,
                    "ok": "true",
                    "error": "",
                }
            )


def _codes(bundle: Path, manifest, **kwargs: object) -> set[str]:
    return {finding.code for finding in check_run_validity(bundle, manifest, **kwargs)}


def _write_multi_tick_probes(path: Path, ticks: int, probes_per_tick: int = 2) -> None:
    """Write a well-formed ``probes.csv`` folding into exactly ``ticks`` passes of the probe set."""
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(PROBES_CSV_HEADER))
        writer.writeheader()
        for tick in range(ticks):
            for probe_index in range(probes_per_tick):
                writer.writerow(
                    {
                        "ts": f"2026-01-01T00:{tick:02d}:{probe_index:02d}+00:00",
                        "probe_id": f"PROBE-{probe_index}",
                        "target": "/_healthz",
                        "method": "GET",
                        "status_code": 200,
                        "latency_ms": 1,
                        "ok": "true",
                        "error": "",
                    }
                )


def _write_multi_tick_resources(path: Path, ticks: int) -> None:
    """Write a well-formed ``resources.csv`` with exactly ``ticks`` distinct sample timestamps."""
    fields = (
        "ts",
        "series",
        "namespace",
        "workload",
        "container",
        "cpu_cores",
        "mem_bytes",
        "storage_bytes",
        "restarts_total",
    )
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for tick in range(ticks):
            writer.writerow(
                {
                    "ts": f"2026-01-01T00:{tick:02d}:00+00:00",
                    "series": "app",
                    "namespace": "boutique",
                    "workload": "frontend",
                    "container": "server",
                    "cpu_cores": 0.1,
                    "mem_bytes": 100,
                    "storage_bytes": 0,
                    "restarts_total": 0,
                }
            )


def test_probe_gap_boundary_comes_from_protocol_mirror(tmp_path: Path) -> None:
    bundle, manifest = _framework_bundle(tmp_path)
    threshold = PROBE_INTERVAL_SECONDS * 3
    _write_probes(bundle / "probes.csv", (0.0, float(threshold)))
    assert "probe-gap" not in _codes(bundle, manifest)

    _write_probes(bundle / "probes.csv", (0.0, threshold + 0.001))
    assert "probe-gap" in _codes(bundle, manifest)


def test_probe_gaps_are_compared_per_probe_id(tmp_path: Path) -> None:
    bundle, manifest = _framework_bundle(tmp_path)
    path = bundle / "probes.csv"
    rows = path.read_text(encoding="utf-8").splitlines()
    header = rows[0]
    path.write_text(
        header
        + "\n2026-01-01T00:00:00Z,p1,/,GET,200,1,true,"
        + "\n2026-01-01T00:00:14Z,p2,/,GET,200,1,true,"
        + "\n2026-01-01T00:00:16Z,p1,/,GET,200,1,true,\n",
        encoding="utf-8",
    )
    assert "probe-gap" in _codes(bundle, manifest)


def test_unrelated_oom_marker_invalidates_but_scenario_target_is_exempt(tmp_path: Path) -> None:
    bundle, manifest = _framework_bundle(tmp_path)
    unrelated = {
        "summary": "pod terminated OOMKilled",
        "resource": {"ns": "boutique", "kind": "Pod", "name": "frontend"},
    }
    (bundle / "monitor_events.jsonl").write_text(json.dumps(unrelated) + "\n", encoding="utf-8")
    assert "infra-failure" in _codes(bundle, manifest)

    # SCN-CVE-04's target workload is adservice since ADR-091 (was productcatalogservice); an OOM on
    # the scenario's own target is the incident doing its job, not infra flake, so it is exempt.
    related = {
        "summary": "pod terminated OOMKilled",
        "resource": {"ns": "boutique", "kind": "Pod", "name": "adservice"},
    }
    (bundle / "monitor_events.jsonl").write_text(json.dumps(related) + "\n", encoding="utf-8")
    assert "infra-failure" not in _codes(bundle, manifest)


def test_per_call_alias_or_provider_change_invalidates_framework_run(tmp_path: Path) -> None:
    bundle, manifest = _framework_bundle(tmp_path)
    calls = [
        {"model_alias": manifest.model_alias, "model": manifest.model_provider_string},
        {"model_alias": "switched-alias", "model": "other/provider"},
    ]
    (bundle / "tokens.json").write_text(json.dumps(calls), encoding="utf-8")
    assert "model-alias-changed" in _codes(bundle, manifest)


def test_baseline_is_exempt_from_model_and_scenario_marker_checks(tmp_path: Path) -> None:
    campaign = build_campaign_manifest("CAMP-20260101-pilot")
    planned = next(run for run in campaign.runs if run.is_baseline)
    bundle = tmp_path / planned.run_id
    bundle.mkdir()
    populate_bundle(bundle, planned, planned.seed)
    manifest = synthetic_manifest(planned, campaign.campaign_id)
    (bundle / "tokens.json").write_text('[{"model_alias":"changed"}]', encoding="utf-8")
    assert "model-alias-changed" not in _codes(bundle, manifest)
    assert "infra-failure" not in _codes(bundle, manifest)


def _entry(manifest, index: int, attempt_models: list[object] | None) -> dict:
    """One tokens.json entry answered under the manifest's alias and provider at the call level.

    ``attempt_models`` becomes ADR-060's ``attempt_usage``, one record per request, each answered
    under the model given; ``None`` writes the entry as it was before ADR-060, with no attempts.
    """
    entry: dict = {
        "index": index,
        "phase": "containment",
        "role_id": "executor",
        "model_alias": manifest.model_alias,
        "model": manifest.model_provider_string,
        "prompt_tokens": 110,
        "completion_tokens": 30,
    }
    if attempt_models is not None:
        entry["attempt_usage"] = [
            {
                "attempt": number,
                "model": model,
                "prompt_tokens": 100,
                "completion_tokens": 20,
                "reasoning_tokens": None,
            }
            for number, model in enumerate(attempt_models, 1)
        ]
    return entry


def _write_tokens(bundle: Path, entries: list[dict]) -> None:
    (bundle / "tokens.json").write_text(json.dumps(entries), encoding="utf-8")


def test_a_substitution_on_an_earlier_attempt_invalidates_the_run(tmp_path: Path) -> None:
    """The entry-level model is the last answer's (ADR-060): only attempt_usage shows this one."""
    bundle, manifest = _framework_bundle(tmp_path)
    attempts = ["other/provider", manifest.model_provider_string]
    _write_tokens(bundle, [_entry(manifest, 0, attempts)])
    assert "model-alias-changed" in _codes(bundle, manifest)


def test_every_attempt_on_the_manifest_provider_leaves_the_run_valid(tmp_path: Path) -> None:
    """A retried call, a call that sent no request, and an entry written before ADR-060."""
    bundle, manifest = _framework_bundle(tmp_path)
    provider = manifest.model_provider_string
    entries = [
        _entry(manifest, 0, [provider, provider]),
        _entry(manifest, 1, []),
        _entry(manifest, 2, None),
    ]
    _write_tokens(bundle, entries)
    assert "model-alias-changed" not in _codes(bundle, manifest)


def test_an_attempt_the_check_cannot_read_is_not_waved_through(tmp_path: Path) -> None:
    """An attempt without a model, a non-record attempt, and an attempt list that is not a list."""
    bundle, manifest = _framework_bundle(tmp_path)
    for attempt_usage in ([{"attempt": 1}], ["not-a-record"], None):
        entry = _entry(manifest, 0, None)
        entry["attempt_usage"] = attempt_usage
        _write_tokens(bundle, [entry])
        assert "model-alias-changed" in _codes(bundle, manifest), attempt_usage


# --- ADR-085 / supervisor ruling B3: the measurement-window refusal --------------------------


def test_measurement_window_samples_reads_the_live_protocol_value_without_restating_it() -> None:
    """Reads the real evaluation-protocol.md; checks shape only, never repeats its literal value.

    Asserting the exact number here would be a fourth occurrence of a value
    .agents/rules/00-source-of-truth.md single-homes in evaluation-protocol.md section 4 (the
    protocol prose and this reader are two of the other three); this test is about the read
    succeeding and returning something plausible, not about which positive integer it currently is.
    """
    value = measurement_window_samples()
    assert isinstance(value, int)
    assert value > 0


def test_measurement_window_samples_parses_the_documented_bold_backtick_form(
    tmp_path: Path,
) -> None:
    """The parser accepts exactly section 4's spelling, exercised against a fixture value.

    A fixture number "resembling nothing real", for the reason
    infra/tests/test_constants_match_protocol.py's FIXTURE_BLOCK gives for doing the same: the M1
    Definition of done greps each real protocol value for exactly two occurrences, and a fixture
    reusing the real 121 would be an uncounted third.
    """
    protocol = tmp_path / "evaluation-protocol.md"
    protocol.write_text(
        "some prose **`measurement_window_samples: 9973`** more prose\n", encoding="utf-8"
    )
    assert measurement_window_samples(protocol) == 9973


def test_measurement_window_samples_refuses_to_invent_a_value(tmp_path: Path) -> None:
    """A protocol whose wording no longer matches the expected form is a loud, named refusal."""
    protocol = tmp_path / "evaluation-protocol.md"
    protocol.write_text(
        "measurement_window_samples: 121 (no bold, no backticks: not what this reader expects)\n",
        encoding="utf-8",
    )
    with pytest.raises(MeasurementWindowUnavailable, match="no longer states"):
        measurement_window_samples(protocol)
    with pytest.raises(MeasurementWindowUnavailable, match="cannot read"):
        measurement_window_samples(tmp_path / "does-not-exist.md")


def test_window_checks_are_opt_in_and_off_by_default(tmp_path: Path) -> None:
    """Every existing caller's synthetic fixtures keep validating clean with no window_samples.

    ``runner/campaign_cli.py``, ``runner/pilot_cli.py`` and ``runner/validate.py`` all call
    ``check_run_validity(bundle_dir, manifest)`` with no ``window_samples`` today, against bundles
    ``runner/synthetic.py`` builds from a handful of hand-written rows -- nowhere near a real
    121-tick window. Defaulting the new checks on regressed eight of their passing tests (confirmed
    against runner/tests/test_validate.py and runner/tests/test_campaign_cli.py while building this
    change); none of those three call sites, nor runner/synthetic.py, is a file this stream may
    edit, so the default has to stay out of their way. See check_run_validity's own docstring and
    ADR-085.
    """
    bundle, manifest = _framework_bundle(tmp_path)
    _write_multi_tick_probes(bundle / "probes.csv", ticks=1)
    _write_multi_tick_resources(bundle / "resources.csv", ticks=1)
    assert _codes(bundle, manifest) == set()


def test_probe_window_short_is_reported_only_when_asked_for(tmp_path: Path) -> None:
    bundle, manifest = _framework_bundle(tmp_path)
    _write_multi_tick_probes(bundle / "probes.csv", ticks=2)
    assert "probe-window-short" not in _codes(bundle, manifest)
    assert "probe-window-short" in _codes(bundle, manifest, window_samples=5)
    assert "probe-window-short" not in _codes(bundle, manifest, window_samples=2)


def test_resource_window_short_is_reported_only_when_asked_for(tmp_path: Path) -> None:
    bundle, manifest = _framework_bundle(tmp_path)
    _write_multi_tick_resources(bundle / "resources.csv", ticks=2)
    assert "resource-window-short" not in _codes(bundle, manifest)
    assert "resource-window-short" in _codes(bundle, manifest, window_samples=5)
    assert "resource-window-short" not in _codes(bundle, manifest, window_samples=2)


def test_a_single_tick_has_no_gap_but_is_caught_by_the_window_check(tmp_path: Path) -> None:
    """Reproduces the exact defect ADR-085 fixes: one probe tick, no gap, but a collapsed window.

    RUN-G0-FULL-SCN-SIM-02-INJ-A-101 (2026-09-13) sealed with one probe tick against
    measurement_window_samples: 121, and its lone tick predated the first injection. A single
    sample has no neighbour, so the pre-existing gap check (data-management section 4's "gaps >
    probe interval x3") reports nothing wrong with it -- which is why that defect reached seal in
    the first place, and exactly why this second check exists.
    """
    bundle, manifest = _framework_bundle(tmp_path)
    _write_multi_tick_probes(bundle / "probes.csv", ticks=1)
    codes = _codes(bundle, manifest, window_samples=121)
    assert "probe-gap" not in codes
    assert "probe-window-short" in codes


def test_window_findings_defer_to_the_existing_malformed_timeline_finding(tmp_path: Path) -> None:
    """A file the gap check already calls invalid is not also reported as merely short."""
    bundle, manifest = _framework_bundle(tmp_path)
    (bundle / "probes.csv").write_text("not,a,probes,csv\n1,2,3,4\n", encoding="utf-8")
    codes = _codes(bundle, manifest, window_samples=121)
    assert "probe-timeline-invalid" in codes
    assert "probe-window-short" not in codes


def test_a_wide_enough_window_reports_neither_new_code(tmp_path: Path) -> None:
    bundle, manifest = _framework_bundle(tmp_path)
    _write_multi_tick_probes(bundle / "probes.csv", ticks=3)
    _write_multi_tick_resources(bundle / "resources.csv", ticks=3)
    codes = _codes(bundle, manifest, window_samples=3)
    assert "probe-window-short" not in codes
    assert "resource-window-short" not in codes


def test_baseline_bundles_are_not_exempt_from_the_window_check(tmp_path: Path) -> None:
    """Unlike the model/scenario checks, a short window invalidates a baseline too.

    A baseline is required to carry probes.csv and resources.csv exactly as a framework-on run is
    (data-management section 3's baseline profile), and RQ4's overhead and interference deltas need
    a baseline window as long as the framework-on run it is matched against -- so there is no reason
    to read a baseline's short window as anything other than the same defect.
    """
    campaign = build_campaign_manifest("CAMP-20260101-pilot")
    planned = next(run for run in campaign.runs if run.is_baseline)
    bundle = tmp_path / planned.run_id
    bundle.mkdir()
    populate_bundle(bundle, planned, planned.seed)
    manifest = synthetic_manifest(planned, campaign.campaign_id)
    _write_multi_tick_probes(bundle / "probes.csv", ticks=1)
    assert "probe-window-short" in _codes(bundle, manifest, window_samples=121)
