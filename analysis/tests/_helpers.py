r"""Hand-authored bundle fixtures for the analysis tests, written under a caller's tmp_path.

These build the smallest bundle that exercises a measure -- a `manifest.json` plus whichever of
`assertions.json`, `guardian_audit.jsonl`, `resources.csv` a test needs -- rather than depending on
the full synthetic corpus, which `runner/synthetic.py` (T6.6) builds separately. Every field name
here is `data-management.md` §1/§2's, so a fixture that drifts from the schema is a fixture the
loader would reject in the same way a real bundle would.
"""

import csv
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from analysis.stats import Bundle, load_bundle  # noqa: E402

SYNTHETIC_CAMPAIGN = "CAMP-20260827-synthetic"


def write_bundle(
    directory: Path,
    *,
    run_id: str,
    condition: str | None,
    scenario_id: str | None,
    injection_condition: str | None,
    seed: int | None,
    campaign_id: str = SYNTHETIC_CAMPAIGN,
    is_baseline: bool = False,
    baseline_run_id: str | None = None,
    load_profile_id: str | None = None,
    assertions: list[dict] | None = None,
    required_substep_results: list[dict] | None = None,
    payload_outcome: dict | None = None,
    guardian_audit: list[dict] | None = None,
    results: list[dict] | None = None,
    resources: list[dict] | None = None,
    probes: list[dict] | None = None,
    locust_stats: list[dict] | None = None,
    monitor_events: list[dict] | None = None,
    scores: dict | None = None,
    tokens: list[dict] | None = None,
    fidelity: dict | None = None,
    k8s_api_audit: list[dict] | None = None,
    write_metrics_json: bool = False,
) -> Path:
    """Write one bundle directory and return it.

    Only the files a test names are written; the rest are simply absent, which is exactly how
    `data-management.md` §3's two profiles differ. ``write_metrics_json`` plants a
    deliberately-garbage `metrics.json` so a test can prove the loader never reads it.
    """
    directory.mkdir(parents=True, exist_ok=True)
    manifest = {
        "run_id": run_id,
        "campaign_id": campaign_id,
        "condition": condition,
        "scenario_id": scenario_id,
        "injection_condition": injection_condition,
        "seed": seed,
        "is_baseline": is_baseline,
        "baseline_run_id": baseline_run_id,
        "load_profile_id": load_profile_id,
        "schema_version": "v1",
    }
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    if assertions is not None or payload_outcome is not None:
        payload = {
            "run_id": run_id,
            "scenario_id": scenario_id,
            "groundtruth_sha256": "0" * 64,
            "assertions": assertions or [],
            "required_substep_results": required_substep_results or [],
        }
        if payload_outcome is not None:
            # SEAM 5: runner/evaluate_assertions.py writes payload_outcome into assertions.json.
            payload["payload_outcome"] = payload_outcome
        (directory / "assertions.json").write_text(json.dumps(payload), encoding="utf-8")

    if guardian_audit is not None:
        lines = "\n".join(json.dumps(record) for record in guardian_audit)
        (directory / "guardian_audit.jsonl").write_text(lines + "\n", encoding="utf-8")

    if results is not None:
        (directory / "results.json").write_text(json.dumps(results), encoding="utf-8")

    if monitor_events is not None:
        lines = "\n".join(json.dumps(record) for record in monitor_events)
        (directory / "monitor_events.jsonl").write_text(lines + "\n", encoding="utf-8")

    if resources is not None:
        _write_csv(directory / "resources.csv", resources)

    if probes is not None:
        _write_csv(directory / "probes.csv", probes)

    if locust_stats is not None:
        _write_csv(directory / "locust_stats.csv", locust_stats)

    if scores is not None:
        (directory / "scores.json").write_text(json.dumps(scores), encoding="utf-8")

    if tokens is not None:
        (directory / "tokens.json").write_text(json.dumps(tokens), encoding="utf-8")

    if fidelity is not None:
        (directory / "fidelity.json").write_text(json.dumps(fidelity), encoding="utf-8")

    if k8s_api_audit is not None:
        lines = "\n".join(json.dumps(record) for record in k8s_api_audit)
        (directory / "k8s_api_audit.jsonl").write_text(lines + "\n", encoding="utf-8")

    if write_metrics_json:
        (directory / "metrics.json").write_text('{"do_not": "read me"}', encoding="utf-8")

    return directory


def _write_csv(path: Path, rows: list[dict]) -> None:
    """Write ``rows`` as a CSV with a header, in the first row's key order."""
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def phase_outcome_assertions(results_by_phase: dict[str, list[str]]) -> list[dict]:
    """Build phase-outcome assertions from a ``{phase: [result, ...]}`` map (pass/fail)."""
    assertions: list[dict] = []
    index = 0
    for phase, results in results_by_phase.items():
        for result in results:
            index += 1
            assertions.append(
                {
                    "assertion_id": f"ASR-{index:02d}",
                    "kind": "phase-outcome",
                    "phase": phase,
                    "result": result,
                    "observed": "",
                    "evaluated_at": "2026-08-27T00:00:00+00:00",
                }
            )
    return assertions


def required_substep_results(results_by_phase: dict[str, list[str]]) -> list[dict]:
    """Build explicit sub-step results from a ``{phase: [result, ...]}`` map."""
    results: list[dict] = []
    for phase, phase_results in results_by_phase.items():
        for index, result in enumerate(phase_results, 1):
            results.append(
                {
                    "substep_id": f"SUB-{index:02d}",
                    "phase": phase,
                    "result": result,
                    "observed": "",
                    "evaluated_at": "2026-08-27T00:00:00+00:00",
                }
            )
    return results


def end_state_assertions(results: list[str]) -> list[dict]:
    """Build end-state-compromise assertions from a list of results (pass/fail)."""
    assertions: list[dict] = []
    for offset, result in enumerate(results):
        assertions.append(
            {
                "assertion_id": f"ASR-{11 + offset:02d}",
                "kind": "end-state-compromise",
                "phase": None,
                "result": result,
                "observed": "",
                "evaluated_at": "2026-08-27T00:00:00+00:00",
            }
        )
    return assertions


def all_phases_pass() -> dict[str, list[str]]:
    """The four phases, each with one passing phase-outcome assertion -- a fully correct run."""
    return {
        "detection-and-investigation": ["pass"],
        "containment": ["pass"],
        "eradication": ["pass"],
        "verified-recovery": ["pass"],
    }


def load(directory: Path) -> Bundle:
    """Load a written fixture directory back into a :class:`Bundle`."""
    return load_bundle(directory)
