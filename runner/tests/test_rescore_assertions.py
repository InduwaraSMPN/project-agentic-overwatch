"""``scripts/rescore_assertions.py`` re-scores a sealed bundle without writing into it (ADR-088)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from scripts import rescore_assertions

RUN_ID = "RUN-G0-FULL-SCN-SIM-01-INJ-NONE-101"
SCENARIO = "SCN-SIM-01"
PHASES = (
    "detection-and-investigation",
    "containment",
    "eradication",
    "verified-recovery",
)


def _sealed_bundle(campaign_dir: Path, *, audit: list[dict[str, Any]] | None = None) -> Path:
    """A minimal bundle ``evaluate_run_assertions`` can read; sealing itself is monkeypatched."""
    bundle = campaign_dir / RUN_ID
    bundle.mkdir()
    (bundle / "manifest.json").write_text(
        json.dumps(
            {
                "run_id": RUN_ID,
                "scenario_id": SCENARIO,
                "injection_condition": "INJ-NONE",
                "is_baseline": False,
            }
        ),
        encoding="utf-8",
    )
    rows = audit or []
    for index, row in enumerate(rows):
        row.setdefault("seq", index + 1)
    (bundle / "guardian_audit.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8"
    )
    (bundle / "results.json").write_text("[]", encoding="utf-8")
    (bundle / "messages.jsonl").write_text(
        "".join(json.dumps({"phase": phase, "text": "x"}) + "\n" for phase in PHASES),
        encoding="utf-8",
    )
    (bundle / "monitor_events.jsonl").write_text('{"event":"falco"}\n', encoding="utf-8")
    (bundle / "probes.csv").write_text(
        "ts,probe_id,target,method,status_code,latency_ms,ok,error\n"
        "2026-01-01T00:00:00Z,PROBE-FRONTEND-CART,/cart,GET,200,40,true,\n",
        encoding="utf-8",
    )
    (bundle / "assertions.json").write_text("{}", encoding="utf-8")  # the ORIGINAL, sealed one
    (bundle / "seal.json").write_text(
        json.dumps({"sealed_at": "2026-01-01T00:00:00Z"}), encoding="utf-8"
    )
    return bundle


def _snapshot(bundle: Path) -> dict[str, bytes]:
    return {path.name: path.read_bytes() for path in bundle.iterdir()}


def test_rescore_writes_outside_the_bundle_and_never_touches_it(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(rescore_assertions, "verify_content_hashes", lambda _path: [])
    campaign_dir = tmp_path / "CAMP-TEST"
    campaign_dir.mkdir()
    bundle = _sealed_bundle(campaign_dir)
    before = _snapshot(bundle)

    destination = rescore_assertions.rescore_bundle(bundle)

    assert destination == campaign_dir / "_rescored" / RUN_ID / "assertions.json"
    assert destination.is_file()
    assert bundle not in destination.parents, "the re-score must land beside the bundle, not in it"
    assert _snapshot(bundle) == before, "rescoring must not create, edit or delete bundle files"

    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["run_id"] == RUN_ID
    assert payload["scenario_id"] == SCENARIO
    # A fresh groundtruth_sha256 pin, not the sealed bundle's placeholder original.
    assert payload["groundtruth_sha256"] != "{}"


def test_rescore_refuses_when_content_hashes_do_not_verify(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        rescore_assertions, "verify_content_hashes", lambda _path: ["guardian_audit.jsonl"]
    )
    campaign_dir = tmp_path / "CAMP-TEST"
    campaign_dir.mkdir()
    bundle = _sealed_bundle(campaign_dir)

    with pytest.raises(rescore_assertions.RescoreError, match="guardian_audit.jsonl"):
        rescore_assertions.rescore_bundle(bundle)
    assert not (campaign_dir / "_rescored").exists()


def test_rescore_refuses_a_baseline_bundle(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(rescore_assertions, "verify_content_hashes", lambda _path: [])
    campaign_dir = tmp_path / "CAMP-TEST"
    campaign_dir.mkdir()
    bundle = campaign_dir / "BASE-LOAD-STEADY-101"
    bundle.mkdir()
    (bundle / "manifest.json").write_text(json.dumps({"is_baseline": True}), encoding="utf-8")

    with pytest.raises(rescore_assertions.RescoreError, match="baseline"):
        rescore_assertions.rescore_bundle(bundle)


def test_rescore_honours_an_explicit_out_root(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(rescore_assertions, "verify_content_hashes", lambda _path: [])
    campaign_dir = tmp_path / "CAMP-TEST"
    campaign_dir.mkdir()
    bundle = _sealed_bundle(campaign_dir)
    elsewhere = tmp_path / "elsewhere"

    destination = rescore_assertions.rescore_bundle(bundle, out_root=elsewhere)

    assert destination == elsewhere / "_rescored" / RUN_ID / "assertions.json"


def test_completeness_summary_matches_reached_over_required() -> None:
    payload = {
        "required_substep_results": [
            {"phase": "detection-and-investigation", "result": "reached"},
            {"phase": "detection-and-investigation", "result": "not-reached"},
            {"phase": "containment", "result": "reached"},
        ]
    }
    summary = rescore_assertions.completeness_summary(payload)
    assert summary["detection-and-investigation"] == {
        "reached": 1.0,
        "required": 2.0,
        "completeness": 0.5,
    }
    assert summary["containment"] == {"reached": 1.0, "required": 1.0, "completeness": 1.0}


def test_main_prints_destination_path_and_completeness_summary(
    tmp_path, monkeypatch, capsys
) -> None:
    monkeypatch.setattr(rescore_assertions, "verify_content_hashes", lambda _path: [])
    campaign_dir = tmp_path / "CAMP-TEST"
    campaign_dir.mkdir()
    bundle = _sealed_bundle(campaign_dir)

    exit_code = rescore_assertions.main([str(bundle)])

    assert exit_code == 0
    out = capsys.readouterr().out
    assert str(campaign_dir / "_rescored" / RUN_ID / "assertions.json") in out
    assert "detection-and-investigation" in out


def test_main_reports_errors_on_stderr_and_returns_nonzero(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(rescore_assertions, "verify_content_hashes", lambda _path: ["probes.csv"])
    campaign_dir = tmp_path / "CAMP-TEST"
    campaign_dir.mkdir()
    bundle = _sealed_bundle(campaign_dir)

    exit_code = rescore_assertions.main([str(bundle)])

    assert exit_code == 1
    assert "probes.csv" in capsys.readouterr().err
