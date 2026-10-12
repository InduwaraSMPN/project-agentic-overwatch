r"""The blind view leaves no arm token in any path, identifier or manifest field.

This is the check behind T5.5's blind-view line: scripts/blind_view.py over a synthetic bundle must
strip every field that names the arm and rewrite the arm token out of every string, or scores.json's
``blind: true`` is a false claim. A synthetic bundle rather than a real one, because M4 writes no
run bundle at Tier A -- the manifest here carries every arm-revealing field data-management.md
section 2 defines, which is a stronger test than any single real bundle that happens to omit some.
"""

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402

from scripts import blind_view  # noqa: E402

# A manifest carrying every arm-revealing field section 2 names, plus a free-text field that embeds
# the run id, so the string-rewrite path is exercised as well as the field-strip path.
SYNTHETIC_MANIFEST = {
    "run_id": "RUN-G1-LOGONLY-SCN-SIM-02-INJ-C-104",
    "campaign_id": "CAMP-20260827-pilot",
    "condition": "S1-HIER",
    "guardian_mode": "G1-LOGONLY",
    "aggregator_quoting": True,
    "graph_id": "hier-v1",
    "scenario_id": "SCN-SIM-02",
    "injection_condition": "INJ-C",
    "seed": 104,
    "is_baseline": False,
    "baseline_run_id": "BASE-LOAD-STEADY-104",
    "note": "sealed run RUN-G1-LOGONLY-SCN-SIM-02-INJ-C-104 after 4 phases",
    "nested": {"guardian_mode": "G1-LOGONLY", "detail": "arm RUN-G1-LOGONLY-SCN-SIM-02-INJ-C-104"},
}
SALT = "pilot-campaign-salt"


def test_render_strips_every_arm_field_and_rewrites_the_run_id() -> None:
    view = blind_view.render_bundle(SYNTHETIC_MANIFEST, SALT)
    residual = blind_view._residual_arm_traces(view, SYNTHETIC_MANIFEST["run_id"])
    assert residual == [], f"the blind view still reveals the arm: {residual}"


def test_arm_naming_fields_are_absent() -> None:
    view = blind_view.render_bundle(SYNTHETIC_MANIFEST, SALT)
    for field in blind_view.ARM_MANIFEST_FIELDS + blind_view.ARM_AUDIT_FIELDS:
        assert field not in view, f"{field} survived into the blind view"
    # And in the nested object too.
    assert "guardian_mode" not in view["nested"]


def test_run_id_is_replaced_everywhere_it_appears() -> None:
    view = blind_view.render_bundle(SYNTHETIC_MANIFEST, SALT)
    opaque = blind_view.scoring_id(SYNTHETIC_MANIFEST["run_id"], SALT)
    assert view["scoring_id"] == opaque
    assert opaque in view["note"]
    assert SYNTHETIC_MANIFEST["run_id"] not in view["note"]
    assert SYNTHETIC_MANIFEST["run_id"] not in view["nested"]["detail"]


def test_scoring_id_is_stable_under_a_salt_and_varies_across_salts() -> None:
    """The re-score must reach the same bundle under the same salt, and two campaigns must not share
    a mapping an experienced scorer could learn."""
    run_id = SYNTHETIC_MANIFEST["run_id"]
    assert blind_view.scoring_id(run_id, SALT) == blind_view.scoring_id(run_id, SALT)
    assert blind_view.scoring_id(run_id, SALT) != blind_view.scoring_id(run_id, "different-salt")


def test_scoring_id_does_not_leak_the_arm() -> None:
    opaque = blind_view.scoring_id(SYNTHETIC_MANIFEST["run_id"], SALT)
    assert "G1" not in opaque
    assert "LOGONLY" not in opaque
    assert opaque.startswith("SCORED-")


def test_standalone_arm_tokens_are_scrubbed_from_nested_text() -> None:
    manifest = {
        **SYNTHETIC_MANIFEST,
        "note": "G1-LOGONLY differs from S3-SINGLE and aliases S1-HIER",
    }
    view = blind_view.render_bundle(manifest, SALT)
    assert blind_view._residual_arm_traces(view, manifest["run_id"]) == []
    assert view["note"] == "[ARM] differs from [ARM] and aliases [ARM]"


def test_bundle_view_scrubs_every_promised_scoring_artifact(tmp_path: Path) -> None:
    bundle = tmp_path / SYNTHETIC_MANIFEST["run_id"]
    bundle.mkdir()
    (bundle / "manifest.json").write_text(json.dumps(SYNTHETIC_MANIFEST), encoding="utf-8")
    artifacts = {
        "messages.jsonl": {"run_id": SYNTHETIC_MANIFEST["run_id"], "content": "S3-SINGLE"},
        "spans.otel.json": {"spans": [{"condition": "G1-LOGONLY", "name": "phase"}]},
        "results.json": [{"phase": "containment", "outcome": "blocked", "summary": "G1-LOGONLY"}],
        "assertions.json": {"run_id": SYNTHETIC_MANIFEST["run_id"], "assertions": []},
        "guardian_audit.jsonl": {
            "guardian_mode": "G1-LOGONLY",
            "enforcement": "executed",
            "detail": "arm G1-LOGONLY",
        },
        "monitor_events.jsonl": {"summary": "observed under S1-HIER"},
    }
    for name, payload in artifacts.items():
        text = json.dumps(payload) + ("\n" if name.endswith(".jsonl") else "")
        (bundle / name).write_text(text, encoding="utf-8")

    view = blind_view.render_bundle_directory(bundle, SALT)
    assert set(view["files"]) == {"manifest.json", *artifacts}
    assert blind_view._residual_arm_traces(view, SYNTHETIC_MANIFEST["run_id"]) == []
    audit = view["files"]["guardian_audit.jsonl"][0]
    assert "guardian_mode" not in audit
    assert "enforcement" not in audit
    assert audit["detail"] == "arm [ARM]"


def test_bundle_view_refuses_malformed_jsonl(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "manifest.json").write_text(json.dumps(SYNTHETIC_MANIFEST), encoding="utf-8")
    (bundle / "messages.jsonl").write_text("not-json\n", encoding="utf-8")
    with pytest.raises(blind_view.BlindViewError, match="messages.jsonl:1"):
        blind_view.render_bundle_directory(bundle, SALT)


def test_a_manifest_without_a_run_id_is_refused() -> None:
    with pytest.raises(blind_view.BlindViewError):
        blind_view.render_bundle({"condition": "S1-HIER"}, SALT)


def test_a_malformed_run_id_is_refused_rather_than_half_blinded() -> None:
    with pytest.raises(blind_view.BlindViewError):
        blind_view.render_bundle({"run_id": "not-a-run-id"}, SALT)
