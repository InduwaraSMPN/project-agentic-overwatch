"""Formal pilot coordinates reach the existing runner without weakening grid validation."""

import json
from dataclasses import replace
from pathlib import Path

import pytest

from runner.campaign import from_dict
from runner.campaign_cli import run_campaign
from runner.run import RunError, run_planned
from runner.validate import ValidationError, validate_extended_cost_pilot_manifest

ROOT = Path(__file__).resolve().parents[2]


def _plan(slug):
    return from_dict(json.loads((ROOT / "runner" / f"CAMP-20261004-{slug}.json").read_text()))


def test_validated_pilot_dispatches_registered_seed_and_rejects_nonmember(tmp_path):
    plan = _plan("smoke-p1a")
    planned = plan.runs[0]
    outcome = run_planned(
        planned,
        campaign_id=plan.campaign_id,
        out_root=tmp_path,
        offline=True,
        pilot=("smoke", plan),
    )
    assert outcome.sealed
    other = replace(
        planned, injection_condition="INJ-A", run_id=planned.run_id.replace("INJ-NONE", "INJ-A")
    )
    with pytest.raises(RunError, match="exact member"):
        run_planned(
            other,
            campaign_id=plan.campaign_id,
            out_root=tmp_path,
            offline=True,
            pilot=("smoke", plan),
        )
    with pytest.raises(RunError, match="canonical protocol seed"):
        run_planned(planned, campaign_id=plan.campaign_id, out_root=tmp_path, offline=True)


def test_p1b_preserves_cost_pairs_and_requires_every_supplemental_arm():
    plan = _plan("cost-p1b")
    counts = validate_extended_cost_pilot_manifest(plan)
    assert counts["G0-FULL"] == counts["G1-LOGONLY"] == 3
    assert counts["G2-SHAREDCRED"] == 1
    with pytest.raises(ValidationError):
        validate_extended_cost_pilot_manifest(replace(plan, runs=plan.runs[:-1]))
    path = ROOT / "runner" / "CAMP-20261004-cost-p1b.json"
    assert (
        run_campaign(path, 0, skip_preflight=True, pilot_kind="cost-extended")
        == plan.generated_order
    )
