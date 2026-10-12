"""The live golden gate must bind token issuance and submission to one graph-owned identity."""

from pathlib import Path


def test_live_golden_supplies_the_executor_identity() -> None:
    script = (Path(__file__).resolve().parents[2] / "scripts" / "agents_golden.sh").read_text(
        encoding="utf-8"
    )

    assert '--executor-id "executor-$RUN_ID"' in script, (
        "the live golden path omitted its graph-owned executor identity, so Supervisors minted "
        "for model-invented subjects while the Executor submitted as its role id"
    )
