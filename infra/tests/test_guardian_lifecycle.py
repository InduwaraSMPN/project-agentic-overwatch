"""Static integration checks for Guardian lifecycle and status registration."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_ci_round_trip_uses_the_same_bring_up_configuration() -> None:
    """The second up must fit the same runner and build the same substrate as the first."""
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/env-bringup.yml").read_text(encoding="utf-8")
    )
    steps = {step["name"]: step for step in workflow["jobs"]["bringup"]["steps"]}
    first = steps["make up"]["env"]
    second = steps["make down then make up again"]["env"]
    assert second == first


def test_guardian_status_row_is_landed_and_points_at_deployment() -> None:
    registry = yaml.safe_load(
        (ROOT / "infra" / "status" / "components.yaml").read_text(encoding="utf-8")
    )
    guardian = next(row for row in registry["components"] if row["id"] == "guardian")
    assert guardian == {
        "id": "guardian",
        "description": (
            "The Guardian mediation service, sole credential holder and reference monitor"
        ),
        "milestone": "M3",
        "landed": True,
        "kind": "deployment",
        "namespace": "guardian",
        "name": "guardian",
        "min_count": 1,
        "owner": "guardian/deploy/deployment.yaml",
        # ADR-148: the Guardian is the one component the `substrate` profile omits, because
        # scripts/guardian_deploy.sh refuses without `guardian-signing-key` and ADR-114 forbids
        # every repository path from creating it, so an ephemeral CI runner has nothing to
        # provision from. `required_in: full` is what makes `up.sh` skip its layer and `status.sh`
        # report it `not-required` under `UP_PROFILE=substrate`.
        "required_in": "full",
    }


def test_only_the_guardian_is_scoped_to_a_bring_up_profile() -> None:
    """`required_in` is the Guardian's alone; every other component is required in every profile."""
    registry = yaml.safe_load(
        (ROOT / "infra" / "status" / "components.yaml").read_text(encoding="utf-8")
    )
    scoped = [row["id"] for row in registry["components"] if "required_in" in row]
    assert scoped == ["guardian"]


def test_up_and_down_integrate_guardian_without_deleting_audit_claim() -> None:
    up = (ROOT / "scripts" / "up.sh").read_text(encoding="utf-8")
    down = (ROOT / "scripts" / "down.sh").read_text(encoding="utf-8")
    assert "GUARDIAN_DEPLOY=scripts/guardian_deploy.sh" in up
    assert 'sh "$GUARDIAN_DEPLOY"' in up
    assert 'wait_ns_ready guardian 1 "Guardian"' in up
    # ADR-148: the Guardian layer is gated on the active profile, so `UP_PROFILE=substrate` skips
    # it honestly rather than failing. The gate reads the same `required_in` value `status.sh` uses,
    # so `up` and `status` can never disagree about whether the Guardian belongs in this profile.
    assert "component_field guardian required_in" in up
    assert "bring_up_guardian" in up
    assert "GUARDIAN_MANIFEST=guardian/deploy/deployment.yaml" in down
    assert "delete deployment guardian service guardian" in down
    assert 'delete -f "$GUARDIAN_MANIFEST"' not in down


def test_deployment_does_not_embed_signing_material() -> None:
    manifest = (ROOT / "guardian" / "deploy" / "deployment.yaml").read_text(encoding="utf-8")
    assert "kind: Secret" not in manifest
    assert "GUARDIAN_SIGNING_KEY_FILE" in manifest
    assert "secretName: guardian-signing-key" in manifest
