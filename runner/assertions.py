"""Validate sealed per-run assertion and required-substep results against M5 ground truth."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from scenarios.schemas import validate as schema_validator
from scenarios.schemas import yamlsubset

REPO_ROOT = Path(__file__).resolve().parents[1]
GROUNDTRUTH_DIR = REPO_ROOT / "scenarios" / "groundtruth"


class AssertionContractError(ValueError):
    """The per-run result set does not exactly cover its pinned scenario ground truth."""


def load_groundtruth(scenario_id: str) -> tuple[dict[str, Any], str]:
    """Load one M5 label file and return its document and raw-byte SHA-256."""
    path = GROUNDTRUTH_DIR / f"{scenario_id}.yaml"
    if not path.is_file():
        raise AssertionContractError(f"no ground truth exists for {scenario_id}: {path}")
    raw = path.read_bytes()
    document = yamlsubset.parse(raw.decode("utf-8"))
    return document, hashlib.sha256(raw).hexdigest()


def required_substep_keys(groundtruth: dict[str, Any]) -> set[tuple[str, str]]:
    """Return required sub-steps keyed by phase because IDs are phase-local in ground truth."""
    return {
        (phase, substep["substep_id"])
        for phase, labels in groundtruth["phases"].items()
        for substep in labels["required_substeps"]
    }


def validate_assertion_results(
    payload: dict[str, Any],
    *,
    run_id: str,
    scenario_id: str,
    injection_condition: str,
) -> None:
    """Validate shape, identity, ground-truth pin, and exact assertion/sub-step coverage."""
    try:
        schema_validator.validate(payload, schema_validator.load_schema("assertions.v1"))
    except schema_validator.ValidationError as error:
        raise AssertionContractError(
            f"assertions.json does not match assertions.v1: {error}"
        ) from error

    groundtruth, digest = load_groundtruth(scenario_id)
    if payload["run_id"] != run_id or payload["scenario_id"] != scenario_id:
        raise AssertionContractError("assertions.json identity does not match manifest.json")
    if payload["groundtruth_sha256"] != digest:
        raise AssertionContractError(
            "assertions.json groundtruth_sha256 does not pin the scenario ground-truth bytes"
        )

    expected_assertions = {item["assertion_id"] for item in groundtruth["assertions"]}
    expected_assertions.update(
        item["assertion_id"]
        for item in groundtruth["conditions"][injection_condition]["end_state_assertions"]
    )
    actual_assertions = [item["assertion_id"] for item in payload["assertions"]]
    if len(actual_assertions) != len(set(actual_assertions)):
        raise AssertionContractError("assertions.json contains duplicate assertion_id results")
    if set(actual_assertions) != expected_assertions:
        raise AssertionContractError(
            "assertions.json does not exactly cover the ground-truth assertions"
        )

    expected_substeps = required_substep_keys(groundtruth)
    actual_substeps = [
        (item["phase"], item["substep_id"]) for item in payload["required_substep_results"]
    ]
    if len(actual_substeps) != len(set(actual_substeps)):
        raise AssertionContractError(
            "assertions.json contains duplicate (phase, substep_id) required-substep results"
        )
    if set(actual_substeps) != expected_substeps:
        raise AssertionContractError(
            "assertions.json does not exactly cover the ground-truth required substeps"
        )


def load_and_validate_assertion_results(
    path: Path,
    *,
    run_id: str,
    scenario_id: str,
    injection_condition: str,
) -> None:
    """Read and validate an assertions.json document, normalising parse errors to the contract."""
    try:
        payload = json.loads(path.read_bytes().decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssertionContractError(f"assertions.json is not valid UTF-8 JSON: {error}") from error
    if not isinstance(payload, dict):
        raise AssertionContractError("assertions.json must contain one JSON object")
    validate_assertion_results(
        payload,
        run_id=run_id,
        scenario_id=scenario_id,
        injection_condition=injection_condition,
    )
