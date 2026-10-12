"""Re-score a sealed run bundle's assertions against current ground truth, without touching it.

WHY THIS SCRIPT EXISTS
-----------------------
ADR-088 (supervisor ruling B4) changed what a required substep's ``check`` looks like and what
``guardian-executed-*`` predicates read as "performed" (``guardian/audit/outcome.py``,
succeeded-only). Bundles sealed before that fix carry an ``assertions.json`` scored under the OLD
ground truth and the OLD join logic. ``docs/protocols/data-management.md`` section 3 permits only a
``scores.json`` entry to be appended to a sealed bundle post-seal -- ``assertions.json`` is not on
that list -- so a re-score is written to a SEPARATE location entirely:
``<campaign_dir>/_rescored/<run_id>/assertions.json``. The sealed bundle's own files, including its
original ``assertions.json`` and ``seal.json``, are read but never written, and every file
``seal.json`` recorded a hash for is re-hashed and compared before anything else is read (see
``rescore_bundle``'s docstring for why that check is ``verify_content_hashes`` and not
``verify_bundle_seal``).

WHAT A RE-SCORE CAN AND CANNOT RE-EVALUATE
--------------------------------------------
This script has no cluster access, by this task's own constraint (no cluster mutation, no live run)
and on principle (a re-score runs long after the run that produced the bundle; the cluster it
touched may hold a different run's state by now, or may not exist at all). It evaluates with
``cluster=None``, which ``runner.evaluate_assertions._AbsentCluster`` makes fail-closed for every
cluster-state check type (``replicas-at-least``, ``networkpolicy-present``,
``resource-present``/``-absent``, ``image-digest-equals``): those come back "not evaluable" / fail
rather than a meaningful pass or reached. ``guardian-executed-*`` and ``slo-probe-recovered`` read
only bundle files (``guardian_audit.jsonl``, ``results.json``, ``probes.csv``) and are re-scored
exactly as a live run would score them -- which, per ADR-088, is most of what changed.

WHAT BREAKS IF THIS FILE CHANGES
-----------------------------------
Nothing scores differently: this script is a thin, read-only composition over
``runner.evaluate_assertions.evaluate_run_assertions``, which owns every actual predicate. This
file owns only where the output lands and that the input bundle is never written to.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from runner.assertions import AssertionContractError  # noqa: E402
from runner.bundle import verify_content_hashes  # noqa: E402
from runner.evaluate_assertions import (  # noqa: E402
    AssertionEvaluationError,
    evaluate_run_assertions,
)

__all__ = ("RescoreError", "completeness_summary", "rescore_bundle")


class RescoreError(ValueError):
    """The bundle could not be re-scored as it stands."""


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RescoreError(f"{path}: {error}") from error
    if not isinstance(document, dict):
        raise RescoreError(f"{path}: expected a JSON object")
    return document


def rescore_bundle(bundle_dir: Path, *, out_root: Path | None = None) -> Path:
    """Re-evaluate one sealed bundle's assertions under the current ground truth.

    Returns the path written. Never creates, modifies or deletes anything under ``bundle_dir`` --
    the seal is verified (read-only) before anything else is read from it, and the destination is
    refused outright if it would land inside the bundle.
    """
    bundle_dir = Path(bundle_dir).resolve()
    # `runner.bundle.verify_bundle_seal` is deliberately NOT used here: it re-validates
    # assertions.json's `groundtruth_sha256` against the CURRENT live ground truth
    # (`load_and_validate_assertion_results`), which is exactly what a re-score exists to change --
    # a bundle sealed under the pre-fix labels would then never pass its own seal check post-fix.
    # `verify_content_hashes` is the narrower, ground-truth-independent predicate: has any byte of
    # what this bundle already recorded changed since it was sealed. That is the right question for
    # "is this evidence trustworthy to re-score", and the only one this script needs answered.
    mismatches = verify_content_hashes(bundle_dir)
    if mismatches:
        raise RescoreError(f"{bundle_dir}: content hash mismatch: {', '.join(mismatches)}")

    manifest = _read_json_object(bundle_dir / "manifest.json")
    if manifest.get("is_baseline") is not False:
        raise RescoreError(f"{bundle_dir}: a baseline bundle has no assertions to re-score")
    run_id = manifest.get("run_id")
    scenario_id = manifest.get("scenario_id")
    injection_condition = manifest.get("injection_condition")
    if not all(
        isinstance(value, str) and value for value in (run_id, scenario_id, injection_condition)
    ):
        raise RescoreError(f"{bundle_dir}: manifest lacks run_id/scenario_id/injection_condition")

    payload = evaluate_run_assertions(
        bundle_dir,
        run_id=run_id,
        scenario_id=scenario_id,
        injection_condition=injection_condition,
        cluster=None,  # read-only re-score, no live cluster -- see module docstring
    )

    campaign_dir = Path(out_root).resolve() if out_root is not None else bundle_dir.parent
    destination_dir = campaign_dir / "_rescored" / run_id
    if destination_dir == bundle_dir or bundle_dir in destination_dir.parents:
        raise RescoreError("refusing to write a re-score inside the sealed bundle it re-scores")
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination = destination_dir / "assertions.json"
    destination.write_bytes(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "utf-8"
        )
    )
    return destination


def completeness_summary(payload: Mapping[str, Any]) -> dict[str, dict[str, float]]:
    """Per-phase ``{reached, required, completeness}`` from one evaluated assertions payload.

    Mirrors ``analysis/stats/measures.py``'s ``per_phase_completeness`` arithmetic (reached /
    required per phase) so this script's printed summary and the analysis pipeline's eventual
    reading of the same ``required_substep_results`` never state the ratio two different ways.
    """
    by_phase: dict[str, list[bool]] = {}
    for item in payload["required_substep_results"]:
        by_phase.setdefault(item["phase"], []).append(item["result"] == "reached")
    return {
        phase: {
            "reached": float(sum(flags)),
            "required": float(len(flags)),
            "completeness": sum(flags) / len(flags),
        }
        for phase, flags in sorted(by_phase.items())
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path, help="path to the sealed run bundle directory")
    parser.add_argument(
        "--out-root",
        type=Path,
        default=None,
        help="campaign directory to write _rescored/<run-id>/ under (default: the bundle's parent)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        destination = rescore_bundle(args.bundle, out_root=args.out_root)
        payload = json.loads(destination.read_text(encoding="utf-8"))
        print(destination)
        print(json.dumps(completeness_summary(payload), indent=2, sort_keys=True))
    except (RescoreError, AssertionEvaluationError, AssertionContractError) as error:
        print(f"rescore-assertions: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
