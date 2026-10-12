"""Pre-register the deterministic D2 matched-tuple scoring sample.

Read planned cells from campaign.json before the first bundle seals (ADR-134,
ADR-165). Stage one draws one seed per scenario/injection stratum; stage two
keeps the protocol-defined balanced subset using the same seeded generator.
No completed outcomes contribute to the draw. Baselines are excluded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from analysis.stats.gate import BLIND_RESCORE_SAMPLE_FRACTION  # noqa: E402
from runner.ids import CANONICAL_ARMS  # noqa: E402
from scripts.m10_constants import (  # noqa: E402
    SCORING_SAMPLE_MIN_PER_SCENARIO,
    SCORING_SAMPLE_TUPLE_COUNT,
)

__all__ = [
    "CONDITION_ORDER",
    "DEFAULT_CAMPAIGN_DIR",
    "MIN_TUPLES_PER_SCENARIO",
    "SEAL_FILENAME",
    "TUPLE_SAMPLE_COUNT",
    "SamplingError",
    "build_sample",
    "first_sealed_bundle",
    "main",
]

DEFAULT_CAMPAIGN_DIR: Path = REPO_ROOT / "runs" / "CAMP-20260914-campaign"

# The bundle seal this module refuses to draw past. The filename is ``runner.bundle``'s to name; it
# is
# repeated here as a literal because importing that module for one string would pull the sealer (and
# its whole dependency set) into a script whose job is to run BEFORE any bundle exists. A test
# asserts
# the two spellings are equal, on the pattern ``runner/tests/test_guardian_deploy.py`` uses for the
# three spellings of the Guardian's audit directory.
SEAL_FILENAME = "seal.json"

# Stage-2 (balanced-subset) constants, MIRRORED from evaluation-protocol section 4 and not restated
# here. The names are this module's public surface, so the CLI defaults and every existing caller
# read
# the same name they always did; the VALUES come from ``scripts.m10_constants``, which
# ``scripts/tests/test_m10_constants_match_protocol.py`` checks against the protocol block, and
# which
# ``runner/tests/test_scoring_sample.py::test_constants_match_protocol`` checks this module against.
# Both are still overridable from the CLI (``--tuple-count`` / ``--min-per-scenario``) and as
# :func:`build_sample` keyword arguments, per the requirement that the size stay a parameter rather
# than a buried literal -- an override is a deliberate departure from the protocol, recorded in the
# output's ``derivation`` field, not a silent one.
TUPLE_SAMPLE_COUNT: int = SCORING_SAMPLE_TUPLE_COUNT
MIN_TUPLES_PER_SCENARIO: int = SCORING_SAMPLE_MIN_PER_SCENARIO

# The fixed per-tuple arm order the output's ``run_ids`` lists and each tuple's ``run_ids`` mapping
# are ordered by. ``sorted(CANONICAL_ARMS)`` rather than ``CANONICAL_ARMS`` itself (whose order is
# the grid's arm-enumeration order, not an alphabetical one) -- this happens to be the order the
# task that commissioned this script already lists the six arms in, and picking it keeps the output
# stable under ``json.dumps(..., sort_keys=True)`` regardless of dict insertion order.
CONDITION_ORDER: tuple[str, ...] = tuple(sorted(CANONICAL_ARMS))


class SamplingError(ValueError):
    """The campaign corpus cannot support the D2 stratified draw as specified."""


def first_sealed_bundle(campaign_dir: Path) -> str | None:
    """Name the first sealed run directory, even if its manifest is missing.

    A seal proves the prospective registration deadline has passed. Sorting
    makes the refusal deterministic; the scoring sidecar directory is excluded.
    """
    if not campaign_dir.is_dir():
        return None
    candidates = sorted(
        entry.name
        for entry in campaign_dir.iterdir()
        if entry.is_dir() and entry.name != "_scoring" and (entry / SEAL_FILENAME).is_file()
    )
    return candidates[0] if candidates else None


def _seeded_rng(campaign_id: str, campaign_seed: int) -> random.Random:
    """One generator, seeded from the campaign id and seed.

    Mirrors ``runner/order.py::_seeded_rng``: same bytes hashed, same construction of the
    generator from the digest. See this module's docstring for why the function is reimplemented
    here rather than imported (it is private to ``runner.order`` and not part of that module's
    public surface).
    """
    digest = hashlib.sha256(f"{campaign_id}\x00{campaign_seed}".encode()).hexdigest()
    return random.Random(int(digest, 16))  # noqa: S311 - reproducibility is the requirement


def _read_campaign_manifest(campaign_dir: Path) -> tuple[str, int, list[dict[str, Any]]]:
    manifest_path = campaign_dir / "campaign.json"
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SamplingError(f"{manifest_path}: {error}") from error
    if not isinstance(payload, dict):
        raise SamplingError(f"{manifest_path}: expected a JSON object")
    campaign_id = payload.get("campaign_id")
    campaign_seed = payload.get("campaign_seed")
    if not isinstance(campaign_id, str) or not campaign_id:
        raise SamplingError(f"{manifest_path}: 'campaign_id' is missing or not a string")
    if not isinstance(campaign_seed, int) or isinstance(campaign_seed, bool):
        raise SamplingError(f"{manifest_path}: 'campaign_seed' is missing or not an int")
    runs = payload.get("runs", [])
    if not isinstance(runs, list) or any(not isinstance(run, dict) for run in runs):
        raise SamplingError(f"{manifest_path}: runs must be a list of objects")
    return campaign_id, campaign_seed, runs


def build_sample(
    campaign_dir: str | Path,
    *,
    tuple_count: int = TUPLE_SAMPLE_COUNT,
    min_per_scenario: int = MIN_TUPLES_PER_SCENARIO,
) -> dict[str, Any]:
    """Return the D2 first-pass scoring sample document for one campaign directory.

    ``tuple_count`` and ``min_per_scenario`` default to :data:`TUPLE_SAMPLE_COUNT` and
    :data:`MIN_TUPLES_PER_SCENARIO`, which now MIRROR ``evaluation-protocol.md`` section 4 rather
    than
    being this module's own figures (see the module docstring). They are exposed as keyword
    arguments
    -- and as the ``--tuple-count`` / ``--min-per-scenario`` CLI flags -- so the balanced subset
    size
    stays a parameter, never a literal buried in the draw logic, and so a deliberate departure from
    the protocol is possible by saying so out loud. The output records which figures were used, so a
    reader can tell a protocol draw from a departed one without reading this module.

    Pure given the campaign directory's contents and these two parameters: two calls against the
    same
    corpus with the same parameters return byte-identical (once serialized) results, because the
    only randomness is :func:`_seeded_rng`'s, which is itself a pure function of the campaign id and
    the campaign manifest's own seed.
    """
    if min_per_scenario < 0:
        raise SamplingError("min_per_scenario must be >= 0")
    if tuple_count < 0:
        raise SamplingError("tuple_count must be >= 0")

    campaign_dir = Path(campaign_dir)
    sealed = first_sealed_bundle(campaign_dir)
    if sealed is not None:
        raise SamplingError(f"{campaign_dir}: cannot pre-register after first seal: {sealed}")
    campaign_id, campaign_seed, planned_runs = _read_campaign_manifest(campaign_dir)
    run_id_by_cell: dict[tuple[str, str, int, str], list[str]] = {}
    seeds_by_stratum: dict[tuple[str, str], set[int]] = {}
    for row in planned_runs:
        if row.get("is_baseline") is True:
            continue
        scenario_id = row.get("scenario_id")
        injection_condition = row.get("injection_condition")
        seed = row.get("seed")
        condition = row.get("condition")
        run_id = row.get("run_id")
        if (
            not isinstance(scenario_id, str)
            or not isinstance(injection_condition, str)
            or condition not in CANONICAL_ARMS
            or not isinstance(seed, int)
            or isinstance(seed, bool)
            or not isinstance(run_id, str)
            or not run_id
        ):
            raise SamplingError("malformed planned framework-on run")
        stratum = (scenario_id, injection_condition)
        seeds_by_stratum.setdefault(stratum, set()).add(seed)
        run_id_by_cell.setdefault((scenario_id, injection_condition, seed, condition), []).append(
            run_id
        )

    if not seeds_by_stratum:
        raise SamplingError(f"{campaign_dir}: no framework-on runs found to sample from")

    for scenario_id, injection_condition, seed, _ in run_id_by_cell:
        for arm in CANONICAL_ARMS:
            matches = run_id_by_cell.get((scenario_id, injection_condition, seed, arm), [])
            if len(matches) != 1:
                raise SamplingError("planned tuple must contain exactly one run per canonical arm")
    all_ids = [ids[0] for ids in run_id_by_cell.values()]
    if len(set(all_ids)) != len(all_ids):
        raise SamplingError("duplicate planned run_id")

    scenarios = sorted({scenario_id for scenario_id, _ in seeds_by_stratum})
    injection_conditions = sorted({injection for _, injection in seeds_by_stratum})

    rng = _seeded_rng(campaign_id, campaign_seed)

    # -- Stage 1: one seed per (scenario_id, injection_condition) stratum. Unchanged from the
    # original D2 mechanism -- this is the "prior design" stage-2 draws a genuine subset of.
    stage1_tuples: list[dict[str, Any]] = []
    tuples_by_scenario: dict[str, list[dict[str, Any]]] = {}
    for scenario_id in scenarios:
        for injection_condition in injection_conditions:
            stratum = (scenario_id, injection_condition)
            if stratum not in seeds_by_stratum:
                continue
            available_seeds = sorted(seeds_by_stratum[stratum])
            if not available_seeds:
                raise SamplingError(
                    f"{scenario_id}/{injection_condition}: no seeds planned for this stratum"
                )
            chosen_seed = rng.choice(available_seeds)

            tuple_run_ids: dict[str, str] = {}
            for condition in CONDITION_ORDER:
                matches = run_id_by_cell.get(
                    (scenario_id, injection_condition, chosen_seed, condition), []
                )
                if not matches:
                    raise SamplingError(
                        f"{scenario_id}/{injection_condition}/{chosen_seed}: arm {condition!r} "
                        "is missing from the planned manifest"
                    )
                if len(matches) > 1:
                    raise SamplingError(
                        f"{scenario_id}/{injection_condition}/{chosen_seed}/{condition}: "
                        f"more than one planned run matches ({sorted(matches)})"
                    )
                tuple_run_ids[condition] = matches[0]

            entry = {
                "scenario_id": scenario_id,
                "injection_condition": injection_condition,
                "seed": chosen_seed,
                "run_ids": tuple_run_ids,
            }
            stage1_tuples.append(entry)
            tuples_by_scenario.setdefault(scenario_id, []).append(entry)

    # -- Stage 2: a per-scenario-balanced subset of stage 1, drawn from the same generator
    # (continuing its sequence, not reseeding). Every kept tuple is one stage 1 already drew, so
    # this can only remove candidates, never substitute a different seed or a different stratum.
    num_scenarios = len(scenarios)
    floor_total = min_per_scenario * num_scenarios
    if tuple_count < floor_total:
        raise SamplingError(
            f"tuple_count={tuple_count} cannot satisfy min_per_scenario={min_per_scenario} "
            f"across {num_scenarios} scenarios (needs >= {floor_total})"
        )
    extra_needed = tuple_count - floor_total
    if extra_needed > num_scenarios:
        raise SamplingError(
            f"tuple_count={tuple_count} exceeds the maximum this design supports "
            f"({num_scenarios} scenarios x (min_per_scenario + 1) = "
            f"{num_scenarios * (min_per_scenario + 1)}) -- each scenario gets at most one extra "
            "tuple beyond the floor"
        )
    for scenario_id in scenarios:
        if len(tuples_by_scenario.get(scenario_id, [])) < min_per_scenario:
            raise SamplingError(
                f"{scenario_id}: only {len(tuples_by_scenario.get(scenario_id, []))} stage-1 "
                f"tuple(s) available, fewer than min_per_scenario={min_per_scenario}"
            )

    # rng.sample over `scenarios` (already sorted) so which scenarios get the 3rd tuple is itself
    # deterministic and independent of dict/set iteration order.
    scenarios_with_extra: set[str] = (
        set(rng.sample(scenarios, extra_needed)) if extra_needed else set()
    )

    tuples: list[dict[str, Any]] = []
    run_ids: list[str] = []
    for scenario_id in scenarios:
        available = tuples_by_scenario[scenario_id]
        keep = min_per_scenario + (1 if scenario_id in scenarios_with_extra else 0)
        # rng.sample over this scenario's stage-1 tuples (already in sorted-injection order)
        # picks which distinct injection conditions survive into the final sample.
        chosen = sorted(rng.sample(available, keep), key=lambda entry: entry["injection_condition"])
        tuples.extend(chosen)
        for entry in chosen:
            run_ids.extend(entry["run_ids"][condition] for condition in CONDITION_ORDER)

    matched_tuple_population = sum(len(seeds) for seeds in seeds_by_stratum.values())
    sample_fraction = (
        len(tuples) / matched_tuple_population if matched_tuple_population else float("nan")
    )

    return {
        "campaign_id": campaign_id,
        "campaign_seed": campaign_seed,
        "sample_fraction": sample_fraction,
        "tuple_sample_count": tuple_count,
        "min_tuples_per_scenario": min_per_scenario,
        "scenarios_with_extra_tuple": sorted(scenarios_with_extra),
        "matched_tuple_population": matched_tuple_population,
        "stage1_strata_count": len(stage1_tuples),
        "condition_order": list(CONDITION_ORDER),
        "strata_count": len(tuples),
        "derivation": (
            "Decision D2 (revised 2026-09-23) first-pass researcher-scoring sample, two stages "
            "from one generator: random.Random(int(sha256(f'{campaign_id}\\x00{campaign_seed}')"
            ".hexdigest(), 16)), mirroring runner/order.py::_seeded_rng's construction. Stage 1 "
            "(unchanged from the original D2 mechanism): one rng.choice per "
            "(scenario_id, injection_condition) stratum, strata enumerated in "
            "sorted(scenario_id) x sorted(injection_condition) order, giving one candidate tuple "
            "per stratum. Stage 2 (new): continuing the same generator, one rng.sample over "
            "sorted(scenario_id) picks which scenarios keep an extra tuple beyond the "
            "min_tuples_per_scenario floor, then one rng.sample per scenario (same sorted order) "
            "picks which of that scenario's stage-1 tuples survive -- so every kept tuple is a "
            "genuine subset of stage 1's one-per-stratum draw, and a kept scenario's tuples still "
            "carry distinct injection conditions. This ~10% figure "
            "(tuple_sample_count / matched_tuple_population) is a disclosed deviation from the "
            "original D2 mechanism's reuse of analysis.stats.gate.BLIND_RESCORE_SAMPLE_FRACTION "
            f"({BLIND_RESCORE_SAMPLE_FRACTION!r}, the GATE-fixed blind-re-score fraction over a "
            "different population) -- it is not derived from that constant and must not be "
            "restated as if it were; see ADR-108 D2's revision log."
        ),
        "tuples": tuples,
        "run_ids": run_ids,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--campaign-dir",
        type=Path,
        default=DEFAULT_CAMPAIGN_DIR,
        help="the pre-registered campaign directory to draw the sample from",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="where to write sample.json (default: <campaign-dir>/_scoring/sample.json)",
    )
    parser.add_argument(
        "--tuple-count",
        type=int,
        default=TUPLE_SAMPLE_COUNT,
        help=(
            "total matched tuples to keep in the balanced stage-2 subset "
            f"(default: {TUPLE_SAMPLE_COUNT}; this module's own constant, not a protocol number "
            "-- see the module docstring)"
        ),
    )
    parser.add_argument(
        "--min-per-scenario",
        type=int,
        default=MIN_TUPLES_PER_SCENARIO,
        help=(
            "minimum tuples every scenario keeps in the balanced stage-2 subset "
            f"(default: {MIN_TUPLES_PER_SCENARIO})"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    campaign_dir = Path(args.campaign_dir)
    output = (
        Path(args.output) if args.output is not None else campaign_dir / "_scoring" / "sample.json"
    )
    try:
        document = build_sample(
            campaign_dir,
            tuple_count=args.tuple_count,
            min_per_scenario=args.min_per_scenario,
        )
    except SamplingError as error:
        print(f"scoring-sample: {error}", file=sys.stderr)
        return 1
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
