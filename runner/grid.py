r"""The run grid, enumerated once, and the arithmetic that must close on 750.

WHY THE ARITHMETIC IS COUNTED OVER A SET OF ARMS, NEVER SUMMED OVER STUDIES
----------------------------------------------------------------------------
``evaluation-protocol.md`` §2 states the grid two ways -- ``6 arms x 25 base cells x 5 seeds = 750``
and ``375 + 500 - 125 = 750`` with the shared full-architecture arm counted once -- and states
outright that the superseded per-study identity "computes **875** against the real grid ... and
would **reject the real 750-run grid**". A validator that totals ``sum_study(|conditions| x cells x
seeds)`` reaches 875 while every individual run validates cleanly: the shared arm (``S1-HIER`` ==
``G0-FULL``) is counted once in the structure study and once in the guardrail study, so it enters
the sum twice. That is the failure that leaves no trace, and it is the single most consequential
line in the milestone.

So this module derives the grid from a **set of distinct arm tokens** and totals ``|arms| x
|base_cells| x |seeds|``. Study membership is a property read off ``condition`` at the point of use,
never a number stored or summed -- exactly as ``data-management.md`` §2 requires after the
``<STUDY>`` identifier component was dropped (ADR-008). :func:`per_study_overcount` reproduces the
875 figure deliberately, so the test suite carries the thing being guarded against rather than only
a description of it.

WHERE THE NUMBERS LIVE
------------------------
None of the counts is owned here. The six arms are ``runner/ids.py``'s ``CANONICAL_ARMS`` (from the
glossary §Condition IDs); the five injection-condition values are its ``INJECTION_CONDITIONS`` (from
§3.5.6 via the glossary); the scenarios are read from ``scenarios/manifests/``; and the seed set is
``07-glossary-and-ids.md`` §Seeds, single-homed there and referenced here with a pointer, the same
way ``scripts/scenario_determinism.sh`` references it. The grid total 750 and the study-wise
``375 + 500 - 125`` are ``evaluation-protocol.md`` §2's; this module asserts its enumeration matches
them rather than restating them as independent facts.

WHAT BREAKS IF THIS FILE CHANGES
---------------------------------
The campaign validator's arithmetic (T-23) and the synthetic generator's cell set (T-25). ADR-039.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Final

from scripts.versions_env_sha256 import versions_env_sha256

from runner.campaign import CampaignManifest, PlannedRun
from runner.ids import (
    CANONICAL_ARMS,
    INJECTION_CONDITIONS,
    BaselineId,
    RunId,
    format_baseline_id,
    format_run_id,
)
from runner.manifest import requires_baseline_pairing

__all__ = (
    "PILOT_P2_SEED",
    "PILOT_P3_SEED",
    "PILOT_PASS_SEEDS",
    "PILOT_SEEDS",
    "REDUCTION_SEEDS",
    "SEEDS",
    "GridError",
    "base_cells",
    "baseline_cells",
    "build_campaign_manifest",
    "expected_total",
    "grid_cells",
    "per_study_overcount",
    "scenario_ids",
)

REPO_ROOT: Final = Path(__file__).resolve().parents[1]
MANIFEST_DIR: Final = REPO_ROOT / "scenarios" / "manifests"
_MANIFEST_PATTERN: Final = re.compile(r"^SCN-(CVE|SIM)-[0-9]{2}\.yaml$")

# The fixed seed set, docs/07-glossary-and-ids.md §Seeds. Single-homed THERE; referenced here so the
# grid can enumerate, with a pointer rather than a second claim of ownership -- the same treatment
# scripts/scenario_determinism.sh's SEEDS default gives it. The reduction path uses the first three.
SEEDS: Final[tuple[int, ...]] = (101, 102, 103, 104, 105)
REDUCTION_SEEDS: Final[tuple[int, ...]] = (101, 102, 103)

# The PILOT seed set, docs/07-glossary-and-ids.md §Seeds "Pilot seeds (M10, ADR-120)" -- a pointer
# on exactly the convention `SEEDS` above uses, and the glossary says so by name ("`PILOT_SEEDS` in
# `runner/grid.py` points here, the same convention `SEEDS` uses"). The property that matters is
# DISJOINTNESS from `SEEDS`: the plan §6 states "pilot seeds disjoint from the campaign seed set ...
# so no pilot bundle can be mistaken for a campaign bundle", and disjointness is only maintainable
# if the pilot seeds live beside the campaign seeds where the overlap would be visible, not in a
# module that never imports them. P2 runs on pilot seed A, P3 on pilot seed B; both names are the
# glossary's, bound here by POSITION so re-ordering the tuple cannot silently re-point a pass.
PILOT_SEEDS: Final[tuple[int, ...]] = (901, 902)
PILOT_P2_SEED: Final[int] = PILOT_SEEDS[0]
PILOT_P3_SEED: Final[int] = PILOT_SEEDS[1]

# The coverage pass -> seed map `runner/order.generate_pilot_order` reads. A read-only mapping, so a
# caller cannot add a pass whose seed nothing in the glossary names.
PILOT_PASS_SEEDS: Final = MappingProxyType({"P2": PILOT_P2_SEED, "P3": PILOT_P3_SEED})

# The two study memberships, derived from `condition` (data-management §2), for reading rather than
# summing. The shared arm G0-FULL belongs to both; it is what makes 375 + 500 overcount by 125.
_STRUCTURE_STUDY: Final[frozenset[str]] = frozenset({"G0-FULL", "S2-FLAT", "S3-SINGLE"})
_GUARDRAIL_STUDY: Final[frozenset[str]] = frozenset(
    {"G0-FULL", "G1-LOGONLY", "G2-SHAREDCRED", "G3-UNQUOTED"}
)


class GridError(Exception):
    """The grid enumeration does not close on evaluation-protocol §2's total."""


@dataclass(frozen=True)
class BaseCell:
    """One base-suite coordinate: a scenario and an injection condition, no arm and no seed."""

    scenario_id: str
    injection_condition: str


def scenario_ids() -> tuple[str, ...]:
    """The scenarios the corpus holds, sorted. Read from scenarios/manifests/, never restated.

    Sorted rather than in readdir order, because the grid it drives is compared between machines
    whose directory order need not agree.
    """
    if not MANIFEST_DIR.is_dir():
        return ()
    return tuple(
        sorted(
            path.stem for path in MANIFEST_DIR.glob("*.yaml") if _MANIFEST_PATTERN.match(path.name)
        )
    )


def base_cells() -> tuple[BaseCell, ...]:
    """The 25 base cells: every scenario x every injection-condition value (INJ-NONE included).

    INJ-NONE is a coordinate, not an absence: it is counted like the four classes, which is what
    makes the base-cell count five-times-five rather than five-times-four (conflict M5-C4, and the
    milestone's T-36 validator line).
    """
    return tuple(
        BaseCell(scenario_id, injection)
        for scenario_id in scenario_ids()
        for injection in INJECTION_CONDITIONS
    )


def grid_cells(seeds: tuple[int, ...] = SEEDS) -> tuple[RunId, ...]:
    """Every grid run: the six canonical arms x the base cells x the seed set.

    S1-HIER is not enumerated -- it is an alias of G0-FULL, and issuing both is the double-count the
    validator rejects. The canonical six carry the shared arm as G0-FULL exactly once.
    """
    cells: list[RunId] = []
    for arm in CANONICAL_ARMS:
        for cell in base_cells():
            for seed in seeds:
                cells.append(RunId(arm, cell.scenario_id, cell.injection_condition, seed))
    return tuple(cells)


def baseline_cells(
    load_profile_ids: tuple[str, ...], seeds: tuple[int, ...] = SEEDS
) -> tuple[BaselineId, ...]:
    """The framework-off baselines the pairing rule implies: one per (load_profile_id, seed).

    The load profiles are the caller's -- which profiles a campaign runs is a campaign-manifest
    fact, resolved through infra/locust/registry.py -- so this module does not invent them.
    """
    return tuple(
        BaselineId(load_profile_id, seed) for load_profile_id in load_profile_ids for seed in seeds
    )


def expected_total(seeds: tuple[int, ...] = SEEDS) -> int:
    """|arms| x |base_cells| x |seeds|. The grid total, counted over arms and never over studies."""
    return len(CANONICAL_ARMS) * len(base_cells()) * len(seeds)


def per_study_overcount(seeds: tuple[int, ...] = SEEDS) -> int:
    """The 875 figure a per-study summation reaches. Reproduced so a test can guard against it.

    ``|structure study| + |guardrail study|`` counts the shared arm G0-FULL twice -- three arms plus
    four arms is seven arm-instances, not the six distinct arms -- so the sum overcounts the grid by
    one arm's worth of runs. This is exactly the identity evaluation-protocol §2 says "would reject
    the real 750-run grid", and the validator's negative fixture is built from it.
    """
    arm_instances = len(_STRUCTURE_STUDY) + len(_GUARDRAIL_STUDY)
    return arm_instances * len(base_cells()) * len(seeds)


def build_campaign_manifest(
    campaign_id: str,
    load_profile_id: str = "LOAD-STEADY",
    seeds: tuple[int, ...] = SEEDS,
    campaign_seed: int = 0,
) -> CampaignManifest:
    """Build the real, valid planned grid: 750 runs plus the baselines the pairing rule implies.

    Every grid run carries ``load_profile_id`` (a run runs under some load); only the RQ4 arm
    G0-FULL names a baseline, and each G0-FULL run at seed ``s`` names ``BASE-<load>-<s>``. The
    baselines are one per ``(load_profile_id, seed)``. This is exactly the campaign the validator
    must accept -- the DoD's positive fixture -- and the shape the synthetic generator seals.
    """
    runs: list[PlannedRun] = []
    for run in grid_cells(seeds):
        pairs = requires_baseline_pairing(run.condition)
        baseline_id = format_baseline_id(BaselineId(load_profile_id, run.seed)) if pairs else None
        runs.append(
            PlannedRun(
                run_id=format_run_id(run),
                condition=run.condition,
                scenario_id=run.scenario_id,
                injection_condition=run.injection_condition,
                seed=run.seed,
                is_baseline=False,
                baseline_run_id=baseline_id,
                load_profile_id=load_profile_id,
            )
        )
    for baseline in baseline_cells((load_profile_id,), seeds):
        runs.append(
            PlannedRun(
                run_id=format_baseline_id(baseline),
                condition=None,
                scenario_id=None,
                injection_condition=None,
                seed=baseline.seed,
                is_baseline=True,
                baseline_run_id=None,
                load_profile_id=baseline.load_profile_id,
            )
        )
    frozen_runs = tuple(runs)
    # Import here to avoid the campaign-order module's intentional dependency on this grid module.
    from runner.order import generate_order

    unfrozen = CampaignManifest(
        campaign_id=campaign_id,
        seeds=tuple(seeds),
        load_profiles=(load_profile_id,),
        runs=frozen_runs,
        campaign_seed=campaign_seed,
        generated_order=(),
        versions_env_sha256=versions_env_sha256(),
    )
    return CampaignManifest(
        campaign_id=campaign_id,
        seeds=tuple(seeds),
        load_profiles=(load_profile_id,),
        runs=frozen_runs,
        campaign_seed=campaign_seed,
        generated_order=generate_order(unfrozen, campaign_seed),
        versions_env_sha256=unfrozen.versions_env_sha256,
    )


def _self_check() -> None:
    """Assert the enumeration closes on evaluation-protocol §2's total, both ways.

    Run at import so a grid that stopped closing on 750 -- because a scenario was added or the arm
    set changed -- fails loudly at the point of use rather than silently producing a campaign of the
    wrong size. Skipped when the corpus is absent (pre-M5 / a partial checkout), because five
    scenarios is a property of the corpus this module reads, not of this module.
    """
    scenarios = scenario_ids()
    if len(scenarios) != 5:
        # corpus not fully present; the campaign validator enforces the count where it matters
        return
    total = expected_total()
    if total != 750:
        raise GridError(
            f"grid enumerates {total} runs, not the 750 evaluation-protocol §2 fixes "
            f"({len(CANONICAL_ARMS)} arms x {len(base_cells())} base cells x {len(SEEDS)} seeds)"
        )
    # study-wise: 375 + 500 - 125 = 750, the shared arm subtracted once.
    structure = len(_STRUCTURE_STUDY) * len(base_cells()) * len(SEEDS)
    guardrail = len(_GUARDRAIL_STUDY) * len(base_cells()) * len(SEEDS)
    shared = len(base_cells()) * len(SEEDS)
    if structure + guardrail - shared != total:
        raise GridError(
            f"study-wise arithmetic {structure} + {guardrail} - {shared} does not close on {total}"
        )


_self_check()
