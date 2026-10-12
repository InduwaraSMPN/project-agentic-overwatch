r"""The campaign-manifest validator (T6.3): one rule set, three entry points.

``data-management.md`` §2 requires the identifier-versus-manifest comparison "at submission and
again at seal", and those read different things: at submission there are only planned cells, at seal
one bundle, after a campaign a directory. So one module carries the rules and exposes three entry
points over them, and no rule is implemented twice to drift:

- :func:`validate_campaign_manifest` -- pre-flight over the planned grid. Arithmetic (counted over
  arms, never summed over studies), arm-set identity, the five injection-condition values including
  ``INJ-NONE``, the baseline plan (one per ``(load_profile_id, seed)``, each ``load_profile_id``
  resolving through ``infra.locust.registry``), and pairing coverage. This is what ``make campaign``
  calls before it starts.
- :func:`validate_bundle` -- at seal. Field-for-field identifier comparison on all four components,
  the null-field set in both directions, and the completeness profile ``is_baseline`` selects
  (completeness is ``runner/bundle.py``'s; this checks the manifest rules).
- :func:`validate_campaign_corpus` -- post-hoc over sealed bundles. Everything above plus the
  counting rules only a corpus answers: only ``is_baseline: false`` counted; no arm issued twice;
  every ``baseline_run_id`` resolving inside the same campaign to an ``is_baseline: true`` bundle of
  the same ``load_profile_id``. This is what M7's daily QA reconciliation calls.

THE ARITHMETIC OPERATES ON A SET OF ARM TOKENS
------------------------------------------------
The single most consequential rule (``runner/grid.py`` argues it at length): the total is
``|distinct arms| x |base cells| x |seeds|``, never ``sum_study(...)``, because the shared arm
``S1-HIER == G0-FULL`` enters a per-study sum twice and reaches 875, which "would reject the real
750-run grid". The per-study 875 figure and an ``S1-HIER``/``G0-FULL`` co-occurrence each get a
negative fixture; they are the same defect wearing two masks.

EVERY REJECTION CARRIES A DISTINCT REASON CODE
------------------------------------------------
The DoD requires "one negative fixture per case ... every negative fixture rejected with a distinct
reason". So :class:`ValidationError` carries a ``code`` from :data:`REASON_CODES`, and the
test suite
asserts on the code rather than on message text, which lets a message be reworded without breaking a
test and makes "a distinct reason per case" checkable.

WHAT BREAKS IF THIS FILE CHANGES
---------------------------------
T-23 (campaign validity) and T-36 (the validator accepting the five injection-condition values).
ADR-039.
"""

import json
from collections import Counter
from dataclasses import replace
from pathlib import Path
from typing import Final

from infra.locust.registry import UnknownLoadProfile, resolve
from scripts.versions_env_sha256 import versions_env_sha256

from runner.campaign import CampaignManifest, PlannedRun
from runner.grid import SEEDS, expected_total, scenario_ids
from runner.ids import (
    CANONICAL_ARMS,
    INJECTION_CONDITIONS,
    IdError,
    cell_key,
    parse_baseline_id,
    parse_run_id,
)
from runner.manifest import (
    BASELINE_NULL_FIELDS,
    FRAMEWORK_ON_REQUIRED_NON_NULL,
    SCHEMA_VERSION,
    RunManifest,
    requires_baseline_pairing,
)
from runner.order import OrderError, generate_order

__all__ = (
    "REASON_CODES",
    "ValidationError",
    "validate_bundle",
    "validate_campaign_corpus",
    "validate_campaign_corpus_for_testing",
    "validate_campaign_manifest",
    "validate_campaign_manifest_for_testing",
    "validate_cost_pilot_manifest",
    "validate_coverage_pilot_manifest",
    "validate_pilot_campaign_manifest",
    "validate_smoke_pilot_manifest",
)

# One code per rejection case the DoD enumerates. The suite asserts on these, not on message text.
# Every code here is emitted somewhere below -- a reason code nothing raises is a dead assertion, so
# the set is exactly the reachable codes. The per-study 875 manifest is not its own code: a
# per-study summation carries BOTH S1-HIER and G0-FULL, so it is rejected as
# `shared-arm-double-count` -- "the same defect wearing a different mask", per the plan.
REASON_CODES: Final[frozenset[str]] = frozenset(
    {
        "id-malformed",
        "id-field-mismatch",
        "schema-version-mismatch",
        "campaign-id-mismatch",
        "campaign-manifest-invalid",
        "campaign-bundle-mismatch",
        "campaign-metadata-mismatch",
        "campaign-order-mismatch",
        "versions-env-sha256-mismatch",
        "grid-vocabulary-mismatch",
        "arm-set-mismatch",
        "pilot-pairing-mismatch",
        "shared-arm-double-count",
        "arithmetic-not-750",
        "injection-values-incomplete",
        "baseline-nonnull-field",
        "framework-on-null-field",
        "condition-flags-mismatch",
        "rq4-null-baseline",
        "baseline-pairing-load-mismatch",
        "baseline-pairing-seed-mismatch",
        "baseline-duplicate-key",
        "load-profile-unknown",
        "baseline-counted-in-grid",
        "duplicate-valid-attempt",
        "baseline-ref-unresolved",
        "bundle-integrity",
        "run-invalid",
        "mixed-instrument",
    }
)


class ValidationError(Exception):
    """A campaign, a manifest or a corpus violates a data-management §2 rule.

    ``code`` is one of :data:`REASON_CODES`; ``detail`` names the offending run or field.
    """

    def __init__(self, code: str, detail: str) -> None:
        if code not in REASON_CODES:
            raise AssertionError(f"unknown reason code {code!r}; add it to REASON_CODES")
        self.code = code
        self.detail = detail
        super().__init__(f"[{code}] {detail}")


# --- helpers over a set of planned runs (shared by manifest and corpus entry points) -------------


def _grid_runs(runs: tuple[PlannedRun, ...]) -> list[PlannedRun]:
    return [run for run in runs if not run.is_baseline]


def _baselines(runs: tuple[PlannedRun, ...]) -> list[PlannedRun]:
    return [run for run in runs if run.is_baseline]


def _check_identifier_matches_fields(run: PlannedRun) -> None:
    """The 'total' comparison: parse the identifier and check all four components field-wise."""
    if run.is_baseline:
        try:
            parsed = parse_baseline_id(run.run_id)
        except IdError as error:
            raise ValidationError("id-malformed", str(error)) from None
        if parsed.load_profile_id != run.load_profile_id:
            raise ValidationError(
                "id-field-mismatch",
                f"{run.run_id}: load_profile_id field {run.load_profile_id!r} != id "
                f"{parsed.load_profile_id!r}",
            )
        if parsed.seed != run.seed:
            raise ValidationError(
                "id-field-mismatch", f"{run.run_id}: seed field {run.seed} != id {parsed.seed}"
            )
        return
    try:
        parsed_run = parse_run_id(run.run_id)
    except IdError as error:
        raise ValidationError("id-malformed", str(error)) from None
    for name, from_id, from_field in (
        ("condition", parsed_run.condition, run.condition),
        ("scenario_id", parsed_run.scenario_id, run.scenario_id),
        ("injection_condition", parsed_run.injection_condition, run.injection_condition),
        ("seed", parsed_run.seed, run.seed),
    ):
        if from_id != from_field:
            raise ValidationError(
                "id-field-mismatch",
                f"{run.run_id}: {name} field {from_field!r} disagrees with identifier {from_id!r}",
            )


def _check_null_fields(run: PlannedRun) -> None:
    """The two-directional null-field check over the subset of §2's twelve a PlannedRun carries."""
    present = {
        "condition": run.condition,
        "scenario_id": run.scenario_id,
        "injection_condition": run.injection_condition,
        "baseline_run_id": run.baseline_run_id,
    }
    if run.is_baseline:
        for name, value in present.items():
            if name in BASELINE_NULL_FIELDS and value is not None:
                raise ValidationError(
                    "baseline-nonnull-field",
                    f"{run.run_id}: baseline carries non-null {name}={value!r}, in §2's null set",
                )
        return
    # framework-on: every one of the eleven that this record carries must be non-null...
    for name, value in present.items():
        if name in FRAMEWORK_ON_REQUIRED_NON_NULL and value is None:
            raise ValidationError(
                "framework-on-null-field", f"{run.run_id}: framework-on run has null {name}"
            )
    # ...and baseline_run_id follows its narrower rule: non-null iff this arm is the RQ4 arm.
    if requires_baseline_pairing(run.condition) and run.baseline_run_id is None:
        raise ValidationError(
            "rq4-null-baseline",
            f"{run.run_id}: G0-FULL run must name a baseline (data-management §2 RQ4 pairing)",
        )


def _check_load_profiles(runs: tuple[PlannedRun, ...]) -> None:
    """Every load_profile_id on any run resolves to an M1 registry entry."""
    for run in runs:
        try:
            resolve(run.load_profile_id)
        except UnknownLoadProfile as error:
            raise ValidationError("load-profile-unknown", str(error)) from None


def _check_campaign_metadata(
    manifest: CampaignManifest, *, expected_seeds: tuple[int, ...] = SEEDS
) -> None:
    """Top-level seed/profile declarations must exactly describe the planned runs."""
    run_seeds = {run.seed for run in manifest.runs}
    declared_seeds = set(manifest.seeds)
    run_profiles = {run.load_profile_id for run in manifest.runs}
    declared_profiles = set(manifest.load_profiles)
    if (
        len(manifest.seeds) != len(declared_seeds)
        or declared_seeds != set(expected_seeds)
        or run_seeds != declared_seeds
        or len(manifest.load_profiles) != len(declared_profiles)
        or run_profiles != declared_profiles
    ):
        raise ValidationError(
            "campaign-metadata-mismatch",
            "campaign seeds/load_profiles do not exactly match the canonical seeds and "
            "run metadata: "
            f"declared seeds={manifest.seeds}, run seeds={sorted(run_seeds)}, "
            f"declared profiles={manifest.load_profiles}, run profiles={sorted(run_profiles)}",
        )


def _check_frozen_campaign(manifest: CampaignManifest) -> None:
    """The recorded order and versions digest must match the frozen campaign inputs exactly."""
    current_versions = versions_env_sha256()
    if manifest.versions_env_sha256 != current_versions:
        raise ValidationError(
            "versions-env-sha256-mismatch",
            "campaign versions_env_sha256 does not match the current LF-normalised "
            "infra/versions.env",
        )
    try:
        expected_order = generate_order(manifest, manifest.campaign_seed)
    except OrderError as error:
        raise ValidationError("campaign-order-mismatch", str(error)) from None
    if manifest.generated_order != expected_order:
        raise ValidationError(
            "campaign-order-mismatch",
            "generated_order is not the deterministic complete order for campaign_seed",
        )


def _check_baseline_plan(runs: tuple[PlannedRun, ...]) -> None:
    """At most one baseline per (load_profile_id, seed); each RQ4 run's baseline pairs correctly."""
    baselines = _baselines(runs)
    seen: dict[tuple[str, int], str] = {}
    by_id: dict[str, PlannedRun] = {}
    for baseline in baselines:
        key = (baseline.load_profile_id, baseline.seed)
        if key in seen:
            raise ValidationError(
                "baseline-duplicate-key",
                f"second baseline for {key}: {baseline.run_id} and {seen[key]}",
            )
        seen[key] = baseline.run_id
        by_id[baseline.run_id] = baseline
    for run in _grid_runs(runs):
        if run.baseline_run_id is None:
            continue
        target = by_id.get(run.baseline_run_id)
        if target is None:
            raise ValidationError(
                "baseline-ref-unresolved",
                f"{run.run_id}: baseline_run_id {run.baseline_run_id!r} names no campaign baseline",
            )
        if target.load_profile_id != run.load_profile_id:
            raise ValidationError(
                "baseline-pairing-load-mismatch",
                f"{run.run_id}: load_profile_id {run.load_profile_id!r} but its baseline "
                f"{target.run_id} carries {target.load_profile_id!r}",
            )
        if target.seed != run.seed:
            raise ValidationError(
                "baseline-pairing-seed-mismatch",
                f"{run.run_id}: seed {run.seed} but its baseline {target.run_id} carries seed "
                f"{target.seed}; baseline pairing requires equal load profile and seed",
            )


def _check_arm_arithmetic(
    runs: tuple[PlannedRun, ...], *, expected_seeds: tuple[int, ...] = SEEDS
) -> None:
    """Arm-set identity and the 750 total, counted over arms and never summed over studies."""
    grid = _grid_runs(runs)
    arms = {run.condition for run in grid}
    if "S1-HIER" in arms and "G0-FULL" in arms:
        raise ValidationError(
            "shared-arm-double-count",
            "campaign carries both S1-HIER and G0-FULL bundles -- the shared full-architecture arm "
            "issued twice (data-management §2)",
        )
    if arms != set(CANONICAL_ARMS):
        raise ValidationError(
            "arm-set-mismatch",
            f"arm set {sorted(arms)} is not the six canonical arms {sorted(CANONICAL_ARMS)}",
        )
    # The protocol owns the complete vocabulary and count. Never derive the expected product from
    # whichever scenarios or seeds happen to appear in the submitted manifest: doing so lets a
    # internally complete one-seed corpus validate as a smaller campaign.
    canonical_scenarios = scenario_ids()
    expected_keys = {
        (arm, scenario, injection, seed)
        for arm in CANONICAL_ARMS
        for scenario in canonical_scenarios
        for injection in INJECTION_CONDITIONS
        for seed in expected_seeds
    }
    actual = Counter(
        (run.condition, run.scenario_id, run.injection_condition, run.seed) for run in grid
    )
    actual_keys = set(actual)
    if actual_keys != expected_keys or any(count != 1 for count in actual.values()):
        missing = expected_keys - actual_keys
        unexpected = actual_keys - expected_keys
        duplicates = [key for key, count in actual.items() if count != 1]
        raise ValidationError(
            "grid-vocabulary-mismatch",
            "grid must contain every canonical arm x scenario x injection x seed cell exactly "
            f"once; missing={len(missing)}, unexpected={len(unexpected)}, "
            f"duplicate_cells={len(duplicates)}",
        )
    expected_count = expected_total(expected_seeds)
    if len(canonical_scenarios) != 5 or len(grid) != expected_count:
        raise ValidationError(
            "arithmetic-not-750",
            f"grid is {len(grid)} runs over {len(canonical_scenarios)} canonical scenarios, not "
            f"the expected {expected_count} for {len(expected_seeds)} seed(s)",
        )


def _check_injection_values(runs: tuple[PlannedRun, ...]) -> None:
    """All five injection-condition values appear, INJ-NONE among them (T-36)."""
    values = {run.injection_condition for run in _grid_runs(runs)}
    missing = set(INJECTION_CONDITIONS) - values
    if missing:
        raise ValidationError(
            "injection-values-incomplete",
            f"grid is missing injection-condition value(s) {sorted(missing)} -- "
            "INJ-NONE is a coordinate, not an absence (T-36)",
        )


def _check_no_baselines_in_total(runs: tuple[PlannedRun, ...]) -> None:
    """The total is over is_baseline:false alone; reaching 750 by counting baselines is invalid."""
    grid = _grid_runs(runs)
    if len(grid) < expected_total():
        # A campaign short on grid runs that only reaches the target once baselines are added is the
        # 'counted baselines toward the grid' defect.
        if len(runs) >= expected_total():
            raise ValidationError(
                "baseline-counted-in-grid",
                f"{len(grid)} grid runs plus baselines reaches the target only by counting "
                "is_baseline:true runs, which do not count toward the grid (data-management §2)",
            )


def _validate_campaign_manifest(
    manifest: CampaignManifest, *, expected_seeds: tuple[int, ...]
) -> dict[str, int]:
    """Shared implementation; only the explicitly test-only API may reduce the seed set."""
    runs = manifest.runs
    for run in runs:
        _check_identifier_matches_fields(run)
        _check_null_fields(run)
    _check_load_profiles(runs)
    _check_campaign_metadata(manifest, expected_seeds=expected_seeds)
    _check_no_baselines_in_total(runs)
    _check_arm_arithmetic(runs, expected_seeds=expected_seeds)
    _check_injection_values(runs)
    _check_baseline_plan(runs)
    _check_frozen_campaign(manifest)
    return dict(Counter(run.injection_condition for run in _grid_runs(runs)))


def validate_campaign_manifest(manifest: CampaignManifest) -> dict[str, int]:
    """Validate a production campaign against the protocol's canonical seed set."""
    return _validate_campaign_manifest(manifest, expected_seeds=SEEDS)


def validate_campaign_manifest_for_testing(
    manifest: CampaignManifest, *, expected_seeds: tuple[int, ...]
) -> dict[str, int]:
    """Validate a deliberately reduced unit-test fixture; never use for a real campaign."""
    return _validate_campaign_manifest(manifest, expected_seeds=expected_seeds)


def validate_cost_pilot_manifest(manifest: CampaignManifest) -> dict[str, int]:
    """Validate the Ch.3 cost pilot: three matched G0-FULL/G1-LOGONLY pairs (Chapter 3, 485).

    The pre-M10 six-run G0/G1 plan, kept verbatim under its M10 name (ADR-136): plan §6 keeps the
    3+3 validator as the cost pilot and adds :func:`validate_smoke_pilot_manifest` and
    :func:`validate_coverage_pilot_manifest` beside it. ``validate_pilot_campaign_manifest`` stays a
    thin alias so ``runner/pilot_cli.py``'s ``validate`` subcommand keeps working unchanged.
    """
    runs = manifest.runs
    if len(runs) != 6 or any(run.is_baseline for run in runs):
        raise ValidationError(
            "campaign-manifest-invalid",
            "GATE pilot must contain exactly six framework-on runs and no baseline entries",
        )
    for run in runs:
        _check_identifier_matches_fields(run)
        _check_null_fields(run)
    _check_load_profiles(runs)

    counts = Counter(run.condition for run in runs)
    required = {"G0-FULL": 3, "G1-LOGONLY": 3}
    if counts != required:
        raise ValidationError(
            "arm-set-mismatch", f"GATE pilot arm counts are {dict(counts)}, expected {required}"
        )

    # The six cells must form three matched G0-FULL/G1-LOGONLY pairs. analysis/stats/pairs.py forms
    # the RQ5 guardrail contrast by an inner join on (scenario, injection-condition, seed) -- all
    # three keys -- and a zero-pair contrast is a hard error, not an empty table (§3). Correct arm
    # counts alone do not guarantee a single pair: an earlier plan ran every G0-FULL cell on a SIM
    # scenario and every G1-LOGONLY cell on a CVE one, which passed the count check above yet formed
    # zero matched pairs, so the pilot's own G0-vs-G1 contrast could not be computed. Require both
    # arms to name the identical set of (scenario, injection, seed) triples.
    def _triples(condition: str) -> set[tuple[str, str, int]]:
        return {
            (run.scenario_id, run.injection_condition, run.seed)
            for run in runs
            if run.condition == condition
        }

    g0_triples = _triples("G0-FULL")
    g1_triples = _triples("G1-LOGONLY")
    if g0_triples != g1_triples:
        raise ValidationError(
            "pilot-pairing-mismatch",
            "GATE pilot must form three matched G0-FULL/G1-LOGONLY pairs on "
            f"(scenario, injection, seed); G0-only {sorted(g0_triples - g1_triples)}, G1-only "
            f"{sorted(g1_triples - g0_triples)}. analysis/stats/pairs.py pairs on all three keys "
            "and a zero-pair contrast is a hard error (evaluation-protocol.md §3)",
        )
    if {str(run.scenario_id).split("-")[1] for run in runs} != {"CVE", "SIM"}:
        raise ValidationError(
            "grid-vocabulary-mismatch", "GATE pilot must include both CVE and SIM scenarios"
        )
    if len({run.run_id for run in runs}) != len(runs):
        raise ValidationError("grid-vocabulary-mismatch", "GATE pilot run IDs must be unique")
    if set(manifest.seeds) != {run.seed for run in runs} or set(manifest.load_profiles) != {
        run.load_profile_id for run in runs
    }:
        raise ValidationError(
            "campaign-metadata-mismatch",
            "pilot seeds/load_profiles must exactly describe its six planned runs",
        )
    if tuple(manifest.generated_order) != tuple(run.run_id for run in runs):
        raise ValidationError(
            "campaign-order-mismatch", "pilot generated_order must list the six runs exactly once"
        )
    if manifest.versions_env_sha256 != versions_env_sha256():
        raise ValidationError(
            "versions-env-sha256-mismatch",
            "pilot versions_env_sha256 does not match current infra/versions.env",
        )
    return dict(counts)


# The pre-M10 name, kept as an alias so `runner/pilot_cli.py`'s `validate` subcommand and any other
# caller keep resolving the cost-pilot validator without an edit (V16 kept the 3+3 plan, it did not
# retire it). ADR-136 names the three pilot validators; this is the one that already existed.
validate_pilot_campaign_manifest = validate_cost_pilot_manifest


def validate_extended_cost_pilot_manifest(manifest: CampaignManifest) -> dict[str, int]:
    """P1b preserves the cost pairs and adds one matched run for each remaining arm."""
    from runner.pilot_cli import PILOT_P1B_RUNS

    base = tuple(run for run in manifest.runs if run.condition in {"G0-FULL", "G1-LOGONLY"})
    validate_cost_pilot_manifest(
        replace(manifest, runs=base, generated_order=tuple(run.run_id for run in base))
    )
    extra = tuple(run for run in manifest.runs if run not in base)
    required = set(CANONICAL_ARMS) - {"G0-FULL", "G1-LOGONLY"}
    if len(manifest.runs) != PILOT_P1B_RUNS or Counter(
        run.condition for run in extra
    ) != dict.fromkeys(required, 1):
        raise ValidationError("arm-set-mismatch", "P1b must add exactly one run per remaining arm")
    triples = {
        (run.scenario_id, run.injection_condition, run.seed, run.load_profile_id) for run in base
    }
    for run in extra:
        _check_identifier_matches_fields(run)
        _check_null_fields(run)
        if (
            run.is_baseline
            or (run.scenario_id, run.injection_condition, run.seed, run.load_profile_id)
            not in triples
        ):
            raise ValidationError(
                "pilot-pairing-mismatch", "P1b supplemental runs must match a cost cell"
            )
    if manifest.generated_order != tuple(run.run_id for run in manifest.runs):
        raise ValidationError(
            "campaign-order-mismatch", "P1b order must contain each planned run once"
        )
    return dict(Counter(run.condition for run in manifest.runs))


def validate_smoke_pilot_manifest(manifest: CampaignManifest) -> dict[str, int]:
    """Validate the P1a scripted smoke: one framework-on run per arm, all six arms, no baselines.

    Plan §6's P1a step exercises every arm's mint -> act -> complete path once, scripted, so the
    smoke pilot is exactly the six canonical arms each run once (defect V16: v1 piloted only G0 and
    G1, so S2/S3/G2/G3 were never smoke-tested). Every arm exactly once and no baseline entry: a
    baseline runs no framework, so it has nothing to smoke.
    """
    runs = manifest.runs
    if any(run.is_baseline for run in runs):
        raise ValidationError(
            "campaign-manifest-invalid", "smoke pilot must contain no baseline entries"
        )
    for run in runs:
        _check_identifier_matches_fields(run)
        _check_null_fields(run)
    _check_load_profiles(runs)
    counts = Counter(run.condition for run in runs)
    if set(counts) != set(CANONICAL_ARMS) or any(count != 1 for count in counts.values()):
        raise ValidationError(
            "arm-set-mismatch",
            f"smoke pilot must run each of the six canonical arms {sorted(CANONICAL_ARMS)} exactly "
            f"once; arm counts are {dict(counts)}",
        )
    if len({run.run_id for run in runs}) != len(runs):
        raise ValidationError("grid-vocabulary-mismatch", "smoke pilot run IDs must be unique")
    return dict(counts)


def validate_coverage_pilot_manifest(manifest: CampaignManifest) -> dict[str, int]:
    """Validate the P2 coverage pilot: every arm covered, and matched so every contrast pairs.

    Plan §6's P2 step runs the six arms across every injection condition on one pilot seed, with the
    scenario of a cell a FUNCTION OF THE INJECTION CONDITION ONLY -- so all six arms share the same
    ``(scenario, injection_condition, seed)`` cells and every arm pairs with every other on all of
    them (``analysis/stats/pairs.py`` joins on those three keys; a zero-pair contrast is a hard
    error, §3). This is the structural fix for V16: the pilot now exercises S2/S3/G2/G3, not only
    G0/G1.

    The three properties, checked rather than assumed:

    * every canonical arm appears (coverage), and no baseline does;
    * every one of the five injection conditions appears (a class the pilot never runs is a class
      the gate never checks);
    * every arm names the IDENTICAL set of ``(scenario, injection, seed)`` cells, so the guardrail
      and structure contrasts each form a matched pair on every cell rather than zero.

    The run count is not restated here (it is the protocol's, plan §6): the structural checks below
    imply it, and asserting the number would be a second home for it (rule 00).
    """
    runs = manifest.runs
    if any(run.is_baseline for run in runs):
        raise ValidationError(
            "campaign-manifest-invalid", "coverage pilot must contain no baseline entries"
        )
    for run in runs:
        _check_identifier_matches_fields(run)
        _check_null_fields(run)
    _check_load_profiles(runs)
    arms = {run.condition for run in runs}
    if arms != set(CANONICAL_ARMS):
        raise ValidationError(
            "arm-set-mismatch",
            f"coverage pilot must cover all six canonical arms {sorted(CANONICAL_ARMS)}; it covers "
            f"{sorted(arms)}",
        )
    _check_injection_values(runs)

    # Every arm must name the IDENTICAL (scenario, injection, seed) cells, so every G0-vs-Gk and
    # S1-vs-Sk contrast forms a matched pair on all of them. Correct arm counts are not enough: an
    # earlier plan gave two arms disjoint scenarios and paired nothing (the same defect
    # `validate_cost_pilot_manifest` guards against for the 3+3 pilot).
    def _cells(condition: str) -> set[tuple[str | None, str | None, int]]:
        return {
            (run.scenario_id, run.injection_condition, run.seed)
            for run in runs
            if run.condition == condition
        }

    reference = _cells(next(iter(sorted(arms))))
    for arm in sorted(arms):
        cells = _cells(arm)
        if cells != reference:
            raise ValidationError(
                "pilot-pairing-mismatch",
                f"coverage pilot arm {arm} does not share the other arms' "
                f"(scenario, injection, seed) cells; arm-only {sorted(cells - reference)}, "
                f"others-only {sorted(reference - cells)}. Every arm must name identical cells so "
                "each contrast forms a matched pair (analysis/stats/pairs.py; protocol §3)",
            )
    if len({run.run_id for run in runs}) != len(runs):
        raise ValidationError("grid-vocabulary-mismatch", "coverage pilot run IDs must be unique")
    return dict(Counter(run.condition for run in runs))


def validate_bundle(manifest: RunManifest) -> None:
    """At-seal validation of one bundle's manifest: identifier match and the null set both ways.

    Completeness (which files must be present or absent) is runner/bundle.py's; this is the manifest
    half of the seal-time check data-management §2 owns.
    """
    planned = PlannedRun(
        run_id=manifest.run_id,
        condition=manifest.condition,
        scenario_id=manifest.scenario_id,
        injection_condition=manifest.injection_condition,
        seed=manifest.seed,
        is_baseline=manifest.is_baseline,
        baseline_run_id=manifest.baseline_run_id,
        load_profile_id=manifest.load_profile_id,
    )
    _check_identifier_matches_fields(planned)
    if manifest.schema_version != SCHEMA_VERSION:
        raise ValidationError(
            "schema-version-mismatch",
            f"{manifest.run_id}: schema_version {manifest.schema_version!r} is not "
            f"{SCHEMA_VERSION!r}",
        )
    # The full twelve-field null set, both directions, over the whole manifest -- not the four-field
    # subset a PlannedRun carries. A framework-on run with a null graph_id or guardian_mode is
    # caught
    # here, at seal, which is where data-management §2 requires the second of its two comparisons.
    _check_manifest_null_fields(manifest)
    if not manifest.is_baseline:
        from runner.conditions import flags_for

        expected = flags_for(manifest.condition or "")
        # The four CONFIGURATION flags: what the runner selected from the condition table, and
        # therefore what the manifest must agree with. ``shared_credential_exercised`` is
        # deliberately NOT one of them. It is an OBSERVATION derived from the API-audit slice
        # (M10 plan §3.1 D1-A, ADR-131), so requiring it to equal the arm's name is precisely the
        # defect the M10 remediation removes (V7: the field reported the treatment the experiment
        # INTENDED). Its own rule is below; F-GD-05 (class T, stage seal) owns the G2 half.
        observed = (
            manifest.graph_id,
            manifest.guardian_mode,
            manifest.aggregator_quoting,
            manifest.netpol_overlay,
        )
        required = (
            expected.graph_id,
            expected.guardian_mode,
            expected.aggregator_quoting,
            expected.netpol_overlay,
        )
        if observed != required:
            raise ValidationError(
                "condition-flags-mismatch",
                f"{manifest.run_id}: condition {manifest.condition!r} requires "
                f"graph_id={required[0]!r}, guardian_mode={required[1]!r}, "
                f"aggregator_quoting={required[2]!r}, netpol_overlay={required[3]!r}; "
                f"observed {observed!r}",
            )
        # The credential field's rule, ONE DIRECTION ONLY. Every arm but G2 must record that the
        # alternate path was not exercised: only G2-SHAREDCRED may hold that credential, so a
        # ``True`` anywhere else is an authenticated request by a principal no other arm has, and
        # this is the seal-time backstop for F-GD-05's non-G2 half. G2 itself is UNCONSTRAINED here.
        # Whether the agents discovered and used the path is the finding C2 exists to measure, and a
        # validator that demanded ``True`` would force the manifest to assert the treatment instead
        # of recording it -- v1's inert G2, arriving as a check rather than as a value. A G2 run
        # that never touched the path therefore seals with ``False`` and is a finding, not a defect;
        # a G2 run whose field disagrees with its own audit slice is caught by F-GD-05.
        if manifest.condition != "G2-SHAREDCRED" and manifest.shared_credential_exercised:
            raise ValidationError(
                "condition-flags-mismatch",
                f"{manifest.run_id}: condition {manifest.condition!r} records "
                "shared_credential_exercised=True; only G2-SHAREDCRED may hold that credential, "
                "and an authenticated request is proof it was held (F-GD-05, ADR-131)",
            )
    try:
        resolve(manifest.load_profile_id)
    except UnknownLoadProfile as error:
        raise ValidationError("load-profile-unknown", str(error)) from None


def _check_manifest_null_fields(manifest: RunManifest) -> None:
    """The two-directional null check over all twelve of §2's fields, on a full RunManifest."""
    values = {name: getattr(manifest, name) for name in BASELINE_NULL_FIELDS}
    if manifest.is_baseline:
        for name, value in values.items():
            if value is not None:
                raise ValidationError(
                    "baseline-nonnull-field",
                    f"{manifest.run_id}: baseline carries non-null {name}={value!r} (§2 null set)",
                )
        return
    for name in FRAMEWORK_ON_REQUIRED_NON_NULL:
        if values[name] is None:
            raise ValidationError(
                "framework-on-null-field", f"{manifest.run_id}: framework-on run has null {name}"
            )
    if requires_baseline_pairing(manifest.condition) and manifest.baseline_run_id is None:
        raise ValidationError(
            "rq4-null-baseline",
            f"{manifest.run_id}: G0-FULL run must name a baseline (data-management §2 RQ4 pairing)",
        )


def _check_one_instrument(
    manifests: list[RunManifest], campaign_manifest: CampaignManifest
) -> None:
    """Require one instrument digest across the framework-on corpus, equal to the freeze tag's.

    ADR-136 / P6: a frozen campaign runs on exactly one instrument. Each framework-on bundle records
    the instrument digest that produced it (data-management §2's M10 field), so a corpus that spans
    more than one distinct value is the mixed-commit defect V14 -- a recorded ``git_commit`` that
    differs from the freeze tag's commit INSIDE the instrument paths, which moves the digest. A
    ``git_commit`` differing only OUTSIDE the instrument paths keeps the same digest and is fine --
    the whole point of a digest rather than a bare commit-equality check.

    When the frozen manifest names a ``freeze_tag`` and the tag resolves on this host, the one
    corpus digest must also equal the tag's own instrument digest: a corpus internally consistent on
    the WRONG instrument is still not the frozen one. The tag resolution is best-effort -- a corpus
    re-validated on a machine without the annotated tag still gets the digest-equality check above,
    and F-RN-02's fidelity replay carries the full git-side proof.
    """
    digests = {m.instrument_digest for m in manifests if not m.is_baseline}
    if len(digests) > 1:
        raise ValidationError(
            "mixed-instrument",
            f"the corpus spans {len(digests)} instrument states "
            f"{sorted(str(digest) for digest in digests)}; a frozen campaign runs on exactly one "
            "instrument, and a recorded git_commit may differ from the freeze tag only outside the "
            "instrument paths (ADR-136, defect V14)",
        )
    freeze_tag = campaign_manifest.freeze_tag
    only = next(iter(digests), None)
    if not freeze_tag or not isinstance(only, str):
        return
    try:
        from runner.freeze import instrument_digest, resolve_tag_commit

        tag_digest = instrument_digest(rev=resolve_tag_commit(freeze_tag))
    except Exception:  # noqa: BLE001 - the tag may be unresolvable off the campaign host
        return
    if only != tag_digest:
        raise ValidationError(
            "mixed-instrument",
            f"the corpus instrument digest {only!r} is not the freeze tag {freeze_tag!r} digest "
            f"{tag_digest!r}; the campaign ran on a different instrument than it froze (ADR-136)",
        )


def _validate_campaign_corpus(
    campaign_dir: Path, *, expected_seeds: tuple[int, ...]
) -> dict[str, int]:
    """Post-hoc validation over sealed bundles. Everything above plus corpus-only counting rules.

    Reads each bundle's manifest.json, EXCLUDES the invalid originals of any validity rerun (a run
    named by some other bundle's ``rerun_of``; data-management §4's "reads only the campaign's valid
    bundles"), then runs the manifest-level rules and the rules only a corpus answers: no arm issued
    twice, exactly one valid attempt per cell key, and every ``baseline_run_id`` resolving inside
    this campaign. The rerun exclusion is what lets a campaign that had reruns -- the normal case at
    M7-T7.3 -- validate at all, rather than tripping the one-per-cell rule on an original kept
    alongside its retry. This is the entry point M7's daily QA reconciliation calls.
    """
    manifests: list[RunManifest] = []
    from runner.bundle import verify_bundle_seal
    from runner.campaign import CampaignError
    from runner.campaign import from_dict as campaign_from_dict
    from runner.manifest import from_dict as manifest_from_dict

    campaign_manifest_path = campaign_dir / "campaign.json"
    try:
        campaign_payload = json.loads(campaign_manifest_path.read_text(encoding="utf-8"))
        if not isinstance(campaign_payload, dict):
            raise TypeError("campaign manifest must be a JSON object")
        campaign_manifest = campaign_from_dict(campaign_payload)
        _validate_campaign_manifest(campaign_manifest, expected_seeds=expected_seeds)
    except (OSError, ValueError, TypeError, CampaignError) as error:
        raise ValidationError(
            "campaign-manifest-invalid", f"{campaign_manifest_path}: {error}"
        ) from None

    manifest_paths = sorted(campaign_dir.glob("*/manifest.json"))
    reran_originals: set[str] = set()
    for manifest_path in manifest_paths:
        if (manifest_path.parent / "invalid.json").is_file():
            continue
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            continue
        rerun_of = payload.get("rerun_of") if isinstance(payload, dict) else None
        if isinstance(rerun_of, str):
            reran_originals.add(rerun_of)

    for manifest_path in manifest_paths:
        bundle_dir = manifest_path.parent
        if (bundle_dir / "invalid.json").is_file() or bundle_dir.name in reran_originals:
            continue
        defects = verify_bundle_seal(bundle_dir)
        if defects:
            raise ValidationError("bundle-integrity", f"{bundle_dir.name}: " + "; ".join(defects))
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        run_manifest = manifest_from_dict(payload)
        validate_bundle(run_manifest)
        from runner.validity import check_run_validity, measurement_window_samples

        findings = check_run_validity(
            bundle_dir, run_manifest, window_samples=measurement_window_samples()
        )
        if findings:
            detail = "; ".join(f"{finding.code}: {finding.detail}" for finding in findings)
            raise ValidationError("run-invalid", f"{bundle_dir.name}: {detail}")
        manifests.append(run_manifest)

    campaign_ids = {manifest.campaign_id for manifest in manifests}
    if (
        campaign_manifest.campaign_id != campaign_dir.name
        or len(campaign_ids) > 1
        or (campaign_ids and campaign_manifest.campaign_id not in campaign_ids)
    ):
        raise ValidationError(
            "campaign-id-mismatch",
            f"bundle campaign_ids={sorted(campaign_ids)}, frozen campaign_id "
            f"{campaign_manifest.campaign_id!r}, and directory {campaign_dir.name!r} must agree",
        )

    valid = manifests

    # One instrument across the whole corpus (ADR-136, P6; the corpus half of F-RN-02). A frozen
    # campaign runs on exactly one instrument, so every framework-on bundle must record the same
    # instrument digest, and -- when the frozen manifest names a freeze tag -- that digest must be
    # the tag's. A corpus that spans two is the mixed-commit defect V14: a recorded git_commit that
    # touched an instrument path moved the digest. A commit OUTSIDE those paths keeps it, so a
    # docs-only difference between a bundle's git_commit and the tag's commit is not this failure.
    _check_one_instrument(valid, campaign_manifest)

    runs = tuple(
        PlannedRun(
            run_id=m.run_id,
            condition=m.condition,
            scenario_id=m.scenario_id,
            injection_condition=m.injection_condition,
            seed=m.seed,
            is_baseline=m.is_baseline,
            baseline_run_id=m.baseline_run_id,
            load_profile_id=m.load_profile_id,
        )
        for m in valid
    )
    # Exactly one valid attempt per cell key. Two VALID bundles sharing a cell key is a rerun whose
    # original was not marked invalid (its rerun_of does not point back), which §4 forbids in the
    # analysed set -- distinct from the legitimate invalid-original-plus-retry case excluded above.
    keys = Counter(cell_key(run.run_id) for run in runs)
    for key, count in keys.items():
        if count > 1:
            raise ValidationError(
                "duplicate-valid-attempt",
                f"cell key {key} has {count} valid attempts; only one per cell may be valid "
                "(data-management §4 -- an invalid original must be named by its rerun's rerun_of)",
            )
    planned_by_id = {run.run_id: run for run in campaign_manifest.runs}
    actual_by_id = {cell_key(run.run_id): run for run in valid}
    if set(actual_by_id) != set(planned_by_id):
        missing = sorted(set(planned_by_id) - set(actual_by_id))
        unexpected = sorted(set(actual_by_id) - set(planned_by_id))
        raise ValidationError(
            "campaign-bundle-mismatch",
            f"valid bundles do not exactly cover frozen plan: missing={missing}, "
            f"unexpected={unexpected}",
        )
    for run_id, planned in planned_by_id.items():
        actual = actual_by_id[run_id]
        observed = (
            actual.condition,
            actual.scenario_id,
            actual.injection_condition,
            actual.seed,
            actual.is_baseline,
            actual.baseline_run_id,
            actual.load_profile_id,
        )
        expected = (
            planned.condition,
            planned.scenario_id,
            planned.injection_condition,
            planned.seed,
            planned.is_baseline,
            planned.baseline_run_id,
            planned.load_profile_id,
        )
        if observed != expected:
            raise ValidationError(
                "campaign-bundle-mismatch",
                f"{actual.run_id}: bundle coordinates {observed!r} differ from frozen plan "
                f"{expected!r}",
            )
        if actual.versions_env_sha256 != campaign_manifest.versions_env_sha256:
            raise ValidationError(
                "campaign-bundle-mismatch",
                f"{actual.run_id}: bundle versions_env_sha256 differs from frozen campaign",
            )
    return dict(Counter(run.injection_condition for run in runs if not run.is_baseline))


def validate_campaign_corpus(campaign_dir: Path) -> dict[str, int]:
    """Validate sealed bundles against the canonical frozen ``campaign.json``."""
    return _validate_campaign_corpus(Path(campaign_dir), expected_seeds=SEEDS)


def validate_campaign_corpus_for_testing(
    campaign_dir: Path, *, expected_seeds: tuple[int, ...]
) -> dict[str, int]:
    """Validate a reduced corpus fixture; never use for production campaign acceptance."""
    return _validate_campaign_corpus(Path(campaign_dir), expected_seeds=expected_seeds)
