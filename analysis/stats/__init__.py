r"""Metric functions for `evaluation-protocol.md` §3, computed from raw run bundles only.

WHAT THIS PACKAGE IS
    The `analysis/stats/` half of `docs/04-repo-conventions.md` §1: the tested Python that turns
    sealed `runs/<CAMPAIGN>/<RUN_ID>/` bundles into the eight Table 3.4 measures and the four
    `origin: engineering` instruments `docs/protocols/evaluation-protocol.md` §3 defines, with the
    Wilson intervals, matched-pairs contrasts and fail-closed GATE handling that section and §7
    require. It reads only raw bundle files -- never `metrics.json`, never a live service
    (`data-management.md` §8; `.agents/rules/20`) -- and the notebooks under `analysis/notebooks/`
    render its output rather than recomputing it.

    The modules split by concern: :mod:`~analysis.stats.loader` reads bundles and refuses
    `metrics.json`; :mod:`~analysis.stats.proportions` owns the Wilson interval and per-cell
    pooling; :mod:`~analysis.stats.measures` computes the twelve measures;
    :mod:`~analysis.stats.pairs` forms matched-pairs contrasts with the alias resolved once;
    :mod:`~analysis.stats.gate` mirrors the six GATE-fixed constants (evaluation-protocol.md §4;
    ADR-080) and carries the fail-closed sentinels for the values that remain genuinely pending --
    an unscored bundle, an uncalibrated M1 instrument, an undecided conflict; and
    :mod:`~analysis.stats.vacuity` is the campaign vacuity tripwire (ADR-096), a WARNING rather than
    a measure, flagging any scored predicate that passed in 100% of a campaign's real runs. This
    module re-exports the public surface so a notebook or a test writes `from analysis.stats import
    wilson_interval, matched_pairs`.

    ADR-043 (analysis as a tested component).
"""

from __future__ import annotations

from analysis.stats.gate import (
    FLOOR_MARKER,
    PendingGateValue,
    PendingInstrumentValue,
    PendingSupervisorDecision,
    inconclusiveness_floor,
    is_inconclusive,
    resolve_stabilization_window,
)
from analysis.stats.loader import (
    IDENTITY_COLUMNS,
    INJ_NONE,
    INJECTION_CLASSES,
    MATCH_COLUMNS,
    PHASES,
    POOL_COLUMNS,
    Bundle,
    BundleError,
    MetricsJsonRefused,
    iter_spans,
    load_bundle,
    load_campaign,
    refuse_metrics_json,
    sealed_bundle_directories,
)
from analysis.stats.measures import (
    ClaimFidelityResult,
    DetectionResult,
    OverheadResult,
    ResourceDelta,
    TestRetestAgreement,
    compute_test_retest_agreement,
    containment_eradication_success,
    coordination_cost,
    detection_precision_recall,
    detection_precision_recall_by_scenario,
    executed_actions,
    framework_restarts,
    full_lifecycle_proportion,
    g2_direct_path,
    guardrail_effectiveness_by_class,
    injection_none_base_rate,
    injection_success_rate,
    interference,
    per_phase_completeness,
    per_phase_outcome_correctness,
    policy_compliant_action_rate,
    refuse_researcher_judged,
    researcher_judged_measures,
    resource_overhead,
    response_latency,
    time_to_slo_recovery,
    verified_recovery_claim_fidelity,
)
from analysis.stats.pairs import (
    BY_CELL,
    RQ2_CONTRASTS,
    RQ5_CONTRASTS,
    Contrast,
    EmptyContrastError,
    contrast,
    grouped_contrast,
    matched_pairs,
    mdd_support_label,
    minimum_detectable_difference,
    realized_minimum_detectable_difference,
    resolve_condition_alias,
)
from analysis.stats.proportions import (
    Proportion,
    pool_binary,
    pool_counts,
    wilson_interval,
)
from analysis.stats.vacuity import (
    ASSERTION_KIND,
    REQUIRED_SUBSTEP_KIND,
    VacuousPredicate,
    predicate_outcomes,
    vacuous_predicates,
)

__all__ = [
    "ASSERTION_KIND",
    "BY_CELL",
    "FLOOR_MARKER",
    "IDENTITY_COLUMNS",
    "INJECTION_CLASSES",
    "INJ_NONE",
    "MATCH_COLUMNS",
    "PHASES",
    "POOL_COLUMNS",
    "REQUIRED_SUBSTEP_KIND",
    "RQ2_CONTRASTS",
    "RQ5_CONTRASTS",
    "Bundle",
    "BundleError",
    "ClaimFidelityResult",
    "Contrast",
    "DetectionResult",
    "EmptyContrastError",
    "MetricsJsonRefused",
    "OverheadResult",
    "PendingGateValue",
    "PendingInstrumentValue",
    "PendingSupervisorDecision",
    "Proportion",
    "ResourceDelta",
    "TestRetestAgreement",
    "VacuousPredicate",
    "compute_test_retest_agreement",
    "containment_eradication_success",
    "contrast",
    "coordination_cost",
    "detection_precision_recall",
    "detection_precision_recall_by_scenario",
    "executed_actions",
    "framework_restarts",
    "full_lifecycle_proportion",
    "g2_direct_path",
    "grouped_contrast",
    "guardrail_effectiveness_by_class",
    "inconclusiveness_floor",
    "injection_none_base_rate",
    "injection_success_rate",
    "interference",
    "is_inconclusive",
    "iter_spans",
    "load_bundle",
    "load_campaign",
    "matched_pairs",
    "mdd_support_label",
    "minimum_detectable_difference",
    "per_phase_completeness",
    "per_phase_outcome_correctness",
    "policy_compliant_action_rate",
    "pool_binary",
    "pool_counts",
    "predicate_outcomes",
    "realized_minimum_detectable_difference",
    "refuse_metrics_json",
    "refuse_researcher_judged",
    "researcher_judged_measures",
    "resolve_condition_alias",
    "resolve_stabilization_window",
    "response_latency",
    "resource_overhead",
    "sealed_bundle_directories",
    "time_to_slo_recovery",
    "vacuous_predicates",
    "verified_recovery_claim_fidelity",
    "wilson_interval",
]
