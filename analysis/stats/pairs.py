r"""Matched-pairs ablation contrasts -- the alias resolved once, zero pairs a hard error.

WHAT THIS MODULE IS FOR
    `docs/protocols/evaluation-protocol.md` §3 fixes how every rigorous contrast is formed:
    "computed as matched-pairs differences between the full-architecture configuration and each
    ablated configuration, matched cell for cell on scenario, condition, and seed, so that each
    ablated run is compared against its own matched counterpart rather than against a pooled
    baseline". In this kit's grid vocabulary the matched cell is `(scenario, injection-condition,
    seed)` -- all three keys, "row T-39" -- and the difference is taken between arms. This module
    owns that pairing: :func:`matched_pairs` joins two arms on those three keys,
    :func:`resolve_condition_alias` is the one place the `S1-HIER` alias becomes `G0-FULL`, and
    :func:`contrast` attaches the worst-case and realized minimum detectable differences and the
    GATE-fixed floor marker row T-34 requires beside every rigorous result.

THE ALIAS IS RESOLVED IN ONE FUNCTION, AND ZERO PAIRS IS AN ERROR
    §3 names the trap precisely: the two RQ2 structure contrasts name the shared arm by its
    structure-study alias `S1-HIER`, but the bundles they read carry its canonical token `G0-FULL`
    (glossary §Condition IDs), "so a contrast script that selects `S1-HIER` bundles by identifier
    finds none and silently pairs nothing -- it must resolve the alias first". :func:`matched_pairs`
    resolves both arms through :func:`resolve_condition_alias` before selecting, so a contrast
    written against the alias finds the canonical bundles. And "a contrast returning zero pairs is a
    hard error, not an empty table" (`docs/plans/M6-implementation-plan.md`):
    :class:`EmptyContrastError` is raised rather than an empty frame returned, because an empty
    table reads as "no difference" when the truth is "the pairing never happened".

THE MDD IS REPORTED TWICE, AND THE FLOOR IS GATE-FIXED (row T-34)
    §7 requires every rigorous-area result to carry a minimum detectable difference and the
    inconclusiveness floor beside its point estimate and Wilson interval. Both are now GATE-fixed
    (evaluation-protocol.md §4's `gate-constants` block; ADR-080; supervisor rulings 2026-09-13,
    item 3), so neither is pending, but the ruling's second condition requires *two* MDD figures
    rather than one: :func:`minimum_detectable_difference` is the pre-registered worst-case bound
    (alpha, power and the paired-difference SD all fixed at GATE, the SD a conservative assumption
    rather than a measurement), and :func:`realized_minimum_detectable_difference` is the same
    alpha and power applied to the *observed* sample SD of that contrast's own matched-pair
    differences. "A contrast clearing the conservative bar is strongly supported; one clearing
    only the realized bar is reported with that caveat" -- :func:`mdd_support_label` renders that
    classification so a reader is not left to compare three numbers by eye. :func:`contrast`
    attaches all of these plus the GATE-fixed floor marker to every rigorous result.

WHAT BREAKS IF THIS FILE CHANGES
    Pairing on fewer than the three keys, or resolving the alias in more than one place, is exactly
    the defect §3 spends a paragraph on -- "A script that pools instead of pairing, or that pairs on
    fewer than all three keys, is wrong regardless of what it reports." Returning an empty table for
    a zero-pair contrast reintroduces the silent-pairing failure. Letting a caller pass a local
    alpha, power or SD would defeat the pre-registration row T-34 exists to make -- both MDD
    functions read their inputs only from `analysis.stats.gate`, never from a keyword argument.
    ADR-043 (analysis as a tested component); ADR-080 (the GATE constants); after `v1.0` any change
    here is a logged hotfix ADR (AGENTS.md iron rule 6).
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass
from statistics import NormalDist
from typing import Final

import pandas as pd

from analysis.stats.gate import (
    FLOOR_MARKER,
    MDD_ALPHA_TWO_SIDED,
    MDD_TARGET_POWER,
    MDD_WORST_CASE_PAIRED_DIFF_SD,
)
from analysis.stats.loader import MATCH_COLUMNS

__all__ = [
    "BY_CELL",
    "CONDITION_ALIASES",
    "RQ2_CONTRASTS",
    "RQ5_CONTRASTS",
    "Contrast",
    "EmptyContrastError",
    "contrast",
    "grouped_contrast",
    "matched_pairs",
    "mdd_support_label",
    "minimum_detectable_difference",
    "realized_minimum_detectable_difference",
    "resolve_condition_alias",
]

# The D13 primary grain: one contrast row per scenario × injection condition × phase (ADR-133;
# evaluation-protocol.md §3). Named here so the render and the default reads it rather than
# restating
# the three-column list, and so a change to the grain is one edit. `phase` is a measure's own
# sub-axis, present on the per-phase measures grouped_contrast is called with, not a fourth
# matched-pairs key (pairing stays on scenario, injection condition and seed; see
# :func:`matched_pairs`).
BY_CELL: Final = ("scenario_id", "injection_condition", "phase")

# The two-sided-alpha and target-power quantiles the GATE-fixed MDD formula uses, computed once
# from `MDD_ALPHA_TWO_SIDED` and `MDD_TARGET_POWER` (`analysis.stats.gate`'s mirror of
# evaluation-protocol.md §4) rather than hardcoded, to full double precision via the standard
# library's `statistics.NormalDist` -- no third-party dependency beyond what
# `analysis/stats/proportions.py` already declares for the Wilson interval.
_Z_ALPHA_TWO_SIDED: Final = NormalDist().inv_cdf(1 - MDD_ALPHA_TWO_SIDED / 2)
_Z_POWER: Final = NormalDist().inv_cdf(MDD_TARGET_POWER)

# The one alias the grid carries: S1-HIER is the structure study's name for the shared
# full-architecture arm, whose bundles carry the canonical token G0-FULL (glossary §Condition IDs;
# ADR-008). Every contrast resolves through here before selecting bundles, so a contrast named
# against the alias finds the canonical runs instead of silently pairing nothing.
CONDITION_ALIASES: Final = {"S1-HIER": "G0-FULL"}

# The RQ2 structure contrasts and the RQ5 guardrail contrasts, full-architecture arm first so the
# matched-pairs difference is "full-architecture minus ablated" (§3.5.7). The RQ2 arms are named by
# the S1-HIER alias exactly as §3 names them; resolve_condition_alias turns it into G0-FULL.
RQ2_CONTRASTS: Final = (("S1-HIER", "S2-FLAT"), ("S1-HIER", "S3-SINGLE"))
RQ5_CONTRASTS: Final = (
    ("G0-FULL", "G1-LOGONLY"),
    ("G0-FULL", "G2-SHAREDCRED"),
    ("G0-FULL", "G3-UNQUOTED"),
)


class EmptyContrastError(Exception):
    """Raised when a contrast forms no matched pairs.

    A zero-pair contrast is never an empty table: an empty table reads downstream as "no
    difference", while the truth is that the pairing never happened -- most often because an arm's
    bundles are absent, or because the `S1-HIER` alias was not resolved to `G0-FULL` before
    selecting. Raising is what turns that silent nothing into a stop
    (`docs/plans/M6-implementation-plan.md`; §3).
    """


def resolve_condition_alias(condition: str) -> str:
    """Return the canonical arm token for ``condition``, mapping `S1-HIER` to `G0-FULL`.

    The single home of the alias resolution §3 requires "in one function used by every contrast".
    Any token that is already canonical is returned unchanged, so this is safe to call on every arm
    of every contrast without a caller having to know which ones are aliased.
    """
    return CONDITION_ALIASES.get(condition, condition)


def _pairing_keys(frame: pd.DataFrame) -> list[str]:
    """The join keys: the three matched-pairs coordinates, plus a measure's own sub-axis if present.

    §3's matched cell is `(scenario, injection-condition, seed)` -- all three, always. A per-phase
    or per-class measure additionally carries a `phase` or `injection_class` column, and a pair must
    align on it too, so that a phase is compared against the same phase rather than cross-joined
    against the other three. That sub-axis is not a fourth pairing coordinate; it selects which
    measure value at the shared cell is being differenced.
    """
    keys = list(MATCH_COLUMNS)
    for axis in ("phase", "injection_class"):
        if axis in frame.columns:
            keys.append(axis)
    return keys


def matched_pairs(
    per_seed: pd.DataFrame,
    arm_a: str,
    arm_b: str,
    *,
    value_column: str,
) -> pd.DataFrame:
    """Form matched pairs of ``arm_a`` against ``arm_b`` over a measure's per-seed result.

    ``per_seed`` is the long-form output of a measure in :mod:`analysis.stats.measures` -- one row
    per run, carrying ``condition`` and the three matched-pairs coordinates. Both arms are resolved
    through :func:`resolve_condition_alias` (so `S1-HIER` selects the `G0-FULL` bundles), their rows
    are joined on the pairing keys, and one row per matched cell is returned with ``value_a``,
    ``value_b`` and their signed ``difference`` (``arm_a`` minus ``arm_b``, full-architecture minus
    ablated). Zero pairs raises :class:`EmptyContrastError`; it is never an empty table.
    """
    canonical_a = resolve_condition_alias(arm_a)
    canonical_b = resolve_condition_alias(arm_b)
    if canonical_a == canonical_b:
        raise ValueError(
            f"a contrast needs two distinct arms; {arm_a!r} and {arm_b!r} both resolve to "
            f"{canonical_a!r}"
        )
    for column in ("condition", value_column):
        if column not in per_seed.columns:
            raise ValueError(f"per_seed frame has no {column!r} column")

    keys = _pairing_keys(per_seed)
    left = per_seed[per_seed["condition"] == canonical_a][[*keys, value_column]]
    right = per_seed[per_seed["condition"] == canonical_b][[*keys, value_column]]
    merged = left.merge(right, on=keys, suffixes=("_a", "_b"), how="inner")
    if merged.empty:
        raise EmptyContrastError(
            f"contrast {arm_a} (->{canonical_a}) vs {arm_b} (->{canonical_b}) formed no matched "
            f"pairs on {keys}: an arm's bundles are absent, or the alias was not resolved. A "
            "zero-pair contrast is a hard error, not an empty table (evaluation-protocol.md §3)."
        )
    merged = merged.rename(columns={f"{value_column}_a": "value_a", f"{value_column}_b": "value_b"})
    merged["difference"] = merged["value_a"] - merged["value_b"]
    return merged.sort_values(keys, kind="stable").reset_index(drop=True)


def minimum_detectable_difference(n_pairs: int) -> float:
    """The pre-registered worst-case MDD: GATE-fixed two-sided alpha, target power and
    paired-difference SD bound, none of them read from a caller-supplied argument.

    All three inputs come from `analysis.stats.gate` (`MDD_ALPHA_TWO_SIDED`, `MDD_TARGET_POWER`,
    `MDD_WORST_CASE_PAIRED_DIFF_SD` -- evaluation-protocol.md §4; ADR-080), never from a
    caller-supplied ``power`` or ``sd`` -- see the module docstring's "WHAT BREAKS IF THIS FILE
    CHANGES". This is the conservative bound: it assumes the worst-case paired-difference standard
    deviation the protocol fixes rather than the SD this contrast's own pairs actually show, which
    is what :func:`realized_minimum_detectable_difference` reports beside it (supervisor rulings
    2026-09-13, item 3, condition 2).
    """
    if n_pairs < 1:
        raise ValueError(f"n_pairs must be positive, got {n_pairs}")
    return (_Z_ALPHA_TWO_SIDED + _Z_POWER) * MDD_WORST_CASE_PAIRED_DIFF_SD / math.sqrt(n_pairs)


def realized_minimum_detectable_difference(differences: Iterable[float]) -> float:
    """MDD at the same GATE-fixed alpha and power, using the *observed* sample SD of
    ``differences``.

    ``differences`` is one contrast's own matched-pair ``difference`` column -- the same population
    :func:`contrast` already averages for ``mean_difference`` -- so the realized MDD describes
    exactly the sample the point estimate does, not a different pooling of it. The formula is
    :func:`minimum_detectable_difference`'s, with the GATE-fixed worst-case SD bound replaced by
    ``differences``'s own sample standard deviation (``ddof=1``): ``(z_alpha/2 + z_power) *
    sd_observed / sqrt(n)``.

    Returns ``nan`` when fewer than two differences are given: a standard deviation needs at least
    two points to be estimated, and inventing one would misstate what this specific realised sample
    could detect (`.agents/rules/00`: never fabricate a value). Raises on zero differences, where
    the divide-by-``sqrt(n)`` is undefined rather than merely unestimated. Alpha and power are never
    caller-suppliable here either, for the same reason :func:`minimum_detectable_difference` refuses
    them.
    """
    values = pd.Series(list(differences), dtype=float)
    n = len(values)
    if n == 0:
        raise ValueError("realized_minimum_detectable_difference needs at least one difference")
    sd = float(values.std(ddof=1))  # NaN for n == 1: pandas' own "undefined, not invented" answer
    return (_Z_ALPHA_TWO_SIDED + _Z_POWER) * sd / math.sqrt(n)


def mdd_support_label(mean_difference: float, mdd_worst_case: float, mdd_realized: float) -> str:
    """Classify one contrast's observed difference against both MDD figures (ADR-080, condition 2).

    Supervisor rulings 2026-09-13, item 3: "A contrast clearing the conservative bar is strongly
    supported; one clearing only the realized bar is reported with that caveat." This renders that
    classification as a label so `analysis.render` and a reader are not left to compare three
    numbers by eye. ``mdd_realized`` may be ``nan`` (fewer than two matched pairs); that case is
    named explicitly rather than falling through to "below both".
    """
    observed = abs(mean_difference)
    if observed >= mdd_worst_case:
        return "clears worst-case MDD: strongly supported"
    if math.isnan(mdd_realized):
        return "below worst-case MDD; realized MDD undefined (fewer than two matched pairs)"
    if observed >= mdd_realized:
        return "clears realized MDD only: reported with caveat, not the conservative bound"
    return "below both MDD figures: no effect detectable at this design's power"


@dataclass(frozen=True, slots=True)
class Contrast:
    """A rigorous ablation contrast: matched pairs, mean difference, both MDD figures and the floor.

    ``mdd_worst_case`` is the pre-registered conservative bound
    (:func:`minimum_detectable_difference`); ``mdd_realized`` is the same alpha/power against this
    contrast's own observed paired-difference SD (:func:`realized_minimum_detectable_difference`),
    ``nan`` below two pairs. ``support`` is :func:`mdd_support_label`'s classification of
    ``mean_difference`` against both. ``floor`` is the
    GATE-fixed inconclusiveness floor marker (:data:`~analysis.stats.gate.FLOOR_MARKER`).
    """

    arm_a: str
    arm_b: str
    canonical_a: str
    canonical_b: str
    pairs: pd.DataFrame
    n_pairs: int
    mean_difference: float
    mdd_worst_case: float
    mdd_realized: float
    floor: str
    support: str


def contrast(
    per_seed: pd.DataFrame,
    arm_a: str,
    arm_b: str,
    *,
    value_column: str,
) -> Contrast:
    """Build a :class:`Contrast`: the matched pairs, their mean difference, both MDD figures, the
    floor and the support label.

    A thin composition over :func:`matched_pairs`, :func:`minimum_detectable_difference` and
    :func:`realized_minimum_detectable_difference`. Raises :class:`EmptyContrastError` on zero
    pairs; never emits a plausible invented figure for any other input, since every number besides
    the pairs themselves is either GATE-fixed or computed from those same pairs.
    """
    pairs = matched_pairs(per_seed, arm_a, arm_b, value_column=value_column)
    n_pairs = int(len(pairs))
    mean_difference = float(pairs["difference"].mean())
    mdd_worst_case = minimum_detectable_difference(n_pairs)
    mdd_realized = realized_minimum_detectable_difference(pairs["difference"])
    return Contrast(
        arm_a=arm_a,
        arm_b=arm_b,
        canonical_a=resolve_condition_alias(arm_a),
        canonical_b=resolve_condition_alias(arm_b),
        pairs=pairs,
        n_pairs=n_pairs,
        mean_difference=mean_difference,
        mdd_worst_case=mdd_worst_case,
        mdd_realized=mdd_realized,
        floor=FLOOR_MARKER,
        support=mdd_support_label(mean_difference, mdd_worst_case, mdd_realized),
    )


def grouped_contrast(
    per_seed: pd.DataFrame,
    arm_a: str,
    arm_b: str,
    *,
    value_column: str,
    by: list[str] | tuple[str, ...] = BY_CELL,
) -> pd.DataFrame:
    """One contrast row per cell of ``by`` -- the D13 primary grain (ADR-133; §3, row 460-466).

    Where :func:`contrast` collapses a measure to a single rollup difference, this is the primary
    reporting shape D13 fixes: "scenario × injection condition × phase is primary (n = seeds per
    cell, descriptive, with the MDD floor)". It groups ``per_seed`` by ``by`` (default
    :data:`BY_CELL`)
    and, within each cell, forms the matched pairs of ``arm_a`` against ``arm_b`` and computes that
    cell's own ``n_pairs``, mean difference, both MDD figures and support label -- so each cell
    carries
    its own n and its own realized MDD (``nan`` at n = 1 by design, exactly as
    :func:`realized_minimum_detectable_difference` returns for a single pair). Pairing stays on
    ``(scenario_id, injection_condition, seed)`` inside every cell (:func:`matched_pairs`), never on
    ``by``: ``by`` selects which per-seed values are differenced, and ``phase`` in the default is a
    measure's own sub-axis, not a fourth matched-pairs key.

    Written as a plain ``for keys, group in per_seed.groupby(by, sort=True)`` loop rather than a
    ``.apply()``: pandas 3.0 removed the ``include_groups`` opt-out of ``.apply()``, and a groupby
    loop is the ``proportions.pool_counts`` idiom already used in this package. ``sort=True`` keeps
    the
    output a deterministic function of the cell keys (rule 20).

    A cell in which the two arms form no matched pair -- one arm was not run for that
    (scenario, injection, phase) -- contributes no row rather than a fabricated zero, the same
    absence
    rule the pooling functions use. But a contrast that forms **no** pair in **any** cell is the
    silent-pairing failure :class:`EmptyContrastError` exists to catch (most often the `S1-HIER`
    alias
    left unresolved, or an arm wholly absent), so an all-empty result raises rather than returning
    an
    empty table that reads downstream as "no difference".
    """
    canonical_a = resolve_condition_alias(arm_a)
    canonical_b = resolve_condition_alias(arm_b)
    if canonical_a == canonical_b:
        raise ValueError(
            f"a contrast needs two distinct arms; {arm_a!r} and {arm_b!r} both resolve to "
            f"{canonical_a!r}"
        )
    for column in ("condition", value_column):
        if column not in per_seed.columns:
            raise ValueError(f"per_seed frame has no {column!r} column")
    by = list(by)
    missing_by = [key for key in by if key not in per_seed.columns]
    if missing_by:
        raise ValueError(f"'by' names column(s) absent from the frame: {missing_by}")

    columns = [
        *by,
        "arm_a",
        "arm_b",
        "canonical_a",
        "canonical_b",
        "n_pairs",
        "mean_difference",
        "mdd_worst_case",
        "mdd_realized",
        "floor",
        "support",
    ]
    rows: list[dict[str, object]] = []
    for keys, group in per_seed.groupby(by, sort=True):
        key_values = keys if isinstance(keys, tuple) else (keys,)
        try:
            result = contrast(group, arm_a, arm_b, value_column=value_column)
        except EmptyContrastError:
            # This one cell has no matched pair between the two arms (an arm not run for it); skip
            # it.
            # An all-empty result is caught below, so the silent-nothing failure still raises.
            continue
        row: dict[str, object] = dict(zip(by, key_values, strict=True))
        row.update(
            arm_a=result.arm_a,
            arm_b=result.arm_b,
            canonical_a=result.canonical_a,
            canonical_b=result.canonical_b,
            n_pairs=result.n_pairs,
            mean_difference=result.mean_difference,
            mdd_worst_case=result.mdd_worst_case,
            mdd_realized=result.mdd_realized,
            floor=result.floor,
            support=result.support,
        )
        rows.append(row)
    if not rows:
        raise EmptyContrastError(
            f"grouped_contrast {arm_a} (->{canonical_a}) vs {arm_b} (->{canonical_b}) formed no "
            f"matched pairs in any cell of {by}: an arm's bundles are absent, or the alias was not "
            "resolved. A zero-pair contrast is a hard error, not an empty table "
            "(evaluation-protocol.md §3)."
        )
    return pd.DataFrame(rows, columns=columns)
