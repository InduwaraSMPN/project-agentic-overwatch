r"""The Wilson score interval, and the per-cell pooling that never becomes a grand mean.

WHAT THIS MODULE IS FOR
    `docs/protocols/evaluation-protocol.md` §3 fixes the uncertainty treatment for every
    proportion-type measure: "Binary-outcome uncertainty: Wilson intervals,
    `statsmodels.stats.proportion.proportion_confint(k, n, alpha=0.05, method='wilson')`, computed
    per condition." The pooling rule is bound from §3.5.7 -- each scenario-condition cell is run
    across five seeds and "the interval is computed with the Wilson score interval for the
    proportion-type measures rather than the normal approximation, which is unreliable at five
    seeds", reported "alongside the point estimate for every outcome measure", with "per-seed
    results always reported alongside pooled" and "results reported per scenario and per condition
    rather than collapsed into a grand mean".

    This module owns exactly two things: :func:`wilson_interval`, the one wrapper every measure
    calls, and :func:`pool_binary`, the one grouping that turns per-seed binary values into a pooled
    Wilson interval per cell -- and refuses to pool in a way that would collapse the per-scenario,
    per-condition reporting §3 requires.

THE VARIANT IS `'wilson'`, THE UNCORRECTED SCORE INTERVAL
    `evaluation-protocol.md` §3's Wilson-variant note (flagged for supervisor, binding-log §T0.6)
    settles the one thing the dissertation's wording leaves open. The chapters say "95% Wilson score
    confidence intervals (Pearson's variant)"; `statsmodels`' `proportion_confint` offers `normal`,
    `agresti_coull`, `beta`, `wilson`, `jeffreys` and `binom_test`, and no `'pearson'`. The Wilson
    score interval is the inversion of the Pearson score test, and "Pearson's variant" reads as the
    uncorrected score interval, so `method='wilson'` is the one used. `statsmodels` carries no
    continuity-corrected Wilson method to choose instead, so there is no rejected alternative to
    name.
    The token is a named constant here so there is one place the choice is made, and
    `analysis/tests/test_proportions.py` pins it to a real `proportion_confint` method.

WHAT BREAKS IF THIS FILE CHANGES
    Switching to the normal approximation, or to any other `proportion_confint` method, changes
    every
    reported interval in Chapter 4 -- §3.5.7 chose Wilson precisely because the normal approximation
    is unreliable at five seeds. Letting :func:`pool_binary` group without `scenario_id` and
    `condition` in the keys
    would produce the grand mean §3 forbids. ADR-043 (analysis as a tested component); after the
    `v1.0` freeze either change is a logged hotfix ADR (AGENTS.md iron rule 6).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

import pandas as pd
from statsmodels.stats.proportion import proportion_confint

__all__ = [
    "ALPHA",
    "POOLED_COLUMNS",
    "WILSON_METHOD",
    "Proportion",
    "pool_binary",
    "pool_counts",
    "wilson_interval",
]

# 95% intervals: alpha = 0.05. Dissertation-fixed, not kit-chosen -- bound from Table 3.4's note
# ("All rates report 95% Wilson score confidence intervals") and homed in evaluation-protocol.md §0.
ALPHA: Final = 0.05

# The statsmodels method: 'wilson', the uncorrected score interval (Pearson's variant). See the
# module docstring's variant note. This constant is the single home of the choice, so a change is
# one
# edit a reviewer can find, and analysis/tests/test_proportions.py pins it to a real
# proportion_confint method.
WILSON_METHOD: Final = "wilson"

# The columns a pooled result is keyed by, and the guard against a grand mean. Both scenario_id and
# condition MUST appear in any pooling, because §3 reports "per scenario and per condition rather
# than collapsed into a grand mean"; pool_binary refuses a grouping that omits either.
POOLED_COLUMNS: Final = ("scenario_id", "condition")


@dataclass(frozen=True, slots=True)
class Proportion:
    """A proportion point estimate with its 95% Wilson score interval and the counts behind it.

    ``k`` successes out of ``n`` trials. The counts are carried, not just the rate, for two reasons:
    §3 requires the raw attempt counts reported alongside the RQ5 rates, and a reader cannot tell a
    1/1 from a 100/100 -- both are a point estimate of 1.0 -- without them. ``point`` is ``k / n``;
    ``ci_low`` and ``ci_high`` are the Wilson bounds. Frozen because a reported proportion is a fact
    about a run set, not a value a downstream cell should be able to edit.
    """

    k: int
    n: int
    point: float
    ci_low: float
    ci_high: float
    method: str = WILSON_METHOD


def wilson_interval(k: int, n: int) -> Proportion:
    """Return the 95% Wilson score interval for ``k`` successes in ``n`` trials.

    The one wrapper around ``proportion_confint(k, n, alpha=0.05, method='wilson')`` -- see the
    module docstring for why the variant is ``'wilson'`` (the uncorrected score interval). ``n ==
    0``
    is a
    named error rather than a division by zero, because a cell with no runs is a gap in the campaign
    and reporting an interval for it would invent evidence; the caller decides what an empty cell
    means (a rerun is owed, or the cell was intentionally reduced under §7) rather than being handed
    a NaN that propagates silently.
    """
    if n < 0 or k < 0:
        raise ValueError(f"k and n must be non-negative, got k={k}, n={n}")
    if k > n:
        raise ValueError(f"k must not exceed n, got k={k}, n={n}")
    if n == 0:
        raise ValueError(
            "wilson_interval is undefined for n=0; an empty scenario-condition cell is a gap in "
            "the campaign, not a proportion of zero"
        )
    ci_low, ci_high = proportion_confint(k, n, alpha=ALPHA, method=WILSON_METHOD)
    return Proportion(k=int(k), n=int(n), point=k / n, ci_low=float(ci_low), ci_high=float(ci_high))


def pool_binary(
    frame: pd.DataFrame,
    *,
    value_column: str,
    by: list[str],
) -> pd.DataFrame:
    """Pool a per-seed binary measure into one Wilson interval per cell, keyed by ``by``.

    ``frame`` is a long-form per-seed table -- one row per run (per phase or per class, where the
    measure has that axis) -- with a 0/1 ``value_column``. Grouping by ``by`` sums the successes and
    counts the trials in each cell and computes the Wilson interval for each, returning one row per
    cell with ``k``, ``n``, ``point``, ``ci_low`` and ``ci_high``. The seeds are the trials, which
    is the pooling §3.5.7 fixes: "each scenario-condition cell is run across five seeds".

    ``by`` MUST contain both ``scenario_id`` and ``condition``. That is the structural guard against
    §3's one prohibition -- "never collapsed into a grand mean": a pooling that dropped either key
    would average across scenarios or across arms, which is exactly the grand mean the dissertation
    refuses. Omitting either raises rather than silently returning a coarser table, so the property
    is enforced by the type of the call rather than trusted to the caller. Per-seed results are the
    input ``frame`` itself and are reported alongside this pooled output, never in place of it.
    """
    missing_keys = [key for key in POOLED_COLUMNS if key not in by]
    if missing_keys:
        raise ValueError(
            f"pool_binary must group by {list(POOLED_COLUMNS)} at least, to keep results per "
            f"scenario and per condition (evaluation-protocol.md §3); 'by' omits {missing_keys}. "
            "Pooling without these keys is the grand mean §3 forbids."
        )
    if value_column not in frame.columns:
        raise ValueError(f"value_column {value_column!r} is not a column of the frame")
    missing_by = [key for key in by if key not in frame.columns]
    if missing_by:
        raise ValueError(f"'by' names column(s) absent from the frame: {missing_by}")

    values = frame[value_column]
    if not values.isin((0, 1, True, False)).all():
        raise ValueError(
            f"pool_binary expects a 0/1 measure in {value_column!r}; found non-binary values. "
            "Continuous measures (latency, overhead) are summarised by medians and IQR, not Wilson "
            "intervals (evaluation-protocol.md §3)."
        )

    counts = frame.assign(_k=frame[value_column].astype(int), _n=1)
    return pool_counts(counts, k_column="_k", n_column="_n", by=by)


def pool_counts(
    frame: pd.DataFrame,
    *,
    k_column: str,
    n_column: str,
    by: list[str],
) -> pd.DataFrame:
    """Pool a per-row (k successes, n trials) measure into one Wilson interval per cell.

    Where :func:`pool_binary` treats each row as one Bernoulli trial and the seeds as the trials,
    this pools a measure whose row already carries its own counts -- the RQ5 rates, which §3
    normalises "per action attempted" (``k`` permits or blocks out of ``n`` attempted actions in a
    run), and the full-lifecycle proportion (``k`` phases correct out of ``n`` = 4). Summing ``k``
    and ``n`` across a cell's seeds and inverting Wilson on the totals is what "normalised per
    action attempted" with a per-cell interval means: the trials are the actions (or the phase
    slots), not the seeds, and the raw totals travel with the interval so §3's "raw attempt counts
    reported alongside" is satisfied by the same row.

    The same ``scenario_id``/``condition`` guard as :func:`pool_binary` applies, for the same
    reason.
    """
    missing_keys = [key for key in POOLED_COLUMNS if key not in by]
    if missing_keys:
        raise ValueError(
            f"pool_counts must group by {list(POOLED_COLUMNS)} at least, to keep results per "
            f"scenario and per condition (evaluation-protocol.md §3); 'by' omits {missing_keys}."
        )
    for column in (k_column, n_column):
        if column not in frame.columns:
            raise ValueError(f"count column {column!r} is not a column of the frame")
    missing_by = [key for key in by if key not in frame.columns]
    if missing_by:
        raise ValueError(f"'by' names column(s) absent from the frame: {missing_by}")

    rows: list[dict[str, object]] = []
    # sort=True keeps the output order a deterministic function of the cell keys, so two runs of the
    # analysis over one corpus produce byte-identical tables (rule 20).
    for keys, group in frame.groupby(by, sort=True):
        key_values = keys if isinstance(keys, tuple) else (keys,)
        k = int(group[k_column].astype(int).sum())
        n = int(group[n_column].astype(int).sum())
        if n == 0:
            # An empty pooled cell (every row in the cell attempted zero of this kind) is
            # legitimate data, not a gap wilson_interval should refuse -- unlike its single caller
            # contract, pool_counts is expected to see this across a full grid, so it reports the
            # cell as an undefined point/interval rather than raising the whole pipeline down.
            interval = Proportion(
                k=0,
                n=0,
                point=float("nan"),
                ci_low=float("nan"),
                ci_high=float("nan"),
                method=WILSON_METHOD,
            )
        else:
            interval = wilson_interval(k, n)
        row: dict[str, object] = dict(zip(by, key_values, strict=True))
        row.update(
            k=interval.k,
            n=interval.n,
            point=interval.point,
            ci_low=interval.ci_low,
            ci_high=interval.ci_high,
            method=interval.method,
        )
        rows.append(row)
    return pd.DataFrame(rows, columns=[*by, "k", "n", "point", "ci_low", "ci_high", "method"])
