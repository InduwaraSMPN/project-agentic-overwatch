"""Whether a Guardian decision's execution succeeded, whichever audit schema recorded it.

WHY THIS EXISTS
---------------
Audit schema v3 records ``enforcement: executed`` when the Guardian *attempted* an action, and
nothing about whether the attempt worked. On 2026-09-12 a ``create networkpolicies`` the API server
refused was recorded ``executed``, and every ``guardian-executed-*`` predicate and both RQ5 measures
would have counted it as performed. The supervisor's ruling of 2026-09-13 (§3.2) is that the chain
carries the execution status and that predicates count only ``succeeded``.

This module is the single reading of that ruling, so the evaluator, the analysis measures and the
re-scoring of sealed bundles cannot each decide it differently:

* A record carrying ``execution_status`` (schema v4 onward) is read directly.
* A record without it (schema v3) is resolved through the bundle's ``results.json``: every decided
  action there carries the ``audit_seq`` of its chain record and the ``ActionResult`` execution
  status, which is the join ADR-077 already requires at seal. That is what lets bundles sealed
  before v4 be re-scored post-seal without re-running them.
* A v3 record that was executed but has no joinable result is ``unknown``, and ``unknown`` is never
  ``succeeded``. An outcome the evidence cannot establish is not counted as performed.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
Every predicate that asks whether the response did something, and every RQ5 rate.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, Final

from guardian.audit.record_types import EXECUTION_RECORD_TYPE, is_run_start

__all__ = (
    "DECISION_SEQ_FIELD",
    "EXECUTION_RECORD_TYPE",
    "EXECUTION_STATUS_FIELD",
    "FAILED",
    "NOT_ATTEMPTED",
    "SUCCEEDED",
    "UNKNOWN",
    "bundle_status_by_seq",
    "execution_status",
    "results_status_by_seq",
    "succeeded",
    "succeeded_records",
)

EXECUTION_STATUS_FIELD: Final = "execution_status"
# The chain may carry the outcome in either of two shapes, and this module reads both, so scoring
# need not wait on which one the Guardian settles: the field above on the decision record itself,
# or a follow-up record of this type naming the decision's ``seq`` in ``decision_seq``. The second
# keeps the decision write-ahead of the execution it authorises, and it is what ADR-082 chose: see
# ``guardian/app/mediation.py`` for why the direct-field shape cannot carry a true post-execution
# outcome without breaking write-ahead. ``EXECUTION_RECORD_TYPE`` is imported rather than restated
# here -- record_types.py is its one home, exactly as it already is for ``is_run_start``.
DECISION_SEQ_FIELD: Final = "decision_seq"
SUCCEEDED: Final = "succeeded"
FAILED: Final = "failed"
NOT_ATTEMPTED: Final = "not-attempted"
UNKNOWN: Final = "unknown"

_RECORDED: Final = frozenset({SUCCEEDED, FAILED, NOT_ATTEMPTED})


def results_status_by_seq(results: object) -> dict[int, str]:
    """Map ``audit_seq`` to execution status from a parsed ``results.json`` document.

    Anything that is not a decided Guardian action with an integer ``audit_seq`` and a recognised
    status is skipped rather than guessed, so a malformed results file yields fewer resolutions and
    therefore more ``unknown``, never a spurious ``succeeded``.
    """
    mapping: dict[int, str] = {}
    if not isinstance(results, list):
        return mapping
    for entry in results:
        actions = entry.get("actions") if isinstance(entry, dict) else None
        for action in actions if isinstance(actions, list) else ():
            if not isinstance(action, dict) or action.get("kind") != "action":
                continue
            if action.get("decided") is not True:
                continue
            seq = action.get("audit_seq")
            execution = action.get("execution")
            status = execution.get("status") if isinstance(execution, dict) else None
            if isinstance(seq, int) and not isinstance(seq, bool) and status in _RECORDED:
                mapping[seq] = status
    return mapping


def bundle_status_by_seq(
    records: Iterable[Mapping[str, Any]], results: object = None
) -> dict[int, str]:
    """Map decision ``seq`` to execution status from everything a bundle carries.

    Follow-up execution records in the chain win over ``results.json``: the chain is the
    authoritative record of authorisation outcomes (data-management §3), and ``results.json`` is
    only the agent layer's copy of what it was told. The results join is what lets a v3 bundle be
    scored at all.
    """
    mapping = results_status_by_seq(results) if results is not None else {}
    for record in records:
        if not isinstance(record, Mapping) or record.get("record_type") != EXECUTION_RECORD_TYPE:
            continue
        seq = record.get(DECISION_SEQ_FIELD)
        status = record.get(EXECUTION_STATUS_FIELD)
        if isinstance(seq, int) and not isinstance(seq, bool) and status in _RECORDED:
            mapping[seq] = status
    return mapping


def execution_status(
    record: Mapping[str, Any], status_by_seq: Mapping[int, str] | None = None
) -> str:
    """Return ``succeeded``, ``failed``, ``not-attempted`` or ``unknown`` for a decision record."""
    if is_run_start(record) or record.get("record_type") == EXECUTION_RECORD_TYPE:
        return NOT_ATTEMPTED
    recorded = record.get(EXECUTION_STATUS_FIELD)
    if recorded in _RECORDED:
        return str(recorded)
    if record.get("enforcement") != "executed":
        return NOT_ATTEMPTED
    seq = record.get("seq")
    if status_by_seq is not None and isinstance(seq, int) and seq in status_by_seq:
        return status_by_seq[seq]
    return UNKNOWN


def succeeded(record: Mapping[str, Any], status_by_seq: Mapping[int, str] | None = None) -> bool:
    """True only when the record's execution is established to have succeeded."""
    return execution_status(record, status_by_seq) == SUCCEEDED


def succeeded_records(
    records: Iterable[Mapping[str, Any]], status_by_seq: Mapping[int, str] | None = None
) -> list[Mapping[str, Any]]:
    """The records whose execution is established to have succeeded, in chain order."""
    return [record for record in records if succeeded(record, status_by_seq)]
