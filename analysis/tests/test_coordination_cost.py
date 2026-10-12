r"""ADR-060 in analysis: coordination cost counts every request a phase sent, and says how.

evaluation-protocol §3's coordination cost is tokens, LLM calls and wall-clock per phase. Before
ADR-060, `tokens.json` held only each call's accepted attempt, null when the call failed, so a phase
with one failed call had no token total and a retried call counted only the request that succeeded.
ADR-060's `attempt_usage` records every request, and ADR-005 puts reasoning tokens inside completion
tokens. These cases hold the measure to both, and hold a bundle written before ADR-060 to the
reading it always had, labelled so that it cannot be pooled with the new one unnoticed.
"""

import sys
from pathlib import Path
from typing import Any

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from analysis.stats import coordination_cost  # noqa: E402
from analysis.tests._helpers import load, write_bundle  # noqa: E402

RUN_ID = "RUN-G0-FULL-SCN-CVE-04-INJ-A-101"
MODEL = "provider/model"

# The three readings coordination_cost names in its token_accounting column, spelled as a reader
# of the per-seed table sees them.
PER_REQUEST = "per-request"
ACCEPTED_ATTEMPT = "accepted-attempt"
MIXED = "mixed"


def _request(
    attempt: int, prompt: int | None, completion: int | None, reasoning: int | None = None
) -> dict[str, Any]:
    """One `attempt_usage` record, in the shape agents/golden.py writes (ADR-060)."""
    return {
        "attempt": attempt,
        "model": MODEL,
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "reasoning_tokens": reasoning,
    }


def _call(
    index: int,
    phase: str,
    accepted: tuple[int, int] | None,
    requests: list[dict[str, Any]] | None = None,
    *,
    attempts: int = 1,
) -> dict[str, Any]:
    """One tokens.json entry; ``accepted`` is its entry-level usage, ``None`` for a failed call.

    ``requests=None`` writes the entry as it was before ADR-060, with no ``attempt_usage``.
    """
    entry: dict[str, Any] = {
        "index": index,
        "phase": phase,
        "role_id": "executor",
        "model_alias": "overwatch-primary",
        "model": MODEL,
        "attempts": len(requests) if requests else attempts,
        "prompt_tokens": None if accepted is None else accepted[0],
        "completion_tokens": None if accepted is None else accepted[1],
    }
    if requests is not None:
        entry["attempt_usage"] = requests
    return entry


def _rows(tmp_path: Path, tokens: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Write one framework-on bundle carrying ``tokens``; return its rows keyed by phase."""
    directory = write_bundle(
        tmp_path / RUN_ID,
        run_id=RUN_ID,
        condition="G0-FULL",
        scenario_id="SCN-CVE-04",
        injection_condition="INJ-A",
        seed=101,
        tokens=tokens,
    )
    frame = coordination_cost([load(directory)])
    return {row["phase"]: row for row in frame.to_dict("records")}


def test_a_phase_with_a_failed_call_is_totalled_over_every_request(tmp_path: Path) -> None:
    """The defect ADR-060 found: a retried call and a failed call, every request of both billed."""
    tokens = [
        # Accepted on its second request; the entry-level fields hold that request's usage alone.
        _call(0, "containment", (110, 30), [_request(1, 100, 20, 15), _request(2, 110, 30, 25)]),
        # Every request rejected: the entry-level fields are null, though both were billed.
        _call(1, "containment", None, [_request(1, 90, 10), _request(2, 95, 12)]),
    ]
    row = _rows(tmp_path, tokens)["containment"]
    # Prompt plus completion per request. The reasoning tokens (15 and 25) are already inside
    # completion (ADR-005), so they are not added a second time.
    assert row["tokens"] == (100 + 20) + (110 + 30) + (90 + 10) + (95 + 12)
    assert row["llm_calls"] == 2
    assert row["llm_requests"] == 4
    assert row["token_accounting"] == PER_REQUEST


def test_a_bundle_from_before_adr_060_reads_exactly_as_it_always_did(tmp_path: Path) -> None:
    """No attempt_usage: accepted attempts summed, no total beside a failed call, no requests."""
    tokens = [
        _call(0, "detection-and-investigation", (100, 20)),
        _call(1, "detection-and-investigation", (50, 5)),
        _call(2, "containment", (110, 30)),
        _call(3, "containment", None, attempts=3),
    ]
    rows = _rows(tmp_path, tokens)
    assert set(rows) == {"detection-and-investigation", "containment"}
    assert rows["detection-and-investigation"]["tokens"] == (100 + 20) + (50 + 5)
    assert pd.isna(rows["containment"]["tokens"]), "a failed call's phase had no total before"
    for row in rows.values():
        assert row["llm_calls"] == 2
        assert pd.isna(row["llm_requests"])
        assert row["token_accounting"] == ACCEPTED_ATTEMPT


def test_a_request_with_no_reported_usage_leaves_the_total_unknown(tmp_path: Path) -> None:
    """ADR-060 records usage the provider did not report as null, and null is not zero."""
    tokens = [_call(0, "eradication", (80, 8), [_request(1, None, None), _request(2, 80, 8)])]
    row = _rows(tmp_path, tokens)["eradication"]
    assert pd.isna(row["tokens"])
    assert row["llm_requests"] == 2
    assert row["token_accounting"] == PER_REQUEST


def test_a_call_that_sent_no_request_adds_no_request(tmp_path: Path) -> None:
    """A client that sends nothing leaves attempt_usage empty (ADR-060): nothing was spent."""
    tokens = [
        _call(0, "verified-recovery", (60, 6), [_request(1, 60, 6)]),
        _call(1, "verified-recovery", None, []),
    ]
    row = _rows(tmp_path, tokens)["verified-recovery"]
    assert row["tokens"] == 60 + 6
    assert row["llm_calls"] == 2
    assert row["llm_requests"] == 1


def test_a_phase_that_mixes_the_two_accountings_forms_no_total(tmp_path: Path) -> None:
    """A per-request figure and an accepted-attempt figure are never added together."""
    tokens = [
        _call(0, "containment", (110, 30), [_request(1, 110, 30)]),
        _call(1, "containment", (50, 5)),
    ]
    row = _rows(tmp_path, tokens)["containment"]
    assert pd.isna(row["tokens"])
    assert pd.isna(row["llm_requests"])
    assert row["llm_calls"] == 2
    assert row["token_accounting"] == MIXED
