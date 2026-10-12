r"""Draw the D2 blind re-score sample: whole matched tuples, covering distinct injection conditions.

WHY THIS SCRIPT EXISTS
-----------------------
Decision D2 (revised 2026-09-26; ADR-134) scopes the blind RE-SCORE -- the second scoring pass whose
agreement with the first is the test-retest statistic Ch.3 494 asks for -- to a subset of the
pre-registered first-pass sample :mod:`scripts.scoring_sample` drew. Two properties make it its own
tool rather than a flag on that one:

* **Whole matched tuples.** The test-retest statistic is exact agreement over the three-field
  judgement tuple (``analysis.stats.measures.compute_test_retest_agreement``), so re-scoring one arm
  of a tuple would measure something other than what the first pass recorded. This tool draws whole
  ``(scenario_id, injection_condition, seed)`` tuples -- all six arms -- so every arm is equally
  represented (plan §3.1).
* **A time gate the first-pass draw does not have.** Each re-score "starts only after the protocol's
  delay has elapsed since that bundle's initial ``scored_at``" (plan §3.1). This tool REFUSES to
  emit
  a sample whose drawn bundles have not all cleared :data:`BLIND_RESCORE_DELAY_DAYS` since their
  first-pass ``scored_at`` -- a re-score run too soon remembers the first pass, and the agreement
  statistic would be inflated by memory rather than measuring reproducibility.

Not to be confused with ``scripts/rescore_assertions.py`` (ADR-088), which re-evaluates ground-truth
ASSERTIONS over sealed bundles; that is a different tool over a different object.

THE DRAW IS DETERMINISTIC AND INDEPENDENT OF WHEN SCORING HAPPENED
------------------------------------------------------------------
Which tuples are drawn is a pure function of ``(campaign_id, campaign_seed)`` and the first-pass
sample's contents -- never of the ``scored_at`` timings. The delay is a PRECONDITION on emitting the
draw, not a filter on it: the same tuples are chosen whether they are eligible yet or not, and the
tool refuses until they are. So a reader with the campaign manifest and ``sample.json`` can
recompute
exactly which tuples the re-score covers, and the refusal never silently swaps one tuple for a
more-eligible one (which would make the re-score set depend on outcomes -- what pre-registration
forbids).

THE SEED IS THE CAMPAIGN'S OWN, WITH A ``rescore`` SALT
-------------------------------------------------------
The only randomness is :func:`_seeded_rng`, seeded from ``(campaign_id, campaign_seed)`` exactly as
``runner/order.py`` and :mod:`scripts.scoring_sample` seed theirs, plus a fixed ``rescore`` salt so
this draw is a distinct, reproducible sequence rather than a replay of the first-pass draw. Both are
recorded in the output, so the draw is reproducible from the file alone.

DISTINCT INJECTION CONDITIONS
-----------------------------
The :data:`SCORING_RESCORE_TUPLE_COUNT` tuples carry distinct injection conditions (plan §3.1), so
the
re-score is not three tuples of the same class. The draw groups the first-pass tuples by injection
condition, picks that many distinct conditions from the seeded generator, then one tuple per
condition.

WHAT THIS SCRIPT DOES NOT DO
----------------------------
It writes no score and reads no run bundle beyond each sampled bundle's own ``scores.json`` (for the
first-pass ``scored_at``) and the campaign's ``campaign.json`` and ``_scoring/sample.json``. Its
output is the one file ``<campaign_dir>/_scoring/rescore_sample.json``, in the leading-underscore
``_scoring`` directory ``analysis.stats.loader.load_campaign`` never walks into. The re-score's
blind
view hides the arm AND the scenario (``scripts/scoring_ui.py`` / ``scripts/blind_view.py`` /
``score_bundle._hide_scenario``); this file records which fields to hide, it does not render them.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
A change to the RNG construction, the salt, the grouping/enumeration order, or the delay source
draws
a DIFFERENT re-score set than a previous run drew from the same corpus -- invalidating a test-retest
statistic already computed under the old draw. Per AGENTS.md iron rule 6 and this repo's determinism
rule, that is a decision needing its own record, not a quiet edit here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from analysis.stats.gate import BLIND_RESCORE_DELAY_DAYS  # noqa: E402
from scripts.m10_constants import SCORING_RESCORE_TUPLE_COUNT  # noqa: E402
from scripts.scoring_sample import CONDITION_ORDER, DEFAULT_CAMPAIGN_DIR  # noqa: E402

__all__ = [
    "DEFAULT_CAMPAIGN_DIR",
    "RESCORE_TUPLE_COUNT",
    "SAMPLE_FILENAME",
    "SEED_SALT",
    "RescoreError",
    "build_rescore_sample",
    "main",
]

# The first-pass sample this tool draws its re-score subset FROM. scripts.scoring_sample.main
# writes it
# to <campaign>/_scoring/sample.json; the name is a literal rather than an import because
# scoring_sample
# exposes no constant for it, and runner/tests/test_scoring_rescore_sample.py holds the two equal.
SAMPLE_FILENAME = "sample.json"

# The blind re-score's tuple count, MIRRORED from evaluation-protocol section 4 via
# scripts.m10_constants
# (D2; ADR-134) -- never restated. The name is this module's public surface, so the CLI default and
# the
# build keyword read it; the VALUE comes from the mirror, checked by test_constants_match_protocol.
# Overridable from the CLI (--tuple-count) as a deliberate, recorded departure.
RESCORE_TUPLE_COUNT: int = SCORING_RESCORE_TUPLE_COUNT

# The salt that makes this a distinct, reproducible draw from the first-pass draw. Fixed, so the
# sequence is a pure function of (campaign_id, campaign_seed, this salt).
SEED_SALT = "rescore"

# The fields the re-score's blind view hides, recorded for scripts/scoring_ui.py. The initial pass
# hides
# the arm; the re-score also hides the scenario (ADR-134; score_bundle._hide_scenario).
BLIND_HIDES: tuple[str, ...] = ("condition", "scenario_id")


class RescoreError(ValueError):
    """The re-score sample cannot be drawn or is not yet eligible to be emitted."""


def _seeded_rng(campaign_id: str, campaign_seed: int) -> random.Random:
    """One generator, seeded from the campaign id, seed and the ``rescore`` salt.

    Mirrors ``runner/order.py::_seeded_rng`` and ``scripts.scoring_sample._seeded_rng`` -- same
    bytes
    hashed, same construction -- with :data:`SEED_SALT` appended so this draw is distinct from the
    first-pass draw while staying a pure function of the campaign's own seed. Reimplemented rather
    than
    imported, as scoring_sample does, because both upstreams keep the function private.
    """
    digest = hashlib.sha256(f"{campaign_id}\x00{campaign_seed}\x00{SEED_SALT}".encode()).hexdigest()
    return random.Random(int(digest, 16))  # noqa: S311 - reproducibility is the requirement


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RescoreError(f"{path}: {error}") from error


def _read_campaign_manifest(campaign_dir: Path) -> tuple[str, int]:
    manifest = campaign_dir / "campaign.json"
    payload = _read_json(manifest)
    if not isinstance(payload, dict):
        raise RescoreError(f"{manifest}: expected a JSON object")
    campaign_id = payload.get("campaign_id")
    campaign_seed = payload.get("campaign_seed")
    if not isinstance(campaign_id, str) or not campaign_id:
        raise RescoreError(f"{manifest}: 'campaign_id' is missing or not a string")
    if not isinstance(campaign_seed, int) or isinstance(campaign_seed, bool):
        raise RescoreError(f"{manifest}: 'campaign_seed' is missing or not an int")
    return campaign_id, campaign_seed


def _read_sample(campaign_dir: Path) -> dict[str, Any]:
    """The first-pass sample document, or a refusal naming why the re-score cannot start.

    The re-score is a subset of the first-pass sample, so the first pass must have been drawn
    first. An
    absent sample.json is the ordering error stated plainly rather than a draw over nothing.
    """
    sample_path = campaign_dir / "_scoring" / SAMPLE_FILENAME
    if not sample_path.is_file():
        raise RescoreError(
            f"{sample_path} does not exist; draw the first-pass sample "
            "(python -m scripts.scoring_sample) before the blind re-score subset"
        )
    payload = _read_json(sample_path)
    if not isinstance(payload, dict) or not isinstance(payload.get("tuples"), list):
        raise RescoreError(f"{sample_path}: not a first-pass sample document (no 'tuples' list)")
    return payload


def _parse_iso(text: Any) -> datetime | None:
    """Parse an ISO-8601 instant, reading a naive value as UTC.

    A naive timestamp is read as UTC, not local wall time -- the only reading that cannot silently
    SHRINK the measured delay, and a shortened delay is the direction that would let a re-score run
    too
    soon (the reasoning scripts/scoring_provenance.py gives for the same choice).
    """
    if not isinstance(text, str):
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _initial_scored_at(campaign_dir: Path, run_id: str) -> datetime | None:
    """The ``scored_at`` of ``run_id``'s first (``initial``) scoring pass, or ``None``.

    Reads only the bundle's own ``scores.json`` (what ``scripts/score_bundle.py`` writes), finds the
    ``initial`` pass -- score_bundle guarantees it is passes[0] when present -- and returns its
    ``scored_at``. ``None`` when the bundle has no scores.json, no initial pass, or an unparseable
    ``scored_at``: all three mean the first pass has not established a delay start, which the caller
    turns into a refusal naming the bundle.
    """
    scores_path = campaign_dir / run_id / "scores.json"
    if not scores_path.is_file():
        return None
    document = _read_json(scores_path)
    if not isinstance(document, dict) or not isinstance(document.get("passes"), list):
        return None
    for entry in document["passes"]:
        if isinstance(entry, dict) and entry.get("pass") == "initial":
            return _parse_iso(entry.get("scored_at"))
    return None


def build_rescore_sample(
    campaign_dir: str | Path,
    *,
    tuple_count: int = RESCORE_TUPLE_COUNT,
    delay_days: int = BLIND_RESCORE_DELAY_DAYS,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return the D2 blind re-score sample document, or raise if it is not yet eligible.

    ``tuple_count`` defaults to :data:`RESCORE_TUPLE_COUNT` (the protocol's, via the mirror) and
    ``delay_days`` to :data:`BLIND_RESCORE_DELAY_DAYS` (the GATE block's, via analysis.stats.gate).
    ``now`` is injectable so a test can place a bundle's ``scored_at`` either side of the delay; it
    defaults to the current UTC instant.

    Deterministic given the directory's contents and these parameters: the DRAW depends only on
    ``(campaign_id, campaign_seed)`` and the first-pass sample. The delay gate depends on ``now``
    and
    the first-pass ``scored_at`` values, and turns "too soon" into a :class:`RescoreError`, never a
    different draw.
    """
    if tuple_count < 1:
        raise RescoreError("tuple_count must be >= 1")
    if delay_days < 0:
        raise RescoreError("delay_days must be >= 0")

    campaign_dir = Path(campaign_dir)
    now = now if now is not None else datetime.now(UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)

    campaign_id, campaign_seed = _read_campaign_manifest(campaign_dir)
    sample = _read_sample(campaign_dir)
    if sample.get("campaign_id") not in (None, campaign_id):
        raise RescoreError(
            f"{campaign_dir / '_scoring' / SAMPLE_FILENAME} is for campaign "
            f"{sample.get('campaign_id')!r}, not {campaign_id!r}"
        )
    condition_order = tuple(sample.get("condition_order") or CONDITION_ORDER)

    first_pass_tuples = [t for t in sample["tuples"] if isinstance(t, dict)]
    if not first_pass_tuples:
        raise RescoreError(f"{campaign_dir}: the first-pass sample carries no tuples to re-score")

    # -- Draw: distinct injection conditions, one whole tuple each, deterministic and timing-free.
    by_injection: dict[str, list[dict[str, Any]]] = {}
    for entry in first_pass_tuples:
        injection = entry.get("injection_condition")
        if isinstance(injection, str):
            by_injection.setdefault(injection, []).append(entry)
    injections = sorted(by_injection)
    if len(injections) < tuple_count:
        raise RescoreError(
            f"the first-pass sample covers {len(injections)} distinct injection condition(s) "
            f"({', '.join(injections)}), fewer than the {tuple_count} the re-score must cover "
            "with distinct conditions (plan §3.1)"
        )

    rng = _seeded_rng(campaign_id, campaign_seed)
    chosen_injections = sorted(rng.sample(injections, tuple_count))
    drawn: list[dict[str, Any]] = []
    for injection in chosen_injections:
        # Sorted so the choice is independent of the order tuples appear in sample.json.
        candidates = sorted(
            by_injection[injection],
            key=lambda t: (str(t.get("scenario_id")), int(t.get("seed", 0))),
        )
        drawn.append(rng.choice(candidates))

    # -- Delay gate: every drawn bundle must have an initial pass that cleared the delay.
    delay = timedelta(days=delay_days)
    missing: list[str] = []
    pending: list[tuple[str, datetime]] = []
    tuples_out: list[dict[str, Any]] = []
    run_ids_out: list[str] = []
    for entry in drawn:
        run_ids_map = entry.get("run_ids")
        if not isinstance(run_ids_map, dict):
            raise RescoreError(f"a first-pass tuple is missing its run_ids mapping: {entry!r}")
        bundles: dict[str, Any] = {}
        for condition in condition_order:
            run_id = run_ids_map.get(condition)
            if not isinstance(run_id, str) or not run_id:
                raise RescoreError(
                    f"tuple {entry.get('scenario_id')}/{entry.get('injection_condition')}/"
                    f"{entry.get('seed')} is missing arm {condition!r}"
                )
            scored_at = _initial_scored_at(campaign_dir, run_id)
            if scored_at is None:
                missing.append(run_id)
                continue
            earliest = scored_at + delay
            if now < earliest:
                pending.append((run_id, earliest))
            bundles[condition] = {
                "run_id": run_id,
                "initial_scored_at": scored_at.isoformat(),
                "earliest_rescore_at": earliest.isoformat(),
            }
            run_ids_out.append(run_id)
        tuples_out.append(
            {
                "scenario_id": entry.get("scenario_id"),
                "injection_condition": entry.get("injection_condition"),
                "seed": entry.get("seed"),
                "run_ids": {c: run_ids_map[c] for c in condition_order},
                "bundles": bundles,
            }
        )

    if missing:
        raise RescoreError(
            f"{len(missing)} drawn bundle(s) have no first-pass scoring yet, so their re-score "
            f"delay has not started: {sorted(set(missing))}. Complete the first-pass scoring of "
            "the drawn tuples before drawing the re-score subset"
        )
    if pending:
        soonest = min(instant for _, instant in pending)
        raise RescoreError(
            f"{len(pending)} drawn bundle(s) have not cleared the {delay_days}-day re-score delay "
            f"since their initial scored_at; the earliest is eligible at {soonest.isoformat()} "
            f"(now {now.isoformat()}). A re-score before the delay measures memory of the first "
            "pass, not reproducibility (ADR-134); re-run once the delay has elapsed"
        )

    return {
        "campaign_id": campaign_id,
        "campaign_seed": campaign_seed,
        "seed_salt": SEED_SALT,
        "rescore_tuple_count": tuple_count,
        "blind_rescore_delay_days": delay_days,
        "blind_hides": list(BLIND_HIDES),
        "condition_order": list(condition_order),
        "injection_conditions": list(chosen_injections),
        "drawn_at": now.isoformat(),
        "first_pass_tuple_count": len(first_pass_tuples),
        "derivation": (
            "Decision D2 (ADR-134) blind re-score subset of the first-pass sample. Draw: "
            "random.Random over sha256(campaign_id, campaign_seed, 'rescore' salt), mirroring "
            "runner/order.py::_seeded_rng; one rng.sample over sorted(injection_condition) picks "
            "the distinct injection conditions, then one rng.choice per condition over its "
            "first-pass tuples in sorted(scenario_id, seed) order picks a whole tuple. The draw is "
            "independent of scored_at timings; the delay gate (blind_rescore_delay_days since each "
            "initial scored_at) is a precondition on emitting this file, not a filter on the draw, "
            "so the re-score set cannot depend on outcomes."
        ),
        "tuples": tuples_out,
        "run_ids": run_ids_out,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--campaign-dir",
        type=Path,
        default=DEFAULT_CAMPAIGN_DIR,
        help="the sealed campaign directory whose _scoring/sample.json to draw the re-score from",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="rescore_sample.json path (default: <campaign-dir>/_scoring/rescore_sample.json)",
    )
    parser.add_argument(
        "--tuple-count",
        type=int,
        default=RESCORE_TUPLE_COUNT,
        help=(
            "whole matched tuples to re-score, with distinct injection conditions "
            f"(default: {RESCORE_TUPLE_COUNT}, the protocol's via scripts.m10_constants)"
        ),
    )
    parser.add_argument(
        "--delay-days",
        type=int,
        default=BLIND_RESCORE_DELAY_DAYS,
        help=(
            "days that must elapse since a bundle's initial scored_at before it is eligible "
            f"(default: {BLIND_RESCORE_DELAY_DAYS}, the GATE block's via analysis.stats.gate)"
        ),
    )
    parser.add_argument(
        "--now",
        default=None,
        help="ISO-8601 instant to evaluate eligibility against (default: now, UTC); for testing",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    campaign_dir = Path(args.campaign_dir)
    output = (
        Path(args.output)
        if args.output is not None
        else campaign_dir / "_scoring" / "rescore_sample.json"
    )
    now = None
    if args.now is not None:
        now = _parse_iso(args.now)
        if now is None:
            print(
                f"scoring-rescore-sample: --now {args.now!r} is not an ISO-8601 instant",
                file=sys.stderr,
            )
            return 1
    try:
        document = build_rescore_sample(
            campaign_dir,
            tuple_count=args.tuple_count,
            delay_days=args.delay_days,
            now=now,
        )
    except RescoreError as error:
        print(f"scoring-rescore-sample: {error}", file=sys.stderr)
        return 1
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
