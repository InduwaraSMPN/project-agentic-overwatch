r"""Generate a campaign's ``_scoring/provenance.json`` from EVIDENCE, and refuse a batch signature.

WHY A GENERATOR, AND WHY IT REPLACES A HAND-AUTHORED FILE
-------------------------------------------------------
V12: the v1 campaign's ``_scoring/provenance.json`` was written by hand, by the same LLM that wrote
the 78 judgements it described, and it said so -- ``"produced_by": "an LLM assistant ... in one
batch"``, ``"human_validation_pass": false``, ``"scored_at_span_seconds": 1.965206``. A provenance
document that its own author drafted is not provenance; it is a description, and the person it
concerns is the person least able to check it. This file replaces the description with a computation
over artefacts nobody can edit without leaving a trace:

* every sampled bundle's own ``scores.json`` -- the pass, its ``scored_at``, and whether it was
blind;
* ``_scoring/session_log.jsonl`` -- the append-only record ``scripts/scoring_ui.py`` writes of every
  open, every submit and every refusal, carrying the token FINGERPRINT (never the token, never the
  secret) so an open can be tied to its submit without the log becoming a replayable credential.

The output says what the evidence supports and nothing more. In particular
``human_validation_pass`` is COMPUTED here, from the findings below, and is not a field anybody may
set: a v1-shaped corpus cannot produce ``true`` here, whatever it claims about itself.

WHAT A BATCH SIGNATURE IS, AND WHY EACH ONE IS A NECESSARY CONDITION RATHER THAN A HEURISTIC
--------------------------------------------------------------------------------------------
A signature is not "this looks fast". Each of the four is a violation of a property the write path
already enforces, observed after the fact:

1. **A score with no session behind it.** Every judgement ``scripts/score_bundle.write_score``
accepts
   is written through a grant, and every grant produces a ``submit`` event naming the bundle and the
   pass. A score with no matching event was written by something that is not this repository's
   scoring
   server. This is the check that catches the v1 sample outright: it has no session log at all.
2. **Two submits closer together than the minimum open-to-submit interval.** The floor in
   ``evaluation-protocol.md`` section 4 (``scoring_min_elapsed_seconds``, mirrored in
   ``scripts/m10_constants.py``) bounds the time between opening a bundle and submitting a judgement
   for it. Two judgements recorded less than that apart cannot both have had it: at least one
   skipped
   the floor. The 78 scores of the v1 sample carry 78 distinct ``scored_at`` values inside 1.965 s,
   so
   this check fires on the real corpus and not only on a synthetic one. It is a spacing argument,
   not
   a threshold of convenience: the number it uses is the protocol's, and no number of this file's
   own
   appears in it.
3. **A submit whose own recorded elapsed time is under the floor.** The same property, read from the
   session log's own ``elapsed_seconds`` rather than inferred from ``scored_at`` spacing, so a
   disagreement between the two sources is itself reported.
4. **A bundle scored twice for one pass.** One open-to-submit interval produces one score. A second
   one for the same pass is either an ungated write or a hand edit, and both are things a reader of
   this document needs to know.

None of these can be triggered by an honest session, and none of them requires knowing who the
scorer was. That is also the LIMIT, stated here so the document cannot be read as claiming more:
this is a provenance control against unattended batch writes, not proof of human authorship. A
person
who holds the scoring secret can drive a compliant session. What the document can therefore claim is
"no batch signature was observed in this corpus", and that is exactly the key it carries.

WHAT BREAKS IF THIS FILE CHANGES
    A corpus it would have flagged, and a verdict a reader relies on. Every threshold it uses comes
    from ``scripts/m10_constants`` or from a count of what is in the corpus; a number introduced
    here
    would be a protocol value with no owner. It is read-only over the bundles and writes exactly one
    new file under ``_scoring/``, which ``analysis.stats.loader.load_campaign`` never walks (it only
    considers children carrying a ``manifest.json``), so generating provenance cannot make a later
    corpus load see a phantom bundle. ADR-134 records the decision this implements and supersedes
    ADR-110 prospectively for v2; the v1 document stays as recorded evidence, unchanged.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.m10_constants import SCORING_MIN_ELAPSED_SECONDS  # noqa: E402

__all__ = (
    "PROVENANCE_SCHEMA",
    "ProvenanceError",
    "batch_signatures",
    "build_provenance",
    "main",
    "write_provenance",
)

PROVENANCE_SCHEMA = "scoring-provenance.v1"

# The session log's own event vocabulary, as ``scripts/scoring_ui.py`` writes it. Named here so a
# typo in either file surfaces as a missing event rather than as a silently empty document.
EVENT_OPEN = "open"
EVENT_SUBMIT = "submit"
EVENT_REFUSE = "refuse"

# The two files under ``_scoring/`` this tool reads. Named, because their ABSENCE is itself a
# finding
# (a corpus with no session log is the v1 shape) and a tool that only reported on what it found
# would
# report nothing at all.
SAMPLE_FILE = "sample.json"
SESSION_LOG_FILE = "session_log.jsonl"
OUTPUT_FILE = "provenance.json"


class ProvenanceError(Exception):
    """The campaign directory cannot be read as a scoring corpus at all."""


def _read_json(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProvenanceError(f"{path}: {error}") from error
    if not isinstance(document, dict):
        raise ProvenanceError(f"{path}: expected a JSON object")
    return document


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    events: list[dict[str, Any]] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ProvenanceError(f"{path}:{number}: {error}") from error
        if isinstance(event, dict):
            events.append(event)
    return events


def _parse_iso(text: Any) -> datetime | None:
    if not isinstance(text, str):
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    # A naive timestamp is read as UTC rather than as local wall time, which is the only reading
    # that
    # cannot silently SHRINK a measured interval -- and a shortened interval is the direction that
    # would manufacture a batch signature out of nothing.
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _sorted_instants(values: Iterable[datetime]) -> list[datetime]:
    return sorted(values)


def _load_scores(campaign_dir: Path, run_ids: list[str]) -> list[dict[str, Any]]:
    """Return one record per (bundle, pass) found, in sample order then file order.

    Only the sampled bundles are read. A bundle outside the sample carries no judged measure, so its
    scores.json -- if it has one -- is not part of this document's population, and reading the whole
    campaign would be both slower and less clear about what the claim covers.
    """
    records: list[dict[str, Any]] = []
    for run_id in run_ids:
        scores_path = campaign_dir / run_id / "scores.json"
        if not scores_path.is_file():
            continue
        document = _read_json(scores_path)
        passes = document.get("passes")
        if not isinstance(passes, list):
            raise ProvenanceError(f"{scores_path}: 'passes' is not a list")
        for entry in passes:
            if not isinstance(entry, dict):
                raise ProvenanceError(f"{scores_path}: a pass entry is not an object")
            records.append(
                {
                    "run_id": run_id,
                    "pass": entry.get("pass"),
                    "scored_at": entry.get("scored_at"),
                    "blind": entry.get("blind"),
                    "rubric_version": document.get("rubric_version"),
                }
            )
    return records


def batch_signatures(
    scores: list[dict[str, Any]],
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return every observed violation of the write path's guarantees, in a fixed order.

    Each finding names the rule it violates and carries the evidence, so a reader does not have to
    take the tool's word for it. The order is fixed rather than sorted by count, so two runs over
    the
    same corpus produce the same findings in the same order.
    """
    findings: list[dict[str, Any]] = []

    submits = [
        event
        for event in events
        if event.get("event") == EVENT_SUBMIT and isinstance(event.get("run_id"), str)
    ]
    # Keyed on (run_id, pass), which is what write_score's grant binding produces: a grant names one
    # bundle and one pass, and scripts/scoring_ui.py's session log records both. The opaque
    # `scoring_id` is recorded beside it and is not what this joins on -- the run id is the stable
    # name, and the scoring id is salted per campaign and would make this tool unrunnable against a
    # corpus whose salt.txt has been archived.
    submit_keys = {(event["run_id"], event.get("pass")) for event in submits}

    untraced = [
        record for record in scores if (record["run_id"], record["pass"]) not in submit_keys
    ]
    if untraced:
        findings.append(
            {
                "signature": "scores_without_a_session",
                "rule": (
                    "every judgement is written through a session grant, and every grant records a "
                    "submit event naming the bundle and the pass"
                ),
                "count": len(untraced),
                "evidence": [
                    {"run_id": record["run_id"], "pass": record["pass"]} for record in untraced[:10]
                ],
                "note": (
                    "no submit event in the session log matches these passes. Either the "
                    "session log is absent -- the v1 shape, where provenance.json was "
                    "hand-authored -- or these scores were written outside scripts/scoring_ui.py, "
                    "which ADR-134's gate refuses. A hand edit of scores.json shows up here for "
                    "the same reason, which is the intended outcome rather than a limitation."
                ),
            }
        )

    # Spacing, over the observed scored_at values. Only pairs that are genuinely out of order are
    # compared, because the queue's order is deliberate rather than chronological and a comparison
    # across the whole list would flag honest scoring that visited bundles in a shuffled order.
    instants = [
        (record["run_id"], record["pass"], moment)
        for record in scores
        if (moment := _parse_iso(record["scored_at"])) is not None
    ]
    ordered = sorted(instants, key=lambda entry: entry[2])
    too_close: list[tuple[tuple[str, Any, datetime], tuple[str, Any, datetime], float]] = []
    for earlier, later in zip(ordered, ordered[1:], strict=False):
        gap = (later[2] - earlier[2]).total_seconds()
        if 0 <= gap < SCORING_MIN_ELAPSED_SECONDS:
            too_close.append((earlier, later, gap))
    if too_close:
        findings.append(
            {
                "signature": "scored_at_closer_than_the_minimum_open_to_submit",
                "rule": (
                    "two judgements cannot be recorded less than "
                    "scoring_min_elapsed_seconds apart, because each had to be read before it was "
                    "judged"
                ),
                "count": len(too_close),
                "evidence": [
                    {
                        "earlier": {
                            "run_id": earlier[0],
                            "pass": earlier[1],
                            "scored_at": earlier[2].isoformat(),
                        },
                        "later": {
                            "run_id": later[0],
                            "pass": later[1],
                            "scored_at": later[2].isoformat(),
                        },
                        "gap_seconds": round(gap, 6),
                        "minimum_seconds": SCORING_MIN_ELAPSED_SECONDS,
                    }
                    for earlier, later, gap in too_close[:10]
                ],
                "note": (
                    "adjacent pairs only, in scored_at order. The v1 sample's 78 scores span "
                    "1.965 s in total, so every adjacent pair in it is inside the floor."
                ),
            }
        )

    fast = [
        event
        for event in submits
        if isinstance(event.get("elapsed_seconds"), (int, float))
        and not isinstance(event.get("elapsed_seconds"), bool)
        and event["elapsed_seconds"] < SCORING_MIN_ELAPSED_SECONDS
    ]
    if fast:
        findings.append(
            {
                "signature": "submit_faster_than_the_minimum_open_to_submit",
                "rule": (
                    "the session log records the measured open-to-submit interval, and it is below "
                    "scoring_min_elapsed_seconds"
                ),
                "count": len(fast),
                "evidence": [
                    {
                        "scoring_id": event.get("scoring_id"),
                        "pass": event.get("pass"),
                        "elapsed_seconds": event.get("elapsed_seconds"),
                    }
                    for event in fast[:10]
                ],
                "note": (
                    "read from the session log rather than inferred from scored_at spacing, so a "
                    "disagreement between the two sources shows up as its own finding"
                ),
            }
        )

    seen: dict[tuple[str, Any], int] = {}
    for event in submits:
        key = (event["run_id"], event.get("pass"))
        seen[key] = seen.get(key, 0) + 1
    doubled = [
        {"run_id": key[0], "pass": key[1], "submits": count}
        for key, count in sorted(seen.items(), key=lambda item: str(item[0]))
        if count > 1
    ]
    if doubled:
        findings.append(
            {
                "signature": "one_bundle_scored_twice_for_one_pass",
                "rule": "one open-to-submit interval produces one score for one pass",
                "count": len(doubled),
                "evidence": doubled[:10],
                "note": (
                    "an override through the scoring UI replaces the pass rather than appending "
                    "one, so a second submit for the same pass is an ungated write or a hand edit"
                ),
            }
        )

    return findings


def build_provenance(
    campaign_dir: str | Path, *, generated_at: str | None = None
) -> dict[str, Any]:
    """Return the provenance document for one campaign directory, computed from its artefacts."""
    campaign_dir = Path(campaign_dir)
    if not campaign_dir.is_dir():
        raise ProvenanceError(f"campaign directory not found: {campaign_dir}")
    scoring_dir = campaign_dir / "_scoring"

    sample_path = scoring_dir / SAMPLE_FILE
    sample: dict[str, Any] = {}
    run_ids: list[str] = []
    if sample_path.is_file():
        sample = _read_json(sample_path)
        raw = sample.get("run_ids", [])
        if isinstance(raw, list) and all(isinstance(item, str) for item in raw):
            run_ids = list(raw)
        else:
            # The pre-M10 sampler wrote a bare array; `load_sample` in scoring_ui accepts both
            # shapes
            # for the same reason. A corpus whose sample is a bare list still deserves a document.
            document = json.loads(sample_path.read_text(encoding="utf-8"))
            if isinstance(document, list) and all(isinstance(item, str) for item in document):
                run_ids = list(document)

    events = _read_jsonl(scoring_dir / SESSION_LOG_FILE)
    scores = _load_scores(campaign_dir, run_ids)
    findings = batch_signatures(scores, events)

    scored_at = [
        moment
        for moment in (_parse_iso(record["scored_at"]) for record in scores)
        if moment is not None
    ]
    ordered = _sorted_instants(scored_at)
    span = (ordered[-1] - ordered[0]).total_seconds() if len(ordered) >= 2 else None
    elapsed_values = sorted(
        float(event["elapsed_seconds"])
        for event in events
        if event.get("event") == EVENT_SUBMIT
        and isinstance(event.get("elapsed_seconds"), (int, float))
        and not isinstance(event.get("elapsed_seconds"), bool)
    )
    unblinded = [record for record in scores if record.get("blind") is not True]

    # The one boolean anybody will quote, computed and never set. It is false for the v1 shape and
    # cannot be made true by a document that says so, which is the whole difference between this and
    # the file it replaces.
    human_validation_pass = (
        not findings
        and bool(scores)
        and any(record["pass"] == "initial" for record in scores)  # noqa: S105 - a pass NAME
        and not unblinded
    )

    return {
        "schema_version": PROVENANCE_SCHEMA,
        "campaign_id": campaign_dir.name,
        "generated_at": generated_at or datetime.now(UTC).isoformat(),
        "generator": "scripts/scoring_provenance.py",
        "decision_record": "docs/adr/ADR-134-human-scoring-provenance-sample-rescore.md",
        "controls": {
            "session_token": (
                "a per-session HMAC token minted when a bundle is OPENED and required by "
                "every write path, including scripts/score_bundle.py's CLI and the scoring UI's "
                "override branch"
            ),
            "minimum_open_to_submit_seconds": SCORING_MIN_ELAPSED_SECONDS,
            "minimum_source": (
                "docs/protocols/evaluation-protocol.md section 4, mirrored by "
                "scripts/m10_constants.py"
            ),
        },
        "what_this_document_proves": (
            "that no batch signature was observed over the sampled corpus. It does NOT "
            "establish that the judgements are human: a person holding the scoring secret can "
            "drive a compliant session. ADR-134 records the same limit, and the distinction is why "
            "the batch-signature findings are the load-bearing part of this document rather than a "
            "footnote."
        ),
        "sample_file": f"_scoring/{SAMPLE_FILE}",
        "sample_run_count": len(run_ids),
        "sample_tuple_count": sample.get("tuple_sample_count"),
        "bundles_carrying_scores": len({record["run_id"] for record in scores}),
        "pass_count": len(scores),
        "pass_kinds_present": sorted({str(record["pass"]) for record in scores}),
        "rubric_versions": sorted(
            {str(record["rubric_version"]) for record in scores if record["rubric_version"]}
        ),
        "scored_at_min": ordered[0].isoformat() if ordered else None,
        "scored_at_max": ordered[-1].isoformat() if ordered else None,
        "scored_at_distinct": len({record["scored_at"] for record in scores}),
        "scored_at_span_seconds": round(span, 6) if span is not None else None,
        "session_log": {
            "file": f"_scoring/{SESSION_LOG_FILE}",
            "present": (scoring_dir / SESSION_LOG_FILE).is_file(),
            "events": len(events),
            "opens": sum(1 for event in events if event.get("event") == EVENT_OPEN),
            "submits": sum(1 for event in events if event.get("event") == EVENT_SUBMIT),
            "refusals": sum(1 for event in events if event.get("event") == EVENT_REFUSE),
            "recorded_elapsed_seconds_median": (
                round(statistics.median(elapsed_values), 3) if elapsed_values else None
            ),
            "recorded_elapsed_seconds_min": (
                round(elapsed_values[0], 3) if elapsed_values else None
            ),
        },
        "passes_not_recorded_blind": [
            {"run_id": record["run_id"], "pass": record["pass"], "blind": record["blind"]}
            for record in unblinded
        ],
        "batch_signatures": findings,
        "human_validation_pass": human_validation_pass,
        "must_not_be_reported_as": (
            "proof of human authorship"
            if not findings
            else "a compliant scoring session: the batch signatures above are disqualifying"
        ),
    }


def write_provenance(
    campaign_dir: str | Path,
    output_path: Path | None = None,
    *,
    generated_at: str | None = None,
    overwrite: bool = False,
) -> tuple[Path, bool]:
    """Write the document and return (path, human_validation_pass).

    A batch signature does not stop the document being WRITTEN: the whole point is that the evidence
    is recorded, including when the evidence is damning. Whether it stops the exit status is
    :func:`main`'s business, and the plan's definition of done makes that non-zero.

    AN EXISTING DOCUMENT IS NEVER CLOBBERED WITHOUT ``overwrite``. The v1 campaign's
    ``_scoring/provenance.json`` is a hand-authored artefact that is itself the EVIDENCE of defect
    V12 -- it is the document that says, in the annotator's own words, that the judgements were
    LLM-applied. Regenerating this tool's computed document over it would replace the record of the
    defect with a computed one and quietly destroy the only statement of the defect that was written
    at the time. ADR-134 says the same thing from the other end: "the v1 scoring stays as recorded
    evidence." Point ``--output`` somewhere else, or pass ``--overwrite`` knowing what you are
    replacing.
    """
    document = build_provenance(campaign_dir, generated_at=generated_at)
    path = (
        Path(output_path)
        if output_path is not None
        else Path(campaign_dir) / "_scoring" / OUTPUT_FILE
    )
    if path.is_file() and not overwrite:
        raise ProvenanceError(
            f"{path} already exists and this tool will not overwrite it. For the v1 campaign that "
            "file IS the evidence of defect V12 -- the hand-authored statement that its judgements "
            "were LLM-applied -- and replacing it would destroy the record of the defect (ADR-134: "
            "'the v1 scoring stays as recorded evidence'). Write elsewhere with --output, or pass "
            "--overwrite if you are deliberately superseding a document you have read."
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path, bool(document["human_validation_pass"])


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--campaign",
        type=Path,
        required=True,
        help="campaign directory, e.g. runs/CAMP-20260914-campaign",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help=f"where to write the document (default: <campaign>/_scoring/{OUTPUT_FILE})",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "do not write; exit non-zero if a batch signature is present. Used by the campaign's "
            "definition of done, which requires this tool to pass on the final corpus"
        ),
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help=(
            "replace an existing provenance.json. Off by default, and the reason is in "
            "write_provenance: for the v1 campaign that file is the evidence of defect V12"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.check:
            document = build_provenance(args.campaign)
            passed = bool(document["human_validation_pass"])
        else:
            path, passed = write_provenance(args.campaign, args.output, overwrite=args.overwrite)
            document = json.loads(path.read_text(encoding="utf-8"))
            print(path)
    except ProvenanceError as error:
        print(f"scoring-provenance: {error}", file=sys.stderr)
        return 2

    signatures: list[Mapping[str, Any]] = document["batch_signatures"]
    for finding in signatures:
        print(
            f"scoring-provenance: BATCH SIGNATURE {finding['signature']} "
            f"({finding['count']} occurrence(s)): {finding['rule']}",
            file=sys.stderr,
        )
    if signatures:
        print(
            "scoring-provenance: FAIL — the corpus carries batch signatures; this is the v1 shape "
            "(provenance hand-authored, judgements written in one pass with nothing opened). The "
            "judged measures may not be reported as researcher-judged until a compliant session "
            "produced them (ADR-134).",
            file=sys.stderr,
        )
        return 1
    print(
        f"scoring-provenance: PASS — {document['pass_count']} pass(es) over "
        f"{document['bundles_carrying_scores']} bundle(s), no batch signature observed. This is a "
        "statement about the evidence, not about who scored: see what_this_document_proves."
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
