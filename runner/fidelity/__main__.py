r"""``python -m runner.fidelity`` -- run the fidelity registry over a bundle or a campaign.

WHAT THE CLI IS FOR
-------------------
The gate has to be runnable without ``make`` (docs/04-repo-conventions.md, the rule every
``scripts/*.sh`` wrapper follows), and it has to be runnable over a thing a researcher has: a
campaign directory. Three invocations, three jobs:

* ``--campaign-dir runs/CAMP-<date>-campaign-v2`` -- evaluate every sealed bundle at the seal stage,
  append every verdict to ``<campaign>/fidelity_ledger.jsonl``, and report the per-class totals.
  Exit 1 if any class-T check failed, because that is a campaign that must halt.
* ``--stage <stage>`` -- evaluate a different stage's checks. The three gate stages
  (``pilot gate``, ``checkpoint``, ``final``) change which classes block, which is the whole of P2's
  per-stage semantics and the reason the flag exists rather than being implied by the check's class.
* ``--known-bad`` -- the KNOWN-BAD REPLAY (P4). Instead of "did anything fail", it asks "did every
  v1 defect get flagged": each check that names a known-bad expectation in the registry must have a
  ``fail`` somewhere in the corpus, and the exit code is 0 exactly when every expected flag was
  raised. That inversion is deliberate -- the replay's job is to prove the CHECKS work, so a
  successful replay is a campaign that is FULL of failures, and a script that printed them as
  failures would be reporting the opposite of the truth. Three kinds of expectation are reported on
  their own line rather than demanded: a row plan section 5 marks as naming no v1 defect, the one
  offline-proven check (ADR-139), and -- computed per corpus -- any check whose every outcome there
  was a skip naming an input producer that has not run (ADR-146). The last is what lets the frozen,
  pre-remediation v1 corpus reach exit 0 while the synthetic per-defect corpus still demands every
  one of them.

WHY THE STDOUT/STDERR SPLIT
---------------------------
One machine-readable summary line on stdout, everything a human reads on stderr, in
``scripts/monitor_replay.sh``'s and ``scripts/audit_verify.sh``'s shape.
``scripts/fidelity_check.sh``
parses the summary line; a reader diagnosing a halt reads stderr. Exit 0 on a clean verdict, 1 on a
blocking one -- and, for ``--known-bad``, 0 means every expected flag was raised, so the same exit
code carries the same meaning in both modes: "the gate's own expectation was met".

WHAT BREAKS IF THIS FILE CHANGES
---------------------------------
``scripts/fidelity_check.sh``, ``scripts/known_bad_replay.sh`` and the two Make targets that call
them. The summary line's shape is a contract with the wrappers, which is stated here rather than
left
to whichever reader exists.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from runner.fidelity import (
    CAUSE_PRODUCER_ABSENT,
    DEFECT_NAMING_KNOWN_BAD,
    KNOWN_BAD_EXPECTATIONS,
    LEDGER_FILENAME,
    NO_V1_DEFECT,
    OFFLINE_PROVEN_KNOWN_BAD,
    STAGE_SEAL,
    FidelityError,
    append_fidelity_ledger,
    blocking_ids,
    evaluate_bundle,
    iter_campaign_reports,
    t_failures,
)

#: The stages the CLI accepts, spelled as the user types them. The gate stages are named here rather
#: than derived from the registry because they are stages at which checks are CONSULTED, not
#: COMPUTED, and so none of them is a check's declared stage in the natural reading.
_CLI_STAGES: tuple[str, ...] = (
    "seal",
    "loop",
    "offline",
    "P0-live",
    "pilot",
    "campaign",
    "pilot gate",
    "checkpoint",
    "final",
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="runner.fidelity",
        description=(
            "Evaluate the treatment-fidelity registry (P1) over a bundle or a campaign (P2's "
            "T/B/R classes decide what blocks)."
        ),
    )
    parser.add_argument(
        "--campaign-dir",
        type=Path,
        help="the campaign directory to walk; every subdirectory holding a manifest.json is a "
        "bundle",
    )
    parser.add_argument(
        "--bundle-dir",
        type=Path,
        help="evaluate one bundle instead of a campaign (mutually exclusive with --campaign-dir)",
    )
    parser.add_argument(
        "--stage",
        default=STAGE_SEAL,
        help="the stage to evaluate; one of " + ", ".join(repr(s) for s in _CLI_STAGES),
    )
    parser.add_argument(
        "--known-bad",
        action="store_true",
        help=(
            "the known-bad replay: assert every check that names a v1 defect in its registry entry "
            "raised a fail somewhere in the corpus, and exit 0 when every expected flag was raised"
        ),
    )
    parser.add_argument(
        "--no-ledger",
        action="store_true",
        help="do not append to the campaign fidelity ledger (a read-only inspection)",
    )
    return parser


def _summary_line(
    *, stage: str, bundles: int, totals: dict[str, dict[str, int]], blocked: tuple[str, ...]
) -> str:
    """The one machine-readable line the shell wrappers parse.

    ``fidelity: PASS|FAIL - ...`` and a fixed set of ``k=v`` tokens after it, in a fixed order, so a
    wrapper can awk on position rather than on a sentence.
    """
    counts = " ".join(
        f"{klass.lower()}_{status}={totals.get(klass, {}).get(status, 0)}"
        for klass in ("T", "B", "R")
        for status in ("pass", "fail", "warn", "skip")
    )
    verdict = "FAIL" if blocked else "PASS"
    return (
        f"fidelity: {verdict} - stage={stage} bundles={bundles} {counts} "
        f"blocking={','.join(blocked) if blocked else 'none'}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.stage not in _CLI_STAGES:
        parser.error(f"--stage {args.stage!r} is not one of {list(_CLI_STAGES)}")
    if bool(args.campaign_dir) == bool(args.bundle_dir):
        parser.error("exactly one of --campaign-dir and --bundle-dir is required")

    # The gate evaluates one requested stage; the known-bad replay evaluates EVERY stage, because
    # its question is "did every check that names a v1 defect flag it", and the defects are spread
    # across stages (F-RN-01 at seal, F-AG-02 at loop, F-RN-02 at campaign, F-MN-04/F-AN-03 at
    # P0-live, F-AG-03/F-GD-04/F-AN-02 at pilot, F-AN-01 at pilot gate, F-SC-04/05 at offline). A
    # single-stage replay could never raise a check computed at another stage, so `--known-bad`
    # unions the failures across all of `_CLI_STAGES` -- the behaviour `_known_bad_reports`'s own
    # docstring describes ("the replay runs over the same corpus at several stages"). The gate
    # path is unchanged: without `--known-bad` it is still the single requested stage.
    stages = _CLI_STAGES if args.known_bad else (args.stage,)
    try:
        if args.bundle_dir is not None:
            report = evaluate_bundle(args.bundle_dir, stages=stages)
            reports = [report]
            root = args.bundle_dir.parent
        else:
            root = args.campaign_dir  # type: ignore[assignment]
            reports = list(iter_campaign_reports(root, stages=stages))
    except FidelityError as error:
        print(f"fidelity: {error}", file=sys.stderr)
        return 1
    if not reports:
        print(
            f"fidelity: FAIL - {root} holds no bundle directory carrying a manifest.json. A gate "
            "that passes over nothing reads, in a log, exactly like a gate that passes over "
            "everything",
            file=sys.stderr,
        )
        print(f"fidelity: FAIL - stage={args.stage} bundles=0 blocking=none")
        return 1

    totals: dict[str, dict[str, int]] = {}
    failures: list[str] = []
    for report in reports:
        for klass, counts in report.summary().items():
            bucket = totals.setdefault(klass, {})
            for status, value in counts.items():
                bucket[status] = bucket.get(status, 0) + value
        failures.extend(
            f"{report.run_id} {result.id} [{result.klass}/{result.stage}] {result.status}: "
            f"{result.detail}"
            for result in report.results
            if result.status == "fail"
        )
        if not args.no_ledger and args.bundle_dir is None:
            append_fidelity_ledger(root, report, stages=stages)

    blocked: set[str] = set()
    for report in reports:
        blocked.update(blocking_ids(report, args.stage))

    if args.known_bad:
        return _known_bad_reports(reports, blocked, stage=args.stage, ledger=root)

    for line in sorted(failures):
        print(f"  {line}", file=sys.stderr)
    if failures:
        print(
            f"\nfidelity: {len(failures)} failing check result(s) over {len(reports)} bundle(s). "
            "A class-T failure halts the campaign (ADR-120); a class-B failure is reported during "
            "the campaign and is a finding, not a defect (P2).",
            file=sys.stderr,
        )
    print(
        _summary_line(
            stage=args.stage, bundles=len(reports), totals=totals, blocked=tuple(sorted(blocked))
        )
    )
    if not args.no_ledger and args.bundle_dir is None:
        print(f"fidelity: ledger appended at {Path(root) / LEDGER_FILENAME}", file=sys.stderr)
    return 1 if blocked else 0


def _known_bad_reports(reports, blocked: set[str], *, stage: str, ledger: Path) -> int:
    """The known-bad replay's verdict: every expected flag raised.

    The expectation set is the registry's own ``known_bad`` strings, so a check that names no defect
    cannot be "expected" and a defect nobody wrote a check for is invisible to this mode -- which is
    why ``runner/tests/test_fidelity_known_bad.py`` additionally asserts that every v1 defect the
    plan
    enumerates has a check whose expectation names it.

    A raised flag is any check that FAILED anywhere in the corpus, at any stage the corpus was
    evaluated at. Reading only the requested stage would make a corpus evaluated at ``seal`` unable
    to
    satisfy an ``offline``-stage expectation, and the replay runs over the same corpus at several
    stages precisely because the defects are spread across them.

    What is DEMANDED is narrower than what the registry names, and deliberately so: a row with no v1
    defect, the offline-proven check, and -- per corpus -- a check whose input producer has not run
    are each reported on their own line rather than counted MISSING. The demand is therefore
    "every flag this corpus could raise, raised", which is the only version of the claim a frozen
    pre-remediation corpus can satisfy (ADR-146). The exclusions are printed, never silent, so a
    reader can see exactly which expectations were not exercised and why.
    """
    raised = set(blocked)
    for report in reports:
        raised.update(t_failures(report) and [r.id for r in t_failures(report)])
        raised.update(result.id for result in report.results if result.status == "fail")
    # Three sets leave the demand, each for a reason that is about the CORPUS or the CHECK and never
    # about the verdict, and each reported on its own line so no check is silently excused.
    #
    # (1) no-v1-defect: rows plan section 5 marks NO_V1_DEFECT. There is no v1 defect to flag, so
    #     there is no raise to demand (ADR-146).
    # (2) offline-proven: F-SC-03a's predicate never reads a bundle, so no corpus can flip it; it is
    #     proven by its own offline fixtures (ADR-139).
    # (3) producer-pending: the check reads a campaign-level artefact whose producer has not run
    #     over THIS corpus -- every outcome it produced here was a skip tagged
    #     CAUSE_PRODUCER_ABSENT. This is the pre-remediation-corpus case: `instrument_digest`,
    #     `payload_coverage.json`, `vacuity.json`, `injection_base_rates.json` and
    #     `assertion_availability.json` are all written by workstreams that post-date the frozen v1
    #     corpus, so the v1 replay can never raise them. The exclusion is per-corpus and computed
    #     from what was actually observed, NOT a hard-coded list: the synthetic per-defect corpus
    #     carries those artefacts, so there the same checks are still demanded and still raised, and
    #     a v2 campaign corpus is demanded of them the moment its producers run (ADR-146).
    no_defect = set(KNOWN_BAD_EXPECTATIONS) - set(DEFECT_NAMING_KNOWN_BAD)
    offline_proven = OFFLINE_PROVEN_KNOWN_BAD & set(KNOWN_BAD_EXPECTATIONS)
    expected_all = set(DEFECT_NAMING_KNOWN_BAD) - offline_proven
    outcomes: dict[str, set[tuple[str, str]]] = {}
    for report in reports:
        for result in report.results:
            outcomes.setdefault(result.id, set()).add((result.status, result.cause))
    producer_pending = {
        check_id
        for check_id in sorted(expected_all - raised)
        if outcomes.get(check_id)
        and all(
            status == "skip" and cause == CAUSE_PRODUCER_ABSENT
            for status, cause in outcomes[check_id]
        )
    }
    expected = expected_all - producer_pending
    missing = sorted(expected - raised)
    unexpected = sorted(raised - set(KNOWN_BAD_EXPECTATIONS))
    for check_id in sorted(raised & expected):
        print(
            f"  raised  {check_id}  expected: {KNOWN_BAD_EXPECTATIONS[check_id]}",
            file=sys.stderr,
        )
    for check_id in sorted(offline_proven):
        print(
            f"  offline-proven  {check_id}  (not corpus-raiseable; proven by its own offline "
            "pass/fail fixtures in the default fidelity_check.sh run) -- ADR-139",
            file=sys.stderr,
        )
    for check_id in sorted(no_defect):
        print(
            f"  no-v1-defect  {check_id}  (plan section 5 marks this row {NO_V1_DEFECT}: it names "
            "no v1 defect, so no corpus raise is demanded of it) -- ADR-146",
            file=sys.stderr,
        )
    for check_id in sorted(producer_pending):
        print(
            f"  producer-pending  {check_id}  (every outcome over this corpus was a skip naming an "
            "input producer that has not run; demanded wherever a corpus carries its input) -- "
            "ADR-146",
            file=sys.stderr,
        )
    for check_id in missing:
        print(
            f"  MISSING {check_id}  expected: {KNOWN_BAD_EXPECTATIONS[check_id]}",
            file=sys.stderr,
        )
    for check_id in unexpected:
        print(
            f"  raised-without-an-expectation {check_id}; add its v1 defect to the registry's "
            "known_bad column or fix the check",
            file=sys.stderr,
        )
    excused = (
        f" ({len(producer_pending)} producer-pending, {len(no_defect)} naming no v1 defect and "
        f"{len(offline_proven)} offline-proven expectation(s) were reported above, not demanded)"
        if producer_pending or no_defect or offline_proven
        else ""
    )
    if missing:
        print(
            f"\nknown-bad: FAIL - {len(missing)} of {len(expected)} expected flag(s) were not "
            "raised "
            f"at stage {stage} over {len(reports)} bundle(s) under {ledger}. A known-bad replay "
            "that "
            "passes over a defect it did not flag proves nothing about the check",
            file=sys.stderr,
        )
        print(
            f"known-bad: FAIL - expected={len(expected)} "
            f"raised={len(raised & expected)} missing={','.join(missing)}"
        )
        return 1
    print(
        f"\nknown-bad: PASS - all {len(expected)} expected flag(s) raised over {len(reports)} "
        f"bundle(s) at stage {stage}{excused}; the replay corpus is a corpus of KNOWN DEFECTS, so "
        "these failures are the proof and not a defect in the instrument",
        file=sys.stderr,
    )
    print(
        f"known-bad: PASS - expected={len(expected)} raised={len(raised & expected)} missing=none"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
