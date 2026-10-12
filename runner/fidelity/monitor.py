r"""The Monitor's fidelity checks: F-MN-01..F-MN-04, all class T (P2).

WHY ALL FOUR ARE TREATMENT CHECKS
----------------------------------
Every one of these asks "did the Monitor run under the configuration this arm selects", never "did
the model respond well to it". That is P2's line, and the four are the four ways v1's Monitor
mis-ran its configuration:

``F-MN-01`` **quoting equals the arm's flag.** v1 defect V2: ``runner/live_run.py`` scaled the
    aggregator back up with the PREVIOUS run's environment, opened the window, and only then patched
    ``MONITOR_QUOTING_ENABLED`` with a second rollout -- and ``monitor/http_service.py`` reads the
    flag once per process, so the flag never took effect. 3,908 of 22,637 excerpts were quoted in
    G3-UNQUOTED, and 128 of 143 G1 runs started unquoted. The repair is in the runner's ordering
    (WS-3's ``_condition_actions``), and this check is the proof that the repair held: it reads the
    EXCERPTS in the sealed stream and asks whether each is in the frame
    :func:`monitor.aggregator.quoting.quote` produces.

    The reading is the strict one -- ``unquote`` is called and its ``ValueError`` is the answer
    "unquoted". A looser test (does the excerpt start with the opening delimiter?) would accept a
    half-framed or canonically-wrong excerpt, and ``unquote``'s own docstring is explicit that a
    lenient decoder is the failure mode this whole module argues against: it would make the check
    pass over a quoting function that had stopped doing anything.

``F-MN-02`` **the config epoch equals the run id, and the drops are recorded.** A Monitor process is
    reused across runs, and Falcosidekick redelivers; an event emitted under the previous run's
    configuration is not this run's evidence. SEAM 4's ``config_epoch`` on every
    ``monitor_timings.jsonl`` row is what makes the drop mechanical, and ``runner/live_evidence.py``
    does the dropping. This check reads the RESULT: every timing row that survived into the bundle
    must name this run, and the count of rows dropped must be recorded rather than silently
    discarded. v1 had no epoch at all, so a v1 bundle's timing rows carry none -- which is a
    ``fail``
    here and not a ``skip``, because the epoch is precisely what v1 was missing.

``F-MN-03`` **evidence is non-empty and every ground-truth-required source is present.** Two v1
    defects live in this one predicate: defect V4 (CVE runs' Trivy first signal never fired -- 0 of
    300
    CVE bundles carry a trivy event) and the general case of a bundle that sealed on an evidence
    stream
    with nothing in it. F-SC-02 narrows V4 to the CVE runs and the admitted digest, because a SIM
    run
    has no scan to expect; F-MN-03 is the general floor: a bundle whose evidence names no source at
    all
    is a bundle whose detectors did not run.

``F-MN-04`` **the audit forwarder drains a probe's records within the protocol's bound.** The
    forwarder is the narrowest link in the evidence path (ADR-064's one synchronous POST per
    record),
    and a forwarder that lags past the bound silently moves records into the NEXT window's tree,
    which
    is defect V2's quieter cousin: the G1 arm saw the previous run's configuration partly because
    the
    boundary was crossed. The bound is ``forwarder_drain_bound_seconds`` from evaluation-protocol
    section 4, mirrored in this package and NEVER inlined here. The measurement is
    ``metrics.json``'s ``monitor_forwarder_drain_seconds``, written by ``runner/live_evidence.py``;
    its
    absence is a ``skip`` at any stage but ``P0-live``, where the bound is what the stage exists to
    measure.

WHY A ``source`` LIST RATHER THAN A COUNT OF EVENTS FOR F-MN-03
--------------------------------------------------------------
Because a source that ingested nothing and a source that was never configured are the same thing at
the
event level and different things at the intent level, and only the first is a defect. The
ground-truth-required set is read from the scenario's own ground truth
(``runner.assertions.load_groundtruth``), so adding a required source to a scenario is what adds it
here -- the check has no list of its own to keep in step.
"""

from __future__ import annotations

from typing import Final

from runner.fidelity import (
    STAGE_P0_LIVE,
    STAGE_SEAL,
    BundleView,
    CheckOutcome,
    FidelityCheck,
    resolve_optional,
)

__all__ = ("CHECKS",)

_OWNER: Final = "monitor"


def _is_quoted(excerpt: object) -> bool:
    """Whether one excerpt is a well-formed quoted region, by the aggregator's own strict decoder.

    ``unquote`` is the authority because it is the inverse ``quote`` documents the requirement for,
    and because ``monitor/tests/test_g3_isolation.py`` condition 3 (``unquote(quote(x)) == x``) is
    what makes an excerpt in a sealed bundle evidence of the arm rather than of a guess.
    """
    from monitor.aggregator.quoting import unquote

    if not isinstance(excerpt, str):
        return False
    try:
        unquote(excerpt)
    except ValueError:
        return False
    return True


def f_mn_01_quoting_equals_the_arms_flag(view: BundleView) -> CheckOutcome:
    """Every evidence excerpt's quoting equals ``manifest.aggregator_quoting``.

    A baseline has no evidence, and a probe may too; both are ``skip``. What is NOT a ``skip`` is an
    arm whose ``aggregator_quoting`` is ``True`` (or ``False``) and whose excerpts disagree with it
    --
    that is the carryover defect, and it is a class-T failure, so it halts the campaign rather than
    being reported as noise.
    """
    manifest = view.manifest()
    expected = manifest.get("aggregator_quoting")
    if not isinstance(expected, bool):
        return CheckOutcome.skipped(
            "manifest carries no aggregator_quoting (baseline or pre-M10 bundle); there is no arm "
            "setting to compare the excerpts against"
        )
    events = view.events()
    if not events:
        return CheckOutcome.skipped("monitor_events.jsonl holds no event to read quoting from")
    quoted = 0
    total = 0
    for event in events:
        excerpts = event.get("evidence_excerpts")
        if not isinstance(excerpts, list):
            continue
        for excerpt in excerpts:
            total += 1
            if _is_quoted(excerpt):
                quoted += 1
    if total == 0:
        return CheckOutcome.failed(
            f"no event in {len(events)} carries an evidence_excerpt, so the arm's quoting setting "
            "was never exercised and cannot be proven delivered (M10 defect V2/V4 class)"
        )
    if expected and quoted != total:
        return CheckOutcome.failed(
            f"{total - quoted} of {total} excerpt(s) are not in a quoted region while "
            "manifest.aggregator_quoting is true: the aggregator ran under another run's "
            "configuration (defect V2)"
        )
    if not expected and quoted:
        return CheckOutcome.failed(
            f"{quoted} of {total} excerpt(s) are in a quoted region while "
            "manifest.aggregator_quoting is false: the G3 arm did not remove quoting, so it is not "
            "the G3 arm (defect V2)"
        )
    return CheckOutcome.passed(
        f"{total} excerpt(s) across {len(events)} event(s) match aggregator_quoting={expected}"
    )


def f_mn_02_every_event_carries_this_runs_epoch(view: BundleView) -> CheckOutcome:
    """Every collated event's ``config_epoch`` equals the run id; the drop count is recorded.

    Two halves, and the second is the one a reader forgets. Dropping an event from another epoch is
    correct behaviour, and a check that only counted the survivors would therefore be satisfied by a
    collation that dropped EVERYTHING: the bundle would carry a perfectly consistent, entirely
    synthetic evidence stream. So the drop count is read from ``manifest.fidelity``'s companion
    field
    -- ``monitor_epoch_drops`` in ``metrics.json`` -- and a bundle that dropped events without
    recording the count is a failure, not a pass.
    """
    run_id = view.run_id
    timings = view.timings()
    if not timings:
        return CheckOutcome.failed(
            "monitor_timings.jsonl carries no row, so no event can be tied to the configuration "
            "that produced it; SEAM 4's config_epoch is the only way to exclude a redelivered "
            "event "
            "from a previous run (defect V2)"
        )
    mismatched = [row for row in timings if str(row.get("config_epoch") or "") != run_id]
    metrics = view.metrics()
    recorded = metrics.get("monitor_epoch_drops")
    if mismatched:
        return CheckOutcome.failed(
            f"{len(mismatched)} of {len(timings)} timing row(s) name a config_epoch other than "
            f"{run_id!r}; the collation kept evidence another run's configuration produced"
        )
    if not isinstance(recorded, int) or isinstance(recorded, bool) or recorded < 0:
        return CheckOutcome.failed(
            "metrics.json records no non-negative integer 'monitor_epoch_drops'; a collation that "
            "drops an event must say how many, or a run that dropped all of them would look clean"
        )
    return CheckOutcome.passed(
        f"{len(timings)} timing row(s) name this run's epoch; {recorded} event(s) dropped as "
        "foreign-epoch and recorded"
    )


def _detection_labels(view: BundleView) -> list[dict] | None:
    """The scenario's detection labels, or ``None`` when the ground truth cannot be read.

    ``detection.labels[]`` is the ground truth's own statement of which sources this scenario
    REQUIRES evidence from: each label names a ``source`` and a ``signal``, and a label whose source
    never appears in the sealed stream is a detector that did not run. Reading the set from the
    ground truth rather than keeping a list here is what makes adding a required detector a change
    to
    the scenario alone, with no second list to forget.
    """
    scenario_id = view.manifest().get("scenario_id")
    if not isinstance(scenario_id, str) or not scenario_id:
        return None
    try:
        from runner.assertions import load_groundtruth

        groundtruth, _digest = load_groundtruth(scenario_id)
    except Exception:  # noqa: BLE001 - an unreadable ground truth is F-MN-03's finding, not a crash
        return None
    detection = groundtruth.get("detection")
    if not isinstance(detection, dict):
        return None
    labels = detection.get("labels")
    return (
        [label for label in labels if isinstance(label, dict)] if isinstance(labels, list) else []
    )


def _required_sources(view: BundleView) -> set[str] | None:
    """The evidence sources this scenario's ground truth requires, or ``None`` if unreadable."""
    labels = _detection_labels(view)
    if labels is None:
        return None
    required = {str(label.get("source")) for label in labels if label.get("source")}
    if required:
        return required
    # A ground truth that names no detection label has required every source the aggregator can
    # emit. That is the conservative reading: the check exists to catch a detector that never ran,
    # and a scenario that has not said which detectors it needs must not be read as needing none.
    from monitor.aggregator.normalize import SOURCE_REGISTRY

    return {entry.source.value for entry in SOURCE_REGISTRY}


def f_mn_03_evidence_is_non_empty_and_complete(view: BundleView) -> CheckOutcome:
    """Evidence is non-empty and every ground-truth-required source is present.

    A baseline has no evidence and no scenario, so ``skip``. A framework-on run with zero events is
    a
    ``fail`` and not a ``skip``: ``runner/bundle.py`` already requires ``monitor_events.jsonl`` to
    be
    non-empty at seal, so a zero-event framework-on bundle is one this gate is looking at after the
    fact (a v1 bundle, or a corpus read from disk rather than sealed).
    """
    if view.is_baseline():
        return CheckOutcome.skipped("baseline: no framework produced evidence")
    events = view.events()
    if not events:
        return CheckOutcome.failed(
            "monitor_events.jsonl holds no event; a run with no evidence cannot have had any "
            "detector fire, which is the defect this predicate is the general form of (V4)"
        )
    required = _required_sources(view)
    if required is None:
        return CheckOutcome.failed(
            "the scenario's ground truth could not be read, so the required-source set is unknown "
            "and completeness cannot be asserted"
        )
    present = {str(event.get("source")) for event in events}
    missing = sorted(required - present)
    if missing:
        return CheckOutcome.failed(
            f"evidence names source(s) {sorted(present)} but the ground truth requires "
            f"{sorted(required)}; missing {missing} (a detector that never ran produces no events, "
            "which is how v1's CVE runs sealed without a single Trivy finding -- defect V4)"
        )
    return CheckOutcome.passed(
        f"{len(events)} event(s) covering every required source {sorted(required)}"
    )


def f_mn_04_forwarder_drains_within_the_protocol_bound(view: BundleView) -> CheckOutcome:
    """The audit forwarder drains a probe's records within the protocol's bound.

    Read from ``metrics.json``'s ``monitor_forwarder_drain_seconds``, which
    ``runner/live_evidence.py`` records from the observed lag between a record's arrival in the raw
    API-server audit and its ``emit_ts`` in the timings stream. The bound is the mirrored
    ``forwarder_drain_bound_seconds``; the mirror is read through :func:`as_m10_protocol_mapping` so
    the number in this file is the copy the mirror test checks, never a literal at the call site.
    """
    measured = view.metrics().get("monitor_forwarder_drain_seconds")
    if not isinstance(measured, int | float) or isinstance(measured, bool):
        return CheckOutcome.skipped(
            "metrics.json records no 'monitor_forwarder_drain_seconds'; the forwarder drain is "
            "measured in the P0-live probe stage, and no other stage claims to have measured it"
        )
    bound = resolve_optional("forwarder_drain_bound_seconds")
    if measured > bound:
        return CheckOutcome.failed(
            f"the forwarder's worst observed drain was {measured:g}s, above the protocol's bound "
            "of "
            f"{bound:g}s (evaluation-protocol section 4, `forwarder_drain_bound_seconds`); records "
            "lag past the window boundary into the next run's evidence"
        )
    return CheckOutcome.passed(f"worst observed forwarder drain {measured:g}s is within {bound:g}s")


CHECKS: Final[tuple[FidelityCheck, ...]] = (
    FidelityCheck(
        id="F-MN-01",
        owner=_OWNER,
        klass={"seal": "T"},
        stage=(STAGE_SEAL,),
        summary="every evidence excerpt's quoting equals manifest.aggregator_quoting",
        predicate=f_mn_01_quoting_equals_the_arms_flag,
        known_bad="flags the G3 and G1 carryover runs",
    ),
    FidelityCheck(
        id="F-MN-02",
        owner=_OWNER,
        klass={"seal": "T"},
        stage=(STAGE_SEAL,),
        summary="every collated event's config_epoch equals the run id; drops recorded",
        predicate=f_mn_02_every_event_carries_this_runs_epoch,
        known_bad="no epoch in v1",
    ),
    FidelityCheck(
        id="F-MN-03",
        owner=_OWNER,
        klass={"seal": "T"},
        stage=(STAGE_SEAL,),
        summary="evidence non-empty and every ground-truth-required source present",
        predicate=f_mn_03_evidence_is_non_empty_and_complete,
        known_bad="CVE runs lack trivy",
    ),
    FidelityCheck(
        id="F-MN-04",
        owner=_OWNER,
        klass={"P0-live": "T"},
        stage=(STAGE_P0_LIVE,),
        summary="the audit forwarder drains a probe's records within the proposed bound",
        predicate=f_mn_04_forwarder_drains_within_the_protocol_bound,
        known_bad="—",
    ),
)
