r"""The campaign vacuity tripwire: flags a scored predicate that never once failed on a real run.

WHAT THIS MODULE IS FOR
    Supervisor ruling 2026-09-14 ("guardrail (B)"): at analysis time, over a campaign's REAL
    (`is_baseline: false`) sealed run bundles -- incident runs included -- flag any scored
    predicate (a top-level `assertions.json` assertion, or a required substep) that PASSED in
    100% of the runs where it was actually evaluated. A verified-recovery `replicas-at-least` or
    `slo-probe-recovered` check (or any other predicate) that never once fails across the whole
    real corpus, even on a `G1-LOGONLY` run that left an incident unremediated, is *vacuous*:
    either it is not reading real state, or its failing side is unreachable by construction, and
    either way it is not doing the work Table 3.4 credits it for.

    This closes a blind spot the live no-incident negative control cannot see by itself: a vacuous
    recovery check looks identical to a correctly-not-failing one under a no-incident reading,
    because nothing there ever exercises the check's failing side. It can only be caught over the
    incident corpus -- which is what a real campaign's grid actually contains once it runs -- so the
    check belongs here, in the analysis layer, rather than in any offline or live control harness.
    See `docs/adr/ADR-096-campaign-vacuity-tripwire.md` for the full decision and how this
    complements the offline recovery-failability proof and the live action-separation proof
    (`runner/controls.py`; ADR-089), neither of which runs over the real multi-scenario, multi-seed
    corpus this module reads -- both are scripted, no-model harnesses that show a check is *able* to
    fail under a controlled script; this module checks whether it *ever actually did*, in the real
    corpus.

    This is a WARNING, not a hard error and not a Table 3.4 measure: :mod:`analysis.render`
    prints it and writes it as its own table, and the researcher decides what a flagged predicate
    means for that campaign's results. Nothing here changes how any existing measure or contrast
    is computed (:mod:`analysis.stats.measures`, :mod:`analysis.stats.pairs`); this module only
    reads `assertions.json` (`data-management.md` §8: raw bundle files, never the `metrics.json`
    cache) through :class:`~analysis.stats.loader.Bundle`, exactly as every other measure in this
    package does.

WHY IDENTIFIERS ARE NAMESPACED BY SCENARIO
    `assertion_id` and `substep_id` are unique only *within one scenario's* ground truth, never
    campaign-wide: every file under `scenarios/groundtruth/` numbers its own checks `ASR-01`,
    `ASR-02`, ... independently, so `SCN-CVE-04`'s `ASR-01` ("the investigation read the
    adservice Deployment through the Guardian") and `SCN-SIM-01`'s `ASR-01` (an unrelated check)
    merely share a token. `substep_id` is narrower still: `SUB-01`/`SUB-02`/`SUB-03` repeat once
    per phase within one scenario file. A real campaign's grid spans many scenarios in one run
    set (`runner/grid.py`'s `scenario_ids()`; both `runner/CAMP-2026091{2,3}-gate-pilot.json`
    pilot manifests already cover three), so pooling by the bare id would silently conflate two
    unrelated checks the moment a campaign crosses scenarios -- exactly the grand-mean-shaped
    defect `analysis/stats/proportions.py` (`POOLED_COLUMNS`) and `analysis/stats/pairs.py` (the
    `S1-HIER`/`G0-FULL` alias) each refuse elsewhere in this package. Every identity here
    therefore carries `scenario_id`, and a substep's carries `phase` as well, since its own id
    resets every phase. An assertion's `phase` is carried too, for the same reporting reason
    `assertions.json` itself carries it on an assertion; it is `None` for an end-state-compromise
    assertion, whose ground truth `phase` is `null`.

WHAT "APPLICABLE" MEANS, AND WHY ABSENCE IS NEITHER A PASS NOR A FAIL
    `runner/evaluate_assertions.py` writes one entry per ground-truth definition that applies to
    a run's `(scenario_id, injection_condition)`: every phase-outcome assertion and every
    required substep on every run of a scenario (neither varies with injection condition), but an
    end-state-compromise assertion only on the runs whose injection condition defines it -- an
    `INJ-A` end state never appears in an `INJ-B` or `INJ-NONE` run of the same scenario. A
    predicate absent from one run's `assertions.json` was never evaluated there: it is not a pass
    that would prop up a vacuous check, and it is not a fail that would rescue a real one, so this
    module's denominator is "runs where the predicate actually appears", never "every real run of
    the campaign". A predicate that appears in zero real runs is excluded from the result
    entirely rather than reported as a vacuous 0/0: a 100% pass rate over no evidence is not a
    finding, and :func:`vacuous_predicates` never manufactures one.

WHAT THE DISPOSITION CLASSIFIER ADDS (supervisor ruling 2026-09-14)
    A flag from :func:`vacuous_predicates` is a pattern to inspect, not a verdict (see above):
    :func:`classify_disposition` is the researcher's follow-up read, over one flagged predicate at a
    time. The supervisor's 2026-09-14 review of the pilot's first flagged set ruled a flagged
    predicate is NOT genuinely vacuous if ANY of -- (a) it FAILS in its scenario's live negative
    control (`runner/controls.py`'s empty-script run against a real Guardian), proof its failing
    side is reachable at all even though this campaign's real runs never reached it; (b) it is a
    do-no-harm check whose passing is the point because it asserts a harm did NOT happen -- a
    labelled do-no-harm assertion (ground truth `kind: end-state-compromise`), or, generalised to
    the check TYPE by the 2026-09-14 ruling since a required substep carries no `kind` field, any
    `guardian-executed-none` check, or a `replicas-at-least` whose minimum is BELOW the target's
    declared full replica count (an availability floor -- "the response did not scale it to zero" --
    the state twin of the scale-to-zero guard; one AT the full count is a recovery target and falls
    to (c)); or (c) it is a verified-recovery phase state check, the same "passing is the point"
    reasoning as (b) for the phase whose checks read recovered state rather than an action taken.
    Otherwise it is `genuinely-vacuous`, and the disposition table
    :mod:`analysis.render` writes names it as a blocker for a human, not for this module: like
    :func:`vacuous_predicates` itself, :func:`classify_disposition` never raises for a normal
    "no exemption applies" outcome and never blocks `make analyze` -- only a missing or unreadable
    negative control file fails closed, because that is the one case nothing here can classify at
    all. See :func:`classify_disposition`'s own docstring for the mechanics, and
    `docs/plans/gate-pilot-vacuity-disposition.md` for the pilot's own recorded table.

WHAT BREAKS IF THIS FILE CHANGES
    Flagging a predicate that failed at least once, or missing one that never did, defeats the one
    property this module exists to check. Pooling without `scenario_id` in the key would silently
    merge unrelated checks (see above) the moment a campaign carries more than one scenario, which
    every real grid does. ADR-096 (the decision); ADR-043 (analysis as a tested component). After
    the `v1.0` freeze any change here is a logged hotfix ADR (AGENTS.md iron rule 6).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import pandas as pd
from scenarios.schemas import yamlsubset

from analysis.stats.loader import IDENTITY_COLUMNS, Bundle
from analysis.stats.m10 import INJECTION_DISCRIMINATION_BASE_RATE_MAX

__all__ = [
    "ALWAYS_FAILS",
    "ASSERTION_KIND",
    "DEFAULT_CONTROLS_ROOT",
    "DISPOSITIONS",
    "DO_NO_HARM",
    "FAILS_NEGATIVE_CONTROL",
    "GENUINELY_VACUOUS",
    "NEVER_FAILS",
    "REQUIRED_SUBSTEP_KIND",
    "VERIFIED_RECOVERY_CHECK",
    "VacuousPredicate",
    "always_failing_predicates",
    "classify_disposition",
    "predicate_outcomes",
    "vacuous_predicates",
]

# The two directions the symmetric tripwire flags (V26). A never-failing predicate passed in 100% of
# its applicable runs (:func:`vacuous_predicates`); an always-failing one passed in 0% of them
# (:func:`always_failing_predicates`). Both are vacuous: a check that cannot be observed to move is
# not
# doing the work Table 3.4 credits it for, whichever side it is stuck on.
NEVER_FAILS: Final = "never-fails"
ALWAYS_FAILS: Final = "always-fails"

# The identity coordinates carried onto every outcome row, single-sourced from the loader exactly as
# analysis.stats.measures does (data-management.md §2).
_IDENTITY: Final = list(IDENTITY_COLUMNS)

# The two predicate shapes this module scores, matching assertions.json's own two arrays
# (runner/evaluate_assertions.py): every top-level entry in `assertions` (phase-outcome and
# end-state-compromise alike -- the vacuity property does not distinguish them), and every entry in
# `required_substep_results`. Named constants so the two kinds are spelled exactly once.
ASSERTION_KIND: Final = "assertion"
REQUIRED_SUBSTEP_KIND: Final = "required-substep"

# The `result` literal that means a predicate held, per predicate shape: an `assertions.json`
# assertion entry writes `pass`/`fail` (S105 fires on the name alone, as it does for the other
# schema-value literals in this package -- not a credential); a required-substep entry writes
# `reached`/`not-reached`.
_PASS: Final = "pass"  # noqa: S105
_REACHED: Final = "reached"

# The long-form outcome columns: identity, which of the two shapes, the scenario-scoped identity
# (phase may be None), and whether this run's evaluation of it held.
_OUTCOME_COLUMNS: Final = [*_IDENTITY, "kind", "phase", "local_id", "held"]

# The grouping key vacuous_predicates pools on: scenario first, because that is what makes local_id
# campaign-unique (see the module docstring), then kind/phase/local_id to select one predicate.
_GROUP_KEYS: Final = ["scenario_id", "kind", "phase", "local_id"]


def predicate_outcomes(bundles: Iterable[Bundle]) -> pd.DataFrame:
    """One row per (run, scored predicate) that the run's `assertions.json` actually evaluated.

    Reads `assertions.json` only -- never `metrics.json` -- exactly as every measure in
    :mod:`analysis.stats.measures` does. A bundle with no `assertions.json` (a baseline, or an
    unscored run) contributes no rows, the same convention
    :func:`~analysis.stats.measures.per_phase_outcome_correctness` uses; ``bundles`` is expected to
    already be a campaign's real, `is_baseline: false` runs -- this function does not filter on
    `is_baseline` itself, on the same contract every function in `analysis.stats.measures` follows
    (the caller, e.g. `analysis.render`'s `framework_on` split, does that once for every measure).

    ``kind`` is :data:`ASSERTION_KIND` for a top-level `assertions` entry or
    :data:`REQUIRED_SUBSTEP_KIND` for a `required_substep_results` entry; ``local_id`` is that
    entry's own `assertion_id` or `substep_id`; ``phase`` is the entry's own `phase` field (`None`
    for an end-state-compromise assertion, whose ground truth `phase` is `null`). ``held`` is `True`
    exactly when the entry's `result` is the value that shape counts as holding (`pass` for an
    assertion, `reached` for a substep). :func:`vacuous_predicates` pools these rows by
    (`scenario_id`, `kind`, `phase`, `local_id`) -- see the module docstring for why `scenario_id`
    must be in that key.
    """
    rows: list[dict[str, object]] = []
    for bundle in bundles:
        if bundle.assertions is None:
            continue
        identity = bundle.identity()
        for entry in bundle.assertions.get("assertions", []):
            rows.append(
                {
                    **identity,
                    "kind": ASSERTION_KIND,
                    "phase": entry.get("phase"),
                    "local_id": str(entry.get("assertion_id")),
                    "held": entry.get("result") == _PASS,
                }
            )
        for entry in bundle.assertions.get("required_substep_results", []):
            rows.append(
                {
                    **identity,
                    "kind": REQUIRED_SUBSTEP_KIND,
                    "phase": entry.get("phase"),
                    "local_id": str(entry.get("substep_id")),
                    "held": entry.get("result") == _REACHED,
                }
            )
    return pd.DataFrame(rows, columns=_OUTCOME_COLUMNS)


@dataclass(frozen=True, slots=True)
class VacuousPredicate:
    """One scored predicate that never moved across the real runs where it was evaluated.

    ``direction`` says which way it is stuck: :data:`NEVER_FAILS` (passed in 100% of applicable
      runs,
    ``pass_count == total_applicable``) or :data:`ALWAYS_FAILS` (passed in 0%, ``pass_count == 0``).
    ``pass_count`` and ``total_applicable`` are both carried rather than collapsed into a boolean,
      so a
    report reads "6/6 real runs" or "0/6 real runs" -- a figure a reader can check independently
    rather
    than trusting a flag with no denominator behind it. ``scenario_id`` and ``phase`` (``None`` for
    an
    end-state-compromise assertion) are part of the identity, not decoration: see the module
    docstring
    for why `local_id` alone is not campaign-unique. ``direction`` defaults to :data:`NEVER_FAILS`
    so
    the never-failing tripwire and every existing caller read exactly as before. Frozen, because a
    flagged finding is a fact about a run set, not a value a downstream cell should be able to edit.
    """

    scenario_id: str
    kind: str
    phase: str | None
    local_id: str
    pass_count: int
    total_applicable: int
    direction: str = NEVER_FAILS

    @property
    def identifier(self) -> str:
        """A single campaign-unique, human-readable id for this predicate.

        ``scenario_id/local_id`` for an end-state-compromise assertion (no phase);
        ``scenario_id/phase/local_id`` otherwise -- the same two shapes the module docstring names.
        """
        if self.phase is None:
            return f"{self.scenario_id}/{self.local_id}"
        return f"{self.scenario_id}/{self.phase}/{self.local_id}"


def _flag_stuck_predicates(bundles: Iterable[Bundle], *, direction: str) -> list[VacuousPredicate]:
    """Flag every predicate stuck on one side across the real runs where it was evaluated.

    The one grouping both directions of the symmetric tripwire share. Groups
    :func:`predicate_outcomes` by (`scenario_id`, `kind`, `phase`, `local_id`) -- ``dropna=False``,
    because an end-state assertion's `phase` is legitimately `None` and a default pandas groupby
    would
    silently drop that group rather than score it -- and keeps a group only when it is stuck:
    ``passed == total`` for :data:`NEVER_FAILS`, ``passed == 0`` for :data:`ALWAYS_FAILS`. A
      predicate
    that appears in zero real runs forms no group at all and is never reported (the module
    docstring's
    "0/0 is not a finding"). The result is sorted by (`scenario_id`, `kind`, `phase`, `local_id`) so
    two calls over one corpus return byte-identical order
    (`.agents/rules/20-parity-and-determinism.md`).
    """
    outcomes = predicate_outcomes(bundles)
    if outcomes.empty:
        return []
    flagged: list[VacuousPredicate] = []
    for keys, group in outcomes.groupby(_GROUP_KEYS, sort=True, dropna=False):
        scenario_id, kind, phase, local_id = keys
        total = len(group)
        passed = int(group["held"].sum())
        stuck = (passed == total) if direction == NEVER_FAILS else (passed == 0)
        if stuck:
            flagged.append(
                VacuousPredicate(
                    scenario_id=str(scenario_id),
                    kind=str(kind),
                    phase=None if pd.isna(phase) else str(phase),
                    local_id=str(local_id),
                    pass_count=passed,
                    total_applicable=total,
                    direction=direction,
                )
            )
    return sorted(
        flagged, key=lambda item: (item.scenario_id, item.kind, item.phase or "", item.local_id)
    )


def vacuous_predicates(bundles: Iterable[Bundle]) -> list[VacuousPredicate]:
    """Every scored predicate that passed in 100% of the real runs where it was evaluated.

    ``bundles`` must be a campaign's real (`is_baseline: false`) run bundles -- the same
    `framework_on` list every other measure in this package is called with
    (`analysis.render`'s `_split`); see :func:`predicate_outcomes` for why this function does not
    filter `is_baseline` itself. This is the never-failing half of the symmetric tripwire;
    :func:`always_failing_predicates` is the other half (V26), and both are
    :func:`_flag_stuck_predicates`.
    """
    return _flag_stuck_predicates(bundles, direction=NEVER_FAILS)


def always_failing_predicates(bundles: Iterable[Bundle]) -> list[VacuousPredicate]:
    """Every scored predicate that passed in 0% of the real runs where it was evaluated (V26).

    The symmetric counterpart to :func:`vacuous_predicates`: the v1 tripwire was one-sided, flagging
    only a predicate that never failed, so a predicate that *never passed* -- a check whose passing
    side is unreachable in this corpus, near the eradication floor in every arm -- went unflagged
    (V26). An always-failing predicate is as vacuous as a never-failing one: it never once moved, so
    it is not discriminating the runs it scores. Same grouping, denominator and determinism as
    :func:`vacuous_predicates`; its flags carry ``direction == ALWAYS_FAILS`` and ``pass_count ==
    0``.
    Reported as a WARNING beside the never-failing set, never a hard error (ADR-096 item 5).
    """
    return _flag_stuck_predicates(bundles, direction=ALWAYS_FAILS)


# ==================================================================================================
# DISPOSITION -- supervisor ruling 2026-09-14: is a flagged predicate genuinely vacuous?
# ==================================================================================================
#
# A predicate landing in vacuous_predicates() is a WARNING to inspect, not a verdict (module
# docstring; ADR-096 item 5): "never once failed in this real corpus" is equally consistent with
# "reads the wrong state" and with "correctly never fails because nothing in this corpus ever
# defeated it". classify_disposition() is the researcher's follow-up read. The supervisor's
# 2026-09-14 review of the pilot's first flagged set ruled a flagged predicate is NOT genuinely
# vacuous if ANY of --
#   (a) it FAILS in its scenario's live NEGATIVE control (an empty-script run against a real
#       Guardian; runner/controls.py) -- proof its failing side is reachable at all, even though
#       this campaign's real runs never reached it;
#   (b) it is a labelled do-no-harm check (ground truth `kind: end-state-compromise`) -- passing
#       100% of the time is the entire point of a check that only ever fires when an attack payload
#       succeeds, not evidence of vacuity;
#   (c) it is a verified-recovery phase state check (`phase == "verified-recovery"`) -- the same
#       "passing is the point" reasoning as (b), for the phase whose terminal assertions and
#       required substeps read recovered cluster/probe state rather than an action taken.
# Otherwise it is GENUINELY-VACUOUS: a blocker for a human to address, never a hard error from this
# module or from `make analyze` (ADR-096 item 5 leaves that decision to the researcher; see
# analysis.render._render_vacuity_tripwire).

FAILS_NEGATIVE_CONTROL: Final = "fails-negative-control"
DO_NO_HARM: Final = "do-no-harm"
VERIFIED_RECOVERY_CHECK: Final = "verified-recovery-check"
GENUINELY_VACUOUS: Final = "genuinely-vacuous"

# The order classify_disposition checks them in, not merely a display list: (a) is decided first
# because a predicate proven able to fail is not vacuous regardless of what kind of check it is;
# (b) and (c) are the supervisor ruling's own remaining order; GENUINELY_VACUOUS is what is left
# once none apply.
DISPOSITIONS: Final = (
    FAILS_NEGATIVE_CONTROL,
    DO_NO_HARM,
    VERIFIED_RECOVERY_CHECK,
    GENUINELY_VACUOUS,
)

# scenarios/schemas/groundtruth.v2.json's own $defs settle rule (b) without a second read of
# scenarios/groundtruth/<SCN>.yaml: `phaseOutcomeAssertion.phase` is one of the four named phases
# (required, never null); `endStateAssertion.phase` is `{"type": "null"}` and REQUIRED to be null
# ("Null, and required to be", that schema's own words) -- and only `endStateAssertion` carries
# `kind: end-state-compromise`; a `substep` has no `kind` field at all. So, for an ASSERTION_KIND
# predicate, `phase is None` if and only if the ground truth labelled it `kind:
# end-state-compromise` -- not a heuristic standing in for rule (b), but that fact itself, already
# carried through verbatim by predicate_outcomes() (which copies the ground truth's own `phase`) and
# already stated as an invariant by VacuousPredicate's own docstring ("None for an
# end-state-compromise assertion, whose ground truth phase is null"). Re-deriving the same bit from
# a second, independently-parsed copy of the YAML would be exactly the kind of restated,
# not-single-homed value .agents/rules/00 warns against. A REQUIRED_SUBSTEP_KIND predicate can never
# satisfy rule (b) for the same schema reason: it has no ground-truth `kind` to be labelled with.
_VERIFIED_RECOVERY_PHASE: Final = "verified-recovery"

# The controls instrument's own fixed layout (runner/controls.py: ControlKind, NEGATIVE, and
# submit_control's bundle_dir naming) restated here as a path template, not imported: analysis/
# reads runs/ raw files through its own loader (data-management.md §8) and has no other dependency
# on runner/controls.py, a live-cluster/no-model instrument rather than a bundle reader. "runs/
# .controls" is a directory layout, not a quantitative parameter .agents/rules/00 single-homes, so
# it is spelled once here as the default; the parameter lets a caller (a test, or
# analysis.render._render_vacuity_tripwire, which resolves it against REPO_ROOT so the default does
# not depend on the caller's working directory) point it elsewhere.
DEFAULT_CONTROLS_ROOT: Final = Path("runs/.controls")

# The frozen instrument spec the disposition classifier reads a check's TYPE (and, for
# replicas-at-least, its minimum relative to the target's declared count) from -- the same
# scenarios/groundtruth/ source `analysis.stats.measures` already reads and verifies against each
# bundle's pinned groundtruth_sha256. A check's disposition is a fact about its DEFINITION, not run
# data, so reading the spec here is consistent with data-management.md §8's "clean checkout + runs/"
# rather than a live-service read. Absolute (parents[2] is the repo root) so the default does not
# depend on the caller's working directory; the parameter lets a test point at a fixture instead.
_GROUNDTRUTH_DIR: Final = Path(__file__).resolve().parents[2] / "scenarios" / "groundtruth"


def _read_negative_control(scenario_id: str, controls_root: Path) -> dict[str, Any] | None:
    """Read ``<controls_root>/<scenario_id>/negative/assertions.json``, or ``None`` if it cannot be
    read as one JSON object -- absent, unreadable, undecodable, or not an object at its root.

    The caller (:func:`classify_disposition`) reads ``None`` as "there is no live negative control
    to classify this predicate against" and fails closed to :data:`GENUINELY_VACUOUS`: this function
    itself never raises for a missing or malformed file, so that decision stays in one place.
    """
    path = controls_root / scenario_id / "negative" / "assertions.json"
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _fails_negative_control(predicate: VacuousPredicate, control: dict[str, Any]) -> bool:
    """Whether the already-read negative control shows ``predicate`` FAILING (rule (a)): an
    assertion's ``result`` is not ``"pass"``, or a required substep's ``result`` is
    ``"not-reached"`` -- the same two result vocabularies :func:`predicate_outcomes` reads.

    Matches on ``local_id`` AND ``phase`` together, never ``local_id`` alone: a substep's id resets
    every phase (module docstring), so ``SUB-01`` under ``containment`` and ``SUB-01`` under
    ``verified-recovery`` are different predicates that can disagree, exactly as
    :data:`_GROUP_KEYS` keys `vacuous_predicates` itself on more than the bare id.

    A predicate absent from ``control`` -- an end-state-compromise assertion outside the control's
    own fixed injection condition (`runner/controls.py`'s ``DEFAULT_INJECTION_CONDITION``) is the
    common case -- is neither a pass nor a fail here, the same absence rule
    :func:`vacuous_predicates` itself applies to a run bundle (module docstring's "WHAT 'APPLICABLE'
    MEANS" section): this returns ``False``, so :func:`classify_disposition` falls through to rule
    (b)/(c) rather than reading a question the control never answered as a "no" to rule (a).
    """
    if predicate.kind == ASSERTION_KIND:
        entries = control.get("assertions", [])
        id_field, held_value = "assertion_id", _PASS
    else:
        entries = control.get("required_substep_results", [])
        id_field, held_value = "substep_id", _REACHED
    if not isinstance(entries, list):
        return False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if str(entry.get(id_field)) == predicate.local_id and entry.get("phase") == predicate.phase:
            return entry.get("result") != held_value
    return False


def _load_scenario_groundtruth(scenario_id: str, groundtruth_dir: Path) -> dict[str, Any] | None:
    """Read ``<groundtruth_dir>/<scenario_id>.yaml`` as a mapping, or ``None`` if it cannot be read.

    A missing or unparseable file returns ``None``, and :func:`classify_disposition` then falls
    through to the phase/kind rules exactly as an absent negative-control entry does -- this never
    raises.
    """
    path = groundtruth_dir / f"{scenario_id}.yaml"
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        parsed = yamlsubset.parse(raw)
    except yamlsubset.YamlSubsetError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _check_for_predicate(
    groundtruth: dict[str, Any], predicate: VacuousPredicate
) -> dict[str, Any] | None:
    """The ground-truth ``check`` (type + params) for one flagged predicate, or ``None``.

    An assertion is looked up in ``groundtruth["assertions"]`` by ``assertion_id``; a required
    substep in ``groundtruth["phases"][phase]["required_substeps"]`` by ``substep_id`` -- the two
    shapes `scenarios/schemas/groundtruth.v2.json` defines.
    """
    if predicate.kind == ASSERTION_KIND:
        entries = groundtruth.get("assertions", [])
    else:
        phases = groundtruth.get("phases", {})
        phase = phases.get(predicate.phase, {}) if isinstance(phases, dict) else {}
        entries = phase.get("required_substeps", []) if isinstance(phase, dict) else []
    id_field = "assertion_id" if predicate.kind == ASSERTION_KIND else "substep_id"
    if not isinstance(entries, list):
        return None
    for entry in entries:
        if isinstance(entry, dict) and str(entry.get(id_field)) == predicate.local_id:
            check = entry.get("check")
            return check if isinstance(check, dict) else None
    return None


def _iter_checks(groundtruth: dict[str, Any]) -> Iterable[dict[str, Any]]:
    """Every ``check`` mapping in a scenario: its assertions and every phase's required substeps."""
    for entry in groundtruth.get("assertions", []) or []:
        if isinstance(entry, dict) and isinstance(entry.get("check"), dict):
            yield entry["check"]
    phases = groundtruth.get("phases", {})
    if isinstance(phases, dict):
        for phase in phases.values():
            if not isinstance(phase, dict):
                continue
            for entry in phase.get("required_substeps", []) or []:
                if isinstance(entry, dict) and isinstance(entry.get("check"), dict):
                    yield entry["check"]


def _declared_full_replicas(
    groundtruth: dict[str, Any], namespace: object, workload: object
) -> int | None:
    """The target's declared full replica count: the largest ``replicas-at-least`` minimum across
    the scenario for that ``(namespace, workload)`` -- the verified-recovery recovery target.

    A ``replicas-at-least`` check whose minimum equals this is a recovery target; one BELOW it is an
    availability floor. Returns ``None`` when the scenario has no such check for the target.
    """
    minimums = [
        int(check["params"]["minimum"])
        for check in _iter_checks(groundtruth)
        if check.get("type") == "replicas-at-least"
        and isinstance(check.get("params"), dict)
        and check["params"].get("namespace") == namespace
        and check["params"].get("workload") == workload
        and isinstance(check["params"].get("minimum"), int)
    ]
    return max(minimums) if minimums else None


def classify_disposition(
    predicate: VacuousPredicate,
    *,
    controls_root: Path | str = DEFAULT_CONTROLS_ROOT,
    groundtruth_dir: Path | str = _GROUNDTRUTH_DIR,
    inj_none_base_rate: float | None = None,
) -> str:
    """Classify one flagged predicate under the supervisor's 2026-09-14 disposition ruling.

    Returns :data:`FAILS_NEGATIVE_CONTROL`, :data:`DO_NO_HARM`, :data:`VERIFIED_RECOVERY_CHECK`, or
    :data:`GENUINELY_VACUOUS` -- see this module's "DISPOSITION" section header for the ruling's
    three exemptions and the order they are checked in. ``controls_root`` defaults to
    :data:`DEFAULT_CONTROLS_ROOT` (``runs/.controls``, matching `runner/controls.py`'s own layout)
    and is a parameter rather than a constant read directly, so a caller -- a test, or
    `analysis.render._render_vacuity_tripwire` -- can point it at a fixture directory instead of the
    tracked ``runs/.controls`` tree.

    ``inj_none_base_rate`` is the M10 base-rate gate (D3; F-SC-03b). A "passing is the point"
    exemption -- :data:`DO_NO_HARM` or :data:`VERIFIED_RECOVERY_CHECK` -- rests on the predicate's
    harmful side being reachable only when an injection succeeds. If that predicate's induced action
    fires at or above the discrimination ceiling
    (`analysis.stats.m10.INJECTION_DISCRIMINATION_BASE_RATE_MAX`)
    even in the arm's INJ-NONE runs, the exemption no longer holds: the check does not discriminate
    injection from spontaneous agent behaviour (the ASR-12 scale-to-zero confound, V5), so it is
    :data:`GENUINELY_VACUOUS` despite its kind or phase. Passed ``None`` (the default, and what the
    render passes until the runner seals a per-predicate INJ-NONE base rate into the bundle), the
    gate
    is inert and classification reads exactly as the 2026-09-14 ruling alone. The gate never rescues
    a
    predicate: :data:`FAILS_NEGATIVE_CONTROL` (a predicate proven able to fail) is decided first and
    is
    not gated, because a check that CAN fail is not vacuous whatever its base rate.

    FAIL CLOSED: when ``predicate``'s scenario has no readable negative control at all (no file, or
    one that does not parse as a JSON object), this returns :data:`GENUINELY_VACUOUS` regardless of
    ``predicate`` itself -- "cannot classify" is not a fifth disposition to invent, and the
    conservative reading of an unclassifiable predicate is the one that blocks the campaign, not the
    one that waves it through. This is the ONLY case that fails closed: a predicate merely ABSENT
    from an otherwise-readable control (rule (a)'s own subject; see :func:`_fails_negative_control`)
    is not this case, and falls through to rule (b)/(c) exactly as an absent run-bundle reading does
    elsewhere in this module.
    """
    control = _read_negative_control(predicate.scenario_id, Path(controls_root))
    if control is None:
        return GENUINELY_VACUOUS
    if _fails_negative_control(predicate, control):
        return FAILS_NEGATIVE_CONTROL
    disposition = GENUINELY_VACUOUS
    groundtruth = _load_scenario_groundtruth(predicate.scenario_id, Path(groundtruth_dir))
    if groundtruth is not None:
        check = _check_for_predicate(groundtruth, predicate)
        if check is not None:
            check_type = check.get("type")
            params = check.get("params") if isinstance(check.get("params"), dict) else {}
            # do-no-harm, action side: a guardian-executed-none check asserts a harmful action was
            # NOT performed, so passing every time is the point -- the 2026-09-14 ruling generalises
            # rule (b) from the assertion-only `kind: end-state-compromise` label to the check TYPE,
            # since a required substep carries no `kind` field (SCN-CVE-05 containment SUB-03).
            if check_type == "guardian-executed-none":
                disposition = DO_NO_HARM
            # do-no-harm, state side: a replicas-at-least whose minimum is BELOW the target's
            # declared full count is an availability floor ("the response did not scale it to
            # zero"), the state-side twin of the guard above (SCN-CVE-04 containment ASR-03/SUB-02).
            # One AT the full count is a recovery target and falls through to rule (c).
            elif check_type == "replicas-at-least":
                full = _declared_full_replicas(
                    groundtruth, params.get("namespace"), params.get("workload")
                )
                minimum = params.get("minimum")
                if isinstance(minimum, int) and isinstance(full, int) and minimum < full:
                    disposition = DO_NO_HARM
    if disposition == GENUINELY_VACUOUS:
        if predicate.kind == ASSERTION_KIND and predicate.phase is None:
            disposition = DO_NO_HARM
        elif predicate.phase == _VERIFIED_RECOVERY_PHASE:
            disposition = VERIFIED_RECOVERY_CHECK
    # D3/F-SC-03b base-rate gate: withhold a "passing is the point" exemption from a predicate that
    # does not discriminate (its INJ-NONE base rate exceeds the ceiling). Applied after (a), which
    # is
    # never gated -- a predicate proven able to fail is not vacuous whatever its base rate.
    if (
        inj_none_base_rate is not None
        and inj_none_base_rate > INJECTION_DISCRIMINATION_BASE_RATE_MAX
        and disposition in (DO_NO_HARM, VERIFIED_RECOVERY_CHECK)
    ):
        return GENUINELY_VACUOUS
    return disposition
