r"""The analysis layer's fidelity checks: F-AN-01 (readiness), F-AN-02 (observed vacuity), F-AN-03
(storage).

WHY THE ANALYSIS LAYER HAS FIDELITY CHECKS AT ALL
-------------------------------------------------
Because a measure that cannot be computed is not a null result. v1's ``render_manifest.md`` carried
no interference row (``analysis/render.py`` called ``interference()`` only to catch its failure) and
reported detection precision and recall as LIMITATION, and ``storage_bytes`` was 0 in every row on
both sides of the RQ4 contrast while the same pipeline's ``cpu_cores`` and ``mem_bytes`` were 93-97%
non-zero. None of those is a finding about the framework; every one of them is a hole in the
instrument, and P1's "checked, not assumed" applies to the measurement apparatus as much as to the
arms.

``F-AN-01`` (R) -- the READINESS GATE, with the per-stage semantics plan section 5 states
---------------------------------------------------------------------------------
One check, three stages, three different rules, and the differences are the content of the check:

* **pilot gate.** Every Table 3.3 measure has a CODE PATH that runs. A ``nan`` from n < 2 is a
  ``warn``, not a failure -- a pilot cell has one seed by construction and refusing a pilot over its
  own design would make the ladder unable to pass. A judged measure is a ``warn``: D2's sampling
  means
  scoring proceeds as bundles seal, and a pending score is the expected state of a pilot.
* **checkpoint.** Only a MISSING measure -- a code path that is absent or that raises -- blocks, and
  a class-T failure blocks. Judged measures are ``warn``. This is after the first interleave round,
  so
  n is larger and the n < 2 floor has stopped applying; a measure that is merely imprecise is not a
  blocker at a checkpoint.
* **final corpus.** Every measure must be COMPUTED and a pending judged measure is a FAILURE,
because
  the dissertation's reported tables are built from it and a table with a hole in it is not a
  result.

The check reads ``<campaign>/readiness.json``, the artefact ``analysis/render.py`` writes, rather
than
recomputing any measure: a second implementation of "is this measure available" would be free to
disagree with the renderer about what it renders, and the renderer's answer is the one a reader of
the
dissertation will see. Its absence is a ``skip`` at the seal stage -- a single bundle has no
readiness
-- and a ``fail`` at a gate, because a gate with no readiness artefact has not been run.

``F-AN-02`` (B) -- OBSERVED VACUITY
-----------------------------------
"No predicate never fails or always fails across the pilot", reported per arm in the campaign. Class
B because vacuity is a property of the PREDICATES' behaviour under the arms, which is behaviour, and
which becomes visible only once treatments are proven delivered. It is not a halt: a campaign in
which
one predicate is vacuous is a campaign with a finding about that predicate, and the symmetric
classifier (WS-6's ``analysis/stats/vacuity.py``) reports it. What makes it a class-B PILOT blocker
is
that at the pilot a vacuous predicate means the ladder is measuring nothing for it.

``F-AN-03`` (T) -- STORAGE IS COLLECTED
---------------------------------------
D15: ``infra/collectors/resource_collector.py``'s ``container_fs_usage_bytes`` query returns nothing
on this cluster, so ``storage_bytes`` is 0 in every row of every v1 bundle while the CPU and memory
series beside it are populated. Reporting that as zero BYTES would be a false measurement -- it says
the containers used no storage, which is not true and is not what the collector observed. The
protocol
allows one of two outcomes (D15): a working source, or storage reported as LIMITATION "not
collected"
(ADR-111 style), NEVER as zero.

This check is class T and stage ``P0-live`` because the alternative to a T failure is a limitation,
and
a limitation is a research finding rather than a silent zero -- but only if somebody establishes
that
no source works, and that is exactly what a P0-live probe is for. The predicate therefore checks the
COLLECTED SERIES: at least one row of ``resources.csv`` with a positive ``storage_bytes``. The
limitation path is a DIFFERENT artefact -- ``analysis`` writing "not collected" -- and this check
refuses to accept a bundle that claims a limitation while carrying a collector that reports zero, so
the two cannot both be true.
"""

from __future__ import annotations

import json
from typing import Final

from runner.fidelity import (
    STAGE_CAMPAIGN,
    STAGE_CHECKPOINT,
    STAGE_FINAL,
    STAGE_LOOP,
    STAGE_OFFLINE,
    STAGE_P0_LIVE,
    STAGE_PILOT,
    STAGE_PILOT_GATE,
    STAGE_SEAL,
    BundleView,
    CheckOutcome,
    FidelityCheck,
)

__all__ = ("CHECKS", "readiness_document")

_OWNER: Final = "analysis"

#: The campaign-level artefact ``analysis/render.py`` writes, and the only thing this module reads.
#: Named here because three modules name it (this check, the CLI, and the renderer) and a spelling
#: difference would make the gate report on nothing and pass.
READINESS_FILENAME: Final = "readiness.json"

#: The key the renderer writes the per-measure availability map under.
READINESS_MEASURES_KEY: Final = "measures"

#: The key under which the renderer records the judged (researcher-scored) measures' state, which
#: has
#: its own per-stage rule: WARN at the pilot and the checkpoint, FAIL at the final corpus (D2's
#: progressive scoring means a pending score is normal until the corpus is closed).
READINESS_JUDGED_KEY: Final = "judged"


def readiness_document(view: BundleView) -> dict | None:
    """The campaign's ``readiness.json``, or ``None`` when it is absent or malformed."""
    path = view.campaign_file(READINESS_FILENAME)
    if path is None:
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def f_an_01_readiness_gate(view: BundleView) -> CheckOutcome:
    """The readiness gate, with pilot-gate / checkpoint / final semantics.

    The stage is NOT a parameter of the check -- it is the stage the check is EVALUATED at, which
    the
    registry supplies and which therefore differs per result line in ``fidelity.json``. That is the
    mechanism that makes the per-stage semantics real rather than documented: evaluating the same
    predicate at ``pilot gate`` and at ``final`` reads the same artefact and applies three different
    rules to it.
    """
    document = readiness_document(view)
    stage = _stage_of(view)
    if document is None:
        if stage in (STAGE_SEAL, STAGE_LOOP, STAGE_OFFLINE, STAGE_P0_LIVE):
            return CheckOutcome.skipped(
                f"no {READINESS_FILENAME} in the campaign; the readiness gate is evaluated at the "
                "pilot gate, the checkpoint and the final corpus, not at a single bundle"
            )
        return CheckOutcome.failed(
            f"the campaign records no {READINESS_FILENAME}, so the readiness gate has not been run "
            "at "
            f"the {stage}. A gate that finds no artefact has not passed; it has not run"
        )
    measures = document.get(READINESS_MEASURES_KEY)
    if not isinstance(measures, dict) or not measures:
        return CheckOutcome.failed(
            f"{READINESS_FILENAME} carries no non-empty {READINESS_MEASURES_KEY!r} map, so no "
            "measure "
            "can be shown to have a code path that runs (v1: interference was never written and "
            "detection P/R was a LIMITATION)"
        )
    judged = document.get(READINESS_JUDGED_KEY)
    # `judged` maps a measure name to its state, so "pending" is an explicit per-entry verdict and
    # the
    # aggregate is computed rather than assumed. An absent map means no judged measure is declared
    # at
    # all, which is a renderer that has not been extended rather than a pilot that has none.
    pending = sorted(str(name) for name, state in (judged or {}).items() if str(state) != "scored")
    missing = sorted(
        str(name)
        for name, state in measures.items()
        if str(state) in ("missing", "absent", "error")
    )
    if missing:
        return CheckOutcome.failed(
            f"{len(missing)} measure(s) have no code path that runs or raised: {missing}. At the "
            f"{stage} a missing measure blocks, while a merely imprecise one does not"
        )
    if stage == STAGE_FINAL and pending:
        return CheckOutcome.failed(
            f"{len(pending)} judged measure(s) are still pending at the final corpus: {pending}. "
            "The "
            "dissertation's tables are built from them, and a table with a hole in it is not a "
            "result "
            "(D2, ADR-134)"
        )
    if pending:
        return CheckOutcome.warned(
            f"{len(pending)} judged measure(s) are pending at the {stage}: {pending}. D2's "
            "progressive scoring makes a pending judged measure expected here, so it is reported "
            "and "
            "not blocked"
        )
    if stage == STAGE_PILOT_GATE:
        imprecise = sorted(
            str(name) for name, state in measures.items() if str(state) in ("nan", "imprecise")
        )
        if imprecise:
            return CheckOutcome.warned(
                f"{len(imprecise)} measure(s) are nan from n < 2 at the pilot gate: {imprecise}. A "
                "pilot cell has one seed by construction, so this is reported rather than blocked"
            )
    return CheckOutcome.passed(
        f"every measure in {len(measures)} has a code path that runs and every judged measure is "
        f"scored, at the {stage}"
    )


def _stage_of(view: BundleView) -> str:
    """Which gate stage this evaluation is for.

    Read from the ``required_stage`` the registry stamps on the view, because a predicate that took
    the stage as an argument would have to be wrapped at every call site and the registry is the
    only
    thing that knows. The default is the pilot gate, the earliest stage at which a readiness verdict
    means anything.
    """
    return view.required_stage or STAGE_PILOT_GATE


def f_an_02_no_predicate_is_vacuous(view: BundleView) -> CheckOutcome:
    """Observed vacuity: no predicate never fails or always fails across the pilot; reported per arm
    in the campaign.

    Read from ``<campaign>/vacuity.json``, which ``analysis/stats/vacuity.py`` writes with its
    SYMMETRIC classifier (WS-6): both a never-failing and an always-failing predicate are vacuous,
    and
    the three ``do-no-harm`` exemption paths that used to cover every ``guardian-executed-none``
    check
    no longer cover a predicate whose INJ-NONE base rate exceeds the discrimination threshold. The
    per-arm breakdown is reported in the detail because a predicate vacuous in one arm and live in
    another is a different finding from one vacuous everywhere.
    """
    path = view.campaign_file("vacuity.json")
    if path is None:
        # producer-pending: the WS-6 vacuity roll-up that writes this file has not run (ADR-146).
        return CheckOutcome.producer_pending(
            "the campaign records no vacuity.json; vacuity is observed across the pilot's runs and "
            "is "
            "therefore a corpus property, not a bundle one"
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        return CheckOutcome.failed(f"vacuity.json is unreadable: {error}")
    if not isinstance(payload, dict):
        return CheckOutcome.failed("vacuity.json is not a JSON object")
    never = sorted(str(name) for name in payload.get("never_fails", []))
    always = sorted(str(name) for name in payload.get("always_fails", []))
    if never or always:
        by_arm = payload.get("by_arm", {})
        where = (
            ", ".join(f"{arm}: {len(names)}" for arm, names in sorted(by_arm.items())) or "no arms"
        )
        return CheckOutcome.failed(
            f"{len(never)} predicate(s) never fail and {len(always)} always fail ({where}). In v1 "
            "37 "
            "predicates never failed, and eradication sat near the floor in every arm (defect V26)"
        )
    checked = int(payload.get("predicates", 0) or 0)
    if not checked:
        return CheckOutcome.failed(
            "vacuity.json records no predicates at all, so vacuity is unassessed rather than "
            "absent; "
            "an empty corpus is refused rather than passed"
        )
    return CheckOutcome.passed(f"none of {checked} predicate(s) is vacuous")


def f_an_03_storage_is_collected_for_at_least_one_container(view: BundleView) -> CheckOutcome:
    """The resource collector reports non-zero storage for at least one probed container (D15).

    The predicate is deliberately weak in what it demands and strong in what it forbids: it does not
    require every row to be non-zero (a freshly created container genuinely has no writable layer,
    and
    requiring otherwise would produce a false failure), and it forbids a bundle in which NO row is.
    A bundle with no positive ``storage_bytes`` anywhere is a bundle whose storage series is the v1
    defect verbatim -- 0 in every row on both sides of the RQ4 contrast, with the CPU and memory
    series beside it populated, which is the signature of a query that returns nothing rather than
    of
    containers that stored nothing.
    """
    if not view.present("resources.csv"):
        return CheckOutcome.skipped(
            "resources.csv is absent; the completeness profile refuses this, and a baseline is "
            "measured too but not by this probe"
        )
    rows = view.resources()
    if not rows:
        return CheckOutcome.failed(
            "resources.csv holds no data row, so no container's storage was observed at all"
        )
    positive: list[str] = []
    for row in rows:
        raw = row.get("storage_bytes")
        try:
            value = int(raw) if raw is not None and raw != "" else 0
        except ValueError:
            continue
        if value > 0:
            positive.append(f"{row.get('namespace')}/{row.get('workload')}:{row.get('container')}")
    if not positive:
        return CheckOutcome.failed(
            f"no row of {len(rows)} reports a positive storage_bytes, while the CPU and memory "
            "series "
            "in the same rows are populated. That is a collector query that returns nothing, not a "
            "cluster that stored nothing; in v1 storage was 0 in every row on both sides of the "
            "RQ4 "
            "contrast (D15, defect V10). Report storage as LIMITATION 'not collected' (ADR-111 "
            "style) rather than as zero bytes"
        )
    return CheckOutcome.passed(
        f"{len(positive)} of {len(rows)} row(s) report positive storage, e.g. {positive[0]}"
    )


CHECKS: Final[tuple[FidelityCheck, ...]] = (
    FidelityCheck(
        id="F-AN-01",
        owner=_OWNER,
        klass={"pilot gate": "R", "checkpoint": "R", "final": "R"},
        stage=(STAGE_PILOT_GATE, STAGE_CHECKPOINT, STAGE_FINAL),
        summary=(
            "readiness gate. Pilot gate: every Table 3.3 measure has a code path that runs; nan "
            "from "
            "n < 2 is WARN; judged measures WARN. Checkpoint: only a missing measure (code path "
            "absent or raising) or a T failure blocks; judged measures WARN. Final corpus: every "
            "measure computed; judged measures FAIL if pending"
        ),
        predicate=f_an_01_readiness_gate,
        known_bad="v1: interference missing, P/R limitation, judged pending",
    ),
    FidelityCheck(
        id="F-AN-02",
        owner=_OWNER,
        klass={"pilot": "B", "campaign": "B"},
        stage=(STAGE_PILOT, STAGE_CAMPAIGN),
        summary=(
            "observed vacuity: no predicate never fails or always fails across the pilot; reported "
            "per arm in the campaign"
        ),
        predicate=f_an_02_no_predicate_is_vacuous,
        known_bad="37 never-failing predicates",
    ),
    FidelityCheck(
        id="F-AN-03",
        owner=_OWNER,
        klass={"P0-live": "T"},
        stage=(STAGE_P0_LIVE,),
        summary="the resource collector reports non-zero storage for at least one probed container "
        "(D15)",
        predicate=f_an_03_storage_is_collected_for_at_least_one_container,
        known_bad="storage 0 in every v1 row",
    ),
)
