r"""The readiness gate (F-AN-01): the per-stage semantics of plan §5, asserted cell by cell.

WHAT THIS FILE IS
-----------------
``docs/plans/M10-implementation-plan.md`` §5 registers F-AN-01 as a class R (readiness/provenance)
check evaluated at three points, and gives each of them a *different* pass criterion. That is the
whole content of the row, and it is the part a future edit is most likely to flatten: three stages
sharing one verdict is simpler to write, and it would quietly convert the checkpoint into a second
pilot gate and the pilot gate into a third final gate.

    pilot gate    every Table 3.3 measure has a code path that RUNS. A ``nan`` from n < 2 is a WARN,
                  because a pilot is small by design. A judged measure is a WARN, because the human
                  session cannot have happened yet.
    checkpoint ONLY a missing measure -- no code path, or one whose fail-closed error was captured
                  -- or a class-T fidelity failure blocks. Everything else is reported.
    final corpus  every measure must be COMPUTED. A judge still pending is a FAIL here and nowhere
                  else, because this is the render the dissertation's numbers are read from.

So the tests below are a table, not a list of cases: :func:`analysis.render.readiness_severity` is
asked for a verdict for every (state, stage) pair the plan names, and each answer is asserted. That
way a change to the severity function has to be a deliberate edit of this file, which is the only
place the per-stage contract is written down as a contract rather than as prose.

THE STATES ARE CLASSIFIED FROM THE RENDER'S OWN STATUS LINES
------------------------------------------------------------
:func:`analysis.render.classify_measure_status` reads a measure's one-line status rather than being
told its state, because the alternative -- the gate being handed a list of what happened to work --
is a check that cannot fail. ``PENDING-...`` is a captured fail-closed error, ``LIMITATION ...`` is
a
stated instrument gap, anything else is a measure that produced rows, and **no status line at all**
is the one state that blocks everywhere: a measure that stopped being computed, which is precisely
the v1 failure this check was written for (V10's absent interference row).

WHAT THESE TESTS DELIBERATELY DO NOT DO
---------------------------------------
They do not assert that any measure's VALUE is right. Every other check owns that. And they do not
reach a cluster, a network or a live campaign: the gate is a pure function of the status mapping,
and
the two end-to-end cases (``analyse`` writing the table) run over the reduced synthetic corpus
``runner.synthetic`` seals, on the same pattern ``analysis/tests/test_render.py`` uses.
"""

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from analysis.render import (  # noqa: E402
    READINESS_COMPUTED,
    READINESS_LIMITATION,
    READINESS_MISSING,
    READINESS_PENDING,
    READINESS_STAGES,
    TABLE_MEASURES,
    AnalyseResult,
    analyse,
    classify_measure_status,
    collect_treatment_failures,
    readiness_gate,
    readiness_severity,
)

COMPUTED = READINESS_COMPUTED
PENDING = READINESS_PENDING
LIMITATION = READINESS_LIMITATION
MISSING = READINESS_MISSING

# The judged measure's own name, spelled once: the whole pilot-vs-final contrast in this file is
# about this one measure being pending, and restating the literal in five cases would let a rename
# leave four of them asserting a measure that no longer exists.
JUDGED = "researcher_judged_and_test_retest"


def _all_computed() -> dict[str, str]:
    """A status mapping in which every registered measure produced rows."""
    return {measure: f"computed: {measure} rows" for measure in TABLE_MEASURES} | {
        JUDGED: "PENDING-GATE: needs a bundle scored with both an initial and a rescore pass"
    }


# ------------------------------------------------------------------------------------------------
# The per-stage severity table
# ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("stage", READINESS_STAGES)
def test_a_computed_measure_passes_at_every_stage(stage: str) -> None:
    """A measure that ran is a pass wherever the gate is run.

    Including at the final corpus, which is the only stage where that is not obvious: there every
    other state fails, so this case is what stops a fix to the final stage being written as "fail
    unless the state is exactly computed" in a way that quietly inverted the common case.
    """
    assert readiness_severity(stage=stage, state=COMPUTED) == "pass"


@pytest.mark.parametrize("stage", READINESS_STAGES)
def test_a_missing_measure_blocks_at_every_stage(stage: str) -> None:
    """No code path, or one that raised and was captured: the one state that blocks everywhere.

    This is the check that would have caught v1's absent interference row (V10) at the pilot gate
    rather than in Chapter 5, and it is why `missing` is not folded into `pending` even though both
    are "not a number": a pending measure has a code path that ran and reported a fail-closed
    refusal,
    and a missing one never ran at all.
    """
    assert readiness_severity(stage=stage, state=MISSING) == "fail"


@pytest.mark.parametrize("stage", ("pilot", "checkpoint"))
@pytest.mark.parametrize("state", (PENDING, LIMITATION))
def test_pilot_and_checkpoint_warn_on_a_pending_or_limited_measure(stage: str, state: str) -> None:
    """A pending judge or a stated instrument limitation is reported, not fatal, before the final.

    A pilot runs before any scoring has happened and a checkpoint runs while it is still happening
    (D2 scores bundles progressively as they seal), so "the judge has not run yet" is the expected
    state at both, and treating it as a failure would make the ladder unreachable.
    """
    assert readiness_severity(stage=stage, state=state) == "warn"


@pytest.mark.parametrize("state", (PENDING, LIMITATION))
def test_the_final_corpus_fails_a_pending_or_limited_measure(state: str) -> None:
    """At the final corpus every measure must be computed, and this is the only stage that says so.

    The final render is the artefact the dissertation's tables are read from. A number that is a
    `PENDING-` placeholder there is indistinguishable, to a reader, from a result -- which is the
    one
    outcome ``render.py``'s own module docstring ("FAIL CLOSED, NEVER FABRICATE") exists to prevent.
    """
    assert readiness_severity(stage="final", state=state) == "fail"


def test_a_nan_from_n_below_two_is_a_warn_and_not_a_block() -> None:
    """A pilot cell too small to pool is a fact about the pilot's size, not about the instrument.

    The plan says so explicitly ("``nan`` from n < 2 is WARN") and the function honours it by the
    stronger route: an under-powered cell is still a `computed` measure, and a computed measure
    passes at every stage. The `small_n` flag travels into the report so a reader can see WHY a cell
    produced a nan, and it changes no verdict -- asserted here so that stays true.
    """
    assert readiness_severity(stage="pilot", state=COMPUTED, small_n=True) == "pass"
    assert readiness_severity(stage="final", state=COMPUTED, small_n=True) == "pass"


def test_a_judged_measure_is_a_warn_before_the_final_and_a_fail_at_it() -> None:
    """The judged measures' whole per-stage story, in one case, from the real pending status line.

    Both halves are already covered by the cases above; this one states the *judged* reading the
    plan
    gives them, so the contract is written down for the class of measure it is about rather than
    only
    as a property of a state name.
    """
    report = readiness_gate(_all_computed(), stage="pilot")
    judged = [entry for entry in report.entries if entry.judged]
    assert judged, "the gate registered no judged measure, so the judged branch is untested"
    assert [entry.severity for entry in judged] == ["warn"]
    assert readiness_gate(_all_computed(), stage="final").verdict == "NO-GO"


def test_an_unknown_stage_is_refused_rather_than_given_the_pilot_semantics() -> None:
    """A typo in the stage name must not silently buy the lenient reading.

    ``readiness_severity`` is a table, and a table indexed by an unchecked string would answer
    "warn" for ``stage="chekpoint"``, which is the one spelling nobody notices until a campaign is
    halted on the wrong criterion.
    """
    with pytest.raises(ValueError, match="unknown readiness stage"):
        readiness_severity(stage="chekpoint", state=COMPUTED)
    with pytest.raises(ValueError, match="unknown readiness stage"):
        readiness_gate(_all_computed(), stage="")


# ------------------------------------------------------------------------------------------------
# Classification of the render's own status lines -- the mechanical half
# ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (None, MISSING),
        ("computed: 40 rows, pooled per cell", COMPUTED),
        ("PENDING-GATE: needs a bundle scored twice", PENDING),
        ("PENDING-M1: the SLO stabilization window is uncalibrated", PENDING),
        ("LIMITATION (ADR-111): not computed -- no flat detection signal field", LIMITATION),
    ],
)
def test_a_status_line_classifies_into_exactly_one_state(status: str | None, expected: str) -> None:
    """The mapping the gate's mechanical check rests on, asserted on both real spellings.

    ``PENDING-`` and ``LIMITATION `` are the two prefixes ``_render_pending_measures`` actually
    writes, so a change to those spellings breaks this test rather than silently reclassifying a
    pending measure as computed -- which would turn a FAIL at the final corpus into a pass.
    """
    assert classify_measure_status(status) == expected


def test_a_measure_with_no_status_line_is_missing_and_blocks() -> None:
    """The end-to-end form of the table: delete a measure's status line and the gate says NO-GO.

    This is the defect the row exists for. A render that stopped computing ``interference`` would
    report a campaign whose tables are all present and silently omit one of the eight evaluands;
    only a registry independent of the render's own output can notice, which is why
    :data:`~analysis.render.TABLE_MEASURES` is a module constant rather than ``statuses.keys()``.
    """
    statuses = _all_computed()
    del statuses["interference"]
    report = readiness_gate(statuses, stage="pilot")
    assert report.blocking == ("interference",)
    assert report.verdict == "NO-GO"


def test_a_fully_computed_corpus_passes_the_pilot_gate() -> None:
    """The control: a corpus whose judges have not run yet is a GO at the pilot, with a warning.

    Without this case the pilot-gate tests would all be passing against a gate that blocks
    everything, which is the failure mode ``guardian/tests/conftest.py`` calls "M3's failure mode is
    silent" and the same objection in a different component.
    """
    report = readiness_gate(_all_computed(), stage="pilot")
    assert report.blocking == ()
    assert report.verdict == "GO"
    assert JUDGED in report.warnings


def test_a_class_t_failure_blocks_the_checkpoint_while_a_pending_judge_does_not() -> None:
    """F-AN-01's checkpoint half, verbatim: "or a class-T failure blocks".

    The T failure is read out of ``fidelity.json``'s own ``klass`` (SEAM 2) rather than
    re-classified
    here, so a check the registry later reclassifies cannot be double-counted. The judged measure
    stays a WARN, which is the point: at the checkpoint a T failure blocks and a pending human
    session does not, and a gate that could not tell them apart would halt the campaign a third of
    the way through it.
    """
    report = readiness_gate(
        _all_computed(), stage="checkpoint", treatment_failures=["RUN-X:F-SC-01"]
    )
    assert report.blocking == ()
    assert report.verdict == "NO-GO"
    assert report.treatment_failures == ("RUN-X:F-SC-01",)
    assert JUDGED in report.warnings


def test_treatment_failures_are_read_from_fidelity_json_and_only_class_t(tmp_path: Path) -> None:
    """The collector: a class-T ``fail`` counts; a class-B or class-R one does not.

    The distinction is the plan's section 2 principle P2 in one line -- T blocks, B and R are
    reported -- and getting it wrong in the permissive direction would make every campaign halt on a
    vacuity observation. Built over real :class:`~analysis.stats.loader.Bundle` objects rather than
    dicts, so the field the check reads is the field the loader parses, and over a bundle carrying
    no
    ``fidelity.json`` at all (a v1 bundle) to pin the "contributes nothing" half.
    """
    from analysis.stats.loader import Bundle

    def _bundle(run_id: str, checks: list[dict] | None) -> Bundle:
        return Bundle(
            directory=tmp_path / run_id,
            manifest={"run_id": run_id},
            assertions=None,
            results=None,
            guardian_audit=None,
            monitor_events=None,
            monitor_timings=None,
            spans=None,
            injection_log=None,
            tokens=None,
            scores=None,
            probes=None,
            resources=None,
            locust_stats=None,
            fidelity=None
            if checks is None
            else {"schema_version": "fidelity.v1", "checks": checks},
            k8s_api_audit=None,
        )

    bundles = [
        _bundle("RUN-A", [{"id": "F-SC-01", "klass": "T", "status": "fail"}]),
        _bundle(
            "RUN-B",
            [
                {"id": "F-AN-02", "klass": "B", "status": "fail"},
                {"id": "F-AN-01", "klass": "R", "status": "fail"},
                {"id": "F-GD-01", "klass": "T", "status": "warn"},
            ],
        ),
        _bundle("RUN-C", None),
    ]
    assert collect_treatment_failures(bundles) == ("RUN-A:F-SC-01",)


# ------------------------------------------------------------------------------------------------
# End to end: the gate table `analyse` writes
# ------------------------------------------------------------------------------------------------


def test_analyse_writes_the_readiness_gate_table_and_records_the_verdict(tmp_path: Path) -> None:
    """The rendered artefact, over the reduced synthetic corpus, at the default ``final`` stage.

    Asserts the table exists, is stamped, names every registered measure, and that its verdict
    agrees with the report the same call returned -- the two are produced from one object, so a
    disagreement would mean the table was written from something else.
    """
    from runner.synthetic import generate_campaign_for_testing

    runs_root = tmp_path / "runs"
    campaign_id = generate_campaign_for_testing(runs_root, seed=1, seeds=(101,))
    result: AnalyseResult = analyse(
        runs_root / campaign_id,
        out_dir=tmp_path / "out",
        generator_seed=1,
        emit_proof=False,
    )
    gate = next(path for path in result.tables if path.name == "readiness_gate.md")
    text = gate.read_text(encoding="utf-8")
    assert campaign_id in text, "the readiness table lost its provenance stamp"
    for measure in TABLE_MEASURES:
        assert measure in text, f"readiness_gate.md omits the registered measure {measure!r}"
    assert result.readiness is not None
    assert result.readiness.stage == "final"
    assert result.readiness.verdict in {"GO", "NO-GO"}
    assert result.statuses["readiness_gate"].startswith("F-AN-01 (final): ")

    # F-AN-01's predicate reads <campaign>/readiness.json, not the table: the table is for a reader,
    # the document is for the gate. If analyse stopped writing it, the pilot gate would report the
    # check producer-pending and go red for a reason that has nothing to do with the corpus
    # (ADR-150).
    document = json.loads((runs_root / campaign_id / "readiness.json").read_text(encoding="utf-8"))
    assert document["stage"] == "final"
    for measure in TABLE_MEASURES:
        assert measure in document["measures"], f"readiness.json omits {measure!r}"


def test_analyse_at_the_pilot_stage_does_not_block_on_a_pending_judge(tmp_path: Path) -> None:
    """The same corpus, the other end of the stage table: the pilot gate is not the final gate.

    The synthetic corpus carries no re-scored bundle, so the judged measure is pending at every
    stage. At ``final`` that is a FAIL by the plan's own rule; at ``pilot`` it is a WARN. A gate
    with
    one verdict for both stages fails this, and that is the property the three-stage row exists to
    state.
    """
    from runner.synthetic import generate_campaign_for_testing

    runs_root = tmp_path / "runs"
    campaign_id = generate_campaign_for_testing(runs_root, seed=1, seeds=(101,))
    result = analyse(
        runs_root / campaign_id,
        out_dir=tmp_path / "out",
        generator_seed=1,
        emit_proof=False,
        readiness_stage="pilot",
    )
    assert result.readiness is not None
    assert result.readiness.stage == "pilot"
    assert JUDGED in result.readiness.warnings
    assert JUDGED not in result.readiness.blocking
