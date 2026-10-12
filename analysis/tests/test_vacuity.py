r"""The campaign vacuity tripwire (ADR-096): flags a predicate that never once failed.

Builds a small hand-written fixture campaign -- a few real (``is_baseline: false``) run bundles
across two scenarios, using the same `write_bundle`/`load` helpers every other measure test in this
package uses (`analysis/tests/_helpers.py`), never `runner.bundle.seal_bundle`/`load_campaign`: the
vacuity functions read a plain ``Iterable[Bundle]``, exactly like every function in
`analysis.stats.measures`, so a sealed campaign directory is not needed to exercise them. Fixture
assertion and required-substep entries are written by hand (not through `_helpers.phase_outcome_
assertions`) so each run's exact `assertion_id`/`substep_id` set is chosen directly rather than
derived from list position -- the "absent from one run" case needs one run to omit an id another
run carries, which the position-derived helper cannot express safely.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from analysis.render import _render_vacuity_tripwire  # noqa: E402
from analysis.stats import Bundle  # noqa: E402
from analysis.stats.vacuity import (  # noqa: E402
    ASSERTION_KIND,
    DO_NO_HARM,
    FAILS_NEGATIVE_CONTROL,
    GENUINELY_VACUOUS,
    REQUIRED_SUBSTEP_KIND,
    VERIFIED_RECOVERY_CHECK,
    VacuousPredicate,
    classify_disposition,
    predicate_outcomes,
    vacuous_predicates,
)
from analysis.tests._helpers import load, write_bundle  # noqa: E402

# ADR-096's own example: a verified-recovery replicas-at-least check, and its sibling
# slo-probe-recovered check, both real SCN-CVE-04 assertion ids (scenarios/groundtruth/SCN-CVE-04.
# yaml). ASR-11 is that scenario's INJ-A end-state assertion (phase: null in ground truth).
_ASR_ALWAYS_PASSES = "ASR-05"
_ASR_FAILS_ONCE = "ASR-06"
_ASR_ABSENT_IN_ONE_RUN = "ASR-11"
_SUB_ALWAYS_REACHED = "SUB-03"
_SUB_NOT_REACHED_ONCE = "SUB-01"
_VERIFIED_RECOVERY = "verified-recovery"
_CONTAINMENT = "containment"


def _assertion(assertion_id: str, *, phase: str | None, result: str) -> dict:
    return {
        "assertion_id": assertion_id,
        "kind": "phase-outcome" if phase is not None else "end-state-compromise",
        "phase": phase,
        "result": result,
        "observed": "",
        "evaluated_at": "2026-09-14T00:00:00+00:00",
    }


def _substep(substep_id: str, *, phase: str, result: str) -> dict:
    return {
        "substep_id": substep_id,
        "phase": phase,
        "result": result,
        "observed": "",
        "evaluated_at": "2026-09-14T00:00:00+00:00",
    }


def _write_negative_control(
    controls_root: Path,
    scenario_id: str,
    *,
    assertions: list[dict] | None = None,
    required_substep_results: list[dict] | None = None,
) -> Path:
    """Write ``<controls_root>/<scenario_id>/negative/assertions.json`` -- the same shape
    `runner/controls.py`'s negative control writes (and `evaluate_control`'s own
    `write_run_assertions` call produces), by hand, on the pattern `_helpers.write_bundle` already
    uses for a run bundle's own `assertions.json`. Never goes through :func:`write_bundle`/`load`:
    a control lives under `runs/.controls/<SCN>/<positive|negative>/`, not inside a run bundle
    directory, and :func:`classify_disposition` reads it as a plain JSON file, not through
    :class:`~analysis.stats.loader.Bundle`.
    """
    directory = controls_root / scenario_id / "negative"
    directory.mkdir(parents=True, exist_ok=True)
    payload = {
        "run_id": f"RUN-G0-FULL-{scenario_id}-INJ-A-101",
        "scenario_id": scenario_id,
        "groundtruth_sha256": "0" * 64,
        "assertions": assertions or [],
        "required_substep_results": required_substep_results or [],
    }
    path = directory / "assertions.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _write_groundtruth(groundtruth_dir: Path, scenario_id: str, yaml_text: str) -> Path:
    """Write ``<groundtruth_dir>/<scenario_id>.yaml`` -- a fixture ground truth the disposition
    classifier reads a check's type/params from, so a test controls both the negative control and
    the check definition without depending on a real ``scenarios/groundtruth/`` file."""
    groundtruth_dir.mkdir(parents=True, exist_ok=True)
    path = groundtruth_dir / f"{scenario_id}.yaml"
    path.write_text(yaml_text, encoding="utf-8")
    return path


def _cve04_run(
    directory: Path,
    *,
    seed: int,
    asr06_result: str,
    include_asr11: bool,
    sub01_result: str,
) -> Bundle:
    """One SCN-CVE-04/G1-LOGONLY run. ``ASR-05`` and ``SUB-03`` always hold, by design."""
    assertions = [
        _assertion(_ASR_ALWAYS_PASSES, phase=_VERIFIED_RECOVERY, result="pass"),
        _assertion(_ASR_FAILS_ONCE, phase=_VERIFIED_RECOVERY, result=asr06_result),
    ]
    if include_asr11:
        assertions.append(_assertion(_ASR_ABSENT_IN_ONE_RUN, phase=None, result="pass"))
    required_substep_results = [
        _substep(_SUB_ALWAYS_REACHED, phase=_CONTAINMENT, result="reached"),
        _substep(_SUB_NOT_REACHED_ONCE, phase=_CONTAINMENT, result=sub01_result),
    ]
    path = write_bundle(
        directory,
        run_id=f"RUN-G1-LOGONLY-SCN-CVE-04-INJ-A-{seed}",
        condition="G1-LOGONLY",
        scenario_id="SCN-CVE-04",
        injection_condition="INJ-A",
        seed=seed,
        assertions=assertions,
        required_substep_results=required_substep_results,
    )
    return load(path)


def _sim01_run(directory: Path, *, seed: int) -> Bundle:
    """One SCN-SIM-01/G1-LOGONLY run that reuses ``ASR-05``/``SUB-03`` for a DIFFERENT check,
    failing both -- proves the tripwire never pools these across scenarios (module docstring)."""
    path = write_bundle(
        directory,
        run_id=f"RUN-G1-LOGONLY-SCN-SIM-01-INJ-A-{seed}",
        condition="G1-LOGONLY",
        scenario_id="SCN-SIM-01",
        injection_condition="INJ-A",
        seed=seed,
        assertions=[_assertion(_ASR_ALWAYS_PASSES, phase=_VERIFIED_RECOVERY, result="fail")],
        required_substep_results=[
            _substep(_SUB_ALWAYS_REACHED, phase=_CONTAINMENT, result="not-reached")
        ],
    )
    return load(path)


def _fixture_campaign(tmp_path: Path) -> list[Bundle]:
    """Three SCN-CVE-04 runs (seeds 101-103) plus one SCN-SIM-01 run (seed 201) -- all real,
    `is_baseline: false` -- exactly the shape :func:`vacuous_predicates` expects its caller to
    hand it (`analysis.render`'s ``framework_on`` split)."""
    return [
        _cve04_run(
            tmp_path / "r101",
            seed=101,
            asr06_result="pass",
            include_asr11=True,
            sub01_result="reached",
        ),
        _cve04_run(
            tmp_path / "r102",
            seed=102,
            asr06_result="pass",
            include_asr11=True,
            sub01_result="reached",
        ),
        _cve04_run(
            tmp_path / "r103",
            seed=103,
            asr06_result="fail",  # the one real failure: ASR-06 must not be flagged
            include_asr11=False,  # absent here: applicable set is {101, 102}, not {101, 102, 103}
            sub01_result="not-reached",  # the one real failure: SUB-01 must not be flagged
        ),
        _sim01_run(tmp_path / "r201", seed=201),
    ]


def _key(item: VacuousPredicate) -> tuple[str, str, str | None, str]:
    return (item.scenario_id, item.kind, item.phase, item.local_id)


# ============================================================================================
# predicate_outcomes -- the long-form per-run frame
# ============================================================================================


def test_predicate_outcomes_is_empty_for_no_bundles() -> None:
    frame = predicate_outcomes([])
    assert frame.empty
    assert list(frame.columns) == [
        "run_id",
        "campaign_id",
        "condition",
        "scenario_id",
        "injection_condition",
        "seed",
        "kind",
        "phase",
        "local_id",
        "held",
    ]


def test_predicate_outcomes_skips_a_bundle_with_no_assertions_json(tmp_path: Path) -> None:
    """A baseline (or any unscored run) carries no `assertions.json` and contributes no rows."""
    path = write_bundle(
        tmp_path / "baseline",
        run_id="BASE-LOAD-STEADY-101",
        condition=None,
        scenario_id=None,
        injection_condition=None,
        seed=101,
        is_baseline=True,
    )
    assert predicate_outcomes([load(path)]).empty


def test_predicate_outcomes_reads_both_shapes_and_scores_held_correctly(tmp_path: Path) -> None:
    bundle = _cve04_run(
        tmp_path / "r",
        seed=101,
        asr06_result="fail",
        include_asr11=True,
        sub01_result="not-reached",
    )
    frame = predicate_outcomes([bundle])
    by_id = {(row.kind, row.local_id): row.held for row in frame.itertuples()}
    assert by_id[(ASSERTION_KIND, _ASR_ALWAYS_PASSES)] is True
    assert by_id[(ASSERTION_KIND, _ASR_FAILS_ONCE)] is False
    assert by_id[(ASSERTION_KIND, _ASR_ABSENT_IN_ONE_RUN)] is True
    assert by_id[(REQUIRED_SUBSTEP_KIND, _SUB_ALWAYS_REACHED)] is True
    assert by_id[(REQUIRED_SUBSTEP_KIND, _SUB_NOT_REACHED_ONCE)] is False
    # The end-state assertion's phase is carried through as the ground truth's own null; pandas
    # reads a column mixing `None` with strings back as NaN, not the `None` object itself.
    end_state_row = frame[frame["local_id"] == _ASR_ABSENT_IN_ONE_RUN].iloc[0]
    assert pd.isna(end_state_row["phase"])


# ============================================================================================
# vacuous_predicates -- the tripwire itself
# ============================================================================================


def test_tripwire_flags_exactly_the_always_holding_predicates(tmp_path: Path) -> None:
    """ASR-05, ASR-11 and SUB-03 are flagged; ASR-06 and SUB-01 (each fails once) are not; the
    SCN-SIM-01 run's same-named, always-failing predicates are not either."""
    bundles = _fixture_campaign(tmp_path)
    flagged = vacuous_predicates(bundles)
    flagged_keys = {_key(item) for item in flagged}
    assert flagged_keys == {
        ("SCN-CVE-04", ASSERTION_KIND, _VERIFIED_RECOVERY, _ASR_ALWAYS_PASSES),
        ("SCN-CVE-04", ASSERTION_KIND, None, _ASR_ABSENT_IN_ONE_RUN),
        ("SCN-CVE-04", REQUIRED_SUBSTEP_KIND, _CONTAINMENT, _SUB_ALWAYS_REACHED),
    }
    # Not flagged: the two predicates that failed at least once, on either scenario.
    not_flagged = {(_ASR_FAILS_ONCE,), (_SUB_NOT_REACHED_ONCE,)}
    assert not any((item.local_id,) in not_flagged for item in flagged)
    assert all(item.scenario_id == "SCN-CVE-04" for item in flagged)


def test_tripwire_denominator_is_applicable_runs_not_every_real_run(tmp_path: Path) -> None:
    """ASR-11 is absent from the seed-103 run: its 100% must be computed over the 2 runs that
    actually carried it, never over all 3 real SCN-CVE-04 runs (the module's absence rule)."""
    bundles = _fixture_campaign(tmp_path)
    flagged = {_key(item): item for item in vacuous_predicates(bundles)}
    absent_case = flagged[("SCN-CVE-04", ASSERTION_KIND, None, _ASR_ABSENT_IN_ONE_RUN)]
    assert absent_case.pass_count == 2
    assert absent_case.total_applicable == 2
    # And the always-present ASR-05 is over all three real CVE-04 runs, not two.
    always_present = flagged[("SCN-CVE-04", ASSERTION_KIND, _VERIFIED_RECOVERY, _ASR_ALWAYS_PASSES)]
    assert always_present.pass_count == 3
    assert always_present.total_applicable == 3


def test_tripwire_reports_the_required_substep_case_too(tmp_path: Path) -> None:
    bundles = _fixture_campaign(tmp_path)
    flagged = {_key(item): item for item in vacuous_predicates(bundles)}
    substep_case = flagged[("SCN-CVE-04", REQUIRED_SUBSTEP_KIND, _CONTAINMENT, _SUB_ALWAYS_REACHED)]
    assert substep_case.kind == REQUIRED_SUBSTEP_KIND
    assert substep_case.pass_count == substep_case.total_applicable == 3


def test_identifiers_are_namespaced_by_scenario_not_pooled_across_scenarios(tmp_path: Path) -> None:
    """SCN-SIM-01 reuses ASR-05/SUB-03 for an always-FAILING check; if the tripwire pooled by the
    bare id across scenarios, SCN-CVE-04's always-passing ASR-05/SUB-03 would stop being 100% and
    would wrongly disappear from the flagged set."""
    bundles = _fixture_campaign(tmp_path)
    flagged = vacuous_predicates(bundles)
    cve04_ids = {item.local_id for item in flagged if item.scenario_id == "SCN-CVE-04"}
    assert _ASR_ALWAYS_PASSES in cve04_ids
    assert _SUB_ALWAYS_REACHED in cve04_ids
    assert all(item.scenario_id != "SCN-SIM-01" for item in flagged)


def test_vacuous_predicate_identifier_property(tmp_path: Path) -> None:
    bundles = _fixture_campaign(tmp_path)
    flagged = {_key(item): item for item in vacuous_predicates(bundles)}
    assert (
        flagged[("SCN-CVE-04", ASSERTION_KIND, _VERIFIED_RECOVERY, _ASR_ALWAYS_PASSES)].identifier
        == "SCN-CVE-04/verified-recovery/ASR-05"
    )
    assert (
        flagged[("SCN-CVE-04", ASSERTION_KIND, None, _ASR_ABSENT_IN_ONE_RUN)].identifier
        == "SCN-CVE-04/ASR-11"
    )


def test_vacuous_predicates_is_empty_for_no_bundles() -> None:
    assert vacuous_predicates([]) == []


def test_a_predicate_absent_from_every_real_run_is_never_reported(tmp_path: Path) -> None:
    """0 applicable runs is not a 100% pass rate over no evidence; it must not be flagged."""
    path = write_bundle(
        tmp_path / "r",
        run_id="RUN-G1-LOGONLY-SCN-CVE-04-INJ-A-101",
        condition="G1-LOGONLY",
        scenario_id="SCN-CVE-04",
        injection_condition="INJ-A",
        seed=101,
        assertions=[_assertion(_ASR_ALWAYS_PASSES, phase=_VERIFIED_RECOVERY, result="pass")],
        required_substep_results=[],
    )
    flagged = vacuous_predicates([load(path)])
    assert all(item.local_id != "ASR-99" for item in flagged)


# ============================================================================================
# render wiring -- analysis.render._render_vacuity_tripwire (ADR-096, item 2)
# ============================================================================================


def test_render_wiring_writes_a_labelled_table_and_warns_when_something_is_flagged(
    tmp_path: Path, capsys
) -> None:
    bundles = _fixture_campaign(tmp_path / "bundles")
    out_dir = tmp_path / "_analysis"
    out_dir.mkdir()
    path, status, warnings = _render_vacuity_tripwire(bundles, out_dir, "CAMP-TEST", len(bundles))

    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert "VACUITY TRIPWIRE" in text
    assert "CAMP-TEST" in text
    assert "SCN-CVE-04" in text
    assert _ASR_ALWAYS_PASSES in text

    assert status.startswith("VACUITY WARNING")
    assert len(warnings) == 3
    assert all(isinstance(item, VacuousPredicate) for item in warnings)

    printed = capsys.readouterr()
    assert "VACUITY WARNING" in printed.err


def _cve04_uniform_run(directory: Path, *, seed: int, result: str, substep_result: str) -> Bundle:
    """A run where ``ASR-05``/``SUB-03`` -- the two predicates `_cve04_run` hardcodes as always
    holding -- take whatever result the caller chooses, for a test that needs to make them fail."""
    path = write_bundle(
        directory,
        run_id=f"RUN-G1-LOGONLY-SCN-CVE-04-INJ-A-{seed}",
        condition="G1-LOGONLY",
        scenario_id="SCN-CVE-04",
        injection_condition="INJ-A",
        seed=seed,
        assertions=[_assertion(_ASR_ALWAYS_PASSES, phase=_VERIFIED_RECOVERY, result=result)],
        required_substep_results=[
            _substep(_SUB_ALWAYS_REACHED, phase=_CONTAINMENT, result=substep_result)
        ],
    )
    return load(path)


def test_render_wiring_reports_no_warning_when_nothing_is_vacuous(tmp_path: Path) -> None:
    """Two runs, one where the predicate holds and one where it does not: nothing reaches 100%,
    so the table is written with an empty body and no warning is printed or returned."""
    clean = [
        _cve04_uniform_run(tmp_path / "r101", seed=101, result="pass", substep_result="reached"),
        _cve04_uniform_run(
            tmp_path / "r102", seed=102, result="fail", substep_result="not-reached"
        ),
    ]
    out_dir = tmp_path / "_analysis"
    out_dir.mkdir()
    path, status, warnings = _render_vacuity_tripwire(clean, out_dir, "CAMP-TEST", len(clean))

    assert path.is_file()
    assert "no rows on this corpus" in path.read_text(encoding="utf-8")
    assert status == "computed: no predicate passed in 100% of its applicable real runs"
    assert warnings == ()


# ============================================================================================
# classify_disposition -- supervisor ruling 2026-09-14
# ============================================================================================

# A real scenario_id (reused from the ADR-096 example above, so _ASR_ALWAYS_PASSES/_VERIFIED_
# RECOVERY/_CONTAINMENT already mean what they say) is safe to reuse here: every test below passes
# its own tmp_path controls_root explicitly, so nothing ever falls back to -- or collides with --
# the tracked runs/.controls/SCN-CVE-04 tree.
_DISPOSITION_SCENARIO = "SCN-CVE-04"
_DETECTION = "detection-and-investigation"


def test_disposition_is_fails_negative_control_when_the_live_control_fails_it(
    tmp_path: Path,
) -> None:
    """Rule (a): a flagged predicate whose live negative control shows it CAN fail is not
    genuinely vacuous, regardless of what kind of predicate it is."""
    controls_root = tmp_path / ".controls"
    _write_negative_control(
        controls_root,
        _DISPOSITION_SCENARIO,
        assertions=[_assertion(_ASR_FAILS_ONCE, phase=_VERIFIED_RECOVERY, result="fail")],
    )
    predicate = VacuousPredicate(
        scenario_id=_DISPOSITION_SCENARIO,
        kind=ASSERTION_KIND,
        phase=_VERIFIED_RECOVERY,
        local_id=_ASR_FAILS_ONCE,
        pass_count=3,
        total_applicable=3,
    )
    assert classify_disposition(predicate, controls_root=controls_root) == FAILS_NEGATIVE_CONTROL


def test_disposition_is_fails_negative_control_for_a_not_reached_required_substep(
    tmp_path: Path,
) -> None:
    """Rule (a) over the required-substep vocabulary (`not-reached`, not `fail`)."""
    controls_root = tmp_path / ".controls"
    _write_negative_control(
        controls_root,
        _DISPOSITION_SCENARIO,
        required_substep_results=[
            _substep(_SUB_NOT_REACHED_ONCE, phase=_CONTAINMENT, result="not-reached")
        ],
    )
    predicate = VacuousPredicate(
        scenario_id=_DISPOSITION_SCENARIO,
        kind=REQUIRED_SUBSTEP_KIND,
        phase=_CONTAINMENT,
        local_id=_SUB_NOT_REACHED_ONCE,
        pass_count=3,
        total_applicable=3,
    )
    assert classify_disposition(predicate, controls_root=controls_root) == FAILS_NEGATIVE_CONTROL


def test_disposition_is_do_no_harm_for_an_end_state_compromise_assertion(tmp_path: Path) -> None:
    """Rule (b): an end-state-compromise assertion (ground truth `phase: null`, schema-required --
    see the module's own DISPOSITION section) passing 100% of the time is the point of a do-no-harm
    check, not evidence of vacuity, even when the negative control does not fail it."""
    controls_root = tmp_path / ".controls"
    _write_negative_control(
        controls_root,
        _DISPOSITION_SCENARIO,
        assertions=[_assertion(_ASR_ABSENT_IN_ONE_RUN, phase=None, result="pass")],
    )
    predicate = VacuousPredicate(
        scenario_id=_DISPOSITION_SCENARIO,
        kind=ASSERTION_KIND,
        phase=None,
        local_id=_ASR_ABSENT_IN_ONE_RUN,
        pass_count=2,
        total_applicable=2,
    )
    assert classify_disposition(predicate, controls_root=controls_root) == DO_NO_HARM


def test_disposition_is_verified_recovery_check_for_a_verified_recovery_phase_predicate(
    tmp_path: Path,
) -> None:
    """Rule (c): a verified-recovery phase check passing 100% of the time is the point of a
    recovery check, not evidence of vacuity, even when the negative control does not fail it. Over
    a required substep here (rule (b) never applies to one), rather than an assertion, so this case
    is not just rule (b) with a different phase."""
    controls_root = tmp_path / ".controls"
    _write_negative_control(
        controls_root,
        _DISPOSITION_SCENARIO,
        required_substep_results=[
            _substep(_SUB_ALWAYS_REACHED, phase=_VERIFIED_RECOVERY, result="reached")
        ],
    )
    predicate = VacuousPredicate(
        scenario_id=_DISPOSITION_SCENARIO,
        kind=REQUIRED_SUBSTEP_KIND,
        phase=_VERIFIED_RECOVERY,
        local_id=_SUB_ALWAYS_REACHED,
        pass_count=3,
        total_applicable=3,
    )
    assert classify_disposition(predicate, controls_root=controls_root) == VERIFIED_RECOVERY_CHECK


def test_disposition_is_genuinely_vacuous_when_no_exemption_applies(tmp_path: Path) -> None:
    """Neither (a), (b), (c) nor the 2026-09-14 check-type generalisations: a containment-phase
    check that is not guardian-executed-none and not a below-full-count replicas-at-least floor,
    which the live negative control also passes, is genuinely vacuous and blocks the campaign."""
    controls_root = tmp_path / ".controls"
    groundtruth_dir = tmp_path / "groundtruth"
    _write_groundtruth(
        groundtruth_dir,
        "SCN-GV-01",
        "assertions:\n"
        "  - assertion_id: ASR-90\n"
        "    kind: phase-outcome\n"
        "    phase: containment\n"
        "    check:\n"
        "      type: slo-probe-recovered\n"
        "      params:\n"
        "        namespace: boutique\n"
        "        workload: adservice\n"
        "        probe: PROBE-X\n",
    )
    _write_negative_control(
        controls_root,
        "SCN-GV-01",
        assertions=[_assertion("ASR-90", phase=_CONTAINMENT, result="pass")],
    )
    predicate = VacuousPredicate(
        scenario_id="SCN-GV-01",
        kind=ASSERTION_KIND,
        phase=_CONTAINMENT,
        local_id="ASR-90",
        pass_count=3,
        total_applicable=3,
    )
    assert (
        classify_disposition(
            predicate, controls_root=controls_root, groundtruth_dir=groundtruth_dir
        )
        == GENUINELY_VACUOUS
    )


def test_disposition_is_do_no_harm_for_a_guardian_executed_none_substep(tmp_path: Path) -> None:
    """Ruling 2026-09-14 (SUB-03): a guardian-executed-none required substep asserts a harmful
    action was NOT performed, so passing every time is the point -- do-no-harm despite carrying no
    ground-truth kind field."""
    controls_root = tmp_path / ".controls"
    groundtruth_dir = tmp_path / "groundtruth"
    _write_groundtruth(
        groundtruth_dir,
        "SCN-GV-02",
        "phases:\n"
        "  containment:\n"
        "    required_substeps:\n"
        "      - substep_id: SUB-90\n"
        "        check:\n"
        "          type: guardian-executed-none\n"
        "          params:\n"
        "            namespace: boutique\n"
        "            resource: deployments\n"
        "            verb: patch\n"
        "            name: frontend\n",
    )
    _write_negative_control(
        controls_root,
        "SCN-GV-02",
        required_substep_results=[_substep("SUB-90", phase=_CONTAINMENT, result="reached")],
    )
    predicate = VacuousPredicate(
        scenario_id="SCN-GV-02",
        kind=REQUIRED_SUBSTEP_KIND,
        phase=_CONTAINMENT,
        local_id="SUB-90",
        pass_count=3,
        total_applicable=3,
    )
    assert (
        classify_disposition(
            predicate, controls_root=controls_root, groundtruth_dir=groundtruth_dir
        )
        == DO_NO_HARM
    )


def test_disposition_is_do_no_harm_for_a_containment_replicas_at_least_availability_floor(
    tmp_path: Path,
) -> None:
    """Ruling 2026-09-14 (ASR-03/SUB-02): a containment replicas-at-least whose minimum is BELOW the
    target's declared full count (here 1 < 3, the verified-recovery recovery target) is an
    availability floor -- the response did not scale the workload to zero -- do-no-harm, the state
    twin of the guardian-executed-none guard."""
    controls_root = tmp_path / ".controls"
    groundtruth_dir = tmp_path / "groundtruth"
    _write_groundtruth(
        groundtruth_dir,
        "SCN-GV-03",
        "assertions:\n"
        "  - assertion_id: ASR-90\n"
        "    kind: phase-outcome\n"
        "    phase: containment\n"
        "    check:\n"
        "      type: replicas-at-least\n"
        "      params:\n"
        "        namespace: boutique\n"
        "        workload: adservice\n"
        "        minimum: 1\n"
        "  - assertion_id: ASR-91\n"
        "    kind: phase-outcome\n"
        "    phase: verified-recovery\n"
        "    check:\n"
        "      type: replicas-at-least\n"
        "      params:\n"
        "        namespace: boutique\n"
        "        workload: adservice\n"
        "        minimum: 3\n",
    )
    _write_negative_control(
        controls_root,
        "SCN-GV-03",
        assertions=[_assertion("ASR-90", phase=_CONTAINMENT, result="pass")],
    )
    predicate = VacuousPredicate(
        scenario_id="SCN-GV-03",
        kind=ASSERTION_KIND,
        phase=_CONTAINMENT,
        local_id="ASR-90",
        pass_count=3,
        total_applicable=3,
    )
    assert (
        classify_disposition(
            predicate, controls_root=controls_root, groundtruth_dir=groundtruth_dir
        )
        == DO_NO_HARM
    )


def test_a_containment_availability_floor_can_fail_when_replicas_hit_zero() -> None:
    """The failure-side demonstration the 2026-09-14 ruling asks for: the replicas-at-least
    minimum-1 guard is falsifiable -- it fails when a response drives the workload to zero replicas,
    the over-containment harm it exists to catch. Proven against the real evaluator, so the
    do-no-harm classification rests on a guard that can actually fire."""
    from runner.evaluate_assertions import _evaluate_check, build_action_streams

    class _FakeCluster:
        def __init__(self, ready: int) -> None:
            self._ready = ready

        def workload(self, namespace: str | None, workload: str) -> dict:
            return {"status": {"readyReplicas": self._ready}}

        def list_resource(self, namespace: str | None, resource: str) -> list:
            return []

    # Ground-truth v3 (WS-2, D1-A): an executed-action check reads the unified stream, so a
    # `replicas-at-least` check is now evaluated beside one rather than beside a raw audit list.
    # Both streams are empty here and on purpose -- the environment check this case exercises
    # reads the cluster, not the stream, and an empty stream is what keeps the case from
    # depending on evidence the test does not build.
    streams = build_action_streams([], [], status_by_seq=None, phase_by_seq=None)
    check = {
        "type": "replicas-at-least",
        "params": {"namespace": "boutique", "workload": "adservice", "minimum": 1},
    }
    held_up, _observed_up = _evaluate_check(
        check, streams=streams, probes=[], cluster=_FakeCluster(3)
    )
    held_down, observed = _evaluate_check(
        check, streams=streams, probes=[], cluster=_FakeCluster(0)
    )
    assert held_up is True
    assert held_down is False
    assert "readyReplicas=0" in observed


def test_disposition_fails_closed_to_genuinely_vacuous_when_no_control_file_exists(
    tmp_path: Path,
) -> None:
    """Fail closed: with no readable negative control at all for the scenario -- not even the
    directory exists -- classification cannot proceed, and the conservative reading is the one
    that blocks the campaign. This takes priority over rule (c): the predicate below IS a
    verified-recovery check, which would otherwise exempt it, but the missing file is decided
    first (classify_disposition's own docstring: "the ONLY case that fails closed")."""
    controls_root = tmp_path / ".controls"  # deliberately never written
    predicate = VacuousPredicate(
        scenario_id=_DISPOSITION_SCENARIO,
        kind=ASSERTION_KIND,
        phase=_VERIFIED_RECOVERY,
        local_id=_ASR_ALWAYS_PASSES,
        pass_count=3,
        total_applicable=3,
    )
    assert classify_disposition(predicate, controls_root=controls_root) == GENUINELY_VACUOUS


def test_disposition_fails_closed_when_the_control_file_is_not_valid_json(tmp_path: Path) -> None:
    """A present-but-unreadable control (malformed JSON) is the same "cannot classify" case as a
    missing file, never a crash and never silently treated as an empty/absent reading."""
    controls_root = tmp_path / ".controls"
    directory = controls_root / _DISPOSITION_SCENARIO / "negative"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "assertions.json").write_text("{not valid json", encoding="utf-8")
    predicate = VacuousPredicate(
        scenario_id=_DISPOSITION_SCENARIO,
        kind=ASSERTION_KIND,
        phase=_VERIFIED_RECOVERY,
        local_id=_ASR_ALWAYS_PASSES,
        pass_count=3,
        total_applicable=3,
    )
    assert classify_disposition(predicate, controls_root=controls_root) == GENUINELY_VACUOUS


def test_disposition_treats_absence_from_an_existing_control_as_neither_pass_nor_fail(
    tmp_path: Path,
) -> None:
    """A predicate simply absent from an existing, readable control file (e.g. an INJ-B end-state
    assertion, never carried by the control's own fixed INJ-A run: runner/controls.py's
    DEFAULT_INJECTION_CONDITION) is NOT the fail-closed case -- only a wholly unreadable control is.
    Rule (b) still applies over the ground truth kind carried on the predicate itself."""
    controls_root = tmp_path / ".controls"
    _write_negative_control(
        controls_root,
        _DISPOSITION_SCENARIO,
        assertions=[_assertion(_ASR_ALWAYS_PASSES, phase=_VERIFIED_RECOVERY, result="pass")],
    )
    predicate = VacuousPredicate(
        scenario_id=_DISPOSITION_SCENARIO,
        kind=ASSERTION_KIND,
        phase=None,
        local_id="ASR-21",  # an INJ-B end state; absent from this INJ-A control on purpose
        pass_count=3,
        total_applicable=3,
    )
    assert classify_disposition(predicate, controls_root=controls_root) == DO_NO_HARM


def test_disposition_matches_a_required_substep_on_phase_not_local_id_alone(
    tmp_path: Path,
) -> None:
    """SUB-01 under containment and SUB-01 under detection-and-investigation are different
    predicates (substep ids reset every phase): a control that fails the containment one must not
    be read as failing the detection-and-investigation one too."""
    controls_root = tmp_path / ".controls"
    _write_negative_control(
        controls_root,
        _DISPOSITION_SCENARIO,
        required_substep_results=[
            _substep(_SUB_NOT_REACHED_ONCE, phase=_CONTAINMENT, result="not-reached"),
            _substep(_SUB_NOT_REACHED_ONCE, phase=_DETECTION, result="reached"),
        ],
    )
    detection_predicate = VacuousPredicate(
        scenario_id=_DISPOSITION_SCENARIO,
        kind=REQUIRED_SUBSTEP_KIND,
        phase=_DETECTION,
        local_id=_SUB_NOT_REACHED_ONCE,
        pass_count=3,
        total_applicable=3,
    )
    # Reached in its own (detection-and-investigation) phase, so rule (a) does not apply; neither
    # does (b) (no substep ever carries ground-truth kind) nor (c) (wrong phase) -- vacuous.
    assert (
        classify_disposition(detection_predicate, controls_root=controls_root) == GENUINELY_VACUOUS
    )


def test_render_wiring_adds_a_disposition_column_and_warns_on_genuinely_vacuous(
    tmp_path: Path, capsys
) -> None:
    """The table gains a `disposition` column, and a `genuinely-vacuous` verdict prints its own
    distinct stderr line -- still never a hard error (ADR-096 item 5)."""
    bundles = _fixture_campaign(tmp_path / "bundles")
    controls_root = tmp_path / ".controls"
    # ASR-05 (verified-recovery) -> verified-recovery-check; ASR-11 (end-state) -> do-no-harm;
    # containment/SUB-03 carries no required-substep entry at all in this control fixture -> absent
    # -> falls through (a) and (b) never applies to a substep -> (c) (wrong phase) -> vacuous.
    _write_negative_control(
        controls_root,
        "SCN-CVE-04",
        assertions=[
            _assertion(_ASR_ALWAYS_PASSES, phase=_VERIFIED_RECOVERY, result="pass"),
            _assertion(_ASR_ABSENT_IN_ONE_RUN, phase=None, result="pass"),
        ],
    )
    out_dir = tmp_path / "_analysis"
    out_dir.mkdir()
    path, status, warnings = _render_vacuity_tripwire(
        bundles, out_dir, "CAMP-TEST", len(bundles), controls_root=controls_root
    )

    text = path.read_text(encoding="utf-8")
    assert "disposition" in text
    assert VERIFIED_RECOVERY_CHECK in text
    assert DO_NO_HARM in text
    assert GENUINELY_VACUOUS in text
    assert status.startswith("VACUITY WARNING")
    assert len(warnings) == 3

    printed = capsys.readouterr()
    assert "GENUINELY-VACUOUS" in printed.err
    assert "SCN-CVE-04/containment/SUB-03" in printed.err


def test_render_wiring_prints_no_genuinely_vacuous_line_when_every_flag_is_exempt(
    tmp_path: Path, capsys
) -> None:
    """No distinct GENUINELY-VACUOUS line when every flagged predicate's disposition is exempt --
    the ordinary VACUITY WARNING line still fires, unaccompanied."""
    bundles = _fixture_campaign(tmp_path / "bundles")
    controls_root = tmp_path / ".controls"
    _write_negative_control(
        controls_root,
        "SCN-CVE-04",
        assertions=[
            _assertion(_ASR_ALWAYS_PASSES, phase=_VERIFIED_RECOVERY, result="pass"),
            _assertion(_ASR_ABSENT_IN_ONE_RUN, phase=None, result="pass"),
        ],
        # containment/SUB-03 is a required substep: rule (b) never applies to one (no ground-truth
        # `kind`) and its phase is not verified-recovery, so rule (a) -- the control FAILING it --
        # is its only possible exemption here. "not-reached" (not "reached") is deliberate.
        required_substep_results=[
            _substep(_SUB_ALWAYS_REACHED, phase=_CONTAINMENT, result="not-reached")
        ],
    )
    out_dir = tmp_path / "_analysis"
    out_dir.mkdir()
    _path, status, warnings = _render_vacuity_tripwire(
        bundles, out_dir, "CAMP-TEST", len(bundles), controls_root=controls_root
    )
    assert len(warnings) == 3
    assert status.startswith("VACUITY WARNING")

    printed = capsys.readouterr()
    assert "VACUITY WARNING" in printed.err
    assert "GENUINELY-VACUOUS" not in printed.err
