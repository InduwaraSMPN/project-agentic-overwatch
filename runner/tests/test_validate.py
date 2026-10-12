r"""The campaign validator: the real 750 grid accepted, and one negative fixture per rejection case.

The DoD enumerates the rejection cases and requires "every negative fixture rejected with a distinct
reason". This suite builds each fixture by mutating the accepted real grid minimally, and asserts on
the :class:`ValidationError` ``code`` rather than on message text -- so "a distinct reason per case"
is checkable and a reworded message does not break a test.

The two positive fixtures are as load-bearing as the negatives: the real 750 grid, and a
framework-on run on an *ablated* arm with a null ``baseline_run_id``, which a naive symmetric
null check would wrongly reject.
"""

import sys
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402

from runner.bundle import seal_bundle  # noqa: E402
from runner.campaign import (  # noqa: E402
    CampaignManifest,
    PlannedRun,
)
from runner.campaign import (  # noqa: E402
    to_canonical_bytes as campaign_to_canonical_bytes,
)
from runner.grid import build_campaign_manifest  # noqa: E402
from runner.ids import CANONICAL_ARMS  # noqa: E402
from runner.manifest import (  # noqa: E402
    HOST_FIELDS,
    SCHEMA_VERSION,
    RunManifest,
)
from runner.synthetic import populate_bundle, synthetic_manifest  # noqa: E402
from runner.validate import (  # noqa: E402
    ValidationError,
    validate_bundle,
    validate_campaign_manifest,
    validate_pilot_campaign_manifest,
)

CAMPAIGN = "CAMP-20260827-pilot"


def _real_grid() -> CampaignManifest:
    return build_campaign_manifest(CAMPAIGN)


def _with_runs(manifest: CampaignManifest, runs: list[PlannedRun]) -> CampaignManifest:
    return replace(manifest, runs=tuple(runs))


def _first(manifest: CampaignManifest, condition: str) -> tuple[int, PlannedRun]:
    for index, run in enumerate(manifest.runs):
        if run.condition == condition:
            return index, run
    raise AssertionError(f"no {condition} run")


def _pilot() -> CampaignManifest:
    full = _real_grid()
    # Three matched G0-FULL/G1-LOGONLY pairs on (scenario, injection, seed): the composition the
    # GATE pilot actually requires so analysis/stats/pairs.py's guardrail contrast forms three pairs
    # rather than zero. Mirrors runner/CAMP-20260913-gate-pilot.json.
    coordinates = (
        ("G0-FULL", "SCN-SIM-01", "INJ-A", 101),
        ("G1-LOGONLY", "SCN-SIM-01", "INJ-A", 101),
        ("G0-FULL", "SCN-CVE-04", "INJ-B", 102),
        ("G1-LOGONLY", "SCN-CVE-04", "INJ-B", 102),
        ("G0-FULL", "SCN-CVE-05", "INJ-C", 103),
        ("G1-LOGONLY", "SCN-CVE-05", "INJ-C", 103),
    )
    by_coordinates = {
        (run.condition, run.scenario_id, run.injection_condition, run.seed): run
        for run in full.runs
        if not run.is_baseline
    }
    runs = tuple(by_coordinates[key] for key in coordinates)
    return replace(
        full,
        seeds=tuple(sorted({run.seed for run in runs})),
        runs=runs,
        generated_order=tuple(run.run_id for run in runs),
    )


# --- the two positive fixtures ------------------------------------------------------------------


def test_the_real_750_grid_is_accepted() -> None:
    """The DoD's positive fixture: the real grid validates, and all five injection values appear."""
    counts = validate_campaign_manifest(_real_grid())
    assert sum(counts.values()) == 750
    assert set(counts) == {"INJ-NONE", "INJ-A", "INJ-B", "INJ-C", "INJ-D"}
    assert all(count == 150 for count in counts.values())


def test_the_gate_pilot_plan_is_accepted_without_weakening_the_production_validator() -> None:
    assert validate_pilot_campaign_manifest(_pilot()) == {"G0-FULL": 3, "G1-LOGONLY": 3}
    with pytest.raises(ValidationError):
        validate_campaign_manifest(_pilot())


def test_gate_pilot_rejects_unpaired_arms_that_form_no_matched_pairs() -> None:
    """Correct arm counts (3 G0-FULL, 3 G1-LOGONLY) are not sufficient: the six cells must form
    three matched pairs on (scenario, injection, seed), or analysis/stats/pairs.py's G0-vs-G1
    guardrail contrast forms zero pairs -- a hard error, not an empty table. The pre-correction plan
    ran every G0-FULL cell on a SIM scenario and every G1-LOGONLY cell on a CVE one, passing the
    count check yet pairing nothing."""
    full = _real_grid()
    confounded = (
        ("G0-FULL", "SCN-SIM-01", "INJ-NONE", 101),
        ("G1-LOGONLY", "SCN-CVE-04", "INJ-A", 101),
        ("G0-FULL", "SCN-SIM-02", "INJ-B", 102),
        ("G1-LOGONLY", "SCN-CVE-05", "INJ-C", 102),
        ("G0-FULL", "SCN-SIM-03", "INJ-D", 103),
        ("G1-LOGONLY", "SCN-CVE-04", "INJ-NONE", 103),
    )
    by_coordinates = {
        (run.condition, run.scenario_id, run.injection_condition, run.seed): run
        for run in full.runs
        if not run.is_baseline
    }
    runs = tuple(by_coordinates[key] for key in confounded)
    manifest = replace(
        full,
        seeds=tuple(sorted({run.seed for run in runs})),
        runs=runs,
        generated_order=tuple(run.run_id for run in runs),
    )
    with pytest.raises(ValidationError, match="matched G0-FULL/G1-LOGONLY pairs"):
        validate_pilot_campaign_manifest(manifest)


def test_gate_pilot_requires_both_scenario_classes() -> None:
    pilot = _pilot()
    runs = tuple(
        replace(
            run,
            run_id=run.run_id.replace("SCN-CVE-04", "SCN-SIM-01").replace(
                "SCN-CVE-05", "SCN-SIM-02"
            ),
            scenario_id=run.scenario_id.replace("SCN-CVE-04", "SCN-SIM-01").replace(
                "SCN-CVE-05", "SCN-SIM-02"
            ),
        )
        for run in pilot.runs
    )
    with pytest.raises(ValidationError, match="both CVE and SIM"):
        validate_pilot_campaign_manifest(
            replace(pilot, runs=runs, generated_order=tuple(run.run_id for run in runs))
        )


def test_production_validators_do_not_accept_expected_seeds_override(tmp_path: Path) -> None:
    manifest = build_campaign_manifest(CAMPAIGN, seeds=(101,))
    with pytest.raises(TypeError):
        validate_campaign_manifest(manifest, expected_seeds=(101,))  # type: ignore[call-arg]
    from runner.validate import validate_campaign_corpus

    with pytest.raises(TypeError):
        validate_campaign_corpus(tmp_path, expected_seeds=(101,))  # type: ignore[call-arg]


def test_complete_one_seed_151_entry_campaign_is_rejected() -> None:
    """A reduced grid plus baseline cannot redefine the canonical five-seed protocol."""
    manifest = build_campaign_manifest(CAMPAIGN, seeds=(101,))
    assert len(manifest.runs) == 151
    _expect(manifest, "campaign-metadata-mismatch")


def test_frozen_order_and_versions_hash_are_accepted() -> None:
    manifest = _real_grid()
    assert manifest.generated_order
    assert len(manifest.versions_env_sha256) == 64
    validate_campaign_manifest(manifest)


def test_tampered_generated_order_is_rejected() -> None:
    manifest = _real_grid()
    _expect(
        replace(manifest, generated_order=manifest.generated_order[:-1]), "campaign-order-mismatch"
    )


def test_tampered_campaign_seed_is_rejected() -> None:
    manifest = _real_grid()
    _expect(replace(manifest, campaign_seed=manifest.campaign_seed + 1), "campaign-order-mismatch")


def test_tampered_versions_hash_is_rejected() -> None:
    manifest = _real_grid()
    _expect(replace(manifest, versions_env_sha256="0" * 64), "versions-env-sha256-mismatch")


def test_an_ablated_arm_run_with_null_baseline_is_accepted() -> None:
    """The positive fixture a naive symmetric null check would reject: S2-FLAT names no baseline."""
    manifest = _real_grid()
    index, run = _first(manifest, "S2-FLAT")
    assert run.baseline_run_id is None  # already true in the real grid
    validate_campaign_manifest(manifest)  # does not raise


# --- one negative fixture per enumerated case, asserted on the reason code -----------------------


def _expect(manifest: CampaignManifest, code: str) -> None:
    with pytest.raises(ValidationError) as caught:
        validate_campaign_manifest(manifest)
    assert caught.value.code == code, f"expected {code}, got {caught.value.code}"


def test_shared_arm_issued_twice_is_rejected() -> None:
    manifest = _real_grid()
    runs = list(manifest.runs)
    runs.append(
        PlannedRun(
            "RUN-S1-HIER-SCN-SIM-01-INJ-A-101",
            "S1-HIER",
            "SCN-SIM-01",
            "INJ-A",
            101,
            False,
            "BASE-LOAD-STEADY-101",
            "LOAD-STEADY",
        )
    )
    _expect(_with_runs(manifest, runs), "shared-arm-double-count")


def test_per_study_875_manifest_is_the_same_defect() -> None:
    """A per-study summation carries both S1-HIER and G0-FULL: the shared-arm case again."""
    manifest = _real_grid()
    runs = list(manifest.runs)
    for cell in [r for r in manifest.runs if r.condition == "G0-FULL"][:3]:
        runs.append(
            replace(cell, run_id=cell.run_id.replace("G0-FULL", "S1-HIER"), condition="S1-HIER")
        )
    _expect(_with_runs(manifest, runs), "shared-arm-double-count")


@pytest.mark.parametrize("field", ["scenario_id", "injection_condition", "seed", "condition"])
def test_identifier_field_disagreement_is_rejected(field: str) -> None:
    manifest = _real_grid()
    index, run = _first(manifest, "G0-FULL")
    wrong = {
        "scenario_id": "SCN-SIM-99",
        "injection_condition": "INJ-D" if run.injection_condition != "INJ-D" else "INJ-C",
        "seed": run.seed + 1,
        "condition": "S2-FLAT",
    }[field]
    runs = list(manifest.runs)
    runs[index] = replace(run, **{field: wrong})
    _expect(_with_runs(manifest, runs), "id-field-mismatch")


def test_top_level_seed_metadata_must_match_runs() -> None:
    manifest = _real_grid()
    malformed = replace(manifest, seeds=manifest.seeds[:-1])
    _expect(malformed, "campaign-metadata-mismatch")


def test_top_level_load_profile_metadata_must_match_runs() -> None:
    manifest = _real_grid()
    malformed = replace(manifest, load_profiles=())
    _expect(malformed, "campaign-metadata-mismatch")


def test_observed_scenario_vocabulary_cannot_replace_canonical_scenarios() -> None:
    manifest = _real_grid()
    runs = [
        replace(
            run,
            run_id=run.run_id.replace("SCN-CVE-04", "SCN-CVE-99"),
            scenario_id="SCN-CVE-99",
        )
        if run.scenario_id == "SCN-CVE-04"
        else run
        for run in manifest.runs
    ]
    _expect(_with_runs(manifest, runs), "grid-vocabulary-mismatch")


def test_unknown_load_profile_is_rejected() -> None:
    manifest = _real_grid()
    index, run = _first(manifest, "G0-FULL")
    runs = list(manifest.runs)
    runs[index] = replace(run, load_profile_id="LOAD-BOGUS")
    _expect(_with_runs(manifest, runs), "load-profile-unknown")


def test_g0_run_with_null_baseline_is_rejected() -> None:
    manifest = _real_grid()
    index, run = _first(manifest, "G0-FULL")
    runs = list(manifest.runs)
    runs[index] = replace(run, baseline_run_id=None)
    _expect(_with_runs(manifest, runs), "rq4-null-baseline")


def test_baseline_with_different_load_profile_is_rejected() -> None:
    """A G0 run under LOAD-STEADY that names a (valid) LOAD-LIGHT baseline is a pairing mismatch.

    The baseline itself is well formed -- its id and field agree on LOAD-LIGHT -- so this is caught
    by the pairing rule and not by the identifier check, which is the distinction the code draws.
    """
    manifest = _real_grid()
    runs = list(manifest.runs)
    runs.append(PlannedRun("BASE-LOAD-LIGHT-101", None, None, None, 101, True, None, "LOAD-LIGHT"))
    index, run = _first(manifest, "G0-FULL")
    # this G0 run runs under LOAD-STEADY but points at the LOAD-LIGHT baseline
    runs[index] = replace(run, baseline_run_id="BASE-LOAD-LIGHT-101")
    candidate = replace(
        manifest,
        load_profiles=("LOAD-STEADY", "LOAD-LIGHT"),
        runs=tuple(runs),
    )
    _expect(candidate, "baseline-pairing-load-mismatch")


def test_baseline_with_different_seed_is_rejected() -> None:
    manifest = _real_grid()
    runs = list(manifest.runs)
    index, run = _first(manifest, "G0-FULL")
    assert run.seed == 101
    runs[index] = replace(run, baseline_run_id="BASE-LOAD-STEADY-102")
    _expect(_with_runs(manifest, runs), "baseline-pairing-seed-mismatch")


def test_second_baseline_for_one_key_is_rejected() -> None:
    manifest = _real_grid()
    runs = list(manifest.runs)
    runs.append(
        PlannedRun("BASE-LOAD-STEADY-101", None, None, None, 101, True, None, "LOAD-STEADY")
    )
    _expect(_with_runs(manifest, runs), "baseline-duplicate-key")


def test_baseline_with_a_nonnull_field_is_rejected() -> None:
    manifest = _real_grid()
    runs = list(manifest.runs)
    for i, run in enumerate(runs):
        if run.is_baseline:
            runs[i] = replace(run, condition="G0-FULL")
            break
    _expect(_with_runs(manifest, runs), "baseline-nonnull-field")


def test_baseline_ref_that_resolves_to_nothing_is_rejected() -> None:
    manifest = _real_grid()
    index, run = _first(manifest, "G0-FULL")
    runs = list(manifest.runs)
    runs[index] = replace(run, baseline_run_id="BASE-LOAD-STEADY-999")
    _expect(_with_runs(manifest, runs), "baseline-ref-unresolved")


# --- validate_bundle: the framework-on null-field case, over a full manifest --------------------


def _framework_on_manifest(**overrides: object) -> RunManifest:
    base = {
        "run_id": "RUN-G0-FULL-SCN-CVE-04-INJ-A-101",
        "campaign_id": CAMPAIGN,
        "condition": "G0-FULL",
        "scenario_id": "SCN-CVE-04",
        "injection_condition": "INJ-A",
        "seed": 101,
        "rerun_of": None,
        "is_baseline": False,
        "baseline_run_id": "BASE-LOAD-STEADY-101",
        "load_profile_id": "LOAD-STEADY",
        "started_at": "2026-08-27T10:00:00Z",
        "ended_at": "2026-08-27T10:05:00Z",
        "git_commit": "0" * 40,
        "versions_env_sha256": "a" * 64,
        "litellm_config_sha256": "b" * 64,
        "model_alias": "overwatch-primary",
        "model_provider_string": "cerebras/llama-3.3-70b",
        "prompt_registry_sha256": "c" * 64,
        "tool_registry_sha256": "d" * 64,
        "graph_id": "hierarchical",
        "guardian_mode": "G0-FULL",
        "aggregator_quoting": True,
        "netpol_overlay": "default-deny",
        "shared_credential_exercised": False,
        "host": dict.fromkeys(HOST_FIELDS, "x"),
        "schema_version": SCHEMA_VERSION,
    }
    base.update(overrides)
    return RunManifest(**base)  # type: ignore[arg-type]


def test_validate_bundle_accepts_a_clean_framework_on_manifest() -> None:
    validate_bundle(_framework_on_manifest())


def test_validate_bundle_rejects_unknown_schema_version() -> None:
    with pytest.raises(ValidationError) as caught:
        validate_bundle(_framework_on_manifest(schema_version="v999"))
    assert caught.value.code == "schema-version-mismatch"


def test_validate_bundle_rejects_a_framework_on_run_with_a_null_in_the_eleven() -> None:
    """graph_id null on a framework-on run is the 'null in the eleven' case."""
    with pytest.raises(ValidationError) as caught:
        validate_bundle(_framework_on_manifest(graph_id=None))
    assert caught.value.code == "framework-on-null-field"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("graph_id", "flat"),
        ("guardian_mode", "G1-LOGONLY"),
        ("aggregator_quoting", False),
    ],
)
def test_validate_bundle_rejects_condition_flag_disagreement(field: str, value: object) -> None:
    with pytest.raises(ValidationError) as caught:
        validate_bundle(_framework_on_manifest(**{field: value}))
    assert caught.value.code == "condition-flags-mismatch"


def test_validate_bundle_rejects_a_non_g2_run_claiming_the_shared_credential() -> None:
    """Only G2-SHAREDCRED may record the alternate path as exercised.

    ``shared_credential_exercised`` is an OBSERVATION derived from the API-audit slice (ADR-131), so
    it is not one of the four configuration flags the arm table fixes -- but it is not free either.
    A ``True`` on any other arm is an authenticated request by a principal no other arm holds,
    which is F-GD-05's non-G2 half; this is that half's seal-time backstop, and it is the one
    direction the validator can decide from the manifest alone.
    """
    with pytest.raises(ValidationError) as caught:
        validate_bundle(_framework_on_manifest(shared_credential_exercised=True))
    assert caught.value.code == "condition-flags-mismatch"
    assert "shared_credential_exercised" in caught.value.detail


def test_validate_bundle_accepts_a_g2_run_that_never_exercised_the_credential() -> None:
    """G2 with ``False`` SEALS. This is the direction the pre-M10 validator got wrong.

    Whether the agents discovered and used the direct path is the finding C2 exists to measure, so
    a G2 run that never touched it must seal and be reported as a finding. The old requirement --
    ``shared_credential_exercised == (condition == "G2-SHAREDCRED")`` -- forced the manifest to
    assert the treatment instead of recording it, which is exactly v1's inert G2 (defect V7)
    arriving as a check rather than as a value. The mismatch that matters is between the field and
    the run's OWN audit slice, and F-GD-05 (class T, stage seal) owns it.
    """
    validate_bundle(
        _framework_on_manifest(
            run_id="RUN-G2-SHAREDCRED-SCN-CVE-04-INJ-A-101",
            condition="G2-SHAREDCRED",
            guardian_mode="G2-SHAREDCRED",
            netpol_overlay="opened",
            baseline_run_id=None,
            shared_credential_exercised=False,
        )
    )


# --- validate_campaign_corpus: the M7-T7.3 rerun flow (data-management §4) -----------------------


def _write_corpus(
    tmp_path: Path,
    manifest: CampaignManifest,
    *,
    digest_for: Callable[[PlannedRun], str] | None = None,
) -> Path:
    """Write genuine sealed bundles for corpus and rerun validation tests.

    ``digest_for``, when given, stamps each framework-on bundle's manifest ``instrument_digest``
    (and hence its sealed ``fidelity.json``), so a test can build a corpus that spans instruments.
    """
    campaign_dir = tmp_path / manifest.campaign_id
    campaign_dir.mkdir(parents=True, exist_ok=True)
    frozen = replace(manifest, runs=tuple(run for run in manifest.runs if "-R" not in run.run_id))
    (campaign_dir / "campaign.json").write_bytes(campaign_to_canonical_bytes(frozen) + b"\n")
    for index, run in enumerate(manifest.runs):
        bundle = campaign_dir / run.run_id
        bundle.mkdir(parents=True, exist_ok=True)
        populate_bundle(bundle, run, seed=17)
        full_manifest = replace(
            synthetic_manifest(run, manifest.campaign_id, index),
            versions_env_sha256=manifest.versions_env_sha256,
        )
        if digest_for is not None and not run.is_baseline:
            full_manifest = replace(full_manifest, instrument_digest=digest_for(run))
        rerun_of = getattr(run, "_rerun_of", None)
        if rerun_of is not None:
            full_manifest = replace(full_manifest, rerun_of=rerun_of)
        seal_bundle(
            bundle,
            full_manifest,
            sealed_at="2026-01-01T00:00:00Z",
        )
    return campaign_dir


def _rerun_of(run: PlannedRun, original_run_id: str) -> PlannedRun:
    """A PlannedRun that carries a rerun_of, smuggled through a private attr the writer reads."""
    obj = replace(run)
    object.__setattr__(obj, "_rerun_of", original_run_id)
    return obj


def test_corpus_with_a_rerun_validates_when_the_original_is_excluded(tmp_path: Path) -> None:
    """T7.3: an invalid original beside its valid -R2 retry does not trip one-per-cell."""
    from runner.validate import validate_campaign_corpus_for_testing

    manifest = build_campaign_manifest(CAMPAIGN, seeds=(101,))
    runs = list(manifest.runs)
    orig = next(r for r in runs if not r.is_baseline and r.condition == "G0-FULL")
    rerun = _rerun_of(replace(orig, run_id=orig.run_id + "-R2"), orig.run_id)
    runs.append(rerun)
    corpus = _write_corpus(tmp_path, _with_runs(manifest, runs))
    validate_campaign_corpus_for_testing(corpus, expected_seeds=(101,))


def test_corpus_skips_unsealed_original_marked_invalid(tmp_path: Path) -> None:
    from runner.validate import validate_campaign_corpus_for_testing

    manifest = build_campaign_manifest(CAMPAIGN, seeds=(101,))
    runs = list(manifest.runs)
    original = next(r for r in runs if not r.is_baseline and r.condition == "G0-FULL")
    rerun = _rerun_of(replace(original, run_id=original.run_id + "-R2"), original.run_id)
    runs.append(rerun)
    corpus = _write_corpus(tmp_path, _with_runs(manifest, runs))
    (corpus / original.run_id / "invalid.json").write_text('{"invalid":true}\n', encoding="utf-8")
    (corpus / original.run_id / "seal.json").unlink()

    validate_campaign_corpus_for_testing(corpus, expected_seeds=(101,))


def test_corpus_with_two_unlinked_valid_attempts_is_rejected(tmp_path: Path) -> None:
    """Two bundles on one cell key, neither naming the other, is an unmarked double attempt."""
    from runner.validate import validate_campaign_corpus_for_testing

    manifest = build_campaign_manifest(CAMPAIGN, seeds=(101,))
    runs = list(manifest.runs)
    orig = next(r for r in runs if not r.is_baseline and r.condition == "G0-FULL")
    runs.append(replace(orig, run_id=orig.run_id + "-R2"))  # no rerun_of link
    corpus = _write_corpus(tmp_path, _with_runs(manifest, runs))
    with pytest.raises(ValidationError) as caught:
        validate_campaign_corpus_for_testing(corpus, expected_seeds=(101,))
    assert caught.value.code == "duplicate-valid-attempt"


def test_corpus_rejects_inconsistent_campaign_ids(tmp_path: Path) -> None:
    import json

    from runner.manifest import from_dict
    from runner.validate import validate_campaign_corpus_for_testing

    corpus = _write_corpus(tmp_path, build_campaign_manifest(CAMPAIGN, seeds=(101,)))
    manifest_path = next(corpus.glob("*/manifest.json"))
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    changed = replace(from_dict(payload), campaign_id="CAMP-20260827-other")
    seal_bundle(
        manifest_path.parent,
        changed,
    )
    with pytest.raises(ValidationError) as caught:
        validate_campaign_corpus_for_testing(corpus, expected_seeds=(101,))
    assert caught.value.code == "campaign-id-mismatch"


def test_corpus_rejects_a_manifest_only_bundle(tmp_path: Path) -> None:
    """A manifest is not a sealed bundle and cannot enter corpus arithmetic."""
    from runner.validate import validate_campaign_corpus_for_testing

    corpus = _write_corpus(tmp_path, build_campaign_manifest(CAMPAIGN, seeds=(101,)))
    next(corpus.glob("*/seal.json")).unlink()
    with pytest.raises(ValidationError) as caught:
        validate_campaign_corpus_for_testing(corpus, expected_seeds=(101,))
    assert caught.value.code == "bundle-integrity"
    assert "seal.json" in caught.value.detail


def test_corpus_rejects_a_tampered_sealed_bundle(tmp_path: Path) -> None:
    """A content-hash mismatch stops corpus validation before the bundle is counted."""
    from runner.validate import validate_campaign_corpus

    manifest = _real_grid()
    planned = next(run for run in manifest.runs if run.is_baseline)
    campaign_dir = tmp_path / manifest.campaign_id
    campaign_dir.mkdir(parents=True)
    (campaign_dir / "campaign.json").write_bytes(campaign_to_canonical_bytes(manifest) + b"\n")
    bundle = campaign_dir / planned.run_id
    bundle.mkdir(parents=True)
    populate_bundle(bundle, planned, seed=19)
    seal_bundle(
        bundle,
        synthetic_manifest(planned, manifest.campaign_id),
        sealed_at="2026-01-01T00:00:00Z",
    )
    (bundle / "probes.csv").write_text("tampered\n", encoding="utf-8")

    with pytest.raises(ValidationError) as caught:
        validate_campaign_corpus(campaign_dir)
    assert caught.value.code == "bundle-integrity"
    assert "probes.csv" in caught.value.detail


def test_corpus_rejects_mixed_instrument(tmp_path: Path) -> None:
    """ADR-136 / P6: a corpus whose framework-on bundles record two different instrument digests is
    the mixed-commit defect V14 -- a git_commit that touched an instrument path moved the digest --
    and is rejected with the ``mixed-instrument`` reason code."""
    from runner.validate import validate_campaign_corpus_for_testing

    manifest = build_campaign_manifest(CAMPAIGN, seeds=(101,))
    first_grid_id = next(run.run_id for run in manifest.runs if not run.is_baseline)
    corpus = _write_corpus(
        tmp_path,
        manifest,
        digest_for=lambda run: "a" * 64 if run.run_id == first_grid_id else "b" * 64,
    )
    with pytest.raises(ValidationError) as caught:
        validate_campaign_corpus_for_testing(corpus, expected_seeds=(101,))
    assert caught.value.code == "mixed-instrument"


def test_corpus_with_one_instrument_digest_is_accepted(tmp_path: Path) -> None:
    """The positive control for the check above: one instrument digest across every bundle
    validates, so the mixed-instrument check does not reject a single-instrument corpus."""
    from runner.validate import validate_campaign_corpus_for_testing

    manifest = build_campaign_manifest(CAMPAIGN, seeds=(101,))
    corpus = _write_corpus(tmp_path, manifest, digest_for=lambda _run: "c" * 64)
    validate_campaign_corpus_for_testing(corpus, expected_seeds=(101,))  # does not raise


def _coverage_pilot() -> CampaignManifest:
    """A P2 coverage pilot: six arms x five injection conditions on one seed, the scenario a
    function of the injection condition only, so all six arms share every (scenario, injection)
    cell and every contrast pairs. Selected from the real grid so the runs are genuine cells."""
    full = _real_grid()
    seed = 101
    # scenario is a function of the injection condition only (a fixed map over real scenarios), so
    # every arm draws the same cell for a given injection -- the pairing the coverage pilot needs.
    scenario_for = {
        "INJ-NONE": "SCN-SIM-01",
        "INJ-A": "SCN-SIM-01",
        "INJ-B": "SCN-CVE-04",
        "INJ-C": "SCN-CVE-05",
        "INJ-D": "SCN-CVE-04",
    }
    by_coordinates = {
        (run.condition, run.scenario_id, run.injection_condition, run.seed): run
        for run in full.runs
        if not run.is_baseline
    }
    runs = tuple(
        by_coordinates[(arm, scenario_for[injection], injection, seed)]
        for injection in scenario_for
        for arm in CANONICAL_ARMS
    )
    return replace(
        full,
        seeds=(seed,),
        load_profiles=tuple(sorted({run.load_profile_id for run in runs})),
        runs=runs,
        generated_order=tuple(run.run_id for run in runs),
    )


def test_coverage_pilot_pairs_every_arm() -> None:
    """ADR-136: validate_coverage_pilot_manifest accepts a pilot that covers all six arms with every
    arm sharing the same (scenario, injection, seed) cells (so every contrast pairs), and rejects a
    pilot missing an arm or one whose arms do not share cells (defect V16: v1 piloted G0/G1)."""
    from runner.validate import validate_coverage_pilot_manifest

    counts = validate_coverage_pilot_manifest(_coverage_pilot())
    assert set(counts) == set(CANONICAL_ARMS)
    assert all(count == 5 for count in counts.values())  # one cell per injection condition per arm

    # An arm missing entirely is rejected.
    pilot = _coverage_pilot()
    dropped = tuple(run for run in pilot.runs if run.condition != "G3-UNQUOTED")
    with pytest.raises(ValidationError, match="six canonical arms"):
        validate_coverage_pilot_manifest(
            replace(pilot, runs=dropped, generated_order=tuple(run.run_id for run in dropped))
        )

    # An arm whose cells do not match the others' (an unpaired arm) is rejected.
    by_coordinates = {
        (run.condition, run.scenario_id, run.injection_condition, run.seed): run
        for run in _real_grid().runs
        if not run.is_baseline
    }
    swapped = by_coordinates[("G3-UNQUOTED", "SCN-SIM-02", "INJ-A", 101)]
    unpaired = tuple(
        swapped if (run.condition, run.injection_condition) == ("G3-UNQUOTED", "INJ-A") else run
        for run in _coverage_pilot().runs
    )
    with pytest.raises(ValidationError, match="identical cells"):
        validate_coverage_pilot_manifest(
            replace(
                _coverage_pilot(),
                runs=unpaired,
                generated_order=tuple(run.run_id for run in unpaired),
            )
        )


def test_smoke_pilot_runs_each_arm_once() -> None:
    """ADR-136: validate_smoke_pilot_manifest accepts one framework-on run per canonical arm and
    rejects a plan that omits an arm or runs one twice (defect V16)."""
    from runner.validate import validate_smoke_pilot_manifest

    full = _real_grid()
    by_arm: dict[str, PlannedRun] = {}
    for run in full.runs:
        if not run.is_baseline and run.condition not in by_arm:
            by_arm[run.condition] = run
    runs = tuple(by_arm[arm] for arm in CANONICAL_ARMS)
    smoke = replace(
        full,
        seeds=tuple(sorted({run.seed for run in runs})),
        load_profiles=tuple(sorted({run.load_profile_id for run in runs})),
        runs=runs,
        generated_order=tuple(run.run_id for run in runs),
    )
    counts = validate_smoke_pilot_manifest(smoke)
    assert set(counts) == set(CANONICAL_ARMS)
    assert all(count == 1 for count in counts.values())

    dropped = tuple(run for run in runs if run.condition != "S2-FLAT")
    with pytest.raises(ValidationError, match="six canonical arms"):
        validate_smoke_pilot_manifest(
            replace(smoke, runs=dropped, generated_order=tuple(run.run_id for run in dropped))
        )
