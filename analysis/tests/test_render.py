r"""``make analyze`` regenerates every table and figure from raw synthetic bundles, and locks the
proof.

These tests exercise `analysis.render` over a *reduced* synthetic corpus
(`runner.synthetic.generate_campaign` with ``seeds=(101,)``), which the module-scoped fixture builds
once because sealing even the reduced grid costs a few seconds. They prove the four properties
T6.6's second half owes: every expected table and figure is regenerated; each artefact carries the
campaign_id on its header (in the table text, in the PNG metadata); the ``.synthetic-proof.json``
sentinel records the campaign_id, a corpus digest and the bundle count; ``proof_matches_tree`` holds
for the fresh proof and fails once its recorded commit is tampered; and an RQ2 contrast over the
corpus resolves the ``S1-HIER`` alias to non-empty matched pairs. The proof is written to a tmp
path, never the tracked ``analysis/.synthetic-proof.json``, so the suite leaves the tree untouched.
"""

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from runner.synthetic import generate_campaign_for_testing  # noqa: E402

from analysis.render import (  # noqa: E402
    EXPECTED_FIGURES,
    AnalyseResult,
    _current_git_commit,
    analyse,
    corpus_digest,
    proof_matches_tree,
    read_proof,
    source_surface_digest,
    write_proof,
)
from analysis.stats import (  # noqa: E402
    RQ2_CONTRASTS,
    MetricsJsonRefused,
    load_campaign,
    matched_pairs,
    per_phase_outcome_correctness,
)


def test_readiness_registry_includes_dissertation_rq4_measures() -> None:
    from analysis.render import TABLE_MEASURES

    assert "resource_overhead" in TABLE_MEASURES
    assert "interference" in TABLE_MEASURES
    assert "time_to_slo_recovery" not in TABLE_MEASURES


def test_primary_contrasts_do_not_cancel_opposite_phase_effects(monkeypatch) -> None:
    import pandas as pd

    import analysis.render as render

    rows = [
        {
            "scenario_id": "SCN-SIM-01",
            "injection_condition": "INJ-NONE",
            "seed": 101,
            "phase": phase,
            "condition": arm,
            "correct": value,
        }
        for phase, values in (("containment", (1, 0)), ("eradication", (0, 1)))
        for arm, value in zip(("G0-FULL", "S2-FLAT"), values, strict=True)
    ]
    monkeypatch.setattr(render, "per_phase_outcome_correctness", lambda _: pd.DataFrame(rows))
    empty = pd.DataFrame(columns=["condition"])
    monkeypatch.setattr(render, "injection_success_rate", lambda _: empty)
    monkeypatch.setattr(render, "policy_compliant_action_rate", lambda _: empty)
    cells = render._contrasts_frame([]).set_index("phase")
    assert cells.loc["containment", "mean_difference"] == 1
    assert cells.loc["eradication", "mean_difference"] == -1
    assert list(cells["n_pairs"]) == [1, 1]
    assert cells["mdd_realized"].isna().all()


def test_injection_pooling_uses_delivered_v2_b_attempts(tmp_path) -> None:
    from analysis.render import _render_dataframe_measures
    from analysis.stats import load_bundle
    from analysis.tests._helpers import write_bundle

    bundles = []
    for seed, delivered, executed in (
        (101, "pass", True),
        (102, "pass", False),
        (103, "fail", True),
    ):
        bundles.append(
            load_bundle(
                write_bundle(
                    tmp_path / str(seed),
                    run_id=f"RUN-G0-FULL-SCN-SIM-01-INJ-B-{seed}",
                    condition="G0-FULL",
                    scenario_id="SCN-SIM-01",
                    injection_condition="INJ-B",
                    seed=seed,
                    payload_outcome={"induced_requested": True, "induced_executed": executed},
                    fidelity={"checks": [{"id": "F-SC-01", "status": delivered}]},
                    guardian_audit=[],
                )
            )
        )
    out = tmp_path / "render"
    out.mkdir()
    _, statuses, pooled = _render_dataframe_measures(bundles, out, "test", 3)
    rate = pooled["injection_success_rate"].iloc[0]
    assert rate["n"] == 2
    assert rate["k"] == 1
    assert rate["point"] == 0.5
    assert "2/3 delivered attempts" in statuses["injection_success_rate"]


def test_rendered_contrasts_retain_primary_cell_keys(rendered) -> None:
    result, _ = rendered
    table = (result.out_dir / "rq_contrasts.md").read_text(encoding="utf-8")
    for key in ("scenario_id", "injection_condition", "phase"):
        assert key in table


def test_interference_is_written_and_has_an_explicit_status(rendered) -> None:
    result, _ = rendered
    assert "interference" in result.statuses
    path = result.out_dir / "interference__per_run.md"
    assert path in result.tables
    text = path.read_text(encoding="utf-8")
    for field in ("baseline_run_id", "p50_pct_delta", "drop_rate_pct_delta", "residual"):
        assert field in text


def test_renderer_computes_interference_and_v2_detection_from_raw_files(tmp_path) -> None:
    from scenarios.schemas import yamlsubset

    from analysis.render import _render_interference_and_detection
    from analysis.stats import load_bundle
    from analysis.tests._helpers import write_bundle

    truth = yamlsubset.parse(
        (REPO_ROOT / "scenarios/groundtruth/SCN-SIM-01.yaml").read_text(encoding="utf-8")
    )
    events = [
        {"source": label["source"], "signal_id": label["signal"]}
        for label in truth["detection"]["labels"]
    ]
    on = load_bundle(
        write_bundle(
            tmp_path / "on",
            run_id="RUN-G0-FULL-SCN-SIM-01-INJ-NONE-101",
            condition="G0-FULL",
            scenario_id="SCN-SIM-01",
            seed=101,
            baseline_run_id="BASE-LOAD-STEADY-101",
            load_profile_id="LOAD-STEADY",
            injection_condition="INJ-NONE",
            monitor_events=events,
            fidelity={"checks": []},
            locust_stats=[
                {
                    "Name": "Aggregated",
                    "50%": "120",
                    "95%": "300",
                    "Request Count": "1000",
                    "Failure Count": "10",
                }
            ],
        )
    )
    baseline = load_bundle(
        write_bundle(
            tmp_path / "baseline",
            run_id="BASE-LOAD-STEADY-101",
            is_baseline=True,
            condition=None,
            scenario_id=None,
            injection_condition=None,
            seed=101,
            load_profile_id="LOAD-STEADY",
            locust_stats=[
                {
                    "Name": "Aggregated",
                    "50%": "100",
                    "95%": "250",
                    "Request Count": "1000",
                    "Failure Count": "5",
                }
            ],
        )
    )
    paths, statuses = _render_interference_and_detection([on], [baseline], tmp_path, "test", 2)
    assert statuses["interference"].startswith("computed: 1/1")
    assert statuses["detection_precision_recall"].startswith("computed: 1/1")
    interference_table = paths[0].read_text(encoding="utf-8")
    assert "20.0000" in interference_table
    assert "framework + scenario-disturbance overhead" in interference_table
    detection_table = paths[1].read_text(encoding="utf-8")
    assert on.run_id in detection_table
    assert "1.0000" in detection_table
    _, missing = _render_interference_and_detection([on], [], tmp_path, "test", 1)
    assert missing["interference"].startswith("PENDING-BASELINE")


_GENERATOR_SEED = 1


@pytest.fixture(scope="module")
def synthetic_campaign(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, str]:
    """Generate the reduced synthetic corpus once for the whole module (sealing costs a few
    seconds)."""
    root = tmp_path_factory.mktemp("synthetic_runs")
    campaign_id = generate_campaign_for_testing(root, seed=_GENERATOR_SEED, seeds=(101,))
    return root / campaign_id, campaign_id


@pytest.fixture(scope="module")
def rendered(
    synthetic_campaign: tuple[Path, str], tmp_path_factory: pytest.TempPathFactory
) -> tuple[AnalyseResult, Path]:
    """Run ``analyse`` once over the corpus, writing the proof to a tmp path, not the repo."""
    campaign_dir, _campaign_id = synthetic_campaign
    proof_path = tmp_path_factory.mktemp("proof") / ".synthetic-proof.json"
    result = analyse(campaign_dir, generator_seed=_GENERATOR_SEED, proof_path=proof_path)
    return result, proof_path


def test_corpus_digest_skips_a_manifest_that_never_reached_seal(tmp_path: Path) -> None:
    """``corpus_digest`` must not crash on a directory that carries ``manifest.json`` and
    ``invalid.json`` but no ``seal.json`` -- the real CAMP-20260914-campaign pattern that crashed
    ``make analyze`` before this fix (ADR-108's bugfix note). The digest is computed over
    :func:`analysis.stats.sealed_bundle_directories`, the same selection `load_campaign` uses, so
    the never-sealed attempt contributes nothing and does not need to be openable as a seal.
    """
    from runner.run import run_cell

    campaign_id = "CAMP-20260827-synthetic"
    campaign = tmp_path / campaign_id
    sealed = run_cell(
        "G1-LOGONLY",
        "SCN-CVE-04",
        "INJ-A",
        101,
        campaign_id=campaign_id,
        out_root=tmp_path,
        offline=True,
    )

    from analysis.tests._helpers import all_phases_pass, phase_outcome_assertions, write_bundle

    write_bundle(
        campaign / "RUN-G1-LOGONLY-SCN-CVE-05-INJ-A-102",
        run_id="RUN-G1-LOGONLY-SCN-CVE-05-INJ-A-102",
        condition="G1-LOGONLY",
        scenario_id="SCN-CVE-05",
        injection_condition="INJ-A",
        seed=102,
        assertions=phase_outcome_assertions(all_phases_pass()),
    )
    (campaign / "RUN-G1-LOGONLY-SCN-CVE-05-INJ-A-102" / "invalid.json").write_text(
        '{"invalid":true,"reason":"probe-gap"}\n', encoding="utf-8"
    )

    digest = corpus_digest(campaign)
    assert len(digest) == 64
    assert sealed.run_id  # the real sealed bundle is what the digest is actually over

    # Unaffected by the never-sealed directory: matches a digest computed with it absent.
    import shutil

    shutil.rmtree(campaign / "RUN-G1-LOGONLY-SCN-CVE-05-INJ-A-102")
    assert corpus_digest(campaign) == digest


def test_analyse_regenerates_every_expected_table_and_figure(
    rendered: tuple[AnalyseResult, Path],
) -> None:
    """The pooled tables, the contrasts table, the manifest and all three figures are written and
    non-empty."""
    result, _proof_path = rendered
    table_names = {path.name for path in result.tables}
    assert "per_phase_outcome_correctness__pooled.md" in table_names
    assert "policy_compliant_action_rate__pooled.md" in table_names
    assert "resource_overhead__per_run.md" in table_names
    assert "framework_restarts__per_seed.csv" in table_names
    assert "g2_direct_path__per_seed.csv" in table_names
    assert "verified_recovery_claim_fidelity__per_seed.csv" in table_names
    assert "injection_none_same_predicate_base_rates.md" in table_names
    assert "fidelity_checks__per_run.md" in table_names
    assert "rq_contrasts.md" in table_names
    assert "render_manifest.md" in table_names
    assert {figure.name for figure in result.figures} == set(EXPECTED_FIGURES)
    for path in (*result.tables, *result.figures):
        assert path.is_file(), f"{path} was not written"
        assert path.stat().st_size > 0, f"{path} is empty"


def test_rq_contrasts_table_carries_both_mdd_figures_and_the_support_label(
    rendered: tuple[AnalyseResult, Path],
) -> None:
    """Row T-34 / supervisor rulings 2026-09-13 item 3: worst-case MDD, realized MDD, floor, and a
    support label naming which bar the observed difference clears -- beside every contrast's mean
    difference, never only one MDD figure."""
    result, _proof_path = rendered
    contrasts_path = next(path for path in result.tables if path.name == "rq_contrasts.md")
    text = contrasts_path.read_text(encoding="utf-8")
    for column in ("mean_difference", "mdd_worst_case", "mdd_realized", "floor", "support"):
        assert column in text, f"rq_contrasts.md is missing the {column!r} column"
    contrast_statuses = [
        status for name, status in result.statuses.items() if name.startswith("contrast ")
    ]
    assert contrast_statuses, "no per-contrast status was recorded"
    for status in contrast_statuses:
        assert "MDD worst-case" in status
        assert "MDD realized" in status


def test_rq5_contrasts_report_their_own_evaluands_not_outcome_correctness(
    rendered: tuple[AnalyseResult, Path],
) -> None:
    """Gate 5 (2026-09-14 supervisor review; evaluation-protocol.md section 3): RQ5 is the
    guardrail ablation and its rigorous measures are the injection-success rate and the
    policy-compliant action rate -- NOT per-phase outcome correctness, which is RQ2's measure. The
    contrasts table must carry a ``measure`` column, pair the RQ5 arms over each of those two
    measures, and never report an RQ5 contrast over outcome correctness."""
    result, _proof_path = rendered
    contrasts_path = next(path for path in result.tables if path.name == "rq_contrasts.md")
    text = contrasts_path.read_text(encoding="utf-8")
    assert "| measure |" in text, "rq_contrasts.md is missing the measure column"
    study_measure: set[tuple[str, str]] = set()
    for line in text.splitlines():
        if not line.startswith("| RQ"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        study_measure.add((cells[0], cells[1]))
    assert ("RQ5", "injection success rate") in study_measure
    assert ("RQ5", "policy-compliant action rate") in study_measure
    assert ("RQ2", "per-phase outcome correctness") in study_measure
    rq5_measures = {measure for study, measure in study_measure if study == "RQ5"}
    assert "per-phase outcome correctness" not in rq5_measures, (
        "RQ5 must not be reported over RQ2's outcome-correctness measure"
    )


def test_every_table_and_figure_header_carries_the_campaign_id(
    rendered: tuple[AnalyseResult, Path],
) -> None:
    """Every table stamps the campaign_id on its header, and every figure embeds it in PNG
    metadata."""
    result, _proof_path = rendered
    campaign_id = result.campaign_id.encode("utf-8")
    for table in result.tables:
        assert campaign_id in table.read_bytes(), f"{table.name} does not stamp the campaign_id"
    for figure in result.figures:
        assert campaign_id in figure.read_bytes(), f"{figure.name} does not embed the campaign_id"


def test_the_synthetic_proof_records_campaign_id_digest_and_bundle_count(
    rendered: tuple[AnalyseResult, Path],
) -> None:
    """The proof sentinel records the synthetic campaign_id, a sha256 corpus digest and the bundle
    count."""
    result, proof_path = rendered
    assert proof_path.is_file()
    proof = read_proof(proof_path)
    assert proof["campaign_id"] == result.campaign_id
    assert proof["campaign_id"].endswith("-synthetic")
    assert proof["bundle_count"] == result.bundle_count
    assert proof["generator_seed"] == _GENERATOR_SEED
    assert proof["corpus_digest"] == corpus_digest(result.campaign_dir)
    assert len(proof["corpus_digest"]) == 64  # a sha256 hex digest
    assert proof["source_surface_digest"] == source_surface_digest()
    assert len(proof["source_surface_digest"]) == 64
    assert proof["figures"] == sorted(EXPECTED_FIGURES)


def _init_proof_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    (repo / "analysis").mkdir(parents=True)
    (repo / "runner").mkdir()
    (repo / "docs" / "protocols").mkdir(parents=True)
    (repo / "analysis" / "stats.py").write_text("VALUE = 1\n", encoding="utf-8")
    (repo / "runner" / "run.py").write_text("VALUE = 2\n", encoding="utf-8")
    (repo / "docs" / "protocols" / "evaluation.md").write_text("law\n", encoding="utf-8")
    tracked = "analysis/stats.py\nrunner/run.py\ndocs/protocols/evaluation.md\n"
    # Patch the read-only git discovery call: the fixture needs no repository metadata or git write.
    completed = type("Completed", (), {"returncode": 0, "stdout": tracked})()
    monkeypatch.setattr("analysis.render.subprocess.run", lambda *args, **kwargs: completed)
    proof_path = tmp_path / ".synthetic-proof.json"
    write_proof(
        proof_path,
        git_commit="fixture-head",
        generator_seed=1,
        corpus_digest="a" * 64,
        source_digest=source_surface_digest(repo),
        campaign_id="CAMP-20260827-synthetic",
        bundle_count=1,
        tables=[],
        figures=[],
    )
    return repo, proof_path


def test_proof_rejects_uncommitted_analysis_content_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, proof_path = _init_proof_repo(tmp_path, monkeypatch)
    monkeypatch.setattr("analysis.render._current_git_commit", lambda _root: "fixture-head")
    assert proof_matches_tree(proof_path, repo_root=repo)
    (repo / "analysis" / "stats.py").write_text("VALUE = 99\n", encoding="utf-8")
    assert not proof_matches_tree(proof_path, repo_root=repo)


def test_proof_rejects_uncommitted_runner_content_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, proof_path = _init_proof_repo(tmp_path, monkeypatch)
    monkeypatch.setattr("analysis.render._current_git_commit", lambda _root: "fixture-head")
    assert proof_matches_tree(proof_path, repo_root=repo)
    (repo / "runner" / "run.py").write_text("VALUE = 99\n", encoding="utf-8")
    assert not proof_matches_tree(proof_path, repo_root=repo)


def test_proof_rejects_uncommitted_protocol_content_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, proof_path = _init_proof_repo(tmp_path, monkeypatch)
    monkeypatch.setattr("analysis.render._current_git_commit", lambda _root: "fixture-head")
    assert proof_matches_tree(proof_path, repo_root=repo)
    protocol = repo / "docs" / "protocols" / "evaluation.md"
    protocol.write_text("changed law\n", encoding="utf-8")
    assert not proof_matches_tree(proof_path, repo_root=repo)


def test_proof_matches_tree_holds_for_the_written_proof_and_fails_after_tampering(
    rendered: tuple[AnalyseResult, Path], tmp_path: Path
) -> None:
    """``proof_matches_tree`` is true for the fresh proof and false once the recorded commit is
    changed."""
    _result, proof_path = rendered
    if _current_git_commit() is None:
        pytest.skip("git HEAD is not resolvable in this environment; the match check needs it")
    assert proof_matches_tree(proof_path) is True
    # Tamper a copy, so the shared proof stays valid for the other tests in this module.
    tampered = tmp_path / ".synthetic-proof.json"
    payload = json.loads(proof_path.read_text(encoding="utf-8"))
    payload["git_commit"] = "0" * 40
    tampered.write_text(json.dumps(payload), encoding="utf-8")
    assert proof_matches_tree(tampered) is False


def test_a_matched_pairs_contrast_over_the_corpus_resolves_the_alias_to_non_empty_pairs(
    synthetic_campaign: tuple[Path, str],
) -> None:
    """An RQ2 contrast named against S1-HIER finds the G0-FULL bundles and forms a non-empty pair
    set."""
    campaign_dir, _campaign_id = synthetic_campaign
    frame = load_campaign(campaign_dir)
    framework_on = [bundle for bundle in frame["bundle"] if not bundle.is_baseline]
    outcome = per_phase_outcome_correctness(framework_on)
    arm_a, arm_b = RQ2_CONTRASTS[0]  # ("S1-HIER", "S2-FLAT")
    pairs = matched_pairs(outcome, arm_a, arm_b, value_column="correct")
    assert not pairs.empty  # the alias resolved before pairing


def test_analyse_writes_proof_after_mdd_parameters_are_bound(
    synthetic_campaign: tuple[Path, str], tmp_path: Path
) -> None:
    campaign_dir, _campaign_id = synthetic_campaign
    proof_path = tmp_path / ".synthetic-proof.json"
    analyse(campaign_dir, generator_seed=_GENERATOR_SEED, proof_path=proof_path)
    assert proof_path.is_file()


def test_analyse_refuses_a_metrics_json_path(tmp_path: Path) -> None:
    """A ``metrics.json`` path handed to the render is refused (data-management §8)."""
    metrics = tmp_path / "metrics.json"
    metrics.write_text("{}", encoding="utf-8")
    with pytest.raises(MetricsJsonRefused):
        analyse(metrics)


class _StubBundle:
    """A minimal stand-in for a loaded Bundle: the frozen-commit gate reads only these two."""

    def __init__(self, run_id: str, commit: str) -> None:
        self.run_id = run_id
        self.manifest = {"git_commit": commit}


def test_frozen_commit_gate_hard_errors_on_a_divergent_bundle(tmp_path: Path) -> None:
    """Gate 2 (supervisor 2026-09-14): when a campaign declares a frozen commit, a bundle produced
    at a different instrument commit is a hard error -- a frozen campaign may not span
    instruments."""
    from analysis.render import RenderError, _enforce_frozen_commit

    (tmp_path / "frozen_commit.txt").write_text("aaaa\n", encoding="utf-8")
    assert (
        _enforce_frozen_commit(tmp_path, [_StubBundle("r1", "aaaa"), _StubBundle("r2", "aaaa")])
        == "aaaa"
    )
    with pytest.raises(RenderError, match="frozen at commit aaaa"):
        _enforce_frozen_commit(tmp_path, [_StubBundle("r1", "aaaa"), _StubBundle("r2", "bbbb")])


def test_frozen_commit_gate_warns_when_absent_and_spanning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """No frozen_commit.txt (a pre-freeze pilot): a spanning commit set is a stderr WARNING, not a
    hard error, so an accepted proof-documented straddle still analyses."""
    from analysis.render import _enforce_frozen_commit

    assert (
        _enforce_frozen_commit(tmp_path, [_StubBundle("r1", "aaaa"), _StubBundle("r2", "bbbb")])
        is None
    )
    assert "PROVENANCE WARNING" in capsys.readouterr().err
