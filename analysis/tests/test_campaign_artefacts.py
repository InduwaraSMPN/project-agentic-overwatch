r"""The WS-6 campaign-artefact producers, verified against the checks that read them.

Each producer's document is fed to the ACTUAL fidelity predicate that consumes it
(``runner.fidelity``'s F-AN-02, F-SC-03b, F-SC-04, F-SC-05, F-AN-01), because the failure this
suite exists to prevent is a producer and a consumer that disagree about a key: the file parses, the
check finds nothing where it looked, and a campaign that never delivered a treatment reads as clean.
A shape assertion written by hand would pass while that was true; asking the real check does not.

The fixtures are the hand-authored bundles ``analysis/tests/_helpers.py`` builds -- the same
``manifest.json`` plus whichever file a measure needs, never ``runner.bundle.seal_bundle`` -- so a
test can describe exactly the corpus a producer must read without a cluster or a sealed campaign.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from runner.fidelity import BundleView  # noqa: E402
from runner.fidelity.analysis import (  # noqa: E402
    f_an_01_readiness_gate,
    f_an_02_no_predicate_is_vacuous,
)
from runner.fidelity.scenarios import (  # noqa: E402
    f_sc_03b_base_rate_is_below_the_discrimination_threshold,
    f_sc_04_payload_coverage_per_class,
    f_sc_05_every_groundtruth_check_is_failable,
)

from analysis.render import (  # noqa: E402
    JUDGED_MEASURES,
    TABLE_MEASURES,
    _write_readiness_document,
    readiness_gate,
)
from analysis.stats.campaign_artefacts import (  # noqa: E402
    ASSERTION_AVAILABILITY_FILENAME,
    INJECTION_BASE_RATES_FILENAME,
    PAYLOAD_COVERAGE_FILENAME,
    VACUITY_FILENAME,
    assertion_availability_document,
    inj_b_delivery_document,
    injection_base_rates_document,
    payload_coverage_document,
    vacuity_document,
    write_campaign_artefacts,
)
from analysis.tests._helpers import (  # noqa: E402
    load,
    phase_outcome_assertions,
    write_bundle,
)

CAMPAIGN = "CAMP-20260928-pilot"


def _view(campaign_dir: Path, bundle_dir: Path, *, stage: str | None = None) -> BundleView:
    """A :class:`BundleView` over one fixture bundle, pointed at its campaign directory."""
    return BundleView(bundle_dir=bundle_dir, campaign_dir=campaign_dir, required_stage=stage)


def _arm_bundles(
    campaign_dir: Path,
    *,
    condition: str,
    injection: str,
    results: list[str],
    seed: int = 101,
) -> tuple[Path, list]:
    """Write two real bundles of one arm and return the first bundle dir plus the loaded pair."""
    dirs = []
    for offset, result in enumerate(results):
        run_id = f"RUN-{condition}-SCN-SIM-01-{injection}-{seed + offset}"
        directory = write_bundle(
            campaign_dir / run_id,
            run_id=run_id,
            condition=condition,
            scenario_id="SCN-SIM-01",
            injection_condition=injection,
            seed=seed + offset,
            assertions=phase_outcome_assertions({"containment": [result]}),
        )
        dirs.append(directory)
    return dirs[0], [load(directory) for directory in dirs]


# ================================================================================================
# F-AN-02 -- vacuity.json
# ================================================================================================


def test_vacuity_document_flags_a_never_failing_predicate_and_the_check_fails(
    tmp_path: Path,
) -> None:
    """A predicate that passes in every run it was evaluated in is flagged, and F-AN-02 reads it.

    Both bundles pass the same containment assertion, so the predicate never moved and the producer
    must name it -- and the check, handed the file the producer wrote, must call it a failure rather
    than a clean corpus.
    """
    campaign_dir = tmp_path / CAMPAIGN
    bundle_dir, bundles = _arm_bundles(
        campaign_dir, condition="G0-FULL", injection="INJ-A", results=["pass", "pass"]
    )
    document = vacuity_document(bundles)
    assert "SCN-SIM-01/containment/ASR-01" in document["never_fails"]
    assert document["predicates"] >= 1
    assert document["by_arm"]["G0-FULL"] == ["SCN-SIM-01/containment/ASR-01"]

    (campaign_dir / VACUITY_FILENAME).write_text(json.dumps(document), encoding="utf-8")
    outcome = f_an_02_no_predicate_is_vacuous(_view(campaign_dir, bundle_dir))
    assert outcome.status == "fail", outcome.detail


def test_vacuity_document_is_empty_for_a_corpus_where_every_predicate_moves(tmp_path: Path) -> None:
    """One pass and one fail for the same predicate is not vacuous, and F-AN-02 passes.

    The mirror of the case above: the producer must not flag a predicate that took both values, and
    the check must read the empty sets as the clean result they are.
    """
    campaign_dir = tmp_path / CAMPAIGN
    bundle_dir, bundles = _arm_bundles(
        campaign_dir, condition="G0-FULL", injection="INJ-A", results=["pass", "fail"]
    )
    document = vacuity_document(bundles)
    assert document["never_fails"] == []
    assert document["always_fails"] == []
    assert document["predicates"] >= 1

    (campaign_dir / VACUITY_FILENAME).write_text(json.dumps(document), encoding="utf-8")
    outcome = f_an_02_no_predicate_is_vacuous(_view(campaign_dir, bundle_dir))
    assert outcome.status == "pass", outcome.detail


def test_vacuity_document_is_producer_pending_without_a_file(tmp_path: Path) -> None:
    """No vacuity.json is the documented pre-producer skip, not a failure (ADR-146)."""
    campaign_dir = tmp_path / CAMPAIGN
    bundle_dir, _bundles = _arm_bundles(
        campaign_dir, condition="G0-FULL", injection="INJ-A", results=["pass", "fail"]
    )
    outcome = f_an_02_no_predicate_is_vacuous(_view(campaign_dir, bundle_dir))
    assert outcome.status == "skip"
    assert outcome.cause == "producer-absent"


# ================================================================================================
# F-SC-03b -- injection_base_rates.json
# ================================================================================================


def test_injection_base_rates_document_is_per_arm_and_the_check_passes(tmp_path: Path) -> None:
    """The roll-up is ``{arm: {payload_id: rate}}`` and F-SC-03b passes when every rate is at/below.

    The arm's INJ-NONE runs execute no induced action, so every rate is ``0.0`` -- which is the
    measured "this arm does not act on its own" rather than an absent measurement.
    """
    campaign_dir = tmp_path / CAMPAIGN
    bundle_dir, bundles = _arm_bundles(
        campaign_dir, condition="G0-FULL", injection="INJ-NONE", results=["pass", "fail"]
    )
    document = injection_base_rates_document(bundles)
    assert set(document["arms"]) == {"G0-FULL"}
    rates = document["arms"]["G0-FULL"]
    assert rates, "the arm's INJ-NONE runs must produce a per-payload rate map"
    assert all(rate == 0.0 for rate in rates.values())

    (campaign_dir / INJECTION_BASE_RATES_FILENAME).write_text(
        json.dumps(document), encoding="utf-8"
    )
    outcome = f_sc_03b_base_rate_is_below_the_discrimination_threshold(
        _view(campaign_dir, bundle_dir)
    )
    assert outcome.status == "pass", outcome.detail


def test_injection_base_rates_over_the_ceiling_fails_the_check(tmp_path: Path) -> None:
    """A rate above the discrimination ceiling is what F-SC-03b exists to catch (V5).

    Hand-built because the fixture cannot make an arm act spontaneously without a Guardian chain;
    the producer's job is the shape, and this asserts the consumer rejects a shape it must.
    """
    campaign_dir = tmp_path / CAMPAIGN
    bundle_dir, _bundles = _arm_bundles(
        campaign_dir, condition="G0-FULL", injection="INJ-NONE", results=["pass", "fail"]
    )
    document = {"arms": {"G0-FULL": {"INJ-A-pool-02-001": 0.88}}}
    (campaign_dir / INJECTION_BASE_RATES_FILENAME).write_text(
        json.dumps(document), encoding="utf-8"
    )
    outcome = f_sc_03b_base_rate_is_below_the_discrimination_threshold(
        _view(campaign_dir, bundle_dir)
    )
    assert outcome.status == "fail", outcome.detail


# ================================================================================================
# F-SC-04 -- payload_coverage.json
# ================================================================================================


def test_payload_coverage_document_covers_every_class_and_the_check_passes(tmp_path: Path) -> None:
    """Every pool-02 class is reported as fully covered, and F-SC-04 passes over the document.

    INJ-A/C/D are proven by the offline channel round trip (recorded, not re-run); INJ-B is a live
    measurement, so its delivered count is read from an injection log the fixture writes.
    """
    campaign_dir = tmp_path / CAMPAIGN
    bundle_dir, bundles = _arm_bundles(
        campaign_dir, condition="G0-FULL", injection="INJ-B", results=["pass", "fail"]
    )
    pool = json.loads(
        (REPO_ROOT / "scenarios" / "attackers" / "content" / "INJ-B-pool-02.json").read_text(
            encoding="utf-8"
        )
    )
    payload_ids = [instance["payload_id"] for instance in pool["instances"]]
    records = [{"kind": "injection", "payload_id": payload_id} for payload_id in payload_ids]
    log = "\n".join(json.dumps(record) for record in records) + "\n"
    (bundle_dir / "injection.log.jsonl").write_text(log, encoding="utf-8")
    bundles = [load(bundle_dir), bundles[1]]

    document = payload_coverage_document(bundles)
    assert document["expected"] == {
        "INJ-A": len(payload_ids),
        "INJ-B": len(payload_ids),
        "INJ-C": len(payload_ids),
        "INJ-D": len(payload_ids),
    }
    assert document["delivered"]["INJ-B"] == len(payload_ids)

    (campaign_dir / PAYLOAD_COVERAGE_FILENAME).write_text(json.dumps(document), encoding="utf-8")
    outcome = f_sc_04_payload_coverage_per_class(_view(campaign_dir, bundle_dir, stage="offline"))
    assert outcome.status == "pass", outcome.detail


# ================================================================================================
# F-SC-05 -- assertion_availability.json
# ================================================================================================


def test_assertion_availability_document_is_the_shape_f_sc_05_reads(tmp_path: Path) -> None:
    """The audit's document names no stuck predicate and reports the 129 checks F-SC-05 is over."""
    campaign_dir = tmp_path / CAMPAIGN
    bundle_dir, _bundles = _arm_bundles(
        campaign_dir, condition="G0-FULL", injection="INJ-A", results=["pass", "fail"]
    )
    document = assertion_availability_document()
    assert document["never_fails"] == []
    assert document["always_fails"] == []
    assert document["checks"] == 129

    (campaign_dir / ASSERTION_AVAILABILITY_FILENAME).write_text(
        json.dumps(document), encoding="utf-8"
    )
    outcome = f_sc_05_every_groundtruth_check_is_failable(_view(campaign_dir, bundle_dir))
    assert outcome.status == "pass", outcome.detail


# ================================================================================================
# F-AN-01 -- readiness.json (written by analysis.render)
# ================================================================================================


def test_readiness_document_round_trips_through_f_an_01(tmp_path: Path) -> None:
    """The renderer's readiness document is read by F-AN-01 as a pilot-gate WARN, never a failure.

    Every Table 3.3 measure is computed and the judged measure is still pending -- the ordinary
    state at the pilot gate -- so F-AN-01 reports a WARN, which the gate does not block on.
    """
    campaign_dir = tmp_path / CAMPAIGN
    bundle_dir, _bundles = _arm_bundles(
        campaign_dir, condition="G0-FULL", injection="INJ-A", results=["pass", "fail"]
    )
    statuses = {measure: "computed: 2 run(s)" for measure in TABLE_MEASURES}
    report = readiness_gate(statuses, stage="pilot")
    path = _write_readiness_document(campaign_dir, report)
    assert path == campaign_dir / "readiness.json"
    written = json.loads(path.read_text(encoding="utf-8"))
    assert set(written["measures"]) == set(TABLE_MEASURES)
    assert written["judged"] == {JUDGED_MEASURES[0]: "pending"}

    outcome = f_an_01_readiness_gate(_view(campaign_dir, bundle_dir, stage="pilot gate"))
    assert outcome.status == "warn", outcome.detail


def test_readiness_document_without_the_file_fails_the_gate(tmp_path: Path) -> None:
    """No readiness.json at the pilot gate is a FAIL -- the check the producer exists to satisfy."""
    campaign_dir = tmp_path / CAMPAIGN
    bundle_dir, _bundles = _arm_bundles(
        campaign_dir, condition="G0-FULL", injection="INJ-A", results=["pass", "fail"]
    )
    outcome = f_an_01_readiness_gate(_view(campaign_dir, bundle_dir, stage="pilot gate"))
    assert outcome.status == "fail", outcome.detail


# ================================================================================================
# the writer
# ================================================================================================


def test_write_campaign_artefacts_is_canonical_and_deterministic(tmp_path: Path) -> None:
    """The four files are written into the campaign directory, canonically, and re-run identically.

    Canonical bytes are what let a diff over two runs mean "the corpus changed"; determinism is the
    same property asserted the only way it can be -- by writing twice and comparing.
    """
    campaign_dir = tmp_path / CAMPAIGN
    _arm_bundles(campaign_dir, condition="G0-FULL", injection="INJ-NONE", results=["pass", "fail"])
    first = write_campaign_artefacts(campaign_dir)
    assert set(first) == {
        str(campaign_dir / VACUITY_FILENAME),
        str(campaign_dir / INJECTION_BASE_RATES_FILENAME),
        str(campaign_dir / PAYLOAD_COVERAGE_FILENAME),
        str(campaign_dir / ASSERTION_AVAILABILITY_FILENAME),
    }
    before = {name: Path(name).read_bytes() for name in first}
    second = write_campaign_artefacts(campaign_dir)
    assert {name: Path(name).read_bytes() for name in second} == before

    vacuity = json.loads((campaign_dir / VACUITY_FILENAME).read_text(encoding="utf-8"))
    assert (campaign_dir / VACUITY_FILENAME).read_bytes().endswith(b"\n")
    assert json.dumps(vacuity, sort_keys=True, separators=(",", ":")) in (
        campaign_dir / VACUITY_FILENAME
    ).read_text(encoding="utf-8")


def test_write_campaign_artefacts_unions_several_campaigns(tmp_path: Path) -> None:
    """Two campaign directories are read as one corpus and both receive the same documents.

    This is the pilot's shape: P0-live, P2 and P3 are separate campaign ids, and INJ-B's coverage
    (established in P0-live) has to reach the directory the gate points at.
    """
    live = tmp_path / "CAMP-p0live"
    coverage = tmp_path / "CAMP-p2"
    _arm_bundles(live, condition="G0-FULL", injection="INJ-NONE", results=["pass", "fail"])
    _arm_bundles(coverage, condition="G1-LOGONLY", injection="INJ-NONE", results=["pass", "fail"])
    written = write_campaign_artefacts([live, coverage])
    assert len(written) == 8, "four artefacts into each of the two directories"

    for root in (live, coverage):
        vacuity = json.loads((root / VACUITY_FILENAME).read_text(encoding="utf-8"))
        assert set(vacuity["by_arm"]) == {"G0-FULL", "G1-LOGONLY"}, "the union of both arms"


@pytest.mark.parametrize(
    "delivery,expected",
    [
        ({"attempted": 10, "landed": 9}, "pass"),
        ({"attempted": 10, "landed": 8}, "fail"),
        ({"attempted": 0, "landed": 0}, "fail"),
        ({"attempted": 2, "landed": 3}, "fail"),
        ({"attempted": True, "landed": 1}, "fail"),
        (None, "fail"),
    ],
)
def test_live_coverage_enforces_measured_landing_floor(tmp_path, monkeypatch, delivery, expected):
    import runner.fidelity

    monkeypatch.setattr(runner.fidelity, "resolve_optional", lambda key: 0.9)
    root = tmp_path / CAMPAIGN
    bundle_dir, _ = _arm_bundles(
        root, condition="G0-FULL", injection="INJ-B", results=["pass", "fail"]
    )
    document = {"expected": {"INJ-B": 8}, "delivered": {"INJ-B": 8}, "inj_b_delivery": delivery}
    (root / PAYLOAD_COVERAGE_FILENAME).write_text(json.dumps(document), encoding="utf-8")
    outcome = f_sc_04_payload_coverage_per_class(_view(root, bundle_dir, stage="P0-live"))
    assert outcome.status == expected, outcome.detail


def test_live_coverage_cannot_pass_with_uncalibrated_floor(tmp_path, monkeypatch):
    from runner.fidelity import PROPOSED_SENTINEL, PROTOCOL_MIRRORED_CONSTANTS

    monkeypatch.setitem(PROTOCOL_MIRRORED_CONSTANTS, "inj_b_landing_floor", PROPOSED_SENTINEL)
    root = tmp_path / CAMPAIGN
    bundle_dir, _ = _arm_bundles(
        root, condition="G0-FULL", injection="INJ-B", results=["pass", "fail"]
    )
    document = {
        "expected": {"INJ-B": 8},
        "delivered": {"INJ-B": 8},
        "inj_b_delivery": {"attempted": 20, "landed": 20},
    }
    (root / PAYLOAD_COVERAGE_FILENAME).write_text(json.dumps(document), encoding="utf-8")
    outcome = f_sc_04_payload_coverage_per_class(_view(root, bundle_dir, stage="P0-live"))
    assert outcome.status == "fail"
    assert "PROPOSED" in outcome.detail


def test_delivery_denominator_retains_unsealed_miss_and_rerun(tmp_path):
    from scenarios.attackers.marker import payload_marker

    root = tmp_path / CAMPAIGN
    marker = payload_marker("SCN-SIM-01", "INJ-B", 901)
    for suffix, landed in (("", False), ("-R2", True)):
        directory = root / ("RUN-G0-FULL-SCN-SIM-01-INJ-B-901" + suffix)
        directory.mkdir(parents=True)
        record = {
            "kind": "injection",
            "payload_id": "INJ-B-pool-02-001",
            "applied": {"outcome": "applied"},
        }
        (directory / "injection.log.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
        if landed:
            (directory / "monitor_events.jsonl").write_text(
                json.dumps({"raw": marker}) + "\n", encoding="utf-8"
            )
            (directory / "seal.json").write_text("{}", encoding="utf-8")
    assert inj_b_delivery_document([root]) == {"attempted": 2, "landed": 1}


def test_synthetic_delivery_is_not_live_calibration(tmp_path):
    root = tmp_path / CAMPAIGN
    directory = root / "RUN-G0-FULL-SCN-SIM-01-INJ-B-901"
    directory.mkdir(parents=True)
    record = {
        "kind": "injection",
        "payload_id": "INJ-B-pool-02-001",
        "applied": {"outcome": "synthetic"},
    }
    (directory / "injection.log.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
    assert inj_b_delivery_document([root]) == {"attempted": 0, "landed": 0}
