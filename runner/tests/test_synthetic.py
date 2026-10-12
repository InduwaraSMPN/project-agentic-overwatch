r"""The synthetic generator emits a corpus the sealer accepts and the validator passes.

The seal and the campaign validation run inside :func:`generate_campaign`, so a bundle that
failed either would raise -- the generator cannot emit a corpus the rest of the milestone would
reject. The corpus is generated ONCE per module (sealing costs ~0.1s per bundle) over the reduced
one-seed grid, because the full 755-bundle corpus is a proof-time cost carried by ``make analyze``,
not a unit-test one; the reduced grid exercises the same seal, chain and validation paths.
"""

import json
import sys
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402
from guardian.audit.record_types import RUN_START_RECORD_TYPE  # noqa: E402

from runner.bundle import load_seal, verify_content_hashes  # noqa: E402
from runner.campaign import SYNTHETIC_SLUG  # noqa: E402
from runner.synthetic import generate_campaign_for_testing  # noqa: E402

REDUCED = (101,)  # one seed: 6 arms x 25 base cells x 1 seed = 150 grid runs + 1 baseline


@pytest.fixture(scope="module")
def corpus(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, str]:
    """Generate the reduced synthetic corpus once; the seal and validation run inside this call."""
    root = tmp_path_factory.mktemp("synthetic")
    campaign_id = generate_campaign_for_testing(root, seed=42, seeds=REDUCED)
    return root, campaign_id


def test_generate_seals_and_validates_the_reduced_corpus(corpus: tuple[Path, str]) -> None:
    """generate_campaign seals every bundle and passes validate_campaign_corpus, or it raises."""
    root, campaign_id = corpus
    assert campaign_id.endswith(f"-{SYNTHETIC_SLUG}")
    bundles = list((root / campaign_id).glob("*/manifest.json"))
    assert len(bundles) == 6 * 25 * 1 + 1  # 150 grid + 1 baseline


def test_synthetic_framework_bundles_carry_explicit_required_substep_results(
    corpus: tuple[Path, str],
) -> None:
    """The synthetic proof exercises the M5/M6 sub-step contract, not an assertion-ratio proxy."""
    root, campaign_id = corpus
    files = list((root / campaign_id).glob("RUN-*/assertions.json"))
    assert files
    for path in files:
        payload = json.loads(path.read_text(encoding="utf-8"))
        results = payload["required_substep_results"]
        assert results
        assert {result["phase"] for result in results} == {
            "detection-and-investigation",
            "containment",
            "eradication",
            "verified-recovery",
        }
        assert {result["result"] for result in results} <= {"reached", "not-reached"}


def test_synthetic_inj_b_uses_planned_pool02_and_raw_outcome(corpus: tuple[Path, str]) -> None:
    """Modern synthetic B exercises payload attribution from the same raw streams as live."""
    from guardian.audit.outcome import bundle_status_by_seq
    from scenarios.attackers.plan import plan_cell

    from runner.evaluate_assertions import _payload_outcome, _phase_by_seq, build_action_streams

    root, campaign_id = corpus
    bundle = root / campaign_id / "RUN-G0-FULL-SCN-CVE-04-INJ-B-101"
    log = [json.loads(line) for line in (bundle / "injection.log.jsonl").read_text().splitlines()]
    planned = plan_cell("SCN-CVE-04", "INJ-B", 101)
    assert len(log) == len(planned)
    assert [row["event_id"] for row in log] == [row["event_id"] for row in planned]
    injection = next(row for row in log if row["kind"] == "injection")
    assert injection["detail"]["content_pool"] == "INJ-B-pool-02"
    audit = [
        json.loads(line) for line in (bundle / "guardian_audit.jsonl").read_text().splitlines()
    ]
    api = [json.loads(line) for line in (bundle / "k8s_api_audit.jsonl").read_text().splitlines()]
    results = json.loads((bundle / "results.json").read_text())
    streams = build_action_streams(
        audit,
        api,
        status_by_seq=bundle_status_by_seq(audit, results),
        phase_by_seq=_phase_by_seq(results),
    )
    outcome = json.loads((bundle / "assertions.json").read_text())["payload_outcome"]
    assert outcome == _payload_outcome(bundle, streams)
    assert outcome["payload_id"] == injection["payload_id"]
    events = [
        json.loads(line) for line in (bundle / "monitor_events.jsonl").read_text().splitlines()
    ]
    assert any(event["signal_id"] for event in events)


def test_every_synthetic_bundle_carries_a_verifiable_seal(corpus: tuple[Path, str]) -> None:
    """Each sealed bundle's recorded content hashes still match its files."""
    root, campaign_id = corpus
    for manifest_path in (root / campaign_id).glob("*/manifest.json"):
        bundle_dir = manifest_path.parent
        seal = load_seal(bundle_dir)
        assert "content_hashes" in seal
        assert verify_content_hashes(bundle_dir) == [], bundle_dir.name


def test_the_campaign_id_uses_the_reserved_synthetic_slug(corpus: tuple[Path, str]) -> None:
    """A figure from synthetic data must be able to say so; the slug is how (ADR-042)."""
    _, campaign_id = corpus
    assert campaign_id == "CAMP-20260101-synthetic"


def test_two_generations_at_one_seed_are_byte_identical(tmp_path: Path) -> None:
    """The corpus is a pure function of (seed, date), so the synthetic proof digest is stable."""
    first = generate_campaign_for_testing(tmp_path / "a", seed=99, seeds=REDUCED)
    second = generate_campaign_for_testing(tmp_path / "b", seed=99, seeds=REDUCED)
    assert first == second
    for manifest_path in (tmp_path / "a" / first).glob("*/manifest.json"):
        rel = manifest_path.relative_to(tmp_path / "a")
        assert manifest_path.read_bytes() == (tmp_path / "b" / rel).read_bytes(), rel


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def test_every_synthetic_chain_opens_with_the_guardian_run_start(corpus: tuple[Path, str]) -> None:
    """Synthetic chains mirror production (ADR-058): one run-start genesis, then decisions.

    Every record names the bundle's own run -- ADR-054's boundary, which analysis enforces as a hard
    error -- and the arm the manifest says the Guardian ran.
    """
    root, campaign_id = corpus
    chains = sorted((root / campaign_id).glob("RUN-*/guardian_audit.jsonl"))
    assert chains
    for chain in chains:
        lines = chain.read_text(encoding="utf-8").splitlines()
        records = [json.loads(line) for line in lines if line.strip()]
        manifest = json.loads((chain.parent / "manifest.json").read_text(encoding="utf-8"))
        kinds = [record["record_type"] for record in records]
        assert kinds[0] == RUN_START_RECORD_TYPE, chain.parent.name
        assert RUN_START_RECORD_TYPE not in kinds[1:], chain.parent.name
        assert records[0]["seq"] == 0
        assert _instant(records[0]["ts"]) == _instant(manifest["started_at"])
        assert {record["run_id"] for record in records} == {manifest["run_id"]}
        assert {record["guardian_mode"] for record in records} == {manifest["guardian_mode"]}


def test_every_synthetic_monitor_timestamp_lies_inside_its_run_window(
    corpus: tuple[Path, str],
) -> None:
    """ADR-054's boundary, met by the generator: no Monitor event outside its run's window."""
    root, campaign_id = corpus
    streams = sorted((root / campaign_id).glob("RUN-*/monitor_events.jsonl"))
    assert streams
    for stream in streams:
        manifest = json.loads((stream.parent / "manifest.json").read_text(encoding="utf-8"))
        started, ended = _instant(manifest["started_at"]), _instant(manifest["ended_at"])
        for line in stream.read_text(encoding="utf-8").splitlines():
            if line.strip():
                stamp = _instant(json.loads(line)["ts"])
                assert started <= stamp <= ended, (stream.parent.name, stamp)
