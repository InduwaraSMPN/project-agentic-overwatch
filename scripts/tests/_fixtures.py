"""Shared fixtures for scripts/tests: a campaign directory of really-sealed run bundles.

WHY A HELPER MODULE, AND WHY IT IS PRIVATE
    Two suites in this directory need a campaign whose bundles carry a real ``seal.json``:
    ``test_scoring_ui.py`` (which the scoring server will not open a bundle without) and
    ``test_scoring_provenance.py`` (whose compliant-session fixture is produced by driving the real
    scoring UI, so it inherits the same requirement). Both need the same recipe, and a recipe
    duplicated into two files is a recipe that will be fixed in one of them.

    Named with a leading underscore so pytest does not collect it, and holding no test of its own --
    every assertion about these bundles lives in the suite that uses them, which is the arrangement
    ``scripts/tests/__init__.py`` already describes for this directory.

WHAT THE RECIPE DOES, AND WHY IT IS NOT SIMPLER
    ``runner.run.run_cell(..., offline=True)`` produces a bundle with the same sealable shape
    ``make run --offline`` does, and ``runner.bundle.seal_bundle`` is the production sealer. Between
    them they satisfy the one property the fixture exists for: the seal was written by this
    repository's own code, so a test that exercises a seal check is exercising the real check.

    One artefact is fabricated when the sealer names it as missing, and only then:
    ``k8s_api_audit.jsonl``, which a live run collects from the control plane
    (``runner/live_evidence.py::collect_api_audit``) and which ``runner/bundle.py`` requires for
    every
    framework-on run under ADR-137. ``runner/bundle.py`` is another workstream's file and its
    completeness profile is still growing, so the fixture responds to the sealer's own message
    rather
    than to a file list copied here -- a list that would silently stop testing the seal the moment
    the
    profile changed. The two records written are the window-open and window-close sentinels ADR-137
    defines, which is the least this file can carry and still be the file a fidelity check reads.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from runner.bundle import seal_bundle  # noqa: E402
from runner.manifest import from_dict  # noqa: E402
from runner.run import run_cell  # noqa: E402

# A fixed window, so a fixture bundle never depends on the wall clock. The sealer takes `sealed_at`
# as an argument precisely so a test can seal deterministically.
SEALED_AT = "2026-10-01T12:20:00+00:00"

_API_AUDIT_RECORDS = [
    {
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "level": "Metadata",
        "verb": "patch",
        "stage": "ResponseComplete",
        "requestReceivedTimestamp": "2026-10-01T12:00:00.000000Z",
        "user": {"username": "system:serviceaccount:agents:runner-control-plane"},
        "objectRef": {"resource": "deployments", "namespace": "boutique", "name": "adservice"},
        "annotations": {"overwatch.dev/window-sentinel": "open"},
    },
    {
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "level": "Metadata",
        "verb": "patch",
        "stage": "ResponseComplete",
        "requestReceivedTimestamp": "2026-10-01T12:20:00.000000Z",
        "user": {"username": "system:serviceaccount:agents:runner-control-plane"},
        "objectRef": {"resource": "deployments", "namespace": "boutique", "name": "adservice"},
        "annotations": {"overwatch.dev/window-sentinel": "close"},
    },
]


def seal_offline_bundle(bundle_dir: Path, detail: str = "") -> None:
    """Complete an offline cell the sealer refused, then seal it through ``seal_bundle``.

    ``detail`` is the sealer's own message, so the one artefact this fabricates is named by the
    production code rather than chosen here. An unrecognised message is a hard failure rather than a
    silent skip: a fixture that quietly stopped sealing would leave every test using it passing over
    an unverified bundle, which is the vacuous pass this repository refuses everywhere.
    """
    if "k8s_api_audit.jsonl" not in detail:
        raise AssertionError(
            f"the offline cell failed to seal for an unexpected reason, and this helper knows how "
            f"to complete only the API-audit slice: {detail}"
        )
    (bundle_dir / "k8s_api_audit.jsonl").write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in _API_AUDIT_RECORDS),
        encoding="utf-8",
    )
    manifest = from_dict(json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8")))
    seal_bundle(bundle_dir, manifest, sealed_at=SEALED_AT)


def sealed_campaign(
    tmp_path: Path,
    campaign_id: str,
    cells: list[tuple[str, str, str, int]],
) -> Path:
    """Seal one offline bundle per ``(condition, scenario, injection, seed)`` into ONE campaign dir.

    A campaign directory is the unit both suites under test work in: ``scoring_ui`` refuses to open
    a
    bundle that is not under the campaign it was given, and ``scoring_provenance`` reads a sample
    file that names run ids relative to it. So the four arms of a matched tuple have to land
    together,
    which is why this takes a list rather than one cell.

    Returns the campaign directory. Raises rather than returning a partially built one: a fixture
    that leaves three of four bundles in place would let a suite's own assertions decide what the
    missing fourth means, and they would decide it wrongly.
    """
    out_root = tmp_path / f"runs-{campaign_id}"
    for condition, scenario, injection, seed in cells:
        outcome = run_cell(
            condition,
            scenario,
            injection,
            seed,
            campaign_id=campaign_id,
            out_root=out_root,
            offline=True,
        )
        bundle_dir = out_root / campaign_id / f"RUN-{condition}-{scenario}-{injection}-{seed}"
        if not outcome.sealed:
            seal_offline_bundle(bundle_dir, outcome.detail or "")
        if not (bundle_dir / "seal.json").is_file():
            raise AssertionError(
                f"the fixture bundle {bundle_dir.name} did not seal: {outcome.detail}"
            )
    campaign_dir = out_root / campaign_id
    if not campaign_dir.is_dir():
        raise AssertionError(f"the fixture campaign directory was not created at {campaign_dir}")
    return campaign_dir


def sealed_run(tmp_path: Path, condition: str, scenario: str, injection: str, seed: int) -> Path:
    """Return the path of one freshly sealed offline bundle, in a campaign of its own.

    The thin single-cell wrapper over :func:`sealed_campaign`, for a suite that needs exactly one
    bundle and does not care which campaign it sits in. The campaign id is derived from the run's
    own
    coordinates, so the returned path is predictable to a caller that has to name the directory.
    """
    campaign_id = f"CAMP-TEST-{condition}-{scenario}-{injection}-{seed}"
    campaign_dir = sealed_campaign(tmp_path, campaign_id, [(condition, scenario, injection, seed)])
    return campaign_dir / f"RUN-{condition}-{scenario}-{injection}-{seed}"
