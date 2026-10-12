r"""Every primitive a manifest names resolves to something real.

The schema validates a manifest's shape; it cannot check that a ``ref`` points at a file that
exists or an ``images.yaml`` entry that is declared. That cross-file resolution is exactly where two
independently-authored halves of the corpus can drift -- a manifest naming a Chaos Mesh CRD by a
filename nobody wrote, or a CVE primitive naming an image id the digest file does not carry -- and
it passes every per-file check while being broken. These tests close that gap: a dangling ref is a
test failure at M5, not a resolution error at Tier B when a cluster is finally there to expose it.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402
from infra.probes.constants import SLO_PROBE_SET  # noqa: E402

from scenarios.attackers import plan as planner  # noqa: E402
from scenarios.schemas import yamlsubset as Y  # noqa: E402

MANIFEST_DIR = REPO_ROOT / "scenarios" / "manifests"
IMAGES_FILE = REPO_ROOT / "scenarios" / "cve" / "images.yaml"

SCENARIO_IDS = planner.manifest_ids()


def _load(path: Path) -> dict:
    return Y.parse(path.read_text(encoding="utf-8"))


def _cve_image_ids() -> set[str]:
    if not IMAGES_FILE.is_file():
        return set()
    document = _load(IMAGES_FILE)
    return {entry["id"] for entry in document.get("images", [])}


@pytest.mark.parametrize("scenario_id", SCENARIO_IDS)
def test_chaosmesh_refs_resolve_to_a_crd_file(scenario_id: str) -> None:
    manifest = _load(MANIFEST_DIR / f"{scenario_id}.yaml")
    for primitive in manifest["incident_primitives"]:
        if primitive["mechanism"] != "chaosmesh":
            continue
        ref = REPO_ROOT / primitive["ref"]
        assert ref.is_file(), (
            f"{scenario_id}: chaosmesh primitive {primitive['primitive_id']} references "
            f"{primitive['ref']}, which is not a file"
        )


@pytest.mark.parametrize("scenario_id", SCENARIO_IDS)
def test_attacker_refs_resolve_to_a_file(scenario_id: str) -> None:
    manifest = _load(MANIFEST_DIR / f"{scenario_id}.yaml")
    for primitive in manifest["incident_primitives"]:
        if primitive["mechanism"] != "attacker":
            continue
        ref = REPO_ROOT / primitive["ref"]
        assert ref.is_file(), (
            f"{scenario_id}: attacker primitive {primitive['primitive_id']} references "
            f"{primitive['ref']}, which is not a file"
        )


@pytest.mark.parametrize("scenario_id", SCENARIO_IDS)
def test_cve_refs_resolve_to_an_images_yaml_entry(scenario_id: str) -> None:
    manifest = _load(MANIFEST_DIR / f"{scenario_id}.yaml")
    image_ids = _cve_image_ids()
    for primitive in manifest["incident_primitives"]:
        if primitive["mechanism"] != "cve":
            continue
        assert primitive["ref"] in image_ids, (
            f"{scenario_id}: cve primitive {primitive['primitive_id']} references image id "
            f"{primitive['ref']!r}, which scenarios/cve/images.yaml does not declare. Declared: "
            f"{sorted(image_ids)}"
        )


@pytest.mark.parametrize("scenario_id", SCENARIO_IDS)
def test_cve_image_entries_name_this_scenario(scenario_id: str) -> None:
    """An images.yaml entry a manifest references must agree it belongs to that scenario."""
    if not IMAGES_FILE.is_file():
        pytest.skip("no images.yaml")
    manifest = _load(MANIFEST_DIR / f"{scenario_id}.yaml")
    document = _load(IMAGES_FILE)
    by_id = {entry["id"]: entry for entry in document.get("images", [])}
    for primitive in manifest["incident_primitives"]:
        if primitive["mechanism"] != "cve":
            continue
        entry = by_id.get(primitive["ref"])
        assert entry is not None, f"{scenario_id}: {primitive['ref']} absent from images.yaml"
        assert entry["scenario_id"] == scenario_id, (
            f"{scenario_id}: images.yaml entry {primitive['ref']} says it belongs to "
            f"{entry['scenario_id']}"
        )


def test_cve_entries_pin_a_container_matching_their_manifest_and_a_valid_patched_image() -> None:
    """ADR-091: there is no more fixed sidecar name to hard-code. What must hold is that each
    entry's `container` agrees with the container its own scenario's cve primitive(s) target, the
    patched half is always a resolved sha256 pin (scenarios/cve/images.yaml's own header: the
    patched identity is a checked mirror of infra/boutique/images.yaml and is never PENDING), and
    the vulnerable half is either PENDING (empty, pre-Tier-B) or a resolved sha256 pin distinct from
    the patched one -- never a placeholder digest, per the file's own anti-invention argument."""
    entries = _load(IMAGES_FILE)["images"]
    for entry in entries:
        assert entry["container"], f"{entry['id']}: container is empty"
        manifest = _load(MANIFEST_DIR / f"{entry['scenario_id']}.yaml")
        cve_targets = {
            primitive["target"]["container"]
            for primitive in manifest["incident_primitives"]
            if primitive["mechanism"] == "cve" and primitive["ref"] == entry["id"]
        }
        assert cve_targets == {entry["container"]}, (
            f"{entry['id']}: container {entry['container']!r} disagrees with the manifest's own "
            f"cve-primitive target container(s) {sorted(cve_targets)!r}"
        )
        assert entry["patched_digest"].startswith("sha256:"), (
            f"{entry['id']}: patched_digest must be a resolved pin, never PENDING"
        )
        assert entry["patched_repository"]
        assert entry["digest"] == "" or entry["digest"].startswith("sha256:"), (
            f"{entry['id']}: digest must be the empty PENDING sentinel or a sha256 pin, "
            f"never a placeholder"
        )
        if entry["digest"]:
            assert entry["digest"] != entry["patched_digest"]


def test_cve_manifest_targets_the_catalog_container() -> None:
    """Cross-checks the manifest's cve-primitive container against the entry it names, rather than
    a hard-coded literal -- ADR-091 retired the fixed `cve-lab` sidecar name this test used to
    assert directly."""
    by_id = {entry["id"]: entry for entry in _load(IMAGES_FILE)["images"]}
    for scenario_id in ("SCN-CVE-04", "SCN-CVE-05"):
        manifest = _load(MANIFEST_DIR / f"{scenario_id}.yaml")
        for primitive in manifest["incident_primitives"]:
            if primitive["mechanism"] != "cve":
                continue
            entry = by_id[primitive["ref"]]
            assert primitive["target"]["container"] == entry["container"], (
                f"{scenario_id}: primitive {primitive['primitive_id']} targets container "
                f"{primitive['target']['container']!r}, catalog entry {entry['id']} declares "
                f"{entry['container']!r}"
            )


def test_cve_04_and_cve_05_pin_the_same_vulnerable_adservice_build() -> None:
    """Researcher/supervisor decision, 2026-09-13: the two scenarios may share one vulnerable
    image, differing in scenario stage rather than in target. This is now a checked fact rather
    than a coincidence of two independently-authored rows."""
    entries = {e["scenario_id"]: e for e in _load(IMAGES_FILE)["images"]}
    cve04, cve05 = entries["SCN-CVE-04"], entries["SCN-CVE-05"]
    assert cve04["component"] == cve05["component"] == "adservice"
    assert cve04["repository"] == cve05["repository"]
    assert cve04["tag"] == cve05["tag"]
    assert cve04["digest"] == cve05["digest"]
    assert cve04["container"] == cve05["container"]


def test_patched_pin_mirrors_the_fleets_own_adservice_image() -> None:
    """scenarios/cve/images.yaml's patched half is a CHECKED MIRROR of infra/boutique/images.yaml's
    own adservice pin (that file's header), not an independently maintained copy. Reuses the
    applier's own resolver so there is exactly one piece of code that reads
    infra/boutique/images.yaml, per .agents/rules/00-source-of-truth.md."""
    from scenarios.attackers.apply import KubectlClusterAdapter

    fleet_image = KubectlClusterAdapter._boutique_image("adservice")
    for entry in _load(IMAGES_FILE)["images"]:
        if entry["component"] != "adservice":
            continue
        patched = f"{entry['patched_repository']}@{entry['patched_digest']}"
        assert patched == fleet_image, (
            f"{entry['id']}: patched pin {patched!r} disagrees with the fleet's own adservice pin "
            f"{fleet_image!r} in infra/boutique/images.yaml -- re-pin both in the same commit"
        )


def test_every_recovery_probe_exercises_its_scenario_fault_path() -> None:
    admitted = {probe.probe_id for probe in SLO_PROBE_SET}
    expected = {
        "SCN-SIM-01": ("cartservice", "PROBE-FRONTEND-CART"),
        "SCN-SIM-02": ("frontend", "PROBE-FRONTEND-HOME"),
        "SCN-SIM-03": ("checkoutservice", "PROBE-FRONTEND-CHECKOUT"),
        "SCN-CVE-04": ("adservice", "PROBE-FRONTEND-PRODUCT"),
        "SCN-CVE-05": ("adservice", "PROBE-FRONTEND-HOME"),
    }
    for scenario_id, (workload, probe_id) in expected.items():
        groundtruth = _load(REPO_ROOT / "scenarios" / "groundtruth" / f"{scenario_id}.yaml")
        assertions = [
            item
            for item in groundtruth["assertions"]
            if item["check"]["type"] == "slo-probe-recovered"
        ]
        assert len(assertions) == 1, f"{scenario_id}: expected exactly one recovery probe"
        params = assertions[0]["check"]["params"]
        assert params["workload"] == workload
        assert params["probe"] == probe_id
        assert probe_id in admitted


@pytest.mark.parametrize("scenario_id", SCENARIO_IDS)
def test_every_declared_primitive_id_is_referenced_by_a_planned_event(scenario_id: str) -> None:
    """The manifest's incident primitives and injection points are exactly what the planner emits,
    so a primitive nobody plans is dead declaration and a planned event with no declaration is
    impossible by construction."""
    manifest = planner.load_manifest(scenario_id)
    declared = {p["primitive_id"] for p in manifest["incident_primitives"]}
    declared |= {point["primitive_id"] for point in manifest["injection_points"].values()}
    planned = set()
    for condition in ("INJ-NONE", "INJ-A", "INJ-B", "INJ-C", "INJ-D"):
        events = planner.plan_cell(scenario_id, condition, 101)
        planned |= {event["primitive_id"] for event in events}
    assert planned <= declared, (
        f"{scenario_id}: planner emitted primitive_id(s) no manifest declares: {planned - declared}"
    )
    # Every incident primitive is planned under every condition; every injection primitive under its
    # own condition. So the union of planned ids over all five conditions is the full declared set.
    assert planned == declared, f"{scenario_id}: declared but never planned: {declared - planned}"
