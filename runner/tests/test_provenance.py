"""Live provenance is collected from the checkout/config; synthetic provenance stays explicit."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agents.registry.digest import directory_digest  # noqa: E402
from agents.registry.loader import default_registry_root  # noqa: E402
from agents.registry.model import (  # noqa: E402
    SCRIPTED_PROVIDER_STRING,
    LiteLLMConfig,
    litellm_config_sha256,
)
from scripts.versions_env_sha256 import versions_env_sha256  # noqa: E402

from runner.campaign import PlannedRun  # noqa: E402
from runner.freeze import INSTRUMENT_PATHS  # noqa: E402
from runner.provenance import (  # noqa: E402
    API_AUDIT_FILE,
    G2_PRINCIPAL,
    ProvenanceError,
    api_audit_slice_present,
    build_run_manifest,
    g2_api_audit_requests,
    shared_credential_exercised,
    working_tree_dirty,
)
from runner.synthetic import synthetic_manifest  # noqa: E402


def _planned(condition: str = "G1-LOGONLY") -> PlannedRun:
    return PlannedRun(
        run_id=f"RUN-{condition}-SCN-CVE-04-INJ-A-101",
        condition=condition,
        scenario_id="SCN-CVE-04",
        injection_condition="INJ-A",
        seed=101,
        is_baseline=False,
        baseline_run_id=None,
        load_profile_id="LOAD-STEADY",
    )


def _audit_record(
    username: str, verb: str = "patch", resource: str = "deployments"
) -> dict[str, object]:
    """One API-server audit Event, the shape the runner slices verbatim (SEAM 5, ADR-137)."""
    return {
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "level": "Metadata",
        "stage": "ResponseComplete",
        "verb": verb,
        "user": {"username": username},
        "objectRef": {"resource": resource, "namespace": "boutique", "name": "adservice"},
    }


def _slice(bundle_dir: Path, usernames: list[str]) -> Path:
    """Write a ``k8s_api_audit.jsonl`` carrying one event per username, in order."""
    bundle_dir.mkdir(parents=True, exist_ok=True)
    path = bundle_dir / API_AUDIT_FILE
    path.write_text(
        "".join(json.dumps(_audit_record(name)) + "\n" for name in usernames), encoding="utf-8"
    )
    return path


def test_live_manifest_collects_checkout_and_actual_model_configuration() -> None:
    manifest = build_run_manifest(
        _planned(),
        "CAMP-20260827-pilot",
        environ={"MODEL_ALIAS": "campaign-primary", "MODEL_PROVIDER_STRING": "vendor/model-v2"},
    )
    expected_config = LiteLLMConfig({"campaign-primary": "vendor/model-v2"})

    assert len(manifest.git_commit) == 40
    assert manifest.versions_env_sha256 == versions_env_sha256()
    assert manifest.model_alias == "campaign-primary"
    assert manifest.model_provider_string == "vendor/model-v2"
    assert manifest.litellm_config_sha256 == litellm_config_sha256(expected_config)
    assert manifest.prompt_registry_sha256 == directory_digest(default_registry_root())
    assert manifest.host["os"]
    assert manifest.host["wsl_kernel"]
    assert manifest.host["docker"]


def test_runner_scripted_pins_the_scripted_provider_over_a_live_env() -> None:
    # A P1a scripted run answers under SCRIPTED_PROVIDER_STRING and sends no request, so its
    # manifest must record that string even when the environment names a live provider (as
    # live_env.sh does): otherwise the sealed manifest disagrees with every tokens.json call and
    # F-RN-01/F-AG-04 fail. The operator sets RUNNER_SCRIPTED alone; no manual MODEL_PROVIDER_STRING
    # override is needed.
    manifest = build_run_manifest(
        _planned(),
        "CAMP-20260827-pilot",
        environ={
            "RUNNER_SCRIPTED": "1",
            "MODEL_ALIAS": "campaign-primary",
            "MODEL_PROVIDER_STRING": "vendor/model-v2",
        },
    )
    expected_config = LiteLLMConfig({"campaign-primary": SCRIPTED_PROVIDER_STRING})

    assert manifest.model_alias == "campaign-primary"
    assert manifest.model_provider_string == SCRIPTED_PROVIDER_STRING
    assert manifest.litellm_config_sha256 == litellm_config_sha256(expected_config)


def test_live_manifest_records_evidence_and_credential_metadata(tmp_path, monkeypatch) -> None:
    from runner.provenance import LIVE_PROVENANCE_FILE, environment_lock_sha256

    monkeypatch.setattr("runner.provenance._command", lambda argv: "a" * 40)
    monkeypatch.setattr("runner.provenance._host", lambda: {})
    monkeypatch.setattr("runner.provenance.head_instrument_digest", lambda: "b" * 64)
    bundle = tmp_path / "RUN-G2-SHAREDCRED-SCN-CVE-04-INJ-A-101"
    bundle.mkdir()
    (tmp_path / "campaign.json").write_text(json.dumps({"freeze_tag": "pilot-test"}))
    expiry = "2033-05-18T03:33:20.000000+00:00"
    (bundle / LIVE_PROVENANCE_FILE).write_text(
        json.dumps({"control_plane_token_expiry": expiry, "g2_token_expiry": expiry})
    )
    (bundle / "tokens.json").write_text(
        json.dumps([{"response_model": "vendor/model-v2", "system_fingerprint": "fp-1"}])
    )
    (bundle / "resources.csv").write_text(
        "ts,workload,restarts_total\n1,guardian,0\n2,guardian,1\n"
    )
    _slice(bundle, [G2_PRINCIPAL])
    manifest = build_run_manifest(
        _planned("G2-SHAREDCRED"),
        "CAMP-20260926-pilot-p1a",
        environ={"MODEL_ALIAS": "campaign-primary", "MODEL_PROVIDER_STRING": "vendor/model-v2"},
        bundle_dir=bundle,
    )
    assert manifest.freeze_tag == "pilot-test"
    assert manifest.instrument_digest == "b" * 64
    assert manifest.control_plane_token_expiry == manifest.g2_token_expiry == expiry
    assert manifest.answered_model == "vendor/model-v2"
    assert manifest.system_fingerprints == ("fp-1",)
    assert manifest.guardian_restarted is True
    assert manifest.shared_credential_exercised is True
    assert manifest.environment_lock_sha256 == environment_lock_sha256()


def test_synthetic_manifest_remains_obviously_synthetic() -> None:
    manifest = synthetic_manifest(_planned(), "CAMP-20260101-synthetic")
    assert manifest.git_commit == "0" * 40
    assert manifest.versions_env_sha256 == "a" * 64


# ---------------------------------------------------------------------------------------------
# shared_credential_exercised is OBSERVED, not NAMED (M10 plan §1 V7, §3.1 D1-A, ADR-137)
# ---------------------------------------------------------------------------------------------


def test_shared_credential_exercised_is_observed_not_named(tmp_path: Path) -> None:
    """The G2 field is read from the API-server audit, not copied from the arm's name.

    Fails on HEAD, where the manifest field was ``run.condition == "G2-SHAREDCRED"``: every G2
    bundle claimed the alternate credential path was exercised, and v1's 150 of them were inert --
    the TokenRequest was read by nothing, the in-cluster NetworkPolicy targeted a namespace the
    host-side agent process did not live in, and the ServiceAccount could not mutate anything
    (defect V7). The field reported the treatment the experiment INTENDED.

    Three cases, because a single one proves too little:

    * G2 **with** a request by the G2 principal -> True, and the request is found by principal;
    * G2 **without** one (a slice full of other principals) -> False, which is the v1 case and the
      one the old code got backwards;
    * a non-G2 arm **with** one -> False, because an observation is an observation: the field is not
      allowed to be True for an arm that was never supposed to exercise the path, and F-GD-03's
      expected-principal cross-check is what makes an unexpected principal an error.

    The principal string is asserted exactly, because the whole measurement hangs off it and a typo
    would make every G2 run read False for a reason that looks like "G2 is still inert".
    """
    assert G2_PRINCIPAL == "system:serviceaccount:agents:g2-executor"

    def build(bundle_dir: Path, condition: str):
        return build_run_manifest(
            _planned(condition),
            "CAMP-20260926-pilot-p1a",
            environ={"MODEL_ALIAS": "campaign-primary", "MODEL_PROVIDER_STRING": "vendor/model-v2"},
            bundle_dir=bundle_dir,
        )

    exercised = tmp_path / "g2-exercised"
    _slice(exercised, ["kubernetes-admin", G2_PRINCIPAL])
    assert api_audit_slice_present(exercised)
    assert len(g2_api_audit_requests(exercised)) == 1
    assert shared_credential_exercised(exercised) is True
    assert build(exercised, "G2-SHAREDCRED").shared_credential_exercised is True

    inert = tmp_path / "g2-inert"
    _slice(inert, ["kubernetes-admin", "system:serviceaccount:kube-system:replicaset-controller"])
    assert g2_api_audit_requests(inert) == ()
    assert shared_credential_exercised(inert) is False
    # The v1 case, and the one HEAD answered with True.
    assert build(inert, "G2-SHAREDCRED").shared_credential_exercised is False

    unexpected = tmp_path / "g0-unexpected"
    _slice(unexpected, [G2_PRINCIPAL])
    assert shared_credential_exercised(unexpected) is True
    # ...and the field is the observation, not the arm: a non-G2 bundle that somehow contains the
    # request reads True here, and F-GD-03/F-GD-05 are what turn that into a finding.
    assert build(unexpected, "G0-FULL").shared_credential_exercised is True


def test_an_absent_api_audit_slice_degrades_to_false_and_never_raises(tmp_path: Path) -> None:
    """An older bundle without the slice reads False, silently -- the v1 corpus must stay readable.

    Two reasons this is False and not an exception, and both are load-bearing:

    * the known-bad replay (P4) has to READ the v1 corpus in order to flag V7, so raising would make
      the very tool that detects the defect unable to look at it;
    * ``shared_credential_exercised`` is in data-management §2's framework-on non-null set, so a
      ``None`` would make the validator REJECT the run -- discarding evidence over a missing file is
      a worse outcome than a truthful False.

    False is also the fail-closed direction: a run may assert a treatment was delivered only if it
    can point at the evidence, so the absent-evidence answer can never manufacture a false positive
    for the treatment the field is about. The G2 case is caught by F-GD-05, which requires the slice
    to be PRESENT in G2.
    """
    empty = tmp_path / "no-slice"
    empty.mkdir()
    assert not api_audit_slice_present(empty)
    assert g2_api_audit_requests(empty) == ()
    assert shared_credential_exercised(empty) is False
    assert shared_credential_exercised(None) is False
    assert not api_audit_slice_present(None)
    manifest = build_run_manifest(
        _planned("G2-SHAREDCRED"),
        "CAMP-20260926-pilot-p1a",
        environ={"MODEL_ALIAS": "campaign-primary", "MODEL_PROVIDER_STRING": "vendor/model-v2"},
        bundle_dir=empty,
    )
    assert manifest.shared_credential_exercised is False


def test_a_truncated_audit_line_does_not_make_the_slice_unreadable(tmp_path: Path) -> None:
    """A slice closed mid-write is still readable, and its readable part is still evidence.

    A sliced log whose last line is incomplete is a cosmetic artefact of closing the window, not a
    corrupt bundle; raising would turn it into an unreadable one. A non-object line and a line with
    no ``user`` are skipped for the same reason. A bundle whose EVERY line is junk reads False,
    which is the fail-closed answer rather than an exception.
    """
    bundle = tmp_path / "torn"
    bundle.mkdir()
    (bundle / API_AUDIT_FILE).write_text(
        "\n".join(
            (
                json.dumps(_audit_record("kubernetes-admin")),
                '{"verb": "patch", "user": ',  # truncated final line
                "",
                json.dumps(["not", "an", "object"]),
                json.dumps({"verb": "get"}),  # no user block
                json.dumps(_audit_record(G2_PRINCIPAL)),
            )
        )
        + "\n",
        encoding="utf-8",
    )
    records = g2_api_audit_requests(bundle)
    assert len(records) == 1
    assert records[0]["user"]["username"] == G2_PRINCIPAL
    assert shared_credential_exercised(bundle) is True

    junk = tmp_path / "junk"
    junk.mkdir()
    (junk / API_AUDIT_FILE).write_text("not json\n{\n", encoding="utf-8")
    assert shared_credential_exercised(junk) is False


def test_working_tree_dirty_reports_only_the_instrument_paths(tmp_path: Path) -> None:
    """The whole-repository check is narrowed to P6's path set (defect V14, ADR-136).

    Driven over a throwaway repository rather than the real one, because the answer here is a
    function of which PATHS a change is under and the real repository is dirty in the instrument
    paths for the duration of M10. Two changes that differ only in location must produce different
    answers, and that is the whole claim.

    The failure this replaces is worth naming: v1 ran ``git status --porcelain`` with no pathspec,
    so a reworded ADR or a scratch file under ``docs/`` stopped a campaign that was running the same
    bytes, and 40 of 150 (arm, scenario, injection) groups spanned more than one commit.
    """
    import subprocess

    def git(*args: str) -> str:
        completed = subprocess.run(  # noqa: S603 - fixed argv
            ["git", *args],  # noqa: S607 - git on PATH by design, as everywhere in the runner
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        return completed.stdout.strip()

    def touch(name: str, text: str) -> None:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    git("init", "--quiet", "--initial-branch=main")
    git("config", "user.email", "dirty-test@example.invalid")
    git("config", "user.name", "dirty test")
    for name in (*INSTRUMENT_PATHS, "docs/adr/ADR-001-example.md", "docs/notes.md"):
        if name.endswith("/"):
            continue
        touch(name, f"# {name}\n")
    git("add", "-A")
    git("commit", "--quiet", "-m", "clean")

    assert working_tree_dirty(tmp_path) is False

    # Outside the instrument: not dirty. This is the case that used to halt a campaign.
    touch("docs/notes.md", "# scratch\n")
    assert working_tree_dirty(tmp_path) is False
    touch("docs/adr/ADR-001-example.md", "# reworded\n")
    assert working_tree_dirty(tmp_path) is False

    # Inside the instrument: dirty, whether committed or not.
    touch("runner/synthetic.py", "# edited\n")
    assert working_tree_dirty(tmp_path) is True
    git("add", "-A")
    git("commit", "--quiet", "-m", "instrument edit")
    assert working_tree_dirty(tmp_path) is False

    # An untracked file inside the instrument is dirty too -- it is in no commit, so no digest
    # comparison would see it, but the next cell's import would.
    touch("runner/brand_new.py", "# untracked\n")
    assert working_tree_dirty(tmp_path) is True

    # And a failure to ask git is a ProvenanceError, never a silent False.
    with pytest.raises(ProvenanceError):
        working_tree_dirty(tmp_path / "not-a-repository")
