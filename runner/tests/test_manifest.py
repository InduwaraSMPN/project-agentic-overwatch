r"""The manifest schema: the field set, the null set, the RQ4 predicate, canonical bytes."""

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402

from runner.manifest import (  # noqa: E402
    BASELINE_NULL_FIELDS,
    FRAMEWORK_ON_REQUIRED_NON_NULL,
    MANIFEST_FIELDS,
    ManifestError,
    from_dict,
    requires_baseline_pairing,
    to_canonical_bytes,
)


def test_the_field_set_is_the_twenty_six_of_section_2() -> None:
    assert len(MANIFEST_FIELDS) == 26
    assert MANIFEST_FIELDS[0] == "run_id"
    assert "host" in MANIFEST_FIELDS


def test_the_null_set_is_fourteen_and_the_framework_required_is_thirteen() -> None:
    """The asymmetry is baseline_run_id, which keeps its own narrower rule."""
    assert len(BASELINE_NULL_FIELDS) == 14
    assert len(FRAMEWORK_ON_REQUIRED_NON_NULL) == 13
    assert "baseline_run_id" in BASELINE_NULL_FIELDS
    assert "baseline_run_id" not in FRAMEWORK_ON_REQUIRED_NON_NULL


def test_the_rq4_predicate_is_g0_full_alone() -> None:
    assert requires_baseline_pairing("G0-FULL") is True
    for arm in ("S2-FLAT", "S3-SINGLE", "G1-LOGONLY", "G2-SHAREDCRED", "G3-UNQUOTED"):
        assert requires_baseline_pairing(arm) is False


def test_from_dict_rejects_a_wrong_field_set() -> None:
    with pytest.raises(ManifestError):
        from_dict({"run_id": "x"})


def test_canonical_bytes_are_stable_and_sorted() -> None:
    """The manifest is hashed into seal.json, so its bytes must be a function of content alone."""
    payload = dict.fromkeys(MANIFEST_FIELDS, None)
    payload.update(
        run_id="BASE-LOAD-STEADY-101",
        campaign_id="CAMP-20260827-pilot",
        seed=101,
        is_baseline=True,
        load_profile_id="LOAD-STEADY",
        started_at="2026-08-27T10:00:00Z",
        ended_at="2026-08-27T10:05:00Z",
        git_commit="0" * 40,
        versions_env_sha256="a" * 64,
        host={"os": "linux", "wsl_kernel": "6.6", "docker": "27"},
        schema_version="v1",
        rerun_of=None,
    )
    manifest = from_dict(payload)
    first = to_canonical_bytes(manifest)
    assert first == to_canonical_bytes(manifest)
    # sorted keys, compact separators
    reparsed = json.loads(first)
    assert list(reparsed) == sorted(reparsed)
    assert b", " not in first and b": " not in first


def test_same_model_provider_accepts_an_inserted_vendor_namespace() -> None:
    """A gateway may answer with the upstream vendor's namespace inserted (ADR-106)."""
    from runner.manifest import same_model_provider

    pinned = "custom_openai/gpt-5.6-terra"
    assert same_model_provider(pinned, pinned)
    assert same_model_provider("custom_openai/openai/gpt-5.6-terra", pinned)


def test_same_model_provider_still_refuses_a_changed_model_or_provider() -> None:
    """The check keeps catching a genuinely changed instrument (ADR-100, ADR-106)."""
    from runner.manifest import same_model_provider

    pinned = "custom_openai/gpt-5.6-terra"
    assert not same_model_provider("custom_openai/gpt-5.6-luna", pinned)
    assert not same_model_provider("custom_openai/openai/gpt-5.6-luna", pinned)
    assert not same_model_provider("anthropic/gpt-5.6-terra", pinned)
    assert not same_model_provider("gpt-5.6-terra", pinned)
    assert not same_model_provider(None, pinned)
