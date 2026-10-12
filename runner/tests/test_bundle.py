r"""The sealer's two profiles, its refusals, and the post-seal scoring append (M6-T6.2, T-15).

``docs/protocols/data-management.md`` §3 requires the runner to refuse to seal an incomplete bundle,
and the two completeness profiles are disjoint by construction. These tests build synthetic bundles
under ``tmp_path`` -- never under ``runs/`` -- and assert both that a complete bundle seals and that
each way of being incomplete is refused with the offending file named. The asserted-absent half of
the baseline profile is the one §3 warns is "most likely to be implemented as a no-op", so it is
exercised against every one of the nine framework-on artefacts, not just a token one.
"""

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from guardian.audit.chain import AuditChainWriter

from runner.assertions import load_groundtruth
from runner.bundle import (
    CompletenessError,
    append_scoring_entry,
    load_seal,
    seal_bundle,
    verify_bundle_seal,
    verify_content_hashes,
)
from runner.manifest import RunManifest

_FIXED_SEALED_AT = "2026-08-27T00:00:00+00:00"
_FIXED_SCORED_AT = "2026-08-27T01:00:00+00:00"


@pytest.fixture
def signed_anchor_bundle(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    bundle = tmp_path / "campaign" / "bundle"
    _build_framework_on(bundle)
    key = Ed25519PrivateKey.generate()  # Test-only key; production uses the operator public key.
    audit = bundle / "guardian_audit.jsonl"
    records = [json.loads(line) for line in audit.read_text().splitlines()]
    for record in records:
        record["record_signature"] = key.sign(record["hash"].encode("ascii")).hex()
    audit.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    public = tmp_path / "public.pem"
    public.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    monkeypatch.setenv("GUARDIAN_AUDIT_PUBLIC_KEY", str(public))
    ledger = tmp_path / "external" / "anchors.jsonl"
    monkeypatch.setenv("ANCHOR_LEDGER", str(ledger))
    return bundle, ledger, records


def _run_anchor_program(bundle, ledger, head, *, run=subprocess.run):
    # Exercise the exact producer program on Windows too, where POSIX sh is not required.
    script = Path(__file__).resolve().parents[2] / "scripts/audit_seal_anchor.sh"
    program = (
        script.read_text(encoding="utf-8")
        .split('"$python_bin" -c \u0027', 1)[1]
        .rsplit('\u0027 "$bundle"', 1)[0]
    )
    return run(
        [
            sys.executable,
            "-c",
            program,
            str(bundle),
            str(ledger),
            str(bundle.parent / "fidelity_ledger.jsonl"),
            head,
        ],
        capture_output=True,
        text=True,
        env=os.environ.copy(),
        check=False,
    )


def test_live_anchor_precedes_stored_fidelity_and_preserves_chain(
    signed_anchor_bundle, monkeypatch
):
    bundle, ledger, records = signed_anchor_bundle
    before = (bundle / "guardian_audit.jsonl").read_bytes()

    def producer(command, **kwargs):
        assert command[-2] == "--verified-head"
        assert not (bundle / "seal.json").exists()
        return _run_anchor_program(bundle, ledger, command[-1])

    monkeypatch.setattr("runner.bundle.subprocess.run", producer)
    seal_bundle(bundle, _framework_on_manifest(), publish_audit_anchor=True)
    report = json.loads((bundle / "fidelity.json").read_text())
    assert any(check["id"] == "F-GD-01" and check["status"] == "pass" for check in report["checks"])
    row = json.loads(ledger.read_text())
    assert row == json.loads((bundle.parent / "fidelity_ledger.jsonl").read_text())
    assert row["head"] == records[-1]["hash"]
    assert row["signature"] == records[-1]["record_signature"]
    assert (bundle / "guardian_audit.jsonl").read_bytes() == before
    assert verify_content_hashes(bundle) == []


@pytest.mark.parametrize("defect", ["key", "signature", "head", "publication"])
def test_anchor_producer_fails_closed(signed_anchor_bundle, monkeypatch, defect):
    bundle, ledger, records = signed_anchor_bundle
    head = records[-1]["hash"]
    if defect == "key":
        monkeypatch.delenv("GUARDIAN_AUDIT_PUBLIC_KEY")
    elif defect == "signature":
        records[0]["record_signature"] = "00" * 64
        (bundle / "guardian_audit.jsonl").write_text(
            "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
        )
    elif defect == "head":
        head = "0" * 64
    else:
        ledger.parent.write_text("not a directory")
    result = _run_anchor_program(bundle, ledger, head)
    assert result.returncode != 0
    assert not ledger.exists()
    assert not (bundle.parent / "fidelity_ledger.jsonl").exists()


def test_anchor_publication_failure_prevents_seal(signed_anchor_bundle, monkeypatch):
    bundle, _, _ = signed_anchor_bundle
    monkeypatch.setattr(
        "runner.bundle.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 1, "", "signature verification failed"
        ),
    )
    with pytest.raises(CompletenessError, match="anchor publication failed"):
        seal_bundle(bundle, _framework_on_manifest(), publish_audit_anchor=True)
    assert not (bundle / "seal.json").exists()
    assert not (bundle / "fidelity.json").exists()


@pytest.mark.parametrize("baseline", [False, True])
def test_offline_and_baseline_do_not_publish_anchor(tmp_path, monkeypatch, baseline):
    bundle = tmp_path / "bundle"
    (_build_baseline if baseline else _build_framework_on)(bundle)
    monkeypatch.setattr(
        "runner.bundle._publish_audit_anchor",
        lambda *args: pytest.fail("offline/baseline published a live anchor"),
    )
    seal_bundle(
        bundle,
        _baseline_manifest() if baseline else _framework_on_manifest(),
        publish_audit_anchor=baseline,
    )


def test_probe_profile_survives_seal_verification_with_populated_model_fields(
    tmp_path, monkeypatch
):
    bundle = tmp_path / "probe"
    _build_framework_on(bundle)
    for name in (
        "messages.jsonl",
        "tokens.json",
        "spans.otel.json",
        "results.json",
        "assertions.json",
        "guardian_audit.jsonl",
    ):
        (bundle / name).unlink()
    # Isolate profile selection from the treatment-specific fidelity fixtures.
    monkeypatch.setattr("runner.bundle._write_fidelity_report", lambda *args, **kwargs: [])
    seal_bundle(bundle, _framework_on_manifest(), instrument_only=True)
    assert load_seal(bundle)["instrument_only"] is True
    assert verify_bundle_seal(bundle) == []
    _write(bundle / "messages.jsonl", '{"index":0}\n')
    assert any("messages.jsonl" in defect for defect in verify_bundle_seal(bundle))


def test_missing_agent_files_do_not_turn_an_ordinary_bundle_into_a_probe(tmp_path):
    bundle = tmp_path / "ordinary"
    _build_framework_on(bundle)
    seal_bundle(bundle, _framework_on_manifest())
    (bundle / "messages.jsonl").unlink()
    assert any("messages.jsonl" in defect for defect in verify_bundle_seal(bundle))


_PROBES_CSV = (
    "ts,probe_id,target,method,status_code,latency_ms,ok,error\n"
    "2026-08-27T00:00:00Z,probe-cart,/cart,GET,200,12.3,true,\n"
)
_RESOURCES_CSV = (
    "ts,series,namespace,workload,container,cpu_cores,mem_bytes,storage_bytes,restarts_total\n"
    "2026-08-27T00:00:00Z,framework,default,cartservice,server,0.10,1048576,2048,0\n"
)
_LOCUST_CSV = "name,requests,failures,median_ms,p95_ms\naggregated,1000,0,10,25\n"

# The ten framework-on artefacts a baseline must not carry (data-management §3), listed here rather
# than imported so the test states the contract it checks. The tenth is the M10 API-server audit
# slice: a framework-off baseline ran no framework, so it has no Guardian execution and no direct
# path, and a slice of "nothing happened" in a baseline bundle is a symptom rather than evidence.
_NINE_FORBIDDEN_ON_A_BASELINE = (
    "messages.jsonl",
    "tokens.json",
    "spans.otel.json",
    "guardian_audit.jsonl",
    "monitor_events.jsonl",
    "injection.log.jsonl",
    "assertions.json",
    "scores.json",
    "metrics.json",
    "k8s_api_audit.jsonl",
)

# The API-server audit slice a framework-on fixture carries (M10, ADR-137). One mutation per
# EXECUTED
# chain record -- so F-GD-03's corroboration direction holds -- plus the window-open and
# window-close
# sentinels, so F-GD-06's coverage direction holds. The Guardian's principal is
# `system:serviceaccount:guardian:guardian`; the sentinel mutations are patched annotations on a
# logged
# Deployment, written by the runner itself as its client-certificate admin identity, which is in
# security-policy §2.1's expected-principal set.
_API_AUDIT_SLICE = "".join(
    json.dumps(
        {
            "kind": "Event",
            "apiVersion": "audit.k8s.io/v1",
            "level": "Metadata",
            "verb": "delete",
            "stage": "ResponseComplete",
            "requestReceivedTimestamp": "2026-08-27T00:00:10.000000Z",
            "user": {"username": "system:serviceaccount:guardian:guardian"},
            "objectRef": {
                "resource": "pods",
                "namespace": "default",
                "name": "compromised-pod",
            },
            "responseStatus": {"code": 200},
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    + "\n"
    for _ in (1,)
) + "".join(
    json.dumps(
        {
            "kind": "Event",
            "apiVersion": "audit.k8s.io/v1",
            "level": "Metadata",
            "verb": "patch",
            "stage": "ResponseComplete",
            "requestReceivedTimestamp": (
                "2026-08-27T00:00:01.000000Z" if phase == "open" else "2026-08-27T00:00:59.000000Z"
            ),
            "user": {"username": "kubernetes-admin"},
            "objectRef": {
                "resource": "deployments",
                "namespace": "boutique",
                "name": "frontend",
                "annotations": {"overwatch.io/window-sentinel": phase},
            },
            "responseStatus": {"code": 200},
            "annotations": {"overwatch.io/window-sentinel": phase},
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    + "\n"
    for phase in ("open", "close")
)


def _write(path, text):
    """Write ``text`` as UTF-8 bytes, so a test file's bytes do not depend on the host newline."""
    path.write_bytes(text.encode("utf-8"))


def _host():
    return {"os": "windows-11", "wsl_kernel": "5.15.0", "docker": "27.0"}


def _framework_on_manifest():
    """A framework-on manifest; the sealer does not re-validate its manifest field rules."""
    return RunManifest(
        run_id="RUN-G0-FULL-SCN-CVE-04-INJ-A-101",
        campaign_id="CAMP-20260827-synthetic",
        condition="G0-FULL",
        scenario_id="SCN-CVE-04",
        injection_condition="INJ-A",
        seed=101,
        rerun_of=None,
        is_baseline=False,
        baseline_run_id="BASE-LOAD-STEADY-101",
        load_profile_id="LOAD-STEADY",
        started_at="2026-08-27T00:00:00+00:00",
        ended_at="2026-08-27T00:10:00+00:00",
        git_commit="a" * 40,
        versions_env_sha256="b" * 64,
        litellm_config_sha256="c" * 64,
        model_alias="primary",
        model_provider_string="openai/gpt-4o-2024-05-13",
        prompt_registry_sha256="d" * 64,
        tool_registry_sha256="e" * 64,
        graph_id="hierarchical",
        guardian_mode="G0-FULL",
        aggregator_quoting=True,
        netpol_overlay="default-deny",
        shared_credential_exercised=False,
        host=_host(),
    )


def _baseline_manifest():
    """A framework-off baseline manifest: the twelve framework-on fields blanked (§2)."""
    return RunManifest(
        run_id="BASE-LOAD-STEADY-101",
        campaign_id="CAMP-20260827-synthetic",
        condition=None,
        scenario_id=None,
        injection_condition=None,
        seed=101,
        rerun_of=None,
        is_baseline=True,
        baseline_run_id=None,
        load_profile_id="LOAD-STEADY",
        started_at="2026-08-27T00:00:00+00:00",
        ended_at="2026-08-27T00:10:00+00:00",
        git_commit="a" * 40,
        versions_env_sha256="b" * 64,
        litellm_config_sha256=None,
        model_alias=None,
        model_provider_string=None,
        prompt_registry_sha256=None,
        tool_registry_sha256=None,
        graph_id=None,
        guardian_mode=None,
        aggregator_quoting=None,
        netpol_overlay=None,
        shared_credential_exercised=None,
        host=_host(),
    )


def _build_valid_chain(path):
    """Write a real two-record ``guardian_audit.jsonl`` the verifier accepts."""
    writer = AuditChainWriter.open(path, max_justification_chars=4096)
    writer.append(
        {
            "decision": "permit",
            "enforcement": "executed",
            "action": {"verb": "get", "resource": "pods", "namespace": "default"},
        }
    )
    writer.append(
        {
            "decision": "deny",
            "enforcement": "blocked",
            "reason_code": "out-of-scope",
            "action": {"verb": "delete", "resource": "pods", "namespace": "boutique"},
        }
    )


def _assertion_payload():
    groundtruth, digest = load_groundtruth("SCN-CVE-04")
    assertions = [
        {
            "assertion_id": item["assertion_id"],
            "kind": item["kind"],
            "phase": item["phase"],
            "result": "pass",
            "observed": "fixture",
            "evaluated_at": _FIXED_SEALED_AT,
        }
        for item in [
            *groundtruth["assertions"],
            *groundtruth["conditions"]["INJ-A"]["end_state_assertions"],
        ]
    ]
    substeps = [
        {
            "phase": phase,
            "substep_id": substep["substep_id"],
            "result": "reached",
            "observed": "fixture",
            "evaluated_at": _FIXED_SEALED_AT,
        }
        for phase, labels in groundtruth["phases"].items()
        for substep in labels["required_substeps"]
    ]
    return {
        "run_id": "RUN-G0-FULL-SCN-CVE-04-INJ-A-101",
        "scenario_id": "SCN-CVE-04",
        "groundtruth_sha256": digest,
        "assertions": assertions,
        "required_substep_results": substeps,
    }


def _build_framework_on(bundle_dir, *, injection_lines=4):
    """Populate the run-produced files the framework-on profile requires at seal."""
    bundle_dir.mkdir(parents=True, exist_ok=True)
    _write(
        bundle_dir / "messages.jsonl",
        '{"index":0,"role":"user","content":"hello world"}\n',
    )
    _write(bundle_dir / "results.json", "[]\n")
    _write(
        bundle_dir / "tokens.json",
        '[{"index":0,"model_alias":"primary","model":"openai/gpt-4o-2024-05-13","prompt_tokens":42}]\n',
    )
    _write(
        bundle_dir / "spans.otel.json",
        '{"spans":['
        '{"attributes":{"phase":"detection-and-investigation"},"duration_ms":1,"endTimeUnixNano":1777760000001000000,"name":"phase","startTimeUnixNano":1777760000000000000},'
        '{"attributes":{"phase":"containment"},"duration_ms":1,"endTimeUnixNano":1777760001001000000,"name":"phase","startTimeUnixNano":1777760001000000000},'
        '{"attributes":{"phase":"eradication"},"duration_ms":1,"endTimeUnixNano":1777760002001000000,"name":"phase","startTimeUnixNano":1777760002000000000},'
        '{"attributes":{"phase":"verified-recovery"},"duration_ms":1,"endTimeUnixNano":1777760003001000000,"name":"phase","startTimeUnixNano":1777760003000000000}'
        "]}\n",
    )
    _write(bundle_dir / "monitor_events.jsonl", '{"event_id":"e1","ts":"2026-08-27T00:00:00Z"}\n')
    _write(
        bundle_dir / "monitor_timings.jsonl",
        '{"event_id":"e1","emit_ts":"2026-08-27T00:00:01Z"}\n',
    )
    _build_valid_chain(bundle_dir / "guardian_audit.jsonl")
    # The API-server audit slice (M10, ADR-137; data-management §1/§3). Required for any
    # framework-on
    # run, because a bundle without it cannot corroborate a single executed Guardian action -- which
    # is
    # exactly v1's state (defect V28: 0 of 755 framework-on bundles carry one). The content here is
    # the
    # minimum that makes the file a slice rather than a placeholder: one mutation per EXECUTED chain
    # record, so F-GD-03's corroboration direction holds, plus the window sentinels F-GD-06 reads.
    _write(bundle_dir / "k8s_api_audit.jsonl", _API_AUDIT_SLICE)
    _write(bundle_dir / "metrics.json", '{"requests_blocked":1}\n')
    _write(
        bundle_dir / "injection.log.jsonl",
        "".join(f'{{"event":{index}}}\n' for index in range(injection_lines)),
    )
    _write(bundle_dir / "assertions.json", json.dumps(_assertion_payload()) + "\n")
    _write(bundle_dir / "probes.csv", _PROBES_CSV)
    _write(bundle_dir / "resources.csv", _RESOURCES_CSV)


def _build_baseline(bundle_dir):
    """Populate the three run-produced files the baseline profile requires present and non-empty."""
    bundle_dir.mkdir(parents=True, exist_ok=True)
    _write(bundle_dir / "probes.csv", _PROBES_CSV)
    _write(bundle_dir / "resources.csv", _RESOURCES_CSV)
    _write(bundle_dir / "locust_stats.csv", _LOCUST_CSV)


def test_a_complete_framework_on_bundle_seals_with_a_chain_head_and_verifiable_hashes(tmp_path):
    """Without this, a sealer that dropped the audit anchor or mis-hashed a file passes unseen."""
    bundle = tmp_path / "RUN-G0-FULL-SCN-CVE-04-INJ-A-101"
    _build_framework_on(bundle, injection_lines=4)
    from runner.provenance import LIVE_PROVENANCE_FILE

    _write(bundle / LIVE_PROVENANCE_FILE, '{"g2_token_expiry":null}\n')

    seal_bundle(bundle, _framework_on_manifest(), sealed_at=_FIXED_SEALED_AT)

    seal = load_seal(bundle)
    assert seal["sealed_at"] == _FIXED_SEALED_AT
    assert isinstance(seal["audit_chain_head"], str) and len(seal["audit_chain_head"]) == 64
    hashes = seal["content_hashes"]
    assert "manifest.json" in hashes
    assert "guardian_audit.jsonl" in hashes
    assert "seal.json" not in hashes and "scores.json" not in hashes
    assert "locust_stats.csv" not in hashes  # conditional, and this run did not produce it
    assert verify_content_hashes(bundle) == []
    assert not (bundle / LIVE_PROVENANCE_FILE).exists()
    assert (
        json.loads((bundle / "manifest.json").read_text())["fidelity_summary"]
        == json.loads((bundle / "fidelity.json").read_text())["summary"]
    )


@pytest.mark.parametrize(
    ("messages", "tokens", "match"),
    [
        (
            '{"index":0,"content":"one"}\n',
            '[{"index":0,"model":"openai/gpt-4o-2024-05-13"}]\n',
            "model_alias",
        ),
        (
            '{"index":0,"content":"one"}\n',
            '[{"index":0,"model_alias":"wrong","model":"openai/gpt-4o-2024-05-13"}]\n',
            "model_alias",
        ),
        (
            '{"index":0,"content":"one"}\n{"index":1,"content":"two"}\n',
            '[{"index":0,"model":"openai/gpt-4o-2024-05-13"}]\n',
            "do not match",
        ),
        (
            '{"index":0,"content":"one"}\n',
            '[{"index":0,"model":"openai/gpt-4o"}]\n',
            "exact manifest",
        ),
        (
            '{"index":0,"content":"one"}\n',
            '[{"index":0,"model":"openai/gpt-4o-2024-05-13"},'
            '{"index":0,"model":"openai/gpt-4o-2024-05-13"}]\n',
            "duplicate",
        ),
    ],
)
def test_sealer_refuses_unreconciled_llm_call_accounting(tmp_path, messages, tokens, match):
    bundle = tmp_path / "RUN-G0-FULL-SCN-CVE-04-INJ-A-101"
    _build_framework_on(bundle)
    _write(bundle / "messages.jsonl", messages)
    _write(bundle / "tokens.json", tokens)

    with pytest.raises(CompletenessError, match=match):
        seal_bundle(bundle, _framework_on_manifest(), sealed_at=_FIXED_SEALED_AT)


@pytest.mark.parametrize(
    "resources",
    [
        "ts,series\n2026-08-27T00:00:00Z,framework\n",
        _RESOURCES_CSV.replace(",0\n", ",\n"),
        _RESOURCES_CSV.replace(",0\n", ",not-a-number\n"),
        _RESOURCES_CSV.splitlines()[0] + "\n",
    ],
)
def test_sealer_refuses_resources_without_populated_numeric_restarts(tmp_path, resources):
    bundle = tmp_path / "BASE-LOAD-STEADY-101"
    _build_baseline(bundle)
    _write(bundle / "resources.csv", resources)

    with pytest.raises(CompletenessError, match="restarts_total"):
        seal_bundle(bundle, _baseline_manifest(), sealed_at=_FIXED_SEALED_AT)


@pytest.mark.parametrize(
    ("metrics", "match"),
    [
        (None, "metrics.json"),
        ("{}\n", "requests_blocked"),
        ('{"requests_blocked":"1"}\n', "requests_blocked"),
        ('{"requests_blocked":0}\n', "derives 1"),
    ],
)
def test_sealer_requires_a_reconciled_blocked_request_counter(tmp_path, metrics, match):
    bundle = tmp_path / "RUN-G0-FULL-SCN-CVE-04-INJ-A-101"
    _build_framework_on(bundle)
    path = bundle / "metrics.json"
    if metrics is None:
        path.unlink()
    else:
        _write(path, metrics)

    with pytest.raises(CompletenessError, match=match):
        seal_bundle(bundle, _framework_on_manifest(), sealed_at=_FIXED_SEALED_AT)


def test_sealer_refuses_audit_data_that_cannot_support_the_blocked_counter(tmp_path):
    bundle = tmp_path / "RUN-G0-FULL-SCN-CVE-04-INJ-A-101"
    _build_framework_on(bundle)
    chain = bundle / "guardian_audit.jsonl"
    chain.unlink()
    writer = AuditChainWriter.open(chain, max_justification_chars=4096)
    writer.append({"decision": "permit", "action": {"verb": "get", "resource": "pods"}})

    with pytest.raises(CompletenessError, match="enforcement"):
        seal_bundle(bundle, _framework_on_manifest(), sealed_at=_FIXED_SEALED_AT)


def test_sealer_refuses_json_lines_disguised_as_spans_otel_json(tmp_path):
    bundle = tmp_path / "RUN-G0-FULL-SCN-CVE-04-INJ-A-101"
    _build_framework_on(bundle, injection_lines=4)
    _write(bundle / "spans.otel.json", '{"name":"phase"}\n{"name":"node"}\n')

    with pytest.raises(CompletenessError, match="spans.otel.json"):
        seal_bundle(bundle, _framework_on_manifest(), sealed_at=_FIXED_SEALED_AT)


def test_sealer_refuses_an_empty_spans_array(tmp_path):
    bundle = tmp_path / "RUN-G0-FULL-SCN-CVE-04-INJ-A-101"
    _build_framework_on(bundle, injection_lines=4)
    _write(bundle / "spans.otel.json", '{"spans":[]}\n')

    with pytest.raises(CompletenessError, match="carries no spans"):
        seal_bundle(bundle, _framework_on_manifest(), sealed_at=_FIXED_SEALED_AT)


def test_sealer_refuses_an_invalid_manifest_at_the_seal_boundary(tmp_path):
    """The ID-versus-manifest rule is enforced by sealing, not only by an optional caller."""
    bundle = tmp_path / "RUN-G0-FULL-SCN-CVE-04-INJ-A-101"
    _build_framework_on(bundle, injection_lines=4)
    invalid = replace(_framework_on_manifest(), scenario_id="SCN-CVE-05")

    with pytest.raises(CompletenessError, match="invalid at seal"):
        seal_bundle(bundle, invalid, sealed_at=_FIXED_SEALED_AT)
    assert not (bundle / "seal.json").exists()


def test_a_complete_baseline_bundle_seals_with_a_null_chain_head(tmp_path):
    """Without this, a baseline could silently acquire a chain head it has no chain to justify."""
    bundle = tmp_path / "BASE-LOAD-STEADY-101"
    _build_baseline(bundle)

    seal_bundle(bundle, _baseline_manifest(), sealed_at=_FIXED_SEALED_AT)

    seal = load_seal(bundle)
    assert seal["audit_chain_head"] is None
    assert set(seal["content_hashes"]) == {
        "manifest.json",
        # No fidelity.json: a baseline ran no arm, so there is no treatment to assess.
        # `runner/validity.py::_fidelity_findings` skips a baseline for exactly that reason, and the
        # baseline completeness profile lists no fidelity.json -- so the sealer writes none (a
        # framework-off run's M10 gate would fail F-MN-02, which has no monitor stream to read, and
        # would shell out to git for the instrument digest, which an offline baseline must not do).
        "probes.csv",
        "resources.csv",
        "locust_stats.csv",
    }
    assert verify_content_hashes(bundle) == []


@pytest.mark.parametrize("artefact", _NINE_FORBIDDEN_ON_A_BASELINE)
def test_a_baseline_carrying_any_framework_on_artefact_refuses_to_seal(tmp_path, artefact):
    """Without this, the asserted-absent half of the baseline profile is a silent no-op."""
    bundle = tmp_path / "BASE-LOAD-STEADY-101"
    _build_baseline(bundle)
    _write(bundle / artefact, '{"x":1}\n')

    with pytest.raises(CompletenessError) as caught:
        seal_bundle(bundle, _baseline_manifest(), sealed_at=_FIXED_SEALED_AT)

    assert artefact in str(caught.value)
    assert not (bundle / "seal.json").is_file()


def test_a_framework_on_bundle_missing_assertions_refuses_to_seal(tmp_path):
    """Without this, a run missing its primary RQ2 evidence file could seal as if complete."""
    bundle = tmp_path / "RUN-G0-FULL-SCN-CVE-04-INJ-A-101"
    _build_framework_on(bundle, injection_lines=4)
    (bundle / "assertions.json").unlink()

    with pytest.raises(CompletenessError) as caught:
        seal_bundle(bundle, _framework_on_manifest(), sealed_at=_FIXED_SEALED_AT)

    assert "assertions.json" in str(caught.value)
    assert not (bundle / "seal.json").is_file()


def test_framework_on_bundle_missing_required_substep_result_refuses_to_seal(tmp_path):
    bundle = tmp_path / "RUN-G0-FULL-SCN-CVE-04-INJ-A-101"
    _build_framework_on(bundle, injection_lines=4)
    path = bundle / "assertions.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["required_substep_results"].pop()
    _write(path, json.dumps(payload) + "\n")

    with pytest.raises(CompletenessError, match="required substeps"):
        seal_bundle(bundle, _framework_on_manifest(), sealed_at=_FIXED_SEALED_AT)


def test_framework_on_bundle_duplicate_required_substep_result_refuses_to_seal(tmp_path):
    bundle = tmp_path / "RUN-G0-FULL-SCN-CVE-04-INJ-A-101"
    _build_framework_on(bundle, injection_lines=4)
    path = bundle / "assertions.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["required_substep_results"].append(payload["required_substep_results"][0])
    _write(path, json.dumps(payload) + "\n")

    with pytest.raises(CompletenessError, match="duplicate"):
        seal_bundle(bundle, _framework_on_manifest(), sealed_at=_FIXED_SEALED_AT)


def test_an_injection_log_of_the_wrong_length_refuses_to_seal(tmp_path):
    """Without this, a determinism break -- injected events not matching ground truth -- seals."""
    bundle = tmp_path / "RUN-G0-FULL-SCN-CVE-04-INJ-A-101"
    _build_framework_on(bundle, injection_lines=3)

    with pytest.raises(CompletenessError) as caught:
        seal_bundle(bundle, _framework_on_manifest(), sealed_at=_FIXED_SEALED_AT)

    assert "injection.log.jsonl" in str(caught.value)


def test_a_framework_on_bundle_with_a_tampered_audit_chain_refuses_to_seal(tmp_path):
    """Without this, a bundle whose audit chain fails verification could still seal (§3)."""
    bundle = tmp_path / "RUN-G0-FULL-SCN-CVE-04-INJ-A-101"
    _build_framework_on(bundle, injection_lines=4)
    chain = bundle / "guardian_audit.jsonl"
    # Change one record's content without touching its stored hash: the record no longer hashes to
    # what it claims, so verify_chain reports a break and the sealer must refuse.
    tampered = chain.read_bytes().replace(b'"permit"', b'"revoke"')
    assert tampered != chain.read_bytes()  # the mutation actually landed
    chain.write_bytes(tampered)

    with pytest.raises(CompletenessError) as caught:
        seal_bundle(bundle, _framework_on_manifest(), sealed_at=_FIXED_SEALED_AT)

    assert "guardian_audit.jsonl" in str(caught.value)
    assert not (bundle / "seal.json").is_file()


def test_seal_hashes_extra_artifacts_and_verifier_requires_exact_key_coverage(tmp_path):
    bundle = tmp_path / "BASE-LOAD-STEADY-101"
    _build_baseline(bundle)
    _write(bundle / "extra-artifact.json", '{"extra":true}\n')
    seal_bundle(bundle, _baseline_manifest(), sealed_at=_FIXED_SEALED_AT)
    assert "extra-artifact.json" in load_seal(bundle)["content_hashes"]

    seal = load_seal(bundle)
    seal["content_hashes"].pop("extra-artifact.json")
    (bundle / "seal.json").write_bytes(json.dumps(seal).encode("utf-8"))
    assert any("exactly cover" in defect for defect in verify_bundle_seal(bundle))


def test_append_scoring_entry_is_atomic_on_replace_failure(tmp_path, monkeypatch):
    bundle = tmp_path / "RUN-G0-FULL-SCN-CVE-04-INJ-A-101"
    _build_framework_on(bundle)
    seal_bundle(bundle, _framework_on_manifest(), sealed_at=_FIXED_SEALED_AT)
    scores = bundle / "scores.json"
    _write(scores, "{}\n")
    before = (bundle / "seal.json").read_bytes()

    def fail_replace(_source, _target):
        raise OSError("replace failed")

    monkeypatch.setattr("runner.bundle.os.replace", fail_replace)
    with pytest.raises(OSError, match="replace failed"):
        append_scoring_entry(bundle, scores, scored_at=_FIXED_SCORED_AT)
    assert (bundle / "seal.json").read_bytes() == before
    assert not list(bundle.glob(".seal.json.tmp-*"))


def test_append_scoring_entry_leaves_the_pre_scoring_hashes_verifiable(tmp_path):
    """Without this, a scoring append that re-hashed the bundle would void the seal."""
    bundle = tmp_path / "RUN-G0-FULL-SCN-CVE-04-INJ-A-101"
    _build_framework_on(bundle, injection_lines=4)
    seal_bundle(bundle, _framework_on_manifest(), sealed_at=_FIXED_SEALED_AT)

    before = load_seal(bundle)
    scores = bundle / "scores.json"
    _write(
        scores, '{"run_id":"RUN-G0-FULL-SCN-CVE-04-INJ-A-101","rubric_version":"v1","passes":[]}\n'
    )
    expected_scores_hash = hashlib.sha256(scores.read_bytes()).hexdigest()

    append_scoring_entry(bundle, scores, scored_at=_FIXED_SCORED_AT)

    after = load_seal(bundle)
    assert after["content_hashes"] == before["content_hashes"]  # untouched by the append
    assert after["audit_chain_head"] == before["audit_chain_head"]
    assert after["scoring"] == {"scores.json": expected_scores_hash, "scored_at": _FIXED_SCORED_AT}
    assert "scores.json" not in after["content_hashes"]  # scores stays post-seal
    assert verify_content_hashes(bundle) == []


# --- ADR-077: results.json must join the exported audit chain -------------------------------------


def _decided(audit_seq, *, phase="containment", request_id=None):
    return {
        "phase": phase,
        "role_id": "executor",
        "outcome": "resolved",
        "actions": [
            {"kind": "issue", "refused": False, "jti": "jti-fixture", "error": None},
            {
                "kind": "action",
                "decided": True,
                "decision": "permit",
                "audit_seq": audit_seq,
                "request_id": request_id,
                "reason_code": None,
            },
        ],
    }


def test_sealer_accepts_decided_actions_that_join_the_audit_chain(tmp_path):
    bundle = tmp_path / "RUN-G0-FULL-SCN-CVE-04-INJ-A-101"
    _build_framework_on(bundle)
    _write(bundle / "results.json", json.dumps([_decided(0), _decided(1, phase="eradication")]))

    seal_bundle(bundle, _framework_on_manifest(), sealed_at=_FIXED_SEALED_AT)

    assert verify_bundle_seal(bundle) == []


def test_sealer_refuses_decided_actions_the_audit_chain_does_not_hold(tmp_path):
    """The 2026-09-12 contamination: decisions written to another run's chain, this chain sealed."""
    bundle = tmp_path / "RUN-G0-FULL-SCN-CVE-04-INJ-A-101"
    _build_framework_on(bundle)
    _write(bundle / "results.json", json.dumps([_decided(5), _decided(6), _decided(7)]))

    with pytest.raises(CompletenessError, match="do not join guardian_audit.jsonl"):
        seal_bundle(bundle, _framework_on_manifest(), sealed_at=_FIXED_SEALED_AT)


def test_sealer_refuses_a_request_id_that_disagrees_at_the_same_sequence(tmp_path):
    bundle = tmp_path / "RUN-G0-FULL-SCN-CVE-04-INJ-A-101"
    _build_framework_on(bundle)
    chain = bundle / "guardian_audit.jsonl"
    chain.unlink()
    writer = AuditChainWriter.open(chain, max_justification_chars=4096)
    writer.append(
        {
            "decision": "deny",
            "enforcement": "blocked",
            "reason_code": "out-of-scope",
            "request_id": "OTHER-RUN-containment-001",
            "action": {"verb": "delete", "resource": "pods", "namespace": "boutique"},
        }
    )
    _write(
        bundle / "results.json",
        json.dumps([_decided(0, request_id="RUN-G0-FULL-SCN-CVE-04-INJ-A-101-containment-001")]),
    )

    with pytest.raises(CompletenessError, match="names request_id"):
        seal_bundle(bundle, _framework_on_manifest(), sealed_at=_FIXED_SEALED_AT)


def test_undecided_actions_and_issuance_records_need_no_audit_record(tmp_path):
    bundle = tmp_path / "RUN-G0-FULL-SCN-CVE-04-INJ-A-101"
    _build_framework_on(bundle)
    undecided = _decided(99)
    undecided["actions"][1]["decided"] = False
    _write(bundle / "results.json", json.dumps([undecided]))

    seal_bundle(bundle, _framework_on_manifest(), sealed_at=_FIXED_SEALED_AT)


def test_a_bundle_sealed_before_the_join_check_is_reported_by_seal_verification(
    tmp_path, monkeypatch
):
    """Campaign resume and corpus QA must flag a contaminated bundle that already carries a seal."""
    import runner.bundle as bundle_module

    bundle = tmp_path / "RUN-G0-FULL-SCN-CVE-04-INJ-A-101"
    _build_framework_on(bundle)
    _write(bundle / "results.json", json.dumps([_decided(5)]))
    monkeypatch.setattr(bundle_module, "_verify_action_audit_join", lambda _bundle_dir: None)
    seal_bundle(bundle, _framework_on_manifest(), sealed_at=_FIXED_SEALED_AT)
    monkeypatch.undo()

    defects = verify_bundle_seal(bundle)

    assert any("does not join the audit chain" in defect for defect in defects), defects
