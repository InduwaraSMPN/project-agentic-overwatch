"""The API-server audit slice (ADR-137): offset, sentinel writer, and window-bracketed collation.

These pin the live producer runner/bundle.py and fidelity F-GD-03/F-GD-06 require but that only
runner/synthetic.py fabricated before M10 -- so every framework-on run failed to seal (defect found
by the M10 smoke run). The producer lives in runner/live_evidence.py; here it is exercised in
isolation, and the sentinel vocabulary is held equal to the fidelity reader's.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from runner.live_evidence import (
    SENTINEL_ANNOTATION_KEY,
    SENTINEL_PHASES,
    EvidenceProductionError,
    api_audit_offset,
    collect_api_audit,
    write_api_audit_sentinel,
)


class _FakeCompleted:
    def __init__(self, returncode: int = 0, stderr: bytes = b"") -> None:
        self.returncode = returncode
        self.stderr = stderr


def test_sentinel_constants_match_the_fidelity_reader() -> None:
    """The writer's and F-GD-06's sentinel vocabulary must agree, or the reader looks for a sentinel
    the writer never wrote (the guardian.py:171 comment's failure mode)."""
    from runner.fidelity import guardian as fidelity_guardian

    assert SENTINEL_ANNOTATION_KEY == fidelity_guardian.SENTINEL_ANNOTATION_KEY
    assert tuple(SENTINEL_PHASES) == tuple(fidelity_guardian.SENTINEL_PHASES)


def test_api_audit_offset_is_the_byte_length_and_fails_closed_on_an_absent_log(
    tmp_path: Path,
) -> None:
    log = tmp_path / "k8s_audit.jsonl"
    log.write_bytes(b"one\ntwo\n")
    assert api_audit_offset(log) == 8
    with pytest.raises(EvidenceProductionError, match="audit log is unavailable"):
        api_audit_offset(tmp_path / "absent.jsonl")


def _event(**over: object) -> dict:
    event: dict = {
        "verb": "patch",
        "objectRef": {"resource": "deployments", "namespace": "guardian", "name": "guardian"},
        "user": {"username": "kubernetes-admin"},
        "requestReceivedTimestamp": "2026-09-27T00:00:00Z",
    }
    event.update(over)
    return event


def test_collect_slices_from_offset_and_lifts_the_sentinel_annotation(tmp_path: Path) -> None:
    """The slice is the window tail past the offset; sentinels (recognised by the requestObject
    annotation) gain the top-level annotation F-GD-06 reads; other events pass through byte for
    byte."""
    log = tmp_path / "k8s_audit.jsonl"
    before = _event(objectRef={"resource": "pods", "namespace": "boutique", "name": "before"})
    log.write_bytes((json.dumps(before) + "\n").encode("utf-8"))
    offset = api_audit_offset(log)

    open_sentinel = _event(
        requestObject={"metadata": {"annotations": {SENTINEL_ANNOTATION_KEY: "open"}}}
    )
    executed = _event(
        objectRef={"resource": "deployments", "namespace": "boutique", "name": "cartservice"}
    )
    close_sentinel = _event(
        requestObject={"metadata": {"annotations": {SENTINEL_ANNOTATION_KEY: "close"}}}
    )
    with log.open("ab") as handle:
        for event in (open_sentinel, executed, close_sentinel):
            handle.write((json.dumps(event) + "\n").encode("utf-8"))

    destination = tmp_path / "k8s_api_audit.jsonl"
    written = collect_api_audit(log, offset, destination)
    assert written == 3  # the pre-window "before" event is excluded by the offset

    records = [json.loads(line) for line in destination.read_text().splitlines() if line.strip()]
    phases = {r.get("annotations", {}).get(SENTINEL_ANNOTATION_KEY) for r in records}
    assert {"open", "close"} <= phases
    executed_records = [r for r in records if r["objectRef"].get("name") == "cartservice"]
    assert executed_records
    assert SENTINEL_ANNOTATION_KEY not in (executed_records[0].get("annotations") or {})


def test_collect_copies_a_malformed_line_unchanged(tmp_path: Path) -> None:
    log = tmp_path / "k8s_audit.jsonl"
    log.write_bytes(b"not json at all\n" + (json.dumps(_event()) + "\n").encode("utf-8"))
    destination = tmp_path / "out.jsonl"
    assert collect_api_audit(log, 0, destination) == 2
    assert destination.read_bytes().splitlines()[0] == b"not json at all"


@pytest.mark.parametrize("phase", ("open", "close"))
def test_write_sentinel_patches_only_guardian_metadata(
    monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_: object) -> _FakeCompleted:
        calls.append(argv)
        return _FakeCompleted()

    monkeypatch.setattr("runner.live_evidence.subprocess.run", fake_run)
    write_api_audit_sentinel(phase, run_id="RUN-X", kubeconfig="/kc", context="ctx")
    write_api_audit_sentinel(phase, run_id="RUN-X", kubeconfig="/kc", context="ctx")

    assert len(calls) == 2  # metadata patches, no Pod-template change or configmap create
    argv = calls[0]
    assert argv[:5] == ["kubectl", "--kubeconfig", "/kc", "--context", "ctx"]
    assert "patch" in argv and "--type=merge" in argv and "deployment/guardian" in argv
    body = json.loads(argv[argv.index("-p") + 1])
    assert set(body) == {"metadata"} and set(body["metadata"]) == {"annotations"}
    annotations = body["metadata"]["annotations"]
    assert set(annotations) == {SENTINEL_ANNOTATION_KEY, f"{SENTINEL_ANNOTATION_KEY}-nonce"}
    assert annotations[SENTINEL_ANNOTATION_KEY] == phase
    nonce_key = f"{SENTINEL_ANNOTATION_KEY}-nonce"
    assert annotations[nonce_key].startswith(f"RUN-X-{phase}-")
    second_body = json.loads(calls[1][calls[1].index("-p") + 1])
    assert second_body["metadata"]["annotations"][nonce_key] != annotations[nonce_key]
    assert second_body["metadata"]["annotations"][SENTINEL_ANNOTATION_KEY] == phase


def test_write_sentinel_fails_closed_on_a_kubectl_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "runner.live_evidence.subprocess.run",
        lambda argv, **_: _FakeCompleted(returncode=1, stderr=b"forbidden"),
    )
    with pytest.raises(EvidenceProductionError, match="API-audit sentinel"):
        write_api_audit_sentinel("close", run_id="RUN-X")


def test_write_sentinel_rejects_an_unknown_phase() -> None:
    with pytest.raises(EvidenceProductionError, match="phase"):
        write_api_audit_sentinel("middle", run_id="RUN-X")


def test_repeated_open_sentinel_keeps_phase_in_audit_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An interrupted run leaves open on the object; annotate's diff omits that unchanged key."""
    log = tmp_path / "audit.jsonl"
    log.write_bytes(b"")
    existing = {SENTINEL_ANNOTATION_KEY: "open"}

    def fake_run(argv: list[str], **_: object) -> _FakeCompleted:
        if "annotate" in argv:
            annotations = dict(arg.split("=", 1) for arg in argv if "=" in arg)
            patch = {key: value for key, value in annotations.items() if existing.get(key) != value}
            body = {"metadata": {"annotations": patch}}
        else:
            body = json.loads(argv[argv.index("-p") + 1])
        with log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(_event(requestObject=body)) + "\n")
        return _FakeCompleted()

    monkeypatch.setattr("runner.live_evidence.subprocess.run", fake_run)
    offset = api_audit_offset(log)
    write_api_audit_sentinel("open", run_id="RUN-X")
    destination = tmp_path / "slice.jsonl"
    assert collect_api_audit(log, offset, destination) == 1
    record = json.loads(destination.read_text())
    assert record.get("annotations", {}).get(SENTINEL_ANNOTATION_KEY) == "open"
    assert record["requestObject"]["metadata"]["annotations"][SENTINEL_ANNOTATION_KEY] == "open"
