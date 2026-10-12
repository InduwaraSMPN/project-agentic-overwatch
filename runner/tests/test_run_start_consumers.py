"""ADR-058 at the runner's seal: a chain that opens with a run-start, sanitised, scanned and sealed.

The Guardian writes a run-start genesis at the head of every per-run chain, and the runner is the
consumer that carries such a chain into a sealed bundle unchanged:

* The sanitiser never rewrites the chain -- ``guardian_audit.jsonl`` is outside
  ``SANITISE_FILES`` -- and neither scanner finds anything to change in a genesis.
* The seal's blocked-request reconciliation skips the genesis by its ``record_type``
  (``runner/bundle.py``), so a zero-action run -- whose chain is the genesis alone -- seals, and so
  does an ordinary one. The control seals the same bundle without the genesis, so the cases differ
  in the genesis and in nothing else; the disguised case shows the skip is the discriminator and
  not an accident of which fields a genesis lacks.
"""

import pytest
from guardian.app.models import AUDIT_RECORD_SCHEMA_VERSION
from guardian.audit.chain import AuditChainWriter, scan_chain_file
from guardian.audit.record_types import DECISION_RECORD_TYPE, RUN_START_RECORD_TYPE

from runner.bundle import load_seal, seal_bundle
from runner.sanitize import SANITISE_FILES, sanitize_bundle, scan_for_secrets
from runner.tests.test_bundle import (
    _FIXED_SEALED_AT,
    _build_framework_on,
    _framework_on_manifest,
)

RUN_ID = "RUN-G0-FULL-SCN-CVE-04-INJ-A-101"
CHAIN = "guardian_audit.jsonl"

# A test parameter for the writer, as runner/tests/test_bundle.py uses it; not a protocol value.
_JUSTIFICATION_BOUND = 4096

_ACTED = (
    {
        "decision": "permit",
        "enforcement": "executed",
        "action": {"verb": "get", "resource": "pods", "namespace": "default"},
    },
    {
        "decision": "deny",
        "enforcement": "blocked",
        "action": {"verb": "delete", "resource": "pods", "namespace": "boutique"},
    },
)


def _write_chain(path, *, decisions, genesis=True, genesis_extra=None):
    """Write a real chain the way the Guardian does: the run-start genesis, then ``decisions``."""
    writer = AuditChainWriter.open(path, max_justification_chars=_JUSTIFICATION_BOUND)
    if genesis:
        writer.append(
            {
                "ts": "2026-08-27T00:00:00Z",
                "run_id": RUN_ID,
                "guardian_mode": "G0-FULL",
                "record_type": RUN_START_RECORD_TYPE,
                "schema_version": AUDIT_RECORD_SCHEMA_VERSION,
                **(genesis_extra or {}),
            }
        )
    for decision in decisions:
        writer.append({"run_id": RUN_ID, "record_type": DECISION_RECORD_TYPE, **decision})
    return writer.head


def _bundle_with_chain(tmp_path, *, decisions, blocked, genesis=True, genesis_extra=None):
    """A complete framework-on bundle whose chain and blocked counter are the ones named."""
    bundle = tmp_path / RUN_ID
    _build_framework_on(bundle, injection_lines=4)
    (bundle / CHAIN).unlink()
    head = _write_chain(
        bundle / CHAIN, decisions=decisions, genesis=genesis, genesis_extra=genesis_extra
    )
    (bundle / "metrics.json").write_bytes(f'{{"requests_blocked":{blocked}}}\n'.encode())
    return bundle, head


def test_the_sanitiser_never_rewrites_a_chain_that_opens_with_run_start(tmp_path):
    """Nothing in a genesis is secret-shaped, and the chain is not the sanitiser's to touch."""
    bundle, _ = _bundle_with_chain(tmp_path, decisions=_ACTED, blocked=1)
    chain = bundle / CHAIN
    before = chain.read_bytes()
    assert CHAIN not in SANITISE_FILES
    sanitize_bundle(bundle)
    assert chain.read_bytes() == before
    assert scan_for_secrets(before.decode("utf-8")) == []
    assert scan_chain_file(chain) == []


@pytest.mark.parametrize(
    ("decisions", "blocked"), [((), 0), (_ACTED, 1)], ids=["zero-action", "acted"]
)
def test_a_bundle_whose_chain_opens_with_run_start_seals(tmp_path, decisions, blocked):
    """The run ADR-058 exists for, and the ordinary one, both sealing with the genesis in front."""
    bundle, head = _bundle_with_chain(tmp_path, decisions=decisions, blocked=blocked)
    seal_bundle(bundle, _framework_on_manifest(), sealed_at=_FIXED_SEALED_AT)
    assert load_seal(bundle)["audit_chain_head"] == head


def test_a_genesis_is_never_counted_as_a_blocked_request(tmp_path):
    """Skipped by ``record_type``: a genesis given ``enforcement: blocked`` still counts as nothing.

    Were the skip keyed on the missing field rather than the discriminator, this genesis would be
    counted and the reconciliation against ``requests_blocked`` -- one, the decision's block --
    would refuse the seal.
    """
    bundle, head = _bundle_with_chain(
        tmp_path, decisions=_ACTED, blocked=1, genesis_extra={"enforcement": "blocked"}
    )
    seal_bundle(bundle, _framework_on_manifest(), sealed_at=_FIXED_SEALED_AT)
    assert load_seal(bundle)["audit_chain_head"] == head


def test_the_same_bundle_without_the_genesis_seals(tmp_path):
    """The control: the sealing cases above differ from this one in the genesis alone."""
    bundle, head = _bundle_with_chain(tmp_path, decisions=_ACTED, blocked=1, genesis=False)
    seal_bundle(bundle, _framework_on_manifest(), sealed_at=_FIXED_SEALED_AT)
    assert load_seal(bundle)["audit_chain_head"] == head
