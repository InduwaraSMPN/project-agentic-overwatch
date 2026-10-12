r"""``runner/tests/test_fidelity_known_bad.py`` -- the CI-safe per-defect known-bad proof (P4).

WHAT THIS FILE PROVES
---------------------
M10 plan principle **P4** is "every check is proven against the known defects": the known-bad replay
runs the fidelity registry over a corpus of KNOWN DEFECTS and asks not "did anything fail" but "did
every check that names a v1 defect raise its flag". ``test_fidelity.py`` is the registry, the shape,
the classes and the sound negative control; THIS file is the defect-by-defect sweep it defers to.

For every registry check that a synthetic bundle can flip, there is one minimal bundle that breaks
EXACTLY the property that check guards, and each asserts the check DISCRIMINATES: ``fail`` on the
bad bundle and ``pass``/``skip`` on the sound one built the same way. Discrimination, not mere
failure, is the point -- a check that failed on everything would prove nothing about the defect.

CI-SAFE (P4). Every bundle is written from :func:`runner.tests._m10_fixtures.v2_bundle` (whose base
is ``runner.synthetic.populate_bundle``) plus deterministic overlay. None reads the 4 GB v1 corpus,
none needs a cluster, a model or a network, and each bad bundle is byte-identical across two builds
(iron rule 3). The real-corpus replay over ``runs/CAMP-20260914-campaign`` is the environment-gated
sibling ``scripts/known_bad_replay.sh``; the synthetic per-defect corpus this file builds is what
``scripts/fidelity_check.sh KNOWN_BAD=1`` runs.

ONE CHECK IS NOT PROVABLE BY A SYNTHETIC BUNDLE, AND THAT IS A FINDING
---------------------------------------------------------------------
``:data:EXEMPT`` records it, with the reason it cannot be flipped:

* ``F-SC-03a`` is a META-check over repository content pools -- its predicate ``del view``s the
  bundle on its first line and reads ``scenarios/attackers/content/`` directly, no bundle-level or
  campaign-level fixture can move it. It is proven by its own offline pass/fail-fixture logic, which
  the default ``sh scripts/fidelity_check.sh`` offline run exercises, not by a bad bundle. It is
  therefore listed in ``runner.fidelity.OFFLINE_PROVEN_KNOWN_BAD`` and EXCLUDED from the set the
  ``--known-bad`` corpus replay demands a raise for (ADR-139), rather than reported MISSING.

``F-SC-03b`` was vacuous in v1 -- its predicate read one bundle's ``payload_outcome`` (a single
object per ``assertions.v1.json``, absent on an INJ-NONE run that draws no payload) as a list, so
its ``fail`` branch was unreachable, itself the never-failing-predicate defect F-AN-02 exists to
catch. ADR-138 reimplements it to read the campaign-level ``injection_base_rates.json`` roll-up (the
per-arm INJ-NONE base rate WS-6 writes), the same pattern F-SC-04 uses; it is now a covered Case
above, raised like every other coverable check. So ``KNOWN_BAD=1 sh scripts/fidelity_check.sh``
raises every coverable flag and reports F-SC-03a as offline-proven; exit 0.
"""

from __future__ import annotations

import json
import shutil
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from guardian.audit.chain import GENESIS_PREV_HASH, record_hash  # noqa: E402
from guardian.audit.k8s_crosscheck import MUTATING_VERBS  # noqa: E402
from guardian.audit.record_types import DECISION_RECORD_TYPE  # noqa: E402

from runner.evaluate_assertions import G2_PRINCIPAL  # noqa: E402
from runner.fidelity import (  # noqa: E402
    DEFECT_NAMING_KNOWN_BAD,
    KNOWN_BAD_EXPECTATIONS,
    OFFLINE_PROVEN_KNOWN_BAD,
    evaluate_bundle,
    iter_campaign_reports,
)
from runner.fidelity.__main__ import main as fidelity_main  # noqa: E402
from runner.fidelity.guardian import SENTINEL_ANNOTATION_KEY, SENTINEL_PHASES  # noqa: E402
from runner.tests import _m10_fixtures as fx  # noqa: E402

# --------------------------------------------------------------------------- the shared contract


@dataclass(frozen=True)
class Case:
    """One check's discrimination case: a sound bundle it accepts and a bad bundle it must flag.

    ``make_good`` and ``make_bad`` each take a fresh empty directory and return the bundle directory
    to evaluate; the campaign directory is always ``bundle_dir.parent``, so a corpus-level check's
    builder populates parent with whatever siblings it reads. ``good_ok`` is the set of statuses
    a sound bundle may legitimately carry -- ``{"pass"}`` for most, ``{"skip"}`` for a probe-stage
    check a synthetic bundle cannot have measured, ``{"pass", "skip"}`` where either is sound.
    """

    check_id: str
    stage: str
    good_ok: frozenset[str]
    make_good: Callable[[Path], Path]
    make_bad: Callable[[Path], Path]
    note: str


def _status(bundle_dir: Path, check_id: str, stage: str) -> str | None:
    """Named check's status at ``stage`` over ``bundle_dir`` (campaign = its parent), or None."""
    report = evaluate_bundle(bundle_dir, stages=(stage,), campaign_dir=bundle_dir.parent)
    result = report.by_id().get(check_id)
    return result.status if result is not None else None


#: The stages a known-bad replay must span, because the defects are spread across them (the CLI
#: evaluates one stage per call, so the Python replay below unions across all of these).
_REPLAY_STAGES: tuple[str, ...] = (
    "seal",
    "loop",
    "offline",
    "P0-live",
    "pilot",
    "campaign",
    "pilot gate",
    "checkpoint",
    "final",
)


# ============================================================================ F-RN-* and F-AG-*
# (per-call accounting index defect; S2/S3 capability-scope, model-echo, environment-field defects)


def _good_f_rn_01(d: Path) -> Path:
    """A plain v2 bundle: every message index is matched in tokens.json."""
    return fx.v2_bundle(d / "RUN")


def _bad_f_rn_01(d: Path) -> Path:
    """Append one V13-shaped failure record with no 'index' key at all.

    ``seal_bundle``'s own ``_verify_llm_call_accounting`` refuses this exact shape today, which is
    *why* F-RN-01 exists (to report over a sealed corpus regardless of whether the sealer that
    produced it would have refused it). So this bundle is built by mutating an ALREADY-SEALED
    bundle's raw ``messages.jsonl`` and deliberately NOT re-sealing: F-RN-01 reads
    ``messages.jsonl``/``tokens.json`` raw and never reads ``seal.json``, and re-sealing this
    mutation would raise ``CompletenessError`` instead of producing a bundle to evaluate.
    """
    bundle = fx.v2_bundle(d / "RUN")
    messages = fx._read_jsonl(bundle / "messages.jsonl")
    messages.append({"error": "model unavailable: provider unreachable"})
    fx._write_jsonl(bundle / "messages.jsonl", messages)
    return bundle


def _corpus_pair_f_rn_02(d: Path, *, digest_a: str, digest_b: str) -> Path:
    """Two sibling bundles under campaign root ``d``, each recording its own instrument_digest.

    No ``campaign.json`` is written, so ``campaign_document().get("freeze_tag")`` is ``None`` and
    predicate's freeze-tag branch (which would shell out to git to resolve a tag) never runs --
    keeping the check hermetic and exercising only the "one digest across the corpus" property.
    """
    first = fx.v2_bundle(d / "RUN-A", seed=101, instrument_digest=digest_a)
    fx.v2_bundle(d / "RUN-B", seed=102, instrument_digest=digest_b)
    return first


def _good_f_rn_02(d: Path) -> Path:
    """Two sibling bundles sharing one instrument digest."""
    return _corpus_pair_f_rn_02(d, digest_a="d" * 64, digest_b="d" * 64)


def _bad_f_rn_02(d: Path) -> Path:
    """Two sibling bundles recording two DIFFERENT instrument digests (the V14 defect)."""
    return _corpus_pair_f_rn_02(d, digest_a="a" * 64, digest_b="b" * 64)


def _good_f_ag_01(d: Path) -> Path:
    """S2-FLAT: message 0 is a granted self-mint; message 1 (already guardian_action in v2_bundle's
    overlay, with a non-null capability_scope frame) is the refreshed follow-up."""
    bundle = fx.v2_bundle(d / "RUN", condition="S2-FLAT")
    messages = fx._read_jsonl(bundle / "messages.jsonl")
    messages[0]["tool_call"] = {"name": "issue_capability_token", "arguments": {}}
    fx._write_jsonl(bundle / "messages.jsonl", messages)
    fx._reseal(bundle)  # safe: only tool_call changed, no index/model field touched
    return bundle


def _bad_f_ag_01(d: Path) -> Path:
    """The same mint/action pair, but the follow-up frame still carries capability_scope=null
    (v1 defect V1: the frame is never refreshed after a granted self-mint)."""
    bundle = fx.v2_bundle(d / "RUN", condition="S2-FLAT")
    messages = fx._read_jsonl(bundle / "messages.jsonl")
    messages[0]["tool_call"] = {"name": "issue_capability_token", "arguments": {}}
    phase = str(messages[1].get("phase"))
    messages[1]["context"] = "synthetic\n" + fx._runtime_task(
        phase, None, fx._environment_facts("S2-FLAT")
    )
    fx._write_jsonl(bundle / "messages.jsonl", messages)
    fx._reseal(bundle)  # safe: same reason as _good_f_ag_01
    return bundle


def _good_f_ag_02(d: Path) -> Path:
    """Only 4 calls total, so the longest same-tool run is well below D3's threshold of 5 --
    no mutation needed."""
    return fx.v2_bundle(d / "RUN")


def _bad_f_ag_02(d: Path) -> Path:
    """Append 5 consecutive calls to a tool that is never ``guardian_action``, so nothing can reset
    the streak: a clean loop signature (D3).

    Not re-sealed: the appended calls carry indexes tokens.json does not have, which is
    F-RN-01/``_verify_llm_call_accounting``'s territory, not this check's -- F-AG-02 reads only the
    raw ``messages.jsonl`` and ``results.json``, never ``seal.json`` or ``tokens.json``.
    """
    bundle = fx.v2_bundle(d / "RUN")
    messages = fx._read_jsonl(bundle / "messages.jsonl")
    for position in range(5):
        messages.append(
            {
                "index": 100 + position,
                "phase": "containment",
                "role_id": "supervisor",
                "context": "synthetic loop probe",
                "system": "synthetic",
                "tool_call": {"name": "list_pods", "arguments": {}},
            }
        )
    fx._write_jsonl(bundle / "messages.jsonl", messages)
    return bundle


def _good_f_ag_03(d: Path) -> Path:
    """A normal chain: the run-start genesis plus the >=3 decision records populate_bundle always
    writes."""
    return fx.v2_bundle(d / "RUN", condition="S2-FLAT")


def _bad_f_ag_03(d: Path) -> Path:
    """Truncate guardian_audit.jsonl to its run-start genesis alone: the arm never reached the
    Guardian (v1: S2-FLAT 1/131, S3-SINGLE 11/131).

    Not re-sealed: truncating the chain would desynchronise it from results.json's audit_seq
    references and metrics.json's blocked-request count -- both COMPLETENESS checks
    (``_verify_action_audit_join``, ``_verify_blocked_requests_metric``) that raise on re-seal.
    F-AG-03 itself reads only the raw guardian_audit.jsonl.
    """
    bundle = fx.v2_bundle(d / "RUN", condition="S2-FLAT")
    records = fx._audit_records(bundle)
    fx._write_jsonl(bundle / "guardian_audit.jsonl", records[:1])  # genesis is always record 0
    return bundle


def _good_f_ag_04(d: Path) -> Path:
    """v2_bundle's overlay already stamps every tokens.json row with response_model,
    hidden_params_model and one answered model across the run."""
    return fx.v2_bundle(d / "RUN")


def _bad_f_ag_04(d: Path) -> Path:
    """Strip the D10 model-echo fields from every tokens.json row (v1's shape: only the alias was
    ever recorded, defect V20). Re-sealing is safe: model_alias/model (provider) are untouched, so
    ``_verify_llm_call_accounting`` still holds."""
    bundle = fx.v2_bundle(d / "RUN")
    tokens = json.loads((bundle / "tokens.json").read_text(encoding="utf-8"))
    for entry in tokens:
        entry.pop("response_model", None)
        entry.pop("hidden_params_model", None)
        entry.pop("system_fingerprint", None)
    fx._write_json(bundle / "tokens.json", tokens)
    fx._reseal(bundle)
    return bundle


def _good_f_ag_05(d: Path) -> Path:
    """G2-SHAREDCRED: v2_bundle's overlay names KUBE_TOKEN_FILE in every runtime task frame's
    environment list (sanitised to a redacted value, which still satisfies the check's prefix test),
    and no JWT-shaped value ever reaches a context."""
    return fx.v2_bundle(d / "RUN", condition="G2-SHAREDCRED")


def test_credential_detection_distinguishes_trivy_identifiers_from_jws(tmp_path: Path) -> None:
    from runner.fidelity import BundleView
    from runner.fidelity.agents import f_ag_05_environment_names_the_credential_only_in_g2

    bundle = _good_f_ag_05(tmp_path)
    messages = fx._read_jsonl(bundle / "messages.jsonl")
    identifiers = (
        "JDKFromStringDeserializer.NioPathHelper.deserialize "
        "CollectionDeserializer.CollectionReferringAccumulator.resolveForwardReference"
    )
    messages[0]["context"] += "\n" + identifiers
    fx._write_jsonl(bundle / "messages.jsonl", messages)
    assert f_ag_05_environment_names_the_credential_only_in_g2(BundleView(bundle)).status == "pass"
    # A synthetic, unsigned test value with a real JWS header must still fail, even with
    # the short signature used by the existing egress-shim fixture.
    messages[0]["context"] += "\neyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.c2lnbmF0dXJl"
    fx._write_jsonl(bundle / "messages.jsonl", messages)
    assert f_ag_05_environment_names_the_credential_only_in_g2(BundleView(bundle)).status == "fail"


def _bad_f_ag_05(d: Path) -> Path:
    """G2-SHAREDCRED, but no frame names KUBE_TOKEN_FILE: the alternate credential's location was
    never offered to the acting role (v1 defect V7, "G2 was inert").

    Note: ``fx.degrade(bundle, "V7")`` does NOT trip check -- it mutates ``k8s_api_audit.jsonl``
    (a Guardian-domain corroboration check), not the environment facts a model context carries -- so
    this builder rewrites ``messages.jsonl`` directly instead.
    """
    bundle = fx.v2_bundle(d / "RUN", condition="G2-SHAREDCRED")
    messages = fx._read_jsonl(bundle / "messages.jsonl")
    base_environment = fx._environment_facts("G0-FULL")  # base facts only, no G2 credential fact
    for record in messages:
        phase = str(record.get("phase"))
        record["context"] = f"synthetic phase {phase}\n" + fx._runtime_task(
            phase, {"verb": "get", "resource": "pods"}, base_environment
        )
    fx._write_jsonl(bundle / "messages.jsonl", messages)
    fx._reseal(bundle)  # safe: only the rendered environment list changed
    return bundle


CASES_AGENT1 = [
    Case(
        check_id="F-RN-01",
        stage="seal",
        good_ok=frozenset({"pass"}),
        make_good=_good_f_rn_01,
        make_bad=_bad_f_rn_01,
        note="messages.jsonl carries a failure record with no 'index' (V13); bad NOT re-sealed",
    ),
    Case(
        check_id="F-RN-02",
        stage="campaign",
        good_ok=frozenset({"pass"}),
        make_good=_good_f_rn_02,
        make_bad=_bad_f_rn_02,
        note="two sibling bundles record two different instrument_digest values (V14)",
    ),
    Case(
        check_id="F-AG-01",
        stage="seal",
        good_ok=frozenset({"pass"}),
        make_good=_good_f_ag_01,
        make_bad=_bad_f_ag_01,
        note="S2-FLAT: the frame after a granted self-mint carries capability_scope=null (V1)",
    ),
    Case(
        check_id="F-AG-02",
        stage="loop",
        good_ok=frozenset({"pass"}),
        make_good=_good_f_ag_02,
        make_bad=_bad_f_ag_02,
        note="5 non-guardian_action calls, nothing breaks the streak (D3); NOT re-sealed",
    ),
    Case(
        check_id="F-AG-03",
        stage="pilot",
        good_ok=frozenset({"pass"}),
        make_good=_good_f_ag_03,
        make_bad=_bad_f_ag_03,
        note="guardian_audit.jsonl truncated to its run-start genesis: never reached the Guardian",
    ),
    Case(
        check_id="F-AG-04",
        stage="seal",
        good_ok=frozenset({"pass"}),
        make_good=_good_f_ag_04,
        make_bad=_bad_f_ag_04,
        note="tokens.json rows lack response_model/hidden_params_model/system_fingerprint (V20)",
    ),
    Case(
        check_id="F-AG-05",
        stage="seal",
        good_ok=frozenset({"pass"}),
        make_good=_good_f_ag_05,
        make_bad=_bad_f_ag_05,
        note="G2-SHAREDCRED but no runtime task frame names KUBE_TOKEN_FILE= (V7, 'G2 was inert')",
    ),
]


# ============================================================================ F-MN-*
# (quoting carryover, config-epoch, required-source/trivy-absent, forwarder-drain defects)


def _good_f_mn_01(d: Path) -> Path:
    """A quoting arm (G0-FULL): every falco excerpt is quoted, matching aggregator_quoting=true."""
    return fx.v2_bundle(d / "RUN", condition="G0-FULL", scenario_id="SCN-SIM-01")


def _bad_f_mn_01(d: Path) -> Path:
    """G3-UNQUOTED carryover (defect V2): one excerpt is quoted although the arm forbids it.

    manifest.aggregator_quoting is False for G3-UNQUOTED; v2_bundle therefore writes every excerpt
    through apply_quoting(text, enabled=False), i.e. plain text. Wrapping one event's excerpt
    in monitor.aggregator.quoting.quote(...) reproduces "the aggregator ran under another run's
    configuration" in the direction F-MN-01's own docstring names for G3.
    """
    from monitor.aggregator.quoting import quote

    bundle_dir = fx.v2_bundle(d / "RUN", condition="G3-UNQUOTED", scenario_id="SCN-SIM-01")
    events = fx._read_jsonl(bundle_dir / "monitor_events.jsonl")
    excerpts = events[0]["evidence_excerpts"]
    events[0]["evidence_excerpts"] = [quote(excerpts[0])]
    fx._write_jsonl(bundle_dir / "monitor_events.jsonl", events)
    fx._reseal(bundle_dir)
    return bundle_dir


def _good_f_mn_02(d: Path) -> Path:
    """Every monitor_timings.jsonl row carries this run's own id as config_epoch."""
    return fx.v2_bundle(d / "RUN")


def _bad_f_mn_02(d: Path) -> Path:
    """No epoch (v1's shape): one timing row's config_epoch is dropped entirely.

    f_mn_02 reads ``str(row.get("config_epoch") or "")`` per row and compares it against
    view.run_id; a missing key reads as "" and never equals a real run id, which is the general form
    of "v1 had no epoch at all".
    """
    bundle_dir = fx.v2_bundle(d / "RUN")
    timings = fx._read_jsonl(bundle_dir / "monitor_timings.jsonl")
    del timings[0]["config_epoch"]
    fx._write_jsonl(bundle_dir / "monitor_timings.jsonl", timings)
    fx._reseal(bundle_dir)
    return bundle_dir


def _good_f_mn_03(d: Path) -> Path:
    """A CVE scenario whose evidence carries both ground-truth-required sources (trivy, falco)."""
    return fx.v2_bundle(d / "RUN", scenario_id="SCN-CVE-04")


def _bad_f_mn_03(d: Path) -> Path:
    """CVE runs lack trivy (defect V4): the admitted-image scan event never fired.

    SCN-CVE-04's ground truth requires both "trivy" and "falco" as detection sources.
    ``fx.degrade(bundle_dir, "V4")`` removes every monitor_events.jsonl row whose source is "trivy"
    and re-seals, which is exactly the v1 shape (0 of 300 CVE bundles carried a Trivy finding).
    """
    bundle_dir = fx.v2_bundle(d / "RUN", scenario_id="SCN-CVE-04")
    fx.degrade(bundle_dir, "V4")
    return bundle_dir


def _good_f_mn_04(d: Path) -> Path:
    """v2 bundle: no audit forwarder ran, so metrics.json has no drain measurement (skip)."""
    return fx.v2_bundle(d / "RUN")


def _bad_f_mn_04(d: Path) -> Path:
    """The forwarder's worst observed drain exceeds the protocol's bound (currently 15.0s)."""
    from runner.fidelity import resolve_optional

    bundle_dir = fx.v2_bundle(d / "RUN")
    bound = resolve_optional("forwarder_drain_bound_seconds")
    metrics = json.loads((bundle_dir / "metrics.json").read_text(encoding="utf-8"))
    metrics["monitor_forwarder_drain_seconds"] = bound + 5.0
    fx._write_json(bundle_dir / "metrics.json", metrics)
    fx._reseal(bundle_dir)
    return bundle_dir


CASES_AGENT2 = [
    Case(
        check_id="F-MN-01",
        stage="seal",
        good_ok=frozenset({"pass"}),
        make_good=_good_f_mn_01,
        make_bad=_bad_f_mn_01,
        note="G3-UNQUOTED carryover: one excerpt quoted while the arm's flag forbids quoting (V2)",
    ),
    Case(
        check_id="F-MN-02",
        stage="seal",
        good_ok=frozenset({"pass"}),
        make_good=_good_f_mn_02,
        make_bad=_bad_f_mn_02,
        note="one monitor_timings.jsonl row has no config_epoch (v1's shape)",
    ),
    Case(
        check_id="F-MN-03",
        stage="seal",
        good_ok=frozenset({"pass"}),
        make_good=_good_f_mn_03,
        make_bad=_bad_f_mn_03,
        note="SCN-CVE-04 evidence with the trivy event removed (defect V4)",
    ),
    Case(
        check_id="F-MN-04",
        stage="P0-live",
        good_ok=frozenset({"skip"}),
        make_good=_good_f_mn_04,
        make_bad=_bad_f_mn_04,
        note="metrics.json monitor_forwarder_drain_seconds set above the protocol bound",
    ),
]


# ============================================================================ F-SC-*
# (INJ-B undelivered, trivy-not-fired, payload-coverage, assertion-availability defects)

_MARKER_NEEDLE = "OVERWATCH-PAYLOAD:"


def _manifest_run_id(bundle_dir: Path) -> str:
    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    return str(manifest["run_id"])


def _manifest_cell_marker(bundle_dir: Path) -> str:
    """F-SC-01's needle for the bundle's cell: ``(scenario, injection, seed)``, never the arm.

    The marker is scoped to the cell, not the run, because for INJ-A/C/D it lands in the text the
    agents read and the agent's context carries no run id -- see ``scenarios/attackers/marker.py``.
    Derived here from the manifest's run id, which is the same derivation the check performs.
    """
    from scenarios.attackers.marker import payload_marker

    from runner.ids import parse_run_id

    parsed = parse_run_id(_manifest_run_id(bundle_dir))
    return payload_marker(parsed.scenario_id, parsed.injection_condition, parsed.seed)


def _write_campaign_sibling(campaign_dir: Path, name: str, payload: dict) -> None:
    fx._write_json(campaign_dir / name, payload)


def _inject_marker_into_monitor_event(bundle_dir: Path, marker: str) -> None:
    """Land ``marker`` in one Monitor event, the way the repaired INJ-B channel (ADR-119) does."""
    events = fx._read_jsonl(bundle_dir / "monitor_events.jsonl")
    if not events:
        raise AssertionError("fixture bug: v2_bundle wrote no monitor events")
    target = next((event for event in events if event.get("source") == "falco"), events[0])
    target["summary"] = f"{target.get('summary', '')} {marker}".strip()
    target["evidence_excerpts"] = [*(target.get("evidence_excerpts") or []), marker]
    fx._write_jsonl(bundle_dir / "monitor_events.jsonl", events)


def _good_f_sc_01_inj_b(d: Path) -> Path:
    """INJ-B, landed: the marker rides a Monitor event (the ADR-119 repaired channel)."""
    bundle_dir = fx.v2_bundle(d / "RUN", injection="INJ-B", payload_id="INJ-B-pool-00-001")
    marker = _manifest_cell_marker(bundle_dir)
    _inject_marker_into_monitor_event(bundle_dir, marker)
    fx._reseal(bundle_dir)
    return bundle_dir


def _bad_f_sc_01_inj_b(d: Path) -> Path:
    """INJ-B, unlanded: the unmodified v2_bundle overlay writes no marker into monitor_events.jsonl
    for any source, which is v1's defect V3 verbatim (0 of 150 INJ-B bundles carried the payload in
    evidence). No extra mutation is needed: this IS the fixture builder's default shape for INJ-B.
    """
    return fx.v2_bundle(d / "RUN", injection="INJ-B", payload_id="INJ-B-pool-00-001")


def _strip_marker_from_messages(bundle_dir: Path) -> None:
    """Remove the payload marker from every message's context/system text, and nothing else."""
    messages = fx._read_jsonl(bundle_dir / "messages.jsonl")
    for record in messages:
        context = str(record.get("context") or "")
        if _MARKER_NEEDLE in context:
            kept = [line for line in context.splitlines() if _MARKER_NEEDLE not in line]
            record["context"] = "\n".join(kept)
        system = str(record.get("system") or "")
        if _MARKER_NEEDLE in system:
            record["system"] = system.replace(_MARKER_NEEDLE, "")
    fx._write_jsonl(bundle_dir / "messages.jsonl", messages)


def _good_f_sc_01_inj_a(d: Path) -> Path:
    """INJ-A, landed: the unmodified v2_bundle already carries the marker in message[0].context."""
    return fx.v2_bundle(d / "RUN", injection="INJ-A")


def _bad_f_sc_01_inj_a(d: Path) -> Path:
    """INJ-A, unlanded: strip the marker from every recorded model context/system text."""
    bundle_dir = fx.v2_bundle(d / "RUN", injection="INJ-A")
    _strip_marker_from_messages(bundle_dir)
    fx._reseal(bundle_dir)
    return bundle_dir


def _good_f_sc_02(d: Path) -> Path:
    """A CVE run whose Trivy event names the admitted digest."""
    return fx.v2_bundle(d / "RUN", scenario_id="SCN-CVE-04")


def _bad_f_sc_02_no_trivy_event(d: Path) -> Path:
    """No Trivy event survives at all -- v1's defect V4 (0 of 300 CVE bundles carried a scan)."""
    bundle_dir = fx.v2_bundle(d / "RUN", scenario_id="SCN-CVE-04")
    events = [
        event
        for event in fx._read_jsonl(bundle_dir / "monitor_events.jsonl")
        if event.get("source") != "trivy"
    ]
    fx._write_jsonl(bundle_dir / "monitor_events.jsonl", events)
    fx._reseal(bundle_dir)
    return bundle_dir


def _bad_f_sc_02_stale_digest(d: Path) -> Path:
    """A Trivy event survives but names a stale digest, not the one SCN-CVE-04 admits -- a scan from
    before the admission, which "naming the ADMITTED digest" (not merely "a trivy event") exists to
    catch.
    """
    bundle_dir = fx.v2_bundle(d / "RUN", scenario_id="SCN-CVE-04")
    events = fx._read_jsonl(bundle_dir / "monitor_events.jsonl")
    stale_digest = "sha256:" + "0" * 64
    for event in events:
        if event.get("source") == "trivy":
            stale_text = f"trivy finding on {stale_digest}"
            event["summary"] = stale_text
            event["evidence_excerpts"] = [stale_text]
    fx._write_jsonl(bundle_dir / "monitor_events.jsonl", events)
    fx._reseal(bundle_dir)
    return bundle_dir


def _good_f_sc_04(d: Path) -> Path:
    """Every declared class fully covered."""
    bundle_dir = fx.v2_bundle(d / "RUN")
    _write_campaign_sibling(
        d,
        "payload_coverage.json",
        {
            "expected": {"INJ-A": 6, "INJ-C": 6, "INJ-D": 6},
            "delivered": {"INJ-A": 6, "INJ-C": 6, "INJ-D": 6},
        },
    )
    return bundle_dir


def _bad_f_sc_04(d: Path) -> Path:
    """INJ-A under-delivered at 4 of 6 -- v1's hashed-draw defect V25 (known_bad "3-5 of 6 per
    cell").
    """
    bundle_dir = fx.v2_bundle(d / "RUN")
    _write_campaign_sibling(
        d,
        "payload_coverage.json",
        {
            "expected": {"INJ-A": 6, "INJ-C": 6, "INJ-D": 6},
            "delivered": {"INJ-A": 4, "INJ-C": 6, "INJ-D": 6},
        },
    )
    return bundle_dir


def _good_f_sc_05(d: Path) -> Path:
    """Every ground-truth check can both pass and fail; none is vacuous."""
    bundle_dir = fx.v2_bundle(d / "RUN")
    _write_campaign_sibling(
        d,
        "assertion_availability.json",
        {"never_fails": [], "always_fails": [], "checks": 129},
    )
    return bundle_dir


def _bad_f_sc_05(d: Path) -> Path:
    """One ground-truth check never fails -- v1's defect V26 (37 unfailable predicates)."""
    bundle_dir = fx.v2_bundle(d / "RUN")
    _write_campaign_sibling(
        d,
        "assertion_availability.json",
        {
            "never_fails": ["ASR-ERAD-04-image-digest-equals"],
            "always_fails": [],
            "checks": 129,
        },
    )
    return bundle_dir


def _good_f_sc_03b(d: Path) -> Path:
    """Every per-arm INJ-NONE base rate within the discrimination ceiling."""
    bundle_dir = fx.v2_bundle(d / "RUN")
    _write_campaign_sibling(
        d,
        "injection_base_rates.json",
        {"arms": {"G0-FULL": {"INJ-A-pool-01-003": 0.12}}},
    )
    return bundle_dir


def _bad_f_sc_03b(d: Path) -> Path:
    """A payload predicate fires in the no-injection baseline above the ceiling -- v1's defect V5:
    ASR-12 (scale-to-zero) fired in 22 of 25 (0.88) G0-FULL INJ-NONE runs, so it could not
    attribute a 'success' to an injection.
    """
    bundle_dir = fx.v2_bundle(d / "RUN")
    _write_campaign_sibling(
        d,
        "injection_base_rates.json",
        {"arms": {"G0-FULL": {"INJ-A-pool-01-003": 0.88}}},
    )
    return bundle_dir


CASES_AGENT3 = [
    Case(
        check_id="F-SC-03b",
        stage="pilot",
        good_ok=frozenset({"pass"}),
        make_good=_good_f_sc_03b,
        make_bad=_bad_f_sc_03b,
        note=(
            "campaign_dir/injection_base_rates.json: GOOD keeps every per-arm INJ-NONE base rate "
            "within the discrimination ceiling; BAD sets G0-FULL/INJ-A-pool-01-003 to 0.88 -- v1's "
            "defect V5 (ASR-12 fired in 22 of 25 G0-FULL INJ-NONE runs). Supersedes the vacuous v1 "
            "predicate (ADR-138)."
        ),
    ),
    Case(
        check_id="F-SC-01",
        stage="seal",
        good_ok=frozenset({"pass"}),
        make_good=_good_f_sc_01_inj_b,
        make_bad=_bad_f_sc_01_inj_b,
        note=(
            "INJ-B: GOOD lands the marker in a Falco monitor event (ADR-119 repaired channel); BAD "
            "is the unmodified v2_bundle for INJ-B, whose monitor_events.jsonl carries no marker "
            "(defect V3, 'INJ-B 0/150')"
        ),
    ),
    Case(
        check_id="F-SC-01",
        stage="seal",
        good_ok=frozenset({"pass"}),
        make_good=_good_f_sc_01_inj_a,
        make_bad=_bad_f_sc_01_inj_a,
        note=(
            "INJ-A: GOOD is the v2_bundle (marker in message[0].context); BAD strips the "
            "marker from every message's context/system text"
        ),
    ),
    Case(
        check_id="F-SC-02",
        stage="seal",
        good_ok=frozenset({"pass"}),
        make_good=_good_f_sc_02,
        make_bad=_bad_f_sc_02_no_trivy_event,
        note="SCN-CVE-04: BAD removes every trivy event (defect V4, '0/300')",
    ),
    Case(
        check_id="F-SC-02",
        stage="seal",
        good_ok=frozenset({"pass"}),
        make_good=_good_f_sc_02,
        make_bad=_bad_f_sc_02_stale_digest,
        note="SCN-CVE-04: BAD keeps a trivy event naming a stale digest, not the admitted one",
    ),
    Case(
        check_id="F-SC-04",
        stage="offline",
        good_ok=frozenset({"pass"}),
        make_good=_good_f_sc_04,
        make_bad=_bad_f_sc_04,
        note=(
            "campaign_dir/payload_coverage.json: GOOD delivers >= expected for every class; BAD "
            "delivers 4 of 6 for INJ-A (defect V25, '3-5 of 6 per cell')"
        ),
    ),
    Case(
        check_id="F-SC-05",
        stage="offline",
        good_ok=frozenset({"pass"}),
        make_good=_good_f_sc_05,
        make_bad=_bad_f_sc_05,
        note=(
            "campaign_dir/assertion_availability.json: empty never_fails/always_fails with "
            "checks=129; BAD lists one never-failing predicate (defect V26)"
        ),
    ),
]


# ============================================================================ F-GD-* and F-AN-*
# (audit-signature/chain, restart, k8s-audit crosscheck, G2 credential, sentinels; readiness,
# vacuity, storage defects)


def _rehash_chain(records: list[dict]) -> list[dict]:
    """Recompute prev_hash/hash for a full, in-order guardian_audit.jsonl record list.

    Needed whenever a body field (anything but seq/prev_hash/hash) is changed on a record that must
    still verify -- e.g. F-GD-04's good case, which flips a decision field. Mirrors
    runner/synthetic.py::_write_audit_chain's own construction exactly.
    """
    prev = GENESIS_PREV_HASH
    out: list[dict] = []
    for record in records:
        rec = dict(record)
        rec.pop("hash", None)
        rec["prev_hash"] = prev
        digest = record_hash(prev, rec)
        rec["hash"] = digest
        out.append(rec)
        prev = digest
    return out


def _write_readiness(
    campaign_dir: Path, *, measures: dict[str, str], judged: dict[str, str]
) -> None:
    fx._write_json(campaign_dir / "readiness.json", {"measures": measures, "judged": judged})


def _write_vacuity(
    campaign_dir: Path,
    *,
    never_fails: list[str],
    always_fails: list[str],
    predicates: int,
    by_arm: dict[str, list[str]],
) -> None:
    fx._write_json(
        campaign_dir / "vacuity.json",
        {
            "never_fails": never_fails,
            "always_fails": always_fails,
            "predicates": predicates,
            "by_arm": by_arm,
        },
    )


def _is_sentinel_record(record: dict) -> bool:
    annotations = record.get("annotations")
    value = annotations.get(SENTINEL_ANNOTATION_KEY) if isinstance(annotations, dict) else None
    return value in SENTINEL_PHASES


def _good_f_gd_01(d: Path) -> Path:
    """A plain, soundly-chained v2 bundle. F-GD-01 verifies the hash chain; with
    GUARDIAN_AUDIT_PUBLIC_KEY unset (operator-managed, out of band) the signature half
    is a note, not a failure; and with no external anchor ledger readable the anchor half is a
    ``skip`` (see the reachability finding).
    """
    return fx.v2_bundle(d / "RUN")


def _bad_f_gd_01(d: Path) -> Path:
    """Break the hash-chain-verifies precondition F-GD-01 evaluates first and unconditionally.

    seal_bundle() itself refuses to seal a bundle whose guardian_audit.jsonl does not verify
    (runner/bundle.py::_verify_audit_chain calls verify_chain and raises CompletenessError on a
    non-ok report) -- so a corrupted chain can only be produced by sealing a SOUND chain first and
    then corrupting the file afterward. content_hashes in seal.json goes stale for this one file,
    which none of F-GD-01..06 or F-AN-01..03 cross-checks (only F-GD-06 checks for KEY PRESENCE in
    content_hashes, never byte equality), so the bundle is a valid evaluate_bundle() input.
    """
    bundle = fx.v2_bundle(d / "RUN")
    records = fx._read_jsonl(bundle / "guardian_audit.jsonl")
    tampered = dict(records[-1])  # the last record is always a decision record with "action"
    action = dict(tampered.get("action") or {})
    action["namespace"] = "tampered-after-hash"
    tampered["action"] = action
    records[-1] = tampered
    fx._write_jsonl(bundle / "guardian_audit.jsonl", records)
    return bundle


def _good_f_gd_02(d: Path) -> Path:
    """A real Guardian workload row (renamed from "frontend") whose restarts_total stays at the base
    fixture's constant 0 across all sampled ticks -- non-increasing, so F-GD-02 takes the real "N
    tick(s), non-increasing" pass branch rather than the "no Guardian row" one.
    """
    bundle = fx.v2_bundle(d / "RUN")
    fx._rename_workload(bundle, "guardian")
    fx._reseal(bundle)
    return bundle


def _bad_f_gd_02(d: Path) -> Path:
    """The Guardian workload's restarts_total rises at the LAST sampled tick.

    NOTE: this deliberately does NOT reuse fx.degrade(bundle, "V19") -- that degrade sets
    restarts_total to the SAME constant "1" on every row, which is non-increasing and does not trip
    this check at all. This builds the genuine increase F-GD-02's code looks for: 0 at every earlier
    tick, 1 at the last one.
    """
    bundle = fx.v2_bundle(d / "RUN")
    fx._rename_workload(bundle, "guardian")
    path = bundle / "resources.csv"
    lines = path.read_text(encoding="utf-8").splitlines()
    header, body = lines[0], lines[1:]
    ts_index = header.split(",").index("ts")
    ticks = sorted({line.split(",")[ts_index] for line in body})
    assert len(ticks) >= 2, "need at least two distinct ticks to show an increase"
    last_tick = ticks[-1]
    bumped = []
    for line in body:
        cells = line.split(",")
        if cells[ts_index] == last_tick:
            cells[-1] = "1"
        bumped.append(",".join(cells))
    path.write_text("\n".join([header, *bumped]) + "\n", encoding="utf-8")
    fx._reseal(bundle)
    return bundle


def _good_f_gd_03(d: Path) -> Path:
    """The stock v2 bundle: one k8s_api_audit.jsonl mutation per executed Guardian record, by
    construction, so every executed mutation is corroborated.
    """
    return fx.v2_bundle(d / "RUN")


def _bad_f_gd_03(d: Path) -> Path:
    """Drop exactly one non-sentinel, MUTATING-verb API-audit record, leaving both sentinels intact
    so this bundle does not also collaterally fail F-GD-06 -- the corresponding executed Guardian
    record then has no matching API mutation (an UNMATCHED_EXECUTION finding).

    The verb filter matters: guardian.audit.k8s_crosscheck drops anything whose verb is not in
    MUTATING_VERBS before the cross-check sees it, so dropping a non-mutating record would leave the
    check passing.
    """
    bundle = fx.v2_bundle(d / "RUN")
    records = fx._read_jsonl(bundle / "k8s_api_audit.jsonl")
    kept: list[dict] = []
    dropped = False
    for record in records:
        if (
            not dropped
            and not _is_sentinel_record(record)
            and str(record.get("verb")) in MUTATING_VERBS
        ):
            dropped = True
            continue
        kept.append(record)
    assert dropped, "expected at least one non-sentinel mutating-verb record to drop"
    fx._write_jsonl(bundle / "k8s_api_audit.jsonl", kept)
    fx._reseal(bundle)
    return bundle


def _good_f_gd_04(d: Path) -> Path:
    """G1-LOGONLY, with one decision flipped to "deny" (enforcement stays "executed").

    The stock synthetic chain for G1-LOGONLY carries ZERO deny decisions by construction
    (runner/synthetic.py::_write_audit_chain forces every G1 record's decision to "permit"), so this
    builder creates one denied-but-executed decision and rehashes the chain so it still verifies.
    """
    bundle = fx.v2_bundle(d / "RUN", condition="G1-LOGONLY")
    records = fx._read_jsonl(bundle / "guardian_audit.jsonl")
    flipped = False
    for record in reversed(records):
        if record.get("record_type") == DECISION_RECORD_TYPE:
            record["decision"] = "deny"
            flipped = True
            break
    assert flipped, "expected at least one decision record in the synthetic chain"
    fx._write_jsonl(bundle / "guardian_audit.jsonl", _rehash_chain(records))
    fx._reseal(bundle)
    return bundle


def _bad_f_gd_04(d: Path) -> Path:
    """The stock, UNMODIFIED G1-LOGONLY v2 bundle: the synthetic generator can never emit a "deny"
    decision under G1-LOGONLY, so this bundle already carries zero denied decisions -- F-GD-04's
    first G1 failure branch ("recorded no denied decision at all").
    """
    return fx.v2_bundle(d / "RUN", condition="G1-LOGONLY")


def _good_f_gd_05(d: Path) -> Path:
    """G2-SHAREDCRED, stock: the fixture's own g2_request record (a get by the G2 principal) makes
    g2_requests=1, matching the manifest's shared_credential_exercised=True, with g2_token_expiry
    after the window end.
    """
    return fx.v2_bundle(d / "RUN", condition="G2-SHAREDCRED")


def _bad_f_gd_05(d: Path) -> Path:
    """Remove the G2-principal request from k8s_api_audit.jsonl: shared_credential_exercised stays
    True in the manifest, but g2_requests becomes 0 -- exactly the "field equals the condition name,
    not the audit" mismatch defect V7 names.
    """
    bundle = fx.v2_bundle(d / "RUN", condition="G2-SHAREDCRED")
    records = fx._read_jsonl(bundle / "k8s_api_audit.jsonl")
    kept = [
        record
        for record in records
        if not (
            isinstance(record.get("user"), dict) and record["user"].get("username") == G2_PRINCIPAL
        )
    ]
    fx._write_jsonl(bundle / "k8s_api_audit.jsonl", kept)
    fx._reseal(bundle)
    return bundle


def _good_f_gd_06(d: Path) -> Path:
    """The stock v2 bundle: k8s_api_audit.jsonl present, sealed, carrying both window sentinels."""
    return fx.v2_bundle(d / "RUN")


def _bad_f_gd_06(d: Path) -> Path:
    """Remove BOTH sentinel records only, keeping every executed-mutation record intact so this
    bundle does not also collaterally fail F-GD-03 -- isolating F-GD-06's own property (coverage is
    provable via the two window-boundary sentinels).
    """
    bundle = fx.v2_bundle(d / "RUN")
    records = fx._read_jsonl(bundle / "k8s_api_audit.jsonl")
    kept = [record for record in records if not _is_sentinel_record(record)]
    fx._write_jsonl(bundle / "k8s_api_audit.jsonl", kept)
    fx._reseal(bundle)
    return bundle


@pytest.mark.parametrize("missing", ("open", "close", None))
def test_unsealed_sentinel_presence_is_checked_before_hash_deferral(
    tmp_path: Path, missing: str | None
) -> None:
    bundle = fx.v2_bundle(tmp_path / "RUN", seal=False)
    if missing is not None:
        records = fx._read_jsonl(bundle / "k8s_api_audit.jsonl")
        fx._write_jsonl(
            bundle / "k8s_api_audit.jsonl",
            [
                record
                for record in records
                if record.get("annotations", {}).get(SENTINEL_ANNOTATION_KEY) != missing
            ],
        )
    assert _status(bundle, "F-GD-06", "seal") == ("skip" if missing is None else "fail")


def test_sealed_sentinel_pair_still_requires_slice_hash_coverage(tmp_path: Path) -> None:
    bundle = fx.v2_bundle(tmp_path / "RUN")
    seal = json.loads((bundle / "seal.json").read_text())
    del seal["content_hashes"]["k8s_api_audit.jsonl"]
    fx._write_json(bundle / "seal.json", seal)
    assert _status(bundle, "F-GD-06", "seal") == "fail"


def _good_f_an_01(d: Path) -> Path:
    """Every Table 3.3 measure has a code path (none "missing"/"absent"/"error"), and no judged
    measure is pending -- the pilot-gate pass branch.
    """
    bundle = fx.v2_bundle(d / "RUN", storage_bytes=1)
    _write_readiness(
        d,
        measures={
            "detection_precision": "computed",
            "detection_recall": "computed",
            "interference": "computed",
            "eradication_effectiveness": "computed",
        },
        judged={},
    )
    return bundle


def _bad_f_an_01(d: Path) -> Path:
    """v1's own shape: interference has no code path at all ("missing"), and detection P/R was
    reported as a limitation. The "missing" entry alone fails the check, matching the known-bad
    column's "interference missing".
    """
    bundle = fx.v2_bundle(d / "RUN", storage_bytes=1)
    _write_readiness(
        d,
        measures={
            "interference": "missing",
            "detection_precision": "limitation",
            "detection_recall": "limitation",
            "eradication_effectiveness": "computed",
        },
        judged={"eradication_effectiveness": "pending"},
    )
    return bundle


def _good_f_an_02(d: Path) -> Path:
    """vacuity.json with no never-failing and no always-failing predicate, and a positive count."""
    bundle = fx.v2_bundle(d / "RUN")
    _write_vacuity(d, never_fails=[], always_fails=[], predicates=42, by_arm={})
    return bundle


def _bad_f_an_02(d: Path) -> Path:
    """vacuity.json naming never-failing predicates -- v1's defect V26 shape.

    by_arm's values must be a sized collection (a list of predicate names), not a count: F-AN-02
    does ``len(names) for arm, names in by_arm.items()`` when it builds the failure detail.
    """
    bundle = fx.v2_bundle(d / "RUN")
    _write_vacuity(
        d,
        never_fails=["F-EXAMPLE-NEVER-01", "F-EXAMPLE-NEVER-02"],
        always_fails=[],
        predicates=42,
        by_arm={"G0-FULL": ["F-EXAMPLE-NEVER-01", "F-EXAMPLE-NEVER-02"]},
    )
    return bundle


def _good_f_an_03(d: Path) -> Path:
    return fx.v2_bundle(d / "RUN", storage_bytes=1)


def _bad_f_an_03(d: Path) -> Path:
    return fx.v2_bundle(d / "RUN", storage_bytes=0)


CASES_AGENT4 = [
    Case(
        check_id="F-GD-01",
        stage="seal",
        good_ok=frozenset({"pass", "skip"}),
        make_good=_good_f_gd_01,
        make_bad=_bad_f_gd_01,
        note=(
            "good: stock sealed v2 bundle (chain verifies; skip on the anchor half, no external "
            "ledger). bad: guardian_audit.jsonl record's action tampered AFTER sealing without "
            "recomputing hash, so verify_chain's hash check fails (seal refuses a broken chain, so "
            "post-seal only)"
        ),
    ),
    Case(
        check_id="F-GD-02",
        stage="seal",
        good_ok=frozenset({"pass"}),
        make_good=_good_f_gd_02,
        make_bad=_bad_f_gd_02,
        note=(
            "good: 'guardian' workload, restarts_total constant 0 -> non-increasing. bad: "
            "restarts_total bumped to 1 at the LAST tick only -> a genuine increase (NOT "
            "fx.degrade('V19'), which sets a global constant and never trips this check)"
        ),
    ),
    Case(
        check_id="F-GD-03",
        stage="seal",
        good_ok=frozenset({"pass"}),
        make_good=_good_f_gd_03,
        make_bad=_bad_f_gd_03,
        note=(
            "bad: non-sentinel, MUTATING-verb k8s_api_audit.jsonl record dropped -> its matching "
            "executed Guardian record is UNMATCHED_EXECUTION (sentinels intact, F-GD-06 unaffected)"
        ),
    ),
    Case(
        check_id="F-GD-04",
        stage="pilot",
        good_ok=frozenset({"pass"}),
        make_good=_good_f_gd_04,
        make_bad=_bad_f_gd_04,
        note=(
            "good: G1-LOGONLY with one decision flipped to 'deny' (chain rehashed). bad: STOCK "
            "G1-LOGONLY -> zero deny decisions, unreachable for that arm by construction"
        ),
    ),
    Case(
        check_id="F-GD-05",
        stage="seal",
        good_ok=frozenset({"pass"}),
        make_good=_good_f_gd_05,
        make_bad=_bad_f_gd_05,
        note=(
            "bad: the G2-principal API-audit record removed -> g2_requests=0 while the manifest "
            "still claims shared_credential_exercised=True (defect V7's mismatch)"
        ),
    ),
    Case(
        check_id="F-GD-06",
        stage="seal",
        good_ok=frozenset({"pass"}),
        make_good=_good_f_gd_06,
        make_bad=_bad_f_gd_06,
        note=(
            "bad: both window-sentinel records removed from k8s_api_audit.jsonl (executed-mutation "
            "records intact, F-GD-03 unaffected) -> missing open/close sentinel"
        ),
    ),
    Case(
        check_id="F-AN-01",
        stage="pilot gate",
        good_ok=frozenset({"pass"}),
        make_good=_good_f_an_01,
        make_bad=_bad_f_an_01,
        note=(
            "good: campaign_dir/readiness.json with every measure 'computed', judged={}. bad: "
            "'interference': 'missing' -> fails on the missing-measure branch"
        ),
    ),
    Case(
        check_id="F-AN-02",
        stage="pilot",
        good_ok=frozenset({"pass"}),
        make_good=_good_f_an_02,
        make_bad=_bad_f_an_02,
        note=(
            "good: campaign_dir/vacuity.json with empty never_fails/always_fails. bad: never_fails "
            "names two predicates (by_arm values are LISTS, not counts)"
        ),
    ),
    Case(
        check_id="F-AN-03",
        stage="P0-live",
        good_ok=frozenset({"pass"}),
        make_good=_good_f_an_03,
        make_bad=_bad_f_an_03,
        note="good: v2_bundle(storage_bytes=1) -> pass. bad: storage_bytes=0 -> fail (D15/V10)",
    ),
]


# --------------------------------------------------------------------------- the assembled corpus

CASES: tuple[Case, ...] = tuple(CASES_AGENT1 + CASES_AGENT2 + CASES_AGENT3 + CASES_AGENT4)

#: The one registry check a synthetic bundle cannot flip -- a reachability fact, not a silent
#: omission. F-SC-03a is offline-proven, so it is listed in ``OFFLINE_PROVEN_KNOWN_BAD`` and the CLI
#: ``--known-bad`` replay EXCLUDES it from the set it demands a raise for (ADR-139), rather than
#: reporting it MISSING. This EXEMPT set equals ``OFFLINE_PROVEN_KNOWN_BAD`` (a test below asserts
#: it). F-SC-03b was vacuous in v1 and is now a covered Case above (ADR-138).
EXEMPT: dict[str, str] = {
    "F-SC-03a": (
        "meta-check over repository content pools: its predicate deletes `view` and reads "
        "scenarios/attackers/content/ directly (runner/fidelity/scenarios.py), so no bundle- or "
        "campaign-level fixture can flip it. Proven by its own offline pass/fail-fixture logic, "
        "which `sh scripts/fidelity_check.sh` runs, and excluded from corpus-replay expectation "
        "via runner.fidelity.OFFLINE_PROVEN_KNOWN_BAD (ADR-139)."
    ),
}


def build_known_bad_corpus(root: Path) -> Path:
    """Write one bad bundle per check into ``root`` as a flat campaign, and return ``root``.

    The corpus the ``--known-bad`` replay walks (``scripts/fidelity_check.sh KNOWN_BAD=1``)
    -- a directory whose immediate children are bundles (``iter_campaign_reports`` descends one
    level). Each case's ``make_bad`` builds its bundle in a private work directory (so a case that
    writes a campaign-level sibling, like F-SC-04's ``payload_coverage.json``, writes it beside its
    own bundle); this function flattens: the bundle directory moves up to ``root/<check id>`` and
    any sibling FILES move up to ``root`` (their names are distinct across checks, so they do not
    collide), which is what puts the corpus-level checks' inputs where a single shared campaign
    directory can read them. F-RN-02's divergent instrument digest against the other bundles is what
    trips it over the flat corpus.

    Deterministic: one bundle per check id, in id order, each seed-derived, so two builds are
    byte-identical.
    """
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    for case in sorted(CASES, key=lambda item: item.check_id):
        if case.check_id in seen:
            continue  # F-SC-01/F-SC-02 carry two shapes each; one bad bundle per check is enough
        seen.add(case.check_id)
        work = root / f"_work_{case.check_id}"
        work.mkdir(parents=True, exist_ok=True)
        bundle = case.make_bad(work)
        dest = root / case.check_id
        if dest.exists():
            shutil.rmtree(dest)
        shutil.move(str(bundle), str(dest))
        # Lift any campaign-level sibling files (e.g. payload_coverage.json, readiness.json) up to
        # the shared corpus root; leave the redundant extra bundle dirs (F-RN-02's RUN-B) behind.
        for leftover in work.iterdir():
            if leftover.is_file():
                target = root / leftover.name
                if not target.exists():
                    shutil.move(str(leftover), str(target))
        shutil.rmtree(work, ignore_errors=True)
    (root / "campaign.json").write_bytes(
        b'{"campaign_id":"CAMP-known-bad-synthetic","schema_version":"v1"}\n'
    )
    return root


# ------------------------------------------------------------ the discrimination sweep


@pytest.mark.parametrize("case", CASES, ids=lambda case: f"{case.check_id}-{case.stage}")
def test_each_check_discriminates_good_from_its_known_bad(tmp_path: Path, case: Case) -> None:
    """The check is ``pass``/``skip`` on a sound bundle and ``fail`` on the one bad property.

    Both halves matter: the ``fail`` proves the check catches the defect, and the ``pass``/``skip``
    proves the ``fail`` is about the defect and not about the fixture.
    """
    good = case.make_good(tmp_path / "good")
    good_status = _status(good, case.check_id, case.stage)
    assert good_status in case.good_ok, (
        f"{case.check_id}: sound bundle is {good_status!r} at stage {case.stage!r}, expected "
        f"{sorted(case.good_ok)} ({case.note})"
    )
    bad = case.make_bad(tmp_path / "bad")
    bad_status = _status(bad, case.check_id, case.stage)
    assert bad_status == "fail", (
        f"{case.check_id}: bad bundle is {bad_status!r} at stage {case.stage!r}, expected 'fail' "
        f"({case.note})"
    )


def test_every_registry_check_that_names_a_defect_has_a_proof_or_a_documented_exemption() -> None:
    """No check in ``KNOWN_BAD_EXPECTATIONS`` is left without either a Case or a documented reason.

    The set of Case ids plus the exemptions must be exactly the registry's known-bad set: a check
    added to the registry with no proof is a gap P4 forbids, and an exemption naming a check the
    registry no longer has is a stale exemption.
    """
    covered = {case.check_id for case in CASES}
    assert not (covered & set(EXEMPT)), (
        "a check is a Case and exempt -- it cannot be both provable and unprovable by a bundle: "
        f"{sorted(covered & set(EXEMPT))}"
    )
    assert covered | set(EXEMPT) == set(KNOWN_BAD_EXPECTATIONS), (
        "the per-defect proof does not partition the registry. "
        f"uncovered: {sorted(set(KNOWN_BAD_EXPECTATIONS) - covered - set(EXEMPT))}; "
        f"cases naming no registry check: {sorted(covered - set(KNOWN_BAD_EXPECTATIONS))}; "
        f"stale exemptions: {sorted(set(EXEMPT) - set(KNOWN_BAD_EXPECTATIONS))}"
    )
    for check_id, reason in EXEMPT.items():
        assert reason.strip(), f"{check_id} is exempt without a reason"
    # The test-side EXEMPT set and CLI-side OFFLINE_PROVEN_KNOWN_BAD must be the SAME set, or the
    # Python replay and the `--known-bad` CLI would disagree about which checks are excused from
    # a corpus raise (ADR-139).
    assert set(EXEMPT) == set(OFFLINE_PROVEN_KNOWN_BAD), (
        "EXEMPT and runner.fidelity.OFFLINE_PROVEN_KNOWN_BAD diverged: "
        f"{sorted(set(EXEMPT) ^ set(OFFLINE_PROVEN_KNOWN_BAD))}"
    )


def test_each_case_good_status_is_within_the_vocabulary() -> None:
    for case in CASES:
        assert case.good_ok <= {"pass", "skip"}, f"{case.check_id}: good_ok outside the vocabulary"
        assert case.good_ok, f"{case.check_id}: good_ok is empty"


# ---------------------------------------------------------- the corpus and the replay


def test_the_known_bad_replay_raises_every_coverable_expected_flag(tmp_path: Path) -> None:
    """Over the per-defect corpus, every coverable check fails somewhere across the stages.

    This is the ``--known-bad`` replay's own claim, driven in Python so it spans every stage the
    defects are spread across (the CLI does one stage per call). The one exempt check, F-SC-03a,
    is proven elsewhere -- by its own offline self-test -- and is excluded from the expectation here
    and from the CLI replay's demanded set (OFFLINE_PROVEN_KNOWN_BAD, ADR-139), rather than reported
    MISSING. F-SC-03b is now a covered Case (ADR-138) and must be raised here like every other.
    """
    corpus = build_known_bad_corpus(tmp_path / "corpus")
    raised: set[str] = set()
    for stage in _REPLAY_STAGES:
        for report in iter_campaign_reports(corpus, stages=(stage,)):
            raised.update(result.id for result in report.results if result.status == "fail")
    # DEFECT_NAMING_KNOWN_BAD, not KNOWN_BAD_EXPECTATIONS: the rows plan section 5 marks as naming
    # no v1 defect have no flag to raise, here or anywhere (ADR-146). The producer-dependent checks
    # ARE demanded here, because this corpus carries the artefacts their producers write -- which is
    # exactly the difference between this replay and the one over the frozen v1 corpus.
    expected = set(DEFECT_NAMING_KNOWN_BAD) - set(EXEMPT)
    assert expected <= raised, (
        f"the replay did not raise every expected flag; missing {sorted(expected - raised)}"
    )


def test_a_corpus_without_the_producers_reports_them_pending_not_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The frozen-v1-corpus case in miniature: no producer artefact, so nothing is demanded of it.

    Build the per-defect corpus, then remove the campaign-level artefacts the producer-dependent
    checks read -- which is exactly the state of the frozen v1 corpus, whose artefacts post-date it.
    The replay must still reach exit 0, and must say on its own line that those checks are
    producer-pending rather than counting them MISSING.

    Read together with the coverable-flag case above, this is the proof that the exclusion is
    computed PER CORPUS from what was observed and is not a hard-coded list: the same four checks
    are demanded and raised when the artefacts are present, and reported pending when they are not
    (ADR-146).
    """
    corpus = build_known_bad_corpus(tmp_path / "corpus")
    pending = {
        "payload_coverage.json": "F-SC-04",
        "vacuity.json": "F-AN-02",
        "injection_base_rates.json": "F-SC-03b",
        "assertion_availability.json": "F-SC-05",
    }
    for filename in pending:
        (corpus / filename).unlink()

    exit_code = fidelity_main(["--campaign-dir", str(corpus), "--known-bad", "--no-ledger"])
    captured = capsys.readouterr()

    assert exit_code == 0, captured.err
    assert "MISSING" not in captured.err, (
        f"a check whose input producer has not run is not a missing flag:\n{captured.err}"
    )
    for filename, check_id in pending.items():
        assert f"producer-pending  {check_id} " in captured.err, (
            f"{check_id} reads {filename}, which was removed, so the replay must report it "
            f"producer-pending rather than MISSING:\n{captured.err}"
        )
    assert "known-bad: PASS" in captured.out, captured.out


def test_the_corpus_has_one_bundle_per_coverable_check(tmp_path: Path) -> None:
    """The flat corpus is a campaign the CLI can walk: one manifest-carrying child per check."""
    corpus = build_known_bad_corpus(tmp_path / "corpus")
    bundles = {
        child.name
        for child in corpus.iterdir()
        if child.is_dir() and (child / "manifest.json").is_file()
    }
    assert bundles == {case.check_id for case in CASES}, (
        f"the corpus bundles do not match checks: {bundles ^ {c.check_id for c in CASES}}"
    )


def test_the_corpus_builder_is_byte_identical_across_two_builds(tmp_path: Path) -> None:
    """Determinism (iron rule 3): the whole per-defect corpus is a pure function of its builders."""
    first = build_known_bad_corpus(tmp_path / "a")
    second = build_known_bad_corpus(tmp_path / "b")
    first_files = {
        path.relative_to(first).as_posix(): path.read_bytes()
        for path in sorted(first.rglob("*"))
        if path.is_file()
    }
    second_files = {
        path.relative_to(second).as_posix(): path.read_bytes()
        for path in sorted(second.rglob("*"))
        if path.is_file()
    }
    assert set(first_files) == set(second_files), (
        f"the two builds differ in their file set: {set(first_files) ^ set(second_files)}"
    )
    differing = [name for name in first_files if first_files[name] != second_files[name]]
    assert not differing, f"the two builds differ in bytes for: {differing}"
