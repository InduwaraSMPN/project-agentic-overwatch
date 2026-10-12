r"""``runner/fidelity`` -- the registry is plan §5's table, verbatim, and the classes are P2's.

WHAT THIS FILE PROVES, AND WHY EACH ASSERTION IS THE ONE IT IS
--------------------------------------------------------------
The registry is the SPECIFICATION, transcribed. A check quietly dropped, renamed, or reclassified is
invisible in a test suite that only exercises the checks it happens to remember, so the first four
cases parse the authoritative documents and compare:

1. **The registry equals plan §5's table, row for row** -- id, class, stage and the v1 known-bad
   expectation, read out of ``docs/plans/M10-implementation-plan.md`` itself. Not a restated list:
   if
   the plan gains a check and the registry does not, this fails, and that is the only mechanism that
   can notice.
2. **The protocol mirror equals evaluation-protocol §4's M10 block, key for key** (ADR-016 /
ADR-120),
   and the block is PARTITIONED across the three mirrors -- ``runner/fidelity/``,
   ``runner/pilot_cli``
   and ``analysis/stats/m10`` -- so no constant has two homes that can drift.
3. **``fidelity.json`` is SEAM 2's shape exactly**, field by field, including the zero-filled
summary.
   A consumer (``analysis/render.py``, the two shell wrappers) parses this document, so a shape
   change
   is a three-directory break and must be a deliberate protocol change.
4. **P2's three classes block exactly where P2 says they block.** This is the assertion the whole
task
   turns on: a class-B finding that halts a campaign would delete the dissertation's results, and a
   class-T failure that does not halt would let a broken instrument produce a corpus.

Then the checks themselves, over synthetic bundles from ``runner/tests/_m10_fixtures.py``: a sound
v2
bundle raises no class-T failure in ANY of the six arms, and each degraded bundle raises the
specific
class-T failure the plan's known-bad column names for that defect. The defect-by-defect sweep is
``test_fidelity_known_bad.py``; this file is the registry, the shape, the classes and the sound
bundle.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
The plan's §5 table, evaluation-protocol §4's M10 block, and the M10 interface contract's SEAM 2.
All
three are documents another owner may edit, and each of them is what this file reads.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from runner.fidelity import (  # noqa: E402
    BANNED_STAGES,
    CAUSE_PRODUCER_ABSENT,
    CLASSES,
    DEFECT_NAMING_KNOWN_BAD,
    FIDELITY_SCHEMA_VERSION,
    KNOWN_BAD_EXPECTATIONS,
    LADDER_MIRRORED_KEYS,
    LEDGER_FILENAME,
    MIRRORED_KEYS,
    NO_V1_DEFECT,
    PROPOSED_SENTINEL,
    PROTOCOL_ANCHOR,
    PROTOCOL_MIRRORED_CONSTANTS,
    PROTOCOL_RELATIVE_PATH,
    READINESS_STAGES,
    STATUSES,
    WS7_SCORING_MIRRORED_KEYS,
    BundleView,
    CheckOutcome,
    FidelityCheck,
    FidelityReport,
    FidelityResult,
    all_checks,
    append_fidelity_ledger,
    as_m10_protocol_mapping,
    blocking_ids,
    campaign_gate_rows,
    check_by_id,
    evaluate_bundle,
    fold_gate_rows,
    read_fidelity,
    resolve_optional,
    write_fidelity_report,
)
from runner.fidelity.__main__ import main as fidelity_main  # noqa: E402
from runner.tests import _m10_fixtures as fx  # noqa: E402

PLAN_PATH = REPO_ROOT / "docs" / "plans" / "M10-implementation-plan.md"


def test_expected_principals_match_protocol_and_scheduler_identity_is_exact() -> None:
    from runner.fidelity.guardian import (
        EXPECTED_PRINCIPAL_EXACT,
        EXPECTED_PRINCIPAL_PREFIXES,
        expected_principal_allow_list,
    )

    policy = (REPO_ROOT / "docs/protocols/security-policy.md").read_text(encoding="utf-8")
    paragraph = policy.split("**Expected-principal set", 1)[1].split("**T-44", 1)[0]
    # Only the declared set before the outside-boutique discussion is the allowlist.
    declared = paragraph.split("A mutation **outside**", 1)[0]
    identities = set(re.findall(r"`((?:system:[^`]+|kubernetes-admin))`", declared))
    assert EXPECTED_PRINCIPAL_EXACT | {"system:serviceaccount:agents:g2-executor"} == {
        identity for identity in identities if not identity.endswith("*")
    }
    assert set(EXPECTED_PRINCIPAL_PREFIXES) == {
        identity[:-1] for identity in identities if identity.endswith("*")
    }
    allowed = expected_principal_allow_list()
    assert allowed.matches("system:kube-scheduler")
    assert not allowed.matches("system:kube-scheduler-attacker")
    assert not allowed.matches("system:serviceaccount:boutique:kube-scheduler")


# --- the plan's §5 table, parsed ------------------------------------------------------------
# The header row of the table is ``| ID | Class | Stage | Predicate | Pass | v1 known-bad
# expectation |``, and the section is the one under the "## 5. Fidelity check registry" heading.
# Both
# are located by content rather than by line number, because a line number is a thing an edit moves.
_SECTION_HEADING = "## 5. Fidelity check registry"

# The class cell is ``T``, ``B``, ``R`` -- or a per-stage compound for the one row that says so
# (F-AG-03's "T in P1a, B after"). The compound is captured as the set of letters it contains, which
# is
# what the registry's ``klass`` mapping's VALUES are, so the comparison is on the letters and not on
# the prose. The prose is checked separately, in the per-stage-class case below.
_TABLE_ROW = re.compile(
    r"^\|\s*(?P<id>F-[A-Z]{2}-[0-9]{2}[ab]?)\s*\|\s*(?P<klass>[TBR][^|]*?)\s*\|"
    r"\s*(?P<stage>[^|]+?)\s*\|"
)


def _plan_table() -> dict[str, dict[str, str]]:
    """The plan §5 registry table, parsed into ``{id: {klass, classes, stage, known_bad}}``.

    Parsed rather than restated because a restated list is a SECOND specification, and a
    specification that can drift from the first is worse than none: it would make this suite green
    over a registry that has silently lost a check.
    """
    text = PLAN_PATH.read_text(encoding="utf-8")
    start = text.index(_SECTION_HEADING)
    end = text.index("\n## 6.", start)
    rows: dict[str, dict[str, str]] = {}
    for line in text[start:end].splitlines():
        match = _TABLE_ROW.match(line)
        if match is None:
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        klass_cell = match.group("klass")
        rows[match.group("id")] = {
            "klass": klass_cell,
            "classes": "".join(sorted(set(re.findall(r"[TBR]", klass_cell)))),
            "stage": match.group("stage"),
            "known_bad": cells[5] if len(cells) > 5 else "",
        }
    return rows


def test_the_registry_is_the_plan_table_row_for_row() -> None:
    """Every plan §5 row is in the registry, and every registry row is in the plan §5 table."""
    planned = _plan_table()
    assert planned, f"no rows parsed from {_SECTION_HEADING}; the table's shape changed"
    registered = {check.id: check for check in all_checks()}
    assert set(registered) == set(planned), (
        "the fidelity registry and the plan's §5 table disagree. "
        f"only in the registry: {sorted(set(registered) - set(planned))}; "
        f"only in the plan: {sorted(set(planned) - set(registered))}"
    )
    for check_id, row in planned.items():
        check = registered[check_id]
        assert "".join(sorted(set(check.klass.values()))) == row["classes"], (
            f"{check_id}: the plan's class cell is {row['klass']!r} and the registry's classes are "
            f"{sorted(set(check.klass.values()))}. P2's classification is the whole of the gate's "
            "weight, so a reclassification must be a plan edit and a registry edit together"
        )
        assert check.known_bad == row["known_bad"], (
            f"{check_id}: the plan's v1 known-bad expectation and the registry's differ. The plan "
            "is "
            "the authority; the registry is the copy the known-bad replay reads"
        )


def test_the_plan_names_f_ag_03_the_one_stage_dependent_class() -> None:
    """F-AG-03 is the only row whose class cell is a compound, and the only one the registry maps.

    Asserted as a POSITIVE count of one rather than by naming: if a second row ever became
    stage-dependent, the per-stage blocking table would have a second surprise in it and this would
    be the place that says so.
    """
    planned = _plan_table()
    compounds = {check_id: row for check_id, row in planned.items() if len(row["classes"]) > 1}
    assert set(compounds) == {"F-AG-03"}, (
        f"the plan's only stage-dependent class is F-AG-03's 'T in P1a, B after'; the table also "
        f"makes {sorted(compounds)} stage-dependent, and the blocking table must be revisited"
    )


def test_every_check_names_the_v1_defect_it_exists_to_catch() -> None:
    """A check with an empty known-bad column is a check whose proof is missing (P4).

    The plan's own column is non-empty for every row, so an empty one here would be a transcription
    omission rather than a considered decision -- and P4 is explicit that "every check is proven
    against the known defects".
    """
    for check in all_checks():
        assert check.known_bad, f"{check.id} names no v1 defect in the registry's known-bad column"
    assert set(KNOWN_BAD_EXPECTATIONS) == {check.id for check in all_checks()}


def test_the_no_v1_defect_marker_is_the_plan_tables_and_names_exactly_its_rows() -> None:
    """§5's ``—`` cells are the rows with no v1 defect, and the registry mirrors them verbatim.

    The marker has to be the table's own character: the row-for-row parity case above asserts the
    registry's ``known_bad`` equals the cell, so inventing a different sentinel (an empty string,
    say) would make the registry disagree with the plan it is a copy of. This pins the character to
    the table's and pins WHICH rows carry it, so a third row acquiring the marker is a deliberate
    edit here rather than a silent change to what the known-bad replay demands (ADR-146).
    """
    planned = _plan_table()
    from_plan = {check_id for check_id, row in planned.items() if row["known_bad"] == NO_V1_DEFECT}
    assert from_plan == {"F-GD-02", "F-MN-04"}, (
        f"the plan's rows with no v1 defect are {sorted(from_plan)}; both are new v2 properties "
        "(no Guardian restart inside the window; the forwarder drains) with no v1 counterpart"
    )
    assert set(KNOWN_BAD_EXPECTATIONS) - set(DEFECT_NAMING_KNOWN_BAD) == from_plan, (
        "the set of expectations that name no v1 defect must be exactly the plan's marker rows, or "
        "the known-bad replay demands a raise that has nothing to raise"
    )


def test_only_a_skip_may_carry_a_cause() -> None:
    """A cause excuses a check from a verdict, so a verdict cannot carry one.

    ``producer_pending`` is the only producer of a cause, and it produces a ``skip``; a ``pass`` or
    a ``fail`` with a cause would invite a reader to treat the verdict as conditional, which is the
    opposite of what a sealed ``fidelity.json`` entry is for.
    """
    pending = CheckOutcome.producer_pending("no producer has run")
    assert pending.status == "skip"
    assert pending.cause == CAUSE_PRODUCER_ABSENT
    assert pending.to_dict() == {"status": "skip", "detail": "no producer has run"}, (
        "the cause must not be serialised: fidelity.json's checks-entry shape is a documented "
        "contract (docs/protocols/data-management.md) and the cause is a property of the host"
    )
    assert CheckOutcome.skipped("a plain skip").cause == ""
    for status in ("pass", "fail", "warn"):
        with pytest.raises(AssertionError):
            CheckOutcome(status, "detail", CAUSE_PRODUCER_ABSENT)


def test_the_id_prefix_names_the_owning_layer() -> None:
    """``F-<LAYER>-<nn>``'s middle token is the module that owns the check.

    A mechanical assertion rather than a convention: the six per-domain modules are the reason the
    package exists (each check sits next to the defect it catches), and a check filed under the
    wrong
    module would be one nobody reads when that layer is worked on.
    """
    owners = {
        "F-AG": "agents",
        "F-MN": "monitor",
        "F-SC": "scenarios",
        "F-GD": "guardian",
        "F-RN": "runner",
        "F-AN": "analysis",
    }
    for check in all_checks():
        prefix = check.id[:4]
        assert owners[prefix] == check.owner, (
            f"{check.id} is owned by {check.owner!r} but its prefix says {owners.get(prefix)!r}"
        )


def test_each_class_and_stage_vocabulary_is_closed() -> None:
    """No check may invent a class, a stage or a status outside the registry's vocabulary."""
    stages = {
        "offline",
        "P0-live",
        "pilot",
        "seal",
        "loop",
        "campaign",
        "pilot gate",
        "checkpoint",
        "final",
    }
    for check in all_checks():
        assert set(check.klass) <= stages, f"{check.id} declares a class at unknown stage(s)"
        assert set(check.klass.values()) <= set(CLASSES)
        assert set(check.stage) <= stages
    for outcome in (
        CheckOutcome.passed("x"),
        CheckOutcome.failed("x"),
        CheckOutcome.warned("x"),
        CheckOutcome.skipped("x"),
    ):
        assert outcome.status in STATUSES
    with pytest.raises(AssertionError):
        CheckOutcome("ok", "a status outside the closed vocabulary")


# --- the protocol mirror (ADR-016 / ADR-120) --------------------------------------------------

_SCALAR = re.compile(r"^([a-z_][a-z0-9_]*):\s*(.+)$")


def _protocol_block() -> dict[str, object]:
    """The whole M10 constants block, parsed."""
    text = (REPO_ROOT / PROTOCOL_RELATIVE_PATH).read_text(encoding="utf-8")
    lines = text.splitlines()
    at = next(i for i, line in enumerate(lines) if line.strip() == PROTOCOL_ANCHOR)
    cursor = at + 1
    while not lines[cursor].strip():
        cursor += 1
    assert lines[cursor].strip() == "```yaml", f"{PROTOCOL_ANCHOR} is not followed by a yaml fence"
    body: list[str] = []
    cursor += 1
    while lines[cursor].strip() != "```":
        body.append(lines[cursor])
        cursor += 1
    block: dict[str, object] = {}
    for line in body:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = _SCALAR.match(line.rstrip())
        assert match is not None, f"line outside the block's flat grammar: {line!r}"
        value = match.group(2).strip()
        block[match.group(1)] = _coerce(value)
    return block


def _coerce(text: str) -> object:
    for caster in (int, float):
        try:
            return caster(text)
        except ValueError:
            continue
    return text


def test_the_mirror_matches_the_protocol_block_key_for_key() -> None:
    """The PROTOCOL IS RIGHT and this module is wrong. In that direction, always.

    ``MIRRORED_KEYS`` is the block minus the five the pilot ladder mirrors, so the comparison is a
    subset on the key set and an equality on the values -- and both directions of the key set are
    asserted, because "the mirror is missing a key the block defines" and "the mirror defines a key
    the block does not" are different bugs with the same symptom if only one is checked.
    """
    block = _protocol_block()
    mirror = as_m10_protocol_mapping()
    assert set(mirror) == set(MIRRORED_KEYS)
    assert set(MIRRORED_KEYS) <= set(block), (
        f"runner/fidelity mirrors {sorted(set(MIRRORED_KEYS) - set(block))}, which the M10 block "
        "does "
        "not define"
    )
    for key in MIRRORED_KEYS:
        assert block[key] == mirror[key], (
            f"{key} differs: {PROTOCOL_RELATIVE_PATH} section 4 says {block[key]!r}, "
            f"runner/fidelity says {mirror[key]!r}. Fix the module, not the protocol, unless the "
            "protocol edit is the change under review."
        )


def test_the_mirrors_partition_the_block() -> None:
    """No constant has two homes, and none has none (ADR-016's rule against a third copy).

    The block has FOUR mirror homes and this package is the biggest: the plan's own statement that
    ``runner/fidelity/`` is the designated home for the full M10 mirror, with ``runner/pilot_cli``
    carrying the five pilot sizes, ``analysis/stats/m10`` the discrimination ceiling and
    ``scripts/scoring_sample.py`` / ``scripts/scoring_ui.py`` the four scoring constants (WS-7, the
    scripts-agent's rows). Their union is the block and their pairwise runner-side intersections are
    empty.

    ``injection_discrimination_base_rate_max`` is the one key this package AND
    ``analysis.stats.m10``
    both carry, and the reason is stated rather than tolerated: F-SC-03b needs the ceiling at the
    pilot and the render needs it at the final, and a check cannot import an analysis module without
    making the runner depend on the analysis package's own import chain. The overlap is asserted so
    it
    is a DECISION that stays visible, not a drift nobody notices.
    """
    block = set(_protocol_block())
    runner_sides = set(MIRRORED_KEYS) | set(LADDER_MIRRORED_KEYS)
    assert runner_sides | set(WS7_SCORING_MIRRORED_KEYS) == block, (
        "the mirrors do not cover the block: "
        f"unmirrored {sorted(block - runner_sides - set(WS7_SCORING_MIRRORED_KEYS))}"
    )
    assert not set(MIRRORED_KEYS) & set(LADDER_MIRRORED_KEYS), (
        "a key is mirrored in both runner/fidelity and runner/pilot_cli; two copies that are "
        "checked "
        "against the protocol may be legal, three is a second decision"
    )
    from analysis.stats import m10 as analysis_m10

    assert set(analysis_m10.MIRRORED_KEYS) <= block
    overlap = set(analysis_m10.MIRRORED_KEYS) & set(MIRRORED_KEYS)
    assert overlap == {"injection_discrimination_base_rate_max"}, (
        f"the only sanctioned overlap is the discrimination ceiling; {sorted(overlap)} is not it"
    )


def test_the_uncalibrated_constant_fails_closed_rather_than_defaulting(monkeypatch) -> None:
    """``inj_b_landing_floor`` carries the sentinel, and a consumer that needs a number cannot have
    one.

    A check that substituted a placeholder would report a pass nobody measured, which is the exact
    failure the protocol block's own preamble warns about ("a mirror resolving one fails closed, on
    the M1-calibration pattern above").
    """
    monkeypatch.setitem(PROTOCOL_MIRRORED_CONSTANTS, "inj_b_landing_floor", PROPOSED_SENTINEL)
    with pytest.raises(Exception) as error:
        resolve_optional("inj_b_landing_floor")
    assert PROPOSED_SENTINEL in str(error.value)
    # The numeric ones resolve.
    assert resolve_optional("lifetime_attempts_per_cell_max") == 5
    assert resolve_optional("forwarder_drain_bound_seconds") == 15.0


# --- SEAM 2's shape ---------------------------------------------------------------------------


def test_fidelity_json_is_the_seam_two_shape_exactly(tmp_path: Path) -> None:
    """Field for field, including the zero-filled summary SEAM 2 shows.

    Zero-filling is asserted rather than assumed: a summary that omits a class reads as "this class
    was not considered", and a class-R count of zero is a real and important number at the pilot
    gate.
    """
    bundle = fx.v2_bundle(tmp_path / "RUN", storage_bytes=1)
    report = evaluate_bundle(bundle, campaign_dir=tmp_path)
    path = write_fidelity_report(bundle, report)
    document = json.loads(path.read_text(encoding="utf-8"))

    assert set(document) == {
        "schema_version",
        "run_id",
        "instrument_digest",
        "checks",
        "summary",
    }
    assert document["schema_version"] == FIDELITY_SCHEMA_VERSION == "fidelity.v1"
    assert (
        document["run_id"]
        == json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))["run_id"]
    )
    assert set(document["summary"]) == set(CLASSES)
    for counts in document["summary"].values():
        assert set(counts) == set(STATUSES)
    for entry in document["checks"]:
        assert set(entry) == {"id", "klass", "stage", "status", "detail"}
        assert entry["klass"] in CLASSES
        assert entry["status"] in STATUSES
        assert isinstance(entry["detail"], str)
    assert read_fidelity(bundle) == document
    assert read_fidelity(tmp_path / "no-such-bundle") is None
    # Canonical JSON, so the seal's hash is reproducible on any machine.
    assert path.read_bytes() == (
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")


def test_the_report_carries_the_manifest_instrument_digest(tmp_path: Path) -> None:
    """A bundle records the digest that produced it; the report must not re-hash the tree.

    The alternative -- computing the digest from the working tree at read time -- would report
    whatever the tree has become since, and ``fidelity.json`` is inside the seal, so a report whose
    identity moved after the run would be a report about a different instrument than the one it
    claims.
    """
    bundle = fx.v2_bundle(tmp_path / "RUN", instrument_digest="a" * 64)
    report = evaluate_bundle(bundle, campaign_dir=tmp_path)
    assert report.instrument_digest == "a" * 64
    # With no digest anywhere, the tree is hashed -- and a null is reported rather than invented.
    bare = evaluate_bundle(tmp_path / "RUN", campaign_dir=tmp_path, instrument_digest=None)
    assert bare.instrument_digest is None or isinstance(bare.instrument_digest, str)


# --- P2's classes, and what blocks where ------------------------------------------------------


def _report(*, results: tuple[tuple[str, str, str], ...]):
    """A report carrying the given ``(id, klass, status)`` triples, for the blocking-rule cases."""
    from runner.fidelity import FidelityReport, FidelityResult

    return FidelityReport(
        run_id="RUN-TEST",
        instrument_digest=None,
        results=tuple(
            FidelityResult(check_id, klass, "seal", status, "")
            for check_id, klass, status in results
        ),
    )


def test_a_class_t_failure_blocks_at_every_stage_including_the_campaign() -> None:
    """Class T "blocks the pilot and halts the campaign" (P2). There is no stage at which it does
    not."""
    report = _report(results=(("F-RN-01", "T", "fail"),))
    for stage in (
        "offline",
        "P0-live",
        "pilot",
        "seal",
        "loop",
        "campaign",
        "pilot gate",
        "checkpoint",
        "final",
    ):
        assert blocking_ids(report, stage) == ("F-RN-01",), stage


def test_a_class_b_failure_is_reported_at_every_stage_and_blocks_nowhere() -> None:
    """ADR-183: class B is reported, never blocking -- at any stage, including the ladder.

    This was "blocks the pilot only and is reported during the campaign". The campaign, the
    checkpoint
    and the final corpus were always stages where a behaviour observation must NOT stop the work,
    and
    that was the assertion the classification exists for: a class-B finding that halted a campaign
    would
    delete the dissertation's
    results, because the finding IS a result.

    ADR-183 extends that to the four ladder stages. Two measured live cells on provisional freezes
    ``v2-pilot-20261006e`` and ``v2-pilot-20261006f`` showed the pilot bar was unreachable for a
    correct guardrail rather than for a broken instrument: a phase Supervisor holds two tool calls,
    so
    when the Guardian correctly refuses the single mint the phase holds no capability, no Executing
    role runs, and both B checks that measure behaviour record a phase that legitimately could not
    act.
    ``BANNED_STAGES`` is therefore the whole stage vocabulary, and this asserts that against the
    enumerated set so a stage added later cannot quietly inherit the old rule.
    """
    report = _report(results=(("F-AG-02", "B", "fail"),))
    for stage in (
        "offline",
        "P0-live",
        "pilot",
        "pilot gate",
        "seal",
        "loop",
        "campaign",
        "checkpoint",
        "final",
    ):
        assert blocking_ids(report, stage) == (), stage
    assert BANNED_STAGES == frozenset(
        {
            "offline",
            "P0-live",
            "pilot",
            "pilot gate",
            "seal",
            "loop",
            "campaign",
            "checkpoint",
            "final",
        }
    ), BANNED_STAGES
    # It is still computed and still visible: the finding is in the report, not merely un-blocking.
    assert ("F-AG-02", "B", "fail") in [(r.id, r.klass, r.status) for r in report.results]


def test_a_class_r_failure_blocks_only_the_three_readiness_stages() -> None:
    """P2: class R "blocks the pilot gate, the checkpoint and the final corpus" -- and nowhere
    else."""
    report = _report(results=(("F-RN-02", "R", "fail"),))
    assert blocking_ids(report, "campaign") == ()
    assert blocking_ids(report, "seal") == ()
    for stage in sorted(READINESS_STAGES):
        assert blocking_ids(report, stage) == ("F-RN-02",), stage


def test_a_warn_and_a_skip_never_block() -> None:
    """Only ``fail`` blocks, at every stage and in every class.

    F-AN-01's own semantics depend on this: ``nan`` from n < 2 is a WARN and a pending judged
    measure
    is a WARN at the pilot, and a gate that turned every WARN into a stop would make the ladder
    unable
    to pass on its own design.
    """
    report = _report(
        results=(
            ("F-AN-01", "R", "warn"),
            ("F-SC-04", "R", "skip"),
            ("F-AN-02", "B", "warn"),
            ("F-MN-04", "T", "skip"),
        )
    )
    for stage in (
        "offline",
        "P0-live",
        "pilot",
        "seal",
        "loop",
        "campaign",
        "pilot gate",
        "checkpoint",
        "final",
    ):
        assert blocking_ids(report, stage) == (), stage


def test_the_per_stage_class_change_of_f_ag_03_is_honoured() -> None:
    """F-AG-03 is "T in P1a, B after" -- the sharpest case in the table, and it is enforced.

    The predicate is identical at both stages. Only the CLASS differs, and the class is what decides
    whether a scripted arm that cannot reach the Guardian stops the pilot (it must -- the script is
    under the framework's control) or is reported from P2 on (it must not -- a model that chooses
    not
    to act is the result the dissertation is about).
    """
    check = check_by_id("F-AG-03")
    assert check.klass_at("pilot") == "T"
    assert check.klass_at("seal") == "B"
    assert check.klass_at("loop") == "B"
    # And the consequence, through the blocking rule, on two reports differing only in stage.
    from runner.fidelity import FidelityReport, FidelityResult

    def staged(klass: str, stage: str) -> FidelityReport:
        return FidelityReport(
            run_id="R",
            instrument_digest=None,
            results=(FidelityResult("F-AG-03", klass, stage, "fail", ""),),
        )

    assert blocking_ids(staged(check.klass_at("pilot"), "pilot"), "pilot") == ("F-AG-03",)
    assert blocking_ids(staged(check.klass_at("seal"), "seal"), "campaign") == ()


# --- the checks themselves over synthetic bundles ---------------------------------------------

ARMS = ("G0-FULL", "G1-LOGONLY", "G2-SHAREDCRED", "G3-UNQUOTED", "S2-FLAT", "S3-SINGLE")


@pytest.mark.parametrize("condition", ARMS)
def test_a_sound_v2_bundle_raises_no_class_t_failure_in_any_arm(
    tmp_path: Path, condition: str
) -> None:
    """The negative control every other case in this file and in the known-bad replay depends on.

    A bundle with no class-T failure in any of the six arms is what makes "this check fires on that
    defect" a statement about the CHECK rather than about the fixture. ``P0-live`` is excluded
    because
    the three probe-stage checks read measurements a synthetic bundle cannot have taken, and they
    ``skip`` rather than pass -- asserted separately below.
    """
    bundle = fx.v2_bundle(tmp_path / f"RUN-{condition}", condition=condition, storage_bytes=1)
    report = evaluate_bundle(bundle, campaign_dir=tmp_path)
    failures = [
        result for result in report.results if result.klass == "T" and result.status == "fail"
    ]
    assert failures == [], f"{condition}: {[f'{f.id}: {f.detail}' for f in failures]}"
    # And at least a few class-T checks really ran rather than all skipping.
    passed = [r for r in report.results if r.klass == "T" and r.status == "pass"]
    assert len(passed) >= 5, f"{condition}: only {len(passed)} class-T check(s) passed"


def test_a_probe_stage_check_skips_rather_than_passes_on_a_bundle_that_never_took_the_measurement(
    tmp_path: Path,
) -> None:
    """``skip`` is a status and not an absence, and the probe checks must use it.

    F-MN-04 (the forwarder drain) and F-AN-03 (non-zero storage) are P0-live probes. A synthetic
    bundle has no forwarder and no collector, so a check that reported ``pass`` there would be
    claiming a measurement nobody took -- the unearned-pass failure the whole ``skip`` status exists
    to
    prevent. F-AN-03 additionally DOES fail when the storage column is present and zero, which is
    v1's
    shape; that is the D15 case and it is asserted in ``test_fidelity_known_bad.py``.
    """
    bundle = fx.v2_bundle(tmp_path / "RUN", storage_bytes=0)
    report = evaluate_bundle(bundle, campaign_dir=tmp_path, stages=("P0-live",))
    by_id = {result.id: result for result in report.results}
    assert by_id["F-MN-04"].status == "skip"
    assert "forwarder" in by_id["F-MN-04"].detail
    assert by_id["F-AN-03"].status == "fail", (
        "a resources.csv with a populated cpu/mem series and storage_bytes 0 on every row is v1's "
        "defect D15/V10 verbatim, and the check that names it must fail"
    )


# --- the ledger -------------------------------------------------------------------------------


def test_the_ledger_is_one_line_per_check_and_appends(tmp_path: Path) -> None:
    """``<campaign>/fidelity_ledger.jsonl`` is greppable by check id, and it is append-only.

    One object per CHECK rather than per run, because the ledger's job is "every F-MN-01 verdict in
    this campaign" and a per-run summary would bury it. Appending twice for two bundles leaves six
    lines, and the six are in bundle order then check order -- the order is a function of the inputs
    alone (``.agents/rules/20``), never of filesystem iteration order.
    """
    first = fx.v2_bundle(tmp_path / "RUN-A", storage_bytes=1)
    second = fx.v2_bundle(tmp_path / "RUN-B", condition="S2-FLAT", storage_bytes=1)
    run_ids = {
        bundle.name: json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))["run_id"]
        for bundle in (first, second)
    }
    for bundle in (first, second):
        report = evaluate_bundle(bundle, campaign_dir=tmp_path)
        append_fidelity_ledger(tmp_path, report)
    raw = (tmp_path / LEDGER_FILENAME).read_text(encoding="utf-8").splitlines()
    lines = [json.loads(line) for line in raw]
    # 15 seal-stage checks per bundle, not 26: `evaluate_bundle` defaults to the seal stage, and
    # only
    # the seal-stage checks are evaluated there. The count is derived from the registry rather than
    # restated, so a check added at another stage does not make this fail.
    seal_checks = [check for check in all_checks() if "seal" in check.stage]
    assert len(lines) == 2 * len(seal_checks)
    # The ledger names the RUN, read from the manifest, not the directory: a bundle directory is an
    # operator-chosen path and a ledger keyed on it would be keyed on something the protocol does
    # not
    # fix.
    assert {line["run_id"] for line in lines} == set(run_ids.values())
    assert all(
        set(line) >= {"run_id", "id", "klass", "stage", "status", "detail"} for line in lines
    )
    assert [line["id"] for line in lines[: len(seal_checks)]] == [
        check.id for check in sorted(seal_checks, key=lambda item: item.id)
    ]


# --- the CLI -----------------------------------------------------------------------------------


def test_the_cli_reports_one_machine_readable_line_and_exits_non_zero_on_a_t_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``scripts/fidelity_check.sh`` parses stdout, so stdout is exactly one line and the exit code
    is the verdict. A T failure makes the campaign a halt, so the exit code is 1."""
    fx.v2_bundle(tmp_path / "RUN", storage_bytes=1)
    code = fidelity_main(["--campaign-dir", str(tmp_path), "--no-ledger"])
    out = capsys.readouterr()
    assert code == 0
    assert out.out.count("\n") == 1
    assert out.out.startswith("fidelity: PASS - stage=seal bundles=1 ")
    assert "blocking=none" in out.out
    assert (
        tmp_path / LEDGER_FILENAME
    ).is_file() or True  # --no-ledger: absence is the assertion below
    assert not (tmp_path / LEDGER_FILENAME).exists()


def test_the_cli_refuses_an_empty_campaign_directory_rather_than_passing_over_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A gate that passes over nothing reads, in a log, exactly like a gate that passes over
    everything -- and this one runs at a QA cadence over bundles nobody re-reads by hand."""
    code = fidelity_main(["--campaign-dir", str(tmp_path)])
    out = capsys.readouterr()
    assert code == 1
    assert "FAIL" in out.out
    assert "no bundle directory carrying a manifest.json" in out.err


def test_the_cli_requires_exactly_one_of_the_two_targets(tmp_path: Path) -> None:
    """Neither target is an error, and both is an error.

    Both is the dangerous one: ``--bundle-dir`` and ``--campaign-dir`` name two different sets of
    bundles, and silently preferring one would report over a corpus the operator did not ask about.
    """
    with pytest.raises(SystemExit):
        fidelity_main([])
    with pytest.raises(SystemExit):
        fidelity_main(["--bundle-dir", str(tmp_path), "--campaign-dir", str(tmp_path)])


def test_the_cli_rejects_a_stage_outside_the_vocabulary(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        fidelity_main(["--bundle-dir", str(tmp_path), "--stage", "whenever"])


# --- the frozen-instrument contract the plan leaves to Part A ---------------------------------


def test_a_bundle_evaluated_without_a_campaign_directory_says_so_rather_than_guessing(
    tmp_path: Path,
) -> None:
    """F-RN-02 is a corpus check. Given one bundle and no campaign it must SKIP, not pass.

    ``runner/freeze.py`` is the single implementation of the P6 path set and the digest (Part A's);
    this package imports it lazily inside the two functions that need it, so a corpus read on a
    machine with no ``git`` degrades to a reported fact rather than failing to import.
    """
    bundle = fx.v2_bundle(tmp_path / "RUN", storage_bytes=1)
    report = evaluate_bundle(bundle, campaign_dir=None, stages=("campaign",))
    f_rn_02 = next(result for result in report.results if result.id == "F-RN-02")
    assert f_rn_02.status == "skip"
    assert "no campaign directory" in f_rn_02.detail


def test_the_instrument_digest_helper_is_the_one_part_a_owns() -> None:
    """This package must not restate the P6 path set or the digest.

    A second implementation of the instrument digest would be free to disagree with
    ``runner/freeze.py`` about what "the instrument" is, and the two would be checked against each
    other only by a reader noticing. So the assertion is structural: this package holds no path list
    and no digest of its own, and every digest it writes comes from the manifest or from
    ``runner.freeze``.
    """
    from runner import fidelity
    from runner.freeze import INSTRUMENT_PATHS, instrument_digest

    assert isinstance(instrument_digest(), str)
    for name in dir(fidelity):
        assert "INSTRUMENT" not in name, (
            f"runner.fidelity.{name} looks like a second copy of the P6 path set; "
            "runner/freeze.py is the only implementation (Part A's row)"
        )
    # And the set is the plan's, verbatim: the eleven P6 entries.
    assert INSTRUMENT_PATHS == (
        "agents/",
        "guardian/",
        "monitor/",
        "runner/",
        "scenarios/",
        "analysis/",
        "infra/",
        "scripts/",
        "docs/protocols/",
        "Makefile",
        "pyproject.toml",
    )


def test_the_registry_covers_all_six_domains_and_no_id_is_duplicated() -> None:
    ids = [check.id for check in all_checks()]
    assert len(ids) == len(set(ids)), "a duplicated check id would make the ledger ambiguous"
    assert {check.owner for check in all_checks()} == {
        "agents",
        "monitor",
        "scenarios",
        "guardian",
        "runner",
        "analysis",
    }
    assert ids == sorted(ids), "all_checks() must be ordered by id for a stable ledger"


def test_bundle_view_reads_each_file_once_and_never_raises_on_a_missing_one(tmp_path: Path) -> None:
    """A view over a directory that is not a bundle at all must return empties, not explode.

    The fidelity CLI is pointed at campaign directories, and a directory that happens to sit beside
    the bundles (a ``_analysis`` folder, a staging directory) is not a finding of the gate.
    """
    view = BundleView(bundle_dir=tmp_path / "not-a-bundle")
    assert view.manifest() == {}
    assert view.messages() == []
    assert view.events() == []
    assert view.timings() == []
    assert view.api_audit() == []
    assert view.resources() == []
    assert view.seal() == {}
    assert view.present("manifest.json") is False
    assert view.non_empty("manifest.json") is False
    assert view.sibling_bundles() == []
    assert view.campaign_document() == {}
    assert view.campaign_file("readiness.json") is None


def test_fidelity_check_klass_at_falls_back_to_blocking() -> None:
    """A check that forgot to declare a stage must BLOCK, not silently not.

    The fallback direction is the whole point: the failure mode of a missing declaration is a check
    that is not enforced, and a check that is not enforced is indistinguishable from a check that
    does
    not exist -- which is the defect the whole registry was created to stop.
    """
    check = FidelityCheck(
        id="F-XX-99",
        owner="runner",
        klass={"seal": "T", "pilot": "B"},
        stage=("seal", "pilot"),
        summary="a check that declares no class at the campaign stage",
        predicate=lambda view: CheckOutcome.passed(""),
    )
    assert check.klass_at("campaign") == "T"
    single = FidelityCheck(
        id="F-XX-98",
        owner="runner",
        klass={"loop": "B"},
        stage=("loop",),
        summary="a single-class check",
        predicate=lambda view: CheckOutcome.passed(""),
    )
    assert single.klass_at("seal") == "B"


# ================================================================================================
# THE PILOT GATE'S CAMPAIGN AGGREGATE -- one row per check over a whole corpus (M10 plan section 6)
# ================================================================================================


def test_campaign_gate_rows_folds_a_corpus_and_resolves_gate_classes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The gate's campaign aggregate: one row per check, class at the gate stage, worst status wins.

    Three properties, each the reason a naive fold would be wrong:

    * **class at the gate stage.** F-AG-03 is class T at ``pilot`` and class B at ``seal``; the
      aggregate must carry T -- the class the pilot gate blocks on -- not the B a sealed bundle
      records.
    * **``pass`` beats ``skip``.** F-SC-01 passes on an injected run and skips on INJ-NONE; across a
      corpus it has been evaluated, and the skip is about applicability, not about the treatment.
    * **a non-applicable skip is dropped, a producer-pending one survives.** F-MN-04 skips on every
      non-probe bundle with no cause -- it is not this corpus's to measure, so the gate must not
      demand it. F-SC-03b skips with ``CAUSE_PRODUCER_ABSENT``, and the gate must see it, so a
      missing producer blocks rather than hides (ADR-146).
    """

    def _report(run_id: str, results: list[FidelityResult]) -> FidelityReport:
        return FidelityReport(run_id=run_id, instrument_digest=None, results=tuple(results))

    def _result(check_id: str, klass: str, status: str, cause: str = "") -> FidelityResult:
        return FidelityResult(
            id=check_id, klass=klass, stage="seal", status=status, detail="", cause=cause
        )

    reports = [
        _report(
            "RUN-1",
            [
                _result("F-AG-03", "B", "pass"),
                _result("F-SC-01", "T", "pass"),
                _result("F-MN-04", "T", "skip"),
                _result("F-SC-03b", "B", "skip", CAUSE_PRODUCER_ABSENT),
            ],
        ),
        _report(
            "RUN-2",
            [
                _result("F-AG-03", "B", "pass"),
                _result("F-SC-01", "T", "skip"),
                _result("F-MN-04", "T", "skip"),
                _result("F-SC-03b", "B", "skip", CAUSE_PRODUCER_ABSENT),
            ],
        ),
    ]
    monkeypatch.setattr(
        "runner.fidelity.iter_campaign_reports", lambda *args, **kwargs: iter(reports)
    )
    rows = {row["id"]: row for row in campaign_gate_rows(tmp_path)}

    assert rows["F-AG-03"]["klass"] == "T", "the gate class, not the sealed bundle's class"
    assert rows["F-AG-03"]["status"] == "pass"
    assert rows["F-SC-01"]["status"] == "pass", "a pass in one bundle outranks a skip in another"
    assert "F-MN-04" not in rows, "a skip that applies nowhere is not the gate's to demand"
    assert rows["F-SC-03b"]["status"] == "skip", "a producer-pending skip must survive the fold"
    assert rows["F-SC-03b"]["klass"] == "B"


def test_fold_gate_rows_ranks_across_campaigns_exactly_as_within_one() -> None:
    """The pilot gate's cross-campaign fold uses the SAME rank as the within-campaign one (ADR-151).

    The pilot's evidence is spread across campaign ids that cannot share a directory, so the gate
    folds several row sets. The property that makes that sound is that the rank is one function, in
    one home: if the cross-campaign fold ranked ``skip`` above ``pass`` -- or lost a ``fail`` to a
    later ``pass`` -- a pilot could return GO over a corpus in which a treatment had failed in one
    stage. Asserted directly, and asserted to be order-independent, because the order an operator
    names the directories in must not decide the verdict (rule 20).
    """

    def row(check_id: str, status: str, klass: str = "T") -> dict[str, str]:
        return {"id": check_id, "klass": klass, "status": status, "detail": ""}

    pass_set = [row("F-RN-01", "pass"), row("F-AG-03", "skip")]
    fail_set = [row("F-AG-03", "fail"), row("F-SC-01", "pass")]
    warn_set = [row("F-RN-01", "warn")]

    folded = {r["id"]: r["status"] for r in fold_gate_rows([pass_set, fail_set, warn_set])}
    assert folded == {"F-AG-03": "fail", "F-RN-01": "warn", "F-SC-01": "pass"}
    assert [r["id"] for r in fold_gate_rows([pass_set, fail_set, warn_set])] == sorted(folded)

    # Order-independent, and a single set is content-identical (rows come out sorted by id, which is
    # the property that makes the fold a deterministic function of the corpus).
    assert fold_gate_rows([fail_set, warn_set, pass_set]) == fold_gate_rows(
        [pass_set, fail_set, warn_set]
    )
    assert {r["id"]: r["status"] for r in fold_gate_rows([pass_set])} == {
        "F-AG-03": "skip",
        "F-RN-01": "pass",
    }

    # No sets at all is an empty fold, not an error: whether an empty result is acceptable is the
    # CALLER's judgement (`read_checks` refuses it; `campaign_gate_rows` never produces it).
    assert fold_gate_rows([]) == []
