r"""The pilot ladder: the instrument-digest key, the freeze, and the gate decision (ADR-120, §6).

WHAT IS PROVEN HERE, AND WHY IT IS PROVEN OVER A THROWAWAY REPOSITORY
---------------------------------------------------------------------
Two of the three named cases are about what happens when the INSTRUMENT moves, which means they need
two commits. The real repository is, by construction during M10, dirty in the instrument paths --
the
whole remediation is uncommitted work under ``runner/`` and ``agents/`` -- and ``.agents/rules/30``
forbids a git write. So every ladder test here drives a miniature repository under ``tmp_path`` with
P6's path set in it and passes its root down as ``repo_root``; the freeze machinery itself is
exercised in ``runner/tests/test_freeze.py``, and this file is about the ladder's RESPONSE to it.

The three named cases:

* :func:`test_instrument_change_resets_ladder` -- plan §6's restart rule, verbatim.
* :func:`test_docs_only_commit_keeps_ladder` -- the same rule from the other side, and the case v1's
  whole-repository dirty check got backwards (defect V14).
* :func:`test_decide_requires_every_T_check` -- the gate's T rule, including the ``warn``/``skip``
  cases that a naive "any failure blocks" would get wrong in the other direction.

Plus the properties the gate is worthless without: the state is byte-reproducible, the ladder is
climbed in order, an out-of-order record is refused, and a NO-GO names every reason.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from runner.fidelity import FidelityReport, FidelityResult  # noqa: E402
from runner.freeze import FROZEN_COMMIT_SIDECAR, FreezeError, read_frozen_commit  # noqa: E402
from runner.pilot_cli import (  # noqa: E402
    GATE_DECISION_FILE,
    GO,
    LADDER_STAGES,
    LADDER_STATE_FILE,
    NO_GO,
    RESET_STAGE,
    GateDecision,
    LadderError,
    LadderState,
    coverage_order,
    evaluate_gate,
    gate_decision,
    ladder_complete,
    load_gate_decision,
    load_ladder_state,
    main,
    next_stage,
    read_checks,
    record_stage,
)

# A miniature instrument: one file per instrument path is enough, because the freeze keys on the
# path set and git's reporting of it, not on the files' contents.
_FIXTURE_FILES = (
    "agents/graphs/nodes.py",
    "guardian/policies/authority.rego",
    "monitor/rules/overwatch-rules.yaml",
    "runner/pilot_cli.py",
    "scenarios/manifests/SCN-SIM-01.yaml",
    "analysis/stats/measures.py",
    "infra/audit/audit-policy.yaml",
    "scripts/up.sh",
    "docs/protocols/evaluation-protocol.md",
    "Makefile",
    "pyproject.toml",
    "docs/adr/ADR-120-treatment-fidelity-gate-pilot-ladder-halt.md",
)


def _git(repo: Path, *args: str) -> str:
    """One git invocation in the throwaway repository. Never touches the real one."""
    completed = subprocess.run(  # noqa: S603 - fixed argv
        ["git", *args],  # noqa: S607 - git on PATH by design, as everywhere in the runner
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, f"git {' '.join(args)} failed: {completed.stderr}"
    return completed.stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A clean, committed, tagged miniature repository carrying P6's path set."""
    root = tmp_path / "instrument"
    root.mkdir()
    _git(root, "init", "--quiet", "--initial-branch=main")
    _git(root, "config", "user.email", "pilot-test@example.invalid")
    _git(root, "config", "user.name", "pilot test")
    _git(root, "config", "commit.gpgsign", "false")
    _git(root, "config", "tag.gpgsign", "false")
    for name in _FIXTURE_FILES:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# {name}\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "--quiet", "-m", "instrument at v1")
    _git(root, "tag", "-a", "v1.0", "-m", "instrument freeze v1.0")
    return root


def _commit(repo: Path, name: str, text: str, message: str) -> None:
    (repo / name).write_text(text, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "--quiet", "-m", message)


def _climb(repo: Path, state_dir: Path, campaign_dir: Path) -> LadderState:
    """Record every stage in order on the current instrument, and return the final state."""
    state = None
    for stage in LADDER_STAGES:
        state = record_stage(
            state_dir, stage, freeze_tag="v1.0", repo_root=repo, campaign_dir=campaign_dir
        )
    assert state is not None
    return state


def _check(check_id: str, klass: str, status: str = "pass") -> dict[str, str]:
    """One SEAM 2 fidelity row. Built by a helper so no test hand-rolls the key set."""
    return {"id": check_id, "klass": klass, "stage": "seal", "status": status}


def _fidelity(tmp_path: Path, checks: list[dict[str, str]]) -> Path:
    path = tmp_path / "fidelity.json"
    path.write_text(
        json.dumps({"schema_version": "fidelity.v1", "run_id": "RUN-X", "checks": checks}),
        encoding="utf-8",
    )
    return path


# ================================================================================================
# THE THREE NAMED CASES
# ================================================================================================


def test_instrument_change_resets_ladder(repo: Path, tmp_path: Path) -> None:
    """Plan §6: "an instrument change resets the ladder to P1a".

    Driven on the PRE-FREEZE path (no ``freeze_tag``), because that is where the ladder actually
    runs: it is climbed long before ``v2.0`` exists. Post-freeze the same edit is a HALT, not a
    reset -- the campaign-grade rule -- and the last assertion below proves both halves, so neither
    can be quietly relaxed into the other.

    The whole ladder is climbed, then the instrument changes, and the recorded progress is GONE:
    every earlier result was produced by an instrument that no longer exists, so none of it is
    evidence about this one. Asserted three ways -- the completed set is emptied, the resume point
    is
    P1a, and the reset is counted -- because a reset that only cleared the list would leave the
    operator believing the ladder had been climbed.

    The docs-only half of the same rule is :func:`test_docs_only_commit_keeps_ladder`; together they
    are the whole of §6's restart rule and they are the reason the state is keyed on the digest.
    """
    state_dir = tmp_path / "state"
    campaign_dir = tmp_path / "runs" / "CAMP-20260926-pilot-p3"
    state = None
    for stage in LADDER_STAGES:
        state = record_stage(state_dir, stage, repo_root=repo, campaign_dir=campaign_dir)
    assert state is not None
    assert state.resets == 0
    assert state.resume_stage is None
    assert ladder_complete(state)
    digest_before = state.instrument_digest

    _commit(repo, "runner/pilot_cli.py", "# an instrument edit\n", "instrument change")

    after = record_stage(state_dir, "p0", repo_root=repo, campaign_dir=campaign_dir)
    assert after.instrument_digest != digest_before
    assert after.completed == ("p0",)
    assert after.resets == 1
    assert not ladder_complete(after)

    # The resume point is P1a -- the plan's restart stage -- and P0 is separately recordable because
    # §6 re-runs P0-offline in full. Both are allowed; nothing between them is.
    assert next_stage(after) == RESET_STAGE
    with pytest.raises(LadderError, match="cannot be recorded before"):
        record_stage(state_dir, "p2", repo_root=repo, campaign_dir=campaign_dir)

    re_reached = record_stage(state_dir, RESET_STAGE, repo_root=repo, campaign_dir=campaign_dir)
    assert re_reached.completed == ("p0", RESET_STAGE)
    assert re_reached.resume_stage is None
    # P0-offline is re-run in full (§6), so the first stage still missing is p0-live even though the
    # reset point p1a has been re-reached.
    assert next_stage(re_reached) == "p0-live"

    # POST-FREEZE the same move is a halt, not a reset: with a freeze tag the digest comparison
    # fires first, so `retarget` is unreachable and the ladder cannot be re-pointed at a new
    # instrument.
    with pytest.raises(FreezeError, match="instrument moved after the freeze"):
        record_stage(state_dir, "p0", freeze_tag="v1.0", repo_root=repo, campaign_dir=campaign_dir)


def test_docs_only_commit_keeps_ladder(repo: Path, tmp_path: Path) -> None:
    """Plan §6: "A commit outside the instrument paths does not reset the ladder."

    The mirror of the previous test and the one v1 got backwards. A reworded ADR, a reworded plan, a
    dissertation chapter: none of them can change what a run does, so under P6 none of them may cost
    the operator a re-run of P1a, P1b, P2 and P3 -- thirty-one live runs and about six hours of
    manifest-window time for a comment.

    Also asserted: the ladder advances normally across such a commit, and the recorded digest is
    byte-identical, so the two tests together prove the digest -- not the commit count, not HEAD's
    SHA -- is the key.
    """
    state_dir = tmp_path / "state"
    campaign_dir = tmp_path / "runs" / "CAMP-20260926-pilot-p2"
    climbed = _climb(repo, state_dir, campaign_dir)
    assert ladder_complete(climbed)

    for index in range(3):
        _commit(
            repo,
            "docs/adr/ADR-120-treatment-fidelity-gate-pilot-ladder-halt.md",
            f"# reworded, revision {index}\n",
            f"prose only, revision {index}",
        )

    after = record_stage(
        state_dir, "p0", freeze_tag="v1.0", repo_root=repo, campaign_dir=campaign_dir
    )
    assert after.instrument_digest == climbed.instrument_digest
    assert after.completed == climbed.completed
    assert after.resets == 0
    assert after.resume_stage is None
    assert ladder_complete(after)
    assert after.frozen_commit == climbed.frozen_commit


def test_decide_requires_every_T_check(repo: Path, tmp_path: Path) -> None:
    """Every class-T check at 100% is required to return GO -- including ``warn`` and ``skip``.

    Plan §5/§6: class T blocks the pilot and halts the campaign, and every stage's exit criterion is
    "T 100%". The subtle half is that ``warn`` and ``skip`` are NOT passes: a check that could not
    run has not passed, and a gate that read it as one would be satisfiable by a check that never
    executed -- which is defect V16's shape.

    The other half of the rule is that a check list with NO class-T row at all is refused, because a
    gate that never looked at the arms is exactly the v1 gate pilot.
    """
    state_dir = tmp_path / "state"
    campaign_dir = tmp_path / "runs" / "CAMP-20260926-pilot-p3"
    complete = _climb(repo, state_dir, campaign_dir)
    assert ladder_complete(complete)

    passing = [_check("F-RN-01", "T"), _check("F-AG-03", "T"), _check("F-SC-01", "T")]
    go = evaluate_gate(passing, ladder_state=complete)
    assert go.decision == "GO"
    assert go.reasons == ()
    assert go.counts["T"]["pass"] == 3
    assert go.instrument_digest == complete.instrument_digest

    for status in ("fail", "warn", "skip"):
        decision = evaluate_gate([*passing, _check("F-GD-05", "T", status)], ladder_state=complete)
        assert decision.decision == NO_GO, f"a T check at {status!r} must block the gate"
        assert any("F-GD-05" in reason for reason in decision.reasons)
        assert any("class T" in reason for reason in decision.reasons)

    # A check list with no class-T row cannot return GO however healthy it looks.
    without_t = evaluate_gate(
        [_check("F-AN-01", "R"), _check("F-AG-02", "B")], ladder_state=complete
    )
    assert without_t.decision == NO_GO
    assert any("no class-T check" in reason for reason in without_t.reasons)

    # Class B does not gate (ADR-183), and the decision says so by COUNTING it rather than by
    # mentioning it: a B failure must not withhold GO, and must still be visible in the tally a
    # reader of gate_decision.json consults. Class R still blocks on `fail`; F-AN-01's readiness
    # gate owns the per-stage semantics, so a WARN on R does not.
    reported = evaluate_gate([*passing, _check("F-AG-02", "B", "fail")], ladder_state=complete)
    assert reported.decision == GO, "a class-B finding is reported, not gating (ADR-183)"
    assert reported.counts["B"]["fail"] == 1, "and it must still be counted"
    assert evaluate_gate(
        [*passing, _check("F-AN-01", "R", "fail")], ladder_state=complete
    ).decision == (NO_GO)
    assert evaluate_gate(
        [*passing, _check("F-AN-01", "R", "warn")], ladder_state=complete
    ).decision == ("GO")

    # T still gates at every status short of a pass, and a B failure cannot make a bad T pass.
    assert (
        evaluate_gate(
            [*passing, _check("F-AG-02", "B", "fail"), _check("F-GD-05", "T", "skip")],
            ladder_state=complete,
        ).decision
        == NO_GO
    )

    # P3's exit criterion: zero framework-attributable failures across P1-P3.
    assert evaluate_gate(passing, ladder_state=complete, framework_failures=1).decision == NO_GO

    # An incomplete ladder cannot be gated GO, whatever the checks say.
    partial = LadderState(
        instrument_digest=complete.instrument_digest,
        completed=("p0", "p1a"),
        freeze_tag="v1.0",
        frozen_commit=complete.frozen_commit,
        resets=0,
        resume_stage=None,
    )
    assert evaluate_gate(passing, ladder_state=partial).decision == NO_GO
    assert evaluate_gate(passing, ladder_state=None).decision == NO_GO


# ================================================================================================
# THE STATE FILE, THE CLI, AND THE DECISION DOCUMENT
# ================================================================================================


def test_the_ladder_state_is_byte_reproducible_and_carries_no_timestamp(
    repo: Path, tmp_path: Path
) -> None:
    """Iron rule 3: the state is a function of the instrument and the stages recorded, nothing else.

    Re-recording a completed stage is idempotent, and the file is canonical JSON, so a fix loop that
    re-runs a stage leaves the artifact byte-identical -- which is what lets the researcher tell "I
    re-ran it" from "it changed" by looking at the bytes.
    """
    state_dir = tmp_path / "state"
    campaign_dir = tmp_path / "runs" / "CAMP-20260926-pilot-p1a"
    record_stage(state_dir, "p0", freeze_tag="v1.0", repo_root=repo, campaign_dir=campaign_dir)
    record_stage(state_dir, "p0-live", freeze_tag="v1.0", repo_root=repo, campaign_dir=campaign_dir)
    record_stage(state_dir, "p1a", freeze_tag="v1.0", repo_root=repo, campaign_dir=campaign_dir)
    state_file = state_dir / LADDER_STATE_FILE
    first = state_file.read_bytes()
    time_before = state_file.stat().st_mtime_ns

    same = record_stage(
        state_dir, "p1a", freeze_tag="v1.0", repo_root=repo, campaign_dir=campaign_dir
    )
    assert state_file.read_bytes() == first
    assert same.completed == ("p0", "p0-live", "p1a")
    assert next_stage(same) == "p1b"
    # Content-identical on a re-run; the file is not even rewritten when nothing changed.
    assert state_file.stat().st_mtime_ns == time_before

    # The payload carries no clock value of any kind.
    payload = json.loads(first)
    assert set(payload) == {
        "instrument_digest",
        "completed",
        "freeze_tag",
        "frozen_commit",
        "resets",
        "resume_stage",
        "schema_version",
    }
    assert not any(
        isinstance(value, str) and value[:2] == "20" and "T" in value for value in payload.values()
    )


def test_the_ladder_is_climbed_in_order_and_records_the_frozen_commit(
    repo: Path, tmp_path: Path
) -> None:
    """A stage cannot be claimed before its predecessor, and the freeze sidecar is written once.

    Order matters because each stage's exit criterion is a precondition for the next (plan §6): a
    ladder that accepts `p3` first has recorded a conclusion about a ladder nobody climbed, which is
    the v1 gate pilot's failure in a different costume.
    """
    state_dir = tmp_path / "state"
    campaign_dir = tmp_path / "runs" / "CAMP-20260926-pilot-p2"
    assert load_ladder_state(state_dir) is None
    assert next_stage(None) == LADDER_STAGES[0]

    with pytest.raises(LadderError, match="a new ladder starts at"):
        record_stage(state_dir, "p1b", freeze_tag="v1.0", repo_root=repo, campaign_dir=campaign_dir)
    with pytest.raises(LadderError, match="is not a pilot-ladder stage"):
        record_stage(state_dir, "p9", freeze_tag="v1.0", repo_root=repo, campaign_dir=campaign_dir)
    assert not (state_dir / LADDER_STATE_FILE).exists()

    state = _climb(repo, state_dir, campaign_dir)
    assert state.completed == LADDER_STAGES
    assert state.freeze_tag == "v1.0"
    assert state.frozen_commit == read_frozen_commit(campaign_dir)
    assert (campaign_dir / FROZEN_COMMIT_SIDECAR).is_file()
    assert next_stage(state) == LADDER_STAGES[-1]


def test_each_coverage_stage_generates_the_protocols_run_count() -> None:
    """P2 and P3 are checked against the mirrored protocol constant, not against a literal here.

    This is where a change to the pilot grid becomes a test failure instead of a coverage pass that
    quietly came back one run short (M10 principle P5: the deterministic parts are proven offline
    for every cell).
    """
    for stage in ("p2", "p3"):
        order = coverage_order(stage)
        assert order
        assert len({cell.condition for cell in order}) == 6
        assert len({cell.injection_condition for cell in order}) == 5
    with pytest.raises(LadderError, match="is not a coverage stage"):
        coverage_order("p1a")


def test_gate_decision_writes_a_document_a_freeze_checklist_can_read(
    repo: Path, tmp_path: Path
) -> None:
    """`decide` reads a fidelity.json, evaluates the gate, and writes gate_decision.json (plan §7).

    Driven through the CLI as well as the function, because ``gate_decision.json`` is what the
    ``v2.0`` freeze checklist is gated on and an operator reaches it only as a subprocess. The exit
    code is asserted too: a NO-GO that returned 0 would let a Makefile target proceed past the gate.
    """
    state_dir = tmp_path / "state"
    campaign_dir = tmp_path / "runs" / "CAMP-20260926-pilot-p3"
    _climb(repo, state_dir, campaign_dir)
    good = _fidelity(tmp_path, [_check("F-RN-01", "T"), _check("F-AN-01", "R", "warn")])

    assert main(["decide", "--state-dir", str(state_dir), "--fidelity", str(good)]) == 0
    recorded = load_gate_decision(state_dir)
    assert recorded is not None
    assert recorded["decision"] == "GO"
    assert recorded["reasons"] == []
    assert recorded["counts"]["T"] == {"pass": 1, "fail": 0, "warn": 0, "skip": 0}
    assert (state_dir / GATE_DECISION_FILE).is_file()
    # Canonical JSON, so a re-run of `decide` on the same inputs rewrites the same bytes.
    first_bytes = (state_dir / GATE_DECISION_FILE).read_bytes()
    assert main(["decide", "--state-dir", str(state_dir), "--fidelity", str(good)]) == 0
    assert (state_dir / GATE_DECISION_FILE).read_bytes() == first_bytes

    bad = _fidelity(tmp_path, [_check("F-RN-01", "T"), _check("F-GD-01", "T", "fail")])
    assert main(["decide", "--state-dir", str(state_dir), "--fidelity", str(bad)]) == 1
    refused = load_gate_decision(state_dir)
    assert refused is not None
    assert refused["decision"] == NO_GO
    assert any("F-GD-01" in reason for reason in refused["reasons"])

    # A missing or malformed fidelity document is an error, not an empty pass list.
    assert (
        main(["decide", "--state-dir", str(state_dir), "--fidelity", str(tmp_path / "nope")]) == 1
    )


def test_gate_decision_refuses_an_incomplete_ladder_and_records_why(
    repo: Path, tmp_path: Path
) -> None:
    """A GO on a ladder that was not climbed is the v1 defect; the file must say so in words.

    The reasons are the deliverable: an unactionable NO-GO is the failure this workstream exists to
    close, so the ids of every non-passing check appear in the document, not only a verdict.
    """
    state_dir = tmp_path / "state"
    campaign_dir = tmp_path / "runs" / "CAMP-20260926-pilot-p2"
    record_stage(state_dir, "p0", freeze_tag="v1.0", repo_root=repo, campaign_dir=campaign_dir)
    checks = _fidelity(tmp_path, [_check("F-RN-01", "T"), _check("F-GD-05", "T", "skip")])

    decision = gate_decision(state_dir, checks, framework_failures=2)
    assert isinstance(decision, GateDecision)
    assert decision.decision == NO_GO
    assert decision.framework_failures == 2
    assert any("F-GD-05" in reason for reason in decision.reasons)
    assert any("ladder is not complete" in reason for reason in decision.reasons)
    assert any("framework-attributable" in reason for reason in decision.reasons)
    assert load_gate_decision(state_dir)["decision"] == NO_GO


def test_read_checks_reads_a_fidelity_document_inside_a_campaign_directory(tmp_path: Path) -> None:
    """A campaign directory carrying its own ``fidelity.json`` is read as that document.

    The gate is reached by pointing it at a directory (``FIDELITY=<campaign> make pilot-gate``), and
    a directory that already carries an aggregate -- a hand-assembled one, or a campaign whose
    bundles were folded by an earlier step -- must be read as-is rather than re-folded. Asserted
    through :func:`read_checks` because that is the one place the two accepted inputs are told
    apart, and a regression here would silently re-evaluate a corpus the operator had already
    aggregated.
    """
    campaign_dir = tmp_path / "runs" / "CAMP-20260926-pilot-p3"
    campaign_dir.mkdir(parents=True)
    document = {
        "schema_version": "fidelity.v1",
        "run_id": "RUN-X",
        "checks": [_check("F-RN-01", "T")],
    }
    (campaign_dir / "fidelity.json").write_text(json.dumps(document), encoding="utf-8")

    assert read_checks(campaign_dir) == [_check("F-RN-01", "T")]


def test_read_checks_aggregates_a_campaign_directory_of_sealed_bundles(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A directory with no root ``fidelity.json`` is folded from its bundles, and the gate uses it.

    This is the path ``FIDELITY=<pilot campaign dir> make pilot-gate`` takes: a pilot campaign
    directory holds one ``fidelity.json`` per bundle and never one at its root, so a gate pointed
    at the directory has to build the corpus-level verdict itself. The fold is
    ``runner.fidelity.campaign_gate_rows`` (tested in ``test_fidelity.py``); what this proves is
    that :func:`read_checks` -- and therefore ``decide`` -- reaches it, and that a directory which
    folds to nothing is refused rather than read as an empty pass list.

    The synthetic report carries one passing class-T row and one non-applicable skip, so the
    assertion covers both halves of the fold's contract: the pass survives, the skip that applied
    nowhere is dropped.
    """
    state_dir = tmp_path / "state"
    campaign_dir = tmp_path / "runs" / "CAMP-20260926-pilot-p3"
    campaign_dir.mkdir(parents=True)
    _climb(repo, state_dir, campaign_dir)

    report = FidelityReport(
        run_id="RUN-1",
        instrument_digest=None,
        results=(
            FidelityResult(id="F-RN-01", klass="T", stage="seal", status="pass", detail=""),
            FidelityResult(id="F-MN-04", klass="T", stage="seal", status="skip", detail="no probe"),
        ),
    )
    monkeypatch.setattr(
        "runner.fidelity.iter_campaign_reports", lambda *args, **kwargs: iter([report])
    )

    rows = read_checks(campaign_dir)
    assert [row["id"] for row in rows] == ["F-RN-01"], "the non-applicable skip is dropped"
    assert rows[0]["klass"] == "T"

    assert main(["decide", "--state-dir", str(state_dir), "--fidelity", str(campaign_dir)]) == 0
    recorded = load_gate_decision(state_dir)
    assert recorded is not None
    assert recorded["decision"] == "GO"

    # A directory whose bundles fold to nothing is refused, not read as an empty pass list: a gate
    # that passed over nothing would read, in a log, exactly like a gate that passed over
    # everything.
    empty = tmp_path / "runs" / "CAMP-20260926-pilot-p0"
    empty.mkdir(parents=True)
    monkeypatch.setattr("runner.fidelity.iter_campaign_reports", lambda *args, **kwargs: iter(()))
    with pytest.raises(LadderError, match="no fidelity results"):
        read_checks(empty)


def test_read_checks_folds_several_campaign_directories(repo: Path, tmp_path: Path) -> None:
    """The gate folds the pilot's several campaign directories into one row per check (SEAM 2).

    The pilot's evidence is spread across campaign ids that CANNOT share a directory: P1a's scripted
    runs and P2's live runs both name ``RUN-<arm>-SCN-SIM-01-INJ-NONE-901``, so merging their
    bundles would silently lose one. So the gate folds ROWS, and the rule is the fidelity package's
    own -- worst status wins -- which is why this asserts the two directions that matter: a pass in
    one campaign does not rescue a fail in another, and a skip that applied nowhere is outranked by
    a pass elsewhere (the fold's rank, not the order the campaigns were named in).

    Driven through the CLI as well, because an operator reaches the gate only as a subprocess and
    the repeated ``--fidelity`` flag is the whole interface to this behaviour.
    """
    state_dir = tmp_path / "state"
    campaign_dir = tmp_path / "runs" / "CAMP-20260926-pilot-p3"
    _climb(repo, state_dir, campaign_dir)

    def written(name: str, checks: list[dict[str, str]]) -> Path:
        path = tmp_path / name
        path.write_text(
            json.dumps({"schema_version": "fidelity.v1", "run_id": "RUN-X", "checks": checks}),
            encoding="utf-8",
        )
        return path

    p1a = written(
        "p1a.json",
        [_check("F-RN-01", "T"), _check("F-AG-03", "T", "skip"), _check("F-SC-01", "T")],
    )
    p2 = written("p2.json", [_check("F-RN-01", "T"), _check("F-AG-03", "T")])

    folded = read_checks([p1a, p2])
    by_id = {row["id"]: row for row in folded}
    assert [row["id"] for row in folded] == ["F-AG-03", "F-RN-01", "F-SC-01"], "sorted by id"
    # F-AG-03 skips in one campaign and passes in the other: the PASS wins, because a skip is an
    # applicability statement and the check did run somewhere.
    assert by_id["F-AG-03"]["status"] == "pass"
    assert by_id["F-RN-01"]["status"] == "pass"

    # A fail anywhere survives the fold -- the direction the whole gate depends on.
    p3 = written("p3.json", [_check("F-RN-01", "T", "fail")])
    assert {row["id"]: row["status"] for row in read_checks([p1a, p2, p3])}["F-RN-01"] == "fail"

    # No source at all is refused, not read as an empty pass list.
    with pytest.raises(LadderError, match="no fidelity source"):
        read_checks([])

    # The CLI accepts the repeated flag, folds it, and reaches GO -- the fold is what the gate
    # evaluates, not merely what a helper returns.
    assert (
        main(
            [
                "decide",
                "--state-dir",
                str(state_dir),
                "--fidelity",
                str(p1a),
                "--fidelity",
                str(p2),
            ]
        )
        == 0
    )
    recorded = load_gate_decision(state_dir)
    assert recorded is not None
    assert recorded["decision"] == "GO"
    assert recorded["counts"]["T"] == {"pass": 3, "fail": 0, "warn": 0, "skip": 0}


def test_a_hand_edited_state_file_is_refused_rather_than_interpreted(tmp_path: Path) -> None:
    """A ladder_state.json with an unknown key is a defect, not a state with defaults.

    Reading it "leniently" is how a ladder ends up claiming stages that were never recorded, which
    is
    the one thing the ladder exists to prevent.
    """
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    (state_dir / LADDER_STATE_FILE).write_text(
        json.dumps(
            {
                "instrument_digest": "d" * 64,
                "completed": ["p0", "p1a", "p1b", "p2", "p3"],
                "freeze_tag": "v2.0",
                "frozen_commit": "c" * 40,
                "resets": 0,
                "resume_stage": None,
                "schema_version": "v1",
                "everything_passed": True,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(LadderError, match="ladder-state shape"):
        load_ladder_state(state_dir)


def test_validate_selects_the_validator_by_kind(tmp_path: Path) -> None:
    """``validate --kind`` applies the named pilot validator (ADR-136, plan §6).

    The four manifests the M10 generator emits have three different shapes -- P1a's six-arm smoke,
    P1b's six-run cost pilot, P2/P3's thirty-cell coverage -- so one validator cannot accept all of
    them. ``cost`` stays the default, so a bare ``validate`` keeps checking a cost-pilot manifest
    exactly as it always did (V16 kept the 3+3 plan; it did not retire it); ``smoke`` and
    ``coverage`` reach their own validators by name.

    Each case is driven through the CLI as well as the function, because an operator reaches this
    only as a subprocess, and the wrong kind is asserted to FAIL: a selector that accepted every
    kind would be a selector that did nothing.
    """
    from runner.generate_pilot_manifests import (
        build_cost_pilot_manifest,
        build_p1a_manifest,
        build_p2_manifest,
    )

    def written(manifest: object, name: str) -> Path:
        path = tmp_path / name
        path.write_text(json.dumps(manifest.to_dict()), encoding="utf-8")  # type: ignore[attr-defined]
        return path

    cases = (
        (build_p1a_manifest(), "smoke-p1a.json", "smoke"),
        (build_cost_pilot_manifest(), "cost-p1b.json", "cost"),
        (build_p2_manifest(), "coverage-p2.json", "coverage"),
    )
    for manifest, name, kind in cases:
        path = written(manifest, name)
        assert main(["validate", "--manifest", str(path), "--kind", kind]) == 0, kind
        wrong = "coverage" if kind != "coverage" else "cost"
        assert main(["validate", "--manifest", str(path), "--kind", wrong]) == 1, (
            f"the {wrong} validator must refuse a {kind} manifest"
        )

    # `cost` is the default, so a bare `validate` on the smoke manifest is refused as it always was.
    smoke = written(build_p1a_manifest(), "smoke-default.json")
    assert main(["validate", "--manifest", str(smoke)]) == 1


def test_generated_pilots_use_only_registered_pilot_seeds() -> None:
    """Every ladder stage must remain disjoint from the campaign seed set (ADR-149)."""
    from runner.generate_pilot_manifests import (
        build_cost_pilot_manifest,
        build_p1a_manifest,
        build_p2_manifest,
        build_p3_manifest,
    )
    from runner.grid import PILOT_SEEDS, SEEDS

    builders = (build_p1a_manifest, build_cost_pilot_manifest, build_p2_manifest, build_p3_manifest)
    for build in builders:
        manifest = build()
        seeds = {run.seed for run in manifest.runs}
        assert seeds <= set(PILOT_SEEDS)
        assert seeds.isdisjoint(SEEDS)
        assert set(manifest.seeds) == seeds
        assert len(manifest.seeds) == len(seeds)
