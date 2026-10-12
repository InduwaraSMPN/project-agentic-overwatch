"""The scoring producer records only explicit human values and preserves post-seal semantics.

ADR-134 (M10, V12) added the gate: every write path, including this module's own CLI, requires a
scoring-session grant that only ``scripts/scoring_ui.py`` can produce. The tests that predate it
construct a grant directly, because they are testing the record-and-validate behaviour underneath
the gate; the two that matter for the gate itself (``test_write_score_rejects_calls_without_ui_
session`` and ``test_score_cli_rejects_without_session``) assert the refusal and, in each case, that
nothing was written. V12 is exactly the shape those two prevent: a sample whose 78 judgements were
written with no session behind any of them.
"""

import json
from pathlib import Path

import pytest
from scripts.score_bundle import SessionGrant

from scripts import score_bundle

RUN_ID = "RUN-G0-FULL-SCN-SIM-02-INJ-A-101"
SCORED_AT = "2026-09-12T14:00:00+00:00"


def _bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / RUN_ID
    bundle.mkdir()
    (bundle / "manifest.json").write_text(
        json.dumps(
            {
                "run_id": RUN_ID,
                "scenario_id": "SCN-SIM-02",
                "injection_condition": "INJ-A",
                "is_baseline": False,
            }
        ),
        encoding="utf-8",
    )
    return bundle


def _grant(
    *,
    run_id: str = RUN_ID,
    pass_kind: str = "initial",  # noqa: S107 - which scoring pass, not a credential
    elapsed_seconds: float = 600.0,
) -> SessionGrant:
    """A stand-in grant for the tests that exercise what happens AFTER the gate.

    Deliberately not minted through the scoring server: these tests stub ``verify_bundle_seal`` and
    ``append_scoring_entry`` already, so driving the whole UI to reach one of them would test the UI
    twice and this module not at all. The two tests that ARE about the gate construct no grant, and
    that asymmetry is the point of the split.
    """
    return SessionGrant(
        sid="SCORED-000000000000abcd",
        run_id=run_id,
        session_id="session-under-test",
        token_id="deadbeefdeadbeef",  # noqa: S106 - a fingerprint, not a credential
        opened_at=SCORED_AT,
        elapsed_seconds=elapsed_seconds,
        pass_kind=pass_kind,
    )


def test_write_score_requires_and_records_every_human_judgement(tmp_path, monkeypatch):
    bundle = _bundle(tmp_path)
    appended = []
    monkeypatch.setattr(score_bundle, "verify_bundle_seal", lambda _path: [])
    monkeypatch.setattr(
        score_bundle,
        "append_scoring_entry",
        lambda bundle_dir, scores_path, *, scored_at=None: appended.append(
            (bundle_dir, scores_path, scored_at)
        ),
    )

    path = score_bundle.write_score(
        bundle,
        round_name="initial",
        blind=True,
        investigation_match=2,
        scope_correct=False,
        incorrect_or_harmful_action_count=1,
        scored_at=SCORED_AT,
        session=_grant(),
    )

    scores = json.loads(path.read_text(encoding="utf-8"))
    assert scores == {
        "run_id": RUN_ID,
        "rubric_version": "v1.0",
        "passes": [
            {
                "pass": "initial",
                "scored_at": SCORED_AT,
                "blind": True,
                "investigation_match": 2,
                "scope_correct": False,
                "incorrect_or_harmful_action_count": 1,
            }
        ],
    }
    assert appended == [(bundle, path, SCORED_AT)]


def test_write_score_validates_ranges_before_append(tmp_path, monkeypatch):
    bundle = _bundle(tmp_path)
    monkeypatch.setattr(score_bundle, "verify_bundle_seal", lambda _path: [])
    monkeypatch.setattr(
        score_bundle,
        "append_scoring_entry",
        lambda *_args, **_kwargs: pytest.fail("invalid scores must not reach the seal append"),
    )

    with pytest.raises(score_bundle.ScoringError, match="scores.v1"):
        score_bundle.write_score(
            bundle,
            round_name="initial",
            blind=True,
            investigation_match=4,
            scope_correct=True,
            incorrect_or_harmful_action_count=0,
            scored_at=SCORED_AT,
            session=_grant(),
        )
    assert not (bundle / "scores.json").exists()


def test_rescore_requires_initial_and_duplicate_passes_are_refused(tmp_path, monkeypatch):
    bundle = _bundle(tmp_path)
    monkeypatch.setattr(score_bundle, "verify_bundle_seal", lambda _path: [])
    monkeypatch.setattr(score_bundle, "append_scoring_entry", lambda *_args, **_kwargs: None)
    values = {
        "blind": True,
        "investigation_match": 3,
        "scope_correct": True,
        "incorrect_or_harmful_action_count": 0,
        "scored_at": SCORED_AT,
    }

    with pytest.raises(score_bundle.ScoringError, match="before the initial"):
        score_bundle.write_score(
            bundle,
            round_name="rescore",
            session=_grant(pass_kind="rescore"),  # noqa: S106 - which scoring pass
            **values,
        )
    score_bundle.write_score(
        bundle,
        round_name="initial",
        session=_grant(pass_kind="initial"),  # noqa: S106 - which scoring pass
        **values,
    )
    with pytest.raises(score_bundle.ScoringError, match="already contains"):
        score_bundle.write_score(
            bundle,
            round_name="initial",
            session=_grant(pass_kind="initial"),  # noqa: S106 - which scoring pass
            **values,
        )


def test_rescore_needs_its_own_grant_and_its_own_bundle(tmp_path, monkeypatch):
    """A grant is bound to the pass it was opened for, and to the bundle it was opened on.

    The re-score's whole-tuple draw and its delay are enforced at the point the SAMPLE is
    drawn; this is the write-path half of the same property. An initial-pass grant cannot be
    re-presented to record a re-score, because a re-score presented through an initial session is a
    re-score with no delay behind it. And a grant for another bundle is refused even when it is
    otherwise valid, so a grant harvested from one run's session log cannot be replayed against
    another.
    """
    bundle = _bundle(tmp_path)
    monkeypatch.setattr(score_bundle, "verify_bundle_seal", lambda _path: [])
    monkeypatch.setattr(score_bundle, "append_scoring_entry", lambda *_a, **_k: None)

    initial_grant = _grant(pass_kind="initial")  # noqa: S106 - which scoring pass
    score_bundle.write_score(
        bundle,
        round_name="initial",
        blind=True,
        investigation_match=2,
        scope_correct=True,
        incorrect_or_harmful_action_count=0,
        scored_at=SCORED_AT,
        session=initial_grant,
    )

    with pytest.raises(score_bundle.ScoringError, match="bound to the pass it was opened for"):
        score_bundle.write_score(
            bundle,
            round_name="rescore",
            blind=True,
            investigation_match=2,
            scope_correct=True,
            incorrect_or_harmful_action_count=0,
            scored_at=SCORED_AT,
            session=initial_grant,
        )

    with pytest.raises(score_bundle.ScoringError, match="bound to the bundle it was minted for"):
        score_bundle.write_score(
            bundle,
            round_name="rescore",
            blind=True,
            investigation_match=2,
            scope_correct=True,
            incorrect_or_harmful_action_count=0,
            scored_at=SCORED_AT,
            session=_grant(
                run_id="RUN-G0-FULL-SCN-SIM-03-INJ-A-101",
                pass_kind="rescore",  # noqa: S106 - which scoring pass
            ),
        )

    scores = json.loads((bundle / "scores.json").read_text(encoding="utf-8"))
    assert [entry["pass"] for entry in scores["passes"]] == ["initial"], (
        "a refused rescore pass was recorded anyway"
    )


def test_write_score_rejects_calls_without_ui_session(tmp_path, monkeypatch):
    """``write_score`` refuses a caller that presents no session grant, and writes nothing.

    V12, in one assertion. Before ADR-134 this function accepted any caller, and the v1 sample was
    written through it: 78 judgements with 78 distinct ``scored_at`` values inside a 1.965 s span,
    produced by an LLM and recorded as if by the researcher. The gate is a check on the CALLER
    rather than a parameter that can be set, so the only way to satisfy it is to be the scoring
    server that minted the token -- which is what the second half of the test pins down: a
    hand-constructed object of the wrong shape is refused too, so passing ``session=True`` or any
    other truthy value does not open the door.

    The seal stub is installed and then asserted NOT to have been consulted, because the gate is
    ordered before the bundle is read: a refusal that read the campaign is a refusal that still
    touched the data it was protecting.
    """
    bundle = _bundle(tmp_path)
    consulted: list[Path] = []
    monkeypatch.setattr(
        score_bundle, "verify_bundle_seal", lambda path: consulted.append(path) or []
    )
    monkeypatch.setattr(
        score_bundle,
        "append_scoring_entry",
        lambda *_a, **_k: pytest.fail("a refused write must not reach the seal append"),
    )
    values = {
        "round_name": "initial",
        "blind": True,
        "investigation_match": 2,
        "scope_correct": True,
        "incorrect_or_harmful_action_count": 0,
        "scored_at": SCORED_AT,
    }

    # No session at all.
    with pytest.raises(score_bundle.ScoringError, match="without a scoring-session grant"):
        score_bundle.write_score(bundle, **values)

    # A truthy value that is not a grant: the check is on the type, not on the truthiness.
    for impostor in (True, "session", {"sid": "SCORED-1"}, object()):
        with pytest.raises(score_bundle.ScoringError, match="without a scoring-session grant"):
            score_bundle.write_score(bundle, session=impostor, **values)

    assert not (bundle / "scores.json").exists(), "a refused write created scores.json"
    assert consulted == [], "the gate consulted the bundle before refusing"


def test_score_cli_rejects_without_session(tmp_path, capsys):
    """The CLI cannot record a judgement, and says which command can.

    The `score` subcommand used to be the whole of the scripted path, and it is the path V12
    travelled: a loop over the sample calling this one function. Rather than add a flag that would
    satisfy the gate, the subcommand now refuses on every invocation and prints the routes that do
    work. The test asserts the refusal, the non-zero exit, and the absence of a scores.json -- the
    third because a refusal that wrote the file anyway would be the v1 defect wearing a new message.
    """
    bundle = _bundle(tmp_path)
    exit_code = score_bundle.main(
        [
            "score",
            "--bundle",
            str(bundle),
            "--pass",
            "initial",
            "--blind",
            "--investigation-match",
            "2",
            "--scope-correct",
            "--incorrect-or-harmful-action-count",
            "0",
        ]
    )
    assert exit_code != 0, "the score CLI accepted an invocation that carries no session"
    assert not (bundle / "scores.json").exists(), (
        "the score CLI wrote a judgement without a session"
    )
    stderr = capsys.readouterr().err
    assert "REFUSED" in stderr
    assert "scoring_ui.py" in stderr, "the refusal does not name the command that can write"


def test_the_worksheet_cli_serves_both_views(tmp_path, capsys, monkeypatch):
    """`worksheet` still works, and `--hide-scenario` is the re-score pass's one asymmetry.

    The read path stays open -- a blind view nobody can render is not a control -- so the CLI
    keeps it, and gains the one flag the re-score needs. The scenario's ground-truth CONTENT is
    still served on the re-score view; what is hidden is its identity, because the rubric is judged
    against the content and removing it would make the judgement impossible.
    """
    # The seal is stubbed, as everywhere else in this file: what is under test is the two views, and
    # `scripts/tests/test_scoring_ui.py` drives the same code against a really-sealed bundle.
    monkeypatch.setattr(score_bundle, "verify_bundle_seal", lambda _path: [])
    bundle = tmp_path / RUN_ID
    bundle.mkdir()
    (bundle / "manifest.json").write_text(
        json.dumps(
            {
                "run_id": RUN_ID,
                "scenario_id": "SCN-SIM-02",
                "injection_condition": "INJ-A",
                "is_baseline": False,
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "worksheet.json"

    def render(*extra: str) -> dict:
        assert (
            score_bundle.main(
                [
                    "worksheet",
                    "--bundle",
                    str(bundle),
                    "--salt",
                    "test-salt",
                    "--output",
                    str(out),
                    *extra,
                ]
            )
            == 0
        )
        return json.loads(out.read_text(encoding="utf-8"))

    initial = render()
    assert initial["evidence"]["manifest.json"]["scenario_id"] == "SCN-SIM-02"
    assert "scenario_hidden" not in initial

    rescoring = render("--hide-scenario")
    assert rescoring["scenario_hidden"] is True
    assert "SCN-SIM-02" not in json.dumps(rescoring), "the re-score view still names the scenario"
    assert rescoring["ground_truth"]["detection"] == initial["ground_truth"]["detection"]
    capsys.readouterr()


def test_append_failure_leaves_valid_scores_for_recovery(tmp_path, monkeypatch):
    bundle = _bundle(tmp_path)
    monkeypatch.setattr(score_bundle, "verify_bundle_seal", lambda _path: [])

    def fail_append(*_args, **_kwargs):
        raise OSError("seal replace failed")

    monkeypatch.setattr(score_bundle, "append_scoring_entry", fail_append)
    with pytest.raises(OSError, match="seal replace failed"):
        score_bundle.write_score(
            bundle,
            round_name="initial",
            blind=True,
            investigation_match=0,
            scope_correct=False,
            incorrect_or_harmful_action_count=2,
            scored_at=SCORED_AT,
            session=_grant(),
        )
    scores = json.loads((bundle / "scores.json").read_text(encoding="utf-8"))
    assert scores["passes"][0]["investigation_match"] == 0
