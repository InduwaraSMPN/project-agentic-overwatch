"""Small pytest smoke tests for scripts/scoring_ui.py.

Deliberately not under a component's own tests/ directory (scripts/ has none yet, and this is
the first script here with tests of its own) -- see scripts/tests/__init__.py for why this
directory now exists. Bare ``assert`` is avoided throughout (raising ``AssertionError`` directly
instead) so this file needs no S101 per-file-ignore entry in pyproject.toml, matching the
project's rule that per-file-ignores are added one named directory at a time, deliberately, not
widened to cover a new directory as a side effect of adding a test.

THE FIXTURE IS A SEALED BUNDLE THIS REPOSITORY BUILDS, NOT A v1 BUNDLE COPIED OUT OF runs/
    The v1 corpus is real evidence and is read-only, but a v1 bundle no longer passes
    ``verify_bundle_seal``: the ground truth has been revised since the campaign sealed
    (ADR-088, ADR-127 and later), so every v1 bundle's ``assertions.json`` carries a
    ``groundtruth_sha256`` that no longer pins the live ground-truth bytes. Scoring it is
    therefore impossible by construction, which is correct -- a re-score against changed ground
    truth is what ADR-088's separate tool is for. The fixture below is
    ``runner.run.run_cell(..., offline=True)``, the same sealable shape ``make run --offline``
    produces, in ``tmp_path`` and never against anything under ``runs/``.

THE CLOCK IS INJECTED, AND THAT IS THE POINT
    The open-to-submit floor is ``scoring_min_elapsed_seconds`` from
    ``docs/protocols/evaluation-protocol.md`` section 4, mirrored in ``scripts/m10_constants.py``.
    A test that had to sleep for it would either be slow or would have to weaken the constant it
    exists to test, so every app in this file is built with a ``clock`` the test advances by hand.
    The constant is never restated here: the tests assert a refusal at elapsed == 0 and a grant at
    elapsed == the mirrored value, read from the module.
"""

from __future__ import annotations

import json
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.m10_constants import SCORING_MIN_ELAPSED_SECONDS  # noqa: E402
from scripts.tests._fixtures import sealed_run  # noqa: E402

from scripts import scoring_ui  # noqa: E402

CONDITION = "G0-FULL"
SCENARIO = "SCN-SIM-01"
INJECTION = "INJ-A"
SEED = 101
RUN_ID = f"RUN-{CONDITION}-{SCENARIO}-{INJECTION}-{SEED}"

# A test-local secret. Nothing in this repository ships a literal secret (AGENTS.md iron rule 4) and
# nothing here is a default: ScoringApp takes this explicitly, and with nothing -- neither argument
# nor environment -- it refuses to start. The control would be vacuous if the repository carried a
# committed one.
_TEST_SECRET = "test-only-scoring-secret-not-a-real-credential"  # noqa: S105 - not a credential


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


class FakeClock:
    """A hand-advanced UTC clock, so the protocol's elapsed floor can be tested without sleeping."""

    def __init__(self, start: datetime | None = None) -> None:
        self.now = start or datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now = self.now + timedelta(seconds=seconds)


@pytest.fixture
def campaign(tmp_path: Path) -> tuple[Path, Path, str]:
    """A one-bundle campaign directory: a freshly sealed offline run plus its scoring sample.

    The bundle and its seal come from `scripts/tests/_fixtures.py`, which seals through
    `runner.bundle.seal_bundle` -- the PRODUCTION sealer, not a hand-written `seal.json`. That
    matters because `scripts/scoring_ui.py` calls `verify_bundle_seal` before it will show a
    bundle or record a score, so a fixture whose seal this repository did not produce would be
    testing a path no real bundle can take.
    """
    bundle_dir = sealed_run(tmp_path, CONDITION, SCENARIO, INJECTION, SEED)
    campaign_dir = bundle_dir.parent
    sample_path = campaign_dir / "_scoring" / "sample.json"
    sample_path.parent.mkdir(parents=True, exist_ok=True)
    sample_path.write_text(json.dumps([RUN_ID]), encoding="utf-8")
    return campaign_dir, sample_path, RUN_ID


def _app(
    campaign_dir: Path, sample_path: Path, clock: FakeClock, **kwargs
) -> scoring_ui.ScoringApp:
    return scoring_ui.build_app(
        campaign_dir, sample_path, salt=None, session_secret=_TEST_SECRET, clock=clock, **kwargs
    )


# ------------------------------------------------------------------------------------------------
# The pre-M10 behaviour that must keep working
# ------------------------------------------------------------------------------------------------


def test_load_sample_missing_file_raises_clear_error(tmp_path: Path) -> None:
    missing = tmp_path / "sample.json"
    with pytest.raises(scoring_ui.ScoringUIError, match="sample file not found"):
        scoring_ui.load_sample(missing)


def test_load_sample_accepts_plain_list_and_run_ids_object(tmp_path: Path) -> None:
    plain = tmp_path / "a.json"
    plain.write_text(json.dumps(["RUN-A", "RUN-B"]), encoding="utf-8")
    _require(scoring_ui.load_sample(plain) == ["RUN-A", "RUN-B"], "plain list form failed")

    wrapped = tmp_path / "b.json"
    wrapped.write_text(json.dumps({"run_ids": ["RUN-C"]}), encoding="utf-8")
    _require(scoring_ui.load_sample(wrapped) == ["RUN-C"], "run_ids object form failed")


def test_load_or_create_salt_is_generated_once_and_reused(tmp_path: Path) -> None:
    scoring_dir = tmp_path / "_scoring"
    salt1 = scoring_ui.load_or_create_salt(scoring_dir, None)
    salt2 = scoring_ui.load_or_create_salt(scoring_dir, None)
    _require(salt1 == salt2, "salt was not reused across calls")
    _require((scoring_dir / "salt.txt").is_file(), "salt.txt was not written")


def test_load_or_create_salt_rejects_conflicting_explicit_salt(tmp_path: Path) -> None:
    scoring_dir = tmp_path / "_scoring"
    scoring_ui.load_or_create_salt(scoring_dir, "first-salt")
    with pytest.raises(scoring_ui.ScoringUIError, match="does not match"):
        scoring_ui.load_or_create_salt(scoring_dir, "different-salt")


def test_summarize_worksheet_joins_decision_and_execution_by_seq() -> None:
    worksheet = {
        "scoring_id": "SCORED-abc",
        "rubric_version": "v1.0",
        "ground_truth": {"detection": {"first_signal_label_id": "DET-01"}},
        "evidence": {
            "guardian_audit.jsonl": [
                {"record_type": "run-start"},
                {
                    "record_type": "decision",
                    "seq": 1,
                    "request_id": "SCORED-abc-containment-001",
                    "iss": "supervisor-containment",
                    "decision": "permit",
                    "policy_rule_id": "guardian:permit:x",
                    "reason_code": "permit.rule-allow",
                    "action": {
                        "resource": "pods",
                        "verb": "delete",
                        "namespace": "boutique",
                        "name": "adservice-1",
                        "params": {},
                        "justification": "contain",
                    },
                },
                {"record_type": "execution", "decision_seq": 1, "execution_status": "succeeded"},
            ],
            "messages.jsonl": [
                {
                    "phase": "containment",
                    "role_id": "supervisor-containment",
                    "attempt_outcomes": [
                        {
                            "tool_calls": [
                                {"name": "issue_capability_token", "arguments": '{"scope":"x"}'}
                            ]
                        }
                    ],
                }
            ],
            "results.json": [
                {
                    "phase": "verified-recovery",
                    "role_id": "orchestrator",
                    "outcome": "resolved",
                    "summary": "done",
                    "tool_calls_spent": 1,
                    "turns_spent": 1,
                }
            ],
        },
    }
    summary = scoring_ui.summarize_worksheet(worksheet)
    _require(len(summary["actions"]) == 1, "expected exactly one joined action row")
    action = summary["actions"][0]
    _require(action["phase"] == "containment", f"phase parse failed: {action['phase']!r}")
    _require(action["decision"] == "permit", "decision field missing")
    _require(action["execution_status"] == "succeeded", "execution join failed")
    _require(len(summary["token_issuances"]) == 1, "issue_capability_token call not captured")
    _require(summary["final_report"]["outcome"] == "resolved", "final report selection failed")


# ------------------------------------------------------------------------------------------------
# ADR-134's provenance control: the session token and the minimum open-to-submit interval
# ------------------------------------------------------------------------------------------------


def test_app_refuses_to_start_without_a_session_secret(
    campaign, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No secret from the argument and none from the environment is a refusal, not a default.

    This is the assertion that keeps the control from being theatre: if the tool ever grew a
    fallback, this test would fail, and with it the claim that a token means "the scoring server
    minted this".
    """
    campaign_dir, sample_path, _ = campaign
    monkeypatch.delenv(scoring_ui.SESSION_SECRET_ENV, raising=False)
    with pytest.raises(scoring_ui.ScoringUIError, match="no scoring-session secret"):
        scoring_ui.build_app(campaign_dir, sample_path, salt=None)


def test_open_mints_a_token_bound_to_that_bundle_and_that_open(campaign) -> None:
    """A token belongs to one bundle and to one open-to-submit interval, and to nothing else.

    Three properties, in the order they matter. The token is bound to its scoring id, so it does not
    travel. Re-opening keeps the ORIGINAL open instant, so the elapsed floor cannot be restarted by
    re-opening in a loop -- which is the whole reason ``open_bundle`` is idempotent while a
    session is open. And a submit closes the session, so the next open mints a different token: one
    token per interval, not one per campaign.
    """
    campaign_dir, sample_path, _ = campaign
    clock = FakeClock()
    app = _app(campaign_dir, sample_path, clock)
    sid = next(iter(app.index))

    first = app.open_bundle(sid)
    _require(bool(first["session_token"]), "the open minted no token")
    _require(first["min_elapsed_seconds"] == SCORING_MIN_ELAPSED_SECONDS, "floor not reported")

    second = app.open_bundle(sid)
    _require(second["opened_at"] == first["opened_at"], "re-opening restarted the open instant")
    _require(
        second["session_token"] == first["session_token"],
        "re-opening minted a second token for one still-open interval",
    )

    # A token signed for a DIFFERENT scoring id does not verify against this one. The app holds a
    # single bundle in this fixture, so the binding is asserted through the signer rather than
    # through a second submission -- which is where the property actually lives.
    other_sid = "SCORED-0000000000000000"
    _require(
        app._sign(other_sid, first["session_id"], first["opened_at"]) != first["session_token"],
        "a token verified against a scoring id it was not minted for",
    )

    # After a successful submit the session is closed, and the next open is a new session.
    clock.advance(SCORING_MIN_ELAPSED_SECONDS)
    app.submit_score(
        sid,
        investigation_match=1,
        scope_correct=True,
        incorrect_or_harmful_action_count=0,
        override=True,
        session_token=first["session_token"],
    )
    third = app.open_bundle(sid)
    _require(
        third["session_token"] != first["session_token"],
        "the token survived its session, so it is not single-use per open-to-submit interval",
    )
    _require(
        third["opened_at"] != first["opened_at"], "the re-opened session did not restart the clock"
    )


def test_submit_before_minimum_elapsed_is_rejected(campaign) -> None:
    """The protocol's open-to-submit floor refuses a judgement, and writes nothing.

    Before ADR-134 this submit succeeded: the app held no notion of an open, so a caller could
    score the instant it had read a run. The floor is the control against that, and the test
    asserts both halves of a refusal -- the exception AND the absence of a scores.json -- because a
    control that raised after writing would be worse than no control.
    """
    campaign_dir, sample_path, run_id = campaign
    clock = FakeClock()
    app = _app(campaign_dir, sample_path, clock)
    sid = next(iter(app.index))

    # No token at all: refused, with the message that names the control.
    with pytest.raises(scoring_ui.ScoringUIError, match="no session token presented"):
        app.submit_score(
            sid,
            investigation_match=2,
            scope_correct=True,
            incorrect_or_harmful_action_count=0,
            override=False,
        )
    _require(
        not (campaign_dir / run_id / "scores.json").exists(),
        "a submission with no token wrote scores.json",
    )

    # A valid token, submitted immediately after the open: still refused, on the floor.
    opened = app.open_bundle(sid)
    with pytest.raises(
        scoring_ui.ScoringUIError, match="minimum before a judgement may be submitted"
    ):
        app.submit_score(
            sid,
            investigation_match=2,
            scope_correct=True,
            incorrect_or_harmful_action_count=0,
            override=False,
            session_token=opened["session_token"],
        )
    _require(
        not (campaign_dir / run_id / "scores.json").exists(),
        "a submission inside the minimum-elapsed window wrote scores.json",
    )

    # The refusal left the session OPEN, so the researcher can keep reading and submit when ready
    # rather than having to reload the run. A control that closed the session on refusal would be an
    # obstacle rather than a floor.
    state = json.loads((campaign_dir / "_scoring" / "ui_state.json").read_text(encoding="utf-8"))
    _require(sid in state["opened_at"], "the refused submit closed the open session")

    # One second before the floor is still refused; exactly at the floor it is accepted.
    clock.advance(SCORING_MIN_ELAPSED_SECONDS - 1)
    with pytest.raises(
        scoring_ui.ScoringUIError, match="minimum before a judgement may be submitted"
    ):
        app.submit_score(
            sid,
            investigation_match=2,
            scope_correct=True,
            incorrect_or_harmful_action_count=0,
            override=False,
            session_token=opened["session_token"],
        )
    clock.advance(1)
    result = app.submit_score(
        sid,
        investigation_match=2,
        scope_correct=True,
        incorrect_or_harmful_action_count=0,
        override=False,
        session_token=opened["session_token"],
    )
    _require(result["ok"] is True, "a submission at the floor was not accepted")
    scores = json.loads((campaign_dir / run_id / "scores.json").read_text(encoding="utf-8"))
    _require(len(scores["passes"]) == 1, "the accepted submission did not record exactly one pass")
    _require(
        scores["passes"][0]["pass"] == "initial",  # noqa: S105 - a pass NAME, not a credential
        "the initial pass was not recorded as 'initial'",
    )


def test_a_token_from_another_bundle_is_refused(campaign) -> None:
    """The gate is per-bundle, not per-server: a harvested token does not travel.

    Two refusals, because there are two ways to present the wrong token and each names a different
    mistake. A token presented for a bundle that was never opened fails as an absent session. A
    token minted for a DIFFERENT scoring id, presented for a bundle that IS open, fails the MAC
    comparison -- which is the property that makes the token worth having.
    """
    campaign_dir, sample_path, _ = campaign
    clock = FakeClock()
    app = _app(campaign_dir, sample_path, clock)
    sid = next(iter(app.index))
    opened = app.open_bundle(sid)
    clock.advance(SCORING_MIN_ELAPSED_SECONDS)

    # Never opened under this scoring id: refused as an absent session.
    with pytest.raises(scoring_ui.ScoringUIError, match="no open session for this bundle"):
        app.submit_score(
            "SCORED-1111111111111111",
            investigation_match=1,
            scope_correct=True,
            incorrect_or_harmful_action_count=0,
            override=False,
            session_token=opened["session_token"],
        )

    # Open, but with a token signed for a different scoring id: refused on the MAC comparison.
    foreign = app._sign("SCORED-1111111111111111", opened["session_id"], opened["opened_at"])
    with pytest.raises(scoring_ui.ScoringUIError, match="not valid for this bundle"):
        app.submit_score(
            sid,
            investigation_match=1,
            scope_correct=True,
            incorrect_or_harmful_action_count=0,
            override=False,
            session_token=foreign,
        )

    # The refusal log records both, so the provenance document can see that an attempt was made.
    refusals = [event for event in app.session_log_events() if event["event"] == "refuse"]
    _require(len(refusals) == 2, f"expected two recorded refusals, got {len(refusals)}")


def test_override_branch_requires_session(campaign) -> None:
    """The override branch -- the one write path that does not go through write_score -- is gated.

    This is the row that had no second check to pass. The override rewrites scores.json in place
    because ``write_score`` refuses a second ``initial`` pass by design, so before ADR-134 an
    override was a write with no control on it at all, and an override is exactly what a bulk writer
    wants. The test drives the branch with an EXISTING initial score in place, so it fails for the
    reason that matters: the session is demanded before the rewrite happens.
    """
    campaign_dir, sample_path, run_id = campaign
    clock = FakeClock()
    app = _app(campaign_dir, sample_path, clock)
    sid = next(iter(app.index))
    bundle_dir = campaign_dir / run_id

    # A first, properly gated score, so the second submit takes the OVERRIDE branch.
    opened = app.open_bundle(sid)
    clock.advance(SCORING_MIN_ELAPSED_SECONDS)
    app.submit_score(
        sid,
        investigation_match=1,
        scope_correct=True,
        incorrect_or_harmful_action_count=0,
        override=False,
        session_token=opened["session_token"],
    )
    before = json.loads((bundle_dir / "scores.json").read_text(encoding="utf-8"))
    _require(len(before["passes"]) == 1, "the first score was not recorded")

    # No token: the override is refused and the recorded judgement is untouched.
    with pytest.raises(scoring_ui.ScoringUIError, match="no session token presented"):
        app.submit_score(
            sid,
            investigation_match=3,
            scope_correct=False,
            incorrect_or_harmful_action_count=2,
            override=True,
        )
    unchanged = json.loads((bundle_dir / "scores.json").read_text(encoding="utf-8"))
    _require(unchanged == before, "a session-less override rewrote scores.json")

    # A token, but inside the floor: also refused, and again with nothing written.
    second_open = app.open_bundle(sid)
    with pytest.raises(
        scoring_ui.ScoringUIError, match="minimum before a judgement may be submitted"
    ):
        app.submit_score(
            sid,
            investigation_match=3,
            scope_correct=False,
            incorrect_or_harmful_action_count=2,
            override=True,
            session_token=second_open["session_token"],
        )
    unchanged = json.loads((bundle_dir / "scores.json").read_text(encoding="utf-8"))
    _require(unchanged == before, "an override inside the floor rewrote scores.json")

    # Gated properly, the override is accepted and replaces the pass rather than appending one.
    clock.advance(SCORING_MIN_ELAPSED_SECONDS)
    result = app.submit_score(
        sid,
        investigation_match=3,
        scope_correct=False,
        incorrect_or_harmful_action_count=2,
        override=True,
        session_token=second_open["session_token"],
    )
    _require(result["overridden"] is True, "the gated override did not report an override")
    after = json.loads((bundle_dir / "scores.json").read_text(encoding="utf-8"))
    _require(len(after["passes"]) == 1, f"the override appended a pass: {after['passes']}")
    _require(after["passes"][0]["investigation_match"] == 3, "the override did not take effect")


def test_the_session_log_records_opens_and_submits_without_the_token(campaign) -> None:
    """The provenance evidence is append-only, and carries no replayable credential."""
    campaign_dir, sample_path, _ = campaign
    clock = FakeClock()
    app = _app(campaign_dir, sample_path, clock)
    sid = next(iter(app.index))
    opened = app.open_bundle(sid)
    clock.advance(SCORING_MIN_ELAPSED_SECONDS)
    app.submit_score(
        sid,
        investigation_match=2,
        scope_correct=False,
        incorrect_or_harmful_action_count=1,
        override=False,
        session_token=opened["session_token"],
    )

    events = app.session_log_events()
    kinds = [event["event"] for event in events]
    _require(kinds == ["open", "submit"], f"unexpected session log: {kinds}")
    submit = events[-1]
    _require(submit["scoring_id"] == sid, "the submit event does not name the scoring id")
    _require(
        submit["token_id"] == scoring_ui.token_fingerprint(opened["session_token"]),
        "the submit event does not carry the token's fingerprint",
    )
    _require(
        opened["session_token"] not in json.dumps(events),
        "the session log leaked the token itself, which would make it a replayable credential",
    )
    _require(_TEST_SECRET not in json.dumps(events), "the session log leaked the signing secret")


def test_the_rescore_view_hides_the_scenario_and_the_initial_view_does_not(campaign) -> None:
    """ADR-134's second asymmetry: the re-score pass hides the scenario as well as the arm.

    The arm is hidden by ``scripts/blind_view.py`` in both passes. What the re-score adds is that
    the SCENARIO's identity is not available either, so a re-score cannot be reconstructed from
    memory ("the CVE scenario, which I scored last week"). The scenario's ground-truth CONTENT
    still reaches the scorer, because the rubric is judged against it -- so the assertion is that
    the scenario ID is gone and the detection labels are not.
    """
    campaign_dir, sample_path, _ = campaign
    clock = FakeClock()
    initial = _app(campaign_dir, sample_path, clock)
    sid = next(iter(initial.index))
    initial_view = initial.worksheet(sid)
    _require(
        initial_view["evidence"]["manifest.json"].get("scenario_id") == SCENARIO,
        "the initial view no longer carries the scenario, which ADR-134 does not ask it to hide",
    )

    rescoring = _app(
        campaign_dir,
        sample_path,
        clock,
        pass_kind="rescore",  # noqa: S106 - a pass NAME
    )
    rescore_view = rescoring.worksheet(sid)
    _require(rescore_view.get("scenario_hidden") is True, "the re-score view did not say it hid it")
    _require(
        SCENARIO not in json.dumps(rescore_view),
        "the re-score view still names the scenario somewhere",
    )
    _require(
        rescore_view["ground_truth"]["detection"] == initial_view["ground_truth"]["detection"],
        "the re-score view dropped the ground truth the rubric is judged against",
    )
    _require(
        rescoring.hide_scenario is True and initial.hide_scenario is False,
        "the two passes are not distinguished by what they hide",
    )


# ------------------------------------------------------------------------------------------------
# The HTTP layer
# ------------------------------------------------------------------------------------------------


def _require_http_url(url: str) -> None:
    # Test client only ever talks to the loopback server this file just started; validated before
    # every urlopen call the same way infra/probes/slo_probe.py and infra/locust/driver.py do
    # (ADR-026), so the noqa at each call site has somewhere to point.
    if urllib.parse.urlsplit(url).scheme not in {"http", "https"}:
        raise ValueError("test client only speaks http(s)")


def _get(url: str) -> tuple[int, str]:
    _require_http_url(url)
    with urllib.request.urlopen(url, timeout=10) as resp:  # noqa: S310 - scheme validated above
        return resp.status, resp.read().decode("utf-8")


def _post(url: str, body: dict) -> tuple[int, dict]:
    _require_http_url(url)
    data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - scheme validated above
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as resp:  # noqa: S310 - validated above
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))


def test_server_scores_a_run_and_refuses_double_scoring(campaign) -> None:
    """The end-to-end path, over HTTP, with the session token the open endpoint mints.

    The double-score refusal is the pre-M10 assertion and still holds. What is new is that the first
    submission needs the token the open returned, which is why the test opens before it submits --
    and that the second submission, now with a fresh token, is refused on the double score rather
    than on the session.
    """
    campaign_dir, sample_path, run_id = campaign
    clock = FakeClock()
    app = _app(campaign_dir, sample_path, clock)
    sid = next(iter(app.index))

    server = scoring_ui.make_server(app, "127.0.0.1", 0)
    host, port = server.server_address[:2]
    base = f"http://{host}:{port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)

    try:
        status, body = _get(base + "/")
        _require(status == 200 and "<html" in body.lower(), "index page did not render")

        status, body = _get(base + f"/api/run/{sid}")
        _require(run_id not in body, "raw run_id leaked into the API response")
        _require("G0-FULL" not in body, "arm token leaked into the API response")

        # The open endpoint is what mints the token; the browser cannot have one before this call.
        status, opened = _post(base + f"/api/run/{sid}/open", {})
        _require(status == 200 and bool(opened.get("session_token")), "the open minted no token")

        # Submitting inside the floor is refused, over HTTP, with the control's own message.
        status, refused = _post(
            base + f"/api/run/{sid}/score",
            {
                "investigation_match": 1,
                "scope_correct": True,
                "incorrect_or_harmful_action_count": 0,
                "session_token": opened["session_token"],
            },
        )
        _require(status == 409, f"a too-early submission was not refused: {refused}")

        clock.advance(SCORING_MIN_ELAPSED_SECONDS)
        status, result = _post(
            base + f"/api/run/{sid}/score",
            {
                "investigation_match": 1,
                "scope_correct": True,
                "incorrect_or_harmful_action_count": 0,
                "session_token": opened["session_token"],
            },
        )
        _require(status == 200, f"first score submission failed: {result}")

        # A second submission needs a fresh session, so it is opened again before being refused --
        # which proves the refusal is about the double score and not about a spent token.
        _post(base + f"/api/run/{sid}/open", {})
        status, result = _post(
            base + f"/api/run/{sid}/score",
            {
                "investigation_match": 2,
                "scope_correct": False,
                "incorrect_or_harmful_action_count": 1,
                "session_token": opened["session_token"],
            },
        )
        _require(status == 409, "double score without override was not refused")
    finally:
        server.shutdown()
        server.server_close()

    scores = json.loads((campaign_dir / run_id / "scores.json").read_text(encoding="utf-8"))
    _require(scores["run_id"] == run_id, "scores.json run_id mismatch")
    _require(len(scores["passes"]) == 1, "double-score leaked a second pass despite the refusal")
