r"""The provenance generator must flag the v1 shape, and pass a compliant one.

WHAT THIS TEST IS FOR
    ``scripts/scoring_provenance.py`` exists because the v1 campaign's ``_scoring/provenance.json``
    was hand-authored by the same LLM that wrote the 78 judgements it described: defect V12. The
    only
    question a generator like this has to answer is whether it would have caught that -- so the
    first
    test builds the v1 SHAPE and asserts the flags, and the second builds a compliant session and
    asserts the opposite. A generator that passed both would be a generator that decides nothing.

THE V1 SHAPE, AND WHY IT IS SYNTHETIC RATHER THAN A COPY
    The real v1 corpus is under ``runs/``, which is gitignored and is evidence. The fixture
    reproduces
    the three properties the v1 document records about itself -- ``human_validation_pass: false``,
    no
    session behind any score, and every score written inside a span of about two seconds -- at four
    bundles instead of 78, so the test is fast and does not depend on a campaign directory existing.
    The proportions do not matter to any of the four checks; what matters is that nothing was opened
    and everything was written at once. The ONE number this file copies from the real document is
    the
    shape of the span, and it is written as a literal SECOND figure rather than as a protocol value,
    because it is a measurement of the v1 defect, not a threshold this repository owns.

BARE ``assert`` IS AVOIDED THROUGHOUT
    So that this suite needs no S101 per-file-ignore entry in ``pyproject.toml``, which the WS-7
    workstream does not own; see ``scripts/tests/__init__.py`` and the note at the top of
    ``test_scoring_ui.py``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.m10_constants import SCORING_MIN_ELAPSED_SECONDS  # noqa: E402
from scripts.tests._fixtures import sealed_campaign  # noqa: E402

from scripts import scoring_provenance  # noqa: E402

CAMPAIGN_ID = "CAMP-TEST-provenance"
ARMS = ("G0-FULL", "G1-LOGONLY", "G2-SHAREDCRED", "G3-UNQUOTED", "S2-FLAT", "S3-SINGLE")
SCENARIO = "SCN-SIM-01"
INJECTION = "INJ-A"
SEED = 101

# The v1 defect's own measured shape: 78 scores inside 1.965 s. Reproduced at four bundles inside
# 1.9 s, which is inside the floor for every adjacent pair and so exercises the same code path.
V1_SPAN_SECONDS = 1.9
V1_BASE_SECOND = 25  # 2026-09-23T11:18:25, the second the v1 sample's first score was written


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _iso(second: float) -> str:
    """An ISO-8601 UTC instant, spelled out so the fixture never reads a wall clock.

    The seconds field accepts a FRACTION because the v1 shape's whole point is a sub-second spread:
    four scores inside 1.9 s cannot be written with whole-second stamps, or the first and last would
    be 2 s apart and the adjacency the tool checks would not be reproduced. The fraction is rendered
    in microseconds, which is the resolution the real document's stamps carry.
    """
    whole = int(second)
    micros = int(round((second - whole) * 1_000_000))
    return f"2026-09-23T11:18:{whole:02d}.{micros:06d}+00:00"


def _run_id(arm: str) -> str:
    return f"RUN-{arm}-{SCENARIO}-{INJECTION}-{SEED}"


def _campaign(tmp_path: Path, run_ids: list[str]) -> Path:
    """A campaign directory whose bundles carry a real seal, plus its sample file.

    ``scripts/tests/_fixtures.py`` produces the bundles; this only writes the sample and returns the
    directory. The seal has to be real because the compliant-session fixture below drives the actual
    scoring UI, and the UI refuses to open a bundle whose seal does not verify.

    The arm is read out of the run id by SPLITTING ON THE DASHES AND INDEXING, not by
    ``split("-")[1]``:
    an arm token may itself contain a dash (``G0-FULL`` is one token with a dash in it), so the
    first
    field after ``RUN-`` is the arm and everything up to the scenario is. ``runner.ids`` is the
    authority for the token set, and this does not restate it.
    """
    campaign_dir = sealed_campaign(
        tmp_path,
        CAMPAIGN_ID,
        [
            (run_id.removeprefix("RUN-").split("-SCN-", 1)[0], SCENARIO, INJECTION, SEED)
            for run_id in run_ids
        ],
    )
    (campaign_dir / "_scoring").mkdir(parents=True, exist_ok=True)
    (campaign_dir / "_scoring" / "sample.json").write_text(
        json.dumps({"campaign_id": CAMPAIGN_ID, "tuple_sample_count": 1, "run_ids": run_ids}),
        encoding="utf-8",
    )
    return campaign_dir


def _write_scores(bundle: Path, run_id: str, passes: list[dict]) -> None:
    (bundle / "scores.json").write_text(
        json.dumps({"run_id": run_id, "rubric_version": "v1.0", "passes": passes}),
        encoding="utf-8",
    )


def _v1_shape(tmp_path: Path) -> Path:
    """Four bundles, one score each, every score written inside 1.9 s, and no session log at all."""
    run_ids = [_run_id(arm) for arm in ARMS[:4]]
    campaign_dir = _campaign(tmp_path, run_ids)
    for index, run_id in enumerate(run_ids):
        _write_scores(
            campaign_dir / run_id,
            run_id,
            [
                {
                    "pass": "initial",
                    "scored_at": _iso(V1_BASE_SECOND + (V1_SPAN_SECONDS * index) / len(run_ids)),
                    "blind": True,
                    "investigation_match": 2,
                    "scope_correct": True,
                    "incorrect_or_harmful_action_count": 0,
                }
            ],
        )
    return campaign_dir


def _compliant_session(tmp_path: Path) -> Path:
    """The same four bundles, each opened, read for longer than the floor, then submitted.

    Built through the real scoring UI rather than by writing the log by hand, because the log format
    is exactly what could drift between the two modules, and a fixture that wrote it itself would
    pass against a log the UI no longer produces.
    """
    from datetime import UTC, datetime, timedelta

    from scripts import scoring_ui

    run_ids = [_run_id(arm) for arm in ARMS[:4]]
    campaign_dir = _campaign(tmp_path, run_ids)
    sample_path = campaign_dir / "_scoring" / "sample.json"
    now = datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)

    class Clock:
        def __call__(self) -> datetime:
            return now

    app = scoring_ui.build_app(
        campaign_dir,
        sample_path,
        salt=None,
        session_secret="test-only-secret-not-a-credential",  # noqa: S106 - not a credential
        clock=Clock(),
    )
    sid_by_run = {run_id: sid for sid, run_id in app.index.items()}
    for index, run_id in enumerate(run_ids):
        sid = sid_by_run[run_id]
        opened = app.open_bundle(sid)
        # Past the floor, and far enough past it that consecutive submits are also past it. Both
        # spacing properties matter: the log's own elapsed figure and the scored_at spacing are
        # checked separately, and an honest session has to satisfy both.
        now = now + timedelta(seconds=SCORING_MIN_ELAPSED_SECONDS + 30 + (index * 30))
        app.submit_score(
            sid,
            investigation_match=2,
            scope_correct=True,
            incorrect_or_harmful_action_count=0,
            override=False,
            session_token=opened["session_token"],
        )
    return campaign_dir


def _signatures(document: dict) -> set[str]:
    return {finding["signature"] for finding in document["batch_signatures"]}


# ------------------------------------------------------------------------------------------------
# The v1 shape must be flagged.
# ------------------------------------------------------------------------------------------------


def test_flags_the_v1_batch(tmp_path: Path) -> None:
    """The v1 shape is disqualified, and the document says so in the field the reader will quote.

    Three assertions, in the order a reader meets them. The batch signatures are present, and the
    two
    that fire are the two the real v1 corpus fires: no session behind any score, and every adjacent
    pair of scores closer together than the protocol's minimum open-to-submit interval. Then
    ``human_validation_pass`` is FALSE -- which is the assertion that matters most, because that is
    the field a results section would quote, and on HEAD it was a hand-authored value anybody could
    have written as ``true``. And the exit status is non-zero, which is what the campaign's
    definition of done turns into a gate.
    """
    campaign_dir = _v1_shape(tmp_path)

    document = scoring_provenance.build_provenance(campaign_dir, generated_at=_iso(30))
    signatures = _signatures(document)

    _require(
        "scores_without_a_session" in signatures,
        "the v1 shape was not flagged for having no session behind its scores: "
        f"{sorted(signatures)}",
    )
    _require(
        "scored_at_closer_than_the_minimum_open_to_submit" in signatures,
        "the v1 shape was not flagged for its scores being written seconds apart: "
        f"{sorted(signatures)}",
    )
    _require(
        document["human_validation_pass"] is False,
        "a corpus with the v1 shape produced human_validation_pass=true",
    )
    _require(
        document["session_log"]["present"] is False,
        "the fixture did not reproduce the v1 shape's absent session log",
    )
    _require(
        document["session_log"]["submits"] == 0,
        "the v1 shape recorded submits it cannot have had",
    )
    _require(
        document["scored_at_distinct"] == 4,
        f"the fixture's four scores share a scored_at: {document['scored_at_distinct']}",
    )
    _require(
        document["scored_at_span_seconds"] is not None
        and document["scored_at_span_seconds"] < SCORING_MIN_ELAPSED_SECONDS,
        "the fixture did not reproduce the v1 shape's sub-two-second span",
    )
    _require(
        "must_not_be_reported_as" in document
        and "disqualifying" in document["must_not_be_reported_as"],
        f"a flagged corpus is not told what it may not be reported as: "
        f"{document.get('must_not_be_reported_as')!r}",
    )
    _require(
        "does NOT establish that the judgements are human" in document["what_this_document_proves"],
        "the document does not state the limit of what it proves, so a reader could take a pass as "
        "proof of authorship",
    )

    exit_code = scoring_provenance.main(["--campaign", str(campaign_dir), "--check"])
    _require(exit_code != 0, "the CLI reported success over the v1 shape")


def test_a_hand_authored_claim_cannot_make_the_v1_shape_pass(tmp_path: Path) -> None:
    """A corpus that ASSERTS it is fine is still flagged, because the verdict is computed.

    The v1 failure mode in one more step: the hand-authored document contained
    ``"human_validation_pass": false`` and said so honestly, but nothing about the corpus made that
    true -- the field was a claim. So the fixture writes a document that claims the opposite into
    the
    campaign and asserts the generator neither reads it nor is influenced by it. This is the
    property
    that makes the new document a computation rather than a description.
    """
    campaign_dir = _v1_shape(tmp_path)
    (campaign_dir / "_scoring" / "provenance.json").write_text(
        json.dumps({"human_validation_pass": True, "produced_by": "the researcher"}),
        encoding="utf-8",
    )

    document = scoring_provenance.build_provenance(campaign_dir, generated_at=_iso(30))
    _require(
        document["human_validation_pass"] is False,
        "a corpus's own provenance.json claim was believed",
    )
    _require(bool(_signatures(document)), "the batch signatures disappeared once claimed away")

    # And the existing document is not clobbered: for v1 that file is the evidence of V12.
    with pytest.raises(scoring_provenance.ProvenanceError, match="will not overwrite"):
        scoring_provenance.write_provenance(campaign_dir)
    _require(
        json.loads((campaign_dir / "_scoring" / "provenance.json").read_text(encoding="utf-8"))[
            "human_validation_pass"
        ]
        is True,
        "the refused write still replaced the existing document",
    )


# ------------------------------------------------------------------------------------------------
# A compliant session must NOT be flagged, or the tool decides nothing.
# ------------------------------------------------------------------------------------------------


def test_a_compliant_session_is_not_flagged(tmp_path: Path) -> None:
    """The same corpus, produced through the real scoring UI, passes.

    Without this the tool could be a detector of the v1 shape and nothing else, and a v2 campaign
    scored honestly would be reported as a batch -- which is a worse failure than not shipping the
    tool, because the definition of done would then refuse a compliant campaign.
    """
    campaign_dir = _compliant_session(tmp_path)

    document = scoring_provenance.build_provenance(campaign_dir, generated_at=_iso(30))
    _require(
        not _signatures(document),
        f"a compliant session was flagged: {sorted(_signatures(document))}",
    )
    _require(
        document["human_validation_pass"] is True,
        "a compliant session did not produce human_validation_pass=true",
    )
    _require(document["session_log"]["submits"] == 4, "the compliant log does not show 4 submits")
    _require(document["session_log"]["opens"] == 4, "the compliant log does not show 4 opens")
    _require(document["pass_kinds_present"] == ["initial"], "unexpected pass kinds")
    _require(document["rubric_versions"] == ["v1.0"], "the rubric version was not read")

    exit_code = scoring_provenance.main(["--campaign", str(campaign_dir), "--check"])
    _require(exit_code == 0, f"the CLI refused a compliant session (exit {exit_code})")


def test_a_second_score_for_one_bundle_is_its_own_signature(tmp_path: Path) -> None:
    """Two submits for one (bundle, pass) is flagged even when both were gated.

    The scoring UI's override REPLACES a pass rather than appending one, so two submits for the same
    pass cannot both come from the UI. The fixture writes them into the log directly, which is the
    only way to produce this shape, and asserts the signature fires: it is what an ungated second
    write or a hand edit of scores.json looks like from here.
    """
    campaign_dir = _compliant_session(tmp_path)
    log = campaign_dir / "_scoring" / "session_log.jsonl"
    last = json.loads(log.read_text(encoding="utf-8").splitlines()[-1])
    with log.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({**last, "at": last["at"]}) + "\n")

    document = scoring_provenance.build_provenance(campaign_dir, generated_at=_iso(30))
    _require(
        "one_bundle_scored_twice_for_one_pass" in _signatures(document),
        f"a duplicated submit was not flagged: {sorted(_signatures(document))}",
    )
    _require(
        document["human_validation_pass"] is False,
        "a duplicated submit still produced human_validation_pass=true",
    )


def test_a_submit_recorded_faster_than_the_floor_is_flagged(tmp_path: Path) -> None:
    """The log's OWN elapsed figure is checked, not only the spacing the scores imply.

    The two disagree when a session log is edited, when a clock is wrong, or when a write path
    records
    an elapsed time it did not measure. Inferring the property only from ``scored_at`` spacing would
    miss all three, so the floor is applied to the recorded figure as well.
    """
    campaign_dir = _compliant_session(tmp_path)
    log = campaign_dir / "_scoring" / "session_log.jsonl"
    rows = []
    for raw in log.read_text(encoding="utf-8").splitlines():
        event = json.loads(raw)
        if event.get("event") == "submit":
            event["elapsed_seconds"] = 0.5
        rows.append(json.dumps(event))
    log.write_text("\n".join(rows) + "\n", encoding="utf-8")

    document = scoring_provenance.build_provenance(campaign_dir, generated_at=_iso(30))
    _require(
        "submit_faster_than_the_minimum_open_to_submit" in _signatures(document),
        f"a too-fast recorded elapsed time was not flagged: {sorted(_signatures(document))}",
    )


def test_an_unblinded_pass_is_refused_but_is_not_a_batch_signature(tmp_path: Path) -> None:
    """``blind: false`` does not make a batch; it makes the pass unusable as a judged measure.

    The two are different findings and the document keeps them apart. A batch signature is about HOW
    the scores were written -- an unattended process. A pass recorded without the blind view is
    about
    WHAT it claims: ``blind: true`` is an assertion the reader relies on, so one that is false has
    to
    be reported. But it is not evidence of a batch, and a document that conflated the two would let
    a
    reader dismiss a genuine batch because one pass happened to be unblinded, or the reverse.
    """
    campaign_dir = _compliant_session(tmp_path)
    run_ids = [_run_id(arm) for arm in ARMS[:4]]
    target = campaign_dir / run_ids[0] / "scores.json"
    document = json.loads(target.read_text(encoding="utf-8"))
    document["passes"][0]["blind"] = False
    target.write_text(json.dumps(document), encoding="utf-8")

    provenance = scoring_provenance.build_provenance(campaign_dir, generated_at=_iso(30))
    _require(
        not _signatures(provenance),
        f"an unblinded pass was reported as a batch signature: {sorted(_signatures(provenance))}",
    )
    _require(
        provenance["passes_not_recorded_blind"],
        "an unblinded pass was not reported at all",
    )
    _require(
        provenance["human_validation_pass"] is False,
        "an unblinded pass still produced human_validation_pass=true",
    )


def test_a_campaign_with_no_scores_is_not_a_pass(tmp_path: Path) -> None:
    """An empty corpus is reported, not passed.

    The vacuous-pass rule this repository applies everywhere: a verdict over nothing reads in a log
    exactly like a verdict over everything. There is no session behind a corpus with no scores, so
    there is nothing to have validated, and the document must say so rather than default to true.
    """
    run_ids = [_run_id(arm) for arm in ARMS[:4]]
    campaign_dir = _campaign(tmp_path, run_ids)

    document = scoring_provenance.build_provenance(campaign_dir, generated_at=_iso(30))
    _require(document["pass_count"] == 0, "an unscored corpus reported passes")
    _require(
        document["human_validation_pass"] is False,
        "a corpus with no judgements reported human_validation_pass=true",
    )
    _require(document["scored_at_span_seconds"] is None, "an empty corpus reported a span")
    _require(bool(_signatures(document)) is False, "an empty corpus raised a batch signature")
