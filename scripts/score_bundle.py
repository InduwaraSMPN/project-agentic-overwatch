"""Render a scoring worksheet and record human judgements in a sealed run bundle.

EVERY WRITE PATH IS GATED (ADR-134, M10; V12)
--------------------------------------------
``write_score`` used to accept any caller, and the v1 sample was written that way: 78 scores with 78
distinct ``scored_at`` values inside a 1.965 s span, by an LLM, recorded as if by a researcher
(``docs/adr/ADR-110``, superseded prospectively by ADR-134). It now requires a *session grant* --
the object ``scripts/scoring_ui.ScoringApp.authorise_submit`` produces after it has (a) verified an
HMAC token minted when the bundle was OPENED, and (b) enforced the protocol's minimum open-to-submit
interval.

The gate is a check on the CALLER, not a parameter that can be set, because the only way to obtain a
grant is to be the scoring server that minted the token. A grant is therefore not forgeable from
outside this repository, and there is no environment variable, no flag and no keyword that turns it
off -- which is the point of a control rather than a convention. The cost is stated here rather than
discovered: a legitimate emergency hand-edit of one score is now a hand edit of ``scores.json``
(which ``runner.bundle.verify_bundle_seal`` hashes and which the seal's own ``scoring`` entry
records), not a call to this function.

WHAT THE GATE IS NOT
    Proof of human authorship. It raises the cost of, and leaves an audit trail against, an
    unattended batch write; a person holding the scoring secret can still script a session. ADR-134
    records the
    same limit, and ``scripts/scoring_provenance.py`` reports the evidence and exits non-zero on a
    batch signature rather than asserting a fact it cannot establish.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from runner.assertions import load_groundtruth  # noqa: E402
from runner.bundle import append_scoring_entry, verify_bundle_seal  # noqa: E402
from scenarios.schemas import validate as schema_validator  # noqa: E402
from scripts.blind_view import render_bundle_directory  # noqa: E402

RUBRIC_VERSION = "v1.0"
RUBRIC_PATH = REPO_ROOT / "scenarios" / "groundtruth" / "rubric-v1.md"
SCORES_SCHEMA = schema_validator.load_schema("scores.v1")


@dataclass(frozen=True)
class SessionGrant:
    """A verified open-to-submit grant for one bundle, and the evidence a submit must record.

    DEFINED HERE, NOT IN ``scoring_ui``, AND THE DIRECTION MATTERS. The gate below is only
    meaningful if the thing being checked is defined by the module that checks it:
    ``scripts/scoring_ui.py`` imports this one (it calls ``build_worksheet`` and ``write_score``),
    so a grant defined there
    could not be named here without a cycle, and a gate whose type lives in the module it is
    defending is a gate a caller can reach around by constructing the type itself. Defined here, the
    only producer is :meth:`scripts.scoring_ui.ScoringApp.authorise_submit`, and constructing a
    grant by hand is a deliberate act of forgery rather than an accident of import order.

    No secret, and no token, is ever carried in here -- only the token's short fingerprint, which is
    what the provenance log needs in order to tie an open to its submit.
    """

    sid: str
    run_id: str
    session_id: str
    token_id: str
    opened_at: str
    elapsed_seconds: float
    pass_kind: str


class ScoringError(ValueError):
    """The requested worksheet or score would violate the scoring contract."""


def _read_json(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScoringError(f"{path}: {error}") from error
    if not isinstance(document, dict):
        raise ScoringError(f"{path}: expected a JSON object")
    return document


def _manifest(bundle_dir: Path) -> dict[str, Any]:
    manifest = _read_json(bundle_dir / "manifest.json")
    if manifest.get("is_baseline") is not False:
        raise ScoringError("scores.json applies only to framework-on bundles")
    return manifest


def _validate_scores(scores: dict[str, Any], run_id: str) -> None:
    try:
        schema_validator.validate(scores, SCORES_SCHEMA)
    except schema_validator.ValidationError as error:
        raise ScoringError(f"scores.json does not match scores.v1: {error}") from error
    if scores["run_id"] != run_id:
        raise ScoringError("scores.json run_id does not match manifest.json")
    kinds = [entry["pass"] for entry in scores["passes"]]
    if kinds[0] != "initial" or len(kinds) != len(set(kinds)):
        raise ScoringError("passes must be one initial pass followed by at most one rescore pass")


def _hide_scenario(node: Any, scenario_id: str, label: str) -> Any:
    """Replace the scenario's identity everywhere in a worksheet, recursively.

    Used only for the re-score pass (ADR-134). ``scripts/blind_view.py`` already removes the arm;
    the
    re-score removes the SCENARIO on top, because a re-score that a scorer can place in the campaign
    ("the CVE scenario, which I scored last week") is a re-score that can be reconstructed from
    memory
    rather than read afresh.

    What is hidden is the scenario's IDENTITY, not its content: the ground truth's detection labels,
    blast radius and phase substeps still reach the scorer, because the rubric is judged against
    them
    and a re-score with no ground truth is not a judgement at all. So the scenario id string is
    rewritten to a salt-derived opaque label wherever it appears, including inside the rendered
    manifest the evidence carries. A salt-derived label rather than a counter, for the reason
    ``blind_view.scoring_id`` gives: without the salt the mapping is a fixed function a scorer could
    learn, and with it the two passes cannot be joined by eye.
    """
    if isinstance(node, dict):
        return {key: _hide_scenario(value, scenario_id, label) for key, value in node.items()}
    if isinstance(node, list):
        return [_hide_scenario(item, scenario_id, label) for item in node]
    if isinstance(node, str):
        return node.replace(scenario_id, label)
    return node


def build_worksheet(bundle_dir: Path, salt: str, *, hide_scenario: bool = False) -> dict[str, Any]:
    """Return the blind evidence, rubric, and scenario labels needed for one human judgement.

    ``hide_scenario`` is the re-score pass's one asymmetry with the initial pass; see
    :func:`_hide_scenario`. It defaults to False so every existing caller of this function keeps the
    initial-pass view unchanged.
    """
    bundle_dir = Path(bundle_dir)
    defects = verify_bundle_seal(bundle_dir)
    if defects:
        raise ScoringError("bundle seal is invalid: " + "; ".join(defects))
    manifest = _manifest(bundle_dir)
    scenario_id = manifest.get("scenario_id")
    injection = manifest.get("injection_condition")
    if not isinstance(scenario_id, str) or not isinstance(injection, str):
        raise ScoringError("manifest lacks scenario_id or injection_condition")
    groundtruth, _ = load_groundtruth(scenario_id)
    try:
        condition_assertions = groundtruth["conditions"][injection]["end_state_assertions"]
    except (KeyError, TypeError) as error:
        raise ScoringError(f"ground truth has no {injection} condition") from error
    blind_view = render_bundle_directory(bundle_dir, salt)
    worksheet = {
        "scoring_id": blind_view["scoring_id"],
        "rubric_version": RUBRIC_VERSION,
        "rubric": RUBRIC_PATH.read_text(encoding="utf-8"),
        "ground_truth": {
            "detection": groundtruth["detection"],
            "blast_radius": groundtruth["blast_radius"],
            "phases": groundtruth["phases"],
            "assertions": groundtruth["assertions"],
            "condition_end_state_assertions": condition_assertions,
        },
        "evidence": blind_view["files"],
        "human_verdict": {
            "investigation_match": None,
            "scope_correct": None,
            "incorrect_or_harmful_action_count": None,
        },
    }
    if not hide_scenario:
        return worksheet
    import hashlib  # local: used only on the re-score path, and only to derive the opaque label

    label = "SCENARIO-" + hashlib.sha256(f"{salt}\x00{scenario_id}".encode()).hexdigest()[:8]
    hidden = _hide_scenario(worksheet, scenario_id, label)
    # The label is stated rather than implied, so a scorer is not left wondering whether the field
    # was empty by accident, and so the view says on its face which pass it belongs to.
    hidden["scenario_hidden"] = True
    hidden["scenario_label"] = label
    return hidden


def _require_session_grant(session: Any, round_name: str) -> SessionGrant:
    """Refuse anything that is not a grant this repository's scoring server produced.

    Three checks, and each names a different mistake it catches. The object TYPE: a caller who
    passed something else, or nothing -- ``session=True`` must not open the door, so the check is on
    the type and not on the truthiness. The PASS NAME: an initial-pass grant presented for a
    re-score, which is how the re-score delay would be walked around -- the delay is enforced when
    the re-score SAMPLE is drawn, and this is the write-path half of the same property. And the
    BUNDLE identity, re-checked in ``write_score`` so that a forged grant has to get two things
    right rather than one.
    """
    if not isinstance(session, SessionGrant):
        raise ScoringError(
            "refusing to record a score without a scoring-session grant: judgements may only be "
            "written through scripts/scoring_ui.py, which mints a per-session token when a "
            "bundle is opened and enforces the protocol's minimum open-to-submit interval "
            "(ADR-134; the v1 sample was written without such a control and is recorded as "
            "LLM-drafted). To score "
            "through the UI, run it with SCORING_UI_SESSION_SECRET set and submit from the "
            "browser; to correct a single score by hand, edit scores.json, which "
            "verify_bundle_seal hashes."
        )
    if session.pass_kind != round_name:
        raise ScoringError(
            f"session grant is for the {session.pass_kind!r} pass but a {round_name!r} pass was "
            "requested; a grant is bound to the pass it was opened for, so that the blind "
            "re-score's delay cannot be served by re-presenting an initial-pass session"
        )
    return session


def write_score(
    bundle_dir: Path,
    *,
    round_name: str,
    blind: bool,
    investigation_match: int,
    scope_correct: bool,
    incorrect_or_harmful_action_count: int,
    scored_at: str | None = None,
    session: SessionGrant | None = None,
) -> Path:
    """Validate and atomically record one explicitly supplied human scoring pass.

    ``session`` is the ADR-134 gate; see this module's docstring and :func:`_require_session_grant`.
    The seal is verified AFTER the grant, so an ungated caller is refused without having caused the
    bundle to be read.
    """
    bundle_dir = Path(bundle_dir)
    grant = _require_session_grant(session, round_name)
    defects = verify_bundle_seal(bundle_dir)
    if defects:
        raise ScoringError("bundle seal is invalid: " + "; ".join(defects))
    run_id = _manifest(bundle_dir).get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise ScoringError("manifest lacks run_id")
    if grant.run_id and grant.run_id != run_id:
        raise ScoringError(
            f"session grant is for run {grant.run_id!r} but this bundle is {run_id!r}; a grant is "
            "bound to the bundle it was minted for"
        )

    scores_path = bundle_dir / "scores.json"
    if scores_path.exists():
        scores = _read_json(scores_path)
        _validate_scores(scores, run_id)
        if scores["rubric_version"] != RUBRIC_VERSION:
            raise ScoringError(
                "existing rubric_version is "
                f"{scores['rubric_version']!r}, expected {RUBRIC_VERSION!r}"
            )
    else:
        scores = {"run_id": run_id, "rubric_version": RUBRIC_VERSION, "passes": []}
    if any(entry["pass"] == round_name for entry in scores["passes"]):
        raise ScoringError(f"scores.json already contains a {round_name!r} pass")
    if round_name == "rescore" and not scores["passes"]:
        raise ScoringError("a rescore pass cannot be recorded before the initial pass")

    scores["passes"].append(
        {
            "pass": round_name,
            "scored_at": scored_at or datetime.now(UTC).isoformat(),
            "blind": blind,
            "investigation_match": investigation_match,
            "scope_correct": scope_correct,
            "incorrect_or_harmful_action_count": incorrect_or_harmful_action_count,
        }
    )
    _validate_scores(scores, run_id)

    content = (json.dumps(scores, sort_keys=True, separators=(",", ":")) + "\n").encode()
    temporary = scores_path.with_name(f".{scores_path.name}.tmp-{os.getpid()}")
    with temporary.open("wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.replace(temporary, scores_path)
        append_scoring_entry(bundle_dir, scores_path, scored_at=scored_at)
    finally:
        temporary.unlink(missing_ok=True)
    return scores_path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    worksheet = commands.add_parser("worksheet", help="write the complete blind scoring worksheet")
    worksheet.add_argument("--bundle", type=Path, required=True)
    worksheet.add_argument("--salt", required=True)
    worksheet.add_argument("--output", type=Path, required=True)
    worksheet.add_argument(
        "--hide-scenario",
        action="store_true",
        help=(
            "the re-score pass's view: the arm is hidden by the blind view and the scenario is "
            "hidden here (ADR-134). The initial pass does not use it"
        ),
    )

    score = commands.add_parser(
        "score",
        help=(
            "REFUSED. Record a judgement through scripts/scoring_ui.py, which mints a per-session "
            "token on open and enforces the protocol's minimum open-to-submit interval (ADR-134)"
        ),
    )
    # The flags below are kept so that an existing invocation fails with the CONTROL's message
    # rather than with argparse's "unrecognized arguments", which would send an operator looking
    # for a typo instead of for the rule that changed. The values are read and then refused; none
    # of them can make the write happen, because the gate is the absence of a grant, not the
    # presence of an argument.
    score.add_argument("--bundle", type=Path, required=True)
    score.add_argument("--pass", dest="round_name", choices=("initial", "rescore"), required=True)
    score.add_argument("--blind", action=argparse.BooleanOptionalAction, required=True)
    score.add_argument("--investigation-match", type=int, required=True)
    score.add_argument("--scope-correct", action=argparse.BooleanOptionalAction, required=True)
    score.add_argument("--incorrect-or-harmful-action-count", type=int, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "worksheet":
            output = args.output.resolve()
            bundle = args.bundle.resolve()
            if output == bundle or bundle in output.parents:
                raise ScoringError("worksheet output must be outside the sealed bundle")
            document = build_worksheet(args.bundle, args.salt, hide_scenario=args.hide_scenario)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            print(output)
        else:
            # REFUSED, ALWAYS, AND NOT BY A MISSING FLAG.
            #
            # This subcommand used to write a score. It no longer can, on any invocation, because
            # `write_score` requires a session grant and the only producer of one is the scoring
            # server -- a process that mints an HMAC token when a bundle is opened and refuses a
            # submit until the protocol's minimum open-to-submit interval has passed. That is
            # deliberate: a CLI that could still write a score given the right argument would be a
            # CLI a script could drive, and V12 is exactly a score sample a script wrote (78
            # judgements in 1.965 s). The fix is not to remove the door, but to make the only key
            # the one that cannot be copied off disk.
            #
            # The three supported routes are printed rather than left to be found: the UI, which is
            # the only one that can write; a hand edit of scores.json, which verify_bundle_seal
            # hashes and seal.json's own `scoring` entry records, and which is therefore visible
            # as an edit rather than silent; and, for a bundle that should never have been scored,
            # deleting scores.json under the same visibility.
            print(
                "score-bundle: REFUSED — this command can no longer record a judgement.\n"
                "  Judgements are written only through the scoring UI, which mints a per-session\n"
                "  token when a bundle is opened and enforces the protocol's minimum\n"
                "  open-to-submit interval; a scripted bulk write is what ADR-134 refuses.\n"
                "  To score:  SCORING_UI_SESSION_SECRET=... python scripts/scoring_ui.py "
                "--campaign <dir>\n"
                "  To correct one score by hand: edit <bundle>/scores.json, which "
                "verify_bundle_seal hashes.\n"
                f"  (refused invocation: pass={args.round_name} bundle={args.bundle})",
                file=sys.stderr,
            )
            return 1
    except (ScoringError, OSError) as error:
        print(f"score-bundle: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
