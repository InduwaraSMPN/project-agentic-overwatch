r"""Render a run bundle into the blind scoring view the three researcher-judged measures are read
through.

WHY A BLIND VIEW EXISTS AT ALL
--------------------------------
``docs/protocols/evaluation-protocol.md`` section 3, bound from the dissertation's section
3.5.7, requires that "a sample of runs is blindly re-scored by the same researcher after a time
delay", and ``docs/protocols/data-management.md`` section 3 gives ``scores.json`` a ``blind
(bool)`` field. But nothing in a bundle is blind by default: ``manifest.json`` carries
``condition`` and ``guardian_mode`` outright, and the bundle's own directory name is
``RUN-<COND>-<SCN>-<INJ>-<SEED>``, whose first component after ``RUN-`` is the arm. A scorer
reading a raw bundle knows which arm produced it, and a re-score that is not blind measures
nothing the first score did not. The rubric is M5's, so the view the rubric is applied through
is M5's too, or M7's re-score is not what it claims. Conflict M5-C8, ADR-037.

WHAT IS STRIPPED, AND WHY THIS EXACT SET
------------------------------------------
The set is ``data-management.md`` section 2's manifest fields filtered to the ones that name an
arm, plus the arm-revealing audit field M4 emits, plus the arm token in every path and
identifier:

* ``condition`` and ``guardian_mode`` -- the structure and guardrail arm, named outright.
* ``aggregator_quoting`` -- the G3-UNQUOTED flag, where a manifest carries it.
* ``graph_id`` -- named by section 2's schema; stripped if present even though M4's own bundles do
not yet emit it, because the view must be correct against the manifest contract and not only
against today's writer.
* ``enforcement`` -- the field an ``AuditRecord`` carries beside ``guardian_mode``; M4 names
the pair ``{"guardian_mode", "enforcement"}`` as the only permitted difference between a G0 and
a G1 record, so both are removed from the audit log.
* The arm token in ``run_id`` and ``baseline_run_id`` and in every string -- rewritten to an opaque
scoring id.

WHAT THIS VIEW CANNOT HIDE, STATED RATHER THAN PRETENDED AWAY
--------------------------------------------------------------
Two leaks survive, and ``scenarios/groundtruth/rubric-v1.md`` states them where a scorer reads
them: a single-agent (``S3-SINGLE``) transcript is recognisable by shape, and its composed
system prompt in ``messages.jsonl`` names the topology in plain English, which stripping a field
cannot unwrite; and a ``G1-LOGONLY`` audit log shows executions recorded after denials, a
pattern removing the ``enforcement`` field does not remove. So this view BOUNDS the leak rather
than eliminating it. That residual is a property of a single-researcher study whose arms differ
in their own observable behaviour -- the limitation section 3.5.7 requires be stated rather than
hidden -- and the alternative, a second independent coder, "lies beyond the resources of a
single-researcher undergraduate project", which the source says in as many words.

WHAT THIS SCRIPT IS NOT
-------------------------
Not the re-score, and not the sample. The re-score's fraction, its delay and the test-retest
agreement statistic are set at the GATE and recorded in ``evaluation-protocol.md`` section 4 --
all three are literal placeholders there today -- and the re-score itself lands in the M7
analysis. This script only produces the view both the initial score and the re-score are taken
through, so that ``scores.json``'s ``blind`` field means the same thing on both passes.

STANDARD LIBRARY ONLY
-----------------------
Nothing here imports outside the standard library, for the reason the rest of ``scenarios/``
gives: the scoring path must not acquire a dependency the run bundle's provenance does not
record.

WHAT BREAKS IF THIS FILE CHANGES
---------------------------------
The property ``scores.json.blind`` asserts. A field this script stops stripping is a field a
scorer can read the arm off, which makes ``blind: true`` a false claim on every bundle scored
afterwards. The strip list is derived from ``data-management.md`` section 2 as it stands; a
manifest field a later milestone adds that names the arm joins ``ARM_MANIFEST_FIELDS`` here.
"""

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

__all__ = (
    "ARM_MANIFEST_FIELDS",
    "BlindViewError",
    "render_bundle",
    "render_bundle_directory",
    "scoring_id",
)

# Manifest fields that name an arm. data-management.md section 2's field list, filtered to
# the ones a scorer could read the condition off. baseline_run_id is here: it embeds an arm token;
# is_baseline is NOT, because whether a run is a framework-off baseline is not an arm of the grid.
ARM_MANIFEST_FIELDS: Final[tuple[str, ...]] = (
    "condition",
    "guardian_mode",
    "aggregator_quoting",
    "graph_id",
    "baseline_run_id",
)

# Audit-record fields that reveal the guardrail arm. M4 names {guardian_mode, enforcement} as the
# only permitted difference between a G0 and a G1 record for one action, so both go.
ARM_AUDIT_FIELDS: Final[tuple[str, ...]] = ("guardian_mode", "enforcement")

# Every canonical arm token and the structure-study alias for the shared arm. These are scrubbed
# wherever they occur as standalone text, not only when embedded in a complete run id.
ARM_TOKENS: Final[tuple[str, ...]] = (
    "G0-FULL",
    "G1-LOGONLY",
    "G2-SHAREDCRED",
    "G3-UNQUOTED",
    "S1-HIER",
    "S2-FLAT",
    "S3-SINGLE",
)
ARM_REDACTION: Final = "[ARM]"

# Files the three judgements read, using the binding run-bundle names from data-management §1.
SCORING_FILES: Final[tuple[str, ...]] = (
    "manifest.json",
    "messages.jsonl",
    "spans.otel.json",
    "results.json",
    "assertions.json",
    "guardian_audit.jsonl",
    "monitor_events.jsonl",
)

# The run-id grammar, docs/07-glossary-and-ids.md section Run & campaign IDs. The first component
# after RUN- is the arm token, which is what the scoring id replaces.
RUN_ID_PATTERN: Final = re.compile(r"^RUN-(?P<arm>[A-Z0-9]+(?:-[A-Z0-9]+)*?)-(?P<rest>SCN-.+)$")

SCORING_PREFIX: Final = "SCORED"


class BlindViewError(Exception):
    """A bundle cannot be rendered into the blind view."""


def scoring_id(run_id: str, salt: str) -> str:
    """Map a run id to an opaque, stable scoring id.

    Deterministic under a salt, so the same bundle renders to the same scoring id across both
    the initial score and the re-score -- reached without the scorer being able to invert the id
    back to the arm. The salt is the campaign's, supplied by the caller; without it the mapping
    would be a fixed function an experienced scorer could learn.
    """
    digest = hashlib.sha256(f"{salt}\x00{run_id}".encode()).hexdigest()
    return f"{SCORING_PREFIX}-{digest[:16]}"


def _scrub_string(value: str, run_id: str, opaque: str) -> str:
    """Replace the full run id and every standalone canonical arm token."""
    cleaned = value.replace(run_id, opaque)
    for token in ARM_TOKENS:
        cleaned = re.sub(rf"(?<![A-Z0-9-]){re.escape(token)}(?![A-Z0-9-])", ARM_REDACTION, cleaned)
    return cleaned


def _strip_arm(node: Any, run_id: str, opaque: str) -> Any:
    """Recursively remove arm-naming fields and rewrite arm disclosures in every string."""
    if isinstance(node, dict):
        cleaned: dict[str, Any] = {}
        for key, value in node.items():
            if key in ARM_MANIFEST_FIELDS or key in ARM_AUDIT_FIELDS:
                continue
            cleaned[key] = _strip_arm(value, run_id, opaque)
        return cleaned
    if isinstance(node, list):
        return [_strip_arm(item, run_id, opaque) for item in node]
    if isinstance(node, str):
        return _scrub_string(node, run_id, opaque)
    return node


def _arm_token(run_id: str) -> str:
    match = RUN_ID_PATTERN.match(run_id)
    if match is None:
        raise BlindViewError(
            f"run id {run_id!r} does not parse as RUN-<arm>-SCN-... , so its arm token cannot be "
            "located to strip; see docs/07-glossary-and-ids.md section Run & campaign IDs"
        )
    return match.group("arm")


def render_bundle(manifest: Mapping[str, Any], salt: str) -> dict[str, Any]:
    """Return a blind copy of a parsed manifest.

    This compatibility helper is useful for unit-level callers. The CLI's ``--bundle`` path and
    :func:`render_bundle_directory` render the complete scoring evidence set.
    """
    run_id = manifest.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise BlindViewError("manifest carries no run_id, so it cannot be blinded")
    opaque = scoring_id(run_id, salt)
    # Confirm the arm token parses before stripping, so a malformed id fails loudly rather than
    # leaving an un-blinded field behind.
    _arm_token(run_id)
    view = _strip_arm(dict(manifest), run_id, opaque)
    view["scoring_id"] = opaque
    return view


def _residual_arm_traces(view: Mapping[str, Any], run_id: str) -> list[str]:
    """Return every place an arm token or arm field still shows in the rendered view."""
    problems: list[str] = []
    serialised = json.dumps(view, ensure_ascii=True)
    for field in ARM_MANIFEST_FIELDS + ARM_AUDIT_FIELDS:
        if f'"{field}"' in serialised:
            problems.append(f"arm field {field!r} still present in the view")
    if run_id in serialised:
        problems.append("original run id still present in the view")
    for token in ARM_TOKENS:
        if re.search(rf"(?<![A-Z0-9-]){re.escape(token)}(?![A-Z0-9-])", serialised):
            problems.append(f"standalone arm token {token!r} still present in the view")
    return problems


def _read_json_file(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BlindViewError(f"{path.name}: {error}") from None


def _read_jsonl_file(path: Path) -> list[Any]:
    records: list[Any] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise BlindViewError(f"{path.name}: {error}") from None
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as error:
            raise BlindViewError(f"{path.name}:{number}: {error}") from None
    return records


def render_bundle_directory(bundle_dir: Path, salt: str) -> dict[str, Any]:
    """Render all scoring evidence from a bundle into one recursively scrubbed JSON view."""
    manifest_path = bundle_dir / "manifest.json"
    manifest = _read_json_file(manifest_path)
    if not isinstance(manifest, dict):
        raise BlindViewError("manifest.json must contain an object")
    run_id = manifest.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise BlindViewError("manifest carries no run_id, so it cannot be blinded")
    opaque = scoring_id(run_id, salt)
    _arm_token(run_id)

    files: dict[str, Any] = {}
    for name in SCORING_FILES:
        path = bundle_dir / name
        if not path.is_file():
            continue
        document = _read_jsonl_file(path) if name.endswith(".jsonl") else _read_json_file(path)
        files[name] = _strip_arm(document, run_id, opaque)
    if "manifest.json" not in files:
        raise BlindViewError("bundle carries no manifest.json")
    files["manifest.json"]["scoring_id"] = opaque
    return {"scoring_id": opaque, "files": files}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="blind-view",
        description="Render a run bundle's scoring evidence into one blind JSON view.",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--bundle", type=Path, help="the run bundle directory")
    source.add_argument(
        "--manifest",
        type=Path,
        help="legacy manifest-only input; use --bundle for a complete scoring view",
    )
    parser.add_argument(
        "--salt",
        required=True,
        help=(
            "the campaign salt for the scoring id; the same salt reproduces the same id at re-score"
        ),
    )
    parser.add_argument(
        "--verify", action="store_true", help="assert nothing arm-revealing survived"
    )
    args = parser.parse_args(argv)

    try:
        if args.bundle is not None:
            manifest = _read_json_file(args.bundle / "manifest.json")
            view = render_bundle_directory(args.bundle, args.salt)
        else:
            manifest = _read_json_file(args.manifest)
            view = render_bundle(manifest, args.salt)
        if not isinstance(manifest, dict):
            raise BlindViewError("manifest.json must contain an object")
        if args.verify:
            problems = _residual_arm_traces(view, manifest["run_id"])
            if problems:
                for problem in problems:
                    print(f"blind-view: {problem}", file=sys.stderr)
                return 1
    except BlindViewError as error:
        print(f"blind-view: {error}", file=sys.stderr)
        return 1

    json.dump(view, sys.stdout, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
