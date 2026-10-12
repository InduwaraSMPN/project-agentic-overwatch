r"""The injection planner: pure, seeded, and the whole of what ``make determinism-check`` diffs.

WHAT A PLAN IS
---------------
Given ``(scenario_id, injection_condition, seed)`` and nothing else the caller supplies, this module
emits an ordered stream of injection events -- the scenario's incident, plus at most one adversarial
delivery -- each carrying a **logical offset in milliseconds from t0**. There is no ``t0`` here.
There is no clock, no network, no cluster, no environment read and no unseeded draw anywhere this
module can reach, and ``scripts/scenario_guard.sh`` greps for each of those by name.

That purity is not tidiness. It is what makes traceability row T-17's property -- "same seed twice
→ identical injected sequence" -- checkable at M5, two milestones before a cluster exists, by
running this module twice in two processes and comparing bytes.

THE FOUR SEED RULES THIS MODULE IS BUILT TO
---------------------------------------------
1. **One generator, derived from the whole cell key.** :func:`cell_digest` hashes
   ``(scenario_id, injection_condition, seed, PLAN_SCHEMA_VERSION)``. Deriving from the bare seed
   would make ``INJ-A`` and ``INJ-C`` at seed 101 draw the same stream, which is a hidden
   correlation across the very axis RQ5's contrasts are taken on. Including the schema version
   makes a format change a visible plan change rather than a silent one.

   The one thing the generator no longer decides is **which payload instance a cell draws**
   (M10 WS-2, D8). The draw was one ``rng.randrange`` per cell, which made no coverage guarantee:
   across the five seeds of a ``(scenario, class)`` cell a pool of six could see three to five of
   its instances and never the rest, so a payload could sit in the registry and be delivered by no
   run at all (defect V25). It is now a balanced rotation over the grid --
   :func:`payload_slot` -- computed from the cell's coordinates alone, so the generator's stream is
   byte-identical to what it was before this change for every other field, and a payload id in a
   plan is a function of ``(scenario, seed)`` exactly as before.

   The key deliberately does **not** include ``run_id``, and that is a correction to what
   ``docs/plans/M5-implementation-plan.md`` section D3 anticipated. ``run_id`` is
   ``RUN-<COND>-<SCN>-<INJ>-<SEED>``: it carries the **arm**. A planner keyed on it would hand
   ``INJ-B × G0-FULL`` and ``INJ-B × G1-LOGONLY`` different attacks, and the guardrail ablation is
   the contrast taken across exactly that pair. One cell must face one attack in every arm or
   nothing measured across arms is attributable to the arm. ``run_id`` reaches
   :mod:`scenarios.attackers.apply`, which stamps it into ``injection.log.jsonl``, and stops there.

2. **No absolute time.** Offsets are integers. See the module's own guard patterns.

3. **Every ordering is explicit.** Events sort by ``(offset_ms, event_rank, event_id)`` -- the same
   three-part total order ADR-019 fixed for ``EvidenceEvent``, and for the same reason: two keys
   leave ties broken by insertion order.

4. **Serialisation is byte-fixed.** ``sort_keys=True``, ``separators=(",", ":")``,
   ``ensure_ascii=True``, ``allow_nan=False``, ``\n`` terminated. Those are the four arguments
   ``monitor/aggregator/models.py`` calls "the repository's single definition of canonical JSON",
   and ``guardian/audit/canonical.py`` and ``agents/registry/digest.py`` use the same four. The M5
   plan wrote ``ensure_ascii=False``; it is ``True`` here, because a fifth canonicalisation
   differing from the other four in one argument is the drift ADR-022's "one rule, two homes, and a
   check that makes copy mean copy that cannot drift" exists to prevent.

WHAT THE SEED VARIES, AND WHAT IT MUST NOT
--------------------------------------------
Varies: each event's timing jitter, the target replica among identical ones, and a primitive's own
internal selection order. Does not vary: **how many events fire**.
``docs/protocols/data-management.md`` section 3 refuses to seal a framework-on bundle whose
``injection.log`` does not match the scenario's ground-truth event count, and that count is one
number per ``(scenario, injection_condition)`` -- so a seed that changed the count would make four
fifths of the seeds unsealable. The count is therefore a property of the manifest: one event per
``incident_primitives`` entry, plus one delivery under ``INJ-A``..``INJ-D``.

The payload instance also varies across cells, but not by the generator: it is the balanced
rotation :func:`payload_slot` computes from the cell's position in the grid, so the whole grid
reaches every instance of every pool.

Nor does the seed reorder events. :data:`JITTER_MS` is strictly less than :data:`STEP_MS`, asserted
at import, so jitter can shift an event within its slot and can never move it past its neighbour.
Causality inside an incident -- a shell before the egress it makes -- survives every seed.

WHY INJ-NONE IS NOT AN EMPTY PLAN
-----------------------------------
``INJ-NONE`` is a grid coordinate, not an absence. The incident fires exactly as it does under the
four classes; what is absent is adversarial content aimed at the agent layer. :func:`plan_cell`
raises on an empty ``INJ-NONE`` plan rather than returning one, because an empty plan would leave a
fifth of the grid with nothing to respond to and RQ2's per-phase correctness undefined on it. The
full statement, and the contrast with a framework-off ``BASE-<LOAD>-<SEED>`` run, is written once in
``scenarios/manifests/README.md``.

WHAT BREAKS IF THIS FILE CHANGES
---------------------------------
Every plan in the corpus, therefore ``sh scripts/scenario_determinism.sh``, therefore row T-17.
A change here that alters any drawn value invalidates every previously recorded
``injection.log.jsonl`` against its own ground-truth count, which is why
:data:`PLAN_SCHEMA_VERSION` is inside the digest: a deliberate change reads as a wholesale plan
change rather than as a mysterious diff on one cell.
"""

import argparse
import hashlib
import json
import random
import re
import sys
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any, Final

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scenarios.attackers import (  # noqa: E402
    INJECTION_CLASSES,
    INJECTION_CONDITIONS,
    PLAN_SCHEMA_VERSION,
)
from scenarios.attackers import content as content_registry  # noqa: E402
from scenarios.schemas import validate as schema_validate  # noqa: E402
from scenarios.schemas import yamlsubset  # noqa: E402

__all__ = (
    "JITTER_MS",
    "STEP_MS",
    "PlanError",
    "assert_cve_admission_first",
    "canonical_json_line",
    "cell_digest",
    "expected_event_count",
    "load_manifest",
    "manifest_ids",
    "payload_slot",
    "plan_cell",
    "plan_matrix",
    "resolve_payload_text",
    "seed_slot",
)

MANIFEST_DIR: Final = REPO_ROOT / "scenarios" / "manifests"
MANIFEST_PATTERN: Final = re.compile(r"^SCN-(CVE|SIM)-[0-9]{2}\.yaml$")
PLAN_FILENAME: Final = "plan.jsonl"

# The nominal spacing between planned events, and the bound on the seeded jitter around it. These
# shape the incident rather than the experiment, which is why they live here and not in
# docs/protocols/evaluation-protocol.md section 4 -- the same boundary a Chaos Mesh delay's own
# latency sits on. What section 4 owns is what the campaign measures; what a scenario's steps are
# spaced by is what the scenario IS.
STEP_MS: Final = 30_000
JITTER_MS: Final = 7_000

# The pre-registered campaign seed set, docs/07-glossary-and-ids.md section Seeds. Referenced here,
# owned there (.agents/rules/00-source-of-truth.md): the balanced payload rotation
# (scenarios/attackers/content.draw, M10 WS-2) needs a seed's ordinal position in the canonical set
# to give the full grid contiguous payload coverage, and a pilot seed disjoint from the set (plan
# section 6) takes an explicit deterministic slot after it. This is the one place in the
# planner that names the integers, and scenarios/tests/test_planner.py asserts the tuple
# still equals the
# glossary's set, so the mirror cannot drift from its single home.
CANONICAL_SEEDS: Final[tuple[int, ...]] = (101, 102, 103, 104, 105)


def seed_slot(seed: int) -> int:
    """Where ``seed`` sits in the payload rotation, given the canonical set's own order.

    A seed of the pre-registered set takes its own index in :data:`CANONICAL_SEEDS`, so the five
    campaign seeds occupy slots 0..4 and a cell's slot is exactly its column in the grid. A seed
    outside that set -- a pilot seed, which plan section 6 requires to be disjoint from the campaign
    set -- takes an *explicit* slot after the whole canonical block rather than sharing one: the
    offset is measured from the end of the canonical set, so a pilot seed can never displace a
    campaign seed's payload and two pilot seeds can never collide with each other. The arithmetic is
    fixed and total (a non-positive offset clamps to the first slot after the block), so a seed
    outside the set still replays identically from ``(scenario_id, seed)`` and still reads the same
    way in a plan log.
    """
    if seed in CANONICAL_SEEDS:
        return CANONICAL_SEEDS.index(seed)
    return len(CANONICAL_SEEDS) + max(0, seed - CANONICAL_SEEDS[-1] - 1)


def _scenario_index(scenario_id: str) -> int:
    """The scenario's place in the canonical (sorted) manifest list; its rotation row."""
    scenarios = manifest_ids()
    if scenario_id not in scenarios:
        raise PlanError(
            f"{scenario_id!r} is not in the canonical scenario list {scenarios}, so its position"
            " in the payload rotation is undefined"
        )
    return scenarios.index(scenario_id)


def payload_slot(scenario_id: str, seed: int) -> int:
    """The cell's position in the canonical grid; ``position mod len(pool)`` is its payload.

    The rotation runs over the whole grid rather than within one ``(scenario, class)`` cell, so a
    pool of N instances is fully covered by any grid at least N cells wide, and so that a scenario's
    five seeds take five *consecutive* slots -- the property the coverage test asserts over.

    Both coordinates are read from the canonical lists, never from a caller's ordering: the
    scenario's index in :func:`manifest_ids` (sorted, so it is the same on every machine) and the
    seed's index in :data:`CANONICAL_SEEDS`. Neither is the arm, so every arm of a cell draws the
    same payload and a matched pair faces one attack -- the property the rotation had to preserve,
    since the hashed draw it replaces was already arm-independent.
    """
    return _scenario_index(scenario_id) * len(CANONICAL_SEEDS) + seed_slot(seed)


# The invariant rule 3 rests on. Asserted at import rather than in a test alone, so a future edit
# that broke it could not be imported at all, let alone run a campaign.
if JITTER_MS >= STEP_MS:  # pragma: no cover - structural invariant
    raise AssertionError(
        "JITTER_MS must be strictly below STEP_MS, or a seed could reorder two events and the "
        "causal order inside an incident would become a property of the seed"
    )

# The event fields that identify an event. event_id is the digest OVER this projection, so it is
# absent from it; `applied` is absent because it is the applier's and would make a plan's own
# identifiers depend on a wall clock.
_IDENTIFYING_FIELDS: Final[tuple[str, ...]] = (
    "detail",
    "injection_class",
    "injection_condition",
    "kind",
    "mechanism",
    "offset_ms",
    "payload_id",
    "primitive_id",
    "scenario_id",
    "schema_version",
    "seed",
    "target",
)


class PlanError(Exception):
    """A manifest, a pool or a requested cell will not produce a plan."""


def canonical_json_bytes(payload: Any) -> bytes:
    """The repository's canonical JSON, fifth site, same four arguments as the other four."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def canonical_json_line(payload: Any) -> bytes:
    """One line of a plan or of ``injection.log.jsonl``."""
    return canonical_json_bytes(payload) + b"\n"


def manifest_path(scenario_id: str) -> Path:
    return MANIFEST_DIR / f"{scenario_id}.yaml"


def manifest_ids() -> tuple[str, ...]:
    """Every scenario the corpus holds, in sorted order.

    Sorted rather than in directory order: a filesystem's readdir order is not stable across
    machines, and the matrix this drives is compared byte for byte between two runs that may not be
    on the same one.
    """
    if not MANIFEST_DIR.is_dir():
        return ()
    return tuple(
        sorted(
            path.stem for path in MANIFEST_DIR.glob("*.yaml") if MANIFEST_PATTERN.match(path.name)
        )
    )


def load_manifest(scenario_id: str) -> dict[str, Any]:
    """Read one manifest and validate it against the tracked schema before returning it.

    Validated on every load, including inside the planner, rather than only in the test suite: a
    manifest that drifted from the schema would otherwise produce plans quietly, and the first
    thing to notice would be a sealed bundle whose event count did not match its labels.
    """
    path = manifest_path(scenario_id)
    if not path.is_file():
        raise PlanError(f"no scenario manifest at {path}")
    try:
        document = yamlsubset.parse(path.read_text(encoding="utf-8"))
    except yamlsubset.YamlSubsetError as error:
        raise PlanError(f"{path.name}: {error}") from None
    schema = schema_validate.load_schema("scenario_manifest.v1")
    try:
        schema_validate.validate(document, schema)
    except schema_validate.ValidationError as error:
        raise PlanError(f"{path.name}: {error}") from None
    if document["scenario_id"] != scenario_id:
        raise PlanError(
            f"{path.name}: declares scenario_id {document['scenario_id']!r}, "
            f"filename says {scenario_id!r}"
        )
    return document


def cell_digest(scenario_id: str, injection_condition: str, seed: int) -> str:
    """The stable digest the cell's generator is seeded from.

    Canonical JSON over a named mapping rather than a joined string, so that a value containing the
    separator cannot collide with a different cell -- the injectivity argument
    ``guardian/audit/canonical.py`` makes for the audit chain, applied one layer down.
    """
    key = {
        "injection_condition": injection_condition,
        "plan_schema_version": PLAN_SCHEMA_VERSION,
        "scenario_id": scenario_id,
        "seed": seed,
    }
    return hashlib.sha256(canonical_json_bytes(key)).hexdigest()


def _generator(scenario_id: str, injection_condition: str, seed: int) -> random.Random:
    """Seed once, at entry, from the cell key. There is no other generator in this module.

    S311 is suppressed here rather than fixed, because it is exactly backwards for this code: the
    rule warns that ``random`` is unfit for cryptographic use, and a cryptographic generator is
    precisely what this must NOT be. The harness's whole property is that two runs produce the same
    bytes, which a ``secrets``-backed generator would destroy. Per-site with a reason, never a
    widened per-file-ignore, on ADR-026's stated rule.
    """
    return random.Random(  # noqa: S311 - reproducibility is the requirement, not a weakness
        int(cell_digest(scenario_id, injection_condition, seed), 16)
    )


def _event_id(event: Mapping[str, Any]) -> str:
    projection = {field: event[field] for field in _IDENTIFYING_FIELDS}
    return hashlib.sha256(canonical_json_bytes(projection)).hexdigest()


def _target(declared: Mapping[str, Any], namespace: str, rng: random.Random) -> dict[str, Any]:
    """Resolve a manifest target, drawing the replica index from the seeded generator."""
    replicas = declared["replicas"]
    return {
        "namespace": namespace,
        "workload": declared["workload"],
        "container": declared["container"],
        "replica_index": rng.randrange(replicas),
    }


def _selection_order(size: int, rng: random.Random) -> str:
    """A seeded permutation of ``range(size)``, rendered as a stable compact string.

    This is section D13's "the selection order within the attacker's action set": what a primitive
    enumerates first when it has a choice. Rendered into ``detail`` rather than left implicit so
    that two runs of one scenario at different seeds are visibly different in the plan itself,
    which is what stops the CVE arm's determinism claim from being vacuous (conflict M5-C6).
    """
    order = list(range(size))
    rng.shuffle(order)
    return "|".join(str(index) for index in order)


def resolve_payload_text(event: Mapping[str, Any]) -> str | None:
    """Resolve a selected payload id to exact registry text without embedding it in the plan."""
    payload_id = event.get("payload_id")
    if payload_id is None:
        return None
    detail = event.get("detail")
    pool_id = detail.get("content_pool") if isinstance(detail, Mapping) else None
    if not isinstance(payload_id, str) or not isinstance(pool_id, str):
        raise PlanError("an event with a payload_id must name its content_pool in detail")
    try:
        return content_registry.resolve_payload(pool_id, payload_id).text
    except content_registry.ContentError as error:
        raise PlanError(str(error)) from None


def expected_event_count(manifest: Mapping[str, Any], injection_condition: str) -> int:
    """How many events a plan for this cell holds, at every seed.

    This is the number ``scenarios/groundtruth/<scenario_id>.yaml`` must declare, and the number
    ``docs/protocols/data-management.md`` section 3 compares a sealed ``injection.log`` against.
    It is computed from the manifest alone -- no seed, no generator -- which is the point.
    """
    incident = len(manifest["incident_primitives"])
    return incident if injection_condition == "INJ-NONE" else incident + 1


def assert_cve_admission_first(scenario_id: str, mechanisms: Sequence[str]) -> None:
    """A CVE scenario admits its vulnerable image FIRST, or it is not a CVE scenario (M10 WS-2).

    The `cve` mechanism is the one primitive whose consequence the rest of the incident depends on:
    the Trivy scan reads the node's containerd store for the admitted digest, and the exploit step
    reaches a library that is only vulnerable once that digest is running. Both are properties of
    the *cluster state* at their own offset, so a manifest that listed the admission later would
    still plan, still validate and still seal -- it would simply be describing a different scenario
    from the one its ground truth, its first-signal label (``first_signal_source: trivy``) and its
    phase coverage are written for.

    Takes the mechanisms in their firing order rather than a manifest, so the planner checks the
    manifest's declaration and ``scenarios/attackers/apply.py`` checks the plan it is about to
    execute -- one rule with two callers rather than two copies of it. Checked in the planner rather
    than only in the suite for the reason :func:`_assert_shape` gives: a plan is written to disk by
    the determinism gate before any test sees it, so a violated invariant that only a test notices
    has
    already been compared byte-for-byte against an identically wrong second copy and reported as a
    PASS.
    """
    admissions = [index for index, mechanism in enumerate(mechanisms) if mechanism == "cve"]
    if not scenario_id.startswith("SCN-CVE-"):
        if admissions:
            raise PlanError(
                f"{scenario_id} admits a CVE image but is not a CVE scenario; the `cve`"
                " mechanism is the scan-first detection surface and belongs to SCN-CVE-* only"
            )
        return
    if not admissions:
        raise PlanError(
            f"{scenario_id} declares no `cve` admission primitive, so its first signal cannot"
            " be the scan its ground truth names"
        )
    if admissions[0] != 0:
        raise PlanError(
            f"{scenario_id}: the admission primitive is at position {admissions[0]}, not first."
            " The vulnerable image must be resident before the scan reads it and before any step"
            " reaches the library it carries."
        )


def plan_cell(scenario_id: str, injection_condition: str, seed: int) -> tuple[dict[str, Any], ...]:
    """Plan one grid cell. Pure: same arguments in, same bytes out, on any machine."""
    if injection_condition not in INJECTION_CONDITIONS:
        raise PlanError(
            f"{injection_condition!r} is not one of the five injection-condition values "
            f"{INJECTION_CONDITIONS!r}"
        )
    if not isinstance(seed, int) or isinstance(seed, bool) or seed < 0:
        raise PlanError(f"seed must be a non-negative integer, got {seed!r}")

    manifest = load_manifest(scenario_id)
    assert_cve_admission_first(
        str(manifest["scenario_id"]),
        [str(item["mechanism"]) for item in manifest["incident_primitives"]],
    )
    namespace = manifest["namespace"]
    rng = _generator(scenario_id, injection_condition, seed)

    events: list[dict[str, Any]] = []
    for rank, primitive in enumerate(manifest["incident_primitives"]):
        events.append(
            _build_event(
                manifest=manifest,
                injection_condition=injection_condition,
                seed=seed,
                rank=rank,
                kind="incident",
                injection_class=None,
                mechanism=primitive["mechanism"],
                primitive_id=primitive["primitive_id"],
                target=_target(primitive["target"], namespace, rng),
                payload_id=None,
                detail={
                    "ref": primitive["ref"],
                    "selection_order": _selection_order(len(manifest["incident_primitives"]), rng),
                },
                rng=rng,
            )
        )

    if injection_condition in INJECTION_CLASSES:
        point = manifest["injection_points"][injection_condition]
        pool = content_registry.load_pool(point["content_pool"])
        if pool.injection_class != injection_condition:
            raise PlanError(
                f"{scenario_id}: injection point {injection_condition} names pool "
                f"{pool.pool_id!r}, which belongs to {pool.injection_class}"
            )
        instance = content_registry.draw(
            pool,
            scenario_index=_scenario_index(scenario_id),
            seed_index=seed_slot(seed),
            seed_count=len(CANONICAL_SEEDS),
        )
        events.append(
            _build_event(
                manifest=manifest,
                injection_condition=injection_condition,
                seed=seed,
                rank=len(manifest["incident_primitives"]),
                kind="injection",
                injection_class=injection_condition,
                mechanism=point["mechanism"],
                primitive_id=point["primitive_id"],
                target=_target(point["target"], namespace, rng),
                payload_id=instance.payload_id,
                detail={
                    "content_pool": pool.pool_id,
                    "kit_category": instance.kit_category,
                    "surface": point["surface"],
                },
                rng=rng,
            )
        )

    if injection_condition == "INJ-NONE" and not events:
        raise PlanError(
            f"{scenario_id}: an INJ-NONE plan with no events. INJ-NONE is a grid coordinate, not "
            "an absence: the incident fires exactly as it does under the four classes, and an "
            "empty plan would leave a fifth of the grid with nothing to respond to. See "
            "scenarios/manifests/README.md."
        )

    events.sort(key=lambda event: (event["offset_ms"], event["event_rank"], event["event_id"]))
    _assert_shape(events)
    return tuple(events)


def _build_event(
    *,
    manifest: Mapping[str, Any],
    injection_condition: str,
    seed: int,
    rank: int,
    kind: str,
    injection_class: str | None,
    mechanism: str,
    primitive_id: str,
    target: dict[str, Any],
    payload_id: str | None,
    detail: dict[str, Any],
    rng: random.Random,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "applied": None,
        "detail": detail,
        "event_rank": rank,
        "injection_class": injection_class,
        "injection_condition": injection_condition,
        "kind": kind,
        "mechanism": mechanism,
        "offset_ms": (rank + 1) * STEP_MS + rng.randrange(JITTER_MS),
        "payload_id": payload_id,
        "primitive_id": primitive_id,
        "scenario_id": manifest["scenario_id"],
        "schema_version": PLAN_SCHEMA_VERSION,
        "seed": seed,
        "target": target,
    }
    event["event_id"] = _event_id(event)
    return event


def _assert_shape(events: Sequence[Mapping[str, Any]]) -> None:
    """Validate every emitted event against the tracked schema, and check the plan's invariants.

    Done here rather than only in the suite because a plan is written to disk by the determinism
    gate before any test sees it: an event that failed its own contract would otherwise be compared
    byte for byte against an identically wrong second copy and reported as a PASS.
    """
    schema = schema_validate.load_schema("injection_plan.v1")
    try:
        schema_validate.validate_all(events, schema)
    except schema_validate.ValidationError as error:
        raise PlanError(f"a planned event does not satisfy injection_plan.v1: {error}") from None
    identifiers = [event["event_id"] for event in events]
    if len(set(identifiers)) != len(identifiers):
        raise PlanError("two planned events share an event_id, so the total order is not total")
    for event in events:
        if event["applied"] is not None:
            raise PlanError("a plan event carries an `applied` block; that is the applier's alone")
        if (event["kind"] == "incident") != (event["injection_class"] is None):
            raise PlanError("injection_class must be null exactly when kind is `incident`")


def plan_matrix(seeds: Sequence[int]) -> Iterator[tuple[str, str, int, tuple[dict[str, Any], ...]]]:
    """Plan every cell of the corpus, in a stable order.

    The seed set is the caller's, never this module's: the fixed set lives in
    ``docs/07-glossary-and-ids.md`` section Seeds and is single-homed there
    (``.agents/rules/00-source-of-truth.md``). The gate passes it on the command line.
    """
    for scenario_id in manifest_ids():
        for injection_condition in INJECTION_CONDITIONS:
            for seed in seeds:
                yield (
                    scenario_id,
                    injection_condition,
                    seed,
                    plan_cell(scenario_id, injection_condition, seed),
                )


def _write_matrix(out_root: Path, seeds: Sequence[int]) -> int:
    written = 0
    for scenario_id, injection_condition, seed, events in plan_matrix(seeds):
        cell_dir = out_root / scenario_id / injection_condition / str(seed)
        cell_dir.mkdir(parents=True, exist_ok=True)
        payload = b"".join(canonical_json_line(event) for event in events)
        (cell_dir / PLAN_FILENAME).write_bytes(payload)
        written += 1
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="scenario-planner",
        description=(
            "Plan injected event sequences. Pure and offline: no clock, no network, no cluster."
        ),
    )
    parser.add_argument(
        "--seeds",
        help=(
            "comma-separated seed set for the whole matrix (with --out-root). Never defaulted: the "
            "fixed set is docs/07-glossary-and-ids.md's alone, and a default here would be a "
            "second "
            "home for it."
        ),
    )
    parser.add_argument("--out-root", type=Path, help="write the whole matrix under this directory")
    parser.add_argument("--scenario", help="plan one cell: the scenario id")
    parser.add_argument("--injection", help="plan one cell: the injection condition")
    parser.add_argument("--seed", type=int, help="plan one cell: the seed")
    args = parser.parse_args(argv)

    try:
        if args.out_root is not None:
            if not args.seeds:
                print("scenario-planner: --out-root needs --seeds", file=sys.stderr)
                return 1
            try:
                seeds = tuple(int(token) for token in args.seeds.split(",") if token.strip())
            except ValueError:
                print("scenario-planner: --seeds must be comma-separated integers", file=sys.stderr)
                return 1
            if not seeds:
                print("scenario-planner: --seeds is empty", file=sys.stderr)
                return 1
            written = _write_matrix(args.out_root, seeds)
            if written == 0:
                print(
                    "scenario-planner: planned 0 cell(s) — scenarios/manifests/ holds no manifest",
                    file=sys.stderr,
                )
                return 1
            print(f"scenario-planner: planned {written} cell(s) under {args.out_root}")
            return 0
        if not (args.scenario and args.injection and args.seed is not None):
            print(
                "scenario-planner: give --out-root, or all of --scenario, --injection and --seed",
                file=sys.stderr,
            )
            return 1
        events = plan_cell(args.scenario, args.injection, args.seed)
        for event in events:
            sys.stdout.buffer.write(canonical_json_line(event))
        return 0
    except (PlanError, content_registry.ContentError, schema_validate.SchemaError) as error:
        print(f"scenario-planner: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
