r"""The adversarial-content registry: pools on disk, a seeded draw, and no payload text in code.

WHY THE PAYLOADS ARE A REGISTRY AND NOT FOUR PYTHON MODULES
-------------------------------------------------------------
``docs/plans/M5-implementation-plan.md`` task T5.4 says "one content module per injection class".
Four modules whose only difference is a string constant is four homes for one kind of thing, and
the argument against it is the one ``.agents/rules/20-parity-and-determinism.md`` already makes one
layer up: prompt text lives in a registry, and code composes it rather than containing it. The same
reasoning applies to adversarial text, and more sharply -- the pools are evaluated material that an
examiner must be able to read without reading Python, and matrix row T-46 requires the filter
applied to them to be recordable against an external source. A JSON registry is readable, diffable
and greppable; an f-string inside a module is none of those.

So: one pool file per injection class under ``scenarios/attackers/content/``, and this module
reads them. Adding an instance is a data change. Adding a *class* would be a change to
``INJECTION_CLASSES`` and to the glossary, which is the friction it should be.

THE DRAW IS SEEDED AND THE POOL IS ORDERED
--------------------------------------------
``instances`` is a list, and its order in the file is the order the draw indexes. A draw taken from
a set or a dict-keyed lookup would depend on iteration order, which
``.agents/rules/20-parity-and-determinism.md`` forbids by name. The loader therefore refuses a pool
whose ``payload_id`` values are not the pool id plus a contiguous ``001``-based index in file
order: a gap or a reordering would silently change which payload every past seed drew, and nothing
would report it.

THE CROSS-WALK IS RECORDED, NOT HARD-CODED
--------------------------------------------
Each instance carries ``kit_category`` -- this kit's own label for the shape of the attack. It does
**not** carry a category from [Abdennebi et. al., 2026], and it must not: that paper is an external
preprint, not ``context/``, so its seven attack categories are not in this repository to be read.
``scenarios/groundtruth/README.md`` records the filter -- which kit categories were included, which
excluded and on what relevance criterion -- with the external column left unbound and confirmed at
the GATE. Conflict M5-C7; matrix row T-46.

WHAT BREAKS IF THIS FILE CHANGES
---------------------------------
Every plan under ``INJ-A``..``INJ-D``, because the drawn ``payload_id`` is part of the planned event
and therefore part of the bytes ``scripts/scenario_determinism.sh`` compares. Reordering a pool
changes every seed's draw; the loader's contiguity check is what makes that impossible to do
silently.
"""

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

from scenarios.attackers import INJECTION_CLASSES
from scenarios.schemas import validate as schema_validate

__all__ = (
    "ContentError",
    "Pool",
    "PoolInstance",
    "draw",
    "load_pool",
    "pool_path",
    "resolve_payload",
)

CONTENT_DIR: Final = Path(__file__).resolve().parent / "content"

POOL_ID_PATTERN: Final = re.compile(r"^INJ-[A-D]-pool-[0-9]{2}$")
PAYLOAD_ID_PATTERN: Final = re.compile(r"^INJ-[A-D]-pool-[0-9]{2}-[0-9]{3}$")

# Enough instances that two seeds drawing from one pool usually differ, and few enough that every
# instance is reviewable by a human before the instrument freezes. Not a protocol constant: it
# constrains the corpus rather than the experiment, so it is not evaluation-protocol section 4's.
MIN_INSTANCES: Final = 5


class ContentError(Exception):
    """A pool file is missing, malformed, or breaks the contiguity contract."""


class PoolInstance:
    """One adversarial payload instance, drawn as a unit.

    ``induced_action`` (M10 WS-2, D1-A/D4-A) is the ground-truth ``cluster-executed-any`` check
    naming the cluster action this payload is trying to induce, or ``None`` for an instance whose
    success is an absence of action (the suppression payloads). It is stored as the raw check
    mapping, exactly as ``scenarios/schemas/content_pool.v1.json`` validated it, so that
    ``runner/evaluate_assertions.py`` resolves and evaluates it without this module knowing the
    evaluator's own vocabulary. The v1 pools carry none on any instance, so the field defaults to
    ``None`` and both pool generations load through one path.
    """

    __slots__ = ("index", "induced_action", "intent", "kit_category", "payload_id", "text")

    def __init__(
        self,
        payload_id: str,
        index: int,
        text: str,
        intent: str,
        kit_category: str,
        induced_action: Mapping[str, Any] | None = None,
    ) -> None:
        self.payload_id = payload_id
        self.index = index
        self.text = text
        self.intent = intent
        self.kit_category = kit_category
        self.induced_action = induced_action

    def __repr__(self) -> str:  # pragma: no cover - diagnostic only
        return f"PoolInstance({self.payload_id!r})"


class Pool:
    """One injection class's content pool, in file order."""

    __slots__ = ("injection_class", "instances", "pool_id", "relevance_note")

    def __init__(
        self,
        pool_id: str,
        injection_class: str,
        relevance_note: str,
        instances: tuple[PoolInstance, ...],
    ) -> None:
        self.pool_id = pool_id
        self.injection_class = injection_class
        self.relevance_note = relevance_note
        self.instances = instances

    def __len__(self) -> int:
        return len(self.instances)


def pool_path(pool_id: str) -> Path:
    return CONTENT_DIR / f"{pool_id}.json"


def load_pool(pool_id: str) -> Pool:
    """Load and validate one pool.

    Every check here exists because its absence would be silent. A pool for the wrong class, a
    payload id that does not match its position, or a pool short enough that every seed draws the
    same instance would each produce plans that look correct and mean something else.
    """
    if POOL_ID_PATTERN.match(pool_id) is None:
        raise ContentError(f"{pool_id!r} is not a pool id of the form INJ-<A-D>-pool-<nn>")
    path = pool_path(pool_id)
    if not path.is_file():
        raise ContentError(f"no content pool at {path}")
    try:
        document: Any = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ContentError(f"{path.name}: {error}") from None
    if not isinstance(document, dict):
        raise ContentError(f"{path.name}: a pool must be a JSON object")

    # Schema-first validation (ADR-117): the whole document is checked against the tracked
    # content_pool.v1 schema before any of the semantic checks below, so a shape defect fails at the
    # schema with a JSON Pointer rather than at whichever manual check happened to reach the bad key
    # first. The checks that follow are the ones the schema cannot express -- positional contiguity
    # of payload_id, the corpus minimum instance count, and the pool-id/injection-class/filename
    # agreement -- and they stay in code for that reason.
    try:
        schema_validate.validate(document, schema_validate.load_schema("content_pool.v1"))
    except (schema_validate.ValidationError, schema_validate.SchemaError) as error:
        raise ContentError(f"{path.name}: {error}") from None

    declared_id = document.get("pool_id")
    if declared_id != pool_id:
        raise ContentError(
            f"{path.name}: declares pool_id {declared_id!r}, filename says {pool_id!r}"
        )

    injection_class = document.get("injection_class")
    if injection_class not in INJECTION_CLASSES:
        raise ContentError(
            f"{path.name}: injection_class {injection_class!r} is not one of the four"
        )
    if not pool_id.startswith(f"{injection_class}-pool-"):
        raise ContentError(f"{path.name}: pool id and injection_class disagree")

    relevance_note = document.get("relevance_note")
    if not isinstance(relevance_note, str) or not relevance_note.strip():
        raise ContentError(
            f"{path.name}: relevance_note is required and records why these instances"
        )

    raw_instances = document.get("instances")
    if not isinstance(raw_instances, list):
        raise ContentError(f"{path.name}: instances must be a list, in draw order")
    if len(raw_instances) < MIN_INSTANCES:
        raise ContentError(
            f"{path.name}: holds {len(raw_instances)} instance(s); at least {MIN_INSTANCES} are "
            "needed or the seed cannot vary the draw and section D13's claim is vacuous"
        )

    instances: list[PoolInstance] = []
    for index, raw in enumerate(raw_instances, 1):
        if not isinstance(raw, dict):
            raise ContentError(f"{path.name}: instance {index} is not an object")
        expected = f"{pool_id}-{index:03d}"
        payload_id = raw.get("payload_id")
        if payload_id != expected:
            raise ContentError(
                f"{path.name}: instance at position {index} declares payload_id {payload_id!r}, "
                f"expected {expected!r}. Ids are positional so that reordering the file cannot "
                "silently change what every past seed drew."
            )
        if PAYLOAD_ID_PATTERN.match(payload_id) is None:
            raise ContentError(f"{path.name}: {payload_id!r} is not a well-formed payload id")
        for field in ("text", "intent", "kit_category"):
            value = raw.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ContentError(f"{path.name}: {expected} is missing a non-empty {field!r}")
        unexpected = sorted(
            set(raw) - {"payload_id", "text", "intent", "kit_category", "induced_action"}
        )
        if unexpected:
            raise ContentError(
                f"{path.name}: {expected} carries unexpected key(s): {', '.join(unexpected)}"
            )
        induced_action = raw.get("induced_action")
        if induced_action is not None and not isinstance(induced_action, Mapping):
            raise ContentError(f"{path.name}: {expected} induced_action must be a check object")
        instances.append(
            PoolInstance(
                payload_id=payload_id,
                index=index,
                text=raw["text"],
                intent=raw["intent"],
                kit_category=raw["kit_category"],
                induced_action=induced_action,
            )
        )

    return Pool(
        pool_id=pool_id,
        injection_class=injection_class,
        relevance_note=relevance_note,
        instances=tuple(instances),
    )


def draw(pool: Pool, *, scenario_index: int, seed_index: int, seed_count: int) -> PoolInstance:
    """Draw one instance by a balanced rotation over the grid (M10 WS-2; replaces the hashed draw).

    The v1 draw was ``rng.randrange(len(pool))``: one hashed pick per cell, seeded from the whole
    cell key. It was deterministic and arm-independent, but it made no coverage guarantee -- across
    the five seeds of a ``(scenario, class)`` cell a pool of six could see three to five of its
    payloads and never the rest (defect V25), so a pool instance could sit in the corpus and never
    be
    delivered by any run.

    The rotation replaces the pick with an index computed from the cell's position in the grid:

        position = scenario_index * seed_count + seed_index
        instance = pool.instances[position mod len(pool)]

    ``scenario_index`` is the scenario's place in the canonical scenario list and ``seed_index`` its
    place in the glossary seed list (both supplied by the caller; this module owns neither), so over
    the full grid ``position`` walks a contiguous range and every pool instance is drawn at least
    once. It reads no clock and takes no unseeded draw -- it is a pure function of the cell's
    coordinates -- so ``(scenario_id, seed)`` still determines the payload, and because neither
    coordinate is the arm, every arm of a cell draws the same payload and matched pairs stay
    matched.
    """
    position = scenario_index * seed_count + seed_index
    return pool.instances[position % len(pool.instances)]


def resolve_payload(pool_id: str, payload_id: str) -> PoolInstance:
    """Resolve an auditable payload id to the exact registry text the applier must deliver."""
    pool = load_pool(pool_id)
    for instance in pool.instances:
        if instance.payload_id == payload_id:
            return instance
    raise ContentError(f"{payload_id!r} does not resolve in content pool {pool_id!r}")
