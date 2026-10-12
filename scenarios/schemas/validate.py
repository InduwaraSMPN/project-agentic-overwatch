r"""A JSON Schema validator over the subset the four M5 schemas actually use -- and a check that
the subset is not smaller than they use.

WHY THIS EXISTS RATHER THAN ``import jsonschema``
--------------------------------------------------
``jsonschema`` is not pinned in ``infra/versions.env``, is not installed by
``scripts/install_runtime_deps.sh``, and is importable in this repository today only as a LiteLLM
transitive -- which means it is outside ``versions_env_sha256`` and would vanish if LiteLLM's
dependency set changed. Building the label gate on it would put a package nobody pinned on the
critical path of the evidence behind traceability rows T-17 and T-20.

The available answers were the ones M4 weighed for the parity checker and ``monitor/tests/
test_limits_match_protocol.py`` weighed before it: acquire the dependency through the full
ADR-021 procedure, or need nothing. This module needs nothing, and there is a second reason beyond
M4's. ``scripts/scenario_determinism.sh``'s single job is to answer "is the planner deterministic",
and ``scripts/monitor_determinism.sh`` -- the gate it is built to the contract of -- has exactly one
exit path that breaks its own stdout contract: the branch where the interpreter cannot import the
aggregator. A gate that cannot fail for a dependency reason can only fail for the reason it exists
to test. ADR-035.

WHY A SUBSET, AND WHY THE SUBSET IS ASSERTED RATHER THAN ASSUMED
-----------------------------------------------------------------
A hand-written validator that silently ignores a keyword it does not implement is worse than no
validator: it reports PASS over a constraint it never applied, which is the vacuous-pass shape this
repository refuses everywhere. So :data:`SUPPORTED` and :data:`IGNORED` between them are a closed
set, :func:`unsupported_keywords` reports anything outside it, and ``scenarios/tests/`` runs that
function over every tracked schema. Widening a schema with a keyword this module does not implement
fails the suite at the schema, not at the instance.

The subset is a *subset*, never a superset: a document a conforming validator would read
differently from this one is a document this module refuses. That is the same discipline
``agents/registry/loader.py`` and ``infra/locust/registry.py`` state for their YAML parsers.

WHAT IS DELIBERATELY NOT IMPLEMENTED
--------------------------------------
``$ref`` resolves local pointers into the document's own ``$defs`` and nothing else -- no remote
schemas, no ``$id`` resolution, no ``$dynamicRef``. ``format`` is not implemented and is not in
``IGNORED`` either, so writing one is an error rather than a decoration: ``format`` is
annotation-only
by default in 2020-12, and a schema author writing ``"format": "date-time"`` would reasonably expect
it to be checked. Composition keywords (``allOf``, ``anyOf``, ``oneOf``, ``not``, ``if``) are absent
for the same reason -- the four schemas are written without them, and implementing them
speculatively would be code no test covers.

WHAT BREAKS IF THIS FILE CHANGES
---------------------------------
Every M5 label and manifest check: the ground-truth resolution test behind T-20, the manifest
validity test behind T5.1, and the plan-shape assertion the planner makes on every event it emits.
"""

import json
import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any, Final

__all__ = (
    "IGNORED",
    "SUPPORTED",
    "SchemaError",
    "ValidationError",
    "load_schema",
    "schema_path",
    "unsupported_keywords",
    "validate",
)

SCHEMA_DIR: Final = Path(__file__).resolve().parent

# The dialect the four schemas declare. Pinned so a document written against another draft is
# refused rather than validated under rules it was not written to.
DIALECT: Final = "https://json-schema.org/draft/2020-12/schema"

# Keywords this module applies. Every one has an arm in _check below and a case in the suite.
SUPPORTED: Final[frozenset[str]] = frozenset(
    {
        "$defs",
        "$ref",
        "additionalProperties",
        "const",
        "enum",
        "items",
        "maxItems",
        "maxLength",
        "maximum",
        "minItems",
        "minLength",
        "minimum",
        "pattern",
        "properties",
        "propertyNames",
        "required",
        "type",
        "uniqueItems",
    }
)

# Keywords that carry no constraint and are skipped knowingly. `description` and `title` are prose;
# `$schema` is checked once at load rather than per node. Nothing else may be skipped.
IGNORED: Final[frozenset[str]] = frozenset(
    {"$comment", "$schema", "description", "examples", "title"}
)

# JSON's type names, mapped to what a parsed document actually holds. `bool` precedes `int`
# everywhere it matters because bool is a subclass of int in Python and `True` is not an integer in
# JSON Schema.
_TYPES: Final[dict[str, tuple[type, ...]]] = {
    "array": (list,),
    "boolean": (bool,),
    "integer": (int,),
    "null": (type(None),),
    "number": (int, float),
    "object": (dict,),
    "string": (str,),
}


class SchemaError(Exception):
    """The schema itself is malformed or uses a keyword this module does not implement."""


class ValidationError(Exception):
    """An instance does not satisfy its schema.

    Carries the JSON Pointer of the failing node, because a failure that names only the rule is
    not actionable on a document with four nested phase blocks.
    """

    def __init__(self, pointer: str, message: str) -> None:
        self.pointer = pointer or "/"
        self.message = message
        super().__init__(f"{self.pointer}: {message}")


def schema_path(name: str) -> Path:
    """Return the path of a tracked schema by bare name, e.g. ``groundtruth.v1``."""
    return SCHEMA_DIR / f"{name}.json"


def load_schema(name: str) -> dict[str, Any]:
    """Load a tracked schema and refuse one written against another dialect."""
    path = schema_path(name)
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise SchemaError(f"{path.name}: a schema must be a JSON object")
    declared = document.get("$schema")
    if declared != DIALECT:
        raise SchemaError(f"{path.name}: $schema is {declared!r}, expected {DIALECT!r}")
    return document


def _walk(node: Any) -> Iterator[Mapping[str, Any]]:
    """Yield every schema-shaped mapping in a document, at every depth."""
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item)


def unsupported_keywords(document: Mapping[str, Any]) -> set[str]:
    """Return every keyword in ``document`` that is neither supported nor knowingly ignored.

    The schemas' own vocabulary is what makes this decidable: a key under ``properties``,
    ``$defs`` or ``propertyNames`` is an author-chosen name rather than a keyword, so those three
    subtrees are entered but their immediate keys are not read as keywords.
    """
    found: set[str] = set()

    def visit(node: Any) -> None:
        if isinstance(node, list):
            for item in node:
                visit(item)
            return
        if not isinstance(node, dict):
            return
        for key, value in node.items():
            if key in ("properties", "$defs"):
                if isinstance(value, dict):
                    for child in value.values():
                        visit(child)
                continue
            if key not in SUPPORTED and key not in IGNORED:
                found.add(key)
            if key in ("required", "enum", "const", "type"):
                continue
            visit(value)

    visit(document)
    return found


def _resolve(schema: Mapping[str, Any], root: Mapping[str, Any]) -> Mapping[str, Any]:
    """Resolve one local ``$ref`` into the root document's ``$defs``."""
    ref = schema.get("$ref")
    if ref is None:
        return schema
    if not isinstance(ref, str) or not ref.startswith("#/$defs/"):
        raise SchemaError(f"only local #/$defs/ references are implemented, got {ref!r}")
    key = ref[len("#/$defs/") :]
    defs = root.get("$defs")
    if not isinstance(defs, dict) or key not in defs:
        raise SchemaError(f"unresolvable reference {ref!r}")
    target = defs[key]
    if not isinstance(target, dict):
        raise SchemaError(f"{ref!r} does not name a schema object")
    return target


def _type_names(declared: Any) -> tuple[str, ...]:
    if isinstance(declared, str):
        return (declared,)
    if isinstance(declared, list) and all(isinstance(item, str) for item in declared):
        return tuple(declared)
    raise SchemaError(f"`type` must be a string or a list of strings, got {declared!r}")


def _matches_type(value: Any, name: str) -> bool:
    expected = _TYPES.get(name)
    if expected is None:
        raise SchemaError(f"unknown type name {name!r}")
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if name in ("array", "object", "string", "null"):
        return isinstance(value, expected)
    return isinstance(value, expected)


def _check(value: Any, schema: Mapping[str, Any], root: Mapping[str, Any], pointer: str) -> None:
    ref = schema.get("$ref")
    if ref is not None:
        # Draft 2020-12 treats $ref as an applicator: validate the referenced schema and then every
        # sibling constraint at this location. Do not merge mappings; duplicate keywords on the two
        # schemas are independent constraints and must both hold.
        _check(value, _resolve({"$ref": ref}, root), root, pointer)
        schema = {name: constraint for name, constraint in schema.items() if name != "$ref"}

    if "type" in schema:
        names = _type_names(schema["type"])
        if not any(_matches_type(value, name) for name in names):
            raise ValidationError(
                pointer, f"expected type {'|'.join(names)}, got {_name_of(value)}"
            )

    if "const" in schema and value != schema["const"]:
        raise ValidationError(pointer, f"expected the constant {schema['const']!r}, got {value!r}")

    if "enum" in schema:
        allowed = schema["enum"]
        if not isinstance(allowed, list):
            raise SchemaError(f"{pointer}: `enum` must be a list")
        # Membership by identity for booleans, so `True` does not satisfy an enum holding 1.
        if not any(
            item == value and isinstance(value, bool) == isinstance(item, bool) for item in allowed
        ):
            raise ValidationError(pointer, f"{value!r} is not one of {allowed!r}")

    if isinstance(value, str):
        _check_string(value, schema, pointer)
    if isinstance(value, int) and not isinstance(value, bool) or isinstance(value, float):
        _check_number(value, schema, pointer)
    if isinstance(value, list):
        _check_array(value, schema, root, pointer)
    if isinstance(value, dict):
        _check_object(value, schema, root, pointer)


def _check_string(value: str, schema: Mapping[str, Any], pointer: str) -> None:
    pattern = schema.get("pattern")
    if pattern is not None and re.search(pattern, value) is None:
        raise ValidationError(pointer, f"{value!r} does not match {pattern!r}")
    minimum = schema.get("minLength")
    if minimum is not None and len(value) < minimum:
        raise ValidationError(pointer, f"shorter than minLength {minimum} ({len(value)})")
    maximum = schema.get("maxLength")
    if maximum is not None and len(value) > maximum:
        raise ValidationError(pointer, f"longer than maxLength {maximum} ({len(value)})")


def _check_number(value: float, schema: Mapping[str, Any], pointer: str) -> None:
    minimum = schema.get("minimum")
    if minimum is not None and value < minimum:
        raise ValidationError(pointer, f"{value} is below minimum {minimum}")
    maximum = schema.get("maximum")
    if maximum is not None and value > maximum:
        raise ValidationError(pointer, f"{value} is above maximum {maximum}")


def _check_array(
    value: Sequence[Any], schema: Mapping[str, Any], root: Mapping[str, Any], pointer: str
) -> None:
    minimum = schema.get("minItems")
    if minimum is not None and len(value) < minimum:
        raise ValidationError(pointer, f"holds {len(value)} item(s), minItems is {minimum}")
    maximum = schema.get("maxItems")
    if maximum is not None and len(value) > maximum:
        raise ValidationError(pointer, f"holds {len(value)} item(s), maxItems is {maximum}")
    if schema.get("uniqueItems") is True:
        seen: list[str] = []
        for item in value:
            rendered = json.dumps(item, sort_keys=True, separators=(",", ":"))
            if rendered in seen:
                raise ValidationError(pointer, f"duplicate item {item!r} under uniqueItems")
            seen.append(rendered)
    item_schema = schema.get("items")
    if isinstance(item_schema, dict):
        for index, item in enumerate(value):
            _check(item, item_schema, root, f"{pointer}/{index}")


def _check_object(
    value: Mapping[str, Any], schema: Mapping[str, Any], root: Mapping[str, Any], pointer: str
) -> None:
    required = schema.get("required")
    if isinstance(required, list):
        missing = [key for key in required if key not in value]
        if missing:
            raise ValidationError(pointer, f"missing required key(s): {', '.join(sorted(missing))}")

    properties = schema.get("properties")
    known: set[str] = set()
    if isinstance(properties, dict):
        known = set(properties)
        for key, child_schema in properties.items():
            if key in value:
                _check(value[key], child_schema, root, f"{pointer}/{_escape(key)}")

    names_schema = schema.get("propertyNames")
    if isinstance(names_schema, dict):
        for key in value:
            _check(key, names_schema, root, f"{pointer}/{_escape(key)}")

    extra = schema.get("additionalProperties")
    if extra is False:
        unexpected = sorted(set(value) - known)
        if unexpected:
            raise ValidationError(pointer, f"unexpected key(s): {', '.join(unexpected)}")
    elif isinstance(extra, dict):
        for key in sorted(set(value) - known):
            _check(value[key], extra, root, f"{pointer}/{_escape(key)}")


def _escape(key: str) -> str:
    """JSON Pointer escaping, so a key holding '/' does not produce a misleading pointer."""
    return key.replace("~", "~0").replace("/", "~1")


def _name_of(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def validate(instance: Any, schema: Mapping[str, Any]) -> None:
    """Validate ``instance`` against ``schema``, raising the first :class:`ValidationError`.

    First fault rather than a collected list, deliberately: these documents are hand-authored and
    an author fixes them one at a time, whereas a list invites skimming to the end.
    """
    outstanding = unsupported_keywords(schema)
    if outstanding:
        raise SchemaError(
            "schema uses keyword(s) this validator does not implement: "
            + ", ".join(sorted(outstanding))
            + " -- see this module's docstring before widening SUPPORTED"
        )
    _check(instance, schema, schema, "")


def validate_all(instances: Iterable[Any], schema: Mapping[str, Any]) -> None:
    """Validate every instance in a stream. Used by the planner over the events it emits."""
    for index, instance in enumerate(instances):
        try:
            validate(instance, schema)
        except ValidationError as error:
            raise ValidationError(f"[{index}]{error.pointer}", error.message) from None
