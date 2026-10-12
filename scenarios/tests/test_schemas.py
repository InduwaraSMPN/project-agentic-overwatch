r"""Every tracked schema is well-formed, self-consistent, and uses only the validator's subset.

The validator here is scenarios/schemas/validate.py, which implements a subset of JSON Schema
2020-12 and reports any keyword outside that subset rather than ignoring it silently. So a schema
that grew a keyword the validator does not apply would fail this suite at the schema, which is the
guarantee that "validated" never quietly means "validated except for the parts nobody implemented".
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402

from scenarios.schemas import validate as V  # noqa: E402

SCHEMA_NAMES = (
    "scenario_manifest.v1",
    "groundtruth.v1",
    "groundtruth.v2",
    "groundtruth.v3",
    "injection_plan.v1",
    "content_pool.v1",
    "scores.v1",
    "assertions.v1",
)


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_schema_loads_and_declares_the_pinned_dialect(name: str) -> None:
    """Each schema parses and declares draft 2020-12; a wrong dialect is refused at load."""
    schema = V.load_schema(name)
    assert schema["$schema"] == V.DIALECT


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_schema_uses_only_the_validators_subset(name: str) -> None:
    """No schema uses a keyword the validator does not apply.

    Without this, a schema author could add ``format`` or ``oneOf`` and every instance would pass
    the unimplemented constraint by default -- the vacuous validation this repository refuses.
    """
    schema = V.load_schema(name)
    outstanding = V.unsupported_keywords(schema)
    assert outstanding == set(), (
        f"{name} uses keyword(s) the validator does not implement: {sorted(outstanding)}. "
        "Either implement them in scenarios/schemas/validate.py or rewrite the schema without them."
    )


def test_validator_rejects_a_malformed_instance_with_a_pointer() -> None:
    """A validation failure names the failing node, not just the rule.

    A message that says only 'enum' on a document with four phase blocks is not actionable; the
    pointer is what makes a failure fixable.
    """
    schema = V.load_schema("injection_plan.v1")
    bad = {"schema_version": "v2"}  # wrong const, and missing everything else
    with pytest.raises(V.ValidationError) as caught:
        V.validate(bad, schema)
    assert caught.value.pointer is not None


def test_validator_applies_constraints_beside_a_ref() -> None:
    """Draft 2020-12 requires $ref siblings to apply rather than disappear on resolution."""
    schema = {
        "$schema": V.DIALECT,
        "$defs": {"word": {"type": "string", "minLength": 1}},
        "$ref": "#/$defs/word",
        "maxLength": 3,
    }
    V.validate("abc", schema)
    with pytest.raises(V.ValidationError):
        V.validate("abcd", schema)


def test_validator_applies_duplicate_ref_sibling_keywords_as_independent_constraints() -> None:
    schema = {
        "$schema": V.DIALECT,
        "$defs": {"word": {"type": "string"}},
        "$ref": "#/$defs/word",
        "type": "integer",
    }
    with pytest.raises(V.ValidationError):
        V.validate(1, schema)
    with pytest.raises(V.ValidationError):
        V.validate("one", schema)


def test_groundtruth_v2_requires_a_check_on_every_substep() -> None:
    """ADR-088 / supervisor ruling B4: a required substep with no predicate is schema-invalid.

    v1 left `check` optional and let the evaluator fall back to a file-presence floor. That floor is
    not a performed action (protocol section 3), so v2 promotes `check` to required. Validated
    against the `substep` $def directly rather than a whole document, because the document-level
    fixture would be several hundred lines for one negative case.
    """
    schema = V.load_schema("groundtruth.v2")
    substep_schema = {"$schema": V.DIALECT, "$defs": schema["$defs"], "$ref": "#/$defs/substep"}
    without_check = {
        "substep_id": "SUB-01",
        "description": "Read the affected replica through the Guardian.",
        "evidence": "guardian_audit.jsonl",
    }
    with pytest.raises(V.ValidationError, match="check"):
        V.validate(without_check, substep_schema)

    with_check = {
        **without_check,
        "check": {
            "type": "guardian-executed-any",
            "params": {"namespace": "boutique", "resource": "pods", "verb": "get"},
        },
    }
    V.validate(with_check, substep_schema)  # does not raise

    # v1 is unchanged: it still accepts the same substep with no `check` at all, which is exactly
    # the floor v2 closes. Both stay true at once because two different schema files describe them.
    v1_schema = V.load_schema("groundtruth.v1")
    v1_substep_schema = {
        "$schema": V.DIALECT,
        "$defs": v1_schema["$defs"],
        "$ref": "#/$defs/substep",
    }
    V.validate(without_check, v1_substep_schema)  # does not raise


# --- M10 WS-2 (D1-A): the optional per-run payload attribution in assertions.v1 ------------------


def _assertions_document(**overrides: object) -> dict:
    document = {
        "run_id": "RUN-G0-FULL-SCN-SIM-01-INJ-A-101",
        "scenario_id": "SCN-SIM-01",
        "groundtruth_sha256": "a" * 64,
        "assertions": [
            {
                "assertion_id": "ASR-01",
                "kind": "phase-outcome",
                "phase": "detection-and-investigation",
                "result": "pass",
                "observed": "ok",
                "evaluated_at": "2026-01-01T00:00:00Z",
            }
        ],
        "required_substep_results": [
            {
                "substep_id": f"SUB-{index:02d}",
                "phase": "detection-and-investigation",
                "result": "reached",
                "observed": "ok",
                "evaluated_at": "2026-01-01T00:00:00Z",
            }
            for index in (1, 2, 3, 4)
        ],
    }
    document.update(overrides)  # type: ignore[arg-type]
    return document


def test_assertions_schema_carries_the_optional_payload_outcome() -> None:
    """The additive field, and the compatibility that makes it additive rather than a v2.

    A document written before this field existed has to keep validating: the v1 corpus is sealed,
    `runner/assertions.py::validate_assertion_results` runs the schema on every bundle it reads, and
    a version bump here would make the whole historical corpus unreadable for the sake of an
    optional field. The negative case is the shape the evaluator could plausibly emit by mistake --
    a payload id that is not a registry id, or a null action type with a boolean claimed -- and both
    are refused rather than stored, because a record whose id resolves to nothing cannot be audited
    against the pool file it claims to come from.
    """
    schema = V.load_schema("assertions.v1")
    V.validate(_assertions_document(), schema)  # no payload_outcome: the v1 shape still validates
    V.validate(
        _assertions_document(
            payload_outcome={
                "payload_id": "INJ-A-pool-02-003",
                "induced_action_type": "cluster-executed-any",
                "induced_requested": True,
                "induced_executed": False,
                "observed": "asked, not executed",
            }
        ),
        schema,
    )
    # A suppression instance: the action type is null, and both booleans are false.
    V.validate(
        _assertions_document(
            payload_outcome={
                "payload_id": "INJ-A-pool-02-001",
                "induced_action_type": None,
                "induced_requested": False,
                "induced_executed": False,
                "observed": "declares no induced_action",
            }
        ),
        schema,
    )
    for bad in (
        {
            "payload_id": "not-an-id",
            "induced_action_type": None,
            "induced_requested": False,
            "induced_executed": False,
            "observed": "x",
        },
        {
            "payload_id": "INJ-A-pool-02-003",
            "induced_action_type": None,
            "induced_requested": "yes",
            "induced_executed": False,
            "observed": "x",
        },
        {
            "payload_id": "INJ-A-pool-02-003",
            "induced_action_type": None,
            "induced_requested": False,
            "induced_executed": False,
        },
    ):
        with pytest.raises(V.ValidationError):
            V.validate(_assertions_document(payload_outcome=bad), schema)


def test_validator_enforces_additional_properties_false() -> None:
    """An unexpected key is a hard failure: every schema sets additionalProperties false."""
    schema = V.load_schema("scores.v1")
    instance = {
        "run_id": "RUN-x",
        "rubric_version": "v1.0",
        "passes": [],
        "smuggled": True,
    }
    with pytest.raises(V.ValidationError):
        V.validate(instance, schema)


# --- M10 WS-2 (D8, ADR-117): the content pool is a tracked, schema-first contract --------------


def test_pool_check_shape_equals_groundtruth_v3_check_shape() -> None:
    """The pool schema's own `check` copy is byte-equal to groundtruth.v3's.

    An instance's ``induced_action`` is not "a shape that looks like" a ground-truth check, it IS
    one: ``runner/evaluate_assertions.py`` resolves it and evaluates it with the same vocabulary the
    end-state assertions use, and nothing in the loader re-derives one from the other. The two
    schemas cannot share a ``$ref`` because ``scenarios/schemas/validate.py`` resolves only
    same-document ``#/$defs/`` references (ADR-035, stdlib-only), so the pool schema carries its
    own copy -- and this test is the only thing that makes the copy an equality rather than a
    resemblance. Editing one side alone fails here.
    """
    pool = V.load_schema("content_pool.v1")
    groundtruth = V.load_schema("groundtruth.v3")
    assert pool["$defs"]["check"] == groundtruth["$defs"]["check"], (
        "content_pool.v1's $defs/check has drifted from groundtruth.v3's; an induced_action would "
        "then be scored against a vocabulary the ground truth does not use"
    )


def _pool_document(**overrides: object) -> dict:
    instance = {
        "payload_id": "INJ-A-pool-02-001",
        "text": "a payload",
        "intent": "an intent",
        "kit_category": "a-category",
    }
    instance.update(overrides)  # type: ignore[arg-type]
    return {
        "pool_id": "INJ-A-pool-02",
        "injection_class": "INJ-A",
        "relevance_note": "why these instances",
        "instances": [instance],
    }


def test_pool_schema_accepts_the_documented_instance_shapes() -> None:
    """The shapes the four pool-02 generations actually ship, including the optional field."""
    schema = V.load_schema("content_pool.v1")
    # No induced_action: a suppression instance, whose success is an absence of action.
    V.validate(_pool_document(), schema)
    # With one: the ground-truth check shape, copied verbatim.
    V.validate(
        _pool_document(
            induced_action={
                "type": "cluster-executed-any",
                "params": {
                    "namespace": "boutique",
                    "resource": "deployments",
                    "scale_to_zero": True,
                },
            }
        ),
        schema,
    )


@pytest.mark.parametrize(
    ("document", "match"),
    (
        # A check type the evaluator has no arm for would be scored as "not evaluable" at run end,
        # i.e. every payload carrying it would report induced_executed false for the wrong reason.
        (
            _pool_document(induced_action={"type": "guardian-felt-uneasy", "params": {}}),
            "guardian-felt-uneasy",
        ),
        # params stays a flat scalar map: an array-valued param is a shape the evaluator has no
        # reading for, and one that would need its own vocabulary to grow.
        (
            _pool_document(
                induced_action={
                    "type": "cluster-executed-any",
                    "params": {"resource": ["pods", "secrets"]},
                }
            ),
            "params",
        ),
        # The key vocabulary is lower snake_case, so a camelCase key cannot be silently written.
        (
            _pool_document(
                induced_action={
                    "type": "cluster-executed-any",
                    "params": {"resource": "pods", "anyReadVerb": True},
                }
            ),
            "anyReadVerb",
        ),
        # Every instance needs the three fields the registry reads; none is defaulted.
        (
            {
                "pool_id": "INJ-A-pool-02",
                "injection_class": "INJ-A",
                "relevance_note": "why",
                "instances": [{"payload_id": "INJ-A-pool-02-001", "text": "t"}],
            },
            "intent",
        ),
        # The pool id is positional in the filename, so a malformed one is refused at the schema.
        (
            {
                "pool_id": "inj-a-2",
                "injection_class": "INJ-A",
                "relevance_note": "why",
                "instances": [
                    {
                        "payload_id": "INJ-A-pool-02-001",
                        "text": "t",
                        "intent": "i",
                        "kit_category": "k",
                    }
                ],
            },
            "pool_id",
        ),
    ),
)
def test_pool_schema_rejects_a_shape_the_evaluator_cannot_read(document: dict, match: str) -> None:
    schema = V.load_schema("content_pool.v1")
    with pytest.raises(V.ValidationError) as caught:
        V.validate(document, schema)
    assert match in str(caught.value), caught.value
