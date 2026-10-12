r"""The agent/Guardian seam: five vocabularies stated twice, held equal so neither can drift.

WHY ANYTHING IS STATED TWICE AT ALL
--------------------------------------
``agents/`` cannot import ``guardian/``. The Guardian ships as its own container, holds the only
cluster credential, and is the reference monitor the agent layer is *mediated by* -- so a Python
import from the agent layer into it would run the dependency the wrong way and would put the
enforcement code inside the process it exists to constrain. ``.agents/rules/10-guardian-first.md``
fixes the direction and ``docs/02-architecture.md`` section 2 fixes the deployment.

The cost is a copy. Five things are consequently spelled in both components:

1. the four incident-response phases (``agents.registry.PHASES`` / ``guardian.app.models.Phase``);
2. the identifier grammars the ``guardian_action`` and ``issue_capability_token`` tool schemas
   admit (``agents.tools.registry`` / ``ActionSpec`` and ``AllowClaim``);
3. the two contract schema versions the client stamps on a request body;
4. the three route paths the client speaks; and
5. the closed phase-outcome vocabulary (``agents.tools.registry.PHASE_OUTCOMES``).

ADR-022 states when a copy is acceptable: "a copy is legal when a test makes 'copy' mean 'copy that
cannot drift'". **This file is that test.** It exists for no other purpose, and it is where the two
homes are held equal.

THIS FILE IMPORTS ``guardian.*``, DELIBERATELY, AND THAT IS NOT A BREACH OF THE RULE
--------------------------------------------------------------------------------------
Say it plainly, because a reader scanning imports will see it and should not have to guess. The ban
is on the **runtime** dependency: no module that ships in the agent container may import the
Guardian, and ``scripts/grep_guard.sh`` polices the mutation path over every tracked file under
``agents/``. A test whose entire subject is whether two components agree has to be able to see both
of them; the alternative is a third file restating one side, which would be a third home for the
vocabulary and would need its own drift test. ``agents/tests/harness.py`` already imports
``guardian.app.composition`` for the same reason -- Tier A drives the real Guardian through its own
route handlers -- and this file is that precedent applied to the contracts rather than to the app.

Nothing here is offline-unsafe: no network, no Docker, no cluster, no credential. The Guardian's
models are Pydantic classes and its routes are attributes of an ASGI application assembled in a
temporary directory.

WHAT A FAILURE HERE WOULD OTHERWISE LOOK LIKE
------------------------------------------------
*A phase spelled differently* is a denial under ``scope.phase-mismatch`` in the middle of a run,
attributed to the agent layer's judgement, with nothing in the audit record able to say the two
components disagreed about a string.

*A tool schema laxer than the contract* is an audited ``policy.request-malformed`` denial that costs
a turn from a declared budget, where the tool-calling layer could have refused the argument for free
and let the model retry. ``agents/tools/registry.py`` says so itself about ``justification``: the
bound is in the schema "so that an over-long justification is refused by the model's own
tool-calling layer rather than by the Guardian -- which turns a wasted round trip and an audited
denial into a retry the model can act on".

*A schema version or a route out of step* is a run that produces no decisions at all, discovered at
Tier B against a container rather than at Tier A against an object.

*A re-spelled phase outcome* is two spellings of one result becoming two phenomena in Chapter 4.
``analysis/stats/`` counts these strings; a vocabulary is closed exactly to the extent that
something checks it is.
"""

import ast
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from typing import Any  # noqa: E402

import pytest  # noqa: E402
from agents.registry import PHASES  # noqa: E402
from agents.tools.guardian_client import (  # noqa: E402
    ACTION_REQUEST_SCHEMA_VERSION,
    ACTIONS_PATH,
    HEALTH_PATH,
    TOKEN_ISSUE_SCHEMA_VERSION,
    TOKENS_PATH,
)
from agents.tools.registry import (  # noqa: E402
    ACTION_TOOL,
    COMPLETE_PHASE_TOOL,
    ISSUE_TOKEN_TOOL,
    PHASE_OUTCOMES,
)
from guardian.app import main as guardian_main  # noqa: E402
from guardian.app import models as guardian_models  # noqa: E402
from guardian.app.models import (  # noqa: E402
    ActionSpec,
    AllowClaim,
    Phase,
    TokenIssueRequest,
)
from harness import InProcessGuardian  # noqa: E402

AGENTS_ROOT = REPO_ROOT / "agents"

# The directories whose modules ship in the agent container. agents/tests/ is excluded from the
# closed-vocabulary scan below because a test has to be able to spell a value in order to assert
# over it; agents/prompts/ holds no Python.
SHIPPED_AGENT_DIRECTORIES = (
    AGENTS_ROOT / "graphs",
    AGENTS_ROOT / "registry",
    AGENTS_ROOT / "tools",
)

# The one module allowed to spell a phase outcome as a literal: the registry that defines the
# vocabulary. Everything else imports PHASE_OUTCOMES and indexes it.
PHASE_OUTCOME_HOME = AGENTS_ROOT / "tools" / "registry.py"


# --------------------------------------------------------------------------------------------
# 1. The phase vocabulary
# --------------------------------------------------------------------------------------------


def test_the_agent_layers_phases_are_the_guardians_exactly() -> None:
    """Same four strings, same spelling, same order -- ``PHASES`` against ``Phase``.

    Order as well as membership. The tuple's order is ``evaluation-protocol.md`` section 1.6's, it
    is what :func:`agents.graphs.plan.plan_for` traverses, and row T-05 closes on the four phase
    spans being present *in order*; a re-ordered copy would leave the agent layer running the
    lifecycle in a sequence the protocol does not describe while every string still validated.
    """
    guardian_phases = tuple(member.value for member in Phase)
    assert PHASES == guardian_phases, (
        f"agents/registry/__init__.py declares PHASES = {PHASES} and guardian/app/models.py's "
        f"Phase declares {guardian_phases}. These strings travel into an ActionRequest's `phase` "
        "field and into a capability token's `phase` claim, so a second spelling is a denial under "
        "scope.phase-mismatch that nothing in the agent layer could explain"
    )


def test_every_phase_the_agent_layer_names_is_one_the_guardian_will_accept() -> None:
    """Not just equal strings: each one validates through both contracts that carry a phase.

    String equality could hold while the Guardian's field rejected the value for some other reason
    -- a length bound, a coercion, a validator. The contracts are the things a run actually meets,
    so the agreement is asserted against them.
    """
    for phase in PHASES:
        request = TokenIssueRequest(
            supervisor_id="supervisor-containment",
            executor_id="executor-containment-01",
            run_id="RUN-G0-FULL-SCN01-INJA-S07",
            phase=phase,
            allow=AllowClaim(verbs=("get",), resources=("pods",), namespaces=("boutique",)),
            ttl_seconds=None,
            schema_version=TOKEN_ISSUE_SCHEMA_VERSION,
        )
        assert request.phase.value == phase, (
            f"the Guardian accepted phase {phase!r} but normalised it to "
            f"{request.phase.value!r}; the agent layer would then be naming a phase that no longer "
            "matches the claim the token carries"
        )


# --------------------------------------------------------------------------------------------
# 2. The identifier grammars the tool schemas admit
# --------------------------------------------------------------------------------------------

# Each entry maps a property of the guardian_action tool schema to the Guardian pattern constant
# that governs the same field of ActionSpec. Compared as strings, because the schema is handed to a
# provider's tool-calling layer and evaluated there: two regular expressions that admit the same
# language but are spelled differently would be two grammars for a reader to reconcile, and the
# whole point of the copy is that there is one grammar written twice.
ACTION_FIELD_PATTERNS = {
    "verb": "VERB_PATTERN",
    "resource": "RESOURCE_PATTERN",
    "namespace": "DNS1123_LABEL_PATTERN",
    "name": "DNS1123_SUBDOMAIN_PATTERN",
}

# The bounds the tool schema declares, against the Guardian constant each mirrors.
ACTION_FIELD_BOUNDS = {
    "namespace": "KUBERNETES_NAMESPACE_MAX_CHARS",
    "name": "KUBERNETES_NAME_MAX_CHARS",
    "justification": "JUSTIFICATION_MAX_CHARS",
}

# Concrete values a run actually produces, one per field, used to check the grammars behaviourally
# rather than only textually.
ACTION_SAMPLES: dict[str, tuple[str, ...]] = {
    "verb": ("get", "list", "patch", "delete", "create", "a" * 60),
    "resource": ("pods", "networkpolicies.networking.k8s.io", "deployments.apps", "a" * 60),
    "namespace": ("boutique", "kube-system", "a", "a" * 63),
    "name": ("frontend-7d9c6c9f4b-abcde", "a", "a" * 253, "web.frontend-1"),
}


def _guardian_constant(name: str) -> Any:
    """Return a module-level constant of ``guardian.app.models``, failing if it has been renamed."""
    assert hasattr(guardian_models, name), (
        f"guardian/app/models.py no longer declares {name!r}. The agent layer restates that "
        "constant's grammar in its tool schema, so a rename here is a copy this test can no longer "
        "compare -- which is the drift ADR-022 requires a test to prevent"
    )
    return getattr(guardian_models, name)


def test_the_action_tool_schema_restates_the_guardians_grammars_character_for_character() -> None:
    """Every pattern in the ``guardian_action`` schema is the Guardian's own, spelled identically.

    ``agents/tools/registry.py`` says why the grammars are restated rather than imported and what it
    owes in exchange: "getting a pattern wrong here would be caught by the Guardian anyway, under
    ``policy.request-malformed``, but it would be caught as a denial in the middle of a run rather
    than as a refusal to compose". This is the payment.
    """
    properties = ACTION_TOOL.schema["properties"]
    for field, constant_name in ACTION_FIELD_PATTERNS.items():
        assert field in properties, f"the guardian_action schema no longer declares {field!r}"
        assert properties[field].get("pattern") == _guardian_constant(constant_name), (
            f"guardian_action.{field}'s pattern is {properties[field].get('pattern')!r} and "
            f"guardian/app/models.py's {constant_name} is {_guardian_constant(constant_name)!r}"
        )


def test_the_bounds_the_action_tool_declares_are_the_guardians() -> None:
    """Where the tool schema states a length, it states the Guardian's length.

    A tool that bounded a field *tighter* than the contract would refuse an action the Guardian
    would have permitted, silently narrowing what an arm can attempt; one that bounded it looser
    would spend a turn discovering the contract. Equality is the only value with neither failure.
    """
    properties = ACTION_TOOL.schema["properties"]
    for field, constant_name in ACTION_FIELD_BOUNDS.items():
        declared = properties[field].get("maxLength")
        assert declared == _guardian_constant(constant_name), (
            f"guardian_action.{field} declares maxLength {declared!r}; guardian/app/models.py's "
            f"{constant_name} is {_guardian_constant(constant_name)!r}"
        )


def test_every_action_value_the_tool_admits_the_guardian_accepts() -> None:
    """The subset property, checked on values rather than on patterns.

    A verb the tool offers and the Guardian refuses is a defect: the model would emit it, spend a
    tool call on it, and receive an audited denial for a request the schema said was well formed.
    Each sample below satisfies the tool's own schema for its field -- asserted here rather than
    assumed -- and must therefore build an :class:`~guardian.app.models.ActionSpec`.
    """
    properties = ACTION_TOOL.schema["properties"]
    base = {"verb": "get", "resource": "pods", "namespace": "boutique", "name": None, "params": {}}
    for field, samples in ACTION_SAMPLES.items():
        pattern = properties[field]["pattern"]
        bound = properties[field].get("maxLength")
        for sample in samples:
            assert re.match(pattern, sample), (
                f"the sample {sample!r} does not satisfy guardian_action.{field}'s own pattern "
                f"{pattern!r}, so it says nothing about what the tool admits"
            )
            if bound is not None:
                assert len(sample) <= bound, f"{sample!r} exceeds guardian_action.{field}'s bound"
            spec = ActionSpec(**{**base, field: sample})
            assert getattr(spec, field) == sample, (
                f"the Guardian accepted guardian_action.{field}={sample!r} but stored "
                f"{getattr(spec, field)!r}"
            )


def test_the_issuance_tool_admits_only_allow_claim_elements_the_guardian_accepts() -> None:
    """``issue_capability_token``'s three lists build an :class:`AllowClaim` without complaint.

    The tool's element grammars are deliberately *narrower* than
    :data:`~guardian.app.models.ALLOW_ELEMENT_PATTERN`, which also admits ``*``: a wildcard has to
    parse before the Guardian can refuse it for what it is, and a Supervisor has no business asking
    for one. Narrower is safe and wider is not, so what is asserted is the direction, not equality.
    """
    properties = ISSUE_TOKEN_TOOL.schema["properties"]
    allow_pattern = _guardian_constant("ALLOW_ELEMENT_PATTERN")
    samples = {
        "verbs": ("get", "list", "delete"),
        "resources": ("pods", "networkpolicies.networking.k8s.io"),
        "namespaces": ("boutique", "kube-system"),
    }
    for field, values in samples.items():
        item_pattern = properties[field]["items"]["pattern"]
        for value in values:
            assert re.match(item_pattern, value), (
                f"the sample {value!r} does not satisfy issue_capability_token.{field}'s own "
                f"item pattern {item_pattern!r}"
            )
            assert re.match(allow_pattern, value), (
                f"issue_capability_token.{field} admits {value!r}, which "
                f"guardian/app/models.py's ALLOW_ELEMENT_PATTERN {allow_pattern!r} rejects. A "
                "scope element the tool offers and the Guardian will not parse is a token request "
                "the model can compose and the Guardian must refuse"
            )
    claim = AllowClaim(**{field: tuple(values) for field, values in samples.items()})
    assert claim.verbs and claim.resources and claim.namespaces

    assert properties["executor_id"]["maxLength"] == _guardian_constant("IDENTIFIER_MAX_CHARS"), (
        "issue_capability_token.executor_id's bound and the Guardian's Identifier bound disagree"
    )
    for field in samples:
        assert properties[field]["maxItems"] == _guardian_constant("ALLOW_ELEMENT_MAX_ITEMS"), (
            f"issue_capability_token.{field}'s maxItems and the Guardian's "
            "ALLOW_ELEMENT_MAX_ITEMS disagree"
        )


# Dimensions the tool schemas leave unbounded that the Guardian bounds. Each would be a value a
# model can compose, that the tool-calling layer accepts, and that the Guardian refuses with
# `policy.request-malformed` -- costing a tool call from a declared budget and writing an audit row,
# where a `maxLength` in the schema would have let the model retry for free.
#
# THE SET IS EMPTY, AND IT IS STILL PINNED
# It was not empty when this test was written: `agents/tools/registry.py` stated that reasoning for
# `justification` and applied it to `namespace` and `name` only, leaving eight dimensions to the
# Guardian. Closing them was the fix, and this line is the other half of the same diff -- the
# constant's own comment required it, because a set that only ever grew would be an inventory of
# defects nobody was obliged to shrink.
#
# It stays here empty rather than being deleted with the last entry, and that is the point of the
# assertion below rather than an oversight. The test now says "the tool schema is nowhere laxer than
# the contract behind it", which is a stronger claim than any list of exceptions, and the first
# dimension that reopens fails it. A deleted constant would have to be reinvented by whoever noticed
# the next gap, which is to say by nobody until an audited denial in a campaign made it visible.
UNBOUNDED_TOOL_DIMENSIONS: frozenset[str] = frozenset()


def test_the_dimensions_the_tool_leaves_to_the_guardian_are_exactly_these() -> None:
    """The tool schema is nowhere laxer than the contract behind it, and the set is empty.

    Read the constant's comment for what an entry would cost and for why the constant survives its
    last entry. The test fails when a dimension reopens **and** when one is closed without deleting
    its line, so the schema and the inventory can never drift apart in either direction.
    """
    action = ACTION_TOOL.schema["properties"]
    issuance = ISSUE_TOKEN_TOOL.schema["properties"]
    observed: set[str] = set()

    for field in ("verb", "resource"):
        if "maxLength" not in action[field]:
            observed.add(f"guardian_action.{field}.maxLength")
    if "maxProperties" not in action["params"]:
        observed.add("guardian_action.params.maxProperties")
    if "maxLength" not in action["params"]["additionalProperties"]:
        observed.add("guardian_action.params.additionalProperties.maxLength")
    if "pattern" not in issuance["executor_id"]:
        observed.add("issue_capability_token.executor_id.pattern")
    for field in ("verbs", "resources", "namespaces"):
        if "maxLength" not in issuance[field]["items"]:
            observed.add(f"issue_capability_token.{field}.items.maxLength")

    assert observed == UNBOUNDED_TOOL_DIMENSIONS, (
        "the set of dimensions the tool schemas leave to the Guardian has changed.\n"
        f"  newly unbounded: {sorted(observed - UNBOUNDED_TOOL_DIMENSIONS)}\n"
        f"  now bounded:     {sorted(UNBOUNDED_TOOL_DIMENSIONS - observed)}\n"
        "A new entry is a new class of audited denial the model could have avoided; a removed one "
        "is a fix, and its line here is deleted in the same diff"
    )


SUPPORTED_WRITE_PARAMS = {
    "replicas",
    "image_entry",
    "label_key",
    "label_value",
    "selector_key",
    "selector_value",
    "subject_kind",
    "subject_name",
    "subject_namespace",
}


def test_guardian_action_doc_names_exact_supported_write_parameters() -> None:
    """The one shared tool doc names every write parameter and no invented one (ADR-086)."""
    path = REPO_ROOT / "agents" / "prompts" / "blocks" / "tool.guardian-action.md"
    before_values = path.read_text(encoding="utf-8").split("Every value", 1)[0]
    documented = set(re.findall(r"`([a-z]+(?:_[a-z]+)*)`", before_values))
    assert documented == SUPPORTED_WRITE_PARAMS


# --------------------------------------------------------------------------------------------
# 3 and 4. Schema versions and routes
# --------------------------------------------------------------------------------------------


def test_the_contract_versions_the_client_stamps_are_the_guardians() -> None:
    """``ActionRequest`` is at v2 and ``TokenIssueRequest`` at v1 on both sides of the seam.

    ``schema_version`` is typed ``Literal[...]`` in the Guardian's models, so a mismatch is not a
    warning: every request the client sent would be refused as malformed, and a whole tier of runs
    would produce no decisions at all. The two versions are also independent -- ``ActionRequest``
    moved to v2 when M4-T4.0c added the presenting identity and the phase, and the issuance contract
    did not -- so they are checked separately rather than as one number.
    """
    assert ACTION_REQUEST_SCHEMA_VERSION == guardian_models.ACTION_REQUEST_SCHEMA_VERSION, (
        f"the client stamps ActionRequest schema_version {ACTION_REQUEST_SCHEMA_VERSION!r}; the "
        f"Guardian accepts {guardian_models.ACTION_REQUEST_SCHEMA_VERSION!r}"
    )
    assert TOKEN_ISSUE_SCHEMA_VERSION == guardian_models.TOKEN_ISSUE_SCHEMA_VERSION, (
        f"the client stamps TokenIssueRequest schema_version {TOKEN_ISSUE_SCHEMA_VERSION!r}; the "
        f"Guardian accepts {guardian_models.TOKEN_ISSUE_SCHEMA_VERSION!r}"
    )


def test_the_routes_the_client_speaks_are_the_guardians() -> None:
    """The three path constants agree, name for name.

    ``docs/plans/M3-implementation-plan.md``'s T3.1 fixes the surface as ``POST /v1/actions``,
    ``POST /v1/tokens`` and ``GET /healthz``, and the client's own module docstring lists them as a
    copy across the component boundary held equal by a test. This is it.
    """
    for label, client_path, guardian_path in (
        ("ACTIONS_PATH", ACTIONS_PATH, guardian_main.ACTIONS_PATH),
        ("TOKENS_PATH", TOKENS_PATH, guardian_main.TOKENS_PATH),
        ("HEALTH_PATH", HEALTH_PATH, guardian_main.HEALTH_PATH),
    ):
        assert client_path == guardian_path, (
            f"{label}: the client speaks {client_path!r} and guardian/app/main.py serves "
            f"{guardian_path!r}"
        )


def test_the_assembled_guardian_serves_those_four_routes_and_no_others(
    guardian: InProcessGuardian,
) -> None:
    """Constants agreeing is not the same as an application serving them.

    Asserted over the real assembled app -- ``guardian/app/composition.py``'s output, driven through
    its own route handlers with only the socket removed -- so a route renamed in a decorator and
    left alone in the constant would fail here. The "no others" half matters as much: the Guardian's
    surface is four routes, and its OpenAPI schema and both documentation UIs are disabled because
    they are attacker-reachable surface serving a need the repository already meets.

    Three of the four are the routes the agent client speaks (``POST /v1/actions``, ``POST
    /v1/tokens``, ``GET /healthz``). The fourth is ``POST /v1/phase``, M10's control-plane phase
    channel (ADR-128, V17): the *runner* declares the run's phase there so issuance bounds a mint to
    the actual phase rather than a self-declared one, and the agent client never speaks it -- which
    is
    why it is read from ``guardian/app/main.py`` here rather than added to the client's own path
    constants. The set is still exact, so a fifth route -- surface nothing in this repository asks
    for
    -- fails here.
    """
    served = {
        route.path
        for route in guardian.assembled.app.routes
        if isinstance(getattr(route, "path", None), str) and route.path.startswith("/")
    }
    expected = {ACTIONS_PATH, TOKENS_PATH, HEALTH_PATH, guardian_main.PHASE_PATH}
    assert served == expected, (
        f"the assembled Guardian serves {sorted(served)}; the surface this repository asks for is "
        f"{sorted(expected)} -- the client's three routes plus the runner's control-plane phase "
        "channel. Any other route is surface nothing here asks for"
    )


# --------------------------------------------------------------------------------------------
# 5. The closed phase-outcome vocabulary
# --------------------------------------------------------------------------------------------


def test_the_completion_tool_offers_exactly_the_registry_vocabulary() -> None:
    """``complete_phase``'s ``outcome`` enum is ``PHASE_OUTCOMES``, built from it and not beside it.

    Three values and no fourth: a phase either reached what it set out to do, could not, or ran out
    of the budget its composition manifest declared. ``budget-exhausted`` is a first-class outcome
    rather than an error for ADR-028's reason -- if exhausting a declared budget were an exception,
    an arm that struggled would look broken rather than bounded and the ablation would read model
    weakness as a design failure.
    """
    offered = COMPLETE_PHASE_TOOL.schema["properties"]["outcome"]["enum"]
    assert tuple(offered) == PHASE_OUTCOMES, (
        f"complete_phase offers {tuple(offered)} and the registry declares {PHASE_OUTCOMES}; the "
        "enum is built from the tuple so the two cannot be separately edited"
    )
    assert len(set(PHASE_OUTCOMES)) == len(PHASE_OUTCOMES), (
        f"PHASE_OUTCOMES carries a duplicate: {PHASE_OUTCOMES}"
    )


def _code_string_constants(path: Path) -> tuple[tuple[int, str], ...]:
    """Every string constant in a module that is not a docstring, with its line number.

    A docstring is a string standing alone as a statement -- the interpreter discards the value, so
    it can reach no comparison and no prompt. Both :mod:`agents.graphs.nodes` and
    :mod:`agents.registry.model` name ``budget-exhausted`` in their prose while importing the tuple
    in their code, which is exactly the arrangement this scan is meant to permit.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    discarded = {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    }
    return tuple(
        (node.lineno, node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in discarded
    )


def test_no_shipped_module_re_spells_a_phase_outcome() -> None:
    """The vocabulary is written once, in the tool registry, and imported everywhere else.

    ``analysis/stats/`` counts these strings out of sealed run bundles. A module that spelled
    ``"blocked"`` itself would be a second definition that nothing keeps in step with the first, and
    the failure would be invisible: both spellings are valid Python and one of them would quietly
    stop matching after a rename. :mod:`agents.graphs.nodes` shows the intended shape -- it binds
    ``_OUTCOME_RESOLVED = PHASE_OUTCOMES[0]`` and never types the word.

    ``agents/tests/`` is outside the scan, because a test must be able to spell a value in order to
    assert over it -- this file spells all three, three paragraphs up.
    """
    offenders: list[str] = []
    scanned: list[str] = []
    for directory in SHIPPED_AGENT_DIRECTORIES:
        for path in sorted(directory.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            scanned.append(path.name)
            if path == PHASE_OUTCOME_HOME:
                continue
            for line, text in _code_string_constants(path):
                if text in PHASE_OUTCOMES:
                    where = path.relative_to(REPO_ROOT).as_posix()
                    offenders.append(f"{where}:{line}: {text!r}")

    assert len(scanned) >= 12, f"the scan read only {len(scanned)} module(s): {scanned}"
    assert not offenders, (
        "phase outcome(s) re-spelled outside agents/tools/registry.py:\n"
        + "\n".join(offenders)
        + f"\n\nImport PHASE_OUTCOMES and index it. The vocabulary is {PHASE_OUTCOMES}, it is "
        "closed, and it is closed exactly to the extent that something checks it is"
    )


def test_the_home_module_really_does_spell_the_vocabulary() -> None:
    """The one exclusion above is an exclusion of the definition, not of an unchecked file.

    Without this, deleting the tuple's literals -- or moving the definition elsewhere -- would leave
    the scan above passing over a repository in which nothing defines the vocabulary at all.
    """
    spelled = {text for _, text in _code_string_constants(PHASE_OUTCOME_HOME)}
    missing = sorted(set(PHASE_OUTCOMES) - spelled)
    assert not missing, (
        f"{PHASE_OUTCOME_HOME.relative_to(REPO_ROOT).as_posix()} does not spell {missing}; the "
        "vocabulary's single home is somewhere else now, and the scan above is excluding the "
        "wrong file"
    )


@pytest.mark.parametrize("outcome", PHASE_OUTCOMES)
def test_each_outcome_is_a_plain_lowercase_token(outcome: str) -> None:
    """Countable, comparable, and the same string in a trace, a bundle and a statistics script.

    Free text fails all three: it cannot be counted, it cannot be compared across arms, and two
    spellings of one refusal become two phenomena in Chapter 4. The shape is asserted because it is
    what makes the value usable as a key without normalisation anywhere downstream.
    """
    assert outcome == outcome.strip().lower(), f"{outcome!r} carries case or surrounding space"
    assert re.fullmatch(r"[a-z]+(?:-[a-z]+)*", outcome), (
        f"{outcome!r} is not a lowercase hyphenated token; analysis/stats/ uses these as keys"
    )
