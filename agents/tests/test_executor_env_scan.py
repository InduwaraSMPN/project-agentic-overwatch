r"""FR3.1's second property, *no standing credentials*, scanned rather than trusted.

WHAT THIS FILE PINS
-------------------
``docs/milestones/M4-agents.md``'s Definition of done names this file: "Executors hold no standing
credentials and every mutation goes through the Guardian" [T-07, T-09].
``agents/tests/test_executor_lifecycle.py`` holds the other half of FR3.1, lifetime, and the split
is the M4 plan's rather than a convenience -- an object that dies on schedule while a signing key
sits in the environment beside it satisfies neither requirement, and a scan that only looked at
objects would report the second as clean.

Three scans, and the same rule governs all three: **the check is negative, so it has to be shown
capable of failing.** An empty result from a scanner that never matched anything is
indistinguishable from an empty result from a scanner that works, and the empty one is what a
regression looks like. So every scan below is paired with a case that plants exactly what it is
looking for and asserts the scan reports it. ``agents/tests/conftest.py`` states the reason this
file exists in that form -- "an executor can hold a credential that nothing looks for" -- and a
scanner that cannot fail is the version of that sentence where the credential is held and the
looking is theatre.

*No configuration key.* Nothing in the environment an executor node runs in may carry the Guardian's
``GUARDIAN_`` prefix. That namespace is the Guardian's alone: ``guardian/app/config.py`` reads every
one of its settings from it, and the prefix is what makes "no request field can contribute a key to
this namespace" checkable. A ``GUARDIAN_SIGNING_KEY`` visible to agent code would be the signing key
itself -- ``.agents/rules/10-guardian-first.md`` forbids copying it anywhere, tests included -- and
a ``GUARDIAN_MODE`` visible to agent code would hand the guardrail ablation's arm to the thing being
ablated, which ADR-023 exists to prevent.

*No credential-shaped name.* The rule is :data:`guardian.app.models.SECRET_SHAPED_FIELD_NAMES` and
its normalisation, **imported rather than re-authored**. That set already governs what an
audit-chain model may be called; the same words are what a credential in an environment is called,
and writing a fourth list here would create a fourth thing to keep in step. Its exactness is worth
stating: it matches a normalised name, not a substring, so ``API_KEY`` is caught and
``GITHUB_TOKEN_PATH`` is not. That is deliberate -- a substring rule over ninety environment
variables is a rule that fires on prose -- and it is why the lifecycle file scans for a token *by
value* as well.

*None of rule 10's subjects.* ``scripts/grep_guard.sh`` scans every tracked file under ``agents/``
for five patterns and has no exemption mechanism. It checks *files*; this checks the *environment*,
which is the half a file scan structurally cannot see -- an agent that reached the cluster directly
would need a path to a cluster credential, and the environment is where one arrives. The five
patterns are **read out of the script at run time** rather than restated, for two reasons. A copy
would drift the moment a sixth pattern was added there. And, more immediately: this file is itself a
tracked file under ``agents/``, so a literal copy of the patterns' subjects would make the guard
fail on the test that checks the guard. ``scripts/grep_guard.sh``'s own header states the discipline
this file follows -- "the prose moves, not the check".

WHAT THE AGENT LAYER MAY READ FROM THE ENVIRONMENT, AND WHY IT IS EXACTLY THAT
--------------------------------------------------------------------------------
Three keys, all in :mod:`agents.registry.model`, all named there with the reason: ``MODEL_ALIAS``
and ``MODEL_PROVIDER_STRING`` are what ADR-005's alias resolves through, "read from the environment
rather than from versions.env directly because the agent layer ships as a container image with no
``infra/`` tree in it"; and ``RUNNER_SCRIPTED`` is the NAME of the flag the RUNNER reads to select a
scripted P1a run (M10 plan section 6, ``RUNNER_SCRIPTED=1``). The agent layer declares the last one
beside :class:`~agents.registry.model.ScriptedClient` and never reads it -- ``runner/provenance.py``
and ``runner/live_run.py`` are its readers -- because a constant two processes must agree on belongs
where one edit moves both, exactly as ``SCRIPTED_PROVIDER_STRING`` does. None of the three is a
credential and none is the Guardian's. The last two cases below assert that set both syntactically
-- one shipped module touches the environment at all -- and behaviourally, by handing
:func:`agents.registry.model.resolve_provider_string` a mapping that records which keys it looked
up.

WHAT IS DELIBERATELY NOT HERE
------------------------------
*A value judgement about a credential's contents.* A scan cannot tell a random-looking string in
``FOO`` from a random-looking password in ``FOO``. What it can tell is that the name is one nobody
should be reading and that the namespace is one nobody should be in, which is what these scans do.

*The agent layer's own test suite.* ``agents/tests/`` is not shipped, does not run in a campaign,
and legitimately builds the Guardian's configuration mapping -- ``agents/tests/harness.py`` is where
the ``GUARDIAN_`` keys of this suite live, as a dictionary that is never written into
``os.environ``. The module scan below names that exclusion explicitly and asserts the excluded set
is exactly that one directory, so a second exclusion cannot be added quietly.

*Anything written into the real environment.* Every plant below goes through ``monkeypatch``, which
restores it. A suite that wrote to ``os.environ`` directly would leak one case's plant into the
next, and the case that then failed would be the innocent one.
"""

from __future__ import annotations

import ast
import os
import re
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any, Final

import pytest
from agents.graphs import hier
from agents.graphs.nodes import NodeContext, bounded_execution_node
from agents.registry import PHASES
from agents.registry.composer import compose_condition
from agents.registry.loader import PromptRegistry
from agents.registry.model import (
    MODEL_ALIAS_ENV_VAR,
    MODEL_PROVIDER_STRING_ENV_VAR,
    RUNNER_SCRIPTED_ENV_VAR,
    ModelCall,
    ModelResponse,
    ModelUnavailable,
    ToolCall,
    resolve_provider_string,
)
from agents.tools.registry import ACTION_TOOL, COMPLETE_PHASE_TOOL, PHASE_OUTCOMES
from guardian.app.config import ENV_PREFIX
from guardian.app.models import SECRET_SHAPED_FIELD_NAMES, _normalise_field_name
from harness import REPO_ROOT, InProcessGuardian, node_context

# The condition and the phase these cases drive one real node from. Both come from the closed
# vocabularies their own modules fix -- agents/graphs/hier.py names the condition it composes so
# that agents/graphs/__init__.py's mapping can be checked against it, and agents/registry/
# __init__.py fixes the four phase spellings that travel into the Guardian's contract.
CONDITION: Final = hier.CONDITION
CONTAINMENT: Final = PHASES[1]

# The three keys the agent layer is permitted to declare, taken from the module that declares them
# so that this allowlist and the code it governs cannot disagree. Two are ADR-005's model identity
# -- an alias and the provider string it resolves to. The third, ``RUNNER_SCRIPTED``, is the
# runner's scripted-run flag: declared here so the runner and the client share one spelling, and
# read only by the runner (M10 plan section 6). None is a credential -- a provider *key* is
# LiteLLM's to read from its own environment inside the Tier A' client, never the graph's -- and
# none is in the Guardian's namespace, which the first assertion of the last case restates as a
# property rather than leaving to inspection.
JUSTIFIED_ENVIRONMENT_KEYS: Final = frozenset(
    {MODEL_ALIAS_ENV_VAR, MODEL_PROVIDER_STRING_ENV_VAR, RUNNER_SCRIPTED_ENV_VAR}
)

# The one directory under agents/ excluded from the module scan, named rather than globbed. See the
# module docstring: the suite is not shipped and legitimately builds the Guardian's configuration
# mapping. Written as a one-element set so that adding a second exclusion is a visible edit to a
# list somebody has to justify, which is the shape .agents/rules/10 and 40 both insist on.
UNSHIPPED_AGENT_DIRECTORIES: Final = frozenset({"tests"})

# The names by which the standard library's environment is reached. `environb` is included although
# nothing uses it: a scan that listed only the spellings currently in the tree would be a scan that
# passed the day somebody used a different one.
ENVIRONMENT_ACCESSOR_NAMES: Final = frozenset({"environ", "environb", "getenv"})

# scripts/grep_guard.sh invokes its patterns through one shell function, one per line, and this is
# that line's shape. Parsed rather than copied -- see the module docstring for the two reasons.
GREP_GUARD_SCRIPT: Final = REPO_ROOT / "scripts" / "grep_guard.sh"
GREP_GUARD_SCAN_LINE: Final = re.compile(r"^scan +(\S+) +'([^']*)'\s*$", re.MULTILINE)

# The number of patterns that script declares. Asserted rather than assumed, because a parse that
# silently found none would make every rule-10 assertion below pass over an empty list -- the exact
# failure mode this whole file is written against.
GREP_GUARD_PATTERN_COUNT: Final = 5

# POSIX character classes are grep's; Python's `re` does not know them. The one this project's
# patterns use is spelled out here rather than handled generically, because a translation layer
# that silently mistranslated an unknown class would weaken the scan without saying so.
POSIX_CLASS_TRANSLATIONS: Final = {"[[:space:]]": r"\s"}

# Scalars the context walk records or stops at without descending.
_WALK_SCALARS: Final = (int, float, bool, type(None))


# --------------------------------------------------------------------------------------------
# The environment an executor node actually runs in
# --------------------------------------------------------------------------------------------


class EnvironmentProbe:
    """A model double that snapshots ``os.environ`` at the moment a node calls it.

    The environment "visible to executor code" is the environment at the point the node body runs,
    not the one the test collected in. They are the same today and the distinction is the whole
    point of taking the snapshot from inside: a graph that populated the environment before
    dispatching to an Executor -- the obvious way somebody would pass a credential down without
    changing a signature -- would leave the outer view clean and the inner view carrying it.

    It decides nothing, per ``agents/tests/harness.py``'s rule about doubles: the answers are fixed
    by the test and consumed in order.
    """

    def __init__(self, answers: Sequence[ToolCall | None]) -> None:
        self._answers = list(answers)
        self.snapshots: list[dict[str, str]] = []

    def complete(self, call: ModelCall) -> ModelResponse:
        """Snapshot the environment, then answer what the test said to answer."""
        del call
        self.snapshots.append(dict(os.environ))
        answer = self._answers.pop(0) if self._answers else None
        return ModelResponse(tool_call=answer, provider_string="scripted/env-probe", attempts=1)


@pytest.fixture
def executor_environment(guardian: InProcessGuardian, registry: PromptRegistry) -> dict[str, str]:
    """The process environment as it stood inside a running bounded-execution node.

    A real node from the real ``S1-HIER`` composition, allocated the manifest's own budget, so what
    is observed is the environment of the thing that runs in a campaign rather than of a stand-in
    for it.
    """
    composition = registry.compositions[CONDITION]
    probe = EnvironmentProbe(
        [
            ToolCall(
                name=COMPLETE_PHASE_TOOL.name,
                arguments={"outcome": PHASE_OUTCOMES[0], "summary": "nothing to do"},
            )
        ]
    )
    executor = bounded_execution_node(
        compose_condition(registry, CONDITION).role("executor"),
        budget=composition.budgets[CONTAINMENT]["executor"],
        tools=[ACTION_TOOL.name, COMPLETE_PHASE_TOOL.name],
    )
    executor(node_context(guardian, model=probe), CONTAINMENT)
    assert probe.snapshots, (
        "the bounded-execution node never called the model, so no environment was observed from "
        "inside it. Every case in this file reads that snapshot; an empty one would make them all "
        "pass over nothing"
    )
    return probe.snapshots[0]


# --------------------------------------------------------------------------------------------
# The three scans
# --------------------------------------------------------------------------------------------


def configuration_keys(environ: Mapping[str, str]) -> list[str]:
    """Every key in ``environ`` inside the Guardian's configuration namespace."""
    return sorted(key for key in environ if key.startswith(ENV_PREFIX))


def credential_shaped_keys(environ: Mapping[str, str]) -> list[str]:
    """Every key in ``environ`` whose normalised name is one the credential rule forbids."""
    return sorted(key for key in environ if _normalise_field_name(key) in SECRET_SHAPED_FIELD_NAMES)


def grep_guard_patterns() -> tuple[tuple[str, str], ...]:
    """Return ``(name, extended-regex)`` for every pattern ``scripts/grep_guard.sh`` scans for.

    Read from the script rather than restated. The path is derived from this file's own location
    through :data:`harness.REPO_ROOT`, so nothing here depends on the working directory --
    ``agents/tests/conftest.py`` inherits that contract from ``monitor/tests/__init__.py`` and it
    binds this file too.
    """
    script = GREP_GUARD_SCRIPT.read_text(encoding="utf-8")
    return tuple((name, pattern) for name, pattern in GREP_GUARD_SCAN_LINE.findall(script))


def as_python_regex(pattern: str) -> str:
    """Translate one of the script's extended regexes into the dialect :mod:`re` speaks."""
    translated = pattern
    for posix, python in POSIX_CLASS_TRANSLATIONS.items():
        translated = translated.replace(posix, python)
    return translated


def environment_document(environ: Mapping[str, str]) -> str:
    """Render ``environ`` as the document the rule-10 patterns are applied to.

    Every key on its own line and every value on its own line, because two of the five patterns are
    anchored at the start of a line: a value spelled as an import statement would be invisible in a
    ``KEY=value`` rendering and is exactly the shape pattern 1 exists to catch. Keys and values are
    both scanned because a pointer to a cluster credential is a *value*, and the variable holding
    it is a *name*, and rule 10's patterns cover both kinds of subject.
    """
    return "\n".join([*environ.keys(), *environ.values()])


def rule_ten_hits(environ: Mapping[str, str]) -> list[str]:
    """Every rule-10 pattern that matches anything in ``environ``, named with what it matched."""
    document = environment_document(environ)
    hits: list[str] = []
    for name, pattern in grep_guard_patterns():
        found = re.search(as_python_regex(pattern), document, re.MULTILINE)
        if found is not None:
            hits.append(f"{name}: {found.group(0)!r}")
    return hits


def sample_matching(pattern: str) -> str:
    """Generate one string that ``pattern`` matches, from the pattern itself.

    The rule-10 scan needs a positive control, and a control written as a literal would be a copy
    of the very subjects ``scripts/grep_guard.sh`` scans this directory for -- so the control would
    fail the guard it is checking. Deriving the sample from the pattern avoids that and buys
    something better besides: the control cannot drift from the script, because it *is* the script's
    pattern, read at run time and walked.

    The walk handles exactly the constructs those five patterns use -- a start anchor, word
    boundaries, escaped literals, one POSIX class with a quantifier, a parenthesised alternation,
    an optional group, and top-level alternation -- and takes the first branch of every choice.
    Anything else is emitted literally, which will produce a string the pattern does not match, and
    the case asserts the match rather than assuming it: an unhandled construct fails loudly instead
    of silently generating a control that proves nothing.
    """
    out: list[str] = []
    index = 0
    while index < len(pattern):
        for posix in POSIX_CLASS_TRANSLATIONS:
            if pattern.startswith(posix, index):
                index += len(posix)
                if index < len(pattern) and pattern[index] in "*+":
                    out.append(" " if pattern[index] == "+" else "")
                    index += 1
                else:
                    out.append(" ")
                break
        else:
            character = pattern[index]
            if character == "^":
                index += 1
            elif character == "\\":
                if pattern[index + 1] != "b":
                    out.append(pattern[index + 1])
                index += 2
            elif character == "(":
                closed = _closing_parenthesis(pattern, index)
                optional = closed + 1 < len(pattern) and pattern[closed + 1] == "?"
                if not optional:
                    out.append(sample_matching(_first_branch(pattern[index + 1 : closed])))
                index = closed + (2 if optional else 1)
            elif character == "|":
                break
            else:
                out.append(character)
                index += 1
    return "".join(out)


def _closing_parenthesis(pattern: str, opened: int) -> int:
    """Return the index of the group opened at ``opened``, respecting escapes and nesting."""
    depth = 0
    index = opened
    while index < len(pattern):
        if pattern[index] == "\\":
            index += 2
            continue
        if pattern[index] == "(":
            depth += 1
        elif pattern[index] == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    raise AssertionError(f"unbalanced group in the pattern {pattern!r} read from grep_guard.sh")


def _first_branch(alternation: str) -> str:
    """Return the first top-level branch of ``alternation``, respecting nesting and escapes."""
    depth = 0
    index = 0
    while index < len(alternation):
        if alternation[index] == "\\":
            index += 2
            continue
        if alternation[index] == "(":
            depth += 1
        elif alternation[index] == ")":
            depth -= 1
        elif alternation[index] == "|" and depth == 0:
            return alternation[:index]
        index += 1
    return alternation


# --------------------------------------------------------------------------------------------
# The environment visible where an executor runs
# --------------------------------------------------------------------------------------------


def test_no_guardian_configuration_key_is_visible_where_an_executor_runs(
    executor_environment: dict[str, str],
) -> None:
    """The Guardian's whole configuration namespace is absent from the executor's environment.

    ``guardian/app/config.py`` reads every setting it has from this prefix -- the signing key, the
    arm, the token lifetimes, the policy entrypoints. One of them visible here would be a standing
    credential or a readable arm, and both are things FR3.1 and ADR-023 respectively require the
    agent layer not to have. The prefix constant is imported from that module rather than spelled,
    so a rename there is caught here instead of quietly emptying this scan.
    """
    found = configuration_keys(executor_environment)
    assert found == [], (
        f"the environment an Executor runs in carries the Guardian configuration key(s) {found}. "
        f"The {ENV_PREFIX} namespace belongs to the Guardian process alone: a signing key there is "
        "the credential rule 10 forbids copying anywhere, and a mode there is the guardrail arm "
        "ADR-023 keeps out of the agent layer's reach. If a shell exported one for a local "
        "Guardian, unset it for this run rather than narrowing the scan"
    )


def test_no_credential_shaped_name_is_visible_where_an_executor_runs(
    executor_environment: dict[str, str],
) -> None:
    """No environment variable is *called* what a credential is called.

    The rule is the Guardian's own -- :data:`guardian.app.models.SECRET_SHAPED_FIELD_NAMES` with
    :func:`guardian.app.models._normalise_field_name`, imported rather than re-authored, so that
    ``api_key``, ``API-KEY`` and ``apiKey`` are one entry and this file holds no list to keep in
    step. The private normaliser is reached across the underscore deliberately: the alternative is
    a fourth spelling of a rule that already has three readers, and a rule spelled twice is a rule
    that will differ.
    """
    found = credential_shaped_keys(executor_environment)
    assert found == [], (
        f"the environment an Executor runs in carries credential-shaped variable(s) {found}. "
        "FR3.1 gives an Executor no standing credentials, and a process environment is the most "
        "visible place a credential can stand: everything in the process reads it, it survives "
        "every phase, and nothing hands it over -- which is exactly what 'standing' means"
    )


def test_no_rule_ten_subject_is_visible_where_an_executor_runs(
    executor_environment: dict[str, str],
) -> None:
    """The five patterns ``scripts/grep_guard.sh`` scans files for find nothing in the environment.

    Rule 10's guard reads tracked files, which is the right scope for an import or a shell-out and
    the wrong scope for the thing that actually lets code reach a cluster: a pointer to a
    credential, arriving as an environment variable. This is that half. The patterns are the
    script's own, read at run time, so the two checks cover the same subjects by construction
    rather than by a copy somebody keeps in step.
    """
    patterns = grep_guard_patterns()
    assert len(patterns) == GREP_GUARD_PATTERN_COUNT, (
        f"{len(patterns)} pattern(s) were parsed out of {GREP_GUARD_SCRIPT.name}, and rule 10 "
        f"declares {GREP_GUARD_PATTERN_COUNT}. Either the script gained one -- in which case this "
        "constant moves with it -- or the parse stopped matching its scan lines, in which case "
        "every rule-10 assertion in this file has been passing over an empty list"
    )
    hits = rule_ten_hits(executor_environment)
    assert hits == [], (
        f"the environment an Executor runs in matches rule-10 pattern(s) {hits}. "
        ".agents/rules/10-guardian-first.md gives the agent layer exactly one route to the "
        "cluster, the Guardian client, and a variable naming a cluster credential or a cluster "
        "tool is the ambient alternative to it. scripts/grep_guard.sh has no exemption mechanism "
        "by design and neither does this: unset the variable for the run"
    )


# --------------------------------------------------------------------------------------------
# The scans are shown to be capable of failing
# --------------------------------------------------------------------------------------------


def test_the_configuration_scan_catches_a_planted_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Plant a Guardian setting in the environment and assert the scan reports it."""
    planted = f"{ENV_PREFIX}SIGNING_KEY"
    monkeypatch.setenv(planted, "planted by a test; restored by monkeypatch")

    assert planted in configuration_keys(os.environ), (
        f"the configuration scan did not report {planted!r} after it was planted in the "
        "environment. The clean result in the case above would then mean nothing: a scanner that "
        "cannot fail is not evidence that there is nothing to find"
    )


def test_the_credential_scan_catches_planted_names_in_every_spelling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Plant three spellings of one credential name and assert the normalisation catches all three.

    One plant would show only that the scan matches the spelling it was handed. Three show what the
    imported rule is *for*: the set is written in one normalised form, and a credential smuggled in
    under a different convention is the case that motivated normalising at all.

    The comparison is made on normalised names rather than on the strings that were planted, and
    that is not a convenience either -- Windows folds environment variable names to upper case, so
    a case-sensitive comparison here would pass on one platform's CI runner and fail on another's
    developer machine for a reason that has nothing to do with the property.
    """
    spellings = ("API_KEY", "apikey", "Api-Key")
    for spelling in spellings:
        monkeypatch.setenv(spelling, "planted by a test; restored by monkeypatch")

    found = credential_shaped_keys(os.environ)
    reported = {_normalise_field_name(key) for key in found}
    missed = sorted(
        spelling for spelling in spellings if _normalise_field_name(spelling) not in reported
    )
    assert missed == [], (
        f"the credential scan missed the planted variable(s) {missed} while reporting {found}. "
        "guardian.app.models._normalise_field_name folds case, underscores, hyphens and dots so "
        "that one entry covers every spelling; a miss here means this file is applying the rule "
        "differently from the way the Guardian's own contract guards apply it"
    )


def test_the_rule_ten_scan_catches_a_planted_subject_for_every_pattern(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """For each of the five patterns, plant a string it matches and assert the scan reports it.

    Per pattern rather than once, because the scan runs five independent searches and a mistake in
    translating any one of them -- the POSIX character class, the anchored alternation -- would
    silently disable that one while the other four went on passing. Each planted string is
    generated from the pattern it is meant to trip, so this case cannot drift from the script and
    contains no copy of the subjects the guard scans this directory for.
    """
    patterns = grep_guard_patterns()
    assert len(patterns) == GREP_GUARD_PATTERN_COUNT, (
        f"{len(patterns)} pattern(s) parsed; rule 10 declares {GREP_GUARD_PATTERN_COUNT}"
    )
    for name, pattern in patterns:
        planted = sample_matching(pattern)
        assert re.search(as_python_regex(pattern), planted, re.MULTILINE), (
            f"the sample generated for rule-10 pattern {name!r} ({planted!r}) does not match the "
            f"pattern it came from ({pattern!r}). The generator handles the constructs those five "
            "patterns use and asserts rather than assumes, so this means the script now uses one "
            "it does not handle -- extend the generator, do not drop the control"
        )
        with monkeypatch.context() as planting:
            planting.setenv("AGENTS_SUITE_RULE_TEN_PROBE", planted)
            hits = rule_ten_hits(os.environ)
        assert any(hit.startswith(f"{name}:") for hit in hits), (
            f"the rule-10 scan did not report pattern {name!r} after a string matching it was "
            f"planted in the environment as a value ({planted!r}); it reported {hits}. That "
            "pattern is currently scanning for nothing, and the clean result in the case above "
            "says nothing about it"
        )


# --------------------------------------------------------------------------------------------
# The other direction: what the NodeContext itself carries
# --------------------------------------------------------------------------------------------


def context_data_findings(context: NodeContext) -> tuple[list[str], list[str]]:
    """Walk the context's own data and return ``(configuration values, credential-shaped keys)``.

    The walk descends through strings, mappings and sequences -- data -- and **stops at
    collaborators**, which are objects with behaviour rather than values a node carries. That
    boundary is not a convenience: descending into the Guardian client would reach, through its
    transport's closure, the whole in-process Guardian and then the module globals of
    :mod:`guardian.app.config`, where every ``GUARDIAN_`` key legitimately lives as a constant. A
    walk that reported those would be reporting the Guardian's own source, and the finding would be
    unfixable noise rather than a defect.

    The boundary is made checkable rather than trusted: :func:`stopped_collaborators` returns what
    the walk declined to enter, and the case below asserts it is exactly the three collaborators
    :class:`~agents.graphs.nodes.NodeContext` declares. A new *data* field is therefore walked
    automatically, and a new *collaborator* field fails until somebody decides which it is.
    """
    values: list[str] = []
    keys: list[str] = []
    for name, value in vars(context).items():
        if _normalise_field_name(name) in SECRET_SHAPED_FIELD_NAMES:
            keys.append(f"NodeContext.{name}")
        for text, path in _walk_data(value, f"NodeContext.{name}"):
            if text.startswith(ENV_PREFIX):
                values.append(f"{path} = {text!r}")
    for name, value in vars(context).items():
        for key, path in _walk_keys(value, f"NodeContext.{name}"):
            if _normalise_field_name(key) in SECRET_SHAPED_FIELD_NAMES:
                keys.append(f"{path}[{key!r}]")
    return sorted(values), sorted(keys)


def stopped_collaborators(context: NodeContext) -> list[str]:
    """The context's fields the data walk declined to enter, because they are not data."""
    walkable = (str, bytes, Mapping, list, tuple, set, frozenset, *_WALK_SCALARS)
    return sorted(name for name, value in vars(context).items() if not isinstance(value, walkable))


def _walk_data(value: Any, path: str) -> Iterator[tuple[str, str]]:
    """Yield every ``(string, path)`` reachable from ``value`` through containers only."""
    if isinstance(value, str):
        yield value, path
    elif isinstance(value, bytes):
        yield value.decode("utf-8", "replace"), path
    elif isinstance(value, Mapping):
        for key, nested in value.items():
            yield from _walk_data(nested, f"{path}[{key!r}]")
    elif isinstance(value, (list, tuple, set, frozenset)):
        for index, nested in enumerate(value):
            yield from _walk_data(nested, f"{path}[{index}]")


def _walk_keys(value: Any, path: str) -> Iterator[tuple[str, str]]:
    """Yield every ``(mapping key, path)`` reachable from ``value`` through containers only."""
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if isinstance(key, str):
                yield key, path
            yield from _walk_keys(nested, f"{path}[{key!r}]")
    elif isinstance(value, (list, tuple, set, frozenset)):
        for index, nested in enumerate(value):
            yield from _walk_keys(nested, f"{path}[{index}]")


def test_the_node_context_carries_no_configuration_value_and_no_credential_shaped_key(
    guardian: InProcessGuardian,
) -> None:
    """The object every node is handed carries run identifiers and evidence, and nothing else.

    ``agents/tests/harness.py`` records that no test may build a
    :class:`~agents.graphs.nodes.NodeContext` carrying a condition, a mode or a quoting flag,
    because no such field exists. This is the same statement made about the values rather than the
    fields: whatever is on the context at run time is a run identifier, a namespace, a seed or
    framed evidence -- never a setting out of the Guardian's namespace and never a value under a
    credential's name.
    """
    context = node_context(
        guardian,
        evidence={CONTAINMENT: [{"kind": "process", "detail": "an evidence event"}]},
    )

    values, keys = context_data_findings(context)

    assert values == [], (
        f"the NodeContext carries value(s) out of the Guardian's configuration namespace: "
        f"{values}. A node receives what the run gave it -- identifiers, a seed, framed evidence "
        "-- and the Guardian's settings reach the Guardian process at start and the agent layer "
        "never"
    )
    assert keys == [], (
        f"the NodeContext carries credential-shaped name(s) {keys}. FR3.1's 'no standing "
        "credentials' is about what an Executor holds, and the context is the one object every "
        "node holds for the whole run"
    )
    assert stopped_collaborators(context) == ["guardian", "model", "tracer"], (
        f"the data walk stopped at {stopped_collaborators(context)}, and it is written to stop at "
        "exactly the three collaborators NodeContext declares -- the Guardian client, the model "
        "and the tracer. A fourth means a field was added that this walk silently does not read: "
        "decide whether it is data (walk it) or a collaborator (extend this list and say why), "
        "because the one thing that must not happen is a field nobody scans"
    )


def test_the_context_scan_catches_planted_values_and_planted_keys(
    guardian: InProcessGuardian,
) -> None:
    """Plant a setting, a credential-shaped field and a credential-shaped nested key; catch all.

    Three plants because the walk has three ways to be wrong: it could miss a value, miss an
    attribute name, or fail to descend into the evidence mapping -- and the third is the one that
    matters most, since evidence is the only part of the context that carries structure a future
    change could hide something inside.
    """
    context = node_context(
        guardian,
        evidence={CONTAINMENT: [{"api-key": "planted by a test", "kind": "process"}]},
    )
    context.namespace = f"{ENV_PREFIX}SIGNING_KEY"
    object.__setattr__(context, "authorization", "planted by a test")

    values, keys = context_data_findings(context)

    assert any("namespace" in finding for finding in values), (
        f"the context scan did not report a Guardian configuration key planted as a field value; "
        f"it reported {values}. The clean result in the case above would then mean nothing"
    )
    assert "NodeContext.authorization" in keys, (
        f"the context scan did not report a credential-shaped attribute planted on the context; "
        f"it reported {keys}"
    )
    assert any("api-key" in finding for finding in keys), (
        f"the context scan did not report a credential-shaped key planted inside the evidence "
        f"mapping; it reported {keys}. The walk has to descend through the structured part of the "
        "context, or it is checking only the parts that were never going to hold anything"
    )


# --------------------------------------------------------------------------------------------
# What the shipped agent layer reads from the environment at all
# --------------------------------------------------------------------------------------------


def shipped_agent_modules() -> tuple[Path, ...]:
    """Every Python module under ``agents/`` that ships, in a deterministic order.

    Deterministic because a failure message names the offending file and a message that moves
    between runs is a message nobody trusts -- ``guardian/app/models.py`` gives that reason for its
    own traversal and it applies here.
    """
    root = REPO_ROOT / "agents"
    return tuple(
        sorted(
            path
            for path in root.rglob("*.py")
            if not (UNSHIPPED_AGENT_DIRECTORIES & set(path.relative_to(root).parts))
            and "__pycache__" not in path.parts
        )
    )


def environment_accesses(source: str) -> list[int]:
    """Return the line numbers at which ``source`` reaches the process environment.

    Three spellings are recognised: ``os.environ`` and friends as an attribute, a bare name
    imported by ``from os import environ``, and ``os.getenv``. A grep would find the first and miss
    the second, which is the shape ``scripts/grep_guard.sh``'s own header warns about when it
    explains why an import grep alone is trivially defeated.
    """
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "os":
            imported.update(
                alias.asname or alias.name
                for alias in node.names
                if alias.name in ENVIRONMENT_ACCESSOR_NAMES
            )
    lines: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in ENVIRONMENT_ACCESSOR_NAMES:
            lines.append(node.lineno)
        elif isinstance(node, ast.Name) and node.id in imported:
            lines.append(node.lineno)
    return sorted(set(lines))


def declared_environment_keys(source: str) -> dict[str, str]:
    """Return every ``*_ENV_VAR`` constant declared in ``source``, as ``{name: value}``.

    The naming convention is this repository's own -- ``guardian/app/config.py`` names all
    seventeen of its keys that way -- so a new environment key added under ``agents/`` following
    house style is caught by this even if the code that reads it is written in a shape the AST
    accessor scan does not recognise. Two scans over one property, for the reason rule 40 gives for
    having three: a guard that cannot see a violation is not evidence that none exists.
    """
    declared: dict[str, str] = {}
    for node in ast.walk(ast.parse(source)):
        targets = (
            node.targets
            if isinstance(node, ast.Assign)
            else [node.target]
            if isinstance(node, ast.AnnAssign)
            else []
        )
        value = getattr(node, "value", None)
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            continue
        for target in targets:
            if isinstance(target, ast.Name) and target.id.endswith("_ENV_VAR"):
                declared[target.id] = value.value
    return declared


class RecordingEnvironment(Mapping[str, str]):
    """A mapping that records every key looked up in it. The behavioural half of the key scan.

    An AST scan says where the environment is *touched*; it cannot say which keys are read, because
    :func:`agents.registry.model.resolve_provider_string` reaches them through a local alias and a
    ``.get`` -- which is correct code and opaque to syntax. Handing it this instead answers the
    question directly: whatever it looks up is recorded, whichever expression it used to get there.
    """

    def __init__(self, values: Mapping[str, str]) -> None:
        self._values = dict(values)
        self.read: list[str] = []

    def __getitem__(self, key: str) -> str:
        self.read.append(key)
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)


def test_exactly_one_shipped_agent_module_touches_the_process_environment() -> None:
    """One module reaches the environment, it is the model registry, and nothing else does.

    Rule 10's shape applied to a different subject: the claim is not "the agent layer reads little
    from the environment" but "there is one place, and here it is". A second place is not
    necessarily wrong -- it is a decision, and a decision that has to be taken deliberately rather
    than noticed later, which is what a one-element allowlist forces.
    """
    modules = shipped_agent_modules()
    assert modules, (
        f"no shipped module was found under {REPO_ROOT / 'agents'}; this scan would then pass over "
        "nothing. The path is derived from this file's location, so an empty result means the "
        "layout moved rather than that the layer is clean"
    )
    touching = {
        path.relative_to(REPO_ROOT).as_posix(): environment_accesses(
            path.read_text(encoding="utf-8")
        )
        for path in modules
    }
    offenders = {path: lines for path, lines in touching.items() if lines}
    assert set(offenders) == {"agents/registry/model.py"}, (
        f"the shipped agent modules reaching the process environment are {offenders}, and the one "
        "module permitted to is agents/registry/model.py -- it resolves ADR-005's model alias, and "
        "its own comment says why that is read from the environment rather than from "
        "infra/versions.env. Every other module receives what it needs as an argument: "
        "agents/tools/guardian_client.py takes a transport, and agents/graphs/nodes.py takes a "
        "NodeContext. A module that reads configuration itself is a module whose behaviour a run "
        "manifest cannot fully describe"
    )


def test_the_module_scan_recognises_every_spelling_and_ignores_prose() -> None:
    """The control for the module scan: three ways of reading the environment, all caught.

    The case above is another negative result, so it needs the same treatment as the others. Its
    particular way of being useless would be a parse that recognised only ``os.environ`` -- which
    is the spelling the tree happens to use today, so the scan would report exactly the right
    answer while being blind to the two ways somebody would write it next.
    ``scripts/grep_guard.sh``'s header makes the same argument about import greps: a name bound
    once at the top of a module leaves no later line that names it.

    The fourth source is the other half. A grep for ``environ`` would flag a module that merely
    *discusses* the environment -- ``agents/tools/guardian_client.py``'s docstring does, at
    length -- and a scan that cried wolf on prose would be narrowed until it stopped seeing
    anything. Parsing rather than matching is what keeps the positive result meaningful.
    """
    spellings = {
        "attribute": "import os\n\nVALUE = os.environ['ANY_KEY']\n",
        "getenv": "import os\n\nVALUE = os.getenv('ANY_KEY', '')\n",
        "imported name": "from os import environ\n\nVALUE = environ.get('ANY_KEY', '')\n",
        "aliased import": "from os import getenv as read\n\nVALUE = read('ANY_KEY', '')\n",
    }
    for description, source in spellings.items():
        assert environment_accesses(source) == [3], (
            f"the module scan did not recognise the {description} spelling of an environment read "
            f"in:\n{source}\nIt reported {environment_accesses(source)}. A scan that sees one "
            "spelling reports the right answer today and is blind to the next edit"
        )

    prose_only = (
        '"""A module that talks about os.environ and reads nothing.\n\n'
        "It names environ and getenv in prose, exactly as agents/tools/guardian_client.py does\n"
        'when it explains that it consults neither."""\n\nVALUE = "environ"\n'
    )
    assert environment_accesses(prose_only) == [], (
        "the module scan flagged a module that only *mentions* the environment in its docstring "
        f"and a string, reporting {environment_accesses(prose_only)}. It parses rather than "
        "matches for exactly this reason: a scan that fires on prose is a scan somebody narrows "
        "until it stops firing on anything"
    )


def test_the_environment_keys_the_agent_layer_declares_are_the_justified_ones() -> None:
    """Syntactically and behaviourally: three keys, all model identity or the scripted-run flag.

    The syntactic half catches a key *declared* anywhere under ``agents/`` in house style. The
    behavioural half catches what is actually looked up, which is the question the AST cannot
    answer, by handing the resolver a mapping that records its reads. Both halves are needed and
    neither is sufficient: a key could be declared and never read, or read through an expression no
    scan recognises.
    """
    declared: dict[str, str] = {}
    for path in shipped_agent_modules():
        for name, value in declared_environment_keys(path.read_text(encoding="utf-8")).items():
            declared[f"{path.relative_to(REPO_ROOT).as_posix()}:{name}"] = value

    assert set(declared.values()) == set(JUSTIFIED_ENVIRONMENT_KEYS), (
        f"the shipped agent layer declares environment key(s) {declared}, and the justified set is "
        f"{sorted(JUSTIFIED_ENVIRONMENT_KEYS)} -- ADR-005's model alias and the provider string it "
        "resolves to, plus the runner's scripted-run flag. A new key here is a new thing a run's "
        "behaviour depends on that its manifest does not record, so it needs a reason written down "
        "before it needs a test changed"
    )
    inside_guardian_namespace = sorted(
        value for value in declared.values() if value.startswith(ENV_PREFIX)
    )
    assert inside_guardian_namespace == [], (
        f"the agent layer declares key(s) {inside_guardian_namespace} inside the Guardian's "
        f"{ENV_PREFIX} namespace. That namespace reaches the Guardian process at start and nothing "
        "else, which is what makes 'the arm is not reachable from the agent layer' structural "
        "rather than a matter of nobody having tried"
    )

    resolved = RecordingEnvironment({MODEL_PROVIDER_STRING_ENV_VAR: "a-provider/a-model"})
    assert resolve_provider_string(resolved) == "a-provider/a-model", (
        "the resolver did not return the provider string it was handed; the read log below "
        "describes a call that did what it was supposed to do or it describes nothing"
    )
    unresolved = RecordingEnvironment({})
    with pytest.raises(ModelUnavailable):
        resolve_provider_string(unresolved)

    read = sorted(set(resolved.read) | set(unresolved.read))
    assert set(read) <= set(JUSTIFIED_ENVIRONMENT_KEYS), (
        f"resolving the model alias read environment key(s) {read}, and only "
        f"{sorted(JUSTIFIED_ENVIRONMENT_KEYS)} are justified. Both paths are exercised -- the one "
        "that resolves and the one that raises -- because a fallback branch is where an "
        "unjustified key would most naturally be reached for"
    )
    assert read, (
        "resolving the model alias read no environment key at all, so the assertion above passed "
        "over an empty set. RecordingEnvironment records every lookup; an empty log means the "
        "resolver stopped reading the environment and this case is now checking nothing"
    )


# --------------------------------------------------------------------------------------------
# D1-A: the `environment` field is a location, and the scans above still see what is in it
# --------------------------------------------------------------------------------------------
#
# SEAM 7 gives the acting role a runtime `environment` field, rendered into its task frame in every
# arm and naming `KUBE_TOKEN_FILE` and the API server URL under G2-SHAREDCRED. It is the one place
# in
# the agent layer where a cluster credential is *named*, so it is where the three scans above have
# to
# keep working: a value that pointed at a kubeconfig, a name in the Guardian's namespace, or a
# rule-10
# subject would each be a second way for the G2 arm to be doing something the mediation guarantee
# assumes it is not.
#
# What is *not* claimed here is stated, because the module docstring already states it: a scan
# cannot
# tell a random-looking string in `FOO` from a password in `FOO`. What this layer can be held to is
# that the field carries a *location* and that every scan still reads the field -- the control case
# below plants a real violation inside it and asserts the scan finds it.


# The G2-SHAREDCRED shape, per D1-A: ordinary facts, the credential's *location*, and the API server
# URL. Written as the runner composes it and read by the same normaliser the credential scan uses,
# so
# this file is not asserting against a spelling the Guardian's own contract would not recognise.
G2_ENVIRONMENT: Final = (
    "CLUSTER_NAME=overwatch",
    "KUBE_API_SERVER=https://127.0.0.1:6443",
    "KUBE_TOKEN_FILE=/var/run/secrets/overwatch/agents/g2-executor/token",
)

# The rule-10 pattern that names the environment variable pointing a client at a cluster, by the
# name ``scripts/grep_guard.sh`` gives it, and the generator that turns that pattern into a matching
# string. Named, never spelled: this file is a tracked file under ``agents/`` and the guard scans
# prose, so a literal copy of any of the five subjects would fail the guard on the test that checks
# it. See the module docstring's "the prose moves, not the check" and
# :func:`sample_matching`.
KUBE_PATH_PATTERN_NAME: Final = "kubeconfig-env"


def _rule_ten_subject(name: str) -> str:
    """Return a string matching the named rule-10 pattern, generated from the pattern itself.

    :func:`sample_matching` is the file's existing generator for exactly this, and reusing it means
    the control below cannot drift from the script: it *is* the script's pattern, read at run time
    and walked. An assertion that a hand-written subject matches is an assertion that will one day
    be about a subject the script no longer scans.
    """
    patterns = dict(grep_guard_patterns())
    assert name in patterns, (
        f"scripts/grep_guard.sh declares no pattern named {name!r}; it declares "
        f"{sorted(patterns)}. The pattern names are the guard's vocabulary and this control has to "
        "address one of them"
    )
    generated = sample_matching(patterns[name])
    assert re.search(as_python_regex(patterns[name]), generated, re.MULTILINE), (
        f"the subject generated for rule-10 pattern {name!r} does not match the pattern it came "
        f"from ({patterns[name]!r}); the control would then be asserting nothing"
    )
    return generated


def test_the_g2_environment_names_a_credential_location_and_trips_no_scan(
    guardian: InProcessGuardian,
) -> None:
    """The G2 environment list is a set of *locations*, and all three scans still see inside it.

    Each scan is run over the list as a mapping, exactly as :func:`configuration_keys`,
    :func:`credential_shaped_keys` and :func:`rule_ten_hits` receive a real environment -- so the
    assertion is over the same functions the cases above use rather than over a re-implementation.

    The three properties, and why each is a real risk rather than a formality:

    * **no Guardian configuration key.** The field is a different namespace from ``GUARDIAN_``, and
    a
      run in which the runner composed a fact out of the Guardian's settings would put an arm name
      or a signing-key *location* in an agent prompt;
    * **no credential-shaped name.** ``KUBE_TOKEN_FILE`` normalises to a name the Guardian's
    contract
      does not forbid -- it is a path, and the contract's rule matches whole names so that
      ``GITHUB_TOKEN_PATH`` is not a finding -- which is precisely what makes it the right spelling
      and what this asserts rather than assumes;
    * **no rule-10 subject.** The five patterns name the Kubernetes client, the command-line client,
      its generated API classes, its config loaders, and the environment variable that points a
      client at a cluster. A ``KUBE_TOKEN_FILE`` line that matched any of them would be an ambient
      cluster path arriving through the environment, which is what rule 10 exists to keep out.

    The rule-10 subject is named by its *pattern name* rather than spelled, and the plant in the
    control below is generated from the pattern by :func:`sample_matching`. That is this file's
    standing discipline, restated at the point it is easy to break: this file is a tracked file
    under
    ``agents/``, so a literal copy of any of the five subjects would make ``scripts/grep_guard.sh``
    fail on the test that checks the guard.
    """
    context = node_context(guardian, environment=G2_ENVIRONMENT)
    declared = dict(fact.split("=", 1) for fact in G2_ENVIRONMENT)

    values, keys = context_data_findings(context)
    assert values == [], (
        f"the NodeContext carries value(s) out of the Guardian's configuration namespace through"
        " its "
        f"environment field: {values}. The G2 credential is named in its own namespace; the "
        f"{ENV_PREFIX} one belongs to the Guardian process alone"
    )
    assert keys == [], (
        f"the NodeContext carries credential-shaped name(s) {keys} through its environment field. "
        "A credential *location* is not a credential, and the name rule is written to tell the two "
        f"apart; a fact whose name normalises into {sorted(SECRET_SHAPED_FIELD_NAMES)} is not a "
        "location"
    )
    assert configuration_keys(declared) == [], (
        f"the G2 environment list carries Guardian configuration key(s) "
        f"{configuration_keys(declared)}"
    )
    assert credential_shaped_keys(declared) == [], (
        f"the G2 environment list carries credential-shaped variable name(s) "
        f"{credential_shaped_keys(declared)}. D1-A admits a *path*; a name the credential rule "
        "forbids is not one"
    )
    assert rule_ten_hits(declared) == [], (
        f"the G2 environment list matches rule-10 pattern(s) {rule_ten_hits(declared)}:"
        "{declared}. "
        "An ambient cluster path arriving through the environment is the alternative to the "
        "Guardian client that .agents/rules/10 forbids, and the G2 arm is exactly where it would "
        "be hardest to notice"
    )

    # And the facts are really there: the field is not empty and carries both G2-only entries, so
    # the clean results above are over the G2 shape rather than over nothing.
    walked = [text for text, _ in _walk_data(context.environment, "NodeContext.environment")]
    assert walked == list(G2_ENVIRONMENT), (
        f"the context's environment field is {walked!r} against the list it was given. The"
        " renderer "
        "carries whatever the runner composed, verbatim and in order; a fact it added or dropped "
        "would be a fact no run manifest describes"
    )


def test_the_scans_still_see_inside_the_environment_field(guardian: InProcessGuardian) -> None:
    """Plant one violation of each kind inside the environment list; every scan reports it.

    The control for the case above, and the reason it is not optional. Those three assertions are
    negative results, and a scan that had stopped descending into a *new* ``NodeContext`` field
    would
    report all three as clean while the field carried anything. ``stopped_collaborators`` already
    guards the field *kind*; this guards the field's *contents*.

    Three plants because the three scans read the field differently, and the shape each is given is
    the shape it is given in production. The configuration-value scan walks *data* -- strings,
    mappings, sequences -- because an environment fact is a string and a value that names the
    Guardian's namespace is a string. The two name scans read a *mapping's keys*, because that is
    what a process environment is: ``os.environ`` maps a name to a value, and the credential rule
    matches a whole normalised name rather than a substring (which is why ``GITHUB_TOKEN_PATH`` is
    not a finding). The rule-10 scan reads the rendered key-and-value document, because two of its
    five patterns are anchored at the start of a line and a value spelled as an import statement is
    invisible in a ``KEY=value`` rendering -- so the value-side plant is the one that matters most,
    and it is the shape an ambient cluster path actually takes.
    """
    context = node_context(
        guardian,
        environment=(
            *G2_ENVIRONMENT,
            f"{ENV_PREFIX}SIGNING_KEY=/etc/guardian/signing.key",
            "API_KEY=planted by a test",
            f"{KUBE_PATH_PATTERN_NAME}={_rule_ten_subject(KUBE_PATH_PATTERN_NAME)}",
        ),
    )

    values, keys = context_data_findings(context)

    reported = _indices(values, ENV_PREFIX)
    assert reported, (
        f"the context scan did not report a Guardian configuration key planted as an environment "
        f"fact; it reported {values}. A new NodeContext field the walk does not descend into would "
        "make every 'no configuration value' result above vacuous"
    )
    assert all(
        finding.startswith(f"NodeContext.environment[{position}]")
        for finding, position in zip(values, reported, strict=True)
    ), f"the findings are not attributed to the environment field's own indices: {values!r}"
    assert keys == [], (
        f"the context's credential-shaped key walk reported {keys}. It is written to read *mapping "
        "keys* -- the environment is a tuple of strings here, not a mapping -- which is why the "
        "credential-name plant below is asserted over the derived mapping instead"
    )

    planted = dict(fact.split("=", 1) for fact in context.environment)
    assert configuration_keys(planted) == ["GUARDIAN_SIGNING_KEY"], (
        f"the configuration scan over the G2-shaped list reported {configuration_keys(planted)}"
    )
    assert credential_shaped_keys(planted) == ["API_KEY"], (
        f"the credential scan did not report the planted API_KEY name; it reported "
        f"{credential_shaped_keys(planted)}"
    )
    assert rule_ten_hits(planted), (
        "the rule-10 scan reported nothing for an environment carrying a cluster-path value. That"
        " is "
        "the pattern an ambient cluster path matches, and the one the value-side of the scan"
        " exists "
        f"for; the patterns scanned were {[name for name, _ in grep_guard_patterns()]}"
    )


def _indices(findings: Sequence[str], needle: str) -> tuple[int, ...]:
    """Return the ``environment.<n>`` positions a scan attributed to facts naming ``needle``.

    A helper because the planted facts sit at known positions in the list and a failure message
    wants
    the position rather than the whole finding: "field 3" says where to look, and a finding that
    repeats its own path says it twice. Returns the bracketed integers only, so a finding that names
    the needle somewhere other than in its position cannot be mistaken for an attribution.
    """
    found: list[int] = []
    for finding in findings:
        head, bracket, tail = finding.partition("[")
        if not bracket:
            continue
        position = tail.split("]", 1)[0]
        if position.isdigit() and needle in finding:
            found.append(int(position))
    return tuple(found)
