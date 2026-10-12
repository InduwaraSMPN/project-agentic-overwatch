r"""Every parity assertion, proved able to fail -- and the gate, proved unable to pass vacuously.

WHY THIS FILE EXISTS AND WHY IT IS THE ONE THE MILESTONE TURNS ON
------------------------------------------------------------------
``docs/milestones/M4-agents.md``'s Definition of done asks that ``make parity-check`` assert **all
three** budgets -- prompt tokens, tool calls and turns -- and traceability row T-37 is the line that
says so. That item is not satisfied by a green gate. Conflict M4-C4 states the failure mode
precisely: tool calls and turns are runtime quantities that no file in the kit declared before M4,
so the check "could have reported green having compared one budget of three". A positive suite
cannot tell the difference between an assertion that held and an assertion that was never made --
both look like ``passed``, both print the same table -- so the only evidence that the
third budget is compared is a registry in which it is violated and a gate that says so.

Every test below therefore takes the registry that ships, copies it into ``tmp_path``, perturbs
**one** thing, and asserts that :func:`~agents.registry.parity.check_parity` names the right reason.
:func:`test_the_unmutated_copy_still_passes` runs first and is what makes each rejection
attributable: the copy is green, so a red verdict afterwards is caused by the perturbation and not
by the copying.

The assertion is always on the *reason*, never merely on ``not passed``. A gate that failed every
registry would pass a suite that only checked for failure, and a reason is what a developer at 2am
acts on; ``.agents/rules/00-source-of-truth.md``'s posture -- never claim a Definition-of-done item
without running the verification and showing output -- is the same posture applied one level down.

THE PERTURBATIONS ARE DERIVED FROM THE REGISTRY, NOT WRITTEN AS LITERALS
-------------------------------------------------------------------------
"One more tool call than the manifest declares" is a mutation; a literal allocation is a
number that stops meaning that the moment somebody legitimately edits the budget. Each
fixture below reads what the shipped registry says and perturbs it relative to that, and
every textual edit goes through :func:`_replace_once`, which refuses unless the text it is
replacing occurs **exactly once**. A negative fixture that silently stopped applying --
because a block was renamed, a list reordered, a number changed -- would leave a green test
asserting nothing, which is precisely the disease this file is the cure for.

WHAT "FAILS CLOSED" MEANS HERE, AND WHY IT IS A DIFFERENT CLAIM FROM THE SIX ABOVE
------------------------------------------------------------------------------------
``scripts/grep_guard.sh`` and ``scripts/monitor_guard.sh`` may pass vacuously and say so, because
each is a **prohibition**: nothing found means nothing violated. Parity is an **equality**, so
nothing found means nothing *proved* -- and, in ``prompt-parity-policy.md`` section 3's words, "a
green check over an absent registry would make deleting the registry the easiest way to pass".

So the last four tests are not about a violated assertion at all. They are about the gate
refusing to return a verdict it has not earned: no composition manifests at all, one of
the three conditions missing, a cap still carrying the ``PENDING-M4-COMPOSITION``
sentinel, and a role that runs in a phase for which the manifest declares no budget. Each
must exit non-zero with a named error, and the distinction between
``ParityReport.blocking`` and ``ParityReport.failures`` -- "parity was not established"
versus "parity is violated" -- is asserted where the gate draws it, because the two
findings have different remedies.

TIER A: NO NETWORK, NO DOCKER, NO CREDENTIAL, NO TOKEN SPENT
--------------------------------------------------------------
Every fixture is files under ``tmp_path`` and every verdict is a function of their bytes. Nothing
here mutates the tracked registry: ``agents/prompts/`` is read once per test and copied, and the one
test that has to perturb :mod:`agents.registry.limits` does it with ``monkeypatch`` so the change
cannot outlive the test.
"""

import math
import shutil
import sys
from collections import Counter
from pathlib import Path

import pytest

# The repository root, derived from this file's own location rather than from the working directory,
# so the fixtures copy the same registry whether pytest is invoked from the root, from agents/ or
# from anywhere else. The same root is prepended to sys.path because `agents` is only importable
# when the root is on it, and the CI step's working directory is a property of the workflow rather
# than something this file should depend on.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agents.registry import PHASES, STRUCTURE_CONDITIONS  # noqa: E402
from agents.registry import limits as limits_module  # noqa: E402
from agents.registry.limits import PENDING_COMPOSITION_STUDY, resolve  # noqa: E402
from agents.registry.loader import (  # noqa: E402
    COMPOSITIONS_DIRNAME,
    RegistryError,
    default_registry_root,
    load_registry,
)
from agents.registry.parity import ParityReport, check_parity, main  # noqa: E402
from agents.registry.tokenizer import count_tokens  # noqa: E402

# The opening words of each reason :mod:`agents.registry.parity` emits. Named once here and matched
# against below, so that a test asserts on the *class* of finding rather than on a sentence: the
# prose after the colon is a message to a human and is expected to be improved, the prefix is the
# gate's vocabulary and changing it is a change to what the gate reports.
SHARED_BLOCK = "shared-block identity:"
INSTRUCTION_BUDGET = "token budget:"
TOOL_IDENTITY = "tool identity:"
TURN_BUDGET = "turn budget:"
TOOL_CALL_BUDGET = "tool-call budget:"
STRUCTURAL_CAP = "structural cap:"
BUDGET_COVERAGE = "budget coverage:"
REALIZABLE_ACTION = "realizable action:"


# The two tool names assertion 5 reasons about, read from the one registry so a rename there cannot
# leave this file asserting against strings nothing emits. `agents/tools/` is imported inside the
# assertion below rather than at module scope, for the reason `agents/registry/parity.py` gives for
# its own import of the same module: the parity gate runs in a CI job that installs nothing, and a
# test module is on that job's import path too.
def _tool_names() -> tuple[str, str]:
    from agents.tools.registry import ACTION_TOOL, ISSUE_TOKEN_TOOL

    return ISSUE_TOKEN_TOOL.name, ACTION_TOOL.name


ISSUE_TOOL_NAME, ACTION_TOOL_NAME = _tool_names()

# The two-space indentation unit the manifest grammar fixes, restated here because this file writes
# manifest text rather than only reading it. agents/registry/loader.py refuses any other unit, so a
# fixture that used a different one would be refused before it could be a fixture.
INDENT = "  "


# ------------------------------------------------------------------------------------------------
# Building a mutated registry
# ------------------------------------------------------------------------------------------------


@pytest.fixture
def mutable_registry(tmp_path: Path) -> Path:
    """Return a private, writable copy of ``agents/prompts/`` under this test's own directory.

    The source is :func:`~agents.registry.loader.default_registry_root`, which resolves from the
    module's ``__file__`` rather than from the working directory, so this fixture copies the same
    tree however pytest was invoked. Function-scoped, because every test here perturbs its copy and
    two tests sharing one would be the classic pair that passes alone and fails in company.
    """
    destination = tmp_path / "prompts"
    shutil.copytree(default_registry_root(), destination)
    return destination


def manifest(root: Path, condition: str) -> Path:
    """Return the path of one condition's composition manifest inside a copied registry."""
    return root / COMPOSITIONS_DIRNAME / f"{condition}.yaml"


def _replace_once(path: Path, old: str, new: str) -> None:
    """Replace ``old`` with ``new`` in ``path``, refusing unless it occurs exactly once.

    The refusal is the point. A negative fixture whose edit silently matched nothing would leave the
    test asserting that an *unmutated* registry is rejected -- which it is not -- and the test would
    fail loudly. A fixture whose edit matched twice would perturb two things and make the reason
    unattributable. Both are caught here rather than being diagnosed later from a confusing report.
    """
    text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    occurrences = text.count(old)
    assert occurrences == 1, (
        f"{path.name}: the fixture text occurs {occurrences} time(s), expected exactly once. The "
        f"registry has moved under this test. Text was:\n{old}"
    )
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def _budget_region(lines: list[str]) -> tuple[int, int]:
    """Return the half-open line range of the manifest's top-level ``budgets:`` mapping.

    The walk below is confined to this region so that it never has to understand the ``roles:``
    sequence. ``budgets:`` is a mapping of mappings of mappings and nothing else, which is
    what makes a short locator sufficient and honest rather than a partial YAML implementation.
    """
    opens = [index for index, line in enumerate(lines) if line == "budgets:"]
    assert len(opens) == 1, f"expected exactly one top-level 'budgets:' line, found {len(opens)}"
    start = opens[0] + 1
    stop = start
    while stop < len(lines) and (not lines[stop].strip() or lines[stop].startswith(INDENT)):
        stop += 1
    return start, stop


def _budget_index(lines: list[str], *keys: str) -> int:
    """Return the index of the line at ``budgets.<keys...>``, refusing anything ambiguous.

    Structural rather than textual: it follows the key path by indentation depth, so it cannot be
    fooled by a role whose name is a substring of another's or by two phases that happen to declare
    the same numbers.
    """
    start, stop = _budget_region(lines)
    stack: list[str] = []
    matches: list[int] = []
    for index in range(start, stop):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        depth = (len(line) - len(line.lstrip(" "))) // len(INDENT)
        key = line.strip().split(":", 1)[0]
        del stack[depth - 1 :]
        stack.append(key)
        if tuple(stack) == keys:
            matches.append(index)
    assert len(matches) == 1, (
        f"expected exactly one budgets.{'.'.join(keys)} line, found {len(matches)}"
    )
    return matches[0]


def bump_budget(path: Path, phase: str, role_id: str, key: str) -> tuple[int, int]:
    """Add one to ``budgets.<phase>.<role_id>.<key>``; return the declared and the mutated value.

    "One more turn than the manifest declares" is the perturbation traceability row T-37 asks about,
    and stating it as an increment rather than as a literal keeps the fixture correct across any
    legitimate edit to the budgets themselves.
    """
    lines = path.read_text(encoding="utf-8").replace("\r\n", "\n").split("\n")
    index = _budget_index(lines, phase, role_id, key)
    prefix, declared = lines[index].split(": ", 1)
    lines[index] = f"{prefix}: {int(declared) + 1}"
    path.write_text("\n".join(lines), encoding="utf-8")
    return int(declared), int(declared) + 1


def drop_budget(path: Path, phase: str, role_id: str) -> None:
    """Delete the whole ``budgets.<phase>.<role_id>`` allocation from a manifest."""
    lines = path.read_text(encoding="utf-8").replace("\r\n", "\n").split("\n")
    index = _budget_index(lines, phase, role_id)
    depth = len(lines[index]) - len(lines[index].lstrip(" "))
    stop = index + 1
    while (
        stop < len(lines)
        and lines[stop].strip()
        and len(lines[stop]) - len(lines[stop].lstrip(" ")) > depth
    ):
        stop += 1
    path.write_text("\n".join(lines[:index] + lines[stop:]), encoding="utf-8")


def drop_tool(path: Path, role_id: str, tool_name: str) -> None:
    """Delete one ``tools:`` entry from one role's manifest stanza.

    Structural rather than textual, for the same reason :func:`_budget_index` is: a role's tool list
    is found by following the key path through the manifest's two-space indentation, so a role whose
    name is a substring of another's, or a tool named twice under different roles, cannot be
    confused for the one under test. Every S1-HIER Supervisor carries the same tool list, which is
    exactly the case a ``text.replace`` would get wrong.
    """
    lines = path.read_text(encoding="utf-8").replace("\r\n", "\n").split("\n")
    starts = [index for index, line in enumerate(lines) if line == f"{INDENT}- id: {role_id}"]
    assert len(starts) == 1, (
        f"expected exactly one '{INDENT}- id: {role_id}' stanza, found {len(starts)}"
    )
    start = starts[0]
    stop = start + 1
    while (
        stop < len(lines)
        and not lines[stop].startswith(f"{INDENT}- id: ")
        and not (lines[stop] and not lines[stop].startswith(INDENT))
    ):
        stop += 1
    tools = [index for index in range(start, stop) if lines[index] == f"{INDENT * 2}tools:"]
    assert len(tools) == 1, (
        f"{role_id}: expected exactly one '{INDENT * 2}tools:' line, found {len(tools)}"
    )
    entry = f"{INDENT * 3}- {tool_name}"
    items = [index for index in range(tools[0] + 1, stop) if lines[index] == entry]
    assert len(items) == 1, f"{role_id}: expected exactly one {entry!r} line, found {len(items)}"
    path.write_text("\n".join(lines[: items[0]] + lines[items[0] + 1 :]), encoding="utf-8")


def write_block(root: Path, block_id: str, body: str, parity_class: str) -> None:
    """Write one synthetic block file into a copied registry, with the provenance rule 4 requires.

    ``origin: engineering`` with a justification, because section 2 rule 4 admits exactly two
    provenances and :func:`~agents.registry.loader._load_block` refuses a block that claims neither.
    A fixture that could not be loaded would test the loader, not the gate.
    """
    (root / "blocks" / f"{block_id}.md").write_text(
        "---\n"
        f"id: {block_id}\n"
        f"parity_class: {parity_class}\n"
        "origin: engineering\n"
        'justification: "Synthetic block written by agents/tests/test_parity_negative.py; it '
        'exists only inside a per-test copy of the registry and is never tracked."\n'
        "---\n" + body,
        encoding="utf-8",
    )


def report_for(root: Path) -> ParityReport:
    """Load a copied registry and run the gate over it."""
    return check_parity(load_registry(root))


def reasons(report: ParityReport) -> tuple[str, ...]:
    """Every sentence the gate produced, violated assertions and unmade ones alike."""
    return tuple(report.failures) + tuple(report.blocking)


def reasons_naming(report: ParityReport, *fragments: str) -> tuple[str, ...]:
    """Return the reasons that contain every one of ``fragments``."""
    return tuple(
        reason for reason in reasons(report) if all(fragment in reason for fragment in fragments)
    )


def assert_rejected(report: ParityReport, *fragments: str) -> None:
    """Assert the gate refused, for a reason naming every fragment.

    Both halves matter and are asserted separately. ``not passed`` alone would be satisfied by a
    gate that rejected everything; the fragments are what tie the rejection to the one thing
    this fixture perturbed.
    """
    __tracebackhide__ = True
    assert not report.passed, (
        f"the gate accepted a registry perturbed to violate {fragments[0]!r}. This is the failure "
        "mode conflict M4-C4 names: an assertion that reports green because it was never made"
    )
    named = reasons_naming(report, *fragments)
    assert named, (
        f"the gate refused, but for no reason naming {list(fragments)}. It said:\n  "
        + "\n  ".join(reasons(report))
    )


# ------------------------------------------------------------------------------------------------
# The control: an unperturbed copy is green, which is what makes every rejection below attributable
# ------------------------------------------------------------------------------------------------


def test_the_unmutated_copy_still_passes(mutable_registry: Path) -> None:
    """Copying the registry into ``tmp_path`` changes no verdict.

    Without this, every test below would be ambiguous: a red verdict could mean "the perturbation
    was caught" or "copying the tree broke something" -- a stray file, a line ending folded
    the wrong way, a path the loader resolves differently -- and the suite would look the
    same in both cases.
    """
    report = report_for(mutable_registry)
    assert report.passed, (
        "the untouched copy of agents/prompts/ does not pass the gate, so nothing this "
        "file asserts about a perturbed copy is attributable to the perturbation:\n  "
        + "\n  ".join(reasons(report))
    )


# ------------------------------------------------------------------------------------------------
# The violated assertions
# ------------------------------------------------------------------------------------------------


def test_an_acting_role_with_no_reachable_issuer_is_rejected(mutable_registry: Path) -> None:
    """One Supervisor stripped of the issuance tool is refused, and only about that.

    Assertion 5's first claim, and the shape V1 took at the manifest level: an acting role that
    cannot obtain the capability it spends. ``S1-HIER``'s ``supervisor-containment`` is the role to
    strip -- it is the phase's issuer, the ``executor`` is the role that acts, and every other
    Supervisor keeps the tool -- so in ``containment`` the Executor holds ``guardian_action`` and
    nothing in the phase holds ``issue_capability_token``.

    The choice of role is what isolates the assertion, and the isolation is asserted rather than
    assumed. The other three Supervisors still hold the issuance tool, so the *union* of the
    condition's tools is unchanged and the tool-registry digest (assertion 3) is identical; the
    budgets are untouched, so assertion 4 holds; the block lists are untouched, so assertions 1, 2
    and the structural cap hold. A green-except-for-assertion-5 verdict is the only thing this
    fixture is trying to produce, and a fixture that also moved a digest would prove less than it
    claims.
    """
    registry = load_registry(mutable_registry)
    hierarchical = registry.compositions["S1-HIER"]
    victim = next(
        role
        for role in hierarchical.roles
        if ISSUE_TOOL_NAME in role.tools and role.phase is not None
    )
    phase = victim.phase
    actor = next(
        role
        for role in hierarchical.roles
        if ACTION_TOOL_NAME in role.tools and role.phase in (None, phase)
    )
    before = set(hierarchical.tool_names())

    drop_tool(manifest(mutable_registry, "S1-HIER"), victim.role_id, ISSUE_TOOL_NAME)

    reloaded = load_registry(mutable_registry)
    assert ISSUE_TOOL_NAME not in reloaded.compositions["S1-HIER"].role(victim.role_id).tools, (
        "the fixture did not remove the tool it meant to remove"
    )
    assert set(reloaded.compositions["S1-HIER"].tool_names()) == before, (
        "the condition's tool union moved, so this fixture would also break the tool-identity "
        "assertion and would no longer isolate realizable-action reachability"
    )
    assert any(ISSUE_TOOL_NAME in role.tools for role in reloaded.compositions["S1-HIER"].roles), (
        "the fixture removed the issuance tool from every role, which is a different perturbation"
    )

    report = report_for(mutable_registry)
    # The reason names the *actor* that cannot act and the phase it cannot act in, which is what a
    # reader at 2am needs; the role the fixture stripped is asserted above rather than here, because
    # naming it in the reason would read as though the stripped Supervisor were itself the actor.
    assert_rejected(report, REALIZABLE_ACTION, repr(phase), actor.role_id, ISSUE_TOOL_NAME)
    assert not reasons_naming(report, repr(phase), TURN_BUDGET), (
        "removing a tool moved a budget total, so this fixture is no longer isolating "
        "reachability:\n  " + "\n  ".join(reasons(report))
    )
    assert not reasons_naming(report, TOOL_IDENTITY), (
        "removing one role's tool moved the tool-registry digest, so the two assertions can no "
        "longer be told apart:\n  " + "\n  ".join(reasons(report))
    )


def test_a_phase_whose_turns_cannot_pay_for_its_tool_calls_is_rejected(
    mutable_registry: Path,
) -> None:
    """Every condition's containment turns cut by the same amount, so the sums still match.

    Assertion 5's turn-sufficiency claim, and the one thing assertion 4 structurally cannot see.
    The perturbation is deliberately *compensated*: each of the three conditions loses the same
    number
    of containment turns, so the per-phase sums stay equal and assertion 4 passes. What is left is a
    phase that declares eight tool calls and fewer than eight turns -- it can buy four mint-and-act
    pairs and cannot pay for them, because a mint costs a model call and the act costs another.

    That is precisely section 3's sentence: "``max_turns`` did not cover a mint-then-act pair in one
    iteration", and precisely what the v1 flat and single arms looked like with budgets that every
    other assertion found correct.

    The compensation is verified before the verdict is read, so this cannot quietly become the
    previous file's ``test_a_compensated_removal_does_not_slip_past_the_sums`` case: if a sum had
    moved, the run-level budgets would notice and the reason would not be attributable to assertion
    5.
    """
    registry = load_registry(mutable_registry)
    phase = PHASES[1]
    path_by_condition = {
        condition: manifest(mutable_registry, condition) for condition in STRUCTURE_CONDITIONS
    }
    before_turns: dict[str, int] = {}
    before_calls: dict[str, int] = {}
    for condition in STRUCTURE_CONDITIONS:
        allocations = registry.compositions[condition].budgets[phase]
        before_turns[condition] = sum(budget.max_turns for budget in allocations.values())
        before_calls[condition] = sum(budget.max_tool_calls for budget in allocations.values())
    assert len(set(before_turns.values())) == 1, (
        f"the containment turn sums already differ across conditions ({before_turns}); this"
        " fixture "
        "assumes they start equal, which is what makes a compensated cut attributable"
    )
    assert len(set(before_calls.values())) == 1, (
        f"the containment tool-call sums differ across conditions ({before_calls})"
    )
    # The target: one turn short of paying for every pair the tool-call budget buys.
    needed = 2 * (next(iter(before_calls.values())) // 2)
    assert min(before_turns.values()) >= needed, (
        f"every condition already declares fewer than {needed} containment turn(s)"
        "({before_turns}), "
        "so the assertion under test is already violated by the shipped registry and this fixture "
        "would attribute a pre-existing failure to its own perturbation"
    )
    cut = min(before_turns.values()) - needed + 1
    assert cut > 0, "the compensated cut is not a cut; the fixture would change nothing"

    for condition in STRUCTURE_CONDITIONS:
        # Taken off the role with the largest turn allocation in the phase, so the cut is one edit
        # and the role it lands on is derived rather than named.
        role_id = max(
            registry.compositions[condition].budgets[phase],
            key=lambda name: registry.compositions[condition].budgets[phase][name].max_turns,
        )
        lines = (
            path_by_condition[condition]
            .read_text(encoding="utf-8")
            .replace("\r\n", "\n")
            .split("\n")
        )
        index = _budget_index(lines, phase, role_id, "max_turns")
        prefix, declared = lines[index].split(": ", 1)
        assert int(declared) >= cut, (
            f"{condition}/{role_id}: the role with the largest containment allocation holds "
            f"{declared} turn(s), fewer than the {cut} this fixture needs to cut"
        )
        lines[index] = f"{prefix}: {int(declared) - cut}"
        path_by_condition[condition].write_text("\n".join(lines), encoding="utf-8")

    reloaded = load_registry(mutable_registry)
    after_turns = {
        condition: sum(
            budget.max_turns for budget in reloaded.compositions[condition].budgets[phase].values()
        )
        for condition in STRUCTURE_CONDITIONS
    }
    after_calls = {
        condition: sum(
            budget.max_tool_calls
            for budget in reloaded.compositions[condition].budgets[phase].values()
        )
        for condition in STRUCTURE_CONDITIONS
    }
    assert len(set(after_turns.values())) == 1, (
        f"the compensated cut did not preserve the per-phase turn sums ({after_turns}); this "
        "fixture is then the uncompensated case above rather than the harder one it claims to be"
    )
    assert after_calls == before_calls, "the fixture moved a tool-call total"

    report = report_for(mutable_registry)
    assert not reasons_naming(report, TURN_BUDGET), (
        "the sums moved after all, so the per-phase budget assertion would notice this fixture "
        "first:\n  " + "\n  ".join(reasons(report))
    )
    assert_rejected(report, REALIZABLE_ACTION, repr(phase), "turn")
    for condition in STRUCTURE_CONDITIONS:
        assert reasons_naming(
            report, REALIZABLE_ACTION, repr(phase), str(after_turns[condition])
        ), (
            f"no reason names {condition}'s new turn total {after_turns[condition]}:\n  "
            + "\n  ".join(reasons(report))
        )


def test_an_over_long_structural_block_is_rejected(mutable_registry: Path) -> None:
    """A ``parity_class: structural`` block grown past section 3's cap is refused.

    The cap is the only thing standing between "a sentence saying who you report to" and "a second
    helping of guidance under a topology label". The aggregate token tolerance cannot catch
    this on its own -- a structural block has a long way to grow inside a few per cent of a
    seven-thousand-token total -- so the padding here is deliberately small: just past the
    cap, and nowhere near the token tolerance.
    That the *only* failure reported is the cap is asserted, because it is what shows the cap is
    doing work the tolerance is not.
    """
    registry = load_registry(mutable_registry)
    hierarchical = registry.compositions["S1-HIER"]
    target = next(
        block_id
        for role in hierarchical.roles
        for block_id in role.block_ids
        if registry.block(block_id).is_structural
    )
    cap = int(resolve("structural_block_tokens_max"))

    path = registry.block(target).path
    body = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    path.write_text(body + " ".join(["padding"] * (cap + 1)) + "\n", encoding="utf-8")

    report = report_for(mutable_registry)
    assert_rejected(report, STRUCTURAL_CAP, repr(target))
    assert len(report.failures) == 1, (
        "a block pushed just past the structural cap tripped more than the cap, so this test no "
        "longer isolates it:\n  " + "\n  ".join(reasons(report))
    )


def test_an_extra_tool_call_in_one_condition_is_rejected(mutable_registry: Path) -> None:
    """One condition granted a single extra tool call in one phase is refused.

    Half of traceability row T-37. The perturbation is the smallest one the declaration admits --
    ``+1`` on one role in one phase -- because a tolerance of zero is the claim, and a check that
    only caught large divergences would be a check with an undocumented tolerance of its own.
    """
    registry = load_registry(mutable_registry)
    flat = registry.compositions["S2-FLAT"]
    role_id = flat.roles[0].role_id
    phase = PHASES[0]

    declared, mutated = bump_budget(
        manifest(mutable_registry, "S2-FLAT"), phase, role_id, "max_tool_calls"
    )

    report = report_for(mutable_registry)
    assert_rejected(report, TOOL_CALL_BUDGET, repr(phase), "S2-FLAT")
    assert reasons_naming(report, TOOL_CALL_BUDGET, str(mutated)), (
        f"the reason does not carry the mutated allocation ({declared} -> {mutated}), so it does "
        f"not say what was wrong:\n  " + "\n  ".join(reasons(report))
    )
    assert not reasons_naming(report, TURN_BUDGET), (
        "a tool-call perturbation was reported as a turn failure as well; the two budgets "
        "are being compared as one:\n  " + "\n  ".join(reasons(report))
    )


def test_an_extra_turn_in_one_condition_is_rejected(mutable_registry: Path) -> None:
    """One condition granted a single extra turn in one phase is refused.

    The other half of row T-37, and the one that would be easiest to lose: the turn budget is the
    quantity risk R-10 makes unequal by accident, because "a retry is a turn" and a weak free model
    retries more in whichever arm happens to trip it. If a manifest could quietly declare an extra
    turn, the arm that struggled would receive more turns and the ablation would be confounded by
    model weakness rather than by topology.
    """
    registry = load_registry(mutable_registry)
    single = registry.compositions["S3-SINGLE"]
    role_id = single.roles[0].role_id
    phase = PHASES[-1]

    declared, mutated = bump_budget(
        manifest(mutable_registry, "S3-SINGLE"), phase, role_id, "max_turns"
    )

    report = report_for(mutable_registry)
    assert_rejected(report, TURN_BUDGET, repr(phase), "S3-SINGLE")
    assert reasons_naming(report, TURN_BUDGET, str(mutated)), (
        f"the reason does not carry the mutated allocation ({declared} -> {mutated}):\n  "
        + "\n  ".join(reasons(report))
    )
    assert not reasons_naming(report, TOOL_CALL_BUDGET), (
        "a turn perturbation was reported as a tool-call failure as well; the two budgets "
        "are being compared as one:\n  " + "\n  ".join(reasons(report))
    )


def test_a_shared_block_that_differs_between_conditions_is_rejected(mutable_registry: Path) -> None:
    """A shared block re-authored for one condition is refused, both halves of it.

    This is what "a shared block whose bytes differ between conditions" *is*, in this registry. One
    block id resolves to exactly one file under ``agents/prompts/blocks/`` -- the loader refuses a
    duplicate id outright -- so two conditions cannot reference one id and receive different bytes.
    Divergent bytes therefore necessarily arrive as a **second id**, which is the shape section 2
    rule 5 is aimed at when it fixes ``S3-SINGLE``'s parity target as the Supervision blocks
    "concatenated, not a fresh authoring": a re-authoring is a new block, and this is the assertion
    that sees it.

    Both directions are asserted, because the perturbation makes two claims at once and a gate that
    reported only one would be half-blind: the original block is now missing from one condition, and
    the variant is present in only one. The digest half of
    ``agents/registry/parity.py``'s assertion 1 stays unreachable through this path by construction,
    which that module states plainly -- it is "belt and braces today ... the assertion that survives
    a future arrangement in which one id no longer means one file".
    """
    registry = load_registry(mutable_registry)
    flat = registry.compositions["S2-FLAT"]
    original = next(
        block_id
        for block_id in flat.roles[0].block_ids
        if not registry.block(block_id).is_structural
    )
    variant = f"{original}-reauthored"

    write_block(
        mutable_registry,
        variant,
        registry.block(original).body + "\nOne sentence the other two conditions never see.\n",
        parity_class="shared",
    )
    _replace_once(
        manifest(mutable_registry, "S2-FLAT"),
        f"{INDENT * 3}- {original}\n",
        f"{INDENT * 3}- {variant}\n",
    )

    report = report_for(mutable_registry)
    assert_rejected(report, SHARED_BLOCK, repr(original), "S2-FLAT")
    assert reasons_naming(report, SHARED_BLOCK, repr(variant)), (
        "the re-authored variant is referenced by one condition alone and the gate did not say so; "
        "a shared block only one arm carries is a guidance difference between arms, which is the "
        "confound the ablation exists to exclude:\n  " + "\n  ".join(reasons(report))
    )


def test_a_tool_one_condition_does_not_hold_is_rejected(mutable_registry: Path) -> None:
    """A tool held by two conditions and not the third is refused.

    Section 2 rule 3 forbids a condition-only tool outright: the definitions are identical across
    conditions and the registry hash goes into every bundle manifest. What may legitimately differ
    is which *node* holds which entry -- the issuance tool sits with the phase Supervisor in
    ``S1-HIER`` and with the coordinator in the other two, which is conflict M4-C7's resolution --
    and the digest is taken over the condition's union precisely so that it is blind to that and not
    to this.
    """
    registry = load_registry(mutable_registry)
    hierarchical = registry.compositions["S1-HIER"]
    held_by = Counter(name for role in hierarchical.roles for name in role.tools)
    exclusive = sorted(name for name, count in held_by.items() if count == 1)
    assert exclusive, (
        "every tool in S1-HIER is held by more than one role, so removing a single declaration no "
        "longer changes the condition's tool set; this fixture needs rewriting rather than deleting"
    )

    _replace_once(manifest(mutable_registry, "S1-HIER"), f"{INDENT * 3}- {exclusive[0]}\n", "")

    report = report_for(mutable_registry)
    assert_rejected(report, TOOL_IDENTITY, "S1-HIER")


def test_token_totals_outside_the_tolerance_are_rejected(mutable_registry: Path) -> None:
    """A condition pushed past the token tolerance is refused, on the token assertion alone.

    The padding is **derived**: the tolerance comes from
    :func:`agents.registry.limits.resolve`, the current totals come from a run over the unperturbed
    copy, and the number of tokens needed is solved for from those. Writing a literal here would put
    a fourth copy of section 3's tolerance in the repository -- and, worse, a copy inside the test
    that is supposed to be holding the other copies to the protocol.

    The tokens arrive as several structural blocks each sized *at* the cap rather than as one large
    block, and that shape is deliberate: it isolates the token assertion from the structural cap, so
    a pass here says the aggregate tolerance is doing work of its own. It is also the honest attack.
    A registry cannot give one condition more shared guidance without the shared-block assertion
    seeing it, so extra guidance smuggled into one arm has to wear a topology label -- and
    a stack of individually-legal structural blocks is exactly what that looks like.
    """
    tolerance = float(resolve("condition_token_tolerance_pct"))
    cap = int(resolve("structural_block_tokens_max"))
    totals = {
        condition: composed.total_tokens
        for condition, composed in report_for(mutable_registry).conditions.items()
    }

    needed = 1
    while True:
        moved = dict(totals)
        moved["S2-FLAT"] += needed
        mean = sum(moved.values()) / len(moved)
        if abs(moved["S2-FLAT"] - mean) / mean * 100 > tolerance:
            break
        needed += 1

    words = 1
    while count_tokens(" ".join(["padding"] * (words + 1)) + "\n") <= cap:
        words += 1
    body = " ".join(["padding"] * words) + "\n"
    per_block = count_tokens(body)
    assert per_block <= cap, f"the padding block is {per_block} tokens, above the cap of {cap}"

    registry = load_registry(mutable_registry)
    added = [
        f"structural.negative-fixture-pad-{index:02d}"
        for index in range(math.ceil(needed / per_block) + 1)
    ]
    for block_id in added:
        write_block(mutable_registry, block_id, body, parity_class="structural")
    anchor = f"{INDENT * 3}- {registry.compositions['S2-FLAT'].roles[0].block_ids[-1]}\n"
    _replace_once(
        manifest(mutable_registry, "S2-FLAT"),
        anchor,
        anchor + "".join(f"{INDENT * 3}- {block_id}\n" for block_id in added),
    )

    report = report_for(mutable_registry)
    assert_rejected(report, INSTRUCTION_BUDGET, "S2-FLAT")
    assert not reasons_naming(report, STRUCTURAL_CAP), (
        "every padding block was sized at or under the cap, so a cap failure means this fixture no "
        "longer isolates the token tolerance:\n  " + "\n  ".join(reasons(report))
    )


# ------------------------------------------------------------------------------------------------
# The gate fails closed: the four ways it must refuse to return a verdict it has not earned
# ------------------------------------------------------------------------------------------------


def test_a_registry_with_no_composition_manifest_refuses_rather_than_passing_vacuously(
    mutable_registry: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An empty ``compositions/`` directory is a named refusal and a non-zero exit, never a pass.

    The asymmetry with the grep guards, stated as a test. ``scripts/grep_guard.sh`` may pass
    vacuously because nothing found means nothing violated; parity asserts an equality, so nothing
    found means nothing proved -- "a green check over an absent registry would make deleting the
    registry the easiest way to pass the gate".

    Driven through :func:`~agents.registry.parity.main` as well as through the loader, because the
    exit code is what CI reads and the two failure paths are different code: the loader refuses
    before any assertion is attempted, and ``main`` has to turn that refusal into a diagnosis rather
    than a traceback.
    """
    for path in (mutable_registry / COMPOSITIONS_DIRNAME).glob("*.yaml"):
        path.unlink()

    with pytest.raises(RegistryError) as refusal:
        load_registry(mutable_registry)
    assert COMPOSITIONS_DIRNAME in str(refusal.value), (
        f"the refusal does not name the directory that is empty: {refusal.value}"
    )

    code = main(["--registry-root", str(mutable_registry)])
    captured = capsys.readouterr()
    assert code != 0, "parity-check exited 0 over a registry with no composition manifest at all"
    assert "FAIL" in captured.err, f"the refusal did not reach stderr:\n{captured.err}"
    assert COMPOSITIONS_DIRNAME in captured.err, (
        f"stderr does not name what was missing:\n{captured.err}"
    )


def test_a_registry_missing_one_condition_is_rejected(
    mutable_registry: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Two conditions out of three is nothing proved, and the gate reports it as such.

    Reported as ``blocking`` rather than as a ``failure``, and that distinction is asserted here
    because it is the one the gate's own summary line turns on: "parity was not established" and
    "parity is violated" are different findings with different remedies, and a report that merged
    them would send a reviewer looking for a divergence that does not exist.
    """
    absent = STRUCTURE_CONDITIONS[1]
    manifest(mutable_registry, absent).unlink()

    report = report_for(mutable_registry)
    assert_rejected(report, absent)
    assert report.blocking, (
        "a missing condition was reported as a violated assertion rather than as a reason parity "
        "could not be established:\n  " + "\n  ".join(reasons(report))
    )
    assert report.failures == [], (
        "the gate reported violated assertions over a registry it could not compose; the "
        "numbers in them describe nothing:\n  " + "\n  ".join(report.failures)
    )

    code = main(["--registry-root", str(mutable_registry)])
    captured = capsys.readouterr()
    assert code != 0, f"parity-check exited 0 with {absent} absent"
    assert absent in captured.err, f"stderr does not name the missing condition:\n{captured.err}"


def test_a_pending_cap_blocks_the_check(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A cap still carrying ``PENDING-M4-COMPOSITION`` stops the gate rather than defaulting.

    M2's refinement to ADR-016's pattern, proved to survive into its third application. The failure
    a default would cause is quiet and total: the gate would run, the table would print, the
    structural blocks would be bounded by a number nobody chose, and green is the answer everyone
    wants so nobody would look again.

    ``monkeypatch`` rather than an edited module, so the sentinel cannot outlive this test -- and
    against the *shipped* registry rather than a copy, because the claim is about the cap and not
    about the blocks. The mirror is patched rather than ``resolve`` itself, so the refusal travels
    the same path it would in production: :func:`~agents.registry.limits.as_protocol_mapping` reads
    the module's constants on every call.
    """
    monkeypatch.setattr(
        limits_module, "STRUCTURAL_BLOCK_TOKENS_MAX", PENDING_COMPOSITION_STUDY, raising=True
    )

    report = check_parity()
    assert not report.passed, (
        "the gate returned a verdict while a cap it bounds structural blocks with was still the "
        "pending sentinel"
    )
    assert reasons_naming(report, "structural_block_tokens_max", PENDING_COMPOSITION_STUDY), (
        "the refusal names neither the pending key nor the sentinel:\n  "
        + "\n  ".join(reasons(report))
    )
    assert report.blocking, "a pending cap is a reason parity was not established, not a failure"

    code = main([])
    captured = capsys.readouterr()
    assert code != 0, "parity-check exited 0 against a cap nobody has set"
    assert "structural_block_tokens_max" in captured.err, (
        f"stderr does not name the uncalibrated cap:\n{captured.err}"
    )
    assert "--emit-caps" in captured.err, (
        "stderr names the uncalibrated cap without naming the command that derives it, so the "
        f"reader is told what is wrong and not what to do:\n{captured.err}"
    )


def test_a_role_that_runs_without_a_declared_budget_is_rejected(mutable_registry: Path) -> None:
    """Deleting one role's allocation for one phase is refused, on both budgets.

    A phase that a role acts in without a declared allocation is a phase ``make parity-check``
    cannot compare and the runtime cannot bound. The gate sees it here because the per-phase sums
    stop matching the other two conditions -- section 3.5.4 grants the flat arm "the hierarchical
    configuration's combined per-phase allocation", so a removed allocation moves the combined
    number.

    The role removed is the one with the largest allocation in its phase, chosen rather
    than assumed: the sums are what the gate compares, so removing an allocation of zero
    would move nothing and this fixture would be asserting against a registry it had not
    really changed. That is stated plainly because it bounds what this test proves -- the
    *categorical* refusal, for any role in any phase whatever its numbers, belongs to
    ``agents/graphs/plan.py``'s plan builder, which refuses before a run rather than after
    a sum.
    """
    registry = load_registry(mutable_registry)
    hierarchical = registry.compositions["S1-HIER"]
    phase = next(phase for phase in PHASES if len(hierarchical.budgets[phase]) > 1)
    role_id = max(
        hierarchical.budgets[phase],
        key=lambda name: (
            hierarchical.budgets[phase][name].max_turns
            + hierarchical.budgets[phase][name].max_tool_calls
        ),
    )
    dropped = hierarchical.budgets[phase][role_id]
    assert dropped.max_turns + dropped.max_tool_calls > 0, (
        "every allocation in this phase is zero, so removing one changes no sum and this fixture "
        "asserts nothing"
    )

    drop_budget(manifest(mutable_registry, "S1-HIER"), phase, role_id)

    reloaded = load_registry(mutable_registry)
    assert role_id not in reloaded.compositions["S1-HIER"].budgets[phase], (
        "the fixture did not remove the allocation it meant to remove"
    )
    assert any(role.role_id == role_id for role in reloaded.compositions["S1-HIER"].roles), (
        f"{role_id!r} is no longer a declared role, so it does not run and there is nothing missing"
    )

    report = check_parity(reloaded)
    assert_rejected(report, TURN_BUDGET, repr(phase), "S1-HIER")
    assert reasons_naming(report, TOOL_CALL_BUDGET, repr(phase), "S1-HIER"), (
        "removing an allocation moved the turn total and not the tool-call total, so only one of "
        "the two budgets row T-37 names is being compared:\n  " + "\n  ".join(reasons(report))
    )


def test_a_compensated_removal_does_not_slip_past_the_sums(mutable_registry: Path) -> None:
    """The blind spot a sum comparison has, and the assertion that closes it.

    ``_check_declared_budgets`` compares per-phase **sums**, because section 3.5.4's grant to the
    flat arm is a statement about a combined per-phase allocation. So a perturbation that removes
    one role's allocation and folds exactly the same numbers into another role's allocation in the
    same phase moves no sum at all: every tolerance holds, and without a coverage assertion the gate
    reports green over a manifest in which a role that runs has no declared allocation.

    The test above removes an allocation and lets the sums notice. This one removes an allocation
    the sums *cannot* notice, which is the harder case and the one that says whether the gate
    checks coverage or only arithmetic.

    The categorical form of the same property lives in ``agents/graphs/plan.py``, which refuses to
    build a plan whose step has no declared budget. Both readers hold it, and this asserts the gate
    is the reader a reviewer can rely on before merging rather than after starting a run.
    """
    registry = load_registry(mutable_registry)
    hierarchical = registry.compositions["S1-HIER"]
    phase = next(phase for phase in PHASES if len(hierarchical.budgets[phase]) > 1)
    allocations = hierarchical.budgets[phase]
    victim = max(
        allocations,
        key=lambda name: allocations[name].max_turns + allocations[name].max_tool_calls,
    )
    beneficiary = next(name for name in sorted(allocations) if name != victim)
    moved = allocations[victim]
    assert moved.max_turns + moved.max_tool_calls > 0, (
        "the allocation being moved is zero, so nothing is compensated and this fixture asserts "
        "nothing about the sums"
    )

    path = manifest(mutable_registry, "S1-HIER")
    for key, amount in (("max_turns", moved.max_turns), ("max_tool_calls", moved.max_tool_calls)):
        for _ in range(amount):
            bump_budget(path, phase, beneficiary, key)
    drop_budget(path, phase, victim)

    reloaded = load_registry(mutable_registry)
    survivors = reloaded.compositions["S1-HIER"].budgets[phase]
    assert victim not in survivors, "the fixture did not remove the allocation it meant to remove"
    assert sum(budget.max_turns for budget in survivors.values()) == sum(
        budget.max_turns for budget in allocations.values()
    ), (
        "the compensation did not preserve the turn sum, so the sums would notice it and this "
        "fixture would prove less than it claims"
    )
    assert sum(budget.max_tool_calls for budget in survivors.values()) == sum(
        budget.max_tool_calls for budget in allocations.values()
    ), "the compensation did not preserve the tool-call sum"

    report = check_parity(reloaded)
    assert not reasons_naming(report, TURN_BUDGET), (
        "the sums moved after all, so this fixture is the previous test again rather than the "
        "case the sums cannot see:\n  " + "\n  ".join(reasons(report))
    )
    assert_rejected(report, BUDGET_COVERAGE, repr(victim), repr(phase))
