r"""The four parity assertions, made against the registry that actually ships.

WHAT THIS FILE PINS
-------------------
``docs/protocols/prompt-parity-policy.md`` section 1 states the property the whole ablation rests
on: "The ablation claims are only valid if conditions differ **solely** in the manipulated variable
(topology, or guardrail arm). Prompts, tools, and instruction budgets must be matched; this protocol
makes that a machine-checked invariant instead of an intention." Section 3 turns that into four
assertions and :mod:`agents.registry.parity` implements them. This file asserts each one directly
over ``agents/prompts/``, one test per assertion, plus the two properties the gate's *output* has to
carry for the check to be evidence rather than a claim.

It is the positive half. ``agents/tests/test_parity_negative.py`` is the half that matters more --
row T-37 requires the check to assert **all three** budgets, and a check can report green having
compared one of three -- so this file establishes that the shipped registry satisfies each assertion
and that file establishes that each assertion can fail.

WHY EACH ASSERTION IS ITS OWN TEST RATHER THAN ONE ``report.passed``
----------------------------------------------------------------------
:func:`~agents.registry.parity.check_parity` returns a single verdict, and a suite that only read
``report.passed`` would go green in exactly the situation the milestone's Definition of done is
worried about: an assertion that silently stopped being made. If ``_check_tool_identity`` were
deleted tomorrow, ``report.passed`` would still be ``True``, the table would still print, and
nothing in a one-assertion suite would move. Each test below therefore re-derives its property from
the registry rather than reading the gate's conclusion about it, so the gate and this file are two
independent readings of the same files -- which is the only arrangement in which one of them going
wrong is visible.

WHERE THE NUMBERS COME FROM
----------------------------
Nowhere in this file. The tolerance, the structural cap and the two budget tolerances are read
through :func:`agents.registry.limits.resolve`, which mirrors ``prompt-parity-policy.md`` section
3's anchored block and is itself held to it by ``test_limits_match_parity_policy.py``. Restating any
of them here would create a third home for a number that
``.agents/rules/00-source-of-truth.md`` allows exactly one, and -- worse -- a third home that a test
would then hold the other two to.

TIER A: NO NETWORK, NO CREDENTIAL, NO TOKEN SPENT
---------------------------------------------------
Nothing here composes a request, resolves a model or opens a socket. The reference tokenizer is
:mod:`agents.registry.tokenizer`, which is one regular expression, and every number below is a
function of bytes on disk. That is what makes traceability row T-45's claim -- the token table
reproduces from a clean checkout with no credential -- checkable by this suite rather than only by
CI.
"""

import re
import sys
from pathlib import Path

import pytest

# The repository root, derived from this file's own location rather than from the working directory,
# so the suite reads the same registry whether pytest is invoked from the root, from agents/ or from
# anywhere else. The same root is prepended to sys.path because `agents` is only importable when the
# root is on it, and the CI step's working directory is a property of the workflow rather than
# something this file should depend on.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agents.registry import PHASES, STRUCTURE_CONDITIONS  # noqa: E402
from agents.registry.digest import directory_digest, tool_registry_digest  # noqa: E402
from agents.registry.limits import resolve  # noqa: E402
from agents.registry.loader import Composition, PromptRegistry  # noqa: E402
from agents.registry.parity import ParityReport, check_parity, main, render_table  # noqa: E402
from agents.registry.tokenizer import REFERENCE_TOKENIZER_ID, count_tokens  # noqa: E402
from agents.tools.registry import ACTION_TOOL, ISSUE_TOKEN_TOOL, definitions_for  # noqa: E402

# A sha256 in the form the table prints it. Asserted as a shape rather than as a value: the digest
# changes with every legitimate edit to the registry, and a test that pinned the current one would
# have to be edited by every prompt change -- which is the shape of a test people learn to update
# without reading.
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@pytest.fixture(scope="session")
def report(registry: PromptRegistry) -> ParityReport:
    """One parity run over the shipped registry, shared by every test in this module.

    Session-scoped for the ``registry`` fixture's reason -- composing three conditions renders every
    block three times -- and safe to share because :class:`~agents.registry.parity.ParityReport`
    holds frozen dataclasses and nothing below mutates it.
    """
    return check_parity(registry)


def _sole_role(composition: Composition) -> str:
    """Return the id of the one role a single-node condition declares, or fail saying otherwise.

    ``S2-FLAT``'s "coordinator budget" and ``S3-SINGLE``'s "single-agent budget" are the phrases
    section 3 uses, and both presuppose that those conditions have exactly one role to hold a
    budget. Deriving the id rather than spelling it keeps this file from restating the registry's
    contents, and asserting the count keeps the derivation honest: a second role would make "the
    coordinator budget" ambiguous, and silently taking the first would compare the wrong number.
    """
    __tracebackhide__ = True
    assert len(composition.roles) == 1, (
        f"{composition.condition} declares {len(composition.roles)} roles "
        f"({', '.join(role.role_id for role in composition.roles)}); section 3 speaks of its "
        "single coordinator/agent budget, which only means something while there is one role"
    )
    return composition.roles[0].role_id


# ------------------------------------------------------------------------------------------------
# Assertion 1 -- shared-block identity
# ------------------------------------------------------------------------------------------------


def test_every_shared_block_is_referenced_by_every_condition(report: ParityReport) -> None:
    """Section 2 rule 2: a shared block is defined once and referenced by every condition.

    A shared block that only one condition carries is a guidance difference between arms, which is
    the confound the whole ablation exists to exclude -- and it is the failure that would be hardest
    to see by reading, because each manifest on its own would look complete.

    This is also what makes ``S3-SINGLE``'s composition honest. Section 2 rule 5 fixes its parity
    target as the Supervision layer, "those blocks concatenated, not a fresh authoring", and the
    only mechanical reading of "concatenated, not re-authored" is that the very same block ids
    appear: a re-authored variant would necessarily be a new id, and a new shared id that one
    condition alone references fails here.
    """
    referenced: dict[str, set[str]] = {}
    for condition, composed in report.conditions.items():
        for role in composed.roles.values():
            for block in role.shared_blocks():
                referenced.setdefault(block.block_id, set()).add(condition)

    assert referenced, (
        "no condition referenced a single shared block, so this assertion compared nothing. Parity "
        "is an equality: nothing found means nothing proved"
    )
    every = set(report.conditions)
    for block_id in sorted(referenced):
        assert referenced[block_id] == every, (
            f"shared block {block_id!r} is referenced by {sorted(referenced[block_id])} but not by "
            f"{sorted(every - referenced[block_id])}"
        )


def test_every_shared_block_resolves_to_one_byte_sequence(report: ParityReport) -> None:
    """The same shared block id carries the same bytes in every condition that references it.

    Belt and braces today, and stated because the gate states it: one block id resolves to one file
    under ``agents/prompts/blocks/``, so the digests cannot differ without the loader having been
    changed. It is the assertion that survives a future arrangement in which one id no longer means
    one file -- a per-condition override directory, say -- and the moment such an arrangement
    arrives is exactly the moment nobody would think to add this check.
    """
    digests: dict[str, dict[str, str]] = {}
    for condition, composed in report.conditions.items():
        for role in composed.roles.values():
            for block in role.shared_blocks():
                digests.setdefault(block.block_id, {})[condition] = block.digest

    for block_id in sorted(digests):
        distinct = set(digests[block_id].values())
        assert len(distinct) == 1, (
            f"shared block {block_id!r} resolves to {len(distinct)} different byte sequences "
            f"across conditions: {digests[block_id]}"
        )


# ------------------------------------------------------------------------------------------------
# Assertion 2 -- the token budget
# ------------------------------------------------------------------------------------------------


def test_every_condition_is_within_the_token_tolerance(report: ParityReport) -> None:
    """Section 3: total instruction tokens per condition within the tolerance of the mean.

    The tolerance is read from :mod:`agents.registry.limits`, never written here. Rule 20 is
    explicit that it is never loosened to make a change pass: "If token budgets across conditions
    diverge beyond the policy tolerance, the change is wrong -- fix the change, do not adjust the
    tolerance." A test carrying its own copy of the number would be the easiest place in the
    repository to loosen it without anyone noticing, because loosening a *test* reads as fixing a
    test.

    The unit is the distinct-block sum :class:`~agents.registry.composer.ComposedCondition`
    documents, not the per-instantiation sum: ``S1-HIER`` instantiates seven roles and ``S3-SINGLE``
    one, so a per-instantiation comparison would be unsatisfiable by construction, and a check that
    can only fail is not a check.
    """
    tolerance = float(resolve("condition_token_tolerance_pct"))
    totals = {condition: composed.total_tokens for condition, composed in report.conditions.items()}

    assert set(totals) == set(STRUCTURE_CONDITIONS), (
        f"composed {sorted(totals)}; the structure study is {sorted(STRUCTURE_CONDITIONS)}"
    )
    mean = sum(totals.values()) / len(totals)
    assert mean > 0, (
        "every condition composed to zero tokens, so the mean is zero and the tolerance is "
        "undefined; an equality over nothing is not an equality"
    )
    for condition in sorted(totals):
        deviation = abs(totals[condition] - mean) / mean * 100
        assert deviation <= tolerance, (
            f"{condition} composes {totals[condition]} instruction tokens, {deviation:.2f}% from "
            f"the cross-condition mean of {mean:.1f}, above the {tolerance}% tolerance "
            "prompt-parity-policy.md section 3 owns"
        )


def test_a_conditions_total_is_the_sum_of_the_distinct_blocks_it_references(
    report: ParityReport,
) -> None:
    """The number the tolerance bounds is the sum of the blocks, counted with the pinned tokenizer.

    Asserted rather than assumed because the tolerance above is a *ratio*, and a ratio is satisfied
    by any total that is wrong in the same direction for all three conditions. If ``total_tokens``
    ever came to mean something else -- a per-instantiation sum, a cached value, a count over
    rendered evidence -- all three would move together, the ratio would still pass, and the table
    would carry three numbers that no longer describe the registry.
    """
    for condition, composed in report.conditions.items():
        expected = sum(count_tokens(block.body) for block in composed.blocks.values())
        assert composed.total_tokens == expected, (
            f"{condition} reports {composed.total_tokens} tokens; its {len(composed.blocks)} "
            f"distinct blocks count {expected} with {REFERENCE_TOKENIZER_ID}"
        )


# ------------------------------------------------------------------------------------------------
# Assertion 3 -- tool identity
# ------------------------------------------------------------------------------------------------


def test_the_tool_registry_digest_is_identical_across_conditions(report: ParityReport) -> None:
    """Section 2 rule 3: the tool definitions are identical across conditions, and hashed.

    Recomputed here from each condition's tool names rather than read out of the report, so that
    this test would still fail if the gate stopped computing the digests at all. The hash is over
    *definitions* -- names, schemas, doc-block ids -- rather than over ``agents/tools/``: a
    directory hash would be identical across conditions by construction rather than by check, and
    an assertion that cannot fail is not an assertion.

    What may legitimately differ between conditions is which *node* holds which entry -- the
    issuance tool sits with the phase Supervisor in ``S1-HIER`` and with the coordinator in the
    other two, which is conflict M4-C7's resolution. That is a difference in wiring, and the union
    this digest is taken over is exactly what is blind to it.
    """
    digests = {
        condition: tool_registry_digest(definitions_for(composed.tool_names))
        for condition, composed in report.conditions.items()
    }
    assert set(digests.values()) == set(report.tool_digests.values()), (
        f"recomputed {digests}, the gate reported {dict(report.tool_digests)}"
    )
    distinct = set(digests.values())
    assert len(distinct) == 1, (
        f"the tool-registry digest differs across conditions: {digests}. A condition-only tool is "
        "forbidden outright by section 2 rule 3"
    )
    assert _SHA256.match(next(iter(distinct))), (
        f"the tool-registry digest {next(iter(distinct))!r} is not a sha256 hex digest"
    )


# ------------------------------------------------------------------------------------------------
# Assertion 4 -- the tool-call and turn budgets (traceability row T-37, conflict M4-C4)
# ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "attribute", "tolerance_key"),
    (
        ("turn", "max_turns", "condition_turn_tolerance_pct"),
        ("tool-call", "max_tool_calls", "condition_tool_call_tolerance_pct"),
    ),
)
def test_the_declared_budgets_agree_per_phase_across_conditions(
    registry: PromptRegistry, label: str, attribute: str, tolerance_key: str
) -> None:
    """Section 3.5.4: the flat and single arms get the hierarchy's *combined* per-phase allocation.

    The dissertation grants ``S2-FLAT`` "every phase the same budget of prompt tokens, tool calls,
    and turns as the hierarchical configuration's combined per-phase allocation". So the comparison
    is per phase, summed over roles: ``S1-HIER``'s per-role allocations must sum, in each phase, to
    ``S2-FLAT``'s coordinator budget and to ``S3-SINGLE``'s single-agent budget, and the three must
    be equal.

    This is the assertion conflict M4-C4 says had no artefact to assert over before M4. Tokens are
    countable from rendered prompts; tool calls and turns are runtime quantities that no file
    declared anywhere, so ``make parity-check`` could have reported green having compared one budget
    of three. They are declared now in each composition manifest and read twice -- here, and by
    ``agents/graphs/plan.py``, which enforces the same numbers -- which is the only arrangement in
    which the checked number and the enforced number cannot diverge.

    The comparison is an exact equality, and the tolerance is read first to establish that it may
    be: these are integers somebody wrote down, not measurements with error to absorb, so a non-zero
    tolerance would only ever license one arm quietly receiving more turns than another.
    """
    tolerance = float(resolve(tolerance_key))
    assert tolerance == 0, (
        f"{tolerance_key} is {tolerance}, so a strict equality is no longer the assertion section "
        "3 asks for; this test compares declared integers and must follow the caps block rather "
        "than outrun it"
    )

    hierarchical = registry.compositions["S1-HIER"]
    flat = registry.compositions["S2-FLAT"]
    single = registry.compositions["S3-SINGLE"]
    flat_role, single_role = _sole_role(flat), _sole_role(single)

    grand: dict[str, int] = dict.fromkeys(STRUCTURE_CONDITIONS, 0)
    for phase in PHASES:
        per_role = {
            role_id: getattr(budget, attribute)
            for role_id, budget in hierarchical.budgets[phase].items()
        }
        combined = sum(per_role.values())
        flat_allocation = getattr(flat.budgets[phase][flat_role], attribute)
        single_allocation = getattr(single.budgets[phase][single_role], attribute)

        assert combined == flat_allocation, (
            f"{label} budget in phase {phase!r}: S1-HIER's per-role allocations {per_role} sum to "
            f"{combined}, S2-FLAT's {flat_role!r} declares {flat_allocation}"
        )
        assert combined == single_allocation, (
            f"{label} budget in phase {phase!r}: S1-HIER's per-role allocations sum to {combined}, "
            f"S3-SINGLE's {single_role!r} declares {single_allocation}"
        )

        grand["S1-HIER"] += combined
        grand["S2-FLAT"] += flat_allocation
        grand["S3-SINGLE"] += single_allocation

    assert len(set(grand.values())) == 1, (
        f"the three conditions' total declared {label} budgets differ across the incident: {grand}"
    )
    assert next(iter(set(grand.values()))) > 0, (
        f"every condition declares a total {label} budget of zero across all four phases, so this "
        "equality held over nothing at all"
    )


def test_the_gate_reads_the_same_per_phase_budgets_this_file_does(report: ParityReport) -> None:
    """The gate's own per-phase sums agree with the manifests, phase by phase and arm by arm.

    Separate from the test above on purpose. That one asserts a property of the *registry*; this
    one asserts that the artefact the gate publishes -- and prints in the table a pull request
    carries -- describes that registry. A gate that summed the wrong roles would satisfy the first
    and fail this one.
    """
    for label, per_phase in (("turn", report.phase_turns), ("tool-call", report.phase_tool_calls)):
        assert set(per_phase) == set(PHASES), (
            f"the {label} budgets cover {sorted(per_phase)}; the incident lifecycle is "
            f"{sorted(PHASES)}"
        )
        for phase in PHASES:
            assert set(per_phase[phase]) == set(STRUCTURE_CONDITIONS), (
                f"the {label} budget for {phase!r} covers {sorted(per_phase[phase])}"
            )
            assert len(set(per_phase[phase].values())) == 1, (
                f"{label} budgets in phase {phase!r} differ across conditions: {per_phase[phase]}"
            )


# ------------------------------------------------------------------------------------------------
# Assertion 5 -- realizable mint-and-act pairs (M10, ADR-122)
# ------------------------------------------------------------------------------------------------


def test_realizable_action_budget_equal(registry: PromptRegistry, report: ParityReport) -> None:
    """Every arm can perform the same number of mint-and-act pairs, and can pay for them in turns.

    Section 3's M10 bullet, and the assertion the v1 defect V1 made necessary. Equal budgets are
    "necessary but not sufficient": in v1 ``S2-FLAT`` and ``S3-SINGLE`` declared exactly the
    per-phase allocation ``S1-HIER`` does, every one of the assertions above held, and the flat arm
    still reached the Guardian in 1 of 131 sealed runs. So the number this asserts is not "the
    budgets are equal" -- assertion 4 has that -- it is "the arm can actually act under the budget
    it holds", which is a different claim about the same numbers.

    Three claims, and the first is the one assertion 4 cannot make:

    * **a reachable issuer.** Every role that holds ``guardian_action`` can obtain the capability it
      spends, either by holding the issuance tool itself (``S2-FLAT``'s coordinator and
      ``S3-SINGLE``'s agent -- the self-mint, which is what ``_conduct`` takes when a role holds
      both) or by being the delegate of a role that does (``S1-HIER``'s Supervisor, whose allocation
      the runtime shares with the Executor it builds, ADR-092). Read off the manifest, by tool name,
      so the assertion follows the wiring rather than a table of role ids;
    * **equal pair counts per phase.** A pair costs two tool calls and two turns, and the count is
      ``min(turns // 2, calls // 2)`` over the same per-phase sums assertion 4 compares -- held
      equal
      within ``condition_tool_call_tolerance_pct``, which is read first and asserted to be zero for
      the reason :mod:`agents.registry.limits` gives (declared integers, not measurements);
    * **turns sufficient to pay for them.** Each condition's declared ``max_turns`` covers
      ``2 * (tool_calls // 2)`` -- twice every pair its *tool-call* budget would buy. That is not
      the
      same as covering its own realizable count (which is a tautology, being its own minimum), and
      it
      is the half assertion 4 cannot see: a phase can declare eight tool calls and seven turns,
      match
      the other two conditions on both, and still be unable to turn its own budget into actions.
      Section 3's own words for that: "``max_turns`` did not cover a mint-then-act pair in one
      iteration".
    """
    tolerance = float(resolve("condition_tool_call_tolerance_pct"))
    assert tolerance == 0, (
        f"condition_tool_call_tolerance_pct is {tolerance}. It is the same declared-integer "
        "tolerance assertion 4 uses and must be zero; a non-zero value here would license one arm "
        "performing measurably fewer mint-and-act pairs than another"
    )

    actors_seen = 0
    for condition in STRUCTURE_CONDITIONS:
        composition = registry.compositions[condition]
        for phase in PHASES:
            roles = [role for role in composition.roles if role.phase in (None, phase)]
            actors = [role for role in roles if ACTION_TOOL.name in role.tools]
            issuers = [role for role in roles if ISSUE_TOKEN_TOOL.name in role.tools]
            actors_seen += len(actors)
            unreachable = [
                role.role_id
                for role in actors
                if ISSUE_TOKEN_TOOL.name not in role.tools and not issuers
            ]
            assert not unreachable, (
                f"{condition} in phase {phase!r}: {unreachable} hold(s) {ACTION_TOOL.name} and no "
                f"role in the phase holds {ISSUE_TOKEN_TOOL.name}. A mediated action needs a "
                "single-use capability, so an acting role with no reachable issuer can hold the"
                " tool "
                "and never spend it -- and no budget assertion can see that"
            )

    assert actors_seen >= len(STRUCTURE_CONDITIONS) * len(PHASES), (
        f"{actors_seen} acting role(s) were found across every condition and phase, fewer than one "
        f"per cell ({len(STRUCTURE_CONDITIONS)} conditions x {len(PHASES)} phases). The "
        "reachability check above would then have compared nothing, and a registry in which no"
        " role "
        "acts would satisfy it perfectly"
    )

    assert set(report.realizable_pairs) == set(STRUCTURE_CONDITIONS), (
        f"the gate published realizable pair counts for {sorted(report.realizable_pairs)}"
    )
    for phase in PHASES:
        counts = {
            condition: report.realizable_pairs[condition][phase]
            for condition in STRUCTURE_CONDITIONS
        }
        assert len(set(counts.values())) == 1, (
            f"in phase {phase!r} the arms can perform different numbers of mint-and-act pairs: "
            f"{counts}. Section 3.5.4 grants the flat arm the hierarchy's combined per-phase "
            "allocation precisely so that the arms have equal capacity to act on the same incident"
        )
        for condition in STRUCTURE_CONDITIONS:
            pairs = counts[condition]
            assert pairs > 0, (
                f"{condition} can perform {pairs} mint-and-act pair(s) in phase {phase!r}. An arm "
                "with no realizable pair cannot act at all under any budget, which is V1's"
                " measured "
                "outcome rather than a topology result"
            )
            turns = report.phase_turns[phase][condition]
            calls = report.phase_tool_calls[phase][condition]
            assert turns >= 2 * (calls // 2), (
                f"{condition} in phase {phase!r} declares {turns} turn(s) against {calls} tool "
                f"call(s): the tool-call budget buys {calls // 2} mint-and-act pair(s) and each "
                "needs two model calls, so the phase would end budget-exhausted holding unspent "
                "capability. A retry is a turn (ADR-028), so two is the floor"
            )

    # The gate's own number, re-derived from the manifests rather than read off the report, so a
    # gate that computed it some other way is caught here rather than agreeing with itself.
    for condition in STRUCTURE_CONDITIONS:
        for phase in PHASES:
            allocations = registry.compositions[condition].budgets[phase]
            derived = min(
                sum(budget.max_turns for budget in allocations.values()) // 2,
                sum(budget.max_tool_calls for budget in allocations.values()) // 2,
            )
            assert report.realizable_pairs[condition][phase] == derived, (
                f"{condition} in phase {phase!r}: the gate reports "
                f"{report.realizable_pairs[condition][phase]} pair(s) where the manifest's own"
                " sums "
                f"give {derived}. The published number goes in the token table a pull request "
                "carries, so it has to be the one the reader can re-derive"
            )


def test_the_gate_publishes_the_pair_counts_the_table_prints(report: ParityReport) -> None:
    """The pair counts appear in the emitted table, so the number is reviewable before merging.

    Section 4 requires every pull request touching ``agents/prompts/`` or ``agents/tools/`` to carry
    the table, and a realizable-action number that only lives inside the checker is a number nobody
    reads before approving a rebalanced budget.
    """
    table = render_table(report)
    assert "realizable" in table.lower(), (
        "the emitted table carries no realizable-action block. Section 4 makes this table the "
        "artefact a reviewer reads, and the pair counts are the only part of assertion 5 a human "
        "can look at"
    )
    for phase in PHASES:
        row = [line for line in table.splitlines() if line.strip().startswith(phase)]
        assert row, f"the table has no realizable-action row for phase {phase!r}"
        for condition in STRUCTURE_CONDITIONS:
            assert str(report.realizable_pairs[condition][phase]) in " ".join(row), (
                f"the {phase!r} row does not carry {condition}'s count of "
                f"{report.realizable_pairs[condition][phase]}"
            )


# ------------------------------------------------------------------------------------------------
# The structural cap, and the verdict
# ------------------------------------------------------------------------------------------------


def test_every_structural_block_is_within_the_cap(report: ParityReport) -> None:
    """Section 3's per-block cap on the topology-necessitated connective text.

    The cap is the only thing standing between "a sentence saying who you report to" and "a second
    helping of guidance under a topology label". The ±2% aggregate tolerance cannot do this job on
    its own: a structural block can grow a long way inside a 2% band of a seven-thousand-token
    total, and what it would be growing into is guidance, which is exactly the confound section
    3.4.3 names.
    """
    cap = float(resolve("structural_block_tokens_max"))
    assert report.structural_tokens, (
        "the registry holds no block tagged parity_class: structural, so the cap bounded nothing. "
        "Each condition needs its own connective text, and a registry with none is one whose "
        "topology differences have gone somewhere the cap cannot see"
    )
    for block_id in sorted(report.structural_tokens):
        size = report.structural_tokens[block_id]
        assert size <= cap, (
            f"structural block {block_id!r} is {size} reference tokens, above the cap of "
            f"{int(cap)} frozen in prompt-parity-policy.md section 3"
        )


def test_check_parity_passes_on_the_shipped_registry(report: ParityReport) -> None:
    """The gate's own verdict: every assertion held, and every one of them could be made.

    ``blocking`` and ``failures`` are asserted separately because they are different findings with
    different remedies -- "parity was not established" and "parity is violated" -- and a suite that
    only read ``passed`` would report the two as one.
    """
    assert report.blocking == [], (
        f"parity could not be established: {report.blocking}. This is not a violated assertion; it "
        "is an assertion that was never made"
    )
    assert report.failures == [], f"parity assertions did not hold: {report.failures}"
    assert report.passed, "check_parity() reported failure with neither a blocking nor a failure"
    assert set(report.conditions) == set(STRUCTURE_CONDITIONS), (
        f"the gate composed {sorted(report.conditions)}; the structure study is "
        f"{sorted(STRUCTURE_CONDITIONS)}"
    )


# ------------------------------------------------------------------------------------------------
# The output is the artefact (section 3, section 4, traceability row T-45)
# ------------------------------------------------------------------------------------------------


def test_the_table_names_the_tokenizer_and_the_registry_digest(
    registry: PromptRegistry, report: ParityReport
) -> None:
    """The emitted table carries the two facts that make its numbers reproducible.

    Section 3 requires a "per-condition token table (written into the M4/GATE record)" and section 4
    requires every pull request touching ``agents/prompts/`` or ``agents/tools/`` to carry it. The
    table's *content* is therefore a contract rather than a convenience: a token count without the
    tokenizer that produced it and the registry it was computed over is a number nobody can
    reproduce, and reproducing it from a clean checkout with no credential is traceability row
    T-45's whole claim.
    """
    table = render_table(report)

    assert REFERENCE_TOKENIZER_ID in table, (
        f"the table does not name the tokenizer ({REFERENCE_TOKENIZER_ID}); the count is then a "
        "number in no stated unit"
    )
    assert _SHA256.match(report.registry_digest), (
        f"the registry digest {report.registry_digest!r} is not a sha256 hex digest"
    )
    assert report.registry_digest == directory_digest(registry.root), (
        "the table's registry digest does not describe the registry that was composed"
    )
    assert report.registry_digest in table, "the table does not carry the registry digest"

    for condition in STRUCTURE_CONDITIONS:
        assert condition in table, f"the table has no row for {condition}"
        assert str(report.conditions[condition].total_tokens) in table, (
            f"the table does not carry {condition}'s token total"
        )
        assert report.tool_digests[condition] in table, (
            f"the table does not carry {condition}'s tool-registry digest"
        )
    for phase in PHASES:
        assert phase in table, f"the table has no per-phase budget row for {phase!r}"


def test_main_exits_zero_and_prints_the_table(capsys: pytest.CaptureFixture[str]) -> None:
    """``make parity-check`` succeeds on the shipped registry and emits the table on stdout.

    The end-to-end shape of the gate ``scripts/parity_check.sh`` delegates to, exercised through the
    entry point rather than through :func:`~agents.registry.parity.check_parity`, because the exit
    code is what CI reads and it is produced by :func:`~agents.registry.parity.main` alone. The
    default registry root is resolved from the module's own ``__file__``, so this passes no path and
    still does not depend on the working directory.
    """
    code = main([])
    captured = capsys.readouterr()

    assert code == 0, (
        f"parity-check exited {code} on the shipped registry; stderr said:\n{captured.err}"
    )
    assert REFERENCE_TOKENIZER_ID in captured.out, "the table did not reach stdout"
    assert "PASS" in captured.out, f"stdout carries no verdict line:\n{captured.out}"
    for condition in STRUCTURE_CONDITIONS:
        assert condition in captured.out, f"stdout has no row for {condition}"
