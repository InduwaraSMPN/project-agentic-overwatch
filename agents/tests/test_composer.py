r"""The composer authors nothing: a role's prompt is its blocks' bytes, joined, in manifest order.

WHAT THIS TEST IS FOR
---------------------
:mod:`agents.registry.composer` is shared by ``make parity-check`` and by the graph runtime, and its
docstring says why that sharing is the point: "a checker with its own rendering path measures a
prompt no run ever used". One composer means the number the gate reports and the bytes a model
receives come from the same function. What that arrangement does **not** by itself guarantee is that
the function is faithful -- a composer that inserted a heading, sorted blocks by id, or trimmed a
trailing newline would do it identically for both callers, and both would agree about text no block
in ``agents/prompts/`` authored.

So the assertions below reconstruct each composed role independently, from
:meth:`~agents.registry.loader.PromptRegistry.block` bodies and the published separator, and compare
byte for byte. Reconstruction rather than a property check, because the failures worth catching here
are small: one extra newline between blocks changes every token count in the parity table, and a
sorted block list changes what a model reads first while leaving the count untouched.

WHY "NO TEXT OF ITS OWN" IS CHECKED TWICE, IN TWO DIFFERENT UNITS
-------------------------------------------------------------------
Once by reconstruction, which catches anything at all; and once over the *set of characters* in a
composed role's text, which catches the case reconstruction would miss if the reconstruction itself
were ever rewritten to share a helper with the composer. The second check needs no knowledge of
the joining rule: whatever the composer does, it may not introduce a character that no block body
and no separator contains. ``scripts/prompt_purity_grep.sh`` asserts the same boundary from the
file side -- every byte a model reads lives in ``agents/prompts/`` -- and this is that boundary
asserted from the runtime side, where a violation would actually reach a model.

WHY BLOCK ORDER IS A CORRECTNESS PROPERTY AND NOT A PREFERENCE
----------------------------------------------------------------
:func:`~agents.registry.composer.compose_role` refuses to reorder, deduplicate or supply a default
block, and its docstring names the reason: each of those "would be defensible in isolation and would
each move a composition decision out of the registry and into code, where Chapter 3 cannot describe
it and a reviewer reading the manifest would not see it". The manifest is the artefact the
dissertation describes. A composer that reordered would make the described artefact and the executed
one two different things, and no gate anywhere in this repository would notice, because every gate
reads the composer's output.

WHAT THE SHARED/STRUCTURAL SPLIT HAS TO BE
--------------------------------------------
Section 2 rule 2 divides a role's blocks into exactly two classes and section 3 treats them
differently: ``shared`` blocks must be byte-identical across conditions, ``structural`` blocks are
the topology-necessitated residue a per-block cap bounds. :meth:`ComposedRole.structural_blocks` and
:meth:`ComposedRole.shared_blocks` are what the gate partitions by, so a block that fell into
neither, or into both, would be a block the gate either never compares or compares under the wrong
rule. The partition is asserted below as a partition -- disjoint, exhaustive, order-preserving --
rather than as two independent filters that happen to agree today.

WHAT THIS FILE DELIBERATELY DOES NOT CHECK
--------------------------------------------
*Whether the totals are inside the tolerance.* That is ``make parity-check``'s verdict and the
parity module's subject. What is asserted here is that shared blocks carried by two conditions are
the same bytes in both -- which is the fact the verdict rests on, and is checkable without any
number the protocol owns.

*Token counts.* :mod:`agents.registry.tokenizer` is ``test_reference_tokenizer.py``'s subject.
"""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agents.registry import STRUCTURE_CONDITIONS  # noqa: E402
from agents.registry.composer import (  # noqa: E402
    BLOCK_SEPARATOR,
    ComposedCondition,
    compose_condition,
)
from agents.registry.loader import PromptRegistry, RegistryError  # noqa: E402


def composed_all(registry: PromptRegistry) -> dict[str, ComposedCondition]:
    """Compose every structure condition once, so each test states its subject in one line."""
    return {condition: compose_condition(registry, condition) for condition in STRUCTURE_CONDITIONS}


def test_every_structure_condition_composes(registry: PromptRegistry) -> None:
    """All three conditions compose, and the registry declares exactly those three.

    Both halves matter. Parity asserts an equality *across* conditions, so a condition that failed
    to compose would leave the comparison making a claim about two arms while reporting on three;
    and a fourth manifest nobody expected would be an arm the gate compares and the glossary does
    not name.
    """
    assert set(registry.compositions) == set(STRUCTURE_CONDITIONS), (
        f"the registry declares conditions {sorted(registry.compositions)} but the package names "
        f"{sorted(STRUCTURE_CONDITIONS)}; parity compares exactly the arms that exist"
    )
    for condition, composed in composed_all(registry).items():
        assert composed.condition == condition
        assert composed.roles, f"{condition} composed no roles at all"
        for role_id, role in composed.roles.items():
            assert role.role_id == role_id
            assert role.text.strip(), (
                f"{condition}/{role_id} composed to text that is entirely whitespace"
            )
            assert role.blocks, f"{condition}/{role_id} composed from no blocks"


def test_a_composed_role_is_its_blocks_joined_in_manifest_order(registry: PromptRegistry) -> None:
    """Reconstruct each role from ``registry.block(...)`` bodies and compare byte for byte.

    The reconstruction uses the manifest's declared order and the composer's published separator and
    nothing else, so a passing assertion says three things at once: the order is the manifest's, the
    bodies are unedited, and the separator is the one constant the module publishes rather than a
    literal buried in the join.
    """
    for condition, composed in composed_all(registry).items():
        declared = registry.compositions[condition]
        for role_id, role in composed.roles.items():
            block_ids = declared.role(role_id).block_ids
            bodies = [registry.block(block_id).body for block_id in block_ids]
            expected = BLOCK_SEPARATOR.join(bodies)
            assert role.text == expected, (
                f"{condition}/{role_id}: the composed text is not its blocks joined by "
                f"{BLOCK_SEPARATOR!r} in the order {list(block_ids)}"
            )
            assert tuple(block.block_id for block in role.blocks) == block_ids, (
                f"{condition}/{role_id}: composed blocks are {[b.block_id for b in role.blocks]}, "
                f"but the manifest declares {list(block_ids)}. Reordering moves a composition "
                "decision out of the registry and into code"
            )


def test_composition_introduces_no_character_a_block_did_not_author(
    registry: PromptRegistry,
) -> None:
    """The characters in a composed role's text are exactly those of its bodies plus separators.

    A weaker statement than the reconstruction above and a differently-shaped one: it knows nothing
    about the joining rule, so it still holds if the joining rule changes, and it would still catch
    a preamble, a heading, a bullet marker or a numbering scheme introduced in code. Every byte a
    model reads lives in ``agents/prompts/``; this is that rule stated in the one unit that cannot
    be satisfied by an accidental agreement between the composer and its test.
    """
    for condition, composed in composed_all(registry).items():
        for role_id, role in composed.roles.items():
            authored = set("".join(block.body for block in role.blocks)) | set(BLOCK_SEPARATOR)
            introduced = set(role.text) - authored
            assert not introduced, (
                f"{condition}/{role_id}: the composed text contains {sorted(introduced)!r}, which "
                "appears in no block body and is not the separator -- the composer authored text"
            )


def test_every_block_body_survives_composition_verbatim(registry: PromptRegistry) -> None:
    """Each block's body appears in the composed text of every role that carries it, unedited.

    The complement of the character-set check: that one bounds what may be added, this one bounds
    what may be removed or rewritten. A composer that stripped trailing whitespace, re-wrapped a
    paragraph or normalised a quotation mark would still pass a character-set check while sending a
    model something no reviewer of ``agents/prompts/`` ever read.
    """
    for condition, composed in composed_all(registry).items():
        for role_id, role in composed.roles.items():
            for block in role.blocks:
                assert block.body in role.text, (
                    f"{condition}/{role_id}: block {block.block_id!r} does not appear verbatim in "
                    "the composed text, so composition edited it"
                )


def test_shared_blocks_are_byte_identical_across_the_conditions_that_carry_them(
    registry: PromptRegistry,
) -> None:
    """A non-``structural`` block carried by two conditions is the same bytes in both.

    This is the fact section 3's equality rests on, asserted without any tolerance number: what
    differs between the arms must be topology, and a ``shared`` block that differed would be
    guidance differing under a label that says it does not. Digests are compared rather than text so
    that a failure can name the block without printing it, which is why
    :attr:`~agents.registry.loader.PromptBlock.digest` exists.
    """
    seen: dict[str, tuple[str, str]] = {}
    compared = 0
    for condition, composed in composed_all(registry).items():
        for block_id, block in composed.blocks.items():
            if block.is_structural:
                continue
            previous = seen.get(block_id)
            if previous is None:
                seen[block_id] = (condition, block.digest)
                continue
            compared += 1
            assert block.digest == previous[1], (
                f"shared block {block_id!r} digests {block.digest} in {condition} and "
                f"{previous[1]} in {previous[0]}; section 3 requires it byte-identical"
            )
    assert compared, (
        "no shared block is carried by more than one condition, so this test compared nothing. "
        "Section 2 rule 2 requires every shared block to be carried by some role of every condition"
    )


def test_structural_and_shared_partition_a_role_exactly(registry: PromptRegistry) -> None:
    """Every block of a role is in exactly one of the two classes, and order is preserved in each.

    Asserted as a partition rather than as two filters agreeing by coincidence: a block in neither
    is a block the gate never looks at, and a block in both would be counted twice by whichever
    consumer summed the two. Order is checked as well because both accessors are used to build
    report rows, and a row order that depended on filtering would be a table nobody could diff.
    """
    for condition, composed in composed_all(registry).items():
        for role_id, role in composed.roles.items():
            structural = role.structural_blocks()
            shared = role.shared_blocks()

            structural_ids = [block.block_id for block in structural]
            shared_ids = [block.block_id for block in shared]
            all_ids = [block.block_id for block in role.blocks]

            assert not set(structural_ids) & set(shared_ids), (
                f"{condition}/{role_id}: {sorted(set(structural_ids) & set(shared_ids))} are "
                "reported as both structural and shared"
            )
            assert sorted(structural_ids + shared_ids) == sorted(all_ids), (
                f"{condition}/{role_id}: the two classes hold "
                f"{sorted(structural_ids + shared_ids)} but the role carries {sorted(all_ids)}"
            )
            assert structural_ids == [i for i in all_ids if i in set(structural_ids)], (
                f"{condition}/{role_id}: structural_blocks() reordered the role's blocks"
            )
            assert shared_ids == [i for i in all_ids if i in set(shared_ids)], (
                f"{condition}/{role_id}: shared_blocks() reordered the role's blocks"
            )
            for block in structural:
                assert block.is_structural, (
                    f"{condition}/{role_id}: {block.block_id!r} is reported structural but "
                    f"declares parity_class {block.parity_class!r}"
                )
            for block in shared:
                assert not block.is_structural, (
                    f"{condition}/{role_id}: {block.block_id!r} is reported shared but declares "
                    f"parity_class {block.parity_class!r}"
                )


def test_the_distinct_block_mapping_covers_every_role_and_is_sorted(
    registry: PromptRegistry,
) -> None:
    """``ComposedCondition.blocks`` is the union of the roles' blocks, keyed by id, in sorted order.

    Sorted rather than first-seen because this mapping is what a parity report iterates and what a
    failure names. Rule 20 forbids anything a run depends on resting on the order roles happened to
    be declared in, and a gate verdict is such a thing.
    """
    for condition, composed in composed_all(registry).items():
        union = {block.block_id for role in composed.roles.values() for block in role.blocks}
        assert set(composed.blocks) == union, (
            f"{condition}: the distinct-block mapping holds {sorted(composed.blocks)} but the "
            f"roles carry {sorted(union)}"
        )
        assert list(composed.blocks) == sorted(composed.blocks), (
            f"{condition}: the distinct-block mapping is keyed in {list(composed.blocks)} order, "
            "which is not sorted"
        )


def test_an_unknown_role_is_refused_by_name(registry: PromptRegistry) -> None:
    """``ComposedCondition.role()`` raises, naming the condition and what it actually composes.

    A ``KeyError`` carrying only the missing name would send a caller back to re-derive what the
    object already knows. The caller here is a graph asking for a node's prompt, and the useful next
    step is to see which roles this condition has -- which is exactly the difference between the
    arms.
    """
    for condition, composed in composed_all(registry).items():
        with pytest.raises(RegistryError) as caught:
            composed.role("no-such-role-in-any-condition")
        message = str(caught.value)
        assert condition in message, f"the refusal does not name the condition: {message}"
        assert "no-such-role-in-any-condition" in message, (
            f"the refusal does not name the role that was asked for: {message}"
        )
        for role_id in composed.roles:
            assert role_id in message, (
                f"the refusal does not list {role_id!r} among what {condition} composes: {message}"
            )


def test_an_unknown_condition_is_refused_by_name(registry: PromptRegistry) -> None:
    """Composing a condition with no manifest raises rather than returning an empty composition.

    The fail-closed half of the gate's contract, stated at the earliest point it can be. Parity
    asserts an equality across conditions, so a missing condition means nothing was proved rather
    than nothing being wrong -- and a checker that skipped it would make deleting a manifest the
    easiest way to pass.
    """
    with pytest.raises(RegistryError) as caught:
        compose_condition(registry, "X9-NO-SUCH-CONDITION")
    message = str(caught.value)
    assert "X9-NO-SUCH-CONDITION" in message, (
        f"the refusal does not name the condition that was asked for: {message}"
    )
    for condition in STRUCTURE_CONDITIONS:
        assert condition in message, (
            f"the refusal does not list {condition!r} among what the registry declares: {message}"
        )
