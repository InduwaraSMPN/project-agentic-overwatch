r"""The loader's strictness, pinned: what the registry must say, and what it must refuse to read.

WHAT THIS TEST IS FOR
---------------------
:mod:`agents.registry.loader` is the only reader of ``agents/prompts/`` in the repository, and it
parses those files with a hand-written **subset** of YAML rather than with PyYAML -- conflict M4-C1,
because ``make parity-check`` runs in a CI job that installs nothing. Its own docstring states the
consequence that makes this file necessary: "a parser that shrugs at a line it does not recognise
could silently miss the very key it exists to compare, and a block this reader half-understands is a
block it cannot be trusted about."

That sentence is a claim about behaviour, and until something drives a malformed file through the
parser and watches it refuse, it is only a claim. The negative fixtures below are what turn it into
a check. Each one is a file a *real* YAML parser would happily read into something -- a line
indented three spaces, a top-level key nobody declared, a phase whose budget is simply absent -- and
each must raise, naming the file, rather than parse into a registry that is quietly missing a
constraint.

WHY A SHRUG WOULD BE INVISIBLE RATHER THAN NOISY
-------------------------------------------------
Consider the failure this file is written against. A tolerant parser reads
``agents/prompts/compositions/S2-FLAT.yaml``, silently drops one line it does not recognise, and
returns a composition with one fewer block. ``make parity-check`` then compares three conditions
composed from what the parser understood, finds them within tolerance, and reports green. The gate
has compared the parser's reading rather than the registry, and the run that follows sends a prompt
the gate never counted. Nothing in the output of any tool says so.

The same argument applies to every positive assertion here. ``parity_class`` decides whether the
gate compares a block at all, so a block with an unrecognised class must not be admitted with a
default. A block id must equal its filename stem, or a rename orphans a block while leaving every
manifest green. A manifest reference to a block that does not exist is not a parity failure to be
tabulated later -- it is a registry that cannot be composed, and the graph that loaded it must not
run.

WHY THE FIXTURES LOOK LIKE NOTHING SHIPPED
--------------------------------------------
Every fixture below is written into ``tmp_path`` and uses a condition id, role id and block ids
that appear nowhere in ``agents/prompts/``, for the reason
``monitor/tests/test_limits_match_protocol.py`` gives about its own inline block: a fixture that
resembled a real file would become a second home for something, and a grep over the repository
would find it. The fixtures exercise the *grammar*; the shipped registry, read through the
session-scoped ``registry`` fixture, is what the positive assertions are made about.

WHAT THIS FILE DELIBERATELY DOES NOT CHECK
--------------------------------------------
*Parity verdicts.* Whether the three conditions' token totals sit inside the policy's tolerance is
``make parity-check``'s answer, not the loader's, and :func:`~agents.registry.loader.load_registry`
is explicit that it does not raise for one. A loader that refused an over-budget registry would make
the gate unable to report what was wrong.

*Composition.* Turning a role's block list into the bytes a model receives is
:mod:`agents.registry.composer`'s job and ``test_composer.py``'s subject.

*That every block file is reachable from some manifest.* That direction is
``scripts/prompt_purity_grep.sh``'s boundary. This file asserts the other one: every id a manifest
names exists.
"""

import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agents.registry import PHASES  # noqa: E402
from agents.registry.loader import (  # noqa: E402
    BLOCK_ID_PATTERN,
    BLOCK_SUFFIX,
    BLOCKS_DIRNAME,
    COMPOSITIONS_DIRNAME,
    ENGINEERING_ORIGIN,
    MANIFEST_SUFFIX,
    PARITY_CLASSES,
    ManifestSyntaxError,
    PromptRegistry,
    RegistryError,
    load_registry,
)

# --------------------------------------------------------------------------------------------
# The fixture registry. Every identifier below is deliberately unlike anything in agents/prompts/.
# --------------------------------------------------------------------------------------------

FIXTURE_CONDITION = "X9-FIXTURE"
FIXTURE_ROLE_ID = "sole-fixture-role"
FIXTURE_BLOCK_IDS = ("fixture.alpha", "fixture.beta")

# Provenance that satisfies parity policy section 2 rule 4 by the engineering-origin route, which is
# the route a fixture must take: it has no dissertation anchor and inventing one would put a string
# resembling a source anchor into a file that is not prompt text.
FIXTURE_PROVENANCE = (
    f"origin: {ENGINEERING_ORIGIN}\n"
    "justification: a fixture block written for agents/tests/, standing for nothing shipped\n"
)

# Budget values chosen to resemble no allocation any manifest declares, so that a grep for a real
# per-role allocation cannot land here. The loader checks the shape of a budget and never its size.
FIXTURE_MAX_TURNS = 991
FIXTURE_MAX_TOOL_CALLS = 997

# One tool name from agents/tools/registry.py, because the loader validates that `tools` is a list
# of strings and nothing more -- the name has to be spelled, and spelling a real one keeps the
# fixture from implying that an invented tool would be accepted.
FIXTURE_TOOL = "guardian_action"


def block_text(
    block_id: str,
    *,
    parity_class: str = "shared",
    provenance: str = FIXTURE_PROVENANCE,
    body: str = "A fixture block body, one line of it.",
) -> str:
    """Return one block file: the front-matter fence, a header, the closing fence, and a body."""
    return f"---\nid: {block_id}\nparity_class: {parity_class}\n{provenance}---\n{body}\n"


def manifest_text(
    *,
    condition: str = FIXTURE_CONDITION,
    role_id: str = FIXTURE_ROLE_ID,
    block_ids: Sequence[str] = FIXTURE_BLOCK_IDS,
    phases: Sequence[str] = PHASES,
    tools: Sequence[str] = (FIXTURE_TOOL,),
    extra: str = "",
) -> str:
    """Return one composition manifest in the loader's grammar, assembled line by line.

    Assembled rather than held as one literal so that a negative fixture can remove exactly one
    phase's budget, or add exactly one unknown key, without a string replacement that might also
    match somewhere the test did not intend.
    """
    lines = [
        f"condition: {condition}",
        f"issuance_tool_holder: {role_id}",
        "roles:",
        f"  - id: {role_id}",
        "    node: coordination",
        "    phase: null",
        "    blocks:",
        *(f"      - {block_id}" for block_id in block_ids),
        "    tools:",
        *(f"      - {tool}" for tool in tools),
        "budgets:",
    ]
    for phase in phases:
        lines += [
            f"  {phase}:",
            f"    {role_id}:",
            f"      max_turns: {FIXTURE_MAX_TURNS}",
            f"      max_tool_calls: {FIXTURE_MAX_TOOL_CALLS}",
        ]
    return "\n".join(lines) + "\n" + extra


def write_bytes_with(path: Path, text: str, newline: str) -> None:
    """Write ``text`` with ``newline`` as its line ending, bypassing universal-newline translation.

    ``Path.write_text`` on Windows would translate ``"\\n"`` to ``"\\r\\n"`` on its own, which would
    make the CRLF-versus-LF case below compare a file against itself.
    """
    path.write_bytes(text.replace("\n", newline).encode("utf-8"))


def write_registry(
    root: Path,
    *,
    blocks: Mapping[str, str] | None = None,
    manifest: str | None = None,
    condition: str = FIXTURE_CONDITION,
    newline: str = "\n",
) -> Path:
    """Write a complete, minimal registry under ``root`` and return ``root``."""
    blocks_dir = root / BLOCKS_DIRNAME
    compositions_dir = root / COMPOSITIONS_DIRNAME
    blocks_dir.mkdir(parents=True, exist_ok=True)
    compositions_dir.mkdir(parents=True, exist_ok=True)

    contents = (
        {block_id: block_text(block_id) for block_id in FIXTURE_BLOCK_IDS}
        if blocks is None
        else blocks
    )
    for block_id, text in contents.items():
        write_bytes_with(blocks_dir / f"{block_id}{BLOCK_SUFFIX}", text, newline)
    write_bytes_with(
        compositions_dir / f"{condition}{MANIFEST_SUFFIX}",
        manifest_text() if manifest is None else manifest,
        newline,
    )
    return root


# --------------------------------------------------------------------------------------------
# What the shipped registry must say
# --------------------------------------------------------------------------------------------


def test_every_shipped_block_declares_a_known_parity_class(registry: PromptRegistry) -> None:
    """Every block carries ``parity_class`` from the closed set, so none is classed by default.

    Parity policy section 2 rule 2 is the whole reason: ``structural`` is the tagged class the
    per-block cap bounds and ``shared`` is what the gate requires byte-identical across conditions.
    A block whose class the loader had to guess would be a block the gate treats one way today and
    another way after a refactor, with nothing in between saying so.
    """
    assert registry.blocks, "the shipped registry loaded no blocks at all"
    for block in registry.blocks.values():
        assert block.parity_class in PARITY_CLASSES, (
            f"{block.path.as_posix()} declares parity_class {block.parity_class!r}, which is not "
            f"one of {PARITY_CLASSES}. Section 2 rule 2 defines exactly these two"
        )


def test_every_shipped_block_states_its_provenance(registry: PromptRegistry) -> None:
    """Rule 4, both halves: a source anchor, or an engineering origin *with* a justification.

    Never both, and never neither. A block claiming a source and declaring itself
    engineering-authored is a block whose provenance nobody can state in Chapter 3, and an
    ``origin: engineering`` tag with no justification is the tag doing no work.
    """
    for block in registry.blocks.values():
        where = block.path.as_posix()
        assert not (block.source_anchor and block.origin), (
            f"{where} carries both source_anchor {block.source_anchor!r} and origin "
            f"{block.origin!r}; section 2 rule 4 admits one route to provenance, not two at once"
        )
        if block.source_anchor:
            assert block.source_anchor.strip(), f"{where} has an empty source_anchor"
            continue
        assert block.origin == ENGINEERING_ORIGIN, (
            f"{where} has no source_anchor and declares origin {block.origin!r} rather than "
            f"{ENGINEERING_ORIGIN!r}; those are the only two ways a block may be grounded"
        )
        assert block.justification and block.justification.strip(), (
            f"{where} is tagged {ENGINEERING_ORIGIN!r} with no justification; the tag without the "
            "reason is the tag doing no work"
        )


def test_every_block_id_matches_the_pattern_and_its_filename(registry: PromptRegistry) -> None:
    """A block's id matches the declared pattern, equals its filename stem, and is unique.

    The filename is what a reviewer greps and the id is what a manifest references. If the two could
    disagree, a rename would orphan a block while leaving every manifest green -- a prompt silently
    dropped from a condition with no gate reporting anything.
    """
    pattern = re.compile(BLOCK_ID_PATTERN)
    seen: dict[str, Path] = {}
    for block_id, block in registry.blocks.items():
        assert block.block_id == block_id, (
            f"the registry keys {block.path.as_posix()} under {block_id!r} while the "
            f"block declares {block.block_id!r}"
        )
        assert pattern.match(block_id), (
            f"{block.path.as_posix()}: id {block_id!r} is outside {BLOCK_ID_PATTERN}. Lowercase "
            "dotted segments, so that a case-insensitive filesystem cannot make two ids one file"
        )
        assert block.path.stem == block_id, (
            f"{block.path.as_posix()} declares id {block_id!r} but its filename stem is "
            f"{block.path.stem!r}"
        )
        assert block_id not in seen, (
            f"block id {block_id!r} is declared by both {seen.get(block_id)} and {block.path}"
        )
        seen[block_id] = block.path


def test_every_block_a_manifest_references_exists(registry: PromptRegistry) -> None:
    """Every id named by every role of every shipped condition resolves to a loaded block.

    Asserted over the loaded registry as well as being enforced inside the loader, because this is
    the direction that fails at run time rather than at review time: a composition naming a block
    that does not exist is a registry that cannot be composed, and the graph that loaded it must not
    run.
    """
    assert registry.compositions, "the shipped registry loaded no composition manifests"
    for composition in registry.compositions.values():
        for role in composition.roles:
            assert role.block_ids, (
                f"{composition.path.as_posix()}: role {role.role_id!r} carries no blocks"
            )
            for block_id in role.block_ids:
                assert block_id in registry.blocks, (
                    f"{composition.path.as_posix()}: role {role.role_id!r} references block "
                    f"{block_id!r}, which the registry does not hold"
                )
                # registry.block() is the accessor the composer uses; a mapping hit that the
                # accessor missed would be a difference between what this test proves and what a
                # run does.
                assert registry.block(block_id).block_id == block_id


def test_tool_names_are_sorted_for_every_shipped_condition(registry: PromptRegistry) -> None:
    """``Composition.tool_names()`` is sorted and deduplicated, whatever order the roles declare.

    Order-dependence here would be a gate defect rather than a cosmetic one. The tuple is hashed
    into the tool-registry identity the parity check compares across conditions, so a hash taken
    over declaration order would differ between two conditions holding exactly the same tools --
    and section 2 rule 3's assertion would fail for a reason with nothing to do with the tools.
    """
    for composition in registry.compositions.values():
        names = composition.tool_names()
        assert list(names) == sorted(names), (
            f"{composition.path.as_posix()}: tool_names() returned {names}, which is not sorted"
        )
        assert len(set(names)) == len(names), (
            f"{composition.path.as_posix()}: tool_names() repeated a name in {names}"
        )
        declared = {name for role in composition.roles for name in role.tools}
        assert set(names) == declared, (
            f"{composition.path.as_posix()}: tool_names() returned {set(names)} but the roles "
            f"declare {declared}"
        )


# --------------------------------------------------------------------------------------------
# Determinism and normalisation
# --------------------------------------------------------------------------------------------


def test_loading_the_registry_twice_gives_the_same_bytes() -> None:
    """Two independent loads produce equal block digests and equal compositions.

    ``prompt_registry_sha256`` in a run manifest is a claim that the bytes a run used can be
    reconstructed. A loader whose output depended on directory enumeration order, on dictionary
    iteration or on anything else outside the files would make that claim unverifiable, and the
    failure would surface as two halves of one campaign that appear to have used different prompts.
    Rule 20's determinism, applied to the prompt layer.
    """
    first = load_registry()
    second = load_registry()

    assert {block_id: block.digest for block_id, block in first.blocks.items()} == {
        block_id: block.digest for block_id, block in second.blocks.items()
    }, "two loads of one registry disagreed about at least one block's digest"
    assert first.compositions == second.compositions, (
        "two loads of one registry produced different compositions; a composition is a pure "
        "function of the manifest bytes and must not depend on when it was read"
    )
    assert first == second, "two loads of one registry produced unequal registries"


def test_a_crlf_body_and_an_lf_body_digest_identically(tmp_path: Path) -> None:
    """One registry written CRLF and the same registry written LF load to identical digests.

    ``.gitattributes`` normalises tracked text to LF in the index and the Windows development host
    checks it out with CRLF, so a body hashed raw would give one digest on the development host and
    another on the CI runner -- two manifests from one commit disagreeing about which prompts were
    used. ADR-010's defect, closed here for prompt text.
    """
    lf = write_registry(tmp_path / "lf", newline="\n")
    crlf = write_registry(tmp_path / "crlf", newline="\r\n")
    assert (crlf / BLOCKS_DIRNAME / f"{FIXTURE_BLOCK_IDS[0]}{BLOCK_SUFFIX}").read_bytes().count(
        b"\r\n"
    ) > 0, "the CRLF fixture was written without any CRLF, so this case would compare nothing"

    from_lf = load_registry(lf)
    from_crlf = load_registry(crlf)

    assert {block_id: block.digest for block_id, block in from_lf.blocks.items()} == {
        block_id: block.digest for block_id, block in from_crlf.blocks.items()
    }, "the same block text digested differently depending on its line endings"
    for block_id, block in from_lf.blocks.items():
        assert "\r" not in block.body, (
            f"{block_id}: a loaded body still carries a CR, so the fold to LF did not happen"
        )
        assert block.body == from_crlf.blocks[block_id].body


# --------------------------------------------------------------------------------------------
# What the loader must refuse. Each fixture is a file a tolerant parser would read into something.
# --------------------------------------------------------------------------------------------


def test_a_misindented_manifest_line_is_refused(tmp_path: Path) -> None:
    """Three spaces where the unit is two raises, naming the file and the line.

    An inferred indent unit would mean this file parses into a structure nobody wrote: the budget
    below would attach somewhere other than where it is written, and the gate would compare an
    allocation the manifest does not declare.
    """
    root = write_registry(
        tmp_path, manifest=manifest_text().replace(f"  {PHASES[1]}:", f"   {PHASES[1]}:")
    )
    with pytest.raises(ManifestSyntaxError) as caught:
        load_registry(root)
    message = str(caught.value)
    assert f"{FIXTURE_CONDITION}{MANIFEST_SUFFIX}" in message, (
        f"the refusal does not name the file it refused: {message}"
    )
    assert "indented" in message, f"the refusal does not say what was wrong: {message}"


def test_a_tab_in_the_indentation_is_refused(tmp_path: Path) -> None:
    """A tab raises rather than being read as some number of levels.

    A tab's width is a property of whoever is reading rather than of the file, so a grammar that
    accepted one would let two readers disagree about the structure of the same manifest.
    """
    root = write_registry(
        tmp_path, manifest=manifest_text().replace(f"  {PHASES[1]}:", f"\t{PHASES[1]}:")
    )
    with pytest.raises(ManifestSyntaxError) as caught:
        load_registry(root)
    message = str(caught.value)
    assert f"{FIXTURE_CONDITION}{MANIFEST_SUFFIX}" in message, (
        f"the refusal does not name the file it refused: {message}"
    )
    assert "tab" in message, f"the refusal does not say what was wrong: {message}"


def test_an_unknown_top_level_key_is_refused(tmp_path: Path) -> None:
    """A key nobody declared is refused rather than ignored.

    This is the case the loader's docstring is really about. A tolerant reader would drop the key,
    return a composition that looks complete, and let ``make parity-check`` report green over a
    manifest whose author believed the key did something.
    """
    root = write_registry(tmp_path, manifest=manifest_text(extra="surprise_key: 1\n"))
    with pytest.raises(RegistryError) as caught:
        load_registry(root)
    message = str(caught.value)
    assert f"{FIXTURE_CONDITION}{MANIFEST_SUFFIX}" in message, (
        f"the refusal does not name the file it refused: {message}"
    )
    assert "surprise_key" in message, f"the refusal does not name the key it refused: {message}"


def test_a_phase_with_no_budget_is_refused(tmp_path: Path) -> None:
    """Every phase carries a declared allocation; one that is simply absent raises.

    A phase with no budget is a phase the gate cannot compare and the runtime cannot bound -- and
    the absence is exactly the shape that reads as an oversight rather than as a decision, which is
    why it must not be tolerated silently.
    """
    dropped = PHASES[2]
    root = write_registry(
        tmp_path, manifest=manifest_text(phases=[phase for phase in PHASES if phase != dropped])
    )
    with pytest.raises(RegistryError) as caught:
        load_registry(root)
    message = str(caught.value)
    assert f"{FIXTURE_CONDITION}{MANIFEST_SUFFIX}" in message, (
        f"the refusal does not name the file it refused: {message}"
    )
    assert dropped in message, f"the refusal does not name the unbudgeted phase: {message}"


def test_a_duplicate_block_id_is_refused(tmp_path: Path) -> None:
    """Two files declaring one id raise, naming both, rather than one silently winning.

    The loader walks ``blocks/`` recursively, so a copy in a subdirectory is a second file with the
    same stem. Whichever the sort happened to visit second would otherwise replace the first, and a
    manifest referencing that id would compose text nobody chose.
    """
    duplicated = FIXTURE_BLOCK_IDS[0]
    root = write_registry(tmp_path)
    nested = root / BLOCKS_DIRNAME / "nested"
    nested.mkdir()
    write_bytes_with(
        nested / f"{duplicated}{BLOCK_SUFFIX}",
        block_text(duplicated, body="A second block claiming an id that is already taken."),
        "\n",
    )
    with pytest.raises(RegistryError) as caught:
        load_registry(root)
    message = str(caught.value)
    assert "duplicate block id" in message, f"the refusal does not say what was wrong: {message}"
    assert message.count(f"{duplicated}{BLOCK_SUFFIX}") >= 2, (
        f"the refusal does not name both files that claim {duplicated!r}: {message}"
    )


def test_a_block_id_outside_the_pattern_is_refused(tmp_path: Path) -> None:
    """An id with uppercase in it raises, naming the file and the pattern it failed.

    Case matters because a case-insensitive filesystem would otherwise let two ids differing only in
    case be one file on Windows and two on Linux, which is a difference between what CI reads and
    what a developer reads.
    """
    root = write_registry(tmp_path)
    illegal = "Fixture.Gamma"
    write_bytes_with(
        root / BLOCKS_DIRNAME / f"{illegal}{BLOCK_SUFFIX}",
        block_text(illegal, body="A block whose id is outside the declared pattern."),
        "\n",
    )
    with pytest.raises(RegistryError) as caught:
        load_registry(root)
    message = str(caught.value)
    assert illegal in message, f"the refusal does not name the offending id: {message}"
    assert BLOCK_ID_PATTERN in message, (
        f"the refusal does not show the pattern the id failed: {message}"
    )


def test_a_manifest_referencing_a_block_that_does_not_exist_is_refused(tmp_path: Path) -> None:
    """A dangling block reference raises at load, not at composition time.

    The loader is where this must fail, because the reader is sometimes the runtime rather than the
    gate: a composition naming a block that does not exist is not a number to be tabulated, it is a
    condition that cannot be composed.
    """
    root = write_registry(
        tmp_path, manifest=manifest_text(block_ids=(FIXTURE_BLOCK_IDS[0], "fixture.absent"))
    )
    with pytest.raises(RegistryError) as caught:
        load_registry(root)
    message = str(caught.value)
    assert f"{FIXTURE_CONDITION}{MANIFEST_SUFFIX}" in message, (
        f"the refusal does not name the file it refused: {message}"
    )
    assert "fixture.absent" in message, f"the refusal does not name the missing block: {message}"


def test_a_block_claiming_both_a_source_and_an_engineering_origin_is_refused(
    tmp_path: Path,
) -> None:
    """Rule 4 admits one route to provenance; declaring both raises.

    A block claiming a dissertation source *and* declaring itself engineering-authored is a block
    whose provenance nobody can state in Chapter 3, so the loader refuses rather than picking one.
    """
    contradictory = FIXTURE_BLOCK_IDS[0]
    root = write_registry(
        tmp_path,
        blocks={
            contradictory: block_text(
                contradictory,
                provenance=(
                    'source_anchor: "a fixture anchor, pointing at nothing"\n'
                    f"origin: {ENGINEERING_ORIGIN}\n"
                    "justification: a fixture that claims provenance twice over\n"
                ),
            ),
            FIXTURE_BLOCK_IDS[1]: block_text(FIXTURE_BLOCK_IDS[1]),
        },
    )
    with pytest.raises(RegistryError) as caught:
        load_registry(root)
    message = str(caught.value)
    assert f"{contradictory}{BLOCK_SUFFIX}" in message, (
        f"the refusal does not name the file it refused: {message}"
    )
    assert "source_anchor" in message, f"the refusal does not say what was wrong: {message}"


def test_an_engineering_origin_without_a_justification_is_refused(tmp_path: Path) -> None:
    """The tag without the reason is the tag doing no work, and the loader says so."""
    ungrounded = FIXTURE_BLOCK_IDS[1]
    root = write_registry(
        tmp_path,
        blocks={
            FIXTURE_BLOCK_IDS[0]: block_text(FIXTURE_BLOCK_IDS[0]),
            ungrounded: block_text(ungrounded, provenance=f"origin: {ENGINEERING_ORIGIN}\n"),
        },
    )
    with pytest.raises(RegistryError) as caught:
        load_registry(root)
    message = str(caught.value)
    assert f"{ungrounded}{BLOCK_SUFFIX}" in message, (
        f"the refusal does not name the file it refused: {message}"
    )
    assert "justification" in message, f"the refusal does not say what was missing: {message}"


def test_the_fixture_registry_is_otherwise_loadable(tmp_path: Path) -> None:
    """The unmodified fixture loads, so every refusal above is attributable to its one mutation.

    Without this, a negative case could pass because the fixture was malformed in some second way
    the test never named -- which is the classic shape of a suite that proves nothing while being
    green, and the reason each case above changes exactly one thing.
    """
    loaded = load_registry(write_registry(tmp_path))
    assert set(loaded.blocks) == set(FIXTURE_BLOCK_IDS), (
        f"the fixture registry loaded {sorted(loaded.blocks)} rather than "
        f"{sorted(FIXTURE_BLOCK_IDS)}"
    )
    composition = loaded.compositions[FIXTURE_CONDITION]
    assert composition.issuance_tool_holder == FIXTURE_ROLE_ID
    assert composition.role(FIXTURE_ROLE_ID).block_ids == FIXTURE_BLOCK_IDS
    assert set(composition.budgets) == set(PHASES), (
        f"the fixture declares budgets for {sorted(composition.budgets)}, not for every phase"
    )
