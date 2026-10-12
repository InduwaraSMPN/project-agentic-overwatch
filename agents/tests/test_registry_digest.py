r"""One digest rule, implemented twice: the properties it must hold, and the check that it does.

WHAT THIS TEST IS FOR
---------------------
``docs/protocols/data-management.md`` requires every ``manifest.json`` to carry
``prompt_registry_sha256`` and ``tool_registry_sha256``. A digest is what turns "the run used the
registry" into a checkable statement: two bundles carrying the same number were produced from the
same bytes, and a bundle whose number does not match the tree it claims to come from is a bundle
whose prompts nobody can reconstruct.

That is a claim with an unusual failure mode. A digest is always *some* number, and a wrong one
looks exactly like a right one -- there is no invalid output to notice, no exception to catch, and
no downstream consumer that could tell. The only way it becomes visible is if something asserts,
over files it wrote itself, that the number moves when the tree moves and holds still when it does
not. That is the whole of the first half of this file:

*Stable.* Two calls over one tree agree, or a manifest written twice for one run would disagree
with itself.

*Sensitive to content.* Change a byte in any covered file and the number moves, or a prompt edit
would leave two campaigns looking comparable when they are not.

*Sensitive to membership.* Add or remove a file and the number moves, or a block could be deleted
from a registry that still hashes as it did.

*Insensitive to line endings.* ``.gitattributes`` normalises tracked text to LF in the index and the
Windows development host checks it out with CRLF. A raw byte hash would record **which host loaded
the registry** rather than which registry was loaded, and two manifests from one commit would
disagree. ADR-010's defect, and ADR-022's re-application of the fix.

*Insensitive to enumeration order, and blind to nothing.* Paths are sorted, so the number does not
depend on what order a filesystem handed the files back; and there is no extension filter, because
"an extension filter would be a place to hide a block". Hidden files are the one exclusion, so that
an editor swap file cannot move a run manifest's digest.

WHY THE CROSS-CHECK IS THE POINT OF THIS FILE
------------------------------------------------
``guardian/app/policy.py``'s :meth:`PolicyBundle.load` already implements this rule, for the policy
bundle, and its digest is what ADR-023 asserts equal across ``G0-FULL``, ``G1-LOGONLY`` and
``G2-SHAREDCRED`` -- the direct machine proof that the guardrail arms cannot be reached through
policy. :mod:`agents.registry.digest` implements it a second time, because ``agents/`` cannot import
``guardian/``: the Guardian ships as its own container and holds the only cluster credential, so the
dependency would run the wrong way and would put the enforcement component inside the agent layer's
image.

ADR-022 settled the shape of that trade -- one rule stated once in prose, two homes, and a test that
makes "copy" mean "copy that cannot drift" -- and the digest module's docstring names the obligation
directly. :func:`test_the_two_implementations_of_one_rule_agree` is it: one fixture directory, both
rules, the same string. If the two ever diverge, this names it at the commit that caused it rather
than a milestone later, in a sealed bundle, as a manifest nobody can reproduce.

The fixture the cross-check runs over carries a ``.rego`` file, a nested file, a file with no
extension, a hidden file and a hidden directory, so the two rules are compared on every dimension
each of them decides: coverage, ordering, framing, normalisation and exclusion. One extra condition
is imposed by the Guardian side and is stated rather than worked around -- ``PolicyBundle.load``
refuses a directory with no ``.rego`` file in it, because an empty bundle "denies every action while
looking configured". That is a property of a *policy* bundle and not of the digest rule, so the
fixture satisfies it rather than the test weakening it.

WHY THE TOOL REGISTRY IS NOT A DIRECTORY HASH
------------------------------------------------
``prompt-parity-policy.md`` section 2 rule 3 requires the tool registry hash to be identical across
conditions. A directory hash over ``agents/tools/`` would be the wrong instrument in both
directions: it would move when a docstring changed, which is not a tool-definition change, and it
would be identical across conditions **by construction** rather than by check, since all three read
the same directory. An assertion that cannot fail is not an assertion. So
:func:`~agents.registry.digest.tool_registry_digest` hashes the definitions each condition's
manifest actually gives its roles, and the two cases below assert both halves of what that buys:
equal for the three conditions, and unequal when a definition changes.
"""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agents.registry import STRUCTURE_CONDITIONS  # noqa: E402
from agents.registry.digest import (  # noqa: E402
    digest_files,
    directory_digest,
    tool_registry_digest,
)
from agents.registry.loader import PromptRegistry  # noqa: E402
from agents.tools.registry import TOOL_NAMES, definitions_for  # noqa: E402
from guardian.app.config import PolicyEngineSettings  # noqa: E402
from guardian.app.policy import PolicyBundle  # noqa: E402
from harness import POLICY_ENTRYPOINT, SUITE_POLICY_TIMEOUT_SECONDS  # noqa: E402

# The fixture tree every directory case below is built from: a nested file, a file with no
# extension at all, and a `.rego` file so that the same fixture can be handed to the Guardian's
# loader unchanged. The contents resemble nothing shipped, for the reason
# monitor/tests/test_limits_match_protocol.py gives about its own inline fixture.
FIXTURE_TREE: dict[str, str] = {
    "alpha.rego": "package x9fixture\n\ndefault fixture_rule := false\n",
    "beta.md": "A fixture file that is not policy and not a prompt.\n",
    "nested/gamma.json": '{"fixture": true}\n',
    # No extension, deliberately. An extension filter would be a place to hide a block, so a file
    # a filter would miss has to be in the fixture rather than assumed absent.
    "delta": "a fixture file with no extension at all\n",
}

# Written into the same fixture and expected to be invisible to the digest. Editor swap files and
# VCS metadata are not what the runtime loads, and letting them in would make a run manifest's
# digest depend on whether somebody had a file open.
HIDDEN_ENTRIES: dict[str, str] = {
    ".swapfile": "an editor dropping\n",
    ".hiddendir/inside.rego": "package x9fixture_hidden\n",
}


def write_tree(root: Path, entries: dict[str, str], *, newline: str = "\n") -> Path:
    """Write ``entries`` under ``root`` with ``newline`` line endings and return ``root``.

    ``write_bytes`` rather than ``write_text``, because the latter applies Windows' own
    universal-newline translation and would make the CRLF tree and the LF tree the same bytes --
    leaving the line-ending case asserting nothing on the one host where it matters most.
    """
    for relative, content in entries.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.replace("\n", newline).encode("utf-8"))
    return root


def guardian_digest(root: Path) -> str:
    """Return the Guardian's own digest of ``root``, through the class the Guardian starts with.

    ``PolicyEngineSettings`` is constructed with the suite's entrypoint and timeout, taken from
    ``harness.py`` rather than invented here. Neither value reaches the digest -- ``load`` hashes
    paths and contents and nothing else -- and neither is a number ``docs/protocols/`` owns:
    ``guardian/app/config.py`` says of the timeout in as many words that there is no protocol value
    for it, because it bounds a local call rather than parameterising the experiment.
    """
    return PolicyBundle.load(
        PolicyEngineSettings(
            bundle_path=root,
            entrypoint=POLICY_ENTRYPOINT,
            evaluation_timeout_seconds=SUITE_POLICY_TIMEOUT_SECONDS,
        )
    ).digest


# --------------------------------------------------------------------------------------------
# The directory digest
# --------------------------------------------------------------------------------------------


def test_the_digest_is_stable_across_two_calls(tmp_path: Path) -> None:
    """One tree, two calls, one number -- and the covered file list is stable with it.

    The weakest of the properties here and the one everything else is stated against: a digest that
    disagreed with itself would make every other assertion below meaningless, and would make two
    manifests written for one run disagree about which prompts it used.
    """
    root = write_tree(tmp_path / "tree", FIXTURE_TREE)
    assert directory_digest(root) == directory_digest(root), (
        "two calls over one unchanged tree returned different digests"
    )
    assert digest_files(root) == digest_files(root), (
        "two calls over one unchanged tree returned different file lists"
    )


def test_the_digest_moves_when_a_covered_file_changes(tmp_path: Path) -> None:
    """Editing one byte of any covered file moves the number, whatever the file's extension.

    Asserted for every file in the fixture rather than for one, because the failure this guards
    against is per-file: a rule that skipped, say, files without an extension would pass a
    single-file check and would let a whole class of edits go unrecorded.
    """
    for relative in FIXTURE_TREE:
        root = write_tree(tmp_path / f"changed-{relative.replace('/', '-')}", FIXTURE_TREE)
        before = directory_digest(root)
        target = root / relative
        target.write_bytes(target.read_bytes() + b"one more line\n")
        after = directory_digest(root)
        assert before != after, (
            f"editing {relative!r} left the digest at {before}; a prompt edit that does not move "
            "the digest makes two incomparable campaigns look comparable"
        )


def test_the_digest_moves_when_a_file_is_added_or_removed(tmp_path: Path) -> None:
    """Membership is part of the digest: adding a file moves it, and so does deleting one.

    Both directions, because they fail differently. An addition that did not move the number would
    let a block be introduced into a registry that still hashes as it did; a deletion that did not
    would let one be removed the same way.
    """
    root = write_tree(tmp_path / "tree", FIXTURE_TREE)
    baseline = directory_digest(root)

    added = root / "epsilon"
    added.write_bytes(b"a file that was not there before\n")
    with_addition = directory_digest(root)
    assert with_addition != baseline, "adding a file did not move the digest"

    added.unlink()
    assert directory_digest(root) == baseline, (
        "removing the added file did not return the digest to its previous value, so the digest "
        "depends on something other than the files it covers"
    )

    (root / "beta.md").unlink()
    assert directory_digest(root) != baseline, "deleting a covered file did not move the digest"


def test_line_endings_do_not_change_the_digest(tmp_path: Path) -> None:
    """The same content written CRLF and written LF digests identically.

    The property that makes a digest describe a registry rather than a host. Without it the
    isolation and reproducibility claims would hold on Linux, fail on Windows, and mean nothing on
    either -- which is precisely the defect ADR-010 was written to close for
    ``versions_env_sha256`` and ADR-022 re-applies here.
    """
    crlf = write_tree(tmp_path / "crlf", FIXTURE_TREE, newline="\r\n")
    lf = write_tree(tmp_path / "lf", FIXTURE_TREE, newline="\n")
    assert (crlf / "beta.md").read_bytes() != (lf / "beta.md").read_bytes(), (
        "the two trees hold identical bytes, so this case would compare a tree with itself"
    )
    assert directory_digest(crlf) == directory_digest(lf), (
        "the same registry digested differently depending on the checkout's line endings"
    )


def test_hidden_files_are_excluded_and_everything_else_is_covered(tmp_path: Path) -> None:
    """A hidden file and a whole hidden directory are invisible; a file with no extension is not.

    Two exclusions that could each be got wrong in the opposite direction. Letting hidden entries in
    would make a run manifest's digest depend on whether somebody had an editor open on the tree.
    Filtering by extension would be a place to hide a block -- so the fixture carries a file named
    ``delta`` with no suffix at all, and the digest has to move when it changes.
    """
    plain = write_tree(tmp_path / "plain", FIXTURE_TREE)
    with_hidden = write_tree(write_tree(tmp_path / "hidden", FIXTURE_TREE), HIDDEN_ENTRIES)

    assert directory_digest(plain) == directory_digest(with_hidden), (
        "a hidden file or a hidden directory moved the digest; editor and VCS droppings are not "
        "what the runtime loads"
    )
    covered = digest_files(with_hidden)
    for relative in HIDDEN_ENTRIES:
        assert relative not in covered, f"{relative!r} is hidden but appears in the covered set"
    assert set(covered) == set(FIXTURE_TREE), (
        f"the covered set is {sorted(covered)} but the tree's non-hidden files are "
        f"{sorted(FIXTURE_TREE)}; an uncovered file is a file a change could hide in"
    )

    extensionless = with_hidden / "delta"
    before = directory_digest(with_hidden)
    extensionless.write_bytes(b"edited, and it has no extension to be filtered by\n")
    assert directory_digest(with_hidden) != before, (
        "editing a file with no extension left the digest unchanged, which is exactly the gap an "
        "extension filter would open"
    )


def test_paths_are_digested_in_sorted_order(tmp_path: Path) -> None:
    """The digest does not depend on the order the files were created or enumerated in.

    Built twice from the same contents, once in the fixture's declared order and once reversed, so
    that any dependence on the order a filesystem hands entries back would show as two numbers for
    one tree. ``digest_files`` is asserted sorted beside it, because that list is what a person
    investigating a mismatch reads and an unsorted one would send them looking in the wrong place.
    """
    forward = write_tree(tmp_path / "forward", dict(FIXTURE_TREE))
    backward = write_tree(tmp_path / "backward", dict(reversed(list(FIXTURE_TREE.items()))))

    assert directory_digest(forward) == directory_digest(backward), (
        "two trees holding the same files digested differently because the files were written in "
        "a different order"
    )
    covered = digest_files(forward)
    assert list(covered) == sorted(covered), (
        f"digest_files returned {list(covered)}, which is not sorted; the digest's own ordering "
        "would then rest on whatever the filesystem happened to return"
    )


def test_an_absent_or_empty_directory_is_refused(tmp_path: Path) -> None:
    """Nothing to digest is a refusal, not a digest of nothing.

    An empty registry hashes to a perfectly stable number describing no prompts, and a run manifest
    carrying it would look configured. That is the one failure a digest cannot make visible on its
    own, which is why the module raises instead.
    """
    with pytest.raises(FileNotFoundError):
        directory_digest(tmp_path / "there-is-no-such-directory")

    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError) as caught:
        directory_digest(empty)
    assert "no file to digest" in str(caught.value), (
        f"the refusal does not say what was wrong: {caught.value}"
    )


def test_the_two_implementations_of_one_rule_agree(tmp_path: Path) -> None:
    """ADR-022's check: ``directory_digest`` and ``PolicyBundle.load(...).digest`` are one string.

    One fixture directory, both rules, over the same bytes. The fixture is built to exercise every
    dimension either implementation decides -- a nested file, a file with no extension, a hidden
    file, a hidden directory, and CRLF content on both sides -- so that agreement here is agreement
    about the rule and not about the easy case.

    The covered file lists are compared as well as the digests, and that is not redundant: two
    implementations could agree on a number while disagreeing about which files produced it, and
    the file list is the artefact a person reads when a digest does not match.
    """
    root = write_tree(write_tree(tmp_path / "bundle", FIXTURE_TREE), HIDDEN_ENTRIES)

    bundle_digest = guardian_digest(root)
    registry_digest = directory_digest(root)
    assert registry_digest == bundle_digest, (
        f"agents/registry/digest.py returned {registry_digest} and guardian/app/policy.py returned "
        f"{bundle_digest} over one directory. These are two homes for one rule; a divergence means "
        "a run manifest and a policy bundle that cannot be reasoned about together"
    )

    bundle = PolicyBundle.load(
        PolicyEngineSettings(
            bundle_path=root,
            entrypoint=POLICY_ENTRYPOINT,
            evaluation_timeout_seconds=SUITE_POLICY_TIMEOUT_SECONDS,
        )
    )
    assert digest_files(root) == bundle.files, (
        f"the two implementations cover different files: {digest_files(root)} against "
        f"{bundle.files}. Agreeing on a number while disagreeing about its inputs is worse than "
        "disagreeing outright"
    )

    # Line-ending insensitivity has to hold on both sides or the agreement above is an agreement
    # that only survives on one host.
    crlf = write_tree(
        write_tree(tmp_path / "bundle-crlf", FIXTURE_TREE, newline="\r\n"),
        HIDDEN_ENTRIES,
        newline="\r\n",
    )
    assert guardian_digest(crlf) == bundle_digest, (
        "the Guardian's digest moved with the line endings, so the two rules agree only for a "
        "checkout written the way this one happened to be"
    )
    assert directory_digest(crlf) == registry_digest, (
        "the registry digest moved with the line endings, so the two rules agree only for a "
        "checkout written the way this one happened to be"
    )


# --------------------------------------------------------------------------------------------
# The tool registry digest
# --------------------------------------------------------------------------------------------


def test_the_three_conditions_hash_to_one_tool_registry(registry: PromptRegistry) -> None:
    """Section 2 rule 3, checked rather than assumed: the three arms hold the same tool set.

    Computed from each condition's *manifest* -- the tools its roles actually declare -- rather than
    from the module's own ``TOOL_NAMES``, which is what makes this an assertion that can fail. A
    hash over the directory all three read would be identical by construction and would prove
    nothing about what any arm was given.

    What differs between the arms is which node holds which entry, and in particular which node
    holds the issuance tool: the Supervisor in S1, the coordinator in S2 and S3. That is conflict
    M4-C7's resolution, a configuration difference rather than a code one, and it must not show up
    here -- the digest is a property of the set, not of the distribution.
    """
    digests: dict[str, str] = {}
    for condition in STRUCTURE_CONDITIONS:
        composition = registry.compositions[condition]
        names = composition.tool_names()
        assert names, f"{condition} declares no tools at all"
        digests[condition] = tool_registry_digest(definitions_for(names))

    distinct = set(digests.values())
    assert len(distinct) == 1, (
        f"the conditions hash to {digests}, which is more than one tool registry. Section 2 rule 3 "
        "requires the definitions identical across conditions; a condition-only tool would make "
        "the ablation a comparison of two different toolsets"
    )
    assert distinct == {tool_registry_digest(definitions_for(TOOL_NAMES))}, (
        "the conditions agree with each other but not with the whole registry, so some tool is "
        "defined in agents/tools/registry.py and given to no arm"
    )


def test_a_changed_tool_definition_moves_the_tool_registry_digest() -> None:
    """Both halves of a definition are in the digest: its documentation block and its schema.

    Without this, the equality above would be satisfiable by a digest that ignored whichever half
    somebody later changed -- and rule 3's assertion would be reported green over two arms holding
    tools that differ in exactly the way the projection dropped.

    The variants are built as new mappings rather than by mutating the projections, so the module's
    own definitions are untouched and no later test in the session inherits an edited registry.
    """
    baseline_projections = definitions_for(TOOL_NAMES)
    baseline = tool_registry_digest(baseline_projections)
    first, *rest = baseline_projections

    changed_doc_block = (
        {**first, "doc_block": "fixture.not-a-documentation-block"},
        *rest,
    )
    assert tool_registry_digest(changed_doc_block) != baseline, (
        "changing a tool's documentation block left the digest unchanged; the prose a model is "
        "given about a tool is part of what the tool is"
    )

    changed_schema = (
        {**first, "schema": {**first["schema"], "additionalProperties": True}},
        *rest,
    )
    assert tool_registry_digest(changed_schema) != baseline, (
        "changing a tool's parameter schema left the digest unchanged; two arms could then hold "
        "tools of different shapes under one hash"
    )

    assert tool_registry_digest(definitions_for(TOOL_NAMES)) == baseline, (
        "building the variants above changed the shipped definitions, so the module's registry is "
        "mutable and every later digest in this session would describe an edited tool set"
    )


def test_the_tool_registry_digest_refuses_to_hash_nothing() -> None:
    """An empty definition list raises rather than hashing to a stable, meaningless number.

    A hash over nothing is identical across conditions whatever they hold, which is an assertion
    that cannot fail -- the same defect the module docstring names for a directory hash over
    ``agents/tools/``, arriving by a different route.
    """
    with pytest.raises(ValueError) as caught:
        tool_registry_digest(())
    assert "identical across conditions" in str(caught.value), (
        f"the refusal does not say why hashing nothing is worse than useless: {caught.value}"
    )
