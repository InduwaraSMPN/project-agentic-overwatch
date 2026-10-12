r"""The prompt boundary, checked with a parser -- the half a line-oriented grep cannot reach.

WHAT THIS FILE IS, AND WHY IT IS NOT A SLOWER COPY OF THE SHELL GUARD
------------------------------------------------------------------------
``.agents/rules/20-parity-and-determinism.md``: "Prompts exist only in ``agents/prompts/`` registry
files; code composes, never contains, prompt text." ``scripts/prompt_purity_grep.sh`` enforces that
in CI's ``guardrail-grep`` job, and its own header says where it stops: its patterns are line
anchored and scoped to four constructs, so "a prompt built by concatenating short fragments, a
sentence assembled at run time" walks past it -- and it names this file as the layer that closes
that gap. Rule 40 already established that a boundary worth having gets more than one layer.

So this file is deliberately not the same check written in Python. It adds three things the grep
cannot do, and the second is the one a grep gets structurally wrong rather than merely misses.

**1. It parses, so it sees a prompt however it is spelled.** Python folds adjacent string literals
at parse time, so a sentence split across four indented lines inside a list element is *one*
``ast.Constant`` to a parser and four short lines to ``grep``. The same holds for a triple-quoted
string in any position, a long run of literal text between two f-string placeholders, and a literal
handed to a call the grep's keyword pattern does not name. The positive control below asserts
exactly that: a synthetic module whose inlined prompt trips none of the shell guard's four patterns
is caught here.

**2. It checks block reachability structurally rather than textually.** The guard's block (b) asks
``grep -qF`` whether a block id appears anywhere in the concatenated manifests. Three things pass
that test without being a reference: an id mentioned in a manifest comment, an id that happens to
be a substring of another id, and an id sitting in a key the loader never reads. This file compares
sets instead -- the ``.md`` files on disk, the blocks the loader accepted, and the ids the
manifests' role entries actually name -- so an orphan and a dangling reference are each a named
difference between two sets. It also asserts the premise the grep silently depends on: that no
block id is a substring of another.

**3. It walks the import graph of ``agents/registry/``.** That is conflict M4-C1's resolution and
the reason the parity gate can run in a CI job that installs nothing: ``scripts/parity_check.sh``
runs inside ``guardrail-grep``, which checks out the repository and installs nothing at all, so a
composer with a third-party dependency would fail there for a dependency reason rather than a code
one -- the exact shape ADR-025 records for M3's two guards tripping together.
:mod:`agents.registry.model` and :mod:`agents.registry.tracing` are the two modules that do reach
outside, and they are **not exempted**: the property asserted of them is the one their docstrings
claim, that the backend import sits inside a function body and never on the module's import path.

WHAT COUNTS AS A PROMPT-SHAPED LITERAL, PRECISELY
---------------------------------------------------
A criterion that fires on the house style would be a check whose every hit is false from its first
run, which ``scripts/monitor_guard.sh``'s header spends four paragraphs refusing. So the rule is
stated here in full, and each exemption is a construct rather than a path -- there is no allowlist
file, no inline sentinel and no per-file skip, for the reason rule 10 gives about its own guard.

A ``str`` constant under ``agents/graphs/`` or ``agents/tools/`` is a hit when **all** of:

*It is prose.* At least :data:`PROSE_MIN_CHARS` characters and at least :data:`PROSE_MIN_WORDS`
whitespace-separated words. Sixty characters is the shell guard's own threshold, chosen there so
that an identifier, a path, a URL, a format fragment and a reason code all pass while a sentence
does not; the word count is added here because a parser can see a sixty-character regular expression
as one word and a grep cannot.

*It is not a value the interpreter discards.* A string constant that stands alone as an expression
statement is evaluated and thrown away -- that is exactly the set of module, class, function and
attribute docstrings, and nothing else. It can reach no model, no comparison and no call. Every
module in this repository opens with several hundred words of argued prose, and
:data:`~agents.tools.guardian_client.Transport` carries an attribute docstring; a scan that
failed on documentation would be enforcing a rule nobody wrote.

*It is not an element of a module-level ``__all__``.* Export lists are identifiers.

*It is not inside a ``raise``.* Every exception in this repository carries a long argued message
wrapped across several lines -- that is the house style, and it is what makes a failure legible.
The shell guard makes the identical concession by *omitting* a pattern for argument-position
literals, and gives the same reason: such a pattern "would fire on nearly every ``raise`` under
``agents/`` and every one of those hits would be false". A message a caller reads out of a
traceback is not text a model receives.

The negative control below asserts that all four exemptions hold on a synthetic module built out of
them, so the criterion cannot quietly become "everything is exempt".
"""

import ast
import importlib.abc
import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from collections.abc import Iterator  # noqa: E402

import pytest  # noqa: E402
from agents.registry.loader import PromptRegistry  # noqa: E402
from agents.tools.registry import TOOL_NAMES, documentation_block_ids  # noqa: E402

AGENTS_ROOT = REPO_ROOT / "agents"
SCANNED_DIRECTORIES = (AGENTS_ROOT / "graphs", AGENTS_ROOT / "tools")
REGISTRY_PACKAGE = AGENTS_ROOT / "registry"
BLOCKS_DIR = AGENTS_ROOT / "prompts" / "blocks"
BLOCK_SUFFIX = ".md"

# The prose thresholds. Sixty characters is scripts/prompt_purity_grep.sh's own number, kept
# identical on purpose so that the two layers disagree about coverage and never about what a
# sentence is. The word count is this layer's addition: a parser can see a long regular expression
# or a base64 blob as a single word, and neither is guidance.
PROSE_MIN_CHARS = 60
PROSE_MIN_WORDS = 8

# The two modules agents/registry/__init__.py names as reaching outside the standard library. They
# are listed so the failure message can say which module was expected to be lazy, never so that they
# can be skipped -- the property asserted of them is stronger than the one asserted of the rest.
LAZY_BACKEND_MODULES = ("model.py", "tracing.py")

# Top-level module names that belong to this repository rather than to a distribution.
FIRST_PARTY_ROOTS = frozenset(
    {"agents", "analysis", "guardian", "infra", "monitor", "runner", "scenarios", "scripts"}
)


# --------------------------------------------------------------------------------------------
# The criterion, stated once and applied to real modules and to two controls
# --------------------------------------------------------------------------------------------


def _is_prose(text: str) -> bool:
    """Whether a string is long enough and wordy enough to be guidance rather than a token."""
    return len(text) >= PROSE_MIN_CHARS and len(text.split()) >= PROSE_MIN_WORDS


def _discarded_string_ids(tree: ast.AST) -> set[int]:
    """Identities of every string constant standing alone as a statement -- i.e. every docstring."""
    return {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    }


def _raised_string_ids(tree: ast.AST) -> set[int]:
    """Identities of every node inside a ``raise`` statement, message expressions included."""
    inside: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Raise):
            inside.update(id(child) for child in ast.walk(node))
    return inside


def _export_list_string_ids(tree: ast.AST) -> set[int]:
    """Identities of every node in a module-level ``__all__`` assignment."""
    inside: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets: list[ast.expr] = list(node.targets)
            value: ast.expr | None = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        else:
            continue
        names = {target.id for target in targets if isinstance(target, ast.Name)}
        if "__all__" in names and value is not None:
            inside.update(id(child) for child in ast.walk(value))
    return inside


def _prompt_shaped_literals(tree: ast.AST) -> tuple[tuple[int, str], ...]:
    """Return ``(line, text)`` for every string constant the docstring's criterion calls a hit."""
    exempt = _discarded_string_ids(tree) | _raised_string_ids(tree) | _export_list_string_ids(tree)
    return tuple(
        (node.lineno, node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in exempt
        and _is_prose(node.value)
    )


def _scan_source(source: str) -> tuple[tuple[int, str], ...]:
    """Apply the criterion to a source string, for the two controls below."""
    return _prompt_shaped_literals(ast.parse(source))


def _python_files(*roots: Path) -> tuple[Path, ...]:
    """Every Python source file under ``roots``, in a stable order, ``__pycache__`` excluded."""
    found: list[Path] = []
    for root in roots:
        found.extend(path for path in root.rglob("*.py") if "__pycache__" not in path.parts)
    return tuple(sorted(found))


# A module whose inlined prompt trips none of scripts/prompt_purity_grep.sh's four patterns:
# the assignment is not on one line, no triple quote follows `=`, `(` or `,`, the keyword is not one
# of the five the guard watches, and there is no chat-message mapping. Python folds the adjacent
# literals into one constant at parse time, which is what makes it visible to a parser and invisible
# to a line-oriented scan.
POSITIVE_CONTROL = '''
"""A module docstring, which is exempt."""

def build_context(role):
    fragments = [
        role.name,
        (
            "You are the containment supervisor for this incident. Isolate the "
            "affected workload first, then explain the reasoning behind the choice "
            "you made before requesting any further action."
        ),
    ]
    return "\\n".join(fragments)
'''

# The same criterion applied to the four constructs it must not fire on: a module docstring, an
# attribute docstring, a long argued exception message, and a long token with no whitespace in it.
NEGATIVE_CONTROL = '''
"""A module docstring long enough to be prose several times over, with many words in it."""

__all__ = ("Transport", "resolve")

Transport = int
"""What a transport is, explained at length in an attribute docstring that is discarded."""

PATTERN = "^[a-z0-9]([-a-z0-9.]*[a-z0-9])?(?:/[a-z0-9]([-a-z0-9.]*[a-z0-9])?)*$"

def resolve(name):
    """A function docstring, also several words long and also entirely exempt."""
    if not name:
        raise ValueError(
            f"no transport named {name!r} is registered; the registry holds none at all, and a "
            "caller that reached this point has asked for something that was never declared"
        )
    return name
'''


def test_the_criterion_catches_a_prompt_the_shell_guard_cannot_see() -> None:
    """The positive control: an inlined prompt spelled so that every grep pattern misses it.

    This is the whole justification for a second layer. If it ever stops firing, the criterion has
    been loosened past the point where it adds anything to ``scripts/prompt_purity_grep.sh``, and
    the two checks have become one check run twice.
    """
    hits = _scan_source(POSITIVE_CONTROL)
    assert hits, (
        "the positive control's inlined prompt was not detected, so this file no longer catches "
        "the shapes a line-oriented grep cannot see and is a slower copy of the shell guard"
    )
    assert any("containment supervisor" in text for _, text in hits), (
        f"the detector fired, but on something other than the planted prompt: {hits}"
    )


def test_the_criterion_leaves_the_house_style_alone() -> None:
    """The negative control: a docstring, an attribute docstring, a ``raise`` message and a pattern.

    A check whose first hits are all false is a check nobody reads, and every construct in this
    control appears dozens of times in the modules the scan governs.
    """
    assert not _scan_source(NEGATIVE_CONTROL), (
        "the criterion fired on the house style: "
        f"{_scan_source(NEGATIVE_CONTROL)}. Docstrings, attribute docstrings, __all__ entries and "
        "argued exception messages are documentation and diagnostics, not prompt text"
    )


def test_the_scan_reads_the_two_directories_the_rule_governs() -> None:
    """Not vacuous: the modules exist, they parse, and they contain string constants to judge.

    An empty scan and a clean scan are indistinguishable in a pass line unless something asserts the
    difference. The directory scope is ``agents/graphs/`` and ``agents/tools/``, exactly the shell
    guard's, and for its reason: ``agents/registry/`` is the composer and the renderer,
    ``agents/tests/`` has to be able to write a fixture block and assert on it, and
    ``agents/prompts/`` *is* the prompt text.

    One difference from the shell guard is deliberate and is why this assertion exists at all. That
    script scans ``git ls-files`` -- tracked files only, so that an untracked local scratch file
    cannot fail CI and the check sees exactly what a fresh clone contains -- and it reports a
    *vacuous pass* while the directory holds no tracked file. This scan walks the working tree, so
    it is never vacuous while the modules exist, and it says so out loud rather than reporting a
    pass that was really an absence. The two agree on a fresh clone, which is where CI runs.
    """
    files = _python_files(*SCANNED_DIRECTORIES)
    assert len(files) >= 7, (
        f"only {len(files)} module(s) under {[str(d.name) for d in SCANNED_DIRECTORIES]}: "
        f"{[path.name for path in files]}"
    )
    constants = sum(
        1
        for path in files
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    )
    assert constants > 100, (
        f"the scan found only {constants} string constant(s) across {len(files)} modules, which "
        "means it is not reading the trees it thinks it is"
    )


def test_no_prompt_shaped_literal_lives_under_graphs_or_tools() -> None:
    """The boundary itself: not one byte a model reads is authored in code.

    Parity policy section 3 asserts an equality over the composed registry. A prompt literal in a
    graph or a tool module is guidance no composition manifest lists, that ``make parity-check``
    therefore never counts, and that could differ between two conditions without any gate noticing.
    One inlined sentence in a node function and NFR3's "parity by construction" becomes parity by
    inspection.
    """
    offenders: list[str] = []
    for path in _python_files(*SCANNED_DIRECTORIES):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for line, text in _prompt_shaped_literals(tree):
            excerpt = text if len(text) <= 120 else text[:117] + "..."
            offenders.append(f"{path.relative_to(REPO_ROOT).as_posix()}:{line}: {excerpt!r}")
    assert not offenders, (
        "prompt-shaped string literal(s) in code:\n"
        + "\n".join(offenders)
        + "\n\nMove the text into agents/prompts/blocks/ with a stable block id, reference it from "
        "every composition manifest that needs it, and compose it by id (prompt-parity-policy.md "
        "section 2 rule 1). There is no exemption mechanism by design."
    )


# --------------------------------------------------------------------------------------------
# Reachability, in both directions, over sets rather than substrings
# --------------------------------------------------------------------------------------------


def _referenced_block_ids(registry: PromptRegistry) -> frozenset[str]:
    """Every block id some composition manifest's role entry names."""
    return frozenset(
        block_id
        for composition in registry.compositions.values()
        for role in composition.roles
        for block_id in role.block_ids
    )


def test_every_block_file_is_reached_and_every_reference_exists(registry: PromptRegistry) -> None:
    """Three sets, all equal: the files on disk, the blocks the loader accepted, the ids referenced.

    An orphaned block ships in the repository, is digested into ``prompt_registry_sha256``, and
    reaches no model -- so a reviewer reading the registry sees guidance the run never received. It
    is also the shape a deleted-by-accident reference takes: the manifest edit lands, the block
    stays, and nothing says the role lost its instructions. A dangling reference is the mirror image
    and is the more urgent of the two, because it is a role whose prompt cannot be composed at all.

    Compared as sets rather than as substring queries, which is the difference between this check
    and the shell guard's block (b). See the module docstring for the three things that satisfy a
    ``grep -qF`` without being a reference.
    """
    on_disk = frozenset(path.stem for path in BLOCKS_DIR.glob(f"*{BLOCK_SUFFIX}"))
    loaded = frozenset(registry.blocks)
    referenced = _referenced_block_ids(registry)

    assert on_disk, f"{BLOCKS_DIR} holds no {BLOCK_SUFFIX} file; this check would pass vacuously"
    assert on_disk == loaded, (
        f"the loader accepted a different block set than the directory holds. On disk only: "
        f"{sorted(on_disk - loaded)}; loaded only: {sorted(loaded - on_disk)}"
    )
    assert not (loaded - referenced), (
        f"orphaned block(s) no composition manifest reaches: {sorted(loaded - referenced)}. Either "
        "reference the block from the manifest that lost it, or delete it"
    )
    assert not (referenced - loaded), (
        f"composition manifest(s) name block id(s) that do not exist: {sorted(referenced - loaded)}"
    )


def test_no_block_id_is_a_substring_of_another() -> None:
    """The premise ``scripts/prompt_purity_grep.sh``'s block (b) depends on and cannot assert.

    That guard decides a block is reached by asking ``grep -qF`` whether its id appears anywhere in
    the concatenated manifests. If one id were a substring of another, deleting the shorter one's
    reference would leave the longer one's reference answering for it, and an orphan would read as
    reached. The registry is small enough that the property holds today; this is what keeps it true
    when the twenty-seventh block is added.
    """
    ids = sorted(path.stem for path in BLOCKS_DIR.glob(f"*{BLOCK_SUFFIX}"))
    collisions = [
        (shorter, longer)
        for shorter in ids
        for longer in ids
        if shorter != longer and shorter in longer
    ]
    assert not collisions, (
        f"block id(s) contained in another id: {collisions}. scripts/prompt_purity_grep.sh matches "
        "block ids as substrings, so the containing id's reference would answer for the contained "
        "one and an orphan would pass the guard"
    )


def test_every_tool_has_a_documentation_block_in_the_registry(registry: PromptRegistry) -> None:
    """A tool offered to a model with no description is a tool the model is told nothing about.

    Parity policy section 2 rule 3 requires the tool descriptions to be identical across conditions,
    which cannot hold of a description that does not exist. The ids come from
    :func:`agents.tools.registry.documentation_block_ids`, which the tool registry publishes for
    exactly this assertion, rather than from a second list here.
    """
    doc_blocks = documentation_block_ids()
    assert len(doc_blocks) == len(TOOL_NAMES), (
        f"{len(TOOL_NAMES)} tool(s) {TOOL_NAMES} declare {len(doc_blocks)} documentation block(s) "
        f"{doc_blocks}; two tools sharing one block would be two tools described as one"
    )
    missing = sorted(set(doc_blocks) - set(registry.blocks))
    assert not missing, (
        f"tool documentation block(s) absent from the prompt registry: {missing}. Write the block, "
        "or remove the tool"
    )
    unreferenced = sorted(set(doc_blocks) - _referenced_block_ids(registry))
    assert not unreferenced, (
        f"tool documentation block(s) that exist but no manifest carries: {unreferenced}. A tool "
        "whose description reaches no role is a description the run never sent"
    )


# --------------------------------------------------------------------------------------------
# Conflict M4-C1: the parity gate's import chain acquires no dependency
# --------------------------------------------------------------------------------------------


def _imported_roots(node: ast.Import | ast.ImportFrom) -> tuple[str, ...]:
    """Top-level module names one import statement names. A relative import is first-party."""
    if isinstance(node, ast.Import):
        return tuple(alias.name.split(".")[0] for alias in node.names)
    if node.level:
        return ("agents",)
    return ((node.module or "").split(".")[0],)


def _imports(tree: ast.AST) -> Iterator[tuple[ast.Import | ast.ImportFrom, bool]]:
    """Yield every import in a module with whether it sits inside a function body."""
    nested: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            nested.update(
                id(child)
                for child in ast.walk(node)
                if isinstance(child, ast.Import | ast.ImportFrom)
            )
    for node in ast.walk(tree):
        if isinstance(node, ast.Import | ast.ImportFrom):
            yield node, id(node) in nested


def _third_party(roots: tuple[str, ...]) -> tuple[str, ...]:
    """The names in ``roots`` that are neither standard library nor this repository's."""
    return tuple(
        root
        for root in roots
        if root and root not in sys.stdlib_module_names and root not in FIRST_PARTY_ROOTS
    )


def test_the_registry_package_imports_nothing_outside_the_standard_library() -> None:
    """No module-scope import in ``agents/registry/`` names a distribution. No module is exempt.

    Conflict M4-C1: ``.github/workflows/ci.yml``'s parity step runs inside the ``guardrail-grep``
    job, which checks out the repository, runs shell scripts and installs nothing at all. A parity
    checker with a dependency would fail there for a dependency reason rather than a code one --
    precisely the shape ADR-025 records for M3's two guards tripping together. ADR-025's own
    resolution was "a gate script acquires what it needs", and this package rejects it: a
    ``pip install`` inside a grep job would put a package index on the critical path of a check that
    is supposed to take a second.

    ``model.py`` and ``tracing.py`` are included rather than skipped. The next test states the
    stronger property they satisfy instead of an exemption.
    """
    modules = _python_files(REGISTRY_PACKAGE)
    assert len(modules) >= 8, (
        f"agents/registry/ holds only {len(modules)} module(s): {[p.name for p in modules]}"
    )
    for expected in LAZY_BACKEND_MODULES:
        assert any(path.name == expected for path in modules), (
            f"{expected} is missing from agents/registry/, so the lazy-backend property below "
            "would be asserted of nothing"
        )

    offenders: list[str] = []
    scanned = 0
    for path in modules:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node, is_nested in _imports(tree):
            scanned += 1
            if is_nested:
                continue
            for root in _third_party(_imported_roots(node)):
                offenders.append(
                    f"{path.relative_to(REPO_ROOT).as_posix()}:{node.lineno}: imports {root!r}"
                )
    assert scanned > 20, f"only {scanned} import statement(s) seen; the scan is not reading trees"
    assert not offenders, (
        "agents/registry/ imports a third-party module at module scope:\n"
        + "\n".join(offenders)
        + "\n\nThe parity gate installs nothing (conflict M4-C1). Standard library only, or -- for "
        "a backend a runtime needs -- imported lazily inside the function that uses it."
    )


def test_the_two_backend_modules_reach_their_backends_only_inside_a_function() -> None:
    """``model.py`` and ``tracing.py`` are asserted, not exempted -- and the assertion is stronger.

    Their docstrings claim the backends are "resolved lazily, once, on first use" so that the import
    chain from the parity gate never reaches one. Stated as a property of the syntax tree, that is:
    every third-party import anywhere in ``agents/registry/`` sits inside a function body. The
    package-wide scan above already forbids one at module scope; this says where the permitted ones
    live, and reports them by name so a reviewer can see which backends the package can reach at
    all.
    """
    lazy: list[str] = []
    for path in _python_files(REGISTRY_PACKAGE):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node, is_nested in _imports(tree):
            for root in _third_party(_imported_roots(node)):
                where = f"{path.relative_to(REPO_ROOT).as_posix()}:{node.lineno}: {root}"
                assert is_nested, (
                    f"{where} is a third-party import outside a function body. A backend reached "
                    "at module scope is a backend the parity gate's import chain reaches too"
                )
                lazy.append(where)
                assert path.name in LAZY_BACKEND_MODULES, (
                    f"{where}: a third module in agents/registry/ has acquired a backend. Only "
                    f"{list(LAZY_BACKEND_MODULES)} may, and each degrades to something honest when "
                    "the backend is absent -- a new one needs that behaviour and an ADR before it "
                    "needs a lazy import"
                )


class _NothingInstalled(importlib.abc.MetaPathFinder):
    """A finder that refuses every module outside the standard library and this repository.

    The parity gate's environment, reproduced in one object: ``guardrail-grep`` checks out the
    repository and installs nothing, so the only importable things are the interpreter's own modules
    and the tree. Raising from ``find_spec`` rather than returning ``None`` is deliberate -- a
    ``None`` would let the next finder answer, and the next finder is the one that would find the
    installed distribution this test exists to pretend away. ``path`` and ``target`` are the
    :class:`importlib.abc.MetaPathFinder` signature's and are unread: the decision is made from the
    name alone.
    """

    def find_spec(self, fullname: str, path: object = None, target: object = None) -> None:
        del path, target
        root = fullname.split(".")[0]
        if root in sys.stdlib_module_names or root in FIRST_PARTY_ROOTS:
            return None
        raise ImportError(
            f"{fullname!r} is not importable: this is the parity gate's environment, which "
            "installs nothing. agents/registry/ must execute its module-level statements here"
        )


def test_every_registry_module_executes_with_no_distribution_installed() -> None:
    """Execute each module's top level with every distribution made unimportable, and it must work.

    The scan above reads the syntax tree; this runs it. The difference is worth one test, because a
    tree scan cannot see a backend reached by ``importlib.import_module`` at module scope, by a
    module-level ``__getattr__``, or by any of the other routes that are still an import when the
    interpreter performs them. Conflict M4-C1's failure is exactly this one, and it appears as an
    ``ImportError`` in a job that had no dependency step -- so it is reproduced rather than argued.

    Each module is executed under a throwaway name from its own file, so nothing in
    ``sys.modules`` is replaced and no other test in the session sees a duplicated class.

    The blocker is proved to block before it is trusted to. Every distribution in the pinned runtime
    set is importable on this runner, so a finder that quietly did nothing would let this test pass
    over a module that reached one -- which would be the failure it exists to catch, reported as a
    success.
    """
    blocker = _NothingInstalled()
    sys.meta_path.insert(0, blocker)
    try:
        with pytest.raises(ImportError):
            importlib.import_module("_a_distribution_that_would_not_be_installed")
        assert blocker.find_spec("json") is None, (
            "the blocker refuses a standard-library module, so it is not the parity gate's "
            "environment -- that job has an interpreter, it simply has no dependency step"
        )
        assert blocker.find_spec("agents.registry.loader") is None, (
            "the blocker refuses a first-party module, so agents/registry/ could not import itself"
        )
    finally:
        sys.meta_path.remove(blocker)

    executed: list[str] = []
    for path in _python_files(REGISTRY_PACKAGE):
        spec = importlib.util.spec_from_file_location(f"_purity_probe_{path.stem}", path)
        assert spec is not None and spec.loader is not None, f"{path} has no import spec"
        module = importlib.util.module_from_spec(spec)
        sys.meta_path.insert(0, blocker)
        try:
            spec.loader.exec_module(module)
        except ImportError as blocked:
            pytest.fail(
                f"{path.relative_to(REPO_ROOT).as_posix()} cannot be imported with nothing "
                f"installed: {blocked}. The parity gate runs in a job with no dependency step, so "
                "this is the check failing for a dependency reason rather than a code one"
            )
        finally:
            sys.meta_path.remove(blocker)
        executed.append(path.name)

    assert set(LAZY_BACKEND_MODULES) <= set(executed), (
        f"the two lazy-backend modules were not among the {len(executed)} executed: {executed}"
    )
