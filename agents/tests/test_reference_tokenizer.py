r"""The parity gate's instrument: pinned by name, offline by construction, fixed by golden vectors.

WHAT THIS TEST IS FOR
---------------------
:mod:`agents.registry.tokenizer` is the counter every number in ``make parity-check``'s token table
comes out of, and the table's identity line names it. Three properties have to hold for that number
to mean anything across two machines and two years, and none of them is checked by anything else in
the repository:

*The pin cannot drift.* ``infra/versions.env``'s ``PARITY_TOKENIZER`` and
:data:`~agents.registry.tokenizer.REFERENCE_TOKENIZER_ID` are the same string in two homes. That
copy is legal under ADR-022 only because a test makes "copy" mean "copy that cannot drift", and the
tokenizer's own docstring names this obligation explicitly: the constant is mirrored **and the
mirror is checked**. Without the check, the identity written into a sealed run bundle could name an
algorithm other than the one that produced the count in it, and nothing would say so.

*The gate must run where there is no credential and no network.* ``make parity-check`` runs in the
``guardrail-grep`` job, which installs nothing. A tokenizer that reached a model hub for a
vocabulary -- which is what ``tiktoken``, ``transformers`` and ``sentencepiece`` each do -- would
make a CI-blocking gate's result depend on network reachability. The import check below is what
turns "it uses only the standard library" from a reading of the file into an assertion over its
AST.

*The algorithm must be visible when it changes.* Changing the pattern changes every parity number
in the repository and the structural-block cap that is stated in this unit. The golden vectors are
what make such a change a diff a reviewer sees rather than a silently different set of numbers in
the next token table.

WHY THE GOLDEN VECTORS ARE SO SMALL AND SO SPECIFIC
------------------------------------------------------
Each one is chosen for a branch of the pattern rather than for realism: a contraction (``'t``), an
underscore inside an identifier, a digit run, a hyphen between two words, a run of indentation, and
a run of blank lines. The underscore is the one place the module's own comment says the
transcription from GPT-2's ``\p{L}``/``\p{N}`` classes to Python's ``\w``/``\d`` could be got
quietly wrong, so ``run_id`` counting three pieces rather than one is pinned by name. A vector
list that was merely representative English would have passed either way.

The counts are recorded as literals, deliberately, and they are not derived from the module under
test -- a test that computed its expectation from the thing it is testing asserts only that the
function is deterministic, which is a different property and is checked separately below.

WHY LINE ENDINGS ARE CHECKED THROUGH THE LOADER RATHER THAN AT THIS FUNCTION
-----------------------------------------------------------------------------
:func:`~agents.registry.tokenizer.count_tokens` is a pure function of the ``str`` it is handed, and
the one normalisation it applies is Unicode NFC. It does **not** fold CRLF, and it should not: the
fold belongs to :mod:`agents.registry.loader`, which applies it once when a block is read, so that
every consumer downstream sees LF whatever the checkout convention was.

The property that actually matters -- and the one asserted below -- is therefore about the composed
pipeline rather than about the regular expression: **the parity number must not depend on whether
the host checked the repository out with CRLF or with LF.** ``.gitattributes`` normalises tracked
text to LF in the index while the Windows development host checks it out with CRLF, so a count that
moved with the line ending would put the development host and the CI runner permanently at odds
about a registry neither of them had changed. The test rewrites the whole shipped registry into two
temporary trees, one CRLF and one LF, loads both, and compares every block's count and every
condition's total.

WHAT THIS FILE DELIBERATELY DOES NOT CHECK
--------------------------------------------
*That the count matches a real BPE tokenizer's.* It does not, by design and by a factor the module's
docstring states plainly. Parity is an equality across conditions drawn from one block set, so a
systematic factor divides out of the ratio; what it cannot hide is a condition carrying more or
longer blocks, which is the whole of what the gate looks for. The campaign model's own tokenizer is
compared against this one once, at GATE, as a cross-check and never as the gate.

*Any tolerance, cap or budget.* Those are ``docs/protocols/prompt-parity-policy.md``'s and are not
restated here. This file pins the instrument; the protocol owns what the instrument is compared
against.
"""

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agents.registry import STRUCTURE_CONDITIONS  # noqa: E402
from agents.registry import tokenizer as tokenizer_module  # noqa: E402
from agents.registry.composer import compose_condition  # noqa: E402
from agents.registry.loader import PromptRegistry, load_registry  # noqa: E402
from agents.registry.tokenizer import (  # noqa: E402
    REFERENCE_TOKENIZER_ID,
    count_tokens,
    pre_tokens,
)

# infra/versions.env's key for the reference tokenizer, and the file itself, located from this
# file rather than from the working directory so the test reads the same pin whatever invoked it.
VERSIONS_ENV_PATH = REPO_ROOT / "infra" / "versions.env"
PARITY_TOKENIZER_KEY = "PARITY_TOKENIZER"

# Standard-library modules that reach the network. Named separately from the stdlib check because
# "only the standard library" and "no network" are two claims, and the standard library is perfectly
# capable of opening a socket. A tokenizer that fetched a vocabulary through `urllib` would satisfy
# the first check and defeat the gate's whole reason for existing.
NETWORKING_MODULES = frozenset(
    {
        "asyncio",
        "ftplib",
        "http",
        "imaplib",
        "poplib",
        "smtplib",
        "socket",
        "socketserver",
        "ssl",
        "telnetlib",
        "urllib",
        "xmlrpc",
    }
)

# Fixed inputs and their exact expected counts. See the module docstring for why each is here; the
# numbers are literals rather than anything derived from the module under test.
GOLDEN_VECTORS: tuple[tuple[str, int], ...] = (
    ("", 0),
    ("a", 1),
    ("hello world", 2),
    # A contraction is two pieces, not three: `'t` is its own alternative in the pattern.
    ("don't", 2),
    # The underscore case. `\w` includes `_` and GPT-2's `\p{L}` does not, so the transcription has
    # to add it back to the punctuation class -- without which this would count one, not three.
    ("run_id", 3),
    # A hyphen splits two letter runs, and a digit run is its own piece with its leading space.
    ("namespace-1 has 42 pods\n", 7),
    # A colon is punctuation, a newline terminates a piece, and a value keeps its leading space.
    ("verb: get\nresource: pods\n", 8),
    # A run of indentation is one piece: `\s+(?!\S)` takes every space but the one that belongs to
    # the word after it.
    ("  indented line\n", 4),
    # Consecutive blank lines collapse into a single whitespace piece, so padding is counted but is
    # not counted per line.
    ("\n\n", 1),
)

# One word in two Unicode normalisation forms: the composed `e`-acute as a single code point, and
# the decomposed spelling as a plain `e` followed by a combining acute. The second is written as an
# escape rather than as a literal so the difference survives an editor that would normalise the
# file. NFC is the one normalisation the module applies, so these two must count alike; without it
# the same character typed in two editors would give two parity numbers.
NFC_CAFE = "café"
NFD_CAFE = "café"


def read_pin(text: str, key: str) -> str | None:
    """Return ``key``'s value from ``infra/versions.env``, with ``scripts/`` semantics exactly.

    ``scripts/install_runtime_deps.sh``'s ``read_pin`` is
    ``grep -E "^KEY=" | head -n 1 | cut -d= -f2- | tr -d '\\r'``: the first line whose start is the
    key and an equals sign, everything after that first equals sign, carriage returns removed. It is
    reproduced rather than approximated so that the value this test compares is the value the
    installer would read -- a test that parsed the file more cleverly than the script does could
    agree with the module while the script disagreed with both.
    """
    for line in text.split("\n"):
        stripped = line.replace("\r", "")
        if stripped.startswith(f"{key}="):
            return stripped.split("=", 1)[1]
    return None


def imported_top_level_modules(source: str) -> set[str]:
    """Return the top-level module names ``source`` imports, from its AST.

    Over the AST rather than over a regular expression, because an import is a syntactic construct
    and a grep for ``^import`` misses one inside a function -- which is exactly where a lazily
    imported backend would be written. ``ast.walk`` visits every node at every depth, so a deferred
    import inside a function body is found as readily as a module-level one.
    """
    modules: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and not node.level:
            modules.add((node.module or "").split(".")[0])
    return modules


def dynamic_import_calls(source: str) -> list[str]:
    """Return the names of any ``__import__`` or ``importlib.import_module`` calls in ``source``.

    The import statement is not the only way to reach a package, and a check that only read import
    statements would be the kind of guard ``.agents/rules/40-monitor-non-llm.md`` warns about: one
    that cannot see the route somebody would actually take to get round it.
    """
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        target = node.func
        if isinstance(target, ast.Name) and target.id in ("__import__", "eval", "exec"):
            found.append(target.id)
        elif isinstance(target, ast.Attribute) and target.attr == "import_module":
            found.append("import_module")
    return found


def rewrite_tree(source: Path, destination: Path, newline: str) -> Path:
    """Copy every file under ``source`` into ``destination`` with ``newline`` line endings.

    Written with ``write_bytes`` because ``Path.write_text`` on Windows applies its own
    universal-newline translation, which would silently make the LF copy and the CRLF copy the same
    file and leave the comparison asserting nothing.
    """
    for item in sorted(source.rglob("*")):
        if not item.is_file():
            continue
        target = destination / item.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        folded = item.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
        target.write_bytes(folded.replace("\n", newline).encode("utf-8"))
    return destination


def test_the_tokenizer_id_matches_the_pin_in_versions_env() -> None:
    """``REFERENCE_TOKENIZER_ID`` and ``infra/versions.env``'s ``PARITY_TOKENIZER`` are one string.

    ADR-022's shape: one rule stated once in prose, two homes, and a test that makes "copy" mean
    "copy that cannot drift". The identity is written into the emitted token table and belongs in
    every run bundle's manifest, so a number read out of a sealed bundle says which algorithm
    produced it -- which is only true while these two agree.
    """
    assert VERSIONS_ENV_PATH.is_file(), (
        f"{VERSIONS_ENV_PATH} is missing; it is the single file naming every pin in this project"
    )
    # Read as bytes and decoded, rather than through read_text, so that the CR handling below is the
    # script's `tr -d '\r'` and not the platform's universal-newline translation.
    pinned = read_pin(VERSIONS_ENV_PATH.read_bytes().decode("utf-8"), PARITY_TOKENIZER_KEY)
    assert pinned is not None, (
        f"{PARITY_TOKENIZER_KEY} is absent from {VERSIONS_ENV_PATH}. The parity gate names its "
        "tokenizer in every token table, and an unpinned instrument is one nobody can identify "
        "from a sealed bundle"
    )
    assert pinned == REFERENCE_TOKENIZER_ID, (
        f"{PARITY_TOKENIZER_KEY} is {pinned!r} in {VERSIONS_ENV_PATH.name} but "
        f"agents/registry/tokenizer.py declares {REFERENCE_TOKENIZER_ID!r}. These are one identity "
        "in two homes; a divergence means a token table naming an algorithm that did not produce it"
    )


def test_the_module_imports_only_the_standard_library_and_reaches_no_network() -> None:
    """The tokenizer's AST carries no third-party import, no networking import, and no dynamic one.

    Asserted over the module's own source rather than over an installed dependency set, because the
    gate's requirement is about *this file*: ``make parity-check`` runs in a job that installs
    nothing, so a third-party import here fails CI for a dependency reason before it can fail for a
    code reason. The networking half is checked separately, because the standard library is
    perfectly capable of opening a socket and "stdlib only" would not exclude it.
    """
    source = Path(tokenizer_module.__file__).read_text(encoding="utf-8")
    modules = imported_top_level_modules(source)
    assert modules, "the tokenizer module parsed to no imports at all, which cannot be right"

    outside = sorted(name for name in modules if name not in sys.stdlib_module_names)
    assert not outside, (
        f"agents/registry/tokenizer.py imports {outside}, which is outside the standard library. "
        "The parity gate runs in a CI job that installs nothing, so a dependency here fails for a "
        "dependency reason before it can fail for a code one"
    )

    networking = sorted(modules & NETWORKING_MODULES)
    assert not networking, (
        f"agents/registry/tokenizer.py imports {networking}, which can reach the network. A gate "
        "whose result depends on network reachability is not a gate"
    )

    dynamic = dynamic_import_calls(source)
    assert not dynamic, (
        f"agents/registry/tokenizer.py calls {sorted(set(dynamic))}, which is a route to a module "
        "that no import statement declares -- the one shape an import check cannot otherwise see"
    )


def test_counting_is_pure_and_repeatable() -> None:
    """The same input counts the same every time, and counting mutates nothing.

    Determinism is ``.agents/rules/20-parity-and-determinism.md``'s requirement applied to a gate
    rather than to a scenario: one regular expression over ``str``, no locale, no clock, no
    dictionary iteration order, no network. Repeated deliberately rather than once, because a
    counter holding state -- a cache keyed on something mutable, a compiled pattern rebuilt with
    different flags -- would agree with itself on the first call and not on the fourth.
    """
    samples = [text for text, _ in GOLDEN_VECTORS] + [NFC_CAFE, "a much longer line of prose\n" * 8]
    for text in samples:
        counts = {count_tokens(text) for _ in range(4)}
        assert len(counts) == 1, (
            f"counting {text!r} four times gave {sorted(counts)}; the reference tokenizer must be "
            "a pure function of its input"
        )
        pieces = {pre_tokens(text) for _ in range(4)}
        assert len(pieces) == 1, f"pre_tokens({text!r}) was not stable across four calls"


def test_the_empty_string_counts_zero() -> None:
    """Zero, and by the pattern matching nothing rather than by a special case.

    Worth its own assertion because it is the one input for which "the count is the number of
    pieces" and "the count is a length" could plausibly have been made to differ by a guard clause,
    and because an empty block is refused by the loader -- so nothing else in the suite would ever
    exercise it.
    """
    assert count_tokens("") == 0, "the empty string must count zero tokens"
    assert pre_tokens("") == (), "the empty string must pre-tokenize to no pieces at all"


def test_golden_vectors_count_exactly() -> None:
    """Fixed strings, fixed counts, and the pieces cover the input with nothing dropped.

    The counts are literals. If one of these moves, the pattern changed, and the change is a change
    to every parity number in the repository and to the structural-block cap that is stated in this
    unit -- an ADR before the ``v1.0`` freeze and a logged hotfix ADR after it. The point of the
    literals is that such a change arrives as a red test rather than as a quietly different table.

    The round trip is asserted beside each count because a count is only meaningful if the pieces
    cover the input: a pattern that silently dropped a character would keep counting, and would
    count something other than the text.
    """
    for text, expected in GOLDEN_VECTORS:
        counted = count_tokens(text)
        assert counted == expected, (
            f"count_tokens({text!r}) is {counted}, not {expected}. A changed count means a changed "
            f"pattern: the pieces were {pre_tokens(text)!r}"
        )
        assert len(pre_tokens(text)) == counted, (
            f"count_tokens({text!r}) and pre_tokens({text!r}) disagree, so the number the gate "
            "reports is not the number of pieces a reader debugging it would see"
        )
        assert "".join(pre_tokens(text)) == text, (
            f"the pieces of {text!r} do not concatenate back to it; the pattern dropped a "
            "character and the count describes something other than the input"
        )


def test_counting_is_indifferent_to_unicode_normalisation_form() -> None:
    """A composed character and its decomposed spelling count alike, because NFC is applied once.

    Two byte sequences that render as the same character would otherwise give two parity numbers for
    one prompt, and the difference would be a property of whichever editor typed it rather than of
    the registry.
    """
    assert NFC_CAFE != NFD_CAFE, (
        "the two fixtures are the same string, so this case would compare nothing"
    )
    assert count_tokens(NFC_CAFE) == count_tokens(NFD_CAFE), (
        f"{NFC_CAFE!r} counts {count_tokens(NFC_CAFE)} and its decomposed spelling counts "
        f"{count_tokens(NFD_CAFE)}; NFC normalisation is what must make these one number"
    )


def test_the_parity_count_does_not_depend_on_the_checkout_line_endings(
    registry: PromptRegistry, tmp_path: Path
) -> None:
    """The shipped registry, written CRLF and written LF, produces identical counts and totals.

    The composed guarantee rather than a property of the regular expression:
    :func:`~agents.registry.tokenizer.count_tokens` is a pure function of the ``str`` it is given
    and folds no line endings, because the fold is :mod:`agents.registry.loader`'s and happens once
    when a block is read. What must hold end to end is that the parity number is a property of the
    registry and not of the host -- ``.gitattributes`` normalises tracked text to LF in the index
    while the Windows development host checks it out with CRLF, so a count that moved with the line
    ending would put the development host and the CI runner permanently at odds about files neither
    had changed.
    """
    crlf_root = rewrite_tree(registry.root, tmp_path / "crlf", "\r\n")
    lf_root = rewrite_tree(registry.root, tmp_path / "lf", "\n")
    assert b"\r\n" in next(crlf_root.rglob("*.md")).read_bytes(), (
        "the CRLF copy was written without any CRLF, so this case would compare a tree with itself"
    )

    from_crlf = load_registry(crlf_root)
    from_lf = load_registry(lf_root)

    assert set(from_crlf.blocks) == set(from_lf.blocks) == set(registry.blocks)
    for block_id, block in from_lf.blocks.items():
        assert count_tokens(block.body) == count_tokens(from_crlf.blocks[block_id].body), (
            f"block {block_id!r} counts differently depending on the checkout's line endings"
        )
        assert count_tokens(block.body) == count_tokens(registry.blocks[block_id].body), (
            f"block {block_id!r} counts differently in the temporary copy than in the shipped tree"
        )

    for condition in STRUCTURE_CONDITIONS:
        crlf_total = compose_condition(from_crlf, condition).total_tokens
        lf_total = compose_condition(from_lf, condition).total_tokens
        assert crlf_total == lf_total, (
            f"{condition} totals {crlf_total} tokens from a CRLF checkout and {lf_total} from an "
            "LF one; the parity table would then differ between the development host and CI"
        )
