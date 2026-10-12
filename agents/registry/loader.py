r"""Reading the prompt registry: a strict block grammar, a strict manifest grammar, and no guessing.

WHAT THIS MODULE IS
-------------------
``docs/protocols/prompt-parity-policy.md`` section 2 rule 1 puts every byte of prompt text in
``agents/prompts/`` "as versioned registry files (YAML/MD blocks with stable block IDs)", and rule 2
puts each condition's wiring in ``agents/prompts/compositions/<condition>.yaml``. This module reads
both, validates them against every structural claim those rules make, and returns typed values that
:mod:`agents.registry.composer` and :mod:`agents.registry.parity` can work from. It is the only
reader of those files in the repository.

WHY THERE IS A PARSER HERE AND NOT A YAML DEPENDENCY
------------------------------------------------------
Conflict M4-C1: ``make parity-check`` runs in ``.github/workflows/ci.yml``'s ``guardrail-grep``
job, which checks out the repository, runs shell scripts, and installs nothing at all. A parity
checker that imported PyYAML would fail there for a dependency reason before it could fail for a
code reason -- exactly the shape ADR-025 records for M3's two guards tripping together. The
available answers were to teach a grep job to ``pip install``, which puts a package index on the
critical path of a check that should take a second, or to write the parser. ``monitor/tests/
test_limits_match_protocol.py`` already took the second answer for the same reason and states it:
"adding it to run one assertion would put a third-party package on the critical path of the lint
job for a grammar that is a dozen lines of :mod:`re`". ADR-028.

The grammar below is therefore a **subset** of YAML and is deliberately small. Everything outside
it raises :class:`ManifestSyntaxError` rather than being tolerated, for the reason that module
gives about its own parser: a parser that shrugs at a line it does not recognise could silently
miss the very key it exists to compare, and a block this reader half-understands is a block it
cannot be trusted about. In particular there is **no** flow-style mapping, no anchor, no alias, no
multi-document stream, no multi-line scalar and no tag. The two empty-collection forms ``[]`` and
``{}`` are admitted because "this role holds no tools" has to be sayable.

The subset is a superset of what these files use, never the other way round: a manifest that a real
YAML parser would read differently from this one is a manifest this one refuses.

WHAT THE VALIDATION IS FOR
---------------------------
Every check in :func:`load_registry` corresponds to a sentence in the parity policy, and each is
here rather than in the gate because a malformed registry must fail at the point it is read --
including when the reader is the *runtime* rather than the gate. A composition that names a block
which does not exist is not a parity failure to be reported in a table; it is a registry that
cannot be composed, and the graph that loaded it must not run.

- Rule 1, stable block IDs: a block's ``id`` must equal its filename stem, and no two blocks may
  share one. The filename is what a reviewer greps and the id is what a manifest references; if the
  two could disagree, a rename would silently orphan a block while leaving the manifest green.
- Rule 2, shared by construction: every block declares ``parity_class`` as ``shared`` or
  ``structural``, and nothing else. A block with no class would default to something, and the
  default would decide whether the gate compares it.
- Rule 4, grounding: every block header carries either a ``source_anchor`` or an explicit
  ``origin: engineering`` **with** a ``justification``. Both, or neither, is refused -- a block
  claiming a source *and* declaring itself engineering-authored is a block whose provenance nobody
  can state in Chapter 3.
- Manifest integrity: every referenced block exists; every role's node is one of
  :data:`agents.registry.NODE_KINDS`; every budget phase is one of :data:`agents.registry.PHASES`;
  every budgeted role is a declared role; every declared phase carries a budget for at least one
  role.

WHAT THIS MODULE DELIBERATELY DOES NOT DO
------------------------------------------
*It does not compose.* Turning a role's block list into the bytes a model receives is
:mod:`agents.registry.composer`'s job, and keeping the two apart is what lets the gate and the
runtime share one composer while this module stays a pure reader.

*It does not count tokens.* :mod:`agents.registry.tokenizer` does, and no cap or tolerance appears
here.

*It does not read a condition flag.* The condition selects which manifest is loaded and nothing
below that point knows which arm it is in -- ADR-027 rejects a condition parameter reaching node
behaviour outright, because the branch would be the confound.
"""

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from agents.registry import NODE_KINDS, PHASES

__all__ = (
    "BLOCKS_DIRNAME",
    "COMPOSITIONS_DIRNAME",
    "Budget",
    "Composition",
    "ManifestSyntaxError",
    "PromptBlock",
    "PromptRegistry",
    "RegistryError",
    "RoleComposition",
    "default_registry_root",
    "load_registry",
    "parse_manifest",
)

# The two directories section 2 names, relative to the registry root.
BLOCKS_DIRNAME: Final = "blocks"
COMPOSITIONS_DIRNAME: Final = "compositions"

# A block file is Markdown so that its body is readable as prose in a diff, with a fenced header.
BLOCK_SUFFIX: Final = ".md"
MANIFEST_SUFFIX: Final = ".yaml"

# The front-matter fence. Three hyphens on a line of their own, the convention every static-site
# generator already uses, so a reviewer opening a block file recognises the shape without being
# told what it is.
FRONT_MATTER_FENCE: Final = "---"

# The two parity classes section 2 rule 2 defines. `structural` is the tagged class -- "condition
# manifests may differ only in topology-necessitated connective blocks ... each tagged
# `parity_class: structural`" -- and `shared` is everything else, named explicitly rather than left
# as the absence of a tag so that a block cannot be shared by omission.
PARITY_CLASSES: Final[tuple[str, ...]] = ("shared", "structural")

# The one value `origin` may take. Section 2 rule 4: "New blocks require a source or an explicit
# `origin: engineering` tag with justification." One legal value, so a typo is a refusal rather
# than a new category of provenance nobody decided on.
ENGINEERING_ORIGIN: Final = "engineering"

# A block id: dotted, lowercase, hyphen-separated segments. Dotted because the ids are a namespace
# -- `common.*`, `role.*`, `tool.*`, `structural.*` -- and lowercase because a case-insensitive
# filesystem would otherwise let two ids differing only in case be one file on Windows and two on
# Linux, which is a difference between what CI reads and what a developer reads.
BLOCK_ID_PATTERN: Final = (
    r"^[a-z0-9]+(?:[-a-z0-9]*[a-z0-9])?(?:\.[a-z0-9]+(?:[-a-z0-9]*[a-z0-9])?)*$"
)
_BLOCK_ID = re.compile(BLOCK_ID_PATTERN)

# Indentation is two spaces per level, spaces only. Fixed rather than inferred, because an inferred
# indent unit means a file with mixed indentation parses into a structure nobody wrote.
INDENT_UNIT: Final = 2

_SCALAR_KEY = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*):(?:[ ](.*))?$")
_SEQUENCE_ITEM = re.compile(r"^-(?:[ ](.*))?$")


class RegistryError(RuntimeError):
    """The prompt registry cannot be read as the parity policy requires.

    One exception type for every structural failure -- a missing directory, a duplicate id, a
    dangling block reference, a block with no provenance -- because every one of them has the same
    consequence: the registry cannot be composed, so neither the gate nor the runtime may proceed.
    Distinguishing them by type would invite a caller to catch one and continue.
    """


class ManifestSyntaxError(RegistryError):
    """A line is outside the grammar :func:`parse_manifest` accepts.

    A subclass rather than a separate hierarchy, because a file this parser cannot read and a file
    it can read but which says the wrong thing are the same refusal from the caller's point of
    view. It is nevertheless a distinct name so that ``agents/tests/`` can assert that a malformed
    line raises for a *syntax* reason rather than tripping a later validation by accident.
    """


# --------------------------------------------------------------------------------------------
# The YAML subset
# --------------------------------------------------------------------------------------------


def _coerce_scalar(text: str, *, where: str) -> Any:
    """Return one scalar from the grammar: quoted string, integer, float, boolean, null, or word.

    Double quotes are the only quoting form, with ``\\"`` and ``\\\\`` as the only escapes. Single
    quotes are not admitted: YAML gives them different escaping rules from double quotes, and a
    subset that accepted both would have two string grammars where the files use one.

    An unquoted value that looks like a number *is* a number, which is what makes ``max_turns: 4``
    an integer without the manifest having to say so. A value that looks like neither is a plain
    string, which is what makes ``id: orchestrator`` work. That is YAML's own resolution rule for
    plain scalars, restricted to the four types this grammar has any use for.
    """
    stripped = text.strip()
    if not stripped:
        raise ManifestSyntaxError(f'{where}: empty scalar; write "" for an intentional blank')
    if stripped.startswith('"'):
        if len(stripped) < 2 or not stripped.endswith('"'):
            raise ManifestSyntaxError(f"{where}: unterminated double-quoted scalar")
        body = stripped[1:-1]
        out: list[str] = []
        index = 0
        while index < len(body):
            character = body[index]
            if character != "\\":
                if character == '"':
                    raise ManifestSyntaxError(f"{where}: unescaped quote inside a quoted scalar")
                out.append(character)
                index += 1
                continue
            if index + 1 >= len(body):
                raise ManifestSyntaxError(f"{where}: trailing escape in a quoted scalar")
            marker = body[index + 1]
            if marker not in ('"', "\\"):
                raise ManifestSyntaxError(
                    f'{where}: unknown escape {"\\" + marker!r}; this grammar has two, \\" and \\\\'
                )
            out.append(marker)
            index += 2
        return "".join(out)
    if stripped == "[]":
        return []
    if stripped == "{}":
        return {}
    if stripped == "null":
        return None
    if stripped in ("true", "false"):
        return stripped == "true"
    try:
        return int(stripped)
    except ValueError:
        pass
    try:
        return float(stripped)
    except ValueError:
        pass
    return stripped


@dataclass(frozen=True)
class _Line:
    """One significant line, with its indentation depth already checked and converted."""

    number: int
    depth: int
    text: str


def _significant_lines(source: str, *, where: str) -> list[_Line]:
    """Return the non-blank, non-comment lines with their indentation depths.

    A comment is a line whose first non-space character is ``#``. Inline comments are **not**
    stripped, and that is deliberate rather than lazy: stripping them means deciding whether a
    ``#`` inside a quoted string ends the value, which is a second string grammar hiding inside a
    comment rule. A ``#`` in the middle of a line is therefore a literal character here, and a
    reviewer who wants a comment puts it on its own line.
    """
    lines: list[_Line] = []
    for number, raw in enumerate(source.replace("\r\n", "\n").replace("\r", "\n").split("\n"), 1):
        if "\t" in raw:
            raise ManifestSyntaxError(
                f"{where} line {number}: tab in the indentation; this grammar is spaces only, "
                "because a tab's width is a property of whoever is reading rather than of the file"
            )
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent % INDENT_UNIT:
            raise ManifestSyntaxError(
                f"{where} line {number}: indented {indent} space(s); the unit is {INDENT_UNIT}"
            )
        lines.append(_Line(number=number, depth=indent // INDENT_UNIT, text=raw.strip()))
    return lines


def _parse_block(lines: Sequence[_Line], start: int, depth: int, where: str) -> tuple[Any, int]:
    """Parse one mapping or sequence at ``depth``, returning it and the index just past it."""
    if start >= len(lines):
        raise ManifestSyntaxError(f"{where}: expected a mapping or sequence, found end of file")
    if _SEQUENCE_ITEM.match(lines[start].text):
        return _parse_sequence(lines, start, depth, where)
    return _parse_mapping(lines, start, depth, where)


def _parse_mapping(
    lines: Sequence[_Line], start: int, depth: int, where: str
) -> tuple[dict[str, Any], int]:
    """Parse a block mapping: one ``key: value`` or ``key:`` plus an indented block, per line."""
    mapping: dict[str, Any] = {}
    index = start
    while index < len(lines) and lines[index].depth == depth:
        line = lines[index]
        match = _SCALAR_KEY.match(line.text)
        if match is None:
            raise ManifestSyntaxError(
                f"{where} line {line.number}: not a mapping entry: {line.text!r}"
            )
        key, inline = match.group(1), match.group(2)
        if key in mapping:
            raise ManifestSyntaxError(
                f"{where} line {line.number}: duplicate key {key!r}; a mapping that repeats a key "
                "silently keeps one of the two values and nothing says which"
            )
        if inline is not None and inline.strip():
            mapping[key] = _coerce_scalar(inline, where=f"{where} line {line.number}")
            index += 1
            continue
        nested_start = index + 1
        if nested_start >= len(lines) or lines[nested_start].depth <= depth:
            raise ManifestSyntaxError(
                f"{where} line {line.number}: {key!r} opens a block but nothing is indented under "
                "it; write [] or {} for an intentional empty collection"
            )
        if lines[nested_start].depth != depth + 1:
            raise ManifestSyntaxError(
                f"{where} line {lines[nested_start].number}: indented "
                f"{lines[nested_start].depth - depth} level(s) below {key!r}, expected 1"
            )
        mapping[key], index = _parse_block(lines, nested_start, depth + 1, where)
    if index < len(lines) and lines[index].depth > depth:
        raise ManifestSyntaxError(
            f"{where} line {lines[index].number}: indented under a scalar, which this grammar "
            "has no reading for"
        )
    return mapping, index


def _parse_sequence(
    lines: Sequence[_Line], start: int, depth: int, where: str
) -> tuple[list[Any], int]:
    """Parse a block sequence: ``- scalar`` items, or ``- key: value`` opening a mapping item."""
    items: list[Any] = []
    index = start
    while index < len(lines) and lines[index].depth == depth:
        line = lines[index]
        match = _SEQUENCE_ITEM.match(line.text)
        if match is None:
            raise ManifestSyntaxError(
                f"{where} line {line.number}: not a sequence item: {line.text!r}"
            )
        payload = match.group(1)
        if payload is None or not payload.strip():
            raise ManifestSyntaxError(
                f"{where} line {line.number}: empty sequence item; this grammar has no reading "
                "for a dash on its own"
            )
        entry = _SCALAR_KEY.match(payload.strip())
        if entry is None:
            items.append(_coerce_scalar(payload, where=f"{where} line {line.number}"))
            index += 1
            continue
        # A `- key: value` item is a mapping whose first entry sits on the dash's line. The
        # remaining entries are indented one level further, which is where every YAML writer puts
        # them and the only depth this grammar accepts for them.
        synthetic = [_Line(number=line.number, depth=depth + 1, text=payload.strip())]
        follow = index + 1
        while follow < len(lines) and lines[follow].depth > depth:
            synthetic.append(lines[follow])
            follow += 1
        mapping, consumed = _parse_mapping(synthetic, 0, depth + 1, where)
        if consumed != len(synthetic):
            raise ManifestSyntaxError(
                f"{where} line {synthetic[consumed].number}: unread line inside a sequence item"
            )
        items.append(mapping)
        index = follow
    return items, index


def parse_manifest(source: str, *, where: str = "<manifest>") -> dict[str, Any]:
    """Parse one document in the grammar above and return its top-level mapping.

    ``where`` names the file in every error message. It is a parameter rather than being taken from
    a path because this function is also exercised against inline fixtures, and a fixture failure
    that named no file would be the least useful message in the suite.
    """
    lines = _significant_lines(source, where=where)
    if not lines:
        raise ManifestSyntaxError(f"{where}: the document is empty")
    if lines[0].depth != 0:
        raise ManifestSyntaxError(f"{where} line {lines[0].number}: the document starts indented")
    parsed, consumed = _parse_mapping(lines, 0, 0, where)
    if consumed != len(lines):
        raise ManifestSyntaxError(
            f"{where} line {lines[consumed].number}: unread line after the top-level mapping"
        )
    return parsed


# --------------------------------------------------------------------------------------------
# The registry's types
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class PromptBlock:
    """One addressable unit of prompt text, with the provenance section 2 rule 4 requires.

    ``body`` is the bytes a model eventually receives for this block, exactly -- no trailing
    whitespace stripped beyond one normalisation, no indentation removed, no substitution. The
    composer joins bodies; it never edits one. That is what makes "every non-``structural`` block
    byte-identical across conditions" checkable by comparing digests rather than by re-rendering.

    ``digest`` is the SHA-256 of the LF-normalised body. It exists so the parity check can state
    identity without holding three copies of the text in memory, and so a failure message can name
    a block that differs without printing it.
    """

    block_id: str
    parity_class: str
    body: str
    digest: str
    source_anchor: str | None
    origin: str | None
    justification: str | None
    path: Path

    @property
    def is_structural(self) -> bool:
        """``True`` for the topology-necessitated connective blocks section 2 rule 2 bounds."""
        return self.parity_class == "structural"


@dataclass(frozen=True)
class Budget:
    """One role's declared allocation for one phase: turns and tool calls, both required.

    Declared rather than measured, which is why :mod:`agents.registry.limits` bounds the two with a
    tolerance of zero. Both are read twice -- by ``make parity-check``, which asserts S1's per-role
    allocations sum to S2's coordinator budget and to S3's single-agent budget, and by the graph
    runtime, which enforces the same numbers at execution and records consumption against them.
    One home, two readers, which is the only arrangement in which the checked number and the
    enforced number cannot diverge.

    **A retry is a turn.** Risk R-10's mitigation is "structured-output prompting; retry policy
    logged", and a weak free model retries more in whichever arm happens to trip it. If retries did
    not count here, the arm that struggled would silently receive more turns and the ablation would
    be confounded by model weakness rather than by topology. Exhausting the budget is a recorded
    phase outcome, never an escape hatch. ADR-028.
    """

    max_turns: int
    max_tool_calls: int


@dataclass(frozen=True)
class RoleComposition:
    """One role in one condition: which behaviour it is, which blocks it carries, which tools.

    ``node`` is one of :data:`agents.registry.NODE_KINDS` and is what the graph instantiates.
    ``phase`` is set only for a role scoped to one phase -- S1's four Supervisors -- and is ``None``
    for the roles that span phases, which is every role in S2-FLAT and S3-SINGLE and the
    Orchestrator in S1-HIER.

    ``tools`` names entries in the one tool registry. Section 2 rule 3 makes that registry identical
    across conditions; what differs is which node holds which entries, and in particular which node
    holds the issuance tool -- the Supervisor in S1, the coordinator in S2 and S3. That is
    conflict M4-C7's resolution and it is a configuration difference rather than a code one, which
    is the only resolution that does not touch the enforcement path. ADR-027.
    """

    role_id: str
    node: str
    phase: str | None
    block_ids: tuple[str, ...]
    tools: tuple[str, ...]


@dataclass(frozen=True)
class Composition:
    """One condition's wiring, as ``agents/prompts/compositions/<condition>.yaml`` declares it.

    ``issuance_tool_holder`` names the role that holds the token-issuance tool. It is a role id
    rather than a boolean, because "which node holds it" is exactly the question conflict M4-C7
    asks and a boolean would only answer it for the two-tier case.
    """

    condition: str
    issuance_tool_holder: str
    roles: tuple[RoleComposition, ...]
    budgets: Mapping[str, Mapping[str, Budget]]
    path: Path

    def role(self, role_id: str) -> RoleComposition:
        """Return the named role, or raise naming what this condition actually declares."""
        for candidate in self.roles:
            if candidate.role_id == role_id:
                return candidate
        raise RegistryError(
            f"{self.condition}: no role {role_id!r}; declared roles are "
            f"{', '.join(role.role_id for role in self.roles)}"
        )

    def tool_names(self) -> tuple[str, ...]:
        """Every tool this condition's roles hold, deduplicated, in sorted order.

        Sorted rather than first-seen, because this tuple is hashed into the tool-registry identity
        the parity check compares across conditions, and a hash over an order that depends on which
        role was declared first would differ between two conditions that hold exactly the same
        tools. Rule 20 forbids ordering that depends on declaration order for anything a run
        depends on, and a gate verdict is such a thing.
        """
        return tuple(sorted({name for role in self.roles for name in role.tools}))


@dataclass(frozen=True)
class PromptRegistry:
    """Every block and every composition, loaded and validated together.

    Loaded together on purpose: a composition is only checkable against the blocks it references,
    and a block is only reachable through a composition. ``scripts/prompt_purity_grep.sh`` asserts
    the second direction as a boundary -- no block file that no manifest reaches -- and this class
    is what makes the first direction impossible to get wrong at run time.
    """

    root: Path
    blocks: Mapping[str, PromptBlock]
    compositions: Mapping[str, Composition]

    def block(self, block_id: str) -> PromptBlock:
        """Return the named block, or raise naming the closest thing to a suggestion available."""
        try:
            return self.blocks[block_id]
        except KeyError:
            raise RegistryError(
                f"no prompt block {block_id!r} under {self.root / BLOCKS_DIRNAME}. "
                f"The registry holds {len(self.blocks)} block(s); ids are the filename stems"
            ) from None


# --------------------------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------------------------


def default_registry_root() -> Path:
    """Return ``agents/prompts/``, resolved from this file rather than from the caller's cwd.

    The gate script, the test suite and the graph runtime all reach the registry from different
    working directories. Deriving the path from ``__file__`` is what makes those three read the
    same bytes; deriving it from ``os.getcwd()`` would make the parity number depend on where the
    check was invoked.
    """
    return Path(__file__).resolve().parents[1] / "prompts"


def _normalise_body(text: str) -> str:
    """Return ``text`` with line endings folded to LF and exactly one trailing newline.

    ADR-010's rule, applied to prompt text for ADR-022's reason. ``.gitattributes`` normalises
    tracked text to LF in the index and the Windows development host checks it out with CRLF, so a
    body read raw would give one token count on the development host and another on the CI runner
    -- and the parity table would then differ between two machines holding identical files. The
    single trailing newline is normalised for the same reason a block is joined to its neighbour by
    exactly one blank line: the composer's output must be a function of the blocks and not of
    whoever last pressed return.
    """
    folded = text.replace("\r\n", "\n").replace("\r", "\n")
    return folded.rstrip("\n") + "\n"


def _load_block(path: Path) -> PromptBlock:
    """Read and validate one block file."""
    where = path.as_posix()
    raw = path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
    if not raw.startswith(FRONT_MATTER_FENCE + "\n"):
        raise RegistryError(
            f"{where}: a block file starts with a {FRONT_MATTER_FENCE!r} fence and a header "
            "declaring its id, parity_class and provenance (parity policy section 2 rules 1-4)"
        )
    closing = raw.find("\n" + FRONT_MATTER_FENCE + "\n", len(FRONT_MATTER_FENCE))
    if closing == -1:
        raise RegistryError(f"{where}: the front-matter fence is never closed")
    header_text = raw[len(FRONT_MATTER_FENCE) + 1 : closing + 1]
    body = raw[closing + len(FRONT_MATTER_FENCE) + 2 :]

    header = parse_manifest(header_text, where=where)
    for key, value in header.items():
        if not isinstance(value, str):
            raise RegistryError(
                f"{where}: header key {key!r} is {value!r}; a block header is flat and every "
                "value is a string, so that its provenance reads the same to a person and to the "
                "gate"
            )

    block_id = header.get("id")
    if not isinstance(block_id, str) or not _BLOCK_ID.match(block_id):
        raise RegistryError(f"{where}: id {block_id!r} does not match {BLOCK_ID_PATTERN}")
    if block_id != path.stem:
        raise RegistryError(
            f"{where}: declares id {block_id!r} but is named {path.stem!r}. The filename is what a "
            "reviewer greps and the id is what a manifest references; if the two could disagree, a "
            "rename would orphan a block while leaving every manifest green"
        )

    parity_class = header.get("parity_class")
    if parity_class not in PARITY_CLASSES:
        raise RegistryError(
            f"{where}: parity_class {parity_class!r} is not one of {', '.join(PARITY_CLASSES)}. "
            "A block with no class would default to one, and the default would decide whether the "
            "parity gate compares it"
        )

    source_anchor = header.get("source_anchor")
    origin = header.get("origin")
    justification = header.get("justification")
    if source_anchor and origin:
        raise RegistryError(
            f"{where}: carries both a source_anchor and origin {origin!r}. A block claiming a "
            "source and declaring itself engineering-authored is a block whose provenance nobody "
            "can state in Chapter 3 (parity policy section 2 rule 4)"
        )
    if not source_anchor:
        if origin != ENGINEERING_ORIGIN:
            raise RegistryError(
                f"{where}: no source_anchor, and origin is {origin!r} rather than "
                f"{ENGINEERING_ORIGIN!r}. Section 2 rule 4: every block lists its source anchor, "
                "and a new block requires a source or an explicit engineering origin"
            )
        if not justification or not justification.strip():
            raise RegistryError(
                f"{where}: origin is {ENGINEERING_ORIGIN!r} with no justification. The tag without "
                "the reason is the tag doing no work"
            )

    unknown = set(header) - {"id", "parity_class", "source_anchor", "origin", "justification"}
    if unknown:
        raise RegistryError(
            f"{where}: unknown header key(s) {sorted(unknown)}. The header is a closed set, for "
            "guardian/app/models.py's reason about extra='forbid': a key nobody reads is a key "
            "somebody will assume is read"
        )

    normalised = _normalise_body(body)
    if not normalised.strip():
        raise RegistryError(f"{where}: the body is empty; a block with no text is not a block")

    return PromptBlock(
        block_id=block_id,
        parity_class=parity_class,
        body=normalised,
        digest=hashlib.sha256(normalised.encode("utf-8")).hexdigest(),
        source_anchor=source_anchor,
        origin=origin,
        justification=justification,
        path=path,
    )


def _require_int(value: Any, *, where: str, key: str) -> int:
    """Return ``value`` as a non-negative integer, or raise naming the key and what was found."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise RegistryError(f"{where}: {key} is {value!r}; a budget is a whole number")
    if value < 0:
        raise RegistryError(f"{where}: {key} is {value}; a budget cannot be negative")
    return value


def _load_composition(path: Path, block_ids: frozenset[str]) -> Composition:
    """Read and validate one condition's composition manifest."""
    where = path.as_posix()
    document = parse_manifest(path.read_text(encoding="utf-8"), where=where)

    unknown = set(document) - {"condition", "issuance_tool_holder", "roles", "budgets"}
    if unknown:
        raise RegistryError(f"{where}: unknown top-level key(s) {sorted(unknown)}")

    condition = document.get("condition")
    if condition != path.stem:
        raise RegistryError(
            f"{where}: declares condition {condition!r} but is named {path.stem!r}; the "
            "filename is how the runner and the gate address a condition"
        )

    raw_roles = document.get("roles")
    if not isinstance(raw_roles, list) or not raw_roles:
        raise RegistryError(f"{where}: roles must be a non-empty sequence")

    roles: list[RoleComposition] = []
    seen_roles: set[str] = set()
    for entry in raw_roles:
        if not isinstance(entry, dict):
            raise RegistryError(f"{where}: every role is a mapping; found {entry!r}")
        extra = set(entry) - {"id", "node", "phase", "blocks", "tools"}
        if extra:
            raise RegistryError(f"{where}: role has unknown key(s) {sorted(extra)}")
        role_id = entry.get("id")
        if not isinstance(role_id, str) or not role_id:
            raise RegistryError(f"{where}: role id {role_id!r} is not a name")
        if role_id in seen_roles:
            raise RegistryError(f"{where}: duplicate role id {role_id!r}")
        seen_roles.add(role_id)
        node = entry.get("node")
        if node not in NODE_KINDS:
            raise RegistryError(
                f"{where}: role {role_id!r} declares node {node!r}, which is not one of "
                f"{', '.join(NODE_KINDS)}. ADR-027 indexes the node registry by behaviour and a "
                "fifth behaviour would be a fifth thing parity has to compare"
            )
        phase = entry.get("phase")
        if phase is not None and phase not in PHASES:
            raise RegistryError(f"{where}: role {role_id!r} names phase {phase!r}")
        blocks = entry.get("blocks")
        if not isinstance(blocks, list) or not blocks:
            raise RegistryError(f"{where}: role {role_id!r} carries no blocks")
        for referenced in blocks:
            if not isinstance(referenced, str) or referenced not in block_ids:
                raise RegistryError(
                    f"{where}: role {role_id!r} references block {referenced!r}, which does not "
                    f"exist under {path.parent.parent / BLOCKS_DIRNAME}"
                )
        if len(set(blocks)) != len(blocks):
            raise RegistryError(
                f"{where}: role {role_id!r} references a block twice. A block included twice is "
                "counted twice by the token budget and read twice by the model, and neither is a "
                "thing anybody writes on purpose"
            )
        tools = entry.get("tools", [])
        if not isinstance(tools, list) or any(not isinstance(name, str) for name in tools):
            raise RegistryError(f"{where}: role {role_id!r} declares tools {tools!r}")
        roles.append(
            RoleComposition(
                role_id=role_id,
                node=node,
                phase=phase,
                block_ids=tuple(blocks),
                tools=tuple(tools),
            )
        )

    holder = document.get("issuance_tool_holder")
    if holder not in seen_roles:
        raise RegistryError(
            f"{where}: issuance_tool_holder {holder!r} is not a declared role. Which node holds "
            "the issuance tool is the whole of conflict M4-C7's resolution, so it is named rather "
            "than inferred"
        )

    raw_budgets = document.get("budgets")
    if not isinstance(raw_budgets, dict):
        raise RegistryError(f"{where}: budgets must be a mapping of phase to role allocations")
    missing = [phase for phase in PHASES if phase not in raw_budgets]
    if missing:
        raise RegistryError(
            f"{where}: no budget declared for phase(s) {missing}. Every phase carries a declared "
            "allocation, because a phase with none is a phase the gate cannot compare and the "
            "runtime cannot bound"
        )
    unknown_phases = set(raw_budgets) - set(PHASES)
    if unknown_phases:
        raise RegistryError(f"{where}: budgets name unknown phase(s) {sorted(unknown_phases)}")

    budgets: dict[str, dict[str, Budget]] = {}
    for phase in PHASES:
        allocations = raw_budgets[phase]
        if not isinstance(allocations, dict) or not allocations:
            raise RegistryError(f"{where}: budgets.{phase} declares no role allocation")
        per_role: dict[str, Budget] = {}
        for role_id, allocation in allocations.items():
            if role_id not in seen_roles:
                raise RegistryError(f"{where}: budgets.{phase} names undeclared role {role_id!r}")
            if not isinstance(allocation, dict) or set(allocation) != {
                "max_turns",
                "max_tool_calls",
            }:
                raise RegistryError(
                    f"{where}: budgets.{phase}.{role_id} must declare exactly max_turns and "
                    "max_tool_calls; a partial allocation is a budget with a hole in it"
                )
            per_role[role_id] = Budget(
                max_turns=_require_int(
                    allocation["max_turns"], where=where, key=f"budgets.{phase}.{role_id}.max_turns"
                ),
                max_tool_calls=_require_int(
                    allocation["max_tool_calls"],
                    where=where,
                    key=f"budgets.{phase}.{role_id}.max_tool_calls",
                ),
            )
        budgets[phase] = per_role

    return Composition(
        condition=condition,
        issuance_tool_holder=holder,
        roles=tuple(roles),
        budgets=budgets,
        path=path,
    )


def load_registry(root: Path | None = None) -> PromptRegistry:
    """Load and validate every block and composition under ``root`` (default ``agents/prompts/``).

    Raises :class:`RegistryError` on anything the parity policy's structural rules forbid. It does
    **not** raise for a parity *failure* -- an over-long structural block, a token budget outside
    the tolerance -- because those are the gate's verdict rather than the registry's shape, and a
    loader that refused them would make the gate unable to report what was wrong.
    """
    base = default_registry_root() if root is None else Path(root)
    blocks_dir = base / BLOCKS_DIRNAME
    compositions_dir = base / COMPOSITIONS_DIRNAME
    for directory in (blocks_dir, compositions_dir):
        if not directory.is_dir():
            raise RegistryError(
                f"{directory} is missing. The prompt registry is two directories -- "
                f"{BLOCKS_DIRNAME}/ and {COMPOSITIONS_DIRNAME}/ -- and parity asserts an equality "
                "across conditions, so an absent registry proves nothing rather than nothing being "
                "wrong"
            )

    blocks: dict[str, PromptBlock] = {}
    for path in sorted(blocks_dir.rglob(f"*{BLOCK_SUFFIX}")):
        block = _load_block(path)
        if block.block_id in blocks:
            raise RegistryError(
                f"{path.as_posix()}: duplicate block id {block.block_id!r}, also declared by "
                f"{blocks[block.block_id].path.as_posix()}"
            )
        blocks[block.block_id] = block
    if not blocks:
        raise RegistryError(f"{blocks_dir} holds no {BLOCK_SUFFIX} block file")

    known = frozenset(blocks)
    compositions: dict[str, Composition] = {}
    for path in sorted(compositions_dir.glob(f"*{MANIFEST_SUFFIX}")):
        composition = _load_composition(path, known)
        compositions[composition.condition] = composition
    if not compositions:
        raise RegistryError(f"{compositions_dir} holds no {MANIFEST_SUFFIX} composition manifest")

    return PromptRegistry(root=base, blocks=blocks, compositions=compositions)
