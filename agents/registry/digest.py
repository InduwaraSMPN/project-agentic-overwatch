r"""The registry digests every run manifest carries -- ADR-010's rule, one layer up, twice over.

WHAT THIS MODULE IS
-------------------
``docs/protocols/data-management.md`` requires ``manifest.json`` to carry ``prompt_registry_sha256``
and ``tool_registry_sha256``. This module computes both. A digest is what turns "the run used the
registry" into a checkable statement: two bundles carrying the same digest were produced from the
same bytes, and a bundle whose digest does not match the tree it claims to come from is a bundle
whose prompts nobody can reconstruct.

WHY THE RULE IS THE POLICY BUNDLE'S RULE, AND WHY IT IS IMPLEMENTED TWICE
--------------------------------------------------------------------------
``guardian/app/policy.py``'s :class:`PolicyBundle` already implements the correct rule for a
directory of files, and it is correct for reasons that apply here unchanged:

*LF normalisation.* ``.gitattributes`` normalises tracked text to LF in the index and the Windows
development host checks it out with CRLF. A raw byte hash would record **which host loaded the
registry** rather than which registry was loaded, and two manifests from one commit would disagree.
That is ADR-010's defect, closed for ``versions_env_sha256``, and ADR-022 reapplies it.

*Sorted paths, length-prefixed.* Each path and its content are fed to the hash with their lengths,
so no two different trees can produce the same byte stream by moving a boundary -- a file named
``ab`` containing ``c`` and one named ``a`` containing ``bc`` are otherwise indistinguishable.

*Every non-hidden regular file, no extension filter.* An extension filter is a place to hide a
block. Hidden files are skipped because editor swap files and VCS metadata are not what the runtime
loads, and letting them into the digest would make the number depend on whether somebody had a file
open.

**The rule is implemented here a second time rather than imported, and that is a cost recorded
rather than a benefit claimed.** ``agents/`` cannot import ``guardian/``: the Guardian ships as its
own container and holds the only cluster credential, so the dependency would run the wrong way and
would make the agent layer's image carry the enforcement component. ADR-022 settled the shape for
exactly this trade -- one rule stated once in prose, two homes, and a test that makes "copy" mean
"copy that cannot drift". ``agents/tests/test_registry_digest.py`` is that test: it builds one
fixture directory and asserts :func:`directory_digest` and ``PolicyBundle.load(...).digest`` return
the same string. If the two ever diverge, the test names it at the commit that caused it rather
than a milestone later, in a sealed bundle, as a manifest nobody can reproduce.

WHY THE TOOL REGISTRY GETS ITS OWN DIGEST AND IT IS NOT A DIRECTORY HASH
-------------------------------------------------------------------------
``prompt-parity-policy.md`` section 2 rule 3 requires the *tool registry hash* to be identical
across conditions, and section 3 makes that one of the four parity assertions. A directory hash
over ``agents/tools/`` would be the wrong instrument for that claim in both directions: it would
change when a docstring changed, which is not a tool-definition change, and it would be identical
across conditions **by construction** rather than by check, since all three conditions read the
same directory. An assertion that cannot fail is not an assertion.

So :func:`tool_registry_digest` hashes the *definitions* -- name, schema, and the id of the
documentation block -- as a canonical JSON projection, per condition, from what that condition's
manifest actually gives its roles. Two conditions then produce the same digest only if they really
do hold the same tools with the same shapes, which is the claim rule 3 makes and the one a reader
of Chapter 3 will believe was checked.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
Every ``manifest.json`` written after the change carries a different ``prompt_registry_sha256`` for
an unchanged registry, so two halves of one campaign would appear to have used different prompts.
After the ``v1.0`` freeze that is a logged hotfix ADR under iron rule 6, with a campaign-notes entry
listing the affected runs.
"""

import hashlib
import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, Final

__all__ = (
    "DIGEST_SEPARATOR",
    "canonical_json_bytes",
    "directory_digest",
    "digest_files",
    "tool_registry_digest",
)

# The framing byte between a length, a path, a length and a content. NUL, because it is the one
# byte that cannot occur in a POSIX path and does not occur in any text file this repository
# tracks, so the framing is unambiguous without an escaping rule. The same value
# guardian/app/policy.py uses, deliberately, since the two digests must agree.
DIGEST_SEPARATOR: Final = b"\x00"


def _normalise_line_endings(content: bytes) -> bytes:
    """Return ``content`` with CRLF and lone CR collapsed to LF.

    Lone CR is folded as well as CRLF. It is not a line ending any tool here produces, and leaving
    it unnormalised would mean the rule covered the case that occurs and not the case that would be
    hardest to notice -- which is ``guardian/app/policy.py``'s reasoning, quoted here because a
    reader comparing the two implementations should find the same sentence on both sides.
    """
    return content.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def _is_hidden(item: Path, root: Path) -> bool:
    """Return ``True`` if any path segment below ``root`` begins with a dot.

    Checked on every segment rather than only the name, so a whole hidden directory is skipped
    without needing a second rule.
    """
    return any(part.startswith(".") for part in item.relative_to(root).parts)


def digest_files(root: Path) -> tuple[str, ...]:
    """Return the relative POSIX paths that :func:`directory_digest` will cover, in hash order.

    Published beside the digest for the reason ``PolicyBundle.files`` exists: a digest that does not
    match is a fact, and the file list is what turns it into something a person can investigate.
    """
    base = Path(root)
    return tuple(
        item.relative_to(base).as_posix()
        for item in sorted(
            (
                candidate
                for candidate in base.rglob("*")
                if candidate.is_file() and not _is_hidden(candidate, base)
            ),
            key=lambda candidate: candidate.relative_to(base).as_posix(),
        )
    )


def directory_digest(root: Path) -> str:
    """Return the SHA-256 of every non-hidden regular file under ``root``, LF-normalised.

    Raises ``FileNotFoundError`` when ``root`` is not a directory and ``ValueError`` when it holds
    no file at all. Both are refusals rather than an empty digest: an empty registry hashes to the
    digest of nothing, which is a perfectly stable number describing no prompts, and a manifest
    carrying it would look configured.
    """
    base = Path(root)
    if not base.is_dir():
        raise FileNotFoundError(f"{base} is not a directory, so there is no registry to digest")

    digest = hashlib.sha256()
    covered = 0
    for relative in digest_files(base):
        content = _normalise_line_endings((base / relative).read_bytes())
        digest.update(str(len(relative)).encode("ascii"))
        digest.update(DIGEST_SEPARATOR)
        digest.update(relative.encode("utf-8"))
        digest.update(DIGEST_SEPARATOR)
        digest.update(str(len(content)).encode("ascii"))
        digest.update(DIGEST_SEPARATOR)
        digest.update(content)
        digest.update(DIGEST_SEPARATOR)
        covered += 1
    if covered == 0:
        raise ValueError(
            f"{base} holds no file to digest. An empty registry hashes to a perfectly stable "
            "number describing no prompts, and a run manifest carrying it would look configured"
        )
    return digest.hexdigest()


def canonical_json_bytes(payload: Any) -> bytes:
    """Serialise ``payload`` as canonical JSON: sorted keys, minimal separators, ASCII, no NaN.

    The same four arguments ``monitor/aggregator/models.py`` uses, and for the same reason: the
    output bytes are hashed, so they must be a function of the value alone and not of dictionary
    insertion order, of the platform's float repr, or of whether the writer's locale renders a
    non-ASCII character directly.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def tool_registry_digest(definitions: Iterable[Mapping[str, Any]]) -> str:
    """Return the SHA-256 over a canonical projection of the tool definitions given.

    ``definitions`` is whatever ``agents/tools/registry.py`` publishes for the tools one condition's
    roles hold -- name, parameter schema, and the id of the documentation block, which is where the
    prose lives. Sorted by name inside, so that the digest is a property of the *set* of tools and
    not of the order a manifest happened to list them; two conditions holding the same tools in
    different declaration orders must produce the same number, or rule 3's assertion would fail for
    a reason that has nothing to do with the tools.
    """
    projected = sorted(
        ({key: value for key, value in definition.items()} for definition in definitions),
        key=lambda definition: str(definition.get("name", "")),
    )
    if not projected:
        raise ValueError(
            "no tool definitions to digest. Section 2 rule 3 asserts the tool registry hash is "
            "identical across conditions; a hash over nothing is identical across conditions "
            "whatever they hold, which is an assertion that cannot fail"
        )
    return hashlib.sha256(canonical_json_bytes(projected)).hexdigest()
