r"""The instrument freeze (P6 / ADR-136): one instrument, proven, before any run executes.

WHAT THE INSTRUMENT IS, AND WHY IT IS THIS SET OF PATHS
--------------------------------------------------------
M10 plan principle **P6** defines it in one sentence -- "The *instrument* is the content of
``agents/ guardian/ monitor/ runner/ scenarios/ analysis/ infra/ scripts/ docs/protocols/ Makefile
pyproject.toml``, identified by an instrument digest" -- and :data:`INSTRUMENT_PATHS` is that list,
transcribed once and never extended ad hoc. The set is the union of

* everything whose bytes can change what a run *does* (``agents/``, ``guardian/``, ``monitor/``,
  ``runner/``, ``scenarios/``) or how a bundle is read back (``analysis/``);
* everything whose bytes can change what the cluster *is* (``infra/``);
* the entry points and helper code both of those reach (``scripts/``, ``Makefile``); and
* the binding texts whose numbers the code mirrors (``pyproject.toml``, ``docs/protocols/``).

Everything OUTSIDE the set -- the dissertation under ``context/``, the ADRs, the plans, the
remaining ``docs/``, the CI workflow files -- is evidence ABOUT the instrument, not part of it. A
commit that only touches those can never change a measurement, so P6 requires it never to halt a
campaign or reset the pilot ladder, and that is the whole reason the check is a path-set check and
not the whole-repository one v1 used (defect V14: ``working_tree_dirty()`` walked
``git status --porcelain`` with no pathspec, so a reworded doc comment stopped a campaign).

WHY THE DIGEST IS TAKEN OVER GIT OBJECTS, NOT OVER THE WORKING TREE
---------------------------------------------------------------------
``enforce_freeze`` has to compare "the digest at HEAD" against "the digest at the freeze tag". Both
sides of that comparison are commits, and a commit's content is precisely what ``git ls-tree``
reports: mode, object type, blob SHA-1 and path, per tracked file. Hashing that listing gives a
digest that

* is a function of the committed tree alone, so the working directory cannot perturb it (a dirty
  tree is caught by its own check, which sees the untracked files ``ls-tree`` cannot);
* is content-addressed by git's own blob hash, so a one-byte change to one file moves it and a
  rename-only or mode-only bookkeeping change that git considers identical does not;
* needs no second copy of the tree on disk and no checked-out worktree at the tag, which is what
  lets the same function serve the pilot, the campaign and an offline corpus check alike.

THE RATIONALE FOR A RUNTIME SIDECAR RATHER THAN A TRACKED COMMIT HASH
---------------------------------------------------------------------
ADR-136: "a tracked file cannot carry its own commit's hash" -- ``campaign.json`` is committed in
the very commit ``v2.0`` names, so any commit hash written into it is either the *previous* commit
or a value that changes the moment it is written. That is not a design preference, it is a fixed
point that does not exist, and v1 discovered it the expensive way (``frozen_commit.txt`` was renamed
out of band, ADR-107). So the tracked manifest carries the tag NAME
(:attr:`~runner.campaign.CampaignManifest.freeze_tag`, chosen by hand before tagging) and the
resolved commit lives in a **runtime sidecar** under the campaign directory, written on first
execution and cross-checked on every later invocation.

The sidecar keeps the filename ``frozen_commit.txt`` deliberately: ``analysis/render.py``'s
``_enforce_frozen_commit`` already reads that name out of a campaign directory and hard-errors on a
bundle whose ``git_commit`` differs from it. Renaming it here would silently disable a check
another component owns.

GIT IS READ-ONLY HERE
---------------------
Every invocation below is ``rev-parse``, ``ls-tree`` or ``status``. The runner never writes to the
repository: the researcher creates the annotated tag by hand (``.agents/rules/30``), and the freeze
only ever *reads* what that produced. A freeze mechanism that can move its own reference is not a
freeze.

WHAT BREAKS IF THIS FILE CHANGES
---------------------------------
``runner/campaign_cli.py``'s per-cell freeze gate, ``runner/pilot_cli.py``'s ladder state key, and
ADR-136's whole enforcement design. After the ``v2.0`` freeze, any change here is a logged hotfix
ADR (AGENTS.md iron rule 6).
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from typing import Final

__all__ = (
    "FROZEN_COMMIT_SIDECAR",
    "INSTRUMENT_PATHS",
    "FreezeError",
    "enforce_freeze",
    "instrument_clean",
    "instrument_digest",
    "instrument_dirty_paths",
    "read_frozen_commit",
    "resolve_tag_commit",
)

REPO_ROOT: Final = Path(__file__).resolve().parents[1]

# THE INSTRUMENT (P6; ADR-136), transcribed from M10-implementation-plan.md §0 and used verbatim by
# every check below. Directory entries carry the trailing slash on purpose: it makes each a git
# pathspec for that subtree rather than a glob, so `docs/protocols/` covers the whole protocols
# directory while a sibling `docs/adr/` is excluded by construction. A reworded ADR therefore cannot
# halt a campaign, and a reworded protocol row must.
INSTRUMENT_PATHS: Final[tuple[str, ...]] = (
    "agents/",
    "guardian/",
    "monitor/",
    "runner/",
    "scenarios/",
    "analysis/",
    "infra/",
    "scripts/",
    "docs/protocols/",
    "Makefile",
    "pyproject.toml",
)

# The runtime sidecar's name, in the campaign directory. Frozen at the v1 name on purpose -- see the
# module docstring; `analysis/render.py::_enforce_frozen_commit` reads this exact file.
FROZEN_COMMIT_SIDECAR: Final = "frozen_commit.txt"


class FreezeError(RuntimeError):
    """The freeze is not satisfied: the instrument moved, or the tree is not clean.

    Distinct from a run failure or a validation failure, because the remedy is always the same and
    always the operator's: restore the frozen instrument, or start a new campaign id. Nothing the
    runner can do about it by retrying.
    """


def _git(repo_root: Path, argv: list[str]) -> str:
    """Run one read-only git command in ``repo_root`` and return its stdout.

    Every argv here is a literal in this module -- no caller-supplied argument reaches the command
    line, which is what lets the module carry a blanket "git is read-only" property rather than a
    per-call-site argument check.
    """
    try:
        completed = subprocess.run(  # noqa: S603 - fixed executable, fixed arguments
            ["git", *argv],  # noqa: S607 - git on PATH by design; the pilot and the campaign run
            cwd=repo_root,  # from one WSL2 shell with one git binary (P6)
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        raise FreezeError(f"could not run git {argv[0]}: {error}") from error
    if completed.returncode != 0:
        detail = completed.stderr.strip() or f"exit {completed.returncode}"
        raise FreezeError(f"git {' '.join(argv)} failed: {detail}")
    return completed.stdout


def _ls_tree(repo_root: Path, rev: str) -> list[str]:
    """The instrument's tracked entries at ``rev``, one ``<mode> <type> <sha>\\t<path>`` per entry.

    Sorted by git itself (``ls-tree`` is deterministic for a given tree), so the caller can hash the
    listing without re-sorting and two machines agree. The zero-byte separator keeps a path
    containing a newline -- which git permits -- from being able to forge a second entry.
    """
    raw = _git(repo_root, ["ls-tree", "-r", "-z", "--full-tree", rev, "--", *INSTRUMENT_PATHS])
    return [entry for entry in raw.split("\0") if entry]


def instrument_digest(repo_root: Path = REPO_ROOT, *, rev: str = "HEAD") -> str:
    """The sha256 hex digest of the instrument paths' tracked content at ``rev``.

    A pure function of the committed tree: the same ``(repo_root, rev)`` always yields the same
    digest, on any machine, and a docs-only commit outside :data:`INSTRUMENT_PATHS` does not move it
    because those paths are not in the pathspec at all. This is the value ``F-RN-02`` compares
    across a corpus, and the value :func:`enforce_freeze` compares between HEAD and the tag.
    """
    digest = hashlib.sha256()
    for entry in sorted(_ls_tree(repo_root, rev)):
        # Length-prefixed, so no pair of entries can be re-partitioned into the same byte stream.
        encoded = entry.encode("utf-8")
        digest.update(str(len(encoded)).encode("ascii"))
        digest.update(b"\0")
        digest.update(encoded)
        digest.update(b"\0")
    return digest.hexdigest()


def instrument_dirty_paths(repo_root: Path = REPO_ROOT) -> tuple[str, ...]:
    """The instrument paths carrying an uncommitted change, ``()`` when the instrument is clean.

    ``git status --porcelain`` with the instrument pathspec, so it reports staged, unstaged AND
    untracked entries under those paths -- the case :func:`instrument_digest` cannot see, because an
    untracked file is in no commit. Untracked matters more than usual here: an untracked
    ``runner/`` module is picked up by the next cell's ``import``, so it is an instrument change no
    digest comparison would notice.
    """
    raw = _git(repo_root, ["status", "--porcelain", "--", *INSTRUMENT_PATHS])
    dirty: list[str] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        # Porcelain v1: "XY <path>", with "R  <old> -> <new>" for a rename. The path is what the
        # operator needs to see; the status codes are for the operator's own `git status` to read.
        dirty.append(line[3:].strip())
    return tuple(sorted(dirty))


def instrument_clean(repo_root: Path = REPO_ROOT) -> bool:
    """Whether every instrument path is clean.

    The single-question form :func:`enforce_freeze` and the callers that only want the boolean.
    """
    return not instrument_dirty_paths(repo_root)


def resolve_tag_commit(freeze_tag: str, repo_root: Path = REPO_ROOT) -> str:
    """Resolve ``freeze_tag`` to the commit it names, via ``rev-parse refs/tags/<tag>^{commit}``.

    The ``^{commit}`` peel is what makes an ANNOTATED tag work: ``refs/tags/v2.0`` on its own is the
    tag object, whose hash is not the commit any bundle records, so peeling is the difference
    between a resolvable freeze and a permanent mismatch.
    """
    if not freeze_tag or freeze_tag.startswith("-"):
        raise FreezeError(f"freeze tag {freeze_tag!r} is not a tag name")
    return _git(repo_root, ["rev-parse", f"refs/tags/{freeze_tag}^{{commit}}"]).strip()


def read_frozen_commit(campaign_dir: Path) -> str | None:
    """The sidecar's recorded commit, or ``None`` when the campaign has not been frozen yet."""
    sidecar = Path(campaign_dir) / FROZEN_COMMIT_SIDECAR
    if not sidecar.is_file():
        return None
    return sidecar.read_text(encoding="utf-8").strip() or None


def enforce_freeze(
    campaign_dir: Path,
    freeze_tag: str | None = None,
    *,
    repo_root: Path = REPO_ROOT,
    write_sidecar: bool = True,
    retarget: bool = False,
) -> str:
    """Refuse to run unless the instrument is frozen, and return the frozen commit.

    Three checks, in the cheapest-first order the ladder and the campaign both want:

    1. **the instrument paths are clean** -- refuses an uncommitted or untracked change inside
       :data:`INSTRUMENT_PATHS`, at any point in the campaign;
    2. **the digest at HEAD equals the digest at the freeze tag** -- this is what replaces v1's
       whole-repository ``working_tree_dirty()`` check: a commit *outside* the instrument paths
       cannot move the digest and therefore cannot halt anything, and a commit inside it cannot move
       without halting;
    3. **the sidecar cross-check** -- the first invocation resolves the tag to a commit and records
       it; every later invocation refuses if the reference now names a different one, which catches
       a
       moved tag even when the tree was restored to match it.

    ``freeze_tag=None`` is the pre-freeze path (the ladder runs long before ``v2.0`` exists): HEAD
    is the reference, the digest comparison degenerates to "HEAD equals HEAD", and only the
    cleanliness and sidecar checks bite. That is why the pilot has a freeze at all without a tag.

    **``retarget`` weakens check 3 and exists for exactly one caller.** ``retarget=True`` re-pins
    the
    sidecar when the reference has moved, instead of refusing. It is passed by
    :func:`runner.pilot_cli.record_stage` and by nothing else, because the pilot ladder has a
    DOCUMENTED response to an instrument move -- plan §6's restart rule, "an instrument change
    resets
    the ladder to P1a" -- while a campaign has none and must halt. It is only ever effective with no
    ``freeze_tag``: with a tag, check 2 compares HEAD against the tag and fires first, so a
    post-freeze pilot or campaign can never retarget. The name is the warning.

    Used by BOTH the campaign and the pilot (ADR-136, "Pilot freeze"), which is why this is one
    function and not two: a freeze the pilot can route around is not a freeze.
    """
    campaign_dir = Path(campaign_dir)
    dirty = instrument_dirty_paths(repo_root)
    if dirty:
        where = ", ".join(dirty)
        raise FreezeError(
            f"the instrument has uncommitted changes at {where}; a run must be produced by a "
            "frozen, committed instrument so every bundle's git_commit names the exact instrument "
            "(P6, ADR-136). Commit or stash them, then re-run. A change OUTSIDE the instrument "
            "paths is not this error -- that is the point of P6."
        )

    if freeze_tag:
        tag_commit = resolve_tag_commit(freeze_tag, repo_root)
    else:
        tag_commit = _git(repo_root, ["rev-parse", "HEAD"]).strip()

    if freeze_tag:
        head_digest = instrument_digest(repo_root, rev="HEAD")
        tag_digest = instrument_digest(repo_root, rev=tag_commit)
        if head_digest != tag_digest:
            raise FreezeError(
                f"the instrument digest at HEAD ({head_digest[:12]}) is not the digest at "
                f"freeze tag "
                f"{freeze_tag!r} ({tag_digest[:12]}); the instrument moved after the freeze. An "
                "instrument change halts the campaign and restarts the pilot ladder at P1a "
                "(M10 plan §6, ADR-120). Check out the frozen commit, or re-freeze with a new tag."
            )

    recorded = read_frozen_commit(campaign_dir)
    if recorded is not None and recorded != tag_commit:
        if not retarget:
            raise FreezeError(
                f"this campaign was frozen at commit {recorded} but "
                f"{freeze_tag or 'HEAD'} now resolves "
                f"to {tag_commit}; a campaign or a pilot may not resume onto a different "
                "instrument (ADR-136). Check out the frozen commit, or start a new campaign id."
            )
        # The one documented re-pin. Deliberately silent about the old value in the return: the
        # caller (the ladder) records the move in its own `resets` counter, which is the artefact a
        # reader looks at.
        recorded = None
    if recorded is None and write_sidecar:
        campaign_dir.mkdir(parents=True, exist_ok=True)
        (campaign_dir / FROZEN_COMMIT_SIDECAR).write_text(tag_commit + "\n", encoding="utf-8")
    return tag_commit
