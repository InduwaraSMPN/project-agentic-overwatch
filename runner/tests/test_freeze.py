r"""The instrument freeze (P6 / ADR-136): one instrument, proven, before any run executes.

WHY A THROWAWAY REPOSITORY AND NOT THE REAL ONE
-----------------------------------------------
Every test here builds a small git repository under ``tmp_path`` with the instrument paths laid out
(P6's set, in miniature), and drives ``git`` against THAT. Three reasons, in order of how much they
matter:

* the tests must create commits, move tags and dirty files, and ``.agents/rules/30`` forbids the
  runner -- and the assistant driving it -- from writing to the real repository. A test suite that
  needed a real commit to make its point could not be run at all here;
* the real repository is, by construction during M10, DIRTY in the instrument paths: the whole
  remediation is uncommitted work under ``runner/`` and ``agents/``. Asserting "the freeze refuses a
  dirty instrument" against it would pass for the wrong reason on every run, and asserting "a
  docs-only edit does not halt" would need a commit that must not exist;
* the freeze's correctness is a property of the path set and of git's reporting, neither of which
  depends on this repository's contents. A 40-byte file under ``runner/`` and a 4 KB one hash the
  same way.

THE FOUR NAMED CASES
--------------------
The M10 plan names these four for this file, and each is the shape of the bug the freeze exists to
stop:

* :func:`test_docs_only_edit_does_not_halt` -- a change under ``docs/`` OUTSIDE
  ``docs/protocols/``. v1's whole-repository check halted here (defect V14).
* :func:`test_instrument_edit_halts` -- a change inside the instrument paths, committed.
* :func:`test_frozen_commit_sidecar_cross_checked` -- the sidecar is the runtime answer to "a
  tracked
  file cannot carry its own commit's hash", and a moved tag must be caught even when the tree was
  restored to match it.
* :func:`test_pilot_refuses_dirty_instrument` -- the same freeze, reached through the PILOT's entry
  point, because a freeze the pilot can route around is not a freeze (ADR-136, "Pilot freeze").

Plus the guards that keep the transcription honest: the path set IS P6's set, the digest is
reproducible, and an untracked file inside an instrument path is caught even though no commit
mentions it.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from runner.campaign import CampaignError, from_dict, to_canonical_bytes  # noqa: E402
from runner.freeze import (  # noqa: E402
    FROZEN_COMMIT_SIDECAR,
    INSTRUMENT_PATHS,
    FreezeError,
    enforce_freeze,
    instrument_clean,
    instrument_digest,
    instrument_dirty_paths,
    read_frozen_commit,
    resolve_tag_commit,
)
from runner.grid import build_campaign_manifest  # noqa: E402
from runner.pilot_cli import record_stage  # noqa: E402

# A stand-in for one tracked file under each instrument path, plus one under docs/ OUTSIDE
# docs/protocols/ -- the three-way distinction the freeze turns on.
INSTRUMENT_FILES = (
    "agents/graphs/nodes.py",
    "guardian/policies/authority.rego",
    "monitor/rules/overwatch-rules.yaml",
    "runner/freeze.py",
    "scenarios/manifests/SCN-SIM-01.yaml",
    "analysis/stats/measures.py",
    "infra/audit/audit-policy.yaml",
    "scripts/up.sh",
    "docs/protocols/evaluation-protocol.md",
    "Makefile",
    "pyproject.toml",
)
DOCS_ONLY_FILES = ("docs/adr/ADR-999-example.md", "docs/plans/some-plan.md", "docs/notes.md")


def _git(repo: Path, *args: str) -> str:
    """One git invocation in the throwaway repository. Tests only; never touches the real one."""
    completed = subprocess.run(  # noqa: S603 - fixed argv
        ["git", *args],  # noqa: S607 - git on PATH by design, as everywhere in the runner
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, f"git {' '.join(args)} failed: {completed.stderr}"
    return completed.stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A clean, committed, TAGGED miniature repository carrying P6's path set."""
    root = tmp_path / "instrument"
    root.mkdir()
    _git(root, "init", "--quiet", "--initial-branch=main")
    # Identity and signing are configured locally, never globally: a test must not be able to change
    # the developer's git configuration to make itself pass.
    _git(root, "config", "user.email", "freeze-test@example.invalid")
    _git(root, "config", "user.name", "freeze test")
    _git(root, "config", "commit.gpgsign", "false")
    _git(root, "config", "tag.gpgsign", "false")
    for name in (*INSTRUMENT_FILES, *DOCS_ONLY_FILES):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# {name}\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "--quiet", "-m", "instrument at v1")
    _git(root, "tag", "-a", "v1.0", "-m", "instrument freeze v1.0")
    return root


def _edit(repo: Path, name: str, text: str) -> None:
    (repo / name).write_text(text, encoding="utf-8")


def _commit(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "--quiet", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


# ================================================================================================
# THE FOUR NAMED CASES
# ================================================================================================


def test_docs_only_edit_does_not_halt(repo: Path, tmp_path: Path) -> None:
    """A change under ``docs/`` OUTSIDE ``docs/protocols/`` moves neither the digest nor the gate.

    This is the delicate one, and it is the whole reason the instrument is a PATH SET rather than a
    repository. v1's ``working_tree_dirty()`` ran ``git status --porcelain`` with no pathspec, so
    reworded a doc comment was indistinguishable from editing the agent graph, and a campaign
    stopped (defect V14). P6 requires the opposite: "Edits outside the instrument paths
    (dissertation, ADRs, plans) never halt anything."
    """
    campaign_dir = tmp_path / "runs" / "CAMP-20260926-pilot-p2"
    before = instrument_digest(repo)
    frozen = enforce_freeze(campaign_dir, "v1.0", repo_root=repo)
    assert read_frozen_commit(campaign_dir) == frozen

    # A dissertation chapter, an ADR and a plan: all outside the instrument, all committed.
    for index, name in enumerate(DOCS_ONLY_FILES):
        _edit(repo, name, f"# reworded prose, revision {index}\n")
    head = _commit(repo, "prose only: dissertation, ADR and plan reworded")

    # The digest is unmoved, and the freeze still holds: HEAD has moved, the instrument has not.
    assert instrument_digest(repo) == before
    assert _git(repo, "rev-parse", "HEAD") == head
    assert enforce_freeze(campaign_dir, "v1.0", repo_root=repo) == frozen
    assert read_frozen_commit(campaign_dir) == frozen

    # And a reworded PROTOCOL row is inside the instrument, so it does halt -- the boundary is the
    # `docs/protocols/` pathspec, not `docs/`.
    _edit(repo, "docs/protocols/evaluation-protocol.md", "# a changed number\n")
    _commit(repo, "protocol row changed")
    assert instrument_digest(repo) != before
    with pytest.raises(FreezeError, match="instrument moved after the freeze"):
        enforce_freeze(campaign_dir, "v1.0", repo_root=repo)


def test_instrument_edit_halts(repo: Path, tmp_path: Path) -> None:
    """A committed change inside the instrument paths stops the run, with the digest as evidence."""
    campaign_dir = tmp_path / "runs" / "CAMP-20260926-campaign-v2"
    before = instrument_digest(repo)
    enforce_freeze(campaign_dir, "v1.0", repo_root=repo)

    _edit(repo, "runner/freeze.py", "# the instrument moved\n")
    _commit(repo, "an instrument edit")

    assert instrument_digest(repo) != before
    with pytest.raises(FreezeError, match="instrument moved after the freeze"):
        enforce_freeze(campaign_dir, "v1.0", repo_root=repo)

    # Restoring the frozen bytes restores the freeze, which is what makes the failure actionable
    # rather than terminal. Checked out FROM THE TAG, not from HEAD, and committed: HEAD is the
    # commit that carries the change, so restoring the working-tree file alone would leave the tree
    # clean and the instrument still moved.
    _git(repo, "checkout", "--quiet", "v1.0", "--", "runner/freeze.py")
    _commit(repo, "restore the instrument")
    assert instrument_digest(repo) == before
    assert enforce_freeze(campaign_dir, "v1.0", repo_root=repo) == read_frozen_commit(campaign_dir)


def test_frozen_commit_sidecar_cross_checked(repo: Path, tmp_path: Path) -> None:
    """The sidecar is written once and re-checked on every later invocation, tag moves included.

    The sidecar exists because a tracked file cannot carry its own commit's hash (ADR-136):
    ``campaign.json`` is committed in the very commit ``v2.0`` names. The interesting case is a
    MOVED
    tag whose target has the same instrument digest -- a reworded doc re-tagged -- because the
    digest
    comparison passes and only the sidecar can catch it. v1's tag moved on 2026-09-23 and nothing
    noticed.
    """
    campaign_dir = tmp_path / "runs" / "CAMP-20260926-campaign-v2"
    assert read_frozen_commit(campaign_dir) is None
    sidecar = campaign_dir / FROZEN_COMMIT_SIDECAR

    frozen = enforce_freeze(campaign_dir, "v1.0", repo_root=repo)
    assert sidecar.is_file()
    assert read_frozen_commit(campaign_dir) == frozen
    assert frozen == _git(repo, "rev-parse", "refs/tags/v1.0^{commit}")

    # Re-checking is a no-op while nothing has moved.
    assert enforce_freeze(campaign_dir, "v1.0", repo_root=repo) == frozen

    # A prose-only commit keeps the digest identical and still does not trip the freeze.
    _edit(repo, "docs/notes.md", "# reworded\n")
    docs_commit = _commit(repo, "prose only")
    assert enforce_freeze(campaign_dir, "v1.0", repo_root=repo) == frozen

    # Now move the tag onto that commit: the instrument digest is unchanged, so only the sidecar's
    # cross-check can see it.
    _git(repo, "tag", "-f", "-a", "v1.0", docs_commit, "-m", "moved freeze")
    assert resolve_tag_commit("v1.0", repo) == docs_commit
    assert instrument_digest(repo, rev=docs_commit) == instrument_digest(repo)
    with pytest.raises(FreezeError, match="may not resume onto a different instrument"):
        enforce_freeze(campaign_dir, "v1.0", repo_root=repo)


def test_pilot_refuses_dirty_instrument(repo: Path, tmp_path: Path) -> None:
    """The pilot's entry point refuses a dirty instrument through the same freeze (ADR-136).

    Not a separate check: :func:`runner.pilot_cli.record_stage` calls
    :func:`runner.freeze.enforce_freeze` with its own default, so "the ladder is frozen" and "the
    campaign is frozen" are the same code. The assertion is that an UNCOMMITTED instrument change --
    the case an operator actually creates by editing a file mid-ladder -- is refused at the ladder,
    and that nothing was written, so the refusal leaves no half-recorded state behind.
    """
    state_dir = tmp_path / "pilot-state"
    _edit(repo, "runner/freeze.py", "# edited mid-ladder, uncommitted\n")
    assert instrument_dirty_paths(repo) == ("runner/freeze.py",)
    assert not instrument_clean(repo)

    with pytest.raises(FreezeError, match="uncommitted changes"):
        record_stage(state_dir, "p0", repo_root=repo, campaign_dir=tmp_path / "runs" / "pilot")

    assert not (state_dir / "ladder_state.json").exists()

    # Committing it does not help either -- the instrument has still moved off the freeze -- and
    # with no tag the comparison degenerates to HEAD, so the refusal comes from the digest pair
    # only once a tag exists. With the tag, the message names the moved instrument.
    _commit(repo, "the same edit, committed")
    with pytest.raises(FreezeError, match="instrument moved after the freeze"):
        record_stage(
            state_dir,
            "p0",
            freeze_tag="v1.0",
            repo_root=repo,
            campaign_dir=tmp_path / "runs" / "pilot",
        )

    # Reverted, the same call succeeds -- and the ladder records against the frozen instrument.
    _git(repo, "checkout", "--quiet", "v1.0", "--", "runner/freeze.py")
    _commit(repo, "revert the instrument edit")
    state = record_stage(
        state_dir, "p0", freeze_tag="v1.0", repo_root=repo, campaign_dir=tmp_path / "runs" / "pilot"
    )
    assert state.completed == ("p0",)
    assert state.frozen_commit == read_frozen_commit(tmp_path / "runs" / "pilot")


# ================================================================================================
# THE GUARDS THAT KEEP THE TRANSCRIPTION AND THE MECHANICS HONEST
# ================================================================================================


def test_the_instrument_path_set_is_exactly_p6s_set() -> None:
    """P6's sentence, transcribed once. A guard, not documentation: a silent omission is a hole.

    M10-implementation-plan.md §0: "The *instrument* is the content of ``agents/ guardian/ monitor/
    runner/ scenarios/ analysis/ infra/ scripts/ docs/protocols/ Makefile pyproject.toml``". The set
    is compared as a SET, so order is free but membership is not, and the count is asserted too
    because a duplicate that satisfies the set comparison would otherwise slip through.
    """
    assert len(INSTRUMENT_PATHS) == len(set(INSTRUMENT_PATHS))
    assert set(INSTRUMENT_PATHS) == {
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
    }
    # The directories carry a trailing slash so each is a git pathspec for a subtree. Without it
    # `docs/protocols` would be read as a single file name and the whole protocols directory would
    # silently fall outside the instrument.
    directories = [path for path in INSTRUMENT_PATHS if not path.endswith(".toml") and "/" in path]
    files = [path for path in INSTRUMENT_PATHS if path not in directories]
    assert files == ["Makefile", "pyproject.toml"]
    assert all(path.endswith("/") for path in directories)
    assert len(directories) + len(files) == len(INSTRUMENT_PATHS)


def test_the_digest_is_reproducible_and_ignores_the_working_directory(repo: Path) -> None:
    """Same tree, same digest; a dirty working directory does not perturb it.

    The first half is reproducibility (iron rule 3). The second is a design property with teeth: the
    digest is taken over git OBJECTS, so a modified-but-uncommitted file does not move it -- which
    is
    why :func:`enforce_freeze` needs the separate cleanliness check, and why the two are not
    redundant.
    """
    first = instrument_digest(repo)
    assert first == instrument_digest(repo)
    assert len(first) == 64 and set(first) <= set("0123456789abcdef")

    _edit(repo, "runner/freeze.py", "# not committed\n")
    assert instrument_digest(repo) == first
    assert instrument_dirty_paths(repo) == ("runner/freeze.py",)
    _git(repo, "checkout", "--quiet", "--", "runner/freeze.py")
    assert instrument_digest(repo) == first


def test_an_untracked_instrument_file_is_caught(repo: Path) -> None:
    """An untracked file inside an instrument path is an instrument change no digest can see.

    ``git ls-tree`` reads commits, so an untracked file is in none of them and the digest is
    unchanged -- yet the next cell's ``import runner.freeze`` would find it. This is the case that
    makes the cleanliness check load-bearing rather than decorative.
    """
    before = instrument_digest(repo)
    (repo / "runner" / "sneaky.py").write_text("# untracked\n", encoding="utf-8")
    assert instrument_digest(repo) == before
    assert instrument_dirty_paths(repo) == ("runner/sneaky.py",)
    assert not instrument_clean(repo)


def test_an_untracked_file_outside_the_instrument_is_not_caught(repo: Path) -> None:
    """The mirror image: scratch space under ``docs/`` must not stop a campaign either.

    Without this, "a docs-only edit does not halt" would be true only for a COMMITTED docs edit, and
    the untracked scratch file that motivated P6 would still halt every run.
    """
    (repo / "docs" / "scratch.md").write_text("# notes to self\n", encoding="utf-8")
    assert instrument_dirty_paths(repo) == ()
    assert instrument_clean(repo)


def test_no_tag_still_freezes_on_head_and_the_sidecar(repo: Path, tmp_path: Path) -> None:
    """The pre-freeze path: HEAD is the reference, so the pilot is frozen long before ``v2.0``.

    The ladder runs P0 through P3 before any tag exists, and a ladder with no freeze is not a
    ladder. With ``freeze_tag=None`` the digest comparison degenerates to "HEAD equals HEAD" and the
    cleanliness and sidecar checks carry the whole gate.
    """
    campaign_dir = tmp_path / "runs" / "CAMP-20260926-pilot-p2"
    head = _git(repo, "rev-parse", "HEAD")
    assert enforce_freeze(campaign_dir, repo_root=repo) == head
    assert read_frozen_commit(campaign_dir) == head

    # A commit with no tag is accepted once it is the frozen one only if the sidecar agrees -- which
    # it does not, so the ladder must be restarted rather than silently rebased onto new bytes.
    _edit(repo, "scenarios/manifests/SCN-SIM-01.yaml", "# changed\n")
    _commit(repo, "a commit after the sidecar was written")
    with pytest.raises(FreezeError, match="may not resume onto a different instrument"):
        enforce_freeze(campaign_dir, repo_root=repo)


def test_a_bad_tag_name_is_refused_with_a_freeze_error(repo: Path) -> None:
    """An unresolvable or option-shaped tag raises :class:`FreezeError`, never a git traceback.

    ``freeze_tag`` reaches a command line, so the one caller-supplied value in this module is
    checked rather than trusted: an empty name, or one beginning with ``-`` (which git would read as
    an option), is refused before any subprocess runs.
    """
    for bad in ("", "-q", "--upload-pack=touch /tmp/pwned"):
        with pytest.raises(FreezeError, match="is not a tag name"):
            resolve_tag_commit(bad, repo)
    with pytest.raises(FreezeError, match="is not a tag name"):
        enforce_freeze(repo / "runs" / "x", "--upload-pack=touch /tmp/pwned", repo_root=repo)


def test_enforce_freeze_can_resolve_without_writing_the_sidecar(repo: Path, tmp_path: Path) -> None:
    """The read-only mode exists for the campaign's per-cell drift check (ADR-136's "offline
    self-test").

    ``write_sidecar=False`` answers "is the instrument still the frozen one?" without touching the
    campaign directory, which is what a caller wants on every cell of an existing campaign and what
    an offline self-test on a dirty dev tree needs in order not to litter ``runs/``.
    """
    campaign_dir = tmp_path / "runs" / "CAMP-20260926-campaign-v2"
    enforce_freeze(campaign_dir, "v1.0", repo_root=repo)
    sidecar = campaign_dir / FROZEN_COMMIT_SIDECAR
    sidecar.unlink()
    assert enforce_freeze(campaign_dir, "v1.0", repo_root=repo, write_sidecar=False)
    assert not sidecar.exists()
    assert read_frozen_commit(campaign_dir) is None


# ================================================================================================
# THE TRACKED SIDE OF THE FREEZE: CampaignManifest.freeze_tag (ADR-136, M10 plan §7)
# ================================================================================================


def test_the_campaign_manifest_round_trips_its_freeze_tag() -> None:
    """``freeze_tag`` survives a canonical-bytes round trip, and a null one is written explicitly.

    ADR-136: the TRACKED campaign manifest carries only the tag NAME, because a tracked file cannot
    carry its own commit's hash. The name therefore has to survive serialisation exactly, because
    ``execute_campaign`` compares ``campaign.json`` byte for byte on resume and refuses if the
    frozen document differs -- so a tag that round-tripped lossily would make every campaign
    un-resumable on its second invocation.
    """
    manifest = build_campaign_manifest("CAMP-20260926-campaign-v2")
    assert manifest.freeze_tag is None  # nothing tagged yet
    frozen = replace(manifest, freeze_tag="v2.0")

    payload = frozen.to_dict()
    assert payload["freeze_tag"] == "v2.0"
    assert from_dict(payload) == frozen
    # Byte identity is the real requirement, and it is the same canonical form execute_campaign
    # writes into runs/<CAMP>/campaign.json.
    assert to_canonical_bytes(from_dict(payload)) == to_canonical_bytes(frozen)

    # A manifest predating the field still loads, with the field absent meaning None: the four
    # tracked runner/CAMP-*.json files are exactly that case and are not edited by this change.
    legacy = {key: value for key, value in payload.items() if key != "freeze_tag"}
    assert from_dict(legacy).freeze_tag is None

    # And the key set is still exact: an unknown key is a malformed manifest, not a state with
    # defaults.
    with pytest.raises(CampaignError, match="do not match"):
        from_dict({**payload, "frozen_commit": "c" * 40})
