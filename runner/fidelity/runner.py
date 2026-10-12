r"""The runner's own fidelity checks: F-RN-01 (per-call accounting) and F-RN-02 (one instrument).

WHY THESE TWO LIVE IN THE FIDELITY PACKAGE AND NOT IN ``runner/bundle.py``
-------------------------------------------------------------------------
``F-RN-01`` is about **reporting**, not about the seal's structural completeness. ``seal_bundle``
already refuses a ``messages.jsonl`` line with no non-negative integer ``index`` (that is
``_indexed_records``), and ``_verify_llm_call_accounting`` already reconciles messages against
``tokens.json``. So why is there a check at all? Because the seal raising means the bundle did not
exist, and the M10 requirement is different: the gate must be able to say *how many* attempts were
mis-accounted, and the v1 corpus has 40 of them sitting in directories that DID seal
(defect V13: ``RUN-G0-FULL-SCN-SIM-02-INJ-D-102`` needed 9 attempts). A check over bundle files
reports over the sealed corpus whether or not the sealer is still the version that would have
refused; that is the whole reason a registry that reads artefacts exists alongside a sealer that
refuses artefacts.

``F-RN-02`` is the one class-R check in this module and it is a CORPUS check, not a bundle check.
The
plan states it at stage ``campaign`` for exactly that reason: "one instrument digest across the
corpus, equal to the freeze tag's; every ``git_commit`` differs from the tag only outside the
instrument paths". A single bundle cannot answer it -- one bundle's digest says nothing about
whether
it is the same digest as the next one's -- so the predicate reads the campaign directory, which
:class:`~runner.fidelity.BundleView` exposes through ``campaign_dir``.

WHY THE DIGEST IS THE PRIMARY EVIDENCE AND ``git_commit`` THE SECONDARY
---------------------------------------------------------------------
v1's defect V14 was "mixed commits; freeze bypassed": 40 of 150 (arm, scenario, injection) groups
and
15 of 125 (scenario, injection, seed) cells span more than one commit. The commit alone could not
settle it, because a commit is not the instrument -- a commit outside the instrument paths (a
reworded ADR, a dissertation paragraph) changes the commit and changes nothing about what a run
does.
The instrument digest is taken over the P6 path set precisely so that the two cases are
distinguishable, and the reason code is ``mixed-instrument`` for the digest disagreeing and the
commit differing *inside* the path set, which ``runner/validate.py`` also raises.

The freeze tag's own digest is read from git (a read; the runner never writes a ref -- ADR-136), and
its ABSENCE is a ``skip`` with the detail naming the tag rather than a pass: a corpus checked before
``v2.0`` exists cannot have a tag digest to compare against, and reporting a pass there would be
claiming a check that did not happen.
"""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Final

from runner.fidelity import (
    STAGE_CAMPAIGN,
    STAGE_SEAL,
    BundleView,
    CheckOutcome,
    FidelityCheck,
)

__all__ = ("CHECKS", "reset_corpus_scan_cache")


@functools.lru_cache(maxsize=8)
def _corpus_instrument_scan(
    root_str: str,
) -> tuple[tuple[tuple[str, tuple[str, ...]], ...], tuple[str, ...], tuple[tuple[str, str], ...]]:
    """The (digests, undigested, commits) of every bundle under a campaign root, computed ONCE.

    F-RN-02 is a corpus check but the fidelity registry evaluates it per bundle (once for each
    bundle in the corpus, at the campaign stage), and its body reads every sibling manifest -- so a
    naive implementation reads N manifests N times, which is O(N**2) and turns a known-bad replay
    over the ~800-directory v1 corpus into an hour of manifest parsing. The scan depends only on the
    corpus root and the manifests on disk, both immutable across one evaluation pass, so it is
    memoised by resolved root path: the first bundle pays the scan and the remaining N-1 read the
    cached result. Returned as nested tuples so the value is hashable and cannot be mutated by a
    caller. A process that evaluates a corpus, mutates it and re-evaluates the SAME path must call
    :func:`reset_corpus_scan_cache` between passes; the replay and the campaign never mutate a
    corpus mid-pass, and the tests that do use a fresh temporary path per case.
    """
    root = Path(root_str)
    digests: dict[str, list[str]] = {}
    undigested: list[str] = []
    commits: dict[str, str] = {}
    for bundle_dir in BundleView(bundle_dir=root, campaign_dir=root).sibling_bundles():
        payload = BundleView(bundle_dir=bundle_dir, campaign_dir=root).manifest()
        run_id = str(payload.get("run_id") or bundle_dir.name)
        commits[run_id] = str(payload.get("git_commit") or "")
        digest = payload.get("instrument_digest")
        if isinstance(digest, str) and digest:
            digests.setdefault(digest, []).append(run_id)
        else:
            undigested.append(run_id)
    return (
        tuple((digest, tuple(run_ids)) for digest, run_ids in digests.items()),
        tuple(undigested),
        tuple(commits.items()),
    )


def reset_corpus_scan_cache() -> None:
    """Drop the memoised corpus scan. Call between passes that mutate a corpus at the same path."""
    _corpus_instrument_scan.cache_clear()


# The `RunnerOwner` label is not used for dispatch (each module names its own) but it is the word a
# reader of `fidelity.json` and of the ledger needs: "F-RN" means the runner's own files.
_OWNER: Final = "runner"


def _accounting_issues(view: BundleView) -> list[str]:
    """Every ``messages.jsonl`` entry that is not an indexed record matched in ``tokens.json``.

    Shared by F-RN-01 and by the known-bad replay, which needs the same list to build a bundle that
    reproduces V13 without re-deriving the predicate.
    """
    messages = view.messages()
    if not view.present("messages.jsonl"):
        return []
    token_indexes: set[int] = set()
    for entry in view.tokens():
        index = entry.get("index")
        if isinstance(index, int) and not isinstance(index, bool) and index >= 0:
            token_indexes.add(index)
    issues: list[str] = []
    for position, record in enumerate(messages, start=1):
        index = record.get("index")
        if not isinstance(index, int) or isinstance(index, bool) or index < 0:
            # The v1 shape exactly: a bare {"error": ...} dict appended with no index, which is what
            # `seal_bundle` refuses with "no non-negative integer 'index'" (V13).
            issues.append(
                f"messages.jsonl line {position} carries no non-negative integer 'index'"
                + (f" (record keys: {sorted(record)})" if record else "")
            )
            continue
        if index not in token_indexes:
            issues.append(
                f"messages.jsonl line {position} has index {index}, which no tokens.json entry "
                "matches; an unaccounted model call is a call whose cost and model cannot be read"
            )
    return issues


def f_rn_01_every_call_is_indexed_and_matched(view: BundleView) -> CheckOutcome:
    """Every ``messages.jsonl`` entry, failure records included, carries an index matched in
    ``tokens.json``.

    A baseline has no model calls at all, so the check is ``skip`` there rather than a pass over an
    empty list: a vacuous pass would make the summary count baseline bundles toward a check about
    model calls.
    """
    if view.is_baseline() or not view.present("messages.jsonl"):
        if view.is_baseline():
            return CheckOutcome.skipped(
                "baseline: no model calls, so no per-call accounting to check"
            )
        return CheckOutcome.skipped(
            "messages.jsonl is absent; the completeness profile refuses this"
        )
    issues = _accounting_issues(view)
    if issues:
        return CheckOutcome.failed(
            f"{len(issues)} of {len(view.messages())} recorded call(s) are not indexed and "
            "matched: "
            f"{issues[0]}" + (f"; and {len(issues) - 1} more" if len(issues) > 1 else "")
        )
    return CheckOutcome.passed(f"{len(view.messages())} call(s) indexed and matched in tokens.json")


def _freeze_tag_digest(freeze_tag: str) -> str | None:
    """The instrument digest at ``freeze_tag``, or ``None`` when it cannot be read.

    A read of a git ref, from ``runner/freeze.py`` (Part A's module -- the single implementation of
    the
    P6 path set and the digest, which this package must not restate). An unresolvable tag is
    ``None``
    rather than an exception: an unfrozen corpus is the normal state of a pilot, and the check
    reports
    "no tag to compare against" rather than crashing the replay.
    """
    try:
        from runner.freeze import instrument_digest, resolve_tag_commit
    except ImportError:
        return None
    try:
        return instrument_digest(rev=resolve_tag_commit(freeze_tag))
    except Exception:  # noqa: BLE001 - a missing tag is a fact, not a crash
        return None


def f_rn_02_one_instrument_across_the_corpus(view: BundleView) -> CheckOutcome:
    """One instrument digest across the corpus, equal to the freeze tag's; every ``git_commit``
    differs from the tag only outside the instrument paths.

    Three findings, in the order they matter:

    1. **more than one digest** -- two instrument states produced this corpus, so at least one
       contrast is between two instruments. This is the V14 defect, and it is unfixable after the
       fact: a rerun does not repair a mixed corpus, it replaces it.
    2. **no digest recorded at all** -- a v1 corpus, or a v2 bundle whose manifest predates the M10
       fields. A ``skip``, because a corpus with no digest is the documented pre-remediation state.
    3. **a digest that differs from the tag's** -- the instrument moved after the freeze.

    A bundle whose own recorded ``git_commit`` differs from the campaign's ``frozen_commit.txt`` is
    reported as a finding *in its own right* even when the digest agrees, because the two
    disagreeing
    is itself the fact the check exists to surface: it means the digest was taken over a tree that
    does not match the commit the bundle claims.
    """
    if view.campaign_dir is None:
        return CheckOutcome.skipped(
            "no campaign directory in scope; F-RN-02 is a corpus check (stage campaign)"
        )
    root = view.campaign_dir
    scanned_digests, scanned_undigested, scanned_commits = _corpus_instrument_scan(
        str(Path(root).resolve())
    )
    digests: dict[str, list[str]] = {digest: list(run_ids) for digest, run_ids in scanned_digests}
    undigested: list[str] = list(scanned_undigested)
    commits: dict[str, str] = dict(scanned_commits)
    if not digests:
        # producer-pending, not a plain skip: the instrument that writes the digest is what has not
        # run over this corpus, so the known-bad replay reports it as producer-pending rather than
        # MISSING (ADR-146).
        return CheckOutcome.producer_pending(
            f"no bundle under {root} records an instrument_digest; this is a pre-remediation "
            f"corpus ({len(undigested)} bundle(s) carry none) and F-RN-02 has nothing to compare"
        )
    if len(digests) > 1:
        parts = ", ".join(
            f"{digest[:12]} x{len(run_ids)}" for digest, run_ids in sorted(digests.items())
        )
        return CheckOutcome.failed(
            f"the corpus carries {len(digests)} distinct instrument digests ({parts}); a contrast "
            "drawn across them is a contrast between two instruments, which no rerun repairs "
            "(M10 defect V14, P6)"
        )

    digest = next(iter(digests))
    campaign = view.campaign_document()
    freeze_tag = campaign.get("freeze_tag")
    findings: list[str] = []
    if isinstance(freeze_tag, str) and freeze_tag:
        tag_digest = _freeze_tag_digest(freeze_tag)
        if tag_digest is None:
            findings.append(
                f"freeze tag {freeze_tag!r} does not resolve to a readable instrument digest, so "
                "the corpus could not be compared against the frozen instrument"
            )
        elif tag_digest != digest:
            findings.append(
                f"the corpus digest {digest[:12]} is not the digest at freeze tag {freeze_tag!r} "
                f"({tag_digest[:12]}); the instrument moved after the freeze (P6, ADR-136)"
            )
    # The commit cross-check. `frozen_commit.txt` is the runtime sidecar ADR-136 names; a corpus
    # with
    # no sidecar is a campaign that has not been frozen yet, and the freeze's own machinery (not
    # this
    # check) is what says so.
    sidecar = view.campaign_file("frozen_commit.txt")
    if sidecar is not None:
        frozen = sidecar.read_text(encoding="utf-8").strip()
        if frozen:
            drifted = sorted(run_id for run_id, commit in commits.items() if commit != frozen)
            if drifted:
                findings.append(
                    f"{len(drifted)} bundle(s) record a git_commit other than the campaign's "
                    "frozen "
                    f"commit {frozen[:12]} (e.g. {drifted[0]}); reason code `mixed-instrument`"
                )
    if findings:
        return CheckOutcome.failed("; ".join(findings))
    detail = f"one instrument digest {digest[:12]} across {len(digests[digest])} bundle(s)"
    if isinstance(freeze_tag, str) and freeze_tag:
        detail += f", equal to freeze tag {freeze_tag!r}"
    return CheckOutcome.passed(detail)


CHECKS: Final[tuple[FidelityCheck, ...]] = (
    FidelityCheck(
        id="F-RN-01",
        owner=_OWNER,
        klass={"seal": "T"},
        stage=(STAGE_SEAL,),
        summary=(
            "every messages.jsonl entry, failure records included, carries an index matched in "
            "tokens.json"
        ),
        predicate=f_rn_01_every_call_is_indexed_and_matched,
        known_bad="flags the 40 index-defect attempts",
    ),
    FidelityCheck(
        id="F-RN-02",
        owner=_OWNER,
        klass={"campaign": "R"},
        stage=(STAGE_CAMPAIGN,),
        summary=(
            "one instrument digest across the corpus, equal to the freeze tag's; every git_commit "
            "differs from the tag only outside the instrument paths"
        ),
        predicate=f_rn_02_one_instrument_across_the_corpus,
        known_bad="flags three instrument states",
    ),
)
