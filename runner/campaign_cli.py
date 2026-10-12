r"""``make campaign`` (T6.4/B3): validate the grid, order it, and gate the start on the preflight.

WHAT THIS DOES BEFORE IT STARTS ANYTHING
------------------------------------------
A campaign is the dissertation's evidence, and M6 ends at ``v1.0-rc`` after which behaviour freezes,
so ``make campaign`` refuses to start unless five things hold. Four are gates the milestone's
Scope line names -- ``make status`` green (a healthy environment; evaluation-protocol §5 rule 1),
``make parity-check`` (M4), and ``make determinism-check`` (M2's Monitor half and M5's scenario
half). The fifth is the **synthetic-proof gate** (ADR-042): the analysis was proven to regenerate
every table and figure from raw bundles *before* any real run, and the proof's recorded commit must
match the tree about to produce real data. Changing the analysis after real runs exist then requires
re-running the synthetic proof, which is the pre-registration discipline T6.6 exists for.

The proof gate is a preflight, not an ordering convention: an ordering convention is a thing a tired
person reorders at 2am, and a preflight gate is not.

WHAT IT PRODUCES
------------------
The validated campaign manifest (``runner.validate.validate_campaign_manifest``) and the interleaved
run order (``runner.order.generate_order``), and -- at Tier B, or offline for a proof -- it drives
each run in that order through ``runner.run`` / ``runner.baseline``. The order is regenerated, never
patched, so a reduction lever or a validity rerun re-derives the whole thing.

WHAT BREAKS IF THIS FILE CHANGES
---------------------------------
``make campaign`` and its preflight. ADR-041 (order), ADR-042 (the synthetic-proof gate).
"""

import argparse
import json
import multiprocessing
import os
import subprocess
import sys
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from contextlib import nullcontext
from dataclasses import dataclass, replace
from pathlib import Path
from queue import Empty
from typing import Final, Protocol

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from runner import freeze  # noqa: E402
from runner.campaign import CampaignManifest, PlannedRun, from_dict  # noqa: E402
from runner.campaign import to_canonical_bytes as campaign_to_canonical_bytes  # noqa: E402
from runner.fidelity import read_fidelity, resolve_optional  # noqa: E402
from runner.ids import (  # noqa: E402
    BaselineId,
    RunId,
    format_baseline_id,
    format_run_id,
    parse_baseline_id,
    parse_run_id,
)
from runner.order import generate_order  # noqa: E402
from runner.run_lock import ClusterLeaseError, RunLockHeld, campaign_cluster_lease  # noqa: E402
from runner.validate import ValidationError, validate_campaign_manifest  # noqa: E402

__all__ = (
    "AttemptResult",
    "CampaignExecution",
    "CampaignHaltError",
    "CampaignRunError",
    "PreflightError",
    "classify_failure",
    "execute_campaign",
    "preflight",
    "resume_order",
    "run_campaign",
)

_PREFLIGHT_TARGETS = ("status", "parity-check", "determinism-check")

# The campaign-directory sidecars this module owns beside `campaign.json` and the freeze's
# `frozen_commit.txt`. Each is small, canonical JSON (or the halt marker) and survives reinvocation,
# which is the whole point: the lifetime attempt counter (V15's fix), the campaign's first-seen
# answered model (ADR-123), the once-only checkpoint flag (F-AN-01), and the terminal halt marker
# (ADR-120). They are files, not bundle directories, so `_attempt_ids`, the resume glob and every
# corpus reader skip them by construction.
_HALTED_SIDECAR: Final = "HALTED.json"
_ATTEMPTS_SIDECAR: Final = "attempts.json"
_ANSWERED_MODEL_SIDECAR: Final = "answered_model.json"
_CHECKPOINT_SIDECAR: Final = "checkpoint.json"

# classify_failure's marker vocabulary. An INSTRUMENT failure is a deterministic defect the
# framework produced that a rerun on the SAME instrument cannot fix (ADR-120), so it halts. A
# DELIVERY-MISS is a transient injection landing failure that D5 reruns on the same instrument. And
# everything else -- a timeout, a provider hiccup, a crashed run leaving an incomplete bundle -- is
# INFRA and reruns. The default is infra, deliberately: the lifetime attempt cap bounds a genuinely
# stuck cell, and halting on an unclassified transient is exactly the V15 defect.
_DELIVERY_MISS_MARKERS: Final = ("delivery-miss", "delivery miss", "did not land", "not delivered")
# `non-negative integer 'index'` is v1 defect V13 verbatim (`agents/golden.py` appended a failure
# record with no index); a bundle that fails to seal on it every time is an instrument bug, not a
# flake. The bare token `instrument` lets a caller (or a probe seal) name one explicitly.
_INSTRUMENT_MARKERS: Final = ("non-negative integer 'index'", "instrument")


class CampaignRunError(Exception):
    """The campaign manifest is invalid or cannot be ordered."""


class CampaignHaltError(CampaignRunError):
    """A treatment-fidelity, answered-model, instrument, lifetime-cap or checkpoint HALT (ADR-120).

    Distinct from an invalid attempt, which is quarantined and rerun: a halt is terminal. The
    campaign writes ``HALTED.json`` and stops, and a reinvocation refuses to resume until the
    operator addresses the cause (a fixed instrument is a new digest the freeze then sees). It
    subclasses :class:`CampaignRunError` so the CLI's error handler and any existing
    ``except CampaignRunError`` still catch it, while a caller that must tell a halt from a
    rerunnable failure can catch this type alone.
    """


class PreflightError(Exception):
    """A preflight gate failed; the campaign refuses to start."""


class DriverOutcome(Protocol):
    """The common result surface exposed by run and baseline adapters."""

    run_id: str
    sealed: bool
    detail: str


CampaignDriver = Callable[[PlannedRun, str | None], DriverOutcome]


@dataclass(frozen=True)
class _Outcome:
    run_id: str
    sealed: bool
    detail: str


@dataclass(frozen=True)
class _DefaultDriver:
    """Pickle-safe adapter used by the CLI and therefore safe to isolate in a process."""

    campaign_id: str
    out_root: Path
    offline: bool
    window: object | None
    baseline: bool
    pilot: tuple[str, CampaignManifest] | None = None

    def __call__(self, planned: PlannedRun, rerun_of: str | None) -> DriverOutcome:
        if self.baseline:
            from runner.baseline import run_planned_baseline

            return run_planned_baseline(
                planned,
                campaign_id=self.campaign_id,
                out_root=self.out_root,
                offline=self.offline,
                skip_preflight=True,
                rerun_of=rerun_of,
                window=self.window,  # type: ignore[arg-type]
            )
        from runner.run import run_planned

        return run_planned(
            planned,
            campaign_id=self.campaign_id,
            out_root=self.out_root,
            offline=self.offline,
            skip_preflight=True,
            rerun_of=rerun_of,
            window=self.window,  # type: ignore[arg-type]
            pilot=self.pilot,
        )


@dataclass(frozen=True)
class AttemptResult:
    run_id: str
    cell_id: str
    sealed: bool
    invalid: bool
    detail: str
    rerun_of: str | None = None


@dataclass(frozen=True)
class CampaignExecution:
    campaign_id: str
    attempted: tuple[AttemptResult, ...]
    skipped: tuple[str, ...]

    @property
    def complete(self) -> bool:
        latest: dict[str, AttemptResult] = {}
        for result in self.attempted:
            latest[result.cell_id] = result
        return all(result.sealed for result in latest.values())

    @property
    def flake_count(self) -> int:
        """Invalid retained attempts whose cell eventually completed successfully."""
        completed_cells = {result.cell_id for result in self.attempted if result.sealed}
        return sum(
            result.invalid and result.cell_id in completed_cells for result in self.attempted
        )


def _make(target: str) -> bool:
    result = subprocess.run(  # noqa: S603 - argv fixed, no shell
        ["make", target],  # noqa: S607 - make is on PATH by design
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0


def _synthetic_proof_ok() -> tuple[bool, str]:
    """Whether the proof's commit and tracked source digest match the current tree content.

    Imported lazily from ``analysis`` so the runner does not hard-depend on the analysis package at
    import time; a missing analysis package or a missing proof both fail the gate closed, which is
    correct -- no proof means no campaign.
    """
    try:
        from analysis.render import proof_matches_tree
    except ImportError as error:
        return False, f"synthetic-proof gate unavailable ({error}); analysis/ must be present"
    proof_path = REPO_ROOT / "analysis" / ".synthetic-proof.json"
    if not proof_path.is_file():
        return False, (
            "no analysis/.synthetic-proof.json; run `make analyze` over a synthetic corpus "
            "first so the analysis is pre-registered before any real run (ADR-042)"
        )
    if not proof_matches_tree(proof_path):
        return False, (
            "the synthetic proof does not match the current commit and tracked analysis/runner/"
            "protocol content; source changed since it was proven; re-run `make analyze` over the "
            "synthetic corpus (ADR-042)"
        )
    return True, "synthetic proof current"


def preflight(*, skip_proof: bool = False) -> None:
    """Run every preflight gate. Raises :class:`PreflightError` on the first that fails.

    ``skip_proof`` exists for the offline self-test only; the real campaign never skips it.
    """
    for target in _PREFLIGHT_TARGETS:
        if not _make(target):
            raise PreflightError(f"preflight `make {target}` failed; the campaign refuses to start")
    if not skip_proof:
        ok, detail = _synthetic_proof_ok()
        if not ok:
            raise PreflightError(detail)


def run_campaign(
    manifest_path: Path,
    campaign_seed: int,
    *,
    skip_preflight: bool = False,
    pilot_kind: str | None = None,
) -> tuple[str, ...]:
    """Validate the manifest, run the preflight, and return the interleaved run order.

    Driving the runs is Tier B (each needs the cluster). This returns the order the driver walks,
    which is the deterministic, both-axes-interleaved sequence T-24 covers, so the order itself is
    produced and checkable now.
    """
    payload = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    manifest = from_dict(payload)
    if campaign_seed != manifest.campaign_seed:
        raise CampaignRunError(
            f"campaign seed {campaign_seed} does not match frozen manifest seed "
            f"{manifest.campaign_seed}"
        )
    try:
        if pilot_kind is None:
            validate_campaign_manifest(manifest)
        else:
            _validate_pilot(manifest, pilot_kind)
    except ValidationError as error:
        raise CampaignRunError(f"campaign manifest invalid: {error}") from None
    if not skip_preflight:
        preflight()
    return (
        generate_order(manifest, campaign_seed) if pilot_kind is None else manifest.generated_order
    )


def _validate_pilot(manifest: CampaignManifest, kind: str) -> None:
    from runner import validate as validation
    from runner.pilot_cli import PILOT_VALIDATORS

    if kind not in PILOT_VALIDATORS:
        raise CampaignRunError(f"unknown pilot kind {kind!r}")
    getattr(validation, PILOT_VALIDATORS[kind])(manifest)
    if manifest.generated_order != tuple(run.run_id for run in manifest.runs):
        raise CampaignRunError("pilot order must list each planned run exactly once")


def _attempt_ids(cell_id: str, campaign_dir: Path) -> tuple[str, ...]:
    """Return existing attempts for one cell in numeric attempt order."""
    prefix = f"{cell_id}-R"
    attempts = [cell_id]
    numbered: list[tuple[int, str]] = []
    for child in Path(campaign_dir).glob(f"{cell_id}-R*"):
        if not child.is_dir() or not child.name.startswith(prefix):
            continue
        try:
            parsed = (
                parse_baseline_id(child.name)
                if cell_id.startswith("BASE-")
                else parse_run_id(child.name)
            )
        except Exception as error:  # malformed lookalikes are not campaign attempts
            if child.name.startswith(prefix):
                raise CampaignRunError(
                    f"malformed attempt directory {child.name!r}: {error}"
                ) from error
            continue
        if parsed.attempt is not None:
            numbered.append((parsed.attempt, child.name))
    return tuple([*attempts, *(name for _, name in sorted(numbered))])


def _attempt_defects(bundle_dir: Path) -> list[str]:
    """Return seal or section-4 validity defects for one candidate attempt."""
    from runner.bundle import verify_bundle_seal

    defects = verify_bundle_seal(bundle_dir)
    if defects:
        return defects
    try:
        payload = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
        from runner.manifest import from_dict as manifest_from_dict
        from runner.validity import check_run_validity, measurement_window_samples

        manifest = manifest_from_dict(payload)
        return [
            f"{finding.code}: {finding.detail}"
            for finding in check_run_validity(
                bundle_dir, manifest, window_samples=measurement_window_samples()
            )
        ]
    except (OSError, ValueError, TypeError) as error:
        return [f"validity inputs unreadable: {error}"]


def _verified_attempt(cell_id: str, campaign_dir: Path) -> str | None:
    for attempt_id in reversed(_attempt_ids(cell_id, campaign_dir)):
        bundle_dir = Path(campaign_dir) / attempt_id
        if (bundle_dir / "invalid.json").is_file():
            continue
        if (bundle_dir / "seal.json").is_file() and not _attempt_defects(bundle_dir):
            return attempt_id
    return None


def resume_order(order: tuple[str, ...], campaign_dir: Path) -> tuple[str, ...]:
    """The runs still to execute: the generated order minus cells with a valid sealed bundle.

    Resume semantics (M7-C8, evaluation-protocol §5.4): a campaign interrupted overnight resumes by
    **regenerating** the order deterministically from the campaign seed -- never replaying a stored
    one -- and skipping the cells that already sealed, then continuing. Regenerating rather than
    replaying keeps the interleaving guarantee T-24 proves intact across an interruption; the order
    is a pure function of the seed, so it is the same order nightly; this function drops the
    cells already done. A cell is "already done" only when its bundle passes the shared seal,
    content-hash, completeness, manifest and anchored-audit verification; a stray or truncated
    ``seal.json`` is retried rather than skipped. This is a pure function of the order and the
    on-disk corpus, so the resume property is checkable offline; the loop that walks the returned
    order and drives each run is the Tier B
    campaign driver, which needs the cluster.
    """
    return tuple(run_id for run_id in order if _verified_attempt(run_id, campaign_dir) is None)


def _next_attempt(planned: PlannedRun, campaign_dir: Path) -> tuple[PlannedRun, str | None]:
    attempts = _attempt_ids(planned.run_id, campaign_dir)
    existing = [attempt_id for attempt_id in attempts if (Path(campaign_dir) / attempt_id).exists()]
    if not existing:
        return planned, None
    predecessor = existing[-1]
    if planned.is_baseline:
        parsed = parse_baseline_id(predecessor)
        number = 2 if parsed.attempt is None else parsed.attempt + 1
        attempt_id = format_baseline_id(
            BaselineId(planned.load_profile_id, planned.seed, attempt=number)
        )
    else:
        parsed = parse_run_id(predecessor)
        number = 2 if parsed.attempt is None else parsed.attempt + 1
        attempt_id = format_run_id(
            RunId(
                planned.condition or "",
                planned.scenario_id or "",
                planned.injection_condition or "",
                planned.seed,
                attempt=number,
            )
        )
    return replace(planned, run_id=attempt_id), predecessor


def _mark_invalid(
    bundle_dir: Path, *, detail: str, timed_out: bool, reason: str | None = None
) -> None:
    """Persist attempt status beside, but never by mutating, the sealed evidence."""
    bundle_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "invalid": True,
        "reason": reason or ("runner-timeout" if timed_out else "execution-or-seal-failure"),
        "detail": detail,
    }
    temporary = bundle_dir / ".invalid.json.tmp"
    temporary.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    temporary.replace(bundle_dir / "invalid.json")


def _driver_process(
    driver: CampaignDriver,
    planned: PlannedRun,
    rerun_of: str | None,
    result_queue: object,
) -> None:
    """Run a default adapter in an isolated child and return only its small outcome surface."""
    try:
        outcome = driver(planned, rerun_of)
        result_queue.put((True, outcome.run_id, outcome.sealed, outcome.detail))  # type: ignore[attr-defined]
    except BaseException as error:  # noqa: BLE001 - child must serialize failures to its parent
        result_queue.put((False, type(error).__name__, str(error)))  # type: ignore[attr-defined]


def _invoke_default_driver(
    driver: CampaignDriver,
    planned: PlannedRun,
    rerun_of: str | None,
    timeout_seconds: float,
) -> DriverOutcome:
    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue()
    process = context.Process(
        target=_driver_process, args=(driver, planned, rerun_of, result_queue), daemon=False
    )
    process.start()
    process.join(timeout_seconds)
    if process.is_alive():
        process.terminate()
        process.join()
        result_queue.close()
        raise TimeoutError(f"attempt exceeded {timeout_seconds:g}s runner timeout")
    try:
        payload = result_queue.get(timeout=1)
    except Empty as error:
        raise CampaignRunError(
            f"driver process exited {process.exitcode} without returning an outcome"
        ) from error
    finally:
        result_queue.close()
    if not payload[0]:
        raise CampaignRunError(f"driver failed: {payload[1]}: {payload[2]}")
    return _Outcome(payload[1], payload[2], payload[3])


def _invoke_driver(
    driver: CampaignDriver,
    planned: PlannedRun,
    rerun_of: str | None,
    timeout_seconds: float | None,
) -> DriverOutcome:
    if timeout_seconds is None:
        return driver(planned, rerun_of)
    if timeout_seconds <= 0:
        raise CampaignRunError("timeout_seconds must be positive")
    if isinstance(driver, _DefaultDriver):
        return _invoke_default_driver(driver, planned, rerun_of, timeout_seconds)

    # Injected test/extension drivers may not be pickleable. Preserve that seam, but require a
    # cooperative cancel() hook when available and always join before returning: a timed-out driver
    # can therefore never remain alive to mutate a bundle after invalid.json has been written.
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(driver, planned, rerun_of)
    try:
        return future.result(timeout=timeout_seconds)
    except FutureTimeoutError as error:
        cancel = getattr(driver, "cancel", None)
        if callable(cancel):
            cancel()
        future.cancel()
        raise TimeoutError(f"attempt exceeded {timeout_seconds:g}s runner timeout") from error
    finally:
        executor.shutdown(wait=True, cancel_futures=True)


def _atomic_write_json(path: Path, payload: object) -> None:
    """Publish canonical JSON to ``path`` via a same-directory temp file and atomic replace.

    The campaign-directory sidecars (attempts, answered model, checkpoint, halt) are written this
    way so a killed process never leaves a half-written counter that a reinvocation would misread.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        temporary.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
        )
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _halted_path(campaign_dir: Path) -> Path:
    return Path(campaign_dir) / _HALTED_SIDECAR


def _write_halted(
    campaign_dir: Path,
    *,
    reason: str,
    detail: str,
    run_id: str | None = None,
    extra: dict[str, object] | None = None,
) -> None:
    """Write the terminal ``HALTED.json`` marker into the campaign directory (ADR-120).

    The one artefact a halt leaves behind, so a reinvocation can see the campaign is halted and why
    without re-deriving it. ``reason`` is a stable machine token (treatment-fidelity,
    answered-model-change, instrument, lifetime-attempt-cap, checkpoint); ``detail`` is the human
    sentence and ``extra`` carries the reason-specific fields (the failing check ids, the two model
    strings) a reader wants beside it.
    """
    payload: dict[str, object] = {"halted": True, "reason": reason, "detail": detail}
    if run_id is not None:
        payload["run_id"] = run_id
    if extra:
        payload.update(extra)
    _atomic_write_json(_halted_path(campaign_dir), payload)


def _sealed_t_failures(bundle_dir: Path) -> list[str]:
    """The class-T fidelity check ids a sealed bundle's ``fidelity.json`` records as failed.

    The single predicate the halt rule reads (ADR-120): a sealed, integrity-sound bundle whose
    ``fidelity.json`` carries a class-T ``fail`` is a complete, self-consistent run that measured
    the WRONG thing, and the campaign halts on it rather than rerunning it (P2). Read back, never
    recomputed: ``fidelity.json`` is inside ``seal.json``'s content hashes, so a verified bundle's
    report is the one the sealer wrote (``runner/bundle.py``). ``read_fidelity`` is the module-level
    symbol so a caller can substitute it; the real read is what the wiring proof greps for.
    """
    document = read_fidelity(bundle_dir)
    if not document:
        return []
    return sorted(
        str(entry.get("id"))
        for entry in document.get("checks", [])
        if isinstance(entry, dict) and entry.get("klass") == "T" and entry.get("status") == "fail"
    )


def _bundle_answered_model(bundle_dir: Path) -> str | None:
    """The provider-returned model this sealed bundle's manifest recorded, or ``None`` (ADR-123).

    Read from ``manifest.json``'s ``answered_model`` field (data-management §2's M10 field), which
    is the field ``agents/registry/model.py`` captures and ``agents/golden.py`` writes. A bundle
    that records none -- a baseline, a v1 bundle -- contributes nothing to the cross-run comparison.
    """
    try:
        payload = json.loads((Path(bundle_dir) / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    value = payload.get("answered_model") if isinstance(payload, dict) else None
    return value if isinstance(value, str) and value else None


def _answered_model_change(campaign_dir: Path, answered: str) -> tuple[str, str] | None:
    """Persist the campaign's first answered model; return ``(prior, now)`` on a change (ADR-123).

    The first sealed run to record an answered model fixes it in ``answered_model.json``; every
    later run compares against it. A change of the provider-returned model halts the campaign -- the
    confounder that made v1's silent provider switch (ADR-107) invisible is now on the record. Equal
    is not proof the backend was unchanged (an echoing gateway yields the alias by construction,
    D10), but a change is proof it did, and that is the signal this catches.
    """
    path = Path(campaign_dir) / _ANSWERED_MODEL_SIDECAR
    prior: object = None
    if path.is_file():
        try:
            prior = json.loads(path.read_text(encoding="utf-8")).get("answered_model")
        except (OSError, ValueError, TypeError, AttributeError):
            prior = None
    if not isinstance(prior, str) or not prior:
        _atomic_write_json(path, {"answered_model": answered})
        return None
    if prior != answered:
        return (prior, answered)
    return None


def _read_attempts(campaign_dir: Path) -> dict[str, int]:
    """The persisted per-cell lifetime attempt counts, or ``{}`` before the first attempt.

    Replaces v1's per-invocation ``max_attempts_per_cell`` reset (defect V15: 120 uncounted reruns
    across 51 cells) with a counter that SURVIVES reinvocation, so a cell that flaked five times
    over five nights is capped whether those attempts fell in one invocation or five.
    """
    path = Path(campaign_dir) / _ATTEMPTS_SIDECAR
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return {
        str(key): value
        for key, value in payload.items()
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0
    }


def _checkpoint_ran(campaign_dir: Path) -> bool:
    """Whether the first-interleave-round checkpoint has already run for this campaign (F-AN-01)."""
    path = Path(campaign_dir) / _CHECKPOINT_SIDECAR
    if not path.is_file():
        return False
    try:
        return bool(json.loads(path.read_text(encoding="utf-8")).get("ran"))
    except (OSError, ValueError, TypeError, AttributeError):
        return False


def classify_failure(*, detail: str, timed_out: bool, invalid_reason: str | None = None) -> str:
    """Sort one UNSEALED attempt into ``infra`` / ``delivery-miss`` / ``instrument`` (ADR-120).

    Infra and delivery-miss rerun on the SAME instrument (a timeout, a provider hiccup, a transient
    injection landing miss D5 reruns); an INSTRUMENT failure is a deterministic defect the framework
    produced -- a rerun on the same instrument would reproduce it -- so it halts. The default is
    infra: the lifetime attempt cap bounds a cell that is genuinely stuck, and halting the whole
    campaign on an unclassified transient is exactly the over-eager stop this classification exists
    to avoid. A sealed bundle whose class-T treatment failed is NOT this function's business -- that
    is a halt on the sealed path, read from ``fidelity.json`` (:func:`_sealed_t_failures`).
    """
    haystack = f"{invalid_reason or ''} {detail or ''}".lower()
    if timed_out or "timeout" in haystack:
        return "infra"
    if any(marker in haystack for marker in _DELIVERY_MISS_MARKERS):
        return "delivery-miss"
    if any(marker in haystack for marker in _INSTRUMENT_MARKERS):
        return "instrument"
    return "infra"


def _integrity_defects(bundle_dir: Path) -> list[str]:
    """The seal-integrity defects of a purportedly sealed bundle (``runner/bundle.py``)."""
    from runner.bundle import verify_bundle_seal

    return verify_bundle_seal(bundle_dir)


def _nonfidelity_validity(bundle_dir: Path) -> list[str]:
    """§4 validity findings on an integrity-sound bundle, EXCLUDING ``fidelity-treatment-failed``.

    The fidelity treatment failure is handled by the halt path (:func:`_sealed_t_failures`), so it
    must not also arrive here as a plain invalid finding: routing it through mark-invalid-and-rerun
    is exactly what the plan forbids (WS-5), because a treatment failure is retained as evidence and
    never rerun. Every OTHER §4 finding -- a probe gap, an unrelated infra marker, a within-bundle
    model change, a collapsed window -- still makes the attempt invalid and rerunnable, as before.
    """
    try:
        payload = json.loads((Path(bundle_dir) / "manifest.json").read_text(encoding="utf-8"))
        from runner.manifest import from_dict as manifest_from_dict
        from runner.validity import check_run_validity, measurement_window_samples

        manifest = manifest_from_dict(payload)
        return [
            f"{finding.code}: {finding.detail}"
            for finding in check_run_validity(
                bundle_dir, manifest, window_samples=measurement_window_samples()
            )
            if finding.code != "fidelity-treatment-failed"
        ]
    except (OSError, ValueError, TypeError) as error:
        return [f"validity inputs unreadable: {error}"]


def _default_checkpoint_gate(campaign_dir: Path) -> str:
    """Run the analysis readiness gate at CHECKPOINT stage, returning the verdict (F-AN-01/ADR-133).

    Calls ``analysis.render.analyse`` -- the same F-AN-01 path the pilot gate and the final render
    use -- with ``readiness_stage="checkpoint"``, where only a missing measure (no code path, or one
    that raised) or a class-T failure blocks; a pending judge, a stated LIMITATION and a small-n
    cell are reported and do not stop the campaign, because the checkpoint runs while scoring is in
    progress (D2). The import is lazy so a campaign that never reaches the checkpoint never imports
    the analysis package. ``emit_proof=False`` -- a real campaign is not the synthetic-proof corpus.
    """
    from analysis.render import analyse

    result = analyse(
        campaign_dir,
        out_dir=Path(campaign_dir) / "_analysis",
        readiness_stage="checkpoint",
        emit_proof=False,
    )
    return result.readiness.verdict if result.readiness is not None else "GO"


def execute_campaign(
    manifest: CampaignManifest,
    campaign_seed: int,
    *,
    out_root: Path,
    run_driver: CampaignDriver,
    baseline_driver: CampaignDriver,
    timeout_seconds: float | None = None,
    continue_on_failure: bool = True,
    max_attempts_per_cell: int = 2,
    enforce_freeze: bool = True,
    hold_lease: bool = True,
    run_kubectl: Callable[..., subprocess.CompletedProcess[str]] | None = None,
    lifetime_attempts_cap: int | None = None,
    checkpoint_cells: int | None = None,
    checkpoint_gate: Callable[[Path], str] | None = None,
    pilot_kind: str | None = None,
) -> CampaignExecution:
    """Execute a validated generated order through injected run/baseline adapters.

    Verified attempts are skipped on resume. Every other existing attempt is retained and a new
    ``-R<n>`` attempt is allocated; failures receive an ``invalid.json`` sidecar and never count as
    done merely because a seal file exists.

    THE HALT RULE (ADR-120), the reason this loop is not just a retry loop:

    * A bundle that seals and is integrity-sound has its ``fidelity.json`` read
      (:func:`_sealed_t_failures`). Any class-T failure writes ``HALTED.json`` and raises
      :class:`CampaignHaltError` out of the loop -- the treatment this cell was run to measure was
      not delivered, so the run is retained as evidence and NEVER rerun (P2). A class-B finding is a
      behaviour observation and does not halt: it is a result, and a result that halted a campaign
      would delete the dissertation's data.
    * The run's ``answered_model`` is compared across runs (:func:`_answered_model_change`,
      ADR-123); a change of the provider-returned model halts.
    * An UNSEALED attempt is classified (:func:`classify_failure`): ``infra`` and ``delivery-miss``
      rerun on the same instrument; an ``instrument`` failure -- a deterministic defect a rerun
      would reproduce -- halts.
    * The per-cell attempt count is a LIFETIME counter persisted in ``attempts.json`` and surviving
      reinvocation (defect V15: v1 reset it per invocation and burned 120 uncounted reruns). A cell
      that reaches ``lifetime_attempts_cap`` (default ``lifetime_attempts_per_cell_max`` from the
      protocol) without sealing halts.
    * After the first interleave round -- ``checkpoint_cells`` completed cells (default
      ``checkpoint_cells`` from the protocol, one cell per arm x injection condition) -- the
      readiness gate runs once with CHECKPOINT semantics (:func:`_default_checkpoint_gate`,
      F-AN-01); a ``NO-GO`` halts. ``checkpoint_gate`` is an injectable seam;
      ``max_attempts_per_cell`` still bounds retries within a single invocation.

    ``enforce_freeze`` (P6, ADR-136) pins the campaign to one instrument by calling
    :func:`runner.freeze.enforce_freeze` before each cell: the instrument paths must be clean and,
    once a freeze tag is set, the instrument digest at ``HEAD`` must equal the digest at the tag.
    This replaces v1's whole-repository ``working_tree_dirty()`` check made on every cell (defect
    V14), so a docs-only commit outside the instrument paths no longer halts a campaign and an
    instrument-path commit still does. A :class:`~runner.freeze.FreezeError` becomes a
    :class:`CampaignRunError`.
    It is off only for the offline self-test, whose fake drivers run against a dirty dev tree, the
    way ``skip_preflight`` is.

    ``hold_lease`` (supervisor resumability gate, 2026-09-14) acquires the ADR-087 cluster Lease
    (``runner.run_lock.campaign_cluster_lease``) once, before the first cell, and releases it once
    after the last -- so no second checkout can touch the cluster for the whole 750-run span, not
    only for whichever one attempt happens to be running. Refuses to start with
    :class:`CampaignRunError` (wrapping :class:`~runner.run_lock.RunLockHeld`) if another live run
    or campaign already holds it. Each cell's own driver (``runner.run.run_planned`` /
    ``runner.baseline.run_planned_baseline``, unchanged) still calls ``cluster_lease`` once per
    attempt; while this campaign holds the Lease, that nested call is a re-entrant no-op (see
    ``runner.run_lock.cluster_lease``), so it never re-acquires the object this process already
    holds under a different holder identity and refuses itself. Off only for the offline self-test,
    the way ``enforce_freeze`` is; ``run_kubectl`` is a test seam forwarded to
    ``campaign_cluster_lease`` and otherwise unused.
    """
    if pilot_kind is None:
        validate_campaign_manifest(manifest)
    else:
        _validate_pilot(manifest, pilot_kind)
    if campaign_seed != manifest.campaign_seed:
        raise CampaignRunError(
            f"campaign seed {campaign_seed} does not match frozen manifest seed "
            f"{manifest.campaign_seed}"
        )
    if max_attempts_per_cell < 1:
        raise CampaignRunError("max_attempts_per_cell must be at least one")
    order = (
        generate_order(manifest, campaign_seed) if pilot_kind is None else manifest.generated_order
    )
    planned_by_id = {run.run_id: run for run in manifest.runs}
    campaign_dir = Path(out_root) / manifest.campaign_id
    campaign_dir.mkdir(parents=True, exist_ok=True)
    # A halted campaign is not resumed (ADR-120): the cause is terminal (a broken instrument, a
    # provider change, an exhausted cell) and a reinvocation that quietly continued would either
    # rerun a treatment failure the plan forbids rerunning or spend the budget past the cap. The
    # remedy is the operator's; a fixed instrument is a new digest, which the freeze then enforces.
    if _halted_path(campaign_dir).is_file():
        raise CampaignHaltError(
            f"campaign {manifest.campaign_id} is halted ({_halted_path(campaign_dir)} exists) and "
            "will not resume until the operator addresses the cause and clears the marker (ADR-120)"
        )
    frozen_path = campaign_dir / "campaign.json"
    frozen_bytes = campaign_to_canonical_bytes(manifest) + b"\n"
    if frozen_path.exists() and frozen_path.read_bytes() != frozen_bytes:
        raise CampaignRunError(f"existing frozen campaign manifest differs: {frozen_path}")
    if not frozen_path.exists():
        temporary = frozen_path.with_name(f".{frozen_path.name}.tmp-{os.getpid()}")
        try:
            temporary.write_bytes(frozen_bytes)
            os.replace(temporary, frozen_path)
        finally:
            temporary.unlink(missing_ok=True)

    # The protocol-owned bounds, resolved once (rule 00: the numbers live in evaluation-protocol.md
    # section 4 and are read through the fidelity mirror, never restated here). An explicit argument
    # overrides them for a test that wants a small cap or a two-cell round.
    lifetime_cap = (
        lifetime_attempts_cap
        if lifetime_attempts_cap is not None
        else int(resolve_optional("lifetime_attempts_per_cell_max"))
    )
    checkpoint_threshold = (
        checkpoint_cells
        if checkpoint_cells is not None
        else int(resolve_optional("checkpoint_cells"))
    )
    gate = checkpoint_gate if checkpoint_gate is not None else _default_checkpoint_gate

    lifetime = _read_attempts(campaign_dir)
    checkpoint_ran = _checkpoint_ran(campaign_dir)
    completed = 0
    attempted: list[AttemptResult] = []
    skipped: list[str] = []

    def _checkpoint_if_due() -> None:
        """Run the readiness gate ONCE, after the first interleave round completes (F-AN-01)."""
        nonlocal checkpoint_ran
        if pilot_kind is not None or checkpoint_ran or completed < checkpoint_threshold:
            return
        checkpoint_ran = True
        verdict = gate(campaign_dir)
        _atomic_write_json(
            campaign_dir / _CHECKPOINT_SIDECAR,
            {"ran": True, "completed": completed, "verdict": verdict},
        )
        if verdict != "GO":
            _write_halted(
                campaign_dir,
                reason="checkpoint",
                detail=f"checkpoint readiness gate returned {verdict} after {completed} cell(s)",
            )
            raise CampaignHaltError(
                f"campaign {manifest.campaign_id} halted: the checkpoint readiness gate returned "
                f"{verdict} after the first interleave round ({completed} cell(s)); only a missing "
                "measure or a class-T failure blocks the checkpoint (F-AN-01, ADR-133)"
            )

    # Campaign-span lease hold (supervisor resumability gate, 2026-09-14): acquired once here,
    # before the first cell, released once when this block exits -- never per cell. See the
    # docstring above and `runner.run_lock.campaign_cluster_lease` for why a nested per-attempt
    # `cluster_lease` deep inside each driver does not double-acquire against this. Local checks
    # (manifest validation, the halt marker above) run before this, unconditionally and without
    # touching the network -- cheapest check first, the same ordering `runner/run_lock.py` itself
    # documents for the file lock beside the cluster Lease.
    if hold_lease:
        lease_cm = (
            campaign_cluster_lease(manifest.campaign_id)
            if run_kubectl is None
            else campaign_cluster_lease(manifest.campaign_id, run_kubectl=run_kubectl)
        )
    else:
        lease_cm = nullcontext()

    try:
        with lease_cm:
            for cell_id in order:
                # The freeze, per cell (P6, ADR-136). Instrument-digest based, so a docs-only commit
                # does not halt and an instrument-path commit does -- replacing v1's whole-repo
                # dirty check (defect V14). A FreezeError is the operator's to resolve, so it
                # surfaces as a CampaignRunError rather than a halt marker.
                if enforce_freeze:
                    try:
                        freeze.enforce_freeze(campaign_dir, manifest.freeze_tag)
                    except freeze.FreezeError as error:
                        raise CampaignRunError(
                            f"campaign {manifest.campaign_id} refused: {error}"
                        ) from error
                if _verified_attempt(cell_id, campaign_dir) is not None:
                    skipped.append(cell_id)
                    completed += 1
                    _checkpoint_if_due()
                    continue
                planned = planned_by_id[cell_id]
                for existing_id in _attempt_ids(cell_id, campaign_dir):
                    existing_dir = campaign_dir / existing_id
                    if existing_dir.exists() and not (existing_dir / "invalid.json").is_file():
                        _mark_invalid(
                            existing_dir,
                            detail="existing attempt has no verified valid seal",
                            timed_out=False,
                        )
                attempts_this_invocation = 0
                sealed = False
                while attempts_this_invocation < max_attempts_per_cell and (
                    lifetime.get(cell_id, 0) < lifetime_cap
                ):
                    attempt, rerun_of = _next_attempt(planned, campaign_dir)
                    attempts_this_invocation += 1
                    # Count and PERSIST the attempt before driving it, so a process killed
                    # mid-attempt still spends one of the cell's lifetime attempts -- the counter's
                    # whole purpose (defect V15) is defeated by a count that only lands on return.
                    lifetime[cell_id] = lifetime.get(cell_id, 0) + 1
                    _atomic_write_json(campaign_dir / _ATTEMPTS_SIDECAR, lifetime)
                    driver = baseline_driver if attempt.is_baseline else run_driver
                    timed_out = False
                    try:
                        outcome = _invoke_driver(driver, attempt, rerun_of, timeout_seconds)
                        if outcome.run_id != attempt.run_id:
                            raise CampaignRunError(
                                f"driver returned {outcome.run_id!r} for attempt {attempt.run_id!r}"
                            )
                        detail = outcome.detail
                        sealed = outcome.sealed
                    except TimeoutError as error:
                        timed_out = True
                        detail = str(error)
                        sealed = False
                    except Exception as error:  # noqa: BLE001 - one failed run must not kill a nightly batch
                        detail = f"driver failed: {error}"
                        sealed = False

                    bundle_dir = campaign_dir / attempt.run_id
                    invalid_reason: str | None = None
                    if sealed:
                        # Integrity first: a corrupted or incomplete bundle is invalid and
                        # rerunnable, never a halt -- a fidelity.json in a tampered bundle cannot
                        # be trusted.
                        integrity = _integrity_defects(bundle_dir)
                        if integrity:
                            sealed = False
                            detail = "run validity failed: " + "; ".join(integrity)
                            invalid_reason = integrity[0].split(":", 1)[0]
                        else:
                            # Integrity-sound. THE FIDELITY GATE (ADR-120): a class-T treatment
                            # failure recorded in fidelity.json halts -- the bundle is retained as
                            # evidence and never rerun. read_fidelity is read AFTER the seal, the
                            # wiring the plan's WS-5 row requires.
                            treatment = _sealed_t_failures(bundle_dir)
                            if treatment:
                                _write_halted(
                                    campaign_dir,
                                    reason="treatment-fidelity",
                                    run_id=attempt.run_id,
                                    detail="class-T fidelity failure(s): " + ", ".join(treatment),
                                    extra={"failures": treatment},
                                )
                                raise CampaignHaltError(
                                    f"campaign {manifest.campaign_id} halted at {attempt.run_id}: "
                                    f"class-T fidelity failure(s) {treatment}; the treatment this "
                                    "cell was run to measure was not delivered, so the run is "
                                    "retained as evidence and the campaign HALTS rather than "
                                    "rerunning (P2, ADR-120)"
                                )
                            # The answered-model change halt (ADR-123), on the sealed, sound run.
                            answered = _bundle_answered_model(bundle_dir)
                            if answered is not None:
                                change = _answered_model_change(campaign_dir, answered)
                                if change is not None:
                                    prior, now = change
                                    _write_halted(
                                        campaign_dir,
                                        reason="answered-model-change",
                                        run_id=attempt.run_id,
                                        detail=f"answered model changed from {prior!r} to {now!r}",
                                        extra={"prior": prior, "current": now},
                                    )
                                    raise CampaignHaltError(
                                        f"campaign {manifest.campaign_id} halted at "
                                        f"{attempt.run_id}: the answered model changed from "
                                        f"{prior!r} to {now!r} across runs; a change of the "
                                        "provider-returned model halts (F-AG-04, ADR-123)"
                                    )
                            # Every OTHER section-4 finding still makes the attempt invalid and
                            # rerunnable, exactly as before (the fidelity finding is excluded above,
                            # because it is handled by the halt, not by mark-invalid-and-rerun).
                            validity = _nonfidelity_validity(bundle_dir)
                            if validity:
                                sealed = False
                                detail = "run validity failed: " + "; ".join(validity)
                                invalid_reason = validity[0].split(":", 1)[0]
                    invalid = not sealed
                    if invalid:
                        _mark_invalid(
                            bundle_dir,
                            detail=detail,
                            timed_out=timed_out,
                            reason=invalid_reason,
                        )
                    attempted.append(
                        AttemptResult(attempt.run_id, cell_id, sealed, invalid, detail, rerun_of)
                    )
                    if sealed:
                        break
                    # An instrument failure cannot be fixed by rerunning the same instrument, so it
                    # halts instead of consuming reruns (ADR-120); infra and delivery-miss reruns
                    # continue within the caps.
                    if (
                        classify_failure(
                            detail=detail, timed_out=timed_out, invalid_reason=invalid_reason
                        )
                        == "instrument"
                    ):
                        _write_halted(
                            campaign_dir,
                            reason="instrument",
                            run_id=attempt.run_id,
                            detail=detail,
                        )
                        raise CampaignHaltError(
                            f"campaign {manifest.campaign_id} halted at {attempt.run_id}: an "
                            f"instrument failure a rerun cannot fix -- {detail} (ADR-120)"
                        )
                    if not continue_on_failure:
                        raise CampaignRunError(f"{attempt.run_id} invalid: {detail}")
                if sealed:
                    completed += 1
                    _checkpoint_if_due()
                elif lifetime.get(cell_id, 0) >= lifetime_cap:
                    # The cell exhausted its lifetime attempts across every invocation without
                    # sealing: a persistent failure a rerun will not resolve, so it halts (ADR-120).
                    _write_halted(
                        campaign_dir,
                        reason="lifetime-attempt-cap",
                        run_id=cell_id,
                        detail=(
                            f"cell {cell_id} reached the lifetime attempt cap ({lifetime_cap}) "
                            f"across invocations without sealing"
                        ),
                    )
                    raise CampaignHaltError(
                        f"campaign {manifest.campaign_id} halted: cell {cell_id} reached the "
                        f"lifetime attempt cap ({lifetime_cap}) across invocations without sealing "
                        "(ADR-120)"
                    )
    except RunLockHeld as error:
        raise CampaignRunError(f"campaign {manifest.campaign_id} refused: {error}") from error
    except ClusterLeaseError as error:
        raise CampaignRunError(
            f"campaign {manifest.campaign_id} could not hold the cluster lease: {error}"
        ) from error

    return CampaignExecution(manifest.campaign_id, tuple(attempted), tuple(skipped))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="campaign", description="Validate, order and gate the interleaved grid (T6.4/B3)."
    )
    parser.add_argument("--manifest", type=Path, required=True, help="the campaign manifest (M=)")
    parser.add_argument("--seed", type=int, default=0, help="the campaign seed for the order")
    parser.add_argument(
        "--skip-preflight", action="store_true", help="offline self-test only; never in a real run"
    )
    parser.add_argument("--execute", action="store_true", help="drive the generated order")
    parser.add_argument("--offline", action="store_true", help="use deterministic offline adapters")
    from runner.pilot_cli import PILOT_VALIDATORS

    parser.add_argument("--pilot-kind", choices=tuple(PILOT_VALIDATORS), default=None)
    parser.add_argument("--out-root", type=Path, default=REPO_ROOT / "runs")
    parser.add_argument(
        "--timeout", type=float, default=None, help="per-attempt timeout in seconds"
    )
    parser.add_argument("--max-attempts", type=int, default=2)
    parser.add_argument("--stop-on-failure", action="store_true")
    stop = parser.add_mutually_exclusive_group()
    stop.add_argument("--duration", type=float, metavar="SECONDS")
    stop.add_argument("--samples", type=int, metavar="N")
    args = parser.parse_args(argv)
    try:
        order = run_campaign(
            args.manifest, args.seed, skip_preflight=args.skip_preflight, pilot_kind=args.pilot_kind
        )
        if not args.execute:
            print(f"campaign: PASS — validated, preflight clear, {len(order)} runs ordered")
            return 0
        payload = json.loads(args.manifest.read_text(encoding="utf-8"))
        manifest = from_dict(payload)
        window = None
        if args.offline:
            if args.samples is not None or args.duration is not None:
                raise CampaignRunError("--samples/--duration apply only to live campaign execution")
        else:
            from runner.live_baseline import MeasurementWindow
            from runner.live_run import LiveRunError, dependencies_from_environment

            try:
                dependencies_from_environment()
            except LiveRunError as error:
                raise CampaignRunError(str(error)) from None
            try:
                window = MeasurementWindow(samples=args.samples, duration_seconds=args.duration)
            except ValueError as error:
                raise CampaignRunError(
                    "live campaign execution requires exactly one of --samples or --duration; "
                    f"{error}"
                ) from None

        grid_driver = _DefaultDriver(
            manifest.campaign_id,
            args.out_root,
            args.offline,
            window,
            baseline=False,
            pilot=(args.pilot_kind, manifest) if args.pilot_kind else None,
        )
        baseline_driver = _DefaultDriver(
            manifest.campaign_id, args.out_root, args.offline, window, baseline=True
        )

        # The checkpoint readiness gate reads a real, growing corpus with `analysis.render.analyse`;
        # an offline self-test drives synthetic bundles and is not a real evidence campaign, so it
        # records the checkpoint as GO rather than running the gate over a partial synthetic corpus.
        # A live campaign uses the default gate (F-AN-01, ADR-133).
        checkpoint_gate = (lambda _campaign_dir: "GO") if args.offline else None
        execution = execute_campaign(
            manifest,
            args.seed,
            out_root=args.out_root,
            run_driver=grid_driver,
            baseline_driver=baseline_driver,
            timeout_seconds=args.timeout,
            continue_on_failure=not args.stop_on_failure,
            max_attempts_per_cell=args.max_attempts,
            enforce_freeze=not args.offline,
            hold_lease=not args.offline,
            checkpoint_gate=checkpoint_gate,
            pilot_kind=args.pilot_kind,
        )
    except (CampaignRunError, PreflightError, OSError, ValueError) as error:
        print(f"campaign: {error}", file=sys.stderr)
        return 1
    invalid_attempts = sum(result.invalid for result in execution.attempted)
    print(
        f"campaign: {'PASS' if execution.complete else 'INCOMPLETE'} — "
        f"{len(execution.attempted)} attempts, {len(execution.skipped)} cells resumed, "
        f"{invalid_attempts} invalid attempts, {execution.flake_count} flakes"
    )
    return 0 if execution.complete else 1


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
