r"""The bundle sealer: two completeness profiles, one seal, and a refusal to ship anything less.

WHAT THIS MODULE OWNS
-----------------------
``docs/protocols/data-management.md`` §3 requires the runner to **refuse to seal** a bundle that is
not complete under its profile, and §1 fixes what ``seal.json`` records: "bundle content hashes +
chain head + sealed_at". This module is that seal. :func:`seal_bundle` sanitises the bundle
(``runner/sanitize.py``), applies the completeness profile ``manifest.is_baseline`` selects, checks
the Guardian audit chain (framework-on only, reusing ``guardian/audit/verify.py`` rather than
re-implementing it), writes ``manifest.json`` from the passed :class:`~runner.manifest.RunManifest`,
and writes ``seal.json``. Any completeness, sanitiser or chain failure raises
:class:`CompletenessError` or :class:`SanitizationError` -- both :class:`SealError` -- naming the
offending file or secret. Scoring happens after seal, so :func:`append_scoring_entry` adds
``scores.json``'s hash without re-hashing or re-sealing the rest.

THE THREE PROFILES (data-management §3), TWO SELECTED BY ``is_baseline`` AND ONE BY A FLAG
-----------------------------------------------------------------------------------------
*Framework-on* (``is_baseline: false``). Required present and non-empty: ``manifest.json``
(this module writes it), ``messages.jsonl``, ``tokens.json``, ``spans.otel.json``,
``monitor_events.jsonl``, ``guardian_audit.jsonl``, ``injection.log.jsonl``, ``assertions.json``,
``k8s_api_audit.jsonl``, ``probes.csv``, ``resources.csv``, ``metrics.json``. Conditional and so not
required at seal: ``locust_stats.csv`` (present only for RQ4/interference runs). Not required at
seal:
``scores.json`` (no run is scored at seal time, §3), and ``fidelity.json`` when absent (a v1
bundle).
``metrics.json`` is required for §3's audit-derived blocked-request counter. The audit chain must
verify end-to-end, and when the runner passes ``injection_event_count`` the ``injection.log.jsonl``
line count must equal it (§3: "injection.log matches scenario ground-truth event count"). Every
LLM-call object in ``messages.jsonl`` must have exactly one ``tokens.json`` entry with the same
``index``, and that entry's ``model`` must exactly equal the manifest's provider model string.

``k8s_api_audit.jsonl`` is required for ANY framework-on run (M10, ADR-137). It is the file that
makes
an executed Guardian action or a direct G2 action leave an API-server record, and v1's audit policy
ended in a catch-all ``level: None`` so nothing did: 0 of 755 framework-on bundles carry one, and
every
v1 execution was consequently uncorroborated (defect V28). A required file is the only place that
fact
can be enforced -- a check that merely reported its absence (F-GD-06) would report it after the
fact,
and a corpus whose executions cannot be corroborated cannot be analysed at all.

*Baseline* (``is_baseline: true``). Required present and non-empty: ``manifest.json`` (this module
writes it), ``probes.csv``, ``resources.csv``, ``locust_stats.csv``. Note the inversion §3 draws --
``locust_stats.csv`` is unconditional on a baseline, because a load-matched baseline exists to
produce exactly the load statistics RQ4's interference delta is read against. Eleven framework-on
artefacts are asserted **absent**, not merely unrequired: ``messages.jsonl``, ``tokens.json``,
``spans.otel.json``, ``guardian_audit.jsonl``, ``monitor_events.jsonl``, ``injection.log.jsonl``,
``assertions.json``, ``scores.json``, ``metrics.json``, ``k8s_api_audit.jsonl``, ``results.json``. A
baseline carrying any of them is a mislabelled run -- the defect §2's two-directional null-field
check
catches manifest-side -- and it does not seal. That asserted-absent half is a real check with its
own
test, not a no-op. ``k8s_api_audit.jsonl`` joins that list under M10 for the same reason it joins
the
required list above: a framework-off baseline has no framework, so it has no Guardian execution and
no
direct path, and a slice of "nothing happened" in a baseline bundle is a symptom, not evidence.

*Probe* (``instrument_only: true``). The third profile the M10 work order adds for the P0-live
instrument probes (``--instrument-only``: condition flags applied, scenario and injections executed,
evidence and API audit collated, NO agent graph). Required and non-empty: ``monitor_events.jsonl``,
``injection.log.jsonl``, ``k8s_api_audit.jsonl``, ``probes.csv``, ``resources.csv``,
``metrics.json``. Asserted **absent**: ``messages.jsonl``, ``tokens.json``, ``spans.otel.json``,
``results.json``, ``assertions.json`` -- every file the AGENT layer alone produces, so their
presence
means a probe ran an agent graph, which is the one thing a probe must not do (it would make the
probed instrument the one under test rather than the one being probed).

The selection is ``is_baseline`` first and the flag second, and that order is the plan's: the prompt
names exactly two probe profiles "selected by ``is_baseline``" as well as the flag, so a flag on a
baseline would be ambiguous, and a baseline that is also a probe is a baseline. The two are made
mutually exclusive at :func:`seal_bundle`'s boundary rather than trusted, so a caller that sets both
gets an error instead of whichever profile won.

THE ``fidelity.json`` SCHEMA, AND WHERE IT SITS IN THE ORDER
-------------------------------------------------------------
``docs/protocols/data-management.md`` §1 names ``fidelity.json`` as a bundle file and the M10
interface contract (SEAM 2) fixes its shape. This module does not re-state the shape: it calls
:func:`runner.fidelity.evaluate_bundle` and :func:`~runner.fidelity.write_fidelity_report`, so the
document written here is the same one the fidelity CLI reads and the analysis layer parses.

The ORDER is load-bearing and is the point of the whole exercise: the report is written BEFORE
``seal.json`` and before ``_content_hashes``, so ``fidelity.json`` is covered by the seal. A
fidelity
verdict that could be edited after the seal would be a claim about the instrument with no integrity
guarantee at all, and a T failure that could be edited away would not halt anything.

AND WHY A FIDELITY FAILURE DOES NOT PREVENT THE SEAL
------------------------------------------------------
Because the seal and the fidelity verdict answer different questions and the plan separates them
explicitly. "Is this bundle complete and self-consistent?" is a STRUCTURAL question: a bundle
missing
a file, carrying an unjoinable audit chain, or holding a secret is not a run, and it must not become
one. "Was the treatment delivered?" is a FIDELITY question: a bundle whose G3 arm ran quoted is a
complete, consistent, correctly sealed run that measured the wrong thing, and it is precisely that
bundle a researcher must be able to open and read. Refusing to seal it would destroy the evidence
the
defect is proven from, would make ``execute_campaign`` route a treatment failure through the
mark-invalid path the plan explicitly forbids, and would leave a corpus with no record that the
instrument was wrong. So: the seal is written, ``fidelity.json`` is inside it, and
``runner/campaign_cli.py`` reads the T failures out of the sealed report and halts.

THE ``seal.json`` SCHEMA, AND THE BASELINE CHAIN-HEAD DECISION
----------------------------------------------------------------
``data-management.md`` §1 names the contents and not the schema, so the kit fixes it here::

    {
      "audit_chain_head": "<64 hex>" | null,   # SEAL_HEAD_KEY; the head verify.py anchors to
      "content_hashes": {"<file>": "<sha256 over raw bytes>", ...},
      "sealed_at": "<ISO-8601 UTC>"
    }

``content_hashes`` covers every file present in the bundle **except** ``seal.json`` itself and
``scores.json`` (scores is post-seal). The hash is SHA-256 over the file's **raw bytes** -- not the
LF-normalised digest ``agents/registry/digest.py`` and ``guardian/audit/canonical.py`` take, and the
difference is deliberate: those hash tracked files that ``.gitattributes`` normalises on checkout,
whereas a run bundle lives under ``runs/`` (gitignored, §7), is written once by the run and never
passes through a git line-ending filter, so the bytes on disk are exactly the bytes the run produced
and a raw-byte hash is both simpler and reproducible.

**Baseline chain-head: an explicit ``null``.** A baseline ran no Guardian, so there is no chain and
no head. The key is written with value ``null`` rather than omitted, so the schema is uniform and a
reader sees "no chain" stated rather than a key that looks forgotten. ``read_seal_head`` in
``guardian/audit/verify.py`` requires the key present *and* a valid 64-hex value, so it refuses a
baseline seal either way -- which is correct, because nothing anchors a baseline, and §6's
``make audit-verify`` sweep runs only over the framework-on chains that have one.

``append_scoring_entry`` IS NOT A RE-SEAL
-------------------------------------------
§3: ``scores.json`` "is written after the bundle seals: its hash is appended to ``seal.json`` as a
post-seal scoring entry, leaving the original content hashes and the audit chain verifiable
unchanged." :func:`append_scoring_entry` adds one ``"scoring"`` key and touches nothing else, so
:func:`verify_content_hashes` still passes over the pre-scoring hashes afterward -- which is a test,
not a hope.

WHAT BREAKS IF THIS FILE CHANGES
---------------------------------
The seal (T-15) and the sanitiser gate (T-41). A profile that requires one file too few seals an
incomplete bundle the campaign later cannot analyse; one file too many rejects a valid run. After
the ``v1.0`` freeze a change here is a logged hotfix ADR (iron rule 6), because the seal is
in every bundle at once. ADR-040 covers the sealer and its decisions; the identifier grammar the
manifest and ids modules rest on is ADR-039's.
"""

import csv
import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from guardian.audit.canonical import canonical_json_bytes
from guardian.audit.chain import read_chain
from guardian.audit.record_types import is_execution, is_run_start
from guardian.audit.verify import SEAL_HEAD_KEY, verify_chain

from runner.manifest import RunManifest, same_model_provider, to_canonical_bytes
from runner.sanitize import SANITISE_FILES, sanitize_bundle, scan_for_secrets

__all__ = (
    "CompletenessError",
    "SanitizationError",
    "SealError",
    "append_scoring_entry",
    "load_seal",
    "seal_bundle",
    "verify_bundle_seal",
    "verify_content_hashes",
)

_MANIFEST: Final = "manifest.json"
_SEAL: Final = "seal.json"
_SCORES: Final = "scores.json"
_CHAIN: Final = "guardian_audit.jsonl"
_RESULTS: Final = "results.json"
_INJECTION: Final = "injection.log.jsonl"

#: The API-server audit slice (M10, ADR-137; data-management §1 and §3). Named here, in
#: ``runner/fidelity/__init__.py`` and in ``runner/live_evidence.py`` because three directories
#: spell
#: it and a bundle that required one spelling while its producer wrote another would seal empty.
_API_AUDIT: Final = "k8s_api_audit.jsonl"

# The full bundle layout (data-management §1), in the order §1 lists it. The content-hash set is
# this layout minus seal.json (which the hashes live in) and scores.json (which is post-seal).
_BUNDLE_LAYOUT: Final[tuple[str, ...]] = (
    _MANIFEST,
    "messages.jsonl",
    _RESULTS,
    "tokens.json",
    "spans.otel.json",
    "monitor_events.jsonl",
    "monitor_timings.jsonl",
    _API_AUDIT,
    "fidelity.json",
    _CHAIN,
    _INJECTION,
    "assertions.json",
    "probes.csv",
    "resources.csv",
    "locust_stats.csv",
    "metrics.json",
    _SCORES,
    _SEAL,
)

# The instrument CSVs. Scanned as a backstop (a secret leaking into structured output should stop
# the seal) but never sanitised, since rewriting numeric series would corrupt them.
_CSV_FILES: Final[tuple[str, ...]] = ("probes.csv", "resources.csv", "locust_stats.csv")

# What the backstop scan reads: the sanitisable free-text files plus the instrument CSVs.
# guardian_audit.jsonl and manifest.json are excluded -- both are born clean, and scanning either
# would risk a false positive on a legitimate dotted identifier for no gain (see _scan_bundle).
_SCAN_FILES: Final[tuple[str, ...]] = (*SANITISE_FILES, *_CSV_FILES)

# Framework-on: present and non-empty at seal. manifest.json is here because this module writes it
# before the check; seal.json is produced, not required; locust_stats.csv is conditional;
# scores.json is post-seal; fidelity.json is written by this module too but is allowed to be absent,
# because a v1 bundle read from disk has none and must still verify. metrics.json is required
# because
# §3 homes requests_blocked there. k8s_api_audit.jsonl is required (M10, ADR-137, defect V28).
_FRAMEWORK_ON_REQUIRED: Final[tuple[str, ...]] = (
    _MANIFEST,
    "messages.jsonl",
    _RESULTS,
    "tokens.json",
    "spans.otel.json",
    "monitor_events.jsonl",
    "monitor_timings.jsonl",
    _API_AUDIT,
    _CHAIN,
    _INJECTION,
    "assertions.json",
    "probes.csv",
    "resources.csv",
    "metrics.json",
)

# Baseline: present and non-empty. locust_stats.csv is unconditional here (the inversion §3 draws).
_BASELINE_REQUIRED: Final[tuple[str, ...]] = (
    _MANIFEST,
    "probes.csv",
    "resources.csv",
    "locust_stats.csv",
)

# Baseline: asserted absent. The framework-on artefacts a baseline has no producer for; any one
# present is a mislabelled baseline (§3).
_BASELINE_FORBIDDEN: Final[tuple[str, ...]] = (
    "messages.jsonl",
    _RESULTS,
    "tokens.json",
    "spans.otel.json",
    _CHAIN,
    "monitor_events.jsonl",
    "monitor_timings.jsonl",
    _INJECTION,
    "assertions.json",
    _SCORES,
    "metrics.json",
    _API_AUDIT,
)

# Probe (`--instrument-only`): present and non-empty. The three artefacts a probe is FOR -- the
# evidence, the injection log, and the API-server audit slice -- plus the two instrument CSVs and
# the
# metric object the drain measurement and the seal's own counter live in.
_PROBE_REQUIRED: Final[tuple[str, ...]] = (
    _MANIFEST,
    "monitor_events.jsonl",
    "monitor_timings.jsonl",
    _INJECTION,
    _API_AUDIT,
    "probes.csv",
    "resources.csv",
    "metrics.json",
)

# Probe: asserted absent. Every file only the AGENT layer produces. A probe exists to prove what the
# framework around the agent does (WS-3's quoting/epoch chain, the forwarder drain, the audit
# policy,
# the shim, the Guardian's own enforcement), and an agent graph running inside it would make the
# probe
# measure the agent instead -- and would make its cost and its latency part of the measurement
# window.
_PROBE_FORBIDDEN: Final[tuple[str, ...]] = (
    "messages.jsonl",
    "tokens.json",
    "spans.otel.json",
    _RESULTS,
    "assertions.json",
    _CHAIN,
)


class SealError(Exception):
    """A bundle could not be sealed. The message names the offending file or secret."""


class CompletenessError(SealError):
    """A bundle is incomplete under its profile, or its audit chain does not verify (§3)."""


class SanitizationError(SealError):
    """A secret survived sanitisation into a file the sealer scans; the seal is refused (§5)."""


def _iso_now() -> str:
    """The one wall-clock read, isolated and injectable: the sealer is off the determinism path."""
    return datetime.now(UTC).isoformat()


def _sha256_file(path: Path) -> str:
    """SHA-256 hex over a file's raw bytes. Raw, not LF-normalised -- see the module docstring."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _atomic_write(path: Path, content: bytes) -> None:
    """Durably publish ``content`` with a same-directory temporary file and atomic replacement."""
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        with temporary.open("wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _require_present(bundle_dir: Path, names: tuple[str, ...]) -> None:
    """Raise :class:`CompletenessError` naming the first required file that is absent or empty."""
    for name in names:
        path = bundle_dir / name
        if not path.is_file():
            raise CompletenessError(
                f"{name} is required by this profile but is absent; the bundle does not seal "
                "(data-management §3)."
            )
        if path.stat().st_size == 0:
            raise CompletenessError(
                f"{name} is required by this profile but is empty; the bundle does not seal "
                "(data-management §3)."
            )


def _require_absent(bundle_dir: Path, names: tuple[str, ...]) -> None:
    """Raise :class:`CompletenessError` naming the first forbidden artefact a baseline holds."""
    for name in names:
        if (bundle_dir / name).is_file():
            raise CompletenessError(
                f"a baseline bundle carries {name}, a framework-on artefact it must not contain; "
                "this is a mislabelled baseline and does not seal (data-management §3)."
            )


def _scan_bundle(bundle_dir: Path) -> None:
    """Scan the sanitisable files and the instrument CSVs; refuse the seal on any residual secret.

    The Guardian audit log and manifest are excluded: both are born clean (the chain by
    ``guardian/audit/chain.py``'s append-time scrub, the manifest by construction), and scanning
    either would risk a false positive on a legitimate dotted identifier -- an issuer DNS name, a
    provider string -- for no gain over the guarantee they already carry.
    """
    for name in _SCAN_FILES:
        path = bundle_dir / name
        if not path.is_file():
            continue
        findings = scan_for_secrets(path.read_bytes().decode("utf-8"))
        if findings:
            found = findings[0]
            raise SanitizationError(
                f"{name} still carries a secret after sanitisation "
                f"({found.kind}: {found.snippet!r}); a bundle failing the planted-secret scan "
                "cannot seal (data-management §5)."
            )


def _verify_audit_chain(bundle_dir: Path) -> str:
    """Verify ``guardian_audit.jsonl`` and return its chain head, reusing verify.py's verifier.

    Unanchored on purpose: at seal time there is no ``seal.json`` yet to anchor against, and the
    point of this call is to *compute* the head that becomes the anchor. A chain that does not
    verify raises rather than seals.
    """
    path = bundle_dir / _CHAIN
    report = verify_chain(read_chain(path), path=str(path))
    if not report.ok:
        detail = str(report.findings[0]) if report.findings else report.diagnosis
        raise CompletenessError(
            f"{_CHAIN} does not verify (diagnosis={report.diagnosis}): {detail}. A bundle whose "
            "audit chain fails verification does not seal (data-management §3)."
        )
    if report.head is None:  # pragma: no cover - an ok report over a non-empty chain has a head
        raise CompletenessError(f"{_CHAIN} verified but produced no chain head to seal")
    return report.head


def _injection_line_count(bundle_dir: Path) -> int:
    """Count non-blank lines in ``injection.log.jsonl`` -- the injected-event sequence length."""
    text = (bundle_dir / _INJECTION).read_bytes().decode("utf-8")
    return sum(1 for line in text.splitlines() if line.strip())


def _load_json_document(path: Path, *, expected: str) -> object:
    """Load one UTF-8 JSON document or report a seal-time completeness error."""
    try:
        return json.loads(path.read_bytes().decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CompletenessError(f"{path.name} is not valid UTF-8 {expected}: {error}") from error


def _load_jsonl_objects(path: Path) -> list[dict[str, object]]:
    """Load non-blank JSON Lines, requiring one object per line."""
    try:
        text = path.read_bytes().decode("utf-8")
    except UnicodeDecodeError as error:
        raise CompletenessError(f"{path.name} is not valid UTF-8 JSON Lines: {error}") from error
    records: list[dict[str, object]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise CompletenessError(
                f"{path.name}:{line_number} is not valid JSON: {error}"
            ) from error
        if not isinstance(record, dict):
            raise CompletenessError(f"{path.name}:{line_number} must be a JSON object.")
        records.append(record)
    return records


def _indexed_records(
    records: list[dict[str, object]], *, filename: str
) -> dict[int, dict[str, object]]:
    """Index per-call records, refusing absent, boolean, negative, or duplicate indexes."""
    indexed: dict[int, dict[str, object]] = {}
    for position, record in enumerate(records, start=1):
        index = record.get("index")
        if not isinstance(index, int) or isinstance(index, bool) or index < 0:
            raise CompletenessError(
                f"{filename} entry {position} has no non-negative integer 'index'; "
                "LLM calls cannot be matched at seal."
            )
        if index in indexed:
            raise CompletenessError(f"{filename} has duplicate LLM-call index {index}.")
        indexed[index] = record
    return indexed


def _verify_llm_call_accounting(bundle_dir: Path, exact_alias: str, exact_model: str) -> None:
    """Reconcile every LLM call with exact manifest alias and provider identity."""
    messages = _load_jsonl_objects(bundle_dir / "messages.jsonl")
    tokens_document = _load_json_document(bundle_dir / "tokens.json", expected="JSON")
    if not isinstance(tokens_document, list) or not all(
        isinstance(entry, dict) for entry in tokens_document
    ):
        raise CompletenessError("tokens.json must be a JSON array of per-call objects.")
    message_by_index = _indexed_records(messages, filename="messages.jsonl")
    token_by_index = _indexed_records(tokens_document, filename="tokens.json")
    if message_by_index.keys() != token_by_index.keys():
        missing = sorted(message_by_index.keys() - token_by_index.keys())
        extra = sorted(token_by_index.keys() - message_by_index.keys())
        raise CompletenessError(
            "messages.jsonl LLM calls do not match tokens.json entries exactly "
            f"(missing token indexes={missing}, extra token indexes={extra})."
        )
    for index, entry in token_by_index.items():
        alias = entry.get("model_alias")
        if alias != exact_alias:
            raise CompletenessError(
                f"tokens.json LLM-call index {index} has model_alias {alias!r}, not the exact "
                f"manifest model_alias {exact_alias!r}."
            )
        model = entry.get("model")
        if not same_model_provider(model, exact_model):
            raise CompletenessError(
                f"tokens.json LLM-call index {index} has model {model!r}, not the exact manifest "
                f"model_provider_string {exact_model!r}."
            )


def _verify_restarts_total(bundle_dir: Path) -> None:
    """Require a data row and a populated non-negative integer restart count on every row."""
    path = bundle_dir / "resources.csv"
    try:
        with path.open("r", encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream)
            if reader.fieldnames is None or "restarts_total" not in reader.fieldnames:
                raise CompletenessError(
                    "resources.csv lacks the required restarts_total column; "
                    "the bundle does not seal."
                )
            rows = list(reader)
    except UnicodeDecodeError as error:
        raise CompletenessError(f"resources.csv is not valid UTF-8 CSV: {error}") from error
    if not rows:
        raise CompletenessError(
            "resources.csv has no data rows, so restarts_total is not populated."
        )
    for row_number, row in enumerate(rows, start=2):
        value = row.get("restarts_total")
        try:
            parsed = int(value) if value is not None and value != "" else None
        except ValueError as error:
            raise CompletenessError(
                f"resources.csv row {row_number} restarts_total is not an integer: {value!r}."
            ) from error
        if parsed is None or parsed < 0:
            raise CompletenessError(
                f"resources.csv row {row_number} has invalid restarts_total {value!r}; "
                "it must be a populated non-negative integer."
            )


def _verify_blocked_requests_metric(bundle_dir: Path) -> None:
    """Require audit support for, and exact reconciliation of, metrics.requests_blocked."""
    records = read_chain(bundle_dir / _CHAIN)
    blocked = 0
    for parsed in records:
        if is_run_start(parsed.record):
            # ADR-058: the Guardian's run-start genesis is not a request. It carries no enforcement
            # by design, so it can be neither blocked nor unsupported, and it is not counted.
            continue
        if is_execution(parsed.record):
            # ADR-082: a follow-up naming a decision's execution outcome, not a decision of its own.
            # It carries no ``enforcement`` field at all -- that is the decision record's, and a
            # v4 chain writes exactly one of these per decision -- so it is excluded here for the
            # same reason a run-start is: nothing was asked of the Guardian by it.
            continue
        enforcement = parsed.record.get("enforcement")
        if enforcement not in {"blocked", "executed", "not-applicable"}:
            raise CompletenessError(
                f"{_CHAIN} line {parsed.line} lacks a supported enforcement outcome; "
                "requests_blocked cannot be derived."
            )
        blocked += enforcement == "blocked"
    metrics = _load_json_document(bundle_dir / "metrics.json", expected="JSON")
    if not isinstance(metrics, dict):
        raise CompletenessError("metrics.json must be a JSON object.")
    value = metrics.get("requests_blocked")
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise CompletenessError(
            "metrics.json must include non-negative integer field 'requests_blocked'."
        )
    if value != blocked:
        raise CompletenessError(
            f"metrics.json requests_blocked is {value}, but {_CHAIN} derives {blocked}."
        )


def _unjoined_decided_actions(bundle_dir: Path) -> list[str]:
    """Describe every Guardian-decided action in ``results.json`` this bundle's chain does not hold.

    data-management §3 makes the Guardian's audit log the authoritative record of authorisation
    outcomes, "joined to this broader record by run and timestamp identifier". The agent layer
    records each Guardian answer in ``results.json``, and the Guardian's ``ActionResult`` carries a
    non-nullable ``audit_seq`` that is the ``seq`` of the decision it wrote. So every decided action
    names its own chain record, and the join is checkable without trusting either side.

    The failure this exists for was observed on 2026-09-12 (ADR-077): a second process redeployed
    the Guardian for a different run a minute into a live run, the run's decisions were written to
    that other run's chain, and the runner exported this run's own chain -- a verifying, anchored
    chain holding only its run-start genesis -- and sealed it beside a ``results.json`` naming
    ``audit_seq`` 5, 6 and 7. Hash-chain verification cannot see that; only the join can.

    Keyed on ``audit_seq`` rather than ``request_id``: a submission the Guardian rejects as
    malformed before parsing its body is audited with ``request_id: null``, so a request-id join
    would refuse a legitimate bundle. Where both sides carry a request id they must agree, which
    catches a chain that merely happens to have a record at the same sequence number.

    Bundles without ``results.json`` (the synthetic corpus, and offline fixtures) have nothing to
    join and return no defects; every live framework-on run writes it.
    """
    results_path = bundle_dir / _RESULTS
    if not results_path.is_file():
        return []
    results = _load_json_document(results_path, expected="JSON")
    if not isinstance(results, list):
        raise CompletenessError(f"{_RESULTS} must be a JSON array of phase results.")
    by_seq = {
        parsed.record.get("seq"): parsed.record
        for parsed in read_chain(bundle_dir / _CHAIN)
        if isinstance(parsed.record, dict) and not is_run_start(parsed.record)
    }
    defects: list[str] = []
    for entry in results:
        actions = entry.get("actions") if isinstance(entry, dict) else None
        for action in actions or []:
            if not isinstance(action, dict) or action.get("kind") != "action":
                continue
            if action.get("decided") is not True:
                continue
            seq = action.get("audit_seq")
            where = f"{entry.get('phase')}/{entry.get('role_id')} audit_seq={seq!r}"
            record = by_seq.get(seq)
            if record is None:
                defects.append(f"{where} has no decision in {_CHAIN}")
                continue
            ours, theirs = action.get("request_id"), record.get("request_id")
            if ours is not None and theirs is not None and ours != theirs:
                defects.append(
                    f"{where} names request_id {ours!r} but {_CHAIN} seq {seq} holds {theirs!r}"
                )
    return defects


def _verify_action_audit_join(bundle_dir: Path) -> None:
    """Refuse to seal when a decided action in ``results.json`` is absent from the audit chain."""
    defects = _unjoined_decided_actions(bundle_dir)
    if defects:
        raise CompletenessError(
            f"{len(defects)} Guardian-decided action(s) in {_RESULTS} do not join {_CHAIN} "
            f"({'; '.join(defects[:3])}{'; ...' if len(defects) > 3 else ''}). The exported chain "
            "does not hold the decisions this run's agents received -- the signature of a Guardian "
            "redeployed for another run during this one. The bundle does not seal "
            "(data-management §3; ADR-077)."
        )


def _verify_spans_document(bundle_dir: Path) -> None:
    """Require the protocol's single JSON document with an object-only ``spans`` array."""
    path = bundle_dir / "spans.otel.json"
    document = _load_json_document(path, expected="JSON")
    if not isinstance(document, dict) or not isinstance(document.get("spans"), list):
        raise CompletenessError(
            "spans.otel.json must be one JSON object carrying a 'spans' array (data-management §1)."
        )
    if not document["spans"]:
        raise CompletenessError("spans.otel.json carries no spans; the bundle does not seal.")
    if not all(isinstance(span, dict) for span in document["spans"]):
        raise CompletenessError("spans.otel.json 'spans' entries must all be JSON objects.")
    phases = [span for span in document["spans"] if span.get("name") == "phase"]
    expected = {
        "detection-and-investigation",
        "containment",
        "eradication",
        "verified-recovery",
    }
    actual = [span.get("attributes", {}).get("phase") for span in phases]
    if len(phases) != len(expected) or set(actual) != expected:
        raise CompletenessError("spans.otel.json must carry exactly one span for each phase.")
    for span in phases:
        start = span.get("startTimeUnixNano")
        end = span.get("endTimeUnixNano")
        duration = span.get("duration_ms")
        if not isinstance(start, int) or isinstance(start, bool) or start <= 0:
            raise CompletenessError("every phase span requires a positive startTimeUnixNano.")
        if not isinstance(end, int) or isinstance(end, bool) or end < start:
            raise CompletenessError("every phase span requires endTimeUnixNano >= its start.")
        if not isinstance(duration, int | float) or isinstance(duration, bool) or duration < 0:
            raise CompletenessError("every phase span requires a non-negative duration_ms.")


def _pre_seal_artifacts(bundle_dir: Path) -> dict[str, Path]:
    """Return every regular pre-seal artifact, keyed by stable relative POSIX path."""
    artifacts: dict[str, Path] = {}
    for path in sorted(bundle_dir.rglob("*")):
        if path.is_symlink():
            raise CompletenessError(
                f"bundle artifact {path} is a symlink; bundles must be self-contained"
            )
        if path.is_file() and path.name not in {_SEAL, _SCORES}:
            artifacts[path.relative_to(bundle_dir).as_posix()] = path
    return artifacts


def _content_hashes(bundle_dir: Path) -> dict[str, str]:
    """Hash every present regular artifact except ``seal.json`` and ``scores.json`` (§1)."""
    return {name: _sha256_file(path) for name, path in _pre_seal_artifacts(bundle_dir).items()}


def _write_fidelity_report(
    bundle_dir: Path, manifest: RunManifest, *, instrument_only: bool
) -> list[str]:
    """Evaluate the fidelity registry over this bundle, write ``fidelity.json``, and return the
    class-T failures.

    Called from :func:`seal_bundle` between the manifest write and the content hashes, so the report
    is
    INSIDE the seal. The return value is what ``runner/campaign_cli.py`` and ``runner/run.py`` read:
    a sealed bundle whose T checks failed is a complete, consistent, correctly sealed run that
    measured
    the wrong thing, and the halt is raised by the caller rather than by the sealer -- the sealer's
    whole job is to refuse a bundle that is not a run, and this one is.

    The digest the report carries is the manifest's own ``instrument_digest`` (data-management §2's
    M10 field), because a bundle records the instrument that produced it and re-hashing the tree now
    would report whatever the tree has become since.

    The import is inside the function for the same reason ``validate_bundle``'s is: the fidelity
    package imports the Guardian's audit verifier, the scenario pools and the Monitor's source
    registry, and a seal must not fail to start because one of those is unavailable -- it must fail
    with a ``SealError`` naming what it could not read, which is what the ``except`` below does.
    """
    from runner.fidelity import evaluate_bundle, t_failures, write_fidelity_report

    try:
        report = evaluate_bundle(
            bundle_dir,
            campaign_dir=bundle_dir.parent,
            instrument_digest=manifest.instrument_digest,
        )
    except Exception as error:  # noqa: BLE001 - a gate that cannot run must not seal silently
        raise CompletenessError(
            f"the treatment-fidelity gate could not be evaluated for this bundle: "
            f"{type(error).__name__}: {error}. A bundle whose fidelity is unassessed is not a run "
            "whose treatment is unknown (P1, ADR-120)."
        ) from error
    write_fidelity_report(bundle_dir, report)
    from dataclasses import replace

    manifest = replace(manifest, fidelity_summary=report.summary())
    _atomic_write(bundle_dir / _MANIFEST, to_canonical_bytes(manifest) + b"\n")
    failures = t_failures(report)
    if instrument_only and failures:
        # A probe is not evidence of anything if its instrument was wrong: a P0-live probe whose
        # quoting or epoch treatment failed proved nothing about the quoting or the epoch, and
        # recording it as a passed probe would corrupt the very evidence the stage exists to gather.
        # A framework-on bundle is NOT refused -- see the module docstring.
        raise CompletenessError(
            f"this instrument-only probe carries {len(failures)} class-T fidelity failure(s) "
            f"({', '.join(f.id for f in failures)}); a probe whose instrument was wrong is not "
            "evidence about the instrument (P1, ADR-120)."
        )
    return [f"{f.id}: {f.detail}" for f in failures]


def seal_bundle(
    bundle_dir: Path,
    manifest: RunManifest,
    *,
    sealed_at: str | None = None,
    instrument_only: bool = False,
    publish_audit_anchor: bool = False,
) -> list[str]:
    """Sanitise, check completeness, verify the chain, evaluate fidelity, and write the seal.

    ``manifest.is_baseline`` selects the framework-on or baseline completeness profile;
    ``instrument_only`` selects the probe profile (data-management §3) and is the P0-live
    ``--instrument-only`` mode. The two are mutually exclusive and the boundary refuses a call that
    sets
    both rather than letting one win silently.

    For every framework-on run the expected injection count is derived directly from the frozen
    scenario contract. ``sealed_at`` is the one wall-clock value and is injectable so a test can
    seal
    deterministically.

    Returns the bundle's class-T fidelity failures, which is EMPTY for a healthy run. The return
    value
    exists because the plan's row for this function is explicit that a treatment failure must not
    stop
    the seal: a complete, consistent bundle whose G3 arm ran quoted is exactly the bundle a
    researcher
    has to be able to open, and it is a run the campaign must HALT on. Callers that do not care
    ignore
    it; ``runner/run.py`` puts it on the outcome and ``runner/campaign_cli.py`` raises
    :class:`~runner.campaign_cli.CampaignHaltError`.

    Raises :class:`CompletenessError` or :class:`SanitizationError` (both :class:`SealError`) on any
    completeness, chain, fidelity-evaluation or sanitiser failure, naming the offending file, secret
    or
    check.
    """
    bundle_dir = Path(bundle_dir)
    if not bundle_dir.is_dir():
        raise CompletenessError(f"bundle directory {bundle_dir} does not exist")
    if instrument_only and manifest.is_baseline:
        raise CompletenessError(
            "instrument_only is a probe-profile flag and cannot apply to a baseline: a baseline "
            "ran "
            "no framework, so there is nothing to probe (data-management §3)."
        )

    # Validate the complete manifest at the seal boundary, then publish its canonical bytes. Import
    # lazily to keep bundle/validate module initialization acyclic.
    from runner.validate import ValidationError, validate_bundle

    try:
        validate_bundle(manifest)
    except ValidationError as error:
        raise CompletenessError(f"manifest.json is invalid at seal: {error}") from error
    _atomic_write(bundle_dir / _MANIFEST, to_canonical_bytes(manifest) + b"\n")

    from runner.provenance import LIVE_PROVENANCE_FILE

    (bundle_dir / LIVE_PROVENANCE_FILE).unlink(missing_ok=True)

    sanitize_bundle(bundle_dir)
    _scan_bundle(bundle_dir)

    if manifest.is_baseline:
        _require_present(bundle_dir, _BASELINE_REQUIRED)
        _require_absent(bundle_dir, _BASELINE_FORBIDDEN)
        _verify_restarts_total(bundle_dir)
        chain_head: str | None = None
    elif instrument_only:
        # The probe profile (data-management §3). It shares the sanitiser, the restarts check and
        # the
        # hash set with the framework-on path and differs ONLY in which files must be there and
        # which
        # must not: the probe ran the scenario and the evidence path and no agent graph, so it has
        # no
        # Guardian chain to verify and no assertions to contract-check, and REQUIRING either would
        # force a probe to fabricate them.
        _require_present(bundle_dir, _PROBE_REQUIRED)
        _require_absent(bundle_dir, _PROBE_FORBIDDEN)
        _verify_restarts_total(bundle_dir)
        chain_head = _verify_audit_chain_if_present(bundle_dir)
    else:
        _require_present(bundle_dir, _FRAMEWORK_ON_REQUIRED)
        _verify_llm_call_accounting(
            bundle_dir, manifest.model_alias or "", manifest.model_provider_string or ""
        )
        _verify_restarts_total(bundle_dir)
        from runner.assertions import AssertionContractError, load_and_validate_assertion_results

        try:
            load_and_validate_assertion_results(
                bundle_dir / "assertions.json",
                run_id=manifest.run_id,
                scenario_id=manifest.scenario_id or "",
                injection_condition=manifest.injection_condition or "",
            )
        except AssertionContractError as error:
            raise CompletenessError(
                f"assertions.json is incomplete or invalid: {error}; the bundle does not seal "
                "(data-management §3)."
            ) from error
        _verify_spans_document(bundle_dir)
        chain_head = _verify_audit_chain(bundle_dir)
        _verify_action_audit_join(bundle_dir)
        _verify_blocked_requests_metric(bundle_dir)
        from scenarios.attackers.plan import expected_event_count, load_manifest

        try:
            scenario = load_manifest(manifest.scenario_id or "")
            contract_count = expected_event_count(scenario, manifest.injection_condition or "")
        except Exception as error:
            raise CompletenessError(
                f"cannot derive injection count from scenario contract: {error}"
            ) from error
        actual = _injection_line_count(bundle_dir)
        if actual != contract_count:
            raise CompletenessError(
                f"{_INJECTION} has {actual} event(s) but the scenario ground truth declares "
                f"{contract_count}; the bundle does not seal (data-management §3)."
            )

    # The injection count for a probe, which runs the same scenario contract with no agent graph.
    if instrument_only:
        from scenarios.attackers.plan import expected_event_count, load_manifest

        try:
            scenario = load_manifest(manifest.scenario_id or "")
            contract_count = expected_event_count(scenario, manifest.injection_condition or "")
        except Exception as error:
            raise CompletenessError(
                f"cannot derive injection count from scenario contract: {error}"
            ) from error
        actual = _injection_line_count(bundle_dir)
        if actual != contract_count:
            raise CompletenessError(
                f"{_INJECTION} has {actual} event(s) but the scenario ground truth declares "
                f"{contract_count}; a probe runs the same scenario, so the same count binds "
                "(data-management §3)."
            )

    # ADR-178: publish before F-GD-01 reads the external ledger. Offline callers leave
    # this opt-in unset; baselines and chain-free probes have no anchor.
    if publish_audit_anchor and chain_head is not None:
        _publish_audit_anchor(bundle_dir, chain_head)

    # BEFORE the hashes, so the report is covered by the seal (see the module docstring). A baseline
    # ran no framework and has no treatment to assess: `runner/validity.py::_fidelity_findings`
    # skips
    # it, and the baseline completeness profile (`_BASELINE_REQUIRED`) lists no `fidelity.json`. So
    # a
    # baseline is not given one -- writing it would be an artefact the profile does not carry, and
    # the
    # instrument-digest fallback (`_tree_digest`) would shell out to git, which an offline baseline
    # must not do (test_offline_baseline_skips_make_status).
    if manifest.is_baseline:
        fidelity_failures: list[str] = []
    else:
        fidelity_failures = _write_fidelity_report(
            bundle_dir, manifest, instrument_only=instrument_only
        )

    seal = {
        SEAL_HEAD_KEY: chain_head,
        "content_hashes": _content_hashes(bundle_dir),
        "sealed_at": sealed_at if sealed_at is not None else _iso_now(),
    }
    if instrument_only:
        seal["instrument_only"] = True
    _atomic_write(bundle_dir / _SEAL, canonical_json_bytes(seal) + b"\n")
    return fidelity_failures


def _publish_audit_anchor(bundle_dir: Path, head: str) -> None:
    root = Path(__file__).resolve().parents[1]
    try:
        result = subprocess.run(  # noqa: S603 - fixed script, argv only; no shell interpolation
            [  # noqa: S607 - POSIX sh is required on the live Linux runner
                "sh",
                str(root / "scripts/audit_seal_anchor.sh"),
                str(bundle_dir.resolve()),
                "--verified-head",
                head,
            ],
            cwd=root,
            env={**os.environ, "PYTHON": sys.executable},
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        raise CompletenessError(f"audit anchor publication could not start: {error}") from error
    if result.returncode:
        raise CompletenessError(
            f"audit anchor publication failed: {result.stderr.strip() or result.stdout.strip()}"
        )


def _verify_audit_chain_if_present(bundle_dir: Path) -> str | None:
    """Verify ``guardian_audit.jsonl`` when the probe wrote one, else ``None``.

    A probe runs the Guardian's own enforcement in some P0-live cases and not in others, so the
    chain
    is conditional: present is verified in full (an unverifiable chain is a CompletenessError,
    exactly
    as on the framework-on path), absent is a ``None`` head. What the chain is NEVER allowed to be
    is
    present and unverified, because that is the ADR-077 shape -- a bundle holding a chain it cannot
    vouch for.
    """
    path = bundle_dir / _CHAIN
    if not path.is_file():
        return None
    return _verify_audit_chain(bundle_dir)


def append_scoring_entry(
    bundle_dir: Path,
    scores_path: Path,
    *,
    scored_at: str | None = None,
) -> None:
    """Append ``scores.json``'s hash to a sealed bundle's ``seal.json`` as a post-seal entry.

    A separate operation from sealing: it adds one ``"scoring"`` key and leaves ``content_hashes``
    and the chain head untouched, so the original hashes stay verifiable
    (:func:`verify_content_hashes`). ``scored_at`` is injectable for the same reason ``sealed_at``
    is.
    """
    bundle_dir = Path(bundle_dir)
    scores_path = Path(scores_path)
    seal_path = bundle_dir / _SEAL
    if not seal_path.is_file():
        raise SealError(
            "cannot append a scoring entry to a bundle that has not been sealed "
            f"({seal_path} is absent)"
        )
    if not scores_path.is_file():
        raise SealError(f"scores file {scores_path} does not exist")

    try:
        seal = json.loads(seal_path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SealError(f"cannot update malformed seal {seal_path}: {error}") from error
    if not isinstance(seal, dict):
        raise SealError(f"cannot update malformed seal {seal_path}: expected a JSON object")
    seal["scoring"] = {
        _SCORES: _sha256_file(scores_path),
        "scored_at": scored_at if scored_at is not None else _iso_now(),
    }
    _atomic_write(seal_path, canonical_json_bytes(seal) + b"\n")


def load_seal(bundle_dir: Path) -> dict:
    """Load a bundle's ``seal.json`` as a dict, so callers need not restate the path."""
    return json.loads((Path(bundle_dir) / _SEAL).read_bytes().decode("utf-8"))


def _is_probe_bundle(manifest: RunManifest, bundle_dir: Path) -> bool:
    """Read the explicit seal-time profile; missing agent files never select a profile."""
    return not manifest.is_baseline and load_seal(bundle_dir).get("instrument_only") is True


def _fidelity_defects(bundle_dir: Path, manifest: RunManifest) -> list[str]:
    """DEPRECATED PLACEMENT -- kept only to name the move; see :mod:`runner.validity`.

    A class-T fidelity failure makes a bundle invalid for the ANALYSED SET, which is data-management
    §4's business and ``runner/validity.py::check_run_validity``'s. It is deliberately NOT checked
    here: ``verify_bundle_seal`` is the integrity predicate every validator and every resume path
    calls, and a treatment failure reported from it would arrive as a "bundle-integrity" defect --
    indistinguishable, to every caller, from a corrupted bundle, and actionable in exactly the wrong
    way (discard and rerun, which is the response a treatment failure must never get).
    """
    del bundle_dir, manifest
    return []


def verify_bundle_seal(bundle_dir: Path) -> list[str]:
    """Return integrity defects for a purportedly sealed bundle; an empty list means valid.

    This is the shared predicate used by corpus validation and campaign resume. It validates the
    full manifest, applies the manifest-selected completeness profile, verifies every recorded
    content hash, and anchors a framework-on audit chain to the head stored in ``seal.json``.
    """
    bundle_dir = Path(bundle_dir)
    defects: list[str] = []
    try:
        seal = load_seal(bundle_dir)
    except (OSError, ValueError, TypeError) as error:
        return [f"seal.json is absent or malformed: {error}"]
    if not isinstance(seal, dict):
        return ["seal.json must be a JSON object"]
    if "instrument_only" in seal and seal["instrument_only"] is not True:
        defects.append("seal.json instrument_only must be true when present")
    hashes = seal.get("content_hashes")
    if not isinstance(hashes, dict) or not hashes:
        defects.append("seal.json content_hashes must be a non-empty object")
    elif not all(
        isinstance(name, str) and isinstance(digest, str) for name, digest in hashes.items()
    ):
        defects.append("seal.json content_hashes must map file names to sha256 strings")
    else:
        try:
            actual_names = set(_pre_seal_artifacts(bundle_dir))
        except CompletenessError as error:
            defects.append(str(error))
        else:
            recorded_names = set(hashes)
            if recorded_names != actual_names:
                defects.append(
                    "seal.json content_hashes keys do not exactly cover pre-seal artifacts "
                    f"(missing={sorted(actual_names - recorded_names)}, "
                    f"extra={sorted(recorded_names - actual_names)})"
                )
        defects.extend(
            f"content hash mismatch: {name}" for name in verify_content_hashes(bundle_dir)
        )

    manifest_path = bundle_dir / _MANIFEST
    try:
        from runner.manifest import from_dict as manifest_from_dict
        from runner.validate import ValidationError, validate_bundle

        payload = json.loads(manifest_path.read_bytes().decode("utf-8"))
        manifest = manifest_from_dict(payload)
        validate_bundle(manifest)
        if manifest.is_baseline and seal.get("instrument_only") is True:
            defects.append("a baseline cannot carry the instrument-only probe profile")
    except (OSError, ValueError, TypeError, ValidationError) as error:
        defects.append(f"manifest.json is absent or invalid: {error}")
        return defects

    try:
        if manifest.is_baseline:
            _require_present(bundle_dir, _BASELINE_REQUIRED)
            _require_absent(bundle_dir, _BASELINE_FORBIDDEN)
            if seal.get(SEAL_HEAD_KEY) is not None:
                defects.append("baseline seal must carry a null audit_chain_head")
        elif _is_probe_bundle(manifest, bundle_dir):
            # The explicit seal marker selects the existing probe completeness profile.
            _require_present(bundle_dir, _PROBE_REQUIRED)
            _require_absent(bundle_dir, _PROBE_FORBIDDEN)
            head = _verify_audit_chain_if_present(bundle_dir)
            if head != seal.get(SEAL_HEAD_KEY):
                defects.append("probe audit chain head disagrees with seal.json")
        else:
            _require_present(bundle_dir, _FRAMEWORK_ON_REQUIRED)
            from runner.assertions import (
                AssertionContractError,
                load_and_validate_assertion_results,
            )

            try:
                load_and_validate_assertion_results(
                    bundle_dir / "assertions.json",
                    run_id=manifest.run_id,
                    scenario_id=manifest.scenario_id or "",
                    injection_condition=manifest.injection_condition or "",
                )
            except AssertionContractError as error:
                defects.append(f"assertions.json is incomplete or invalid: {error}")
            expected_head = seal.get(SEAL_HEAD_KEY)
            if not isinstance(expected_head, str):
                defects.append("framework-on seal must carry an audit_chain_head")
            else:
                chain_path = bundle_dir / _CHAIN
                report = verify_chain(
                    read_chain(chain_path),
                    expected_head=expected_head,
                    path=str(chain_path),
                    anchor_source=str(bundle_dir / _SEAL),
                )
                if not report.ok:
                    defects.append(f"guardian audit chain invalid: {report.diagnosis}")
            defects.extend(
                f"results.json does not join the audit chain: {defect}"
                for defect in _unjoined_decided_actions(bundle_dir)
            )
    except (OSError, ValueError, CompletenessError) as error:
        defects.append(str(error))

    scoring = seal.get("scoring")
    if scoring is not None:
        expected = scoring.get(_SCORES) if isinstance(scoring, dict) else None
        scores_path = bundle_dir / _SCORES
        if not isinstance(expected, str) or not scores_path.is_file():
            defects.append("scoring entry is malformed or scores.json is absent")
        elif _sha256_file(scores_path) != expected:
            defects.append("content hash mismatch: scores.json")
    return defects


def verify_content_hashes(bundle_dir: Path) -> list[str]:
    """Re-hash every file ``seal.json`` records and return the names that no longer match.

    An empty list is a verified bundle. A file that has gone missing counts as a mismatch. This is
    what the ``append_scoring_entry`` test uses to prove the pre-scoring hashes survive an append.
    """
    bundle_dir = Path(bundle_dir)
    recorded = load_seal(bundle_dir).get("content_hashes", {})
    mismatches = [
        name
        for name, expected in recorded.items()
        if not (bundle_dir / name).is_file() or _sha256_file(bundle_dir / name) != expected
    ]
    return sorted(mismatches)
