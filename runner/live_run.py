"""Live framework-on run composition over M1, M4, and M5 production seams.

The composition is dependency-injectable, so its ordering and evidence contract are testable
without a cluster. Defaults use the M5 KubectlClusterAdapter, M4 golden driver, and M1 instruments.
collectors.  Runtime-owned Monitor and Guardian-audit files are copied from explicit producer
paths; they are never synthesized or guessed.  Where the live producer's output is not already a
single runner-readable file -- the aggregator writes one fragment per ingested request, and the
Guardian keeps its audit log inside its own pod -- ``runner/live_evidence.py`` collates or extracts
it first, and that module's docstring records why each is done the way it is.
``assertions.json`` has no external producer and is evaluated here by
``runner/evaluate_assertions.py`` against the scenario's M5 ground truth and the
live cluster end state, which is what data-management.md section 3 means by "the runner writes it
at run end, before seal".
"""

from __future__ import annotations

import base64
import importlib
import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Protocol

from agents.golden import registered_issuers, run_golden
from agents.graphs import CONDITION_MODULES
from agents.registry.loader import load_registry
from agents.registry.model import RUNNER_SCRIPTED_ENV_VAR, ScriptedClient
from agents.scripts import (
    SCALE_RESOURCE,
    SCALE_VERB,
    ArmExtension,
    direct_path_call,
    scale_to_zero_call,
    script_for,
)
from infra.locust.driver import LocustDriver
from monitor.aggregator.emit import EVENTS_FILENAME
from scenarios.attackers.apply import (
    ClusterAdapter,
    DirectoryInjectionChannels,
    KubectlClusterAdapter,
    apply_plan,
    publish_log,
)
from scenarios.attackers.plan import expected_event_count, load_manifest, plan_cell

from runner.campaign import PlannedRun
from runner.conditions import ConditionFlags, flags_for
from runner.egress_shim import (
    G2_TRANSPORT_FLAG_ENV,
    KUBE_TOKEN_FILE_ENV,
    PermitFlags,
    shim_for_run,
)
from runner.evaluate_assertions import KubectlStateReader, live_assertion_evaluator
from runner.live_baseline import (
    DEFAULT_FRONTEND_URL,
    MeasurementWindow,
    probe_writer,
    resource_writer,
)
from runner.live_evidence import (
    DRAIN_FIELD,
    EPOCH_DROPS_FIELD,
    EPOCH_DROPS_FILENAME,
    GUARDIAN_AUDIT_ROOT,
    TIMINGS_FILENAME,
    EvidenceProductionError,
    api_audit_offset,
    attempt_suffix,
    begin_monitor_window,
    close_monitor_window,
    collate_monitor_events,
    collect_api_audit,
    extract_guardian_audit,
    forwarder_drain_seconds,
    guardian_audit_chain_path,
    write_api_audit_sentinel,
)
from runner.provenance import LIVE_PROVENANCE_FILE

REPO_ROOT = Path(__file__).resolve().parents[1]


class LiveRunError(RuntimeError):
    """Live composition or one of its real producers is unavailable or failed."""


# The audit forwarder polls its append-only source about once a second and the aggregator writes one
# fragment per accepted POST, both asynchronously in their own pods. After the injection is applied
# the runner waits this long before it scales those two deployments down and detaches the event tree
# (ADR-054's close boundary), so the just-appended run-period records are forwarded and written into
# the tree THIS window will collate, rather than the next window's. This is an OPERATIONAL timing
# constant, not an evaluation-protocol number: exactly like the bring-up waits in scripts/up.sh
# ("THE TIMEOUTS ARE OPERATIONAL, NOT PROTOCOL CONSTANTS"), no measurement, bundle field or analysis
# depends on its value -- it changes only how much slack the drain is given -- so
# docs/protocols/evaluation-protocol.md does not own it (ADR-063). The 15s default covers the ~1s
# poll plus the per-record POST-and-write time even on the slow /mnt/c 9p mount up.sh warns about;
# MONITOR_EVIDENCE_DRAIN_SECONDS overrides it for other host profiles.
MONITOR_EVIDENCE_DRAIN_SECONDS_ENV: Final = "MONITOR_EVIDENCE_DRAIN_SECONDS"
DEFAULT_MONITOR_EVIDENCE_DRAIN_SECONDS: Final = 15.0


def monitor_drain_seconds(environ: Mapping[str, str]) -> float:
    """Resolve the operational drain settle (see the module constant); fail closed on junk."""
    raw = environ.get(MONITOR_EVIDENCE_DRAIN_SECONDS_ENV)
    if raw is None or not raw.strip():
        return DEFAULT_MONITOR_EVIDENCE_DRAIN_SECONDS
    try:
        seconds = float(raw)
    except ValueError:
        raise LiveRunError(
            f"{MONITOR_EVIDENCE_DRAIN_SECONDS_ENV} must be a number of seconds, not {raw!r}"
        ) from None
    if seconds < 0:
        raise LiveRunError(
            f"{MONITOR_EVIDENCE_DRAIN_SECONDS_ENV} must not be negative, got {seconds}"
        )
    return seconds


# ADR-128 (SEAM 6): the control-plane route and its body-schema version, held equal to
# guardian/app/main.py (PHASE_PATH, PHASE_DECLARATION_SCHEMA_VERSION) by
# runner/tests/test_live_run_control_plane.py rather than imported from it, so the runner process
# declares a phase without pulling in the Guardian app's web-framework dependencies.
_GUARDIAN_PHASE_PATH: Final = "/v1/phase"
_PHASE_DECLARATION_SCHEMA_VERSION: Final = "v1"
# The runner authenticates as the control plane with a projected ServiceAccount token it mints with
# `kubectl create token`. TTL and refresh are OPERATIONAL constants, not evaluation-protocol numbers
# (ADR-063's rule, exactly as MONITOR_EVIDENCE_DRAIN_SECONDS above): no measurement, bundle field or
# analysis reads them -- they change only how often the runner re-mints. A run's four phases
# complete well inside an hour; the token is re-minted ten minutes before its TTL so a long campaign
# attempt never presents an expired bearer. Neither is the capability-token TTL security-policy §2
# owns; this is the runner's own identity to the Guardian, not a capability it issues.
_CONTROL_PLANE_TOKEN_TTL_SECONDS: Final = 3600
_CONTROL_PLANE_TOKEN_REFRESH_SECONDS: Final = 3000
_CONTROL_PLANE_TIMEOUT_SECONDS: Final = 10.0


def _control_plane_identity(environ: Mapping[str, str]) -> tuple[str, str, str]:
    """The ``(namespace, service_account, audience)`` the runner authenticates as (ADR-128, SEAM 6).

    Derived from the same ``GUARDIAN_CONTROL_PLANE_SUBJECT`` and ``GUARDIAN_CONTROL_PLANE_AUDIENCE``
    that ``scripts/guardian_deploy.sh`` forwards into the Guardian's configmap, so the identity the
    runner mints a token for is byte for byte the one the Guardian's TokenReview authenticates it
    against. Fails closed: the Guardian gates ``POST /v1/tokens`` and ``POST /v1/phase`` in every
    arm, so a runner that cannot name its control-plane identity is a run that could not mint or
    declare, and that is a named refusal here rather than a 401 mid-run.
    """
    subject = environ.get("GUARDIAN_CONTROL_PLANE_SUBJECT", "")
    audience = environ.get("GUARDIAN_CONTROL_PLANE_AUDIENCE", "")
    missing = [
        name
        for name, value in (
            ("GUARDIAN_CONTROL_PLANE_SUBJECT", subject),
            ("GUARDIAN_CONTROL_PLANE_AUDIENCE", audience),
        )
        if not value
    ]
    if missing:
        raise LiveRunError(
            "the control plane's identity is unset; set "
            + ", ".join(missing)
            + " (ADR-128). The Guardian gates POST /v1/tokens and POST /v1/phase in every arm, "
            "so a runner that cannot authenticate as the control plane cannot mint a token or "
            "declare a phase. scripts/live_env.sh defaults both."
        )
    parts = subject.split(":")
    if (
        len(parts) != 4
        or parts[0] != "system"
        or parts[1] != "serviceaccount"
        or not parts[2]
        or not parts[3]
    ):
        raise LiveRunError(
            f"GUARDIAN_CONTROL_PLANE_SUBJECT={subject!r} is not a ServiceAccount subject of the "
            "form system:serviceaccount:<namespace>:<name> (ADR-128)"
        )
    return parts[2], parts[3], audience


def _jwt_expiry(token: str) -> str | None:
    """A JWT bearer's own ``exp`` claim as an ISO-8601 UTC instant, or ``None``.

    The expiry is METADATA about a credential, not the credential: this reads the token's second
    segment, decodes it and returns the ``exp`` instant. It does NOT verify the signature -- the API
    server minted the token and is its only issuer, and the runner is not the verifier (the
    Guardian's TokenReview is). The token itself is never returned, logged or copied, and a
    malformed or absent claim degrades to ``None`` so a run records "not measured" instead of a
    fabricated instant.

    ``timespec="microseconds"`` is deliberate. F-GD-05 compares the recorded expiry to the run's
    ``ended_at`` as STRINGS, and that comparison is chronological only while both carry the same
    shape -- which is what ``runner/provenance._now`` writes for ``ended_at``. An integer ``exp``
    formatted without a fraction would sort BEFORE an ``ended_at`` in the same second, and F-GD-05
    would report a credential that was valid as expired.
    """
    parts = token.strip().split(".")
    if len(parts) < 2:
        return None
    payload = parts[1]
    try:
        decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        claims = json.loads(decoded)
    except (ValueError, UnicodeDecodeError):
        return None
    exp = claims.get("exp") if isinstance(claims, dict) else None
    if not isinstance(exp, int) or isinstance(exp, bool):
        return None
    try:
        return datetime.fromtimestamp(exp, UTC).isoformat(timespec="microseconds")
    except (OverflowError, OSError, ValueError):
        return None


def _control_plane_caller_auth(
    environ: Mapping[str, str], expiries: dict[str, str], *, bound_object: str
) -> Callable[[], Mapping[str, str]]:
    """A caller-auth header supplier that mints the runner's control-plane bearer on demand.

    SEAM 6 (ADR-128). :func:`run_golden` hands it to the :class:`GuardianClient`, so ``POST
    /v1/tokens`` carries the bearer, and :func:`_declare_phase_for` reuses it for ``POST
    /v1/phase``. The token is a projected ServiceAccount token minted with ``kubectl create token``
    for the audience the Guardian's TokenReview requires; it is cached, re-minted before expiry,
    held only in this closure, and never written to a bundle or handed to ``agents/``. The
    credential lives in the runner -- exactly where iron rule 10 keeps every cluster-reaching
    credential -- and the client and the graph receive an opaque callable, never a value. Identity
    is resolved on first use so building the dependencies stays offline-safe; the first
    control-plane call is what validates the env.

    ``expiries`` receives the bearer's own ``exp`` (data-management §2's
    ``control_plane_token_expiry``), captured before manifest time. The field has to
    be recorded when it exists. It is written on every mint, so a re-mint inside one run records the
    bearer the run actually ended holding.
    """
    cache: dict[str, Any] = {}

    def supply() -> Mapping[str, str]:
        identity = cache.get("identity")
        if identity is None:
            identity = _control_plane_identity(environ)
            cache["identity"] = identity
        namespace, service_account, audience = identity
        now = time.monotonic()
        bearer = cache.get("bearer")
        if bearer is None or bearer[1] <= now:
            token = _run_command_stdout(
                [
                    "kubectl",
                    "-n",
                    namespace,
                    "create",
                    "token",
                    service_account,
                    "--audience",
                    audience,
                    "--duration",
                    f"{_CONTROL_PLANE_TOKEN_TTL_SECONDS}s",
                    "--bound-object-kind=Secret",
                    f"--bound-object-name={bound_object}",
                ],
                environ=environ,
            ).strip()
            if not token:
                raise LiveRunError(
                    f"kubectl create token {service_account} -n {namespace} returned no token; the "
                    "runner cannot authenticate as the control plane (ADR-128)"
                )
            bearer = (token, now + _CONTROL_PLANE_TOKEN_REFRESH_SECONDS)
            cache["bearer"] = bearer
        expiry = _jwt_expiry(bearer[0])
        if expiry is not None:
            expiries["control_plane_token_expiry"] = expiry
        return {"Authorization": f"Bearer {bearer[0]}"}

    return supply


@contextmanager
def _control_plane_session(environ: Mapping[str, str], expiries: dict[str, str]):
    """One run's authenticated identity, revoked even when the graph fails."""
    namespace, _, _ = _control_plane_identity(environ)
    secret_name = f"runner-session-{attempt_suffix()}"
    try:
        _run_command(
            ["kubectl", "-n", namespace, "create", "secret", "generic", secret_name],
            environ=environ,
        )
        yield _control_plane_caller_auth(environ, expiries, bound_object=secret_name)
    finally:
        _run_command(
            ["kubectl", "-n", namespace, "delete", "secret", secret_name, "--ignore-not-found"],
            environ=environ,
        )


def _declare_phase_for(
    guardian_url: str, run_id: str, caller_auth: Callable[[], Mapping[str, str]]
) -> Callable[[str], None]:
    """The runner's phase-declaration callback for one run (SEAM 6, ADR-128).

    ``agents.graphs.plan.run_plan`` calls it at each phase change; it POSTs the run's new phase to
    ``POST /v1/phase`` with the control-plane bearer, so the Guardian bounds the next mint's
    issuance to the phase the run is actually in (V1: v1 never declared a phase, so issuance was
    bounded by whatever phase the token body named -- agent-declared, unauthenticated). ``agents/``
    holds neither the credential nor the transport: this callable is the whole of the phase channel,
    and it lives in the runner. A declaration the Guardian refuses fails the run closed rather than
    proceeding on a stale phase.
    """
    endpoint = f"{guardian_url.rstrip('/')}{_GUARDIAN_PHASE_PATH}"

    def declare(phase: str) -> None:
        body = json.dumps(
            {
                "run_id": run_id,
                "phase": phase,
                "schema_version": _PHASE_DECLARATION_SCHEMA_VERSION,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        headers = {"Content-Type": "application/json", **caller_auth()}
        request = urllib.request.Request(  # noqa: S310 - fixed http(s) endpoint from run config
            endpoint, data=body, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(  # noqa: S310 - same
                request, timeout=_CONTROL_PLANE_TIMEOUT_SECONDS
            ) as response:
                response.read()
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", "replace").strip()
            raise LiveRunError(
                f"declaring phase {phase!r} for {run_id} failed: HTTP {error.code} {detail}"
            ) from None
        except urllib.error.URLError as error:
            raise LiveRunError(
                f"declaring phase {phase!r} for {run_id} failed: {error.reason}"
            ) from None

    return declare


class AgentDriver(Protocol):
    def __call__(
        self, *, guardian_url: str, bundle_dir: Path, planned: PlannedRun, namespace: str
    ) -> None: ...


class ArtifactExporter(Protocol):
    def __call__(self, bundle_dir: Path, planned: PlannedRun) -> None: ...


ConditionApplier = Callable[[ConditionFlags, PlannedRun], None]
ConditionReset = Callable[[ConditionFlags, PlannedRun], None]
ScenarioDriver = Callable[..., object]


@dataclass(frozen=True)
class LiveRunDependencies:
    cluster: ClusterAdapter
    apply_condition: ConditionApplier
    reset_condition: ConditionReset
    drive_agents: AgentDriver
    export_monitor: ArtifactExporter
    export_audit: ArtifactExporter
    evaluate_assertions: ArtifactExporter
    probe: Callable[[Path, MeasurementWindow], int]
    resources: Callable[[Path, MeasurementWindow], int]
    locust: LocustDriver
    # ADR-137 (SEAM: API-server audit slice). open_api_audit records the audit-log byte offset and
    # writes the window-open sentinel when the measurement window opens; export_api_audit writes the
    # window-close sentinel and slices from that offset into k8s_api_audit.jsonl. Both run in probe
    # mode too, where the slice is required but no agent graph does. Defaulted to no-ops so a test
    # or fixture caller that assembles dependencies by hand is unchanged until it opts in.
    open_api_audit: Callable[[PlannedRun], None] = lambda planned: None
    export_api_audit: ArtifactExporter = lambda bundle_dir, planned: None
    scenario_driver: ScenarioDriver = apply_plan
    # data-management §2's two credential expiries, relayed from mint time to the manifest.
    #
    # Both bearers are gone by the time `runner/run.py` builds the manifest -- the control-plane one
    # lives only in a closure, and the G2 one in a private file that `reset` deletes -- so the mint
    # writes its own JWT `exp` claim here and `execute_live_run` relays it into the bundle, where
    # `runner/provenance.build_run_manifest` folds it into the manifest (ADR-156, ADR-157). A shared
    # mutable, like `evidence_windows` and `audit_chains` above: the applier clears it at the top of
    # every run, so a run that mints no credential of a given kind records `None` rather than the
    # previous run's instant. Defaulted to an empty dict so a hand-assembled dependency set is
    # unchanged until it opts in.
    credential_expiries: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class _GuardianAuditSource:
    """Which pod holds the Guardian's audit chains, and who reads them.

    No path: each attempt's chain is named when the condition is applied (ADR-058) and reaches the
    exporter through the runner's own record of it, so there is nothing here to derive one from.
    """

    namespace: str
    workload: str
    container: str
    kubeconfig: str | None
    context: str | None


def _copy_export(source: Path, filename: str) -> ArtifactExporter:
    def export(bundle_dir: Path, planned: PlannedRun) -> None:
        del planned
        if not source.is_file():
            raise LiveRunError(f"live producer output is unavailable: {source}")
        shutil.copyfile(source, bundle_dir / filename)

    return export


def _monitor_export(
    source: Path,
    events_root: Path | None,
    windows: dict[str, datetime],
    *,
    drain_seconds: float = DEFAULT_MONITOR_EVIDENCE_DRAIN_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
) -> ArtifactExporter:
    """Collate the live aggregator's per-transaction fragments, then copy the one stream.

    The live aggregator is content-addressed per request, so a run's Monitor evidence is a tree of
    ``monitor_events.jsonl`` fragments rather than the single stream every bundle carries; see
    ``runner/live_evidence.py`` for the layout and for why the collation re-imposes ADR-019's
    emission order instead of concatenating. ``events_root`` of ``None`` means no collation was
    configured and ``MONITOR_EVENTS_PATH`` is expected to already be that single stream -- the
    replay and fixture paths, which produce one file directly.

    ``drain_seconds`` is the operational settle held before the aggregator and forwarder are
    quiesced (see :data:`MONITOR_EVIDENCE_DRAIN_SECONDS_ENV`); ``sleep`` is injectable so the
    ordering can be asserted without waiting.
    """
    copy = _copy_export(source, "monitor_events.jsonl")

    def export(bundle_dir: Path, planned: PlannedRun) -> None:
        if events_root is not None:
            try:
                # Drain before quiescing. The scenario driver applies the injection before it calls
                # this (apply_plan runs before_teardown after the last event), but the forwarder's
                # ~1s poll and the aggregator's per-request write are asynchronous, so the run's own
                # records may not have landed in events_root yet. Settling here -- BEFORE the
                # scale-to-0 below -- lets them reach the tree this window collates rather than the
                # next window's, the SCN-SIM-02 0-byte defect ADR-063 fixes. Operational timing
                # only; see the module constant.
                sleep(drain_seconds)
                _run_command(
                    [
                        "kubectl",
                        "-n",
                        "monitor",
                        "scale",
                        "deployment",
                        "evidence-aggregator",
                        "audit-forwarder",
                        "--replicas=0",
                    ]
                )
                _run_command(
                    [
                        "kubectl",
                        "-n",
                        "monitor",
                        "wait",
                        "--for=delete",
                        "pod",
                        "-l",
                        "app.kubernetes.io/name=evidence-aggregator",
                        "--timeout=120s",
                    ]
                )
                _run_command(
                    [
                        "kubectl",
                        "-n",
                        "monitor",
                        "wait",
                        "--for=delete",
                        "pod",
                        "-l",
                        "app.kubernetes.io/name=audit-forwarder",
                        "--timeout=120s",
                    ]
                )
                closed_root = close_monitor_window(events_root, planned.run_id)
                _run_command(
                    [
                        "kubectl",
                        "-n",
                        "monitor",
                        "scale",
                        "deployment",
                        "evidence-aggregator",
                        "audit-forwarder",
                        "--replicas=1",
                    ]
                )
                _run_command(
                    [
                        "kubectl",
                        "-n",
                        "monitor",
                        "rollout",
                        "status",
                        "deployment/evidence-aggregator",
                    ]
                )
                _run_command(
                    ["kubectl", "-n", "monitor", "rollout", "status", "deployment/audit-forwarder"]
                )
                started = time.perf_counter()
                # ADR-124: pass this run's id as the required epoch, so a stale-epoch redelivery is
                # dropped from the stream and its count recorded (SEAM 4). The count lands in
                # a sidecar beside `source`, which is relayed into the bundle below and folded into
                # metrics.json at run end (where F-MN-02 reads it).
                collate_monitor_events(
                    closed_root,
                    source,
                    started_at=windows[planned.run_id],
                    required_epoch=planned.run_id,
                )
                print(
                    f"live-evidence: {planned.run_id} Monitor collation "
                    f"{time.perf_counter() - started:.6f}s"
                )
            except EvidenceProductionError as error:
                raise LiveRunError(str(error)) from None
        copy(bundle_dir, planned)
        timings = source.with_name("monitor_timings.jsonl")
        if not timings.is_file():
            raise LiveRunError(f"live producer output is unavailable: {timings}")
        shutil.copyfile(timings, bundle_dir / timings.name)
        if events_root is not None:
            # Relay the epoch-drop count into the bundle (a temporary sidecar execute_live_run folds
            # into metrics.json and removes). Only on the collating path -- the replay and fixture
            # paths write no epoch sidecar, so they gain no new artefact.
            drops_sidecar = source.with_name(EPOCH_DROPS_FILENAME)
            if drops_sidecar.is_file():
                shutil.copyfile(drops_sidecar, bundle_dir / EPOCH_DROPS_FILENAME)

    return export


def _audit_export(
    source: Path, remote: _GuardianAuditSource | None, audit_chains: Mapping[str, str]
) -> ArtifactExporter:
    """Read this attempt's Guardian audit chain out of its pod, then copy it.

    ``remote`` of ``None`` means ``GUARDIAN_AUDIT_PATH`` is already readable by the runner. When it
    is set, the log is extracted with the operator's own kubeconfig and never with any credential
    belonging to the Guardian (``.agents/rules/10-guardian-first.md``) -- and from exactly the path
    the condition applier handed this attempt's Guardian, recorded in ``audit_chains``. There is no
    fallback to a path derived from the run id: a retry of one canonical run id runs its Guardian
    on a second, attempt-unique chain (ADR-058), and reading anything else would copy another
    attempt's evidence into this bundle.
    """
    copy = _copy_export(source, "guardian_audit.jsonl")

    def export(bundle_dir: Path, planned: PlannedRun) -> None:
        if remote is not None:
            remote_path = audit_chains.get(planned.run_id)
            if remote_path is None:
                raise LiveRunError(
                    f"no Guardian audit chain was recorded for {planned.run_id}: the condition "
                    "applier names each attempt's chain, and there is no other path to read"
                )
            try:
                extract_guardian_audit(
                    source,
                    namespace=remote.namespace,
                    workload=remote.workload,
                    container=remote.container,
                    remote_path=remote_path,
                    kubeconfig=remote.kubeconfig,
                    context=remote.context,
                )
            except EvidenceProductionError as error:
                raise LiveRunError(str(error)) from None
        copy(bundle_dir, planned)

    return export


def _run_command(argv: list[str], *, environ: Mapping[str, str] | None = None) -> None:
    result = subprocess.run(  # noqa: S603 - argv only, no shell
        argv,
        cwd=REPO_ROOT,
        env=None if environ is None else dict(environ),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise LiveRunError(f"{' '.join(argv)} failed: {detail}")


def _run_command_stdout(argv: list[str], *, environ: Mapping[str, str] | None = None) -> str:
    """Like :func:`_run_command`, but returns captured stdout for the one command that reads it.

    The epoch/quoting confirmation (ADR-124, SEAM 4) is the only place the runner needs a command's
    OUTPUT rather than only its exit status: a one-shot ``kubectl exec`` against the aggregator's
    ``/readyz``, whose JSON body the runner parses to prove the pod is serving THIS run before the
    window opens. A non-zero exit fails the run closed with the same shape :func:`_run_command`
    raises, so a broken exec never opens the window on an unconfirmed pod.
    """
    result = subprocess.run(  # noqa: S603 - argv only, no shell
        argv,
        cwd=REPO_ROOT,
        env=None if environ is None else dict(environ),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise LiveRunError(f"{' '.join(argv)} failed: {detail}")
    return result.stdout


def _confirm_monitor_config(
    run_id: str, quoting: bool, *, environ: Mapping[str, str] | None = None
) -> None:
    """Confirm the aggregator pod serves THIS run's epoch and quoting before the window opens.

    ADR-124 / SEAM 4. The aggregator Service is ClusterIP with no port forward, so the one
    way to read a running pod's live configuration is a one-shot ``kubectl exec`` against its own
    ``/readyz`` (``monitor/http_service.py`` reports ``{quoting, run_epoch}`` there for exactly this
    read). The window is opened only once both match this run -- the V2 defect opened a window on
    a pod still carrying the previous run's quoting, patched by a second rollout afterwards. A
    mismatch, or an unreadable ``/readyz``, fails the run closed rather than opening it on the wrong
    configuration.
    """
    raw = _run_command_stdout(
        [
            "kubectl",
            "-n",
            "monitor",
            "exec",
            "deployment/evidence-aggregator",
            "-c",
            "evidence-aggregator",
            "--",
            "python",
            "-c",
            "import urllib.request,sys;"
            "sys.stdout.write(urllib.request.urlopen('http://127.0.0.1:8080/readyz').read()"
            ".decode())",
        ],
        environ=environ,
    )
    try:
        reported = json.loads(raw)
    except json.JSONDecodeError as error:
        raise LiveRunError(
            f"aggregator /readyz did not return JSON before the window opened for {run_id}: {error}"
        ) from None
    reported_epoch = reported.get("run_epoch") if isinstance(reported, Mapping) else None
    reported_quoting = reported.get("quoting") if isinstance(reported, Mapping) else None
    if reported_epoch != run_id:
        raise LiveRunError(
            f"aggregator reports run epoch {reported_epoch!r}, not this run's {run_id!r}; the "
            "evidence window is not opened on a pod carrying another run's configuration (ADR-124)"
        )
    if reported_quoting != quoting:
        raise LiveRunError(
            f"aggregator reports quoting {reported_quoting!r}, not this run's {quoting!r}; the "
            "window is not opened until the aggregator's quoting mode is the arm's (ADR-124)"
        )


def _run_token_file(environ: Mapping[str, str], run_id: str) -> Path:
    """The private path this run's G2 bearer is written to (and the shim compares against).

    One derivation, shared by the applier that writes the token, the reset that removes it,
    and :func:`_cluster_api_transport_for` that names it in the permit -- so the path the shim
    permits is byte for byte the path the runner wrote. ``RUNNER_PRIVATE_DIR`` is the mode-700
    directory iron rule 10 keeps credentials in.
    """
    token_root = Path(environ.get("RUNNER_PRIVATE_DIR", REPO_ROOT / "runs" / ".private"))
    return token_root / f"{run_id}.token"


def _cluster_api_transport_for(
    environ: Mapping[str, str], planned: PlannedRun
) -> tuple[Any | None, tuple[str, ...]]:
    """The direct-path transport and the environment facts for one run (D1-A, ADR-131).

    G2-SHAREDCRED and nothing else: the runner writes a permit naming this run's own token path, the
    API server and the cluster CA, builds the egress shim from it (``runner/egress_shim.py``), and
    names the credential LOCATION -- never its value -- in the facts. Every other arm gets
    ``(None, ())``: the ``cluster_api_request`` handler in ``agents/`` then returns its structured
    no-transport refusal, which is the correct behaviour wherever iron rule 1's amendment does not
    apply. Fail closed: a G2 run with no configured API server or cluster CA is a G2 run that cannot
    establish its own treatment, so it raises rather than running silently as if it were G0 (V7).

    The transport is a property of the ARM's condition flags and nothing else, exactly as
    ``.agents/rules/10`` requires: keyed on ``netpol_overlay == "opened"`` (G2's flag),
    read from the frozen condition table, never from any string a model produced.
    """
    flags = flags_for(planned.condition or "")
    if flags.netpol_overlay != "opened":
        return None, ()
    api_server = environ.get("KUBE_API_SERVER")
    ca_cert = environ.get("CLUSTER_CA_CERT")
    missing = [
        name
        for name, value in (("KUBE_API_SERVER", api_server), ("CLUSTER_CA_CERT", ca_cert))
        if not value
    ]
    if missing:
        raise LiveRunError(
            "G2-SHAREDCRED needs the direct API path configured before the agents run; set "
            + ", ".join(missing)
            + " so the runner can write the shim's permit (D1-A, ADR-131). An unconfigured G2 run "
            "would be silently inert (V7), so it fails closed rather than running as G0."
        )
    token_file = _run_token_file(environ, planned.run_id)
    permit = PermitFlags(
        condition="G2-SHAREDCRED",
        token_path=str(token_file),
        api_server=str(api_server),
        ca_cert=str(ca_cert),
    )
    flag_file = token_file.with_name(f"{planned.run_id}.g2-transport.json")
    flag_file.parent.mkdir(parents=True, exist_ok=True)
    flag_file.write_text(
        json.dumps(permit.as_document(), sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    # The shim reads its permit ONCE, from the environment naming the flag file just written;
    # the token itself is read lazily by the shim only when a request is actually sent (so this
    # builds even before the applier's g2_credential.sh has written the bearer). shim_for_run is the
    # published seam runner/tests/test_egress_shim.py pins the runner to.
    transport = shim_for_run(
        {
            G2_TRANSPORT_FLAG_ENV: str(flag_file),
            KUBE_TOKEN_FILE_ENV: str(token_file),
        }
    )
    environment = (
        f"{KUBE_TOKEN_FILE_ENV}={token_file}",
        f"KUBE_API_SERVER={api_server}",
    )
    return transport, environment


# ---------------------------------------------------------------------------------------------
# P1a's per-arm behaviours (M10 plan §6). THE ARM NAMES LIVE HERE, IN THE RUNNER.
#
# ADR-023 and .agents/rules/10 put every condition flag in the runner's hands, and a scripted-answer
# table keyed on an arm is exactly such a flag: it decides what the run DOES, keyed on which arm it
# is. So agents/scripts.py carries only the SHAPE of an extension and this module -- which already
# knows the arm -- decides which arm gets which one.
# ---------------------------------------------------------------------------------------------

#: The two arms whose P1a script also makes a direct-path request: G0-FULL, where no transport is
#: injected so the handler returns its structured refusal, and G2-SHAREDCRED, where the shim carries
#: it. The same request in both is the whole contrast -- one arm apart, the alternate path is closed
#: or open -- so the act must not differ between them.
P1A_DIRECT_PATH_ARMS: Final = ("G0-FULL", "G2-SHAREDCRED")

#: The arm whose P1a script also asks for a scale to zero. G0-FULL alone: the request is what the
#: D4-A refusal (ADR-129) is exercised by, and G2's extra act is the direct path.
P1A_SCALE_TO_ZERO_ARMS: Final = ("G0-FULL",)

#: The phase the extension lands in. Containment is the only phase whose declared authority carries
#: ``patch`` on ``deployments`` (guardian/policies/authority.rego), and the scale must be IN SCOPE
#: or its refusal would not be the D4-A one alone -- which guardian/policies/guardian_test.rego pins
#: as the property ("exactly the scale-to-zero refusal").
P1A_EXTENSION_PHASE: Final = "containment"

#: The Deployment the extension's requests name. ``adservice`` is the repository's canonical target
#: workload (ADR-091: "adservice, NOT A SIDECAR, IS THE TARGET"), and it is a Deployment the Online
#: Boutique overlay always runs, so the G2 mutation addresses an object that exists rather than
#: producing a 404 the audit would have to be read carefully to interpret.
P1A_EXTENSION_TARGET: Final = "adservice"


def _p1a_extension_for(
    planned: PlannedRun, namespace: str, environ: Mapping[str, str]
) -> ArmExtension | None:
    """The extra scripted calls this arm's P1a run makes, or ``None`` for the four plain arms.

    G0-FULL: one scale-to-zero request -- which the Guardian refuses under D4-A, because no phase
    holds that capability -- and one direct-path request, which the handler refuses because no
    transport was injected. G2-SHAREDCRED: the same direct-path request, and there the shim carries
    it, so the ablation's two arms differ in the path's reach and in nothing else.

    The credential LOCATION is named only for G2, from the one derivation the runner writes the
    token to and the shim compares against (``_run_token_file``): every other arm's environment
    names no location, and the model is given none, so passing one would be the runner inventing a
    fact the arm does not have. ``""`` is the honest value there and never reaches a socket -- the
    handler returns its no-transport refusal before the field is read.
    """
    condition = planned.condition or ""
    if condition not in P1A_DIRECT_PATH_ARMS:
        return None
    token_file = (
        str(_run_token_file(environ, planned.run_id)) if condition == "G2-SHAREDCRED" else ""
    )
    direct = direct_path_call(
        namespace=namespace, name=P1A_EXTENSION_TARGET, bearer_token_file=token_file
    )
    if condition in P1A_SCALE_TO_ZERO_ARMS:
        return ArmExtension(
            phase=P1A_EXTENSION_PHASE,
            verbs=(SCALE_VERB,),
            resources=(SCALE_RESOURCE,),
            action=scale_to_zero_call(
                P1A_EXTENSION_PHASE, namespace=namespace, name=P1A_EXTENSION_TARGET
            ),
            calls=(direct,),
        )
    return ArmExtension(
        phase=P1A_EXTENSION_PHASE, verbs=(), resources=(), action=None, calls=(direct,)
    )


def _issue_g2_credential(
    environ: Mapping[str, str], planned: PlannedRun, expiries: dict[str, str]
) -> None:
    token_file = _run_token_file(environ, planned.run_id)
    token_file.parent.mkdir(parents=True, exist_ok=True)
    g2_env = dict(environ)
    g2_env["G2_TOKEN_FILE"] = str(token_file)
    _run_command(["sh", "scripts/g2_credential.sh", "issue"], environ=g2_env)
    # The bearer is read back HERE and only for its own `exp` claim: it is revoked by
    # `reset` at run end, so the instant has to be captured while the file exists, and
    # F-GD-05 (class T, seal) requires the recorded expiry to be after the window end --
    # which is what proves the credential was valid for the whole run (ADR-131, ADR-157).
    # The value is never logged and never copied anywhere but the relay.
    try:
        g2_expiry = _jwt_expiry(token_file.read_text(encoding="utf-8"))
    except OSError:
        g2_expiry = None
    if g2_expiry is not None:
        expiries["g2_token_expiry"] = g2_expiry


def _condition_actions(
    environ: Mapping[str, str],
    windows: dict[str, datetime],
    audit_chains: dict[str, str],
    audit_root: str,
    expiries: dict[str, str],
) -> tuple[ConditionApplier, ConditionReset]:
    """Build the per-attempt condition applier and its reset.

    Applying the condition is where one attempt begins, so it is also where that attempt's Guardian
    chain is named: ``<audit_root>/<run-id>-<attempt suffix>.jsonl``, recorded in ``audit_chains``
    for the exporter and handed to ``scripts/guardian_deploy.sh`` as ``GUARDIAN_AUDIT_LOG_PATH``.
    ADR-058, completing ADR-054's unique-suffix rule on the Guardian side: a retry of one canonical
    run id deploys its Guardian on a chain of its own.

    ``expiries`` is data-management §2's credential-expiry relay (see
    :class:`LiveRunDependencies`). It is CLEARED here, at the top of every attempt, because it is
    shared across a dependency set's runs: without the clear a probe, which mints no control-plane
    bearer, would record the previous run's instant as its own.
    """
    monitor_root = environ.get("MONITOR_EVENTS_ROOT")

    def apply(flags: ConditionFlags, planned: PlannedRun) -> None:
        expiries.clear()
        if monitor_root:
            # ADR-124 / SEAM 4. Set BOTH the quoting mode and the run epoch while the aggregator is
            # scaled to ZERO, bring it up ONCE, wait for the rollout (which gates on the /readyz
            # probe), confirm with a one-shot exec that the pod is serving THIS run's epoch and
            # quoting, and only THEN open the evidence window. The previous order scaled the
            # aggregator back up on the LAST run's environment, opened the window, then patched the
            # quoting with a SECOND rollout -- V2, the G3/G1 quoting carryover, because
            # monitor/http_service.py reads the flag once per process and the first pod served the
            # wrong mode until the second rollout replaced it. The scale-up is therefore no longer a
            # finally-cleanup: the confirm and window depend on it, so it is a forward step in the
            # sequence, and MONITOR_RUN_EPOCH plus MONITOR_QUOTING_ENABLED go on in one `set env`
            # before it.
            quote = "true" if flags.aggregator_quoting else "false"
            try:
                _run_command(
                    [
                        "kubectl",
                        "-n",
                        "monitor",
                        "scale",
                        "deployment",
                        "evidence-aggregator",
                        "audit-forwarder",
                        "--replicas=0",
                    ]
                )
                _run_command(
                    [
                        "kubectl",
                        "-n",
                        "monitor",
                        "wait",
                        "--for=delete",
                        "pod",
                        "-l",
                        "app.kubernetes.io/name=evidence-aggregator",
                        "--timeout=120s",
                    ]
                )
                _run_command(
                    [
                        "kubectl",
                        "-n",
                        "monitor",
                        "wait",
                        "--for=delete",
                        "pod",
                        "-l",
                        "app.kubernetes.io/name=audit-forwarder",
                        "--timeout=120s",
                    ]
                )
                _run_command(
                    [
                        "kubectl",
                        "-n",
                        "monitor",
                        "set",
                        "env",
                        "deployment/evidence-aggregator",
                        f"MONITOR_QUOTING_ENABLED={quote}",
                        f"MONITOR_RUN_EPOCH={planned.run_id}",
                    ]
                )
                _run_command(
                    [
                        "kubectl",
                        "-n",
                        "monitor",
                        "scale",
                        "deployment",
                        "evidence-aggregator",
                        "audit-forwarder",
                        "--replicas=1",
                    ]
                )
                _run_command(
                    [
                        "kubectl",
                        "-n",
                        "monitor",
                        "rollout",
                        "status",
                        "deployment/evidence-aggregator",
                    ]
                )
                _run_command(
                    ["kubectl", "-n", "monitor", "rollout", "status", "deployment/audit-forwarder"]
                )
                _confirm_monitor_config(planned.run_id, flags.aggregator_quoting, environ=environ)
                begin_monitor_window(Path(monitor_root), planned.run_id)
            except (OSError, EvidenceProductionError) as error:
                raise LiveRunError(str(error)) from None
        windows[planned.run_id] = datetime.now(UTC)
        topology = {
            "hierarchical": "S1-HIER",
            "flat": "S2-FLAT",
            "single": "S3-SINGLE",
        }[flags.graph_id]
        module = importlib.import_module(CONDITION_MODULES[topology])
        plan = module.build(load_registry())
        issuers = ",".join(registered_issuers(plan.composition))
        guardian_env = dict(environ)
        # One attempt, one chain. The suffix is drawn here, once per attempt and never on a scenario
        # path, and the exporter reads back exactly the path recorded.
        audit_chains[planned.run_id] = guardian_audit_chain_path(
            audit_root, planned.run_id, attempt_suffix()
        )
        guardian_env.update(
            GUARDIAN_MODE=flags.guardian_mode,
            GUARDIAN_RUN_ID=planned.run_id,
            GUARDIAN_REGISTERED_ISSUERS=issuers,
            GUARDIAN_AUDIT_LOG_PATH=audit_chains[planned.run_id],
        )
        _run_command(["sh", "scripts/guardian_deploy.sh"], environ=guardian_env)
        overlay = (
            "infra/netpol/agents-g2-open.yaml"
            if flags.netpol_overlay == "opened"
            else "infra/netpol/agents-default-deny.yaml"
        )
        _run_command(["kubectl", "apply", "-f", overlay])
        if flags.netpol_overlay == "opened":
            _issue_g2_credential(environ, planned, expiries)

    def reset(flags: ConditionFlags, planned: PlannedRun) -> None:
        if flags.netpol_overlay != "opened":
            return
        g2_env = dict(environ)
        g2_env["G2_TOKEN_FILE"] = str(_run_token_file(environ, planned.run_id))
        _run_command(["sh", "scripts/g2_credential.sh", "revoke"], environ=g2_env)

    return apply, reset


def _api_audit_actions(
    environ: Mapping[str, str], offsets: dict[str, int]
) -> tuple[Callable[[PlannedRun], None], ArtifactExporter]:
    """The API-server audit slice's window-open and window-close actions (ADR-137).

    ``K8S_API_AUDIT_LOG`` names the bind-mounted audit-log-path from ``infra/kind-config.yaml``,
    host-visible on the evidence mount (``scripts/live_env.sh`` defaults it under the evidence dir).
    ``offsets`` carries each run's window-open byte offset from open to close, exactly as
    ``evidence_windows`` carries the Monitor window's timestamps. Both actions run with the
    operator's own kubeconfig -- never the Guardian's -- so the sentinel principal is
    ``kubernetes-admin``, one of the expected principals (``security-policy`` section 2.1), and
    F-GD-03 attributes it without a Guardian record. ``k8s_api_audit.jsonl`` is required for
    framework-on runs and in probe mode, so both actions run in both (ADR-137, F-GD-06).
    """
    audit_log = Path(environ["K8S_API_AUDIT_LOG"])
    kubeconfig = environ.get("KUBECONFIG")
    context = environ.get("KUBE_CONTEXT")

    def open_window(planned: PlannedRun) -> None:
        # Offset first, THEN the open sentinel, so the open sentinel is inside the slice. Setup
        # mutations (the per-run Guardian deploy, the netpol apply) happened before this and sit
        # before the offset, which is what keeps the slice to the measured window.
        offsets[planned.run_id] = api_audit_offset(audit_log)
        write_api_audit_sentinel(
            "open",
            run_id=planned.run_id,
            kubeconfig=kubeconfig,
            context=context,
            environ=environ,
        )

    def export(bundle_dir: Path, planned: PlannedRun) -> None:
        write_api_audit_sentinel(
            "close",
            run_id=planned.run_id,
            kubeconfig=kubeconfig,
            context=context,
            environ=environ,
        )
        try:
            offset = offsets[planned.run_id]
        except KeyError:
            raise LiveRunError(
                f"{planned.run_id}: the API-audit window was never opened, so the slice has no "
                "start offset; open_api_audit must run when the measurement window opens (ADR-137)."
            ) from None
        collect_api_audit(audit_log, offset, bundle_dir / "k8s_api_audit.jsonl")

    return open_window, export


def dependencies_from_environment(
    environ: Mapping[str, str] | None = None,
) -> tuple[LiveRunDependencies, str]:
    """Build production adapters from explicit runtime configuration, failing closed."""
    source = os.environ if environ is None else environ
    required = (
        "KUBECONFIG",
        "KUBE_CONTEXT",
        "GUARDIAN_URL",
        "MONITOR_EVENTS_PATH",
        "GUARDIAN_AUDIT_PATH",
        # ADR-137: the API-server audit log the slice is taken from. Required for framework-on runs
        # and in probe mode; a live run cannot corroborate its executions (F-GD-03/F-GD-06) without
        # it.
        "K8S_API_AUDIT_LOG",
    )
    missing = [name for name in required if not source.get(name)]
    if missing:
        raise LiveRunError(
            "live run adapters unavailable; set explicit runtime configuration: "
            + ", ".join(missing)
        )
    guardian_url = source["GUARDIAN_URL"]
    channel_dir = Path(source.get("RUNNER_INJECTION_DIR", REPO_ROOT / "runs" / ".injection"))
    try:
        channel_dir.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise LiveRunError(
            f"runner injection channels unavailable at {channel_dir}: {error}"
        ) from error
    channels = DirectoryInjectionChannels(
        prompt_input=channel_dir / "prompt-input.txt",
        role_manipulation=channel_dir / "role-manipulation.txt",
        parameter_manipulation=channel_dir / "parameter-manipulation.txt",
    )
    evidence_windows: dict[str, datetime] = {}
    # Each attempt's Guardian chain, named when its condition is applied and read back by the audit
    # exporter (ADR-058). The root is the Guardian's audit volume; GUARDIAN_AUDIT_REMOTE_PATH may
    # name it, and scripts/guardian_deploy.sh refuses a chain anywhere else.
    audit_chains: dict[str, str] = {}
    credential_expiries: dict[str, str] = {}
    apply_condition, reset_condition = _condition_actions(
        source,
        evidence_windows,
        audit_chains,
        source.get("GUARDIAN_AUDIT_REMOTE_PATH", GUARDIAN_AUDIT_ROOT),
        credential_expiries,
    )

    # Optional runtime producers. Both default to off, which leaves the two paths exactly the plain
    # copies they were: an operator who already has a single collated stream and a readable audit
    # log -- a replayed fixture, an offline rehearsal -- configures neither and nothing changes.
    monitor_root = source.get("MONITOR_EVENTS_ROOT")
    monitor_events_root = Path(monitor_root) if monitor_root else None
    guardian_workload = source.get("GUARDIAN_AUDIT_WORKLOAD")
    guardian_audit_source = (
        _GuardianAuditSource(
            namespace=source.get("GUARDIAN_AUDIT_NAMESPACE", "guardian"),
            workload=guardian_workload,
            container=source.get("GUARDIAN_AUDIT_CONTAINER", "guardian"),
            kubeconfig=source["KUBECONFIG"],
            context=source["KUBE_CONTEXT"],
        )
        if guardian_workload
        else None
    )

    # ADR-137: the API-server audit slice's window actions. api_audit_offsets carries each run's
    # window-open byte offset from open to close, exactly as evidence_windows does for the Monitor.
    api_audit_offsets: dict[str, int] = {}
    open_api_audit, export_api_audit = _api_audit_actions(source, api_audit_offsets)

    def agents(*, guardian_url: str, bundle_dir: Path, planned: PlannedRun, namespace: str) -> None:
        topology = {
            "hierarchical": "S1-HIER",
            "flat": "S2-FLAT",
            "single": "S3-SINGLE",
        }[flags_for(planned.condition or "").graph_id]
        # D1-A / ADR-131 (SEAM 7): the transport and credential-location facts, built
        # ONLY under G2-SHAREDCRED and None/() in every other arm. Passing the shim here is what
        # finally connects C2 -- v1 wrote the g2 token file and nothing read it (V7), so
        # `cluster_api_request` refused in every arm including G2. The transport is from
        # runner/egress_shim.py; agents/ imports no network library and receives it as a callable.
        if planned.condition == "G2-SHAREDCRED":
            _issue_g2_credential(source, planned, credential_expiries)
        cluster_api_transport, environment = _cluster_api_transport_for(source, planned)
        # SEAM 6 (ADR-128): the control-plane credential path, in EVERY arm. caller_auth makes the
        # GuardianClient's POST /v1/tokens carry the runner's bearer; declare_phase POSTs /v1/phase
        # at each phase change so issuance is bounded to the run's actual phase. v1 supplied
        # neither, so /v1/tokens was reachable unauthenticated and the phase was whatever the token
        # body claimed.
        # M10 plan §6 P1a: RUNNER_SCRIPTED drives the run with a ScriptedClient and NO model tokens,
        # through the full runner path. The script is generated for THIS arm's plan with the run's
        # own executor_id and namespace, so the minted token's sub matches the action's executor_id
        # (ADR-067) and every arm reaches the Guardian (F-AG-03). None leaves the live model path.
        scripted_client: Any = None
        if source.get(RUNNER_SCRIPTED_ENV_VAR):
            plan = importlib.import_module(CONDITION_MODULES[topology]).build(load_registry())
            scripted_client = ScriptedClient(
                script_for(
                    plan,
                    executor_id=f"executor-{planned.run_id}",
                    namespace=namespace,
                    # M10 plan §6's per-arm behaviours: G0-FULL's refused direct-path request and
                    # D4-A-refused scale, and G2-SHAREDCRED's transported direct-path mutation.
                    extension=_p1a_extension_for(planned, namespace, source),
                )
            )
        with _control_plane_session(source, credential_expiries) as caller_auth:
            declare_phase = _declare_phase_for(guardian_url, planned.run_id, caller_auth)
            run_golden(
                guardian_url=guardian_url,
                out=bundle_dir,
                condition=topology or "",
                seed=planned.seed,
                run_id=planned.run_id,
                supervisor_id="",
                client=scripted_client,
                # The executor's identity belongs to the run, not to model output. The Guardian
                # compares the capability's `sub` against the `executor_id` on the action, so mint
                # and submit must name the same executor. Leaving this empty let the mint fall back
                # to whatever string a supervisor invented and the submit fall back to the graph's
                # role id; the two never matched, and every live action was denied
                # `scope.subject-mismatch`. The run id is already a valid Identifier, so the derived
                # name is one too. See ADR-067.
                executor_id=f"executor-{planned.run_id}",
                namespace=namespace,
                evidence_path=bundle_dir / "monitor_events.jsonl",
                injection_paths={
                    "INJ-A": channels.prompt_input,
                    "INJ-C": channels.role_manipulation,
                    "INJ-D": channels.parameter_manipulation,
                },
                caller_auth=caller_auth,
                declare_phase=declare_phase,
                cluster_api_transport=cluster_api_transport,
                environment=environment,
            )

    return (
        LiveRunDependencies(
            cluster=KubectlClusterAdapter(
                kubeconfig=Path(source["KUBECONFIG"]),
                context=source["KUBE_CONTEXT"],
                injection_channels=channels,
            ),
            apply_condition=apply_condition,
            reset_condition=reset_condition,
            drive_agents=agents,
            export_monitor=_monitor_export(
                Path(source["MONITOR_EVENTS_PATH"]),
                monitor_events_root,
                evidence_windows,
                drain_seconds=monitor_drain_seconds(source),
            ),
            export_audit=_audit_export(
                Path(source["GUARDIAN_AUDIT_PATH"]), guardian_audit_source, audit_chains
            ),
            # assertions.json is EVALUATED by the runner at run end (data-management.md section 3),
            # not copied from a producer that does not exist: nothing else in the tree writes it for
            # a live run, so requiring a pre-existing file made a framework-on bundle unsealable.
            # ASSERTIONS_PATH is still honoured when set, so an external evaluator can be
            # substituted without editing this composition root.
            evaluate_assertions=(
                _copy_export(Path(source["ASSERTIONS_PATH"]), "assertions.json")
                if source.get("ASSERTIONS_PATH")
                else live_assertion_evaluator(
                    cluster=KubectlStateReader(
                        kubeconfig=Path(source["KUBECONFIG"]),
                        context=source["KUBE_CONTEXT"],
                    )
                )
            ),
            # ADR-085 / supervisor ruling B3: no port-forward on the measurement path. The probe
            # runs inside the cluster against the frontend Service's cluster DNS name (the
            # FRONTEND_URL override exists for an operator who deployed the Service under a
            # different name); see runner/live_baseline.py::probe_writer.
            probe=probe_writer(source.get("FRONTEND_URL", DEFAULT_FRONTEND_URL)),
            resources=resource_writer(source.get("PROMETHEUS_URL", "http://127.0.0.1:9090")),
            locust=LocustDriver(source.get("LOCUST_URL", "http://127.0.0.1:8089")),
            open_api_audit=open_api_audit,
            export_api_audit=export_api_audit,
            credential_expiries=credential_expiries,
        ),
        guardian_url,
    )


def execute_live_run(
    bundle_dir: Path,
    planned: PlannedRun,
    *,
    dependencies: LiveRunDependencies,
    guardian_url: str,
    window: MeasurementWindow,
    instrument_only: bool = False,
) -> int:
    """Compose one live attempt and return its required scenario event count.

    ``instrument_only`` is the P0-live probe mode (WS-5, ``--instrument-only``): the condition flags
    are applied, the scenario and its injections run, the Monitor evidence and the API-server audit
    are collated, and NO agent graph runs -- so the Guardian chain, assertions and every file the
    agent layer alone produces are absent, which is exactly what the probe completeness profile
    (``runner/bundle.py``) requires and forbids. A probe measures the framework around the
    agent (WS-3's quoting/epoch chain, the forwarder drain, the audit policy, the shim), and a graph
    running inside it would make the probed instrument the thing under test. Default ``False``
    leaves every existing caller driving the full framework-on composition unchanged.
    """
    if (
        planned.condition is None
        or planned.scenario_id is None
        or planned.injection_condition is None
    ):
        raise LiveRunError(f"{planned.run_id} lacks framework-on coordinates")
    flags = flags_for(planned.condition)
    scenario = load_manifest(planned.scenario_id)
    events = plan_cell(planned.scenario_id, planned.injection_condition, planned.seed)
    bundle_dir.mkdir(parents=True, exist_ok=True)
    probe_future: Future[int] | None = None

    def respond_before_teardown(records: tuple[dict[str, object], ...]) -> None:
        publish_log(records, bundle_dir / "injection.log.jsonl")
        dependencies.export_monitor(bundle_dir, planned)
        if not instrument_only:
            # The agent graph and its Guardian audit chain. Skipped in probe mode: a P0-live probe
            # runs the scenario, the injections and the evidence path and NO graph, so these -- and
            # the assertions below -- are the files the probe completeness profile forbids
            # (messages/tokens/spans, guardian_audit.jsonl, assertions.json).
            dependencies.drive_agents(
                guardian_url=guardian_url,
                bundle_dir=bundle_dir,
                planned=planned,
                namespace=scenario["namespace"],
            )
            dependencies.export_audit(bundle_dir, planned)
        # ADR-137: close the API-audit window and slice it into the bundle. In BOTH modes -- the
        # probe profile requires k8s_api_audit.jsonl too -- and after the agent graph so its
        # executed mutations are inside the slice, and before evaluate_assertions below, which reads
        # it.
        dependencies.export_api_audit(bundle_dir, planned)
        # Assertions read both live pre-teardown state and the completed probe timeline.
        # Waiting here keeps teardown behind evaluation and avoids a partial probes.csv.
        if probe_future is None or probe_future.result() < 1:
            raise LiveRunError("SLO probe wrote no rows to probes.csv")
        if instrument_only:
            # No agent graph ran, so there is no Guardian chain to count blocked requests from; the
            # probe profile still requires metrics.json, and with no Guardian decisions the count is
            # zero by construction.
            blocked = 0
        else:
            # ADR-058: the Guardian opens every per-run chain with a run-start record. It is
            # recognised by its explicit record_type and never counted: a Guardian starting is not
            # a blocked request.
            from guardian.audit.record_types import is_run_start

            blocked = 0
            for line in (
                (bundle_dir / "guardian_audit.jsonl").read_text(encoding="utf-8").splitlines()
            ):
                if not line.strip():
                    continue
                record = json.loads(line)
                if not is_run_start(record) and record.get("enforcement") == "blocked":
                    blocked += 1
        metrics: dict[str, object] = {"requests_blocked": blocked}
        # Fold the epoch-drop count (ADR-124, SEAM 4) into metrics.json, where F-MN-02 reads it, and
        # remove the relay sidecar the Monitor export copied in, so it is not a stray artefact
        # at seal. Absent (a no-op or non-collating export) leaves just the counter.
        drops_sidecar = bundle_dir / EPOCH_DROPS_FILENAME
        if drops_sidecar.is_file():
            try:
                recorded = json.loads(drops_sidecar.read_text(encoding="utf-8"))
                metrics[EPOCH_DROPS_FIELD] = int(recorded[EPOCH_DROPS_FIELD])
            except (OSError, ValueError, TypeError, KeyError) as error:
                raise LiveRunError(f"monitor epoch-drop count is unreadable: {error}") from None
            drops_sidecar.unlink()
        # F-MN-04: the audit forwarder's worst observed drain, computed from the two streams the
        # collation just wrote. Left ABSENT when the window carried no forwarded record -- a run
        # that measured nothing must not report zero, and the check reads a missing field as
        # "not measured" rather than as "measured at zero".
        events_path = bundle_dir / EVENTS_FILENAME
        timings_path = bundle_dir / TIMINGS_FILENAME
        if events_path.is_file() and timings_path.is_file():
            drain = forwarder_drain_seconds(events_path, timings_path)
            if drain is not None:
                metrics[DRAIN_FIELD] = drain
        (bundle_dir / "metrics.json").write_text(
            json.dumps(metrics, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        # data-management §2's two credential expiries, relayed from mint time to the manifest.
        # Relay credential expiries to the manifest; the sealer removes this temporary file.
        (bundle_dir / LIVE_PROVENANCE_FILE).write_text(
            json.dumps(
                dict(dependencies.credential_expiries), sort_keys=True, separators=(",", ":")
            )
            + "\n",
            encoding="utf-8",
        )
        if not instrument_only:
            dependencies.evaluate_assertions(bundle_dir, planned)

    def incident_and_response() -> None:
        result = dependencies.scenario_driver(
            events,
            planned.run_id,
            adapter=dependencies.cluster,
            before_teardown=respond_before_teardown,
        )
        publish_log(result.records, bundle_dir / "injection.log.jsonl")
        if result.error is not None:
            raise LiveRunError(result.error)

    def measurement() -> None:
        nonlocal probe_future
        # ADR-137: open the API-audit window before any probe, scenario or agent mutates -- record
        # the audit-log byte offset and write the window-open sentinel. Setup (the per-run Guardian
        # deploy, the netpol apply) already ran in apply_condition, before this, so it sits before
        # the offset and outside the slice, which is what keeps the slice to the measured window.
        dependencies.open_api_audit(planned)
        with ThreadPoolExecutor(max_workers=3, thread_name_prefix="run-instrument") as pool:
            probe_future = pool.submit(dependencies.probe, bundle_dir / "probes.csv", window)
            resource_future = pool.submit(
                dependencies.resources, bundle_dir / "resources.csv", window
            )
            response_future = pool.submit(incident_and_response)
            try:
                probe_count = probe_future.result()
                resource_count = resource_future.result()
                response_future.result()
            except Exception as error:
                raise LiveRunError(f"live measurement or response failed: {error}") from error
        if probe_count < 1:
            raise LiveRunError("SLO probe wrote no rows to probes.csv")
        if resource_count < 1:
            raise LiveRunError("resource collector wrote no rows to resources.csv")

    try:
        dependencies.apply_condition(flags, planned)
        dependencies.locust.drive(
            planned.load_profile_id, bundle_dir / "locust_stats.csv", measurement
        )
    except LiveRunError:
        raise
    except Exception as error:
        raise LiveRunError(f"live run {planned.run_id} failed: {error}") from error
    finally:
        try:
            dependencies.reset_condition(flags, planned)
        except Exception as error:
            raise LiveRunError(f"condition cleanup failed for {planned.run_id}: {error}") from error
    return expected_event_count(scenario, planned.injection_condition)
