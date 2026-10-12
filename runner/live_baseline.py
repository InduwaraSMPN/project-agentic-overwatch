"""Concurrent M1 measurement orchestration for a real framework-off baseline.

THE SLO PROBE PATH (ADR-085; supervisor ruling B3)
---------------------------------------------------
``probe_writer`` no longer drives HTTP requests from the host process against a
``kubectl port-forward``ed frontend. On 2026-09-12 a live run's probe timeline was pinned, by that
port-forward, to one frontend pod; eradication correctly deleted that pod, and every later
``probes.csv`` row read ``Connection refused`` while the Deployment stayed 2/2 Ready -- inverting
verified recovery for every scenario whose eradication replaces a pod. "An SLO describes the
Service, not a pod" (ruling B3): ``probe_writer`` now creates a per-attempt Pod inside the cluster
(:mod:`infra.probes.deploy`, applied from :data:`PROBE_POD_TEMPLATE`) that runs the identical
:mod:`infra.probes.slo_probe` module against the frontend Service's cluster-DNS name, retrieves the
``probes.csv`` it wrote with ``kubectl exec -- cat`` -- the same technique
``runner/live_evidence.py::extract_guardian_audit`` already uses for the Guardian's audit chain --
and deletes the pod. No port-forward is on the measurement path; ``scripts/port_forward.sh`` keeps
forwarding the Guardian, Prometheus and Locust endpoints, which this module's own
``resource_writer`` and ``execute``'s Locust driver still reach that way.

This is also why a live baseline (this module's own ``execute``, called from ``runner/baseline.py``
with no override) and a live grid run (``runner/live_run.py``, which imports ``probe_writer`` from
here) now share one probe path end to end: supervisor ruling B3 requires "framework-off baselines
[to] use the same probe path" as a framework-on run, and both call sites construct their probe
``Writer`` from this one factory.

THE RESEARCHER'S PRIOR CHANGE TO THIS FILE
---------------------------------------------
The staged edit this stream inherited added a ``before_probe`` hook to ``probe_writer`` so that
``runner/live_run.py`` could repair the frontend port-forward before every request -- a workaround
for the 2026-09-12 defect above that still left a port-forward on the measurement path. It is
superseded outright by the in-cluster design and is not present in the function below; see the ADR
for why a workaround inside the old design could not fix what ruling B3 identifies as the design's
own defect.
"""

from __future__ import annotations

import csv
import subprocess
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from time import monotonic as _monotonic
from time import sleep as _sleep
from typing import Final

from infra.collectors.resource_collector import (
    QueryFn,
    live_query_fn,
    run_collection,
)
from infra.collectors.resource_collector import (
    write_rows as write_resource_rows,
)
from infra.locust.driver import LoadDriverError, Transport, drive_profile, urllib_transport
from infra.probes.constants import PROBE_INTERVAL_SECONDS

REPO_ROOT: Final = Path(__file__).resolve().parents[1]

DEFAULT_LOCUST_URL = "http://127.0.0.1:8089"
# Cluster DNS, not a port-forward port: see the module docstring. `frontend` is the Service name
# Online Boutique's upstream manifests declare (infra/boutique/kustomization.yaml) and `boutique` is
# the namespace scripts/up.sh creates it in; `.svc.cluster.local` is the cluster domain every kind
# cluster in this project uses. Still an operator-overridable default, never a protocol constant --
# the frontend address is an environment fact (infra/probes/constants.py's own module docstring).
DEFAULT_FRONTEND_URL = "http://frontend.boutique.svc.cluster.local"
DEFAULT_PROMETHEUS_URL = "http://127.0.0.1:9090"

# infra/probes/deploy/namespace.yaml. A dedicated namespace, not `boutique` or `agents`, so that no
# NetworkPolicy in either -- and no Guardian-created containment policy, always created inside
# `boutique` -- can ever select this pod; see that manifest's own header for why namespace-scoped
# podSelectors make this true by construction.
PROBE_NAMESPACE: Final = "slo-probe"
# infra/probes/deploy/Dockerfile. Measurement apparatus, not a versions.env pin; see that file's
# header for why.
PROBE_IMAGE: Final = "agentic-overwatch/slo-probe:local"
PROBE_POD_TEMPLATE: Final = REPO_ROOT / "infra" / "probes" / "deploy" / "pod.yaml"

# The mount infra/probes/deploy/pod.yaml gives its one emptyDir volume, and the two paths inside it
# the container's wrapper command writes. Moving either requires the identical edit to that file.
PROBE_DATA_DIR: Final = "/data"
PROBE_OUTPUT_PATH: Final = f"{PROBE_DATA_DIR}/probes.csv"
PROBE_DONE_MARKER: Final = f"{PROBE_DATA_DIR}/DONE"

# The placeholder tokens infra/probes/deploy/pod.yaml declares itself unsubstituted without, in the
# same style infra/netpol/probe/{client,server}.yaml use for NODE_NAME_PLACEHOLDER. Named here,
# beside the one function that substitutes them, rather than only in the manifest's own prose.
_POD_NAME_PLACEHOLDER: Final = "SLO_PROBE_POD_NAME_PLACEHOLDER"
_IMAGE_PLACEHOLDER: Final = "SLO_PROBE_IMAGE_PLACEHOLDER"
_BASE_URL_PLACEHOLDER: Final = "SLO_PROBE_BASE_URL_PLACEHOLDER"
_STOP_ARGS_PLACEHOLDER: Final = "SLO_PROBE_STOP_ARGS_PLACEHOLDER"


class LiveMeasurementError(Exception):
    """The live load or either concurrent instrument failed."""


@dataclass(frozen=True, slots=True)
class MeasurementWindow:
    """A caller-owned stopping rule; exactly one form is required and neither has a default."""

    samples: int | None = None
    duration_seconds: float | None = None

    def __post_init__(self) -> None:
        if (self.samples is None) == (self.duration_seconds is None):
            raise ValueError("exactly one of samples and duration_seconds must be supplied")
        if self.samples is not None and self.samples < 1:
            raise ValueError("samples must be at least one")
        if self.duration_seconds is not None and self.duration_seconds <= 0:
            raise ValueError("duration_seconds must be greater than zero")


Writer = Callable[[Path, MeasurementWindow], int]


@dataclass(frozen=True, slots=True)
class KubectlResult:
    """The bytes of one kubectl invocation, decoupled from subprocess for injectability in tests."""

    returncode: int
    stdout: bytes
    stderr: bytes

    def detail(self) -> str:
        """The stderr text worth showing a caller, or a bare exit code when stderr was empty."""
        return self.stderr.decode("utf-8", "replace").strip() or f"exit {self.returncode}"


# One kubectl invocation: argv plus optional stdin bytes (for `apply -f -`), returning its result
# rather than raising, so every caller decides for itself what a non-zero exit means. Injectable so
# every test in runner/tests/test_live_baseline.py drives this module without a cluster, the same
# NO CLUSTER, NO NETWORK, NO SOCKET property infra/tests/test_probes_schema.py already holds for the
# probe writer this now wraps.
RunKubectl = Callable[[list[str], bytes | None], KubectlResult]


def _run_kubectl(argv: list[str], input_bytes: bytes | None = None) -> KubectlResult:
    result = subprocess.run(  # noqa: S603 - argv only, no shell
        argv, input=input_bytes, capture_output=True, check=False
    )
    return KubectlResult(result.returncode, result.stdout, result.stderr)


def _stop_args(window: MeasurementWindow) -> str:
    """Render one ``MeasurementWindow`` as the CLI form ``infra.probes.slo_probe`` itself parses."""
    if window.samples is not None:
        return f"--samples {window.samples}"
    return f"--duration {window.duration_seconds}"


def _expected_probe_seconds(window: MeasurementWindow) -> float:
    """The wall-clock time one probe collection is expected to take, for sizing a poll timeout.

    A ``--samples`` window is converted through the protocol's own cadence
    (``PROBE_INTERVAL_SECONDS``) rather than assumed; a ``--duration`` window already states its
    own length. Either way this is an *estimate* the poll loop budgets a safety margin on top of
    (see :func:`in_cluster_probe_output`), never a hard deadline the probe itself is held to.
    """
    if window.samples is not None:
        return window.samples * float(PROBE_INTERVAL_SECONDS)
    if window.duration_seconds is not None:
        return window.duration_seconds
    raise LiveMeasurementError(  # pragma: no cover - MeasurementWindow forbids this combination
        "measurement window carries neither samples nor duration_seconds"
    )


def _count_csv_data_rows(content: bytes) -> int:
    """Return the number of data rows (header excluded) in a ``probes.csv`` byte string."""
    return max(len(list(csv.reader(content.decode("utf-8").splitlines()))) - 1, 0)


def render_probe_pod(
    pod_name: str,
    base_url: str,
    window: MeasurementWindow,
    *,
    image: str = PROBE_IMAGE,
    template_path: Path = PROBE_POD_TEMPLATE,
) -> str:
    """Render :data:`PROBE_POD_TEMPLATE` for one attempt, substituting its four placeholders.

    Raises :class:`LiveMeasurementError` naming whichever token is missing rather than applying a
    manifest that silently kept a literal ``..._PLACEHOLDER`` string in a field: the API server
    would reject some of those (a Pod name is a DNS-1123 label) but not all of them, and a base URL
    or stop-args token left unsubstituted would apply cleanly and probe nothing real.
    """
    text = template_path.read_text(encoding="utf-8")
    substitutions = {
        _POD_NAME_PLACEHOLDER: pod_name,
        _IMAGE_PLACEHOLDER: image,
        _BASE_URL_PLACEHOLDER: base_url,
        _STOP_ARGS_PLACEHOLDER: _stop_args(window),
    }
    for token, value in substitutions.items():
        if token not in text:
            raise LiveMeasurementError(
                f"{template_path} is missing the {token} placeholder; the probe manifest and "
                "runner/live_baseline.py::render_probe_pod have drifted apart"
            )
        text = text.replace(token, value)
    return text


def in_cluster_probe_output(
    pod_name: str,
    window: MeasurementWindow,
    *,
    namespace: str = PROBE_NAMESPACE,
    run_kubectl: RunKubectl = _run_kubectl,
    poll_interval_seconds: float = 2.0,
    timeout_margin_seconds: float = 90.0,
    sleep: Callable[[float], None] = _sleep,
    monotonic: Callable[[], float] = _monotonic,
) -> bytes:
    """Poll a running probe pod for its completion marker, then return its ``probes.csv`` bytes.

    The timeout budget is the collection's own expected duration
    (:func:`_expected_probe_seconds`) plus a fixed margin for pod scheduling and image pull --
    generous rather than tight, because the cost of polling a little longer is a few seconds and the
    cost of a false timeout is an aborted measurement. At least one check always runs before the
    deadline is consulted, so a window shorter than one poll interval (as in a test) still gets a
    real attempt rather than an immediate, untried timeout.
    """
    deadline = monotonic() + _expected_probe_seconds(window) + timeout_margin_seconds
    last_detail = "no diagnostic output"
    while True:
        probe_check = run_kubectl(
            ["kubectl", "-n", namespace, "exec", pod_name, "--", "test", "-f", PROBE_DONE_MARKER],
            None,
        )
        if probe_check.returncode == 0:
            break
        last_detail = probe_check.detail()
        if monotonic() >= deadline:
            raise LiveMeasurementError(
                f"in-cluster SLO probe pod {namespace}/{pod_name} did not finish within the "
                f"expected window plus a {timeout_margin_seconds:g}s margin: {last_detail}"
            )
        sleep(poll_interval_seconds)

    cat = run_kubectl(
        ["kubectl", "-n", namespace, "exec", pod_name, "--", "cat", PROBE_OUTPUT_PATH], None
    )
    if cat.returncode != 0:
        raise LiveMeasurementError(
            f"in-cluster SLO probe output is unreadable at {namespace}/{pod_name}:"
            f"{PROBE_OUTPUT_PATH}: {cat.detail()}"
        )
    if not cat.stdout:
        raise LiveMeasurementError(
            f"in-cluster SLO probe at {namespace}/{pod_name} produced an empty probes.csv"
        )
    return cat.stdout


def probe_writer(
    base_url: str = DEFAULT_FRONTEND_URL,
    *,
    namespace: str = PROBE_NAMESPACE,
    image: str = PROBE_IMAGE,
    template_path: Path = PROBE_POD_TEMPLATE,
    run_kubectl: RunKubectl = _run_kubectl,
    poll_interval_seconds: float = 2.0,
    timeout_margin_seconds: float = 90.0,
    sleep: Callable[[float], None] = _sleep,
    monotonic: Callable[[], float] = _monotonic,
    pod_suffix: Callable[[], str] = lambda: uuid.uuid4().hex[:20],
) -> Writer:
    """Build the in-cluster SLO probe writer (ADR-085; supervisor ruling B3).

    Per attempt: render and apply one Pod from :data:`PROBE_POD_TEMPLATE`
    (:func:`render_probe_pod`), poll it for completion and read its ``probes.csv`` back
    (:func:`in_cluster_probe_output`), then delete the pod whether or not that read succeeded -- the
    "per-run lifecycle created and removed by the runner" ruling B3 asks for. ``run_kubectl`` is the
    one injection point every call in this factory goes through, so a test drives the whole
    create/poll/read/delete sequence against a fake and never shells out for real (mirroring
    infra/tests/test_probes_schema.py's "NO CLUSTER, NO NETWORK, NO SOCKET" discipline one layer
    up).

    ``base_url`` defaults to :data:`DEFAULT_FRONTEND_URL`, the frontend Service's cluster-DNS name;
    it is still a parameter, and not a protocol constant, for the same reason
    infra/probes/slo_probe.py's own ``--base-url`` is one -- the frontend address is an environment
    fact. ``pod_suffix`` defaults to a fresh UUID4 per call so two concurrent probe pods (a live run
    and a live baseline, or two campaign workers) never collide on one Pod name; overridden in tests
    for deterministic assertions.
    """

    def write(path: Path, window: MeasurementWindow) -> int:
        pod_name = f"slo-probe-{pod_suffix()}"
        manifest = render_probe_pod(
            pod_name, base_url, window, image=image, template_path=template_path
        )
        applied = run_kubectl(
            ["kubectl", "-n", namespace, "apply", "-f", "-"], manifest.encode("utf-8")
        )
        if applied.returncode != 0:
            raise LiveMeasurementError(
                f"could not create the in-cluster SLO probe pod {namespace}/{pod_name}: "
                f"{applied.detail()}"
            )
        try:
            content = in_cluster_probe_output(
                pod_name,
                window,
                namespace=namespace,
                run_kubectl=run_kubectl,
                poll_interval_seconds=poll_interval_seconds,
                timeout_margin_seconds=timeout_margin_seconds,
                sleep=sleep,
                monotonic=monotonic,
            )
        finally:
            # Best-effort and unconditional: a pod whose output could not be read is still deleted,
            # so a failed attempt never leaves a stray probe pod for the next one to trip over.
            run_kubectl(
                [
                    "kubectl",
                    "-n",
                    namespace,
                    "delete",
                    "pod",
                    pod_name,
                    "--ignore-not-found",
                    "--wait=true",
                    "--timeout=60s",
                ],
                None,
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        pending = path.with_suffix(path.suffix + ".pending")
        pending.write_bytes(content)
        pending.replace(path)
        return _count_csv_data_rows(content)

    return write


def resource_writer(
    prometheus_url: str = DEFAULT_PROMETHEUS_URL,
    query: QueryFn | None = None,
) -> Writer:
    """Build the shared live resource writer; explicit queries keep offline tests isolated."""
    bound_query = query or live_query_fn(prometheus_url)

    def write(path: Path, window: MeasurementWindow) -> int:
        return write_resource_rows(
            run_collection(
                bound_query,
                samples=window.samples,
                duration_seconds=window.duration_seconds,
            ),
            path,
        )

    return write


def collect_concurrently(
    bundle_dir: Path,
    window: MeasurementWindow,
    probe: Writer,
    resources: Writer,
) -> None:
    """Run both instruments over the same window and require non-empty outputs."""
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="baseline-instrument") as pool:
        probe_future = pool.submit(probe, bundle_dir / "probes.csv", window)
        resource_future = pool.submit(resources, bundle_dir / "resources.csv", window)
        try:
            probe_count = probe_future.result()
            resource_count = resource_future.result()
        except Exception as error:
            raise LiveMeasurementError(f"baseline measurement collector failed: {error}") from error
    if probe_count < 1:
        raise LiveMeasurementError("SLO probe wrote no rows to probes.csv")
    if resource_count < 1:
        raise LiveMeasurementError("resource collector wrote no rows to resources.csv")


def execute(
    bundle_dir: Path,
    load_profile_id: str,
    window: MeasurementWindow,
    *,
    locust_url: str = DEFAULT_LOCUST_URL,
    locust_transport: Transport = urllib_transport,
    probe: Writer | None = None,
    resources: Writer | None = None,
) -> None:
    """Drive Locust while the SLO and resource writers run concurrently.

    A framework-off baseline reaches its default ``probe`` from here, unless a caller (or
    ``runner/baseline.py``, which always supplies its own) overrides it -- so a baseline uses the
    identical in-cluster probe path a live run does, per ruling B3's "framework-off baselines must
    use the same probe path". See the module docstring.
    """
    probe_action = probe or probe_writer()
    resource_action = resources or resource_writer()

    def measurement() -> None:
        collect_concurrently(bundle_dir, window, probe_action, resource_action)

    try:
        drive_profile(
            load_profile_id,
            bundle_dir / "locust_stats.csv",
            measurement,
            base_url=locust_url,
            transport=locust_transport,
        )
    except LoadDriverError as error:
        raise LiveMeasurementError(str(error)) from None
