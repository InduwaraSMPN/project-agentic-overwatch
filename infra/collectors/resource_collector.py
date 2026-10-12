"""Resource collector: queries Prometheus and writes the ``resources.csv`` series.

WHY THIS EXISTS
---------------
RQ4 asks what the framework costs to run. The answer is a delta -- resource usage with the
framework on, minus the same measure in a matched baseline -- and a delta is only as trustworthy
as the labelling of the two series it subtracts. ``docs/protocols/data-management.md`` section 1
makes ``resources.csv`` a required member of every sealed run bundle, and section 3 states the
completeness check outright: a bundle whose ``resources.csv`` lacks a populated restart column
does not seal. This module is the only writer of that file.

THE CONTRACT
------------
Columns, in this order and no other, per data-management section 1:

    ts, series, namespace, workload, container, cpu_cores, mem_bytes, storage_bytes,
    restarts_total

``series`` takes exactly three values -- ``app``, ``framework``, ``platform``. The third one is the
whole point of the schema and is worth stating plainly: Prometheus, kube-state-metrics, Grafana
and Locust run in the baseline *and* in the framework-on run, so folding them into ``framework``
would report the measurement apparatus as framework overhead and inflate the RQ4 delta by the cost
of measuring it. Only ``series = framework`` enters that delta. ``platform`` is written to the CSV
rather than filtered out at collection time, so the exclusion is visible in the data and can be
audited after the fact instead of being taken on trust from a line of code nobody re-reads.

``ts`` is taken once per collection tick and stamped identically on every row of that tick, so the
rows of one sample group exactly by ``ts``. Taking it per query instead would scatter a single
sample across four timestamps and make the natural grouping wrong by milliseconds.

WHAT BREAKS IF THE NAMESPACE TABLE IS WRONG
-------------------------------------------
The namespace-to-series table below is the only thing standing between "this is what the framework
cost" and "this is what the framework plus the observability stack cost". A namespace it does not
know falls to ``platform`` -- the conservative direction, since a mislabelled ``platform`` row
understates nothing that RQ4 reports -- but it does so *loudly*, printing one line per unseen
namespace. A silent fallback is the failure mode to fear: M2 and M3 add the Monitor and Guardian
namespaces, and a framework namespace that quietly landed in ``platform`` would remove the
framework's own cost from the framework's own overhead measure, with nothing anywhere saying so.

THE METRICS, AND WHY THESE ONES
-------------------------------
``cpu_cores`` is ``rate(container_cpu_usage_seconds_total[...])``. The counter is CPU-seconds, so
its rate is CPU-seconds per second, which is cores -- no unit conversion and no constant anywhere
in this file.

``mem_bytes`` is ``container_memory_working_set_bytes``, the figure the kubelet itself uses for
eviction decisions. ``container_memory_usage_bytes`` was rejected: it includes reclaimable page
cache, so a workload that merely read a large file reports as if it were holding the memory, and
the framework-versus-baseline delta would then partly measure file access.

``storage_bytes`` is the kubelet Summary API's per-container ephemeral-storage usage
(``container_ephemeral_storage_used_bytes`` below), and getting here took one wrong turn worth
recording so it is not taken again. The v1 source was cAdvisor's ``container_fs_usage_bytes``,
chosen
because it lives in the same family as the CPU and memory series and joins on the same
``(namespace, pod, container)`` label set. It is empty on this cluster: kind runs the kubelet inside
a
container over containerd, and cAdvisor reads CPU and memory from the cgroup hierarchy (always
present)
but filesystem usage from the container runtime's stats, which containerd does not expose to it here
--
so ``container_fs_usage_bytes`` returns nothing while ``container_cpu_usage_seconds_total`` and
``container_memory_working_set_bytes`` beside it are populated. The plan records this as defect V10:
``storage_bytes`` was 0 in every row of every v1 bundle on both sides of the RQ4 delta, a fabricated
zero rather than a measured one. D15 (``docs/adr/ADR-133``) replaces the source with the kubelet
Summary API (``/stats/summary``), whose ephemeral-storage figure the kubelet computes itself -- by
periodic accounting over each container's writable layer and logs plus the pod's ``emptyDir``
volumes
-- and therefore reports on kind where cAdvisor's filesystem view does not. The per-container
component
(``rootfs`` + ``logs`` used bytes) is used rather than the per-pod ``ephemeral-storage`` roll-up so
the
series keeps the ``(namespace, pod, container)`` grain the CPU and memory series join on. The two
rejected v1 alternatives still apply and are kept as the record of what not to reach for:
``kubelet_volume_stats_used_bytes`` is per-PersistentVolumeClaim and Online Boutique declares none
--
its cart cache is an ``emptyDir`` -- so it would be silently all zero; and
``kube_pod_container_resource_requests{resource="ephemeral_storage"}`` is a *declared request*, not
observed usage, and would report the manifest back rather than the run.

WHERE THE STORAGE SERIES COMES FROM, AND WHAT VALIDATES IT
---------------------------------------------------------
The live query adapter reads container rootfs and log usage directly from each node's kubelet
Summary API through authenticated ``kubectl get --raw`` (ADR-162). No Prometheus exporter for
this metric is assumed. CPU, memory and restarts still use Prometheus. Tests inject the same
query interface and remain offline. Failed Summary API reads fail collection; containers without
usage fields supply no storage sample. F-AN-03 confirms positive storage on the live host, and
analysis reports absent storage as a LIMITATION "not collected" rather than measured zero.

``restarts_total`` is ``kube_pod_container_status_restarts_total`` from kube-state-metrics, named
directly by data-management section 3. It is a cumulative counter and is written raw, not rated: a
restart count is evidence about the run, and section 3.5.7 asks for the counter, not its slope.

THE RATE WINDOW IS NOT AN EVALUATION CONSTANT
---------------------------------------------
``--rate-window-seconds`` is a *query* parameter: it changes how much smoothing a rate carries, not
what is being measured. It is therefore deliberately not mirrored into evaluation-protocol section
4, which owns seeds, budgets and thresholds. Its default is 60 seconds, which spans at least two
scrapes at any scrape interval up to 30 s, so a rate is never taken over a window that saw a single
sample. The authority for the actual scrape interval is T1.3's Prometheus values file; if a future
milestone needs the window pinned for reproducibility rather than merely chosen for sanity, that is
a protocol edit with an owner, and it is flagged here rather than pre-empted.

The sampling *cadence*, by contrast, is protocol-owned: it is ``probe_interval_seconds`` from
evaluation-protocol section 4, imported from :mod:`infra.probes.constants` and never restated here.
Sharing the probe's cadence is what lets a ``resources.csv`` row be lined up against the
``probes.csv`` row from the same instant, which is how a restart or a memory spike gets attributed
to a dip in the probe timeline.

GRANULARITY: WORKLOAD AND CONTAINER, NOT POD
--------------------------------------------
The protocol-homed column set carries ``workload`` and ``container`` and no ``pod``, so rows are
aggregated across the replicas of a workload rather than emitted per pod. That is also the right
semantics for an overhead measure: RQ4 asks what the framework costs, which is a total across its
replicas and not a per-replica figure, and summing restarts across replicas is exactly what
"container restarts" means for a workload in section 3.5.7's list of per-run resource counters.
Per-pod detail is therefore deliberately dropped; anything needing it should read Prometheus
directly rather than widen a schema the protocol owns.

``workload`` is derived from the pod name by stripping the suffixes Kubernetes appends, and the
derivation is a heuristic, stated as one: the authoritative source is kube-state-metrics'
``kube_pod_owner``, which costs another query and another join for a column that labels rows rather
than carrying a measurement. The join keys that matter -- ``namespace`` and ``container`` -- come
straight from the metric labels and are not derived at all. If a later milestone needs workload
attribution to be authoritative rather than legible, ``kube_pod_owner`` is the fix and this comment
is the note that it was a known trade.

WHY THE I/O IS INJECTABLE
-------------------------
The ``Unit tests -- infra`` step of ``.github/workflows/ci.yml`` runs on a GitHub runner with no
cluster and no Prometheus. The query function, the clock and the sleep are all parameters with real
defaults, so the tests drive the whole collector end to end against a fake query function and never
open a socket.
"""

import argparse
import csv
import json
import re
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic as _monotonic
from time import sleep as _sleep
from typing import Any

from infra.probes.constants import PROBE_INTERVAL_SECONDS

# The column order is the contract, not a convenience. data-management section 1 fixes it, the
# schema test asserts it, and section 3's completeness check reads restarts_total by name.
RESOURCES_CSV_HEADER: tuple[str, ...] = (
    "ts",
    "series",
    "namespace",
    "workload",
    "container",
    "cpu_cores",
    "mem_bytes",
    "storage_bytes",
    "restarts_total",
)

# csv.writer defaults to CRLF. Pinned to LF for the same reason probes.csv is: a bundle whose bytes
# depend on the host that sealed it is not reproducible.
CSV_LINE_TERMINATOR = "\n"

SERIES_APP = "app"
SERIES_FRAMEWORK = "framework"
SERIES_PLATFORM = "platform"

# Declared in report order, which is also the sort order rows are emitted in. app first because it
# is the system under test, framework second because it is what RQ4 measures, platform last because
# it is what RQ4 excludes.
SERIES_VALUES: tuple[str, ...] = (SERIES_APP, SERIES_FRAMEWORK, SERIES_PLATFORM)

# THE NAMESPACE TABLE.
#
# Only `boutique` is fixed by a repository source today: the M1 plan's T1.2 and T1.3 verification
# steps both name `namespace="boutique"`. The framework entries are provisional and are listed here
# so that the table is total rather than half-written -- M2 lands the Monitor and M3 lands the
# Guardian, and each extends the framework side of this table in its own milestone, in the same
# commit that creates the namespace. Until then a framework namespace that does not exist simply
# never appears in a query result, which costs nothing; a framework namespace that exists under a
# different name falls to `platform` and says so on stderr, which is the case this table's loud
# fallback exists to catch.
#
# The platform entries are the measurement apparatus and the cluster's own machinery. They are
# listed explicitly, even though the fallback would classify them identically, because an explicit
# entry means "this was considered and classified" while a fallback means "nobody has looked at
# this yet", and the stderr notice is what keeps those two apart.
NAMESPACE_SERIES: Mapping[str, str] = {
    "boutique": SERIES_APP,
    "agents": SERIES_FRAMEWORK,
    "guardian": SERIES_FRAMEWORK,
    "monitor": SERIES_FRAMEWORK,
    "observability": SERIES_PLATFORM,
    "locust": SERIES_PLATFORM,
    "kube-system": SERIES_PLATFORM,
    "kube-public": SERIES_PLATFORM,
    "kube-node-lease": SERIES_PLATFORM,
    "local-path-storage": SERIES_PLATFORM,
    "netpol-probe": SERIES_PLATFORM,
}

# See the module docstring: a query smoothing parameter, not an evaluation constant, and so not
# mirrored into evaluation-protocol section 4.
DEFAULT_RATE_WINDOW_SECONDS = 60

DEFAULT_PROMETHEUS_URL = "http://127.0.0.1:9090"

# Every query aggregates to (namespace, pod, container) so the four results join on one key. The
# cAdvisor series carry a container="POD" entry for the pause container and a container="" entry
# for the pod-level cgroup rollup; both are excluded, because keeping either would double-count
# every pod against itself.
_CADVISOR_SELECTOR = '{container!="",container!="POD"}'
_BY = "sum by (namespace, pod, container)"

MEMORY_QUERY = f"{_BY} (container_memory_working_set_bytes{_CADVISOR_SELECTOR})"
# storage_bytes is the kubelet Summary API's per-container ephemeral-storage usage (rootfs + logs),
# NOT cAdvisor's container_fs_usage_bytes, which returns nothing on this kind cluster (defect V10;
# see
# the module docstring and ADR-133 / D15). The same per-container selector applies -- the series is
# keyed by (namespace, pod, container) so it joins the CPU and memory rows on one label set -- and
# excluding the empty and "POD" pseudo-containers is harmless where a summary series does not carry
# them. Making this series reach Prometheus is a companion scrape change outside this file; F-AN-03
# validates it on the live cluster and, if nothing reports, D15's LIMITATION path takes over.
STORAGE_QUERY = f"{_BY} (container_ephemeral_storage_used_bytes{_CADVISOR_SELECTOR})"
RESTARTS_QUERY = f'{_BY} (kube_pod_container_status_restarts_total{{container!=""}})'

# A sample key. `pod` is part of the query grain but not of the CSV grain; see the module docstring
# on granularity. Rows are aggregated from this key up to (namespace, workload, container).
SampleKey = tuple[str, str, str]

# A query function takes one PromQL expression and returns the `data.result` list of an instant
# query. Injectable so the unit tests never reach a Prometheus.
QueryFn = Callable[[str], list[dict[str, Any]]]

# Kubernetes generates pod-template hashes and pod name suffixes from an alphabet that omits vowels
# and the easily confused characters, so a real suffix never contains a, e, i, o or u. Matching that
# alphabet rather than [a-z0-9] is what keeps a static pod such as
# `kube-apiserver-<cluster>-control-plane` from having `plane` stripped off it as if it were a
# generated suffix.
_SAFE_ALPHABET = "bcdfghjklmnpqrstvwxz2456789"
_POD_SUFFIX = re.compile(f"^[{_SAFE_ALPHABET}]{{5}}$")
_TEMPLATE_HASH = re.compile(f"^[{_SAFE_ALPHABET}]{{5,10}}$")
_ORDINAL = re.compile(r"^\d+$")


def cpu_query(rate_window_seconds: int = DEFAULT_RATE_WINDOW_SECONDS) -> str:
    """Return the CPU PromQL for a given rate window.

    Built by a function rather than stored as a template because the window is the only part of any
    query in this module that varies, and a function keeps the one varying thing visible at its one
    call site instead of hidden inside a format string.
    """
    return (
        f"{_BY} (rate(container_cpu_usage_seconds_total"
        f"{_CADVISOR_SELECTOR}[{rate_window_seconds}s]))"
    )


@dataclass(frozen=True, slots=True)
class ResourceRow:
    """One row of ``resources.csv``, in the column order the header declares."""

    ts: str
    series: str
    namespace: str
    workload: str
    container: str
    cpu_cores: float
    mem_bytes: int
    storage_bytes: int
    restarts_total: int

    def as_row(self) -> list[str]:
        """Return the row as the list of strings ``csv.writer`` will quote and emit.

        ``cpu_cores`` keeps six decimals: a sidecar at a few hundred microcores is a real and
        interesting quantity in an overhead measure, and rounding it to milli-cores would floor a
        whole class of framework components to zero. The three byte and count columns are integers
        because they are counts of things, and a fractional byte in a CSV invites a reader to
        wonder whether it was interpolated.
        """
        return [
            self.ts,
            self.series,
            self.namespace,
            self.workload,
            self.container,
            f"{self.cpu_cores:.6f}",
            str(self.mem_bytes),
            str(self.storage_bytes),
            str(self.restarts_total),
        ]


class UnmappedNamespaceLog:
    """Reports namespaces absent from :data:`NAMESPACE_SERIES`, once each.

    Deduplication is the point. A collection runs for the length of a whole measurement window at
    the probe cadence, so an unmapped namespace would otherwise print hundreds of identical lines
    and train whoever reads the log to scroll past them -- which is the same as being silent, only
    noisier. One line per namespace, the first time it is seen, stays readable and stays noticed.
    """

    def __init__(self, emit: Callable[[str], None] | None = None) -> None:
        self._emit = emit if emit is not None else _notice
        self.seen: set[str] = set()

    def note(self, namespace: str) -> None:
        """Report ``namespace`` as unmapped unless it has already been reported."""
        if namespace in self.seen:
            return
        self.seen.add(namespace)
        self._emit(
            f"resource_collector: namespace {namespace!r} is not in NAMESPACE_SERIES; "
            f"classified as {SERIES_PLATFORM!r}. If it is a framework namespace, add it to the "
            "table in infra/collectors/resource_collector.py -- an unmapped framework namespace "
            "removes its own cost from the RQ4 overhead delta."
        )


def _notice(message: str) -> None:
    """Write one operator notice to stderr, leaving stdout free for machine-readable output."""
    print(message, file=sys.stderr)


def _utc_now() -> datetime:
    """Return the current instant as an aware UTC datetime; wrapped so tests can substitute it."""
    return datetime.now(UTC)


def format_timestamp(moment: datetime) -> str:
    """Render ``moment`` as the ISO-8601 UTC string written to the ``ts`` column."""
    return moment.astimezone(UTC).isoformat()


def series_for_namespace(namespace: str) -> str:
    """Return the series a namespace belongs to, defaulting to ``platform``.

    Pure and total: it never warns and never raises, so it can be called from a test or a REPL
    without side effects. The loud part of the contract belongs to :class:`UnmappedNamespaceLog`,
    which the collector consults for the same namespace; keeping the two apart means the fallback
    rule and the reporting of it can each be read on their own.
    """
    return NAMESPACE_SERIES.get(namespace, SERIES_PLATFORM)


def workload_from_pod_name(pod: str) -> str:
    """Return the workload name a pod belongs to, derived from its name.

    Three shapes are recognised, in order of specificity:

    * ``<workload>-<template-hash>-<suffix>`` -- a Deployment's pod, via its ReplicaSet. Both
      trailing segments are dropped.
    * ``<workload>-<ordinal>`` -- a StatefulSet's pod. The ordinal is dropped.
    * ``<workload>-<suffix>`` -- a DaemonSet, Job or bare ReplicaSet pod. The suffix is dropped.

    Anything else is returned unchanged, which is the right answer for a static pod such as
    ``etcd-<node>`` whose name has no generated part at all. See the module docstring: this is a
    labelling heuristic, and ``kube_pod_owner`` is the authoritative source if one is ever needed.
    """
    segments = pod.split("-")
    if (
        len(segments) >= 3
        and _POD_SUFFIX.match(segments[-1])
        and _TEMPLATE_HASH.match(segments[-2])
    ):
        return "-".join(segments[:-2])
    if len(segments) >= 2 and _ORDINAL.match(segments[-1]):
        return "-".join(segments[:-1])
    if len(segments) >= 2 and _POD_SUFFIX.match(segments[-1]):
        return "-".join(segments[:-1])
    return pod


def _require_http_url(url: str) -> None:
    """Reject any URL whose scheme is not ``http`` or ``https``, before it is opened.

    ``urllib.request.urlopen`` honours every scheme its opener knows, which includes ``file:``.
    The URL reaching it here is operator-supplied -- a command-line flag, and at M6 a runner
    manifest -- so without this check a mistyped or malicious value turns a network client into a
    local-file reader that reports its contents as an instrument reading. That is a small hole in a
    research tool and a large one in a bundle whose provenance is the thing being claimed.

    The check exists because ruff's ``S310`` asked the question and the honest answer was to
    validate rather than to silence it (ADR-026). The ``noqa`` at the call site points here.
    """
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(
            f"refusing to open {url!r}: scheme {scheme or '<none>'!r} is not http or https. "
            "This client speaks HTTP to an in-cluster endpoint; any other scheme is a "
            "configuration error, and one that would otherwise be read as a measurement."
        )


def prometheus_query_fn(
    base_url: str = DEFAULT_PROMETHEUS_URL,
    timeout_seconds: float = 10.0,
) -> QueryFn:
    """Return a :data:`QueryFn` bound to a Prometheus instant-query endpoint.

    ``urllib`` and ``json`` rather than a client library, because CI installs ``pytest`` and
    nothing else and a collector that cannot run without a third-party package would put a
    dependency on the critical path of every run for no capability this needs.

    A non-``success`` status from Prometheus raises rather than returning an empty result: an empty
    result and a failed query look identical in the CSV -- rows simply missing -- and a collector
    that cannot tell them apart writes a bundle that looks complete and is not.
    """
    endpoint = base_url.rstrip("/") + "/api/v1/query"

    def query(promql: str) -> list[dict[str, Any]]:
        url = endpoint + "?" + urllib.parse.urlencode({"query": promql})
        _require_http_url(url)
        request = urllib.request.Request(url, method="GET")  # noqa: S310
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310
            payload = json.loads(response.read().decode("utf-8"))
        if payload.get("status") != "success":
            raise RuntimeError(f"prometheus query failed: {payload.get('error', payload)}")
        return list(payload.get("data", {}).get("result", []))

    return query


def kubelet_storage_samples() -> list[dict[str, Any]]:
    """Read actual container rootfs and log usage through the operator's kubeconfig."""

    kubectl = shutil.which("kubectl")
    if kubectl is None:
        raise RuntimeError("kubelet storage collection requires kubectl on PATH")

    def read(path: str) -> dict[str, Any]:
        try:
            result = subprocess.run(  # noqa: S603 - fixed command and API-server node names
                [kubectl, "get", "--raw", path],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            return json.loads(result.stdout)
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            raise RuntimeError(f"kubelet storage collection failed for {path}") from error

    samples = []
    for node in read("/api/v1/nodes")["items"]:
        name = node["metadata"]["name"]
        summary = read(f"/api/v1/nodes/{name}/proxy/stats/summary")
        for pod in summary.get("pods", []):
            reference = pod["podRef"]
            for container in pod.get("containers", []):
                readings = [
                    container[component]["usedBytes"]
                    for component in ("rootfs", "logs")
                    if "usedBytes" in container.get(component, {})
                ]
                if readings:
                    samples.append(
                        {
                            "metric": {
                                "namespace": reference["namespace"],
                                "pod": reference["name"],
                                "container": container["name"],
                            },
                            "value": [0, str(sum(readings))],
                        }
                    )
    return samples


def live_query_fn(base_url: str = DEFAULT_PROMETHEUS_URL) -> QueryFn:
    """Prometheus for CPU/memory/restarts; kubelet Summary API for storage (ADR-162)."""
    prometheus = prometheus_query_fn(base_url)

    def query(expression: str) -> list[dict[str, Any]]:
        return kubelet_storage_samples() if expression == STORAGE_QUERY else prometheus(expression)

    return query


def _sample_value(sample: Mapping[str, Any]) -> float:
    """Return the numeric value of one instant-query sample, mapping non-finite results to zero.

    Prometheus renders a missing or undefined result as the string ``NaN``. Carrying that into the
    CSV would produce a column that some readers parse as a float and others as text, so it is
    normalised to zero here -- the same value an absent series contributes -- and the difference
    between "zero" and "absent" is preserved by the row existing at all.
    """
    raw = sample.get("value", (None, "0"))[1]
    value = float(raw)
    return value if value == value and abs(value) != float("inf") else 0.0


def _index(samples: Iterable[Mapping[str, Any]]) -> dict[SampleKey, float]:
    """Index instant-query samples by ``(namespace, pod, container)``."""
    indexed: dict[SampleKey, float] = {}
    for sample in samples:
        labels = sample.get("metric", {})
        key: SampleKey = (
            str(labels.get("namespace", "")),
            str(labels.get("pod", "")),
            str(labels.get("container", "")),
        )
        indexed[key] = _sample_value(sample)
    return indexed


def collect_once(
    query: QueryFn,
    ts: str,
    rate_window_seconds: int = DEFAULT_RATE_WINDOW_SECONDS,
    unmapped: UnmappedNamespaceLog | None = None,
) -> list[ResourceRow]:
    """Run the four queries once and return the rows of a single sample, in emission order.

    Every container that any of the four queries returned gets a row, and a metric missing for that
    container contributes zero rather than dropping the row. That asymmetry is deliberate: a
    container that has just started has no rate yet, and omitting it would make the timeline show a
    workload appearing several samples after it actually did, which is exactly the kind of shift
    that turns an overhead delta into a fiction.

    Rows are sorted by ``(series, namespace, workload, container)``. Prometheus does not promise a
    result order, and a CSV whose row order varies between two runs of the same scenario would
    diff as a change under ``.agents/rules/20-parity-and-determinism.md`` while carrying identical
    measurements.
    """
    cpu = _index(query(cpu_query(rate_window_seconds)))
    memory = _index(query(MEMORY_QUERY))
    storage = _index(query(STORAGE_QUERY))
    restarts = _index(query(RESTARTS_QUERY))

    totals: dict[tuple[str, str, str], list[float]] = {}
    for key in set(cpu) | set(memory) | set(storage) | set(restarts):
        namespace, pod, container = key
        if unmapped is not None and namespace not in NAMESPACE_SERIES:
            unmapped.note(namespace)
        grain = (namespace, workload_from_pod_name(pod), container)
        bucket = totals.setdefault(grain, [0.0, 0.0, 0.0, 0.0])
        bucket[0] += cpu.get(key, 0.0)
        bucket[1] += memory.get(key, 0.0)
        bucket[2] += storage.get(key, 0.0)
        bucket[3] += restarts.get(key, 0.0)

    def _order(grain: tuple[str, str, str]) -> tuple[int, str, str, str]:
        return (SERIES_VALUES.index(series_for_namespace(grain[0])), *grain)

    return [
        ResourceRow(
            ts=ts,
            series=series_for_namespace(namespace),
            namespace=namespace,
            workload=workload,
            container=container,
            cpu_cores=totals[(namespace, workload, container)][0],
            mem_bytes=int(totals[(namespace, workload, container)][1]),
            storage_bytes=int(totals[(namespace, workload, container)][2]),
            restarts_total=int(totals[(namespace, workload, container)][3]),
        )
        for namespace, workload, container in sorted(totals, key=_order)
    ]


def run_collection(
    query: QueryFn,
    samples: int | None = None,
    duration_seconds: float | None = None,
    interval_seconds: float = float(PROBE_INTERVAL_SECONDS),
    rate_window_seconds: int = DEFAULT_RATE_WINDOW_SECONDS,
    unmapped: UnmappedNamespaceLog | None = None,
    now: Callable[[], datetime] = _utc_now,
    sleep: Callable[[float], None] = _sleep,
    monotonic: Callable[[], float] = _monotonic,
) -> Iterator[ResourceRow]:
    """Yield resource rows, sampling every container once per tick on the probe cadence.

    Exactly one of ``samples`` and ``duration_seconds`` must be given. The scheduling rule is the
    one :func:`infra.probes.slo_probe.run_timeline` uses and for the same reasons: absolute
    deadlines so the cadence does not drift, no back-to-back catch-up after an overrun, and a
    stopping rule counted in ticks emitted rather than in schedule slots.
    """
    if (samples is None) == (duration_seconds is None):
        raise ValueError("exactly one of samples and duration_seconds must be given")

    start = monotonic()
    emitted = 0
    slot = 0
    while True:
        if samples is not None and emitted >= samples:
            return
        if duration_seconds is not None and monotonic() - start >= duration_seconds:
            return
        if slot:
            pause = (start + slot * interval_seconds) - monotonic()
            if pause > 0:
                sleep(pause)
        yield from collect_once(
            query,
            ts=format_timestamp(now()),
            rate_window_seconds=rate_window_seconds,
            unmapped=unmapped,
        )
        emitted += 1
        slot = max(slot + 1, int((monotonic() - start) // interval_seconds) + 1)


def write_rows(rows: Iterable[ResourceRow], out_path: Path) -> int:
    """Append ``rows`` to the CSV at ``out_path`` and return how many were written.

    The header is written only when the file does not exist or is empty, and each row is flushed as
    it is produced, for the reasons :func:`infra.probes.slo_probe.write_rows` documents: a
    collector killed by the per-run timeout must leave what it had on disk, because a partial
    series is evidence and an empty file is not.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    needs_header = not out_path.exists() or out_path.stat().st_size == 0
    written = 0
    with out_path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator=CSV_LINE_TERMINATOR)
        if needs_header:
            writer.writerow(RESOURCES_CSV_HEADER)
        for row in rows:
            writer.writerow(row.as_row())
            handle.flush()
            written += 1
    return written


def build_parser() -> argparse.ArgumentParser:
    """Return the command-line parser.

    ``--duration`` and ``--samples`` are a required, mutually exclusive pair with no default, for
    the reason ``slo_probe.py`` states: the length of a measurement window has no owner in any
    protocol file yet, and a default here would quietly become that owner.
    """
    parser = argparse.ArgumentParser(
        prog="python -m infra.collectors.resource_collector",
        description=(
            "Sample per-container CPU, memory, storage and restart counters from the Prometheus "
            "HTTP API and append the resources.csv series, labelling each row app, framework or "
            "platform."
        ),
    )
    parser.add_argument(
        "--out", required=True, type=Path, help="Path of the resources.csv to append."
    )
    parser.add_argument(
        "--prometheus-url",
        default=DEFAULT_PROMETHEUS_URL,
        help=(
            "Base URL of the Prometheus HTTP API. An operator convenience defaulting to the "
            "conventional port-forward, not a pin: the address is an environment fact and has no "
            "home in the protocol."
        ),
    )
    parser.add_argument(
        "--rate-window-seconds",
        type=int,
        default=DEFAULT_RATE_WINDOW_SECONDS,
        metavar="SECONDS",
        help=(
            "Window for the CPU rate. A query smoothing parameter, not an evaluation constant; "
            "see the module docstring for why it is not mirrored into the protocol."
        ),
    )
    stop = parser.add_mutually_exclusive_group(required=True)
    stop.add_argument("--duration", type=float, metavar="SECONDS", help="Stop after this long.")
    stop.add_argument("--samples", type=int, metavar="N", help="Stop after N collection ticks.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run a collection and return the process exit code.

    Exit codes are deliberately few: 0 when a series was written, 1 when it was not. Unlike the SLO
    probe this module forms no verdict -- resource usage has no threshold in any protocol file, and
    inventing one here would create a number with no owner.
    """
    args = build_parser().parse_args(argv)
    unmapped = UnmappedNamespaceLog()

    _notice(
        f"resource_collector: sampling every {PROBE_INTERVAL_SECONDS}s "
        f"(probe cadence, evaluation-protocol section 4), rate window "
        f"{args.rate_window_seconds}s, prometheus {args.prometheus_url}, out {args.out}"
    )

    query = live_query_fn(args.prometheus_url)
    try:
        written = write_rows(
            run_collection(
                query,
                samples=args.samples,
                duration_seconds=args.duration,
                rate_window_seconds=args.rate_window_seconds,
                unmapped=unmapped,
            ),
            args.out,
        )
    except OSError as failure:
        _notice(f"resource_collector: could not write {args.out}: {failure}")
        return 1
    except RuntimeError as failure:
        _notice(f"resource_collector: {failure}")
        return 1

    _notice(f"resource_collector: wrote {written} rows to {args.out}")
    if written == 0:
        _notice(
            "resource_collector: no rows were produced. data-management section 3 refuses to seal "
            "a bundle whose resources.csv lacks a populated restarts_total column, so an empty "
            "series here will fail the completeness check later rather than here."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
