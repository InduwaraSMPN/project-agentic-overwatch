"""Schema and behaviour tests for the ``resources.csv`` writer.

WHAT IS UNDER TEST
------------------
``docs/protocols/data-management.md`` section 1 owns the column set and order of ``resources.csv``,
and its section 3 states the completeness check that refuses to seal a bundle whose file lacks a
populated ``restarts_total`` column. ``infra/collectors/resource_collector.py`` is the only writer
of that file. As with the probe tests, the assertions are made against bytes read back from a
temporary file, not against the module's own header tuple.

THE THREE-VALUED SERIES IS THE POINT
------------------------------------
``series`` exists so that the RQ4 overhead delta is taken over the framework and not over the
framework plus the apparatus that measures it. So the tests below do not merely check that the
column is present: they check that all three values are producible from one collection, that a
namespace nobody has classified lands in ``platform`` rather than in ``framework``, and that it
says so on the way -- once, not once per sample.

NO CLUSTER, NO PROMETHEUS, NO SOCKET
------------------------------------
These run in CI's ``Unit tests -- infra`` step on a runner with neither. The query function is
injected and answers from a fixture defined inline in this file, shaped exactly like a Prometheus
instant-query ``data.result`` list, so the collector's own parsing is exercised rather than
bypassed.
"""

import csv
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

# The repository root, from this file's location rather than from the working directory, so the
# import works however pytest was invoked. See the same block in test_constants_match_protocol.py.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from infra.collectors.resource_collector import (  # noqa: E402
    MEMORY_QUERY,
    NAMESPACE_SERIES,
    RESOURCES_CSV_HEADER,
    RESTARTS_QUERY,
    SERIES_VALUES,
    STORAGE_QUERY,
    UnmappedNamespaceLog,
    collect_once,
    cpu_query,
    format_timestamp,
    run_collection,
    series_for_namespace,
    workload_from_pod_name,
    write_rows,
)
from infra.probes.constants import PROBE_INTERVAL_SECONDS  # noqa: E402

# The column order data-management section 1 fixes. Written out as a literal rather than imported,
# so that changing the module's tuple has to be done twice and reviewed against the protocol both
# times.
EXPECTED_HEADER = [
    "ts",
    "series",
    "namespace",
    "workload",
    "container",
    "cpu_cores",
    "mem_bytes",
    "storage_bytes",
    "restarts_total",
]

# One pod per series class, plus an unclassified namespace, so a single collection exercises every
# branch of the namespace table. The pod names use the vowel-free alphabet Kubernetes generates
# suffixes from, because that is what the workload derivation is written against.
FIXTURE_PODS = (
    ("boutique", "frontend-6b8d4c7f9-t4wnp", "server"),
    ("guardian", "guardian-api-5b569cd47-9htxq", "guardian"),
    ("observability", "prometheus-server-0", "prometheus"),
    ("some-unmapped-namespace", "mystery-workload-7f4kd", "mystery"),
)


def _samples(values):
    """Return a Prometheus ``data.result`` list for ``{(ns, pod, container): value}``."""
    return [
        {
            "metric": {"namespace": namespace, "pod": pod, "container": container},
            "value": [1767225600.0, str(value)],
        }
        for (namespace, pod, container), value in values.items()
    ]


def fixture_query(overrides=None):
    """Return a query function answering the four collector queries from an inline fixture.

    Dispatch is on the metric name inside the PromQL rather than on call order, so a change to the
    order the collector issues its queries in does not silently start answering the CPU question
    with the memory numbers.
    """
    base = {
        "container_cpu_usage_seconds_total": {key: 0.125 for key in FIXTURE_PODS},
        "container_memory_working_set_bytes": {key: 1048576 for key in FIXTURE_PODS},
        "container_ephemeral_storage_used_bytes": {key: 4096 for key in FIXTURE_PODS},
        "kube_pod_container_status_restarts_total": {key: 2 for key in FIXTURE_PODS},
    }
    if overrides:
        base.update(overrides)

    def query(promql: str):
        for metric, values in base.items():
            if metric in promql:
                return _samples(values)
        raise AssertionError(f"unexpected query: {promql}")

    return query


def read_csv(path: Path) -> list[list[str]]:
    """Return the CSV at ``path`` parsed into rows, header included."""
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.reader(handle))


def collect(query=None, unmapped=None) -> list:
    """Run one collection tick at a fixed timestamp and return its rows."""
    return collect_once(
        query if query is not None else fixture_query(),
        ts=format_timestamp(datetime(2026, 1, 1, tzinfo=UTC)),
        unmapped=unmapped,
    )


def drive(tmp_path: Path, query=None, samples: int = 1) -> Path:
    """Drive the writer end to end against fakes and return the path it wrote."""
    out = tmp_path / "resources.csv"
    write_rows(
        run_collection(
            query if query is not None else fixture_query(),
            samples=samples,
            now=lambda: datetime(2026, 1, 1, tzinfo=UTC),
            sleep=lambda _seconds: None,
            monotonic=lambda: 0.0,
        ),
        out,
    )
    return out


def test_header_row_is_the_protocol_column_order(tmp_path: Path) -> None:
    """The first line of the file is exactly the columns data-management section 1 declares."""
    rows = read_csv(drive(tmp_path))
    assert rows[0] == EXPECTED_HEADER
    assert list(RESOURCES_CSV_HEADER) == EXPECTED_HEADER


def test_restarts_total_is_present_and_populated(tmp_path: Path) -> None:
    """data-management section 3 refuses to seal a bundle without this column populated."""
    rows = read_csv(drive(tmp_path))
    assert "restarts_total" in rows[0]
    column = rows[0].index("restarts_total")
    assert rows[1:], "no data rows were produced"
    for row in rows[1:]:
        assert row[column] != ""
        assert int(row[column]) >= 0


def test_all_three_series_values_are_producible(tmp_path: Path) -> None:
    """app, framework and platform all appear from one collection over the fixture."""
    rows = read_csv(drive(tmp_path))
    column = rows[0].index("series")
    produced = {row[column] for row in rows[1:]}
    assert produced == set(SERIES_VALUES)


def test_rows_are_emitted_app_then_framework_then_platform(tmp_path: Path) -> None:
    """Row order is deterministic; Prometheus promises no ordering of its own."""
    rows = read_csv(drive(tmp_path))
    column = rows[0].index("series")
    order = [row[column] for row in rows[1:]]
    assert order == sorted(order, key=SERIES_VALUES.index)
    assert order[0] == "app"


def test_the_file_uses_lf_line_endings(tmp_path: Path) -> None:
    """No CR bytes anywhere: a bundle's bytes must not depend on the host that wrote them."""
    assert b"\r" not in drive(tmp_path).read_bytes()


def test_one_timestamp_per_tick(tmp_path: Path) -> None:
    """Every row of one sample carries the same ``ts``, so a sample groups exactly."""
    rows = read_csv(drive(tmp_path))
    assert len({row[0] for row in rows[1:]}) == 1


def test_an_unmapped_namespace_falls_to_platform() -> None:
    """The fallback direction is conservative: never framework, always platform."""
    assert series_for_namespace("some-unmapped-namespace") == "platform"
    assert series_for_namespace("boutique") == "app"
    assert series_for_namespace("guardian") == "framework"
    assert set(NAMESPACE_SERIES.values()) <= set(SERIES_VALUES)


def test_an_unmapped_namespace_is_reported_once() -> None:
    """Loud, but not so loud it trains the reader to scroll past it."""
    heard: list[str] = []
    unmapped = UnmappedNamespaceLog(emit=heard.append)
    for _ in range(3):
        collect(unmapped=unmapped)
    assert len(heard) == 1
    assert "some-unmapped-namespace" in heard[0]
    assert "platform" in heard[0]
    assert unmapped.seen == {"some-unmapped-namespace"}


def test_a_mapped_namespace_is_never_reported() -> None:
    """Only the genuinely unclassified is announced; the table's own entries are silent."""
    heard: list[str] = []
    query = fixture_query(
        {
            "container_cpu_usage_seconds_total": {("boutique", "frontend-6b8d4c7f9-t4wnp", "s"): 1},
            "container_memory_working_set_bytes": {},
            "container_ephemeral_storage_used_bytes": {},
            "kube_pod_container_status_restarts_total": {},
        }
    )
    collect(query=query, unmapped=UnmappedNamespaceLog(emit=heard.append))
    assert heard == []


@pytest.mark.parametrize(
    ("pod", "expected"),
    [
        ("frontend-6b8d4c7f9-t4wnp", "frontend"),
        ("redis-cart-5b569cd47-9htxq", "redis-cart"),
        ("prometheus-server-0", "prometheus-server"),
        ("cilium-9htxq", "cilium"),
        ("kube-apiserver-overwatch-control-plane", "kube-apiserver-overwatch-control-plane"),
        ("standalone", "standalone"),
    ],
)
def test_workload_is_derived_from_the_pod_name(pod: str, expected: str) -> None:
    """Deployment, StatefulSet and DaemonSet suffixes are stripped; static pod names are not.

    The ``control-plane`` case is the one that motivates matching the vowel-free alphabet
    Kubernetes actually generates suffixes from: a naive five-character rule would strip ``plane``
    off every static pod and invent a workload nobody deployed.
    """
    assert workload_from_pod_name(pod) == expected


def test_replicas_of_one_workload_aggregate_into_one_row() -> None:
    """The schema has no pod column, so replicas sum rather than producing duplicate keys."""
    pods = {
        ("boutique", "frontend-6b8d4c7f9-t4wnp", "server"): 1,
        ("boutique", "frontend-6b8d4c7f9-9htxq", "server"): 3,
    }
    query = fixture_query(
        {
            "container_cpu_usage_seconds_total": pods,
            "container_memory_working_set_bytes": pods,
            "container_ephemeral_storage_used_bytes": pods,
            "kube_pod_container_status_restarts_total": pods,
        }
    )
    rows = collect(query=query)
    assert len(rows) == 1
    assert rows[0].workload == "frontend"
    assert rows[0].cpu_cores == pytest.approx(4.0)
    assert rows[0].restarts_total == 4


def test_a_container_missing_one_metric_still_gets_a_row() -> None:
    """A just-started container has no rate yet; dropping it would shift the timeline."""
    key = ("boutique", "frontend-6b8d4c7f9-t4wnp", "server")
    query = fixture_query(
        {
            "container_cpu_usage_seconds_total": {},
            "container_memory_working_set_bytes": {key: 2048},
            "container_ephemeral_storage_used_bytes": {},
            "kube_pod_container_status_restarts_total": {key: 0},
        }
    )
    rows = collect(query=query)
    assert len(rows) == 1
    assert rows[0].cpu_cores == 0.0
    assert rows[0].mem_bytes == 2048
    assert rows[0].storage_bytes == 0
    assert rows[0].restarts_total == 0


def test_a_nan_value_becomes_zero() -> None:
    """Prometheus renders an undefined result as NaN; the CSV column stays numeric."""
    key = ("boutique", "frontend-6b8d4c7f9-t4wnp", "server")
    query = fixture_query(
        {
            "container_cpu_usage_seconds_total": {key: "NaN"},
            "container_memory_working_set_bytes": {key: 1},
            "container_ephemeral_storage_used_bytes": {key: 1},
            "kube_pod_container_status_restarts_total": {key: 0},
        }
    )
    assert collect(query=query)[0].cpu_cores == 0.0


def test_the_queries_name_the_metrics_the_protocol_names() -> None:
    """The restart counter in particular is named by data-management section 3, not chosen here."""
    assert "kube_pod_container_status_restarts_total" in RESTARTS_QUERY
    assert "container_memory_working_set_bytes" in MEMORY_QUERY
    assert "container_ephemeral_storage_used_bytes" in STORAGE_QUERY
    assert "container_cpu_usage_seconds_total" in cpu_query()
    assert "rate(" in cpu_query()
    assert "[45s]" in cpu_query(45)


def test_the_cadence_comes_from_the_protocol_constant() -> None:
    """The collector samples on the probe interval, imported and never restated.

    The two timelines have to line up sample for sample: that is how a restart or a memory spike in
    ``resources.csv`` gets attributed to a dip in ``probes.csv``.
    """
    pauses: list[float] = []
    list(
        run_collection(
            fixture_query(),
            samples=3,
            now=lambda: datetime(2026, 1, 1, tzinfo=UTC),
            sleep=pauses.append,
            monotonic=lambda: 0.0,
        )
    )
    assert pauses == [float(PROBE_INTERVAL_SECONDS), float(PROBE_INTERVAL_SECONDS) * 2]


def test_a_missing_stopping_rule_is_rejected() -> None:
    """Neither stopping rule, or both, is a programming error and not a silent default."""
    with pytest.raises(ValueError):
        list(run_collection(fixture_query()))
    with pytest.raises(ValueError):
        list(run_collection(fixture_query(), samples=1, duration_seconds=1.0))


def test_appending_does_not_repeat_the_header(tmp_path: Path) -> None:
    """A restarted collector extends its series rather than starting a second one."""
    out = tmp_path / "resources.csv"
    for _ in range(2):
        write_rows(
            run_collection(
                fixture_query(),
                samples=1,
                now=lambda: datetime(2026, 1, 1, tzinfo=UTC),
                sleep=lambda _seconds: None,
                monotonic=lambda: 0.0,
            ),
            out,
        )
    rows = read_csv(out)
    assert rows[0] == EXPECTED_HEADER
    assert [row for row in rows[1:] if row[0] == "ts"] == []
    assert len(rows) == 1 + 2 * len(FIXTURE_PODS)
