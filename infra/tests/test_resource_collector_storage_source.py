r"""D15: the storage source the resource collector reads, and the LIMITATION that replaces it.

THE DEFECT THIS FILE IS WRITTEN AGAINST
---------------------------------------
``docs/plans/M10-implementation-plan.md`` section 1 records V10: "``storage_bytes`` is 0 in every
row
on both sides ... the collector's ``container_fs_usage_bytes`` query
(``infra/collectors/resource_collector.py:194,240``) returns nothing on this cluster". A storage
column that reads zero on *both* sides of every comparison is not a measurement of zero; it is an
absent measurement wearing a number, and RQ4's storage term was ``nan`` corpus-wide for that reason.

D15's decision (section 3) is to **replace the source** -- naming kubelet ``/stats/summary``
ephemeral-storage ``usedBytes`` as the candidate -- with a P0-live check (F-AN-03) that storage is
non-zero for at least one probed container, and **if no source works**, to report storage as a
LIMITATION "not collected", never as zero bytes.

So this file tests the source, not the arithmetic:

* :func:`test_the_v1_storage_metric_is_never_queried` fails on the current collector and is the
  regression test for the replacement. It is stated as a property of a *collection run* rather than
  of a string constant, so it holds whichever way the replacement is spelled -- another PromQL
  metric, or a kubelet ``/stats/summary`` fetch that is not a PromQL at all -- and it cannot be
  satisfied by leaving the broken query in the module while adding a second, unused one.
* :func:`test_a_non_zero_storage_reading_reaches_the_row` is the control: it proves the plumbing
  still carries a storage value into ``resources.csv`` after the replacement.
* :func:`test_the_analysis_side_agrees_that_a_missing_storage_series_was_not_collected` is the half
  of D15 that does not depend on the source working at all, and it is why the two sides have to
  agree:
  the collector writes zero because it read nothing, and
  ``analysis.stats.measures.resource_overhead``
  must read that zero as "not collected" (``collected is False``, ``pct_delta`` ``nan``) rather than
  as
  a measured zero-byte overhead. It is the same claim as
  ``analysis/tests/test_measures.py::test_storage_limitation_when_not_collected``, reached from the
  other end: that one hand-writes the ``resources.csv`` rows, this one *collects* them.

WHAT A FIXER MUST ALSO UPDATE
-----------------------------
``infra/tests/test_resources_schema.py`` dispatches its fixture query on the metric name inside the
PromQL and asserts ``"container_fs_usage_bytes" in STORAGE_QUERY`` (in its
``test_the_queries_name_the_metrics_the_protocol_names``). Replacing the source breaks that file's
``fixture_query`` -- which raises ``AssertionError`` on an unrecognised query -- so it has to move
with the collector. This file deliberately does not edit it: the collector and its existing test are
one unit, and a test that edited the other half of that unit to match itself would prove nothing.

NO CLUSTER, NO PROMETHEUS, NO SOCKET
------------------------------------
The query function is injected, exactly as in ``test_resources_schema.py``, and every double here
answers from an inline fixture shaped like a Prometheus instant-query ``data.result`` list. The one
import from ``analysis/`` is the module that decides what a zero in the CSV means; it reads a bundle
this test writes, and touches no service.
"""

import json
import math
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from infra.collectors.resource_collector import (  # noqa: E402
    collect_once,
    format_timestamp,
    workload_from_pod_name,
    write_rows,
)

# The v1 source, named once. D15 replaces it, so a test that merely repeated the literal out of the
# collector's own source would keep passing after a partial fix; naming it here is what makes the
# assertion "this metric is gone" rather than "this metric is still spelled the old way".
V1_STORAGE_METRIC = "container_fs_usage_bytes"

TS = format_timestamp(datetime(2026, 1, 1, tzinfo=UTC))

# One probed container per series class, in the vowel-free alphabet Kubernetes generates pod
# suffixes
# from, because `workload_from_pod_name` is written against it. `guardian` is the framework
# namespace
# and `boutique` the app one, so the two bundles below differ by namespace alone and the `series`
# column is derived by the collector rather than asserted here.
APP_POD = ("boutique", "frontend-6b8d4c7f9-t4wnp", "server")
FRAMEWORK_POD = ("guardian", "guardian-api-5b569cd47-9htxq", "guardian")
PROBED = (APP_POD, FRAMEWORK_POD)

# A non-zero storage reading, deliberately not a round number of bytes: D15's check is "non-zero",
# and a fixture whose value was obviously synthetic would be one a fixer could satisfy by
# special-casing it.
STORAGE_BYTES = 4_194_304

MEM_BYTES = 1_048_576


def _samples(values: dict[tuple[str, str, str], object]) -> list[dict]:
    """Return a Prometheus ``data.result`` list for ``{(namespace, pod, container): value}``."""
    return [
        {
            "metric": {"namespace": namespace, "pod": pod, "container": container},
            "value": [1767225600.0, str(value)],
        }
        for (namespace, pod, container), value in values.items()
    ]


def _measurement(promql: str) -> str:
    """Name which of the collector's measurements a PromQL is asking for.

    Dispatch is by *what the query is for*, and for storage by exclusion: the CPU, memory and
    restart
    metrics are named by ``data-management.md`` section 1 and are stable, while the storage source
    is
    the one D15 is replacing and is not spelled yet. So the three known ones are matched by name and
    everything else is the storage question -- which is what lets the doubles below work for a
    replacement this file has never seen.
    """
    for metric, kind in (
        ("container_cpu_usage_seconds_total", "cpu"),
        ("container_memory_working_set_bytes", "memory"),
        ("kube_pod_container_status_restarts_total", "restarts"),
    ):
        if metric in promql:
            return kind
    return "storage"


def _query_double(storage: dict[tuple[str, str, str], object]):
    """Return a query double that records every PromQL and answers the storage question from
    ``storage`` and the other three from fixed readings.

    A measurement answered with an empty dict answers with an empty result, which is what "this
    source
    reported nothing" looks like to the collector.

    The recording is the point of using a double rather than asserting on ``STORAGE_QUERY``: it
    proves
    what the collector *asks* at run time, so a module that kept the v1 query around unused would
    still
    fail.
    """
    seen: list[str] = []

    def query(promql: str) -> list[dict]:
        seen.append(promql)
        kind = _measurement(promql)
        if kind == "storage":
            return _samples(storage)
        if kind == "cpu":
            return _samples({key: 0.125 for key in PROBED})
        if kind == "memory":
            return _samples({key: MEM_BYTES for key in PROBED})
        return _samples({key: 0 for key in PROBED})

    query.seen = seen  # type: ignore[attr-defined]
    return query


def _collect(query) -> list:
    """Run one collection tick at a fixed timestamp and return its rows."""
    return collect_once(query, ts=TS)


def _rows_by_workload(rows) -> dict[tuple[str, str], object]:
    """Index collected rows by ``(namespace, container)``, the grain the CSV actually has."""
    return {(row.namespace, row.container): row for row in rows}


# ------------------------------------------------------------------------------------------------
# The source itself
# ------------------------------------------------------------------------------------------------


def test_the_v1_storage_metric_is_never_queried() -> None:
    """D15's regression test, and the one that fails on the unfixed collector.

    ``container_fs_usage_bytes`` returns nothing on this cluster, so every storage cell v1 recorded
    was a fabricated zero. The assertion is made against the queries a real collection issues rather
    than against the module's text, for the reason the module docstring gives: it survives being
    spelled differently, and it does not pass for a module that merely stopped *using* the constant.
    """
    query = _query_double({key: STORAGE_BYTES for key in PROBED})
    _collect(query)
    assert query.seen, "the collector issued no query at all, so nothing was proved"
    offenders = [promql for promql in query.seen if V1_STORAGE_METRIC in promql]
    assert not offenders, (
        f"the collector still queries {V1_STORAGE_METRIC} ({offenders}), which returns nothing on "
        "this cluster and made every v1 storage cell a fabricated zero (V10). D15 replaces the "
        "source -- see docs/plans/M10-implementation-plan.md section 3"
    )


def test_a_non_zero_storage_reading_reaches_the_row() -> None:
    """The control: whatever the replacement source is, its value lands in ``storage_bytes``.

    Passes only if the whole path still works end to end -- query, index, aggregate to the
    (namespace, workload, container) grain, cast to int. A replacement added *beside* the old query
    rather than in place of it would leave this reading zero, which is why the case is here and not
    only the offender check above.
    """
    query = _query_double({key: STORAGE_BYTES for key in PROBED})
    rows = _rows_by_workload(_collect(query))
    for namespace, pod, container in PROBED:
        row = rows[(namespace, container)]
        assert row.workload == workload_from_pod_name(pod)
        assert row.storage_bytes == STORAGE_BYTES, (
            f"{namespace}/{container}: storage_bytes is {row.storage_bytes}, so the collector is "
            "still reading a source that reports nothing on this cluster"
        )


def test_a_queried_but_absent_storage_series_writes_zero_and_keeps_the_row() -> None:
    """A source that reports nothing must not delete the row, and must not invent a value either.

    The first half is the collector's long-standing asymmetry -- a container missing one metric
    still
    gets a row, so the timeline does not shift -- and the second is D15's requirement that the
    *zero*
    it writes is understood downstream as "not collected", which the next test proves and this one
    sets up.
    """
    rows = _collect(_query_double({}))
    assert len(rows) == len(PROBED), "an absent storage series must not drop the probed rows"
    assert all(row.storage_bytes == 0 for row in rows)
    assert all(row.mem_bytes == MEM_BYTES for row in rows), "the other metrics must be unaffected"


# ------------------------------------------------------------------------------------------------
# The D15 fallback: the collector's zero and the analysis's reading of it must agree
# ------------------------------------------------------------------------------------------------


def _write_bundle(
    directory: Path,
    run_id: str,
    *,
    is_baseline: bool,
    storage: dict[tuple[str, str, str], object],
) -> Path:
    """Collect one bundle's ``resources.csv`` with the doubles above and write its manifest.

    The bundle is built by *running the collector* rather than by writing rows, which is the whole
    point of the case below: the value the analysis reads is the value the collector wrote, produced
    by the same code path a live collection uses.
    """
    directory.mkdir(parents=True, exist_ok=True)
    write_rows(_collect(_query_double(storage)), directory / "resources.csv")
    manifest = {
        "run_id": run_id,
        "campaign_id": "CAMP-20260101-synthetic",
        "condition": None if is_baseline else "G0-FULL",
        "scenario_id": None if is_baseline else "SCN-CVE-04",
        "injection_condition": None if is_baseline else "INJ-NONE",
        "seed": 101,
        "is_baseline": is_baseline,
        "baseline_run_id": None if is_baseline else "BASE-LOAD-STEADY-101",
        "load_profile_id": "LOAD-STEADY",
        "schema_version": "v1",
    }
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return directory


def test_the_analysis_side_agrees_that_a_missing_storage_series_was_not_collected(
    tmp_path: Path,
) -> None:
    """The two ends of D15's fallback, in one case, over bundles this test collected itself.

    The framework-on run's storage source reported nothing, so the collector wrote
    ``storage_bytes = 0``; the baseline app DID report storage. That asymmetry is the interesting
    one:
    a zero over a non-zero baseline computes to ``0.0%``, which reads as "the framework used no
    extra
    storage" -- precisely the fabricated claim D15 forbids and v1 published in every row of both
    sides. So the analysis must read the series as ``collected is False`` with a ``nan`` percentage,
    and never as a measured zero.

    The claim is the one
    ``analysis/tests/test_measures.py::test_storage_limitation_when_not_collected``
    makes; the difference is where the ``resources.csv`` came from. That one hand-writes the rows,
    this one runs the collector, so the two agree about the *value* and neither can drift about the
    *meaning*.
    """
    from analysis.stats.loader import load_bundle
    from analysis.stats.measures import resource_overhead

    framework_on = load_bundle(
        _write_bundle(
            tmp_path / "on",
            "RUN-G0-FULL-SCN-CVE-04-INJ-NONE-101",
            is_baseline=False,
            storage={},
        )
    )
    baseline = load_bundle(
        _write_bundle(
            tmp_path / "base",
            "BASE-LOAD-STEADY-101",
            is_baseline=True,
            storage={APP_POD: STORAGE_BYTES},
        )
    )
    result = resource_overhead(framework_on, baseline)
    storage = next(delta for delta in result.deltas if delta.resource == "storage_bytes")
    cpu = next(delta for delta in result.deltas if delta.resource == "cpu_cores")

    assert storage.collected is False, (
        "the framework-on run's storage source reported nothing, so the zero the collector wrote is "  # noqa: E501 - message
        "an absent measurement. Reading it as collected reports a zero-byte storage overhead, which "  # noqa: E501 - message
        "is what D15 forbids and what v1 did in every row"
    )
    assert math.isnan(storage.pct_delta), (
        f"pct_delta is {storage.pct_delta!r}; an uncollected resource must report nan, never a "
        "number, because any number here is arithmetic on an absent measurement"
    )
    assert cpu.collected is True, "CPU is not D15's concern and must keep reporting"
