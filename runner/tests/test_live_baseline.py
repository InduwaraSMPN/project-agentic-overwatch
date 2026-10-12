"""Live baseline orchestration tests using only injectable in-process fakes."""

import contextlib
import csv
import json
import sys
import threading
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from infra.locust.driver import HttpResponse  # noqa: E402

from runner.baseline import BaselineError, MeasurementWindow, run_baseline  # noqa: E402
from runner.live_baseline import (  # noqa: E402
    PROBE_DONE_MARKER,
    PROBE_NAMESPACE,
    PROBE_OUTPUT_PATH,
    PROBE_POD_TEMPLATE,
    KubectlResult,
    LiveMeasurementError,
    collect_concurrently,
    in_cluster_probe_output,
    probe_writer,
    render_probe_pod,
)
from runner.provenance import build_run_manifest  # noqa: E402

CAMPAIGN = "CAMP-20260101-live"
LOCUST_STATS = (
    b"Type,Name,Request Count,Failure Count,Median Response Time,50%,95%\n"
    b",Aggregated,12,0,20,20,60\n"
)


class LocustTransport:
    def __init__(self) -> None:
        self.paths: list[str] = []

    def __call__(self, method: str, url: str, body: bytes | None, timeout: float) -> HttpResponse:
        del method, body, timeout
        path = url.removeprefix("http://127.0.0.1:8089")
        self.paths.append(path)
        return HttpResponse(200, LOCUST_STATS if path.endswith("/csv") else b"ok")


def _probe(path: Path, window: MeasurementWindow) -> int:
    assert window.samples == 1
    path.write_text(
        "ts,probe_id,target,method,status_code,latency_ms,ok,error\n"
        "2026-01-01T00:00:00+00:00,health,/_healthz,GET,200,1.0,true,\n",
        encoding="utf-8",
    )
    return 1


def _resources(path: Path, window: MeasurementWindow) -> int:
    assert window.samples == 1
    path.write_text(
        "ts,series,namespace,workload,container,cpu_cores,mem_bytes,storage_bytes,restarts_total\n"
        "2026-01-01T00:00:00+00:00,app,boutique,frontend,server,0.1,100,0,0\n",
        encoding="utf-8",
    )
    return 1


def _manifest_builder(*args: object, **kwargs: object):
    return build_run_manifest(
        args[0],
        args[1],
        rerun_of=kwargs.get("rerun_of"),
        started_at=kwargs.get("started_at"),
        ended_at=kwargs.get("ended_at"),
        environ={},
    )


def test_live_baseline_produces_and_seals_all_real_required_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    transport = LocustTransport()
    monkeypatch.setattr("runner.provenance._command", lambda argv: "a" * 40)
    # ADR-087 (Lease stream) nested cluster_lease(run_id) inside runner.baseline's own file lock,
    # and its default path issues a real `kubectl get/create lease` against whatever context is
    # ambient. This test drives the live baseline path end to end through injected probe/resource
    # writers and a fake Locust transport, never a real cluster, so the lease is stubbed the same
    # way -- a no-op context manager.
    monkeypatch.setattr("runner.baseline.cluster_lease", lambda run_id: contextlib.nullcontext())
    timestamps = iter(("2026-01-01T00:00:00+00:00", "2026-01-01T00:00:05+00:00"))

    outcome = run_baseline(
        "LOAD-LIGHT",
        101,
        campaign_id=CAMPAIGN,
        out_root=tmp_path,
        skip_preflight=True,
        window=MeasurementWindow(samples=1),
        locust_transport=transport,
        probe=_probe,
        resources=_resources,
        manifest_builder=_manifest_builder,
        now=lambda: next(timestamps),
    )

    assert outcome.sealed, outcome.detail
    bundle = tmp_path / CAMPAIGN / outcome.run_id
    assert {path.name for path in bundle.iterdir()} == {
        "locust_stats.csv",
        "manifest.json",
        "probes.csv",
        "resources.csv",
        "seal.json",
    }
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["started_at"] == "2026-01-01T00:00:00+00:00"
    assert manifest["ended_at"] == "2026-01-01T00:00:05+00:00"
    assert manifest["git_commit"] == "a" * 40
    assert transport.paths == ["/stats/reset", "/swarm", "/stop", "/stats/requests/csv"]
    with (bundle / "locust_stats.csv").open(newline="", encoding="utf-8") as handle:
        assert list(csv.DictReader(handle))[0]["Name"] == "Aggregated"


# --- ADR-085 / supervisor ruling B3: the in-cluster SLO probe ---------------------------------
#
# "An SLO describes the Service, not a pod. Probe the Service by cluster DNS from a probe pod
# inside the cluster, with no port-forward on the measurement path." The old
# test_probe_writer_repairs_frontend_forward_before_each_request (a `before_probe` hook that
# re-ran scripts/port_forward.sh before every request) tested exactly the design this supersedes,
# and is gone rather than kept skipped: a port-forward workaround for a design whose defect IS the
# port-forward cannot be a passing test of the fix. Every test below drives a fake `run_kubectl`,
# never a real cluster, matching infra/tests/test_probes_schema.py's own "NO CLUSTER, NO NETWORK,
# NO SOCKET" discipline one layer up.


def _fake_kubectl(responses: dict[str, KubectlResult], calls: list[list[str]]) -> object:
    """A ``run_kubectl`` fake dispatching on the argv's kubectl verb (``apply``/``exec ... test``/
    ``exec ... cat``/``delete``), recording every call it saw.
    """

    def run(argv: list[str], input_bytes: bytes | None = None) -> KubectlResult:
        del input_bytes
        calls.append(list(argv))
        if "apply" in argv:
            return responses.get("apply", KubectlResult(0, b"", b""))
        if "test" in argv:
            return responses.get("test", KubectlResult(0, b"", b""))
        if "cat" in argv:
            return responses.get("cat", KubectlResult(0, b"probes-csv-bytes", b""))
        if "delete" in argv:
            return responses.get("delete", KubectlResult(0, b"", b""))
        raise AssertionError(f"unexpected kubectl invocation: {argv}")

    return run


def test_render_probe_pod_substitutes_every_placeholder_of_the_real_template() -> None:
    """Drives the checked-in infra/probes/deploy/pod.yaml, not a copy, so the two cannot drift.

    Checks the four literal SLO_PROBE_*_PLACEHOLDER tokens are gone, not the bare word
    "PLACEHOLDER" -- the manifest's own header prose mentions it (and NODE_NAME_PLACEHOLDER, the
    sibling convention in infra/netpol/probe/) while explaining the technique, which is correct and
    expected in a comment.
    """
    rendered = render_probe_pod(
        "slo-probe-abc123",
        "http://frontend.boutique.svc.cluster.local",
        MeasurementWindow(samples=121),
    )
    for placeholder in (
        "SLO_PROBE_POD_NAME_PLACEHOLDER",
        "SLO_PROBE_IMAGE_PLACEHOLDER",
        "SLO_PROBE_BASE_URL_PLACEHOLDER",
        "SLO_PROBE_STOP_ARGS_PLACEHOLDER",
    ):
        assert placeholder not in rendered, f"{placeholder} was not substituted"
    assert "slo-probe-abc123" in rendered
    assert "http://frontend.boutique.svc.cluster.local" in rendered
    assert "--samples 121" in rendered
    assert "agentic-overwatch/slo-probe:local" in rendered


def test_render_probe_pod_carries_a_duration_stop_rule_when_given_one() -> None:
    rendered = render_probe_pod(
        "slo-probe-abc123", "http://frontend", MeasurementWindow(duration_seconds=600.0)
    )
    assert "--duration 600.0" in rendered


def test_render_probe_pod_refuses_a_template_missing_a_placeholder(tmp_path: Path) -> None:
    """A drifted template -- one placeholder renamed on one side only -- fails loudly."""
    template = tmp_path / "pod.yaml"
    template.write_text(
        "metadata:\n  name: SLO_PROBE_POD_NAME_PLACEHOLDER\n", encoding="utf-8"
    )  # base-url and stop-args placeholders deliberately absent
    with pytest.raises(LiveMeasurementError, match="SLO_PROBE_IMAGE_PLACEHOLDER"):
        render_probe_pod(
            "slo-probe-x", "http://frontend", MeasurementWindow(samples=1), template_path=template
        )


def test_probe_writer_applies_polls_reads_and_always_deletes_the_pod(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    run = _fake_kubectl({"cat": KubectlResult(0, b"ts,probe_id\nA,B\nC,D\n", b"")}, calls)

    written = probe_writer(
        "http://frontend.boutique.svc.cluster.local",
        run_kubectl=run,
        sleep=lambda _seconds: None,
        pod_suffix=lambda: "fixedsuffix",
    )(tmp_path / "probes.csv", MeasurementWindow(samples=1))

    assert written == 2  # two data rows, header excluded
    assert (tmp_path / "probes.csv").read_text(encoding="utf-8") == "ts,probe_id\nA,B\nC,D\n"

    verb_names = {"apply", "exec", "delete"}
    verbs = [next((word for word in call if word in verb_names), None) for call in calls]
    assert verbs[0] == "apply"
    assert verbs[-1] == "delete"
    assert "exec" in verbs

    applied_manifest = next(c for c in calls if "apply" in c)
    # apply -f - takes the manifest on stdin, not argv; argv only names the pod's namespace.
    assert "-n" in applied_manifest
    assert PROBE_NAMESPACE in applied_manifest

    delete_call = calls[-1]
    assert "pod" in delete_call
    assert "slo-probe-fixedsuffix" in delete_call
    assert "--ignore-not-found" in delete_call


def test_probe_writer_deletes_the_pod_even_when_the_output_cannot_be_read(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    run = _fake_kubectl({"cat": KubectlResult(1, b"", b"container not found")}, calls)

    with pytest.raises(LiveMeasurementError, match="unreadable"):
        probe_writer(
            "http://frontend",
            run_kubectl=run,
            sleep=lambda _seconds: None,
            pod_suffix=lambda: "fixedsuffix",
        )(tmp_path / "probes.csv", MeasurementWindow(samples=1))

    assert any("delete" in call for call in calls), "the pod must be deleted even on failure"
    assert not (tmp_path / "probes.csv").exists()


def test_probe_writer_raises_when_the_pod_cannot_be_created(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    failure = KubectlResult(1, b"", b'namespaces "slo-probe" not found')
    run = _fake_kubectl({"apply": failure}, calls)

    with pytest.raises(LiveMeasurementError, match="could not create"):
        probe_writer("http://frontend", run_kubectl=run, pod_suffix=lambda: "fixedsuffix")(
            tmp_path / "probes.csv", MeasurementWindow(samples=1)
        )

    assert not any("delete" in call for call in calls), "nothing was created, so nothing to delete"


def test_in_cluster_probe_output_polls_until_the_completion_marker_appears() -> None:
    attempts = {"n": 0}
    sleeps: list[float] = []

    def run(argv: list[str], input_bytes: bytes | None = None) -> KubectlResult:
        del input_bytes
        if "test" in argv:
            attempts["n"] += 1
            return KubectlResult(0 if attempts["n"] >= 3 else 1, b"", b"not ready")
        if "cat" in argv:
            assert PROBE_OUTPUT_PATH in argv
            return KubectlResult(0, b"header\nrow\n", b"")
        raise AssertionError(argv)

    content = in_cluster_probe_output(
        "slo-probe-x",
        MeasurementWindow(samples=1),
        run_kubectl=run,
        sleep=sleeps.append,
        monotonic=lambda: 0.0,
    )
    assert content == b"header\nrow\n"
    assert attempts["n"] == 3
    assert sleeps == [2.0, 2.0]


def test_in_cluster_probe_output_checks_at_least_once_before_any_timeout(tmp_path: Path) -> None:
    """A window shorter than the poll interval still gets one real attempt, not a bare refusal."""
    del tmp_path
    checked = {"n": 0}

    def run(argv: list[str], input_bytes: bytes | None = None) -> KubectlResult:
        del input_bytes
        if "test" in argv:
            checked["n"] += 1
            return KubectlResult(0, b"", b"")
        return KubectlResult(0, b"header\nrow\n", b"")

    # monotonic already past its own deadline on the very first read: only a do-while loop, not a
    # while/else, still performs the check that succeeds here.
    clock = iter([1_000_000.0, 1_000_000.0, 1_000_000.0])
    in_cluster_probe_output(
        "slo-probe-x",
        MeasurementWindow(samples=1),
        run_kubectl=run,
        sleep=lambda _s: pytest.fail("must not sleep after success"),
        monotonic=lambda: next(clock),
    )
    assert checked["n"] == 1


def test_in_cluster_probe_output_times_out_naming_the_last_diagnostic() -> None:
    def run(argv: list[str], input_bytes: bytes | None = None) -> KubectlResult:
        del input_bytes, argv
        return KubectlResult(1, b"", b"pod still pending")

    clock = iter([0.0, 0.0, 100.0])  # third read is past the deadline: one retry, then raise
    with pytest.raises(LiveMeasurementError, match="pod still pending"):
        in_cluster_probe_output(
            "slo-probe-x",
            MeasurementWindow(samples=1),
            run_kubectl=run,
            sleep=lambda _s: None,
            monotonic=lambda: next(clock),
            timeout_margin_seconds=50.0,
        )


def test_in_cluster_probe_output_raises_on_an_empty_probes_csv() -> None:
    def run(argv: list[str], input_bytes: bytes | None = None) -> KubectlResult:
        del input_bytes
        if "test" in argv:
            return KubectlResult(0, b"", b"")
        assert PROBE_DONE_MARKER  # sanity: the constant this module polls for is defined
        return KubectlResult(0, b"", b"")

    with pytest.raises(LiveMeasurementError, match="empty probes.csv"):
        in_cluster_probe_output(
            "slo-probe-x", MeasurementWindow(samples=1), run_kubectl=run, sleep=lambda _s: None
        )


def test_probe_pod_template_exists_and_is_the_one_the_writer_reads() -> None:
    """Guards against the manifest and the Python renderer silently pointing at different files."""
    assert PROBE_POD_TEMPLATE.is_file()
    assert PROBE_POD_TEMPLATE.name == "pod.yaml"


def test_collectors_really_overlap_instead_of_running_serially(tmp_path: Path) -> None:
    barrier = threading.Barrier(2, timeout=1)

    def overlapping(path: Path, window: MeasurementWindow) -> int:
        del window
        barrier.wait()
        path.write_text("header\nrow\n", encoding="utf-8")
        return 1

    collect_concurrently(tmp_path, MeasurementWindow(samples=1), overlapping, overlapping)


def test_live_baseline_requires_an_explicit_window(tmp_path: Path) -> None:
    with pytest.raises(BaselineError, match="caller-supplied measurement window"):
        run_baseline("LOAD-LIGHT", 101, campaign_id=CAMPAIGN, out_root=tmp_path)


@pytest.mark.parametrize(
    "window",
    [
        lambda: MeasurementWindow(),
        lambda: MeasurementWindow(samples=0),
        lambda: MeasurementWindow(duration_seconds=0),
        lambda: MeasurementWindow(samples=1, duration_seconds=1),
    ],
)
def test_measurement_window_never_supplies_or_accepts_an_implicit_value(window) -> None:
    with pytest.raises(ValueError):
        window()


def test_empty_instrument_output_stops_locust_and_prevents_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    transport = LocustTransport()
    # See test_live_baseline_produces_and_seals_all_real_required_files: this path also runs
    # through runner.baseline's cluster_lease wrapper (ADR-087) and must not reach a real cluster.
    monkeypatch.setattr("runner.baseline.cluster_lease", lambda run_id: contextlib.nullcontext())

    def empty(path: Path, window: MeasurementWindow) -> int:
        del path, window
        return 0

    with pytest.raises(BaselineError, match="SLO probe wrote no rows"):
        run_baseline(
            "LOAD-LIGHT",
            101,
            campaign_id=CAMPAIGN,
            out_root=tmp_path,
            skip_preflight=True,
            window=MeasurementWindow(samples=1),
            locust_transport=transport,
            probe=empty,
            resources=_resources,
        )
    assert transport.paths == ["/stats/reset", "/swarm", "/stop"]


def test_default_resource_writer_preserves_live_storage_in_the_shared_csv(tmp_path, monkeypatch):
    from infra.collectors.resource_collector import STORAGE_QUERY

    from runner import live_baseline

    configured = []

    def adapter(url):
        configured.append(url)

        def query(expression):
            if expression != STORAGE_QUERY:
                return []
            return [
                {
                    "metric": {"namespace": "guardian", "pod": "guardian-0", "container": "api"},
                    "value": [0, "4097"],
                }
            ]

        return query

    monkeypatch.setattr(live_baseline, "live_query_fn", adapter)
    output = tmp_path / "resources.csv"
    written = live_baseline.resource_writer("http://prometheus.invalid")(
        output, MeasurementWindow(samples=1)
    )
    assert configured == ["http://prometheus.invalid"]
    assert written == 1
    rows = list(csv.DictReader(output.open(encoding="utf-8", newline="")))
    assert rows[0]["storage_bytes"] == "4097"
    assert rows[0]["namespace"] == "guardian"
    assert rows[0]["workload"] == "guardian"
    assert rows[0]["container"] == "api"
