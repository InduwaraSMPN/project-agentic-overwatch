"""The live storage adapter consumes real Summary API data rather than an absent metric."""

import json
import subprocess
from types import SimpleNamespace

import pytest

from infra.collectors import resource_collector as collector


def test_summary_storage_reaches_rows_without_a_prometheus_exporter(monkeypatch):
    replies = {
        "/api/v1/nodes": {"items": [{"metadata": {"name": name}} for name in ("a", "b")]},
        "/api/v1/nodes/a/proxy/stats/summary": {
            "pods": [
                {
                    "podRef": {"namespace": "guardian", "name": "guardian-0"},
                    "containers": [
                        {"name": "api", "rootfs": {"usedBytes": 123}, "logs": {"usedBytes": 456}},
                        {"name": "unknown"},
                    ],
                }
            ]
        },
        "/api/v1/nodes/b/proxy/stats/summary": {
            "pods": [
                {
                    "podRef": {"namespace": "boutique", "name": "frontend-0"},
                    "containers": [{"name": "server", "logs": {"usedBytes": 789}}],
                }
            ]
        },
    }
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        assert kwargs["check"] and kwargs["timeout"] == 10
        return SimpleNamespace(stdout=json.dumps(replies[argv[-1]]))

    monkeypatch.setattr(collector.shutil, "which", lambda name: "/usr/bin/kubectl")
    monkeypatch.setattr(collector.subprocess, "run", run)
    monkeypatch.setattr(collector, "prometheus_query_fn", lambda url: lambda expression: [])
    rows = collector.collect_once(collector.live_query_fn(), "2026-10-04T00:00:00+00:00")
    assert {(r.namespace, r.workload, r.container, r.storage_bytes) for r in rows} == {
        ("guardian", "guardian", "api", 579),
        ("boutique", "frontend", "server", 789),
    }
    assert len(calls) == 3


def test_summary_failure_cannot_be_reported_as_zero_storage(monkeypatch):
    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(1, "kubectl")

    monkeypatch.setattr(collector.shutil, "which", lambda name: "/usr/bin/kubectl")
    monkeypatch.setattr(collector.subprocess, "run", fail)
    with pytest.raises(RuntimeError, match="kubelet storage collection failed"):
        collector.kubelet_storage_samples()
