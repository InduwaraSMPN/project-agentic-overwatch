"""Clusterless contract tests for the build-controlled Locust profile driver."""

import csv
import sys
import urllib.parse
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


from infra.locust.driver import (  # noqa: E402
    HttpResponse,
    LoadDriverError,
    LocustDriver,
    build_parser,
    validate_stats_csv,
)
from infra.locust.registry import list_profiles  # noqa: E402

VALID_STATS = (
    b"Type,Name,Request Count,Failure Count,Median Response Time,Average Response Time,"
    b"Min Response Time,Max Response Time,Average Content Size,Requests/s,Failures/s,50%,95%\n"
    b",Aggregated,12,1,20,23,10,80,100,2.0,0.1,20,70\n"
)


class FakeTransport:
    def __init__(self, stats: bytes = VALID_STATS) -> None:
        self.calls: list[tuple[str, str, bytes | None, float]] = []
        self.stats = stats

    def __call__(self, method: str, url: str, body: bytes | None, timeout: float) -> HttpResponse:
        self.calls.append((method, url, body, timeout))
        if url.endswith("/stats/requests/csv"):
            return HttpResponse(200, self.stats)
        return HttpResponse(200, b"ok")


def test_every_registered_profile_is_resolved_reset_started_stopped_and_exported(
    tmp_path: Path,
) -> None:
    """Every legal registry value follows the same API lifecycle without a cluster."""
    for profile in list_profiles():
        transport = FakeTransport()
        driver = LocustDriver("http://locust.test:8089", transport=transport)
        resolved = driver.start_profile(profile.id)
        output = tmp_path / profile.id / "locust_stats.csv"
        assert driver.stop_and_export(output) == 1
        assert resolved == profile

        calls = [(method, urllib.parse.urlsplit(url).path) for method, url, _, _ in transport.calls]
        assert calls == [
            ("GET", "/stats/reset"),
            ("POST", "/swarm"),
            ("GET", "/stop"),
            ("GET", "/stats/requests/csv"),
        ]
        swarm = urllib.parse.parse_qs(transport.calls[1][2].decode())
        assert swarm == {
            "user_count": [str(profile.users)],
            "spawn_rate": [str(profile.spawn_rate)],
            "host": [profile.host],
        }
        with output.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        assert rows[0]["Name"] == "Aggregated"
        assert int(rows[0]["Request Count"]) > 0


def test_drive_brackets_the_caller_supplied_measurement(tmp_path: Path) -> None:
    events: list[str] = []

    class RecordingTransport(FakeTransport):
        def __call__(
            self, method: str, url: str, body: bytes | None, timeout: float
        ) -> HttpResponse:
            events.append(urllib.parse.urlsplit(url).path)
            return super().__call__(method, url, body, timeout)

    driver = LocustDriver(transport=RecordingTransport())
    driver.drive(
        "LOAD-LIGHT",
        tmp_path / "locust_stats.csv",
        lambda: events.append("measurement"),
    )
    assert events == [
        "/stats/reset",
        "/swarm",
        "measurement",
        "/stop",
        "/stats/requests/csv",
    ]


def test_failed_measurement_stops_without_exporting(tmp_path: Path) -> None:
    transport = FakeTransport()
    driver = LocustDriver(transport=transport)

    def fail() -> None:
        raise RuntimeError("collector failed")

    with pytest.raises(RuntimeError, match="collector failed"):
        driver.drive("LOAD-LIGHT", tmp_path / "locust_stats.csv", fail)
    assert [urllib.parse.urlsplit(call[1]).path for call in transport.calls] == [
        "/stats/reset",
        "/swarm",
        "/stop",
    ]
    assert not (tmp_path / "locust_stats.csv").exists()


def test_invalid_export_never_replaces_an_existing_file(tmp_path: Path) -> None:
    output = tmp_path / "locust_stats.csv"
    output.write_text("previous evidence\n", encoding="utf-8")
    driver = LocustDriver(transport=FakeTransport(b"Type,Name,Request Count\n,Aggregated,0\n"))

    with pytest.raises(LoadDriverError, match="missing required column"):
        driver.export(output)
    assert output.read_text(encoding="utf-8") == "previous evidence\n"


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"", "no CSV header"),
        (b"Type,Name,Request Count,Failure Count,50%,95%\n", "no data rows"),
        (
            b"Type,Name,Request Count,Failure Count,50%,95%\n,/,1,0,1,2\n",
            "no Aggregated/Total row",
        ),
        (
            b"Type,Name,Request Count,Failure Count,50%,95%\n,Aggregated,0,0,1,2\n",
            "zero requests",
        ),
    ],
)
def test_stats_validation_refuses_unusable_exports(content: bytes, message: str) -> None:
    with pytest.raises(LoadDriverError, match=message):
        validate_stats_csv(content)


def test_http_errors_are_named_with_method_path_and_status() -> None:
    def failing(method: str, url: str, body: bytes | None, timeout: float) -> HttpResponse:
        del body, timeout
        return HttpResponse(503, b"not ready")

    with pytest.raises(LoadDriverError, match=r"GET /stats/reset returned HTTP 503: not ready"):
        LocustDriver(transport=failing).reset()


def test_drive_requires_a_caller_supplied_duration_and_has_no_default() -> None:
    """The combined CLI may receive a window, but must never invent one."""
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["drive", "--profile", "LOAD-LIGHT", "--out", "locust_stats.csv"])
    args = parser.parse_args(
        [
            "drive",
            "--profile",
            "LOAD-LIGHT",
            "--out",
            "locust_stats.csv",
            "--duration",
            "5",
        ]
    )
    assert args.duration == 5
