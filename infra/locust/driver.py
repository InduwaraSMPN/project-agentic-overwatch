"""Drive a registered Locust load profile and export its request statistics.

The driver owns the run-boundary contract around Locust: resolve the profile, clear counters,
start its swarm through the HTTP API, stop it, and export a validated ``locust_stats.csv``.  It
intentionally owns no measurement duration.  Callers start and finish a session around the
protocol-owned stopping rule appropriate to their run; the command line therefore has separate
``start`` and ``stop-export`` operations rather than a sleep or duration option.

All network I/O goes through :class:`Transport`, so infra tests exercise the complete request and
CSV contract without a cluster.  The standard-library implementation is used in production to keep
the M1 instrument path free of third-party runtime dependencies.
"""

from __future__ import annotations

import argparse
import csv
import io
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from time import sleep as _sleep

from infra.locust.registry import Profile, ProfileRegistryError, list_profiles, resolve

DEFAULT_LOCUST_URL = "http://127.0.0.1:8089"
DEFAULT_TIMEOUT_SECONDS = 10.0
USER_AGENT = "agentic-overwatch-locust-driver/1"

# Locust 2.x request-stat exports contain more percentile columns, but these are the stable fields
# needed by evaluation-protocol section 3's p50/p95/error-rate measure.
REQUIRED_STATS_COLUMNS = frozenset({"Type", "Name", "Request Count", "Failure Count", "50%", "95%"})
AGGREGATE_NAMES = frozenset({"aggregated", "total"})


class LoadDriverError(Exception):
    """The Locust API failed or returned statistics that cannot support the RQ4 measure."""


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """One transport response, including served HTTP errors."""

    status: int
    body: bytes


Transport = Callable[[str, str, bytes | None, float], HttpResponse]
Measurement = Callable[[], None]


def _require_http_url(url: str) -> None:
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(
            f"refusing Locust URL {url!r}: scheme {scheme or '<none>'!r} is not http or https"
        )


def urllib_transport(
    method: str, url: str, body: bytes | None, timeout_seconds: float
) -> HttpResponse:
    """Send one HTTP request with urllib and return its status and bytes."""
    _require_http_url(url)
    request = urllib.request.Request(  # noqa: S310 - scheme validated immediately above
        url,
        data=body,
        method=method,
        headers={
            "User-Agent": USER_AGENT,
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310
            return HttpResponse(int(response.status), response.read())
    except urllib.error.HTTPError as served:
        response = HttpResponse(int(served.code), served.read())
        served.close()
        return response


def validate_stats_csv(content: bytes) -> int:
    """Validate Locust's request CSV and return its number of data rows.

    A header-only response is rejected.  An aggregate row is required because that is the row the
    RQ4 analysis consumes, and its request count must be positive: a syntactically non-empty export
    from a swarm that generated no requests is not evidence that a profile was driven.
    """
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise LoadDriverError(f"Locust statistics are not UTF-8: {error}") from error

    reader = csv.DictReader(io.StringIO(text, newline=""))
    header = reader.fieldnames
    if header is None:
        raise LoadDriverError("Locust statistics have no CSV header")
    missing = sorted(REQUIRED_STATS_COLUMNS.difference(header))
    if missing:
        raise LoadDriverError(
            "Locust statistics schema is missing required column(s): " + ", ".join(missing)
        )
    rows = list(reader)
    if not rows:
        raise LoadDriverError("Locust statistics contain a header but no data rows")

    aggregate = next((row for row in rows if row["Name"].strip().lower() in AGGREGATE_NAMES), None)
    if aggregate is None:
        raise LoadDriverError("Locust statistics contain no Aggregated/Total row")
    try:
        request_count = int(aggregate["Request Count"])
        int(aggregate["Failure Count"])
        float(aggregate["50%"])
        float(aggregate["95%"])
    except (TypeError, ValueError) as error:
        raise LoadDriverError("Locust aggregate counters or percentiles are not numeric") from error
    if request_count < 1:
        raise LoadDriverError("Locust aggregate row records zero requests")
    return len(rows)


class LocustDriver:
    """A small state-free client for one idle Locust process."""

    def __init__(
        self,
        base_url: str = DEFAULT_LOCUST_URL,
        *,
        transport: Transport = urllib_transport,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        _require_http_url(base_url)
        self._base_url = base_url.rstrip("/")
        self._transport = transport
        self._timeout_seconds = timeout_seconds

    def _request(self, method: str, path: str, body: bytes | None = None) -> bytes:
        try:
            response = self._transport(method, self._base_url + path, body, self._timeout_seconds)
        except Exception as error:
            raise LoadDriverError(f"Locust {method} {path} transport failed: {error}") from error
        if not 200 <= response.status < 300:
            detail = response.body.decode("utf-8", errors="replace").strip()
            suffix = f": {detail}" if detail else ""
            raise LoadDriverError(f"Locust {method} {path} returned HTTP {response.status}{suffix}")
        return response.body

    def reset(self) -> None:
        """Clear all statistics before a new run."""
        self._request("GET", "/stats/reset")

    def start(self, profile: Profile) -> None:
        """Reset counters and swarm Locust with exactly the resolved profile values."""
        self.reset()
        body = urllib.parse.urlencode(
            {
                "user_count": profile.users,
                "spawn_rate": profile.spawn_rate,
                "host": profile.host,
            }
        ).encode("ascii")
        self._request("POST", "/swarm", body)

    def start_profile(self, load_profile_id: str) -> Profile:
        """Resolve and start one registry profile, returning the immutable resolved entry."""
        profile = resolve(load_profile_id)
        self.start(profile)
        return profile

    def stop(self) -> None:
        """Stop the swarm while leaving Locust ready for the next run."""
        self._request("GET", "/stop")

    def export(self, out_path: Path) -> int:
        """Fetch, validate, and atomically replace ``out_path`` with Locust request statistics."""
        content = self._request("GET", "/stats/requests/csv")
        rows = validate_stats_csv(content)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = out_path.with_name(out_path.name + ".tmp")
        try:
            temporary.write_bytes(content)
            temporary.replace(out_path)
        except OSError as error:
            temporary.unlink(missing_ok=True)
            raise LoadDriverError(f"could not write {out_path}: {error}") from error
        return rows

    def stop_and_export(self, out_path: Path) -> int:
        """Stop first, then export the final counters for the just-finished run."""
        self.stop()
        return self.export(out_path)

    def drive(self, load_profile_id: str, out_path: Path, measurement: Measurement) -> int:
        """Bracket a caller-supplied measurement action with start, stop, and export.

        ``measurement`` owns the stopping rule.  It may block for a protocol-supplied duration,
        await another component, or collect a caller-supplied number of samples.  This method adds
        no fallback duration.  A failed measurement still stops Locust, but is not exported as a
        successful run.
        """
        self.start_profile(load_profile_id)
        try:
            measurement()
        except BaseException:
            try:
                self.stop()
            except LoadDriverError:
                pass
            raise
        return self.stop_and_export(out_path)


def drive_profile(
    load_profile_id: str,
    out_path: Path,
    measurement: Measurement,
    *,
    base_url: str = DEFAULT_LOCUST_URL,
    transport: Transport = urllib_transport,
) -> int:
    """Convenience entry point shared by runner live paths with injectable network I/O."""
    return LocustDriver(base_url, transport=transport).drive(load_profile_id, out_path, measurement)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m infra.locust.driver",
        description=(
            "Start/reset or stop/export a registered Locust profile. The caller owns the stopping "
            "rule; the combined drive operation requires a duration and has no default."
        ),
    )
    parser.add_argument("--url", default=DEFAULT_LOCUST_URL, help="Locust web API base URL.")
    command = parser.add_subparsers(dest="command", required=True)
    start = command.add_parser("start", help="Resolve, reset, and start one profile.")
    start.add_argument("--profile", required=True, help="A registered LOAD-<slug> identifier.")
    finish = command.add_parser("stop-export", help="Stop and export validated request statistics.")
    finish.add_argument("--out", required=True, type=Path, help="Output locust_stats.csv path.")
    drive = command.add_parser(
        "drive", help="Drive one profile for a caller-supplied number of seconds, then export."
    )
    drive.add_argument("--profile", required=True, help="A registered LOAD-<slug> identifier.")
    drive.add_argument("--out", required=True, type=Path, help="Output locust_stats.csv path.")
    drive.add_argument(
        "--duration",
        required=True,
        type=float,
        metavar="SECONDS",
        help="Caller-supplied measurement window; there is deliberately no default.",
    )
    command.add_parser("reset", help="Clear Locust's current counters.")
    command.add_parser("list", help="List every registered profile identifier.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "list":
            for profile in list_profiles():
                print(profile.id)
            return 0
        driver = LocustDriver(args.url)
        if args.command == "start":
            profile = driver.start_profile(args.profile)
            print(
                f"locust-driver: started {profile.id} with {profile.users} users at "
                f"{profile.spawn_rate}/s"
            )
        elif args.command == "stop-export":
            rows = driver.stop_and_export(args.out)
            print(f"locust-driver: stopped and exported {rows} row(s) to {args.out}")
        elif args.command == "drive":
            if args.duration <= 0:
                raise ValueError("--duration must be greater than zero")
            rows = driver.drive(args.profile, args.out, lambda: _sleep(args.duration))
            print(f"locust-driver: drove {args.profile} and exported {rows} row(s) to {args.out}")
        else:
            driver.reset()
            print("locust-driver: reset statistics")
    except (LoadDriverError, ProfileRegistryError, ValueError) as error:
        print(f"locust-driver: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
