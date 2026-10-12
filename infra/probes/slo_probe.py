"""SLO probe: drives the protocol-owned probe set and writes the ``probes.csv`` timeline.

WHY THIS EXISTS
---------------
Two traceability rows depend on a timeline of application availability taken from outside the
framework. T-21 (restoration time) is measured as the interval between the probe timeline going
red and its going green again, and RQ4's interference measure (evaluation-protocol section 3)
needs a control series that is not produced by the load generator whose numbers it is checking.
``docs/protocols/data-management.md`` section 1 makes ``probes.csv`` a required member of every
sealed run bundle, and section 4 makes gaps in it a run-invalidity condition. This module is the
only writer of that file.

THE CONTRACT
------------
Columns, in this order and no other, per data-management section 1:

    ts, probe_id, target, method, status_code, latency_ms, ok, error

``ts`` is an ISO-8601 UTC timestamp with an explicit ``+00:00`` offset, so a timeline is
unambiguous when read on a machine in another zone and sorts lexicographically in sample order.
``ok`` is the lowercase ``true``/``false`` a CSV reader in any language parses without a
per-language boolean convention. ``error`` is empty on success and carries the exception text
otherwise. ``status_code`` is empty exactly when no response was received at all, which is what
distinguishes a transport failure from a served error page -- a distinction the restoration
measure needs, because a 503 means the frontend is up and its dependency is not.

Rows are appended, and the header is written only when the target file is empty. A probe process
that is restarted mid-run therefore extends its timeline rather than truncating it, which matters
because a truncated timeline reads downstream as a gap and a gap invalidates the run. The CSV is
written with an explicit LF terminator rather than the ``csv`` module default of CRLF: this
repository normalises line endings everywhere (.gitattributes, and the digest normalisation in
``scripts/versions_env_sha256.py``), and a bundle whose byte content differs depending on which
host sealed it defeats the clean-machine reproducibility NFR1 asserts.

WHY THE I/O IS INJECTABLE
-------------------------
The first file under ``infra/tests/`` arms the ``Unit tests -- infra`` step of
``.github/workflows/ci.yml``, which runs on a GitHub runner with no cluster, no Docker and no
network guarantees. Every function below therefore takes its transport, its clock and its sleep as
parameters with real defaults, so the unit tests drive the whole writer end to end against fakes
and never open a socket. A test that needs a cluster belongs in ``env-bringup.yml``, which builds
one.

UNCALIBRATED THRESHOLDS ARE NEVER TREATED AS A PASS
---------------------------------------------------
``slo_latency_p95_ms``, ``slo_error_rate_max`` and ``stabilization_window_seconds`` are measured on
a deployed cluster and are not filled yet (see :mod:`infra.probes.constants`). While any of them
holds the sentinel, this module still writes a complete timeline -- ``ok`` reflects transport
success and HTTP status, which need no threshold -- but it refuses to say whether the SLO was met,
prints a one-line notice naming the missing values, and exits with its own code. Defaulting a
pending threshold to "met" would let a green ``make status`` and a green probe run certify an
environment nobody has ever measured, which is precisely the false green the milestone stub-honesty
argument exists to prevent.

Exit codes, so a caller can tell the four outcomes apart:

    0  timeline written; thresholds calibrated; the SLO was met
    1  usage error, or the timeline could not be written
    2  timeline written; thresholds calibrated; the SLO was breached
    3  timeline written; thresholds pending, so no verdict was formed

Code 3 is deliberately non-zero. A script that treats any non-zero result as a failure gets a
failure, and a script that inspects the code can tell "not measured" from "measured and bad".

CALIBRATION MODE
----------------
``--calibrate`` runs an ordinary timeline and then prints the exact section 4 block to paste, with
the three measured keys filled from what it observed. Two of those values are clamped to the
instrument's own resolution rather than to an invented safety margin, and the difference matters:

* ``slo_error_rate_max`` is the **upper limit of the Wilson score interval** on the observed
  failure proportion, floored at ``1 / n_samples`` -- the smallest non-zero rate a timeline of that
  length can resolve. Both halves are statements about the measurement rather than margins someone
  chose: the interval is the uncertainty the observation actually carries (and is the interval
  ``evaluation-protocol.md`` section 3 already fixes for this project's proportions), and the floor
  is the instrument's resolution. A *maximum* set to the point estimate would sit exactly on
  steady state and reject about half of the timelines that match the one that calibrated it.
* ``stabilization_window_seconds`` is a *dwell*: the duration for which every probe must stay green
  before recovery is declared. It is the shortest candidate that no perturbation episode retracts,
  that every episode still satisfies, and that is at least the system's own post-repair settling
  time -- see :func:`stabilization_dwell_seconds` and :func:`settling_seconds` -- and is never
  below one probe interval, because a dwell shorter than the sampling interval is not observable
  by this instrument.

  Calibrating it therefore requires ``--repair-at``: one timestamp per perturbation marking the
  instant repair was applied. Without them ``--calibrate`` refuses this key rather than inventing
  it, because a dwell cannot be recovered from an unlabelled timeline -- the reasoning is in
  :func:`stabilization_dwell_seconds` and the history is ADR-048. ``--curve`` prints the
  premature/undeclared table the choice was read off, so the number is reviewable and not merely
  asserted.

``slo_latency_p95_ms`` is the observed p95 with no adjustment, taken by the nearest-rank method
(no interpolation) so that the number can be reproduced exactly from the same CSV by any later
analysis without agreeing on a quantile variant first.

Both threshold values are measured over **steady state only**: the induced outages the dwell needs
are removed first, by :func:`steady_state_rows`. A calibration timeline deliberately contains
breaches, and thresholds fitted to it would be fitted to the breaches they exist to detect. The
dwell, by contrast, is measured over the whole timeline, because the outages are its subject.

Section 4 holds one set of values, while the load-profile registry holds more than one profile.
If a calibration run under one profile disagrees with another, that is a protocol-shape question --
whether section 4 gains a per-profile table -- and not something this module may decide, so it
prints what it measured and stops rather than merging the two.

WHAT IS DELIBERATELY NOT HERE
-----------------------------
The *duration* of a measurement window is not a protocol constant. A load profile is a load shape;
the length of a run is a property of a run, and no protocol file currently owns it -- the M1 plan
records that as an open item for M6/GATE in its Out-of-scope section. So ``--duration`` and
``--samples`` are required command-line arguments with no default: the caller states the stopping
rule explicitly, and nothing in this file quietly becomes the number that a campaign is later
found to have been calibrated against.

``--profile`` is recorded in the startup notice and nowhere else. It never selects a threshold:
section 4 holds one threshold set, and a probe that silently applied a different bound per profile
would make two runs incomparable without anything in the bundle saying so. The profile identifier
already has a home in the run manifest (``load_profile_id``, data-management section 2), and
restating it in every CSV row would be a second home for it.

The base URL is a command-line argument for the reason :mod:`infra.probes.constants` gives: the
frontend address is an environment fact, not an evaluation constant.
"""

import argparse
import csv
import http.cookiejar
import math
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import monotonic as _monotonic
from time import perf_counter
from time import sleep as _sleep

from infra.probes.constants import (
    MEASURED_KEYS,
    PROBE_INTERVAL_SECONDS,
    PROBE_TIMEOUT_SECONDS,
    SLO_PROBE_SET,
    ProbeSpec,
    as_protocol_mapping,
    pending_keys,
    render_protocol_block,
)

# The column order is the contract, not a convenience. data-management section 1 fixes it, the
# schema test asserts it, and any reader that positionally indexes a row depends on it.
PROBES_CSV_HEADER: tuple[str, ...] = (
    "ts",
    "probe_id",
    "target",
    "method",
    "status_code",
    "latency_ms",
    "ok",
    "error",
)

# csv.writer defaults to CRLF. See the module docstring: a bundle whose bytes depend on the host
# that sealed it is not reproducible, so the terminator is pinned to LF on every platform.
CSV_LINE_TERMINATOR = "\n"

# Identifies probe traffic in the frontend access log, so probe requests can be told apart from
# Locust requests when a timeline and a load run are being reconciled after the fact.
USER_AGENT = "agentic-overwatch-slo-probe/1"

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_SLO_BREACHED = 2
EXIT_THRESHOLDS_PENDING = 3

# A transport takes (url, method, timeout_seconds) and returns the HTTP status code. It raises on a
# transport failure -- no response at all -- and returns the code for any response, including a 4xx
# or 5xx, because a served error page is a response and the timeline has to say so.
Transport = Callable[[str, str, float], int]


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """One row of ``probes.csv``, in the column order the header declares."""

    ts: str
    probe_id: str
    target: str
    method: str
    status_code: int | None
    latency_ms: float
    ok: bool
    error: str

    def as_row(self) -> list[str]:
        """Return the row as the list of strings ``csv.writer`` will quote and emit.

        ``ok`` is rendered lowercase because that is the spelling every CSV consumer in the
        analysis stack reads without a per-language boolean convention; Python truthiness is not
        the contract here, the two literal words are.
        """
        return [
            self.ts,
            self.probe_id,
            self.target,
            self.method,
            "" if self.status_code is None else str(self.status_code),
            f"{self.latency_ms:.3f}",
            "true" if self.ok else "false",
            self.error,
        ]


@dataclass(frozen=True, slots=True)
class Verdict:
    """The outcome of comparing an observed timeline against the section 4 thresholds.

    ``state`` is one of ``PASS``, ``FAIL`` or ``PENDING``. ``PENDING`` is not a pass and is not a
    fail: it says no comparison was possible because a threshold has never been measured, and it
    is the state the module is in until the calibration commit lands.
    """

    state: str
    reasons: tuple[str, ...]
    observed_p95_ms: float | None
    observed_error_rate: float | None
    samples: int


def _utc_now() -> datetime:
    """Return the current instant as an aware UTC datetime.

    Wrapped in a function so callers can substitute a deterministic clock; a bare
    ``datetime.now`` default would bind the real clock into every signature.
    """
    return datetime.now(UTC)


def format_timestamp(moment: datetime) -> str:
    """Render ``moment`` as the ISO-8601 UTC string written to the ``ts`` column."""
    return moment.astimezone(UTC).isoformat()


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


def urllib_transport(url: str, method: str, timeout_seconds: float) -> int:
    """Issue one request with the standard library and return its HTTP status code.

    ``urllib`` is used rather than ``requests`` because CI installs ``pytest`` and nothing else,
    and a probe that cannot run without a third-party package would be a dependency on the
    critical path of every run for no capability this needs.

    A 4xx or 5xx arrives as :class:`urllib.error.HTTPError`, which is itself a response object, so
    its code is returned rather than raised: the frontend answered, and the timeline records what
    it answered. Anything else -- DNS failure, refused connection, timeout -- propagates, and the
    caller records it as a transport failure with an empty ``status_code``.

    Redirects are followed by the default opener, so a recorded status is the status of the final
    response in the chain.
    """
    _require_http_url(url)
    request = urllib.request.Request(  # noqa: S310
        url, method=method, headers={"User-Agent": USER_AGENT}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310
            response.read()
            return int(response.status)
    except urllib.error.HTTPError as served:
        served.read()
        served.close()
        return int(served.code)


_CHECKOUT_FORM = {
    "email": "someone@example.com",
    "street_address": "1600 Amphitheatre Parkway",
    "zip_code": "94043",
    "city": "Mountain View",
    "state": "CA",
    "country": "United States",
    "credit_card_number": "4432801561520454",
    "credit_card_expiration_month": "1",
    "credit_card_expiration_year": "2099",
    "credit_card_cvv": "672",
}


def checkout_transport(base_url: str, timeout_seconds: float) -> int:
    """Run one isolated add-to-cart then checkout transaction under one deadline."""
    _require_http_url(base_url)
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    deadline = perf_counter() + timeout_seconds
    steps = (
        ("/cart", {"product_id": "OLJCESPC7Z", "quantity": "1"}),
        ("/cart/checkout", _CHECKOUT_FORM),
    )
    status = 0
    for path, form in steps:
        remaining = deadline - perf_counter()
        if remaining <= 0:
            raise TimeoutError("checkout probe exhausted its shared cycle deadline")
        url = base_url.rstrip("/") + path
        _require_http_url(url)
        request = urllib.request.Request(  # noqa: S310 - scheme validated immediately above
            url,
            data=urllib.parse.urlencode(form).encode("ascii"),
            method="POST",
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        try:
            with opener.open(request, timeout=remaining) as response:
                response.read()
                status = int(response.status)
        except urllib.error.HTTPError as served:
            served.read()
            served.close()
            status = int(served.code)
        if status >= 400:
            return status
    return status


def probe_once(
    spec: ProbeSpec,
    base_url: str,
    timeout_seconds: float = float(PROBE_TIMEOUT_SECONDS),
    transport: Transport = urllib_transport,
    now: Callable[[], datetime] = _utc_now,
) -> ProbeResult:
    """Drive one probe entry once and return the row it produces.

    ``ok`` is true when a response arrived and its status is below 400. A redirect counts as
    served rather than failed: this is an availability probe, and the frontend answering with a
    location is the frontend being up. Content is not inspected at all -- a probe that asserted on
    page content would start failing for reasons that belong to the application under test rather
    than to its availability, and the timeline would stop meaning what T-21 reads it as meaning.

    Latency is taken with :func:`time.perf_counter` around the transport call only, so it excludes
    the row formatting and the CSV write, and it is recorded for failures too: how long a request
    took to fail is part of what a restoration curve looks like.
    """
    url = base_url.rstrip("/") + spec.target
    started = perf_counter()
    try:
        status: int | None = (
            checkout_transport(base_url, timeout_seconds)
            if spec.probe_id == "PROBE-FRONTEND-CHECKOUT"
            else transport(url, spec.method, timeout_seconds)
        )
        error = ""
    except Exception as failure:
        status = None
        error = f"{type(failure).__name__}: {failure}"
    latency_ms = (perf_counter() - started) * 1000.0
    return ProbeResult(
        ts=format_timestamp(now()),
        probe_id=spec.probe_id,
        target=spec.target,
        method=spec.method,
        status_code=status,
        latency_ms=latency_ms,
        ok=status is not None and 200 <= status < 400,
        error=error,
    )


def run_timeline(
    specs: Sequence[ProbeSpec] = SLO_PROBE_SET,
    base_url: str = "",
    samples: int | None = None,
    duration_seconds: float | None = None,
    interval_seconds: float = float(PROBE_INTERVAL_SECONDS),
    timeout_seconds: float = float(PROBE_TIMEOUT_SECONDS),
    transport: Transport = urllib_transport,
    now: Callable[[], datetime] = _utc_now,
    sleep: Callable[[float], None] = _sleep,
    monotonic: Callable[[], float] = _monotonic,
) -> Iterator[ProbeResult]:
    """Yield probe rows, driving the whole probe set once per tick on a fixed cadence.

    One *sample* is one tick: every entry of ``specs`` is driven once, in order, so a tick emits
    ``len(specs)`` rows that share nothing but their position in the timeline. ``samples`` counts
    ticks, not rows.

    Exactly one of ``samples`` and ``duration_seconds`` must be given; the module docstring records
    why neither has a default.

    Ticks are scheduled against absolute deadlines derived from the start instant, not by sleeping
    for the interval after each cycle. Sleeping afterwards adds the cycle own duration to every
    interval, so the cadence drifts steadily slower under load -- exactly when the timeline matters
    most -- and a drifting cadence eventually manufactures the gap that data-management section 4
    invalidates a run for.

    When a cycle overruns its deadline, the schedule advances to the next slot that is still in
    the future rather than firing every missed slot back to back. The distinction is not cosmetic:
    a long outage leaves the schedule many slots behind, and firing all of them on recovery would
    put a burst of requests at exactly the instant T-21 measures the restoration at. The stopping
    rule counts cycles actually emitted, not schedule slots, so ``samples`` always yields
    ``samples * len(specs)`` rows however the cadence was disturbed.
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
        cycle_deadline = monotonic() + timeout_seconds
        for spec in specs:
            remaining = cycle_deadline - monotonic()
            if remaining <= 0:
                yield ProbeResult(
                    ts=format_timestamp(now()),
                    probe_id=spec.probe_id,
                    target=spec.target,
                    method=spec.method,
                    status_code=None,
                    latency_ms=0.0,
                    ok=False,
                    error="TimeoutError: probe cycle exhausted its shared deadline",
                )
                continue
            yield probe_once(
                spec,
                base_url=base_url,
                timeout_seconds=remaining,
                transport=transport,
                now=now,
            )
        emitted += 1
        slot = max(slot + 1, int((monotonic() - start) // interval_seconds) + 1)


def write_rows(rows: Iterable[ProbeResult], out_path: Path) -> int:
    """Append ``rows`` to the CSV at ``out_path`` and return how many were written.

    The header is written only when the file does not exist or is empty, so a probe process that
    is restarted mid-run extends its timeline instead of starting a second one. Parent directories
    are created, because the caller is usually a run bundle path that the sealer has not laid down
    yet.

    Rows are flushed as they are produced rather than buffered until the end. A run that is killed
    -- by the per-run timeout evaluation-protocol section 5 requires, or by an operator -- must
    still leave the timeline it had reached on disk: a partial timeline is evidence, and an empty
    file is not.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    needs_header = not out_path.exists() or out_path.stat().st_size == 0
    written = 0
    with out_path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator=CSV_LINE_TERMINATOR)
        if needs_header:
            writer.writerow(PROBES_CSV_HEADER)
        for row in rows:
            writer.writerow(row.as_row())
            handle.flush()
            written += 1
    return written


def percentile_nearest_rank(values: Sequence[float], fraction: float) -> float:
    """Return the nearest-rank percentile of ``values`` at ``fraction`` in [0, 1].

    Nearest rank, not interpolation. The number this produces has to be reproducible from the same
    CSV by whatever the analysis stack is at M7, and every library offers several interpolating
    quantile variants that disagree in the third digit; nearest rank is one definition with one
    answer, computed here in four lines. ``ceil(fraction * n)`` is the standard formulation, and
    the rank is clamped into range so that a single-sample series does not index past the end.
    """
    if not values:
        raise ValueError("percentile of an empty series is undefined")
    ordered = sorted(values)
    rank = max(1, min(len(ordered), math.ceil(fraction * len(ordered))))
    return ordered[rank - 1]


def observed_error_rate(rows: Sequence[ProbeResult]) -> float | None:
    """Return the fraction of ``rows`` whose ``ok`` is false, or None for an empty timeline."""
    if not rows:
        return None
    return sum(0 if row.ok else 1 for row in rows) / len(rows)


def read_rows(path: Path) -> list[ProbeResult]:
    """Read a ``probes.csv`` back into :class:`ProbeResult` values, in file order.

    The inverse of :func:`write_rows`, and it exists so that calibration can be run over a timeline
    that some *other* process recorded. The stabilization dwell is measured across several
    perturbation cycles applied by an external driver, so the probe process that records the
    timeline is not the process that calibrates from it; without this the only calibratable
    timeline would be one a single ``--calibrate`` invocation happened to collect by itself.

    It also makes a calibration reproducible from a sealed run bundle: ``probes.csv`` is a required
    bundle member (data-management section 1), so anyone can re-derive the section 4 block from the
    archived timeline and get the same numbers, rather than having to trust the run that produced
    them.
    """
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != PROBES_CSV_HEADER:
            raise ValueError(
                f"{path}: not a probes.csv -- header is {reader.fieldnames!r}, "
                f"expected {list(PROBES_CSV_HEADER)!r}"
            )
        return [
            ProbeResult(
                ts=row["ts"],
                probe_id=row["probe_id"],
                target=row["target"],
                method=row["method"],
                status_code=int(row["status_code"]) if row["status_code"] else None,
                latency_ms=float(row["latency_ms"]),
                ok=row["ok"] == "true",
                error=row["error"],
            )
            for row in reader
        ]


def wilson_upper_bound(failures: int, total: int, z: float = 1.959963985) -> float:
    """Return the upper limit of the Wilson score interval for ``failures`` out of ``total``.

    WHY A BOUND AND NOT THE POINT ESTIMATE
    --------------------------------------
    ``slo_error_rate_max`` is a *maximum*, and a maximum set to the observed rate is the one value
    guaranteed to be wrong about half the time: steady state sits exactly on it, so a timeline no
    worse than the one that calibrated it fails the comparison on any run whose blips land slightly
    denser than average. The threshold has to sit above the background rate by the amount the
    background rate is itself uncertain, and that quantity is an interval, not a guess.

    Wilson specifically, rather than the normal approximation, because ``evaluation-protocol.md``
    section 3 already fixes it as this project's proportion interval --
    ``proportion_confint(k, n, alpha=0.05, method='wilson')``, chosen there because the normal
    approximation "is unreliable at five seeds". A probe timeline carries more samples than that,
    but a second interval convention in the same repository would be a second decision about the
    same question, and this file does not get to make it. The default ``z`` is the two-sided
    alpha=0.05 value, so this returns the upper limit of exactly the interval that call produces.

    Implemented in four lines rather than imported: ``statsmodels`` is an ``analysis/`` dependency,
    and ``infra/probes/`` runs on a CI runner that installs neither it nor SciPy.
    """
    if total <= 0:
        raise ValueError("Wilson interval of an empty sample is undefined")
    proportion = failures / total
    denominator = 1.0 + (z * z) / total
    centre = (proportion + (z * z) / (2.0 * total)) / denominator
    spread = (
        z
        * math.sqrt(proportion * (1.0 - proportion) / total + (z * z) / (4.0 * total * total))
        / denominator
    )
    return min(1.0, centre + spread)


def observed_p95_ms(rows: Sequence[ProbeResult]) -> float | None:
    """Return the nearest-rank p95 latency over the successful rows, or None if there are none.

    Failed rows are excluded on purpose. A timed-out request contributes the timeout value, not
    the service latency, so leaving failures in would make the p95 a function of
    ``probe_timeout_seconds`` -- a number this project chose -- rather than of the system under
    test. Failures are already carried by the error rate, which is the metric that exists to
    account for them.
    """
    successes = [row.latency_ms for row in rows if row.ok]
    if not successes:
        return None
    return percentile_nearest_rank(successes, 0.95)


@dataclass(frozen=True, slots=True)
class Tick:
    """One complete pass of the probe set: its start instant, and whether every probe was ok.

    The protocol's unit is "all SLO probes are green", which is a property of a *pass*, not of a
    single row. Rows arrive one per probe per pass, so the timeline is folded into passes before
    any dwell question is asked; asking it per row would let a four-probe pass with one failure
    contribute three greens.
    """

    ts: datetime
    ok: bool


def probe_ticks(rows: Sequence[ProbeResult]) -> list[Tick]:
    """Fold ``rows`` into one :class:`Tick` per pass of the probe set.

    A new pass starts at the first row whose ``probe_id`` has already been seen in the pass being
    accumulated. That rule reads the sequence the writer actually produced instead of assuming a
    fixed set size, so a timeline recorded under a different ``SLO_PROBE_SET`` still folds
    correctly and a truncated final pass is not silently merged into the one before it.
    """
    ticks: list[Tick] = []
    seen: set[str] = set()
    start: datetime | None = None
    ok = True
    for row in rows:
        if row.probe_id in seen:
            if start is not None:
                ticks.append(Tick(start, ok))
            seen, start, ok = set(), None, True
        if start is None:
            start = datetime.fromisoformat(row.ts)
        seen.add(row.probe_id)
        ok = ok and row.ok
    if start is not None:
        ticks.append(Tick(start, ok))
    return ticks


def _episode_bounds(
    ticks: Sequence[Tick],
    repairs: Sequence[datetime],
) -> list[tuple[datetime, datetime | None]]:
    """Return the ``(start, end)`` of each attributable recovery episode.

    An episode starts at its repair instant and ends where the **next perturbation begins** -- not
    at the next repair. The distinction is not cosmetic: bounding an episode at the next repair
    leaves the next cycle's deliberate outage inside it, so every recovery is "retracted" by the
    injection that follows it and the premature count never falls below the number of cycles that
    have a successor. Measured on the first three-cycle run, that pinned ``premature`` at 2 for
    every dwell short enough to be declared, and the chosen dwell degenerated to the resolution
    floor for a reason that had nothing to do with the system.

    The next perturbation's start is the start of the next induced outage, which
    :func:`outage_windows` already recovers from the timeline. The last episode is open-ended.
    """
    ordered = sorted(repairs)
    # Keyed by the repair each window was found from, not by list position: a perturbation that
    # broke nothing has no window and no entry, and falls back to its repair below (ADR-048 log).
    starts = {repair: start for repair, (start, _end) in outage_windows(ticks, ordered)}
    bounds: list[tuple[datetime, datetime | None]] = []
    for index, repair in enumerate(ordered):
        end: datetime | None = None
        if index + 1 < len(ordered):
            following = ordered[index + 1]
            # Prefer the next outage's own start; fall back to the next repair when that
            # perturbation left no red tick at all (i.e. it never broke the SLO).
            end = starts.get(following, following)
        bounds.append((repair, end))
    return bounds


def _episodes(
    ticks: Sequence[Tick],
    repairs: Sequence[datetime],
) -> list[list[Tick]]:
    """Split ``ticks`` into one attributable recovery episode per repair instant."""
    return [
        [t for t in ticks if t.ts >= start and (end is None or t.ts < end)]
        for start, end in _episode_bounds(ticks, repairs)
    ]


def outage_windows(
    ticks: Sequence[Tick],
    repairs: Sequence[datetime],
) -> list[tuple[datetime, tuple[datetime, datetime]]]:
    """Return ``(repair, (start, end))`` for each repair that falls inside an induced outage.

    WHY THIS EXISTS
    ---------------
    ``slo_latency_p95_ms`` and ``slo_error_rate_max`` describe **steady state**. The timeline that
    calibrates the dwell does not: it deliberately contains induced outages, because a dwell cannot
    be measured without them. Computing the two thresholds over the whole timeline calibrates the
    SLO bound from the breaches it exists to detect -- measured on the first run of this
    instrument, that produced ``slo_error_rate_max: 0.117098``, an 11.7% error budget that would
    admit almost any real breach. The outage rows have to come out first.

    HOW THE WINDOW IS FOUND WITHOUT A NEW CONSTANT
    ----------------------------------------------
    A repair instant falls *inside* its outage -- repair is applied while the SLO is broken -- so
    the outage is the maximal contiguous run of red ticks containing the repair, found by walking
    backwards and forwards from it. That needs no injection timestamp, no grace period and no
    threshold: it reads the run the timeline actually contains.

    A repair with no red tick around it yields no window, which is the honest answer for a
    perturbation that failed to break the SLO -- and the case the previous pilot was silently in.

    WHY EACH WINDOW CARRIES ITS REPAIR
    ----------------------------------
    Because a repair can yield no window, the windows are not one per repair, and a window's list
    position says nothing about which repair it belongs to. Pairing them with the sorted repair
    instants by position is the defect ADR-048's log records on 2026-09-11: once a repair with no
    window sorted before one with a window, every later window was attributed to the wrong repair,
    which moved the settling anchor and the episode bounds and could leave no clean dwell at all.
    Each window is therefore returned with the repair it was found from, in sorted repair order, so
    a consumer reads the pairing rather than reconstructing it.
    """
    if not ticks:
        return []
    windows: list[tuple[datetime, tuple[datetime, datetime]]] = []
    for repair in sorted(repairs):
        # The last tick at or before the repair; the outage is in progress there.
        candidates = [i for i, t in enumerate(ticks) if t.ts <= repair]
        if not candidates:
            continue
        here = candidates[-1]
        if not ticks[here].ok:
            start = here
            while start > 0 and not ticks[start - 1].ok:
                start -= 1
            end = here
            while end + 1 < len(ticks) and not ticks[end + 1].ok:
                end += 1
            windows.append((repair, (ticks[start].ts, ticks[end].ts)))
    return windows


def steady_state_rows(
    rows: Sequence[ProbeResult],
    repairs: Sequence[datetime],
    interval_seconds: float = float(PROBE_INTERVAL_SECONDS),
) -> list[ProbeResult]:
    """Return ``rows`` with every induced outage removed, for the two steady-state thresholds.

    The window's closing tick is itself red, so the filter excludes up to one further interval past
    it: a tick's rows are stamped across the pass, and dropping only up to the tick's own start
    instant would leave that tick's remaining failed probes in the "steady state" sample.
    """
    windows = [window for _repair, window in outage_windows(probe_ticks(rows), repairs)]
    if not windows:
        return list(rows)
    margin = timedelta(seconds=interval_seconds)
    kept = []
    for row in rows:
        moment = datetime.fromisoformat(row.ts)
        if any(start <= moment < end + margin for start, end in windows):
            continue
        kept.append(row)
    return kept


def _declares_recovery_at(
    episode: Sequence[Tick],
    dwell: float,
    interval_seconds: float = float(PROBE_INTERVAL_SECONDS),
) -> datetime | None:
    """Return the instant this episode would be declared recovered under a ``dwell``-second rule.

    The rule is the protocol's, read literally: the first tick beginning an unbroken green run that
    *spans* the dwell. A run the timeline merely ran out of does not count -- treating it as a
    declaration is how an observation window's end gets reported as a recovery.

    Spanning is compared with a tolerance of half a probe interval, because the tick cadence is the
    interval plus the time the probe set itself takes: measured at 5.027s against a 5s interval. An
    exact comparison makes a dwell of exactly one interval unsatisfiable -- the second tick of the
    run lands ~27ms past the deadline and the run is scored as never having spanned it -- which is
    an artefact of the instrument's own cadence rather than anything about the system. The half
    interval is the same cadence-owning move ADR-050 makes in ``measures.py`` for the same reason,
    and it is bounded well below one interval so it can never let a run of n ticks satisfy a dwell
    that needs n+1.
    """
    tolerance = interval_seconds / 2.0
    index = 0
    while index < len(episode):
        if not episode[index].ok:
            index += 1
            continue
        end = index
        while end + 1 < len(episode) and episode[end + 1].ok:
            end += 1
        if (episode[end].ts - episode[index].ts).total_seconds() + tolerance >= dwell:
            return episode[index].ts
        if end + 1 >= len(episode):
            # The run reached the end of the episode without spanning the dwell: the timeline is
            # exhausted, and no later start has more of it left.
            return None
        index = end + 1
    return None


def false_recovery_curve(
    rows: Sequence[ProbeResult],
    repairs: Sequence[datetime],
    interval_seconds: float = float(PROBE_INTERVAL_SECONDS),
    max_dwell_seconds: float | None = None,
    error_rate_max: float = 0.0,
) -> list[tuple[int, int, int]]:
    """Return ``(dwell, premature, undeclared)`` per candidate dwell, one interval apart.

    For each candidate, every episode is replayed under :func:`_declares_recovery_at`.

    * ``premature`` counts episodes where the rule declared recovery and a red tick followed
      inside the same episode -- the declaration was retracted by the system's own behaviour.
    * ``undeclared`` counts episodes where the rule never declared recovery at all within the
      observation the episode carries.

    The two together are what makes the choice defensible. ``premature`` falls as the dwell grows,
    because a longer dwell is harder to satisfy by accident; ``undeclared`` rises, because a longer
    dwell needs more uninterrupted green than a timeline punctuated by background failures offers.
    The usable dwell is where the first has reached its floor and the second has not yet left zero,
    and if no such dwell exists this function is what shows that, instead of a single number that
    conceals it.

    WHY RETRACTION IS JUDGED BY ``error_rate_max`` AND NOT BY A SINGLE RED TICK
    --------------------------------------------------------------------------
    A declaration is retracted when the rest of the episode *breaches the SLO*, not when it
    contains any red tick at all. This is what ties the dwell to ``slo_error_rate_max`` instead of
    letting the two be chosen independently, and it is required rather than convenient: the
    deployment has a non-zero background failure rate -- measured on this cluster as an occasional
    3s timeout on the home page, unrelated to any perturbation -- and under a
    single-red-tick rule one such blip arriving minutes after a genuine recovery retracts it. That
    is precisely the defect ADR-048 records in its original form: a value that tracks the last red
    sample wherever it falls, and therefore never converges.

    Judging retraction by the same rate that defines "the SLO is met" makes the instrument
    self-consistent. An isolated blip inside a long green tail does not breach a rate-based SLO, so
    it does not retract; a genuine relapse does, because a relapse is many consecutive reds. With
    ``error_rate_max`` left at zero the rule degenerates to the single-red-tick reading, which is
    why the calibration path measures the error rate *first* and passes it in.
    """
    ticks = probe_ticks(rows)
    if not ticks:
        return []
    span = (ticks[-1].ts - ticks[0].ts).total_seconds()
    ceiling = span if max_dwell_seconds is None else max_dwell_seconds
    episodes = _episodes(ticks, repairs)
    # The post-declaration rate is measured over ROWS, not ticks, because ``error_rate_max`` is a
    # per-sample bound -- it is what ``classify`` compares ``observed_error_rate(rows)`` against.
    # A tick is red when any one of its four probes is, so a tick-level rate runs about four times
    # the sample-level one and comparing it against this threshold silently over-retracts.
    bounds = _episode_bounds(ticks, repairs)
    curve: list[tuple[int, int, int]] = []
    step = max(interval_seconds, 1.0)
    dwell = step
    while dwell <= ceiling:
        premature = 0
        undeclared = 0
        for index, episode in enumerate(episodes):
            declared = _declares_recovery_at(episode, dwell, interval_seconds)
            if declared is None:
                undeclared += 1
                continue
            end = bounds[index][1]
            after = [
                row
                for row in rows
                if datetime.fromisoformat(row.ts) > declared
                and (end is None or datetime.fromisoformat(row.ts) < end)
            ]
            if after and (sum(1 for r in after if not r.ok) / len(after)) > error_rate_max:
                premature += 1
        curve.append((int(round(dwell)), premature, undeclared))
        dwell += step
    return curve


def stabilization_dwell_seconds(
    rows: Sequence[ProbeResult],
    repairs: Sequence[datetime],
    interval_seconds: float = float(PROBE_INTERVAL_SECONDS),
    error_rate_max: float = 0.0,
) -> int | None:
    """Return the calibrated stabilization *dwell*, or None when the timeline cannot support one.

    WHAT THIS NUMBER IS, AND WHAT IT REPLACED
    -----------------------------------------
    ``evaluation-protocol.md`` section 3 is the only definitional text for this constant, and it
    consumes it as a dwell: the restoration instant is the "first timestamp where all SLO probes
    are green continuously for the stabilization window". ``analysis/stats/measures.py``
    (``time_to_slo_recovery``) reads it the same way. Until ADR-048 this function computed
    something else entirely -- the elapsed time from the first sample to the start of the final
    unbroken green run, a *settle* time -- and the two are not different estimates of one quantity,
    they are different quantities. The settle reading also could not converge: over a fixed
    observation it tracked the last failing sample wherever it fell, so a single late background
    blip pinned the value near the observation length and no plateau existed to find.

    WHY THE REPAIR INSTANTS ARE REQUIRED
    ------------------------------------
    A dwell cannot be recovered from an unlabelled timeline. The quantity it must exceed is the
    longest green run that occurs *during a recovery* and is then broken -- and a timeline alone
    cannot say which green runs are recoveries and which are the quiet gaps between background
    failures. Those gaps lengthen with the observation, which is the same non-convergence in a new
    place. ``repairs`` supplies the boundary from outside the timeline. With no repair instants
    this returns None and the calibration path refuses, exactly as it refuses a p95 it never
    observed: the module does not fill a protocol constant with a number the run did not
    demonstrate.

    THE CHOICE RULE
    ---------------
    The **shortest** dwell that is both demonstrably clean and at least as long as the system's own
    settling time: the smallest candidate with ``premature == 0`` and ``undeclared == 0`` that is
    not below :func:`settling_seconds`.

    The two halves do different jobs, and neither alone is enough on this deployment. The clean
    condition is the empirical one -- no episode's later behaviour retracts a declaration made under
    this dwell, and every episode can still satisfy it. But the induced outage here is a contiguous
    run of red, so ``premature`` is zero at every candidate and the clean condition on its own
    admits everything from one probe interval upwards. The settling anchor is what selects within
    that: a dwell shorter than the longest observed post-repair settling interval would accept a
    green run that the system's own recovery dynamics have not yet finished, and one much longer
    would be justified by nothing that was measured. See :func:`settling_seconds` for why the
    obvious upper bound -- the background-rate completion ceiling -- cannot do this job here.

    Lengthening the dwell is cheap but not free of meaning. ``measures.py::time_to_slo_recovery``
    returns ``(start - t0)``, the instant the sustained green run *began*, so a longer dwell does
    not push the reported restoration time later; it only demands more evidence before the same
    instant is accepted. That is why the rule is free to take the settling anchor rather than the
    resolution floor. :func:`dwell_completion_ceiling_seconds` remains available as a *check* --
    a chosen dwell far above it would rarely complete -- rather than as the selector.

    When no candidate is clean, None is returned rather than a compromise: see
    :func:`false_recovery_curve` for why that case is a real answer.
    """
    if not probe_ticks(rows) or not repairs:
        return None
    curve = false_recovery_curve(
        rows, repairs, interval_seconds=interval_seconds, error_rate_max=error_rate_max
    )
    clean = [d for d, p, u in curve if p == 0 and u == 0]
    if not clean:
        return None
    anchor = settling_seconds(rows, repairs, interval_seconds=interval_seconds)
    if anchor is None:
        return None
    candidates = [d for d in clean if d >= anchor]
    chosen = min(candidates) if candidates else max(clean)
    return max(chosen, math.ceil(interval_seconds))


def settling_seconds(
    rows: Sequence[ProbeResult],
    repairs: Sequence[datetime],
    interval_seconds: float = float(PROBE_INTERVAL_SECONDS),
) -> int | None:
    """Return the longest observed post-repair settling interval, rounded up to a probe interval.

    WHY THE DWELL IS ANCHORED HERE
    ------------------------------
    The false-recovery curve is the primary evidence, and on this deployment it discriminates
    nothing: the induced outage is a contiguous run of red ticks with no green inside it, so
    ``premature`` is zero at *every* candidate dwell and the curve supplies no lower bound above
    the instrument's resolution. The completion ceiling cannot supply an upper bound either,
    because steady state under load shows no failures at all -- so the ceiling is a function of how
    long the calibration happened to watch (102 steady ticks put it near 9s, 216 near 20s). A
    constant read off either of those would be a fact about the experiment, which is the same
    defect ADR-048 exists to remove, wearing different clothes.

    The settling interval is a fact about the *system*. It is the time from the repair instant to
    the last failing tick of the outage it repairs -- how long the deployment keeps failing after
    the fix is applied. A green run at least that long is evidence of being *past* the settling
    period rather than inside it, which is precisely what the dwell is asked to certify. It is
    measured per perturbation, so it converges as cycles accumulate, and it does not move when the
    observation window changes length.

    The maximum across episodes rather than the mean: the dwell has to survive the slowest
    recovery observed, not the typical one.

    Rounded up to a whole probe interval, and never below one, for the resolution reason that
    applies to every duration this instrument reports.
    """
    ticks = probe_ticks(rows)
    windows = outage_windows(ticks, repairs)
    if not windows:
        return None
    # Each lag runs from a repair to the end of the window found from THAT repair; a perturbation
    # that broke nothing has no window and contributes no lag (ADR-048 log, 2026-09-11).
    lags = [(end - repair).total_seconds() for repair, (_start, end) in windows]
    if not lags:
        return None
    longest = max(max(lags), 0.0)
    steps = math.ceil(longest / interval_seconds)
    return int(max(steps, 1) * interval_seconds)


def dwell_completion_ceiling_seconds(
    rows: Sequence[ProbeResult],
    repairs: Sequence[datetime],
    interval_seconds: float = float(PROBE_INTERVAL_SECONDS),
    confidence: float = 0.95,
) -> float | None:
    """Return the longest strict all-green dwell that completes with ``confidence`` probability.

    A dwell of ``n`` ticks survives a steady-state per-tick failure rate ``q`` with probability
    ``(1 - q)^n``; solving for the confidence gives ``ln(confidence) / ln(1 - q)`` ticks. This is
    the ceiling half of :func:`stabilization_dwell_seconds`'s rule, and the reason the dwell and
    ``slo_error_rate_max`` cannot be chosen independently: both are functions of the same measured
    background rate, one as a bound on how many failures steady state may contain and the other as
    a bound on how long a run may be asked to contain none.

    ``q`` is measured per **tick** and over steady state only, because the dwell's own greenness
    rule is per tick and the induced outages are not background.

    WHY THE BOUND AND NOT THE OBSERVED RATE, AGAIN
    ---------------------------------------------
    ``q`` is taken as the Wilson **upper** limit on the tick failure proportion, for the same reason
    ``slo_error_rate_max`` is. Using the point estimate breaks exactly where it matters: a run with
    no steady-state failure at all gives ``q = 0``, hence no finite ceiling, and the rule then
    returns the longest dwell the *observation window* happened to allow -- 290s on a 300s window,
    a number about the experiment rather than about the system. Observing zero failures in ``n``
    ticks is not evidence that the rate is zero; it is evidence that it is below roughly ``3/n``,
    and the Wilson limit is that statement made precisely.

    A consequence worth stating: a longer steady-state observation tightens the bound and so
    *raises* the ceiling. That is the correct direction. More evidence that the deployment is
    stable is what justifies demanding a longer unbroken green run before believing a recovery.
    """
    ticks = probe_ticks(steady_state_rows(rows, repairs, interval_seconds=interval_seconds))
    if not ticks:
        return None
    failures = sum(1 for t in ticks if not t.ok)
    q = wilson_upper_bound(failures, len(ticks))
    if q <= 0.0 or q >= 1.0:
        return None
    return (math.log(confidence) / math.log(1.0 - q)) * interval_seconds


def calibrated_mapping(
    rows: Sequence[ProbeResult],
    repairs: Sequence[datetime] = (),
    interval_seconds: float = float(PROBE_INTERVAL_SECONDS),
) -> dict[str, object]:
    """Return the section 4 mapping with the three measured keys filled from ``rows``.

    Raises :class:`ValueError` naming what could not be measured, rather than emitting a block
    with a hole in it: a calibration commit is a protocol edit frozen at ``v1.0``, and a value
    that was never observed must not reach it under cover of a plausible default.

    The clamping rules for the error rate and the dwell are stated in the module docstring. Both
    clamp to what the instrument could resolve, never to a chosen margin. The two are computed in
    a fixed order because the dwell depends on the error rate; see the comment below.
    """
    if not repairs:
        raise ValueError(
            "no repair instants given: a stabilization dwell cannot be measured from an "
            "unlabelled timeline (pass --repair-at once per perturbation; see ADR-048)"
        )
    # The two threshold values describe steady state, so the induced outages come out before they
    # are measured; the dwell below is measured over the WHOLE timeline, because the outages are
    # exactly what it needs. See outage_windows. ADR-048.
    steady = steady_state_rows(rows, repairs, interval_seconds=interval_seconds)
    if not steady:
        raise ValueError(
            "the timeline is entirely induced outage: no steady-state sample to threshold against"
        )
    p95 = observed_p95_ms(steady)
    if p95 is None:
        raise ValueError("no successful probe rows: p95 latency was never observed")
    error_rate = observed_error_rate(steady)
    if error_rate is None:
        raise ValueError("empty timeline: error rate was never observed")
    mapping = as_protocol_mapping()
    mapping["slo_latency_p95_ms"] = math.ceil(p95)
    # Rounded to six decimals on both branches. The value is pasted into a protocol file that
    # is frozen at v1.0 and read by humans, and seventeen digits of float repr there would be
    # precision the measurement does not carry, in a place nobody can later tell was spurious.
    # The Wilson upper limit, not the point estimate: see wilson_upper_bound for why a maximum set
    # to the observed rate is wrong about half the time. The resolution floor still applies -- a
    # timeline of n samples cannot resolve a rate below 1/n -- so the bound is the larger of the
    # two, and is never zero even on a flawless timeline.
    failures = round(error_rate * len(steady))
    observed_bound = max(wilson_upper_bound(failures, len(steady)), 1.0 / len(steady))
    mapping["slo_error_rate_max"] = round(observed_bound, 6)

    # The error rate is measured first and fed into the dwell, because section 4's two remaining
    # measured values are not independent and this order is what makes them consistent: the rate
    # that defines "the SLO is met" is the same rate that decides whether a declared recovery held.
    # See false_recovery_curve. ADR-048.
    window = stabilization_dwell_seconds(
        rows,
        repairs,
        interval_seconds=interval_seconds,
        error_rate_max=float(mapping["slo_error_rate_max"]),
    )
    if window is None:
        raise ValueError(
            "no dwell satisfies every episode: at each candidate the timeline either retracted "
            "the declaration or never made one (print --curve to see the trade-off)"
        )
    mapping["stabilization_window_seconds"] = window
    return mapping


def classify(
    rows: Sequence[ProbeResult],
    mapping: Mapping[str, object] | None = None,
) -> Verdict:
    """Compare an observed timeline against the section 4 thresholds and return a verdict.

    Returns ``PENDING`` -- not ``PASS`` -- whenever any threshold still holds the sentinel. This is
    the guard the module docstring describes, and it is checked before anything else so that no
    comparison is ever attempted against a string.

    When the thresholds are calibrated, the verdict is taken over the rows that fall at least one
    stabilization dwell after the first sample, because the start-up period is by definition not
    steady state and grading it would report environment start-up as an SLO breach. A timeline with
    no such row at all is a ``FAIL``: it has not demonstrated the SLO, and calling that anything
    else is the silent pass this module exists to prevent.

    The dwell is used here as an elapsed offset, which is the same arithmetic this function
    performed before ADR-048 but no longer the same claim. It is not asserting that the timeline
    settled at that instant -- that reading was the defect ADR-048 records; it is skipping one
    dwell's worth of start-up, which is the shortest prefix that could contain an unobserved
    recovery.
    """
    source = as_protocol_mapping() if mapping is None else mapping
    missing = pending_keys(source)
    if missing:
        return Verdict(
            state="PENDING",
            reasons=tuple(f"{key} is uncalibrated" for key in missing),
            observed_p95_ms=observed_p95_ms(rows),
            observed_error_rate=observed_error_rate(rows),
            samples=len(rows),
        )

    window = float(source["stabilization_window_seconds"])
    graded = rows
    if rows:
        first = datetime.fromisoformat(rows[0].ts)
        graded = [
            row
            for row in rows
            if (datetime.fromisoformat(row.ts) - first).total_seconds() >= window
        ]

    reasons: list[str] = []
    if not graded:
        reasons.append(
            f"timeline holds no sample after the {window:g}s stabilization window; "
            "the SLO was not demonstrated"
        )
        return Verdict("FAIL", tuple(reasons), None, None, 0)

    p95 = observed_p95_ms(graded)
    error_rate = observed_error_rate(graded)
    latency_budget = float(source["slo_latency_p95_ms"])
    error_budget = float(source["slo_error_rate_max"])

    if p95 is None:
        reasons.append("no successful sample after the stabilization window")
    elif p95 > latency_budget:
        reasons.append(f"p95 latency {p95:.3f} ms exceeds the budget {latency_budget:g} ms")
    if error_rate is not None and error_rate > error_budget:
        reasons.append(f"error rate {error_rate:.6f} exceeds the maximum {error_budget:g}")

    state = "FAIL" if reasons else "PASS"
    return Verdict(state, tuple(reasons), p95, error_rate, len(graded))


def build_parser() -> argparse.ArgumentParser:
    """Return the command-line parser.

    ``--duration`` and ``--samples`` are a required, mutually exclusive pair. Neither carries a
    default, for the reason the module docstring gives: the length of a measurement window has no
    owner in any protocol file yet, and a default here would quietly become that owner.
    """
    parser = argparse.ArgumentParser(
        prog="python -m infra.probes.slo_probe",
        description=(
            "Drive the SLO probe set owned by evaluation-protocol section 4 and append the "
            "probes.csv timeline. Thresholds are compared only when they have been calibrated; "
            "an uncalibrated threshold is reported, never assumed to have been met."
        ),
    )
    # Not required: --calibrate-from reads a timeline rather than writing one, so it has nothing
    # to append to. main() enforces that a run which collects rows was given somewhere to put them.
    parser.add_argument("--out", type=Path, default=None, help="Path of the probes.csv to append.")
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8080",
        help=(
            "Base URL of the Boutique frontend that the section 4 target paths are joined to. "
            "An operator convenience defaulting to the conventional port-forward, not a pin: the "
            "frontend address is an environment fact and has no home in the protocol."
        ),
    )
    parser.add_argument(
        "--profile",
        default=None,
        metavar="LOAD-ID",
        help=(
            "Load profile identifier this timeline was taken under. Recorded in the run notice "
            "only; it never selects a threshold, and its bundle home is the manifest field "
            "load_profile_id."
        ),
    )
    # Not `required=True`: --calibrate-from does not run a timeline, so it has no stopping rule to
    # state. main() enforces that exactly one of the two shapes is given.
    stop = parser.add_mutually_exclusive_group()
    stop.add_argument("--duration", type=float, metavar="SECONDS", help="Stop after this long.")
    stop.add_argument("--samples", type=int, metavar="N", help="Stop after N probe-set cycles.")
    parser.add_argument(
        "--calibrate",
        action="store_true",
        help=(
            "After writing the timeline, compute the three measured section 4 values from it and "
            "print the exact block to paste into evaluation-protocol section 4."
        ),
    )
    parser.add_argument(
        "--repair-at",
        action="append",
        default=[],
        metavar="ISO-8601",
        dest="repair_at",
        help=(
            "Instant a perturbation's repair was applied, repeated once per perturbation. "
            "Required by --calibrate: the stabilization dwell is the duration a green run must "
            "span to count as a recovery, and which green runs are recoveries cannot be read off "
            "an unlabelled timeline (ADR-048)."
        ),
    )
    parser.add_argument(
        "--calibrate-from",
        type=Path,
        default=None,
        metavar="PROBES_CSV",
        dest="calibrate_from",
        help=(
            "Calibrate from this recorded timeline instead of collecting a new one. The dwell is "
            "measured across perturbation cycles applied by an external driver, so the recording "
            "process is not the calibrating one; this also lets a sealed bundle's probes.csv be "
            "re-derived to the same numbers. Implies --calibrate and skips the probe run."
        ),
    )
    parser.add_argument(
        "--curve",
        action="store_true",
        help=(
            "With --calibrate, also print the premature/undeclared table over every candidate "
            "dwell, to stderr, so the chosen value can be checked against the trade-off it was "
            "read off rather than taken on trust."
        ),
    )
    return parser


def _notice(message: str) -> None:
    """Write one operator notice to stderr.

    Notices go to stderr and never to stdout, because ``--calibrate`` writes the protocol block to
    stdout and that block has to stay pasteable straight out of a redirect.
    """
    print(message, file=sys.stderr)


def _emit_calibration(rows: Sequence[ProbeResult], args: argparse.Namespace) -> int:
    """Print the section 4 block for ``rows`` and return the process exit code.

    Shared by the two ways a calibration is reached -- a timeline this process just collected, and
    one ``--calibrate-from`` read back from disk -- so that both produce byte-identical output from
    the same rows. A second copy of this that drifted would mean the block a bundle re-derives is
    not the block the run printed.
    """
    try:
        repairs = [datetime.fromisoformat(stamp) for stamp in args.repair_at]
    except ValueError as failure:
        _notice(f"slo_probe: --repair-at is not an ISO-8601 timestamp: {failure}")
        return EXIT_USAGE
    if args.curve:
        # The same bound calibrated_mapping will write, so the printed curve is the curve the
        # chosen value was actually read off rather than a differently-thresholded one.
        _steady = steady_state_rows(rows, repairs)
        _rate = (observed_error_rate(_steady) or 0.0) if _steady else 0.0
        measured_rate = (
            max(wilson_upper_bound(round(_rate * len(_steady)), len(_steady)), 1.0 / len(_steady))
            if _steady
            else 0.0
        )
        for dwell, premature, undeclared in false_recovery_curve(
            rows, repairs, error_rate_max=measured_rate
        ):
            _notice(f"slo_probe: dwell {dwell:>5}s  premature {premature}  undeclared {undeclared}")
    try:
        mapping = calibrated_mapping(rows, repairs)
    except ValueError as failure:
        _notice(f"slo_probe: cannot calibrate from this timeline: {failure}")
        return EXIT_USAGE
    _notice(
        "slo_probe: calibrated from "
        f"{len(rows)} rows; paste the block below into "
        "docs/protocols/evaluation-protocol.md section 4, and make the identical edit to "
        "infra/probes/constants.py in the same commit."
    )
    print(render_protocol_block(mapping), end="")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Run a probe timeline and return the process exit code.

    The exit-code table is in the module docstring. The uncalibrated case is loud on purpose: one
    line naming every missing threshold, printed whether or not anyone is reading, plus a non-zero
    code so that a caller which only checks the status still learns that nothing was verified.
    """
    args = build_parser().parse_args(argv)

    if args.calibrate_from is not None:
        if args.duration is not None or args.samples is not None:
            _notice(
                "slo_probe: --calibrate-from does not run a timeline; drop --duration/--samples"
            )
            return EXIT_USAGE
        try:
            rows = read_rows(args.calibrate_from)
        except (OSError, ValueError) as failure:
            _notice(f"slo_probe: could not read {args.calibrate_from}: {failure}")
            return EXIT_USAGE
        _notice(f"slo_probe: calibrating from {len(rows)} recorded rows in {args.calibrate_from}")
        return _emit_calibration(rows, args)
    if args.duration is None and args.samples is None:
        _notice("slo_probe: one of --duration, --samples or --calibrate-from is required")
        return EXIT_USAGE
    if args.out is None:
        _notice("slo_probe: --out is required when a timeline is collected")
        return EXIT_USAGE

    _notice(
        f"slo_probe: {len(SLO_PROBE_SET)} probes every {PROBE_INTERVAL_SECONDS}s, "
        f"timeout {PROBE_TIMEOUT_SECONDS}s, base-url {args.base_url}, "
        f"profile {args.profile or 'unset'}, out {args.out}"
    )

    rows: list[ProbeResult] = []

    def _collect() -> Iterator[ProbeResult]:
        for row in run_timeline(
            base_url=args.base_url,
            samples=args.samples,
            duration_seconds=args.duration,
        ):
            rows.append(row)
            yield row

    try:
        written = write_rows(_collect(), args.out)
    except OSError as failure:
        _notice(f"slo_probe: could not write {args.out}: {failure}")
        return EXIT_USAGE

    _notice(f"slo_probe: wrote {written} rows to {args.out}")

    if args.calibrate:
        return _emit_calibration(rows, args)

    verdict = classify(rows)
    if verdict.state == "PENDING":
        _notice(
            "slo_probe: SLO VERDICT UNAVAILABLE -- thresholds are uncalibrated ("
            + ", ".join(MEASURED_KEYS)
            + " are pending); the timeline was written and ok reflects transport and HTTP status "
            "only. Run again with --calibrate against a deployed cluster."
        )
        return EXIT_THRESHOLDS_PENDING
    if verdict.state == "FAIL":
        for reason in verdict.reasons:
            _notice(f"slo_probe: SLO BREACHED -- {reason}")
        return EXIT_SLO_BREACHED
    _notice(
        f"slo_probe: SLO met over {verdict.samples} post-stabilization rows "
        f"(p95 {verdict.observed_p95_ms:.3f} ms, error rate {verdict.observed_error_rate:.6f})"
    )
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
