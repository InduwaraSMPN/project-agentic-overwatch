"""Upload one complete Trivy JSON report to the Monitor HTTP endpoint using only stdlib."""

from __future__ import annotations

import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO, Final

TRIVY_REPORT_ENV: Final = "MONITOR_TRIVY_REPORT"
TRIVY_URL_ENV: Final = "MONITOR_TRIVY_URL"
DEFAULT_TRIVY_REPORT: Final = "/work/trivy.json"
DEFAULT_TRIVY_URL: Final = "http://evidence-aggregator.monitor.svc.cluster.local:8080/v1/trivy"


def upload_report(
    report: Path,
    *,
    url: str,
    urlopen: Callable[..., BinaryIO] = urllib.request.urlopen,
) -> None:
    """Read and post the full report as one request without interpreting or reshaping it."""
    body = report.read_bytes()
    if not body:
        raise ValueError("Trivy report is empty")
    if urllib.parse.urlsplit(url).scheme not in {"http", "https"}:
        raise ValueError("Trivy endpoint must use http or https")
    request = urllib.request.Request(  # noqa: S310 - scheme allowlisted above
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request) as response:
        response.read()


def main() -> int:
    report = Path(os.environ.get(TRIVY_REPORT_ENV, DEFAULT_TRIVY_REPORT))
    url = os.environ.get(TRIVY_URL_ENV, DEFAULT_TRIVY_URL)
    try:
        upload_report(report, url=url)
    except (OSError, ValueError, urllib.error.URLError) as failure:
        print(f"trivy-uploader: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
