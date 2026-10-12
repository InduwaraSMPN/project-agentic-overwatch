"""Checked copy of the instrument constants owned by evaluation-protocol section 4.

WHAT THIS MODULE IS, AND WHAT IT IS NOT
---------------------------------------
``docs/protocols/evaluation-protocol.md`` section 4 is the *authority* for every value below.
This module is a mirror of it and never an independent source. Nothing here may be changed on its
own: an edit to a value in this file that is not accompanied by the identical edit to section 4
fails ``infra/tests/test_constants_match_protocol.py``, which parses the section 4 block and
asserts the two agree key by key. That test is the entire reason a mirror is permitted at all.
``.agents/rules/00-source-of-truth.md`` allows a literal to repeat only where no second *decision*
exists, and a machine check is what turns "a copy" into "a copy that cannot drift".

The alternative shapes were both worse. Parsing the protocol Markdown at runtime would make the
probe's behaviour depend on the prose formatting of a document that is edited by humans for
readability, and would put a Markdown parser on the critical path of every run. Generating a YAML
file from the protocol at build time would create a third artefact that is neither the authority
nor the code, and that a reviewer would have to remember to regenerate. A mirror plus a test keeps
exactly two copies, both reviewable in one diff, with CI holding them equal.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
``slo_probe.py`` drives ``SLO_PROBE_SET`` on the ``PROBE_INTERVAL_SECONDS`` cadence, and
``infra/collectors/resource_collector.py`` imports that same interval so that the two timelines
share one clock. ``docs/protocols/data-management.md`` section 4 invalidates a run whose "probe
timeline has gaps > probe interval x3", so the interval is load-bearing for run validity and not
merely for resolution: change it and every previously recorded campaign's validity was judged
against a different rule.

MEASURED VALUES ARE NOT FILLED YET, AND ARE NOT GUESSED
-------------------------------------------------------
Three of the six keys are *measurements*, not choices. ``slo_latency_p95_ms`` and
``slo_error_rate_max`` come from observing the deployed Boutique under each load profile, and
``stabilization_window_seconds`` from how long the probe timeline takes to settle after load
starts. None of them can be obtained without a running cluster, and inventing a plausible-looking
number for a value the dissertation will report is exactly what
``.agents/rules/00-source-of-truth.md`` forbids. Each therefore carries the sentinel
:data:`PENDING_CALIBRATION` in this file and in section 4, and ``slo_probe.py`` refuses to form an
SLO verdict while any of them is pending rather than defaulting to a pass.
``python -m infra.probes.slo_probe --calibrate`` computes all three from an observed timeline and
prints the exact section 4 block to paste, so the calibration commit is mechanical the moment a
cluster exists.

The remaining three keys are *choices* and are filled. ``probe_interval_seconds`` and
``probe_timeout_seconds`` are a cadence and a per-request bound, not properties of the system under
test; ``slo_probe_set`` names endpoints, which are a property of the application's route table
rather than of its performance.

WHY THE VALUES ARE THE VALUES THEY ARE
--------------------------------------
The probe set covers four read-only ``GET`` routes plus one checkout transaction from the upstream
Online Boutique frontend route table (``GoogleCloudPlatform/microservices-demo``,
``src/frontend/main.go``): the frontend's health endpoint, home page, one product page, cart page,
and the existing cart/checkout probe path. They are ordered cheapest-first so that a cascading
failure appears in the timeline as a widening prefix of failed probes rather than as an unordered
scatter. The checkout probe uses its own isolated synthetic session; the other four remain
idempotent. The product identifier is a real catalogue entry from
``src/productcatalogservice/products.json`` and not an invented one, because a 404 on a
non-existent product would make the product probe measure the frontend error path forever.

Targets are *paths*, not absolute URLs. The frontend host and port are an environment fact -- a
NodePort here, a port-forward there, a service DNS name inside the cluster -- and section 4 is
frozen at ``v1.0``, so a hostname baked into it would pin one operator's laptop into the protocol.
The base URL is supplied by ``slo_probe.py``'s ``--base-url`` instead.

``probe_interval_seconds = 5`` and ``probe_timeout_seconds = 3`` are chosen together, against the
run-validity rule. One full cycle drives every probe in the set in sequence, so the worst case --
every probe timing out -- takes ``len(SLO_PROBE_SET) * PROBE_TIMEOUT_SECONDS`` seconds, which is
12 s for the four-entry set. That is under the ``PROBE_INTERVAL_SECONDS * 3`` gap that
data-management section 4 uses to invalidate a run, so a total outage of the application produces
a *recorded* timeline of failed samples rather than a gap that invalidates the run. That
distinction is the whole point of the instrument: an outage is the phenomenon T-21 measures, and it
must never be mistaken for an instrument fault. The invariant is asserted by
``test_constants_match_protocol.py`` so that growing the probe set past five entries, or raising
the timeout, fails a test instead of quietly making long outages self-invalidating. At five
seconds the probe set adds 0.8 requests per second, which is negligible beside any Locust profile
and so does not itself perturb the interference measure.

MUTABILITY
----------
The probe entries are a frozen dataclass in a tuple, and the module exposes no mutable container.
A module-level list or dict is shared process-wide, so any importer -- including a test that meant
to work on a copy -- could rebind an endpoint and every subsequent probe in that process would
silently drive somewhere else. :func:`as_protocol_mapping` builds a fresh plain-data structure on
each call for the same reason: the comparison surface handed to the test cannot then be poisoned
by an earlier caller.
"""

from collections.abc import Mapping
from dataclasses import dataclass

# The sentinel that stands in for a value which must be measured on a deployed cluster and has not
# been measured yet. It is a string, and deliberately not None or 0: None would read as "this key
# is optional" and 0 would compare as a legitimate threshold, whereas an unmistakable string forces
# every consumer to decide what to do about it. slo_probe.py decides by refusing to form a verdict;
# test_constants_match_protocol.py decides by admitting the sentinel and requiring anything else to
# parse as a positive number.
PENDING_CALIBRATION = "PENDING-M1-CALIBRATION"

# The HTML comment that marks the constants block inside evaluation-protocol.md section 4. An
# anchor is used rather than a heading search because headings are prose and get retitled, whereas
# an anchor exists for exactly one purpose and a reviewer who moves it knows what they are doing.
PROTOCOL_ANCHOR = "<!-- m1-instrument-constants -->"

# The path of the owning protocol file, relative to the repository root. Consumers resolve it
# against a root derived from their own __file__, never against the current working directory.
PROTOCOL_RELATIVE_PATH = "docs/protocols/evaluation-protocol.md"

# The key set is fixed and total: the section 4 block and as_protocol_mapping() must each carry
# exactly these keys, in this order. Order is part of the contract only for rendering -- the
# equality test compares mappings, not text -- but a stable order keeps the protocol diff readable
# when the calibration commit fills the three measured values.
PROTOCOL_KEYS: tuple[str, ...] = (
    "slo_probe_set",
    "probe_interval_seconds",
    "probe_timeout_seconds",
    "slo_latency_p95_ms",
    "slo_error_rate_max",
    "stabilization_window_seconds",
)

# The keys whose values are measured on a deployed cluster rather than chosen. These are the three
# that may legally hold PENDING_CALIBRATION, and the three that --calibrate computes.
MEASURED_KEYS: tuple[str, ...] = (
    "slo_latency_p95_ms",
    "slo_error_rate_max",
    "stabilization_window_seconds",
)


@dataclass(frozen=True, slots=True)
class ProbeSpec:
    """One entry of the SLO probe set: an identifier, a request path and a method.

    ``target`` is a path relative to the frontend base URL, for the reason the module docstring
    gives. ``probe_id`` is what appears in the ``probe_id`` column of ``probes.csv``, so it is the
    join key any later analysis groups a timeline by and it must stay stable across a campaign.
    """

    probe_id: str
    target: str
    method: str


SLO_PROBE_SET: tuple[ProbeSpec, ...] = (
    ProbeSpec(probe_id="PROBE-FRONTEND-HEALTHZ", target="/_healthz", method="GET"),
    ProbeSpec(probe_id="PROBE-FRONTEND-HOME", target="/", method="GET"),
    ProbeSpec(probe_id="PROBE-FRONTEND-PRODUCT", target="/product/OLJCESPC7Z", method="GET"),
    ProbeSpec(probe_id="PROBE-FRONTEND-CART", target="/cart", method="GET"),
    ProbeSpec(probe_id="PROBE-FRONTEND-CHECKOUT", target="/cart/checkout", method="POST"),
)

PROBE_INTERVAL_SECONDS: int = 5
PROBE_TIMEOUT_SECONDS: int = 3

# Measured 2026-09-10 on the WSL2/kind profile under LOAD-STEADY, across three identical
# scale-to-zero perturbations of productcatalogservice. Derivation, curve and caveats: ADR-048.
# These mirror evaluation-protocol.md section 4 and may not be edited without the identical edit
# there; test_constants_match_protocol.py enforces it.
SLO_LATENCY_P95_MS: int | str = 368
SLO_ERROR_RATE_MAX: float | str = 0.013429
STABILIZATION_WINDOW_SECONDS: int | str = 35


def is_pending(value: object) -> bool:
    """Return True when ``value`` is the uncalibrated sentinel rather than a measured number."""
    return value == PENDING_CALIBRATION


def as_protocol_mapping() -> dict[str, object]:
    """Return the mirrored constants in exactly the shape the section 4 block parses to.

    This is the comparison surface the constants test uses and the input the section 4 renderer
    takes. A fresh structure is built on every call so that no caller can mutate the mirror for
    everyone else; see the module docstring note on mutability.
    """
    return {
        "slo_probe_set": [
            {"probe_id": spec.probe_id, "target": spec.target, "method": spec.method}
            for spec in SLO_PROBE_SET
        ],
        "probe_interval_seconds": PROBE_INTERVAL_SECONDS,
        "probe_timeout_seconds": PROBE_TIMEOUT_SECONDS,
        "slo_latency_p95_ms": SLO_LATENCY_P95_MS,
        "slo_error_rate_max": SLO_ERROR_RATE_MAX,
        "stabilization_window_seconds": STABILIZATION_WINDOW_SECONDS,
    }


def pending_keys(mapping: Mapping[str, object] | None = None) -> tuple[str, ...]:
    """Return the measured keys that still hold the sentinel, in :data:`MEASURED_KEYS` order.

    An empty result means every measured value has been calibrated and a consumer may form an SLO
    verdict. A non-empty result names exactly what is missing, which is what ``slo_probe.py``
    prints in its uncalibrated notice: a reader should never have to guess which threshold is the
    absent one.
    """
    source = as_protocol_mapping() if mapping is None else mapping
    return tuple(key for key in MEASURED_KEYS if is_pending(source.get(key)))


def _render_scalar(value: object) -> str:
    """Render one scalar for the section 4 block.

    Values are emitted unquoted. Every value the key set admits is an integer, a float or the
    sentinel, and none of those needs quoting in the block grammar; adding quotes would mean the
    parser has to strip them, which is one more place for the two sides to disagree.
    """
    return str(value)


def render_protocol_block(mapping: Mapping[str, object] | None = None) -> str:
    """Return the exact text of the anchored section 4 constants block, ending in one newline.

    The renderer lives here, beside the mirror, so that the block a calibration run prints and the
    block a reviewer pastes into the protocol are produced by one piece of code rather than by a
    human retyping a table. ``test_constants_match_protocol.py`` round-trips this function through
    its own parser, which is what makes "the text this prints is the text that test accepts" a
    checked claim rather than an assumption.

    ``mapping`` defaults to the mirrored constants. ``--calibrate`` passes a mapping whose three
    measured keys hold freshly computed numbers in place of the sentinel.
    """
    source = as_protocol_mapping() if mapping is None else mapping
    entries = source["slo_probe_set"]
    if not isinstance(entries, list):
        raise TypeError("slo_probe_set must be a list of probe entries")
    lines: list[str] = [PROTOCOL_ANCHOR, "", "```yaml", "slo_probe_set:"]
    for entry in entries:
        lines.append(f"  - probe_id: {entry['probe_id']}")
        lines.append(f"    target: {entry['target']}")
        lines.append(f"    method: {entry['method']}")
    for key in PROTOCOL_KEYS:
        if key == "slo_probe_set":
            continue
        lines.append(f"{key}: {_render_scalar(source[key])}")
    lines.append("```")
    return "\n".join(lines) + "\n"


def main() -> int:
    """Print the section 4 block for the currently mirrored constants; return an exit code.

    ``python -m infra.probes.constants`` exists so that a reviewer can see, without reading Python,
    exactly what this module claims section 4 says. It takes no arguments on purpose: this entry
    point reports the mirror, and computing new values from a live cluster is the job of
    ``slo_probe.py --calibrate``, not of this module.
    """
    print(render_protocol_block(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
