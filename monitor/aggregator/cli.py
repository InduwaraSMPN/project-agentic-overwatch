"""The replay entry point: ``python -m monitor.aggregator.cli``. Parses configuration only.

WHAT THIS MODULE IS FOR
-----------------------
``make monitor-replay`` and ``scripts/monitor_replay.sh`` drive the aggregator through this file,
and so does anyone iterating on a normaliser. It reads one fixture directory, writes
``monitor_events.jsonl`` and ``latency.json`` into an output directory, and does no aggregation
itself: every decision that affects the emitted bytes lives in ``normalize.py``, ``caps.py`` and
``emit.py``, so that the command line cannot become a second place where behaviour is decided.

THE G3 FLAG IS PARSED HERE AND BRANCHED ON NOWHERE
----------------------------------------------------
``--quoting`` / ``--no-quoting`` is the ``G3-UNQUOTED`` toggle. This module's whole involvement with
it is to turn the flag into a field on :class:`~monitor.aggregator.emit.EmitConfig`; it never tests
the value. ``quoting.apply_quoting`` is the one place in the repository that branches on it, and
``emit.py`` calls that function unconditionally.

That is the same discipline ``.agents/rules/10-guardian-first.md`` imposes on the ``G1-LOGONLY`` and
``G2-SHAREDCRED`` arms -- activated only through the runner's condition flags, never by editing the
component. The runner does not exist until M6, so at M2 the flag is a command-line option plus a
configuration field, and ``M6-runner.md`` carries the obligation to drive it from the condition
flags at the task that builds them.

A FIXTURE DIRECTORY IS THE UNIT OF INPUT, AND THE FILENAMES ARE THE CONTRACT
-----------------------------------------------------------------------------
``--input`` names a directory. Each source's raw input is found in it by the filename its registry
row declares -- ``falco.jsonl``, ``prometheus.json``, ``k8s_audit.jsonl``, ``trivy.json`` -- one
name per source, derived mechanically from the source identifier so that a fixture author does not
have to look it up. A source whose file is absent contributes nothing and is reported; a directory
holding none of the four is an error rather than an empty replay, because an empty output that
looked like a successful run is exactly the failure that survives review.

There is deliberately no flag to point one source at an arbitrary file. It would let a replay be
assembled from files that no fixture directory contains, and a golden output that cannot be
reproduced from the tracked corpus is not evidence of anything.

``raw_ref`` PATHS ARE ROOT-RELATIVE, AND THE ROOT IS AN ARGUMENT
-----------------------------------------------------------------
``models.py`` requires ``raw_ref.path`` to carry no root: an absolute path encodes the host that
produced it, so it passes the byte diff on one machine and fails on the next -- the worst shape of
failure available, because the first machine reports success. The path written into each event is
therefore the input file's location relative to ``--raw-root``, which defaults to the repository
root and is a flag because a live run's raw records sit under a run bundle rather than under a
checkout.

CAPS COME FROM THE PROTOCOL, AND THE OVERRIDE IS ALL-OR-NOTHING
-----------------------------------------------------------------
With no cap flags, the limits are resolved from ``limits.py``'s mirror of section 4 and the command
**fails closed** while any of them is still ``PENDING-M2-FIXTURE-STUDY``. That refusal is the point:
during the offline phase a default would let a whole fixture corpus go green against numbers nobody
has measured.

The three ``--*-max`` flags exist because ADR-019 records that the offline replay, the determinism
check and the G3 isolation test have to pass their limits in until the fixture study lands. They are
**fixture-corpus test parameters**, never evidence that section 4's row is closed, and the command
prints that alongside the values so the sentence appears in the log of every run that used them.
Supplying some but not all three is refused: a partial override would silently mix a chosen bound
with a pending one, and the pending one would raise from somewhere that no longer looks like the
call site.

EXIT CODES
----------
``0`` on a completed replay. ``1`` on a named, expected failure -- an uncalibrated limit, a missing
fixture, a malformed record, an unassigned audit severity -- each printed as one line on standard
error with its remediation. ``2`` is argparse's own usage error and is left to argparse. Anything
else is an unexpected exception and is deliberately not caught: a stack trace is the right output
for a defect, and swallowing it into exit 1 would make a bug look like a configuration problem.
"""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from monitor.aggregator import limits as protocol_limits
from monitor.aggregator.caps import CapConfigurationError, CapLimits, protocol_cap_limits
from monitor.aggregator.emit import (
    EmitConfig,
    FixtureInputError,
    NanosecondCounter,
    QuotingUnavailable,
    SourceInput,
    emit,
    read_fixture_inputs,
)
from monitor.aggregator.models import EvidenceSeverity, repository_root
from monitor.aggregator.normalize import DuplicateEventId, RecordLayoutError
from monitor.aggregator.sources import NormalisationError, NormaliserOptions

PROGRAM = "monitor-aggregate"

# The failures this command reports as one line rather than as a stack trace. Every one of them is
# something a caller can act on: a measurement that has not been taken, a fixture that is not
# shaped the way its source is, a severity that has not been assigned. A defect in this package is
# not in the list, on purpose.
_EXPECTED_FAILURES = (
    protocol_limits.UncalibratedLimit,
    CapConfigurationError,
    NormalisationError,
    RecordLayoutError,
    DuplicateEventId,
    QuotingUnavailable,
)


class InputError(ValueError):
    """A problem with what the command was pointed at, rather than with what it found inside."""


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser. Separate from :func:`main` so a test can inspect the surface."""
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description=(
            "Replay one fixture directory through the evidence aggregator, writing "
            "monitor_events.jsonl and latency.json."
        ),
    )
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="fixture directory holding the per-source raw inputs",
    )
    parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="directory to write monitor_events.jsonl and latency.json into",
    )
    parser.add_argument(
        "--quoting",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "quote environment-derived text (default). --no-quoting selects the G3-UNQUOTED "
            "ablation arm; it is configuration and selects no code path in monitor/."
        ),
    )
    parser.add_argument(
        "--raw-root",
        type=Path,
        default=None,
        help=(
            "root that raw_ref paths are expressed relative to; defaults to the repository root. "
            "raw_ref is never absolute, because an absolute path encodes the host."
        ),
    )
    parser.add_argument(
        "--audit-severity",
        choices=[level.value for level in EvidenceSeverity],
        default=None,
        help=(
            "severity assigned to every Kubernetes audit record in this replay. The audit stream "
            "carries none of its own and its 'level' field is a verbosity setting, not a ranking; "
            "the per-rule assignment is authored at T2.4. There is no default."
        ),
    )
    parser.add_argument(
        "--excerpt-count-max",
        type=int,
        default=None,
        help="fixture-corpus override for evidence_excerpt_count_max; never a protocol value",
    )
    parser.add_argument(
        "--excerpt-length-max",
        type=int,
        default=None,
        help="fixture-corpus override for evidence_excerpt_length_max_chars",
    )
    parser.add_argument(
        "--summary-length-max",
        type=int,
        default=None,
        help="fixture-corpus override for summary_length_max_chars",
    )
    return parser


def resolve_cap_limits(args: argparse.Namespace) -> tuple[CapLimits, bool]:
    """Return the cap limits and whether they were overridden. See the module docstring.

    The all-or-nothing rule is enforced here rather than by argparse, because argparse can express
    "these three flags belong together" only as a mutually exclusive group, which is the opposite
    relation.
    """
    overrides = (args.excerpt_count_max, args.excerpt_length_max, args.summary_length_max)
    supplied = [value for value in overrides if value is not None]
    if not supplied:
        return protocol_cap_limits(), False
    if len(supplied) != len(overrides):
        raise InputError(
            "--excerpt-count-max, --excerpt-length-max and --summary-length-max must be given "
            "together or not at all. A partial override would mix a chosen bound with one that is "
            "still PENDING-M2-FIXTURE-STUDY in evaluation-protocol.md section 4."
        )
    return (
        CapLimits(
            evidence_excerpt_count_max=args.excerpt_count_max,
            evidence_excerpt_length_max_chars=args.excerpt_length_max,
            summary_length_max_chars=args.summary_length_max,
        ),
        True,
    )


def collect_inputs(fixture_dir: Path, raw_root: Path) -> list[SourceInput]:
    """Read the fixture directory's inputs through ``emit.read_fixture_inputs``.

    A thin wrapper rather than a second implementation: which filenames count is a property of the
    source registry and belongs in one place, and ``replay_fixture`` reads the same directories from
    inside the package. All this adds is the ``--input`` prefix on the failure message, so that a
    reader of the command's error knows which flag to change.
    """
    try:
        return read_fixture_inputs(fixture_dir, raw_root=raw_root)
    except FixtureInputError as failure:
        raise InputError(f"--input: {failure}") from failure


def main(argv: Sequence[str] | None = None, *, clock: NanosecondCounter | None = None) -> int:
    """Parse arguments, run one replay, and return an exit code.

    ``clock`` is the injected nanosecond counter ``emit.py`` documents. It is a keyword argument
    rather than a flag because nothing under ``monitor/aggregator/`` may obtain one -- the caller
    supplies it, and ``python -m monitor.aggregator.cli`` supplies none, so a replay driven from the
    shell writes a ``latency.json`` that honestly records that no measurement was taken.
    """
    args = build_parser().parse_args(argv)
    raw_root = args.raw_root if args.raw_root is not None else repository_root()

    try:
        cap_limits, overridden = resolve_cap_limits(args)
        inputs = collect_inputs(args.input, raw_root)
        audit_severity = (
            EvidenceSeverity(args.audit_severity) if args.audit_severity is not None else None
        )
        result = emit(
            inputs,
            out_dir=args.out,
            config=EmitConfig(quoting_enabled=args.quoting, cap_limits=cap_limits),
            options=NormaliserOptions(audit_severity=audit_severity),
            clock=clock,
        )
    except (InputError, *_EXPECTED_FAILURES) as failure:
        print(f"{PROGRAM}: {type(failure).__name__}: {failure}", file=sys.stderr)
        return 1

    for source_input in inputs:
        print(f"{PROGRAM}: read {source_input.raw_path} ({len(source_input.data)} bytes)")
    print(f"{PROGRAM}: {len(result.events)} event(s) -> {result.events_path}")
    print(
        f"{PROGRAM}: latency -> {result.latency_path} "
        f"(measured={result.latency['measurement']['measured']})"
    )
    print(
        f"{PROGRAM}: quoting_enabled={args.quoting} "
        f"caps=count:{cap_limits.evidence_excerpt_count_max} "
        f"excerpt:{cap_limits.evidence_excerpt_length_max_chars} "
        f"summary:{cap_limits.summary_length_max_chars}"
    )
    if overridden:
        print(
            f"{PROGRAM}: those caps were supplied on the command line. They are fixture-corpus "
            "test parameters and are NOT evidence that evaluation-protocol.md section 4's caps "
            "row is closed (ADR-019)."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
