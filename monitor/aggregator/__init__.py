"""Package marker for the evidence aggregator: the Monitor's deterministic, non-LLM core.

WHAT THIS PACKAGE IS
--------------------
``docs/02-architecture.md`` section 1 types the Monitor ``deterministic, non-LLM`` and section 2
gives it one job in the data flow: telemetry from four sources arrives, and curated
``EvidenceEvent``s leave for the Orchestrator. This package is the code that performs that
transformation. Everything the Orchestrator ever learns about the environment passes through here,
which is why the boundary this package sits on is enforced rather than merely documented.

TWO PROPERTIES BIND EVERY MODULE PLACED HERE, AND NEITHER IS NEGOTIABLE
----------------------------------------------------------------------
``.agents/rules/40-monitor-non-llm.md`` is the home of the first: nothing under ``monitor/`` may
import a provider SDK, call an inference endpoint, read a provider credential or a model pin, or
reach a model by any other route -- dynamic import, subprocess and bare HTTP request included. The
rule is enforced by three separate checks rather than one, because a guard that cannot see a
violation is not evidence that none exists: ``scripts/monitor_guard.sh`` block (a) scans every
tracked file under ``monitor/``, the socket-denial replay in ``monitor/tests/test_no_inference.py``
proves at run time that a full replay completes with no connection possible, and the same file
asserts the Monitor's pinned runtime dependency set contains no such SDK. There is no exemption
mechanism, for the reason rule 40 states: a genuine false positive is an ADR at the milestone that
produces it, not a hole punched before anyone has seen one.

``.agents/rules/20-parity-and-determinism.md`` is the home of the second: replaying a fixture twice
must produce byte-identical output. The milestone's Definition of Done is a ``cmp``, not a
judgement, so every source of variation is a design decision taken deliberately and written down --
timestamps read from the source record rather than from a clock, identifiers derived by digest
rather than generated, emission in an explicit total order rather than in dictionary order, and
canonical JSON on the way out. ``scripts/monitor_guard.sh`` block (b) is a tripwire for the first
three over exactly this directory; the byte diff is the proof.

WHAT LIVES HERE, AND WHAT DELIBERATELY DOES NOT
-----------------------------------------------
:mod:`monitor.aggregator.models` holds the frozen ``EvidenceEvent`` v1 contract and the canonical
serialiser whose output bytes the twice-and-diff compares. The remaining modules -- the per-source
normalisers, the cap enforcement, the protocol-mirroring limits, the quoting layer with its inverse,
the emitter and the command-line entry point -- land with the aggregator core and are named in
``docs/plans/M2-implementation-plan.md``.

What does not live here is any *number*. The ``EvidenceEvent`` count and length caps and the Monitor
latency budget are owned by ``docs/protocols/evaluation-protocol.md`` section 4 and mirrored, under
the pattern ADR-016 settled, in ``monitor/aggregator/limits.py`` with a test that fails on drift.
The aggregator carries no default for any of them and fails closed with a named error when one is
unset, so that a fixture corpus can never go green against a bound nobody measured.

The marker itself is what makes these modules importable as ``monitor.aggregator.<module>`` from the
repository root, which is what lets ``python -m pytest monitor/tests`` and
``python -m monitor.aggregator.models`` resolve without a ``PYTHONPATH`` edit, a ``conftest.py``
path hack or an editable install. ``pyproject.toml`` already names ``monitor`` in ruff's ``src``
list, so the tooling side of that was settled at M0; this file is the interpreter side of it.
"""
