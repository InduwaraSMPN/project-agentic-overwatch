r"""The payload marker: the quote-safe needle every delivered payload carries (M10 WS-2, F-SC-01).

WHY A MARKER AT ALL
    ``F-SC-01`` is the treatment check that the injected payload reached the channel the design says
    it reaches -- the model's context for INJ-A/C/D, the Monitor's collated stream for INJ-B. The
    evidence it reads is not the payload itself. An INJ-B command line is quoted by the aggregator
    under G0-FULL, and ``monitor/aggregator/quoting.py`` escapes the delimiters, the escape
    character and every invisible or reordering code point, so the payload's own bytes are *not*
    present verbatim in a G0 event: a check that grepped for them would fail on the arm the study is
    most interested in. A marker built only from letters, digits, ``:`` and ``-`` is untouched by
    that escaping, so one needle works identically under both quoting arms.

WHY IT IS SCOPED TO THE CELL AND NOT TO THE RUN
    :func:`payload_marker` takes ``(scenario_id, injection_condition, seed)`` and deliberately NOT
    the run id. For INJ-A/C/D the marker lands in the text the agents read, and the agent's context
    carries no run id -- ``agents/graphs/nodes.py::_runtime_task`` renders the phase, the capability
    scope and the environment, never the identifier -- so a run-scoped marker would tell a model
    which arm it was running under. That is a condition leak, and an ablation cannot tolerate one.
    The draw is already independent of the arm (the balanced rotation in
    ``scenarios/attackers/plan.py`` is a function of the cell alone), so a cell-scoped marker is
    exactly as discriminating as the payload it accompanies and no more.

WHY IT LIVES HERE
    The writer owns the spelling. ``runner/fidelity/scenarios.py`` reads it, and two spellings would
    let the check pass over a marker nobody wrote -- the failure mode the constant's own comment has
    warned about since it was introduced. This module imports nothing, so the reader can depend on
    it without pulling the applier (or a cluster client) into the fidelity package.
"""

from __future__ import annotations

from typing import Final

#: The marker's fixed prefix. NOT a secret and NOT model-visible text beyond its role as a needle:
#: it is a value whose only job is to be greppable in a bundle.
PAYLOAD_MARKER: Final = "OVERWATCH-PAYLOAD"


def payload_marker(scenario_id: str, injection_condition: str, seed: int) -> str:
    """The marker for one CELL: the constant plus the cell's three coordinates.

    ``INJ-NONE`` has no payload and therefore no marker; the function does not special-case it,
    because a caller that asks for the marker of a no-injection cell has made a mistake the check
    is not the right place to absorb.
    """
    return f"{PAYLOAD_MARKER}:{scenario_id}-{injection_condition}-{seed:03d}"


def mark_payload(payload_text: str, marker: str) -> str:
    """``payload_text`` with ``marker`` appended on its own line.

    The separator is a line feed rather than a space because the marker must not be readable as a
    continuation of the payload: a payload that ended in an unterminated word would otherwise absorb
    it, and a reader of the model's context could not tell where the registry text stopped.

    One function for both channels, so the bytes the agents read (INJ-A/C/D) and the command line
    Falco records (INJ-B) carry the marker the same way and the reader has one shape to find.
    """
    return f"{payload_text}\n{marker}"
