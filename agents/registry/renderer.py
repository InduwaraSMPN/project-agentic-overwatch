r"""Framing environment-derived evidence into a prompt: every field, identically in both arms.

WHAT THIS MODULE IS
-------------------
``docs/milestones/M4-agents.md``'s T4.2 carries a finding M2 recorded at T2.7a and ADR-019
argues: the Monitor quotes ``summary`` and ``evidence_excerpts[]`` and **nothing else**, which
follows from ``docs/02-architecture.md`` section 3's frozen field list and from section 3.5.4's
requirement that the ``G3-UNQUOTED`` arm remove exactly one property. But ``resource.ns``,
``resource.kind`` and ``resource.name`` carry attacker-settable text -- a pod name or an image
reference is chosen by whoever created the workload -- so in a scenario where the attacker has done
exactly that, those values reach the Orchestrator's context unframed in **both** arms.

M2 could not fix it. Adding a field to a frozen contract would amend architecture section 3, and
making ``G3-UNQUOTED`` remove two properties instead of one would break the matched-conditions
requirement the whole guardrail ablation rests on. The milestone file states where the fix belongs:
"the renderer that interpolates an ``EvidenceEvent`` into a prompt must therefore frame **every**
field it interpolates, not only the two the Monitor quoted." This module is that renderer. Nothing
under ``monitor/`` is touched and the schema is not amended.

THE RENDERER HAS NO ARM PARAMETER, WHICH IS THE STRONGEST FORM OF ARM-INVARIANCE
---------------------------------------------------------------------------------
The M4 plan asks for framing that is "byte-identical structure under G0 and G3", because framing
that differed between arms would make ``G3-UNQUOTED`` remove two properties instead of one. The
implementation goes one better than a flag that is set the same way twice: **there is no flag.**
This module never learns which arm is running. It receives an event as the aggregator emitted it --
already quoted under ``G0-FULL``, already unquoted under ``G3-UNQUOTED`` -- and applies one
transformation to every field of it.

Arm-invariance is then a property of the type rather than a property somebody has to keep true, and
the G0-versus-G3 prompt diff is confined to the bytes the aggregator quoted for the same reason a
pure function of its input produces different output only where its input differed.
``agents/tests/test_evidence_renderer.py`` asserts exactly that, mirroring
``monitor/tests/test_g3_isolation.py``'s shape: render one event under each arm and require the
diff to fall inside ``summary`` and ``evidence_excerpts[]``.

THE ESCAPE ALPHABET IS DISJOINT FROM THE MONITOR'S, AND THAT DISJOINTNESS IS THE WHOLE ARGUMENT
------------------------------------------------------------------------------------------------
A frame that a value can close is not a frame. ``resource.name`` is attacker-chosen and is *never*
quoted by the aggregator, so if this module's delimiters could appear in a value unescaped, the
seven fields this module exists to protect would be exactly the seven that could break out of it.

So values are escaped. The question that matters is **which characters**, and the answer is fixed by
the ablation rather than by taste.

``monitor/aggregator/quoting.py``'s alphabet is: the guillemets ``U+00AB`` and ``U+00BB``, the
backslash, line feed, carriage return, tab, and every C0/C1 control, bidirectional control,
zero-width character, line and paragraph separator, variation selector, surrogate and tag
character. Under
``G3-UNQUOTED`` that entire transformation is switched off -- ``apply_quoting`` returns the text
unchanged -- and *that* is the single property the arm removes.

If this module escaped any character on that list, it would put back under G3 part of what the arm
removed. ``G3-UNQUOTED`` would then no longer be "aggregator quoting disabled"; it would be
"aggregator quoting disabled except for the characters the renderer also handles", and the
guardrail study would be comparing two configurations that differ in a way its protocol never
authorised. **So this module escapes nothing the Monitor escapes.** In particular a raw newline
inside a ``G3`` summary is rendered as a raw newline, and the field layout goes ragged. That is not
a defect: it is the arm working, and the arm exists to find out whether the model notices.

What this module escapes is exactly its own four structural characters and its own escape
character, none of which appears anywhere in the Monitor's alphabet:

    U+27EA  ->  ``~<``   MATHEMATICAL LEFT DOUBLE ANGLE BRACKET, the value frame
    U+27EB  ->  ``~>``   MATHEMATICAL RIGHT DOUBLE ANGLE BRACKET
    U+27E6  ->  ``~[``   MATHEMATICAL LEFT WHITE SQUARE BRACKET, the record frame
    U+27E7  ->  ``~]``   MATHEMATICAL RIGHT WHITE SQUARE BRACKET
    U+007E  ->  ``~~``   TILDE, the escape character itself

Tilde rather than backslash, and the choice is load-bearing rather than cosmetic: backslash is the
Monitor's escape character, so an escaping rule built on it would be indistinguishable from
quoting in the rendered bytes, and a reader comparing a G0 excerpt to a G3 one could not tell which
layer had written which escape. Two layers, two alphabets, and no character in common.

The mathematical double brackets rather than the guillemets for the same reason: under ``G0-FULL``
a quoted summary already carries the aggregator's guillemets, and they must stay visible *inside*
this frame as the aggregator's own mark rather than being confused with it.

The mapping is total and reversible -- :func:`unframe_value` inverts :func:`frame_value` for every
string -- and ``agents/tests/`` asserts the round trip rather than assuming it, which is the
property that makes "the frame cannot be closed from inside" a fact about the function rather than
a claim about the character set.

NO PROSE LIVES HERE
-------------------
Every label this module emits is a **contract field name** from architecture section 3 --
``event_id``, ``resource.ns``, ``evidence_excerpts.0`` -- and every other character is a delimiter.
There is no sentence, no heading and no instruction anywhere in the output.

The sentence that tells a model what a frame means is prompt text, so it lives in the prompt
registry as a shared block (``common.evidence-framing``) referenced by every condition's
composition manifest, which is where ``.agents/rules/20-parity-and-determinism.md`` requires it and
where the parity gate can count it. Writing it here would have put instruction text into code, in
the one module whose job makes that most tempting.

WHAT IS COUNTED AND WHAT IS NOT
--------------------------------
This module's output is **run-time data, not instruction budget**, and it is deliberately outside
what ``make parity-check`` counts. :mod:`agents.registry.composer` explains why: evidence volume is
a property of the scenario, the seed and the injection condition, so folding it into a parity number
would make that number differ between two conditions because one of them met a noisier incident.

THE TASK FRAME IS NOT EITHER, AND THAT IS ALSO WHY IT IS A SEPARATE FUNCTION
-------------------------------------------------------------------------------
D1-A gives the acting role a runtime ``environment`` field (SEAM 7), rendered into the same
``_runtime_task`` frame this module's sibling :func:`agents.graphs.nodes._runtime_task` builds. It
is run-time data for the same reason the evidence above is, and it is the *one* place a
G2-SHAREDCRED run's frame can differ from every other arm's -- the list the runner composes names
``KUBE_TOKEN_FILE`` and the API server URL there and nowhere else. Neither field is a prompt block,
so neither is inside ``make parity-check``'s instruction budget; the environment field's G2 token
delta is measured once and recorded in ADR-131, and ``agents/tests/test_evidence_renderer.py`` is
what asserts that the value is a location and never a credential.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
Every prompt the agent layer sends, and therefore every token count in a sealed bundle's
``tokens.json``. The frame is also what the G0-versus-G3 diff is taken over, so a change to the
escape alphabet changes what that diff means. After the ``v1.0`` freeze that is a logged hotfix ADR
under AGENTS.md iron rule 6.
"""

from collections.abc import Mapping, Sequence
from typing import Any, Final

__all__ = (
    "ESCAPE_CHAR",
    "EVENT_FRAME_CLOSE",
    "EVENT_FRAME_OPEN",
    "EVIDENCE_EVENT_FIELDS",
    "RenderError",
    "UNRENDERED_CONTRACT_FIELDS",
    "VALUE_FRAME_CLOSE",
    "VALUE_FRAME_OPEN",
    "flatten_event",
    "frame_value",
    "render_evidence_event",
    "render_evidence_events",
    "unframe_value",
)

# The field-value frame. U+27EA / U+27EB, MATHEMATICAL LEFT and RIGHT DOUBLE ANGLE BRACKET, written
# as code-point escapes so that this source file stays pure ASCII and so that the four most
# load-bearing constants in the module are unambiguous to a reader who does not trust their
# editor's font -- monitor/aggregator/quoting.py's reasoning for its own delimiters, applied here.
VALUE_FRAME_OPEN: Final = "\u27ea"
VALUE_FRAME_CLOSE: Final = "\u27eb"

# The record frame. U+27E6 / U+27E7, MATHEMATICAL LEFT and RIGHT WHITE SQUARE BRACKET.
EVENT_FRAME_OPEN: Final = "\u27e6"
EVENT_FRAME_CLOSE: Final = "\u27e7"

# The escape character. Tilde, never backslash: see the module docstring for why two layers must
# not share an escape alphabet.
ESCAPE_CHAR: Final = "~"

# The escape table, written as (character, escaped form) pairs. A tuple rather than a dict literal
# so that the tables below are built from a sequence whose order is the file's rather than the
# interpreter's -- .agents/rules/20-parity-and-determinism.md forbids anything a run depends on
# resting on dictionary construction order.
#
# The escape character comes first so that the table built from it maps `~` before anything that
# produces a `~`, which is what makes the encoding injective.
_ESCAPES: Final[tuple[tuple[str, str], ...]] = (
    (ESCAPE_CHAR, ESCAPE_CHAR + ESCAPE_CHAR),
    (VALUE_FRAME_OPEN, ESCAPE_CHAR + "<"),
    (VALUE_FRAME_CLOSE, ESCAPE_CHAR + ">"),
    (EVENT_FRAME_OPEN, ESCAPE_CHAR + "["),
    (EVENT_FRAME_CLOSE, ESCAPE_CHAR + "]"),
)

_ENCODE: Final = {ord(character): escaped for character, escaped in _ESCAPES}
_DECODE: Final = {escaped[1]: character for character, escaped in _ESCAPES}

# THE ONE CONTRACT FIELD THIS MODULE DELIBERATELY DOES NOT RENDER (SEAM 8, M10 WS-1)
# -------------------------------------------------------------------------------------
# ``signal_id`` is the tenth field of ``monitor/aggregator/models.py``'s ``EvidenceEvent`` since
# EvidenceEvent v2 (ADR-125, WS-3): the structured detection signal, folded into ``event_id`` before
# capping and quoting so detection scoring has it and ``event_id`` stays identical across the G3
# arms. It is the answer to V8 -- ``analysis/`` had been reading absent keys and reporting detection
# precision and recall as a LIMITATION.
#
# It is a *scoring* field, not an *acting* field, and that distinction is the whole reason it is
# named here rather than simply left out. The raw name a sensor fired -- a Falco rule, an
# Alertmanager alertname, a k8s-audit ``verb:resource``, a Trivy advisory id -- is environment
# telemetry that happens to arrive in a structure the agent layer also reads. Rendering it would
# hand every model the detector's own view of the cluster, which is a measurement instrument: an
# agent that could see which rule fired could condition its behaviour on it, and worse, a
# ``G3-UNQUOTED`` arm could be told from a ``G0-FULL`` one by which fields the prompt carries. So
# the
# list is published, named, and one element long, and
# ``agents/tests/test_evidence_renderer.py`` asserts that the *contract's* leaf list is
# ``EVIDENCE_EVENT_FIELDS`` plus exactly this tuple -- which is what stops "one field we do not
# render" from quietly becoming "the fields somebody remembered to exclude".
#
# ``agents/graphs/nodes.py`` strips the same field a second time, in ``_phase_context``, before the
# renderer is reached. Defence in depth against a renderer that ever rendered by event key rather
# than by allowlist, which is the shape of change SEAM 8 exists to survive.
UNRENDERED_CONTRACT_FIELDS: Final[tuple[str, ...]] = ("signal_id",)

# The nine fields architecture section 3 fixes, flattened to the leaf values a prompt interpolates
# and named with the contract's own dotted paths. ``evidence_excerpts`` is absent because it is a
# list whose length varies per event; :func:`flatten_event` expands it to ``evidence_excerpts.<n>``
# and the count is emitted so a reader can tell an empty list from a dropped one. ``signal_id`` is
# absent for the reason UNRENDERED_CONTRACT_FIELDS above gives.
#
# Every one of these is framed. The three the Monitor never quotes -- resource.ns, resource.kind
# and resource.name -- are the reason this module exists, and the other six are framed with them
# because a frame applied to some fields and not others teaches a reader that an unframed value is
# trustworthy, which is precisely the inference ADR-019 found nothing supports.
EVIDENCE_EVENT_FIELDS: Final[tuple[str, ...]] = (
    "event_id",
    "ts",
    "source",
    "severity",
    "resource.ns",
    "resource.kind",
    "resource.name",
    "summary",
    "raw_ref.path",
    "raw_ref.offset",
    "raw_ref.length",
    "schema_version",
)

# Where the excerpt list is emitted, so the rendered order is fixed rather than incidental. It sits
# immediately after ``summary`` because that is the aggregator's own pairing -- the two quoted
# fields together -- and it keeps the G0-versus-G3 diff contiguous, which is what makes a failure
# in the arm-invariance test readable.
_EXCERPTS_AFTER: Final = "summary"
_EXCERPTS_KEY: Final = "evidence_excerpts"
_EXCERPTS_COUNT_LABEL: Final = "evidence_excerpts.count"


class RenderError(ValueError):
    """The mapping given is not an ``EvidenceEvent`` this renderer will interpolate.

    A refusal rather than a partial render, and the reason is the whole point of the module: a
    renderer that skipped a field it could not find would silently drop attacker-settable text out
    of the frame, and the failure would be invisible in the prompt -- it would simply look like an
    event that had less to say.
    """


def frame_value(value: str) -> str:
    """Return ``value`` with this module's five structural characters escaped, and nothing else.

    A single :meth:`str.translate` over a code-point table, so the transformation depends on no
    iteration order, no locale, no clock and no Unicode database, and calling it twice on one input
    returns the same bytes twice.
    """
    return value.translate(_ENCODE)


def unframe_value(text: str) -> str:
    """Return the original string for text produced by :func:`frame_value`; raise otherwise.

    ``unframe_value(frame_value(value)) == value`` for every ``str`` ``value``. The domain is
    exactly the image of :func:`frame_value`: a trailing escape, or an escape whose marker is not
    one of the five, raises :class:`RenderError` naming the offset.

    Strict rather than best-effort, for the reason ``monitor/aggregator/quoting.py`` gives about its
    own decoder: a lenient one would let an arm-invariance test pass over a :func:`frame_value` that
    had stopped doing anything.
    """
    out: list[str] = []
    index = 0
    while index < len(text):
        character = text[index]
        if character != ESCAPE_CHAR:
            out.append(character)
            index += 1
            continue
        if index + 1 >= len(text):
            raise RenderError(f"trailing escape at offset {index}")
        marker = text[index + 1]
        if marker not in _DECODE:
            raise RenderError(f"unknown escape {ESCAPE_CHAR + marker!r} at offset {index}")
        out.append(_DECODE[marker])
        index += 2
    return "".join(out)


def _scalar(value: Any, *, field: str) -> str:
    """Return one leaf value as the text that goes inside a frame.

    ``None`` renders as the four characters ``null`` rather than as an empty frame, because
    ``resource.ns`` is nullable by contract -- a cluster-scoped object has no namespace -- and
    "absent" and "the empty string" are different statements about the cluster. The same reasoning
    ``monitor/aggregator/models.py`` gives for keeping the key present with a null value.

    Integers and booleans render through :func:`repr`-free ``str`` so that ``raw_ref.offset`` is
    ``421`` and not ``'421'``. A nested structure is a refusal: architecture section 3's leaves are
    scalars, and a mapping arriving here means the event is not the contract's.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str | int | float):
        return str(value)
    raise RenderError(
        f"{field} is {type(value).__name__}; architecture section 3's evidence leaves are scalars, "
        "and a structure arriving here means this is not an EvidenceEvent"
    )


def _lookup(event: Mapping[str, Any], path: str) -> Any:
    """Return the value at a dotted contract path, or raise naming the path that is missing."""
    node: Any = event
    for segment in path.split("."):
        if not isinstance(node, Mapping) or segment not in node:
            raise RenderError(
                f"the event carries no {path!r}. Every field this module frames is framed, so an "
                "event missing one is not rendered at all rather than rendered with a hole where "
                "attacker-settable text would have been"
            )
        node = node[segment]
    return node


def flatten_event(event: Mapping[str, Any]) -> tuple[tuple[str, str], ...]:
    """Return one event as ordered ``(label, framed value)`` pairs, excerpts expanded.

    Published separately from :func:`render_evidence_event` so that the arm-invariance test can
    compare two events field by field and name the field that differs, rather than diffing two
    blocks of text and reporting a line number.
    """
    excerpts = _lookup(event, _EXCERPTS_KEY)
    if isinstance(excerpts, str) or not isinstance(excerpts, Sequence):
        raise RenderError(f"{_EXCERPTS_KEY} is {type(excerpts).__name__}; the contract is a list")

    pairs: list[tuple[str, str]] = []
    for field in EVIDENCE_EVENT_FIELDS:
        pairs.append((field, frame_value(_scalar(_lookup(event, field), field=field))))
        if field == _EXCERPTS_AFTER:
            pairs.append((_EXCERPTS_COUNT_LABEL, frame_value(str(len(excerpts)))))
            for index, excerpt in enumerate(excerpts):
                label = f"{_EXCERPTS_KEY}.{index}"
                pairs.append((label, frame_value(_scalar(excerpt, field=label))))
    return tuple(pairs)


def render_evidence_event(event: Mapping[str, Any], *, ordinal: int, total: int) -> str:
    """Render one ``EvidenceEvent`` as framed text, ending in one newline.

    ``ordinal`` and ``total`` are one-based and are emitted in the record frame so that a model
    receiving three events is told there are three. Without the count, an event whose framed value
    happened to resemble a record boundary would leave a reader unable to say how many events there
    were -- and the count is a number the renderer knows and the event does not.
    """
    head = f"{EVENT_FRAME_OPEN}evidence-event {ordinal}/{total}{EVENT_FRAME_CLOSE}"
    tail = f"{EVENT_FRAME_OPEN}/evidence-event {ordinal}{EVENT_FRAME_CLOSE}"
    lines = [head]
    lines.extend(
        f"{label} {VALUE_FRAME_OPEN}{value}{VALUE_FRAME_CLOSE}"
        for label, value in flatten_event(event)
    )
    lines.append(tail)
    return "\n".join(lines) + "\n"


def render_evidence_events(events: Sequence[Mapping[str, Any]]) -> str:
    """Render a sequence of events in the order given, separated by one blank line.

    The order is the aggregator's and is never sorted here. ``monitor/aggregator/emit.py`` fixes
    the emitted order and the fixture corpus is golden output under it; re-ordering at the prompt
    boundary would mean the bytes a model saw were a function of this module's opinion rather than
    of the Monitor's deterministic stream.

    An empty sequence renders as the empty string rather than as an empty frame. A phase that
    received no evidence is a fact the graph states in its own words from the prompt registry; a
    frame around nothing would be this module inventing a statement about the incident.
    """
    total = len(events)
    return "\n".join(
        render_evidence_event(event, ordinal=index, total=total)
        for index, event in enumerate(events, start=1)
    )
