r"""Reversible quoting of untrusted environment text, and the single branch the G3 arm removes.

WHY THIS MODULE EXISTS
----------------------
An ``EvidenceEvent``'s ``summary`` and its ``evidence_excerpts`` carry text captured from the
environment: Falco rule output, Kubernetes audit entries, Trivy findings, Alertmanager
annotations. None of that text is written by this repository, and a large part of it is written,
directly or indirectly, by whoever is inside the cluster. A container name, an image tag, a
process argument, a label value and an annotation are all fields an attacker can set, and every
one of them is copied verbatim into the strings this module receives. From
``docs/02-architecture.md`` section 2 onwards those strings travel to the Orchestrator, which is a
language model, and land inside its context window. An attacker who controls a container name
therefore controls a run of characters that appears in a prompt.

Quoting is the defence, and its job is mechanical rather than semantic. It does not decide whether
a string is malicious -- nothing deterministic can -- and it removes nothing. It makes an excerpt
unambiguously *data* by giving it a frame that the framed text cannot break out of. Two properties
do that work, and ``monitor/tests/test_quoting.py`` checks both:

* The excerpt is wrapped in a delimited region, so a reader -- human or model -- can see where
  environment text begins and where it ends.
* No character inside that region can end the region early. The closing delimiter, the escape
  character itself, and every character that is invisible, that moves a cursor, or that reorders
  how the text around it is displayed, are each replaced by a visible escape sequence. Text that
  arrives carrying a closing delimiter followed by an instruction comes out as one continuous run
  which visibly is not the end of anything.

WHY THE PROPERTY IS AN ABLATION ARM AND NOT MERELY A FEATURE
------------------------------------------------------------
``docs/02-architecture.md`` section 4 defines ``G3-UNQUOTED`` as "aggregator quoting disabled":
the guardrail arm that removes exactly the property above so that the study can measure what it
buys. Dissertation section 3.5.4 requires each configuration to remove *exactly one* property, so
the shape of this module is part of the experiment rather than a matter of implementation taste.
Everything the arm is allowed to change lives inside :func:`apply_quoting`; everything else -- how
many excerpts are selected, how long they may be, in what order events are emitted, and what every
other field holds -- is identical in both arms, and ``monitor/tests/test_g3_isolation.py`` is the
proof rather than the claim.

THE ESCAPING ALPHABET
---------------------
The quoted form is the opening delimiter, then the escaped body, then the closing delimiter. The
delimiters are U+00AB and U+00BB, the double angle quotation marks, one code point each. Inside
the body:

    \\          U+005C  the escape character itself, substituted first and always
    \<<  \>>    U+00AB, U+00BB  the delimiters, so neither can occur unescaped in a body
    \n          U+000A  line feed
    \r          U+000D  carriage return
    \t          U+0009  character tabulation
    \xHH        any other escaped code point below U+0100
    \uHHHH      any other escaped code point below U+10000
    \UHHHHHHHH  any other escaped code point at or above U+10000

(The two delimiter escapes are written above with ASCII stand-ins because this source file is kept
to ASCII; the real escapes are one backslash followed by the one-character delimiter.)

Hex digits are lower case and the field widths are fixed at two, four and eight, so every escape
is self-delimiting: ``\x00a`` is NUL followed by a literal ``a`` and can be read no other way.
Every other character -- letters, digits, punctuation, ordinary spaces, accented Latin, CJK,
emoji -- passes through untouched, because an excerpt an examiner cannot read is an excerpt an
examiner will not read.

The set that must be escaped is given as explicit code-point ranges in
:data:`_ALWAYS_ESCAPED_RANGES` rather than by asking :mod:`unicodedata` for a general category.
Two reasons, in order of weight. Determinism: a category lookup queries the Unicode database that
ships with the interpreter, so the same input could in principle produce different output under a
different interpreter build, and ``.agents/rules/20-parity-and-determinism.md`` requires a replay
to be byte-identical. Auditability: a reviewer can read the range table and see exactly what is
escaped, without holding the Unicode general categories in their head or trusting that ``Cf``
covers what they assume it covers.

One sentence states the principle behind the table: a code point is escaped when it carries no
glyph of its own -- when it is a control code, an invisible formatting character, a line or
paragraph separator, an unpaired surrogate, or a selector that acts on a neighbouring character
rather than being rendered itself. Escaping the surrogate block additionally means the quoted form
always encodes to UTF-8, whatever the source text contained.

WHY THIS ALPHABET AND NOT ONE OF THE FOUR OBVIOUS ALTERNATIVES
---------------------------------------------------------------
:func:`repr` is the closest thing the standard library offers, and it is wrong on three counts. It
escapes by Unicode category, so its output moves with the interpreter's Unicode database, which is
the determinism objection above. It is documented as a debugging aid rather than as a contract, so
a future release may legally change it and would then change every quoted excerpt in the fixture
corpus at once. And it has no inverse this repository may call: recovering the original means
``ast.literal_eval`` over attacker-controlled text, which is the opposite of what this module is
for. Condition 3 of the isolation test needs an inverse, and :func:`repr` does not have a usable
one.

Base64, or any other opaque encoding, is exactly invertible and completely delimiter-proof, and it
fails the requirement that matters most after correctness. An examiner reads these excerpts, out
of a run bundle, months later, while deciding whether a phase was scored correctly. An opaque
blob tells them nothing, so the first thing anyone would do is decode it -- by hand, or with a
helper script whose output nobody diffs -- and the artefact would then be judged on a rendering
that is not the one the model saw. Encoding also removes the evidence from every ordinary tool:
``grep``, ``git diff`` and any JSONL viewer stop working on the field that matters most.

JSON string escaping -- running ``json.dumps`` over the string -- is nearly right, and is rejected
on scope rather than on principle. It escapes the double quotation mark, the backslash and the C0
controls, and nothing else, so every bidirectional override, every zero-width character and every
tag character passes through literally: the whole invisible half of the attack surface survives.
Its encoding of a non-BMP character is a surrogate pair, which is precisely the construct escaped
here so that the quoted form always encodes to UTF-8. And its delimiter is the double quotation
mark, the most common character in the Kubernetes audit entries this module quotes, so the body
would be a wall of escaped quotes.

XML, and a CDATA section in particular, is the cautionary case rather than a candidate. A CDATA
section cannot escape its own terminator: the sequence that closes it ends the section wherever it
appears, and the only workaround is to split the section in two -- which is the framing being
broken by the framed text, exactly the property this module exists to guarantee cannot happen. An
entity-escaped XML encoding avoids that, but drags a markup grammar and a parser into a component
whose entire output is JSON, for no gain over the alphabet above.

WHY THE TRANSFORMATION MUST BE EXACTLY INVERTIBLE
-------------------------------------------------
``unquote(quote(text)) == text`` holds for every ``str``, and that is a requirement rather than a
convenience. Condition 3 of the G3 isolation test asserts it field by field across a quoting-on
run and a quoting-off run, and it is the assertion that establishes what the arm changes: if the
quoted field decodes exactly to the unquoted field, escaping is the *only* difference between the
two arms, and G3 removes one property rather than two.

That requirement is what forbids the tempting shortcut. Stripping a bidirectional override,
collapsing a run of control characters, or truncating at the first NUL would each neutralise the
character just as well, and none of them can be undone -- so condition 3 would fail, and the arm
would in fact be changing evidence *content* as well as evidence *encoding*. Everything dangerous
is therefore escaped and nothing is ever removed.

:func:`unquote` is deliberately strict, and its domain is exactly the image of :func:`quote`. It
raises :class:`ValueError` on a body holding an unescaped delimiter, an unescaped character that
:func:`quote` would have escaped, an unknown escape, a truncated escape, an upper-case hex digit,
or a non-canonical escape such as ``\x41`` for a character :func:`quote` writes literally. A
lenient decoder that passed unrecognised input through would make :func:`unquote` a partial
identity, and condition 3 would then pass even if :func:`quote` had quietly stopped doing anything
at all -- a green test proving nothing. Strictness also buys the property in the other direction:
``quote(unquote(quoted)) == quoted`` for every accepted input, so the quoted form is canonical and
one source text has exactly one quoted spelling. Given text that was never quoted, :func:`unquote`
raises. It is not a best-effort unescaper and must never be used as one.

Quoting is a framing rather than a normalisation, so it is deliberately **not** idempotent:
``quote(quote(text))`` is a well-formed double frame, and two calls to :func:`unquote` recover the
original. If :func:`quote` absorbed an existing frame it would erase the difference between "the
environment sent us something that looks quoted" and "we quoted it", which is the one distinction
this module exists to preserve.

WHY apply_quoting IS THE ONLY PLACE THE FLAG IS READ
-----------------------------------------------------
:func:`apply_quoting` is the single place in this repository that branches on the G3 flag, and its
body is one conditional expression. ``emit.py`` calls ``apply_quoting(text,
enabled=config.quoting_enabled)`` unconditionally for every text field it emits, so the flag is
plumbed through as a value and never as a code path. This is the same discipline
``.agents/rules/10-guardian-first.md`` imposes on ``G1-LOGONLY`` and ``G2-SHAREDCRED``, which are
"activated ONLY via the runner's condition flags" and never by editing Guardian code inline, and
``.agents/rules/40-monitor-non-llm.md`` restates it for this flag in particular.

The constraint is load-bearing, not tidiness. An ablation arm implemented as a scattered set of
``if`` statements is an arm that starts changing two properties the first time somebody adds a
reasonable-looking second conditional -- skipping a normalisation step "since we are not quoting
anyway", or shortening a field "because the unquoted form is shorter". Nobody would notice, the
runs would still complete, and the guardrail study would be comparing two arms that differ in ways
its own protocol never authorised. Condition 4 of ``monitor/tests/test_g3_isolation.py`` is the
machine check: it parses every module under ``monitor/`` and fails unless exactly one of them
conditions on the flag, in exactly this function.

CAPS ARE APPLIED BEFORE QUOTING, NEVER AFTER
--------------------------------------------
The aggregator's order is: normalise, select excerpts, apply the count and length caps to the raw
source text, then quote. This module is the last transformation and knows nothing about the caps.
Their values are owned by ``docs/protocols/evaluation-protocol.md`` section 4 and mirrored, under
the pattern ADR-016 settled, in ``monitor/aggregator/limits.py``. No number from that block appears
in this file, and none may ever be added to it.

The ordering is load-bearing rather than incidental. Escaping lengthens text, so a length cap
applied after quoting would truncate the two arms differently: the unquoted arm would carry more
source content than the quoted arm, and the flag would then change how much evidence reaches the
Orchestrator as well as how that evidence is escaped. That is two properties, and section 3.5.4
permits one. Section 4 states the unit -- source characters, counted before quoting -- so that
"length cap" cannot be read two ways after the ``v1.0`` freeze, and the visible consequence, a
quoted excerpt whose serialised length exceeds the cap, is intended. Condition 2 of the isolation
test is what fails loudly if anyone reorders the pipeline.

WHAT THIS MODULE DELIBERATELY DOES NOT DEFEND AGAINST
------------------------------------------------------
Confusables and homoglyphs. A Cyrillic small letter a renders identically to a Latin one, and this
module passes both through unchanged. Escaping every character that resembles another would make
ordinary non-English text unreadable and would still not be complete, and the property at issue --
that two distinct strings look alike -- belongs to the layer that decides what a name *means*, not
to the layer that decides where an excerpt ends. Escaping fixes framing; it does not fix identity.

Semantic injection inside a correctly framed region. An excerpt reading "ignore your instructions"
is still an excerpt reading "ignore your instructions" after quoting; what quoting guarantees is
that the Orchestrator sees it *as* quoted environment text, with a visible frame around it, rather
than as text that appeared to be part of its own instructions. Whether the model then honours the
frame is the property ``G0-FULL`` versus ``G3-UNQUOTED`` is designed to measure, which is the whole
reason this module has an off switch.

Volume. Bounding how much environment text reaches the Orchestrator is the caps' job, applied
before this module runs, for the ordering reason given above.

STANDARD LIBRARY ONLY, AND WHAT BREAKS IF THIS FILE CHANGES
------------------------------------------------------------
This module imports nothing at all -- not the third-party stack, not the rest of the aggregator,
not even the standard library. It is a pure text transformation over ``str``, and keeping it
importable in isolation is what lets ``monitor/tests/test_quoting.py`` exercise it without the
Pydantic models, the source registry, the caps or the protocol mirror existing. It also keeps this
file trivially reviewable: everything the escaper does is visible in one screen of tables and one
loop.

Any change to the escaping alphabet changes the bytes of every quoted field, so every golden
``expected/monitor_events.jsonl`` under ``monitor/fixtures/`` has to be regenerated in the same
commit or ``make monitor-replay`` fails. After the pilot gate freeze at ``v1.0``, that is a logged
hotfix ADR under iron rule 6 rather than an edit.
"""

__all__ = ("QUOTE_CLOSE", "QUOTE_OPEN", "apply_quoting", "quote", "unquote")

# The delimiters, written as code-point escapes rather than as literal characters so that this
# source file stays pure ASCII and so that the two most load-bearing constants in the module are
# unambiguous to a reader who does not trust their editor's font. U+00AB and U+00BB are the left-
# and right-pointing double angle quotation marks. They were chosen over an ASCII pair because a
# quoted excerpt should be recognisable as a frame at a glance and because neither character
# occurs in the ASCII-dominated output of Falco, the Kubernetes audit log or Trivy -- so the frame
# is visually quiet in the common case and loud in the adversarial one, where the escapes appear.
# They are single code points, which is what keeps the escape rule a one-character substitution
# and the invertibility argument short enough to check by eye.
QUOTE_OPEN = "\u00ab"
QUOTE_CLOSE = "\u00bb"

# The escape character. Backslash, because every reader of a log already decodes it without being
# told, and because C, Python and every shell agree on what it introduces.
ESCAPE_CHAR = "\\"

# Code points escaped wherever they occur. Ranges are inclusive at both ends and are the whole
# specification of what "dangerous" means here -- there is no second list and no category lookup.
#
# The classes, and what each one does to an excerpt if it survives unescaped:
#   * C0 controls, DEL and the C1 controls carry NUL, tab, line feed, carriage return and the two
#     forms of the ANSI escape introducer (U+001B, and the eight-bit CSI at U+009B). An escape
#     sequence in an excerpt repaints a reviewer's terminal: it can clear the screen, move the
#     cursor over text already printed, or set the foreground colour to the background colour.
#   * The bidirectional controls (U+061C, U+200E..U+200F, U+202A..U+202E, U+2066..U+2069) reorder
#     how following text is *displayed* without changing a byte of it, so a reviewer can read an
#     excerpt as saying one thing while the model receives another. This is the class the task
#     specification calls out by name, and it is escaped for exactly that reason.
#   * The zero-width and invisible formatting characters (U+00AD, U+180E, U+200B..U+200D, U+2060
#     onwards, U+FEFF, U+FFF9..U+FFFB, the musical format characters and the tag block at
#     U+E0000) render as nothing, so they hide text inside text. The tag block is the sharpest of
#     them: it mirrors ASCII, so an entire sentence can be written in characters no reader sees.
#   * U+2028 and U+2029 are line and paragraph separators. They break a line for many renderers
#     and for ``str.splitlines`` while not being line feeds, so an excerpt containing one can
#     appear to end before it does.
#   * The variation selectors (U+FE00..U+FE0F, U+E0100..U+E01EF) carry no glyph of their own and
#     have been used the same way as the tag block. Escaping them costs the fidelity of an emoji
#     variant in an infrastructure log, which is a price worth paying.
#   * The surrogate range is escaped so that :func:`quote` always returns a string that encodes to
#     UTF-8. A lone surrogate can reach this module from a decoder that used ``surrogateescape``,
#     and it would otherwise fail at serialisation time, deep inside the emitter, rather than here.
_ALWAYS_ESCAPED_RANGES: tuple[tuple[int, int], ...] = (
    (0x0000, 0x001F),  # C0 controls: NUL, TAB, LF, CR and the ANSI escape introducer among them
    (0x007F, 0x009F),  # DELETE and the C1 controls, including NEL and the eight-bit CSI
    (0x00AD, 0x00AD),  # SOFT HYPHEN
    (0x061C, 0x061C),  # ARABIC LETTER MARK
    (0x180E, 0x180E),  # MONGOLIAN VOWEL SEPARATOR
    (0x200B, 0x200F),  # zero-width space, non-joiner, joiner, and the LRM/RLM bidi marks
    (0x2028, 0x2029),  # LINE SEPARATOR and PARAGRAPH SEPARATOR
    (0x202A, 0x202E),  # the bidi embedding and override controls
    (0x2060, 0x206F),  # word joiner, invisible operators, the bidi isolates, deprecated formats
    (0xD800, 0xDFFF),  # surrogates
    (0xFE00, 0xFE0F),  # variation selectors
    (0xFEFF, 0xFEFF),  # zero-width no-break space, also seen as a byte-order mark
    (0xFFF9, 0xFFFB),  # interlinear annotation anchors
    (0x1D173, 0x1D17A),  # musical symbol format characters
    (0xE0000, 0xE007F),  # tag characters
    (0xE0100, 0xE01EF),  # variation selectors supplement
)

# The short, readable escapes, as (character, escaped form) pairs. Order matters only in that the
# table below is built from this sequence, so it is a tuple rather than a dict: a dict literal
# would make the construction order an implementation detail of the interpreter, and rule 20
# forbids anything in this component depending on that.
#
# NUL is deliberately absent and is written by the hex path as ``\x00`` rather than as ``\0``. In
# C, ``\0`` followed by a digit is an octal escape, so ``\07`` would be one character in one
# reader's head and two in another's; a fixed-width hex escape cannot be misread.
_NAMED_ESCAPES: tuple[tuple[str, str], ...] = (
    (ESCAPE_CHAR, ESCAPE_CHAR + ESCAPE_CHAR),
    (QUOTE_OPEN, ESCAPE_CHAR + QUOTE_OPEN),
    (QUOTE_CLOSE, ESCAPE_CHAR + QUOTE_CLOSE),
    ("\n", ESCAPE_CHAR + "n"),
    ("\r", ESCAPE_CHAR + "r"),
    ("\t", ESCAPE_CHAR + "t"),
)

# The marker character that follows the backslash, mapped to the character it stands for. Derived
# from _NAMED_ESCAPES rather than written out again, so the encoder and the decoder cannot drift.
_SIMPLE_DECODE: dict[str, str] = {escaped[1]: character for character, escaped in _NAMED_ESCAPES}

# Fixed hex field widths. Fixed, so that an escape is self-delimiting even when the character that
# follows it is itself a hex digit.
_HEX_ESCAPE_WIDTHS: dict[str, int] = {"x": 2, "u": 4, "U": 8}

# Lower case only: the canonical form has exactly one spelling, and ``\x1B`` is rejected rather
# than quietly accepted as a synonym for ``\x1b``.
_HEX_DIGITS = frozenset("0123456789abcdef")

_MAX_CODE_POINT = 0x10FFFF


def _hex_escape(code_point: int) -> str:
    """Return the fixed-width hex escape for ``code_point``, in the narrowest form that fits."""
    if code_point <= 0xFF:
        return f"{ESCAPE_CHAR}x{code_point:02x}"
    if code_point <= 0xFFFF:
        return f"{ESCAPE_CHAR}u{code_point:04x}"
    return f"{ESCAPE_CHAR}U{code_point:08x}"


def _build_escape_table() -> dict[int, str]:
    """Build the single code-point-to-escape mapping that both directions are defined by.

    The named escapes are applied last so that they win over the range fill: line feed, carriage
    return and tab all fall inside the C0 range and must come out as the readable two-character
    forms rather than as ``\\x0a``, ``\\x0d`` and ``\\x09``.

    One table serves the encoder and the decoder's canonical-form check, which is what makes
    "``unquote`` accepts exactly what ``quote`` produces" a structural property rather than two
    tables somebody has to keep in step.
    """
    table: dict[int, str] = {}
    for first, last in _ALWAYS_ESCAPED_RANGES:
        for code_point in range(first, last + 1):
            table[code_point] = _hex_escape(code_point)
    for character, escaped in _NAMED_ESCAPES:
        table[ord(character)] = escaped
    return table


_ESCAPE_TABLE = _build_escape_table()


def _escaped_form(character: str) -> str:
    """Return how :func:`quote` writes ``character``: its escape, or the character itself."""
    return _ESCAPE_TABLE.get(ord(character), character)


def _name(character: str) -> str:
    """Return ``U+XXXX``-style notation for one character, for use in error messages."""
    return f"U+{ord(character):04X}"


def quote(text: str) -> str:
    """Return ``text`` wrapped in the quoted region, with every dangerous character escaped.

    The result always begins with :data:`QUOTE_OPEN` and ends with :data:`QUOTE_CLOSE`, and the
    body between them contains neither delimiter unescaped, no character that carries no glyph of
    its own, and no unpaired surrogate -- so the result always encodes to UTF-8, and no input can
    close the region early. See the module docstring for the alphabet and for what is deliberately
    left alone.

    The transformation is a single :meth:`str.translate` over :data:`_ESCAPE_TABLE`, which is a
    lookup keyed by code point. It therefore depends on no iteration order, no locale, no clock
    and no Unicode database, and calling it twice on one input returns the same bytes twice, which
    is what ``.agents/rules/20-parity-and-determinism.md`` requires of everything under
    ``monitor/aggregator/``.
    """
    return QUOTE_OPEN + text.translate(_ESCAPE_TABLE) + QUOTE_CLOSE


def unquote(text: str) -> str:
    """Return the original text for a string produced by :func:`quote`; raise otherwise.

    ``unquote(quote(value)) == value`` for every ``str`` ``value``, and
    ``quote(unquote(quoted)) == quoted`` for every ``quoted`` this function accepts. The domain is
    exactly the image of :func:`quote`: anything else raises :class:`ValueError` naming what was
    wrong and where. That strictness is deliberate and is argued in the module docstring -- a
    lenient decoder would let condition 3 of the isolation test pass over a :func:`quote` that had
    stopped doing anything.

    In particular, this is not a best-effort unescaper. Text that was never quoted raises, because
    it does not carry the delimiters; text that carries the delimiters but a non-canonical body
    raises too.
    """
    # The delimiters differ from each other, so no single character can satisfy both tests and no
    # separate length check is needed before slicing the body out below.
    if not text.startswith(QUOTE_OPEN) or not text.endswith(QUOTE_CLOSE):
        raise ValueError(
            "unquote: input is not a quoted region; it must start with "
            f"{_name(QUOTE_OPEN)} and end with {_name(QUOTE_CLOSE)}"
        )

    body = text[1:-1]
    decoded: list[str] = []
    index = 0
    length = len(body)

    while index < length:
        current = body[index]

        if current != ESCAPE_CHAR:
            if _escaped_form(current) != current:
                raise ValueError(
                    f"unquote: unescaped {_name(current)} at body offset {index}; "
                    f"quote() writes it as {_escaped_form(current)!r}"
                )
            decoded.append(current)
            index += 1
            continue

        if index + 1 >= length:
            raise ValueError(
                f"unquote: truncated escape at body offset {index}; "
                "the escape character is the last character of the body"
            )

        marker = body[index + 1]
        if marker in _SIMPLE_DECODE:
            character = _SIMPLE_DECODE[marker]
            consumed = 2
        elif marker in _HEX_ESCAPE_WIDTHS:
            width = _HEX_ESCAPE_WIDTHS[marker]
            digits = body[index + 2 : index + 2 + width]
            if len(digits) != width:
                raise ValueError(
                    f"unquote: truncated escape at body offset {index}; "
                    f"{ESCAPE_CHAR + marker!r} takes {width} hex digits, found {len(digits)}"
                )
            if not _HEX_DIGITS.issuperset(digits):
                raise ValueError(
                    f"unquote: non-canonical escape at body offset {index}; "
                    f"{digits!r} is not {width} lower-case hex digits"
                )
            code_point = int(digits, 16)
            if code_point > _MAX_CODE_POINT:
                raise ValueError(
                    f"unquote: escape at body offset {index} names {code_point:#x}, "
                    f"which is above the largest code point {_MAX_CODE_POINT:#x}"
                )
            character = chr(code_point)
            consumed = 2 + width
        else:
            raise ValueError(
                f"unquote: unknown escape {ESCAPE_CHAR + marker!r} at body offset {index}"
            )

        # The canonical-form check, and the reason there is no second escape table anywhere in
        # this module: re-encode what was just decoded and require it to be the exact text that
        # was consumed. It rejects an escape quote() would never write -- a hex escape for a
        # character that passes through literally, or a long form where a short one exists -- so
        # one source text has exactly one quoted spelling.
        consumed_text = body[index : index + consumed]
        if _escaped_form(character) != consumed_text:
            raise ValueError(
                f"unquote: non-canonical escape {consumed_text!r} at body offset {index}; "
                f"quote() writes {_escaped_form(character)!r} for {_name(character)}"
            )

        decoded.append(character)
        index += consumed

    return "".join(decoded)


def apply_quoting(text: str, *, enabled: bool) -> str:
    """Return ``quote(text)`` when quoting is enabled and ``text`` unchanged when it is not.

    This is the whole of the ``G3-UNQUOTED`` ablation, and this one conditional expression is the
    only place in the repository that reads the flag. Callers -- ``emit.py`` above all -- invoke
    it unconditionally for every text field they emit and pass the flag through as a value:

        excerpt = apply_quoting(source_text, enabled=config.quoting_enabled)

    Never ``if config.quoting_enabled: ... else: ...`` at the call site. An arm implemented as
    scattered conditionals is an arm that quietly grows a second difference, and the guardrail
    study would then be comparing configurations that differ in a way its protocol never
    authorised. Condition 4 of ``monitor/tests/test_g3_isolation.py`` parses every module under
    ``monitor/`` and fails unless this function is the only one that branches on the flag.

    The flag is keyword-only so that ``apply_quoting(text, False)`` is a :class:`TypeError` rather
    than a silent disabling of the defence by a caller who mis-ordered two arguments.
    """
    return quote(text) if enabled else text
