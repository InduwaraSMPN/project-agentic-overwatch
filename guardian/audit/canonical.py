r"""The audit chain's byte contract: one stated canonicalisation rule, one implementation.

THIS MODULE IS THE AUTHORITY FOR THE RULE
------------------------------------------
``docs/02-architecture.md`` section 3 fixes ``hash = SHA256(prev_hash || canonical_json(record))``
without saying what ``canonical_json`` means. Left unspecified, the chain is reproducible only by
the exact interpreter that wrote it -- separators, key order, ``ensure_ascii``, float repr and
Unicode normalisation all move the bytes -- and ``make audit-verify`` runs at M7's daily QA and
again at M9's clean-checkout reproduction, so a drifting definition surfaces as a **false tamper
alarm months later, on correct data**. That is conflict M3-C8 in
``docs/plans/M3-implementation-plan.md``, and it is the same class of defect ADR-010 closed for
``versions_env_sha256``.

The rule, stated once and in full. A canonical serialisation of a JSON value is the output of
``json.dumps`` under exactly these settings, UTF-8 encoded, with no terminator:

1. ``sort_keys=True`` -- object keys are emitted in ascending order of their Unicode code point
   sequence. Key order is therefore a property of the contract, not of the order in which the
   Guardian happened to build a dictionary, and no code path anywhere may rely on ``dict``
   insertion order to produce a stable digest.
2. ``separators=(",", ":")`` -- no insignificant whitespace anywhere. The default separators emit a
   space after every ``,`` and ``:``, which changes every byte offset in the record and inflates
   every bundle for nothing.
3. ``ensure_ascii=True`` -- every non-ASCII code point is emitted as a ``\uXXXX`` escape, so every
   byte written is ASCII, which is a proper subset of UTF-8. The Guardian records
   attacker-controlled text: an Executor may put arbitrary UTF-8 into ``justification`` or into an
   action parameter. Escaping it means the digest is a function of the code point sequence alone
   and not of the locale, console encoding or filesystem encoding of whatever wrote, read or
   re-encoded the file downstream -- which on a project developed on Windows and run under WSL2 is
   not hypothetical.
4. ``allow_nan=False`` -- ``NaN``, ``Infinity`` and ``-Infinity`` are not JSON. Python emits them
   anyway by default, and no conforming parser reads them back, so a record carrying one would hash
   fine here and be unverifiable everywhere else. Non-finite floats raise instead.
5. No coercion between number types. A Python ``int`` is emitted as a JSON integer and never as
   ``1.0``; a Python ``float`` is emitted with its own repr and never rounded to an integer. The
   second half matters as much as the first: coercing an integral float to an integer would make
   two records with different content hash identically.
6. Finite floats are emitted with CPython's ``repr``, which is the shortest decimal string that
   round-trips to the same IEEE-754 double. This is the one clause a re-implementation in another
   language has to be careful about, so it is written down rather than left to be discovered. Every
   field of ``AuditRecord`` that section 3 names is a string or an integer; a float can only reach
   the digest through an agent-supplied action parameter.
7. No Unicode normalisation. The rule fixes how a given code point sequence is encoded and
   deliberately does not fix which sequence that is. An audit record is a transcript of what an
   untrusted agent actually sent, and normalising it would make the record a lossy paraphrase of
   the evidence -- the opposite of what ``docs/protocols/security-policy.md`` section 1.4 asks the
   log to be. Clause 3 makes the encoding of any sequence deterministic regardless.
8. Input is validated before serialisation. Mapping keys must be ``str``; values must be ``dict``,
   ``list``, ``tuple``, ``str``, ``int``, ``float``, ``bool`` or ``None``. This never changes the
   bytes for an input the plain rule would accept -- it converts three silent mangles into named
   errors. ``json.dumps`` coerces an ``int`` key to a string, so ``{1: "a", "1": "b"}`` serialises
   to an object with a duplicate key; it accepts a ``Mapping`` subclass nowhere and a ``set``
   nowhere, raising a ``TypeError`` that names neither the field nor the path; and a self-
   referencing structure recurses. For a security-critical digest, "rejected with the path" beats
   "silently different" every time.

THE HASH IS TAKEN OVER THE PARSED RECORD, NEVER OVER FILE BYTES
----------------------------------------------------------------
``.gitattributes`` sets ``* text=auto eol=lf``, so tracked text is normalised to LF **in the
index** and materialised in the working tree according to the checking-out host: on the Windows
development host with ``core.autocrlf=true`` a committed ``.jsonl`` fixture arrives with CRLF line
endings. A byte-level hash of the file would therefore give one answer in WSL2 and a different one
on Windows for the same commit, and every fixture in this package would be host-dependent -- the
identical defect ADR-010 was written to close for ``versions_env_sha256``, arriving a second time
in a place where it would read as tampering rather than as a line-ending fault.

So: a chain file is *parsed* into records, and the digest is computed over the parsed record. The
reader in ``verify`` strips a trailing carriage return from each line for exactly this reason, and
a fixture checked out with CRLF verifies identically to one checked out with LF. The writer still
opens the file in binary mode and terminates each line with a bare ``\n``, because producing LF is
free and there is no reason to write bytes that will need normalising later.

TWO IMPLEMENTATIONS OF ONE RULE, AND WHY THAT IS THE RIGHT ANSWER HERE
-----------------------------------------------------------------------
``monitor/aggregator/models.py`` already carries a canonical-JSON definition, written at M2 for
``monitor_events.jsonl``, and its settings are clauses 1-4 above. This module does not import it,
and the duplication is deliberate rather than overlooked.

``.agents/rules/00-source-of-truth.md`` forbids a second home for one rule, and the Guardian
forbids a security-critical digest that depends on another component's module: the Monitor and the
Guardian deploy as separate containers, the Guardian is the sole credential holder and the one
component whose failure mode is silent, and a chain whose reproducibility rested on an import from
the component with the widest input surface would be a coupling nobody would choose. Both
constraints are real and they point opposite ways.

The resolution is **one rule, stated once; two implementations; a test that proves they agree.**
The rule is stated here, in the eight clauses above, and this docstring is what the Monitor's
serialiser is also an implementation of. ``guardian/audit/crosscheck.py`` serialises a shared
fixture through both and asserts byte equality, skipping with a named reason when ``monitor`` is
not importable -- which is the normal case inside the Guardian's own container and an abnormal one
in this repository. Divergence is a failure, not a warning: two implementations of one rule that
disagree mean the rule has quietly become two rules, which is exactly what rule 00 exists to catch.

Note the one framing difference the cross-check has to account for.
``monitor.aggregator.models.canonical_json_bytes`` appends the JSON Lines terminator to its result,
because for the event stream the framed line *is* the deliverable. Here the two are separated:
:func:`canonical_json_bytes` returns the unframed canonical form and :func:`canonical_json_line`
adds the terminator. The digest is taken over the unframed form, so that the framing byte never
enters a hash and a future change to how records are framed on disk cannot change what a record
hashes to.

CHANGING ANY CLAUSE ABOVE
--------------------------
After the ``v1.0`` pilot gate freeze this is a logged hotfix ADR naming the affected runs
(``AGENTS.md`` iron rule 6), for the reason ADR-010 gives about ``versions_env_sha256``: the
digests are in every sealed bundle, so altering the rule silently changes the meaning of every
chain in the corpus at once, and a corpus whose integrity field changed meaning mid-study cannot be
pooled. Before the freeze it is still an ADR, and it is also a regeneration of
``guardian/audit/fixtures/canonical/vectors.json``, whose expected digests are committed literals
precisely so that the change has to be made deliberately and reviewed as a diff.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Final

__all__ = [
    "CANONICAL_JSON_RULE_ID",
    "LINE_TERMINATOR",
    "CanonicalisationError",
    "canonical_json_bytes",
    "canonical_json_line",
    "sha256_hex",
]

# An identifier for the rule above, carried in reports so that a verification transcript records
# which byte contract it was run under. It is not a schema_version: the record schema and the
# serialisation rule change for different reasons and are versioned separately.
CANONICAL_JSON_RULE_ID: Final = "audit-canonical-json/v1"

# The JSON Lines framing byte, named rather than spelled inline so that the one place it is added
# is greppable. It is deliberately NOT part of what gets hashed; see the module docstring.
LINE_TERMINATOR: Final = b"\n"

_MAX_DEPTH_SENTINEL: Final = "the structure is too deeply nested to serialise"


class CanonicalisationError(ValueError):
    """A value cannot be canonicalised, with the path to the offending node in the message.

    A subclass of ``ValueError`` because that is what ``json.dumps`` raises for the cases this
    check anticipates, so a caller that already handles ``ValueError`` keeps working; the added
    value is that the message names the field path instead of the type alone.
    """


def _render_path(path: tuple[object, ...]) -> str:
    """Render a node path as ``$.action.params.name`` or ``$.excerpts[2]``, for error messages."""
    rendered = "$"
    for step in path:
        if isinstance(step, int):
            rendered += f"[{step}]"
        else:
            rendered += f".{step}"
    return rendered


def _validate(node: object, path: tuple[object, ...], branch: frozenset[int]) -> None:
    """Reject anything clause 8 of the module docstring excludes, naming the path.

    ``branch`` carries the ``id()`` of every container on the path from the root to ``node``, which
    is what makes a self-referencing structure a named error rather than a ``RecursionError``. Only
    the current branch is tracked, not every container seen: the same sub-object appearing twice in
    a record is repetition and serialises fine, while the same sub-object appearing inside itself
    is a cycle and does not.
    """
    if node is None or isinstance(node, (str, bool, int)):
        # bool before int is unnecessary here -- both are accepted -- but the ordering is stated so
        # that a later edit does not accidentally treat True as an integer and coerce it.
        return
    if isinstance(node, float):
        if not math.isfinite(node):
            raise CanonicalisationError(
                f"{_render_path(path)} is {node!r}; NaN and Infinity are not JSON "
                "(canonicalisation clause 4)"
            )
        return
    if isinstance(node, dict):
        if id(node) in branch:
            raise CanonicalisationError(
                f"{_render_path(path)} contains itself; cycles cannot be serialised"
            )
        inner = branch | {id(node)}
        for key, value in node.items():
            if not isinstance(key, str):
                raise CanonicalisationError(
                    f"{_render_path(path)} has a non-string key {key!r} of type "
                    f"{type(key).__name__}; JSON object keys are strings and coercing this one "
                    "could collide with an existing key (canonicalisation clause 8)"
                )
            _validate(value, (*path, key), inner)
        return
    if isinstance(node, (list, tuple)):
        if id(node) in branch:
            raise CanonicalisationError(
                f"{_render_path(path)} contains itself; cycles cannot be serialised"
            )
        inner = branch | {id(node)}
        for index, value in enumerate(node):
            _validate(value, (*path, index), inner)
        return
    raise CanonicalisationError(
        f"{_render_path(path)} is of type {type(node).__name__}, which has no JSON form. "
        "Convert it at the boundary that produced it, so that the conversion is visible in the "
        "record rather than performed by the serialiser (canonicalisation clause 8)"
    )


def canonical_json_bytes(payload: object) -> bytes:
    """Serialise ``payload`` to its canonical form: sorted, minimal, ASCII, **unterminated**.

    This is the exact byte sequence the chain hashes. It carries no line terminator, so that the
    JSON Lines framing of ``guardian_audit.jsonl`` is a property of the file rather than of the
    digest. Use :func:`canonical_json_line` to write a record; use this to hash one.

    Returns ``bytes`` rather than ``str`` on purpose: the contract is a byte sequence, and
    returning text would leave the encoding -- clause 3's whole subject -- to the caller.
    """
    try:
        _validate(payload, (), frozenset())
    except RecursionError as exc:  # pragma: no cover - depends on the interpreter's stack limit
        raise CanonicalisationError(_MAX_DEPTH_SENTINEL) from exc
    text = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return text.encode("utf-8")


def canonical_json_line(payload: object) -> bytes:
    """Serialise ``payload`` as one line of a ``.jsonl`` file: the canonical form plus one ``\\n``.

    The caller must write the result to a file opened in **binary** mode. Python's text mode
    translates ``\\n`` to ``\\r\\n`` on Windows, and a chain written that way differs from one
    written under WSL2 in every single line while looking identical in every editor. The verifier
    tolerates the difference deliberately (see the module docstring), but writing bytes that need
    tolerating is a habit worth not forming.
    """
    return canonical_json_bytes(payload) + LINE_TERMINATOR


def sha256_hex(data: bytes) -> str:
    """Return the lowercase hexadecimal SHA-256 of ``data``.

    A named function rather than an inline ``hashlib`` call so that the digest algorithm the chain
    rule names appears in exactly one place: ``docs/02-architecture.md`` section 3 says SHA-256,
    and changing it should be one edit that a reviewer can find by grepping for this name.
    """
    return hashlib.sha256(data).hexdigest()
