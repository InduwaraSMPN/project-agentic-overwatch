r"""Append-only construction of the Guardian's hash chain, and the scrub that keeps records clean.

THE CHAIN RULE, WITH THE CONCATENATION DEFINED
------------------------------------------------
``docs/02-architecture.md`` section 3 states it as::

    hash = SHA256(prev_hash || canonical_json(record_without_hash))

and leaves ``||`` undefined, which is enough ambiguity to build a chain that verifies under one
implementation and not another. This module fixes it:

* ``prev_hash`` enters the digest as its **64 ASCII characters of lowercase hexadecimal**, not as
  the 32 bytes they decode to. That is the same text the field carries in the file, so the rule can
  be checked by hand -- ``printf '%s' "<prev_hash><canonical json>" | sha256sum`` -- and a
  re-implementation needs no unhexlify step it could get wrong. It also keeps
  :data:`GENESIS_PREV_HASH` in the same domain as every other value the operand takes.
* **No separator.** Concatenation without a delimiter is only unambiguous when the split point is
  recoverable, and here it is: the first operand is validated to be exactly
  :data:`CHAIN_HASH_LENGTH` characters from ``[0-9a-f]``, so the digest input decomposes uniquely
  into ``prefix[:64]`` and ``prefix[64:]``. The validation is what makes the absence of a separator
  safe, so it is not optional and :func:`record_hash` refuses a malformed ``prev_hash`` rather than
  hashing it.
* ``canonical_json`` is ``guardian.audit.canonical.canonical_json_bytes``, **unterminated**. The
  line's trailing ``\n`` is file framing and never enters a digest.
* ``record_without_hash`` is the complete record minus the ``hash`` key -- so ``seq`` and
  ``prev_hash`` are both inside the serialised object as well. ``prev_hash`` therefore appears
  twice in the digest input, once as the ASCII prefix and once as a field. That redundancy costs 64
  bytes and is kept because it is what section 3's sentence literally says; dropping the prefix
  would still be *a* chain but would not be *this* chain, and section 3 outranks this file.

THE GENESIS ``prev_hash`` IS SIXTY-FOUR ZEROS
-----------------------------------------------
The first record of a chain has no predecessor and still needs a well-defined first operand.
:data:`GENESIS_PREV_HASH` is ``"0" * 64``. Three reasons, in order of weight:

1. It is in the domain the rule validates, so the fixed-width argument above holds uniformly and
   the digest step needs no special case -- only the *link* check distinguishes ``seq == 0``.
2. It is visibly synthetic. No SHA-256 preimage of it is known, so it cannot be mistaken for a real
   predecessor by a reader or by a tool, which matters because the alternative below fails exactly
   there.
3. It matches the convention a reader already has: an all-zero previous digest is how a genesis
   block is spelled in the systems this chain most resembles.

Alternatives rejected: the empty string or ``null``, both of which make ``prev_hash`` two different
types and destroy the fixed-width injectivity that licenses the missing separator; and the SHA-256
of the empty input, which is a real-looking digest -- a chain whose head had been cut and restarted
from it would read as natural rather than as synthetic.

``seq`` IS ZERO-BASED, AND FINDINGS CARRY THE LINE NUMBER TOO
--------------------------------------------------------------
Nothing above this file fixes the origin. Zero is chosen so that ``seq`` is exactly the number of
records that precede a record: in an intact chain the record at file position *i* declares
``seq == i``, so any deviation is directly the count of records inserted or deleted before it, and
the arithmetic a verifier does to locate a break has no offset in it. The cost is that ``seq`` and
a one-based file line number differ by one, which is a real nuisance when a human is reading a
break report next to the file, so ``guardian.audit.verify`` reports **both** on every finding
rather than making the reader convert.

RECORDS ARE BORN CLEAN, WHICH IS WHY THE PRE-SEAL SANITIZER HAS NOTHING TO DO (M3-C5)
---------------------------------------------------------------------------------------
``docs/protocols/data-management.md`` section 5 sanitizes a bundle *before* seal: strip
``Authorization`` headers, ``api_key``-shaped strings, ``.env`` values and signing keys; keep token
claims but redact signatures. Applied to ``guardian_audit.jsonl`` after the fact, every one of
those edits changes a hashed field and breaks every link after it -- so ``make audit-verify`` at
M7's daily QA would fail on **correct** behaviour, which is conflict M3-C5.

The only resolution under which section 5 and the chain both hold is that the redaction happens
*before* the hash, so there is nothing left to redact afterwards. Three mechanisms, in the order
:meth:`AuditChainWriter.append` applies them:

1. **Structural refusal.** A record carrying a field whose *name* is a credential name -- see
   :data:`FORBIDDEN_RECORD_KEYS` -- is refused outright, at any depth. The record never contains a
   signature, a raw token or an ``Authorization`` header because it has no field that could;
   section 3's field list gives it ``token_jti`` and ``iss``, which is what
   ``docs/protocols/security-policy.md`` section 1.4 and NFR6 actually require for attribution.
   This is a raise and not a redaction on purpose: a token reaching the record builder is a
   Guardian defect, and silently cleaning it would hide the defect for as long as nobody looked.
   The refusal fires at T3.8 test time, not at campaign time, because ``guardian/app`` builds the
   body from section 3's fixed field list rather than from anything an agent supplies.
2. **Bound and scrub ``justification``.** LLM-authored free text is the one field a hostile agent
   fills freely, and under injection classes INJ-A..D it will deliberately fill it with key-shaped
   strings. Section 5's planted-secret test is a *scan*: it cannot tell an invented key-shaped
   string from a real one, so an unscrubbed justification would block a seal on a record that
   leaks nothing. Scrubbing at append time makes the scan find nothing.
3. **Residual scrub of every other string leaf.** Anything else in the body that still matches a
   secret shape is redacted in place rather than refused, because refusing would leave a decision
   unaudited and ``security-policy.md`` section 1.4 requires that every decision -- permit and deny
   -- produces a record. Each redaction is visible in the record as a marker, so the record says
   that something was removed instead of quietly not saying it. Identifier fields are exempted from
   the *entropy* rules only, for the reason :data:`IDENTIFIER_FIELDS` gives.

The test that proves all this is not that the scrubber works. It is that on this file the
sanitizer **has no work to do**: :func:`scan_chain_file` over a produced ``guardian_audit.jsonl``
returns nothing, including when a secret-shaped string was planted in a justification.

THE JUSTIFICATION BOUND HAS NO VALUE IN THIS FILE, DELIBERATELY
-----------------------------------------------------------------
``.agents/rules/00-source-of-truth.md`` puts every quantitative parameter in the protocol file that
owns it, and **no protocol currently owns a justification length bound**: ``evaluation-protocol.md``
section 4 owns the Monitor's evidence caps, and ``security-policy.md`` section 1.5 states the
property ("logged, never evaluated as policy") without a number. Inventing one here would create an
unowned constant in the one component whose numbers most need a home.

So this module fails closed, exactly as ``monitor/aggregator/limits.py`` does for section 4's caps
under the pattern ADR-016 settled: ``max_justification_chars`` is a required constructor argument
with no default, and a missing or non-positive value is a named error rather than a fallback. The
Guardian's start-time configuration supplies it; the fixture corpus supplies its own and records it
as a fixture parameter, which is the same separation ``monitor/fixtures/`` draws with its
``corpus_cap_*`` keys. The consequence is that the missing protocol row stays **visible** instead
of being papered over by a plausible default.
"""

from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol, runtime_checkable

from guardian.audit.canonical import canonical_json_bytes, canonical_json_line, sha256_hex

__all__ = [
    "AUDIT_SIGNATURE_SCHEME",
    "CHAIN_ASSIGNED_FIELDS",
    "CHAIN_HASH_LENGTH",
    "FORBIDDEN_RECORD_KEYS",
    "GENESIS_PREV_HASH",
    "IDENTIFIER_FIELDS",
    "JUSTIFICATION_FIELD",
    "SIGNATURE_FIELD",
    "TRUNCATION_MARKER",
    "AuditChainError",
    "AuditChainWriter",
    "AuditRecordRefused",
    "ChainStateError",
    "LinkCheck",
    "ParsedRecord",
    "SecretShape",
    "SupportsModelDump",
    "is_chain_hash",
    "read_chain",
    "record_hash",
    "scan_chain_file",
    "scan_record",
    "scrub_text",
    "walk_chain",
]

# --- the chain's own fields -------------------------------------------------------------------

CHAIN_HASH_LENGTH: Final = 64
GENESIS_PREV_HASH: Final = "0" * CHAIN_HASH_LENGTH

SEQ_FIELD: Final = "seq"
PREV_HASH_FIELD: Final = "prev_hash"
HASH_FIELD: Final = "hash"
JUSTIFICATION_FIELD: Final = "justification"

# ADR-130: the Ed25519 signature over a record's chain hash, present only on a chain a Guardian
# wrote
# with a signing key. The name is NOT "signature" -- that is a FORBIDDEN_RECORD_KEY, and it would
# also
# be redacted as a credential shape -- and it is deliberately a field the caller never supplies and
# the
# body-hash never covers: it is computed from the hash, so it cannot be inside what was hashed,
# exactly
# as `hash` cannot be. See AuditChainWriter.append and ParsedRecord.body.
SIGNATURE_FIELD: Final = "record_signature"

# The versioned identifier of the signing scheme, carried the way CANONICAL_JSON_RULE_ID carries the
# serialisation rule's: the record schema (guardian/app/models.py's AUDIT_RECORD_SCHEMA_VERSION) and
# the
# signature scheme change for different reasons and are versioned separately. A re-implementation in
# another language reads this to know it must verify Ed25519 over the 64 ASCII hex characters of
# `hash`.
AUDIT_SIGNATURE_SCHEME: Final = "audit-ed25519/v1"

# The three fields the writer assigns to place a record in the chain. A caller supplies the body and
# nothing else; these are properties of the record's position rather than of what happened, and
# letting
# a caller set them would let a caller forge one. `parse_chain_line` requires all three to be
# present;
# SIGNATURE_FIELD is deliberately NOT here, because an unsigned v1 chain carries none and must still
# parse and verify -- signing is additive.
CHAIN_ASSIGNED_FIELDS: Final = (SEQ_FIELD, PREV_HASH_FIELD, HASH_FIELD)

# Every field the writer assigns after the caller's body: the three chain fields plus, when signed,
# the
# signature. A caller may supply none of them, the body-hash covers none of them, and `scan_record`
# skips all of them -- the signature is 128 hex characters and would otherwise trip the entropy
# scan.
WRITER_ASSIGNED_FIELDS: Final = (*CHAIN_ASSIGNED_FIELDS, SIGNATURE_FIELD)

# Fields whose values are high-entropy by construction and are not secrets. security-policy.md
# section 1.4 requires the jti *in* the audit record -- it is a public single-use identifier, and
# redacting it would destroy the attribution the record exists to carry. Run and request
# identifiers are the same shape and the same argument. The exemption is narrow: it removes only
# the entropy rules from these fields, so a PEM block or an Authorization header appearing in one
# is still redacted, because no legitimate identifier contains either.
IDENTIFIER_FIELDS: Final = frozenset({"token_jti", "request_id", "run_id", "policy_rule_id"})

# Key names that may not appear anywhere in a record, at any depth. Matched on the whole key after
# lowercasing and removing '-' and '_', so `token_jti` (-> "tokenjti") is not caught by "token" and
# `prev_hash` is not caught by anything. Bare "key" is deliberately absent: a ConfigMap or Secret
# action parameter legitimately names a key, and refusing that would be a false positive in the one
# place the Guardian most needs to record what was attempted.
FORBIDDEN_RECORD_KEYS: Final = frozenset(
    {
        "accesstoken",
        "apikey",
        "authorization",
        "bearer",
        "clientsecret",
        "credential",
        "credentials",
        "idtoken",
        "jwt",
        "kubeconfig",
        "passwd",
        "password",
        "privatekey",
        "pwd",
        "refreshtoken",
        "secret",
        "secretkey",
        "signature",
        "signingkey",
        "token",
    }
)

# Appended when a bounded field is cut. The stored value therefore exceeds the bound by the length
# of this marker, which is deliberate: a silent truncation is indistinguishable in the record from
# a short justification, and the difference matters when the field is evidence about an injection.
TRUNCATION_MARKER: Final = "[TRUNCATED]"


class AuditChainError(Exception):
    """Base class for every error this module raises, so a caller can catch one name."""


class AuditRecordRefused(AuditChainError):
    """A body was not fit to become an audit record, and was refused rather than cleaned.

    Raised for a forbidden key name and for a caller-supplied chain field. Both are defects in the
    code that built the body, not in the data, and the caller's obligation is to fix the builder --
    never to strip the field and retry, which would make the check ornamental.
    """


class ChainStateError(AuditChainError):
    """The chain on disk is not in a state that can be appended to.

    Refusing to extend a broken chain is the point: an appended record whose predecessor already
    fails verification produces a file in which the new records look sound and the break sits
    behind them, which is the shape most likely to be mistaken for a partial recovery.
    """


def is_chain_hash(value: object) -> bool:
    """True when ``value`` is exactly 64 lowercase hexadecimal characters.

    Lowercase only, and that is a contract rather than fussiness: ``hashlib`` emits lowercase, the
    concatenation in :func:`record_hash` hashes the characters themselves, and accepting uppercase
    would mean two spellings of one predecessor produce two different digests.
    """
    return (
        isinstance(value, str)
        and len(value) == CHAIN_HASH_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def record_hash(prev_hash: str, body: dict[str, Any]) -> str:
    """Return the chain hash of ``body`` following ``prev_hash``.

    ``body`` is the record without its ``hash`` field; passing one that still carries ``hash`` is
    an error rather than a silent removal, because "which object did you hash" is the single
    question a disagreement between two implementations always reduces to.
    """
    if not is_chain_hash(prev_hash):
        raise AuditChainError(
            f"prev_hash must be {CHAIN_HASH_LENGTH} lowercase hex characters, got {prev_hash!r}. "
            "The fixed width is what makes the unseparated concatenation unambiguous, so this is "
            "refused rather than hashed."
        )
    if HASH_FIELD in body:
        raise AuditChainError(
            "record_hash() takes the record WITHOUT its hash field; the object passed still "
            f"carries {HASH_FIELD!r}"
        )
    return sha256_hex(prev_hash.encode("ascii") + canonical_json_bytes(body))


# --- secret shapes: one battery, used both to scrub and to scan --------------------------------
#
# The markers carry no ':' and no run of 32 hexadecimal characters or 40 base64 characters, which
# is what makes scrubbing idempotent and, more importantly, makes the scrubber's OUTPUT contain no
# shape the scanner reports. That property is load-bearing rather than tidy: data-management.md
# section 5's planted-secret test is a scan over the sealed file, and a marker that still looked
# like a secret would fail the seal on a record that is already clean.
#
# Each rule replaces its WHOLE match, so the surrounding key name goes with the value. Keeping the
# name would read better and would break idempotency -- `token: [REDACTED-...]` matches the
# credential rule again -- and the kind inside the marker already tells the reader what shape was
# removed. justification is free text that security-policy.md section 1.5 says is never evaluated
# as policy, so nothing downstream loses a parseable field to this.


@dataclass(frozen=True)
class _SecretRule:
    kind: str
    pattern: re.Pattern[str]
    entropy: bool  # entropy rules do not apply to IDENTIFIER_FIELDS


def _marker(kind: str) -> str:
    return f"[REDACTED-{kind.upper()}]"


_RULES: Final[tuple[_SecretRule, ...]] = (
    # Whole PEM blocks first, terminated or not, so that a private key is never left half-redacted
    # by a later rule biting a chunk out of its base64 body.
    _SecretRule(
        "pem-private-key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)?"
        ),
        entropy=False,
    ),
    # Before the JWT rule, so the header name goes with its value instead of being left behind
    # pointing at a marker.
    _SecretRule(
        "authorization-header",
        re.compile(r"(?i)\bauthorization\b\s*[:=]\s*\S.*"),
        entropy=False,
    ),
    _SecretRule(
        "bearer-credential",
        re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
        entropy=False,
    ),
    # Anchored on the "eyJ" that every JWS header begins with (base64url of '{"'), which makes this
    # rule essentially free of false positives on dotted identifiers. A three-segment blob that is
    # not a JWT is caught by the entropy rules below if it is long enough to matter.
    _SecretRule(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]*)?"),
        entropy=False,
    ),
    # Vendor-prefixed credentials, which are short enough to slip under the entropy thresholds and
    # are exactly what a planted-secret test plants.
    _SecretRule(
        "vendor-credential",
        re.compile(
            r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
            r"|\bsk-[A-Za-z0-9_-]{16,}"
            r"|\bxox[abposr]-[A-Za-z0-9-]{10,}"
            r"|\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}"
            r"|\bgithub_pat_[A-Za-z0-9_]{20,}"
            r"|\bAIza[A-Za-z0-9_-]{20,}"
        ),
        entropy=False,
    ),
    # name=value and name: value where the name reads as a credential. The name may carry a prefix
    # or suffix, so OPENAI_API_KEY and apiKeyId both match; \b would not, because '_' is a word
    # character and would put no boundary before API in OPENAI_API_KEY.
    _SecretRule(
        "credential-assignment",
        re.compile(
            r"(?i)[A-Za-z0-9_.-]*"
            r"(?:api[_-]?key|apikey|access[_-]?key|secret|token|password|passwd|pwd|credential|"
            r"private[_-]?key|signing[_-]?key|session[_-]?key)"
            r"[A-Za-z0-9_.-]*\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;)\]}]+)"
        ),
        entropy=False,
    ),
    # The two generic shapes. Thresholds are stated here rather than tuned: 32 hex characters is a
    # 128-bit value written out, and 40 base64 characters is 240 bits -- below either, a run is
    # more likely to be a resource name than a key. They will occasionally redact something
    # harmless, such as an image digest quoted in a justification, and that trade is taken
    # deliberately: the field is free text that nothing downstream parses, so a false redaction
    # costs a reader some context while a missed secret costs the seal.
    _SecretRule("high-entropy-hex", re.compile(r"\b[0-9a-fA-F]{32,}\b"), entropy=True),
    _SecretRule(
        "high-entropy-base64",
        re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}|\b[A-Za-z0-9_-]{40,}"),
        entropy=True,
    ),
)


@dataclass(frozen=True)
class SecretShape:
    """One secret-shaped span found in a string, with where it was and what it looked like."""

    kind: str
    field_path: str
    start: int
    end: int


def _rules_for(field_path: str) -> tuple[_SecretRule, ...]:
    """Return the rule set that applies to ``field_path``; identifiers skip the entropy rules."""
    root = field_path.split(".", 1)[0]
    if root in IDENTIFIER_FIELDS:
        return tuple(rule for rule in _RULES if not rule.entropy)
    return _RULES


def scrub_text(text: str, *, field_path: str = JUSTIFICATION_FIELD) -> str:
    """Redact every secret shape in ``text``, deterministically and idempotently.

    Deterministic because the chain hashes the result: a replacement that carried a counter, a
    length or a digest of what it removed would make two identical inputs hash differently.
    Idempotent because :func:`scan_record` runs over the output and must find nothing.

    ``field_path`` selects the rule set only; it never appears in the output.
    """
    scrubbed = text
    for rule in _rules_for(field_path):
        scrubbed = rule.pattern.sub(_marker(rule.kind), scrubbed)
    return scrubbed


def bound_text(text: str, max_chars: int) -> str:
    """Cut ``text`` to ``max_chars`` code points, marking the cut when one happens.

    Always called **after** :func:`scrub_text`, and the order is load-bearing: truncating first
    could split a secret so that no rule matches either half, leaving a fragment of a real key in a
    hashed field. Scrubbing first means every match is found against the whole text.
    """
    if max_chars < 1:
        raise AuditChainError(f"max_chars must be at least 1, got {max_chars}")
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + TRUNCATION_MARKER


def scan_record(record: dict[str, Any]) -> list[SecretShape]:
    """Return every secret shape surviving in ``record``, as the pre-seal sanitizer would see it.

    The chain fields are skipped, and skipping them is required rather than convenient: ``hash``
    and ``prev_hash`` are 64 hexadecimal characters by construction, so an entropy rule would
    report every record in every chain, and a sanitizer that acted on the report would break the
    chain -- which is conflict M3-C5 arriving from the scanner's side instead of the redactor's.
    """
    found: list[SecretShape] = []

    def walk(node: object, path: str) -> None:
        if isinstance(node, str):
            for rule in _rules_for(path):
                for match in rule.pattern.finditer(node):
                    found.append(SecretShape(rule.kind, path, match.start(), match.end()))
        elif isinstance(node, dict):
            for key, value in node.items():
                if not path and key in WRITER_ASSIGNED_FIELDS:
                    continue
                walk(value, f"{path}.{key}" if path else str(key))
        elif isinstance(node, (list, tuple)):
            for index, value in enumerate(node):
                walk(value, f"{path}[{index}]")

    walk(record, "")
    return found


def scan_chain_file(path: Path) -> list[tuple[int, SecretShape]]:
    """Run :func:`scan_record` over every record of a chain file, returning ``(line, shape)``.

    This is the pre-seal sanitizer's question asked of a finished file, and a clean answer is the
    evidence M3-C5's resolution rests on: not that the sanitizer works, but that on this file it
    has nothing to change.
    """
    findings: list[tuple[int, SecretShape]] = []
    for parsed in read_chain(path):
        if parsed.defect is not None:
            continue
        findings.extend((parsed.line, shape) for shape in scan_record(parsed.record))
    return findings


# --- the writer -------------------------------------------------------------------------------


@runtime_checkable
class Ed25519Signer(Protocol):
    """The one method the writer needs from a signing key, so it imports no crypto library
    (ADR-130).
        ``cryptography``'s
        :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey`
        satisfies this structurally: ``sign(bytes) -> bytes``. Accepting the protocol rather than
        the
        class
        keeps ``guardian/audit/chain.py`` standard-library at import time (ADR-022) exactly as the
        executor
        imports the Kubernetes client lazily -- the key is *handed in*, built by the
        operator-managed
        process that holds it, and this module never fabricates or reads one. Whoever holds no
        signing
        key
        passes ``None`` and writes an unsigned v1 chain, which is what every pre-M10 caller does.
    """

    def sign(self, data: bytes) -> bytes: ...


@runtime_checkable
class SupportsModelDump(Protocol):
    """The narrow protocol this module accepts instead of importing ``guardian.app.models``.

    ``AuditRecord`` is a Pydantic model owned by ``guardian/app/models.py``. Importing it here
    would put the audit chain downstream of the mediation API's module graph and would make this
    package -- the one piece that must stay standard-library and stable -- depend on Pydantic. So
    the writer accepts either a plain mapping or anything with a ``model_dump`` that returns a
    JSON-ready mapping, which every Pydantic v2 model satisfies structurally and nothing has to be
    changed to provide.
    """

    def model_dump(self, *, mode: str) -> dict[str, Any]: ...


def _as_body(body: SupportsModelDump | dict[str, Any]) -> dict[str, Any]:
    """Coerce the accepted input shapes to a plain ``dict``, with ``mode="json"`` for models."""
    if isinstance(body, dict):
        return dict(body)
    dump = getattr(body, "model_dump", None)
    if callable(dump):
        dumped = dump(mode="json")
        if not isinstance(dumped, dict):
            raise AuditRecordRefused(
                f"model_dump(mode='json') returned {type(dumped).__name__}, not a mapping"
            )
        return dict(dumped)
    raise AuditRecordRefused(
        f"an audit body must be a mapping or expose model_dump(mode='json'); got "
        f"{type(body).__name__}"
    )


def _normalise_key(key: str) -> str:
    return key.lower().replace("-", "").replace("_", "")


def _refuse_forbidden(node: object, path: str) -> None:
    """Raise if any key anywhere under ``node`` names a credential. See FORBIDDEN_RECORD_KEYS."""
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}" if path else str(key)
            if isinstance(key, str) and _normalise_key(key) in FORBIDDEN_RECORD_KEYS:
                raise AuditRecordRefused(
                    f"audit body carries {here!r}, whose name is a credential name. An AuditRecord "
                    "holds token_jti and iss, never the token itself (architecture section 3; "
                    "security-policy.md section 1.4). Fix the builder rather than the record."
                )
            _refuse_forbidden(value, here)
    elif isinstance(node, (list, tuple)):
        for index, value in enumerate(node):
            _refuse_forbidden(value, f"{path}[{index}]")


def _clean_body(body: dict[str, Any], max_justification_chars: int) -> dict[str, Any]:
    """Scrub and bound a body in place-free fashion, returning the cleaned copy."""

    def walk(node: object, path: str) -> object:
        if isinstance(node, str):
            scrubbed = scrub_text(node, field_path=path)
            # MATCH THE LAST PATH SEGMENT, NOT THE WHOLE PATH.
            # This read `path == JUSTIFICATION_FIELD`, and the bound therefore never fired: the
            # field lives at `action.justification`, because guardian/app/models.py nests it inside
            # AuditedAction rather than at the record's top level. The comparison was written
            # against where the field is *named* and not against where it is *dumped*, which is the
            # ordinary way a path-matching bug survives review -- both halves read correctly on
            # their own. Scrubbing was unaffected (it takes the path only to label a finding), so
            # the visible behaviour was a bound silently not applied while the redaction beside it
            # worked, which is the failure mode least likely to be noticed.
            #
            # Matching the last segment keeps the check working wherever the contract nests the
            # field next, which is the property that failed here.
            if path.rsplit(".", 1)[-1] == JUSTIFICATION_FIELD:
                scrubbed = bound_text(scrubbed, max_justification_chars)
            return scrubbed
        if isinstance(node, dict):
            return {
                key: walk(value, f"{path}.{key}" if path else str(key))
                for key, value in node.items()
            }
        if isinstance(node, (list, tuple)):
            return [walk(value, f"{path}[{index}]") for index, value in enumerate(node)]
        return node

    cleaned = walk(body, "")
    if not isinstance(cleaned, dict):  # pragma: no cover - walk preserves the top-level type
        raise AuditRecordRefused("an audit body must be a mapping")
    return cleaned


class AuditChainWriter:
    """Appends records to one ``guardian_audit.jsonl``, assigning ``seq``, ``prev_hash``, ``hash``.

    One writer owns one file. Appends are serialised by a lock, because FastAPI serves concurrent
    requests and two appends racing on ``head`` would produce two records claiming the same
    predecessor -- a break that looks exactly like an insertion. The lock does not protect against
    two *processes*, and nothing here tries to: ``docs/plans/M3-implementation-plan.md``'s threat
    model lists the audit file handle among the positions the attacker does not hold precisely
    because the Guardian is the sole writer.

    Each append opens the file, writes one line, flushes and fsyncs. Per-record durability matters
    for a log whose whole value is that it is complete, and the cost is irrelevant at the volumes
    a run produces.
    """

    def __init__(
        self,
        path: Path,
        *,
        max_justification_chars: int,
        head: str = GENESIS_PREV_HASH,
        next_seq: int = 0,
        signing_key: Ed25519Signer | None = None,
    ) -> None:
        if not isinstance(max_justification_chars, int) or isinstance(
            max_justification_chars, bool
        ):
            raise AuditChainError(
                "max_justification_chars must be an int supplied by the caller. This module "
                "carries no default: no protocol owns the bound yet, and inventing one here would "
                "create an unowned number in the component whose numbers most need a home."
            )
        if max_justification_chars < 1:
            raise AuditChainError(
                f"max_justification_chars must be at least 1, got {max_justification_chars}"
            )
        if not is_chain_hash(head):
            raise AuditChainError(f"head must be a chain hash, got {head!r}")
        if next_seq < 0:
            raise AuditChainError(f"next_seq must not be negative, got {next_seq}")
        self.path = Path(path)
        self.max_justification_chars = max_justification_chars
        self._head = head
        self._next_seq = next_seq
        # ADR-130. None means an unsigned v1 chain, which is every pre-M10 caller; a key means each
        # appended record carries an Ed25519 signature over its hash. Optional so signing is
        # additive
        # and the operator's key custody is not this module's concern -- it is handed in already
        # built.
        self._signing_key = signing_key
        self._lock = threading.Lock()

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        max_justification_chars: int,
        signing_key: Ed25519Signer | None = None,
    ) -> AuditChainWriter:
        """Open ``path`` for appending, resuming an existing chain or starting a new one.

        An existing file is walked before it is extended, and a defect anywhere in it is a
        :class:`ChainStateError`. See that class for why extending a broken chain is refused rather
        than reported. ``signing_key`` (ADR-130) is passed through to every append; a resumed chain
        that was written unsigned and is now reopened with a key gains signatures only on its new
        records, which :func:`guardian.audit.verify.verify_signature` reports honestly rather than
        pretending the whole file is signed.
        """
        path = Path(path)
        if not path.exists():
            return cls(
                path, max_justification_chars=max_justification_chars, signing_key=signing_key
            )
        records = read_chain(path)
        if not records:
            return cls(
                path, max_justification_chars=max_justification_chars, signing_key=signing_key
            )
        for check in walk_chain(records):
            if check.defect is not None:
                raise ChainStateError(
                    f"{path}: line {check.parsed.line} is not an appendable chain record "
                    f"({check.defect}). Run `make audit-verify P={path}` for the full report."
                )
        last = records[-1]
        return cls(
            path,
            max_justification_chars=max_justification_chars,
            head=str(last.stored_hash),
            next_seq=int(last.seq or 0) + 1,
            signing_key=signing_key,
        )

    @property
    def head(self) -> str:
        """The hash of the most recent record, or :data:`GENESIS_PREV_HASH` on an empty chain.

        This is the value ``seal.json`` records as the chain head, and the anchor without which
        tail truncation and whole-chain rewrite are undetectable.
        """
        return self._head

    @property
    def next_seq(self) -> int:
        """The ``seq`` the next appended record will carry."""
        return self._next_seq

    def append(self, body: SupportsModelDump | dict[str, Any]) -> dict[str, Any]:
        """Append one record built from ``body`` and return the completed record.

        ``body`` carries everything except ``seq``, ``prev_hash`` and ``hash``; those three are the
        chain's to assign, and a body that supplies any of them with a non-null value is refused.
        A key present with the value ``None`` is tolerated and overwritten, so a Pydantic model
        that declares the fields as optional can be dumped straight in.

        The returned dict is the record exactly as written, so the caller can read ``seq`` from it
        for ``ActionResult.audit_seq`` without re-reading the file.
        """
        prepared = _as_body(body)
        for field in WRITER_ASSIGNED_FIELDS:
            if field in prepared:
                if prepared[field] is not None:
                    raise AuditRecordRefused(
                        f"the audit body supplied {field!r}; the chain assigns seq, prev_hash, hash "  # noqa: E501 - message
                        "and the signature, and accepting a caller's value would let a caller forge "  # noqa: E501 - message
                        "a link or a signature"
                    )
                del prepared[field]
        _refuse_forbidden(prepared, "")
        cleaned = _clean_body(prepared, self.max_justification_chars)

        with self._lock:
            record = dict(cleaned)
            record[SEQ_FIELD] = self._next_seq
            record[PREV_HASH_FIELD] = self._head
            record[HASH_FIELD] = record_hash(self._head, record)
            # ADR-130: sign the record's hash, not its body. The signature is added AFTER the hash
            # and
            # is excluded from ParsedRecord.body, so it is never part of what was hashed -- which is
            # why
            # a re-hash of the body verifies a signed record unchanged. Signing the hash (rather
            # than
            # the body bytes) means a forger who mutates a record and recomputes its hash produces a
            # hash the stored signature no longer covers, so the whole-chain rewrite the unsigned
            # chain
            # cannot detect (guardian/audit/verify.py) fails signature verification under a key the
            # forger does not hold.
            if self._signing_key is not None:
                record[SIGNATURE_FIELD] = self._signing_key.sign(
                    record[HASH_FIELD].encode("ascii")
                ).hex()
            line = canonical_json_line(record)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("ab") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
            self._head = record[HASH_FIELD]
            self._next_seq += 1
            return record


# --- reading and walking a chain file ----------------------------------------------------------


@dataclass(frozen=True)
class ParsedRecord:
    """One line of a chain file, parsed. ``defect`` is ``None`` when it is usable as a record."""

    line: int
    record: dict[str, Any]
    defect: str | None

    @property
    def seq(self) -> int | None:
        value = self.record.get(SEQ_FIELD)
        return value if isinstance(value, int) and not isinstance(value, bool) else None

    @property
    def prev_hash(self) -> str | None:
        value = self.record.get(PREV_HASH_FIELD)
        return value if is_chain_hash(value) else None

    @property
    def stored_hash(self) -> str | None:
        value = self.record.get(HASH_FIELD)
        return value if is_chain_hash(value) else None

    @property
    def body(self) -> dict[str, Any]:
        """The record without ``hash`` or the signature -- the object the chain rule serialises.

        ``hash`` is excluded because it is the digest of everything else and cannot be inside its
          own
        input. The signature (ADR-130) is excluded for the same reason one layer out: it is computed
        *from* the hash and added after it, so it was never part of what the hash covered, and a
        verifier that re-hashed a record with the signature still in the body would compute a
        different
        digest than the writer did and report tampering on a correct signed chain.
        """
        return {
            key: value
            for key, value in self.record.items()
            if key not in (HASH_FIELD, SIGNATURE_FIELD)
        }


def parse_chain_line(line_number: int, text: str) -> ParsedRecord:
    """Parse one line into a :class:`ParsedRecord`, naming the defect instead of raising.

    Naming rather than raising is what lets a verifier report every problem in a file rather than
    the first one, which is the difference between a report a reader can act on and an exception.
    """
    try:
        loaded = json.loads(text)
    except ValueError as exc:
        return ParsedRecord(line_number, {}, f"not JSON: {exc}")
    if not isinstance(loaded, dict):
        return ParsedRecord(line_number, {}, f"not a JSON object but a {type(loaded).__name__}")
    parsed = ParsedRecord(line_number, loaded, None)
    missing = [field for field in CHAIN_ASSIGNED_FIELDS if field not in loaded]
    if missing:
        return ParsedRecord(line_number, loaded, f"missing chain field(s): {', '.join(missing)}")
    if parsed.seq is None:
        return ParsedRecord(line_number, loaded, f"{SEQ_FIELD} is not an integer")
    if parsed.seq < 0:
        return ParsedRecord(line_number, loaded, f"{SEQ_FIELD} is negative")
    if parsed.prev_hash is None:
        return ParsedRecord(line_number, loaded, f"{PREV_HASH_FIELD} is not a chain hash")
    if parsed.stored_hash is None:
        return ParsedRecord(line_number, loaded, f"{HASH_FIELD} is not a chain hash")
    return parsed


def read_chain(path: Path) -> list[ParsedRecord]:
    """Read a chain file into parsed records, tolerating CRLF and ignoring blank lines.

    The file is read as bytes and decoded as UTF-8 rather than opened in text mode, so the result
    does not depend on the ambient locale, and a trailing carriage return is stripped from every
    line. That tolerance is the practical form of ``canonical``'s rule that the hash is taken over
    the parsed record and never over file bytes: ``.gitattributes`` normalises tracked text to LF
    in the index, so a fixture checked out on the Windows host arrives with CRLF, and a reader that
    fed those bytes to the digest would report tampering on a correct file.
    """
    raw = Path(path).read_bytes()
    text = raw.decode("utf-8")
    records: list[ParsedRecord] = []
    for index, line in enumerate(text.split("\n"), start=1):
        stripped = line[:-1] if line.endswith("\r") else line
        if not stripped.strip():
            continue
        records.append(parse_chain_line(index, stripped))
    return records


@dataclass(frozen=True)
class LinkCheck:
    """One record's three independent checks: its own hash, its link back, and its position.

    The three are separate on purpose, because which of them fails is what distinguishes a mutation
    from a deletion from an insertion. ``expected_prev_hash`` and ``expected_seq`` are ``None`` when
    the preceding record was itself unusable and the expectation cannot be formed -- an
    indeterminate result reported as indeterminate, rather than a second failure derived from a
    first one.
    """

    index: int
    parsed: ParsedRecord
    expected_prev_hash: str | None
    expected_seq: int | None
    computed_hash: str | None

    @property
    def defect(self) -> str | None:
        """A one-line description of the first thing wrong with this record, or ``None``."""
        if self.parsed.defect is not None:
            return self.parsed.defect
        if not self.hash_ok:
            return "content does not hash to its stored hash"
        if self.link_ok is False:
            return "prev_hash does not match the preceding record's hash"
        if self.seq_ok is False:
            return "seq does not follow the preceding record's seq"
        return None

    @property
    def hash_ok(self) -> bool:
        return self.computed_hash is not None and self.computed_hash == self.parsed.stored_hash

    @property
    def link_ok(self) -> bool | None:
        if self.expected_prev_hash is None or self.parsed.prev_hash is None:
            return None
        return self.parsed.prev_hash == self.expected_prev_hash

    @property
    def seq_ok(self) -> bool | None:
        if self.expected_seq is None or self.parsed.seq is None:
            return None
        return self.parsed.seq == self.expected_seq


def walk_chain(records: list[ParsedRecord]) -> list[LinkCheck]:
    """Recompute every record's hash and form every expectation, in one pass over the file.

    One walk, two consumers: :meth:`AuditChainWriter.open` raises on the first defect, and
    ``guardian.audit.verify`` classifies the whole list. Keeping the recomputation here means the
    writer and the verifier can never disagree about what a record hashes to.

    ``expected_seq`` follows the **preceding declared** seq rather than the file position, which is
    what keeps one tampering event to one or two findings instead of a cascade: after a deletion,
    every later record is still one more than its predecessor, so the gap is reported once at the
    point of the deletion and never again.
    """
    checks: list[LinkCheck] = []
    previous: ParsedRecord | None = None
    for index, parsed in enumerate(records):
        if index == 0:
            expected_prev: str | None = GENESIS_PREV_HASH
            expected_seq: int | None = 0
        elif previous is None or previous.defect is not None:
            expected_prev = None
            expected_seq = None
        else:
            expected_prev = previous.stored_hash
            expected_seq = None if previous.seq is None else previous.seq + 1
        computed: str | None = None
        if parsed.defect is None and parsed.prev_hash is not None:
            computed = record_hash(parsed.prev_hash, parsed.body)
        checks.append(LinkCheck(index, parsed, expected_prev, expected_seq, computed))
        previous = parsed
    return checks
