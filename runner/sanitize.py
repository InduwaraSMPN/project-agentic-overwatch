r"""Pre-seal redaction of a run bundle, and the scan that proves nothing survived it.

WHAT THIS MODULE OWNS
-----------------------
``docs/protocols/data-management.md`` §5 requires a bundle to be sanitised **before** seal:
"Strip/redact: ``Authorization`` headers, ``api_key``-shaped strings, ``.env`` values, JWT signing
keys. Capability tokens in audit logs keep claims but redact signatures. Sanitizer is unit-tested
with planted secrets; a bundle failing the planted-secret test cannot seal." This module is that
sanitiser and that scan. :func:`sanitize_bundle` rewrites the free-text files in place;
:func:`scan_for_secrets` is the unit-tested detector the seal wires in as a backstop, so that a
secret the sanitiser could not rewrite refuses the seal rather than shipping.

WHY THE SURFACE IS THE FREE-TEXT FILES AND NOT THE AUDIT LOG
--------------------------------------------------------------
``guardian/audit/chain.py`` records the Guardian's decision that its records are **born clean**
(conflict M3-C5): the append-time scrubber and the structural key refusal mean
``scan_chain_file`` over a produced ``guardian_audit.jsonl`` finds nothing, including when a
secret-shaped string was planted in a justification. Two consequences follow, and both are design
here rather than accident:

* ``guardian_audit.jsonl`` is **never rewritten**. Each of §5's edits changes a hashed field and
  breaks every link after it, so redacting the chain after the fact would turn ``make audit-verify``
  red on correct data -- the exact defect M3-C5 resolves by redacting *before* the hash. The sealer
  therefore does not sanitise the chain and does not re-scan it: M3 already guarantees it clean, and
  re-scanning it here would both duplicate that guarantee and risk a false positive on a legitimate
  high-structure field such as the issuer DNS name (see the dotted-triple trade below).
* The realistic surface is the files a framework produced from model output --
  ``messages.jsonl`` and the span/token files -- where an Executor's text or a captured request
  header can carry a real credential. Those are what :data:`SANITISE_FILES` names.

THE DOTTED-TRIPLE TRADE, AND WHY IT IS NO LONGER TAKEN
-------------------------------------------------------
A compact JWS is ``header.payload.signature`` and §5 asks that the claims survive and the signature
go. :data:`_RE_JWT_TRIPLE` keeps the first two dot-separated segments and redacts the third.

This rule used to match *any* three-segment dotted token whose segments were two characters or
longer, and the over-redaction was recorded here as a deliberate trade: "a false redaction costs a
reader some context while a missed signature costs the seal". The reasoning offered for accepting it
was that the field is "free text nothing downstream parses". **That premise was wrong, and a live
run showed how.** ``monitor_events.jsonl`` is in :data:`SANITISE_FILES` and its
``evidence_excerpts`` are Kubernetes audit fields, so
``runs/CAMP-20260912-gate1/RUN-G0-FULL-SCN-SIM-02-INJ-A-101`` sealed carrying

    objectRef.apiGroup=rbac.authorization.<redacted:jwt-signature>.io

for the one audit event in the whole run -- the ClusterRoleBinding escalation that is SCN-SIM-02's
entire detection label. The literal ``k8s`` had been eaten as a signature. Downstream *does* parse
these: ``analysis/`` reads the bundle, the blind re-score reads it, and an API group is an
identifier rather than prose. A reader losing context is one thing; the corpus losing the API group
that identifies the attack is another.

So the rule is now anchored on what a JWS header is rather than on how many characters it has: the
header is base64url-encoded JSON, so it begins ``{``, so its encoding begins ``e`` followed by one
of ``wxyz0-9-_``. A dotted identifier essentially never opens that way. Coverage of the secret is
unchanged -- ``guardian/token/issuer.py`` mints through PyJWT, so every capability token this
sanitiser exists to catch is a compact JWS and still matches -- while ``svc.cluster.local``,
``192.168.10.20``, ``rbac.authorization.k8s.io`` and ``1.2.3`` now survive intact. The tests carry
one case per JWS header shape rather than the synthetic ``aaa.bbb.ccc`` that the old bound
admitted, because a test whose input is not a JWT cannot show that a JWT is redacted.

MARKERS ARE VISIBLE, IDEMPOTENT, AND INERT TO THE SCAN
--------------------------------------------------------
Each redaction replaces the secret value with ``<redacted:<kind>>`` (data-management §5's
convention, made concrete): the surrounding structure -- the header name, the assignment key, the
JWT claims -- survives so the record still reads, and the marker announces that something was
removed instead of quietly not saying it. Every marker carries ``<``, ``:`` and ``>`` and no dot, so
no marker matches any rule below: :func:`sanitize_bundle` applied twice equals applied once, and
:func:`scan_for_secrets` over sanitised text returns ``[]``. That last property is load-bearing --
it is what makes "a bundle failing the planted-secret scan cannot seal" a check the clean case
passes rather than a gate that fires on its own output.

WHAT BREAKS IF THIS FILE CHANGES
---------------------------------
The seal (T-15, T-41). :func:`runner.bundle.seal_bundle` calls :func:`sanitize_bundle` and refuses
to seal on any finding :func:`scan_for_secrets` returns. A rule that stops matching a secret shape
is a secret that reaches a sealed bundle; a marker that starts matching a rule is a seal that can
never succeed. ADR-040 covers the sealer and its sanitiser; the identifier reuse the manifest and
ids modules rest on is ADR-039's.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final

__all__ = (
    "SANITISE_FILES",
    "Finding",
    "marker_for",
    "sanitize_bundle",
    "sanitize_text",
    "scan_for_secrets",
)

# The free-text files a framework produced and that the sanitiser rewrites in place. Ordered as the
# bundle layout (data-management §1) lists them. `guardian_audit.jsonl` is deliberately absent: it
# is born clean and must stay byte-stable for its hash chain (see the module docstring). The three
# instrument CSVs and `manifest.json` are absent because they are structured, non-free-text output
# that the sealer scans as a backstop but never rewrites. `scores.json` is post-seal; it is listed
# so that if a later scoring pass is sanitised, it is sanitised by the same rules.
SANITISE_FILES: Final[tuple[str, ...]] = (
    "messages.jsonl",
    "tokens.json",
    "spans.otel.json",
    "monitor_events.jsonl",
    "injection.log.jsonl",
    "assertions.json",
    "metrics.json",
    "scores.json",
)


def marker_for(kind: str) -> str:
    """The redaction marker for a secret ``kind``: ``<redacted:authorization>`` and its siblings.

    One home for the marker shape, so the scan and the redactor cannot spell it two ways. The
    angle brackets and colon are what keep a marker from matching any rule below.
    """
    return f"<redacted:{kind}>"


@dataclass(frozen=True)
class _Rule:
    """One secret shape: its ``kind`` label, the pattern that finds it, and how it is redacted.

    ``keep`` returns the text placed *before* the marker when a match is redacted -- the header
    name and separator for an assignment, the two surviving JWT segments for a signature -- so the
    structure §5 asks to preserve is preserved and only the secret value is replaced.
    """

    kind: str
    pattern: re.Pattern[str]
    keep: object  # Callable[[re.Match[str]], str]; typed loosely to keep the table literal readable


# --- the secret shapes -------------------------------------------------------------------------
#
# Each value class stops at whitespace, a quote, a backslash, a JSON/CSV delimiter, or '<'.
# Excluding '<' is what makes redaction idempotent: a marker begins with '<', so a value class
# cannot re-consume the marker a previous pass wrote. Stopping at '"' keeps a redaction inside one
# JSON string, so the surrounding document stays parseable.
#
# **Stopping at a backslash is what makes that last property actually hold.** These files are JSONL,
# so a quote *inside* a record is escaped: an agent that writes a shell command into a tool argument
# produces `... -H \"Authorization: Bearer <token>\" ...` on the wire. A class that excludes '"' but
# not '\' consumes the backslash, stops at the quote, and leaves a bare '"' behind -- which closes
# the JSON string early and makes the record unparseable. That is not hypothetical: it is why
# `RUN-G0-FULL-SCN-SIM-02-INJ-A-101` refused to seal on 2026-09-12 with
# `messages.jsonl:1 is not valid JSON: Expecting ',' delimiter: line 1 column 16599`, after its
# Executor wrote exactly that curl. See ADR-074.
#
# Nothing leaks by stopping one character earlier. A backslash inside a JSON string is an escape
# introducer, never a literal character of the value, so the credential itself ends at the
# backslash; and the secret shapes this file matches -- bearer tokens, API keys, compact JWS -- are
# base64url or hex alphabets that contain no backslash at all.
_BACKSLASH: Final = "\\\\"
_VALUE = rf"(?:\"[^\"]*\"|'[^']*'|[^\s\"',;}}\])<{_BACKSLASH}]+)"

# `Authorization: <credential>` (or `=`). The whole credential goes, an optional `Bearer` scheme
# included, because none of it is claims to preserve -- unlike a JWT, an Authorization header is the
# secret entire. Case-insensitive, since a captured header may arrive `authorization`.
_RE_AUTHORIZATION: Final = re.compile(
    rf"(?i)(authorization)(\s*[:=]\s*)(?:bearer\s+)?[^\s\"',;}}\])<{_BACKSLASH}]+"
)

# A compact JWS `header.payload.signature`. Claims survive; the signature is redacted (§5:
# "capability tokens ... keep claims but redact signatures").
#
# The first segment is anchored on what a JWS header *is* rather than on how long it is. A compact
# JWS header is base64url-encoded JSON, so its plaintext begins `{`; `{` is 0x7B, whose leading six
# bits encode to `e` and whose trailing two bits put the second character in the 48..63 range of the
# base64url alphabet -- `w`, `x`, `y`, `z`, `0`-`9`, `-` or `_`. Every compact JWS header therefore
# begins with one of those pairs, whatever whitespace the encoder left in the JSON, and a dotted
# identifier essentially never does. That anchor is what lets this rule tell a capability token from
# a DNS name; see the module docstring for the false positive that motivated it.
_RE_JWT_TRIPLE: Final = re.compile(
    r"\b(e[wxyz0-9_-][A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]{16,})\b"
)

# `api_key = <value>` in any casing, with an optional vendor prefix or suffix on the name so that
# `OPENAI_API_KEY`, `x-api-key` and `apiKeyId` all match. The name and separator survive; the value
# is redacted.
_RE_API_KEY: Final = re.compile(
    rf"(?i)([A-Za-z0-9_.-]*api[_-]?key[A-Za-z0-9_.-]*)(\s*[:=]\s*)({_VALUE})"
)

# A `.env`-style assignment whose key is an upper-case environment name containing a credential
# word. Restricted to upper-case names so ordinary lower-case JSON keys do not trip it, and to the
# named credential words so `PATH` or `HOME` do not. `bare PASS` is excluded on purpose (BYPASS,
# COMPASS); `PASSWORD`/`PASSWD`/`PASSPHRASE` are the intended shapes. The prefix is `[A-Z0-9_]*`
# (zero or more), not `[A-Z][A-Z0-9_]*`, so a bare `SECRET=` matches: a mandatory leading letter
# would consume the `S` and leave nothing for the `SECRET` alternation to bind.
_RE_ENV_ASSIGNMENT: Final = re.compile(
    r"\b([A-Z0-9_]*"
    r"(?:SECRET|KEY|TOKEN|PASSWORD|PASSWD|PASSPHRASE|CREDENTIAL|PRIVATE)"
    rf"[A-Z0-9_]*)(\s*=\s*)({_VALUE})"
)

# Order matters. Authorization first, so `Authorization: Bearer <jwt>` is taken whole and the JWT
# rule never bites a chunk out of a header. The JWT rule next, so a standalone signature is redacted
# before the assignment rules could wrap a dotted value they do not understand. The two assignment
# rules last; either order between them is fine because each excludes the other's marker.
_RULES: Final[tuple[_Rule, ...]] = (
    _Rule("authorization", _RE_AUTHORIZATION, lambda m: m.group(1) + m.group(2)),
    _Rule("jwt-signature", _RE_JWT_TRIPLE, lambda m: m.group(1) + "."),
    _Rule("api-key", _RE_API_KEY, lambda m: m.group(1) + m.group(2)),
    _Rule("env-value", _RE_ENV_ASSIGNMENT, lambda m: m.group(1) + m.group(2)),
)


@dataclass(frozen=True)
class Finding:
    """One secret-shaped span a scan found: its ``kind``, its bounds, and the text it matched.

    ``snippet`` is the whole match, so a seal-refusal message can name what it saw without the
    caller re-running the pattern. On a redacted document :func:`scan_for_secrets` returns no
    findings at all, which is the property the planted-secret test asserts.
    """

    kind: str
    start: int
    end: int
    snippet: str


def sanitize_text(text: str) -> tuple[str, int]:
    """Redact every secret shape in ``text``; return the cleaned text and the redaction count.

    Deterministic and idempotent: the rules run in a fixed order and no marker matches any rule, so
    ``sanitize_text(sanitize_text(t)[0])`` equals ``sanitize_text(t)`` and re-sealing an already
    sealed bundle changes nothing.
    """
    total = 0
    cleaned = text
    for rule in _RULES:
        keep = rule.keep
        cleaned, count = rule.pattern.subn(
            lambda match, k=keep, kind=rule.kind: k(match) + marker_for(kind),
            cleaned,
        )
        total += count
    return cleaned, total


def scan_for_secrets(text: str) -> list[Finding]:
    """Return every secret-shaped span in ``text``, in the order the rules are declared.

    This is the detector the planted-secret test drives and the backstop the seal wires in: a
    non-empty result on a sanitised bundle is a secret the sanitiser could not rewrite -- a leak
    into a structured file it does not touch -- and the seal refuses rather than shipping it.
    """
    findings: list[Finding] = []
    for rule in _RULES:
        for match in rule.pattern.finditer(text):
            findings.append(Finding(rule.kind, match.start(), match.end(), match.group(0)))
    return findings


def sanitize_bundle(bundle_dir: Path) -> dict[str, int]:
    """Redact every file in :data:`SANITISE_FILES` present under ``bundle_dir``, in place.

    Reads bytes and writes bytes, so a file with no secret keeps its exact bytes (nothing is
    written when nothing changed) and the hashes the seal takes are stable across a no-op sanitise.
    Returns the per-file redaction count, for the runner's log. Files absent from the bundle are
    skipped: which files a profile requires is the sealer's completeness check, not the sanitiser's.
    """
    bundle_dir = Path(bundle_dir)
    counts: dict[str, int] = {}
    for name in SANITISE_FILES:
        path = bundle_dir / name
        if not path.is_file():
            continue
        text = path.read_bytes().decode("utf-8")
        cleaned, count = sanitize_text(text)
        if count:
            path.write_bytes(cleaned.encode("utf-8"))
        counts[name] = count
    return counts
