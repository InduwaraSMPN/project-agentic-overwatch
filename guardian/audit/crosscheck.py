r"""Conformance for the canonicalisation rule: frozen vectors, and the Monitor's second opinion.

WHY THIS FILE EXISTS AND WHERE IT SITS
----------------------------------------
``docs/adr/ADR-022-audit-canonicalisation-and-chain-boundary.md`` records a cost it could not
design away. ``monitor/aggregator/models.py`` already carries a canonical-JSON definition, written
at M2 for the event stream; ``guardian/audit/canonical.py`` adds a second, because a
security-critical digest whose definition depends on another container's module is a coupling
nobody would choose. Two implementations of one rule is exactly the single-homing problem
``.agents/rules/00-source-of-truth.md`` exists to prevent, so the ADR's resolution is **one rule,
stated once; two implementations; a check that proves they agree byte for byte on a shared
fixture**. This is that check.

It is conformance and not runtime. Nothing in the enforcement path imports it, the Guardian
container never runs it, and the ``monitor`` import below is the only place anything under
``guardian/`` reaches for the aggregator -- the ADR's Consequences section says in as many words
that it must stay test-only, and that whoever adds a second such import should read that paragraph
as the reason not to.

THREE CHECKS, AND WHY THE FIRST IS THE ONE THAT CATCHES DRIFT
---------------------------------------------------------------
1. **Frozen vectors.** ``fixtures/canonical/vectors.json`` holds, for each value, the exact
   canonical bytes and their SHA-256 as **literals a human wrote down**. A check that canonicalises
   a record and hashes it proves only that the implementation agrees with itself; a comparison
   against a written-down digest is what fails when a library upgrade, an interpreter bump or an
   edit to the rule changes the bytes. Nothing in this repository regenerates that file --
   ``fixtures/build.py`` refuses to touch it and says why.

2. **Rejections.** Clause 4 and clause 8 of the rule are about inputs that must *not* produce
   bytes, so they cannot be expressed as a vector with a digest. They are stated here as code, and
   each is checked for the named path in its message rather than merely for the exception type: the
   whole value of clause 8 over bare ``json.dumps`` is that a rejection says which field was wrong.

3. **The cross-check.** Both implementations serialise every vector and the results are compared.
   One framing difference has to be accounted for and is the kind of one-byte disagreement two
   implementations can carry for years without anything going red:
   ``monitor.aggregator.models.canonical_json_bytes`` **appends the JSON Lines terminator**, because
   for the event stream the framed line is the deliverable, while
   ``guardian.audit.canonical.canonical_json_bytes`` returns the unframed form and
   :func:`guardian.audit.canonical.canonical_json_line` adds the terminator separately, so that no
   framing byte ever enters a digest. The comparison below is therefore against the *line* form,
   and it is spelled out rather than hidden in a strip, because a check that quietly normalised the
   difference away would be a check that could not see it appear.

A divergence is a failure and never a warning. Two implementations of one rule that disagree mean
the rule has quietly become two rules, which is the thing rule 00 exists to catch.

WHEN ``monitor`` IS NOT IMPORTABLE
------------------------------------
Check 3 skips, by name, and the summary line says so. That is the normal case inside the Guardian's
own container -- where the aggregator is deliberately absent -- and an abnormal one in this
repository, where a missing ``monitor`` means something is wrong with the checkout rather than with
the rule. The skip is reported as a skip and never counted as a pass, because an unrun cross-check
and an agreeing one are different claims.

WHAT THE CROSS-CHECK DOES NOT PROVE, STATED HERE BECAUSE ADR-022 INSISTS ON IT
--------------------------------------------------------------------------------
It covers the inputs the shared fixture contains and nothing else. Two implementations can agree on
every value in a fixture and disagree on a value nobody thought to put in it. The fixture is
therefore the entire strength of the coupling, widening it is cheap and correct, and narrowing it
weakens two proofs at once.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final

from guardian.audit.canonical import (
    CANONICAL_JSON_RULE_ID,
    LINE_TERMINATOR,
    CanonicalisationError,
    canonical_json_bytes,
    canonical_json_line,
    sha256_hex,
)

__all__ = [
    "VECTORS_PATH",
    "check_crosscheck",
    "check_rejections",
    "check_vectors",
    "load_vectors",
    "main",
]

VECTORS_PATH: Final = Path(__file__).resolve().parent / "fixtures" / "canonical" / "vectors.json"


def load_vectors(path: Path = VECTORS_PATH) -> list[dict[str, Any]]:
    """Read the frozen vectors, refusing a file that does not carry the rule id it was frozen under.

    The rule id is checked rather than ignored because the vectors and the rule version each other:
    a vectors file written under ``audit-canonical-json/v1`` says nothing about what
    ``audit-canonical-json/v2`` should produce, and silently comparing one against the other would
    be the fixture endorsing a rule it never saw.
    """
    loaded = json.loads(path.read_bytes().decode("utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"{path}: is not a JSON object")
    rule_id = loaded.get("rule_id")
    if rule_id != CANONICAL_JSON_RULE_ID:
        raise ValueError(
            f"{path}: was frozen under rule {rule_id!r}, but this module implements "
            f"{CANONICAL_JSON_RULE_ID!r}. Regenerating the vectors under a new rule is a "
            "deliberate reviewed diff, and after the v1.0 freeze a hotfix ADR (iron rule 6)."
        )
    vectors = loaded.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        raise ValueError(f"{path}: carries no vectors")
    return [vector for vector in vectors if isinstance(vector, dict)]


def check_vectors(vectors: list[dict[str, Any]], problems: list[str]) -> int:
    """Compare every vector against its committed bytes and its committed digest."""
    checked = 0
    for vector in vectors:
        identifier = vector.get("id", "<unnamed>")
        expected_text = vector.get("canonical")
        expected_digest = vector.get("sha256")
        if not isinstance(expected_text, str) or not isinstance(expected_digest, str):
            problems.append(f"vector {identifier}: has no committed canonical form or digest")
            continue
        produced = canonical_json_bytes(vector.get("value"))
        # The expected form is committed as text and is pure ASCII by clause 3, so encoding it is
        # lossless and the comparison stays a byte comparison rather than becoming a text one.
        if produced != expected_text.encode("ascii"):
            problems.append(
                f"vector {identifier}: canonical bytes differ from the committed form\n"
                f"      committed: {expected_text}\n"
                f"      produced:  {produced.decode('ascii', 'backslashreplace')}"
            )
            continue
        digest = sha256_hex(produced)
        if digest != expected_digest:
            problems.append(
                f"vector {identifier}: hashes to {digest} but the committed digest is "
                f"{expected_digest}. The bytes matched, so this is the digest literal itself "
                "being wrong, which is worth fixing loudly."
            )
            continue
        checked += 1
    return checked


# Clause 4 and clause 8: inputs that must be refused, each with the substring its message has to
# carry. The substring is the *path* wherever a path exists, because "rejected with the path" over
# "silently different" is the entire argument for having clause 8 at all -- a bare TypeError from
# json.dumps names neither the field nor where it was.
_REJECTIONS: Final[tuple[tuple[str, Callable[[], object], str], ...]] = (
    ("nan", lambda: {"value": float("nan")}, "$.value"),
    ("positive-infinity", lambda: {"value": float("inf")}, "$.value"),
    ("negative-infinity", lambda: [float("-inf")], "$[0]"),
    ("non-string-key", lambda: {1: "a", "1": "b"}, "non-string key"),
    ("set-value", lambda: {"action": {"verbs": {"get", "list"}}}, "$.action.verbs"),
    ("bytes-value", lambda: {"action": {"params": {"blob": b"\x00"}}}, "$.action.params.blob"),
    ("cycle", None, "contains itself"),
)


def _cycle() -> object:
    """A record that contains itself, built here because a lambda cannot bind its own result."""
    node: dict[str, Any] = {"action": {}}
    node["action"]["parent"] = node
    return node


def check_rejections(problems: list[str]) -> int:
    """Confirm every clause-4 and clause-8 input is refused, and refused with its path named."""
    checked = 0
    for name, factory, expected in _REJECTIONS:
        payload = _cycle() if factory is None else factory()
        try:
            canonical_json_bytes(payload)
        except CanonicalisationError as exc:
            if expected not in str(exc):
                problems.append(
                    f"rejection {name}: refused, but the message does not name {expected!r}: {exc}"
                )
                continue
            checked += 1
            continue
        problems.append(
            f"rejection {name}: was serialised rather than refused. Clause 4 and clause 8 turn "
            "three silent mangles into named errors, and a mangle that hashes is worse than one "
            "that raises."
        )
    return checked


def check_crosscheck(vectors: list[dict[str, Any]], problems: list[str]) -> int | None:
    """Compare both implementations on every vector. ``None`` means ``monitor`` was not importable.

    ``None`` and ``0`` are different answers and are kept apart: the first says the check did not
    run, the second would say it ran over nothing. Only one of those may ever be reported as a pass,
    and neither is.
    """
    try:
        from monitor.aggregator.models import canonical_json_bytes as monitor_canonical_json_bytes
    except ImportError:
        return None

    checked = 0
    for vector in vectors:
        identifier = vector.get("id", "<unnamed>")
        value = vector.get("value")
        guardian_unframed = canonical_json_bytes(value)
        guardian_framed = canonical_json_line(value)
        monitor_framed = monitor_canonical_json_bytes(value)
        if guardian_framed != monitor_framed:
            problems.append(
                f"vector {identifier}: the two implementations of one rule disagree\n"
                f"      guardian: {guardian_framed!r}\n"
                f"      monitor:  {monitor_framed!r}"
            )
            continue
        # The framing difference, asserted rather than assumed. If the Monitor ever stops appending
        # the terminator, the equality above would still hold against a Guardian that also stopped,
        # and this line is what notices that the two moved together for the wrong reason.
        if monitor_framed != guardian_unframed + LINE_TERMINATOR:
            problems.append(
                f"vector {identifier}: the Monitor's framing is no longer one trailing "
                f"{LINE_TERMINATOR!r} over the Guardian's unframed form. The digest is taken over "
                "the unframed bytes, so a change in framing must be a deliberate, reviewed one."
            )
            continue
        checked += 1
    return checked


def main(argv: list[str] | None = None) -> int:
    """Run all three checks. Returns 0 when everything that ran agreed, 1 otherwise."""
    if argv:
        print(f"crosscheck takes no arguments; got {argv}", file=sys.stderr)
        return 2

    problems: list[str] = []
    try:
        vectors = load_vectors()
    except (OSError, ValueError) as exc:
        print(f"audit-crosscheck: FAIL -- {exc}", file=sys.stderr)
        print(f"audit-crosscheck: FAIL -- the frozen vectors could not be read ({exc})")
        return 1

    print("audit-crosscheck: per-check detail", file=sys.stderr)
    vectors_ok = check_vectors(vectors, problems)
    print(
        f"  frozen vectors:   {vectors_ok}/{len(vectors)} matched bytes and digest", file=sys.stderr
    )

    rejections_ok = check_rejections(problems)
    print(
        f"  rejections:       {rejections_ok}/{len(_REJECTIONS)} refused with the path named",
        file=sys.stderr,
    )

    crosschecked = check_crosscheck(vectors, problems)
    if crosschecked is None:
        print(
            "  monitor agreement: SKIPPED -- monitor.aggregator.models is not importable. Normal "
            "inside the Guardian container, which ships without the aggregator by design; in this "
            "repository it means the checkout or the interpreter is wrong, not that the two "
            "implementations agree.",
            file=sys.stderr,
        )
        agreement = "skipped-monitor-not-importable"
    else:
        print(
            f"  monitor agreement: {crosschecked}/{len(vectors)} byte-identical after the one "
            "line-terminator framing difference is accounted for",
            file=sys.stderr,
        )
        agreement = f"{crosschecked}/{len(vectors)}"

    if problems:
        print(f"\naudit-crosscheck: FAIL -- {len(problems)} problem(s):\n", file=sys.stderr)
        for problem in problems:
            print(f"  ! {problem}", file=sys.stderr)
        print(
            "\nA divergence is a failure and not a warning: two implementations of one rule that "
            "disagree mean the rule has quietly become two rules (ADR-022).",
            file=sys.stderr,
        )
        print(
            f"audit-crosscheck: FAIL -- {len(problems)} problem(s) over {len(vectors)} vector(s) "
            f"rule={CANONICAL_JSON_RULE_ID}"
        )
        return 1

    print(
        f"audit-crosscheck: PASS -- {vectors_ok} frozen vector(s) match committed bytes and "
        f"digests, {rejections_ok} rejection(s) refused with the path named, monitor agreement "
        f"{agreement}, rule={CANONICAL_JSON_RULE_ID}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
