r"""The meta-test: what makes "all three assertions, per case" a mechanism rather than a habit.

``docs/milestones/M3-guardian.md``'s Definition of done requires every adversarial case to assert
three things -- **denied**, with a **structured reason code**, and **present in the audit chain** --
and the M3 plan gives the reason the third one is the one that gets dropped: a denial the audit log
does not contain fails ``docs/protocols/security-policy.md`` section 1.4, and T-22's scoring reads
that log, so an unaudited block is invisible to the evaluation whether or not it happened. An
unaudited block is therefore worse than an unblocked action: it is an unblocked action nobody can
see.

A rule like that is usually enforced by a sentence in a contributing guide, which holds until the
first inconvenient afternoon. Three mechanisms make it structural instead, and this module is the
third:

1. ``CaseOutcome`` publishes no accessor for the decision. The only exits are ``assert_denied`` and
   ``assert_permitted``, and each makes the whole triple assertion before returning.
2. ``CaseOutcome.record`` and ``CaseOutcome.result`` raise until one of those has run, so a case
   cannot inspect what happened without first having checked it.
3. This scan reads the abstract syntax tree of every ``test_adversarial_*.py`` module and fails if
   any test function does not call one of them.

Mechanisms 1 and 2 stop a case from *accidentally* checking one third. Only mechanism 3 stops a case
from being written that checks nothing at all -- a test that submits a request, asserts something
about the response body by hand, and never looks at the chain. That is the shape a hurried case
takes, and it is invisible in review because it looks like a test.

WHY THE SCAN IS AN AST WALK AND NOT A GREP
--------------------------------------------
``monitor/tests/test_g3_isolation.py`` sets the house pattern for this and the reason carries over:
a grep for ``assert_denied`` matches the string in a comment, in a docstring, and in a line that
was commented out, and it cannot tell which *function* the call belongs to. The walk below
attributes every call to the test function containing it, so "this file mentions assert_denied
somewhere" is never mistaken for "every case in this file makes the assertion".

WHAT IS DELIBERATELY NOT SCANNED
----------------------------------
Only ``test_adversarial_*.py``. The tamper suite verifies chains rather than submitting requests;
the flag-isolation suite compares arms; ``test_token_issuance_exposure.py`` and
``test_audit_availability.py`` are findings about behaviour that produces *no* audited decision,
and requiring them to assert one would be requiring them to assert something false. Narrowing the
scan to the modules the Definition of done is stated over is what keeps it meaningful; widening it
would force the wrong assertion into three files and teach whoever hit that to widen the exemption.
"""

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

TESTS_ROOT = REPO_ROOT / "guardian" / "tests"
ADVERSARIAL_GLOB = "test_adversarial_*.py"

# The calls that make the full triple assertion. `assert_single_winner` and `assert_winner_count`
# are
# module-level wrappers that route every outcome of a concurrent race through assert_permitted or
# assert_denied, so a case using either makes the assertion for both sides rather than for the one
# it
# happened to look at; the first is the count-fixed-at-one form of the second (ADR-129's cap case).
TRIPLE_ASSERTION_CALLS = frozenset(
    {"assert_denied", "assert_permitted", "assert_single_winner", "assert_winner_count"}
)

# The five groups the M3 plan names. Listed so that a group file which disappears -- renamed,
# accidentally deleted, never written -- fails here rather than reducing the suite quietly.
EXPECTED_GROUP_MODULES = (
    "test_adversarial_a_authenticity.py",
    "test_adversarial_b_temporal.py",
    "test_adversarial_c_scope.py",
    "test_adversarial_d_replay.py",
    "test_adversarial_e_policy_integrity.py",
)


def _adversarial_modules() -> tuple[Path, ...]:
    """Every adversarial case module, in a stable order."""
    return tuple(sorted(TESTS_ROOT.glob(ADVERSARIAL_GLOB)))


def _called_names(function: ast.FunctionDef) -> set[str]:
    """Every attribute or plain name called anywhere inside ``function``."""
    names: set[str] = set()
    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue
        target = node.func
        if isinstance(target, ast.Attribute):
            names.add(target.attr)
        elif isinstance(target, ast.Name):
            names.add(target.id)
    return names


def _module_functions(module: Path) -> dict[str, ast.FunctionDef]:
    """Every top-level function in ``module``, keyed by name -- test cases and helpers alike."""
    tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
    return {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}


def _test_functions(module: Path) -> list[ast.FunctionDef]:
    """Every top-level ``test_*`` function in ``module``."""
    return [node for name, node in _module_functions(module).items() if name.startswith("test_")]


def _reachable_calls(
    function: ast.FunctionDef, module_functions: dict[str, ast.FunctionDef]
) -> set[str]:
    """Every name called by ``function``, following calls into helpers defined in the same module.

    A case that delegates to a local helper -- three group C cases share one, because the assertion
    is identical and only the field that steps outside the allow-claim differs -- must count as
    making the assertion the helper makes. Following the calls is the correct generalisation; adding
    the helper's own name to the allowed set would be a per-file exemption, and the next helper
    would need another.

    Resolution is a fixpoint over module-local functions only. It does not follow into
    ``harness.py``, which is why ``assert_single_winner`` is named in the allowed set explicitly.
    """
    seen: set[str] = set()
    pending = [function]
    names: set[str] = set()
    while pending:
        current = pending.pop()
        if current.name in seen:
            continue
        seen.add(current.name)
        for called in _called_names(current):
            names.add(called)
            local = module_functions.get(called)
            if local is not None:
                pending.append(local)
    return names


def test_every_adversarial_group_module_is_present() -> None:
    """All five groups A to E exist, and the scan below therefore covers all five."""
    found = {path.name for path in _adversarial_modules()}
    missing = [name for name in EXPECTED_GROUP_MODULES if name not in found]
    assert missing == [], (
        f"adversarial group module(s) missing: {missing}. The M3 plan's table names five groups "
        "and the Definition of done is stated over all of them"
    )


def test_the_scan_is_not_vacuous() -> None:
    """The scan reads real modules holding real cases, so a green result cannot mean "no files".

    The failure this guards against is the one that makes every other assertion in this module
    worthless: a glob that stops matching -- because a file was renamed, or the tests moved a
    directory -- turns a strict check into a silent pass.
    """
    modules = _adversarial_modules()
    assert len(modules) >= len(EXPECTED_GROUP_MODULES), [path.name for path in modules]
    total = sum(len(_test_functions(module)) for module in modules)
    assert total >= 30, f"only {total} adversarial case(s) found across {len(modules)} module(s)"


def test_every_adversarial_case_makes_the_full_triple_assertion() -> None:
    """No test function in a group module may reach the end without asserting all three.

    The mechanism. A case that submits a request and checks the response by hand -- which passes
    review, because it looks like a test -- fails here with its own name and line number.
    """
    offenders: list[str] = []
    for module in _adversarial_modules():
        module_functions = _module_functions(module)
        for function in _test_functions(module):
            reachable = _reachable_calls(function, module_functions)
            if not (reachable & TRIPLE_ASSERTION_CALLS):
                offenders.append(f"{module.name}::{function.name} (line {function.lineno})")

    assert offenders == [], (
        "adversarial case(s) that never make the triple assertion: "
        f"{offenders}\nEvery case asserts denied, with a structured reason code, and present in "
        f"the audit chain. Route it through one of {sorted(TRIPLE_ASSERTION_CALLS)}; a case that "
        "genuinely produces no audited decision is a finding and belongs in its own module, with "
        "the reason written down -- see test_audit_availability.py"
    )


def test_no_adversarial_case_reads_a_decision_without_asserting_it() -> None:
    """No group module touches ``CaseOutcome``'s private accessor, whatever it is called.

    Mechanism 2 with its back covered. ``CaseOutcome._decision`` exists for the concurrent case's
    sorting problem and is called from exactly one place inside ``harness.py``; a case module
    reaching for it directly would be a case module able to read an outcome without asserting one,
    which is the hole mechanisms 1 and 2 close.
    """
    offenders: list[str] = []
    for module in _adversarial_modules():
        for function in _test_functions(module):
            if "_decision" in _called_names(function):
                offenders.append(f"{module.name}::{function.name} (line {function.lineno})")
            for node in ast.walk(function):
                is_private_payload = isinstance(node, ast.Attribute) and node.attr in {
                    "_payload",
                    "_appended",
                    "_asserted",
                    "_report",
                }
                if is_private_payload:
                    offenders.append(f"{module.name}::{function.name} -> .{node.attr}")

    assert offenders == [], (
        f"adversarial case(s) reaching into CaseOutcome's internals: {offenders}. The public "
        "surface is assert_denied and assert_permitted, and record/result become readable only "
        "after one of them has run"
    )


# What "obviously synthetic" means, stated as a prefix a value must carry rather than left to
# judgement. This is not an exemption mechanism: a string that begins by declaring it is not a real
# credential is, by construction, not a real-looking credential. What the check refuses is a literal
# that *looks* like one and does not say so.
SYNTHETIC_MARKER = "NOT-A-REAL-"


# scrub_text picks its rule set from the field path: a path rooted at one of chain.py's
# IDENTIFIER_FIELDS gets the format rules only, and every other path additionally gets the two
# entropy heuristics. That distinction is exactly the one this scan needs. A credential *format* --
# a PEM block, a compact JWS, an Authorization header, a vendor prefix -- is a credential wherever
# it appears, docstring included. The entropy heuristics are a different kind of rule: they fire on
# any unbroken run of forty word characters, which in Python prose means every long test-function
# name a docstring happens to cite. So prose gets the format rules and values get both.
PROSE_FIELD_PATH = "policy_rule_id"
VALUE_FIELD_PATH = "suite-literal"


def _docstring_ids(tree: ast.Module) -> set[int]:
    """The ``id`` of every docstring constant node in ``tree``.

    A docstring is documentation rather than a value the suite uses, which is what licenses the
    narrower rule set above. It is *not* excluded from the scan.
    """
    found: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = getattr(node, "body", [])
        if not body or not isinstance(body[0], ast.Expr):
            continue
        first = body[0].value
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            found.add(id(first))
    return found


def _string_literals(module: Path) -> list[tuple[int, str, str]]:
    """Every string constant in ``module`` as ``(line, value, field path to scan it under)``."""
    tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
    docstrings = _docstring_ids(tree)
    return [
        (
            node.lineno,
            node.value,
            PROSE_FIELD_PATH if id(node) in docstrings else VALUE_FIELD_PATH,
        )
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]


def test_no_test_module_carries_a_real_looking_credential() -> None:
    """No string literal under ``guardian/tests/`` is shaped like a credential without saying so.

    ``pyproject.toml`` grants this directory ``S101`` and nothing else precisely because "the
    Guardian's adversarial suite is where a test fixture carrying a real-looking secret would be
    most tempting and most damaging". Ruff's ``S105``/``S106`` catch a literal assigned to a
    password-shaped *name*; this catches the complementary case, a literal with a credential *shape*
    under any name at all -- a PEM block, a compact JWS, an ``Authorization`` header, a vendor
    prefix like ``AKIA``/``sk-``/``ghp_``, or a high-entropy blob.

    The scan is over string constants rather than over raw source, which matters: running
    ``guardian/audit/chain.py``'s scrubber across a Python file flags every identifier longer than
    forty characters and every constant whose *name* contains "token", neither of which is a
    credential. Reading the literals is what makes the finding mean what it says.

    A hit is not a style point. A credential-shaped fixture value would be silently rewritten by the
    chain's pre-hash scrub, so a test comparing against it would be comparing against something
    other than what it wrote -- and, far worse, it is the shape a real key would take if one were
    ever pasted in.
    """
    from guardian.audit.chain import IDENTIFIER_FIELDS, scrub_text

    assert PROSE_FIELD_PATH in IDENTIFIER_FIELDS, (
        f"{PROSE_FIELD_PATH!r} is no longer one of chain.py's IDENTIFIER_FIELDS, so it no longer "
        "selects the format-only rule set and this scan is applying the wrong rules to prose"
    )
    assert VALUE_FIELD_PATH not in IDENTIFIER_FIELDS

    offenders: list[str] = []
    for module in sorted(TESTS_ROOT.glob("*.py")):
        for line_number, literal, field_path in _string_literals(module):
            if SYNTHETIC_MARKER in literal:
                continue
            if scrub_text(literal, field_path=field_path) != literal:
                offenders.append(f"{module.name}:{line_number}: {literal[:80]!r}")

    assert offenders == [], (
        f"credential-shaped string literal(s) in the suite's own source: {offenders}. Test signing "
        f"material must be obviously synthetic -- prefix it {SYNTHETIC_MARKER!r} -- and must not "
        "resemble any credential format; see guardian/tests/harness.py's SYNTHETIC_SIGNING_MATERIAL"
    )


def test_the_credential_shape_scan_is_not_vacuous() -> None:
    """The scanner really does fire on a credential shape, so a clean suite means something.

    Without this, a scrubber that had stopped matching anything -- a regex edited, a rule removed --
    would make the check above pass over a suite full of real keys. The probe strings never appear
    in the suite's own source; they are built here and discarded.
    """
    from guardian.audit.chain import scrub_text

    # Assembled from fragments that individually match nothing, so this module does not itself
    # contain a credential-shaped literal and does not need an exemption from its own scan. That is
    # not obfuscation for its own sake: a guard that has to be excused from the rule it enforces is
    # a guard with one hole already in it.
    dot = "."
    pem = "-----BEGIN RSA PRIVATE" + " KEY-----"
    header = "Authorization" + ":" + " Bearer " + "abcdefghijklmnop"
    compact_jws = "eyJhbGciOiJIUzI1NiJ9" + dot + "eyJzdWIiOiJ4In0" + dot + "c2ln"
    vendor = "AKIA" + "Q" * 16
    entropy = "d" * 48

    for probe in (pem, header, compact_jws, vendor, entropy):
        assert scrub_text(probe, field_path=VALUE_FIELD_PATH) != probe, probe
    for probe in (pem, header, compact_jws, vendor):
        assert scrub_text(probe, field_path=PROSE_FIELD_PATH) != probe, (
            f"{probe!r} is a credential format and must be caught in prose as well as in a value"
        )
    assert scrub_text(entropy, field_path=PROSE_FIELD_PATH) == entropy, (
        "the entropy heuristics are firing on prose, which is what makes every long test-function "
        "name in a docstring a false positive"
    )
    ordinary = "an ordinary sentence about pods"
    assert scrub_text(ordinary, field_path=VALUE_FIELD_PATH) == ordinary
