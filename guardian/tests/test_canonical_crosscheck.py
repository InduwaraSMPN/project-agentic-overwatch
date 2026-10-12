r"""ADR-022's cross-check, run by pytest instead of by hand.

WHY THIS FILE IS THREE LINES OF LOGIC AND A LONG EXPLANATION
--------------------------------------------------------------
``guardian/audit/crosscheck.py`` already implements the whole check. It was written as a
``python -m`` runnable because ``guardian/tests/`` did not exist when it landed, and a check that
runs only when somebody remembers to type it is a check that stops running. This module wraps it so
that CI's ``Unit tests -- guardian`` step carries it, and it **imports and calls** the existing
functions rather than restating any of them -- a second implementation of a conformance check is
the same defect the check exists to prevent, arriving one level up.

WHAT THE CROSS-CHECK IS FOR
---------------------------
ADR-022 records a cost it could not design away. This repository holds **two** implementations of
one canonical-JSON rule: ``monitor/aggregator/models.py``'s, written at M2 for the event stream, and
``guardian/audit/canonical.py``'s, added at M3 for the audit chain. Importing one into the other is
not available -- ``02-architecture.md`` section 5 ships the aggregator inside the in-cluster Monitor
and the Guardian as its own service, and a security-critical hash whose definition depends on
another component's module makes the Guardian's audit integrity a function of what the Monitor image
happens to contain.

So the resolution is one rule stated once, two implementations, and a cross-check proving they agree
byte for byte on a shared fixture. Drift then fails CI rather than diverging silently -- which
matters because the failure mode is delayed and misleading: ``make audit-verify`` runs at M7's daily
QA and again at M9's clean-checkout reproduction, so a definition that has quietly become two
definitions surfaces as **a false tamper alarm months later, on correct data**.

ADR-022 also records what the cross-check does *not* buy, and it is worth repeating here rather than
leaving in the ADR: it covers only the inputs the shared fixture contains. Two implementations can
agree on every value in a fixture and disagree on one nobody thought to put in it -- a lone
surrogate, a very large integer, a key differing only by Unicode normalisation form. Widening the
fixture is the only mitigation and it is a mitigation rather than a proof.

THE ONE THING THIS WRAPPER ADDS
---------------------------------
``crosscheck.main()`` treats an unimportable ``monitor`` package as a *skip* and prints a note
saying so -- correct behaviour inside the Guardian container, which ships without the aggregator by
design. In this repository it is not correct: both packages are present in the checkout, so a skip
would mean the interpreter or the checkout is wrong, and a green CI step that silently checked one
implementation against nothing is exactly the shape of evidence this milestone exists to refuse.
:func:`test_the_monitor_agreement_half_actually_runs_in_this_repository` turns that skip into a
failure here, and keeps the module's own tolerance for the container case intact.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from guardian.audit.canonical import CANONICAL_JSON_RULE_ID  # noqa: E402
from guardian.audit.crosscheck import (  # noqa: E402
    VECTORS_PATH,
    check_crosscheck,
    check_rejections,
    check_vectors,
    load_vectors,
)


def test_the_frozen_vectors_match_their_committed_bytes_and_digests() -> None:
    """Every vector canonicalises to the committed bytes and hashes to the committed digest.

    The half of the contract that does not depend on the Monitor existing: this implementation still
    produces what it produced when the fixture was frozen. ``load_vectors`` additionally refuses a
    fixture frozen under a different rule id, so a regenerated corpus is a deliberate reviewed diff
    rather than something that quietly starts agreeing with whatever the code now does.
    """
    problems: list[str] = []
    vectors = load_vectors()
    assert vectors, f"{VECTORS_PATH} carries no vectors"
    checked = check_vectors(vectors, problems)
    assert problems == [], problems
    assert checked == len(vectors)


def test_every_uncanonicalisable_value_is_refused_with_its_path_named() -> None:
    """NaN, the infinities, non-string keys, sets, bytes and cycles: refused, not mangled.

    ``guardian/audit/crosscheck.py`` puts the argument in one sentence and it is the right one -- "a
    mangle that hashes is worse than one that raises". A serialiser that coerced a set to a list or
    an integer key to a string would produce bytes, and those bytes would go into a hash chain, and
    the record would then be a faithful hash of something other than what the Guardian meant.
    """
    problems: list[str] = []
    checked = check_rejections(problems)
    assert problems == [], problems
    assert checked > 0


def test_the_two_implementations_of_one_rule_agree_byte_for_byte() -> None:
    """The Guardian's canonicalisation and the Monitor's produce the same bytes on every vector.

    ADR-022's actual cross-check. The two differ in framing by one trailing newline -- the Monitor's
    form is a ``.jsonl`` line and the Guardian's digest is taken over the unframed bytes -- and
    ``check_crosscheck`` asserts that the framing difference is exactly that and nothing more, so a
    change in framing has to be deliberate and reviewed rather than absorbed.
    """
    problems: list[str] = []
    vectors = load_vectors()
    checked = check_crosscheck(vectors, problems)
    assert problems == [], problems
    assert checked == len(vectors), f"the cross-check compared {checked} of {len(vectors)} vectors"


def test_the_monitor_agreement_half_actually_runs_in_this_repository() -> None:
    """A skipped cross-check is a failure *here*, whatever it means inside the container.

    See the module docstring. ``check_crosscheck`` returns ``None`` when ``monitor`` is not
    importable, which is normal in the Guardian's own image and abnormal in a checkout that holds
    both packages. Without this assertion the test above would pass vacuously on a broken
    ``sys.path`` -- comparing one implementation against nothing and reporting success.
    """
    outcome = check_crosscheck(load_vectors(), [])
    assert outcome is not None, (
        "monitor.aggregator.models is not importable, so the cross-check compared nothing. In this "
        "repository that means the checkout or the interpreter is wrong, not that the two "
        "implementations agree"
    )
    assert CANONICAL_JSON_RULE_ID
