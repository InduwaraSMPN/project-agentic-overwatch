r"""The real policy engine: the pinned ``opa`` binary, one evaluation per subprocess, fail-closed.

WHAT THIS MODULE IS
-------------------
``guardian/app/policy.py`` declares :class:`~guardian.app.policy.PolicyEngine` -- "one question, one
answer, one bound" -- and deliberately implements nothing behind it except
:class:`~guardian.app.policy.UnavailablePolicyEngine`, which has no permit path at all. That was the
correct state while T3.2 owned the transport choice and nothing had been chosen. This module is the
choice: ``opa eval``, run as a subprocess against the loaded bundle directory, with its JSON parsed
into the three-key result the entrypoints already emit.

It is the only file in ``guardian/app/`` that starts a process, and that is why the whole of the
next section exists.

WHY A SUBPROCESS, AND WHY ADR-026 PREDICTED THIS FILE
------------------------------------------------------
Three transports were available and each was considered against one question: what does a Guardian
do when the policy engine is not there?

*A sidecar over HTTP* is OPA's usual production shape and is the one this module does **not** take.
It adds a second process with its own lifecycle, its own port, its own readiness semantics and its
own failure modes, all of which have to be right before a single policy is evaluated -- and it makes
"which bytes did the engine actually load" a question about a running service rather than about a
directory this Guardian hashed at start. ADR-023's isolation assertion rests on
:attr:`~guardian.app.policy.PolicyBundle.digest` being a statement about what is evaluated; a
long-lived server that loaded its bundle once, elsewhere, weakens that into a statement about what
was handed to something at some point.

*An in-process evaluator* would mean a Rego implementation inside this Guardian's own interpreter.
There is no such thing in the pinned runtime set, adding one would be adding a second Rego semantics
alongside the ``opa`` binary ``scripts/guardian_test.sh`` tests the bundle with, and the two would
diverge in exactly the cases nobody wrote a test for -- which is the defect
``.agents/rules/00-source-of-truth.md`` exists to prevent, arriving in the component least able to
afford it.

*A subprocess per evaluation* is what is here. It costs a process spawn on the enforcement path, it
is the slowest of the three, and it buys the property the other two do not have: the bytes evaluated
are the bytes at :attr:`~guardian.app.policy.PolicyBundle.path`, read fresh by the same binary the
policy gate tests them with, with no intermediate that could be holding an older copy. The cost is
bounded by ``evaluation_timeout_seconds``, which
:func:`~guardian.app.policy.evaluate_policy` enforces from the caller's side as well as passing to
this engine -- so a spawn that hangs is a denial rather than a hang.

**ADR-026 predicted this file by name.** Its Log records that ruff's ``S`` rules were enabled early,
with the reasoning that "nothing under ``runner/`` exists yet" and that what a later milestone
inherits "is a rule that is already on, so its decision is about how to satisfy S603/S607 rather
than about whether to look". It then says the thing worth quoting here: a subprocess on the
enforcement path is *precisely a finding worth reading*. This module is the first one, and it is
answered rather than suppressed:

- **S607, a partial executable path.** :func:`resolve_opa_binary` resolves the binary to an absolute
  path with :func:`shutil.which` and refuses to build an engine when it cannot -- so the argv never
  carries a bare program name and there is no ``PATH`` lookup at call time.
- **S603, untrusted input to a subprocess.** The argv is built entirely from values fixed at start:
  the resolved binary, the bundle directory the Guardian loaded and digested, and the entrypoint
  from :class:`~guardian.app.config.GuardianConfig`. **No element of it is derived from a request.**
  The input document -- the one thing an attacker influences -- is written to the child's *stdin*,
  never to its command line, so there is no argument through which a crafted namespace or
  justification could reach the process table, a shell, or an argument parser. ``shell=False`` is
  the default and is passed explicitly anyway, because the default is the thing that would change
  silently. A ``# noqa: S603`` remains on the call, because ruff cannot see any of the above; it
  carries the reason, which is what ADR-026 asks a suppression to do.

FAILING CLOSED IS THIS FILE'S ONLY CONTRACT, AND IT HAS EXACTLY TWO EXCEPTIONS TO RAISE
----------------------------------------------------------------------------------------
``guardian/app/policy.py`` fixes what an engine may do when it cannot answer, and the shape of
:func:`~guardian.app.policy.evaluate_policy` is what this module is written against:
:class:`~guardian.app.policy.PolicyEngineTimeout` and
:class:`~guardian.app.policy.PolicyEngineUnavailable` are caught by name and become
:attr:`~guardian.app.models.ReasonCode.POLICY_ENGINE_TIMEOUT` and
:attr:`~guardian.app.models.ReasonCode.POLICY_ENGINE_UNAVAILABLE`; anything else is caught by a
bare ``except Exception`` and denies under the second of those. So an engine that raised something
else would still fail closed -- but it would be *indistinguishable in the audit log* from an outage,
and the whole reason group E carries three separate codes is that an outage, an overrun and an
unreadable answer want different explanations months later when a campaign is being read.

So :meth:`OpaSubprocessEngine.evaluate` raises those two and nothing else. A missing binary, a
non-zero exit, output that is not JSON, output whose shape this module does not recognise, an
``OSError`` from the spawn itself: every one is caught here and re-raised as
:class:`~guardian.app.policy.PolicyEngineUnavailable`. It **never returns a default**, which is the
one thing :class:`~guardian.app.policy.PolicyEngine`'s docstring forbids outright -- a value that
means "I could not evaluate" and is shaped like a decision is the only way an outage becomes a
permit, and no care at the call site can recover a lie told at this boundary.

It also never returns a decision of its own. :func:`parse_opa_eval_output` extracts the entrypoint's
result object out of ``opa eval``'s envelope and hands it on **unread**; whether that object means
permit, explicit deny or deny-by-default is :func:`~guardian.app.policy.interpret_policy_result`'s,
and a second reading here would be a second place the engine and the Guardian can disagree.

WHERE THE BINARY COMES FROM, AND WHY THE RULE IS ``scripts/guardian_test.sh``'S
--------------------------------------------------------------------------------
The gate script resolves ``opa`` in a fixed order -- an explicit ``OPA_BIN`` override first, then
``opa`` on ``PATH`` -- and falls back to fetching and checksum-verifying the pinned release into a
cache. :func:`resolve_opa_binary` reuses the first two rules verbatim and does **not** reuse the
third. A reference monitor that downloaded an executable at start, on the enforcement path, to
acquire the thing that decides its permits, would be doing at run time what ADR-025 deliberately
confined to a gate script that verifies a digest before trusting a byte. The Guardian's answer to a
missing engine is to refuse to start, which is loud at the only moment it is still cheap -- and
which is exactly what :class:`~guardian.app.policy.PolicyBundleError` already does for a missing
bundle, for the same reason.

The override is spelled ``OPA_BIN`` because that is what the gate spells it, and one name is worth
more than a tidier one: an operator who has pointed the gate at a particular binary has pointed this
Guardian at the same one, and a second variable would be a way for the two to disagree about which
engine the policy was tested with. It is read from the environment rather than added to
:class:`~guardian.app.config.GuardianConfig`, and that is deliberate: every field of that class is a
value the *runner* chooses per run, while this is a property of the machine -- the same value for
every arm, every run and every condition on one host. Adding a key there would invite a campaign
manifest to set it, which is the beginning of two arms evaluating with two engines.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
Every permit and every deny in a campaign, and the meaning of every group E reason code in a sealed
bundle. ``scripts/guardian_test.sh`` tests the bundle with the same binary this evaluates it with,
so a divergence between the two is a divergence between what was tested and what ran.
"""

import json
import os
import shutil
import subprocess  # noqa: S404 - the module docstring's ADR-026 section answers this one at length
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

from guardian.app.config import GuardianStartupError
from guardian.app.policy import (
    PolicyBundle,
    PolicyEngineTimeout,
    PolicyEngineUnavailable,
)

# The environment variable ``scripts/guardian_test.sh`` reads to be pointed at a particular binary,
# reused here rather than given a second name. See the module docstring.
OPA_BINARY_ENV_VAR: Final = "OPA_BIN"

# The program name looked up on PATH when no override is set. Resolved to an absolute path before it
# ever reaches an argv, which is half of the S607 answer.
OPA_PROGRAM_NAME: Final = "opa"

# `opa eval` wraps every answer in {"result": [{"expressions": [{"value": ...}]}]}. The three keys
# are named rather than written at the point of use so that a change in the envelope is one edit,
# and so that the parser reads as the shape it is walking.
EVAL_RESULT_KEY: Final = "result"
EVAL_EXPRESSIONS_KEY: Final = "expressions"
EVAL_VALUE_KEY: Final = "value"

# What the child is asked for. `--format json` fixes the envelope above; `--fail` makes an undefined
# result a non-zero exit rather than an empty envelope this module would have to interpret; `--stdin
# -input` is what keeps the attacker-influenced document off the command line; `--bundle` points at
# the directory the Guardian already hashed.
_FORMAT_FLAG: Final = "--format"
_FORMAT_VALUE: Final = "json"
_FAIL_FLAG: Final = "--fail"
_STDIN_INPUT_FLAG: Final = "--stdin-input"
_BUNDLE_FLAG: Final = "--bundle"


class OpaBinaryUnavailable(GuardianStartupError):
    """No usable ``opa`` binary could be found, so this Guardian must not start.

    A :class:`~guardian.app.config.GuardianStartupError` subclass for the reason
    :class:`~guardian.app.policy.PolicyBundleError` is one: the caller that handles it is the
    process entry point, what it must do is exit non-zero with the message intact, and a distinct
    name lets the composition root say *which* half of the policy path was unusable without parsing
    a message.

    Refusing to start is the deliberate answer, and the alternative looks safer than it is. A
    Guardian that started with no engine would deny every action -- fail-closed in the narrow sense
    and catastrophic in the wide one, because a whole campaign of denials would be produced, every
    run bundle would validate, every record would be honest, and nothing anywhere would say that the
    policy the study is about was never evaluated.
    """


def resolve_opa_binary(environ: Mapping[str, str] | None = None) -> Path:
    """Return the absolute path of the ``opa`` binary, or raise :class:`OpaBinaryUnavailable`.

    ``scripts/guardian_test.sh``'s resolution order, minus its fetch-and-verify fallback: an
    explicit :data:`OPA_BINARY_ENV_VAR` override wins, and otherwise :data:`OPA_PROGRAM_NAME` is
    looked up on ``PATH``. The module docstring argues why the fallback is not reused and why the
    override shares the gate's spelling.

    The result is always absolute and always resolved, which is the whole of the S607 answer: the
    argv this module builds names a file rather than a program, so nothing about the child process
    depends on what ``PATH`` says at the moment a request arrives. An override that names a file
    which does not exist, or which is a directory, is refused here rather than at the first
    evaluation -- a Guardian whose engine cannot be started has no correct behaviour available to it
    and the only safe thing a reference monitor can do in that position is not run.

    ``environ`` is injectable so that the refusal path is testable without mutating the process
    environment, which is global and shared with every other test in a session.
    """
    source = os.environ if environ is None else environ
    override = source.get(OPA_BINARY_ENV_VAR)
    if override is not None and override.strip():
        candidate = Path(override.strip())
        located = shutil.which(str(candidate))
        if located is None:
            raise OpaBinaryUnavailable(
                f"{OPA_BINARY_ENV_VAR}={override!r} is not an executable file. It is the same "
                "variable scripts/guardian_test.sh reads, so the Guardian and its policy gate are "
                "pointed at one engine or at none"
            )
        return Path(located).resolve()

    located = shutil.which(OPA_PROGRAM_NAME)
    if located is None:
        raise OpaBinaryUnavailable(
            f"no {OPA_PROGRAM_NAME!r} on PATH and {OPA_BINARY_ENV_VAR} is unset, so no policy "
            "engine can be started. The Guardian does not start without one: a process that "
            "loaded a bundle it could never evaluate would deny an entire campaign while every "
            "record it wrote looked correct. Install the version infra/versions.env pins, or set "
            f"{OPA_BINARY_ENV_VAR} to it"
        )
    return Path(located).resolve()


def parse_opa_eval_output(raw: str) -> Any:
    """Return the entrypoint's result object out of ``opa eval --format json``'s envelope.

    Total over the shapes a subprocess can hand back, and it raises exactly one exception type --
    :class:`~guardian.app.policy.PolicyEngineUnavailable` -- because that is what the contract in
    ``guardian/app/policy.py`` reads. Anything it cannot walk is an engine that did not answer:
    empty output, output that is not JSON, output that is JSON but not the envelope, an envelope
    with no bindings, and an envelope carrying more than one.

    The multiple-result case deserves its own sentence, because rejecting it looks pedantic and is
    not. ``opa eval`` returns one entry per *binding set*, and an entrypoint that produced two
    would be an entrypoint whose answer is ambiguous -- and picking the first would be this module
    resolving a policy ambiguity by position in an array. A Guardian that cannot tell which answer
    it was given has not been given one.

    The extracted value is returned **unread**. Whether it means permit is
    :func:`~guardian.app.policy.interpret_policy_result`'s question, and it is strict enough to
    refuse anything it does not recognise, so nothing is gained by this function forming an opinion
    and a second opinion is exactly what would let the two disagree.
    """
    text = raw.strip()
    if not text:
        raise PolicyEngineUnavailable("opa eval produced no output")
    try:
        envelope = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as error:
        raise PolicyEngineUnavailable("opa eval output is not JSON") from error
    if not isinstance(envelope, Mapping):
        raise PolicyEngineUnavailable("opa eval output is not a JSON object")
    results = envelope.get(EVAL_RESULT_KEY)
    if not isinstance(results, list) or len(results) != 1:
        raise PolicyEngineUnavailable(
            "opa eval returned no single result binding; an entrypoint whose answer is ambiguous "
            "has not answered"
        )
    expressions = results[0].get(EVAL_EXPRESSIONS_KEY) if isinstance(results[0], Mapping) else None
    if not isinstance(expressions, list) or len(expressions) != 1:
        raise PolicyEngineUnavailable("opa eval returned no single expression value")
    first = expressions[0]
    if not isinstance(first, Mapping) or EVAL_VALUE_KEY not in first:
        raise PolicyEngineUnavailable("opa eval returned an expression carrying no value")
    return first[EVAL_VALUE_KEY]


class OpaSubprocessEngine:
    """One ``opa eval`` per question, against one bundle and one entrypoint.

    Construction takes the loaded :class:`~guardian.app.policy.PolicyBundle` rather than a path, so
    the directory this engine evaluates is by construction the directory whose digest ADR-023's
    isolation assertion compares -- there is no second path to keep in step and no way to point the
    two at different places. The ``entrypoint`` is a constructor argument rather than being read off
    the bundle, because the Guardian asks this bundle two different questions: which action may
    proceed, and which capability may be minted. Two engines over one bundle is the shape that
    keeps the digest a statement about all of the policy.

    ``binary`` is resolved once, at construction, and is absolute. The resolution rule and its two
    ruff findings are the module docstring's subject.

    The engine is stateless between calls and holds no process open. That is deliberate rather than
    an omission: a long-lived child would hold a bundle in memory and turn
    :attr:`~guardian.app.policy.PolicyBundle.digest` back into a statement about what was loaded at
    some earlier point, which is the property the sidecar transport was rejected for lacking.
    """

    def __init__(self, *, bundle: PolicyBundle, entrypoint: str, binary: Path) -> None:
        self._bundle = bundle
        self._entrypoint = entrypoint
        self._binary = Path(binary)
        self._argv: tuple[str, ...] = (
            str(self._binary),
            "eval",
            _FORMAT_FLAG,
            _FORMAT_VALUE,
            _FAIL_FLAG,
            _STDIN_INPUT_FLAG,
            _BUNDLE_FLAG,
            str(self._bundle.path),
            self._entrypoint,
        )

    @property
    def argv(self) -> tuple[str, ...]:
        """The exact command line, fixed at construction and carrying nothing from any request.

        Published so that a test can assert the property the S603 suppression rests on -- that no
        element of the argv is derived from request data -- rather than reading the constructor and
        taking its word for it.
        """
        return self._argv

    def evaluate(self, document: Mapping[str, Any], *, timeout_seconds: float) -> Any:
        """Evaluate the entrypoint against ``document``. Raises the two contract exceptions only.

        The document is serialised and written to the child's **stdin**. It is the one input an
        attacker influences and it never touches the command line; see the module docstring's
        ADR-026 section for the whole of that argument.

        ``default=str`` is passed to the serialiser because the document carries closed-vocabulary
        values -- :class:`~guardian.app.models.Phase` in particular -- that are ``str`` subclasses
        and serialise natively, plus paths and enums a future field might add. A serialisation that
        raised would otherwise become an ordinary ``Exception`` on the enforcement path, and
        ``guardian/app/policy.py``'s wrapper would record it as a generic engine outage rather than
        as the Guardian fault it is.

        Every failure below becomes :class:`~guardian.app.policy.PolicyEngineUnavailable` or
        :class:`~guardian.app.policy.PolicyEngineTimeout`, and there is no path to a returned value
        that did not come out of the child's stdout.
        """
        try:
            payload = json.dumps(dict(document), default=str)
        except (TypeError, ValueError) as error:
            raise PolicyEngineUnavailable(
                "the policy input document is not serialisable"
            ) from error

        try:
            completed = subprocess.run(  # noqa: S603 - argv is fixed at construction; the one
                # attacker-influenced value is the document, and it reaches the child on stdin
                # rather than on the command line. See the module docstring's ADR-026 section.
                self._argv,
                input=payload,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout_seconds,
                shell=False,
            )
        except subprocess.TimeoutExpired as error:
            raise PolicyEngineTimeout(
                f"opa eval did not answer within {timeout_seconds}s"
            ) from error
        except OSError as error:
            raise PolicyEngineUnavailable("opa eval could not be started") from error

        if completed.returncode != 0:
            # Deliberately without the child's stderr in the message. It is an external process's
            # own text about a document an attacker influenced, and `guardian/app/policy.py` already
            # refuses to put an engine's message into a reason code for exactly that reason. A
            # non-zero exit here is `--fail` firing on an undefined entrypoint, a bundle that will
            # not compile, or a binary that is not the engine it claims to be -- all outages.
            raise PolicyEngineUnavailable(f"opa eval exited {completed.returncode}")
        return parse_opa_eval_output(completed.stdout)
