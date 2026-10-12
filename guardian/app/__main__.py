r"""``python -m guardian.app``: read the configuration, assemble a Guardian, serve it.

WHAT THIS MODULE IS, AND WHICH SENTENCE IT ANSWERS
----------------------------------------------------
``guardian/app/main.py`` closes with a section headed "WHAT IS NOT HERE, AND WHY THERE IS NO
MODULE-LEVEL ``app``", and it makes two claims. The first still holds and this module depends on it.
The second no longer does, and correcting it is part of this file's job.

*The claim that holds.* There is no ``app = create_app()`` at import time, because a module-level
application would have to read the environment while the module is being imported -- which would
make ``import guardian.app.main`` fail on any machine without a full Guardian configuration: CI's
lint job, a developer's editor, and the very test suite whose job is to check that a missing signing
key refuses to start. "The composition root is a function, and a server is pointed at it" is exactly
the arrangement here, one layer up: :func:`main` is a function, the configuration is read inside it,
and nothing happens at import.

*The claim that is now stale, and the correction.* That section also says there is "no default
composition root that assembles real collaborators, because three of the four do not exist yet: the
token service is M3-T3.3, the audit chain's writer is M3-T3.6, the policy bundle is M3-T3.2, and the
real executor is Tier B". **All four exist.** ``guardian/token/`` mints and verifies,
``guardian/audit/chain.py`` seals a hash chain, ``guardian/policies/`` holds the Rego bundle, and
:mod:`guardian.app.executor` holds the Kubernetes client behind a lazy import. The reasoning that
paragraph gives is untouched and is why :mod:`guardian.app.composition` is written the way it is:
"writing a ``create_default_app`` today would mean writing one that quietly substitutes fakes, which
is the one way this file could ship a Guardian that looks configured and enforces nothing." The
composition root inherits that constraint rather than escaping it -- every collaborator is built
from :class:`~guardian.app.config.GuardianConfig`, and which executor is assembled is a required
setting with no default. The owed edit is to ``main.py``'s prose, not to its design.

WHY THE SERVER IS IMPORTED INSIDE :func:`main` AND NOT AT MODULE LEVEL
------------------------------------------------------------------------
``import guardian.app.__main__`` must succeed on a machine with no ASGI server installed. That is
the same requirement ``main.py`` states for its own module, for the same three reasons -- a lint
job, an editor, and a test suite that needs to import this module to assert on it -- and it would be
defeated by a top-level ``import uvicorn``, which is not in the pinned runtime set that
``scripts/install_runtime_deps.sh`` installs for the Guardian's tests.

So the import is inside :func:`_serve`, reached only after a configuration has been read and a
Guardian assembled. A machine without the server package therefore gets a clear message naming the
package, at the moment somebody asked for a server, rather than an ``ImportError`` at the top of a
traceback in a job that was never going to serve anything.

The ordering has a second consequence worth having: a configuration error is reported *before* the
server package is looked for. An operator with a missing signing key and no ``uvicorn`` is told
about the signing key, which is the fault they can do something about.

EVERY STARTUP FAILURE EXITS NON-ZERO WITH THE MESSAGE INTACT
--------------------------------------------------------------
:class:`~guardian.app.config.GuardianStartupError`'s own docstring fixes what its catcher must do:
"the caller that catches it is the process entry point, and what it must do is exit non-zero with
the message intact rather than fall back to anything". This is that caller. Every subclass is caught
in one place -- :class:`~guardian.app.policy.PolicyBundleError` for a missing or unreadable bundle,
:class:`~guardian.app.opa.OpaBinaryUnavailable` for a missing engine,
:class:`~guardian.app.executor.ExecutorUnavailable` for a real executor that could not be built, and
the base class for a missing key, an unparseable number, an unrecognised arm and an unchosen
executor -- and each is written to stderr and answered with :data:`EXIT_STARTUP_FAILURE`.

The third of those was a plain ``RuntimeError`` until M4 and therefore escaped this catcher as a
traceback, which is what an operator got for starting a Guardian with the Kubernetes executor on a
host with no cluster credential -- a configuration fault reported as a crash, against the contract
this section states. It is a :class:`~guardian.app.config.GuardianStartupError` subclass
now, and nothing here changed: the enumeration above widened because the hierarchy did.

The message is written verbatim and is not wrapped, prefixed with a category, or summarised. Every
one of them was authored to name the offending key and the accepted set, because the person reading
it is by definition somebody whose runner flag did not do what they expected; re-writing it here
would replace the sentence that says which variable was wrong with one that says a Guardian failed
to start.

Nothing else is caught. A defect that is not a startup error is not something this module can make
safe, and a bare ``except Exception`` here would turn a stack trace an operator needs into an exit
code they cannot act on.
"""

import sys
from typing import Final

from guardian.app.composition import create_app_from_config
from guardian.app.config import GuardianConfig, GuardianStartupError

# The package a server is looked for in, named once so the refusal message and the import cannot
# disagree about what to install. Deliberately not a dependency of this repository's pinned runtime
# set: the Guardian's tests drive the ASGI application directly, which is the arrangement
# `guardian/tests/harness.py` argues for, so a server is a deployment concern rather than a
# development one.
SERVER_PACKAGE: Final = "uvicorn"

# The interface and port the container listens on. Bound to every interface because the process is a
# Pod behind a Service and a loopback bind would be a Guardian nothing could reach; the port matches
# `guardian/deploy/`'s. Neither is a security parameter -- the network boundary is Cilium's, in
# `infra/netpol/`, which is where the guardrail ablation's G2 arm moves it.
DEFAULT_HOST: Final = "0.0.0.0"  # noqa: S104 - a Pod listens on its Pod IP; see the comment above
DEFAULT_PORT: Final = 8080

EXIT_STARTUP_FAILURE: Final = 2


def main(argv: list[str] | None = None) -> int:
    """Read the configuration, assemble the Guardian, and serve it. Returns a process exit code.

    Returns rather than calls :func:`sys.exit`, so that the whole of this function is testable in
    process: a test can assert that a broken configuration yields
    :data:`EXIT_STARTUP_FAILURE` and that the message survived, without a subprocess and without
    catching ``SystemExit``. The ``sys.exit`` is at the bottom of the module, in the one place that
    is not reached under import.

    ``argv`` is accepted and deliberately unused. There is no command line: every input to a
    Guardian is an environment key that :class:`~guardian.app.config.GuardianConfig` reads, and a
    flag would be a second way to set something that already has exactly one home -- which for the
    condition arm in particular is the whole of ADR-023's isolation argument. The parameter exists
    so that the signature is the one a reader expects of an entry point, and so that a future
    subcommand is an edit here rather than a second entry point elsewhere.
    """
    del argv
    try:
        config = GuardianConfig.from_environment()
        app = create_app_from_config(config)
    except GuardianStartupError as error:
        # Verbatim, unwrapped. See the module docstring: every one of these messages names the
        # offending key and, where there is one, the accepted set.
        print(f"guardian: {error}", file=sys.stderr)
        return EXIT_STARTUP_FAILURE
    return _serve(app)


def _serve(app: object) -> int:
    """Run ``app`` under an ASGI server, or report that no server is installed.

    Separated from :func:`main` so that the import of the server package happens on one line that a
    reader can find, and so that a test can drive :func:`main`'s configuration handling without
    reaching a call that blocks forever.

    The absent-server case is a startup failure like any other and is reported the same way. It is
    not a :class:`~guardian.app.config.GuardianStartupError`, because the configuration was fine --
    what is missing is a package on the host -- and raising one would put a host-provisioning fault
    into the vocabulary an operator reads as "your runner flags are wrong".
    """
    try:
        import uvicorn
    except ImportError:
        print(
            f"guardian: the {SERVER_PACKAGE!r} package is not installed, so this Guardian cannot "
            "serve. The configuration was read and the application was assembled successfully; "
            "what is missing is a server on this host",
            file=sys.stderr,
        )
        return EXIT_STARTUP_FAILURE
    uvicorn.run(app, host=DEFAULT_HOST, port=DEFAULT_PORT)
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised by running the module, not by importing
    sys.exit(main(sys.argv[1:]))
