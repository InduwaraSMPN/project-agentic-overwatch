"""Two of rule 40's three enforcement layers, as tests: socket denial, and the dependency surface.

WHAT IS BEING ESTABLISHED, AND WHY A GREP CANNOT ESTABLISH IT
---------------------------------------------------------------
``docs/02-architecture.md`` section 1 types the Monitor ``deterministic, non-LLM``; FR1.4 requires
the property end to end; ADR-007 chose Falco over a model-based triage step precisely so that triage
costs zero inference. ``.agents/rules/40-monitor-non-llm.md`` names three enforcement layers, and
``scripts/monitor_guard.sh`` is the first of them. Its own header is honest about what it cannot
reach: its patterns are scoped to constructs that execute, so prose describing the constraint never
has to be reworded -- and the price of that scoping is that an obfuscated import, a URL assembled at
run time, or a client loaded through ``importlib`` walks past it. This file is layers two and three,
and it exists because of that gap rather than in spite of it.

LAYER TWO: SOCKET DENIAL, WHICH IS POSITIVE EVIDENCE RATHER THAN AN ABSENCE
-----------------------------------------------------------------------------
A grep can only report that it did not find something. Denying the socket layer and then replaying
the entire corpus successfully is a different kind of claim: whatever the aggregator did, it did
without opening a connection, and it did it for every fixture and every source family. An inference
call has to become a socket at some point, so a green replay under denial rules one out however the
client was imported.

**Which names are patched, and why each one is on the list.** The rule is to deny at every layer a
client could plausibly reach for, not only the lowest, so that a failure is attributable to this
test rather than to a timeout:

* ``socket.socket`` -- the constructor everything ends at. ``ssl`` does not open connections; it
  wraps a socket that already exists, so this covers every TLS path as well.
* ``socket.create_connection`` -- the convenience wrapper ``http.client`` uses. It calls
  ``socket.socket`` internally, but a caller that captured the module attribute earlier would not
  see the constructor patch, so it is denied in its own right.
* ``socket.socketpair`` -- a connected pair with no name lookup and no address, which is the one
  socket construction that does not pass through either of the two above.
* ``socket.getaddrinfo`` and ``socket.gethostbyname`` -- name resolution. A client typically
  resolves before it connects, and denying resolution makes the failure immediate and legible
  instead of a DNS timeout somebody would retry.
* ``http.client.HTTPConnection.connect`` and ``http.client.HTTPSConnection.connect`` -- the standard
  library's HTTP layer, which is what every third-party HTTP client in this ecosystem eventually
  calls into.
* ``urllib.request.urlopen`` -- the one-call form, which needs none of the above to be named at the
  call site.

**The denial is proved effective before it is relied on.** A test that patched something ineffective
and then reported a green replay would be evidence of nothing at all, so
:func:`test_the_denial_is_effective_before_anything_is_concluded_from_it` runs a control at each
layer and requires every one of them to raise. That control is the reason the replay result means
something.

LAYER THREE: THE DEPENDENCY SURFACE, DERIVED RATHER THAN LISTED
-----------------------------------------------------------------
The third layer catches the client that arrives in a pin nobody reads. It is derived from the
repository's own source of truth -- ``scripts/install_runtime_deps.sh``, which is what CI and a
developer both run, and ``infra/versions.env``, which ADR-021 makes the single pinning surface for
the evaluated artefact. Nothing here is a hardcoded copy of the dependency list, so the assertion
cannot go stale the way a copy would: adding a dependency to the installer is what changes what this
test reads.

**Honest scope, stated rather than implied: this covers direct pins and not transitive pulls.** A
package pinned here could itself depend on an inference client, and neither this test nor
``monitor_guard.sh`` would see it. Closing that would mean resolving the full dependency tree, which
needs either a lock file this repository does not keep or a network call this file exists to forbid.
The socket-denial layer above is what covers the transitive case in practice: a transitively
installed client still has to open a connection to be an inference call.

A note for whoever adds the first agent-layer dependency at M4: this test reads the *installer*,
which installs into one interpreter. An inference SDK pinned there would be importable by the
Monitor even though it was pinned for another component, so this test would go red -- correctly. The
answer at that point is to split the installer per component, not to narrow this assertion.
"""

import re
import socket
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from monitor.tests.replay_harness import discover, nanosecond_counter, replay  # noqa: E402

INSTALLER = REPO_ROOT / "scripts" / "install_runtime_deps.sh"
VERSIONS_ENV = REPO_ROOT / "infra" / "versions.env"

# The distribution names of the provider SDKs, inference frameworks and local model runtimes rule 40
# excludes, as bare lower-case tokens. The same family list scripts/monitor_guard.sh's first pattern
# carries, kept as data here rather than as a regular expression because this layer matches package
# and pin names rather than source lines. A token is matched as a substring of a lower-cased
# name, so a distribution that merely wraps one -- a `-client` or `-sdk` suffix -- is caught too.
INFERENCE_DISTRIBUTIONS = (
    "openai",
    "anthropic",
    "litellm",
    "langchain",
    "langgraph",
    "mistralai",
    "groq",
    "cohere",
    "ollama",
    "transformers",
    "vllm",
    "huggingface",
    "llama_cpp",
    "llamacpp",
    "sentence_transformers",
)

# `read_pin KEY` is how the installer names a pin it will read out of infra/versions.env.
_PIN_KEY = re.compile(r"^\s*read_pin\s+([A-Z][A-Z0-9_]*)\s*$", re.MULTILINE)

# The package the installer names, in `<name>==$<variable>` form.
#
# The pattern was `'"([A-Za-z0-9][A-Za-z0-9._-]*)==\$'` while the installer handed exactly one
# literal to pip. M3 made it component-aware, so packages are now accumulated into a variable and
# the name no longer sits immediately after an opening quote. The old pattern matched nothing, and
# `test_the_pinned_runtime_dependency_set_is_derivable_and_not_empty` caught it — which is the
# entire reason that vacuous-pass guard exists, and evidence that a derived assertion needs one.
#
# The leading character class is `[A-Za-z]` rather than `[A-Za-z0-9]` deliberately. The installer's
# verification helper is called with a positional expansion whose text reads `$1==$3`, and a
# pattern admitting a leading digit would capture `1` from it as a package name — an assertion
# quietly made about a string that is not a package. Requiring a letter first excludes it without a
# lookbehind that would have to be reasoned about every time this file is read.
_PIP_PACKAGE = re.compile(r"([A-Za-z][A-Za-z0-9._-]*)==\$")

# infra/versions.env is values-only by its own contract: one `KEY=value` per line.
_VERSIONS_ENV_LINE = re.compile(r"^([A-Z][A-Z0-9_]*)=(.*)$", re.MULTILINE)

# One arm of the installer's per-component `case` statement: everything between `<component>)` and
# the `;;` that closes it.
#
# WHY THE DERIVATION IS NOW SCOPED TO A COMPONENT, AND WHY THAT IS NOT A HOLE IN RULE 40
# Until M4 the installer served two components and neither declared an inference client, so reading
# the whole file and reading the Monitor's arm gave the same answer. M4 added `agents`, which
# declares LangGraph and LiteLLM by ADR-002 and ADR-005, and the whole-file derivation then reported
# them as the Monitor's dependencies. They are not: `sh scripts/install_runtime_deps.sh monitor`
# installs pydantic and nothing else, and the arm below is the installer's own statement of that.
#
# The narrowing is deliberate, it is recorded in ADR-033 as rule 40 requires of exactly this
# situation -- "a genuine false positive is an ADR at the milestone that produces it" -- and it is
# built so that it cannot become vacuous. `test_the_component_scoping_is_real_and_not_a_blind_spot`
# below asserts that the whole-file derivation DOES contain an inference client while the Monitor's
# arm does not: if the pattern ever stopped matching, or if somebody moved LiteLLM into the
# Monitor's arm, one of those two halves fails.
#
# WHAT THIS LAYER DOES NOT CLAIM, STATED HERE RATHER THAN LEFT TO BE INFERRED
# This is a check on the Monitor's DECLARED dependency set, which is the scope the module docstring
# already fixes for it ("direct pins, not transitive pulls"). It is not a claim about which packages
# happen to be importable in a shared interpreter: `.github/workflows/ci.yml` installs every
# component into one interpreter and then runs each suite in it, so LiteLLM is importable while the
# Monitor's suite runs. What covers that is the other two layers, which are about behaviour rather
# than declaration -- the socket denial in this file, and the `sys.modules` sweep after a replay --
# and they are why rule 40 asks for three checks and not one. ADR-033 records the residual.
_COMPONENT_ARM = r"^\s*{component}\)\s*$(.*?)^\s*;;\s*$"

CORPUS = discover()


class InferenceDenied(AssertionError):
    """Raised by every patched network entry point. An ``AssertionError`` on purpose.

    A client that caught ``OSError`` and fell back to a second transport would swallow a
    connection error and this file would report a green replay over a run that had tried to reach
    the network. ``AssertionError`` is not in the exception family a network client catches, so a
    denied call propagates out of the replay and fails the test that made it.
    """


@pytest.fixture
def denied_network(monkeypatch: pytest.MonkeyPatch) -> tuple[str, ...]:
    """Deny every network entry point named in the module docstring; return what was patched."""
    import http.client
    import urllib.request

    def deny(*args: object, **kwargs: object) -> object:
        raise InferenceDenied(
            "the Monitor opened a network connection during a fixture replay. It is "
            "deterministic and non-LLM by architecture (02-architecture.md section 1, FR1.4) and "
            "its triage costs zero inference by decision (ADR-007); a replay reads fixtures and "
            f"writes events, and opens nothing. Call was {args!r} {kwargs!r}."
        )

    patched: list[str] = []
    for name in (
        "socket",
        "create_connection",
        "socketpair",
        "getaddrinfo",
        "gethostbyname",
    ):
        monkeypatch.setattr(socket, name, deny)
        patched.append(f"socket.{name}")
    for connection in (http.client.HTTPConnection, http.client.HTTPSConnection):
        monkeypatch.setattr(connection, "connect", deny)
        patched.append(f"http.client.{connection.__name__}.connect")
    monkeypatch.setattr(urllib.request, "urlopen", deny)
    patched.append("urllib.request.urlopen")
    return tuple(patched)


def test_the_denial_is_effective_before_anything_is_concluded_from_it(
    denied_network: tuple[str, ...],
) -> None:
    """Every patched entry point raises. Without this, a green replay would prove nothing.

    The control is the whole reason the replay below is evidence: a patch applied to the wrong name,
    or to a module the client does not use, would leave the network open and the replay green, and
    the two outcomes are indistinguishable in a pass line.
    """
    import http.client
    import urllib.request

    assert len(denied_network) == 8, denied_network

    with pytest.raises(InferenceDenied):
        socket.socket()
    with pytest.raises(InferenceDenied):
        socket.create_connection(("127.0.0.1", 9))
    with pytest.raises(InferenceDenied):
        socket.socketpair()
    with pytest.raises(InferenceDenied):
        socket.getaddrinfo("localhost", 80)
    with pytest.raises(InferenceDenied):
        socket.gethostbyname("localhost")
    with pytest.raises(InferenceDenied):
        http.client.HTTPConnection("127.0.0.1", 9).connect()
    with pytest.raises(InferenceDenied):
        http.client.HTTPSConnection("127.0.0.1", 9).connect()
    with pytest.raises(InferenceDenied):
        urllib.request.urlopen("http://127.0.0.1:9/")


def test_the_whole_corpus_replays_with_the_network_denied(
    denied_network: tuple[str, ...], tmp_path
) -> None:
    """Every fixture, every source family, replayed with no way to reach the network.

    The full corpus rather than a sample: the four normalisers are separate modules and a client
    could live in any one of them, so a replay that covered three families would establish the
    property for three. The events are compared against their golden streams as well, so the run is
    not merely completing -- it is producing the same evidence it produces with the network up,
    which rules out a code path that degrades quietly when a connection fails.
    """
    assert CORPUS, "an empty corpus would make this file green having replayed nothing"
    assert denied_network
    for spec in CORPUS:
        out_dir = tmp_path / spec.fixture_id
        events = replay(spec, out_dir=out_dir, clock=nanosecond_counter())
        assert events, spec.fixture_id
        assert (out_dir / "monitor_events.jsonl").read_bytes() == spec.golden_path.read_bytes(), (
            spec.fixture_id
        )


def test_no_inference_client_is_imported_by_a_replay(tmp_path) -> None:
    """Replaying the corpus imports no new inference client into ``sys.modules``.

    Complementary to the socket denial rather than a repeat of it. Denial catches a client that
    tries to connect; this catches one that was imported and did not -- a client constructed behind
    a cached response, a stubbed transport, or a lazy import that had not fired yet. Neither test
    subsumes the other, and both are cheap.
    """
    loaded_before = {name.split(".")[0].lower() for name in sys.modules}
    for spec in CORPUS:
        replay(spec, out_dir=tmp_path / spec.fixture_id, clock=nanosecond_counter())
    loaded_after = {name.split(".")[0].lower() for name in sys.modules}
    newly_loaded = loaded_after - loaded_before
    offenders = sorted(
        name for name in newly_loaded for token in INFERENCE_DISTRIBUTIONS if token in name
    )
    assert not offenders, (
        f"replaying the fixture corpus imported {offenders}. The Monitor is non-LLM by "
        "architecture; a client imported during a replay is one call away from being made."
    )


def _installer_text(component: str | None) -> str:
    """Return the installer's whole text, or the arm of its ``case`` that ``component`` names.

    Raises rather than returning an empty string when a named component has no arm, because an
    empty derivation is exactly the vacuous pass every guard in this repository refuses: an
    assertion over nothing passes, and it would pass loudest at the moment the installer's shape
    changed underneath it.
    """
    text = INSTALLER.read_text(encoding="utf-8")
    if component is None:
        return text
    match = re.search(
        _COMPONENT_ARM.format(component=re.escape(component)),
        text,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(
            f"{INSTALLER.name} declares no `{component})` arm in its per-component case statement. "
            "Either the component was renamed or the installer's shape changed; in both cases the "
            "assertions below would otherwise be made over an empty set."
        )
    return match.group(1)


def read_pinned_runtime_dependencies(
    component: str | None = None,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return ``(pin keys, package names)`` as the installer itself declares them.

    Derived from ``scripts/install_runtime_deps.sh`` rather than copied, so that adding a runtime
    dependency is what changes what the assertions below read. The two halves are both taken because
    they can disagree: a pin key read but never installed, or a package installed from a variable no
    ``read_pin`` produced, are each a defect the installer's own header warns about.

    ``component`` scopes the derivation to one arm of the installer's ``case`` statement. ``None``
    reads the whole file, which is what the two assertions about pin resolution want -- every key
    the installer can read must exist and carry a value, whichever component reads it.
    """
    text = _installer_text(component)
    return tuple(_PIN_KEY.findall(text)), tuple(_PIP_PACKAGE.findall(text))


def test_the_pinned_runtime_dependency_set_is_derivable_and_not_empty() -> None:
    """The derivation finds something, so the assertions built on it are not vacuous.

    An installer whose shape changed -- a different helper name, a different pip invocation -- would
    otherwise silently yield an empty set, and every assertion over that set would pass. This is the
    same vacuous-pass discipline the shell gates apply to an empty corpus.
    """
    keys, packages = read_pinned_runtime_dependencies()
    assert keys, f"{INSTALLER} declares no pin keys; the derivation below would assert nothing"
    assert packages, f"{INSTALLER} installs no package; the derivation below would assert nothing"


def test_every_pinned_runtime_dependency_resolves_to_a_populated_key() -> None:
    """Each key the installer reads exists in ``infra/versions.env`` and carries a value.

    An unpinned runtime dependency resolves to whatever the index serves that day, so two campaigns
    weeks apart would validate their events against different code while recording the same
    ``versions_env_sha256`` digest in every sealed bundle. The installer refuses an empty pin at run
    time; this fails at review time instead.
    """
    keys, _ = read_pinned_runtime_dependencies()
    pins = dict(_VERSIONS_ENV_LINE.findall(VERSIONS_ENV.read_text(encoding="utf-8")))
    for key in keys:
        assert key in pins, f"{key} is read by the installer but absent from {VERSIONS_ENV.name}"
        assert pins[key].strip(), f"{key} is present but empty in {VERSIONS_ENV.name}"


def test_the_monitor_component_declares_a_dependency_set_at_all() -> None:
    """The Monitor's arm of the installer is non-empty, so the assertion below is not vacuous.

    The same discipline the whole-file guard above applies, at the narrower scope: a `case` arm that
    stopped matching would yield an empty set, and every assertion over an empty set passes.
    """
    keys, packages = read_pinned_runtime_dependencies("monitor")
    assert keys, "the installer's monitor arm reads no pin key"
    assert packages, "the installer's monitor arm installs no package"


def test_the_pinned_runtime_dependency_set_holds_no_inference_client() -> None:
    """Rule 40's third layer: nothing an inference call needs is declared for this component.

    Checked over both the package names and the pin key names, because the two can differ and a
    dependency added under an unfamiliar distribution name would still be pinned under a key a
    reader recognises. See the module docstring for the honest scope: direct pins, not
    transitive pulls.

    Scoped to the Monitor's own arm of the installer since M4, which added an ``agents`` component
    declaring LangGraph and LiteLLM. The scoping is argued beside :data:`_COMPONENT_ARM` and
    recorded in ADR-033; the test below is what keeps it from becoming a blind spot.
    """
    keys, packages = read_pinned_runtime_dependencies("monitor")
    offenders = sorted(
        name
        for name in (*packages, *keys)
        for token in INFERENCE_DISTRIBUTIONS
        if token in name.lower()
    )
    assert not offenders, (
        f"{INSTALLER.name} installs {offenders} for the monitor component. The Monitor is non-LLM "
        "by architecture (02-architecture.md section 1, FR1.4) and by decision (ADR-007); rule 40 "
        "forbids the client being present, not merely being called. If the dependency belongs to "
        "another component, declare it in that component's arm rather than narrowing this "
        "assertion further."
    )


def test_the_component_scoping_is_real_and_not_a_blind_spot() -> None:
    """The narrowing above is load-bearing only if the wider set actually differs from it.

    Two halves, and each catches a different way the scoping could stop meaning anything. If the
    repository as a whole declared no inference client, the assertion above would be passing for a
    reason that has nothing to do with the Monitor -- and the day one was added it would be the
    first time the scoping was exercised. And if ``_COMPONENT_ARM`` silently matched the whole file,
    the two derivations would be equal and the narrowing would be undone without anybody editing an
    assertion.

    So: the repository declares at least one inference client somewhere, the Monitor's arm declares
    none, and the two derivations are not the same set.
    """
    _, all_packages = read_pinned_runtime_dependencies()
    _, monitor_packages = read_pinned_runtime_dependencies("monitor")

    elsewhere = sorted(
        name for name in all_packages for token in INFERENCE_DISTRIBUTIONS if token in name.lower()
    )
    assert elsewhere, (
        "no component declares an inference client anywhere in the installer, so the assertion "
        "above is scoped for a situation that does not exist. Either M4's agents component was "
        "removed, or the derivation stopped matching -- and in the second case the assertion above "
        "is now passing over an empty set for the wrong reason"
    )
    assert set(monitor_packages) < set(all_packages), (
        "the monitor arm and the whole file derive the same package set, so the component scoping "
        "matched everything and the narrowing has quietly been undone"
    )
