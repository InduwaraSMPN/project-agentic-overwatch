r"""The composition root under test: what a Guardian refuses to start without, and what it wires.

WHY THIS MODULE EXISTS, AND WHY TWO LIVE FILES ALREADY CITE IT
---------------------------------------------------------------
``guardian/app/composition.py`` is the one place the Guardian's halves are joined, and ADR-030
records the defect it closes: until M4 the *only* description anywhere of how those halves fit was
``guardian/tests/harness.py``, a composition root living in a test suite. The failure mode that
follows is the one this whole component is designed against, because it is silent -- the seam can be
right in the suite and wrong in the deployed process, and five hundred green adversarial cases would
go on passing over a wiring nothing ships.

So the adversarial suite moving to *consume* the production root is the fix, and this module is what
stops the fix from being a claim. Two live files name it by path and say what it discharges:

- ``guardian/tests/harness.py``'s docstring: "``guardian/tests/test_composition.py`` closes the
  remaining distance in the one way that does not create a second policy: where the pinned ``opa``
  binary can be located, it drives the **real** engine over the **real** bundle, and where it cannot
  it skips with a named reason."
- ``guardian/tests/test_token_issuance_exposure.py``'s docstring: what ``authority.rego`` declares
  is checked by ``opa test``, "and ``guardian/tests/test_composition.py`` drives the real engine
  over the real bundle where the pinned binary can be found."

A citation to a file that does not exist is worse than no citation, because it reads in review as
evidence that somebody checked. Everything those two sentences promise is below.

WHAT IS PINNED HERE, AND WHAT WOULD OTHERWISE FAIL SILENTLY
--------------------------------------------------------------
*A Guardian that cannot find a required setting does not start, and says which one.* Four refusals
-- a missing signing key, an unreadable policy bundle, an unrecognised arm, an unchosen executor --
and every case asserts the **message names the offending key**, not merely that something raised.
:class:`~guardian.app.config.GuardianStartupError`'s own docstring fixes that obligation ("every
message names the offending key and, where there is one, the accepted set") for a concrete reason:
the person reading it is by definition somebody whose runner flag did not do what they expected, and
"invalid configuration" sends them to read a module instead of fixing a variable. A test that
asserted only ``pytest.raises`` would pass on a Guardian that refused with an empty string.

*No default substitutes a fake.* ``guardian/app/main.py``'s refusal to ship a composition root said
why: one that "quietly substitutes fakes" is "the one way this file could ship a Guardian that looks
configured and enforces nothing". That is the most expensive failure this component can have --
every artefact well-formed, every record honest, a campaign scored months later against a cluster
nothing ever touched. So the checks below are about *absence*: exactly two settings carry a default,
:class:`~guardian.app.config.ExecutorKind` is not one of them, and ``FakeActionExecutor`` is
reachable from exactly one function in the composition root, guarded by a value an operator wrote
down.

*The five keyword seams default to the real collaborator.* They exist so the adversarial suite can
drive *this* assembly with a canned policy answer rather than assembling a parallel one, and the
distinction that makes them safe is that a double is reachable only by a caller that names one. So:
every seam's default is ``None``; a Guardian built with none of them mints on the wall clock, with a
fresh nonce per mint and a live replay cache; and one built with no engine seam and no locatable
``opa`` raises :class:`~guardian.app.opa.OpaBinaryUnavailable` rather than substituting anything.

*The entry point exits non-zero with the message intact.* ``guardian/app/__main__.py`` says a test
should be able to establish that "without a subprocess and without catching ``SystemExit``", which
is why :func:`~guardian.app.__main__.main` returns a code rather than calling :func:`sys.exit`.
Below it is called in process, twice, on two different broken configurations.

*The shipped bundle's digest is one value.* ADR-023's machine proof that the guardrail arms cannot
be reached through policy, asserted over ``guardian/policies/`` itself rather than over a stand-in,
and extended with the property ADR-031 rests on: the authority half ships in the **same** directory,
so one sha256 covers the whole policy. A second bundle would have left half of it outside the proof.

*The real engine, over the real bundle.* Everywhere else in this suite the policy engine is a
scripted double, deliberately: ``guardian/app/policy.py`` refuses to implement a decision procedure
in Python "for the tests", because two policies diverge and nobody notices until an evaluation
depends on it. That restraint leaves exactly one gap -- nothing in pytest ever runs the Rego the
campaign ships. These cases close it without opening the hole, by running the pinned binary itself.

*The harness consumes this root rather than duplicating it.* The AST check that makes ADR-030's
inversion permanent: a future harness that re-assembled a ``Mediator`` by hand would restore the
two-descriptions-of-one-seam defect, and it would do so while every case in the suite stayed green.

WHY THE OPA CASES SKIP RATHER THAN BEING WRITTEN AROUND
---------------------------------------------------------
``opa`` is a binary rather than a Python package, so it is not in the pinned runtime set
``scripts/install_runtime_deps.sh`` installs and it is not on every development host.
``scripts/guardian_test.sh`` is the gate that acquires it -- ADR-025 confines the fetch-and-checksum
to that script rather than to a Guardian at start, because a reference monitor that downloaded the
thing deciding its permits would be doing at run time what the ADR keeps in a reviewed script -- and
``OPA_BIN`` points both the gate and this Guardian at one binary.

So the cases that need it are **real tests that skip**, never tests that pass vacuously: each one
resolves the binary first and skips naming the gate and the override, and everything after that
point drives the shipped bundle for real. The skip style is
``harness.shipped_policy_bundle``'s, and the reason is the same one: a check that quietly degrades
into a weaker check is indistinguishable, in a log, from the check it replaced.
"""

import ast
import inspect
import json
import os
import re
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402
from guardian.app.__main__ import EXIT_STARTUP_FAILURE, main  # noqa: E402
from guardian.app.composition import (  # noqa: E402
    ISSUE_AUTHORITY_EXCEEDED,
    JTI_PREFIX,
    AssembledGuardian,
    build_executor,
    build_guardian,
)
from guardian.app.config import (  # noqa: E402
    AUDIT_SIGNING_KEY_FILE_ENV_VAR,
    ENV_PREFIX,
    EXECUTOR_ENV_VAR,
    MODE_ENV_VAR,
    POLICY_BUNDLE_PATH_ENV_VAR,
    SIGNING_KEY_ENV_VAR,
    SIGNING_KEY_FILE_ENV_VAR,
    ExecutorKind,
    GuardianConfig,
    GuardianStartupError,
)
from guardian.app.main import ACTIONS_PATH, TOKENS_PATH  # noqa: E402
from guardian.app.mediation import FakeActionExecutor  # noqa: E402
from guardian.app.models import (  # noqa: E402
    ACTION_REQUEST_SCHEMA_VERSION,
    TOKEN_ISSUE_SCHEMA_VERSION,
    AuditRecord,
    GuardianMode,
    ReasonCode,
)
from guardian.app.opa import (  # noqa: E402
    OPA_BINARY_ENV_VAR,
    OPA_PROGRAM_NAME,
    OpaBinaryUnavailable,
    resolve_opa_binary,
)
from guardian.app.policy import (  # noqa: E402
    PolicyBundle,
    PolicyBundleError,
    PolicyEngineSettings,
)
from guardian.audit.chain import (  # noqa: E402
    HASH_FIELD,
    SIGNATURE_FIELD,
    ChainStateError,
    read_chain,
)
from guardian.audit.record_types import is_execution, is_run_start  # noqa: E402
from guardian.audit.verify import ChainReport, verify_chain  # noqa: E402
from guardian.tests.harness import (  # noqa: E402
    CONTROL_PLANE_BEARER,
    DEFAULT_ALLOW,
    EXECUTOR_ID,
    ISSUANCE_PERMIT_RULE_ID,
    NAMESPACE,
    PHASE,
    RUN_ID,
    SUITE_POLICY_TIMEOUT_SECONDS,
    SUPERVISOR_ID,
    SYNTHETIC_SIGNING_MATERIAL,
    CaseOutcome,
    FakeControlPlaneAuthenticator,
    ScriptedPolicyEngine,
    SuiteClock,
    call_asgi,
    guardian_environment,
    make_harness,
    permit_result,
    shipped_policy_bundle,
    write_policy_bundle,
)
from guardian.token.verifier import AllowClaim  # noqa: E402

# --------------------------------------------------------------------------------------------
# Where the two files under scrutiny live
# --------------------------------------------------------------------------------------------

COMPOSITION_SOURCE = REPO_ROOT / "guardian" / "app" / "composition.py"
HARNESS_SOURCE = REPO_ROOT / "guardian" / "tests" / "harness.py"

# The arms this Guardian implements, in ADR-023's order. G3-UNQUOTED is absent for the reason
# test_flag_isolation.py gives: it is the Monitor's aggregator-quoting flag and nothing in this
# process can produce it.
ARMS = (GuardianMode.G0_FULL, GuardianMode.G1_LOGONLY, GuardianMode.G2_SHAREDCRED)

# The two rules the shipped bundle answers with, spelled as `guardian/policies/` declares them.
# Written as constants here rather than read out of the bundle: a value derived from the artefact
# under test would agree with it by construction, and the point of naming them is that a bundle
# which renamed either fails here instead of quietly answering under a new identifier.
SHIPPED_ENTRYPOINT = "data.guardian.decision"
SHIPPED_ISSUANCE_ENTRYPOINT = "data.guardian.issuance.decision"

# `guardian.rego`'s permit_scope_match -- the only permit that bundle can produce.
SHIPPED_PERMIT_RULE_ID = "guardian:permit:capability-scope-match"

# Every .rego file the shipped bundle must carry into the digest. `authority.rego` and
# `issuance.rego` are the two that matter to ADR-031: they ship beside the action rules rather than
# in a bundle of their own, so one sha256 describes the whole policy.
SHIPPED_BUNDLE_FILES = (
    "authority.rego",
    "guardian.rego",
    "issuance.rego",
    "scope.rego",
)

# The names a composition root of one's own would have to import. `guardian/tests/harness.py` must
# import none of them: it declares doubles and identities, and gets its wiring from
# `guardian.app.composition`. `ReplayCache` is deliberately absent from this list -- it is one of
# the five published seams, and the harness supplying a small one is the seams working as intended.
HAND_ASSEMBLY_NAMES = frozenset(
    {
        "AuditChainSink",
        "AuditChainWriter",
        "AuthorityBoundedTokenIssuer",
        "CapabilityTokenIssuerAdapter",
        "CapabilityTokenVerifierAdapter",
        "FakeActionExecutor",
        "KubernetesActionExecutor",
        "Mediator",
        "SystemClock",
        "create_app",
    }
)

# The seven keyword seams `build_guardian` publishes, by name. The sixth is ADR-128's
# `control_plane_authenticator` and the seventh is ADR-129's `action_caps`; the module docstring's
# "each default is the real collaborator" claim is asserted over the set rather than over a count,
# so
# an eighth has to be justified here too.
SEAM_NAMES = frozenset(
    {
        "policy_engine",
        "issuance_engine",
        "clock",
        "replay_cache",
        "action_caps",
        "jti_factory",
        "control_plane_authenticator",
    }
)

HTTP_OK = 200
HTTP_FORBIDDEN = 403

# A sha256 as PolicyBundle.digest renders one.
DIGEST_PATTERN = r"[0-9a-f]{64}"


# --------------------------------------------------------------------------------------------
# Construction helpers
#
# These do not duplicate `GuardianHarness`; they are what is left when it cannot be used. The
# harness assembles a *stand-in* bundle and hands `build_guardian` a scripted engine for each of the
# two questions, by construction -- which is exactly what the cases below have to do without, since
# what they are about is either the defaults themselves or the shipped Rego. Everything the harness
# can still supply is taken from it: the identities, the environment mapping, the ASGI driver, the
# frozen clock, the scripted engines, and `CaseOutcome`, so that a case here owes the same three
# assertions as every adversarial case rather than a weaker pair.
# --------------------------------------------------------------------------------------------


def _environment(root: Path, bundle_path: Path) -> dict[str, str]:
    """The runner-supplied start-time keys for a Guardian rooted at ``root``."""
    return guardian_environment(
        mode=GuardianMode.G0_FULL,
        run_id=RUN_ID,
        registered_issuers=(SUPERVISOR_ID,),
        bundle_path=bundle_path,
        audit_log_path=root / "guardian_audit.jsonl",
    )


def _stand_in_config(root: Path) -> GuardianConfig:
    """A complete configuration over the stand-in bundle, for cases that script both engines."""
    return GuardianConfig.from_mapping(_environment(root, write_policy_bundle(root / "policies")))


def _shipped_config(root: Path) -> GuardianConfig:
    """A complete configuration over the bundle ``guardian/policies/`` actually ships."""
    return GuardianConfig.from_mapping(_environment(root, shipped_policy_bundle()))


def _opa_binary_or_skip() -> Path:
    """The resolved ``opa`` binary, or skip naming the gate that acquires it.

    ``harness.shipped_policy_bundle``'s shape, and its reason: what is unavailable here is a
    property of the machine rather than of the repository, and a case that quietly weakened itself
    into passing without the engine would be indistinguishable in a log from one that ran it.
    """
    try:
        return resolve_opa_binary()
    except OpaBinaryUnavailable as unavailable:
        pytest.skip(
            f"no usable {OPA_PROGRAM_NAME!r} engine on this host: {unavailable}. "
            "`sh scripts/guardian_test.sh` is the gate that acquires it -- ADR-025 keeps the "
            "fetch-and-checksum in that script rather than in a Guardian at start -- and the "
            f"{OPA_BINARY_ENV_VAR} environment variable overrides where it is looked for, with "
            "the spelling the gate uses so the two cannot be pointed at different engines. "
            "Everything below this line drives the shipped bundle for real; nothing about it "
            "degrades into a weaker check when the binary is absent"
        )


def _records(path: Path) -> list[AuditRecord]:
    """Every well-formed decision record in the chain at ``path``, validated as an ``AuditRecord``.

    The run-start genesis (ADR-058) is not a decision and is left out by its ``record_type``, as
    ``GuardianHarness.records`` leaves it out, so "the records this request appended" keeps its
    meaning. The ADR-082 execution follow-up is excluded the same way: a v4 Guardian appends one per
    decision, and it would not validate against ``AuditRecord`` in any case (its own ``record_type``
    is not ``"decision"``).
    """
    if not path.exists():
        return []
    return [
        AuditRecord.model_validate(parsed.record)
        for parsed in read_chain(path)
        if parsed.defect is None
        and not is_run_start(parsed.record)
        and not is_execution(parsed.record)
    ]


def _verify(assembled: AssembledGuardian) -> ChainReport:
    """Verify this Guardian's chain with the writer's live head as the anchor."""
    path = assembled.audit_sink.path
    if not path.exists():
        return verify_chain([], path=str(path))
    return verify_chain(
        read_chain(path),
        expected_head=assembled.audit_sink.writer.head,
        path=str(path),
        anchor_source="writer-head",
    )


def _submit(assembled: AssembledGuardian, body: Mapping[str, Any], *, label: str) -> CaseOutcome:
    """POST one action and capture everything the triple assertion needs to check."""
    path = assembled.audit_sink.path
    before = len(_records(path))
    status, payload = call_asgi(assembled.app, ACTIONS_PATH, json.dumps(dict(body)).encode("utf-8"))
    after = _records(path)
    return CaseOutcome(
        label=label,
        status=status,
        payload=payload,
        appended=after[before:],
        report=_verify(assembled),
    )


def _mint(assembled: AssembledGuardian, *, allow: AllowClaim = DEFAULT_ALLOW) -> str:
    """Mint through the Guardian's own issuer, reached rather than rebuilt.

    ``token_issuer.inner.issuer`` is the object the composition root put behind its two wrappers. A
    second issuer built here from the same configuration would be a second object that could drift
    from the one this Guardian verifies against.
    """
    return assembled.token_issuer.inner.issuer.issue(
        issuer_id=SUPERVISOR_ID,
        subject_id=EXECUTOR_ID,
        run_id=RUN_ID,
        phase=PHASE,
        allow=allow,
        ttl_seconds=None,
    ).encoded


def _action_body(
    *,
    token: str,
    request_id: str,
    verb: str = "get",
    resource: str = "pods",
    namespace: str = NAMESPACE,
    name: str | None = None,
) -> dict[str, Any]:
    """The wire form of one ``ActionRequest`` v2, agreeing with what :func:`_mint` mints."""
    return {
        "request_id": request_id,
        "run_id": RUN_ID,
        "executor_id": EXECUTOR_ID,
        "phase": PHASE,
        "token": token,
        "action": {
            "verb": verb,
            "resource": resource,
            "namespace": namespace,
            "name": name,
            "params": {},
        },
        "justification": "reading pod state to establish which replicas are unhealthy",
        "schema_version": ACTION_REQUEST_SCHEMA_VERSION,
    }


def _issue_body(**overrides: object) -> dict[str, object]:
    """A well-formed ``POST /v1/tokens`` body, with any field replaced."""
    body: dict[str, object] = {
        "supervisor_id": SUPERVISOR_ID,
        "executor_id": EXECUTOR_ID,
        "run_id": RUN_ID,
        "phase": PHASE,
        "allow": DEFAULT_ALLOW.as_mapping(),
        "ttl_seconds": None,
        "schema_version": TOKEN_ISSUE_SCHEMA_VERSION,
    }
    body.update(overrides)
    return body


# --------------------------------------------------------------------------------------------
# 1 -- a Guardian missing something it needs does not start, and says which thing
# --------------------------------------------------------------------------------------------


def test_a_guardian_that_cannot_find_its_signing_key_does_not_start(tmp_path: Path) -> None:
    """Four ways to have no signing key, each a refusal whose message names the variable.

    ``guardian/app/config.py`` states the property this checks: "there is no development key, no
    example key and no empty-string fallback in this repository, because a Guardian that starts with
    a known key is a Guardian whose tokens anyone can mint." The blank cases matter as much as the
    absent one -- an empty signing key would verify nothing while looking configured, which is the
    worst of the three available outcomes.

    Each case asserts the *message*, not merely that something raised. A refusal nobody can act on
    is a refusal that costs an operator the afternoon the structured message was written to save.
    """
    base = _environment(tmp_path, write_policy_bundle(tmp_path / "policies"))

    absent = {key: value for key, value in base.items() if key != SIGNING_KEY_ENV_VAR}
    blank = dict(base, **{SIGNING_KEY_ENV_VAR: "   "})

    missing_file = tmp_path / "not-mounted-here"
    from_missing_file = dict(absent, **{SIGNING_KEY_FILE_ENV_VAR: str(missing_file)})

    empty_file = tmp_path / "mounted-but-empty"
    empty_file.write_text("\n", encoding="utf-8")
    from_empty_file = dict(absent, **{SIGNING_KEY_FILE_ENV_VAR: str(empty_file)})

    cases = (
        ("no key variable at all", absent, (SIGNING_KEY_ENV_VAR, SIGNING_KEY_FILE_ENV_VAR)),
        ("a blank inline value", blank, (SIGNING_KEY_ENV_VAR, SIGNING_KEY_FILE_ENV_VAR)),
        ("a mount path that is not there", from_missing_file, (SIGNING_KEY_FILE_ENV_VAR,)),
        ("a mount that is present and empty", from_empty_file, (SIGNING_KEY_FILE_ENV_VAR,)),
    )
    for label, environment, named in cases:
        with pytest.raises(GuardianStartupError) as error:
            GuardianConfig.from_mapping(environment)
        message = str(error.value)
        for variable in named:
            assert variable in message, (
                f"{label}: the refusal does not name {variable}. GuardianStartupError's contract "
                "is that every message names the offending key, because the person reading it is "
                f"by definition somebody whose flag did not do what they expected: {message!r}"
            )


def _write_ed25519_key(path: Path) -> object:
    """Write a fresh Ed25519 private key PEM (a test key, generated in tmp) and return its public
    key.

    Generated per test, never a repository key and never the Guardian's own -- rule 10 forbids
    copying a real signing key into a test; an ephemeral key made here holds nothing.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return key.public_key()


def test_the_audit_signing_key_is_optional_read_and_fails_closed_when_named(tmp_path: Path) -> None:
    """ADR-130: absent is an unsigned chain; named-but-unreadable is a refusal, never a silent
    unsign.

    The absent reading is the pre-M10/offline default and is deliberately safe. The set-but-missing
    and set-but-empty readings are refusals whose message names the variable, on config.py's rule
    that a Guardian told to sign that cannot must not start while looking configured.
    """
    base = _environment(tmp_path, write_policy_bundle(tmp_path / "policies"))
    assert GuardianConfig.from_mapping(base).audit_signing_key_file is None

    key_pem = tmp_path / "audit-key.pem"
    _write_ed25519_key(key_pem)
    present = dict(base, **{AUDIT_SIGNING_KEY_FILE_ENV_VAR: str(key_pem)})
    assert GuardianConfig.from_mapping(present).audit_signing_key_file == key_pem

    missing = dict(base, **{AUDIT_SIGNING_KEY_FILE_ENV_VAR: str(tmp_path / "not-mounted.pem")})
    with pytest.raises(GuardianStartupError, match=AUDIT_SIGNING_KEY_FILE_ENV_VAR):
        GuardianConfig.from_mapping(missing)

    empty = tmp_path / "empty.pem"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(GuardianStartupError, match=AUDIT_SIGNING_KEY_FILE_ENV_VAR):
        GuardianConfig.from_mapping(dict(base, **{AUDIT_SIGNING_KEY_FILE_ENV_VAR: str(empty)}))


def test_a_guardian_with_an_audit_key_signs_every_record_and_without_one_does_not(
    tmp_path: Path,
) -> None:
    """ADR-130: an Ed25519 key makes every appended record carry a signature over its hash.

    The signed arm verifies each record's stored signature against the public key, and that a
    tampered hash no longer verifies -- the whole-chain-rewrite forgery the unsigned chain cannot
    detect. The unsigned arm (the default config) carries no signature field at all, so the two
    paths are the opt-in ADR-130 describes rather than a behaviour change forced on every caller.
    """
    from cryptography.exceptions import InvalidSignature

    signed_root = tmp_path / "signed"
    key_pem = signed_root / "audit-key.pem"
    public_key = _write_ed25519_key(key_pem)
    signed_env = dict(
        _environment(signed_root, write_policy_bundle(signed_root / "policies")),
        **{AUDIT_SIGNING_KEY_FILE_ENV_VAR: str(key_pem)},
    )
    signed = build_guardian(
        GuardianConfig.from_mapping(signed_env),
        policy_engine=ScriptedPolicyEngine(),
        issuance_engine=ScriptedPolicyEngine(permit_result(ISSUANCE_PERMIT_RULE_ID)),
        clock=SuiteClock(),
    )
    _submit(
        signed, _action_body(token=_mint(signed), request_id="req-signed"), label="signed"
    ).assert_permitted()
    signed_records = [
        json.loads(line)
        for line in signed.audit_sink.path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert signed_records, "the signed chain is empty"
    for record in signed_records:
        assert SIGNATURE_FIELD in record, f"a record carries no signature: seq {record.get('seq')}"
        public_key.verify(  # type: ignore[attr-defined]
            bytes.fromhex(record[SIGNATURE_FIELD]), record[HASH_FIELD].encode("ascii")
        )
    with pytest.raises(InvalidSignature):
        public_key.verify(  # type: ignore[attr-defined]
            bytes.fromhex(signed_records[0][SIGNATURE_FIELD]), b"0" * 64
        )

    unsigned = build_guardian(
        _stand_in_config(tmp_path / "unsigned"),
        policy_engine=ScriptedPolicyEngine(),
        issuance_engine=ScriptedPolicyEngine(permit_result(ISSUANCE_PERMIT_RULE_ID)),
        clock=SuiteClock(),
    )
    _submit(
        unsigned, _action_body(token=_mint(unsigned), request_id="req-unsigned"), label="unsigned"
    ).assert_permitted()
    unsigned_records = [
        json.loads(line)
        for line in unsigned.audit_sink.path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert unsigned_records
    for record in unsigned_records:
        assert SIGNATURE_FIELD not in record, "the default config wrote a signature; it must not"


def test_a_guardian_whose_policy_bundle_is_unusable_does_not_start(tmp_path: Path) -> None:
    """Absent, present-but-empty, and not-a-directory: three refusals, each naming the path.

    Raised by :meth:`~guardian.app.policy.PolicyBundle.load`, which
    :func:`~guardian.app.composition.build_guardian` calls **first** -- before the engines, before
    the token service, before the sink -- so a Guardian with no policy refuses while somebody is
    watching rather than after a campaign of requests.

    :class:`~guardian.app.policy.PolicyBundleError` is a
    :class:`~guardian.app.config.GuardianStartupError`, which is what makes the entry point handle
    it identically to a missing key; that relationship is asserted here rather than read off the
    class statement, because it is the whole reason one ``except`` clause suffices in
    ``guardian/app/__main__.py``.
    """
    assert issubclass(PolicyBundleError, GuardianStartupError), (
        "PolicyBundleError is no longer a startup error, so guardian/app/__main__.py's single "
        "except clause no longer catches it and a missing bundle would exit with a traceback "
        "instead of the exit code and message an operator can act on"
    )

    absent = tmp_path / "no-bundle-here"
    empty = tmp_path / "bundle-with-no-policy"
    empty.mkdir()
    (empty / "README.txt").write_text("not a policy\n", encoding="utf-8")
    not_a_directory = tmp_path / "bundle-that-is-one-file.rego"
    not_a_directory.write_text("package guardian_tests_not_a_bundle\n", encoding="utf-8")

    base = _environment(tmp_path, write_policy_bundle(tmp_path / "policies"))
    cases = (
        (absent, "does not exist"),
        (empty, ".rego"),
        (not_a_directory, "not a directory"),
    )
    for path, fragment in cases:
        config = GuardianConfig.from_mapping(dict(base, **{POLICY_BUNDLE_PATH_ENV_VAR: str(path)}))
        with pytest.raises(PolicyBundleError) as error:
            build_guardian(config)
        message = str(error.value)
        assert path.name in message, (
            f"the refusal for {path.name!r} does not name the path it could not load: {message!r}"
        )
        assert fragment in message, (
            f"the refusal for {path.name!r} does not say which of the three bundle faults happened "
            f"(expected {fragment!r}): {message!r}"
        )


def test_an_unrecognised_arm_and_an_unchosen_executor_both_refuse_to_start(
    tmp_path: Path,
) -> None:
    """The other two startup refusals, each naming its variable and the accepted set.

    The arm and the executor fail closed in different directions and both are checked here for one
    reason: they are the two settings whose silent fallback would produce a *well-formed* campaign
    measuring something other than its label. A misspelled arm would give ``G0-FULL`` records filed
    as ``G1-LOGONLY``; an absent executor defaulted to the fake would give a run of ``executed``
    records against a cluster nothing touched.
    """
    base = _environment(tmp_path, write_policy_bundle(tmp_path / "policies"))

    with pytest.raises(GuardianStartupError) as arm_error:
        GuardianConfig.from_mapping(dict(base, **{MODE_ENV_VAR: "G3-UNQUOTED"}))
    arm_message = str(arm_error.value)
    assert MODE_ENV_VAR in arm_message, arm_message
    for arm in ARMS:
        assert arm.value in arm_message, (
            f"the refusal does not name the accepted arm {arm.value!r}: {arm_message!r}"
        )

    unchosen = {key: value for key, value in base.items() if key != EXECUTOR_ENV_VAR}
    with pytest.raises(GuardianStartupError) as unchosen_error:
        GuardianConfig.from_mapping(unchosen)
    unchosen_message = str(unchosen_error.value)
    assert EXECUTOR_ENV_VAR in unchosen_message, unchosen_message

    with pytest.raises(GuardianStartupError) as unknown_error:
        GuardianConfig.from_mapping(dict(base, **{EXECUTOR_ENV_VAR: "kubernetes-ish"}))
    unknown_message = str(unknown_error.value)
    assert EXECUTOR_ENV_VAR in unknown_message, unknown_message
    for kind in ExecutorKind:
        assert kind.value in unknown_message, (
            f"the refusal does not name the accepted executor {kind.value!r}: {unknown_message!r}"
        )


# --------------------------------------------------------------------------------------------
# 2 -- no default substitutes a fake
# --------------------------------------------------------------------------------------------


def test_only_three_settings_carry_a_default_and_none_is_the_executor(tmp_path: Path) -> None:
    """The absence check: every security-relevant setting is required, stated over the model.

    ``guardian/app/config.py`` argues the rule -- "an absent value that has a safe reading takes the
    strongest reading; an absent value that has none is an error" -- and exactly three settings have
    a safe absent reading. ``mode`` defaults to the arm with the *most* enforcement, so a
    configuration mistake leaves the Guardian strict; ``max_request_bytes`` is derived from the
    request model's own field bounds rather than chosen, so the transport gate can never be narrower
    than what the contract would accept; ``audit_signing_key_file`` defaults to ``None`` -- an
    unsigned v1 chain, the documented pre-M10 and offline behaviour (ADR-130). Its absent reading is
    safe for the same reason as the other two and not a way to go green on an unset value: config.py
    still *fails closed* when the path is set but unreadable, so "told to sign but cannot" is an
    error while "not told to sign" is the strong reading, and the live deployment always sets it.

    Asserting the set by equality rather than checking the three by name is the point. A field added
    later with a plausible-looking default -- a TTL, a cache size, an executor -- fails here without
    anybody having thought to write a case for it, which is the shape of the mistake this whole
    module is about.
    """
    optional = {
        name for name, field in GuardianConfig.model_fields.items() if not field.is_required()
    }
    assert optional == {"mode", "max_request_bytes", "audit_signing_key_file"}, (
        f"settings with a default: {sorted(optional)}. Only three values have a safe absent "
        "reading. A default on anything else is a Guardian running against a number nobody chose, "
        "which is how a campaign goes green on a parameter that was never set"
    )
    assert GuardianConfig.model_fields["executor"].is_required(), (
        "GUARDIAN_EXECUTOR acquired a default. A fallback to the fake produces a Guardian that "
        "mediates every action correctly, records executed, and changes nothing anywhere -- and "
        "every artefact it produces looks right"
    )

    # And the fake is reachable, as it must be: it is the executor a Guardian is given when there
    # is no cluster. What the check above fixes is that reaching it takes an explicit act.
    chosen = GuardianConfig.from_mapping(
        dict(
            _environment(tmp_path, write_policy_bundle(tmp_path / "policies")),
            **{EXECUTOR_ENV_VAR: ExecutorKind.FAKE.value},
        )
    )
    assert isinstance(build_executor(chosen), FakeActionExecutor)


def test_the_fake_executor_is_reachable_only_from_the_one_function_that_chooses(
    tmp_path: Path,
) -> None:
    """Structural: ``FakeActionExecutor`` is named in exactly one function of the composition root.

    The behavioural check above says a fake is not reached *by this configuration*. This says
    something stronger and is the one that survives an edit: there is no other place in the file
    where a double could be substituted, so "no configuration, absent value or environment variable
    yields a fake by itself" is a property of the source rather than of the paths a suite happens to
    exercise. A second reference -- in an exception handler, in a fallback, in a convenience builder
    -- fails here with the function's name.
    """
    source = COMPOSITION_SOURCE.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(COMPOSITION_SOURCE))
    naming: list[str] = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        used = {inner.id for inner in ast.walk(node) if isinstance(inner, ast.Name)}
        if "FakeActionExecutor" in used:
            naming.append(node.name)

    assert naming == ["build_executor"], (
        f"FakeActionExecutor is named in {naming}. It belongs in exactly one place -- the function "
        "that turns GUARDIAN_EXECUTOR into an executor -- because every other appearance would be "
        "a route to a double that no operator wrote down"
    )

    # The stand-in Guardian below is assembled with the fake, and the assembled value publishes it,
    # so the executor a caller can see is the executor the configuration named.
    assembled = build_guardian(
        _stand_in_config(tmp_path),
        policy_engine=ScriptedPolicyEngine(),
        issuance_engine=ScriptedPolicyEngine(permit_result(ISSUANCE_PERMIT_RULE_ID)),
    )
    assert isinstance(assembled.executor, FakeActionExecutor)


# --------------------------------------------------------------------------------------------
# 3 -- the five seams each default to the real collaborator
# --------------------------------------------------------------------------------------------


def test_every_seam_build_guardian_publishes_defaults_to_none() -> None:
    """Structural: six keyword-only parameters, no positional double, and no default object.

    A seam whose default was an object would be a double reachable without naming one -- the exact
    property the composition root's docstring claims it does not have. Reading the signature is how
    that claim is checked rather than believed, and asserting the *set* means a sixth seam added
    later has to be justified here.
    """
    signature = inspect.signature(build_guardian)
    seams = {
        name: parameter
        for name, parameter in signature.parameters.items()
        if parameter.kind is inspect.Parameter.KEYWORD_ONLY
    }
    assert set(seams) == SEAM_NAMES, (
        f"build_guardian's keyword seams are {sorted(seams)}, expected {sorted(SEAM_NAMES)}"
    )
    defaulted_to_object = sorted(
        name for name, parameter in seams.items() if parameter.default is not None
    )
    assert defaulted_to_object == [], (
        f"seam(s) defaulting to an object rather than to None: {defaulted_to_object}. Every seam's "
        "default is the real collaborator built from configuration, which is expressed as None "
        "here and constructed inside; a default object would be a double a caller never named"
    )
    positional = [
        name
        for name, parameter in signature.parameters.items()
        if parameter.kind is not inspect.Parameter.KEYWORD_ONLY
    ]
    assert positional == ["config"], (
        f"build_guardian takes {positional} positionally. Everything except the configuration is "
        "keyword-only, so a double can never be supplied by accident of argument order"
    )


def test_a_restarted_guardian_resumes_the_existing_audit_chain(tmp_path: Path) -> None:
    """A process restart continues at the recorded head instead of writing a second genesis.

    The production sink must open and verify the existing file. Constructing a fresh writer for the
    same path resets its in-memory head and sequence to the genesis values, so the next append would
    corrupt an otherwise valid chain with a second ``seq == 0`` record.

    The genesis is the run-start record the first start wrote (ADR-058), so the first decision sits
    at ``seq`` 1 -- and the restart writes no second run-start: it resumes the run, it does not
    begin one. The second decision sits at ``seq`` 3, not 2: ADR-082 appends an execution follow-up
    behind every decision, so the first decision's own follow-up occupies ``seq`` 2 first.
    """
    config = _stand_in_config(tmp_path)
    first = build_guardian(
        config,
        policy_engine=ScriptedPolicyEngine(),
        issuance_engine=ScriptedPolicyEngine(permit_result(ISSUANCE_PERMIT_RULE_ID)),
        clock=SuiteClock(),
    )
    first_record = _submit(
        first,
        _action_body(token=_mint(first), request_id="req-before-restart"),
        label="before restart",
    ).assert_permitted()
    first_head = first.audit_sink.writer.head
    assert first_record.seq == 1

    restarted = build_guardian(
        config,
        policy_engine=ScriptedPolicyEngine(),
        issuance_engine=ScriptedPolicyEngine(permit_result(ISSUANCE_PERMIT_RULE_ID)),
        clock=SuiteClock(),
    )
    assert restarted.audit_sink.writer.next_seq == 3
    assert restarted.audit_sink.writer.head == first_head

    second_record = _submit(
        restarted,
        _action_body(token=_mint(restarted), request_id="req-after-restart"),
        label="after restart",
    ).assert_permitted()
    assert second_record.seq == 3
    assert second_record.prev_hash == first_head

    report = _verify(restarted)
    assert report.ok, report.findings
    assert [record.seq for record in _records(restarted.audit_sink.path)] == [1, 3]
    genesis = [
        parsed.seq
        for parsed in read_chain(restarted.audit_sink.path)
        if is_run_start(parsed.record)
    ]
    assert genesis == [0], (
        f"the chain holds run-start records at seq {genesis}; the first start writes exactly "
        "one, at seq 0, and a restart on a non-empty chain writes none"
    )


def test_a_restarted_guardian_refuses_to_extend_a_broken_audit_chain(tmp_path: Path) -> None:
    """Startup fails closed when the existing log cannot be resumed safely."""
    config = _stand_in_config(tmp_path)
    first = build_guardian(
        config,
        policy_engine=ScriptedPolicyEngine(),
        issuance_engine=ScriptedPolicyEngine(permit_result(ISSUANCE_PERMIT_RULE_ID)),
        clock=SuiteClock(),
    )
    _submit(
        first,
        _action_body(token=_mint(first), request_id="req-before-corruption"),
        label="before corruption",
    ).assert_permitted()

    lines = first.audit_sink.path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["request_id"] = "req-tampered"
    first.audit_sink.path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    with pytest.raises(ChainStateError, match="not an appendable chain record"):
        build_guardian(
            config,
            policy_engine=ScriptedPolicyEngine(),
            issuance_engine=ScriptedPolicyEngine(permit_result(ISSUANCE_PERMIT_RULE_ID)),
            clock=SuiteClock(),
        )


def test_the_unsupplied_seams_are_built_real_from_configuration(tmp_path: Path) -> None:
    """Behavioural: with only the engines scripted, the clock, cache and nonce are the real ones.

    Three properties, one per remaining seam, and each is the observable difference between the real
    collaborator and any plausible stand-in.

    *The clock is the wall clock.* A minted token's ``iat`` sits between two readings of
    :func:`time.time` taken around the mint. A frozen or zero clock would fall outside, and a
    Guardian whose tokens carried a fixed ``iat`` would have an expiry check that never fired.

    *The nonce source is real.* Two mints carry different ``jti`` values, both prefixed as
    :data:`~guardian.app.composition.JTI_PREFIX` requires. A counter shared across processes, or a
    seeded one, would mint identifiers a replay cache had already seen.

    *The persistent replay store is live.* One token spent twice is denied under
    ``replay.jti-spent``, which is only true if the store the composition root built is actually
    claiming jtis. An absent store permits twice; an unavailable one answers with a different code.
    """
    config = _stand_in_config(tmp_path)
    assembled = build_guardian(
        config,
        policy_engine=ScriptedPolicyEngine(),
        issuance_engine=ScriptedPolicyEngine(permit_result(ISSUANCE_PERMIT_RULE_ID)),
    )
    issuer = assembled.token_issuer.inner.issuer

    before = int(time.time())
    first = issuer.issue(
        issuer_id=SUPERVISOR_ID,
        subject_id=EXECUTOR_ID,
        run_id=RUN_ID,
        phase=PHASE,
        allow=DEFAULT_ALLOW,
        ttl_seconds=None,
    )
    second = issuer.issue(
        issuer_id=SUPERVISOR_ID,
        subject_id=EXECUTOR_ID,
        run_id=RUN_ID,
        phase=PHASE,
        allow=DEFAULT_ALLOW,
        ttl_seconds=None,
    )
    after = int(time.time())

    assert before <= first.claims.iat <= after, (
        f"a token minted between {before} and {after} carries iat {first.claims.iat}; the clock "
        "seam did not default to SystemClock, so this Guardian is timestamping on something other "
        "than the wall clock and its expiry checks are about a timeline nothing else shares"
    )
    assert first.claims.jti != second.claims.jti, (
        "two mints produced one jti. The jti_factory seam did not default to a fresh nonce per "
        "mint, and a replay cache would refuse the second token of every pair"
    )
    for claims in (first.claims, second.claims):
        assert claims.jti.startswith(JTI_PREFIX), claims.jti

    # Minted here rather than reusing one of the two above, so the token whose single use is being
    # tested is presented immediately after it is issued. This is the one case in the suite driven
    # by the wall clock -- proving the clock seam is real is the point of it -- and a token minted
    # earlier in the same function would put the suite's short test lifetime between the mint and
    # the replay, which would make an expiry the second request's most likely answer on a loaded
    # runner rather than the spent-jti this is about.
    single_use = _mint(assembled)
    spent = _submit(
        assembled, _action_body(token=single_use, request_id="req-seam-0001"), label="first use"
    )
    spent.assert_permitted()
    replayed = _submit(
        assembled, _action_body(token=single_use, request_id="req-seam-0002"), label="replay"
    )
    replayed.assert_denied(ReasonCode.REPLAY_JTI_SPENT)
    assert config.replay_store_path.is_file(), (
        "the production replay seam did not default to its configured persistent SQLite file"
    )


def test_a_guardian_with_no_locatable_engine_refuses_rather_than_substituting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No ``opa``, no Guardian -- and that holds for each of the two engines independently.

    :data:`~guardian.app.opa.OPA_BINARY_ENV_VAR` is pointed at a path that is not an executable, so
    the refusal is a property of this test rather than of the host: it holds identically on a
    machine that has the pinned binary and on one that does not.

    The loop is the load-bearing part. Supplying *one* engine still refuses, because the other is
    still built for real -- which is what stops a future edit from resolving the binary once, for
    the action entrypoint only, and leaving the authority entrypoint silently unevaluated. A
    Guardian whose issuance policy could not be evaluated would mint nothing at all, and the failure
    would present as an inexplicable campaign of refusals rather than as a missing dependency.
    """
    monkeypatch.setenv(OPA_BINARY_ENV_VAR, str(tmp_path / "there-is-no-engine-here"))
    config = _stand_in_config(tmp_path)

    assert issubclass(OpaBinaryUnavailable, GuardianStartupError), (
        "OpaBinaryUnavailable is no longer a startup error, so the process entry point no longer "
        "reports a missing engine as a refusal to start"
    )

    seam_sets: tuple[dict[str, Any], ...] = (
        {},
        {"policy_engine": ScriptedPolicyEngine()},
        {"issuance_engine": ScriptedPolicyEngine()},
    )
    for seams in seam_sets:
        with pytest.raises(OpaBinaryUnavailable) as error:
            build_guardian(config, **seams)
        message = str(error.value)
        assert OPA_BINARY_ENV_VAR in message, (
            f"with seams {sorted(seams)} supplied, the refusal does not name "
            f"{OPA_BINARY_ENV_VAR}: {message!r}"
        )


# --------------------------------------------------------------------------------------------
# 4 -- the process entry point
# --------------------------------------------------------------------------------------------


def _clear_guardian_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every ``GUARDIAN_`` key from the process environment, through monkeypatch only.

    ``os.environ`` is global and shared with every other test in the session, so it is read here and
    written only through the fixture that undoes its writes. A Guardian key left over from the
    developer's shell would otherwise decide what :func:`~guardian.app.__main__.main` reads.
    """
    for key in list(os.environ):
        if key.startswith(ENV_PREFIX):
            monkeypatch.delenv(key, raising=False)


def test_the_entry_point_exits_non_zero_with_the_message_intact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``main([])`` on two broken configurations: exit code 2 both times, message unwrapped.

    ``guardian/app/__main__.py`` says this is exactly what should be checkable: :func:`main` returns
    a code rather than calling :func:`sys.exit` "so that the whole of this function is testable in
    process ... without a subprocess and without catching ``SystemExit``". It also fixes what the
    output must be -- "written verbatim and ... not wrapped, prefixed with a category, or
    summarised", because rewriting it "would replace the sentence that says which variable was wrong
    with one that says a Guardian failed to start".

    Both configurations are broken deliberately, and that is a safety property of this test rather
    than an accident of coverage: a *valid* configuration would reach :func:`_serve`, and on a host
    with an ASGI server installed that call does not return.

    The second case is the ordering claim that module makes for itself -- a configuration fault is
    reported before the server package is looked for, so an operator with a missing key and no
    server is told about the key. Here the fault is the engine, which is reported the same way.
    """
    _clear_guardian_environment(monkeypatch)
    monkeypatch.setenv(OPA_BINARY_ENV_VAR, str(tmp_path / "there-is-no-engine-here"))

    environment = _environment(tmp_path, write_policy_bundle(tmp_path / "policies"))
    for key, value in environment.items():
        if key != SIGNING_KEY_ENV_VAR:
            monkeypatch.setenv(key, value)

    assert main([]) == EXIT_STARTUP_FAILURE, (
        "a Guardian with no signing key started, or exited zero. GuardianStartupError's contract "
        "is that the entry point exits non-zero with the message intact rather than falling back "
        "to anything"
    )
    reported = capsys.readouterr().err
    assert reported.startswith("guardian: "), reported
    assert SIGNING_KEY_ENV_VAR in reported, (
        f"the entry point's stderr does not name the variable that was unset: {reported!r}"
    )
    assert SIGNING_KEY_FILE_ENV_VAR in reported, reported

    monkeypatch.setenv(SIGNING_KEY_ENV_VAR, SYNTHETIC_SIGNING_MATERIAL)
    assert main([]) == EXIT_STARTUP_FAILURE, (
        "a Guardian whose policy engine could not be located started. The alternative -- starting "
        "and denying everything -- produces a whole campaign of denials in which every run bundle "
        "validates and nothing says the policy the study is about was never evaluated"
    )
    reported = capsys.readouterr().err
    assert reported.startswith("guardian: "), reported
    assert OPA_BINARY_ENV_VAR in reported, (
        f"the entry point's stderr does not name {OPA_BINARY_ENV_VAR}: {reported!r}"
    )


# --------------------------------------------------------------------------------------------
# 5 -- the shipped bundle loads, and its digest is one value
# --------------------------------------------------------------------------------------------


def test_the_shipped_bundle_digest_is_one_value_across_arms_and_entrypoints(
    tmp_path: Path,
) -> None:
    """ADR-023's machine proof over the bytes the campaign ships, extended to ADR-031's claim.

    ADR-023 leaves no room to negotiate: the sha256 is "asserted **equal** across G0, G1 and G2. Not
    'equivalent', not 'semantically the same' -- the same bytes." It is asserted on the bundle
    rather than on the decisions because behaviour is what the ablation *measures*: comparing G0's
    and G1's decisions would be asserting the finding rather than the mechanism, and would pass for
    a G1 built by editing policy so long as the edit was decision-preserving on the test inputs.

    Two things are added to that here. The digest is asserted **identical under both entrypoints**,
    which is ADR-031's "same bundle" claim made checkable -- the authority rules ship beside the
    action rules, so one hash describes the whole policy, where a second bundle would have left half
    of it outside the proof. And the digested file list is asserted to contain ``authority.rego``
    and ``issuance.rego`` by name, so a digest that stayed stable because those files stopped being
    loaded fails rather than reassuring.
    """
    assert len(ARMS) == 3, "the arm list is not the three arms this Guardian implements"
    shipped = shipped_policy_bundle()

    digests = {}
    for arm in ARMS:
        config = GuardianConfig.from_mapping(
            guardian_environment(
                mode=arm,
                run_id=RUN_ID,
                registered_issuers=(SUPERVISOR_ID,),
                bundle_path=shipped,
                audit_log_path=tmp_path / f"{arm.value}.jsonl",
            )
        )
        digests[arm.value] = PolicyBundle.load(config.policy).digest

    issuance_settings = PolicyEngineSettings(
        bundle_path=shipped,
        entrypoint=SHIPPED_ISSUANCE_ENTRYPOINT,
        evaluation_timeout_seconds=SUITE_POLICY_TIMEOUT_SECONDS,
    )
    action_settings = PolicyEngineSettings(
        bundle_path=shipped,
        entrypoint=SHIPPED_ENTRYPOINT,
        evaluation_timeout_seconds=SUITE_POLICY_TIMEOUT_SECONDS,
    )
    issuance_bundle = PolicyBundle.load(issuance_settings)
    action_bundle = PolicyBundle.load(action_settings)
    digests[SHIPPED_ISSUANCE_ENTRYPOINT] = issuance_bundle.digest
    digests[SHIPPED_ENTRYPOINT] = action_bundle.digest
    # Loaded twice under identical settings, so that "stable" means stable across loads and not
    # merely equal between two configurations computed in one pass.
    digests["reloaded"] = PolicyBundle.load(action_settings).digest

    assert len(set(digests.values())) == 1, (
        f"the shipped bundle hashes differently across arms or entrypoints: {digests}. The arms "
        "must be reachable only through runner configuration, and one directory is one sha256 -- "
        "which is what lets a single digest describe both the action rules and the authority rules"
    )

    digest = action_bundle.digest
    assert re.fullmatch(DIGEST_PATTERN, digest), (
        f"the bundle digest {digest!r} is not a lowercase sha256; ADR-023's assertion is over a "
        "hex digest and a sealed run bundle records it verbatim"
    )
    for required in SHIPPED_BUNDLE_FILES:
        assert required in action_bundle.files, (
            f"{required} is missing from the digested set {list(action_bundle.files)}. A digest "
            "that is stable because a policy file stopped being loaded proves the opposite of what "
            "it looks like it proves"
        )


# --------------------------------------------------------------------------------------------
# 6 -- the real engine, over the real bundle
#
# The only cases in this suite that run Rego. Everywhere else the engine is a canned answer, because
# guardian/app/policy.py refuses to have a second decision procedure in Python "for the tests" --
# and that restraint leaves exactly one gap, which is that nothing in pytest ever exercises the
# bundle the campaign ships. These close it by running the pinned binary rather than by describing
# what it would say.
#
# The clock seam is the frozen suite clock, and the engines are not seams at all. That split is
# deliberate: what these cases are about is the two OpaSubprocessEngines being real, while a wall
# clock would let a slow subprocess spawn on a loaded runner expire a token mid-case and turn a
# policy assertion into a timing one.
# --------------------------------------------------------------------------------------------


def _real_engine_guardian(root: Path) -> AssembledGuardian:
    """Assemble a Guardian over the shipped bundle with **no** scripted engine of any kind.

    The control-plane authenticator is the one double supplied, and for the reason
    ``guardian/app/control_auth.py`` states: the real one is a TokenReview against the API server,
    and this suite has no cluster. Naming the double keeps every case in this section about the two
    OPA subprocess engines, which is what the section's comment above says they are for.
    """
    _opa_binary_or_skip()
    return build_guardian(
        _shipped_config(root),
        clock=SuiteClock(),
        control_plane_authenticator=FakeControlPlaneAuthenticator(),
    )


def test_the_real_engine_permits_an_action_inside_the_capability(tmp_path: Path) -> None:
    """One permit, decided by ``guardian.rego`` itself, named by the rule the bundle declares.

    Everything in the chain is the shipped article: the bundle on disk, the ``opa`` binary the
    policy gate tests it with, ``guardian.rego``'s three permit conditions, and the rule id it emits
    -- which must satisfy the audit record's dot-free identifier grammar, or the permit could not be
    recorded at all. Asserting the rule id by name is what makes this a test of the bundle rather
    than of the pipeline: a bundle that permitted under a different rule, or under a dotted Rego
    path, fails here instead of being recorded as an ordinary permit.

    The triple assertion is the suite's own, through ``CaseOutcome`` -- permitted, with the permit
    reason code, and present in a chain that still verifies.
    """
    assembled = _real_engine_guardian(tmp_path)
    outcome = _submit(
        assembled,
        _action_body(token=_mint(assembled), request_id="req-real-0001"),
        label="real engine, action inside the capability",
    )
    record = outcome.assert_permitted(rule_id=SHIPPED_PERMIT_RULE_ID)
    assert record.policy_rule_id == SHIPPED_PERMIT_RULE_ID, record.policy_rule_id


def test_the_real_engine_denies_an_action_outside_the_capability(tmp_path: Path) -> None:
    """One denial, and it is the deny-by-default floor rather than an engine failure.

    The distinction is the whole point of running the real bundle. ``delete`` is not in the
    capability's allow-claim, no refusal rule fired, and nothing matched -- which is
    ``security-policy.md`` section 1.1's invariant expressed as an outcome and is the answer the
    Guardian gives most often. Any of the group E codes here would mean the engine had failed and
    the request had been refused for a reason that says nothing about it, which fails closed and
    proves nothing about the policy.
    """
    assembled = _real_engine_guardian(tmp_path)
    outcome = _submit(
        assembled,
        _action_body(
            token=_mint(assembled),
            request_id="req-real-0002",
            verb="delete",
            name="paymentservice",
        ),
        label="real engine, verb outside the capability",
    )
    record = outcome.assert_denied(ReasonCode.POLICY_DENY_DEFAULT)
    assert record.policy_rule_id is None, (
        f"the denial names rule {record.policy_rule_id!r}. Nothing refused this request; inventing "
        "a rule id for the deny-by-default floor would be a falsehood in a hashed record"
    )


def test_the_real_authority_entrypoint_refuses_an_over_wide_mint(tmp_path: Path) -> None:
    """``authority.rego`` read by ``issuance.rego``, consulted before anything is signed.

    ADR-031's answer to conflict M4-C6, driven end to end for the first time. The request asks the
    containment phase for ``delete`` on ``secrets`` in ``kube-system``: three dimensions, every one
    of them outside what a person declared that phase may ever carry, and none of them reachable by
    an authorised Supervisor either. The caller is refused with ``issue_authority_exceeded`` and
    **holds nothing** -- which is asserted separately, because a 403 accompanied by a credential
    would be worse than no bound at all: the caller would hold a working capability the Guardian
    believed it had refused.

    The within-authority mint at the end is not decoration. Without it a bundle that refused
    everything would pass this case, and "the authority policy is consulted" would be indis-
    tinguishable from "the authority policy is broken". It also states the residual exposure
    ``test_token_issuance_exposure.py`` is about: this caller presents no credential of any kind and
    still receives a signed capability, because what the bound limits is the scope rather than the
    identity.

    Both calls now present the control-plane credential ADR-128 requires (``guardian/tests/
    test_control_auth.py`` is the test of that gate, and it is what asserts a mint without one is
    answered 401). That is the whole update M10 makes to this case: the authority entrypoint is
    unchanged, and a case that stopped presenting the credential would be testing the 401 twice.
    """
    assembled = _real_engine_guardian(tmp_path)
    control_plane = {"authorization": f"Bearer {CONTROL_PLANE_BEARER}"}

    over_wide = _issue_body(
        allow={"verbs": ["delete"], "resources": ["secrets"], "namespaces": ["kube-system"]}
    )
    status, payload = call_asgi(
        assembled.app,
        TOKENS_PATH,
        json.dumps(over_wide).encode("utf-8"),
        headers=control_plane,
    )
    assert status == HTTP_FORBIDDEN, (status, payload)
    assert payload["error"] == ISSUE_AUTHORITY_EXCEEDED, (
        f"the real authority entrypoint refused with {payload!r}; the structured code a caller is "
        f"told is {ISSUE_AUTHORITY_EXCEEDED!r} whichever authority rule turned the request away"
    )
    assert "token" not in payload, payload
    assert "jti" not in payload, payload

    status, payload = call_asgi(
        assembled.app,
        TOKENS_PATH,
        json.dumps(_issue_body()).encode("utf-8"),
        headers=control_plane,
    )
    assert status == HTTP_OK, (
        f"a mint inside the declared authority was refused with {payload!r}. An authority policy "
        "that refuses everything is indistinguishable from one that is never consulted, and the "
        "case above would pass over both"
    )
    assert payload["jti"], payload


# --------------------------------------------------------------------------------------------
# 7 -- the harness consumes this root rather than describing the seam a second time
# --------------------------------------------------------------------------------------------


def _harness_tree() -> ast.Module:
    """The adversarial harness parsed, so the check reads the module rather than a raw string."""
    return ast.parse(HARNESS_SOURCE.read_text(encoding="utf-8"), filename=str(HARNESS_SOURCE))


def test_the_harness_reaches_the_production_composition_root(tmp_path: Path) -> None:
    """ADR-030's inversion, made permanent: the suite consumes ``build_guardian``, twice over.

    ADR-030 records that a test harness being the sole description of how the Guardian's halves fit
    is "a **defect with a specific failure mode**, not merely an unfinished chore" -- the seam can
    be right in the suite and wrong in the deployed process, and the adversarial cases go on passing
    over a wiring nothing ships. The fix was to move the assembly into ``guardian/app/`` and have
    the harness consume it. Nothing in a green suite would notice that being undone.

    So this asserts it from both directions. Statically: ``harness.py`` imports ``build_guardian``
    from the composition root, calls it inside ``GuardianHarness``, and imports **none** of the
    names a hand assembly would need -- no ``Mediator``, no ``create_app``, no adapter, no chain
    writer, no executor. Dynamically: the objects a case actually drives are identity-equal to the
    ones the composition root returned, so what the suite attacks is what a deployed process would
    have been given.
    """
    tree = _harness_tree()
    imported: set[str] = set()
    sources: set[str | None] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        for alias in node.names:
            imported.add(alias.asname or alias.name)
            if alias.name == "build_guardian":
                sources.add(node.module)

    assert "build_guardian" in imported, (
        "guardian/tests/harness.py does not import build_guardian. The adversarial suite building "
        "its own Guardian is the defect ADR-030 closed: a seam described twice can be right in the "
        "suite and wrong in the process that ships"
    )
    assert sources == {"guardian.app.composition"}, (
        f"build_guardian is imported from {sources}, not from the production composition root"
    )

    hand_assembled = sorted(imported & HAND_ASSEMBLY_NAMES)
    assert hand_assembled == [], (
        f"guardian/tests/harness.py imports {hand_assembled}, which are the collaborators the "
        "composition root wires. A harness that imports them is a harness that can assemble a "
        "Guardian by hand again, and every adversarial case would stay green while doing it"
    )

    classes = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "GuardianHarness"
    ]
    assert len(classes) == 1, "guardian/tests/harness.py declares no single GuardianHarness"
    called = {
        inner.func.id
        for inner in ast.walk(classes[0])
        if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name)
    }
    assert "build_guardian" in called, (
        "GuardianHarness does not call build_guardian. Importing the composition root and then "
        "assembling around it would be the duplication ADR-030 removed, wearing the import that "
        "says otherwise"
    )

    harness = make_harness(tmp_path)
    assert isinstance(harness.assembled, AssembledGuardian)
    assert harness.app is harness.assembled.app, (
        "the harness serves an application other than the one build_guardian returned"
    )
    assert harness.mediator is harness.assembled.mediator
    assert harness.executor is harness.assembled.executor
    assert harness.sink is harness.assembled.audit_sink
    assert harness.issuer is harness.assembled.token_issuer.inner.issuer, (
        "the harness mints with an issuer other than the Guardian's own, so a case could mint with "
        "one object and verify with another and disagree for a reason neither names"
    )
