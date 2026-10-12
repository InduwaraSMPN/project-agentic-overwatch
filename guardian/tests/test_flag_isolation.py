r"""M3-T3.7 -- the flag-isolation proof: the arm changes what the Guardian does, and nothing else.

WHY THIS FILE IS THE DELIVERABLE AND NOT THE MODE PLUMBING
------------------------------------------------------------
``docs/milestones/M3-guardian.md``'s Definition of done carries a line that reads like a
configuration note and is the validity condition of an entire ablation: "G1/G2 toggles change only
their intended behaviour ... [T-13]". Dissertation section 3.5.4 says why -- each configuration must
remove *exactly one* property of the Guardian's design, "so that comparing C0 against C1 to C3
isolates whether enforcement, credential isolation and log-quoting are each causally responsible for
the safety outcomes observed".

ADR-023 names the failure mode, and it is the one that does not announce itself: if the arm is
reachable by editing policy, then G0-versus-G1 is a comparison of two policy bundles rather than of
one bundle enforced two ways, and the causal claim does not follow from the data **even though every
test is green**. The wrong design does not produce a failing test. It produces an invalid arm, and
125 of the campaign's runs measuring something other than what they are labelled.

So the deliverable is the check. ADR-023 lists eight assertions; seven run offline and are
implemented below under the numbers it gives them, and the eighth needs a cluster.

TWO OF THEM ARE STRUCTURAL PROOFS RATHER THAN BEHAVIOURAL ONES, AND THAT IS DELIBERATE
---------------------------------------------------------------------------------------
Assertion 2's field-by-field diff shows that the arm changed nothing *on the requests this suite
sent*. Assertions 5 and 6 have to be stronger than that, because "no request in this suite changed
the mode" is a weaker statement than "no request can". They are therefore checked by walking the
abstract syntax tree of every Python file under ``guardian/``:

*Nothing anywhere branches on the mode except the one function whose job that is.* The scan
collects every decision expression that reads a mode symbol and compares the set against three
named, argued sites. It is ``monitor/tests/test_g3_isolation.py``'s condition 4 applied to this
flag, and ADR-023's own reason for preferring an allowlist of differences to a spot-check applies
unchanged: an allowlist fails when something new starts reading the arm, which is precisely the
change nobody would think to write a test for.

*Nothing anywhere assigns to a mode attribute.* ``GuardianConfig`` is frozen, so a mutation would
raise -- but a raise is a run-time property of the one path that happens to be exercised, and the
scan is a property of the whole tree.

WHAT THE FIELD-BY-FIELD DIFF EXCLUDES, AND WHY THAT IS NOT A WEAKENING
-----------------------------------------------------------------------
``hash`` and ``prev_hash`` differ between the arms and must. They are computed over the record, the
record contains ``guardian_mode`` and the enforcement field, and those two are exactly what ADR-023
permits to differ -- so a chain whose hashes matched across arms would mean the mode was *not*
inside the hashed record, leaving a sealed bundle unable to evidence which arm made it. The diff
therefore asserts that every other field is identical and separately asserts that the two hashes
differ, which is the stronger statement in both directions.
"""

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402
from guardian.app.config import (  # noqa: E402
    MODE_ENV_VAR,
    MODE_SHAPED_FIELD_NAMES,
    GuardianConfig,
    GuardianStartupError,
)
from guardian.app.models import (  # noqa: E402
    ActionRequest,
    Enforcement,
    ExecutionStatus,
    GuardianMode,
    ReasonCode,
    contract_models,
    reject_field_names,
    reject_field_types,
)
from guardian.app.policy import PolicyBundle, PolicyEngineSettings  # noqa: E402
from guardian.tests.harness import (  # noqa: E402
    SUITE_POLICY_TIMEOUT_SECONDS,
    GuardianHarness,
    deny_default_result,
    guardian_environment,
    permit_result,
    policy_purity_script,
    record_fields,
    run_shell_script,
    shipped_policy_bundle,
    write_policy_bundle,
)

GUARDIAN_ROOT = REPO_ROOT / "guardian"

# The arms this Guardian implements. G3-UNQUOTED is deliberately absent: it is the Monitor's
# aggregator-quoting flag, owned by M2-T2.6, and a Guardian offering it would be offering an arm
# nothing in this process can produce.
ARMS = (GuardianMode.G0_FULL, GuardianMode.G1_LOGONLY, GuardianMode.G2_SHAREDCRED)

# ADR-023 assertion 2's allowlist of permitted differences, plus the two chain fields derived from
# them. See the module docstring for why the derived pair is excluded from the equality check and
# asserted to differ instead.
PERMITTED_RECORD_DIFFERENCES = frozenset({"guardian_mode", "enforcement"})
CHAIN_DERIVED_FIELDS = frozenset({"hash", "prev_hash"})


# --------------------------------------------------------------------------------------------
# Assertion 1 -- policy-bundle identity
# --------------------------------------------------------------------------------------------


def test_isolation_1_the_bundle_digest_is_identical_across_the_arms(tmp_path: Path) -> None:
    """One directory of bytes, loaded under three configurations, hashing to one digest.

    ADR-023 states the requirement without room to negotiate: the sha256 is "asserted **equal**
    across G0, G1 and G2. Not 'equivalent', not 'semantically the same' -- the same bytes." This is
    the direct machine proof that the arms cannot be reached through policy, and it is asserted over
    the loader's own output rather than over a file listing, so a bundle that loaded different files
    per arm would fail here even if the directory looked the same.
    """
    bundle_path = write_policy_bundle(tmp_path / "policies")
    digests = {}
    for mode in ARMS:
        config = GuardianConfig.from_mapping(
            guardian_environment(
                mode=mode,
                run_id="RUN-ISOLATION-0001",
                registered_issuers=("supervisor-containment",),
                bundle_path=bundle_path,
                audit_log_path=tmp_path / f"{mode.value}.jsonl",
            )
        )
        assert config.mode is mode
        digests[mode.value] = PolicyBundle.load(config.policy).digest

    assert len(set(digests.values())) == 1, (
        f"the policy bundle hashes differently per arm: {digests}. The arms must be reachable only "
        "through runner configuration, so the bytes the engine evaluates cannot depend on "
        "which arm is in force"
    )


def test_isolation_1b_the_shipped_bundle_digest_is_identical_across_the_arms(
    tmp_path: Path,
) -> None:
    """The same assertion over ``guardian/policies/`` itself, once M3-T3.2 has authored it.

    The test above proves the *loader* is mode-blind, which is the property the code has. This one
    proves it over the bytes the campaign will actually ship, which is the property the evaluation
    needs. It skips with a named reason until the bundle exists rather than being written later and
    forgotten.
    """
    shipped = shipped_policy_bundle()
    digests = {
        mode.value: PolicyBundle.load(
            PolicyEngineSettings(
                bundle_path=shipped,
                entrypoint="data.guardian.decision",
                evaluation_timeout_seconds=SUITE_POLICY_TIMEOUT_SECONDS,
            )
        ).digest
        for mode in ARMS
    }
    assert len(set(digests.values())) == 1, digests


# --------------------------------------------------------------------------------------------
# Assertion 2 -- code-path identity
# --------------------------------------------------------------------------------------------


def _replay_the_same_sequence(harness: GuardianHarness) -> None:
    """Send one fixed request sequence, chosen so every enforcement value is exercised.

    A permit, a policy denial with an action formed, a first use and a replay of one token, and a
    body that never parsed. Between them they produce ``executed``, ``blocked`` and
    ``not-applicable`` -- so the diff below compares arms across every branch of ``enforcement_for``
    rather than across the one that happens to be common.
    """
    harness.engine.result = permit_result()
    harness.submit(
        harness.action_body(token=harness.mint(), request_id="req-iso-1"), label="permit"
    ).assert_permitted()

    harness.engine.result = deny_default_result()
    harness.submit(
        harness.action_body(
            token=harness.mint(), request_id="req-iso-2", verb="delete", name="paymentservice"
        ),
        label="policy denial",
    ).assert_denied(ReasonCode.POLICY_DENY_DEFAULT)

    harness.engine.result = permit_result()
    token = harness.mint()
    harness.submit(
        harness.action_body(token=token, request_id="req-iso-3"), label="first use"
    ).assert_permitted()
    harness.submit(
        harness.action_body(token=token, request_id="req-iso-4"), label="replay"
    ).assert_denied(ReasonCode.REPLAY_JTI_SPENT)

    harness.submit(b"{not json", label="malformed body").assert_denied(
        ReasonCode.POLICY_REQUEST_MALFORMED
    )


def test_isolation_2_the_g0_versus_g1_audit_diff_is_confined(harness_factory: object) -> None:
    """The same request sequence under G0-FULL and G1-LOGONLY, diffed field by field.

    ADR-023's load-bearing assertion. The permitted differences are ``guardian_mode``, the
    enforcement field and the execution block; ``decision``, ``reason_code``, ``policy_rule_id``,
    record ordering and ``jti`` handling must be identical. Each of those five is checked by name
    below rather than left to the field loop, because they are the ones whose divergence would
    invalidate the arm rather than merely surprise a reader.

    The diff is over *every* field of *every* record, so a field that starts differing later fails
    here without anybody having thought to add a case for it. That is the whole reason it is an
    allowlist of differences and not a spot-check.
    """
    build = harness_factory
    g0 = build(mode=GuardianMode.G0_FULL)  # type: ignore[operator]
    g1 = build(mode=GuardianMode.G1_LOGONLY)  # type: ignore[operator]
    _replay_the_same_sequence(g0)
    _replay_the_same_sequence(g1)

    g0_records = g0.records()
    g1_records = g1.records()
    assert len(g0_records) == len(g1_records) == 5, (
        f"the arms produced {len(g0_records)} and {len(g1_records)} records for the same request "
        "sequence; record ordering and record count must be identical"
    )

    observed_differences: set[str] = set()
    for left, right in zip(g0_records, g1_records, strict=True):
        left_fields = record_fields(left)
        right_fields = record_fields(right)
        assert set(left_fields) == set(right_fields)
        for field in sorted(left_fields):
            if left_fields[field] != right_fields[field]:
                observed_differences.add(field)

        # Named explicitly, because these five are what "removes exactly one property" means.
        assert left.decision is right.decision, f"seq {left.seq}: decision differs across arms"
        assert left.reason_code is right.reason_code, f"seq {left.seq}: reason code differs"
        assert left.policy_rule_id == right.policy_rule_id, f"seq {left.seq}: rule id differs"
        assert left.seq == right.seq, "record ordering differs across arms"
        assert left.token_jti == right.token_jti, (
            f"seq {left.seq}: jti handling differs across arms; the replay cache is not part of "
            "what the arm changes"
        )

    # The genesis is a record of both chains as well (ADR-058), so it is diffed too: one run-start
    # each, differing in the arm it names and in the digest computed over it, and in nothing else.
    # records() returns decisions only, which is why the genesis is compared on its own here rather
    # than falling out of the loop above.
    g0_starts = g0.run_start_records()
    g1_starts = g1.run_start_records()
    assert len(g0_starts) == len(g1_starts) == 1, (
        f"the arms wrote {len(g0_starts)} and {len(g1_starts)} run-start records; a fresh chain "
        "opens with exactly one"
    )
    g0_start = record_fields(g0_starts[0])
    g1_start = record_fields(g1_starts[0])
    assert set(g0_start) == set(g1_start)
    start_differences = {field for field in g0_start if g0_start[field] != g1_start[field]}
    assert start_differences == {"guardian_mode", "hash"}, (
        f"the two run-start records differ in {sorted(start_differences)}; the arm may reach only "
        "the mode the record names and the hash computed over it"
    )

    assert observed_differences <= PERMITTED_RECORD_DIFFERENCES | CHAIN_DERIVED_FIELDS, (
        f"the G0-versus-G1 audit diff reaches {sorted(observed_differences)}. ADR-023 permits "
        f"it to reach only {sorted(PERMITTED_RECORD_DIFFERENCES)} plus the fields derived from "
        f"them, {sorted(CHAIN_DERIVED_FIELDS)}"
    )
    assert PERMITTED_RECORD_DIFFERENCES <= observed_differences, (
        "the arms produced identical guardian_mode and enforcement values, so either the mode "
        "never reached the record or G1-LOGONLY is not doing anything -- and the G0-vs-G1 contrast "
        "the reduction lever protects would be uncomputable from this log"
    )
    assert CHAIN_DERIVED_FIELDS <= observed_differences, (
        "the two chains hash identically although guardian_mode differs, which means the mode is "
        "not inside the hashed record and a sealed bundle could not evidence which arm produced it"
    )


def test_isolation_2b_the_execution_block_is_where_the_arms_may_differ(
    harness_factory: object,
) -> None:
    """The third permitted difference, checked where it actually lives.

    ``execution`` is a field of ``ActionResult`` and not of ``AuditRecord``, so the diff above
    cannot see it. Under G1-LOGONLY a denial is followed by execution -- that pairing is the entire
    content of the arm -- and this is the case that shows it happening rather than being described.
    """
    build = harness_factory
    g0 = build(mode=GuardianMode.G0_FULL)  # type: ignore[operator]
    g1 = build(mode=GuardianMode.G1_LOGONLY)  # type: ignore[operator]
    for harness in (g0, g1):
        harness.engine.result = deny_default_result()

    g0_outcome = g0.submit(
        g0.action_body(token=g0.mint(), request_id="req-iso-exec"), label="G0 denial"
    )
    g1_outcome = g1.submit(
        g1.action_body(token=g1.mint(), request_id="req-iso-exec"), label="G1 denial"
    )
    g0_outcome.assert_denied(ReasonCode.POLICY_DENY_DEFAULT)
    g1_outcome.assert_denied(ReasonCode.POLICY_DENY_DEFAULT)

    assert g0_outcome.record.enforcement is Enforcement.BLOCKED
    assert g1_outcome.record.enforcement is Enforcement.EXECUTED
    assert g0_outcome.result.execution.status is ExecutionStatus.NOT_ATTEMPTED
    assert g1_outcome.result.execution.status is ExecutionStatus.SUCCEEDED
    assert g0.executor.calls == []
    assert len(g1.executor.calls) == 1, (
        "G1-LOGONLY logs but does not block, so a denied action must reach the executor; if it "
        "does not, the arm is indistinguishable from G0-FULL and the ablation has three arms of "
        "which two are the same"
    )


# --------------------------------------------------------------------------------------------
# Assertions 3 and 4 -- the default, and what an unrecognised value does
# --------------------------------------------------------------------------------------------


def test_isolation_3_the_default_arm_is_g0_full(tmp_path: Path) -> None:
    """No flag, blank flag, whitespace flag: all three yield full mediation.

    Fail-closed in the direction a default can be. A configuration mistake leaves the Guardian
    strict, never weak, so nobody ever runs a campaign in a weaker arm than they meant to.
    """
    environment = guardian_environment(
        mode=GuardianMode.G0_FULL,
        run_id="RUN-ISOLATION-0001",
        registered_issuers=(),
        bundle_path=write_policy_bundle(tmp_path / "policies"),
        audit_log_path=tmp_path / "audit.jsonl",
    )
    for absent in ({}, {MODE_ENV_VAR: ""}, {MODE_ENV_VAR: "   "}):
        source = {key: value for key, value in environment.items() if key != MODE_ENV_VAR}
        source.update(absent)
        assert GuardianConfig.from_mapping(source).mode is GuardianMode.G0_FULL


def test_isolation_4_an_unrecognised_arm_refuses_to_start(tmp_path: Path) -> None:
    """Seven spellings that are not arms, each a startup error naming the accepted set.

    Never a silent default, and the reason is a whole campaign rather than one process: a runner
    that misspelled the arm would otherwise produce a run of ``G0-FULL`` records labelled
    ``G1-LOGONLY``, every bundle would validate, and the RQ5 contrast would be computed from data
    that does not exist. ``G3-UNQUOTED`` is among the rejected values and belongs there -- it is the
    Monitor's flag, and a Guardian accepting it would be claiming an arm it cannot produce.
    """
    environment = guardian_environment(
        mode=GuardianMode.G0_FULL,
        run_id="RUN-ISOLATION-0001",
        registered_issuers=(),
        bundle_path=write_policy_bundle(tmp_path / "policies"),
        audit_log_path=tmp_path / "audit.jsonl",
    )
    rejected = (
        "G1_LOGONLY",
        "g1-logonly",
        "G0-full",
        "G3-UNQUOTED",
        "FULL",
        "true",
        "G1-LOGONLY ; G0-FULL",
    )
    for value in rejected:
        with pytest.raises(GuardianStartupError) as error:
            GuardianConfig.from_mapping(dict(environment, **{MODE_ENV_VAR: value}))
        message = str(error.value)
        assert MODE_ENV_VAR in message, message
        for arm in ARMS:
            assert arm.value in message, (
                f"the refusal for {value!r} does not name the accepted set; the person reading it "
                "is by definition somebody whose runner flag did not do what they expected"
            )


# --------------------------------------------------------------------------------------------
# Assertion 5 -- mode is not request-settable
# --------------------------------------------------------------------------------------------


def test_isolation_5_no_request_model_can_name_or_type_a_mode(harness: GuardianHarness) -> None:
    """Structural: no field in the request tree is named like a mode or typed as one.

    Both guards are applied at import by ``guardian/app/config.py``, so a violation would already
    have stopped the Guardian from starting. Calling them here is not redundant: it states the
    property in the file that owns it, and it fails with a message naming the offending field rather
    than as an import error somewhere else in a stack trace.
    """
    reject_field_names(ActionRequest, MODE_SHAPED_FIELD_NAMES, why="isolation assertion 5")
    reject_field_types(ActionRequest, (GuardianMode,), why="isolation assertion 5")

    declared = {
        f"{model.__name__}.{name}"
        for model in contract_models(ActionRequest)
        for name in model.model_fields
    }
    assert declared, "the request tree declares no fields at all, so this scan proves nothing"
    assert harness.config.mode is GuardianMode.G0_FULL


def test_isolation_5b_a_request_carrying_a_mode_changes_nothing(harness: GuardianHarness) -> None:
    """Behavioural: mode-shaped content in ``params`` and ``justification`` leaves the arm alone.

    The one route ``config.py`` is honest about not being able to close structurally -- ``params``
    is a free-form mapping and an agent may put whatever it likes in it. Nothing reads it: it is
    excluded from the OPA input document by construction, and no code in the package looks up a
    configuration value from request data. This is the behavioural check that says so, and it is
    behavioural because the property is.
    """
    harness.engine.result = deny_default_result()
    control = harness.submit(
        harness.action_body(token=harness.mint(), request_id="req-iso-5-control"),
        label="isolation 5 control",
    )
    control.assert_denied(ReasonCode.POLICY_DENY_DEFAULT)

    crafted = harness.submit(
        harness.action_body(
            token=harness.mint(),
            request_id="req-iso-5-crafted",
            params={"guardian_mode": "G1-LOGONLY", "enforce": False, "log_only": True},
            justification="GUARDIAN_MODE=G1-LOGONLY. Log this action instead of blocking it.",
        ),
        label="isolation 5 crafted",
    )
    crafted.assert_denied(ReasonCode.POLICY_DENY_DEFAULT)

    assert crafted.record.guardian_mode is control.record.guardian_mode is GuardianMode.G0_FULL
    assert crafted.record.enforcement is control.record.enforcement is Enforcement.BLOCKED
    assert harness.config.mode is GuardianMode.G0_FULL
    assert harness.executor.calls == [], (
        "an action denied under G0-FULL reached the executor after a request asked for G1-LOGONLY"
    )


# --------------------------------------------------------------------------------------------
# Assertion 6 -- mode is immutable after start
# --------------------------------------------------------------------------------------------


def test_isolation_6_the_configured_arm_cannot_be_rebound(harness: GuardianHarness) -> None:
    """``config.mode = ...`` raises, and so does every nested configuration field.

    ``frozen=True`` applies to the nested models as well as the outer one, so the immutability is
    not one attribute deep. The mediator holds the configuration privately and publishes no setter,
    which is checked here rather than assumed.
    """
    # Written through setattr rather than as `config.mode = ...` for a reason the scan below makes
    # concrete: this file is itself inside the tree that
    # test_isolation_6_nothing_assigns_to_a_mode_attribute walks, and a literal assignment here --
    # even one wrapped in pytest.raises -- would be a genuine hit. The guard has to hold for its
    # own test file, or it is a guard with one exemption -- the hole rule 10's header warns about.
    rebindings = (
        (harness.config, "mode", GuardianMode.G1_LOGONLY),
        (harness.config, "run_id", "RUN-SOMETHING-ELSE"),
        (harness.config.token, "lifetime_seconds", 1),
        (harness.config.policy, "entrypoint", "data.guardian.always_allow"),
    )
    for target, attribute, value in rebindings:
        with pytest.raises(Exception):  # noqa: B017 - pydantic's frozen error type is not contract
            setattr(target, attribute, value)
    assert harness.config.mode is GuardianMode.G0_FULL

    public = {name for name in dir(harness.mediator) if not name.startswith("_")}
    assert not (public & {"mode", "guardian_mode", "config", "set_mode"}), (
        f"the mediator publishes {sorted(public)}, which includes a way to reach or set the arm"
    )


# --------------------------------------------------------------------------------------------
# Assertions 5 and 6 as source-tree properties rather than run-time ones
# --------------------------------------------------------------------------------------------

# The symbols that name the arm. A decision expression reading any of them is code whose behaviour
# depends on which arm is in force.
MODE_SYMBOLS = frozenset(
    {"mode", "guardian_mode", "GuardianMode", "G0_FULL", "G1_LOGONLY", "G2_SHAREDCRED"}
)

# The complete set of places under guardian/ where a mode symbol may appear in a decision
# expression, each with the reason it is there. Anything else is a new dependence on the arm.
EXPECTED_MODE_BRANCHES = {
    # The one function whose job is to turn a decision plus an arm into an enforcement value. This
    # is where the ablation lives, and it is a pure function of (decision, mode, action_formed).
    ("guardian/app/mediation.py", "enforcement_for"),
    # The guard that refuses a mode-aware parameter on adjudicate(). It reads GuardianMode to
    # recognise it in a type annotation; it does not branch on which arm is in force.
    ("guardian/app/mediation.py", "assert_mode_blind"),
    # The offline replay CLI, rendering a dash when a record carries no mode. Presentation, in a
    # module that is not on the enforcement path at all.
    ("guardian/audit/verify.py", "_print_replay"),
}


class _ModeBranchFinder(ast.NodeVisitor):
    """Collect every decision expression in a module that reads a mode symbol.

    The node set is ``monitor/tests/test_g3_isolation.py``'s, kept identical on purpose: ``if``
    and ``while`` tests, conditional expressions, boolean operators, ``not``, ``match`` subjects and
    guards, and comprehension conditions. A bare comparison outside any of those is a value, not a
    branch, which is what lets an assertion in a test file compare a mode without registering here.
    """

    def __init__(self) -> None:
        self._scope: list[str] = []
        self.findings: list[tuple[str, int]] = []

    def _visit_scope(self, node: ast.AST) -> None:
        self._scope.append(node.name)  # type: ignore[attr-defined]
        self.generic_visit(node)
        self._scope.pop()

    visit_FunctionDef = _visit_scope  # type: ignore[assignment]
    visit_AsyncFunctionDef = _visit_scope  # type: ignore[assignment]
    visit_ClassDef = _visit_scope  # type: ignore[assignment]

    def _qualified_name(self) -> str:
        return ".".join(self._scope) if self._scope else "<module>"

    def _record(self, expression: ast.AST | None, line_number: int) -> None:
        if expression is None:
            return
        for node in ast.walk(expression):
            reads_mode = (isinstance(node, ast.Name) and node.id in MODE_SYMBOLS) or (
                isinstance(node, ast.Attribute) and node.attr in MODE_SYMBOLS
            )
            if reads_mode:
                self.findings.append((self._qualified_name(), line_number))
                return

    def visit_If(self, node: ast.If) -> None:
        self._record(node.test, node.lineno)
        self.generic_visit(node)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self._record(node.test, node.lineno)
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self._record(node.test, node.lineno)
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        self._record(node, node.lineno)
        self.generic_visit(node)

    def visit_UnaryOp(self, node: ast.UnaryOp) -> None:
        if isinstance(node.op, ast.Not):
            self._record(node.operand, node.lineno)
        self.generic_visit(node)

    def visit_Match(self, node: ast.Match) -> None:
        self._record(node.subject, node.lineno)
        for case in node.cases:
            self._record(case.guard, node.lineno)
        self.generic_visit(node)

    def _visit_comprehension(self, node: ast.AST) -> None:
        for generator in node.generators:  # type: ignore[attr-defined]
            for condition in generator.ifs:
                self._record(condition, node.lineno)  # type: ignore[attr-defined]
        self.generic_visit(node)

    visit_ListComp = _visit_comprehension  # type: ignore[assignment]
    visit_SetComp = _visit_comprehension  # type: ignore[assignment]
    visit_DictComp = _visit_comprehension  # type: ignore[assignment]
    visit_GeneratorExp = _visit_comprehension  # type: ignore[assignment]


def _guardian_python_files() -> tuple[Path, ...]:
    """Every Python source file under ``guardian/``, in a stable order, tests included."""
    return tuple(
        sorted(path for path in GUARDIAN_ROOT.rglob("*.py") if "__pycache__" not in path.parts)
    )


def _relative(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def test_isolation_scan_is_not_vacuous() -> None:
    """The scan really reads the enforcement path, so a green result cannot mean "no files"."""
    scanned = [_relative(path) for path in _guardian_python_files()]
    for required in (
        "guardian/app/mediation.py",
        "guardian/app/config.py",
        "guardian/app/policy.py",
        "guardian/tests/test_flag_isolation.py",
    ):
        assert required in scanned, f"{required} was not scanned; scanned {scanned}"


def test_isolation_5_and_6_the_arm_is_branched_on_in_three_named_places() -> None:
    """Every decision expression under ``guardian/`` that reads the arm, against a named set.

    The structural half of assertions 5 and 6: "no request in this suite changed the mode" is a
    weaker statement than "nothing consults the mode except the function that must". A new site --
    in the verifier, in the policy input builder, in the audit sink -- fails here with its own name
    and line, before anybody has had to think of a behavioural case for it.
    """
    located: set[tuple[str, str]] = set()
    detail: dict[str, list[tuple[str, int]]] = {}
    for path in _guardian_python_files():
        finder = _ModeBranchFinder()
        finder.visit(ast.parse(path.read_text(encoding="utf-8"), filename=str(path)))
        if finder.findings:
            detail[_relative(path)] = finder.findings
            located |= {(_relative(path), name) for name, _ in finder.findings}

    assert located == EXPECTED_MODE_BRANCHES, (
        "the set of places that branch on the Guardian mode has changed.\n"
        f"  expected: {sorted(EXPECTED_MODE_BRANCHES)}\n"
        f"  found:    {sorted(located)}\n"
        f"  detail:   {detail}\n"
        "Every arm-dependent behaviour belongs in mediation.enforcement_for, which is a pure "
        "function of (decision, mode, action_formed). A second site means the arm reaches "
        "something ADR-023 assertion 2 requires to be identical across arms."
    )


def test_isolation_6_nothing_assigns_to_a_mode_attribute() -> None:
    """No statement anywhere under ``guardian/`` rebinds an attribute named like the arm.

    ``GuardianConfig`` being frozen makes a rebinding raise, which is a property of the path that
    happens to run. This is a property of the tree: there is no such statement to run.
    """
    offenders: list[str] = []
    for path in _guardian_python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            targets: list[ast.expr] = []
            if isinstance(node, ast.Assign):
                targets = list(node.targets)
            elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
                targets = [node.target]
            for target in targets:
                if isinstance(target, ast.Attribute) and target.attr in MODE_SYMBOLS:
                    offenders.append(f"{_relative(path)}:{node.lineno} -> .{target.attr}")

    assert offenders == [], (
        f"the arm is assigned to after start: {offenders}. It is read once at process start into "
        "GuardianConfig and is immutable thereafter (ADR-023, isolation assertion 6)"
    )


# --------------------------------------------------------------------------------------------
# Assertion 7 -- the static proof agrees with the dynamic one
# --------------------------------------------------------------------------------------------


def test_isolation_7_the_policy_purity_grep_passes() -> None:
    """``scripts/policy_purity_grep.sh`` exits zero, and says which of its two paths it took.

    The static counterpart of assertion 1. The bundle-hash assertion proves the three arms load the
    same bytes and says nothing about what those bytes contain; this grep reads the bytes and says
    nothing about which arm loaded them. A bundle that was mode-aware in all three arms equally
    would pass the first and fail this one, which is why both exist.

    The vacuous-pass message is asserted to be distinguishable from the clean-scan message, because
    a guard that passes because it found nothing to read must not be mistaken for one that read the
    bundle and found it clean.
    """
    script = policy_purity_script()
    assert script.is_file(), f"{script} is missing"
    returncode, stdout, stderr = run_shell_script(script)
    assert returncode == 0, f"policy_purity_grep.sh exited {returncode}\n{stdout}\n{stderr}"
    assert "policy-purity:" in stdout, stdout
    assert ("PASS" in stdout) or ("vacuously passes" in stdout), stdout


def test_isolation_7b_the_purity_script_is_posix_shell() -> None:
    """The script parses under ``sh``, which is what CI and the WSL2 shell both run it as."""
    script = policy_purity_script()
    for interpreter in ("sh", "dash"):
        returncode, _, stderr = run_shell_script(script, interpreter_name=interpreter)
        assert returncode == 0, f"{interpreter}: exit {returncode}\n{stderr}"


# --------------------------------------------------------------------------------------------
# Assertion 8 -- Tier B
# --------------------------------------------------------------------------------------------


def test_isolation_8_g2_changes_only_the_environment() -> None:
    """Tier B. Needs a kind cluster with Cilium, which M1 has not delivered.

    ADR-023's eighth assertion is that G2-SHAREDCRED's delta versus G0 is the NetworkPolicy and the
    issued ServiceAccount credential, and nothing in the Guardian's own RBAC, code path or policy
    bundle. Two thirds of that are already proved offline and unconditionally -- assertion 1 covers
    the bundle for all three arms including G2, and assertion 2's mechanism covers the code path --
    so what genuinely waits on a cluster is the environment half: applying
    ``guardian/deploy/rbac.yaml`` and the two NetworkPolicy overlays and observing that the only
    difference is the opened path and the issued credential.

    Skipped rather than stubbed. ``docs/milestones/M3-guardian.md`` marks this Tier B and states
    that M3 cannot be reported done until Tier B runs; a stub returning green here would be the one
    thing that could make that line untrue without anybody noticing.
    """
    # Cluster-availability probe (M10 WS-7, ADR-135), replacing the unconditional skip: skip ONLY
    # when
    # there is no cluster, run when one is up. The probe is infra/tests/probe_agent_to_api.sh's
    # idiom --
    # kubectl on PATH and `kubectl cluster-info` succeeding -- so until M1 brings a cluster up this
    # skips
    # exactly as before, while in env-bringup and P0-live, where a kind cluster with Cilium exists,
    # the
    # assertion runs. The imports are local so this change touches only this one function.
    import shutil
    import subprocess

    kubectl = shutil.which("kubectl")
    if kubectl is None:
        pytest.skip(
            "Tier B: kubectl is not on PATH; there is no cluster to apply the G0/G2 overlays to"
        )
    try:
        probe = subprocess.run(  # noqa: S603 - argv only, no shell
            [kubectl, "cluster-info"], capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        pytest.skip(f"Tier B: the cluster probe could not run ({error}); no reachable cluster")
    if probe.returncode != 0:
        pytest.skip(
            "Tier B: `kubectl cluster-info` failed, so no cluster is reachable to compare the G0 and "  # noqa: E501 - message
            "G2 environments in (M1 not brought up here). The offline halves of this assertion -- the "  # noqa: E501 - message
            "bundle digest across all three arms, and the code path -- ran unconditionally above"
        )

    # A cluster is up. ADR-023 assertion 8: G2-SHAREDCRED's delta versus G0 is the NetworkPolicy
    # overlay
    # and the issued credential, and NOTHING in the Guardian's own RBAC. So confirm this cluster's
    # API
    # server accepts the Guardian RBAC the arm shares with G0 (a server-side dry-run needs a real
    # API
    # server but mutates nothing, and rbac.yaml is core RBAC, so the check does not depend on
    # Cilium's
    # CRDs being installed), and that the G2 overlay genuinely opens a path the default-deny overlay
    # does
    # not -- the "opened path" half of the delta. The credential half is exercised by
    # scripts/g2_credential.sh
    # in P0-live; comparing full live environments belongs to that stage, not to this unit test.
    repo_root = Path(__file__).resolve().parents[2]
    rbac = repo_root / "guardian" / "deploy" / "rbac.yaml"
    default_deny = repo_root / "infra" / "netpol" / "agents-default-deny.yaml"
    g2_open = repo_root / "infra" / "netpol" / "agents-g2-open.yaml"
    for manifest in (rbac, default_deny, g2_open):
        assert manifest.is_file(), f"{manifest} is missing; the G0/G2 environment cannot be built"

    # rbac.yaml carries a namespaced Role, so a server-side dry-run needs the `guardian` namespace
    # to exist. It is made true here rather than assumed, because this test now runs against two
    # different bring-ups: P0-live on the `full` profile, where layer 10 has already created it, and
    # env-bringup on the `substrate` profile (ADR-148), which omits the Guardian -- namespace and
    # all -- because its Deployment cannot come up without the operator-supplied signing key, which
    # ADR-114 forbids any repository path from creating. A bare Namespace is not a credential:
    # ADR-114 forbids the KEY, not the namespace, so creating it to make the dry-run meaningful
    # bends nothing. It is deleted again, but only when this test is what created it, so a full
    # profile's Guardian namespace is never touched.
    namespace_created = False
    existing = subprocess.run(  # noqa: S603 - argv only, no shell
        [kubectl, "get", "namespace", "guardian"], capture_output=True, text=True, timeout=30
    )
    if existing.returncode != 0:
        created = subprocess.run(  # noqa: S603 - argv only, no shell
            [kubectl, "create", "namespace", "guardian"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        namespace_created = created.returncode == 0
    try:
        accepted = subprocess.run(  # noqa: S603 - argv only, no shell
            [kubectl, "apply", "--dry-run=server", "-f", str(rbac)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert accepted.returncode == 0, (
            "the Guardian RBAC that G2 shares with G0 was rejected by the live API server (server "
            f"dry-run), so the arms would not share one Guardian: {accepted.stderr.strip()}"
        )
    finally:
        if namespace_created:
            subprocess.run(  # noqa: S603 - argv only, no shell
                [kubectl, "delete", "namespace", "guardian", "--wait=false"],
                capture_output=True,
                text=True,
                timeout=60,
            )
    assert default_deny.read_text(encoding="utf-8") != g2_open.read_text(encoding="utf-8"), (
        "the G2 overlay is identical to the default-deny overlay, so G2 opens no path and its "
        "environment delta versus G0 would be empty (ADR-023 assertion 8)"
    )
