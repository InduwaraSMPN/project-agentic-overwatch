# Shadow-Mode Rollout Guide

Status: active | M8 task T8.5 | Closes traceability row T-29 (`docs/05-traceability-matrix.md`)
Scope: packaging/ops guidance for a deployed, non-experiment installation of the frozen `v1.0`
artifact. Nothing here changes agent, Guardian or Monitor behavior (iron rule 6, `AGENTS.md`;
M8 scope note, `docs/milestones/M8-hardening.md`: "WITHOUT altering frozen v1.0 evaluation
behavior").

## 1. Why shadow-mode-first

`docs/protocols/security-policy.md` section 4 states the mandate this guide exists to satisfy:

> Responsible framing: RQ3 is characterised, not a safety guarantee; M8 mandates
> shadow-mode-first (G1-LOGONLY) before any enforcement in a real setting.

`docs/07-glossary-and-ids.md` defines the term this guide operationalizes:

> **Shadow mode** G1-LOGONLY used as production staged-rollout mechanism (M8).

The reasoning is the same one that makes `G1-LOGONLY` useful as an evaluation ablation arm
(`docs/07-glossary-and-ids.md` Condition IDs table: "Guardian logs, does not block"): the deny
policy runs for real, against real traffic, and every decision it would have enforced is
audited -- but nothing is actually blocked. That lets an operator find out what the policy
*would* do to a live environment before letting it *do* it. This guide is the production use of
that mechanism; it is distinct in purpose (not degree) from the GATE pilot's use of the same
`G1-LOGONLY` arm as an evaluation condition (`docs/milestones/GATE-pilot.md`, traceability row
T-26) -- same underlying mechanism, different reason for invoking it.

This is not a substitute for the residuals recorded elsewhere. In particular
`docs/02-architecture.md` section 6 and `docs/protocols/security-policy.md` section 6 record that
capability issuance authenticates no caller (`POST /v1/tokens` accepts a self-declared
`supervisor_id`/`executor_id`); shadow mode observes what the *policy* would enforce, it does not
close that separate, stated gap. Do not read a clean shadow window as resolving it.

## 2. Prerequisites

- The `v1.0` tag: this guide assumes the frozen artifact, not a development checkout.
- A cluster reachable by the operator, with the Guardian's signing-key Secret already created
  out of band -- see `docs/ops/secrets.md` (T8.2, authored alongside this file) for how that
  Secret and the rest of the deployment's credentials are provisioned and rotated. This guide
  never creates, prints or handles that key.
- The Helm chart under `deploy/helm/agentic-overwatch` (T8.1, authored alongside this file)
  installed for the target namespace(s), and image/version pins resolved per `infra/versions.env`
  the way `docs/04-repo-conventions.md` describes for the dev cluster. As of this writing the
  chart is complete, including `templates/guardian/deployment.yaml` -- see section 3.5 for what
  that template's actual content means for how a mode change must be applied.
- A values override supplying every field `deploy/helm/agentic-overwatch/values.yaml` marks
  `REQUIRED` (Helm's `required` function, enforced by `templates/guardian/configmap-runtime.yaml`
  at render time): `guardian.token.ttlSeconds`, `.maxTtlSeconds`, `.algorithm`,
  `.replayCacheEntries`, `.replayCacheWindowSeconds` (copied from
  `docs/protocols/security-policy.md` section 2, the single source of truth for those numbers --
  the chart deliberately does not default them) and `guardian.auditLogPath` (section 3.4 below).
  A shadow or enforce install cannot render at all without these; that is deliberate fail-closed
  behavior, the same direction `guardian/app/config.py` itself fails closed in.
- `docs/ops/runbook.md` (T8.3, authored alongside this file) read first for the general deploy,
  observe, incident-triage and rollback procedures this guide assumes as background. This file is
  the deep-dive for exactly one step of that runbook -- "promote from shadow to enforce" -- and
  the runbook's promotion step should link back here rather than duplicate section 5 below.

## 3. The mechanism: how the mode is selected (Helm values, not code)

### 3.1 What decides Guardian behavior, structurally

`guardian/app/config.py` is the single place the Guardian's condition arm is read, and it is
deliberately narrow (module docstring, `guardian/app/config.py` lines 1-37):

- The arm is read from exactly one environment variable, `GUARDIAN_MODE` (`MODE_ENV_VAR`), once,
  at process start. `GuardianConfig` is a frozen model -- `config.mode = ...` raises at run time
  (`guardian/app/config.py` line 61 area; `GuardianConfig` docstring).
- The accepted values are `guardian.app.models.GuardianMode`'s three members: `G0-FULL`,
  `G1-LOGONLY`, `G2-SHAREDCRED` (`guardian/app/models.py` lines 579-598). `G3-UNQUOTED` is not a
  Guardian mode at all -- it is the Monitor's aggregator-quoting flag
  (`docs/02-architecture.md` section 4) -- and `GUARDIAN_MODE=G3-UNQUOTED` is rejected by name at
  startup, same as any other unrecognised string.
- **Fail-closed in both directions** (`guardian/app/config.py` `_parse_mode` docstring, lines
  428-441): an absent or blank value defaults to `G0-FULL` -- full mediation, "the arm with the
  most enforcement" -- so a missing or blank values entry can only leave the Guardian strict, never
  silently weaken it. A *present* but unrecognised value (a typo, a stale spelling, an old
  underscore form like `G1_LOGONLY`) raises `GuardianStartupError` and refuses to start, naming the
  accepted set -- it never falls back to a default the operator did not choose.
- **Mode is not request-settable.** No field of `ActionRequest` may be named or typed like a mode
  (`MODE_SHAPED_FIELD_NAMES`, enforced at import time by `guardian.app.models.reject_field_names`
  and `reject_field_types`); the only way a mode reaches the Guardian is the environment variable
  read once at start. This is the same structural guarantee `.agents/rules/10-guardian-first.md`
  and iron rule 1 require for the experiment context, and it holds identically in a deployed one:
  the code path that reads the mode does not change between "runner drives a campaign" and
  "operator runs a production Guardian".

### 3.2 How the experiment context sets it (for reference, not to be copied verbatim)

In the campaign/experiment context, the mode is never chosen by editing Guardian code or policy.
It comes from exactly one table, `runner/conditions.py`'s `CONDITION_FLAGS` (ADR-040; docstring,
`runner/conditions.py` lines 1-27), which maps each of the six canonical condition arms to a
`ConditionFlags` tuple naming, among other things, `guardian_mode`. `scripts/guardian_deploy.sh`
reads that resolved value from `$GUARDIAN_MODE` (defaulting to `G0-FULL`, validated against
`G0-FULL|G1-LOGONLY|G2-SHAREDCRED`), writes it into a `guardian-runtime` ConfigMap
(`--from-literal="GUARDIAN_MODE=$mode"`), applies `guardian/deploy/deployment.yaml` (whose
container reads that ConfigMap via `envFrom: configMapRef: name: guardian-runtime`), and restarts
the Guardian Deployment so the new process picks up the value. `docs/02-architecture.md` section 4
records the same fact in the condition-arms table: "G1-LOGONLY | Guardian logs but does not block
| Guardian mode flag from runner".

### 3.3 How a deployed (non-experiment) installation sets it

There is no runner and no campaign manifest driving a production installation, so "the runner's
condition flags" is not itself the mechanism available here -- but the underlying contract in
section 3.1 is exactly the same one both contexts have to satisfy, because it is the only door
`guardian/app/config.py` opens. T8.1's Helm chart is the deployed-context equivalent of
`runner/conditions.py` plus `scripts/guardian_deploy.sh`, and as of this writing it has landed
far enough to confirm the mechanism directly from its own source rather than by inference:

- **The values key is `guardian.mode`**
  (`deploy/helm/agentic-overwatch/values.yaml`, `guardian:` block), documented in that file in
  its own words: "This is the ONLY values flag that reaches Guardian's arm, and it reaches it
  exactly the way `scripts/guardian_deploy.sh` already does: as the `GUARDIAN_MODE` key of the
  `guardian-runtime` ConfigMap, read once at process start by
  `guardian/app/config.py::_parse_mode`. No template in this chart brings a second mode path
  into existence, and no Guardian source file is templated, patched or forked."
  Accepted values are commented at the same site as `G0-FULL | G1-LOGONLY | G2-SHAREDCRED`,
  matching `guardian.app.models.GuardianMode` exactly (section 3.1).
- **The rendering is confirmed, not inferred**: `templates/guardian/configmap-runtime.yaml`
  renders `data.GUARDIAN_MODE: {{ .Values.guardian.mode | quote }}` into a ConfigMap literally
  named `guardian-runtime` in the Guardian namespace -- the identical name
  `guardian/deploy/deployment.yaml`'s `envFrom.configMapRef` already expects. The chart is a
  drop-in producer for a key the existing Guardian container spec already consumes; no change to
  Guardian code, to Guardian policy, or to `guardian/deploy/deployment.yaml`'s contract is
  involved anywhere in this path.
- **The chart's default is `guardian.mode: G0-FULL`** -- full mediation, mirroring
  `guardian/app/config.py`'s own safe-default direction (section 3.1) rather than defaulting to
  shadow. **This has a direct operational consequence for this guide: a fresh install taken at
  chart defaults starts in full enforcement, not shadow.** An operator following section 5 of
  this guide MUST set `guardian.mode: G1-LOGONLY` explicitly in their values override before the
  first install or upgrade; there is no "just install it, it starts safe" path here the way there
  is for an unset/blank `GUARDIAN_MODE` at the Guardian-process level. State this explicitly in
  the values override and in the runbook's deploy log (section 7, item 1) -- do not rely on the
  chart default to put a fresh deployment into shadow.
- `G2-SHAREDCRED` remains out of scope for this guide regardless of the chart default: it is an
  ablation-study arm (opens the agent-to-cluster NetworkPolicy via the chart's separate
  `agents.networkPolicy.apiServerReach` / `agents.g2.enabled` toggles and issues shared
  ServiceAccounts), not a production rollout stage, and setting it here would be a security
  regression rather than a step between shadow and enforce.

### 3.4 The audit-log path for a standing (non-campaign) deployment

`guardian.auditLogPath` is `REQUIRED` with no default (`values.yaml`: `auditLogPath: ~`,
enforced by `templates/guardian/configmap-runtime.yaml`'s `required` guard, which names this
guide by task id as the place that documents the naming convention for a standing deployment --
`scripts/guardian_deploy.sh`'s per-attempt `<run-id>-<attempt>.jsonl` convention does not apply
here, because `guardian.runId` is legitimately blank for a standing deployment
(`guardian/app/config.py`'s "development posture" reading) and there is no attempt to suffix.

This guide's convention: set `guardian.auditLogPath` to one **fixed** path directly under the
Guardian's audit volume for the life of the deployment, e.g.
`/var/lib/guardian/audit/guardian_audit.jsonl` (the same base filename the repository's own
audit fixtures use, `guardian/audit/fixtures/clean/guardian_audit.jsonl`, for a chain with no
run-id segmentation). Do **not** change this path when flipping between shadow and enforce
(sections 8-9) -- keeping it fixed is what makes the mode-flip visible as a transition inside one
continuous, hash-chained history rather than as a break between two unrelated files, which
section 8 step 3 and section 9 step 2 both depend on.

### 3.5 The restart requirement -- confirmed mandatory, not automatic

Because `GuardianConfig` is read once at process start and is immutable afterward (section 3.1),
a `helm upgrade` that changes `guardian.mode` does **not** take effect until the Guardian pod
restarts -- an env var injected via `envFrom` is read when a container starts, never re-read
while it runs. Whether `helm upgrade` alone is enough depends on whether the Deployment's pod
template changes bytes when only the referenced ConfigMap's data changes; a config-checksum
annotation on the pod template (a common Helm pattern) would make it change, and force a
rollout automatically.

**`templates/guardian/deployment.yaml` carries no such annotation** (read directly: its
`envFrom.configMapRef` at lines 38-40 is the only reference to `guardian-runtime`, and nothing
in the template hashes that ConfigMap's content into a pod-template field). A `helm upgrade
--set guardian.mode=...` therefore changes the ConfigMap's `GUARDIAN_MODE` value while leaving
the running Guardian pod's spec, and its already-injected environment, untouched -- Kubernetes
has no reason to create a new ReplicaSet, and `kubectl rollout status` run immediately afterward
will report success instantly without anything having restarted, because nothing in the
Deployment changed. **A mode change is therefore never complete until an explicit rollout is
requested as its own step**, every time, regardless of how the values change was applied:

```
kubectl -n <guardian-namespace> rollout restart deployment/guardian
kubectl -n <guardian-namespace> rollout status deployment/guardian --timeout=300s
```

This is the same step `scripts/guardian_deploy.sh` already performs unconditionally after every
ConfigMap rewrite in the experiment context, for the identical reason. Do not treat a `helm
upgrade --wait` return, or a `rollout status` run without first issuing `rollout restart`, as
confirmation that the mode actually changed -- confirm instead by reading the mode back from a
fresh decision record (section 5 step 1, section 8 step 3) or from the running pod's own
environment, not from the ConfigMap alone, since the ConfigMap can legitimately disagree with
what the running process actually holds until the restart happens.

## 4. What G0-FULL and G1-LOGONLY actually do (so the audit log reads correctly)

The policy is evaluated identically in both modes; only what happens to a deny differs. This is
not an approximation -- it is a tested property (`docs/05-traceability-matrix.md` row T-13; the
isolation assertion in `guardian/app/mediation.py` line ~47-49, ~1101): a G0-FULL and a
G1-LOGONLY Guardian, given the same request sequence, produce audit records that differ in
**only** three things -- the `guardian_mode` field, the `enforcement` field, and the execution
block. `decision`, `reason_code`, `policy_rule_id`, ordering and `jti` are identical.

`guardian/app/mediation.py`'s `enforcement_for(decision, mode, action_formed)` is the one
expression on the decision path that reads the mode (lines 505-536):

| Mode | permit | deny | no action formed |
|---|---|---|---|
| `G0-FULL` | `executed` | `blocked` | `not-applicable` |
| `G1-LOGONLY` | `executed` | `executed` | `not-applicable` |
| `G2-SHAREDCRED` | `executed` | `blocked` | `not-applicable` |

In other words: under `G1-LOGONLY`, a `deny` decision is still logged as `decision: deny`, with
its reason code and rule id, but `enforcement: executed` -- the action the policy would have
stopped under `G0-FULL` is carried out anyway. That is what "logs, does not block" means at the
record level, and it is the exact signal shadow-mode review reads (section 5).

Every decision, executed or not, gets a paired `ExecutionRecord` (audit schema v4,
`docs/02-architecture.md` lines 99-104) recording `execution_status in {succeeded, failed,
not-attempted}` -- appended after **every** decision, not only an executed one, so record count
and chain position never diverge between arms (ADR-082). Cross-reference a shadow-denial's
`decision_seq` against its `ExecutionRecord` to see what actually happened when that
policy-denied-but-executed action ran.

## 5. Deploying in shadow (step 1)

1. Set `guardian.mode: G1-LOGONLY` explicitly in the operator's values override (section 3.3 --
   the chart default is `G0-FULL`, so this step cannot be skipped), set `guardian.auditLogPath`
   per section 3.4's fixed-path convention, and supply the required `guardian.token.*` fields
   from `docs/protocols/security-policy.md` section 2 (section 2 above). Install, then explicitly
   restart per section 3.5 -- a first install creates the pod fresh either way, so this matters
   most from the first mode *change* onward, but running the restart step is harmless on a fresh
   install too and keeps the procedure identical every time. Confirm the Guardian came up in the
   intended mode (its own startup path fails closed on a typo, so a running pod is itself weak
   evidence the value parsed -- confirm with `kubectl -n <guardian-namespace> logs
   deployment/guardian` showing a clean start, and with a decision record's own `guardian_mode`
   field once real traffic starts flowing).
2. Confirm the audit volume is durable and reachable for review: the PersistentVolumeClaim
   `templates/guardian/pvc.yaml` provisions (the chart's templated equivalent of
   `guardian/deploy/deployment.yaml`'s own `guardian-audit` PVC), mounted by
   `templates/guardian/deployment.yaml` at `/var/lib/guardian/audit`, should survive pod
   restarts, and should hold the one continuous chain named by `guardian.auditLogPath` (section
   3.4) -- not the per-run `RUN-<COND>-...`-segmented layout the experiment context uses.
3. Let the deployment run in shadow against real traffic for an observation window the operator
   sets (section 6 -- these are operational judgment calls, not dissertation evaluation
   parameters; `docs/protocols/evaluation-protocol.md` single-homes those numbers for the
   *campaign*, and a production rollout window is a different concern the protocol does not, and
   should not, own).

## 6. What to look for in the audit log during shadow

Everything below reads the audit chain the Guardian already writes (section 4's schema); nothing
here requires new tooling beyond what the repo already ships.

1. **Verify the chain first.** `make audit-verify P=<path to the mounted audit volume>` (or
   `sh scripts/audit_verify.sh` directly per `docs/04-repo-conventions.md`'s script map,
   `HEAD=<sha256>` optional as an anchor) before trusting anything read from it. A broken chain
   invalidates the review, not just the affected records.
2. **Pull every shadow denial**: records where `decision = deny` and `enforcement = executed`.
   Under `G0-FULL` these same records would read `enforcement: blocked` -- table in section 4.
   Each one is a concrete answer to "what would the policy have stopped here, and was that the
   right call against what was actually happening at the time."
3. **For each shadow denial, read three things together**: the record's `reason_code` and
   `policy_rule_id` (which `guardian/policies/` rule fired and why -- see `guardian/README.md` and
   `guardian/policies/` for the rule set), the paired `ExecutionRecord`'s `execution_status` (what
   happened when the action ran anyway), and whatever independent incident/observability signal
   the operator has for that time window (the runbook's incident-triage section,
   `docs/ops/runbook.md`, is where that correlation procedure belongs).
4. **Classify each shadow denial** into exactly one of:
   - **Correct** -- the action matched real attacker or misconfiguration behavior; blocking it
     under `G0-FULL` would have been the right outcome.
   - **Policy gap (false positive)** -- the action was legitimate operator or workload behavior
     that the policy would incorrectly have blocked.
   - **Ambiguous / needs more signal** -- cannot be classified from the audit record and
     correlated evidence alone; carry it to the next window rather than guessing.
5. **Watch for the absence of denials, too.** A shadow window with zero `deny` records is not on
   its own evidence of safety -- it may mean the policy never saw the traffic shape it exists to
   catch. Cross-check against the runbook's observability section for whether the expected
   incident classes actually occurred during the window; an empty shadow log from a quiet period
   proves less than an empty shadow log from a busy one.
6. **Never treat a clean shadow window as closing the issuance residual.** Section 1's caveat
   again, because it is easy to read "no denials" as "safe": `POST /v1/tokens` still authenticates
   no caller (`docs/protocols/security-policy.md` section 6). Shadow mode reviews the *policy*,
   not that separate, stated gap.

## 7. Promotion criteria (shadow -> enforce)

These are operator-facing rollout criteria for a production deployment, not dissertation
evaluation parameters -- `docs/protocols/evaluation-protocol.md` owns the latter and this section
does not restate or compete with anything it single-homes. Promote from `G1-LOGONLY` to `G0-FULL`
only when **all** of the following hold:

1. The shadow window covered a length of real operation the operator judges representative of
   the deployment's actual traffic and incident patterns (a quiet weekend is not a substitute for
   a normal business cycle; the operator sets and records this window's actual duration and
   rationale in the runbook's deploy log, `docs/ops/runbook.md`).
2. Every shadow denial in that window (section 6, step 2) has been triaged and classified
   (section 6, step 4) -- no shadow denial left "ambiguous" without an explicit decision to accept
   that ambiguity and promote anyway, recorded as such.
3. Every **policy gap** found is resolved, not merely noted: either the policy is fixed
   deliberately in `guardian/policies/`, with a comment and an ADR entry
   (`.agents/rules/10-guardian-first.md`: "Never weaken guardian/policies/ to make a test pass...
   extend the policy deliberately, with a comment and an ADR note"), and the fix has been
   re-observed clean in a subsequent shadow window; or the false positive is explicitly accepted
   as a known, documented, signed-off limitation rather than silently promoted past.
4. The audit chain for the full shadow window verifies clean end to end
   (`make audit-verify`, section 6 step 1) with no unexplained tamper or gap.
5. No unresolved `execution_status: failed` on an `ExecutionRecord` paired to a shadow denial that
   should have executed without incident -- an unexplained execution failure during shadow means
   promoting to enforce would be blocking based on an unverified assumption about what "blocked"
   will actually do to that action path.
6. Sign-off is recorded: who reviewed the window, what window it covered, and the disposition of
   every policy gap found. `docs/ops/runbook.md` is where this sign-off record belongs
   operationally; this guide defines what must be true before it is given, not where it is filed.

A rollout that skips a criterion is not a faster promotion -- it is enforcement against an
unreviewed policy, which is exactly the risk shadow-mode-first exists to prevent (section 1).

## 8. Flipping to enforce (step 2)

1. Confirm section 7's criteria are met and signed off.
2. Set `guardian.mode: G0-FULL` via the same values override (section 3.3) and the same
   redeploy/restart step (section 3.5), **leaving `guardian.auditLogPath` unchanged** (section
   3.4) -- never a Guardian code or policy edit.
3. Confirm the flip landed: a fresh decision record after the restart should
   show `guardian_mode: G0-FULL` (`docs/02-architecture.md` lines 91-98). Because
   `guardian.auditLogPath` was held fixed across the flip (section 3.4), the
   point where `guardian_mode` changes from `G1-LOGONLY` to `G0-FULL` in that one chain is itself
   chain-verifiable, tamper-evident evidence of exactly when enforcement began -- no separate
   change log is needed to answer "when did this go live."
4. Watch the first post-flip window closely: any action that was a shadow denial before the flip
   and is now actually blocked (`enforcement: blocked`) is expected behavior, not a regression --
   confirm it against the classification from section 6/7 rather than reflexively rolling back.
5. Hand off to `docs/ops/runbook.md`'s incident-triage procedure for ongoing operation under
   `G0-FULL`; this guide's job ends at a confirmed, evidenced flip.

## 9. Rolling back to shadow

Rollback uses the identical mechanism in reverse -- this is deliberate: shadow and enforce are
two values of the same flag behind the same fail-closed config module (section 3.1), not two
different deployment paths, so there is nothing rollback-specific to build or maintain separately.

1. Set `guardian.mode` back to `G1-LOGONLY` via section 3.3's values override, redeploy/restart
   the same way (section 3.5), and leave `guardian.auditLogPath` unchanged (section 3.4).
2. Confirm the flip in the audit chain the same way section 8 step 3 does, in reverse.
3. Rollback is warranted whenever enforcement is blocking something it should not be -- a false
   positive discovered live rather than in shadow, an unanticipated interaction with a workload
   the shadow window did not cover, or any incident where the safer immediate move is "stop
   blocking, keep observing" rather than "keep blocking while investigating." Follow
   `docs/ops/runbook.md`'s incident-triage and rollback procedure for the decision to roll back
   and the surrounding response; this section only re-states the mechanism, which rollback shares
   with promotion.
4. A rollback does not erase what enforcement already did while it was active -- every blocked
   decision it made is already an immutable, hash-chained audit record (section 4). Rollback
   changes what happens to the *next* denied action, not what already happened to a previous one.
5. Re-enter the shadow review cycle (sections 6-7) before promoting again. A rollback is a signal
   that shadow review missed something; treat the next shadow window as needing the same scrutiny
   as the first, not an abbreviated re-check.

## 10. Mapping to T-29

`docs/05-traceability-matrix.md` row T-29: "Shadow-mode rollout documented (G1 as mechanism) |
docs/, guardian/ | M8 | runbook review | runbook | open". This file is the "docs/" half of that
row's evidence: it documents the shadow-mode-first rollout end to end -- deploy at `G1-LOGONLY`
(section 5), what to review in the audit log (section 6), objective promotion criteria (section
7), how to flip to `G0-FULL` (section 8), and how to roll back (section 9) -- with the mechanism
throughout grounded in the "guardian/" half already built: `guardian/app/config.py`'s fail-closed
mode contract, `guardian/app/mediation.py`'s `enforcement_for`, and the audit schema
`docs/02-architecture.md` records. The row's verifying check is "runbook review"; that review
should read this file together with `docs/ops/runbook.md`'s promotion step before the row moves
past `open`.

## 11. Cross-references

- `deploy/helm/agentic-overwatch/values.yaml` and
  `deploy/helm/agentic-overwatch/templates/guardian/configmap-runtime.yaml` (T8.1) -- the
  `guardian.mode` / `guardian.auditLogPath` values and the ConfigMap rendering this guide's
  section 3 reads its mechanism from directly.
- `docs/ops/runbook.md` (T8.3) -- general deploy, observe, incident-triage and rollback
  procedures; this guide is the detail behind its shadow-to-enforce promotion step.
- `docs/ops/secrets.md` (T8.2) -- how the Guardian signing key and other deployment credentials
  are provisioned and rotated; this guide assumes that provisioning is already done and never
  handles key material itself.
- `docs/02-architecture.md` sections 3-6 -- `AuditRecord`/`RunStartRecord`/`ExecutionRecord`
  schemas, the condition-arms table, and the capability-issuance residual this guide's section 1
  and section 6 caveat against.
- `docs/protocols/security-policy.md` sections 1, 4 and 6 -- Guardian invariants, the ethics/
  responsible-framing mandate this guide implements, and the issuance residual.
- `docs/05-traceability-matrix.md` row T-29 and `docs/07-glossary-and-ids.md` "Shadow mode" --
  the requirement this guide closes and the term it operationalizes.
- `.agents/rules/10-guardian-first.md` -- the guardian-first rule this guide's section 3 shows
  holds identically in a deployed context: the mode is a runner/chart flag, never a Guardian
  code or policy edit.
- `docs/milestones/M8-hardening.md` -- the task list this file is T8.5 of (T8.1 Helm chart,
  T8.2 secrets, T8.3 runbook, T8.4 SBOM/Trivy, T8.6 optional HA notes).
