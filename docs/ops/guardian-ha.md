# Guardian HA and Key-Management -- Hardening Notes

Status: forward-looking notes, non-normative -- nothing here is implemented, and no number in this
file overrides `docs/protocols/security-policy.md` or `docs/protocols/evaluation-protocol.md`, both
of which stay the sole owners of every quantitative parameter (`.agents/rules/00-source-of-truth.md`).
Task: `docs/milestones/M8-hardening.md` T8.6 (optional). Behaviour boundary: `AGENTS.md` iron rule 6
-- `v1.0` is frozen; nothing in this file changes it.

## 0. What this file is, and is not

- **Notes only.** No code, policy, or deploy manifest is changed by writing this file, and its
  existence should never be read as evidence that Guardian HA has been built. Every item below is
  tagged `[v1.0 today]` (true now, cited against the tree) or `[NOTE -- future]` (a design sketch for
  whoever eventually picks up T8.6, or its likely M9 follow-on, as real engineering work -- gated on
  its own ADR before any code lands, per `AGENTS.md` rule 5).
- Written under the same constraint every M8 task carries: hardening is "packaging/ops around the
  frozen artifact ... WITHOUT altering frozen v1.0 evaluation behavior"
  (`docs/milestones/M8-hardening.md`, Objective; `docs/protocols/security-policy.md` section 5). Any actual
  HA change would be a deploy/packaging-layer overlay -- Helm values, replica counts, a Lease object
  -- never an edit to `guardian/`, its Rego bundle (whose sha256 is identical across `G0-FULL`,
  `G1-LOGONLY` and `G2-SHAREDCRED` by ADR-023's own proof), or the enforcement/audit contract the
  campaign measured.
- Companion doc: `docs/ops/secrets.md` (owed by M8-hardening T8.2; not yet written at the time this
  note was drafted) is where the general Kubernetes-Secret wiring and rotation runbook belongs. This
  file covers the Guardian-specific signing key and HA questions and cross-references that path
  rather than duplicating it -- when it exists, treat section 3 below as an extension of it, not a second
  source for the same facts.

## 1. Guardian as the single point of enforcement

**`[v1.0 today]`** Guardian is the sole credential holder and the sole mutation path: nothing under
`agents/` may hold a Kubernetes client or reach the API server directly
(`.agents/rules/10-guardian-first.md`; grep-enforced by `scripts/grep_guard.sh`, no exemption
mechanism, on the same precedent rule 40 cites for the Monitor). Every `ActionRequest` is mediated:
verify token -> OPA policy -> execute via Guardian's own ServiceAccount -> append audit
(`docs/02-architecture.md` section 2; `guardian/README.md`).

The deployment shape backs this up structurally, not just by policy: `replicas: 1`
(`guardian/deploy/deployment.yaml:14`), one Deployment, one Service, one PersistentVolumeClaim
(`ReadWriteOnce`) for the audit volume. This is a consequence of the enforcement model, not an
oversight -- ADR-023 fixes "one Guardian process serves one arm" for the campaign, and
`GUARDIAN_RUN_ID` is rewritten per run in the live `guardian-runtime` ConfigMap by
`scripts/guardian_deploy.sh` (ADR-066, ADR-087). The process is scoped to one run/condition at a
time by design; it is not a stateless request-router that horizontal replicas could sit behind
unmodified.

**Risk.** If the single Guardian pod is unavailable, the agent layer can take no cluster action at
all -- the system fails closed, not partially. That is the correct security property
(deny-by-default, `security-policy.md` section 1.1), but in plain operations terms it is also a single
point of failure for *availability*. Whether "no agent can act while Guardian restarts" is an
acceptable window is a deployment-time decision: for the dissertation's disposable kind cluster
(`security-policy.md` section 3) it plainly is; for a customer's cluster this note flags the question
rather than answering it.

**Mitigation options that do not touch Guardian's enforcement code:**
- `[v1.0 today]` Readiness and liveness probes against `GET /healthz` already exist
  (`guardian/deploy/deployment.yaml:43-54`), so a wedged pod is taken out of Service rotation and
  restarted rather than silently hung.
- `[NOTE -- future, packaging-only]` A `PodDisruptionBudget` (useful mainly to make voluntary
  eviction during node drains explicit -- with `replicas: 1` it cannot add redundancy by itself), a
  `priorityClassName` so the scheduler is less likely to evict the Guardian pod under pressure, and
  monitoring the pod's restart count/backoff so a crash loop is visible quickly. Deploy-layer YAML
  only; no `guardian/` change.
- `[NOTE -- future]` Real redundancy is section 2 below, and it has real costs this file states rather than
  glosses over.

## 2. Availability / HA considerations

### 2.1 Replicas -- why `replicas: 2` is not a safe drop-in today

`[v1.0 today]` Two independent obstacles exist in the current code, and a future HA design has to
clear both, not just the one that is easiest to notice:

1. **Audit-chain durability.** `guardian/audit/chain.py`'s `AuditChainWriter` documents its own
   limit precisely: "One writer owns one file. Appends are serialised by a lock, because FastAPI
   serves concurrent requests and two appends racing on `head` would produce two records claiming
   the same predecessor -- a break that looks exactly like an insertion. The lock does not protect
   against two *processes*, and nothing here tries to... the Guardian is the sole writer"
   (`chain.py:547-555`). The lock itself is a plain `threading.Lock()` (`chain.py:590`) -- a
   same-process guard only. Two Guardian processes appending to the same `guardian_audit.jsonl`
   would race past it: two records could claim the same `prev_hash`, which is indistinguishable
   from a tamper-inserted record under the chain rule
   (`hash = SHA256(prev_hash || canonical_json(record))`, `docs/02-architecture.md` section 3). This is a
   concrete blocker, not a hypothetical one.
2. **Replay-state sharing -- more solved than it first looks.** The in-memory `ReplayCache` is
   explicitly documented as "deliberately process-local," but production composition already uses
   `SQLiteReplayStore` instead (`guardian/token/persistent_replay.py`, ADR-045), whose own docstring
   says it "serialises claims across threads and processes" via a `BEGIN IMMEDIATE` transaction and
   a `UNIQUE(jti)` constraint, and ADR-045 states outright that "independent Guardian processes
   sharing the configured file cannot both accept one `jti`." So the single-use-`jti` invariant
   (`security-policy.md` section 2) is, by itself, *not* what stops a second replica today -- provided every
   replica points `GUARDIAN_REPLAY_STORE_PATH` at the same file on a volume all of them can write
   with correct POSIX locking. ADR-045 names that limit itself: the guarantee is "appropriate for
   the current local Guardian deployment, not a claim of geographically distributed HA." Most
   `ReadWriteOnce` CSI volumes cannot even be mounted from a second node, and not every
   `ReadWriteMany` network filesystem implements `flock` semantics correctly. Verifying the target
   storage class's locking behaviour is a prerequisite this note flags, not a detail to assume away.

`[NOTE -- future]` Consequence: `replicas: 2` against today's code would fix nothing about (2) --
which is not actually broken, given a correctly-shared store -- while actively breaking (1). A real
HA design has to solve the audit-chain single-writer problem first, by either (a) keeping exactly
one *active* writer at a time (active-passive, fenced, tied to leader election -- see section 2.2) while
standbys stay off the write path, or (b) redesigning the append path itself, e.g. moving append
serialisation to the storage layer or to an external durable log, following the same
transactional-uniqueness pattern ADR-045 already used for the replay store. Either is a behaviour
change to `guardian/audit/` needing its own ADR before any code lands (`AGENTS.md` rule 5), and both
are out of scope for this file and for `v1.0`.

### 2.2 Leader election vs the campaign's single-holder lease -- two unrelated mechanisms

`[v1.0 today]` The repository already holds a cluster-scoped `coordination.k8s.io/v1` Lease --
`live-run-lock`, in the `guardian` namespace (ADR-087) -- held across a whole campaign attempt
(ADR-101, and its `guardian_deploy.sh` hotfix ADR-104). It is easy to mistake this for Guardian
leader election. It is not, and any future HA design must not conflate the two:

- The Lease is acquired and released by the **operator's own kubeconfig**, from runner code
  (`runner/run_lock.py`) and from `scripts/guardian_deploy.sh` -- never by the Guardian's own
  ServiceAccount, which is granted no verb on `leases.coordination.k8s.io` at all (ADR-087, decision
  1, explicit on this point: "`guardian/deploy/rbac.yaml` grants the Guardian's own ServiceAccount
  no verb on `leases.coordination.k8s.io`, and must not").
- Its job is mutual exclusion over the **whole cluster** -- "is anyone else running" -- so that two
  checkouts, or a runner and a stale hand-deploy, cannot both drive the same Guardian/cluster at
  once (the 2026-09-12 incident ADR-087 closes). It says nothing about which Guardian *pod* should
  be active if more than one existed, and it does not fail anything over: a stale holder is taken
  over by the next attempt that starts, not by a health check reacting to a live outage.
- `[NOTE -- future]` Genuine Guardian leader election -- e.g. a second Lease, used the ordinary way,
  with one Guardian replica renewing it to remain "the active writer" while standbys wait -- would
  need to be a **different Lease object, for a different purpose, held by the Guardian's own
  identity**, never the operator's. It must not reuse `live-run-lock` or its timing: that Lease's
  freshness window (`STALE_AFTER_SECONDS`, 3600s, reused deliberately from the file-lock constant
  per `.agents/rules/00-source-of-truth.md`'s single-owner rule) is sized for "a whole campaign
  attempt," not for "how fast should a standby take over" -- repurposing it would silently change a
  number that file's own logic owns, for a purpose it was never sized for.

### 2.3 Audit-log durability under HA

`[v1.0 today]` Durability today is per-process, per-record: every append opens the file, writes one
line, flushes and fsyncs (`chain.py`, `AuditChainWriter` docstring, "Per-record durability matters
for a log whose whole value is that it is complete"). The chain rule detects in-place mutation,
deletion, insertion and reordering, but -- by its own documented admission -- not tail truncation or
a whole-file rewrite by whoever can write the file (`guardian/README.md`, "What the audit chain
detects, and what it honestly does not"). The property that closes the truncation gap is external
to the chain itself: `docs/protocols/data-management.md` section 1 anchors the chain head in `seal.json`,
and `make audit-verify` takes that head as an optional expected value.

`[NOTE -- future]` An HA design changes the durability question from "did this one process's fsync
land" to "do two writers agree on one sequence at all." Worth naming, none built:
- **Active-passive with a fenced single writer** (ties directly to leader election, section 2.2): only the
  elected writer ever appends; standbys serve `/healthz` and reject writes. The simplest correctness
  story, and the cheapest to reason about for a chain whose entire value rests on one monotonic
  sequence.
- **Move the audit store off local disk** to something that natively serialises concurrent writers
  -- a durable log/queue, or a database using the same unique-constraint-plus-transaction pattern
  ADR-045 already validated for the replay store. A real architecture change to `guardian/audit/`:
  its own ADR, its own adversarial tests mirroring the existing tamper/truncation suite, out of
  scope here.
- Whichever is chosen, the chain rule, `canonical_json` (`guardian/audit/canonical.py`), and the
  `seal.json` anchor (`docs/02-architecture.md` section 3; ADR-022) stay exactly as specified. An HA design
  changes *how many writers exist*, never the hash rule they write under.

### 2.4 Replay-state consistency under HA

Covered in section 2.1 item 2 above; repeated here only so a reader jumping straight to "HA considerations"
does not miss it. Bottom line: `[v1.0 today]` the single-use-`jti` invariant already tolerates a
shared `SQLiteReplayStore` file across processes (ADR-045); `[NOTE -- future]` whether it tolerates
the *deployment's actual storage class* is an unverified prerequisite, not a given one.

## 3. Signing-key management

`[v1.0 today]`
- **The signing key is out-of-band operator-supplied.** `guardian/deploy/deployment.yaml`'s own
  header comment states this as policy: "The signing Secret is intentionally referenced, never
  declared: operators create `guardian-signing-key` out of band." No `stringData`, no `--set` path,
  no rendered manifest ever carries the value.
- `guardian/app/config.py` reads `GUARDIAN_SIGNING_KEY_FILE` in preference to the inline
  `GUARDIAN_SIGNING_KEY` variable: "`SIGNING_KEY_FILE_ENV_VAR` is the Kubernetes path -- a projected
  Secret volume, read at start and never re-read -- and it is preferred over the inline variable
  when both are present, because a mounted Secret is the deployment shape section 2 asks for and an
  inline value is the developer convenience" (`config.py:93-96`). A blank value in either is treated
  as absent, and absent is a **startup error**, never a silent default (`config.py:89-91`,
  `_read_signing_key`, `config.py:486-517`) -- "there is no development key, no example key and no
  empty-string fallback in this repository, because a Guardian that starts with a known key is a
  Guardian whose tokens anyone can mint." The deployment manifest mounts `guardian-signing-key`
  read-only at `/var/run/guardian-secrets` (`deployment.yaml:41-42, 67-80`).
- HS256 is symmetric and single-verifier by design (ADR-004): only `guardian/` ever holds the key,
  never copied into a test, a fixture, a `.env` file, or anywhere else
  (`.agents/rules/10-guardian-first.md`; ADR-004's own consequence line, "symmetric key demands
  strict key hygiene").
- No value from this file, or from any file it cites, should ever be pasted into a chat, a run
  bundle, or a log. This note itself contains none.

### 3.1 Rotation

`[v1.0 today, established by config.py's "read once, never re-read" contract above; not yet
operationalised as a runbook step -- that belongs in docs/ops/secrets.md]` Because the key is read
once at process start, rotation is mechanically a restart, never a live re-key:

1. Write the new key material to the `guardian-signing-key` Secret (or its source, if an external
   secrets manager is wired per section 3.2 / `docs/ops/secrets.md`).
2. Restart the Guardian pod so the Secret volume is remounted and re-read at start.
3. Every capability token minted under the old key becomes unverifiable the moment the new key is
   live -- HS256 has one verifying key per process, and Guardian is the only verifier
   (`docs/02-architecture.md` section 3, CapabilityToken). Rotation is therefore correctly treated as a
   **between-runs** operation: mid-campaign, it invalidates the live run's in-flight tokens rather
   than degrading gracefully, and the resulting run is handled under
   `docs/protocols/data-management.md` section 4's validity rules like any other disruption, not through a
   special case invented here.
4. `[NOTE -- future, HA-specific]` With more than one replica (section 2), rotation would have to be
   synchronised across every replica in the same restart, never rolled pod-by-pod: a mixed-key
   window means tokens minted by a pod on the new key fail verification at a pod still holding the
   old one, and vice versa -- a spurious, hard-to-diagnose deny storm rather than a clean cutover. A
   safe rolling-restart sequence (scale to zero and back, or an accepted brief full-unavailability
   window) is design work for whoever eventually builds HA; it is not solved by Kubernetes' default
   rolling-update behaviour, which assumes replicas are interchangeable at every point in the roll.

### 3.2 Storage

`[v1.0 today]` A plain Kubernetes Secret -- base64-encoded at rest, not encrypted, unless the
cluster itself has encryption-at-rest / envelope encryption configured for the Secrets resource
type; the Secret object alone provides no encryption guarantee. `[NOTE -- future]`
`security-policy.md` section 5 already names the direction: "Secrets -> K8s Secrets/external manager;
consider Biscuit/SPIFFE if delegation depth grows." For the signing key specifically, worth naming
as options rather than decisions: a cluster with encryption-at-rest enabled for Secrets; an external
secrets manager (Vault, a cloud KMS) fronted by an External Secrets Operator `ExternalSecret`,
referenced but never defaulted by any chart value. None of this is built. When
`docs/ops/secrets.md` exists, its general rotation/storage guidance should be extended to cover the
Guardian's signing key as a specific instance, cross-referenced from here rather than restated.

### 3.3 Compromise response

`[NOTE -- future -- the least developed area here, stated as such rather than implied otherwise]`
No drilled compromise-response procedure exists in the repository today. A sketch, meant to be
displaced by a real, tested runbook rather than mistaken for one:

1. **Rotate immediately** (section 3.1). This is the only action that stops a leaked key from minting
   further valid tokens, and it is necessary regardless of what else is decided.
2. **Treat every `AuditRecord` since the suspected compromise window as needing manual review.** The
   chain's hash rule proves the Guardian's own append sequence was not altered in place; it cannot
   by itself prove that every token the Guardian *accepted* was genuinely minted by the Guardian's
   own issuer rather than forged with a leaked key -- the chain evidences what the Guardian decided
   and did, not the provenance of a key it was handed to verify against.
3. **Dispose of the affected run(s) under `docs/protocols/data-management.md`'s existing validity
   rules**, rather than inventing a new disposition category in this file. That protocol, not this
   note, owns what makes a run bundle valid.
4. This sequence has never been exercised against the adversarial suite (`guardian/tests/`) or
   drilled operationally. Building and testing it is future work; this note cannot certify it
   sufficient, only sketch its shape.

## 4. What must not change

Restated because it is the reason this exists as notes rather than as a merged change:

- Nothing above is implemented. No file under `guardian/`, its Rego bundle, `agents/`, `monitor/`,
  `runner/`, or `scenarios/` is touched by writing this note, and none of it should be inferred as
  touched from the note's existence.
- Any future implementation of `replicas > 1`, leader election, a redesigned audit-append path, or
  automated key rotation is a packaging/deploy-layer change plus its own ADR(s) (`AGENTS.md` rule
  5), never a direct edit to the frozen `v1.0` enforcement or audit contract. `AGENTS.md` iron rule
  6 and `security-policy.md` section 5 both say the same thing from different angles: these deltas "must
  not alter the frozen `v1.0` behavior used for evaluation."
- If any of this is ever built, it is verified the way every other Guardian property already is:
  `make guardian-test` green, the adversarial suite extended with the new failure modes (a torn
  write from two writers; a replay claim lost across a replica failover), and `make audit-verify`
  against the result -- never asserted from this document alone.

## 5. Cross-references

- `docs/protocols/security-policy.md` section 5 -- "Production hardening deltas," the binding scope line
  this file elaborates on.
- `docs/ops/secrets.md` -- general Secret wiring and rotation (owed by M8-hardening T8.2); not yet
  written as of this note. Treat it as the primary source once it exists; this file's section 3 extends it
  for the Guardian's signing key specifically rather than competing with it.
- `docs/milestones/M8-hardening.md` -- T8.6 (optional), the task this file answers.
- `docs/plans/M8-implementation-plan.md` -- a provisional M8 execution plan drafted ahead of the
  tree. Its "Guardian HA is notes-only, and the replay cache is the reason (T8.6)" section reads
  `guardian/token/replay.py`'s process-local warning as the whole story; section 2.1 above updates that
  finding against the current tree, where ADR-045's `SQLiteReplayStore` already closes the
  cross-process replay gap and the audit-chain writer turns out to be the sharper blocker.
- `docs/02-architecture.md` section 1 (roles and trust boundaries), section 3 (CapabilityToken, AuditRecord, the
  chain rule), section 5 (the component diagram).
- `guardian/README.md` -- the mediation pipeline, "the signing key lives here and nowhere else,"
  and "what the audit chain detects, and what it honestly does not."
- ADR-004 (capability tokens as HS256 JWTs), ADR-023 (Guardian mode flags; one process per arm),
  ADR-045 (persistent, cross-process replay store), ADR-066 (one live run at a time), ADR-087 /
  ADR-101 / ADR-104 (the cluster Lease and its campaign-span holder).
- `guardian/deploy/deployment.yaml`, `guardian/audit/chain.py`, `guardian/token/replay.py`,
  `guardian/token/persistent_replay.py`, `guardian/app/config.py` -- the code this note is grounded
  in; re-check line numbers against the tree at the time of reading, since none of them are pinned
  by this file's own authority.
