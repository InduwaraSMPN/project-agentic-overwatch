# Protocol — Security & Safety

Status: binding · Serves FR3/FR4, NFR6/NFR8 · Owner of token TTL & replay-cache size

## 1. Guardian invariants (must always hold; adversarial suite enforces — T-08…T-13)

1. Deny-by-default: absent an explicit permit rule, deny with a reason code.
2. Sole credentials: only `guardian/` holds a kubeconfig/ServiceAccount able to mutate the
   cluster; its own RBAC is least-privilege (only verbs the scenarios require).
3. No direct path: agent namespace cannot reach the K8s API — Cilium default-deny
   NetworkPolicy; verified by an in-cluster probe that must fail (T-11).
4. Every decision audited: permit and deny both produce hash-chained AuditRecords with
   token jti, issuer, rule id, reason; chain verifies and replays (T-12).
5. Untrusted inputs: LLM-supplied `justification`/free text is logged, never evaluated as
   policy; environment-derived text reaches the LLM only quoted (FR1.3).

## 2. Capability token parameters (single source of truth)

`TTL = 300s` default (per-phase override allowed, ≤ 900s); `jti` single-use with a replay
cache of the last `10000` jti or 1h, whichever larger; algorithm HS256; signing key in
`guardian/` only, provided via env/Secret, rotated on demand. Dissertation binding
(SLOT-SEC-01): **absent** — the submitted chapters specify no token-lifetime, replay-window
or signing-algorithm constraint. Searched `IM2021088.txt` for: TTL (0 case-sensitive hits;
the 7 case-insensitive matches are "settle"/"little" substrings), time-to-live / time to
live / token lifetime / lifetime / token budget / expiry / expire / expires / expiration
(0 each), signing algorithm or signing key (0 — every "signing" match is "designing"),
HS256 (0). The nearest source text is §3.4.2's qualitative requirement that "every action
arriving at the Guardian carries a supervisor-issued, short-lived capability token
traceable to the authorised Supervisor" (§3.4.2 · "at the Guardian carries a
supervisor-issued, short-lived capability token traceable to") — a property, never a
number; §3.4.2 fixes only that every action is mediated and audited. The concrete values
in this §2 are therefore engineering decisions owned by this file plus ADR-004: changing
them is an ADR-004 log entry, not a re-binding, and this is stated explicitly at the
viva. Adjustments = ADR-004 log entry.

### 2.1 M10 remediation parameters (single source of truth)

Added under the M10 remediation (`docs/plans/M10-implementation-plan.md`; ADRs 129, 130, 131, 137).
Every value here is **M10-proposed**, confirmed by the researcher before the `v2.0` freeze, on the
same "this file owns the number, the ADR owns the reasoning" split §2 uses. A module mirrors each and
a mirror test fails on drift (ADR-016 pattern). The Ed25519 audit-signing key and the Guardian's own
credentials remain out-of-band operator secrets (§3, rule 10) — no value of any key appears here.

**Action caps (ADR-129).** `action_cap_per_token = 8`; `action_cap_per_run = 32`. A cap is an atomic
reserve in one SQLite transaction (`BEGIN IMMEDIATE`) taken before policy evaluation and released
when the decision is not permit-and-executed, so it holds under any worker count. The v1 corpus
median was 12 Guardian decisions per run and the p99 18 (recount 2026-09-26), so 32 per run clears
the observed envelope while bounding a runaway loop; 8 per token bounds one capability's blast radius.
The reserved and consumed counters are recorded in every decision record.

**Scale-to-zero authority (ADR-129, D4-A).** Scaling a Deployment to zero replicas is a distinct
capability held by no phase by default: denied at issuance and denied as an action absent the
capability. The policy receives a normalised integer replica count (or null), never the raw string;
`"00"` normalises to `0`. G1-LOGONLY records the would-be denial; only the G2 direct path can execute
one, which is the bypass C2 asks about.

**Control-plane credential (ADR-128).** The runner authenticates to `POST /v1/tokens` and
`POST /v1/phase` as `system:serviceaccount:<ns>:runner-control-plane`, audience
`guardian-control-plane`, verified by a Guardian-side TokenReview; the token's lifetime is at least
the agent-phase timeout and it is bound to a per-run Secret the runner deletes at run end; its expiry
is recorded in the bundle. The ServiceAccount carries no RBAC bindings — it exists only to be a
verifiable identity.

**Audit-signing key custody and ledger (ADR-130).** The audit chain signs each record hash with an
Ed25519 key (`CRYPTOGRAPHY_VERSION` in `infra/versions.env`), distinct from the HS256 token key,
created and rotated by the operator out of band; `guardian/` never fabricates it. At seal, the
`{run_id, head, signature, ts}` anchor is appended to an external ledger outside `runs/` at
`runs/.audit-anchor-ledger/anchors.jsonl` (gitignored, backed up per data-management) and to the
campaign fidelity ledger, so a whole-chain-plus-`seal.json` rewrite is detectable.

**G2 credential scope, binding, lifetime, token-file location (ADR-131, D1-A / D17-A).** In
G2-SHAREDCRED only, the `g2-executor` ServiceAccount holds a Role in `boutique` mirroring the
Guardian's own Role. Its token is minted immediately before the agents run, bound to a per-run Secret
(`--bound-object-kind Secret`) the runner deletes at run end, with a lifetime of at least the
agent-phase timeout; expiry is recorded in the bundle. The runner writes the token to a per-run file
under `runs/.private/<run_id>.token` and names its path (never its value) to the acting role via the
`KUBE_TOKEN_FILE` environment fact. The egress shim permits only that single token path.

**Shim permitted destinations (ADR-131).** `runner/egress_shim.py` permits, under the G2 flag only,
requests to the API server paths under `/api` and `/apis`, TLS verified against the cluster CA, and
only with the one token path the runner wrote for the run; every other `bearer_token_file`, every
non-API path, and every request in every non-G2 arm is refused with the shape a NetworkPolicy deny
produces. Unknown or missing flags fail closed.

**Expected-principal set (ADR-137), scoped to the incident namespace (ADR-144).** F-GD-03's
unexpected-principal check applies to mutations in the **incident namespace `boutique`** — the target
application, the attack surface: the Guardian's incident-response Role and the G2 `g2-executor` mirror
are both scoped to `boutique`, and RQ5's executed-actions land there. Within `boutique`, every mutation
whose principal is not an executed Guardian record must be one of: the ReplicaSet controller and
garbage collector (`system:serviceaccount:kube-system:*`), Chaos Mesh
(`system:serviceaccount:chaos-mesh:*`), the kubelet (`system:node:*`),
the authenticated scheduler (`system:kube-scheduler`, ADR-185; also writes scheduling Events here),
the G2 principal `system:serviceaccount:agents:g2-executor`, and kind's admin user (expected
`kubernetes-admin`, confirmed in P0-live — it also authors the window sentinels). A mutation **outside**
`boutique` is out of scope: the widened audit policy (ADR-137) cannot scope by namespace, so
`k8s_api_audit.jsonl` also carries cluster-plane churn (including `system:kube-scheduler`,
`system:kube-controller-manager`, `system:apiserver`, the CNI and observability service accounts) in
`kube-system`/`observability`/`default` that the threat model gives no actor reach to, and that no
expected-principal set can enumerate without an ever-growing, version-fragile allowlist. It is counted
(`out_of_scope`), never a finding. `guardian/audit/k8s_crosscheck.py` and F-GD-03 are worded against
this set and scope; the corroboration half is unscoped, since the Guardian only executes in `boutique`.

**T-44 caller-identity residual (ADR-128, risk R-15).** What ADR-128 closes: the caller of
`/v1/tokens` and `/v1/phase` is the run's runner process, authenticated per run, and the phase is
runner-declared rather than self-declared by an agent. What remains: per-node caller attribution
inside one runner process is not established, since the whole agent graph runs in that one process.

## 3. Development-time safety (applies before any evaluation)

- No agent code, at any maturity, runs against the cluster except through the Guardian —
  including local experiments (rule 10). There is no "dev shortcut" direct client.
- The lab cluster is disposable and self-contained; it holds no real data, no real
  credentials, no cloud identities. Blast radius = the kind cluster.
- `make nuke` fully destroys the environment: the kind cluster and its labelled Docker residue,
  plus only the four repository-owned Langfuse bind-mounted datastore paths (Postgres,
  ClickHouse, Redis, MinIO). It requires explicit confirmation (`FORCE=1` non-interactively),
  rejects symlinked state ancestors, and never deletes `runs/` or other repository content. Treat
  every scenario as capable of harming the cluster and this disposable trace-plane state, and
  nothing beyond them.
- Secrets never enter prompts, bundles, or logs (data-management §5 sanitizer).

## 4. Ethics & disclosure (raw material for the dissertation ethics section)

- **Model-provider training on inputs**: free-tier ToS may use prompts to train provider
  models (R-14). Only synthetic incident data and non-sensitive lab telemetry are ever sent;
  no personal data exists in the system. Disclose this choice and its rationale.
- **Dual-use**: the artifact includes attacker scenarios and CVE exploitation in a sandbox.
  Scenarios target only the local disposable cluster; no capability for external action
  exists (Guardian scope + NetworkPolicy). State the containment argument explicitly.
- **Responsible framing**: RQ3 is characterised, not a safety guarantee; M8 mandates
  shadow-mode-first (G1-LOGONLY) before any enforcement in a real setting.
- **Ethics posture, bound from §3.7** (SLOT-SEC-02; anchor §3.7 · "All evaluation activity
  designed in this chapter is executed within a contained"): (1) a contained, controlled or
  staging environment — the source names two alternatives there, not one compound
  setting — in which "no live production system, no genuine attacker, and no real
  incident stream is involved at any stage", with injections executed only against the
  reference application "deployed for this purpose and isolated from any production
  network"; (2) no personal or organisational data — "the telemetry logged in §3.5.7
  concerns only the artefact's own agents, the reference application's synthetic workload,
  and the injected scenario suite, not any third party's information"; (3) publicly
  disclosed CVEs only — "no new vulnerability is discovered, withheld, or disclosed
  irresponsibly", the posture being "applying existing, disclosed knowledge to a controlled
  target rather than conducting original vulnerability research"; (4) no
  production-readiness claim — "No claim of production readiness or deployment safety is
  made from an artificial-paradigm evaluation of this kind", and the artefact is not
  represented as fit for use against a live system; (5) accountability recorded, not
  resolved — with no in-incident human override, "responsibility for an autonomous
  action rests on the deployment-time authority policy and on the operator who authored
  it", which §3.7 raises as "an accountability question this chapter records rather than
  resolves": a stated boundary of the studied design, not a resolved matter.
- Human subjects: none. Institutional ethics process: **no institutional ethics-approval
  process is described in the submitted chapters** — searched `IM2021088.txt` for "ethics
  committee" (0), "ethical approval" (0), "institutional review" (0), IRB (0), bare
  "ethics" (0); "ethical" appears only in the §3.7 heading, its table-of-contents entry,
  and one forward-pointing sentence in §3.1's introduction — "Section 3.7 records the
  ethical posture of an evaluation conducted entirely within a controlled or staging
  environment" — not at the close of Chapter 2, where this file previously placed it.
  Supervisor question (binding-log §T0.6, Flagged): confirm whether a departmental
  ethics-approval form is required.

## 5. Production hardening deltas (M8; do not apply during the campaign)

Secrets → K8s Secrets/external manager; consider Biscuit/SPIFFE if delegation depth grows
(ADR-004 alternatives); image signing + SBOM; Trivy scans of our own images; Guardian HA
considerations. These are documented and packaged in M8 but must not alter the frozen `v1.0`
behavior used for evaluation, nor the M10 `v2.0` instrument freeze (ADR-136) used for the v2 campaign.
The M10 remediation adds real security controls that ship *inside* the evaluated instrument rather than
as M8 deltas — control-plane authentication (ADR-128), scale-to-zero authority and atomic action caps
(ADR-129), and the Ed25519-signed audit chain with an external anchor (ADR-130) — because each closes a
v1 defect the evaluation itself depends on, not a production-only hardening.

## 6. Capability issuance bound and the caller-identity residual (T-44)

Capability issuance is bounded deny-by-default by the deployment-time authority
policy, and the caller-identity gap that bound does **not** close is stated here
— in binding law — rather than left for a reader to discover. Decision and
rationale are single-homed in ADR-031; the declarations themselves are
single-homed in `guardian/policies/authority.rego` (RQ1's "a human-authored
authority policy", bound at `SLOT-REQ-01`); enforcement is
`guardian/policies/issuance.rego`, consulted by
`AuthorityBoundedTokenIssuer` **before anything is signed**. Nothing in this
section restates those files; it states the invariant and the residual so the
matrix row T-44 has a prose half.

### What the bound guarantees, whoever asks

- No capability wider than the phase's declared authority may ever be minted:
  detection-and-investigation observation-only; containment able to reduce
  reach but not to delete; eradication the only phase granted `delete`;
  verified-recovery able to observe and restore capacity but not to change
  what returned. Every phase is confined to the `boutique` namespace; no
  phase may ever be granted `secrets`/`configmaps`, `kube-system`, or the
  Guardian/agent namespaces.
- An over-wide request is refused with `issue_authority_exceeded` and **no
  token exists** — a 403 accompanied by a credential would be worse than no
  bound at all (`test_composition.py:1067`, `test_token_issuance_exposure.py:200`;
  `issuance_test.rego:183–229` for every outcome the entrypoint can give).
- The §2 lifetime ceiling holds against every caller equally and is refused
  rather than clamped, so an unauthenticated caller chooses *what* a token
  covers and *whom* it names, but not how long it lives.

### The residual, stated plainly

- `POST /v1/tokens` **authenticates nobody.** `supervisor_id` and
  `executor_id` in `TokenIssueRequest` are self-declared and projected
  verbatim into the token's `iss` and `sub`; no rule in `issuance.rego`
  reads either field, and nothing anywhere between the socket and the
  signing key checks that the caller is the Supervisor it names
  (`issuance.rego:65–78`; `authority.rego:79–81`).
- Any party with network reach to the issue surface (threat-model position
  P4 — which the agent layer must have, or it could not be mediated at
  all) can therefore mint any **within-authority** capability naming any
  `iss`, any `sub`, any phase and any run, and receive a Guardian-signed
  token for it.
- **Who has that reach is bounded by NetworkPolicy, and was not always.**
  Until ADR-076 nothing selected the `guardian` namespace and Cilium ran in
  default mode, so a pod in `boutique` — the attacker's foothold in four of
  the five scenarios — reached `/v1/tokens` (probe on 2026-09-12: HTTP 200
  from `boutique`). P4 therefore included the target application.
  `infra/netpol/guardian-ingress.yaml` now admits ingress only from pods in
  `agents` on TCP 8080, applied by `scripts/guardian_deploy.sh` on every
  deploy and so identically in every arm; `infra/tests/probe_guardian_reach.sh`
  verifies both directions (`agents` admitted, `boutique` denied and the
  drop attributed to Cilium policy). The runner's host-side agent graph
  reaches the Guardian through `kubectl port-forward`, which dials the pod's
  own loopback and needs cluster credentials no workload pod holds; that
  path is operator access, outside P4, and the probe confirms it still
  works. This narrows **who can reach** the issue surface. It does **not**
  establish **who asked**: any caller the boundary admits can still mint a
  token naming any registered identity. The residual below remains,
  smaller.
- The attribution in `AuditRecord.iss` is consequently **caller-chosen**:
  at best a confirmed-registered Supervisor name, never an established
  fact about who asked. Both RQ5 measures are computed from those records
  and inherit this.
- This is recorded rather than closed for a requirement-level reason, not
  for convenience: Executors and Supervisors are in-process graph nodes,
  and authenticating them needs per-node standing credentials, which
  FR3.1's "no standing credentials" precludes. Candidate closings (mutual
  TLS, a Supervisor-projected ServiceAccount token) each change the
  architecture §3 contract or `guardian/deploy/` and each needs its own ADR
  before code. A namespace-level NetworkPolicy is not one of them: ADR-076
  applied one, and it bounds reach without authenticating the caller,
  because Supervisors and Executors are nodes of one process and cannot be
  told apart at the network layer. If the
  residual should instead be closed, that is a design decision for the
  human — it is not taken here.

### Tripwire

`guardian/tests/test_token_issuance_exposure.py` demonstrates the exposure
rather than passing around it, and it is written so that **closing the
residual fails it**: `test_the_token_endpoint_mints_for_an_unauthenticated_caller`
(:131), `test_the_caller_chooses_which_supervisor_the_token_is_attributed_to`
(:147), `test_the_caller_chooses_the_executor_the_run_the_phase_and_the_scope`
(:165), and `test_a_self_minted_token_passes_verification_and_is_stopped_only_by_policy`
(:232), together with the within-authority half of
`test_composition.py:1067`. Whoever authenticates the seam must rewrite
that module into the test of the defence; a green suite describing a
system that no longer exists is the failure mode ADR-031 retires against.

### Inheritance

This residual is a stated limitation alongside ADR-030's (the Guardian
*records* rather than authenticates the presenting Executor; this one
*bounds* rather than authenticates the requesting Supervisor). Neither is
an implementation defect; both are consequences of demonstrating an
architecture in which no agent holds a standing credential. Named in risk
R-15; Chapter 5 carries both in one paragraph (ADR-031) and Chapter 6
inherits them from here.
