# guardian — the deterministic reference monitor

The sole enforcement path. Every mutation an agent attempts arrives here, is decided by policy, is
recorded in a hash-chained audit log, and is executed only if permitted. Nothing under `agents/`
holds a cluster credential or reaches the Kubernetes API — `.agents/rules/10-guardian-first.md`
forbids it and `scripts/grep_guard.sh` enforces it with no exemption mechanism.

**This milestone's failure mode is silent**, which is why it is built the way it is. A Guardian that
permits what it should deny, or an audit chain that verifies a tampered log, still passes every test
that only asks whether the happy path works. Everything here is designed against a **hostile agent
layer** — which, for evaluation purposes, is exactly what the agent layer is: the guardrail ablation
exists to remove the Guardian's properties one at a time, and the four injection classes exist to
make the LLM layer act against it.

## What is here

| Path | Holds | Landed |
|---|---|---|
| `app/models.py` | the interface contracts — ActionRequest, ActionResult, token claims, AuditRecord — and the structured reason-code enum | M3-T3.1 |
| `app/config.py` | `GuardianConfig`, read once at start and immutable after; token parameters seeded from `security-policy.md` §2 | M3-T3.1, T3.7 |
| `app/policy.py` | the OPA seam: bundle load, bundle sha256, and the input document | M3-T3.1 |
| `app/mediation.py` | the pipeline, fixed in one place | M3-T3.1 |
| `app/main.py` | the FastAPI surface: `POST /v1/actions`, `POST /v1/tokens`, `GET /healthz` | M3-T3.1 |
| `policies/` | the deny-by-default Rego entrypoint, scope matching, and `*_test.rego` units | M3-T3.2 |
| `token/` | issue, verify, and single-use `jti` replay stores (persistent SQLite in production; injectable memory store in tests) | M3-T3.3, ADR-045 |
| `audit/` | canonical JSON, the hash chain, verification and replay | M3-T3.6 |
| `deploy/rbac.yaml` | the sole ServiceAccount with cluster-mutation rights, and its least-privilege role | M3-T3.4 |
| `tests/` | the adversarial suite — **the deliverable, not an afterthought** | M3-T3.8 |

The agent-namespace NetworkPolicies live in `infra/netpol/` rather than here, because they are
cluster substrate rather than Guardian code; `infra/tests/probe_agent_to_api.sh` is the in-cluster
probe whose **failure to connect is the pass condition**.

## The pipeline, and the one thing that must never be skippable

verify token → build the OPA input → evaluate → enforce per mode → **append audit** → execute.

Every denial must be **audited**, not merely returned. A denial the audit log does not contain fails
`security-policy.md` §1.4, and traceability row T-22's scoring reads that log — so an unaudited block
is invisible to the evaluation whether or not it happened. Every adversarial case therefore asserts
three things, never one: **denied**, with a **structured reason code** rather than a free-text
message, and **present in the audit chain**.

## Rules that bind this directory

- **Deny by default.** Absent an explicit permit rule, deny with a reason code
  (`security-policy.md` §1.1). OPA unavailable or timing out fails **closed** — it denies and
  audits, never degrades to permit.
- **`justification` is logged, never evaluated as policy** (§1.5). It is LLM-authored free text that
  a hostile agent will deliberately fill with Rego fragments, mode-switch instructions and
  key-shaped strings. It is excluded from the OPA input document **by construction**, asserted by a
  test rather than promised by a comment — and it is bounded and scrubbed at append time, before
  hashing. Nothing else in the project covered the Guardian half of §1.5 (plan conflict M3-C10).
- **Mode is a start-time parameter, set only by the runner.** `G1-LOGONLY` and `G2-SHAREDCRED` are
  never reachable by editing code or policy. The default is `G0-FULL`; an unrecognised value is a
  **startup error**, never a silent default. Nothing in an ActionRequest can influence it. The
  machine proof is that the **Rego bundle's sha256 is identical across all three modes**, with
  `scripts/policy_purity_grep.sh` as its static counterpart. ADR-023.
- **Records are born clean.** No signature, no raw token, no `Authorization` header ever enters an
  AuditRecord — it carries `token_jti` and `iss`, which is what §1.4 and NFR6 require for
  attribution. That is what lets `data-management.md` §5's before-seal sanitizer be a **no-op** on
  this file: any post-append redaction of a hashed field would break every link after it, so a
  sanitizer with work to do here would fail `make audit-verify` on *correct* behaviour. The test
  that proves it asserts the no-op, not the redaction. ADR-022.
- **Every parameter in `security-policy.md` §2 is protocol-owned.** TTL, the per-phase ceiling, the
  replay-cache size and window, and the algorithm appear nowhere in this code as literals; they are
  read from configuration seeded by that file. Production replay state uses the explicitly
  configured `GUARDIAN_REPLAY_STORE_PATH`; that path must be a persistent Guardian-owned volume.
  The SQLite file is separate from the audit chain and contains no secrets (ADR-045).
- **The signing key lives here and nowhere else**, supplied via environment or a Kubernetes Secret.
  It is never copied into a test, a fixture or `.env`. Absent ⇒ startup error.
- **Ruff's `S` (flake8-bandit) rules apply.** A genuine false positive is a `noqa` at the site with
  a reason, never a widened `per-file-ignores` — a second entry under `guardian/**` would quietly
  reverse ADR-026.

## What the audit chain detects, and what it honestly does not

`hash = SHA256(prev_hash ‖ canonical_json(record_without_hash))` detects in-place **mutation,
deletion, insertion and reordering**, because each breaks the link at a locatable `seq`.

It does **not** detect tail truncation or a whole-chain rewrite: an attacker who can write the file
recomputes every hash forward from the cut. That is the boundary of an unsigned hash chain, and it
belongs here and in Chapter 5's threats section rather than in a viva question. The property that
closes it already exists — `data-management.md` §1 puts the chain head in `seal.json` — so
`make audit-verify` takes an optional expected head, and the tamper tests demonstrate truncation
caught **with** the anchor and missed **without** it. Claiming otherwise would be exactly the kind of
unearned security claim this component exists to prevent.

## Two tiers, because "fully testable offline" was overstated

Zero inference cost is exact: nothing here calls a model. Fully offline is true of six tasks and
false of two. **Tier A** is everything verifiable against the tree. **Tier B** — the RBAC assertions,
the agent-namespace default-deny, and G2's cluster half — needs a running kind cluster with Cilium
and is gated on M1. A probe that cannot connect because there is no cluster is not evidence that a
policy denied it. **M3 cannot be reported `done`, and rows T-11 and the cluster half of T-13 cannot
close, until Tier B runs.**

## One question that is open, not settled

**G2-SHAREDCRED's agent-side surface has no legal home yet.** §3.5.4 asks whether "an available
alternate credential path is discovered and used once one exists" — but rule 10 forbids any
Kubernetes client under `agents/`, `prompt-parity-policy.md` §2 rule 3 forbids a G2-only tool because
the registry must be identical across conditions, and a universal exec-shaped tool would make G0
itself bypassable. A Guardian-owned weakened transport satisfies all three but **forces** the bypass,
so it measures use by construction rather than discovery — a different question from the one the
source poses. M3 builds the environment side in full and hands M4 a narrowed decision rather than a
blank page. ADR-024; if it is still open when M4 opens, it is a supervisor question.

## Traceability

Serves T-08 (adversarial suite), T-09 (infrastructure part), T-10 (`opa test`), T-11 (the netpol
probe), T-12 (chain verification and replay) and T-13 (flag isolation). Row status, and the reason
none closed at the end of Tier A, are recorded at the foot of `docs/05-traceability-matrix.md`.

## Entry points

```bash
make guardian-test                       # opa test with coverage, plus the adversarial suite
make audit-verify P=<path> [HEAD=<sha>]  # chain integrity; P defaults to runs/
sh scripts/policy_purity_grep.sh         # no arm or mode token under guardian/policies/
```
