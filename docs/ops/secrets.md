# Secrets — contract, migration and rotation

Status: active · Milestone: M8 hardening (T8.2) · Scope: packaging/ops only, zero behavior change

This file is the authoritative secret contract for the frozen `v1.0` artifact. It exists because
`docs/protocols/security-policy.md` section 5 requires, as an M8 production-hardening delta,
"Secrets to K8s Secrets/external manager" — documented and packaged without altering frozen `v1.0`
behavior. AGENTS.md iron rule 4 ("No secrets in the repo. API keys via `.env` (gitignored) / K8s
Secrets only") and `.agents/rules/10-guardian-first.md` (Guardian is the sole credential holder) are
binding on everything below.

**This is a docs-only deliverable.** It does not create, generate, print or restate any secret
value. Every value referenced below was read on the authoring host only to identify variable
*names*; none is reproduced here, per rule 4.

**Who this is for.** An operator standing up the artifact from `deploy/helm/` (authored in parallel
under T8.1) on a cluster this project has never seen. The K8s Secret names and keys fixed here are
the contract that chart's templates reference by name — see "Chart-facing contract" below.

## 1. What the system actually reads today (grounding)

Two separate trust boundaries exist, and this table keeps them apart because they are migrated
differently.

| # | Logical secret | Consumer | Today's mechanism | Kubernetes-native today? |
|---|---|---|---|---|
| S1 | Guardian JWT signing key | `guardian/` (`guardian/app/config.py`, `guardian/token/issuer.py`) | Operator-created Secret `guardian-signing-key` in namespace `guardian`, projected volume; `GUARDIAN_SIGNING_KEY_FILE` env var. Inline `GUARDIAN_SIGNING_KEY` exists as a dev-only fallback, never used in the deployed shape. | **Yes — already.** This is the one secret the frozen artifact already manages as a K8s Secret. |
| S2 | Model provider credential (`DEV_LLM_KEY`) + provider base URL (`DEV_LLM_BASE_URL`) | `agents/registry/model.py` via LiteLLM's OpenAI-compatible env vars, mapped by `scripts/dev_llm_env.sh` | Repository-root `.env` (gitignored), sourced by `scripts/live_env.sh` before every live run. Host-side only: the agent graph runs as a host process reaching the Guardian through `kubectl port-forward` (ADR-032), not as an in-cluster workload, in the frozen `v1.0` shape. | No — dev `.env` only. Needs a Secret only once the agent graph is containerized (M8's `deploy/images/agents.Dockerfile`, per `docs/plans/M8-implementation-plan.md` T8.1b). |
| S3 | Langfuse OTLP credential (`LANGFUSE_OTLP_AUTH`) + endpoint (`LANGFUSE_OTLP_ENDPOINT`) | The OpenTelemetry Collector (`infra/observability/otel/collector-config.yaml`), Tier B only | Documented to live in the repository-root `.env` (`infra/observability/otel/README.md`, `infra/observability/langfuse/README.md`). Not present in this host's `.env` today because Tier B (the gated Docker Desktop setting) has never been brought up here. | No, and not chart-managed — see section 4. |
| S4 | Langfuse stack's own internal secrets: `POSTGRES_PASSWORD`, `CLICKHOUSE_PASSWORD`, `REDIS_AUTH`, `MINIO_ROOT_PASSWORD`, `LANGFUSE_SALT`, `LANGFUSE_ENCRYPTION_KEY`, `LANGFUSE_NEXTAUTH_SECRET` | The self-hosted Langfuse v3 Docker Compose stack (`infra/observability/langfuse/docker-compose.yml`) | `infra/observability/langfuse/.env` (gitignored), generated per-developer with `openssl rand`, no committed default (ADR-032, ADR-006). | No, and by design never will be — Langfuse runs beside the kind cluster on purpose (ADR-032: keeping the trace plane out of the environment RQ4 measures), so it has no Kubernetes identity at all. |
| S5 | G2-SHAREDCRED ablation credential | Guardian-issued, held by the agent process under the `G2-SHAREDCRED` guardrail arm only | A scoped ServiceAccount token minted through the Kubernetes `TokenRequest` API (ADR-004, ADR-024) — short-lived, K8s-managed, never a long-lived Secret object. | Not applicable — this is evaluation-condition machinery inside frozen `v1.0` behavior, not an operator-managed credential. Listed here for completeness only; **out of scope for migration or rotation** (see section 6). |
| S6 | `boutique` application secrets | Online Boutique (upstream reference app) | None read from this repository's own code. Online Boutique's own manifests are Kustomize overlays under `infra/boutique/`; any secret they define is upstream's, not this artifact's. Not audited further here — out of scope for T8.2, flagged in section 7. | N/A |

**Monitor (`monitor/`) reads zero secrets.** Confirmed by inspection of `monitor/http_service.py`,
`monitor/audit_forwarder.py` and `monitor/trivy_uploader.py`: every environment variable they read
names a path or an in-cluster URL, never a credential. This is consistent with — though a distinct
property from — `.agents/rules/40-monitor-non-llm.md`'s non-LLM boundary, and it means the M8 Helm
chart's aggregator image (`deploy/images/aggregator.Dockerfile`) needs **no Secret reference at
all**.

## 2. The Guardian signing key — out-of-band, operator-only, always

This is the one secret with special handling, stated explicitly because `docs/protocols/security-
policy.md` section 2 requires it and `guardian/app/config.py`'s own docstring states the invariant at
length: **"There is deliberately no default, no bundled development key and no generated one."**

- **It is never in `.env`, never in the Helm chart, and never generated by any tooling in this
  repository** — not `scripts/`, not `deploy/`, not the chart's `values.yaml`, not an install hook.
  A generated key would invalidate every live token on each restart; a bundled one would make every
  capability token forgeable by anyone who has cloned the repository.
- **The chart references the Secret by name and never contains one.** No `stringData`, no `data`,
  no `--set` path that could put key material in a rendered manifest or in Helm's release history.
  `guardian/app/config.py` prefers the file form (`GUARDIAN_SIGNING_KEY_FILE`, a projected Secret
  volume) over the inline env var precisely because a mounted Secret is the deployment shape section
  2 asks for; the chart must set the file variable only, mounting the volume already wired in
  `guardian/deploy/deployment.yaml` — and must never set the inline `GUARDIAN_SIGNING_KEY` from a
  chart value. A rendered-output test should assert that shape holds (see `docs/plans/M8-
  implementation-plan.md`'s T8.2 verification, which pipes `helm template` through the data-
  management.md section 5 sanitizer patterns and requires zero matches).
- **The operator creates it, always, by hand or by their own out-of-band tooling — never through
  this chart, ESO, or sealed-secrets.** `scripts/guardian_deploy.sh` already enforces this for the
  lab deployment: it checks `kubectl -n guardian get secret guardian-signing-key` and refuses to
  proceed if it is absent, printing "create it out of band". The Helm chart inherits the same
  refusal, one layer up: it must not create the Secret, and should fail its own pre-install or
  readiness check if it is missing, rather than substitute a default.
- **Why this secret specifically is excluded from the External Secrets Operator path** documented
  in section 4, even though that mechanism is otherwise recommended: syncing the signing key from an
  external store would make that store a second place capable of minting Guardian trust, which is
  exactly the "sole credential holder" property `.agents/rules/10-guardian-first.md` exists to
  protect. A human action is required to materialize or rotate it, on purpose. See ADR-114.

## 3. Chart-facing contract: Secret names and keys

The M8 Helm chart (`deploy/helm/agentic-overwatch/`, authored in parallel under T8.1) references
every one of the following by name. It creates none of them as a value — either the operator runs
the `kubectl create secret` command in this section, or an `ExternalSecret` resource (section 4)
populates the same name and key.

| Logical name | Namespace | K8s Secret name | Key(s) | Referenced by (chart template) |
|---|---|---|---|---|
| Guardian signing key | `guardian` | `guardian-signing-key` | `signing-key` | Guardian Deployment, projected volume at `/var/run/guardian-secrets`, `GUARDIAN_SIGNING_KEY_FILE` |
| Model provider credential | `agents` | `overwatch-model-provider-credential` | `api-key`, `base-url` | Agents Deployment (new at M8 — see note below), `secretKeyRef` into `OPENAI_API_KEY` / `OPENAI_BASE_URL` |
| Langfuse OTLP credential *(optional — only if the operator containerizes the collector; this chart does not deploy it, matching Prometheus/Grafana/Falco treatment)* | operator's choice | `overwatch-langfuse-otlp-credential` | `otlp-auth`, `otlp-endpoint` | Not templated by this chart. Named here so an operator who does containerize the collector has one canonical name to use rather than inventing one per deployment. |

**Note on the model-provider credential and containerization.** In frozen `v1.0` behavior the agent
graph is a host-side process (ADR-032); `docs/plans/M8-implementation-plan.md` names
`deploy/images/agents.Dockerfile` as one of three images the M8 chart builds, which is what first
gives this credential a Kubernetes consumer. Until that image and its Deployment template exist
(gated on the plan's inbound item I2 / I4), `overwatch-model-provider-credential` is a **contract**,
not a resource that exists in the lab cluster today. Flagged in section 7.

`api-key` and `base-url` are kept as two keys of one Secret rather than a Secret plus a plain
ConfigMap value, matching how the operator already receives them as one credential pair from their
model provider (mirroring `DEV_LLM_KEY` / `DEV_LLM_BASE_URL` in today's `.env`). Splitting them
would not increase security — the base URL is not sensitive on its own — but would add a second
object for no isolation benefit.

**Bootstrap without an external manager (the zero-dependency default, always available):**

```sh
kubectl -n guardian create secret generic guardian-signing-key \
  --from-file=signing-key=/path/kept/off/the/cluster/by/the/operator

kubectl -n agents create secret generic overwatch-model-provider-credential \
  --from-literal=api-key='<value supplied by the model provider>' \
  --from-literal=base-url='<the provider''s OpenAI-compatible base URL>'
```

Neither command's argument is a repository file. Both are what the operator's own shell history or
secret manager already holds outside this checkout — the same posture `guardian_deploy.sh` already
requires for the signing key.

## 4. Migrating dev `.env` to K8s Secrets

Three groups, migrated three different ways, because they are three different trust shapes.

### 4a. Guardian signing key — already K8s-native

Nothing to migrate. It has been a K8s Secret (projected volume) since M3; `.env` was never a valid
location for it (rule 10, and `guardian/app/config.py`'s own refusal to accept a blank inline
value as present). The only "migration" is operational: an operator coming from a from-scratch dev
setup runs the `kubectl create secret` command in section 3 once, before the first `helm install`.

### 4b. Model provider credential — dev `.env` to K8s Secret

1. Read `DEV_LLM_KEY` and `DEV_LLM_BASE_URL` out of the repository-root `.env` (or from wherever the
   operator's provider issued them — the `.env` file is a *dev* convenience, not the credential's
   origin).
2. Create `overwatch-model-provider-credential` in the `agents` namespace with the `kubectl create
   secret` form in section 3, or register it with the external manager per section 5.
3. Leave `.env` in place for host-side / Tier A′ development (`scripts/live_env.sh` still reads it
   for anyone running the runner CLI directly against a cluster rather than through the packaged
   chart) — the two paths are not mutually exclusive, and migrating to a Secret does not retire the
   dev path, which M8 must not touch (`.agents/rules/00-source-of-truth.md`; the plan's "what M8
   must not touch" table forbids editing `agents/`, `runner/` or their environment contracts).
4. `MODEL_PROVIDER_STRING` and `MODEL_ALIAS` (`infra/versions.env`) are **not secrets** and are not
   part of this migration — they are read through from `infra/versions.env`, per `docs/plans/M8-
   implementation-plan.md`'s design decision that packaging never restates an artifact pin.

### 4c. Langfuse / OTel trace-plane credentials — stay host-side, do not migrate

`LANGFUSE_OTLP_AUTH`, `LANGFUSE_OTLP_ENDPOINT`, and the seven Langfuse Compose secrets in table
row S4 are **not candidates for K8s Secret migration** under the current architecture. ADR-032
deliberately keeps the trace plane outside the kind cluster so it is not part of the environment
RQ4 measures; the M8 Helm chart, per `docs/plans/M8-implementation-plan.md`, deploys exactly three
images (Guardian, aggregator, agents) and does not vendor the trace plane, exactly as it does not
vendor Prometheus, Grafana or Falco. An operator who chooses to run Langfuse or the OTel Collector
in-cluster anyway is outside this chart's scope; section 3's optional row gives that operator a
Secret name to converge on rather than none.

## 5. Wiring an external secrets manager

**Choice: External Secrets Operator (ESO).** Justification, briefly (full reasoning and the
rejected alternative are in `docs/adr/ADR-114-secrets-management.md`):

- The chart's own design already treats a Secret as "referenced by name, never contained"
  (`docs/plans/M8-implementation-plan.md`, T8.2 design decision) — ESO's `ExternalSecret` resource
  is exactly that same shape one layer earlier: it populates a same-named, same-keyed Secret from
  a backend the operator already trusts, without the chart ever declaring a value.
  `docs/plans/M8-implementation-plan.md` already names this mechanism in passing ("an external-
  secrets `ExternalSecret` populates it"), so this ADR makes that naming a decision rather than an
  aside.
- A chart meant for redistribution to a foreign cluster cannot assume which secret backend that
  cluster's operator runs. ESO's `SecretStore` / `ClusterSecretStore` abstraction supports Vault,
  AWS/GCP/Azure secret managers, and a dozen others behind one CRD shape, so this doc and the chart
  need to say "point an `ExternalSecret` at your backend" once, rather than support N backends
  directly.
- It requires no per-cluster keypair bootstrap (unlike sealed-secrets — see the ADR's Alternatives
  section), which matters for a solo-operator artifact with no existing PKI story.

**ESO is optional, not required.** The zero-dependency path in section 3 (`kubectl create secret`)
always works and is what the lab deployment already does for the Guardian signing key. ESO is the
documented upgrade path for an operator who wants Secret values to come from a centralized store and
rotate without a manual `kubectl` step — for every secret **except** the Guardian signing key, which
section 2 excludes on purpose.

**Illustrative wiring (values only — no real backend, path or credential; the operator supplies
all three):**

```yaml
# A ClusterSecretStore the operator points at their own backend. Vault shown as one example;
# ESO supports AWS Secrets Manager, GCP Secret Manager, Azure Key Vault and others with the
# same ExternalSecret shape and a different provider block here.
apiVersion: external-secrets.io/v1beta1
kind: ClusterSecretStore
metadata:
  name: overwatch-secret-store
spec:
  provider:
    vault:
      server: "https://vault.example.internal"   # operator's own address
      path: "secret"
      version: v2
      auth:
        kubernetes:
          mountPath: kubernetes
          role: overwatch-eso-reader
---
# Populates overwatch-model-provider-credential in the agents namespace from the operator's
# backend path. Key names on the right (api-key, base-url) match section 3's contract exactly,
# so the chart's secretKeyRef needs no branching between the kubectl-create and ESO paths.
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: overwatch-model-provider-credential
  namespace: agents
spec:
  secretStoreRef:
    name: overwatch-secret-store
    kind: ClusterSecretStore
  target:
    name: overwatch-model-provider-credential
  data:
    - secretKey: api-key
      remoteRef:
        key: agentic-overwatch/model-provider
        property: api-key
    - secretKey: base-url
      remoteRef:
        key: agentic-overwatch/model-provider
        property: base-url
```

**Never** an `ExternalSecret` targeting `guardian-signing-key`. If a chart value or a template ever
makes that possible, it is a defect against section 2 and against ADR-114, not a configuration
choice — the same "no exemption mechanism" posture rule 10 and rule 40 already take for their own
boundaries.

## 6. Rotation procedures

| Secret | Trigger | Procedure | Consequence |
|---|---|---|---|
| Guardian signing key | Suspected compromise, scheduled hygiene, or operator policy | 1. Operator generates new key material out of band (never by cluster tooling). 2. `kubectl -n guardian create secret generic guardian-signing-key --from-file=signing-key=... --dry-run=client -o yaml \| kubectl apply -f -` (or the ESO backend value is updated and ESO reconciles). 3. `kubectl -n guardian rollout restart deployment/guardian` — required, because `config.py` reads the key once at start and never re-reads it. | **Every token minted under the old key becomes invalid immediately.** This is a between-runs operation. During a live campaign or a live incident response it is not a routine operation at all — it ends whatever the Guardian was mid-issuing, per `docs/plans/M8-implementation-plan.md`'s own framing, cross-referenced against `data-management.md` §4 for what an interrupted run means. |
| Model provider credential | Provider-side rotation, suspected leak, or scheduled hygiene | 1. Obtain new credential from the provider. 2. Update the Secret (`kubectl create secret ... --dry-run=client -o yaml \| kubectl apply -f -`, or update the ESO backend value). 3. Restart the agents Deployment so the new env var is picked up (LiteLLM reads the credential from process environment at call time via `OPENAI_API_KEY`; a running pod does not re-read it). | No token invalidation — this credential authenticates to the model provider, not to the Guardian. A run in flight against the old credential fails its next model call and the retry/backoff behavior already in `agents/registry/model.py` (`ModelUnavailable`) applies; it is not a security control, so a mid-run rotation is an availability event, not a security one. |
| Langfuse Compose secrets (S4) | Scheduled hygiene, or a fresh dev machine | Regenerate per `infra/observability/langfuse/README.md`'s `openssl rand` recipe and re-run `docker compose ... up -d`. **`LANGFUSE_ENCRYPTION_KEY` is the one exception: rotating it orphans every provider credential Langfuse itself has stored** (README's own documented cost) — treat it as a one-way rotation requiring re-entry of any credentials Langfuse's UI holds, not a routine key swap. | Trace-plane only; does not affect Guardian, the agent graph's own credential, or any evaluation artifact. |
| Langfuse OTLP credential (project keys) | Project re-issuance in the Langfuse UI, suspected leak | Issue new project keys in the Langfuse UI, update `LANGFUSE_OTLP_AUTH` wherever it is set (host `.env`, or the optional in-cluster Secret from section 3), restart whatever process reads it (the OTel Collector, or the host-side runner). | Spans in flight during the swap may be dropped by the collector's retry queue if the old credential is rejected mid-batch; not evaluation-relevant outside a live campaign. |
| G2-SHAREDCRED ServiceAccount token (S5) | N/A | **Not operator-rotated.** It is short-lived by construction (Kubernetes `TokenRequest` API), reissued per the ablation arm's own lifecycle (ADR-004, ADR-024), and is condition-flag machinery inside frozen `v1.0` behavior — out of scope for T8.2 and for this runbook. | N/A |

## 7. Open items — need researcher / operator confirmation

- **`docs/plans/M8-implementation-plan.md` names this file's path as `deploy/security/secrets.md`,
  not `docs/ops/secrets.md`.** That plan is explicitly self-described as provisional ("drafted
  against a tree that does not yet contain most of what it packages... re-run the Inbound checklist
  against the tree of the day"), was written while M3 was still `active`, and its own proposed ADR
  numbers (027-029) have since been taken by unrelated M4 decisions — confirming it predates the
  current tree and needs re-verification before M8 activates, exactly as its own text says. This
  file is written at the path this task specified. **Flagged rather than resolved**, per
  `.agents/rules/00-source-of-truth.md`: whoever activates M8 should decide whether `docs/ops/`
  supersedes the plan's `deploy/security/` path, or whether this file should be moved/duplicated
  there, and update `docs/README.md`'s kit map accordingly (out of scope for this docs-only change).
- **The `overwatch-model-provider-credential` Secret and its consuming Deployment do not exist yet.**
  They depend on `deploy/images/agents.Dockerfile` and the chart's agents workload template (T8.1),
  both gated on inbound item I2/I4 in `docs/plans/M8-implementation-plan.md`. The name and key
  contract here is forward-looking, not a description of a resource in the lab cluster today.
- **`boutique` namespace secrets (row S6)** were not audited as part of this pass — Online
  Boutique's own Kustomize overlays under `infra/boutique/` are upstream's manifests, out of this
  task's grep scope (`agents/`, `guardian/`, `monitor/`, root `.env`). If the reference application
  reads any secret of its own (payment/currency-service style demo keys are common in that
  upstream), it should be inventoried separately before `v1.0`'s Helm packaging is called complete.
- **Whether the OTel Collector is ever chart-deployed** is an open design question for T8.1c, not
  answered by this file. Section 3's optional row is written so that if the answer becomes "yes",
  the Secret name is already fixed and no rework is needed here.
