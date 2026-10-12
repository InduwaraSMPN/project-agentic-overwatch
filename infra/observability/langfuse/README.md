# Langfuse — the trace plane

Self-hosted Langfuse v3, run under Docker Compose beside the kind cluster. It is the LLM
observability layer ADR-006 chose: every Orchestrator, Supervisor and Executor call is recorded
here as a trace, with the rendered prompt, the model response, the tool calls, the token counts and
the latency. Row **T-05** of `docs/05-traceability-matrix.md` closes against a trace in this
instance; the golden path (`make agents-golden`) is what produces the first one.

The version pin is `LANGFUSE_VERSION` in `infra/versions.env`, and the four datastores Langfuse v3
requires beside it are pinned in `images.env` in this directory, which
`LANGFUSE_STACK_IMAGES_FILE` names from that same file. Nothing in `docker-compose.yml` restates a
version.

## Why Compose, and not a Helm release in the kind cluster

Everything else under `infra/observability/` — Prometheus, kube-state-metrics, Grafana — installs
into the cluster with `install.sh`, so the obvious question is why this one does not follow.

**Because it is the instrument, not the specimen.** The kind cluster is the *environment under
study*: Online Boutique, the Monitor, the Guardian, the injected faults and the agents responding to
them. RQ4 asks what the framework costs that environment, and
`docs/protocols/evaluation-protocol.md` takes that measure over the cluster's own CPU, memory and
scheduling. Langfuse v3 is six containers, two of them a column store and an object store, and
putting them on the same two-node kind cluster would put the thing doing the measuring inside the
thing being measured. The interference number would then include the observer, and no amount of
namespace labelling would separate the two after the fact — `infra/status/components.yaml`'s
resource collector classifies every series as app, framework or platform by namespace, and a trace
plane in-cluster is none of the three.

Two further reasons, each sufficient on its own:

- **Survivability.** `make nuke` destroys the cluster, and scenarios deliberately break it. A trace
  plane that died with the cluster would lose the trace of the run that killed it, which is exactly
  the run worth reading.
- **Footprint.** The WSL2 utility VM already carries kind, Cilium, eleven Boutique services, Locust
  and the metrics trio. ClickHouse and MinIO on top of that is the argument
  `infra/observability/install.sh` already makes against `kube-prometheus-stack`, one size larger.

The cost of this choice is stated rather than hidden: Langfuse is **not** covered by `make status`.
That report is over cluster components and is the run-gating preflight for the environment under
study; `infra/status/components.yaml` carries a comment block saying so, and saying that the
absence is a decision rather than an oversight.

## No credential is committed

There is no secret in this directory and there never should be. Upstream's compose ships working
defaults marked `# CHANGEME` — `mysalt`, `mysecret`, `miniosecret`, `myredissecret`. Every one of
them is written in `docker-compose.yml` as a **required** variable with no default, so the stack
refuses to start rather than starting on a password printed in a public repository.

The values live in `.env` in this directory. `.env` is covered by `.gitignore` (`# secrets & env`),
and `scripts/check_hygiene.sh` block (b) fails the build if any file named `.env` is ever tracked at
any depth, so this is enforced rather than trusted. Create it once:

```sh
cd infra/observability/langfuse
cat > .env <<EOF
POSTGRES_PASSWORD=$(openssl rand -hex 16)
CLICKHOUSE_PASSWORD=$(openssl rand -hex 16)
REDIS_AUTH=$(openssl rand -hex 16)
MINIO_ROOT_PASSWORD=$(openssl rand -hex 16)
LANGFUSE_SALT=$(openssl rand -hex 16)
LANGFUSE_ENCRYPTION_KEY=$(openssl rand -hex 32)
LANGFUSE_NEXTAUTH_SECRET=$(openssl rand -base64 32)
EOF
```

`LANGFUSE_ENCRYPTION_KEY` must be exactly 32 bytes of hex — Langfuse rejects anything else — and it
encrypts stored provider credentials, so changing it later orphans them.

The project **public and secret keys** Langfuse issues are created in the UI, per project, after
first login. They belong in the repository-root `.env` alongside the model provider key, not here:
that is the file `agents/` reads.

## Bring it up

From the repository root, after creating `.env` above:

```sh
mkdir -p infra/observability/langfuse/volumes/postgres \
         infra/observability/langfuse/volumes/clickhouse/data \
         infra/observability/langfuse/volumes/clickhouse/logs \
         infra/observability/langfuse/volumes/redis \
         infra/observability/langfuse/volumes/minio

docker compose \
  --env-file infra/versions.env \
  --env-file infra/observability/langfuse/images.env \
  -f infra/observability/langfuse/docker-compose.yml \
  up -d
```

The two `--env-file` flags are not optional and are not a convenience: they are how the pins reach
the compose file. `.env` in this directory is picked up automatically because it sits beside
`docker-compose.yml`. Omit a flag and compose fails naming the missing key — verified, and that is
the designed behaviour, not a bug to work around by inlining a default.

Check what it resolved to before starting anything, which is the cheap way to catch a bad pin:

```sh
docker compose --env-file infra/versions.env \
  --env-file infra/observability/langfuse/images.env \
  -f infra/observability/langfuse/docker-compose.yml config --images
```

Then open <http://localhost:3000>, create the account, organisation and project, and issue the
project keys. Every port is bound to `127.0.0.1`, including the web UI — the trace plane holds
rendered prompts and model completions, which is the most sensitive material this project produces.

**There is deliberately no `make` target for any of this.**
`docs/04-repo-conventions.md` §3 is the target contract, and a target is added when a *gate* is
added. Bringing up a trace plane produces no verdict; `infra/observability/install.sh` and
`scripts/install_cluster_tools.sh` are treated the same way and for the same reason.

## Take it down

```sh
docker compose -f infra/observability/langfuse/docker-compose.yml down
```

State survives an ordinary Compose `down`, because it is bind-mounted under `volumes/` in this
directory rather than held in a named volume. `FORCE=1 make nuke` is the repository-wide destructive
path: after explicit confirmation it removes the four fixed repo-owned datastore directories
(`postgres`, `clickhouse`, `redis`, `minio`) individually. It does not delete the generic `volumes/`
parent, accepts no path override, and rejects symlinked ancestors so deletion cannot escape the
checkout. `volumes/` is gitignored (the rule landed with this stack, in M4, which is what
`.gitignore`'s note promised).

## Tiers

`docs/plans/M4-implementation-plan.md` splits M4's verification by environment, and this stack is
**Tier B**: it needs the gated Docker Desktop setting. Tier A emits the same spans to a file
exporter and needs none of this, which is deliberate — the offline half of M4 must not be blocked on
a trace plane. `infra/observability/otel/` is the collector that joins the two at Tier B.
