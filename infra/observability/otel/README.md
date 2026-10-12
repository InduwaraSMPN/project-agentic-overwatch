# OpenTelemetry Collector

`collector-config.yaml` is the pipeline that carries agent spans to the Langfuse trace plane in
`../langfuse/`: an OTLP receiver, a batch processor, an OTLP/HTTP exporter. Every block in that file
carries its own reasoning.

**Pin:** `OTEL_COLLECTOR_VERSION` in `infra/versions.env`, which names a tag of
`otel/opentelemetry-collector-contrib`. The contrib distribution, not core. Nothing here restates a
version.

Not to be confused with `OTEL_PYTHON_SDK_VERSION` in the same file, which pins the *emitting* side —
`opentelemetry-sdk` and `opentelemetry-exporter-otlp-proto-http`, one key for two distributions
released in lockstep — and is installed by `scripts/install_runtime_deps.sh` under the `agents`
component.

## Which tier uses it

**Tier B only.** `docs/plans/M4-implementation-plan.md` splits M4's verification by environment, and
this collector sits on the far side of the gated Docker Desktop setting, alongside the Langfuse
Compose stack it exports to.

**Tier A needs no collector.** The offline half of M4 — registries, compositions, the three graphs,
the renderer, the parity gate, executor lifecycle — configures the same SDK with a **file exporter**
and writes spans to disk. That is deliberate, and it is the reason nothing in `agents/` depends on
anything in this directory: a span assertion that required a running collector would make the
offline gates need a network, and `make parity-check` is CI-blocking on a runner that has neither
Docker nor a provider credential.

## Run it

From the repository root, with the pin read out of `infra/versions.env` rather than typed:

```sh
OTELCOL=$(grep '^OTEL_COLLECTOR_VERSION=' infra/versions.env | cut -d= -f2 | tr -d '\r')

docker run --rm --network host \
  -v "$PWD/infra/observability/otel/collector-config.yaml:/etc/otelcol-contrib/config.yaml:ro" \
  -e LANGFUSE_OTLP_ENDPOINT -e LANGFUSE_OTLP_AUTH \
  "otel/opentelemetry-collector-contrib:$OTELCOL"
```

The two environment variables are read by the config and are never written into it:

- `LANGFUSE_OTLP_ENDPOINT` — the Langfuse OTLP path, `http://localhost:3000/api/public/otel` for the
  Compose stack next door.
- `LANGFUSE_OTLP_AUTH` — `base64("<public key>:<secret key>")` for the Langfuse project the run
  belongs to. A credential, so it lives in the repository-root `.env` and nowhere else.

There is no `make` target, here or for the Langfuse stack. `docs/04-repo-conventions.md` §3 is the
target contract and a target is added when a gate is added; starting a collector produces no
verdict.
