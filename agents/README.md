# agents — the LLM layer

Holds `graphs/` (the three topologies), `prompts/` (the prompt registry), `registry/` (the composer,
the reference tokenizer, the digests and the parity checker), `tools/` (Guardian clients) and
`tests/`, as listed in `docs/04-repo-conventions.md` section 1.

- Populated by M4, which composes S1-HIER, S2-FLAT and S3-SINGLE from single shared registries so
  that the conditions differ only in wiring.
- Serves traceability rows T-05 (hierarchy and the four phases), T-06 (parity by construction) and
  T-07 (ephemeral executors holding no standing credentials); also evidences T-09 and T-14.
- Rule 10 invariant (`.agents/rules/10-guardian-first.md`): nothing under this directory imports a
  Kubernetes client library, shells out to the Kubernetes command-line client, or opens a
  connection to the cluster API. The only mutation path opened by this code is the Guardian client
  in `agents/tools/`; the direct-path `cluster_api_request` tool reaches the API server only through
  the runner's environment-gated transport, never through a client held here.
  CI greps every tracked file here for violations, that command-line client's binary name among
  them — which is why this paragraph names the tool by description rather than spelling it.
  ADR-029 records why no exemption mechanism was added when M4 met that guard for the first time.
- Rule 20 invariant (`.agents/rules/20-parity-and-determinism.md`): no prompt text in code. Prompts
  exist only in the `agents/prompts/` registry files, and code composes them.
  `scripts/prompt_purity_grep.sh` and `agents/tests/test_prompt_purity.py` are what make that a
  check rather than a habit.

## What each directory is

| Path | Contents |
|---|---|
| `graphs/` | `nodes.py` (four role behaviours), `plan.py` (a topology's traversal as a value), and `hier.py` / `flat.py` / `single.py` — one short module per structure arm, each deciding only which roles run in a phase and in what order |
| `prompts/` | `blocks/*.md` (every byte a model reads, with a source anchor or an `origin: engineering` justification per parity policy section 2 rule 4) and `compositions/<condition>.yaml` (which roles exist, which blocks and tools each holds, and what each is allocated per phase) |
| `registry/` | the loader, composer, evidence renderer, digests, pinned reference tokenizer, mirrored parity caps and the parity checker `scripts/parity_check.sh` delegates to |
| `tools/` | the one tool registry, identical across conditions, and the Guardian client — the only mutation path this code opens (the direct-path `cluster_api_request` tool is gated by the runner's environment) |
| `tests/` | the Tier A suite: offline, no network, no Docker, no credential, no provider token spent |
| `golden.py` | `python -m agents.golden`, the golden-path driver `scripts/agents_golden.sh` delegates to |

## Two properties worth knowing before editing anything here

**`registry/` is standard library only.** `scripts/parity_check.sh` runs inside `ci.yml`'s
`guardrail-grep` job, which checks out the repository, runs shell scripts and installs nothing at
all. A parity checker with a third-party dependency would fail there for a dependency reason before
it could fail for a code one, so the manifest parser and the tokenizer are both written here rather
than imported. `agents/tests/test_prompt_purity.py` asserts the property; ADR-028 records it. The
two modules that do reach outside — `registry/model.py` and `registry/tracing.py` — import their
backends lazily inside functions and are on no gate's import path.

**No condition string reaches a node.** A condition selects which composition manifest is loaded,
and nothing below that point knows which arm it is in: there is no `condition` parameter on any node
factory and no field on `NodeContext` able to hold an arm, a mode or a quoting flag. ADR-027 rejects
the branch outright because it would be the confound, and ADR-023 keeps every condition flag in the
runner's hands. The arms are reached by starting the Guardian differently and by handing the
renderer differently quoted evidence — `agents/tests/test_flag_exercise.py` is where that is shown.

## Running things

```
make parity-check     # the CI-blocking prompt and tool parity gate; prints the token table
make agents-golden    # the golden path, S1-HIER x G0-FULL; Tier A'/B, refuses without a Guardian
python -m pytest agents/tests
```

`make agents-golden` takes no parameters and never will: `docs/04-repo-conventions.md` section 3
fixes the signature, and a mode or condition variable on it would be exactly the reach ADR-023
refuses. It requires `GUARDIAN_URL` to name a running Guardian and `MODEL_PROVIDER_STRING` to
resolve, and refuses with a named prerequisite rather than degrading to something weaker — the
offline half of the same evidence is `agents/tests/test_golden_path.py`.

The dev/pilot endpoint is OpenAI-compatible. Put only
`DEV_LLM_KEY=...` in the ignored repository-root `.env`, load it into your shell, then
run `. scripts/dev_llm_env.sh`. The tracked primary is
`custom_openai/gpt-5.6-terra`; select Luna for an intentional run with
`MODEL_PROVIDER_STRING=custom_openai/gpt-5.6-luna` (`custom_openai/gpt-5.6-sol` is the third
model, expressible the same way and not selected). The helper maps the existing key
to LiteLLM's `OPENAI_API_KEY` and sets `OPENAI_BASE_URL` without printing or storing the secret.
