# Protocol — Prompt & Instruction-Budget Parity

Status: binding · Serves NFR3 / FR2.3 / dissertation §3.4.3 & §3.5 parity commitments

## 1. Why this exists

The ablation claims are only valid if conditions differ **solely** in the manipulated
variable (topology, or guardrail arm). Prompts, tools, and instruction budgets must be
matched; this protocol makes that a machine-checked invariant instead of an intention.

## 2. Rules

1. **Registry-only prompts.** All prompt text lives in `agents/prompts/` as versioned
   registry files (YAML/MD blocks with stable block IDs). Code composes blocks by ID.
   Zero prompt literals in code (CI grep).
2. **Shared blocks by construction.** Role instructions, tool documentation, safety
   framing, and output-format blocks are defined once and referenced by every condition's
   composition manifest (`agents/prompts/compositions/<condition>.yaml`). Condition
   manifests may differ only in topology-necessitated connective blocks (e.g., "you
   coordinate four supervisors" vs "you handle all phases"), each tagged
   `parity_class: structural`.
3. **One tool registry.** `agents/tools/` definitions (names, schemas, descriptions) are
   identical across conditions; the registry hash goes into every bundle manifest.
   **Which node *holds* an entry is a composition decision, not a registry one** (M4-C7,
   ADR-027). `S2-FLAT` and `S3-SINGLE` have no Supervisor tier, so a reading of FR3.2 under
   which only a Supervisor may hold the token-issuance tool would make two thirds of the
   structure ablation unrunnable. The issuance tool is therefore **one entry in the one
   registry**, and each condition manifest names the role that holds it in its
   `issuance_tool_holder` field — the phase Supervisor in `S1-HIER`, the coordinator in
   `S2-FLAT`, the single agent in `S3-SINGLE`. The run's registered-issuer set is read from
   that field and passed to the Guardian at start, so no Guardian code and no policy file
   differs between arms. A G2-only or S2-only tool remains forbidden outright by this rule.
4. **Grounding.** Prompt blocks derive from peer-reviewed work on comparable
   incident-response and LLM-agent designs, "in preference to composing them ad hoc"
   (§3.4.3 · "Selection criteria are stated instead, matching the system design
   specification's"), with §3.4.3's stated reason: "Chapter 2's engineering-wisdom
   hypothesis and CFA-Bench's counter-evidence (§3.4.1) make guidance quantity itself a
   confound" (§3.4.3 · "criteria are stated at this level because Chapter 2's
   engineering-wisdom hypothesis and"). The operative citations live in §3.5.4–§3.5.5
   (SLOT-PARITY-01, conflict C10 — this slot previously attributed them wholesale to
   §3.4.3): CFA-Bench's task-matched prompt-length parity, "CFA-Bench already matches
   prompt length across flat and multi-agent conditions in a task-specific way
   [De Santis et. al., 2025]" (§3.5.4 · "This parity is drawn from the ablation literature
   the"); the corpus's guardrail-evaluation vocabulary and attack-content source,
   "[Patel, 2026a]" for "threat-model structure and injection-class taxonomy" and
   "[Abdennebi et. al., 2026]" for "a relevance-filtered subset of the seven attack
   categories" (§3.5.4 · "The ablation draws its threat-model structure and
   injection-class taxonomy"); and the GQM paradigm [Basili and Rombach, 1988] that
   structures the measures (§3.5.5 · "Table 3.4 defines the measures per evaluation
   area"). Each block header lists its source anchor. New blocks require a source or an
   explicit `origin: engineering` tag with justification.
5. **S3-SINGLE's parity target is the Supervision layer.** The single-agent composition
   carries "the same role descriptions and procedure text as the hierarchical
   architecture's Supervision layer but uncompressed into one prompt" (§3.5.4 · "C3, a
   single-agent baseline") — those blocks concatenated, not a fresh authoring, and not a
   compression of the whole hierarchical stack.

## 3. The parity check (`make parity-check`, CI-blocking; implemented by `agents/registry/parity.py` behind `scripts/parity_check.sh`)

**The home named in this heading was corrected at M4** (conflict M4-C2, ADR-027). It previously
read "spec for `analysis/stats/parity_check.py`", which conflicted with two other binding files:
`data-management.md` §8 binds `analysis/` to read "only `runs/` raw files (never `metrics.json`
caches, never live services)", and a parity check reads `agents/` and no bundle at all;
`04-repo-conventions.md` §1 separately requires every gate's logic to live in `scripts/`. The
deciding argument is neither of those. **The check must count exactly the bytes the graph sends** —
a checker with its own rendering path measures a prompt no run ever used — so the composer is
agent-layer code shared by the gate and the runtime, it lives in `agents/registry/`, and
`scripts/parity_check.sh` is the one-line gate script §1 asks for. `analysis/stats/parity_check.py`
is not created.

For every condition: render all composed prompts per role; tokenize with the **pinned reference
tokenizer** named by `PARITY_TOKENIZER` in `infra/versions.env`, whose identity is emitted in the
token table and recorded in every bundle manifest beside `prompt_registry_sha256`. Then assert:

- **Shared-block identity**: every non-`structural` block byte-identical across conditions.
- **Budget tolerance**: total instruction tokens per condition within the tolerance the block
  below fixes, of the cross-condition mean, and `structural` blocks each ≤ the cap the block
  below fixes.
- **Tool identity**: tool registry hash identical across conditions.
- **Budget scope — tokens, tool calls, and turns** (conflict C7): parity covers all
  three. §3.5.4 grants the flat arm "every phase the same budget of prompt tokens, tool
  calls, and turns as the hierarchical configuration's combined per-phase allocation",
  and §3.4.3 requires "parity of instruction and tool-description budget across the
  architectural conditions compared in §3.5.4" — instruction tokens alone are too
  narrow. Tool-call and turn budgets are therefore compared across condition
  compositions like token budgets. Traceability: matrix row T-37 (row added by the
  M0-T0.6 matrix task).
- **Realizable-action parity (assertion 5, M10, ADR-122).** Per phase, the number of realizable
  mint-and-act pairs is equal across conditions within `condition_tool_call_tolerance_pct`, and each
  arm's `max_turns` is sufficient for that many pairs. Token/tool-call/turn budgets being equal is
  necessary but not sufficient: the v1 defect V1 left S2-FLAT and S3-SINGLE with budgets identical to
  S1-HIER yet no realizable act path, because the acting role could mint but the composed text never
  told it to act on the mint and `max_turns` did not cover a mint-then-act pair in one iteration. This
  assertion makes "the arm can actually act under its budget" a checked property, not an assumed one.
  The **G2-only `environment` credential lines lie outside this check by construction** (ADR-131,
  D1-A): `make parity-check` compares the structure conditions and `ComposedCondition.total_tokens`
  sums block bodies only, so the runtime `environment` field — runner-supplied data, not a prompt
  block — is not a parity subject; its G2 token delta is measured once and recorded in ADR-131.
  The `cluster_api_request` tool and its neutral doc block ARE parity subjects and are identical
  across all three compositions (tool identity above).

Output: per-condition token table (written into the M4/GATE record). Failure blocks merge.
The tolerance is never loosened to make a change pass (rule 20); if a legitimate structural
need exceeds it, that is a design decision → ADR + supervisor note.

### Why the reference tokenizer is primary and the campaign model's is a cross-check

The clause above previously read "tokenize with the campaign model's tokenizer (via LiteLLM
utilities; fallback: a fixed reference tokenizer, recorded)". M4 makes the fallback the operative
one (conflict M4-C3, ADR-028), and the reason is that the gate is CI-blocking and must be
reproducible on a runner with **no provider credential and no network**. ADR-005 defers the final
model to GATE re-verification under risk R-01 — a provider deleted free models without notice in
May 2026 — so a parity number tokenized by the campaign model's tokenizer would move when a free
catalogue churned. A parity number that moves for a reason that has nothing to do with the
registry is not a parity number.

The campaign model's own tokenizer is compared against the reference **once, at GATE**, when R-01's
limit re-verification fixes the model. It is reported there as a cross-check on the ratio between
the two counts, and never as the gate.

### Why the tool-call and turn budgets have an artefact to read

Tokens are countable from rendered prompts. Tool calls and turns are runtime quantities, and before
M4 no file in the kit declared them anywhere — so the third and fourth assertions above had nothing
to assert over, and the check could have reported green having compared one budget of three
(conflict M4-C4). They are now **declared once** in each
`agents/prompts/compositions/<condition>.yaml`, per phase and per role, as `max_turns` and
`max_tool_calls`, and read twice: `make parity-check` asserts that `S1-HIER`'s per-role allocations
sum, per phase, to `S2-FLAT`'s coordinator budget and to `S3-SINGLE`'s single-agent budget; and the
graph runtime enforces the same declared numbers at execution, recording consumption against them
in the run bundle. One home, two readers, is the only arrangement in which the checked number and
the enforced number cannot diverge.

**A retry is a turn.** Risk R-10's mitigation is "structured-output prompting; retry policy
logged", and a weak free model retries more in whichever arm happens to trip it. If retries did not
count against the declared turn budget, the arm that struggled would silently receive more turns
and the ablation would be confounded by model weakness rather than by topology. Exhausting the
budget is a recorded phase outcome, never an escape hatch. ADR-028.

### The parity caps — the third machine-readable block

Same mechanism as `evaluation-protocol.md` §4's two blocks, and deliberately not a fourth
mechanism: ADR-016's pattern is that a protocol section owns a value, a module mirrors it, and a
test parses the block and fails on drift. What is per-anchor is the *scope*. This block is owned by
this section because `evaluation-protocol.md` §0's ownership table assigns "Parity tolerance" here;
`agents/registry/limits.py` mirrors it key for key and
`agents/tests/test_limits_match_parity_policy.py` parses this block and fails CI on any divergence.
Edit the block here first; the module follows.

`structural_block_tokens_max` is a **measurement** — it is read off the first honest compositions,
as the bullet above requires, and is counted with the pinned reference tokenizer. The three
tolerances are **choices**: `condition_token_tolerance_pct` is §3.5.4's ±2%, entered here as the
number this section owns rather than restated in prose, and the tool-call and turn tolerances are
zero because those budgets are *declared* rather than measured — two manifests that declare
different numbers differ by intent, and a tolerance would be a licence to declare them differently.

The checker carries **no default for any of these**. It fails closed with a named error if a cap is
unset or still carries the sentinel `PENDING-M4-COMPOSITION`, which is the refinement M2 added to
ADR-016's pattern and which is kept here for the same reason: a default would let the gate run —
and go green — against a number nobody set.

The gate also fails closed on an **empty or incomplete registry**, and that is not the same claim.
`scripts/grep_guard.sh` may pass vacuously because nothing found means nothing violated; parity
asserts an *equality*, so nothing found means nothing proved, and a green check over an absent
registry would make deleting the registry the easiest way to pass. It exits non-zero with a named
error when a condition has no composition manifest, when a cap is still pending, or when a declared
budget is missing.

<!-- m4-parity-caps -->

```yaml
structural_block_tokens_max: 39
condition_token_tolerance_pct: 2
condition_tool_call_tolerance_pct: 0
condition_turn_tolerance_pct: 0
```

## 4. Change procedure

Any edit under `agents/prompts/` or `agents/tools/`: run parity check locally; PR includes
the emitted token table; post-`v1.0` freeze such edits are prohibited except hotfix ADRs
(which trigger re-verification and a campaign-notes entry listing affected runs). The M10
remediation re-opens `agents/prompts/` and `agents/tools/` before the new `v2.0` instrument freeze
(ADR-136) — the S2/S3 act-path block and the `cluster_api_request` tool (ADRs 121, 131) — and after
`v2.0` the same prohibition binds: a prompt or tool edit is an instrument change that halts the
campaign and resets the pilot ladder to P1a. `agents/prompts/` and `agents/tools/` are inside the
instrument path set the digest covers.
