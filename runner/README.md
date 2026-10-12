# runner — experiment CLI and campaign manifests

Holds the run CLI and the campaign manifests, as listed in `docs/04-repo-conventions.md`
section 1. It takes a condition, a scenario and a seed, and seals one run bundle.

- Populated by M6, which adds the bundle sealer and sanitizer, the campaign manifest validator,
  and the interleaved deterministic run-order generator.
- Serves traceability rows T-15 (complete sealed bundles), T-23 (campaign grid arithmetic) and
  T-24 (interleaved order and the fixed seed set); it is also where T-13's condition flags are set.
- Constrained by `.agents/rules/10-guardian-first.md`: the G1-LOGONLY and G2-SHAREDCRED ablation
  arms are activated only by this component's condition flags, never by editing Guardian code or
  policy. The same condition flags also carry the G3-UNQUOTED Monitor quoting toggle, which the
  aggregator branches on (see `monitor/README.md`).
- Constrained by `.agents/rules/00-source-of-truth.md`: the grid arithmetic, the seed set and the
  per-run budgets are defined once in `docs/protocols/evaluation-protocol.md`. The validator here
  enforces that definition rather than restating it.
