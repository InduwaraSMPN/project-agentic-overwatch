# analysis — metrics, statistics and figures

Holds `notebooks/` and `stats/`, as listed in `docs/04-repo-conventions.md` section 1. Notebooks
render; the metric functions in `stats/` compute.

- Populated by M6 and proven against synthetic bundles before any real data exists; consumed by M7
  when the campaign runs.
- Serves traceability row T-25 (every metric and figure regenerated from raw bundles alone), and
  produces the outputs behind T-18 and T-20.
- Constrained by `.agents/rules/20-parity-and-determinism.md`: analysis reads raw run bundles from
  `runs/` only, never an intermediate or hand-edited file.
- Constrained by `.agents/rules/00-source-of-truth.md`: metric definitions and statistical
  procedures are owned by `docs/protocols/evaluation-protocol.md`.
