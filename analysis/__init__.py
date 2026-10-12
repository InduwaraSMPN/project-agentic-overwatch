r"""The analysis component: metric functions and rendering notebooks over raw run bundles.

`docs/04-repo-conventions.md` §1 places `notebooks/` and `stats/` here; `stats/` computes and the
notebooks render (`data-management.md` §8). This package marker exists so that `analysis.stats` is
importable as a first-party package -- `pyproject.toml`'s `src` list already names `analysis` for
import sorting, and `analysis/tests/` reaches the metric functions through `from analysis.stats
import ...`. ADR-043 records `analysis/` becoming a tested component at M6.
"""
