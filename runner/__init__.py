r"""The experiment runner and data pipeline: identifiers, grid, manifest, validator, order, sealer.

M6's machinery turns a design into data. It addresses all 750 grid cells plus framework-off
baselines, seals bundles that refuse to be incomplete, validates a campaign manifest against the
grid arithmetic that must close on 750, orders runs so neither varying axis is ever blocked, and --
before a single real run -- proves the analysis regenerates every table and figure from raw bundles
alone.

Unlike ``agents/`` and ``monitor/``, ``runner/`` is NOT bound by .agents/rules/10-guardian-first.md:
it is the experimenter's harness, it sits outside the trust boundary, and it may talk to the cluster
directly. ``scripts/grep_guard.sh`` scans ``agents/`` and not ``runner/`` for exactly that reason.
"""
