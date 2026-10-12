"""SLO probe instrumentation for the RQ4 overhead and T-21 restoration measures.

This package holds two things and deliberately nothing else. :mod:`infra.probes.constants` is a
runtime mirror of the instrument constants that ``docs/protocols/evaluation-protocol.md`` section 4
owns, and :mod:`infra.probes.slo_probe` is the writer that drives those constants against a
deployed Online Boutique and appends the ``probes.csv`` timeline that every run bundle carries
(``docs/protocols/data-management.md`` section 1).

The package is importable without a cluster, without a network and without any third-party
dependency, because the first file placed under ``infra/tests/`` arms the ``Unit tests -- infra``
step in ``.github/workflows/ci.yml``, and that step runs on a GitHub runner which has none of
those. Every module here therefore keeps its input and output behind an injectable callable, so
the tests exercise the logic and never open a socket.
"""
