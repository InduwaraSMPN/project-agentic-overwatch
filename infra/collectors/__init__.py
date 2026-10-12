"""Resource-usage collectors for the RQ4 overhead measure.

This package holds :mod:`infra.collectors.resource_collector`, which queries the Prometheus HTTP
API and appends the ``resources.csv`` series that every run bundle carries
(``docs/protocols/data-management.md`` section 1, whose section 3 completeness check refuses to
seal a bundle whose ``resources.csv`` lacks a populated ``restarts_total`` column).

The collector samples on the cadence owned by ``docs/protocols/evaluation-protocol.md`` section 4
and mirrored in :mod:`infra.probes.constants`; it imports that value rather than restating it, so
the probe timeline and the resource series share one clock and ``resources.csv`` rows line up with
``probes.csv`` rows sample for sample.

As with :mod:`infra.probes`, every module here keeps its I/O behind an injectable callable so that
the CI unit tests run on a runner with no cluster and no Prometheus.
"""
