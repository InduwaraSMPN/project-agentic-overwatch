"""Deterministic scenario-library package.

The package marker keeps ``scenarios.tests`` namespaced during a repository-root pytest run. Without
it, pytest imports ``scenarios/tests`` as the top-level ``tests`` package, which collides with the
other component test packages and prevents the full cross-component suite from collecting.
"""
