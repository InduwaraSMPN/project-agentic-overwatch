"""Test package for the M5 scenario library.

A package marker, following monitor/tests/'s shape rather than agents/tests/'s conftest, because
these tests share no fixtures and each puts REPO_ROOT on sys.path itself. `.github/workflows/ci.yml`
runs `python -m pytest scenarios/tests` armed on hashFiles('scenarios/tests/**').
"""
