"""Tests for scripts/, which had none before scripts/scoring_ui.py.

The other components each own a `<component>/tests/` package (AGENTS.md's "Where things go"
table); scripts/ did not need one until a script grew server-side logic worth a unit test rather
than only a CLI smoke run. This package exists solely so pytest can import
`scripts/tests/test_scoring_ui.py` as a module.
"""
