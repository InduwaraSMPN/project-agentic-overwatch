"""Package marker for the cluster and application substrate described in infra/README.md.

This file holds no code and is not expected to. It exists so that ``infra`` is an importable
package from the repository root, which is what makes ``python -m infra.locust.registry`` and
``python -m pytest infra/tests`` resolve without a PYTHONPATH edit, a conftest.py path hack or an
editable install. pyproject.toml already names ``infra`` in ruff's ``src`` list, so the tooling
side of that arrangement was settled at M0; this marker is the interpreter side of it.

The alternative -- leaving infra/ a plain directory and relying on implicit namespace packages --
does work for a bare ``import infra.locust.registry`` when the repository root happens to be the
current directory, and fails the moment anything is invoked from elsewhere or a second directory
named ``infra`` appears anywhere on sys.path. A namespace package resolves by scanning every
sys.path entry, so which ``infra`` wins is a property of the caller's environment rather than of
this repository. An explicit marker removes that ambiguity for the cost of one file.

If this file is deleted, ``python -m infra.locust.registry`` still appears to work from the
repository root under Python 3 and stops working from anywhere else, which is the worst kind of
breakage: it passes locally and fails in whatever invokes it next.
"""
