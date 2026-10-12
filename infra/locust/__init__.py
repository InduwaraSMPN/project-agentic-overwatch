"""Package marker for the load-driver component: the profile registry, its resolver and its deploy.

The directory holds four things that belong together and nothing else: profiles.yaml, which is the
registry of load profiles and therefore the single home for the value set the run-manifest field
``load_profile_id`` ranges over (docs/protocols/data-management.md section 2); registry.py, which is
the resolution contract the runner imports; locustfile.py, which is the load script those profiles
name; and deployment.yaml, which puts that script in the cluster.

The marker exists so ``python -m infra.locust.registry`` works from the repository root, which is
the form the M1 Definition of Done names for listing the registry. It also fixes the package name
to ``infra.locust``, which is deliberately not the top-level ``locust`` distribution that
locustfile.py imports: absolute imports are the default in Python 3, so ``import locust`` inside
this package resolves to the installed Locust and never to this directory. Nothing here imports
Locust anyway -- registry.py is standard library only, because the runner resolves a profile on a
host that has no reason to have a load-testing framework installed, and because CI's pytest step
installs nothing beyond pytest.
"""
