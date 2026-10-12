#!/bin/sh
#
# install_runtime_deps.sh -- install the Python runtime dependencies of the evaluated artefact at
# exactly the versions infra/versions.env pins.
#
# WHY THE PINS LIVE IN infra/versions.env AND NOT IN pyproject.toml
#   pyproject.toml's own header reserves the field and says why: runtime dependencies are "pinned
#   by the component that introduces them, together with the ADR that justifies it, so
#   `dependencies` stays empty here rather than becoming a second version-pinning surface
#   alongside infra/versions.env". docs/03-tech-stack.md section 5 makes that file the single
#   pinning surface for the whole stack, and docs/protocols/data-management.md section 2 puts its
#   digest -- versions_env_sha256 -- into every sealed run bundle. A dependency that validates
#   every EvidenceEvent the campaign produces is part of the software under study: change it and
#   you have changed the artefact, which the bundle digest must record. A per-component
#   requirements file would be the same second surface under a tidier name. ADR-021.
#
# THIS IS NOT THE SAME CLASS AS THE CI TOOL PINS
#   ADR-011 deliberately keeps ruff and pytest as literals inside .github/workflows/ci.yml,
#   because a linter and a test runner are not part of the evaluated artefact and must stay
#   upgradable without touching a pin frozen at v1.0 or invalidating the digest above. The
#   dependencies installed here are the opposite case, and ADR-017 already drew the same line for
#   the cluster toolchain -- kind, helm and the cilium CLI install from versions.env for exactly
#   this reason. This script extends a settled principle rather than introducing one.
#
# WHY A SCRIPT RATHER THAN A LINE IN THE WORKFLOW
#   docs/04-repo-conventions.md section 1: every gate's logic lives in scripts/, and the workflow
#   files invoke those scripts rather than reimplementing them, "so each gate is defined once and
#   runs identically from `make` in WSL2, from Git Bash on the Windows host ... and on the CI
#   runner". A pin expressed once in a workflow step and again in a developer's README is a pin
#   with two readers and therefore two values. scripts/install_cluster_tools.sh is the sibling
#   this follows.
#
# WHY THERE IS NO MAKE TARGET
#   docs/04-repo-conventions.md section 3 is the target contract, and a target is added when a
#   gate is added. Installing dependencies is not a gate: it produces no verdict and can fail for
#   reasons that say nothing about the repository. scripts/install_cluster_tools.sh is treated the
#   same way and for the same reason. CI calls this script directly, as it calls every other one.
#
# WHAT IT INSTALLS, AND WHAT IT DELIBERATELY DOES NOT
#   Only the runtime dependencies of components that exist. At M2 that was pydantic, for the
#   evidence aggregator; M3 adds FastAPI and PyJWT for the Guardian; M4 adds the `agents` component
#   -- LangGraph, LiteLLM and the two OpenTelemetry distributions -- and adds the Kubernetes client
#   to `guardian`, which is the milestone the Guardian first executes rather than only decides.
#   Later milestones add their own
#   keys to versions.env and their own lines here, in the commit that introduces the component --
#   never ahead of it, because a dependency installed for code that does not exist is a pin nothing
#   checks. Development tooling (ruff, pytest) is not installed here: see the ADR-011 boundary.
#
# COMPONENT SELECTION, AND WHY THIS IS ONE SCRIPT RATHER THAN ONE PER COMPONENT
#   Usage: install_runtime_deps.sh [component ...]  -- with no argument it installs every component
#   whose code is present in the tree; with arguments it installs exactly those. The known set is
#   the registry at the pinned-set block below.
#
#   docs/plans/M3-implementation-plan.md proposes a separate scripts/install_component_deps.sh.
#   That would be a second home for the same logic: two installers drift, and the day they disagree
#   about which interpreter is targeted or which failure mode is correct is the day a CI run and a
#   developer's shell stop matching. The plan's actual requirement is that acquisition be
#   single-homed in infra/versions.env, and a component argument satisfies it without a second
#   script. Recorded in ADR-025 and in that plan's execution record.
#
#   Selection is by presence, not by a milestone marker: a component is installable when its
#   package directory holds Python. That is checkable, needs no second thing to remember, and keeps
#   the no-argument form correct at every point in the project's life with no edit here.
#
# TARGET ENVIRONMENT
#   Installs into whatever Python is on PATH, or into $PYTHON if set. It does not create or
#   activate a virtualenv, because where the packages go is the caller's policy: CI selects an
#   isolated setup-python toolcache interpreter, and a developer may reasonably want a virtualenv,
#   the system interpreter, or a container. Making that choice here would take it away from every
#   caller.
#
# STREAMS
#   stdout carries one line per package plus a final summary line. stderr carries failures.
#
# PORTABILITY
#   Strict POSIX sh -- no bashisms, no GNU-only options -- so it runs under dash in WSL2 Ubuntu,
#   under Git Bash on the Windows host, and on ubuntu-latest.

set -eu

LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

versions_file="infra/versions.env"
PYTHON=${PYTHON:-python3}

if [ ! -f "$versions_file" ]; then
    echo "install-runtime-deps: $versions_file not found; run from a full checkout" >&2
    exit 1
fi

if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "install-runtime-deps: '$PYTHON' is not on PATH. Set PYTHON to the interpreter to install into." >&2
    exit 1
fi

# Read a key with grep and cut rather than by dot-sourcing. infra/versions.env is values-only by
# its own contract, which makes sourcing safe in principle -- but a check that would execute a
# malformed line is a worse check than one that cannot, and scripts/versions_env_sha256.py
# already establishes that this file is read with CRLF normalised away rather than trusted to be
# LF on every host.
read_pin() {
    read_pin_key=$1
    read_pin_value=$(grep -E "^${read_pin_key}=" "$versions_file" | head -n 1 | cut -d= -f2- | tr -d '\r')
    if [ -z "$read_pin_value" ]; then
        echo "install-runtime-deps: $read_pin_key is empty or absent in $versions_file." >&2
        echo "install-runtime-deps: An unpinned runtime dependency resolves to whatever the index" >&2
        echo "install-runtime-deps: serves today, so two campaigns weeks apart would validate their" >&2
        echo "install-runtime-deps: events against different code while recording the same" >&2
        echo "install-runtime-deps: versions_env_sha256 digest. Populate the key and re-run." >&2
        exit 1
    fi
}

# --- component selection ---------------------------------------------------------------------
KNOWN_COMPONENTS="monitor guardian agents analysis"

if [ "$#" -gt 0 ]; then
    selected=$*
    for want in $selected; do
        found=no
        for known in $KNOWN_COMPONENTS; do
            [ "$want" = "$known" ] && found=yes
        done
        if [ "$found" = "no" ]; then
            echo "install-runtime-deps: unknown component '$want'. Known: $KNOWN_COMPONENTS" >&2
            exit 1
        fi
    done
else
    # No argument: every component whose code is present. An explicitly named component that is
    # absent is still an error above, because naming one is a statement that it should be there.
    selected=""
    for known in $KNOWN_COMPONENTS; do
        if [ -d "$known" ] && [ -n "$(find "$known" -name '*.py' -print -quit 2>/dev/null)" ]; then
            selected="$selected $known"
        fi
    done
    if [ -z "$selected" ]; then
        echo "install-runtime-deps: no component with Python code is present; nothing to install."
        echo "install-runtime-deps: PASS - 0 package(s), no component present"
        exit 0
    fi
fi

echo "install-runtime-deps: interpreter $("$PYTHON" --version 2>&1)"
echo "install-runtime-deps: components:$selected"

# --- the pinned set -------------------------------------------------------------------------
# One entry per runtime dependency, each naming the component that needs it. Keep this list and
# infra/versions.env in step: a key added there without a line here installs nothing, and a line
# here without a key there fails on the first run rather than silently resolving to latest.
#
# pydantic appears under both components deliberately. It is one pin behind one key, and installing
# it twice at the same version is a no-op -- whereas giving the Guardian its own pydantic key would
# be exactly the second version home this file exists to prevent.
wanted=""
for component in $selected; do
    case "$component" in
        monitor)
            read_pin PYDANTIC_VERSION
            wanted="$wanted pydantic==$read_pin_value"
            ;;
        guardian)
            read_pin PYDANTIC_VERSION
            wanted="$wanted pydantic==$read_pin_value"
            read_pin FASTAPI_VERSION
            wanted="$wanted fastapi==$read_pin_value"
            read_pin PYJWT_VERSION
            wanted="$wanted PyJWT==$read_pin_value"
            # The Kubernetes client is the Guardian's and only the Guardian's. It is named here
            # rather than under `agents` because guardian/ is the sole credential holder and
            # the guardian-first iron rule (AGENTS.md 1) forbids a Kubernetes client under agents/ at all;
            # installing it for the agent layer would put the import one `pip show` away from the
            # boundary scripts/grep_guard.sh exists to hold.
            read_pin KUBERNETES_CLIENT_VERSION
            wanted="$wanted kubernetes==$read_pin_value"
            read_pin UVICORN_VERSION
            wanted="$wanted uvicorn==$read_pin_value"
            # cryptography is the Ed25519 primitive the audit chain signs and verifies with
            # (ADR-130). It is listed for `guardian` because guardian/tests/ imports it at MODULE
            # level -- test_audit_signing.py and test_audit_tamper.py -- so a run without it does
            # not fail a case, it dies at collection. That is exactly how this line came to be here:
            # the M10 hygiene job reported `ModuleNotFoundError: No module named 'cryptography'`
            # and `2 errors during collection`, and the adversarial half of `make guardian-test`
            # could not run at all. The application code imports it lazily (guardian/app/
            # composition.py, guardian/audit/verify.py), which is why the omission stayed invisible
            # to every import-time check outside the test suite.
            read_pin CRYPTOGRAPHY_VERSION
            wanted="$wanted cryptography==$read_pin_value"
            ;;
        agents)
            # M4's component. LangGraph is the topology the three structure arms are (ADR-002) and
            # LiteLLM is the single call surface every arm reaches a model through (ADR-005); the
            # two OpenTelemetry distributions carry the span emission ADR-006 asks for. Both of the
            # latter install at ONE key, OTEL_PYTHON_SDK_VERSION, because they are released in
            # lockstep from one repository under one version number -- see that key's comment in
            # infra/versions.env for why a second key would be a second home for one version.
            read_pin LANGGRAPH_VERSION
            wanted="$wanted langgraph==$read_pin_value"
            read_pin LITELLM_VERSION
            wanted="$wanted litellm==$read_pin_value"
            read_pin OTEL_PYTHON_SDK_VERSION
            wanted="$wanted opentelemetry-sdk==$read_pin_value"
            wanted="$wanted opentelemetry-exporter-otlp-proto-http==$read_pin_value"
            ;;
        analysis)
            # M6's component. pandas frames the raw bundles, statsmodels computes the Wilson
            # interval evaluation-protocol §3 requires, matplotlib renders the figures. statsmodels
            # pulls scipy/patsy transitively; only the three the artefact imports directly are
            # pinned, on the same rule the OTel pair follows -- a pin per distribution the code
            # names, not per package in the resolved tree. ADR-021, ADR-043.
            read_pin PANDAS_VERSION
            wanted="$wanted pandas==$read_pin_value"
            read_pin STATSMODELS_VERSION
            wanted="$wanted statsmodels==$read_pin_value"
            read_pin MATPLOTLIB_VERSION
            wanted="$wanted matplotlib==$read_pin_value"
            ;;
    esac
done

# De-duplicate, order preserved, so pydantic named by two components installs once and the summary
# counts distinct packages rather than mentions.
packages=""
for spec in $wanted; do
    seen=no
    for already in $packages; do
        [ "$spec" = "$already" ] && seen=yes
    done
    [ "$seen" = "no" ] && packages="$packages $spec"
done

for spec in $packages; do
    echo "install-runtime-deps: $spec"
done

# PEP 668, and why this check exists rather than a --break-system-packages flag.
#
# Debian and Ubuntu mark their system interpreter "externally managed", so pip refuses to install
# into it and prints roughly twenty lines about virtual environments and pipx. WSL2 Ubuntu-24.04 --
# which docs/04-repo-conventions.md section 2 makes this project's development environment -- is
# exactly such a host, so the first developer to run this script hits it. Passed through raw, that
# wall of text buries the one sentence that matters and reads like a defect in this repository.
#
# The flag is deliberately NOT set. --break-system-packages does what its name says: it installs
# into the interpreter the distribution's own packages depend on, and a pydantic upgrade that
# breaks an apt-installed tool is a failure with no connection to anything this project changed.
# A virtualenv costs one command and keeps the pin where it belongs. So the script detects the
# marker, refuses early, and prints the three lines a developer actually needs.
#
# CI uses actions/setup-python's isolated hosted-toolcache interpreter, so the guard does not fire
# there. The workflow must not rely on ubuntu-latest's mutable system-Python packaging policy.
# The virtualenv test comes FIRST, and getting that order wrong is the bug this comment exists to
# stop somebody reintroducing. A virtualenv does not carry its own copy of the standard library --
# sysconfig.get_path("stdlib") inside one resolves to the BASE interpreter's Lib directory. So a
# venv built from an externally-managed base reports the marker as present even though installing
# into it is entirely safe, and the first draft of this guard duly refused to install into the
# repository's own virtualenv. pip resolves it the same way: it skips the PEP 668 check whenever it
# is running inside a virtual environment, because the whole point of the marker is to protect the
# interpreter the distribution's packages depend on, and a venv is not that interpreter.
externally_managed=$("$PYTHON" -c 'import sys,sysconfig,os
if sys.prefix != sys.base_prefix:
    print("no")
else:
    p = sysconfig.get_path("stdlib")
    print("yes" if os.path.exists(os.path.join(p, "EXTERNALLY-MANAGED")) else "no")' 2>/dev/null || echo "no")
if [ "$externally_managed" = "yes" ]; then
    {
        echo "install-runtime-deps: REFUSING -- $PYTHON is an externally managed interpreter (PEP 668)."
        echo "install-runtime-deps: This is normal on Debian and Ubuntu, including the WSL2 distro"
        echo "install-runtime-deps: docs/04-repo-conventions.md section 2 asks you to work in. Installing"
        echo "install-runtime-deps: into it would put a pinned dependency alongside the packages apt-installed"
        echo "install-runtime-deps: tools rely on, so this script will not do it."
        echo
        echo "install-runtime-deps: Create a virtual environment once, then point this script at it:"
        echo "install-runtime-deps:   sudo apt install python3-venv        # once, if 'ensurepip is not available'"
        echo "install-runtime-deps:   python3 -m venv ~/.venvs/agentic-overwatch"
        echo "install-runtime-deps:   PYTHON=~/.venvs/agentic-overwatch/bin/python sh scripts/install_runtime_deps.sh"
        echo
        echo "install-runtime-deps: Then run the Monitor gates against the same interpreter:"
        echo "install-runtime-deps:   PYTHON=~/.venvs/agentic-overwatch/bin/python make monitor-replay"
    } >&2
    exit 1
fi

# THE INSTALL. Two paths, and the split is what keeps the hashed lock (ADR-135) from colliding with
# rule 40. When NO component is named -- the whole-environment install a campaign host and CI's lint job
# run -- install the fully-resolved, hash-pinned lock with --require-hashes, so the transitive closure is
# frozen by digest (V23) and matches the images. When a component IS named, install only that component's
# packages, unchanged: rule 40 (the monitor-non-LLM iron rule (AGENTS.md 7)) requires
# `monitor` to install pydantic and NO inference SDK, and pip cannot install a hashed
# SUBSET of one universal lock (constraint files do not supply hashes
# to command-line requirements), so a named `monitor` install from the full lock would put LiteLLM in the
# Monitor's interpreter. The whole-lock path never carries a component name, so it never contradicts the
# per-component derivation monitor/tests/test_no_inference.py reads out of the case arms above. The
# lock's own consistency with these pins is checked by infra/tests/test_lock_matches_versions_env.py.
if [ "$#" -eq 0 ] && [ -f requirements.lock ]; then
    echo "install-runtime-deps: installing the hashed lock requirements.lock (--require-hashes)"
    "$PYTHON" -m pip install --disable-pip-version-check --quiet --require-hashes -r requirements.lock
else
    # shellcheck disable=SC2086
    "$PYTHON" -m pip install --disable-pip-version-check --quiet $packages
fi

# Verify by import, not by pip's exit status. pip can succeed into an interpreter that is not the
# one that will import -- a shadowed user site directory, a stale PATH entry, a different python on
# the same name -- and that failure stays silent until a test fails for an unrelated-looking reason.
# Asking the target interpreter what it actually holds closes it.
verify_installed() {
    # $1 pip name, $2 import name, $3 expected version, $4 expression printing the version
    verify_have=$("$PYTHON" -c "$4" 2>/dev/null || echo "")
    if [ "$verify_have" != "$3" ]; then
        echo "install-runtime-deps: FAIL -- $2 reports '${verify_have:-<not importable>}' after" >&2
        echo "install-runtime-deps: installing '$1==$3'. The interpreter that ran pip is not the one" >&2
        echo "install-runtime-deps: that imports, or the install was shadowed. Set PYTHON explicitly." >&2
        exit 1
    fi
}

installed_count=0
for spec in $packages; do
    spec_name=${spec%%==*}
    spec_version=${spec#*==}
    # THE FOUR M4 ENTRIES ASK importlib.metadata RATHER THAN IMPORTING, AND THE CHECK IS UNCHANGED.
    # The paragraph above says why this loop exists: pip can succeed into an interpreter that is not
    # the one that will import. importlib.metadata.version() reads the installed distribution's
    # metadata out of the TARGET interpreter's own sys.path -- the same site-packages an import
    # would resolve against, discovered by the same finders -- so it answers exactly that question.
    # What it does not do is execute the package, and for these four that matters twice over:
    # litellm's import is several seconds of provider-registry construction, paid on every CI run
    # for a number the metadata already holds, and langgraph exposes no stable __version__ at all,
    # so an import-based check would have to invent an attribute and would break on the release
    # that moved it. The distribution name is what is asked for, which is why the OTLP exporter is
    # queried under its hyphenated pip name rather than under any module it happens to install.
    case "$spec_name" in
        pydantic) verify_installed pydantic pydantic "$spec_version" 'import pydantic; print(pydantic.VERSION)' ;;
        fastapi)  verify_installed fastapi fastapi "$spec_version" 'import fastapi; print(fastapi.__version__)' ;;
        PyJWT)    verify_installed PyJWT jwt "$spec_version" 'import jwt; print(jwt.__version__)' ;;
        kubernetes)
            verify_installed kubernetes kubernetes "$spec_version" \
                'import kubernetes; print(kubernetes.__version__)' ;;
        uvicorn) verify_installed uvicorn uvicorn "$spec_version" 'import uvicorn; print(uvicorn.__version__)' ;;
        cryptography)
            # ADR-130's Ed25519 primitive. Checked by import rather than by metadata because the
            # thing that failed in CI was an import at module level, not a missing distribution:
            # `import cryptography; print(cryptography.__version__)` is the same statement
            # guardian/tests/test_audit_signing.py makes one line after its own imports, so this
            # check fails in exactly the case the suite does.
            verify_installed cryptography cryptography "$spec_version" \
                'import cryptography; print(cryptography.__version__)' ;;
        langgraph)
            verify_installed langgraph langgraph "$spec_version" \
                'import importlib.metadata as m; print(m.version("langgraph"))' ;;
        litellm)
            verify_installed litellm litellm "$spec_version" \
                'import importlib.metadata as m; print(m.version("litellm"))' ;;
        opentelemetry-sdk)
            verify_installed opentelemetry-sdk opentelemetry-sdk "$spec_version" \
                'import importlib.metadata as m; print(m.version("opentelemetry-sdk"))' ;;
        opentelemetry-exporter-otlp-proto-http)
            # Held in a variable only so the three occurrences of a forty-four character
            # distribution name fit the file's width; it is the same literal three times.
            otlp_dist=opentelemetry-exporter-otlp-proto-http
            verify_installed "$otlp_dist" "$otlp_dist" "$spec_version" \
                "import importlib.metadata as m; print(m.version('$otlp_dist'))" ;;
        pandas)  verify_installed pandas pandas "$spec_version" 'import pandas; print(pandas.__version__)' ;;
        statsmodels)
            verify_installed statsmodels statsmodels "$spec_version" \
                'import importlib.metadata as m; print(m.version("statsmodels"))' ;;
        matplotlib)
            verify_installed matplotlib matplotlib "$spec_version" \
                'import matplotlib; print(matplotlib.__version__)' ;;
        *)
            echo "install-runtime-deps: FAIL -- no import check defined for '$spec_name'." >&2
            echo "install-runtime-deps: Add one beside its pin: an install nothing verifies is a pin" >&2
            echo "install-runtime-deps: nothing checks." >&2
            exit 1
            ;;
    esac
    installed_count=$((installed_count + 1))
done

printf 'install-runtime-deps: PASS — %s package(s) at their pinned versions, components:%s (pins from %s)\n' \
    "$installed_count" "$selected" "$versions_file"
exit 0
