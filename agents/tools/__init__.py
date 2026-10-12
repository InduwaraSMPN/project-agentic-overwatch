r"""The tool registry and the Guardian clients -- the only path from the agent layer to the cluster.

WHAT THIS PACKAGE IS
--------------------
Two things, and keeping them in one package is deliberate.

:mod:`agents.tools.registry` is the **single tool registry**
``docs/protocols/prompt-parity-policy.md`` section 2 rule 3 requires: "``agents/tools/``
definitions (names, schemas, descriptions) are identical across conditions; the registry hash goes
into every bundle manifest." One module, no condition parameter anywhere in it, and no
per-condition variant. What differs between the three topologies is **which node holds which
entry**, which a composition manifest declares and which
:func:`agents.registry.digest.tool_registry_digest` is computed over.

:mod:`agents.tools.guardian_client` is the client every one of those tools calls. It is the whole
of ``.agents/rules/10-guardian-first.md``'s "only mutation path": nothing under ``agents/`` imports
a Kubernetes client, shells out to the Kubernetes command-line client, or opens a connection to the
cluster API, and ``scripts/grep_guard.sh`` scans every tracked file here -- prose included, with no
exemption mechanism -- to keep that true. One direct client call under ``agents/`` would silently
void the guarantee for the whole study: the mediated arm would no longer be mediated, and the
security results would describe a system that is not the one built.

WHY THERE IS NO G2-SHAREDCRED TOOL, AND WHY THERE NEVER WILL BE ONE HERE
-------------------------------------------------------------------------
``G2-SHAREDCRED`` gives agents their own scoped ServiceAccounts and opens the NetworkPolicy, and the
obvious way to let an agent *use* that would be a second tool. Parity section 2 rule 3 forbids it
outright -- the definitions are identical across conditions -- and ADR-024 records why the two naive
answers both fail: a G2-only tool makes the arms differ in their tool registry, which is the
confound the whole ablation excludes, and a Guardian-owned forced transport measures use by
construction rather than by discovery. M3-C7 narrowed the question and did not close it; if it is
still open it is a supervisor question rather than an implementation detail, and this package's
silence on it is the correct state rather than an omission.

WHAT IS DELIBERATELY NOT HERE
------------------------------
*Prompt text.* A tool's documentation is text a model reads, so it is prompt text and lives in
``agents/prompts/blocks/tool.<name>.md`` like every other block, referenced from a composition
manifest and counted by ``make parity-check``. This package holds a tool's **name**, its parameter
**schema**, and the **id** of its documentation block -- structure, never prose.
``scripts/prompt_purity_grep.sh`` and ``agents/tests/test_prompt_purity.py`` check that from the
other side.

*A retry that hides a denial.* ``guardian/app/main.py`` answers HTTP 200 with an ``ActionResult``
for **every** outcome it reached a decision on, denial included, and a non-2xx means it reached no
decision. A client that treated non-2xx as the failure signal would read every denial as a
transport error and retry it, doubling a row in the audit chain for a reason nobody would find. The
client below is written to that contract and says so.
"""
