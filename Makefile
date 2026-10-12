# Agentic Overwatch -- the single entry point.
#
# The authoritative target contract is docs/04-repo-conventions.md section 3; the stub block
# below mirrors that table row for row, so a reader can diff the two by eye. Behaviour is
# the contract, not the recipe.
#
# WSL2 Ubuntu's /bin/sh is dash, not bash, so recipes must stay POSIX: no [[ ]], no arrays,
# no process substitution, no local. .SHELLFLAGS adds -e so a failing command aborts its
# recipe instead of being swallowed mid-pipeline, and -u so an unset variable is an error
# rather than an empty string.
#
# Every recipe is a one-line delegator to scripts/ or to a single tool invocation. The logic
# lives in scripts/*.sh so it is testable without make: Windows has no make, and the same
# script runs unchanged from Git Bash, from WSL2 and on ubuntu-latest, which is also how CI
# calls it -- directly, without depending on make semantics.
#
# Unimplemented targets are declared rather than omitted. The target list is the contract, so
# a stub that names its owning milestone and exits non-zero is honest; a missing target
# reports "No rule to make target" and tells the caller nothing about when it arrives.

SHELL := /bin/sh
.SHELLFLAGS := -eu -c
.DEFAULT_GOAL := help

.PHONY: help verify-slots versions-sha lint \
        up down nuke status netpol-proof monitor-replay guardian-test agents-golden \
        run baseline campaign analyze parity-check determinism-check audit-verify \
        fidelity-check known-bad-replay readiness-gate campaign-artefacts \
        pilot-p0 pilot-p0-live pilot-p1a pilot-p1b pilot-p2 pilot-p3 pilot-gate pilot-validate

# ---------------------------------------------------------------------------
# Implemented
# ---------------------------------------------------------------------------

help: ## List every target with its description
	@grep -E '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN { FS = ":.*## " } { printf "  %-20s %s\n", $$1, $$2 }'

verify-slots: ## Fail while any unexempted dissertation VERIFY marker remains in a tracked file
	@sh scripts/verify_slots.sh

versions-sha: ## Print the sha256 of infra/versions.env, CRLF normalised to LF before hashing
	@python3 scripts/versions_env_sha256.py infra/versions.env

lint: ## Run ruff check and ruff format --check over the repository
	@sh scripts/lint.sh

# The environment lifecycle, landed at M1-T1.6. Each is a one-line delegator for the reason the
# file header gives: Windows has no make, CI calls the same scripts directly, and the logic has
# to be testable without either. `up` composes the per-layer installers T1.1-T1.3 wrote rather
# than reimplementing them, so each layer is described in exactly one place.
#
# `status` reports over the component set declared in infra/status/components.yaml rather than
# over a list hardcoded in a recipe or a script. docs/protocols/evaluation-protocol.md section 5
# rule 1 makes a green `status` the preflight gate for every run, so a summary that silently
# omitted a component that is not deployed yet would still pass at M7 with the Guardian down.
# The declared set is what keeps the check total at every point in time; M2 and M3 add their own
# rows in their own milestones.
#
# `up` and `status` both read UP_PROFILE (default `full`), which names what the environment can
# supply. `full` is every declared component. `substrate` omits the components whose deployment
# needs operator-supplied material no ephemeral machine has -- today the Guardian alone, whose
# `guardian-signing-key` is supplied out of band and which ADR-114 forbids any repository path
# from creating (ADR-148). The two must always be given the same profile: `up` brings up the
# profile's components and `status` asserts over exactly those, so a mismatch would have `status`
# demand a component `up` was never asked to build. A run's preflight never sets it.
#
# netpol-proof is deliberately NOT part of `up`. It is a test, not a bring-up step: it creates a
# throwaway namespace, denies traffic into it, and asserts the denial is attributable to Cilium's
# policy engine rather than to a crashed pod, a DNS miss or a wrong port (ADR-014). Folding it
# into `up` would make every bring-up pay for a test and would leave `up`'s exit status
# conflating "the environment came up" with "policy enforcement was proved" -- two separate
# Definition-of-done lines that M1 has to satisfy independently.

up: ## Bring the environment up from infra/versions.env on a clean machine (UP_PROFILE=full|substrate)
	@sh scripts/up.sh

down: ## Tear the environment down, leaving volumes intact
	@sh scripts/down.sh

nuke: ## Destroy the environment including volumes (FORCE=1 skips the confirmation)
	@sh scripts/nuke.sh

status: ## Health summary over the declared components (UP_PROFILE=full|substrate)
	@sh scripts/status.sh

netpol-proof: ## Prove NetworkPolicy enforcement: attributable denial, same-node and cross-node
	@sh scripts/netpol_proof.sh

# The Monitor gates, landed at M2-T2.7a. Both need only Python, so neither needs a cluster.
#
# F IS OPTIONAL ON monitor-replay, WHICH IS A CORRECTION RATHER THAN A CONVENIENCE.
# Section 3 used to fix the signature as `F=<fixture>` as though F were required, while
# docs/milestones/M2-monitor.md's Definition of done asks for a replay "over all fixtures" and the
# playbook's verify card for one "against every fixture": as written, no invocation satisfied the
# DoD (conflict M2-C2 in docs/plans/M2-implementation-plan.md). With no F the whole corpus replays;
# with F=<id> one fixture does. F is passed explicitly rather than relied on being exported, so the
# parameter is visible here and both `make monitor-replay F=x` and `F=x make monitor-replay` work.
#
# determinism-check HAS TWO HALVES, AND REPORTS EACH BY NAME.
# The Monitor half: every fixture replayed twice, the emitted streams compared with cmp, which is
# what the prompt-parity iron rule (AGENTS.md 2) and NFR2 require of the aggregator. The scenario
# half, landed at M5: each scenario planned twice per seed with the injected event sequences diffed,
# which is what traceability row T-17 closes against. The target runs both halves and prints a line
# for each, so a green result can never conceal a half that was silently skipped; that is exactly
# what section 3's row promises. Note that the recipe's second line only runs if the first
# succeeded, so green means both halves reported. The scenario half fails closed on an empty corpus
# (conflict M5-C1), so the nightly CI step -- which arms on the first file under the five scenarios/
# content directories -- can never report green over a corpus that proves nothing.

monitor-replay: ## Replay every fixture, assert schema-valid EvidenceEvents (F=<fixture> for one)
	@F='$(F)' sh scripts/monitor_replay.sh

determinism-check: ## Replay twice and diff the bytes: Monitor half and scenario half, one line each
	@sh scripts/monitor_determinism.sh
	@sh scripts/scenario_determinism.sh

# The Guardian policy gate, landed at M3-T3.2. Needs no cluster; `opa test` is an offline run over
# guardian/policies/.
#
# TWO FIGURES, BOTH PRINTED, BECAUSE "100%" IS TWO DIFFERENT CLAIMS.
# docs/milestones/M3-guardian.md's Definition of done states it as "`opa test` 100%", and every test
# passing says nothing about whether any test reached a given rule while full coverage says nothing
# about whether the rules that ran answered correctly. Section 3's row therefore requires the pass
# rate AND a coverage floor, both printed; that is conflict M3-C9, and the script prints both and
# fails on either. The floor is 100 and the script states why.
#
# NO PARAMETER, AND NO INSTALL STEP EITHER.
# Section 3's row fixes this target's signature as taking none, so nothing is passed through here.
# The script acquires the pinned `opa` binary itself, with a checksum check, which is what keeps
# `make guardian-test` self-contained and keeps section 4's job assignment true: the `hygiene` job
# that runs it installs nothing of its own (ADR-025). A developer with the pinned version already on
# PATH pays nothing, and every run's summary line says which of the three paths was taken.
#
# TWO HALVES, EACH REPORTED BY NAME, EXACTLY AS determinism-check DOES.
# The `opa test` half is here now; the adversarial suite under guardian/tests/ is M3-T3.8's, and the
# same suite is separately run by ci.yml's `lint` job, which unlike `hygiene` installs the Guardian's
# runtime dependencies. The script runs whichever halves it can, prints a line for each, and puts
# both states on the one summary line, so a green result can never conceal a half that did not run.

guardian-test: ## opa test over guardian/policies -- pass rate and coverage, both printed -- plus the adversarial suite
	@sh scripts/guardian_test.sh

# The Guardian audit gate, landed at M3-T3.6. Needs only Python, so it needs no cluster either.
#
# P IS OPTIONAL AND DEFAULTS TO runs/, WHICH IS A CORRECTION RATHER THAN A CONVENIENCE.
# Section 3 stated this target as "Guardian hash-chain integrity over runs/" and matrix row T-12
# verifies through it -- but runs/ is gitignored and stays empty until M6 seals the first bundle,
# while M3's Definition of done requires the target to pass now and the playbook's verify card
# already assumes a file-level invocation. As written, no invocation satisfied both: conflict M3-C4
# in docs/plans/M3-implementation-plan.md, settled by ADR-022's Consequences. With no P the default
# runs/ is walked and, being empty today, fails loudly rather than passing over nothing; with
# P=<path> a directory is walked for every guardian_audit.jsonl under it, or one file is verified.
#
# HEAD IS THE ANCHOR, AND WITHOUT IT THE GATE SAYS WHAT IT DID NOT CHECK.
# An unsigned hash chain detects mutation, deletion, insertion and reordering on its own; it does
# not detect tail truncation or a whole-chain rewrite, because an attacker who can write the file
# recomputes every hash forward from the cut. data-management.md section 1 puts the chain head in
# seal.json, HEAD is that value, and the script finds a sibling seal.json by itself when there is
# one. Every summary line states whether the run was anchored, so an unanchored pass can never be
# read as evidence of a property the chain does not have (ADR-022).
#
# Both are passed explicitly rather than relied on being exported, exactly as monitor-replay passes
# F, so the parameters are visible here and both `make audit-verify P=x` and `P=x make
# audit-verify` work. The replay half of row T-12 is `sh scripts/audit_verify.sh <path> --replay`;
# it is not a third make variable, because section 3's row fixes this target's parameters as P and
# HEAD and the Makefile mirrors that table row for row.

audit-verify: ## Guardian hash-chain integrity over P=<path>, default runs/; HEAD=<sha256> anchor
	@P='$(P)' HEAD='$(HEAD)' sh scripts/audit_verify.sh

# The agent-layer gates, landed at M4. Both are one-line delegators for the reason the file header
# gives, and both are placed here in the order section 3's table gives them: agents-golden, then
# parity-check.
#
# NO PARAMETER ON EITHER, AND THAT IS THE CONTRACT RATHER THAN AN OMISSION.
# Section 3's rows fix both signatures as taking none. Where monitor-replay carries F and
# audit-verify carries P and HEAD, these carry nothing, so nothing is passed through here; the
# Makefile mirrors that table row for row, and a parameter added here would be a second, quieter
# contract beside it.
#
# parity-check IS CI-BLOCKING AND FAILS CLOSED ON AN EMPTY REGISTRY.
# ci.yml's guardrail-grep job runs it the moment any file is tracked under agents/prompts/, so a red
# result here is a red pull request. That makes the vacuous-pass question load-bearing, and the
# answer is the opposite of scripts/grep_guard.sh's. A grep guard may pass over nothing, because
# nothing found genuinely is nothing violated -- the claim it makes is negative. Parity's claim is
# positive: it asserts that three conditions draw the same shared blocks, the same tool registry and
# comparable token budgets. Over an absent or empty registry there is nothing to compare, and a
# green check there would make deleting agents/prompts/ the cheapest way to pass the gate that
# exists to stop the arms diverging. The script therefore exits non-zero when the registry it reads
# holds no composition, and says so rather than reporting success over nothing (ADR-028).
#
# It also EMITS THE PER-CONDITION TOKEN TABLE the pull request carries: prompt tokens, tool calls
# and turns per condition, counted with the reference tokenizer PARITY_TOKENIZER pins in
# infra/versions.env, so the number in review is the number CI computed and both reproduce offline
# from a clean checkout with no provider credential.
#
# agents-golden RUNS S1-HIER x G0-FULL AND NOTHING ELSE.
# One arm, one guardrail configuration, no sweep: the golden path is a proof that the framework
# traverses all four phases end to end, not a miniature campaign. The G1-LOGONLY and G3-UNQUOTED
# exercises M4's Definition of done also requires are pytest cases under agents/tests/, deliberately
# not a parameter on this target -- ADR-023 puts every condition flag in the runner's hands and
# forbids anything under agents/ from reaching one, so a MODE= variable here would be exactly the
# reach the rule refuses, and section 3's no-parameter row already says the same thing from the
# other side.

agents-golden: ## Golden-path scenario end to end on the dev model tier
	@sh scripts/agents_golden.sh

parity-check: ## Prompt and tool parity per prompt-parity-policy (CI-blocking from M4)
	@sh scripts/parity_check.sh

# ---------------------------------------------------------------------------
# Stubs -- declared now, implemented in the milestone named in brackets.
# Order follows docs/04-repo-conventions.md section 3. Everything from that table implemented so
# far sits above: help, verify-slots, versions-sha and lint from M0; up, down, nuke, status and
# netpol-proof from M1-T1.6; monitor-replay and the Monitor half of determinism-check from
# M2-T2.7a; guardian-test from M3-T3.2 and audit-verify from M3-T3.6; agents-golden and
# parity-check from M4-T4.7 and M4-T4.6.
# ---------------------------------------------------------------------------

# run and baseline are two targets, not one target with a mode flag. A grid run is addressed
# by exactly the four coordinates the run ID carries -- arm, scenario, injection condition,
# seed (docs/07-glossary-and-ids.md) -- which is what makes the identifier and the manifest
# checkable against each other field for field. A baseline is framework-off: it occupies no
# arm, no scenario and no injection condition, and is addressed by load profile and seed
# instead. Folding both into `run` would make every parameter conditional on a BASELINE flag,
# so neither invocation could be stated completely in one `## ` line and neither could be
# validated without first reading the flag. Two targets keep each parameter set total, and
# mirror the split the identifier form and the manifest's is_baseline field already draw.

run: ## One grid run to a sealed bundle in runs/ (COND=<id> SCN=<id> INJ=<id> SEED=<n> CAMP=<id> OFFLINE=1 DURATION=<s> SAMPLES=<n> INSTRUMENT_ONLY=1)
	@COND='$(COND)' SCN='$(SCN)' INJ='$(INJ)' SEED='$(SEED)' CAMP='$(CAMP)' \
	 OFFLINE='$(OFFLINE)' DURATION='$(DURATION)' SAMPLES='$(SAMPLES)' \
	 INSTRUMENT_ONLY='$(INSTRUMENT_ONLY)' sh scripts/run.sh

baseline: ## One framework-off baseline run to a sealed bundle in runs/ (LOAD=<id> SEED=<n> CAMP=<id>)
	@LOAD='$(LOAD)' SEED='$(SEED)' CAMP='$(CAMP)' sh scripts/baseline.sh

campaign: ## Validate, order and drive the interleaved grid (M=<campaign-manifest> SAMPLES=<n>|DURATION=<s>)
	@M='$(M)' sh scripts/campaign.sh

analyze: ## Regenerate every metric and figure from raw run bundles only (C=<campaign>)
	@if [ -n '$(C)' ]; then C= sh scripts/analyze.sh --campaign '$(C)'; else sh scripts/analyze.sh; fi

# ---------------------------------------------------------------------------
# M10 remediation gates (ADR-120, ADR-133, ADR-135, ADR-136). Each is a one-line delegator to a
# scripts/*.sh wrapper, for the reason the file header gives: the logic lives in the script (and, below
# it, in runner/fidelity, runner/pilot_cli and analysis/render), so every gate is testable and runnable
# without make, and CI calls the same script directly. The fidelity, pilot and readiness LOGIC is not
# here and must not move here; these recipes only forward the caller's parameters, exactly as `run`,
# `baseline` and `audit-verify` above do.
#
# The pilot targets are one per ladder stage (M10 plan §6) rather than one target with a MODE flag, on
# the same argument the run/baseline split above makes: each stage's exit criterion is its own, and a
# stage recorded out of order is refused by runner/pilot_cli. pilot-gate is the `decide` step under the
# name the freeze checklist reads. STATE_DIR defaults to runs/_pilot inside the wrapper; FREEZE_TAG,
# NO_FREEZE, FIDELITY (plus FIDELITY2..FIDELITY5, the pilot's further campaign dirs, folded by the
# gate) and FRAMEWORK_FAILURES are passed through when set.

fidelity-check: ## Synthetic treatment-fidelity check, no cluster (CORPUS=<dir> STAGE=<stage> KNOWN_BAD=1)
	@CORPUS='$(CORPUS)' STAGE='$(STAGE)' KNOWN_BAD='$(KNOWN_BAD)' sh scripts/fidelity_check.sh

known-bad-replay: ## Known-bad replay over the v1 corpus, skips if absent (CAMPAIGN=<dir> to override)
	@CAMPAIGN='$(CAMPAIGN)' sh scripts/known_bad_replay.sh

readiness-gate: ## Analysis readiness gate F-AN-01 (C=<campaign> STAGE=pilot|checkpoint|final)
	@C='$(C)' STAGE='$(STAGE)' sh scripts/readiness_gate.sh

campaign-artefacts: ## Write the WS-6 campaign-level fidelity artefacts (C=<campaign> C2..C5=)
	@C='$(C)' C2='$(C2)' C3='$(C3)' C4='$(C4)' C5='$(C5)' sh scripts/campaign_artefacts.sh

pilot-p0: ## Record pilot ladder stage p0 (STATE_DIR= FREEZE_TAG= NO_FREEZE=1)
	@STATE_DIR='$(STATE_DIR)' FREEZE_TAG='$(FREEZE_TAG)' NO_FREEZE='$(NO_FREEZE)' sh scripts/pilot.sh p0

pilot-p0-live: ## Record pilot ladder stage p0-live (STATE_DIR= FREEZE_TAG= NO_FREEZE=1)
	@STATE_DIR='$(STATE_DIR)' FREEZE_TAG='$(FREEZE_TAG)' NO_FREEZE='$(NO_FREEZE)' sh scripts/pilot.sh p0-live

pilot-p1a: ## Record pilot ladder stage p1a (STATE_DIR= FREEZE_TAG= NO_FREEZE=1)
	@STATE_DIR='$(STATE_DIR)' FREEZE_TAG='$(FREEZE_TAG)' NO_FREEZE='$(NO_FREEZE)' sh scripts/pilot.sh p1a

pilot-p1b: ## Record pilot ladder stage p1b (STATE_DIR= FREEZE_TAG= NO_FREEZE=1)
	@STATE_DIR='$(STATE_DIR)' FREEZE_TAG='$(FREEZE_TAG)' NO_FREEZE='$(NO_FREEZE)' sh scripts/pilot.sh p1b

pilot-p2: ## Record pilot ladder stage p2 (STATE_DIR= FREEZE_TAG= NO_FREEZE=1)
	@STATE_DIR='$(STATE_DIR)' FREEZE_TAG='$(FREEZE_TAG)' NO_FREEZE='$(NO_FREEZE)' sh scripts/pilot.sh p2

pilot-p3: ## Record pilot ladder stage p3 (STATE_DIR= FREEZE_TAG= NO_FREEZE=1)
	@STATE_DIR='$(STATE_DIR)' FREEZE_TAG='$(FREEZE_TAG)' NO_FREEZE='$(NO_FREEZE)' sh scripts/pilot.sh p3

pilot-gate: ## Write gate_decision.json from fidelity results (FIDELITY=<path> FIDELITY2..5=; STATE_DIR=)
	@STATE_DIR='$(STATE_DIR)' FIDELITY='$(FIDELITY)' FIDELITY2='$(FIDELITY2)' FIDELITY3='$(FIDELITY3)' \
	 FIDELITY4='$(FIDELITY4)' FIDELITY5='$(FIDELITY5)' FRAMEWORK_FAILURES='$(FRAMEWORK_FAILURES)' \
	 sh scripts/pilot.sh gate

pilot-validate: ## Validate a pilot manifest (MANIFEST=<path> required; KIND=cost|smoke|coverage BUNDLE=)
	@MANIFEST='$(MANIFEST)' KIND='$(KIND)' BUNDLE='$(BUNDLE)' sh scripts/pilot.sh validate
