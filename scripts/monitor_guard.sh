#!/bin/sh
# monitor_guard.sh — machine enforcement of the monitor-non-LLM iron rule (AGENTS.md 7) (rule 40).
#
# WHAT RULE 40 SAYS
# The Monitor is deterministic and non-LLM. docs/02-architecture.md section 1 types it that way in
# the roles table; FR1.4 in docs/01-requirements.md requires the property end to end; ADR-007 chose
# Falco over a model-based triage step precisely so that triage costs zero inference; and
# monitor/README.md repeats it for whoever arrives at the component before they arrive at the
# architecture. What none of those four documents can do is fail. This script is the layer that
# fails. One inference call under monitor/ would not merely add a dependency: it would move the
# Monitor from the trusted, deterministic side of the trust boundary to the untrusted side, make
# its output unreplayable, and leave the dissertation claiming a zero-token triage layer that the
# artefact does not implement. The claim and the artefact have to be checkable against each other,
# and this is the cheapest of the three checks that make them so.
#
# WHY THIS GUARD DOES NOT MATCH THE BARE TOKENS `LLM` OR `model`, AND MUST NOT BE "FIXED" TO DO SO
# scripts/grep_guard.sh — this script's counterpart for rule 10 — resolves its own false-positive
# pressure with a rule stated in its header: the prose moves, not the check. That is why
# agents/README.md describes the Kubernetes command-line client without ever naming the binary. One
# sentence reworded, and the guard stays honest about everything it has actually read.
#
# That resolution is unavailable here, and the difference is one of kind rather than degree. Rule
# 10's forbidden token is the name of a tool that code under agents/ has no business naming at all,
# so silence costs a footnote. Rule 40's subject is the name of the constraint itself.
# monitor/README.md has to be able to say that this layer is non-LLM. So does every docstring in the
# aggregator that explains why a field is computed the way it is, every ADR that records why Falco
# was chosen over a model in the loop, the milestone file, the implementation plan, and the
# traceability row that claims the property. A guard matching the bare token `LLM`, or the even
# broader `model`, would fire on every one of those, and would therefore be a check whose hits were
# all false from its very first run. The predictable responses are all worse than the disease: a
# growing allowlist, a file-class filter that silently drops whole classes of file from the scan, or
# — worst — quietly deleting the word from the documentation that states the invariant, leaving the
# repository unable to write down its own architecture in order to keep a grep quiet. That is the
# check corrupting the artefact instead of protecting it.
#
# So the inversion is deliberate: the design moves, not the prose. Every pattern in block (a) below
# is scoped to a construct that *executes* — an import statement, a dotted attribute access on a
# client module, an HTTP route or a provider host, an environment variable naming a provider
# credential or a model pin, and the handful of method chains that actually send a prompt.
# Documentation under monitor/ can then describe the constraint in full, name it by name, quote the
# SDKs it excludes in prose, and never trip a single pattern. The sentence "This layer is non-LLM by
# design." in monitor/README.md is the worked example, and this script is verified against it.
#
# The price of the inversion is that this guard is narrower than a token grep and can be walked
# around by someone determined to walk around it: an obfuscated import, a URL assembled from
# fragments at run time, a client loaded through importlib. That is not a gap left open by
# oversight — it is the reason rule 40 names three enforcement layers and not one. The socket-denial
# replay in monitor/tests/test_no_inference.py catches the dynamically loaded client that no grep
# can see, and the dependency-surface assertion in the same file catches the SDK that arrives in a
# pin nobody reads. This script is the fast, cheap, first layer, and its header says so rather than
# letting a green run be mistaken for a proof.
#
# WHY BLOCK (a) IS SEVEN PATTERN FAMILIES AND NOT ONE
# The first family is the literal rule: an import of a provider SDK, an inference framework, or a
# local model runtime. The second is the same defence in depth grep_guard.sh uses against
# `import kubernetes as k8s` — an import aliased once at the top of a module leaves no later line
# naming the library, so the guard also looks for the dotted attribute access every call site must
# make regardless of how the import was spelled. The third names the wire: provider hosts and the
# request paths of the OpenAI-compatible, Anthropic and Ollama routes, which is what an inference
# call looks like when it is made with a plain HTTP client and no SDK at all, and what a locally
# hosted model looks like when its host name is an unremarkable private address. The fourth names
# the configuration such code needs before it can run — provider credential variables, and this
# repository's own model-pin names from infra/versions.env, because reading a model pin under
# monitor/ has no innocent explanation. The fifth names the call shapes themselves, for the case
# where the client object arrives from somewhere the first four families did not see it built. The
# sixth closes the process boundary: importing Python's process-launch modules or calling their
# launch surfaces can hand the prompt to a provider CLI and bypass every in-process SDK pattern. The
# seventh names provider executables at that boundary, catching non-Python shell and script routes as
# well as Python argv. Between them they cover the import site, the call site, the wire, the
# configuration and the process boundary — every point at which an inference call has to become
# concrete.
#
# BLOCK (b) IS A TRIPWIRE. IT IS NOT THE PROOF OF DETERMINISM.
# The aggregator's determinism obligation is rule 20's, and the proof of it is a byte-level
# twice-and-diff over every fixture — `make determinism-check`, with
# monitor/tests/test_determinism.py beneath it. That diff is the guarantee. Block (b) greps for the
# four constructs that most commonly break it — a generated UUID, a wall-clock read, an unseeded
# random draw, and direct socket use — so that the mistake is named at the moment it is written
# rather than at the moment a replay diverges, which may be a milestone later and in a stack the
# diff does not point at. A green block (b) means nobody wrote the four obvious mistakes. It does
# not mean the aggregator is deterministic, it cannot mean that, and no wording here should be
# allowed to drift into implying that it does.
#
# Block (b)'s scope is monitor/aggregator/** and therefore contains code and no documentation, so
# rule 10's resolution is available here even though it is not available in block (a): a docstring
# that needs to explain why the aggregator never reads the wall clock can say so without writing the
# call, and should. That asymmetry between the two blocks is the whole reason they are two blocks
# with two scopes rather than one scan with a merged pattern list.
#
# THERE IS DELIBERATELY NO EXEMPTION MECHANISM
# No allowlist file, no inline `# noqa`-style sentinel, no per-path skip, and — in block (a) — no
# file-class filter: every tracked file under monitor/ is scanned, whatever its extension, prose
# included. The reasoning is rule 10's, unchanged. An exemption mechanism added before the first
# true positive is an exemption mechanism sized to convenience rather than to risk, and a
# file-class filter is that same hole under a tidier name, because it drops whole classes of file
# from the scan without ever reporting what it dropped. If M2 or a later milestone produces a
# genuine false positive, that is a decision about how the guardrail is scoped and worded, taken at
# the milestone that produced the evidence and recorded in an ADR with its alternatives. It is not a
# hole punched at M2 against false positives nobody has seen yet.
#
# SCOPE AND EXIT CODES
# Tracked files only (git ls-files), so an untracked local scratch file cannot fail CI and the check
# sees exactly what a fresh clone contains. Each block reports independently, so a failure names
# which invariant broke rather than leaving the reader to infer it from the pattern tag. Exit 0 on a
# clean scan or a vacuous pass — vacuous meaning the block's scope is absent, or holds no tracked
# files at all — exit 1 on any hit in either block. Strict POSIX sh, GNU-ERE patterns (`\b` and
# `\w`, the dialect grep_guard.sh already established): this runs under dash on WSL2 Ubuntu, under
# Git Bash on Windows, and on ubuntu-latest.

set -eu

# Byte-exact matching, and it stops grep from declaring a UTF-8 file binary because its bytes do not
# decode under whatever locale the caller happens to have set.
LC_ALL=C
export LC_ALL

# Repo root derived from this script's own location, so behaviour is identical whether the script is
# invoked by make, by CI, or by hand from an arbitrary working directory.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

# Patterns are spelled exactly once, here, and the failure report below prints these same variables.
# grep_guard.sh spells its patterns twice — once to scan, once to report — which is a drift risk
# this script declines to inherit: a pattern tightened in one place and not the other would
# produce a failure message that does not describe the check that failed.

# (a1) Provider SDKs, inference frameworks and local model runtimes, in an import statement. The
#      anchored (import|from) prefix is what keeps this family call-shaped: prose naming any of
#      these libraries does not match, an import of one does.
PAT_SDK_IMPORT='^[[:space:]]*(import|from)[[:space:]]+(openai|anthropic|litellm|langchain\w*|langgraph|mistralai|groq|cohere|ollama|transformers|vllm|huggingface_hub)\b'
# (a2) Aliased-import defence: the dotted attribute access every call site must make even when the
#      import was renamed out of sight. Restricted to the five libraries whose module name is
#      distinctive enough that a dotted access to it cannot be anything else.
PAT_SDK_ALIAS='\b(openai|anthropic|litellm|langgraph|langchain)\.[A-Za-z_]'
# (a3) The wire: provider hosts, and the request paths of the OpenAI-compatible, Anthropic and
#      Ollama routes. The paths matter more than the hosts, because a self-hosted or proxied model
#      keeps the route and loses the recognisable host name.
PAT_ENDPOINT='api\.(openai|anthropic|groq)\.com|api\.mistral\.ai|api\.cohere\.(ai|com)|generativelanguage\.googleapis\.com|/v1/chat/completions|/v1/(messages|completions|embeddings)\b|/api/generate\b'
# (a4) Configuration such code needs before it can run: provider credential variables, provider base
#      URLs, and this repository's own model-pin names from infra/versions.env. Names only — no
#      credential value appears in this repository, and none should ever appear in this pattern.
PAT_CREDENTIAL='\b(OPENAI|ANTHROPIC|MISTRAL|GROQ|COHERE|HUGGINGFACE|HUGGINGFACEHUB|AZURE_OPENAI)_API_KEY\b|\bLITELLM_[A-Z_]+|\bMODEL_ALIAS\b|\bMODEL_PROVIDER_STRING\b|\bANTHROPIC_BASE_URL\b|\bOPENAI_(API_)?BASE\b|\bOLLAMA_HOST\b'
# (a5) The call shapes themselves, for the case where the client object arrived from somewhere the
#      first four families did not watch it being built.
PAT_CALL_SHAPE='\bchat\.completions\.create\b|\bmessages\.(create|stream)\b|\bChatCompletion\b|\bgenerate_content\b'
# (a6) Process-launch routes. A provider CLI is still inference even when no SDK enters this
#      interpreter, and Python offers two standard doors to it. A subprocess import is itself the
#      capability; for the general-purpose os module, only launch-member imports and dotted launch
#      calls match, so an innocent `os.path` use remains possible. The Monitor has no legitimate
#      child-process responsibility.
PAT_PROCESS_EXEC='^[[:space:]]*(import[[:space:]]+subprocess\b|from[[:space:]]+subprocess[[:space:]]+import\b|from[[:space:]]+os[[:space:]]+import[[:space:]]+[^#]*(system|popen|spawn[a-z0-9_]*|exec[a-z0-9_]*))|\bsubprocess\.(run|call|check_call|check_output|Popen|getoutput|getstatusoutput)\b|\bos\.(system|popen|spawn[a-z0-9_]*|exec[a-z0-9_]*)\b'
# (a7) Provider CLI executables in shell-command position. The command-position anchor prevents prose
#      and test data that merely name a provider from firing while catching direct shell routes that
#      never name Python's process APIs. `llama-cli` and `ollama` cover local runtimes too.
PAT_PROVIDER_CLI='^[[:space:]]*(exec[[:space:]]+)?(openai|anthropic|claude|mistral|groq|cohere|gemini|ollama|llama-cli)([[:space:]]|$)|[;&|][[:space:]]*(openai|anthropic|claude|mistral|groq|cohere|gemini|ollama|llama-cli)([[:space:]]|$)'

# (b1) Generated identifiers. event_id is a sha256 over a canonical projection of the source event,
#      never a fresh UUID, so any uuid/uuid1/uuid4 under the aggregator is the wrong construct.
PAT_NONDET_ID='\buuid[0-9]*\b'
# (b2) Wall-clock reads. ts comes from the source event's own timestamp in the fixture; a clock read
#      makes the twice-and-diff unpassable. Latency figures belong in latency.json, which is not
#      diffed.
PAT_WALL_CLOCK='\b(datetime|date|dt)\.(now|utcnow|today)\b|\butcnow\b|\btime\.(time|time_ns|monotonic|perf_counter)\b'
# (b3) Unseeded randomness. Rule 20 allows a generator seeded once at entry from the run manifest;
#      it does not allow the module-level functions, which is what this matches.
PAT_UNSEEDED_RANDOM='\brandom\.[A-Za-z_]'
# (b4) Direct socket use. The aggregator reads fixtures and writes events; it opens no connection of
#      its own. This is also the construct the socket-denial replay in test_no_inference.py exists
#      to trap at run time, so a hit here is an early warning for that test as well.
PAT_DIRECT_SOCKET='\bsocket\.[A-Za-z_]|^[[:space:]]*(import|from)[[:space:]]+socket\b'

# list_tracked <output-file> <pathspec>
# Writes one tracked path per line into <output-file> and leaves the count in $lt_count. `tr` is the
# POSIX-portable way to consume -z output; `read -d ''` is a bashism. The only case in which that
# conversion is ambiguous is a tracked path containing a literal newline, so the two encodings are
# compared and the assumption proved rather than assumed: git quotes such a path on the non-z path,
# which collapses it to one line, so the counts diverge exactly when the assumption breaks. This is
# a function rather than an inline block only because two scopes need it; it deliberately sets a
# global instead of echoing its result, because `exit 1` inside a command substitution would exit
# the subshell and let the caller carry on scanning.
lt_count=0
list_tracked() {
    lt_out=$1
    lt_spec=$2
    git ls-files -z -- "$lt_spec" | tr '\0' '\n' > "$lt_out"
    lt_count=$(wc -l < "$lt_out" | tr -d ' ')
    lt_plain=$(git ls-files -- "$lt_spec" | wc -l | tr -d ' ')
    if [ "$lt_count" != "$lt_plain" ]; then
        printf 'monitor-guard: refusing to run — a tracked path under %s contains a newline\n' \
            "$lt_spec" >&2
        exit 1
    fi
}

# scan <pattern-name> <extended-regex>
# Appends one line per hit, formatted path:line: <matching line>, tagged with the pattern that
# fired. Reads two globals set by the caller before each block — SCAN_LIST, the file list to walk,
# and SCAN_HITS, the file to append to — which keeps the call shape identical to grep_guard.sh's
# two-argument `scan <name> <regex>` while letting one helper serve two blocks with two scopes.
# -I skips binary files; -E is required because the patterns are extended regexes.
SCAN_LIST=""
SCAN_HITS=""
scan() {
    scan_name=$1
    scan_pattern=$2
    while IFS= read -r scan_file; do
        [ -n "$scan_file" ] || continue
        grep -nEI -e "$scan_pattern" -- "$scan_file" | while IFS= read -r scan_hit; do
            scan_lineno=${scan_hit%%:*}
            scan_text=${scan_hit#*:}
            printf '%s:%s: %s   <-- [%s]\n' \
                "$scan_file" "$scan_lineno" "$scan_text" "$scan_name"
        done >> "$SCAN_HITS"
    done < "$SCAN_LIST"
}

# --- block (a): the non-LLM boundary, over every tracked file under monitor/ ----------------------
# monitor/ is populated at M2 but already holds a tracked README, so the vacuous branches below are
# not the state this repository is in today. They are kept because a guard that reports "absent" and
# a guard that reports "scanned nothing" have to be distinguishable in a log: an all-clear over
# nothing is otherwise byte-identical to an all-clear over everything.
hits_a="$work/hits_a"
: > "$hits_a"
files_a="$work/files_a"

if [ ! -d monitor ]; then
    state_a="vacuous — monitor/ absent (pre-M2)"
    count_a=0
else
    list_tracked "$files_a" 'monitor/*'
    count_a=$lt_count
    if [ "$count_a" -eq 0 ]; then
        state_a="vacuous — monitor/ absent-or-empty: present but holding no tracked files (pre-M2)"
    else
        state_a="scanned $count_a tracked file(s) under monitor/ against 7 pattern families"
        SCAN_LIST=$files_a
        SCAN_HITS=$hits_a
        scan llm-sdk-import      "$PAT_SDK_IMPORT"
        scan llm-sdk-alias       "$PAT_SDK_ALIAS"
        scan inference-endpoint  "$PAT_ENDPOINT"
        scan provider-credential "$PAT_CREDENTIAL"
        scan inference-call      "$PAT_CALL_SHAPE"
        scan process-execution   "$PAT_PROCESS_EXEC"
        scan provider-cli        "$PAT_PROVIDER_CLI"
    fi
fi

# --- block (b): the determinism tripwire, over tracked files under monitor/aggregator/ ------------
# The aggregator lands at T2.1. Until then this block is a vacuous pass and says so, for the reason
# block (a)'s comment gives: silence and cleanliness must not print the same line.
hits_b="$work/hits_b"
: > "$hits_b"
files_b="$work/files_b"

if [ ! -d monitor/aggregator ]; then
    state_b="vacuous — monitor/aggregator/ absent (pre-T2.1)"
    count_b=0
else
    list_tracked "$files_b" 'monitor/aggregator/*'
    count_b=$lt_count
    if [ "$count_b" -eq 0 ]; then
        state_b="vacuous — monitor/aggregator/ absent-or-empty: present but holding no tracked files (pre-T2.1)"
    else
        state_b="scanned $count_b tracked file(s) under monitor/aggregator/ against 4 pattern families"
        SCAN_LIST=$files_b
        SCAN_HITS=$hits_b
        scan nondeterministic-id "$PAT_NONDET_ID"
        scan wall-clock          "$PAT_WALL_CLOCK"
        scan unseeded-random     "$PAT_UNSEEDED_RANDOM"
        scan direct-socket       "$PAT_DIRECT_SOCKET"
    fi
fi

hit_count_a=$(wc -l < "$hits_a" | tr -d ' ')
hit_count_b=$(wc -l < "$hits_b" | tr -d ' ')
hit_total=$((hit_count_a + hit_count_b))

if [ "$hit_total" -gt 0 ]; then
    {
        printf 'monitor-guard: FAIL — the monitor-non-LLM iron rule (AGENTS.md 7) violated (%s hit(s))\n' \
            "$hit_total"
        printf '  block (a) non-LLM boundary:    %s hit(s)\n' "$hit_count_a"
        printf '  block (b) determinism tripwire: %s hit(s)\n' "$hit_count_b"
    } >&2
    if [ "$hit_count_a" -gt 0 ]; then
        {
            echo
            echo "BLOCK (a) — non-LLM boundary, tracked files under monitor/"
            cat "$hits_a"
            echo
            echo "Patterns:"
            printf '  llm-sdk-import       %s\n' "$PAT_SDK_IMPORT"
            printf '  llm-sdk-alias        %s\n' "$PAT_SDK_ALIAS"
            printf '  inference-endpoint   %s\n' "$PAT_ENDPOINT"
            printf '  provider-credential  %s\n' "$PAT_CREDENTIAL"
            printf '  inference-call       %s\n' "$PAT_CALL_SHAPE"
            printf '  process-execution    %s\n' "$PAT_PROCESS_EXEC"
            printf '  provider-cli         %s\n' "$PAT_PROVIDER_CLI"
            echo
            echo "Fix the code: the Monitor is non-LLM by architecture (02-architecture.md"
            echo "section 1, FR1.4) and triage costs zero inference by decision (ADR-007). Every"
            echo "pattern above is scoped to a construct that executes, so prose describing the"
            echo "constraint does not match and never needs rewording. There is no exemption"
            echo "mechanism by design — see this script's header."
        } >&2
    fi
    if [ "$hit_count_b" -gt 0 ]; then
        {
            echo
            echo "BLOCK (b) — determinism tripwire, tracked files under monitor/aggregator/"
            cat "$hits_b"
            echo
            echo "Patterns:"
            printf '  nondeterministic-id  %s\n' "$PAT_NONDET_ID"
            printf '  wall-clock           %s\n' "$PAT_WALL_CLOCK"
            printf '  unseeded-random      %s\n' "$PAT_UNSEEDED_RANDOM"
            printf '  direct-socket        %s\n' "$PAT_DIRECT_SOCKET"
            echo
            echo "This block is a tripwire, not the proof: the byte-level twice-and-diff over every"
            echo "fixture is what establishes determinism, and this grep only names the four common"
            echo "mistakes early. Replace the construct with the deterministic source the M2 plan"
            echo "specifies — source timestamp, sha256 event_id, seeded generator, no socket — per"
            echo "the prompt-parity iron rule (AGENTS.md 2)."
        } >&2
    fi
    exit 1
fi

printf 'monitor-guard: PASS — block (a) non-LLM boundary: %s; block (b) determinism tripwire: %s; no hits\n' \
    "$state_a" "$state_b"
exit 0
