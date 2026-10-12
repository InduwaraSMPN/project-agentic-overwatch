#!/bin/sh
# prompt_purity_grep.sh — machine enforcement of the prompt-parity iron rule (AGENTS.md 2)'s
# first bullet: "Prompts exist only in agents/prompts/ registry files; code composes, never
# contains, prompt text."
#
# WHY THIS GUARD EXISTS AT ALL
# Until M4 that rule was an instruction and no check. docs/prompts-playbook.md's M4-verify card asks
# the assistant to "grep agents/ for prompt string literals" — a manual grep the milestone after can
# forget, and one that produces no artefact when it passes. scripts/policy_purity_grep.sh already
# set the precedent one component over: no arm or mode token under guardian/policies/, run by CI on
# every pull request rather than by hand once. This is the same shape for the agent layer, and it
# joins grep_guard.sh and monitor_guard.sh in ci.yml's guardrail-grep job.
#
# The stakes are the parity claim itself. docs/protocols/prompt-parity-policy.md section 3 asserts
# an equality over the composed registry; a prompt literal in a graph or a tool module is guidance
# that no composition manifest lists, that make parity-check therefore never counts, and that could
# differ between two conditions without any gate noticing. One inlined sentence in a node function
# and NFR3's "parity by construction" becomes parity by inspection.
#
# ALWAYS RUNS, AND CARRIES NO hashFiles() GUARD
# The script handles its own pre-M4 vacuous pass, so there is no workflow guard to go stale — and a
# guard would in any case be wrong here, for the reason monitor_guard.sh records for itself: a
# boundary is enforced from before the first line of code it governs exists.
#
# THREE BLOCKS, THREE DIFFERENT CLAIMS
#
#   (a) NO PROMPT-SHAPED LITERAL under agents/graphs/ and agents/tools/.
#       The scope is deliberately those two directories and not all of agents/. agents/registry/ is
#       the composer, the renderer and the gate; agents/tests/ has to be able to write a fixture
#       block and assert on it; agents/prompts/ IS the prompt text. Widening the scope would make
#       every one of those a hit, and a check whose hits are all false from its first run is a check
#       nobody reads — monitor_guard.sh's header argues that at length and this script inherits the
#       argument rather than relearning it.
#
#       Every pattern is scoped to a CONSTRUCT rather than to a word, which is monitor_guard.sh's
#       inversion applied here: "the design moves, not the prose". A docstring explaining why a node
#       takes a rendered prompt rather than composing one is documentation and must not trip a
#       guard; an assignment of a long English string to a variable is the defect. So the patterns
#       match assignment, keyword argument and collection-element positions, never bare words.
#
#       This block is narrower than an English-detector and can be walked around — a prompt built by
#       concatenating short fragments, a sentence assembled at run time. That is not an oversight:
#       agents/tests/test_prompt_purity.py walks agents/graphs/ and agents/tools/ with the `ast`
#       module and fails on any string constant over a threshold that is not a docstring, which
#       catches the shapes no line-oriented grep can see. Rule 40 already established that a
#       boundary worth having gets more than one layer, and its header says so rather than letting a
#       green grep be mistaken for a proof.
#
#   (b) EVERY BLOCK IS REACHED. No file under agents/prompts/blocks/ whose block id appears in no
#       composition manifest. An orphaned block is prompt text that ships in the repository, is
#       digested into prompt_registry_sha256, and reaches no model — so a reviewer reading the
#       registry sees guidance the run never received. It is also the shape a deleted-by-accident
#       reference takes: the manifest edit lands, the block stays, and nothing says the role lost
#       its instructions.
#
#   (c) EVERY TOOL IS DOCUMENTED. Every doc_block id named in agents/tools/registry.py exists under
#       agents/prompts/blocks/. The converse of (b), and the failure it catches is a tool offered to
#       a model with no documentation at all — which parity policy section 2 rule 3 forbids by
#       requiring the descriptions to be identical across conditions, a claim that cannot hold of a
#       description that does not exist.
#
# THERE IS DELIBERATELY NO EXEMPTION MECHANISM
# No allowlist file, no inline sentinel, no per-path skip. The reasoning is rule 10's, unchanged and
# quoted by rule 40 before it: an exemption mechanism added before the first true positive is an
# exemption mechanism sized to convenience rather than to risk, and a file-class filter is that same
# hole under a tidier name because it drops whole classes of file from the scan without ever
# reporting what it dropped. Block (a)'s scope is a statement about which directories the rule
# governs, decided here in the open and printed in the summary line, not a filter applied inside a
# scan.
#
# SCOPE AND EXIT CODES
# Tracked files only (git ls-files), so an untracked local scratch file cannot fail CI and the check
# sees exactly what a fresh clone contains. Each block reports independently, so a failure names
# which invariant broke. Exit 0 on a clean scan or a vacuous pass — vacuous meaning a block's scope
# is absent or holds no tracked files — exit 1 on any hit in any block. Strict POSIX sh, GNU-ERE
# patterns (the dialect grep_guard.sh established).

set -eu

# Byte-exact matching, and it stops grep from declaring a UTF-8 file binary because its bytes do not
# decode under whatever locale the caller happens to have set.
LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

# Patterns are spelled exactly once, here, and the failure report prints these same variables —
# monitor_guard.sh's correction of grep_guard.sh's double spelling, inherited rather than
# reintroduced: a pattern tightened in one place and not the other produces a failure message that
# does not describe the check that failed.
#
# (a1) A long quoted string assigned to a name. Sixty characters is the threshold, chosen so that an
#      identifier, a path, a URL, a format fragment and a reason code all pass while a sentence does
#      not. The assignment may be annotated (`PROMPT: Final = "..."`) or augmented (`text += "..."`),
#      because both are how an inlined prompt actually gets written.
PAT_LITERAL_ASSIGN='^[[:space:]]*[A-Za-z_][A-Za-z0-9_.]*([[:space:]]*:[^=]*)?[[:space:]]*\+?=[[:space:]]*[fru]?"[^"]{60,}"'
#      A DELIBERATE OMISSION, because getting this wrong once is how a guard becomes noise: there is
#      no pattern for "a long literal in an argument position". Every exception this repository
#      raises carries a long argued message wrapped across several lines — that is the house style,
#      and it is what makes a failure legible — so such a pattern would fire on nearly every `raise`
#      under agents/ and every one of those hits would be false. The two patterns that catch an
#      argument-position prompt are (a3) and (a4), both scoped to the construct rather than to the
#      length, which is monitor_guard.sh's inversion applied one more time.
#
# (a2) A triple-quoted string opened in a VALUE position: immediately after `=`, `(` or `,`. That is
#      where a multi-line prompt literal is written — `PROMPT = """`, `send("""`, `call(x, """` —
#      and it is the one pattern that can see a multi-line prompt at all.
#
#      The narrower spelling is a correction of the obvious one. "A `\"\"\"` that is not the first
#      thing on its line" reads like the right rule and fires on two things it must not: an `r\"\"\"`
#      module docstring, whose raw-string prefix is itself a non-space character, and the closing
#      delimiter of any one-line docstring. This repository is written almost entirely in those two
#      constructs, so that spelling would have been a check whose hits were all false from its first
#      run — the failure mode monitor_guard.sh's header spends four paragraphs refusing.
PAT_TRIPLE_INLINE='[=(,][[:space:]]*[fru]?"""'
# (a3) The keyword a prompt arrives under, paired with a literal of any length. This is the shape a
#      prompt takes when it is passed straight into a model call, and the parameter name is what
#      says the value is prompt text — so no length threshold is needed, or wanted.
PAT_PROMPT_KEYWORD='\b(prompt|system_prompt|system_message|system|instructions|template|content)[[:space:]]*=[[:space:]]*[fru]?"'
# (a4) The same thing written as a chat-message mapping, which is how every provider's API takes it:
#      `{"role": "system", "content": "..."}`. The key is a string rather than a keyword, so (a3)
#      cannot see it.
PAT_MESSAGE_KEY='"(content|system|prompt|instructions|text)"[[:space:]]*:[[:space:]]*[fru]?"'

scan_list=""
scan_hits=""
# scan <pattern-name> <extended-regex>
# Appends one line per hit, formatted path:line: <matching line>, tagged with the pattern that
# fired. Reads two globals set before each block, which keeps the call shape identical to the two
# sibling guards' two-argument `scan <name> <regex>`.
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
        done >> "$scan_hits"
    done < "$scan_list"
}

# list_tracked <output-file> <pathspec...>
# Writes one tracked path per line and leaves the count in $lt_count. `tr` is the POSIX-portable way
# to consume -z output; `read -d ''` is a bashism. The only case in which that conversion is
# ambiguous is a tracked path containing a literal newline, so the two encodings are compared and
# the assumption proved rather than assumed — git quotes such a path on the non-z path, which
# collapses it to one line, so the counts diverge exactly when the assumption breaks. It sets a
# global rather than echoing, because `exit 1` inside a command substitution would exit the subshell
# and let the caller carry on scanning.
lt_count=0
list_tracked() {
    lt_out=$1
    shift
    git ls-files -z -- "$@" | tr '\0' '\n' > "$lt_out"
    lt_count=$(wc -l < "$lt_out" | tr -d ' ')
    lt_plain=$(git ls-files -- "$@" | wc -l | tr -d ' ')
    if [ "$lt_count" != "$lt_plain" ]; then
        printf 'prompt-purity: refusing to run — a tracked path under agents/ contains a newline\n' >&2
        exit 1
    fi
}

# --- block (a): no prompt-shaped literal under agents/graphs/ or agents/tools/ -------------------
hits_a="$work/hits_a"
: > "$hits_a"
files_a="$work/files_a"

if [ ! -d agents ]; then
    state_a="vacuous — agents/ absent (pre-M4)"
    count_a=0
else
    list_tracked "$files_a" 'agents/graphs/*' 'agents/tools/*'
    count_a=$lt_count
    if [ "$count_a" -eq 0 ]; then
        state_a="vacuous — agents/graphs/ and agents/tools/ hold no tracked file (pre-M4)"
    else
        state_a="scanned $count_a tracked file(s) under agents/graphs/ and agents/tools/ against 4 pattern families"
        scan_list=$files_a
        scan_hits=$hits_a
        scan literal-assign  "$PAT_LITERAL_ASSIGN"
        scan triple-inline   "$PAT_TRIPLE_INLINE"
        scan prompt-keyword  "$PAT_PROMPT_KEYWORD"
        scan message-key     "$PAT_MESSAGE_KEY"
    fi
fi

# --- block (b): every block file is reached by a composition manifest ---------------------------
hits_b="$work/hits_b"
: > "$hits_b"
blocks_dir="agents/prompts/blocks"
manifest_glob="agents/prompts/compositions"

if [ ! -d "$blocks_dir" ] || [ ! -d "$manifest_glob" ]; then
    state_b="vacuous — the prompt registry is absent (pre-T4.2)"
    count_b=0
else
    list_tracked "$work/files_b" "$blocks_dir/*"
    count_b=$lt_count
    if [ "$count_b" -eq 0 ]; then
        state_b="vacuous — $blocks_dir/ holds no tracked file (pre-T4.2)"
    else
        state_b="checked $count_b block file(s) for a reference from a composition manifest"
        # The manifests are concatenated once rather than re-read per block: a registry of a few
        # dozen blocks against a few manifests is small, and one read keeps the loop O(blocks).
        cat "$manifest_glob"/*.yaml > "$work/manifests" 2>/dev/null || : > "$work/manifests"
        while IFS= read -r block_file; do
            [ -n "$block_file" ] || continue
            block_base=${block_file##*/}
            block_id=${block_base%.md}
            if ! grep -qF -e "$block_id" "$work/manifests"; then
                printf '%s: block id %s is referenced by no composition manifest\n' \
                    "$block_file" "$block_id" >> "$hits_b"
            fi
        done < "$work/files_b"
    fi
fi

# --- block (c): every tool's documentation block exists ------------------------------------------
hits_c="$work/hits_c"
: > "$hits_c"
tool_registry="agents/tools/registry.py"

if [ ! -f "$tool_registry" ] || [ ! -d "$blocks_dir" ]; then
    state_c="vacuous — the tool registry or the block directory is absent (pre-T4.1)"
    count_c=0
else
    # doc_block="tool.guardian-action" is the only shape the registry writes, and the pattern is
    # anchored to that keyword rather than to a bare id so that a comment mentioning a block cannot
    # be mistaken for a declaration.
    grep -oE 'doc_block="[^"]+"' "$tool_registry" | sed 's/^doc_block="//; s/"$//' | sort -u \
        > "$work/doc_blocks" || : > "$work/doc_blocks"
    count_c=$(wc -l < "$work/doc_blocks" | tr -d ' ')
    if [ "$count_c" -eq 0 ]; then
        state_c="vacuous — $tool_registry declares no doc_block (pre-T4.1)"
    else
        state_c="checked $count_c tool documentation block id(s) against $blocks_dir/"
        while IFS= read -r doc_block; do
            [ -n "$doc_block" ] || continue
            if [ ! -f "$blocks_dir/$doc_block.md" ]; then
                printf '%s: names doc_block %s, and %s/%s.md does not exist\n' \
                    "$tool_registry" "$doc_block" "$blocks_dir" "$doc_block" >> "$hits_c"
            fi
        done < "$work/doc_blocks"
    fi
fi

hit_count_a=$(wc -l < "$hits_a" | tr -d ' ')
hit_count_b=$(wc -l < "$hits_b" | tr -d ' ')
hit_count_c=$(wc -l < "$hits_c" | tr -d ' ')
hit_total=$((hit_count_a + hit_count_b + hit_count_c))

if [ "$hit_total" -gt 0 ]; then
    {
        printf 'prompt-purity: FAIL — rule 20 prompt boundary violated (%s hit(s))\n' "$hit_total"
        printf '  block (a) no prompt literal in code: %s hit(s)\n' "$hit_count_a"
        printf '  block (b) every block is reached:    %s hit(s)\n' "$hit_count_b"
        printf '  block (c) every tool is documented:  %s hit(s)\n' "$hit_count_c"
    } >&2
    if [ "$hit_count_a" -gt 0 ]; then
        {
            echo
            echo "BLOCK (a) — prompt-shaped literals under agents/graphs/ and agents/tools/"
            cat "$hits_a"
            echo
            echo "Patterns:"
            printf '  literal-assign  %s\n' "$PAT_LITERAL_ASSIGN"
            printf '  triple-inline   %s\n' "$PAT_TRIPLE_INLINE"
            printf '  prompt-keyword  %s\n' "$PAT_PROMPT_KEYWORD"
            printf '  message-key     %s\n' "$PAT_MESSAGE_KEY"
            echo
            echo "Fix the code: move the text into agents/prompts/blocks/ with a stable block id,"
            echo "reference it from every composition manifest that needs it, and compose it by ID"
            echo "(prompt-parity-policy.md section 2 rule 1). Text that is not in the registry is"
            echo "guidance make parity-check never counts. There is no exemption mechanism by"
            echo "design — see this script's header."
        } >&2
    fi
    if [ "$hit_count_b" -gt 0 ]; then
        {
            echo
            echo "BLOCK (b) — block files no composition manifest reaches"
            cat "$hits_b"
            echo
            echo "Either reference the block from the manifest that lost it, or delete it. An"
            echo "orphaned block ships in the repository, is digested into prompt_registry_sha256,"
            echo "and reaches no model — so the registry shows guidance the run never received."
        } >&2
    fi
    if [ "$hit_count_c" -gt 0 ]; then
        {
            echo
            echo "BLOCK (c) — tools whose documentation block does not exist"
            cat "$hits_c"
            echo
            echo "Parity policy section 2 rule 3 requires the tool descriptions to be identical"
            echo "across conditions, which cannot hold of a description that does not exist. Write"
            echo "the block, or remove the tool."
        } >&2
    fi
    exit 1
fi

printf 'prompt-purity: PASS — (a) %s; (b) %s; (c) %s; no hits\n' "$state_a" "$state_b" "$state_c"
exit 0
