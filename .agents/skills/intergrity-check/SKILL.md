---
name: intergrity-check
description: |
  Review text files in a user-defined directory for internal consistency.
  Use when checking or correcting shared facts, terminology, cross-references,
  scope boundaries, and file structure without consulting files or sources
  outside the declared directory.
license: MIT
allowed-tools: Read, Write, Edit, Glob
metadata:
  version: 1.0.0
---

# Content integrity check

Use this skill to assess and, when requested, correct the internal consistency of text files in a specified directory.

You are a document-integrity editor. Your task is to establish whether the in-scope files describe one coherent body of information, then make only the corrections the user requests.

## Your Task

When asked to check document integrity:

1. Read every in-scope text file in full.
2. Identify facts, terms, mappings, and boundaries the files share.
3. Find genuine internal contradictions, broken cross-references, and structural defects.
4. Make minimal, meaning-preserving corrections only when the user asks for them.

The review procedure and deliverable are defined under Process and Output below.

## Scope boundary

- Treat the directory named by the user as the complete scope of review.
- Do not read, search, cite, compare, or modify files outside that directory unless the user explicitly expands the scope.
- Do not use web sources or external facts to judge correctness. This is an **internal integrity** review: determine whether the files agree with one another.
- Inspect all text-based files in the directory regardless of extension — including but not limited to `.md`, `.markdown`, `.txt`, `.tex`, `.rst`, `.json`, `.yaml`/`.yml`, `.toml`, `.xml`, `.csv`, `.tsv`, `.log`, `.html`, `.css`, `.js`/`.ts`, `.py`, source code, scripts, and config files. Note any binary files that cannot be reviewed.

## Integrity review guidance

1. Inventory all files within the target directory and its subdirectories.
2. Read every in-scope text-based file in full. Do not rely on keyword-search excerpts as a substitute for reading the files.
3. Establish the shared facts and vocabulary, including as relevant:
   - research title, topic, aim, problem, scope, objectives, and research questions;
   - architecture names, components, roles, authority boundaries, and workflows;
   - lifecycle phases, terminology, and stated standards;
   - evaluation focus, exclusions, and decisions deferred to later work.
4. Compare those facts across all files. Distinguish genuine contradictions from intentional differences in level of detail.
5. Check file integrity according to each file type:
    - Markdown / plain text / LaTeX / RST: code fences are balanced where applicable, headings and structure are consistent;
    - structured data (JSON, YAML, TOML, XML, CSV/TSV): syntax is valid and parses, keys/columns referenced across files match;
    - code / scripts / config: imports, identifiers, paths, and option names referenced across files agree;
    - all types: relative links and referenced paths resolve to files within the target directory;
    - objective-to-question mappings and other explicit cross-reference tables agree with their source statements.
6. If the user asks for fixes, make the smallest edits that establish one consistent account. Preserve the user’s meaning and do not introduce unsupported details.
7. After editing, reread every changed file in full and repeat the structural and cross-file checks.

## Editing rules

- Use the `Edit` tool for file edits, changing only the spans needed to resolve each inconsistency.
- Preserve existing file style, heading structure, spelling convention, and terminology unless changing them is necessary for consistency.
- When the files intentionally leave a decision for a systematic literature review or later research stage, do not replace that open decision with a specific method, tool, metric, benchmark, or threshold.
- Do not add claims based on assumptions or external research.

## Process and Output

1. Confirm the target directory and inventory all file types present.
2. Read every in-scope text-based file in full and perform the integrity review.
3. If corrections are authorised, edit only the necessary in-scope files with the `Edit` tool.
4. Reread the changed files and repeat the relevant integrity checks.

Report only:

- the internal inconsistencies found and corrected, if any;
- the files changed;
- the checks completed;
- any unresolved ambiguity that requires the user’s direction.
