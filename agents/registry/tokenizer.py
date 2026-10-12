r"""The fixed reference tokenizer the parity gate counts with: offline, pinned, and recorded.

WHAT THIS MODULE IS
-------------------
``docs/protocols/prompt-parity-policy.md`` section 3 says to "tokenize with the campaign model's
tokenizer (via LiteLLM utilities; fallback: a fixed reference tokenizer, recorded)". This module is
that fallback, and conflict M4-C3 in ``docs/plans/M4-implementation-plan.md`` is why the fallback
is the operative clause rather than the spare one.

WHY THE CAMPAIGN MODEL'S TOKENIZER CANNOT BE THE GATE'S TOKENIZER
------------------------------------------------------------------
Three facts, and any one of them is sufficient.

*The gate runs where there is no credential.* ``make parity-check`` is CI-blocking and runs in the
``guardrail-grep`` job, which installs nothing and holds no provider key. Resolving a model's
tokenizer through LiteLLM means a provider lookup; on a runner with no ``.env`` there is nothing to
look it up with.

*The model is not fixed yet.* ``infra/versions.env``'s ``MODEL_PROVIDER_STRING`` carries the
dev-tier string and ADR-005 defers the final model to GATE re-verification under risk R-01 -- a
provider deleted free models without notice in May 2026, which is the observed event the whole
alias strategy exists to absorb. A parity number that moves when a free catalogue churns is not a
parity number: the same registry would score differently in two milestones and the equality the
gate asserts would be an equality about the catalogue.

*Every real tokenizer needs a data file.* ``tiktoken`` fetches its BPE tables from a network
endpoint on first use; ``transformers`` and ``tokenizers`` need a vocabulary downloaded from a
model hub; ``sentencepiece`` needs a model file. Each of those makes the gate's result depend on
network reachability, and vendoring a megabyte-scale vocabulary into the repository to avoid that
would put a third-party data artefact on the critical path of a check that must reproduce from a
clean checkout for years. Rejected, with the alternatives named, in ADR-028.

So the gate tokenizes with the algorithm below: fixed, offline, dependency-free, deterministic, and
identified by a string that ``infra/versions.env`` pins. The campaign model's own tokenizer is
compared against it **once, at GATE**, when R-01's limit re-verification fixes the model -- reported
as a cross-check, never as the gate.

WHAT THE ALGORITHM IS, PRECISELY
---------------------------------
It is GPT-2's byte-level pre-tokenization, and one token per pre-token piece.

Every byte-level BPE tokenizer in current use begins by splitting text with a regular expression
into pieces -- contractions, words with a leading space, numbers, punctuation runs, whitespace runs
-- and only then merges within each piece. This module performs that first stage exactly, using
GPT-2's published pattern, and counts the pieces. It does not perform the merge stage, because the
merge stage is what needs the vocabulary.

The consequence is stated plainly rather than glossed: **this count is lower than a full BPE count,
by a factor that is roughly constant on English prose** -- a full BPE pass splits long or rare words
into several sub-tokens where this counts one. That factor is immaterial to what the gate asserts,
and the reason is worth being precise about. Parity is an *equality across conditions drawn from one
block set*. All three conditions are composed from the same blocks in the same language, so any
systematic factor applies to all three numerators and to the mean they are compared against, and
divides out of the ratio the tolerance bounds. What a factor cannot hide is a condition carrying
more or fewer blocks, or a longer structural block, which is the whole of what the check is looking
for.

Two properties this stage does keep exactly, and they are the ones that matter:

*Monotonicity.* Adding text never lowers the count, and adding a whole block raises it by that
block's own count, because the pattern splits at boundaries that no concatenation of blocks can
straddle -- every block ends in a newline, and a newline always terminates a piece.

*Determinism.* One regular expression over ``str``, no locale, no clock, no dictionary iteration
order, no network. Counting the same text twice returns the same number in any interpreter that
implements the pattern, which is ``.agents/rules/20-parity-and-determinism.md``'s requirement
applied to a gate rather than to a scenario.

THE IDENTITY IS PINNED, AND THE PIN IS PROVED RATHER THAN TRUSTED
------------------------------------------------------------------ :data:`REFERENCE_TOKENIZER_ID`
is this algorithm's name. ``infra/versions.env`` carries ``PARITY_TOKENIZER`` with the same string,
and ``agents/tests/test_reference_tokenizer.py`` reads that file and asserts the two agree -- the
ADR-022 pattern, one rule stated once in prose, two homes, and a test that makes "copy" mean "copy
that cannot drift". The identity is written into the emitted token table and belongs in every run
bundle's manifest beside ``prompt_registry_sha256``, so a number read out of a sealed bundle says
which algorithm produced it.

Changing the algorithm changes every parity number in the repository. Before the ``v1.0`` freeze
that is an ADR and a re-run of ``make parity-check``; after it, AGENTS.md iron rule 6 makes it a
logged hotfix ADR.

WHAT BREAKS IF THIS FILE CHANGES
--------------------------------
``make parity-check``'s token table, the structural-block cap frozen in
``prompt-parity-policy.md`` section 3 (which is a number *in this unit*), and the GATE cross-check
that compares this count against the campaign model's.
"""

import re
import unicodedata
from typing import Final

__all__ = (
    "REFERENCE_TOKENIZER_ID",
    "count_tokens",
    "pre_tokens",
)

# The name of this algorithm, mirrored by infra/versions.env's PARITY_TOKENIZER key and held equal
# to it by a test. It is a name and not a version range: there is one algorithm here, and a second
# one would be a second identity rather than a bump.
REFERENCE_TOKENIZER_ID: Final = "overwatch-ref-1"

# GPT-2's byte-level pre-tokenization pattern, in the order its alternatives are tried. Written out
# alternative by alternative rather than as one opaque line, because every branch of it is
# load-bearing for the count and a reader has to be able to check that this is the published
# pattern rather than something close to it.
#
#   's|'t|'re|'ve|'m|'ll|'d   the English contractions, so "don't" is two pieces and not three
#   ?\p{L}+                   a run of letters, optionally with one leading space
#   ?\p{N}+                   a run of digits, optionally with one leading space
#   ?[^\s\p{L}\p{N}]+         a run of punctuation or symbols, optionally with one leading space
#   \s+(?!\S)                 a run of whitespace that is not followed by a non-space -- this is
#                             what makes a line of indentation one piece rather than many
#   \s+                       any remaining whitespace
#
# Python's `re` has no \p{L} or \p{N}, so the three Unicode classes are spelled with `\w` and `\d`
# and the complement of both:
#
#   \p{L}              ->  [^\W\d_]        a word character that is neither a digit nor `_`
#   \p{N}              ->  \d
#   [^\s\p{L}\p{N}]    ->  (?:[^\s\w]|_)   not whitespace and not a word character, plus `_`
#                                          itself, which `\w` includes and `\p{L}` does not
#
# `_` has to be added back explicitly and it is the one place this transcription could be got
# quietly wrong: without it an identifier such as `run_id` would pre-tokenize as one piece in one
# reading and three in another, and the count would depend on which. Every alternative is
# non-capturing, because `re.findall` returns group contents rather than whole matches the moment a
# capturing group appears -- which would silently return empty strings instead of pieces.
_PATTERN_SOURCE: Final = (
    r"'s|'t|'re|'ve|'m|'ll|'d"
    r"| ?[^\W\d_]+"
    r"| ?\d+"
    r"| ?(?:[^\s\w]|_)+"
    r"|\s+(?!\S)"
    r"|\s+"
)

# re.UNICODE is the default for str patterns in Python 3 and is named anyway, because the whole
# correctness of \w and \d here rests on it and a reader should not have to know the default.
_PATTERN: Final = re.compile(_PATTERN_SOURCE, re.UNICODE)


def _normalise(text: str) -> str:
    """Return ``text`` in Unicode NFC, the one normalisation this module applies.

    Two byte sequences that render as the same character -- ``é`` as one code point and as ``e``
    plus a combining acute -- would otherwise pre-tokenize identically but *look* like a difference
    to anyone comparing block bytes, and would give a different count if a future refinement ever
    counted code points. Normalising once here means the token count is a function of the text's
    meaning rather than of which editor typed it. NFC rather than NFD because it is the composed
    form every tool in this repository already writes, and rather than NFKC because NFKC folds
    characters that are genuinely distinct in a prompt -- it would turn a fullwidth character in an
    adversarial excerpt into its ASCII lookalike, which is the opposite of what the Monitor's
    quoting exists to preserve.
    """
    return unicodedata.normalize("NFC", text)


def pre_tokens(text: str) -> tuple[str, ...]:
    """Return the pre-token pieces of ``text``, in order.

    Published as well as :func:`count_tokens` because a parity failure is a question about *which*
    block grew, and a reader debugging one needs to see the pieces rather than a number. Nothing in
    the gate path calls it; ``agents/tests/test_reference_tokenizer.py`` and a human do.

    The pieces concatenate back to the normalised input exactly -- the pattern's alternatives cover
    every character, so nothing is dropped -- and the test asserts that round trip rather than
    assuming it.
    """
    return tuple(_PATTERN.findall(_normalise(text)))


def count_tokens(text: str) -> int:
    """Return the reference token count of ``text``.

    The empty string counts zero, which is the only special case and is not special-cased: the
    pattern simply matches nothing. Whitespace does count -- a block padded with blank lines is
    longer than one that is not, and a parity check that ignored padding could be satisfied by
    padding.
    """
    return len(_PATTERN.findall(_normalise(text)))
