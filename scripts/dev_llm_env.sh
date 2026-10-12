#!/bin/sh
# Map the user's dev/pilot credential onto LiteLLM's OpenAI-compatible environment.
# Source this file; it never prints or persists the credential.
if [ -z "${OPENAI_BASE_URL:-}" ] && [ -n "${DEV_LLM_BASE_URL:-}" ]; then
    # Strip a trailing CR: a .env authored on the Windows host is CRLF, and a URL with a
    # carriage character in it reaches the provider as a malformed request.
    export OPENAI_BASE_URL=$(printf '%s' "$DEV_LLM_BASE_URL" | tr -d '\r')
fi
if [ -n "${DEV_LLM_KEY:-}" ] && [ -z "${OPENAI_API_KEY:-}" ]; then
    # Strip a trailing CR: a .env authored on the Windows host is CRLF, and a credential with a
    # carriage character in it reaches the provider as a malformed Authorization header.
    export OPENAI_API_KEY=$(printf '%s' "$DEV_LLM_KEY" | tr -d '\r')
fi
