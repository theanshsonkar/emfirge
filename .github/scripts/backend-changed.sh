#!/usr/bin/env bash
# Prints backend=true|false. Fails open: anything unclear runs the backend.
# Only a push to dev whose every changed file is docs/, site/, mcp/ or *.md may skip.
set -u
run=true
zero=0000000000000000000000000000000000000000
if [ "${EVENT:-}" = "push" ] && [ "${REF:-}" = "refs/heads/dev" ] \
   && [ -n "${BEFORE:-}" ] && [ "$BEFORE" != "$zero" ] \
   && git cat-file -e "${BEFORE}^{commit}" 2>/dev/null; then
  if files=$(git diff --name-only "$BEFORE" "$SHA") && [ -n "$files" ]; then
    if ! printf '%s\n' "$files" | grep -qvE '^(docs/|site/|mcp/)|\.md$'; then
      run=false
    fi
  fi
fi
echo "backend=$run"
echo "backend job will run: $run" >&2
