#!/usr/bin/env bash
# Hook 2: Auto-commit all local changes after Claude's turn ends.
# Triggered by the Stop hook. NEVER pushes — push is always manual.
set -uo pipefail

# Navigate to repo root in case the hook runs from a different cwd.
ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
cd "$ROOT"

# Bail out if there is nothing to commit.
if git diff --quiet && git diff --cached --quiet && \
   [[ -z "$(git ls-files --others --exclude-standard)" ]]; then
    exit 0
fi

# Stage everything that isn't already staged.
git add -A

# Determine the conventional-commit prefix from which paths changed.
STAGED=$(git diff --cached --name-only 2>/dev/null)

PREFIX="chore"
HAS_SRC=$(echo "$STAGED"   | grep -cE '^src/'   2>/dev/null || true)
HAS_TEST=$(echo "$STAGED"  | grep -cE '^tests/' 2>/dev/null || true)
HAS_DOCS=$(echo "$STAGED"  | grep -cE '\.(md)$' 2>/dev/null || true)
HAS_CFG=$(echo "$STAGED"   | grep -cE '^(\.github|\.claude|Cargo)' 2>/dev/null || true)

if   [[ $HAS_SRC  -gt 0 && $HAS_TEST -gt 0 ]]; then PREFIX="feat"
elif [[ $HAS_SRC  -gt 0 ]]; then PREFIX="feat"
elif [[ $HAS_TEST -gt 0 ]]; then PREFIX="test"
elif [[ $HAS_DOCS -gt 0 ]]; then PREFIX="docs"
elif [[ $HAS_CFG  -gt 0 ]]; then PREFIX="chore"
fi

N=$(echo "$STAGED" | grep -c . 2>/dev/null || echo "0")
MSG="${PREFIX}: update passforge (${N} file(s) changed)"

git commit -m "$MSG

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>" 2>&1

echo ""
echo "Committed locally. Run git push when ready."

# Explicitly never push.
exit 0
