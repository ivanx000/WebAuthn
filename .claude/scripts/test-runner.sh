#!/usr/bin/env bash
# Hook 5: Run the full test suite after any edit inside src/ or tests/.
# Reads the PostToolUse JSON payload from stdin.
set -uo pipefail

INPUT=$(cat)
FILE=$(echo "$INPUT" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(d.get('tool_input',{}).get('file_path',''))" \
  2>/dev/null || true)

if ! echo "$FILE" | grep -qE '/(src|tests)/'; then
    exit 0
fi

echo "=== Tests (triggered by edit to $(basename "$FILE")) ==="

TEST_OUT=$(cargo test 2>&1)
TEST_EXIT=$?
echo "$TEST_OUT"

if [[ $TEST_EXIT -ne 0 ]]; then
    echo "❌ Tests failed — fix failing tests before proceeding."
else
    echo "✅ All tests passing"
fi

exit 0
