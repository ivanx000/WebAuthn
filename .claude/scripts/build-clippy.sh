#!/usr/bin/env bash
# Hook 1: Run cargo build + clippy after any .rs file is edited.
# Reads the PostToolUse JSON payload from stdin to extract the file path.
set -euo pipefail

INPUT=$(cat)
FILE=$(echo "$INPUT" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(d.get('tool_input',{}).get('file_path',''))" \
  2>/dev/null || true)

if [[ "$FILE" != *.rs ]]; then
    exit 0
fi

echo "=== Build + Clippy ($(basename "$FILE") edited) ==="

BUILD_OUT=$(cargo build 2>&1)
BUILD_EXIT=$?
echo "$BUILD_OUT"
if [[ $BUILD_EXIT -ne 0 ]]; then
    echo "❌ cargo build FAILED — fix all errors before proceeding."
    exit 0
fi
echo "✅ Build OK"

CLIPPY_OUT=$(cargo clippy -- -D warnings 2>&1)
CLIPPY_EXIT=$?
echo "$CLIPPY_OUT"
if [[ $CLIPPY_EXIT -ne 0 ]]; then
    echo "❌ cargo clippy has warnings — fix all clippy warnings before proceeding."
    exit 0
fi
echo "✅ Clippy OK (zero warnings)"

exit 0
