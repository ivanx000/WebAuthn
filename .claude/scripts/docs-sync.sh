#!/usr/bin/env bash
# Hook 3: Print docs-sync warnings when security-critical files are edited.
# Reads the PostToolUse JSON payload from stdin.
set -uo pipefail

INPUT=$(cat)
FILE=$(echo "$INPUT" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(d.get('tool_input',{}).get('file_path',''))" \
  2>/dev/null || true)

case "$FILE" in
    */src/registration.rs)
        echo "⚠️  Registration logic changed. Check docs/architecture.md and ensure all W3C spec step comments (§7.1) are still accurate."
        ;;
    */src/authentication.rs)
        echo "⚠️  Authentication logic changed. Check docs/architecture.md and ensure spec step comments (§7.2) are still accurate."
        ;;
    */src/crypto.rs)
        echo "⚠️  Crypto primitives changed. Update docs/security-considerations.md if any cryptographic behaviour changed."
        ;;
    */src/error.rs)
        echo "⚠️  Error types changed. Ensure all new variants are doc-commented and have corresponding test coverage."
        ;;
    */src/lib.rs)
        echo "⚠️  Public API changed. Update README.md quick-start example if the public interface changed."
        ;;
esac

exit 0
