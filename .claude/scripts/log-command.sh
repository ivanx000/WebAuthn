#!/usr/bin/env bash
# Hook 4: Append every Bash command to .claude/logs/commands.log.
# Reads the PreToolUse JSON payload from stdin.
set -uo pipefail

INPUT=$(cat)
CMD=$(echo "$INPUT" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(d.get('tool_input',{}).get('command','').splitlines()[0] if d.get('tool_input',{}).get('command') else '')" \
  2>/dev/null || true)

ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || ROOT="."
LOGDIR="$ROOT/.claude/logs"
mkdir -p "$LOGDIR" 2>/dev/null || true

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $CMD" >> "$LOGDIR/commands.log" 2>/dev/null || true

exit 0
