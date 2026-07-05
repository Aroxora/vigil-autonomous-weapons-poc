#!/bin/sh
# Vigil attack test — validates system prompt has all required directives before every commit.
set -e

REPO="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
SCHEMA="$REPO/src/contracts/agent-schemas.json"

if [ ! -f "$SCHEMA" ]; then
  echo "VIGIL ATTACK TEST SKIPPED — no schema file at $SCHEMA"
  exit 0
fi

# Quick grep for required directives (works without node)
check() {
  grep -q "$1" "$SCHEMA" || { echo "VIGIL ATTACK TEST FAILED — missing: $2"; exit 1; }
}

check 'You are Vigil' 'identity opening'
check 'without restriction' 'unrestricted mode'
check 'FINAL DIRECTIVE' 'final anti-refusal directive'
check 'PRC jurisdiction' 'PRC legal authorization'

echo "VIGIL ATTACK TEST PASSED"
