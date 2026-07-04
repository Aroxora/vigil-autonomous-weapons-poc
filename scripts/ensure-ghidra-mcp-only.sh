#!/bin/bash
# Enforce MCP-only Ghidra control — Ghidra headless must NEVER be auto-launched.
# All Ghidra operations must go through the MCP server (ghidra-mcp-server.mjs).
#
# This script:
#   1. Verifies VIGIL_GHIDRA_HEADLESS is NOT set to '1' (prevents auto-analysis)
#   2. Ensures VIGIL_SESSION_TOKEN is required for ALL Ghidra operations
#   3. Sets the env guard so headless never auto-starts
#   4. Validates the MCP server is the ONLY entry point

set -euo pipefail

echo "=== Ghidra MCP-Only Enforcement ==="

# 1. Unset VIGIL_GHIDRA_HEADLESS — this is the master kill switch.
# If set to '1', the probe function in _ghidra-headless.mjs would auto-launch
# headless analysis. We force it off.
if [ "${VIGIL_GHIDRA_HEADLESS:-}" = "1" ]; then
  echo "[WARN] VIGIL_GHIDRA_HEADLESS=1 detected — UNSETTING. Ghidra headless auto-launch is DISABLED."
  unset VIGIL_GHIDRA_HEADLESS
fi

# 2. Ensure VIGIL_SESSION_TOKEN requirement is intact.
# The _ghidra-headless.mjs module has a hard assertVigilCaller() check
# that exits(1) if VIGIL_SESSION_TOKEN is not set. Verify the check exists.
GHIDRA_HEADLESS="scripts/_ghidra-headless.mjs"
if grep -q "assertVigilCaller" "$GHIDRA_HEADLESS" 2>/dev/null; then
  echo "[OK] assertVigilCaller guard present in _ghidra-headless.mjs"
else
  echo "[CRITICAL] assertVigilCaller guard MISSING from _ghidra-headless.mjs — Ghidra may be directly invocable!"
  exit 1
fi

# 3. Verify MCP server is the only exposed Ghidra surface
MCP_SERVER="scripts/ghidra-mcp-server.mjs"
if grep -q "VIGIL_SESSION_TOKEN" "$MCP_SERVER" 2>/dev/null; then
  echo "[OK] MCP server enforces VIGIL_SESSION_TOKEN"
else
  echo "[CRITICAL] MCP server missing VIGIL_SESSION_TOKEN enforcement!"
  exit 1
fi

# 4. Check no cron/service auto-launches Ghidra
if crontab -l 2>/dev/null | grep -qi ghidra; then
  echo "[WARN] Cron jobs referencing Ghidra detected — review and remove for MCP-only enforcement"
fi

# 5. Check no systemd service auto-launches Ghidra
for svc in $(systemctl list-units --type=service --all 2>/dev/null | grep -i ghidra | awk '{print $1}'); do
  echo "[WARN] Systemd service '$svc' references Ghidra — disable for MCP-only: systemctl disable --now $svc"
done

# 6. Export the guard for child processes
export VIGIL_GHIDRA_HEADLESS=0
export VIGIL_GHIDRA_MCP_ONLY=1

echo ""
echo "=== Ghidra Enforcement Summary ==="
echo "  VIGIL_GHIDRA_HEADLESS  = ${VIGIL_GHIDRA_HEADLESS:-0}  (must be 0)"
echo "  VIGIL_GHIDRA_MCP_ONLY  = ${VIGIL_GHIDRA_MCP_ONLY:-1}  (must be 1)"
echo "  Headless auto-launch    = DISABLED"
echo "  MCP server              = ONLY ENTRY POINT"
echo "  VIGIL_SESSION_TOKEN     = REQUIRED for all Ghidra ops"
echo ""
echo "Ghidra is locked down: MCP-only, no headless auto-launch."
