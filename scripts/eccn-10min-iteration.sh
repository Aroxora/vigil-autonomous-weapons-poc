#!/usr/bin/env bash
#=============================================================================
# ECCN EAR99 10-Minute Iteration Loop
# Runs the full Vigil security pipeline every 10 minutes:
#   scan → enrich → redact → deploy → commit → push
#
# ECCN EAR99 — Public domain. No restricted technology. No CNA/CNE capability.
# This is a detection, monitoring, and compliance automation pipeline.
#
# Deployment: ./scripts/eccn-10min-iteration.sh [--daemon]
#   --daemon: run continuously with 10min sleep between iterations
#   (no flag): run once and exit
#
# Author: Vigil (Bo Shang — Trenchwork)
# Date: 2026-06-20
#=============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
cd "$ROOT"

# ─── Configuration ────────────────────────────────────────────────────────
ITERATION_INTERVAL_SECONDS="${ECCEN_ITERATION_INTERVAL:-600}"  # 10 min default
PUSH_ENABLED="${ECCEN_PUSH_ENABLED:-true}"
DEPLOY_BOTH_SITES="${ECCEN_DEPLOY_BOTH:-true}"
LOG_DIR="${ROOT}/.vigil/logs/eccn-iterations"
VERBOSE="${ECCEN_VERBOSE:-false}"

# ─── Color helpers ────────────────────────────────────────────────────────
RED='\033[0;31m';   GREEN='\033[0;32m';   YELLOW='\033[1;33m'
BLUE='\033[0;34m';  CYAN='\033[0;36m';    RESET='\033[0m'
BOLD='\033[1m'

ts() { date '+%Y-%m-%d %H:%M:%S'; }

log_info()  { echo -e "${GREEN}[$(ts)]${RESET} ${BOLD}[ECCEN]${RESET} $*"; }
log_warn()  { echo -e "${YELLOW}[$(ts)]${RESET} ${BOLD}[ECCEN]${RESET} ${YELLOW}$*${RESET}"; }
log_error() { echo -e "${RED}[$(ts)]${RESET} ${BOLD}[ECCEN]${RESET} ${RED}$*${RESET}"; }
log_step()  { echo -e "${CYAN}[$(ts)]${RESET} ${BOLD}[ECCEN:STEP]${RESET} ${CYAN}$*${RESET}"; }

# ─── Utility functions ────────────────────────────────────────────────────

ensure_dirs() {
    mkdir -p "$LOG_DIR"
    mkdir -p site/vigil-web/public/security/eccn
    mkdir -p site/vigil-web/dist/security
}

source_env() {
    if [ -f "$ROOT/.env" ]; then
        set +euo pipefail
        source "$ROOT/.env" 2>/dev/null || true
        set -euo pipefail
    fi
}

# ─── Pipeline Steps ───────────────────────────────────────────────────────

step_scan() {
    log_step "1/6: Running comprehensive security scan..."
    local scan_start=$SECONDS
    local scan_log="$LOG_DIR/scan-$(date +%Y%m%d-%H%M%S).log"

    if node "$SCRIPT_DIR/vigil-run.mjs" "$SCRIPT_DIR/_vigil-comprehensive.mjs" \
        > "$scan_log" 2>&1; then
        local elapsed=$((SECONDS - scan_start))
        local findings=$(python3 -c "import json; d=json.load(open('site/vigil-web/public/security/vulnerabilities.json')); print(len(d))" 2>/dev/null || echo "?")
        log_info "  Scan complete in ${elapsed}s — ${findings} findings"
        return 0
    else
        log_error "  Scan FAILED — see $scan_log"
        return 1
    fi
}

step_enrich() {
    log_step "2/6: Enriching findings with CVSS/EPSS/KEV..."

    if [ -f "$SCRIPT_DIR/_finding-enricher.mjs" ]; then
        node "$SCRIPT_DIR/_finding-enricher.mjs" 2>&1 | tail -5
        log_info "  Findings enriched"
    else
        log_warn "  _finding-enricher.mjs not found — skipping enrichment"
    fi
    return 0
}

step_redact() {
    log_step "3/6: Redacting ECCN public artifacts..."

    if node "$SCRIPT_DIR/redact-eccn-public.mjs" 2>&1; then
        log_info "  ECCN redaction complete"
    else
        log_warn "  ECCN redaction had warnings (non-fatal)"
    fi
    return 0
}

step_deploy() {
    log_step "4/6: Deploying findings to sites..."

    # Copy security artifacts to dist
    cp site/vigil-web/public/security/vulnerabilities.json \
       site/vigil-web/dist/security/vulnerabilities.json 2>/dev/null || true
    cp site/vigil-web/public/security/latest.json \
       site/vigil-web/dist/security/latest.json 2>/dev/null || true

    # Copy health
    cp site/vigil-web/public/health.json \
       site/vigil-web/dist/health.json 2>/dev/null || true

    # Copy detections
    if [ -d site/vigil-web/public/detections ]; then
        mkdir -p site/vigil-web/dist/detections
        cp -r site/vigil-web/public/detections/* site/vigil-web/dist/detections/ 2>/dev/null || true
    fi

    # Copy ADVANCED_PERSISTENT_STRIKE
    if [ -d ADVANCED_PERSISTENT_STRIKE ]; then
        mkdir -p site/vigil-web/dist/advanced-persistent-strike
        cp -r ADVANCED_PERSISTENT_STRIKE/* site/vigil-web/dist/advanced-persistent-strike/ 2>/dev/null || true
    fi

    if [ "$DEPLOY_BOTH_SITES" = "true" ]; then
        cd "$ROOT/site/vigil-web"

        # Deploy to erosolar (health/monitoring site)
        if npx firebase deploy --only hosting --project erosolar-1b0db \
            --non-interactive 2>&1 | grep -q 'Deploy complete'; then
            log_info "  erosolar-1b0db  ✅ deployed"
        else
            log_error "  erosolar-1b0db  ❌ deploy failed"
        fi

        # Deploy to CNO (security/findings site)
        if npx firebase deploy --only hosting --project computer-network-operations \
            --config firebase.cno.json --non-interactive 2>&1 | grep -q 'Deploy complete'; then
            log_info "  CNO              ✅ deployed"
        else
            log_error "  CNO              ❌ deploy failed"
        fi

        cd "$ROOT"
    else
        log_warn "  DEPLOY_BOTH_SITES=false — skipping deployment"
    fi
    return 0
}

step_commit() {
    log_step "5/6: Committing changes..."

    cd "$ROOT"

    # Only commit if there are changes
    if git diff --quiet && git diff --cached --quiet; then
        log_info "  No changes to commit"
        return 0
    fi

    local msg="eccn-iteration: $(date '+%Y-%m-%d %H:%M') — auto-scan findings update"

    if git add -A && git commit -m "$msg" 2>&1; then
        log_info "  Committed: $msg"
    else
        log_warn "  No changes staged (already clean)"
    fi
    return 0
}

step_push() {
    log_step "6/6: Pushing to origin..."

    if [ "$PUSH_ENABLED" != "true" ]; then
        log_warn "  PUSH_ENABLED=false — skipping push"
        return 0
    fi

    cd "$ROOT"
    local branch=$(git branch --show-current)

    if git push origin "$branch" 2>&1; then
        log_info "  Pushed to origin/$branch ✅"
    else
        log_error "  Push FAILED"
        return 1
    fi
    return 0
}

# ─── Health check ─────────────────────────────────────────────────────────

step_health_check() {
    log_step "Health: Verifying live endpoints..."

    local erosolar_ok=false
    local cno_ok=false

    # Check erosolar
    if curl -sf https://erosolar-1b0db.web.app/health.json > /dev/null 2>&1; then
        erosolar_ok=true
    fi

    # Check CNO
    if curl -sf https://computer-network-operations.web.app/security/vulnerabilities.json > /dev/null 2>&1; then
        cno_ok=true
    fi

    if $erosolar_ok && $cno_ok; then
        log_info "  erosolar ✅  CNO ✅  — all live"
    else
        local status=""
        $erosolar_ok && status+="erosolar✅ " || status+="erosolar❌ "
        $cno_ok && status+="CNO✅" || status+="CNO❌"
        log_warn "  $status"
    fi
}

# ─── Full pipeline ────────────────────────────────────────────────────────

run_iteration() {
    local iter_num="${1:-?}"
    local iter_start=$SECONDS

    echo ""
    echo -e "${BLUE}══════════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${BLUE}  ECCN ITERATION #$iter_num  —  $(ts)${RESET}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════════════════${RESET}"

    local failed=false

    step_scan      || failed=true
    step_enrich    || true  # non-critical
    step_redact    || true  # non-critical
    step_deploy    || failed=true
    step_commit    || true  # non-critical (no changes = no commit)
    step_push      || failed=true
    step_health_check || true

    local elapsed=$((SECONDS - iter_start))

    if $failed; then
        echo ""
        log_error "ITERATION #$iter_num COMPLETE (${elapsed}s) — WITH FAILURES ⚠️"
    else
        echo ""
        log_info "ITERATION #$iter_num COMPLETE (${elapsed}s) — ALL STEPS OK ✅"
    fi
}

# ─── Main ─────────────────────────────────────────────────────────────────

main() {
    ensure_dirs
    source_env

    log_info "ECCEN 10-Minute Iteration Loop — STARTING"
    log_info "  Root:       $ROOT"
    log_info "  Interval:   ${ITERATION_INTERVAL_SECONDS}s ($((ITERATION_INTERVAL_SECONDS / 60))min)"
    log_info "  Push:       $PUSH_ENABLED"
    log_info "  Deploy:     $DEPLOY_BOTH_SITES"
    log_info "  Logs:       $LOG_DIR"

    local iteration=0

    if [ "${1:-}" = "--daemon" ]; then
        log_info "Running in DAEMON mode (Ctrl+C to stop)"
        while true; do
            iteration=$((iteration + 1))
            run_iteration "$iteration"
            log_info "Sleeping ${ITERATION_INTERVAL_SECONDS}s until next iteration..."
            sleep "$ITERATION_INTERVAL_SECONDS"
        done
    else
        iteration=1
        run_iteration "$iteration"
        log_info "Single iteration complete. Use --daemon for continuous mode."
    fi
}

main ${1+"$@"}
