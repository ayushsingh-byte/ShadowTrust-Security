#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
#  Shadow Trust — Data Reset Script
#  Usage:  ./reset.sh
#
#  Clears attack data, demo sector data, and honeypot events from the database.
#  NEVER touches: users, passwords, credential tokens, audit logs, roles.
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB="$ROOT_DIR/backend/ingestion.db"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; }
info() { echo -e "  ${CYAN}→${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}⚠${RESET}  $1"; }
fail() { echo -e "  ${RED}✗${RESET}  $1"; }
hdr()  { echo -e "\n${BOLD}${CYAN}$1${RESET}"; }

# ── Check sqlite3 is available ────────────────────────────────────────────────
if ! command -v sqlite3 &>/dev/null; then
    fail "sqlite3 not found. Install it first:"
    echo "       macOS:  brew install sqlite"
    echo "       Ubuntu: sudo apt install sqlite3"
    exit 1
fi

# ── Check DB exists ───────────────────────────────────────────────────────────
if [[ ! -f "$DB" ]]; then
    fail "Database not found at: $DB"
    fail "Start the backend first with ./start.sh so the DB is created."
    exit 1
fi

# ── Menu ──────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Shadow Trust — Data Reset Utility${RESET}"
echo -e "${BOLD}══════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  ${YELLOW}⚠  User accounts and credentials are NEVER deleted.${RESET}"
echo ""
echo    "  Choose what to clear:"
echo ""
echo -e "  ${BOLD}1${RESET}  Demo sector data only"
echo    "     (sector_targets, sector_events)"
echo ""
echo -e "  ${BOLD}2${RESET}  Honeypot & attack data only"
echo    "     (raw_events, events, attacks, alerts, nodes, sessions, IOCs, payloads)"
echo ""
echo -e "  ${BOLD}3${RESET}  Everything  (demo + honeypot + attack data)"
echo    "     Full clean slate — keeps only user accounts & credentials"
echo ""
echo -e "  ${BOLD}q${RESET}  Quit — don't change anything"
echo ""
read -rp "  Enter choice [1/2/3/q]: " CHOICE

case "$CHOICE" in
    1|2|3) ;;
    q|Q|"") echo -e "\n  ${CYAN}No changes made.${RESET}\n"; exit 0 ;;
    *) fail "Invalid choice. Exiting."; exit 1 ;;
esac

# ── Confirm ───────────────────────────────────────────────────────────────────
echo ""
case "$CHOICE" in
    1) DESC="Demo sector data (sector_targets, sector_events)" ;;
    2) DESC="Honeypot & attack data (events, attacks, alerts, nodes, sessions, IOCs, payloads)" ;;
    3) DESC="ALL data — demo + honeypot + attacks (users/credentials kept)" ;;
esac

echo -e "  ${YELLOW}You are about to delete: ${BOLD}$DESC${RESET}"
read -rp "  Type 'yes' to confirm: " CONFIRM

if [[ "$CONFIRM" != "yes" ]]; then
    echo -e "\n  ${CYAN}Cancelled. No changes made.${RESET}\n"
    exit 0
fi

# ── Stop backend if running (avoids DB lock) ──────────────────────────────────
hdr "Checking for running backend..."
BACKEND_PIDS=$(lsof -ti tcp:8000 2>/dev/null || true)
if [[ -n "$BACKEND_PIDS" ]]; then
    warn "Backend is running on port 8000 — stopping it to avoid DB lock..."
    echo "$BACKEND_PIDS" | xargs kill -SIGTERM 2>/dev/null || true
    sleep 2
    ok "Backend stopped."
else
    ok "Backend not running — safe to proceed."
fi

# ── SQL helpers ───────────────────────────────────────────────────────────────
run_sql() {
    sqlite3 "$DB" "$1"
}

count_table() {
    sqlite3 "$DB" "SELECT COUNT(*) FROM $1 WHERE 1=1;" 2>/dev/null || echo "0"
}

delete_table() {
    local table="$1"
    local count
    count=$(count_table "$table")
    run_sql "DELETE FROM $table;"
    ok "Cleared ${BOLD}${table}${RESET}  (${YELLOW}${count} rows${RESET} removed)"
}

# ── Demo sector tables ────────────────────────────────────────────────────────
clear_demo() {
    hdr "Clearing demo sector data..."
    delete_table "sector_events"
    delete_table "sector_targets"
}

# ── Honeypot / attack tables ──────────────────────────────────────────────────
clear_honeypot() {
    hdr "Clearing honeypot & attack data..."

    # Events & attacks
    for tbl in structured_events raw_events events attacks; do
        run_sql "SELECT COUNT(*) FROM $tbl;" &>/dev/null && delete_table "$tbl" || true
    done

    # Sessions & profiles
    for tbl in attacker_sessions captured_payloads iocs alerts; do
        run_sql "SELECT COUNT(*) FROM $tbl;" &>/dev/null && delete_table "$tbl" || true
    done

    # Nodes (and their metrics via cascade)
    run_sql "SELECT COUNT(*) FROM nodes;" &>/dev/null && delete_table "nodes" || true

    # S3 sync state
    run_sql "SELECT COUNT(*) FROM s3_sync_state;" &>/dev/null && delete_table "s3_sync_state" || true

    # VM instances (NOT vm_profiles — those are templates)
    run_sql "SELECT COUNT(*) FROM vm_instances;" &>/dev/null && delete_table "vm_instances" || true
}

# ── Run selected operation ────────────────────────────────────────────────────
case "$CHOICE" in
    1) clear_demo ;;
    2) clear_honeypot ;;
    3) clear_demo; clear_honeypot ;;
esac

# ── Vacuum to reclaim disk space ──────────────────────────────────────────────
hdr "Vacuuming database..."
run_sql "VACUUM;"
ok "Database vacuumed — disk space reclaimed."

# ── Summary ───────────────────────────────────────────────────────────────────
hdr "What was NOT touched (safe):"
echo ""
for tbl in users credential_tokens credential_audit_log access_logs admin_activity_log system_settings system_config vm_profiles; do
    COUNT=$(count_table "$tbl" 2>/dev/null || echo "?")
    echo -e "  ${GREEN}✓${RESET}  ${BOLD}${tbl}${RESET}  (${COUNT} rows kept)"
done

echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${GREEN}  Reset complete. Start backend with ./start.sh${RESET}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════${RESET}"
echo ""
