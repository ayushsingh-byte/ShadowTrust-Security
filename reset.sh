#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
#  Shadow Trust — Data Reset Script
#  Usage:  ./reset.sh
#
#  Clears attack data and honeypot events from the database.
#  NEVER touches: users, passwords, credential tokens, audit logs, roles.
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# DB credentials come from the root .env (MARIADB_* — see .env.example).
if [[ -f "$ROOT_DIR/.env" ]]; then
    set -a; source "$ROOT_DIR/.env"; set +a
fi
MARIADB_USER="${MARIADB_USER:-shadowtrust}"
MARIADB_PASSWORD="${MARIADB_PASSWORD:-shadowtrust}"
MARIADB_DATABASE="${MARIADB_DATABASE:-shadowtrust}"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; }
info() { echo -e "  ${CYAN}→${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}⚠${RESET}  $1"; }
fail() { echo -e "  ${RED}✗${RESET}  $1"; }
hdr()  { echo -e "\n${BOLD}${CYAN}$1${RESET}"; }

# ── Check the MariaDB container is reachable ──────────────────────────────────
if ! command -v docker &>/dev/null; then
    fail "docker not found — the database runs as the 'db' container."
    exit 1
fi
if ! (cd "$ROOT_DIR" && docker compose exec -T db \
        mariadb -u"$MARIADB_USER" -p"$MARIADB_PASSWORD" "$MARIADB_DATABASE" \
        -e "SELECT 1;" </dev/null &>/dev/null); then
    fail "Can't reach the MariaDB 'db' container."
    fail "Start it first:  docker compose up -d db"
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
echo -e "  ${BOLD}2${RESET}  Honeypot & attack data"
echo    "     (raw_events, normalized_events, events, attacks, alerts, nodes, sessions, IOCs, payloads)"
echo ""
echo -e "  ${BOLD}3${RESET}  Everything  (same as 2 for now — keeps only user accounts & credentials)"
echo ""
echo -e "  ${BOLD}q${RESET}  Quit — don't change anything"
echo ""
read -rp "  Enter choice [2/3/q]: " CHOICE

case "$CHOICE" in
    2|3) ;;
    q|Q|"") echo -e "\n  ${CYAN}No changes made.${RESET}\n"; exit 0 ;;
    *) fail "Invalid choice. Exiting."; exit 1 ;;
esac

# ── Confirm ───────────────────────────────────────────────────────────────────
echo ""
case "$CHOICE" in
    2) DESC="Honeypot & attack data (events, attacks, alerts, nodes, sessions, IOCs, payloads)" ;;
    3) DESC="ALL data (users/credentials kept)" ;;
esac

echo -e "  ${YELLOW}You are about to delete: ${BOLD}$DESC${RESET}"
read -rp "  Type 'yes' to confirm: " CONFIRM

if [[ "$CONFIRM" != "yes" ]]; then
    echo -e "\n  ${CYAN}Cancelled. No changes made.${RESET}\n"
    exit 0
fi

# ── Stop backend if running (avoids DB lock) ──────────────────────────────────
# When the backend runs under docker-compose, port 8000 on the host is Docker
# Desktop's own port-forwarding, not a plain process — `lsof -ti tcp:8000`
# still finds a PID, but SIGTERM'ing it has been observed to take down Docker
# Desktop's whole VM (every container with it) rather than just the backend.
# `docker compose stop` asks the container to stop cleanly instead, so check
# for that case first and only fall back to a raw kill for a bare `uvicorn`
# process (the ./start.sh / manual dev flow), where a PID really is the
# backend itself.
hdr "Checking for running backend..."
RESTART_HINT="./start.sh"
DOCKER_BACKEND_STOPPED=0
if command -v docker &>/dev/null \
    && (cd "$ROOT_DIR" && docker compose ps backend 2>/dev/null) | grep -qi "Up\|running"; then
    warn "Backend is running in Docker — stopping the container to avoid DB lock..."
    (cd "$ROOT_DIR" && docker compose stop backend >/dev/null 2>&1) || true
    ok "Backend container stopped."
    DOCKER_BACKEND_STOPPED=1
    RESTART_HINT="docker compose up -d backend"
elif BACKEND_PIDS=$(lsof -ti tcp:8000 2>/dev/null) && [[ -n "$BACKEND_PIDS" ]]; then
    warn "Backend is running on port 8000 — stopping it to avoid DB lock..."
    echo "$BACKEND_PIDS" | xargs kill -SIGTERM 2>/dev/null || true
    sleep 2
    ok "Backend stopped."
else
    ok "Backend not running — safe to proceed."
fi

# ── SQL helpers ───────────────────────────────────────────────────────────────
# Every batch disables FK checks first so table-by-table DELETEs don't trip over
# each other's constraints. Each `docker compose exec` is its own DB session, so
# the setting is scoped to that one call.
mysql_exec() {
    # </dev/null so `docker compose exec` never swallows the script's own stdin
    # (the interactive menu reads from it).
    (cd "$ROOT_DIR" && docker compose exec -T db \
        mariadb -u"$MARIADB_USER" -p"$MARIADB_PASSWORD" "$MARIADB_DATABASE" -N -B -e "$1" </dev/null)
}

run_sql() {
    mysql_exec "SET FOREIGN_KEY_CHECKS=0; $1"
}

count_table() {
    mysql_exec "SELECT COUNT(*) FROM \`$1\`;" 2>/dev/null || echo "0"
}

delete_table() {
    local table="$1"
    local count
    count=$(count_table "$table")
    run_sql "DELETE FROM $table;"
    ok "Cleared ${BOLD}${table}${RESET}  (${YELLOW}${count} rows${RESET} removed)"
}

# ── Honeypot / attack tables ──────────────────────────────────────────────────
clear_honeypot() {
    hdr "Clearing honeypot & attack data..."

    # Events & attacks
    for tbl in structured_events raw_events events attacks; do
        run_sql "SELECT COUNT(*) FROM $tbl;" &>/dev/null && delete_table "$tbl" || true
    done

    # Local honeynet pipeline — normalized events plus their dedup state.
    # Both must go together: clearing normalized_events but leaving
    # ingest_cursors means the collector still thinks every sensor log line
    # up to the old byte offset is already ingested, so a re-read of the same
    # file after this reset would silently produce zero events instead of
    # repopulating the table.
    for tbl in normalized_events ingest_cursors; do
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

# ── Raw sensor telemetry files ────────────────────────────────────────────────
# Separate from the DB clear above: ingest_cursors tracks byte offsets into
# these exact files, so wiping the DB cursor without also truncating the file
# (or vice versa) leaves the two out of sync. Truncating in place (not
# deleting) keeps the bind-mounted path valid for a sensor container that
# still has the old inode open.
clear_telemetry_files() {
    hdr "Truncating raw sensor telemetry files..."
    local dir="$ROOT_DIR/telemetry/raw"
    local n=0
    if [[ -d "$dir" ]]; then
        while IFS= read -r -d '' f; do
            : > "$f"
            n=$((n + 1))
        done < <(find "$dir" -type f \( -name '*.json' -o -name '*.jsonl' -o -name '*.log' \) -print0)
    fi
    ok "Truncated ${BOLD}${n}${RESET} sensor log file(s) under telemetry/raw/"
}

# ── Run selected operation ────────────────────────────────────────────────────
case "$CHOICE" in
    2|3) clear_honeypot ;;
esac

# ── Optional: also wipe the raw sensor log files ──────────────────────────────
# Only offered alongside a honeypot clear. Skipping this leaves telemetry/raw/
# populated, which is fine (the collector's cursor was just cleared too, so
# those files get fully re-ingested) but is not a truly clean slate for a demo.
if [[ "$CHOICE" == "2" || "$CHOICE" == "3" ]]; then
    echo ""
    read -rp "  Also truncate raw sensor log files under telemetry/raw/? [y/N]: " WIPE_FILES
    if [[ "$WIPE_FILES" =~ ^[Yy]$ ]]; then
        clear_telemetry_files
    else
        warn "Raw sensor log files kept — they will be re-ingested from the start on next collector run."
    fi
fi

# ── Reclaim disk space ───────────────────────────────────────────────────────
# InnoDB frees deleted-row space back to the tablespace on its own; there is no
# VACUUM. OPTIMIZE TABLE would shrink the files but locks each table and is not
# worth it for a demo reset, so it's skipped.
ok "InnoDB reclaims freed space automatically — no VACUUM step needed."

# ── Summary ───────────────────────────────────────────────────────────────────
hdr "What was NOT touched (safe):"
echo ""
for tbl in users credential_tokens credential_audit_log access_logs admin_activity_log system_settings system_config vm_profiles; do
    COUNT=$(count_table "$tbl" 2>/dev/null || echo "?")
    echo -e "  ${GREEN}✓${RESET}  ${BOLD}${tbl}${RESET}  (${COUNT} rows kept)"
done

echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${GREEN}  Reset complete. Start backend with: ${RESTART_HINT}${RESET}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════${RESET}"
echo ""
