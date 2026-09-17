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

# actor <name> — runs scripts/attacker/actors/<name>.sh in its own throwaway
# container (distinct source IP). Same actor files the admin "populate data"
# button uses (backend/app/services/data_admin.py).
actor() {
  local name="st-atk-$1-$RANDOM"
  docker run -d --rm --name "$name" --network "$EDGE_NET" \
    -e COWRIE="$COWRIE" -e DIONAEA="$DIONAEA" -e HONEYTRAP="$HONEYTRAP" \
    -e SSH_P=$SSH_P -e TELNET_P=$TELNET_P -e SMB_P=$SMB_P -e MSSQL_P=$MSSQL_P \
    -e FTP_P=$FTP_P -e HTTP_P=$HTTP_P -e HTTP2_P=$HTTP2_P \
    -e FAIL_PW="123456 password root toor 12345 admin 1234" \
    "$IMG" "$(cat "scripts/attacker/actors/$1.sh")" >/dev/null 2>&1 \
    && RUNNING+=("$name") && echo "    + $name"
}

wave() {
  echo "==> wave $1/$WAVES  ($(date +%H:%M:%S))"
  for a in mirai handson exfil recon web dionaea slowbrute; do actor "$a"; done
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
