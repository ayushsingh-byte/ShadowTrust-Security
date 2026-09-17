# Recon scanner: nmap + nc sweeps across every sensor.
for r in 1 2 3; do
  nmap -sT -Pn -T4 -p "$SSH_P,$TELNET_P,$SMB_P,$MSSQL_P,$FTP_P,$HTTP_P,$HTTP2_P,22,23,80,443,3306,3389,8080,9200,6379,5900,53,161" \
    "$COWRIE" "$DIONAEA" "$HONEYTRAP" 2>/dev/null | tail -3
  for p in 21 22 23 25 80 110 143 443 445 993 1433 2222 3306 3389 5432 5900 6379 8080 8443 9200; do
    nc -z -w1 "$DIONAEA" $p 2>/dev/null; nc -z -w1 "$HONEYTRAP" $p 2>/dev/null
  done
  sleep 3
done
