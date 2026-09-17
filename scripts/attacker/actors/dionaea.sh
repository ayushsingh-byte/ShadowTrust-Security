# Dionaea hunter: SMB negotiate, MSSQL, anonymous FTP.
for r in 1 2 3 4; do
  for p in "$SMB_P" "$MSSQL_P"; do
    printf '\x00\x00\x00\x2f\xff\x53\x4d\x42\x72\x00\x00\x00\x00' | nc -w2 "$DIONAEA" $p
  done
  { printf 'USER anonymous\r\n'; sleep 1; printf 'PASS a@b.c\r\n'; sleep 1; printf 'SYST\r\n'; printf 'LIST\r\n'; sleep 1; printf 'RETR /etc/passwd\r\n'; } | nc -w4 "$DIONAEA" "$FTP_P"
  sleep 2
done
