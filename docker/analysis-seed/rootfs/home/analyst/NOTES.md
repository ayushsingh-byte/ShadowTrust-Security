# incident triage — web-prod-01

context: suspicious POST bursts to /admin/login.php from 198.51.100.0/24

look at:
  - ~deploy/projects/storefront/logs/access.log   (the burst)
  - /var/www/html/admin/login.php                 (auth logic)
  - app/main.py /search endpoint                  (string-formatted SQL — injectable?)
  - /srv/backups                                  (were backups exfiltrated?)

this sandbox has NO network egress — connection attempts are logged and profiled.
