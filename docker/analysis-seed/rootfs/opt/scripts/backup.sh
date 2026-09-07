#!/bin/bash
# nightly db + uploads backup — cron 02:30 as deploy
set -euo pipefail
set -a; source /home/deploy/projects/storefront/.env; set +a
STAMP=$(date +%F)
mysqldump -u storefront -p"$DB_PASSWORD" storefront | gzip > /srv/backups/db_${STAMP}.sql.gz
tar czf /srv/backups/uploads_${STAMP}.tgz -C /var/www/html uploads
find /srv/backups -type f -mtime +14 -delete
