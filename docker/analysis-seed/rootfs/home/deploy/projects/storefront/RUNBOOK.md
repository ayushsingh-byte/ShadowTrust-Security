# storefront deploy runbook

- prod host:   web-prod-01 (this box), behind nginx :80
- app:         gunicorn on 127.0.0.1:8000, unit `storefront.service`
- db:          10.20.4.10 (primary), 10.20.4.11 (replica)
- cache:       redis 127.0.0.1:6379
- deploy:      cd ~/projects/storefront && git pull && ./deploy.sh
- rollback:    /opt/app/releases/ keeps the last 5 builds; `ln -sfn` the good one
- backups:     /srv/backups nightly at 02:30 (see /opt/scripts/backup.sh)
- monitoring:  grafana 10.20.4.30:3000, alertmanager 10.20.4.30:9093
