#!/bin/bash
set -e
cd "$(dirname "$0")"
set -a; source .env; set +a
python3 -m venv .venv 2>/dev/null || true
.venv/bin/pip install -q -r requirements.txt
sudo systemctl restart storefront
echo "deployed $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
