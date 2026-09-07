#!/bin/bash
curl -sf http://127.0.0.1:8000/health >/dev/null || systemctl restart storefront
