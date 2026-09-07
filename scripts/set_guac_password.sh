#!/usr/bin/env bash
#
# Replace the default guacadmin / guacadmin credentials on the Guacamole
# Postgres database with a strong password.
#
#   ./scripts/set_guac_password.sh [password]
#
# With no argument a 24-char random password is generated and printed once.
# Run this AFTER `docker compose up -d guacamole_db` (the container must be
# healthy). Idempotent — safe to run again to rotate the password.
#
# Guacamole's scheme: password_hash = SHA256( password_bytes || salt_bytes ),
# with a fresh 32-byte random salt stored alongside it.

set -euo pipefail

PW="${1:-}"
if [[ -z "$PW" ]]; then
    PW="$(LC_ALL=C tr -dc 'A-Za-z0-9!@#%^_+=' </dev/urandom | head -c 24)"
    GENERATED=1
fi

SALT_HEX="$(LC_ALL=C tr -dc 'a-f0-9' </dev/urandom | head -c 64)"
# SHA256 over: the ASCII password bytes, then the raw salt bytes.
HASH_HEX="$(
    { printf '%s' "$PW"; printf '%s' "$SALT_HEX" | xxd -r -p; } \
    | openssl dgst -sha256 -binary | xxd -p -c 256
)"

DB_CONTAINER="${GUAC_DB_CONTAINER:-guacamole_db}"
DB_USER="${GUAC_DB_USER:-guacamole_user}"
DB_NAME="${GUAC_DB_NAME:-guacamole}"

docker exec -i "$DB_CONTAINER" psql -v ON_ERROR_STOP=1 -U "$DB_USER" -d "$DB_NAME" <<SQL
UPDATE guacamole_user
   SET password_hash = decode('${HASH_HEX}', 'hex'),
       password_salt = decode('${SALT_HEX}', 'hex'),
       password_date = now()
 WHERE entity_id = (
   SELECT entity_id FROM guacamole_entity
   WHERE name = 'guacadmin' AND type = 'USER'
 );
SQL

echo "Guacamole guacadmin password updated."
if [[ "${GENERATED:-0}" == "1" ]]; then
    echo
    echo "  guacadmin / ${PW}"
    echo
    echo "Store this now — it is not shown again. Consider setting GUAC_ADMIN_PASSWORD in .env."
fi
