-- Runs once, the first time the MariaDB data directory is initialised
-- (mounted at /docker-entrypoint-initdb.d in docker-compose.yml).
--
-- Creates the schema the backend test suite uses and grants the application
-- user full rights on it. The main `shadowtrust` schema and user are created
-- by the image from the MARIADB_* environment variables.

CREATE DATABASE IF NOT EXISTS shadowtrust_test
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

GRANT ALL PRIVILEGES ON shadowtrust_test.* TO 'shadowtrust'@'%';
FLUSH PRIVILEGES;
