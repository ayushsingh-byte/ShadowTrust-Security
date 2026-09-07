import os
import psycopg2
from psycopg2.extras import RealDictCursor
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class GuacamoleService:
    """
    Writes/removes Guacamole connection records in its Postgres database.

    Connection details default to the local Guacamole compose stack. Inside
    docker-compose the backend sets GUAC_DB_HOST=guacamole_db; a native
    `./start.sh` run leaves it at localhost (the guacamole_db port is published).
    Explicit constructor args still win, for tests.
    """

    def __init__(self, db_host=None, db_port=None, db_name=None, db_user=None, db_password=None):
        self.db_host = db_host or os.getenv("GUAC_DB_HOST", "localhost")
        self.db_port = db_port or os.getenv("GUAC_DB_PORT", "5432")
        self.db_name = db_name or os.getenv("GUAC_DB_NAME", "guacamole")
        self.db_user = db_user or os.getenv("GUAC_DB_USER", "guacamole_user")
        self.db_password = db_password or os.getenv("GUAC_DB_PASSWORD", "guacamole_password")

    def _get_connection(self):
        """Creates and returns a new Postgres connection to the Guacamole DB."""
        try:
            conn = psycopg2.connect(
                host=self.db_host,
                port=self.db_port,
                dbname=self.db_name,
                user=self.db_user,
                password=self.db_password
            )
            return conn
        except psycopg2.Error as e:
            logger.error(f"Failed to connect to Guacamole PostgreSQL: {e}")
            raise e

    def create_connection(self, lab_id: str, private_ip: str, protocol: str = "rdp", port: str = "3389", username: str = "", password: str = "") -> Optional[int]:
        """
        Dynamically provisions a new remote desktop connection profile inside the Guacamole database.
        Returns the generated connection ID used to map the iframe.
        """
        conn_name = f"lab-{lab_id}"
        
        try:
            with self._get_connection() as conn:
                with conn.cursor() as cursor:
                    # 1. Insert into guacamole_connection (The named profile)
                    # Note: We assign it to connection_group_id = 1 (typically the ROOT group)
                    # max_connections is set to 2 to allow shadowing if needed.
                    cursor.execute("""
                        INSERT INTO guacamole_connection (connection_name, protocol, max_connections, max_connections_per_user)
                        VALUES (%s, %s, %s, %s) RETURNING connection_id;
                    """, (conn_name, protocol, 2, 1))
                    
                    result = cursor.fetchone()
                    if not result:
                        raise Exception("Failed to insert into guacamole_connection.")
                    
                    connection_id = result[0]
                    
                    # 2. Insert the target routing parameters into guacamole_connection_parameter
                    params = [
                        (connection_id, 'hostname', private_ip),
                        (connection_id, 'port', str(port)),
                        (connection_id, 'security', 'any'), # Bypass strict NLA auth for labs
                        (connection_id, 'ignore-cert', 'true'),
                        (connection_id, 'resize-method', 'display-update')
                    ]
                    
                    if username:
                        params.append((connection_id, 'username', username))
                    if password:
                        params.append((connection_id, 'password', password))
                        
                    cursor.executemany("""
                        INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value)
                        VALUES (%s, %s, %s);
                    """, params)
                    
                    # Commit transaction
                    conn.commit()
                    logger.info(f"Successfully created Guacamole mapped connection {conn_name} targeting {private_ip}:{port}")
                    return connection_id
                    
        except Exception as e:
            logger.error(f"Error provisioning Guacamole connection {conn_name}: {e}")
            return None

    def delete_connection(self, connection_id: int) -> bool:
        """
        Removes a Guacamole connection to instantly revoke browser access to the VM.
        """
        try:
            with self._get_connection() as conn:
                with conn.cursor() as cursor:
                    # Due to Guacamole's default database schema, deleting the connection cascades and deletes the parameters.
                    cursor.execute("""
                        DELETE FROM guacamole_connection WHERE connection_id = %s;
                    """, (connection_id,))
                    
                    conn.commit()
                    logger.info(f"Successfully revoked Guacamole connection ID: {connection_id}")
                    return True
        except Exception as e:
            logger.error(f"Error removing Guacamole connection ID {connection_id}: {e}")
            return False
