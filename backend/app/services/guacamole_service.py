import psycopg2
from psycopg2.extras import RealDictCursor
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

# Note: In production, these should be loaded from environment variables or a secure secret store.
# For this lab environment orchestration, we'll initialize them through the service constructor.
class GuacamoleService:
    def __init__(self, db_host="localhost", db_port="5432", db_name="guacamole", db_user="guacamole_user", db_password="guacamole_password"):
        self.db_host = db_host
        self.db_port = db_port
        self.db_name = db_name
        self.db_user = db_user
        self.db_password = db_password

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
