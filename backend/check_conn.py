"""Quick connectivity check against the application database (MariaDB).

Usage:  cd backend && .venv/bin/python check_conn.py
"""

import asyncio
import os

from dotenv import load_dotenv
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

load_dotenv()

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "mysql+aiomysql://shadowtrust:shadowtrust@localhost:3307/shadowtrust",
)

# Mask the password in logs.
_safe_url = DATABASE_URL
if "@" in DATABASE_URL and "//" in DATABASE_URL:
    prefix, rest = DATABASE_URL.split("//", 1)
    creds, host = rest.split("@", 1)
    user = creds.split(":", 1)[0]
    _safe_url = f"{prefix}//{user}:***@{host}"
print(f"URL: {_safe_url}")


async def main() -> int:
    engine = create_async_engine(DATABASE_URL)
    try:
        print("[*] Connecting to MariaDB...")
        async with engine.connect() as conn:
            version = (await conn.execute(text("SELECT VERSION()"))).scalar()
            try:
                users = (await conn.execute(text("SELECT COUNT(*) FROM users"))).scalar()
            except Exception:
                users = "table not created yet"
        print("[+] Connection successful!")
        print(f"[+] Server version: {version}")
        print(f"[+] users rows: {users}")
        return 0
    except Exception as e:  # noqa: BLE001
        print(f"[-] Connection failed: {e}")
        return 1
    finally:
        await engine.dispose()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
