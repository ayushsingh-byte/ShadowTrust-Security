import asyncio
from datetime import timedelta
from sqlalchemy.future import select
from app.db.sqlite_db import AsyncSessionLocal
from app.models.sqlite_models import RawEventModel
from app.db.supabase_client import supabase

class SessionEngine:
    """
    Analyzes raw telemetry from SQLite/Supabase to map disparate events 
    into coherent 'Attacker Sessions' based on IP proximity and time windows.
    """
    SESSION_TIMEOUT_MINUTES = 30

    @staticmethod
    async def process_unmapped_events():
        """
        Periodically runs to correlate raw events into sessions.
        """
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(RawEventModel)
                .where(RawEventModel.session_id == None)
                .limit(500)
            )
            unmapped = result.scalars().all()

            if not unmapped:
                return

            # Group unmapped events by IP
            by_ip = {}
            for evt in unmapped:
                by_ip.setdefault(evt.attacker_ip, []).append(evt)

            # In a production scenario, we'd fetch the latest session per IP from Supabase
            # to see if we append to it, or create a new one.
            for ip, events in by_ip.items():
                print(f"[SessionEngine] Found {len(events)} new events for IP {ip}")
                # Placeholder for complex session chaining logic...
                
                # Assign a local session_id (e.g., using the earliest event timestamp)
                # Then update SQLite records
                # Then sync to attacker_sessions table in Supabase
                pass
