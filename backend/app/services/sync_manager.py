import asyncio
from sqlalchemy.future import select
from sqlalchemy import update
from app.db.sqlite_db import AsyncSessionLocal
from app.models.sqlite_models import RawEventModel
from app.db.supabase_client import supabase

class SyncManager:
    """
    Background worker that fetches PENDING events from local SQLite 
    and batches them over to Supabase for dashboard visualization.
    """
    BATCH_SIZE = 100

    @staticmethod
    async def run_sync_cycle():
        async with AsyncSessionLocal() as db:
            # 1. Fetch pending events
            result = await db.execute(
                select(RawEventModel)
                .where(RawEventModel.sync_status == "PENDING")
                .limit(SyncManager.BATCH_SIZE)
            )
            pending_events = result.scalars().all()
            
            if not pending_events:
                return 0

            # 2. Map formats to Supabase expectations
            supabase_payload = []
            for evt in pending_events:
                # Basic normalization
                details = {
                    "commands": evt.commands,
                    "uploaded_files": evt.uploaded_files,
                    "ports_scanned": evt.ports_scanned,
                    "geoip": evt.geoip_data,
                    "risk_score": evt.risk_score,
                    "protocol": evt.protocol,
                    "target_port": evt.target_port,
                    "attacker_ip": evt.attacker_ip
                }

                # Depending on the Session Engine, we might just pass raw_event_id 
                # and let another worker correlate sessions.
                supabase_payload.append({
                    "raw_event_id": evt.id,
                    "session_id": evt.session_id, # Can be null if not yet correlated
                    "timestamp": evt.timestamp.isoformat(),
                    "honeypot_type": evt.honeypot_type,
                    "event_type": evt.event_type,
                    "details": details
                })
            
            # 3. Push to Supabase
            try:
                # The python supabase client handles sync requests, we should wrap in executor if keeping pure async
                response = supabase.table("structured_events").insert(supabase_payload).execute()
                
                # 4. Mark as SYNCED locally on success
                ids_to_update = [evt.id for evt in pending_events]
                await db.execute(
                    update(RawEventModel)
                    .where(RawEventModel.id.in_(ids_to_update))
                    .values(sync_status="SYNCED")
                )
                await db.commit()
                return len(ids_to_update)
            except Exception as e:
                # Ignore for now, let it retry next cycle
                print(f"[SyncManager] Sync failed: {e}")
                return 0
