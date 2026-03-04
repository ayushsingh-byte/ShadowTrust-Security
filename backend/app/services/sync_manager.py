import asyncio
import uuid
from sqlalchemy.future import select
from sqlalchemy import update
from app.db.sqlite_db import AsyncSessionLocal
from app.models.all_models import RawEventModel, StructuredEvent
from datetime import datetime

class SyncManager:
    """
    Background worker that fetches PENDING events from local SQLite 
    and batches them over into StructuredEvents (now also local).
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

            # 2. Map formats to Structured events expectations
            structured_payloads = []
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

                structured_payloads.append(
                    StructuredEvent(
                        id=str(uuid.uuid4()),
                        raw_event_id=evt.id,
                        session_id=evt.session_id, # Can be null if not yet correlated
                        timestamp=evt.timestamp if evt.timestamp else datetime.utcnow(),
                        honeypot_type=evt.honeypot_type,
                        event_type=evt.event_type,
                        details=details
                    )
                )
            
            # 3. Push to SQLite Local Structured Events
            try:
                db.add_all(structured_payloads)
                
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
