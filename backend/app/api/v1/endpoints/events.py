from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
import uuid

from app.schemas.event import RawEventSchema
from app.models.sqlite_models import RawEventModel
from app.db.sqlite_db import get_db

router = APIRouter()

@router.post("/ingest")
async def ingest_telemetry(events: List[RawEventSchema], db: AsyncSession = Depends(get_db)):
    """
    High-throughput endpoint for honeypot agents to push structured logs.
    Writes raw telemetry directly to local SQLite.
    """
    try:
        db_events = []
        for event in events:
            # Generate ID if none provided by agent
            evt_id = event.id if event.id else str(uuid.uuid4())
            
            new_event = RawEventModel(
                id=evt_id,
                timestamp=event.timestamp,
                attacker_ip=event.attacker_ip,
                target_port=event.target_port,
                protocol=event.protocol,
                honeypot_type=event.honeypot_type,
                session_id=event.session_id,
                event_type=event.event_type,
                commands=event.commands,
                uploaded_files=event.uploaded_files,
                ports_scanned=event.ports_scanned,
                geoip_data=event.geoip_data,
                risk_score=event.risk_score,
                raw_payload=event.raw_payload,
                sync_status="PENDING"
            )
            db_events.append(new_event)
            
        db.add_all(db_events)
        await db.commit()
        
        return {"status": "success", "inserted_count": len(db_events)}
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
