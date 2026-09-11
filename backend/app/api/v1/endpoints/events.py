from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
import uuid

from app.schemas.event import RawEventSchema
from app.models.all_models import RawEventModel
from app.db.database import get_db

from app.api.v1.dependencies import get_current_active_user, require_role

router = APIRouter(dependencies=[Depends(get_current_active_user)])

@router.post("/ingest")
async def ingest_telemetry(
    events: List[RawEventSchema],
    db: AsyncSession = Depends(get_db),
    _admin=Depends(require_role(["SUPER_ADMIN", "ADMIN"])),
):
    """
    High-throughput endpoint for honeypot agents to push structured logs.
    Writes raw telemetry directly to the database.
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

from sqlalchemy import select, desc
from app.api.v1.dependencies import get_current_active_user
from app.models.all_models import User

@router.get("/")
async def get_events(limit: int = 200, db: AsyncSession = Depends(get_db)):
    """
    Retrieves the raw telemetry events directly from the database for the Event Log page. 
    Only accessible to authenticated users.
    """
    try:
        query = await db.execute(
            select(RawEventModel)
            .order_by(desc(RawEventModel.timestamp))
            .limit(limit)
        )
        events = query.scalars().all()
        
        return [
            {
                "id": event.id,
                "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                "attacker_ip": event.attacker_ip,
                "target_port": event.target_port,
                "protocol": event.protocol,
                "honeypot_type": event.honeypot_type,
                "session_id": event.session_id,
                "event_type": event.event_type,
                "commands": event.commands,
                "uploaded_files": event.uploaded_files,
                "ports_scanned": event.ports_scanned,
                "geoip_data": event.geoip_data,
                "risk_score": event.risk_score,
                "raw_payload": event.raw_payload
            }
            for event in events
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch events: {str(e)}")

from ai_engine.classifier import AIEngine
import base64

ai_engine = AIEngine()

@router.get("/{event_id}/analyze")
async def analyze_event(
    event_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    On-demand advanced analysis of a specific honeypot event using the AI engine.
    Extracts the payload, dynamically identifies the attack type, maps it to MITRE,
    and returns a structured report for the frontend modal.
    """
    try:
        # Fetch the event
        result = await db.execute(
            select(RawEventModel).where(RawEventModel.id == event_id)
        )
        event = result.scalars().first()
        
        if not event:
            raise HTTPException(status_code=404, detail="Event not found")
            
        # Extract analysis inputs
        payload = event.raw_payload or event.commands or "{}"
        ip = event.attacker_ip
        port = event.target_port
        
        # Analyze using AIEngine
        analysis_result = ai_engine.analyze_log(payload=payload, ip=ip, port=port)
        
        # Format a decoded payload for readability (often payloads are hex/base64 encoded or raw JSON)
        decoded_payload = payload
        try:
            # Simple heuristic to decode if it looks like base64
            if len(payload) > 20 and not " " in payload and not "{" in payload:
                decoded_bytes = base64.b64decode(payload)
                decoded_payload = decoded_bytes.decode('utf-8')
        except:
            pass
            
        # Construct the advanced intelligence report response
        report = {
            "id": event.id,
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
            "attacker_ip": ip,
            "target_port": port,
            "protocol": event.protocol,
            "geo_ip": event.geoip_data.get("country_name", "Unknown") if event.geoip_data else "Unknown",
            "ai_analysis": {
                "detected_attack": analysis_result["type"],
                "severity": analysis_result["severity"],
                "mitre_mapping": analysis_result["mitre"]
            },
            "payload_data": {
                "raw": payload,
                "decoded": decoded_payload,
                "commands": event.commands,
                "uploaded_files": event.uploaded_files
            }
        }
        
        return {"status": "success", "report": report}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

