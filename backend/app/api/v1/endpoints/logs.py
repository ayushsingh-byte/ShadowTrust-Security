from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.sqlite_db import get_db, AsyncSessionLocal
from app.models.all_models import Event, Attack
from ai_engine.classifier import AIEngine
from app.api.v1.dependencies import get_current_active_user, User

router = APIRouter()
ai_engine = AIEngine()

class LogEntry(BaseModel):
    source_ip: str
    payload: str
    protocol: str
    port: int
    timestamp: Optional[str] = None

async def process_log_background(log_id: str, payload: str, ip: str, port: int):
    # 1. AI Analysis
    analysis = ai_engine.analyze_log(payload, ip, port)
    
    # 2. Store Attack Data if malicious
    if analysis["severity"] != "INFO":
        try:
            async with AsyncSessionLocal() as session:
                attack_data = Attack(
                    log_id=log_id,
                    type=analysis["type"],
                    severity=analysis["severity"],
                    mitre_tactic=analysis["mitre"]["tactic"] if analysis["mitre"] else None,
                    mitre_id=analysis["mitre"]["id"] if analysis["mitre"] else None
                )
                session.add(attack_data)
                await session.commit()
        except Exception as e:
            print(f"Error storing attack: {e}")

@router.post("/")
async def ingest_log(
    log_in: LogEntry, 
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
    # Intentionally not depending on get_current_active_user so honeypot nodes without a JWT can hit this.
    # We might add a separate API key guard here later.
):
    # 1. Store Raw Log
    try:
        new_event = Event(
            src_ip=log_in.source_ip,
            payload=log_in.payload,
            protocol=log_in.protocol,
            type=str(log_in.port) # Using type column for port mapping compatibility
            # node_id could be added if passed
        )
        db.add(new_event)
        await db.commit()
        await db.refresh(new_event)
            
        log_id = str(new_event.id)
        
        # 2. Trigger AI Analysis in Background with Context
        background_tasks.add_task(process_log_background, log_id, log_in.payload, log_in.source_ip, log_in.port)
        
        return {"status": "success", "log_id": log_id}
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
