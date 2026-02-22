
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional
from app.core.supabase import supabase
from ai_engine.classifier import AIEngine

router = APIRouter()
ai_engine = AIEngine()

class LogEntry(BaseModel):
    source_ip: str
    payload: str
    protocol: str
    port: int
    timestamp: Optional[str] = None

def process_log_background(log_id: str, payload: str, ip: str, port: int):
    # 1. AI Analysis
    analysis = ai_engine.analyze_log(payload, ip, port)
    
    # 2. Store Attack Data if malicious
    if analysis["severity"] != "INFO":
        attack_data = {
            "log_id": log_id,
            "type": analysis["type"],
            "severity": analysis["severity"],
            "mitre_tactic": analysis["mitre"]["tactic"] if analysis["mitre"] else None,
            "mitre_id": analysis["mitre"]["id"] if analysis["mitre"] else None
        }
        try:
            supabase.table("attacks").insert(attack_data).execute()
        except Exception as e:
            print(f"Error storing attack: {e}")

@router.post("/")
def ingest_log(log_in: LogEntry, background_tasks: BackgroundTasks):
    # 1. Store Raw Log
    try:
        raw_data = {
            "source_ip": log_in.source_ip,
            "payload": log_in.payload,
            "protocol": log_in.protocol,
            "port": log_in.port,
            "timestamp": log_in.timestamp
        }
        res = supabase.table("logs").insert(raw_data).execute()
        
        if not res.data:
            raise HTTPException(status_code=500, detail="Failed to store log")
            
        log_id = res.data[0]['id']
        
        # 2. Trigger AI Analysis in Background with Context
        background_tasks.add_task(process_log_background, log_id, log_in.payload, log_in.source_ip, log_in.port)
        
        return {"status": "success", "log_id": log_id}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
