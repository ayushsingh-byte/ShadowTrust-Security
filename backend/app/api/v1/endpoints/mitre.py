from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc
from datetime import datetime, timedelta

from app.db.sqlite_db import get_db
from app.models.all_models import RawEventModel
from app.api.v1.dependencies import get_current_active_user, User

router = APIRouter()

# --- MITRE ATT&CK Mapping Rules Engine ---
def map_to_mitre(event: RawEventModel):
    """
    Analyzes raw telemetry from honeypots and maps to MITRE ATT&CK Tactics & Techniques.
    Returns a dictionary of mapped findings or None if insignificant.
    """
    mapped_events = []
    
    # 1. Credential Access (T1110 - Brute Force)
    if event.target_port in [22, 21, 3389, 5900]:
        mapped_events.append({
            "tactic": "Credential Access",
            "id": "T1110",
            "technique": "Brute Force",
            "severity": "HIGH"
        })
        
    # 2. Initial Access (T1190 - Exploit Public-Facing Application)
    if event.target_port in [80, 443, 8080, 8443, 9200]:
        mapped_events.append({
            "tactic": "Initial Access",
            "id": "T1190",
            "technique": "Exploit Public-Facing Application",
            "severity": "CRITICAL"
        })
        
    # 3. Discovery (T1046 - Network Service Discovery)
    if "scan" in (event.event_type or "").lower() or event.ports_scanned:
        mapped_events.append({
            "tactic": "Discovery",
            "id": "T1046",
            "technique": "Network Service Discovery",
            "severity": "MEDIUM"
        })
        
    # 4. Execution (T1059 - Command and Scripting Interpreter)
    if event.commands or event.target_port == 23:
        mapped_events.append({
            "tactic": "Execution",
            "id": "T1059",
            "technique": "Command and Scripting Interpreter",
            "severity": "CRITICAL"
        })
        
    # 5. Command and Control (T1071 - Application Layer Protocol)
    if event.target_port in [53, 123, 161] or event.uploaded_files:
        mapped_events.append({
            "tactic": "Command and Control",
            "id": "T1071",
            "technique": "Application Layer Protocol",
            "severity": "HIGH"
        })
        
    # Fallback for generic connections
    if not mapped_events and event.target_port:
        mapped_events.append({
            "tactic": "Reconnaissance",
            "id": "T1595",
            "technique": "Active Scanning",
            "severity": "LOW"
        })
        
    return mapped_events


@router.get("/")
async def get_mitre_matrix(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Dynamically maps raw honeypot events to the MITRE ATT&CK framework.
    """
    try:
        # Fetch up to 200 recent events from the last 30 days relative to latest event
        latest_res = await db.execute(select(RawEventModel.timestamp).order_by(desc(RawEventModel.timestamp)).limit(1))
        latest_ts = latest_res.scalar()
        now = latest_ts if latest_ts else datetime.utcnow()
        thirty_days_ago = now - timedelta(days=30)
        
        result = await db.execute(
            select(RawEventModel)
            .where(RawEventModel.timestamp >= thirty_days_ago)
            .order_by(desc(RawEventModel.timestamp))
            .limit(200)
        )
        raw_events = result.scalars().all()

        # Initialize Matrix Structure
        matrix = {
            "Reconnaissance": [],
            "Resource Development": [],
            "Initial Access": [],
            "Execution": [],
            "Persistence": [],
            "Privilege Escalation": [],
            "Defense Evasion": [],
            "Credential Access": [],
            "Discovery": [],
            "Lateral Movement": [],
            "Collection": [],
            "Command and Control": [],
            "Exfiltration": [],
            "Impact": []
        }

        # Dynamically map events
        for event in raw_events:
            mapped_findings = map_to_mitre(event)
            for finding in mapped_findings:
                tactic = finding["tactic"]
                if tactic in matrix:
                    matrix[tactic].append({
                        "id": finding["id"],
                        "technique": finding["technique"],
                        "severity": finding["severity"],
                        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                        "raw_id": event.id
                    })
        
        return {"status": "success", "matrix": matrix}

    except Exception as e:
        return {"status": "error", "detail": str(e)}
