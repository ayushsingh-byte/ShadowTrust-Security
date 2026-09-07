import json

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc, func
from datetime import datetime, timedelta

from app.db.database import get_db
from app.models.all_models import (
    Detection,
    Incident,
    NormalizedEventModel,
    RawEventModel,
    SystemConfig,
    User,
)
from app.api.v1.dependencies import get_current_active_user

router = APIRouter()

_ANNOTATIONS_KEY = "mitre_annotations"
_VALID_STATUS = {"observed", "investigating", "mitigated", "false-positive"}

# Small ATT&CK Enterprise catalogue for the "add technique" picker.
ATTACK_CATALOG = [
    {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
    {"id": "T1590", "name": "Gather Victim Network Information", "tactic": "Reconnaissance"},
    {"id": "T1589", "name": "Gather Victim Identity Information", "tactic": "Reconnaissance"},
    {"id": "T1587", "name": "Develop Capabilities", "tactic": "Resource Development"},
    {"id": "T1588", "name": "Obtain Capabilities", "tactic": "Resource Development"},
    {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    {"id": "T1133", "name": "External Remote Services", "tactic": "Initial Access"},
    {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
    {"id": "T1566", "name": "Phishing", "tactic": "Initial Access"},
    {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    {"id": "T1204", "name": "User Execution", "tactic": "Execution"},
    {"id": "T1053", "name": "Scheduled Task/Job", "tactic": "Execution"},
    {"id": "T1543", "name": "Create or Modify System Process", "tactic": "Persistence"},
    {"id": "T1136", "name": "Create Account", "tactic": "Persistence"},
    {"id": "T1547", "name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
    {"id": "T1505", "name": "Server Software Component", "tactic": "Persistence"},
    {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
    {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    {"id": "T1078.003", "name": "Local Accounts", "tactic": "Privilege Escalation"},
    {"id": "T1070", "name": "Indicator Removal", "tactic": "Defense Evasion"},
    {"id": "T1562", "name": "Impair Defenses", "tactic": "Defense Evasion"},
    {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},
    {"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"},
    {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery"},
    {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"},
    {"id": "T1018", "name": "Remote System Discovery", "tactic": "Discovery"},
    {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
    {"id": "T1570", "name": "Lateral Tool Transfer", "tactic": "Lateral Movement"},
    {"id": "T1560", "name": "Archive Collected Data", "tactic": "Collection"},
    {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
    {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
    {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    {"id": "T1572", "name": "Protocol Tunneling", "tactic": "Command and Control"},
    {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    {"id": "T1567", "name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},
    {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
    {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact"},
    {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
]

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


@router.get("/catalog")
async def mitre_catalog(_: User = Depends(get_current_active_user)):
    """ATT&CK technique list for the 'add technique' picker."""
    return {"techniques": ATTACK_CATALOG}


_CATALOG_BY_ID = {t["id"]: t for t in ATTACK_CATALOG}


@router.get("/analytics")
async def mitre_analytics(
    hours: int = 720,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_active_user),
):
    """
    Per observed technique: supporting-event count, source sensors, related
    incidents, confidence, first/last seen. Built live from the detection layer
    + honeypot events — the existing live matrix and analyst overlay are
    untouched.
    """
    since = datetime.utcnow() - timedelta(hours=max(1, hours))

    detections = (await db.execute(
        select(Detection).where(
            Detection.created_at >= since,
            Detection.attack_technique.isnot(None),
        )
    )).scalars().all()

    tech: dict = {}
    for d in detections:
        t = tech.setdefault(d.attack_technique, {
            "technique_id": d.attack_technique,
            "name": (_CATALOG_BY_ID.get(d.attack_technique, {}) or {}).get("name") or d.rule_name,
            "tactic": d.attack_tactic or (_CATALOG_BY_ID.get(d.attack_technique, {}) or {}).get("tactic"),
            "detection_ids": [], "event_ids": set(), "sensors": set(),
            "incident_ids": set(), "confidences": [],
            "first_seen": None, "last_seen": None,
        })
        t["detection_ids"].append(d.id)
        for eid in (d.matched_event_ids or []):
            t["event_ids"].add(eid)
        t["confidences"].append(d.confidence or 0.5)
        if d.incident_id:
            t["incident_ids"].add(d.incident_id)
        fe = d.first_event_at or d.created_at
        le = d.last_event_at or d.created_at
        if fe and (t["first_seen"] is None or fe < t["first_seen"]):
            t["first_seen"] = fe
        if le and (t["last_seen"] is None or le > t["last_seen"]):
            t["last_seen"] = le

    # attribute source sensors from the matched events
    all_event_ids = {eid for t in tech.values() for eid in t["event_ids"]}
    if all_event_ids:
        rows = (await db.execute(
            select(NormalizedEventModel.event_id, NormalizedEventModel.sensor)
            .where(NormalizedEventModel.event_id.in_(all_event_ids))
        )).all()
        sensor_of = {eid: s for eid, s in rows}
        for t in tech.values():
            for eid in t["event_ids"]:
                if sensor_of.get(eid):
                    t["sensors"].add(sensor_of[eid])

    out = []
    for t in tech.values():
        confs = t["confidences"]
        avg = sum(confs) / len(confs) if confs else 0.5
        out.append({
            "technique_id": t["technique_id"],
            "name": t["name"],
            "tactic": t["tactic"],
            "event_count": len(t["event_ids"]),
            "detection_count": len(t["detection_ids"]),
            "sensors": sorted(t["sensors"]),
            "incident_ids": sorted(t["incident_ids"]),
            "confidence": ("High" if avg >= 0.8 else "Medium" if avg >= 0.55 else "Low"),
            "confidence_value": round(avg, 2),
            "first_seen": t["first_seen"].isoformat() if t["first_seen"] else None,
            "last_seen": t["last_seen"].isoformat() if t["last_seen"] else None,
        })
    out.sort(key=lambda x: x["event_count"], reverse=True)
    return {"techniques": out, "count": len(out), "window_hours": hours}


@router.get("/annotations")
async def get_annotations(db: AsyncSession = Depends(get_db),
                          _: User = Depends(get_current_active_user)):
    """
    Operator overlay on the live matrix — per-technique {status, note, pinned,
    order, tactic, manual}. Shared across users (one JSON blob in system_config).
    """
    row = (await db.execute(select(SystemConfig).where(SystemConfig.key == _ANNOTATIONS_KEY))).scalars().first()
    try:
        data = json.loads(row.value) if row and row.value else {}
    except (ValueError, TypeError):
        data = {}
    return {"annotations": data}


class AnnotationsBody(BaseModel):
    annotations: dict


@router.put("/annotations")
async def put_annotations(body: AnnotationsBody,
                          db: AsyncSession = Depends(get_db),
                          _: User = Depends(get_current_active_user)):
    clean: dict = {}
    for tid, a in list(body.annotations.items())[:400]:
        if not isinstance(a, dict):
            continue
        entry = {
            "status": a.get("status") if a.get("status") in _VALID_STATUS else "observed",
            "note": str(a.get("note", ""))[:500],
            "pinned": bool(a.get("pinned", False)),
            "order": int(a.get("order", 0)) if str(a.get("order", 0)).lstrip("-").isdigit() else 0,
            "tactic": str(a.get("tactic", ""))[:60],
            "manual": bool(a.get("manual", False)),
            "name": str(a.get("name", ""))[:120],
        }
        clean[str(tid)[:20]] = entry

    payload = json.dumps(clean)
    if len(payload) > 200_000:
        return {"status": "error", "detail": "annotations blob too large"}

    row = (await db.execute(select(SystemConfig).where(SystemConfig.key == _ANNOTATIONS_KEY))).scalars().first()
    if row:
        row.value = payload
    else:
        db.add(SystemConfig(key=_ANNOTATIONS_KEY, value=payload))
    await db.commit()
    return {"status": "success", "count": len(clean)}
