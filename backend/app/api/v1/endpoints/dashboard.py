from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.db.sqlite_db import get_db
from app.models.all_models import RawEventModel
from datetime import datetime, timedelta

router = APIRouter()

@router.get("/stats")
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)):
    # 1. Total Attacks
    total_attacks_query = await db.execute(select(func.count(RawEventModel.id)))
    total_attacks = total_attacks_query.scalar() or 0
    
    # 2. Unique Attackers
    unique_attackers_query = await db.execute(select(func.count(func.distinct(RawEventModel.attacker_ip))))
    unique_attackers = unique_attackers_query.scalar() or 0
    
    # 3. Recent Attacks (Live Feed)
    recent_query = await db.execute(
        select(RawEventModel)
        .order_by(desc(RawEventModel.timestamp))
        .limit(15)
    )
    recent_events = recent_query.scalars().all()
    
    # --- Advanced Analytics ---

    # 4. Traffic Chart (Last 60 Minutes)
    now = datetime.utcnow()
    one_hour_ago = now - timedelta(hours=1)
    
    # Get all events in the last hour
    hour_query = await db.execute(
        select(RawEventModel.timestamp, RawEventModel.protocol)
        .where(RawEventModel.timestamp >= one_hour_ago)
    )
    hour_events = hour_query.all()
    
    # Bucket into 60 minutes
    # Format: [ssh_count_array, http_count_array, malware_count_array]
    traffic_data = {
        "ssh": [0] * 60,
        "http": [0] * 60,
        "malware": [0] * 60
    }
    for event_ts, protocol in hour_events:
        if event_ts:
            delta_mins = int((now - event_ts).total_seconds() / 60)
            if 0 <= delta_mins < 60:
                idx = 59 - delta_mins # 59 is newest (right side of chart), 0 is oldest
                proto_lower = protocol.lower() if protocol else "unknown"
                if "ssh" in proto_lower or protocol == "22":
                    traffic_data["ssh"][idx] += 1
                elif "http" in proto_lower or protocol in ["80", "443"]:
                    traffic_data["http"][idx] += 1
                else:
                    traffic_data["malware"][idx] += 1 # Grouping everything else as generic/malware

    # 5. Top Attacker Networks (IPs for now since ASN requires lookup)
    top_ips_query = await db.execute(
        select(RawEventModel.attacker_ip, func.count(RawEventModel.id).label("hits"))
        .group_by(RawEventModel.attacker_ip)
        .order_by(desc("hits"))
        .limit(5)
    )
    top_ips = [{"asn": "UNKNOWN", "org": ip, "hits": hits, "risk": "HIGH" if hits > 50 else "MEDIUM"} for ip, hits in top_ips_query.all()]
    
    # 6. Exploit Vectors by Port
    top_ports_query = await db.execute(
        select(RawEventModel.target_port, func.count(RawEventModel.id).label("count"))
        .group_by(RawEventModel.target_port)
        .order_by(desc("count"))
        .limit(5)
    )
    
    port_map = {22: "SSH", 80: "HTTP", 443: "HTTPS", 23: "TELNET", 445: "SMB", 3389: "RDP"}
    top_ports = [{"port": port or 0, "service": port_map.get(port, "UNKNOWN"), "threat": "HIGH", "count": count} for port, count in top_ports_query.all()]
    
    # 7. Protocol Anomaly Radar ['SSH', 'HTTP', 'RDP', 'SMB', 'TELNET', 'FTP']
    radar_counts = {"SSH": 0, "HTTP": 0, "RDP": 0, "SMB": 0, "TELNET": 0, "FTP": 0}
    for port, count in top_ports_query.all():
        if port == 22: radar_counts["SSH"] += count
        elif port in [80, 443]: radar_counts["HTTP"] += count
        elif port == 3389: radar_counts["RDP"] += count
        elif port == 445: radar_counts["SMB"] += count
        elif port == 23: radar_counts["TELNET"] += count
        elif port in [20, 21]: radar_counts["FTP"] += count
    
    radar_data = [radar_counts["SSH"], radar_counts["HTTP"], radar_counts["RDP"], radar_counts["SMB"], radar_counts["TELNET"], radar_counts["FTP"]]

    # 8. Recent Artifacts/Payloads (using unique event_types or commands)
    recent_payloads_query = await db.execute(
        select(RawEventModel.event_type, RawEventModel.honeypot_type)
        .where(RawEventModel.event_type != None)
        .order_by(desc(RawEventModel.timestamp))
        .limit(20)
    )
    
    # Filter for unique ones
    seen = set()
    artifacts = []
    for evt_type, hp_type in recent_payloads_query.all():
        if evt_type not in seen:
            seen.add(evt_type)
            artifacts.append({
                "hash": "N/A", # Don't have actual file hashes yet
                "type": evt_type[:15], 
                "sensor": hp_type,
                "status": "QUARANTINED"
            })
            if len(artifacts) >= 5:
                break
    
    recent_data = [
        {
            "id": event.id,
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
            "attacker_ip": event.attacker_ip,
            "target_port": event.target_port,
            "protocol": event.protocol,
            "honeypot_type": event.honeypot_type,
            "event_type": event.event_type
        }
        for event in recent_events
    ]
    
    return {
        "summary": {
            "total_attacks": total_attacks,
            "unique_attackers": unique_attackers,
            "current_threat_level": "ELEVATED" if total_attacks > 1000 else "LOW"
        },
        "recent": recent_data,
        "traffic_chart": traffic_data,
        "top_attackers": top_ips,
        "top_vectors": top_ports,
        "protocol_radar": radar_data,
        "recent_artifacts": artifacts
    }
