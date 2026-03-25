from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, and_
from datetime import datetime, timedelta
import json

from app.db.sqlite_db import get_db
from app.models.all_models import RawEventModel

# We can import fetch_geoip_batch from dashboard to reuse the cache
from app.api.v1.endpoints.dashboard import fetch_geoip_batch

router = APIRouter()

@router.get("/graphs")
async def get_analytics_graphs(
    db: AsyncSession = Depends(get_db),
):
    """
    Provides aggregated, structured data for all 10 Chart.js widgets on the Deep Analytics page.
    """
    # Establish 'now' relative to the latest event so older test data still appears in graphs
    latest_res = await db.execute(select(RawEventModel.timestamp).order_by(desc(RawEventModel.timestamp)).limit(1))
    latest_ts = latest_res.scalar()
    now = latest_ts if latest_ts else datetime.utcnow()
    
    # Still pull a 30-day window to ensure we get a good spread of data
    thirty_days_ago = now - timedelta(days=30)
    
    # Pre-fetch recent events logic
    result = await db.execute(
        select(RawEventModel)
        .where(RawEventModel.timestamp >= thirty_days_ago)
        .order_by(desc(RawEventModel.timestamp))
    )
    all_recent_events = result.scalars().all()
    
    total_in_7_days = len(all_recent_events)

    # --- 1. Cross-Sector Attack Volume (Main Line Chart) ---
    # We will simulate "Sectors" by distinguishing between Web/DB attacks vs Shell/Auth attacks
    # Format: { "labels": ["Mon", "Tue"...], "datasets": [...] }
    days = [(now - timedelta(days=i)).strftime("%a") for i in range(6, -1, -1)]
    education_counts = {day: 0 for day in days}
    defence_counts = {day: 0 for day in days}
    
    # --- 3. Protocol Distribution (Pie Chart) ---
    # Target Ports: SSH, HTTP, RDP, FTP, DNS
    pie_counts = {"SSH": 0, "HTTP": 0, "RDP": 0, "FTP": 0, "DNS": 0}
    
    # --- 4. Hourly Anomalies (Bar Chart) ---
    # Bucket into 4-hour intervals for today
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    hourly_labels = ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00"]
    hourly_counts = [0] * 6
    
    # --- 5. Geo-Origin Heatmap (Polar Area) ---
    ip_counter = {}
    
    # --- 6. Efficiency Correlation (Scatter Chart) ---
    scatter_critical = []
    scatter_minor = []

    # --- 8. Targeted Port Usage (Horizontal Bar) ---
    horizontal_ports = {"Port 445 (SMB)": 0, "Port 22 (SSH)": 0, "Port 80 (HTTP)": 0, "Port 3389 (RDP)": 0}
    
    # --- 9. Insider Threat (Bubble) ---
    # We'll map internal IPs (10.*, 192.168.*) vs External IPs uploading files
    bubble_data = []
    
    # --- Metrics processing loop ---
    for evt in all_recent_events:
        day_str = evt.timestamp.strftime("%a") if evt.timestamp else now.strftime("%a")
        
        # Sector Simulation (for Line Chart)
        if evt.target_port in [80, 443, 8080, 5060]:
            if day_str in education_counts: education_counts[day_str] += 1
        elif evt.target_port in [22, 23, 445, 3389]:
            if day_str in defence_counts: defence_counts[day_str] += 1
            
        # Pie Chart
        if evt.target_port in [22, 2222]: pie_counts["SSH"] += 1
        elif evt.target_port in [80, 443, 8080]: pie_counts["HTTP"] += 1
        elif evt.target_port == 3389: pie_counts["RDP"] += 1
        elif evt.target_port in [20, 21]: pie_counts["FTP"] += 1
        elif evt.target_port == 53: pie_counts["DNS"] += 1
        
        # Hourly Anomalies
        if evt.timestamp and evt.timestamp >= today_start:
            hour_bucket = evt.timestamp.hour // 4
            if 0 <= hour_bucket < 6:
                hourly_counts[hour_bucket] += 1
                
        # Geo-Origin prep
        if evt.attacker_ip:
            ip_counter[evt.attacker_ip] = ip_counter.get(evt.attacker_ip, 0) + 1
            
        # Scatter prep (simulate TTD/TTR based on Risk Score)
        if evt.risk_score:
            # Fake simulation math: higher risk -> faster detection, slower response
            ttd = max(1, int(100 - evt.risk_score) / 2) # 1 - 50 mins
            ttr = evt.risk_score * 2 # 0 - 200 mins
            if evt.risk_score >= 80:
                if len(scatter_critical) < 50: # Limit points
                    scatter_critical.append({"x": ttd, "y": ttr})
            elif evt.risk_score < 40:
                if len(scatter_minor) < 50:
                    scatter_minor.append({"x": ttd * 3, "y": ttr / 2})
                    
        # Horizontal Bar
        if evt.target_port == 445: horizontal_ports["Port 445 (SMB)"] += 1
        elif evt.target_port == 22: horizontal_ports["Port 22 (SSH)"] += 1
        elif evt.target_port == 80: horizontal_ports["Port 80 (HTTP)"] += 1
        elif evt.target_port == 3389: horizontal_ports["Port 3389 (RDP)"] += 1
        
        # Bubble Insider
        if evt.attacker_ip and (evt.attacker_ip.startswith("10.") or evt.attacker_ip.startswith("192.168.")):
            # Insider
            login_ops = 50 + (evt.risk_score or 0)
            data_exfil = len(evt.commands or "") + (10 if evt.uploaded_files else 0)
            radius = min(40, max(5, data_exfil))
            if len(bubble_data) < 20:
                bubble_data.append({"x": login_ops, "y": data_exfil, "r": radius, "risk": "HI" if radius > 20 else "LO"})

    # --- GeoIP Resolve for Polar Chart ---
    # Sort top 15 IPs to get Top Countries
    sorted_ips = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:15]
    top_ips = [ip for ip, count in sorted_ips]
    geo_map = await fetch_geoip_batch(top_ips)
    
    country_counts = {}
    for ip, count in sorted_ips:
        code = geo_map.get(ip, {}).get("code", "UN")
        if code and code != "INT":
            country_counts[code] = country_counts.get(code, 0) + count
            
    sorted_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    polar_labels = [c[0] for c in sorted_countries]
    polar_data = [c[1] for c in sorted_countries]
    
    # If not enough data, pad it
    while len(polar_labels) < 5:
        polar_labels.append("N/A")
        polar_data.append(0)

    # --- 2. Attack Vector Landscape (Radar) ---
    brute_force = sum([1 for evt in all_recent_events if evt.target_port in [22, 21, 3389]])
    sqli = sum([1 for evt in all_recent_events if evt.target_port in [80, 443] and ("sql" in (evt.commands or "").lower())])
    xss = sum([1 for evt in all_recent_events if evt.target_port in [80, 443] and ("script" in (evt.commands or "").lower())])
    ddos = sum(hourly_counts) # proxy for traffic spikes
    malware = sum([1 for evt in all_recent_events if evt.uploaded_files])
    phishing = len(scatter_minor) # proxy
    
    max_vector = max(1, brute_force, sqli, xss, ddos, malware, phishing)
    radar_data = [
        int((brute_force / max_vector) * 100),
        int((sqli / max_vector) * 100) or 5, # Minimums so chart doesn't collapse entirely
        int((xss / max_vector) * 100) or 5,
        int((ddos / max_vector) * 100),
        int((malware / max_vector) * 100) or 10,
        int((phishing / max_vector) * 100) or 15
    ]

    # --- 7. Mixed Chart (Malware Trends) ---
    # We will aggregate by the last 5 days instead of 5 weeks for higher resolution
    mixed_labels = [(now - timedelta(days=i)).strftime("%a") for i in range(4, -1, -1)]
    mixed_volume = [0] * 5
    mixed_severity = [0.0] * 5
    severity_counts = [0] * 5
    
    for evt in all_recent_events:
        if evt.timestamp:
            delta_days = (now - evt.timestamp).days
            if 0 <= delta_days < 5:
                idx = 4 - delta_days
                mixed_volume[idx] += 1
                mixed_severity[idx] += (evt.risk_score or 50) / 20 # scale 0-100 to 0-5
                severity_counts[idx] += 1
                
    for i in range(5):
        if severity_counts[i] > 0:
            mixed_severity[i] = round(mixed_severity[i] / severity_counts[i], 1)
            
    # --- 10. System Chart (Area) ---
    # Fake system loads based on real event volume in the last 10 minutes
    now_ts = now.timestamp()
    sys_labels = ['10m', '8m', '6m', '4m', '2m', 'Now']
    sys_data = [0] * 6
    for evt in all_recent_events:
        if evt.timestamp:
            delta_mins = (now_ts - evt.timestamp.timestamp()) / 60
            if delta_mins <= 10:
                bucket = int((10 - delta_mins) / 2)
                if 0 <= bucket < 6:
                    sys_data[bucket] += 2 # 2% cpu per event
                    
    sys_data = [min(100, max(5, val)) for val in sys_data] # Floor 5%, ceil 100%

    # --- Compile total response ---
    return {
        "kpi": {
            "processed": f"{(total_in_7_days * 0.12):.1f} MB", # Fake size multiplier
            "threat_intel": f"{len(ip_counter)} IPs",
            "false_positives": "0.4%",
            "decryption": "100%"
        },
        "charts": {
            "main": {
                "labels": days,
                "education": [education_counts[day] for day in days],
                "defence": [defence_counts[day] for day in days]
            },
            "radar": {
                "data": radar_data
            },
            "pie": {
                "data": [pie_counts["SSH"], pie_counts["HTTP"], pie_counts["RDP"], pie_counts["FTP"], pie_counts["DNS"]]
            },
            "bar": {
                "data": hourly_counts
            },
            "polar": {
                "labels": polar_labels,
                "data": polar_data
            },
            "scatter": {
                "critical": scatter_critical,
                "minor": scatter_minor
            },
            "mixed": {
                "labels": mixed_labels,
                "volume": mixed_volume,
                "severity": mixed_severity
            },
            "ports": {
                "data": [horizontal_ports["Port 445 (SMB)"], horizontal_ports["Port 22 (SSH)"], horizontal_ports["Port 80 (HTTP)"], horizontal_ports["Port 3389 (RDP)"]]
            },
            "bubble": {
                "data": bubble_data
            },
            "system": {
                "data": sys_data
            }
        }
    }

@router.get("/credentials")
async def get_credentials_vault(
    db: AsyncSession = Depends(get_db),
):
    """
    Extracts credentials (usernames and passwords) captured by honeypots from the raw payload logs.
    Also computes KPIs explicitly for the Credentials Vault dashboard.
    """
    now = datetime.utcnow()
    one_hour_ago = now - timedelta(hours=1)
    
    # Query for all events that might contain password in raw_payload
    result = await db.execute(
        select(RawEventModel)
        .where(
            and_(
                RawEventModel.raw_payload.isnot(None),
                RawEventModel.raw_payload.like('%"password"%')
            )
        )
        .order_by(desc(RawEventModel.timestamp))
        .limit(1000) # Limit to avoid massive payload
    )
    events = result.scalars().all()
    
    credentials_list = []
    root_attempts = 0
    weak_passwords_count = 0
    unique_fingerprints = set()
    events_last_hour = 0
    
    for evt in events:
        try:
            payload = json.loads(evt.raw_payload)
            username = payload.get("username")
            password = payload.get("password")
            
            # Additional validation to ensure it's a login attempt log
            if username and password:
                ts_str = evt.timestamp.strftime("%Y-%m-%d %H:%M:%S") if evt.timestamp else now.strftime("%Y-%m-%d %H:%M:%S")
                ip = evt.attacker_ip or payload.get("src_ip") or "Unknown"
                protocol = evt.protocol or payload.get("protocol") or "tcp"
                risk = getattr(evt, 'risk_score', 0) or 50.0
                
                credentials_list.append({
                    "timestamp": ts_str,
                    "target_protocol": protocol.upper(),
                    "username": username,
                    "password": password,
                    "source_ip": ip,
                    "risk_score": round(risk, 1)
                })
                
                # KPIs math
                if username.lower() == "root":
                    root_attempts += 1
                    
                if len(password) < 6 or password.lower() in ["123456", "admin", "password", "root", "kali", "test"]:
                    weak_passwords_count += 1
                    
                fingerprint = f"{ip}-{username}-{password}"
                unique_fingerprints.add(fingerprint)
                
                if evt.timestamp and evt.timestamp >= one_hour_ago:
                    events_last_hour += 1
                    
        except json.JSONDecodeError:
            continue
            
    # Velocity: attacks per minute in the last hour
    velocity = events_last_hour / 60.0
    
    return {
        "kpi": {
            "root_attempts": root_attempts,
            "unique_fingerprints": len(unique_fingerprints),
            "weak_passwords": weak_passwords_count,
            "velocity": round(velocity, 2)
        },
        "data": credentials_list
    }
