from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, and_
from datetime import datetime, timedelta
import json


def _fmt_bytes(n: float) -> str:
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return f"{n:,.1f} {u}"
        n /= 1024.0
    return f"{n:,.1f} PB"

from app.db.database import get_db
from app.models.all_models import RawEventModel, NormalizedEventModel, Detection, Incident

# We can import fetch_geoip_batch from dashboard to reuse the cache
from app.api.v1.endpoints.dashboard import fetch_geoip_batch

from app.api.v1.dependencies import get_current_active_user

router = APIRouter(dependencies=[Depends(get_current_active_user)])

@router.get("/graphs")
async def get_analytics_graphs(
    db: AsyncSession = Depends(get_db),
    days: int = Query(7, description="Look-back window for the range buttons: 1, 7, or 30."),
):
    """
    Provides aggregated, structured data for all 10 Chart.js widgets on the Deep Analytics page.
    The ``days`` query param is driven by the Past 24H / 7 Days / 30 Days buttons.
    """
    days_sel = days if days in (1, 7, 30) else 7
    # Establish 'now' relative to the latest event so older test data still appears in graphs
    latest_res = await db.execute(select(RawEventModel.timestamp).order_by(desc(RawEventModel.timestamp)).limit(1))
    latest_ts = latest_res.scalar()
    now = latest_ts if latest_ts else datetime.utcnow()
    
    # Look-back window follows the range button the operator picked.
    window_start = now - timedelta(days=days_sel)

    # Pre-fetch recent events logic
    result = await db.execute(
        select(RawEventModel)
        .where(RawEventModel.timestamp >= window_start)
        .order_by(desc(RawEventModel.timestamp))
    )
    all_recent_events = result.scalars().all()
    
    total_in_7_days = len(all_recent_events)

    # --- 1. Cross-Sector Attack Volume (Main Line Chart) ---
    # Seven buckets spanning the selected window (bucket span scales with the
    # range button: 1d -> ~3.4h, 7d -> daily, 30d -> ~4.3d).
    N_MAIN = 7
    main_span_s = max(1.0, (days_sel * 86400) / N_MAIN)
    _fmt_main = "%H:%M" if days_sel <= 1 else "%m/%d"
    main_labels = [
        (now - timedelta(seconds=main_span_s * (N_MAIN - 1 - i))).strftime(_fmt_main)
        for i in range(N_MAIN)
    ]
    education_counts = [0] * N_MAIN
    defence_counts = [0] * N_MAIN
    
    # --- 3. Protocol Distribution (Pie Chart) ---
    # The lab remaps services off their well-known ports (Cowrie SSH 2222 / Telnet
    # 2223, Dionaea FTP 2121 / MSSQL 1433, Honeytrap HTTP 8022-8023), so each
    # bucket lists both the standard and the lab port.
    pie_counts = {"SSH": 0, "Telnet": 0, "HTTP": 0, "RDP": 0, "FTP": 0, "SMB": 0, "SQL": 0, "DNS": 0, "SIP": 0}
    _PROTO_PORTS = {
        "SSH": {22, 2222}, "Telnet": {23, 2223}, "HTTP": {80, 443, 8080, 8443, 8022, 8023, 9200},
        "RDP": {3389}, "FTP": {20, 21, 2121}, "SMB": {445, 139}, "SQL": {1433, 3306, 5432},
        "DNS": {53}, "SIP": {5060},
    }
    _WEB_PORTS = {80, 443, 8080, 8443, 8022, 8023, 9200, 5060}
    _SHELL_PORTS = {22, 23, 445, 3389, 2222, 2223, 2121, 1433, 3306, 139}
    
    # --- 4. Hourly Anomalies (Bar Chart) ---
    # Bucket into 4-hour intervals for today
    # Rolling last 24h, bucketed by hour-of-day — robust to a stray future-dated event
    hourly_window_start = now - timedelta(hours=24)
    hourly_labels = ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00"]
    hourly_counts = [0] * 6
    
    # --- 5. Geo-Origin Heatmap (Polar Area) ---
    ip_counter = {}
    
    # --- 6. Efficiency Correlation (Scatter Chart) ---
    scatter_critical = []
    scatter_minor = []

    # --- 8. Targeted Port Usage (Horizontal Bar) — built from the real top ports below ---
    port_hits = {}
    
    # --- 9. Insider Threat (Bubble) ---
    # We'll map internal IPs (10.*, 192.168.*) vs External IPs uploading files
    bubble_data = []
    
    # --- Metrics processing loop ---
    for evt in all_recent_events:
        _age_s = (now - evt.timestamp).total_seconds() if evt.timestamp else 0.0
        main_idx = N_MAIN - 1 - int(_age_s / main_span_s)

        _port = evt.target_port or 0

        # Sector split (web/app ports vs shell/auth ports) for the line chart
        if 0 <= main_idx < N_MAIN:
            if _port in _WEB_PORTS:
                education_counts[main_idx] += 1
            elif _port in _SHELL_PORTS:
                defence_counts[main_idx] += 1

        # Pie Chart — first matching protocol bucket
        for _proto, _ports in _PROTO_PORTS.items():
            if _port in _ports:
                pie_counts[_proto] += 1
                break

        # Hourly Anomalies
        if evt.timestamp and evt.timestamp >= hourly_window_start:
            hour_bucket = evt.timestamp.hour // 4
            if 0 <= hour_bucket < 6:
                hourly_counts[hour_bucket] += 1
                
        # Geo-Origin prep
        if evt.attacker_ip:
            ip_counter[evt.attacker_ip] = ip_counter.get(evt.attacker_ip, 0) + 1
            
        # (scatter is built below from real detection/incident timestamps)
                    
        # Horizontal Bar — real port tally
        if _port:
            port_hits[_port] = port_hits.get(_port, 0) + 1
        
        # Bubble Insider
        if evt.attacker_ip and (evt.attacker_ip.startswith("10.") or evt.attacker_ip.startswith("192.168.")):
            # Insider
            login_ops = int(evt.risk_score or 0)
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
    _brute_ports = {22, 21, 23, 3389, 2222, 2223, 2121}
    _web_atk_ports = {80, 443, 8080, 8443, 8022, 8023, 9200}
    brute_force = sum(1 for evt in all_recent_events if evt.target_port in _brute_ports)
    sqli = sum(
        1 for evt in all_recent_events
        if evt.target_port in _web_atk_ports
        and any(k in ((evt.commands or "") + (evt.raw_payload or "")).lower()
                for k in ("sql", "union select", "' or ", "1=1", "sqlmap"))
    )
    xss = sum(
        1 for evt in all_recent_events
        if evt.target_port in _web_atk_ports
        and any(k in ((evt.commands or "") + (evt.raw_payload or "")).lower()
                for k in ("<script", "onerror=", "javascript:", "alert("))
    ) or sum(1 for evt in all_recent_events if evt.target_port in _web_atk_ports)
    ddos = sum(hourly_counts) # proxy for traffic spikes
    _dl_re = ("wget", "curl", "tftp", "certutil", "|sh", "| sh", "|bash")
    malware = sum(
        1 for evt in all_recent_events
        if evt.uploaded_files or any(k in (evt.commands or "").lower() for k in _dl_re)
    )
    phishing = sum(
        1 for e in all_recent_events
        if any(k in ((e.commands or "") + " " + (e.raw_payload or "")).lower()
               for k in ("phish", "credential", "login.php", "verify-account"))
    )
    
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
    # Five buckets across the selected window, same scheme as the main chart.
    N_MIX = 5
    mix_span_s = max(1.0, (days_sel * 86400) / N_MIX)
    _fmt_mix = "%H:%M" if days_sel <= 1 else "%m/%d"
    mixed_labels = [
        (now - timedelta(seconds=mix_span_s * (N_MIX - 1 - i))).strftime(_fmt_mix)
        for i in range(N_MIX)
    ]
    mixed_volume = [0] * 5
    mixed_severity = [0.0] * 5
    severity_counts = [0] * 5
    
    for evt in all_recent_events:
        if evt.timestamp:
            _mix_age_s = (now - evt.timestamp).total_seconds()
            idx = N_MIX - 1 - int(_mix_age_s / mix_span_s)
            if 0 <= idx < N_MIX:
                mixed_volume[idx] += 1
                mixed_severity[idx] += (evt.risk_score or 50) / 20 # scale 0-100 to 0-5
                severity_counts[idx] += 1
                
    for i in range(5):
        if severity_counts[i] > 0:
            mixed_severity[i] = round(mixed_severity[i] / severity_counts[i], 1)
            
    # --- 10. Ingest-rate chart (Area) — real events per 2-minute bucket, last 10 min ---
    now_ts = now.timestamp()
    sys_labels = ['10m', '8m', '6m', '4m', '2m', 'Now']
    sys_data = [0] * 6
    for evt in all_recent_events:
        if evt.timestamp:
            delta_mins = (now_ts - evt.timestamp.timestamp()) / 60
            if 0 <= delta_mins <= 10:
                bucket = min(5, int((10 - delta_mins) / 2))
                sys_data[bucket] += 1

    # --- real detection latency (TTD) & incident resolution time (TTR), in minutes ---
    _dets = (await db.execute(
        select(Detection).where(Detection.created_at >= window_start)
    )).scalars().all()
    for d in _dets:
        if d.created_at and d.first_event_at and d.created_at >= d.first_event_at:
            ttd = (d.created_at - d.first_event_at).total_seconds() / 60.0
            pt = {"x": round(ttd, 1), "y": round((d.confidence or 0) * 100, 1)}
            (scatter_critical if (d.severity or "").upper() == "CRITICAL" else scatter_minor).append(pt)
    _incs = (await db.execute(
        select(Incident).where(Incident.status.in_(["CONTAINED", "RESOLVED", "FALSE_POSITIVE"]))
    )).scalars().all()
    for i in _incs:
        if i.updated_at and i.created_at and i.updated_at > i.created_at:
            ttr = (i.updated_at - i.created_at).total_seconds() / 60.0
            scatter_critical.append({"x": round(ttr, 1), "y": round(i.risk_score or 0, 1)})
    scatter_critical = scatter_critical[:60]
    scatter_minor = scatter_minor[:60]

    # --- real KPI inputs ---
    total_bytes = sum(len((e.raw_payload or "")) for e in all_recent_events)
    _norm = (await db.execute(
        select(func.count(NormalizedEventModel.event_id)).where(NormalizedEventModel.timestamp >= window_start)
    )).scalar() or 0
    _inc_total = (await db.execute(select(func.count(Incident.id)))).scalar() or 0
    _inc_fp = (await db.execute(
        select(func.count(Incident.id)).where(Incident.status == "FALSE_POSITIVE")
    )).scalar() or 0
    fp_rate = (100.0 * _inc_fp / _inc_total) if _inc_total else 0.0
    norm_rate = (100.0 * _norm / total_in_7_days) if total_in_7_days else 0.0

    # --- Compile total response ---
    return {
        "kpi": {
            "processed": _fmt_bytes(total_bytes),
            "threat_intel": f"{len(ip_counter)} IPs",
            "false_positives": f"{fp_rate:.1f}%",
            "normalization_rate": f"{norm_rate:.0f}%",
        },
        "charts": {
            "main": {
                "labels": main_labels,
                "education": education_counts,
                "defence": defence_counts
            },
            "radar": {
                "data": radar_data
            },
            "pie": {
                # Legacy 5-value array (SSH/HTTP/RDP/FTP/DNS) plus dynamic labels+data
                # so the chart shows every protocol that actually saw traffic.
                "data": [pie_counts["SSH"], pie_counts["HTTP"], pie_counts["RDP"], pie_counts["FTP"], pie_counts["DNS"]],
                **(lambda items: {"labels": [k for k, _ in items], "values": [v for _, v in items]})(
                    sorted(((k, v) for k, v in pie_counts.items() if v), key=lambda x: x[1], reverse=True)
                ),
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
                **(lambda top: {
                    "labels": [f"Port {p}" + ({22: " (SSH)", 2222: " (SSH)", 445: " (SMB)", 80: " (HTTP)",
                                               8022: " (HTTP)", 8023: " (HTTP)", 3389: " (RDP)", 1433: " (MSSQL)",
                                               2121: " (FTP)", 2223: " (Telnet)", 23: " (Telnet)", 53: " (DNS)"}.get(p, ""))
                               for p, _ in top],
                    "data": [c for _, c in top],
                })(sorted(port_hits.items(), key=lambda x: x[1], reverse=True)[:8]),
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
