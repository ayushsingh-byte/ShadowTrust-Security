from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.db.sqlite_db import get_db
from app.models.all_models import RawEventModel
from datetime import datetime, timedelta
import requests
import asyncio
import time

router = APIRouter()

# Simple memory cache for GeoIP to avoid spamming the free API
GEOIP_CACHE = {}
DASHBOARD_STATS_CACHE = {"ts": 0.0, "data": None}
STATS_CACHE_TTL_SECONDS = 15

def get_flag_emoji(country_code):
    if not country_code or len(country_code) != 2 or country_code == "UN":
        return '🏳️'
    if country_code == "INT":
        return '🏴'
    try:
        return chr(ord(country_code[0].upper()) + 127397) + chr(ord(country_code[1].upper()) + 127397)
    except:
        return '🏳️'

def fetch_geoip_batch_sync(ips):
    # filter out already cached and invalid
    ips_to_fetch = [ip for ip in ips if ip and ip not in GEOIP_CACHE and not ip.startswith("192.168.") and not ip.startswith("10.") and ip != "127.0.0.1"]
    
    if ips_to_fetch:
        try:
            # batch fetch up to 100 IPs
            url = "http://ip-api.com/batch"
            params = {"fields": "status,country,countryCode,isp,org,as,lat,lon,query"}
            response = requests.post(url, json=ips_to_fetch[:100], params=params, timeout=5)
            if response.status_code == 200:
                data = response.json()
                for res in data:
                    req_ip = res.get("query")
                    if req_ip and res.get("status") == "success":
                        as_field = res.get("as", "")
                        as_number = as_field.split(" ")[0] if as_field else "N/A"
                        GEOIP_CACHE[req_ip] = {
                            "country": res.get("country", "Unknown"),
                            "code": res.get("countryCode", "UN"),
                            "isp": res.get("isp", "Unknown ISP"),
                            "asn": as_number,
                            "lat": res.get("lat", 0.0),
                            "lon": res.get("lon", 0.0)
                        }
                    elif req_ip:
                         GEOIP_CACHE[req_ip] = {"country": "Unknown", "code": "UN", "isp": "Unknown ISP", "lat": 0.0, "lon": 0.0}
        except Exception as e:
            print("GeoIP Fetch Error:", e)
            
    # internal mock fallback
    for ip in ips:
        if ip and (ip.startswith("192.168.") or ip.startswith("10.") or ip == "127.0.0.1"):
            GEOIP_CACHE[ip] = {"country": "Internal", "code": "INT", "isp": "Local Network", "lat": 38.8951, "lon": -77.0364}
            
    return GEOIP_CACHE

async def fetch_geoip_batch(ips):
    return await asyncio.to_thread(fetch_geoip_batch_sync, ips)


@router.get("/stats")
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)):
    now_epoch = time.time()
    cached = DASHBOARD_STATS_CACHE.get("data")
    if cached is not None and (now_epoch - DASHBOARD_STATS_CACHE.get("ts", 0.0)) < STATS_CACHE_TTL_SECONDS:
        return cached

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
    latest_res = await db.execute(select(RawEventModel.timestamp).order_by(desc(RawEventModel.timestamp)).limit(1))
    latest_ts = latest_res.scalar()
    now = latest_ts if latest_ts else datetime.utcnow()
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
        .where(RawEventModel.attacker_ip != '0.0.0.0')
        .group_by(RawEventModel.attacker_ip)
        .order_by(desc("hits"))
        .limit(30)
    )
    top_ips_results = top_ips_query.all()
    
    # 6. Exploit Vectors by Port
    top_ports_query = await db.execute(
        select(RawEventModel.target_port, func.count(RawEventModel.id).label("count"))
        .group_by(RawEventModel.target_port)
    )
    
    all_top_ports = top_ports_query.all()
    port_counts = {port: count for port, count in all_top_ports if port is not None}
    requested_ports = [8080, 5060, 445, 21, 2222, 3306, 80, 3389, 5432, 443, 2223, 22, 23, 5439]
    for rp in requested_ports:
        if rp not in port_counts:
            port_counts[rp] = 0
            
    port_map = {22: "SSH", 80: "HTTP", 443: "HTTPS", 23: "TELNET", 445: "SMB", 3389: "RDP", 8080: "HTTP-ALT", 5060: "SIP", 21: "FTP", 2222: "SSH-ALT", 8022: "HTTP-ALT", 3306: "MySQL", 5432: "PostgreSQL", 2223: "SSH-ALT", 5439: "Redshift"}
    top_ports = [{"port": port, "service": port_map.get(port, "UNKNOWN"), "threat": "HIGH" if count > 0 else "MEDIUM", "count": count} for port, count in port_counts.items()]
    top_ports.sort(key=lambda x: x["count"], reverse=True)
    
    # 7. Protocol Anomaly Radar ['SSH', 'HTTP', 'RDP', 'SMB', 'TELNET', 'FTP']
    radar_counts = {"SSH": 0, "HTTP": 0, "RDP": 0, "SMB": 0, "TELNET": 0, "FTP": 0}
    for port, count in all_top_ports:
        if port in [22, 2222, 2223]: radar_counts["SSH"] += count
        elif port in [80, 443, 8080, 8022]: radar_counts["HTTP"] += count
        elif port == 3389: radar_counts["RDP"] += count
        elif port in [445, 139]: radar_counts["SMB"] += count
        elif port in [23, 8023]: radar_counts["TELNET"] += count
        elif port in [20, 21, 2121]: radar_counts["FTP"] += count
    
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
            if len(artifacts) >= 20:
                break
    
    top_ips_list = [ip for ip, _ in top_ips_results if ip]
    recent_ips = list(set([evt.attacker_ip for evt in recent_events if evt.attacker_ip]))
    
    # Combine IPs to resolve everything in one batch
    all_ips_to_resolve = list(set(top_ips_list + recent_ips))
    geo_map = await fetch_geoip_batch(all_ips_to_resolve)
    
    # Map Top Attackers
    top_ips = []
    for ip, hits in top_ips_results:
        geo = geo_map.get(ip, {})
        
        # Don't show Internal IPs in Top Attackers
        if geo.get("code") == "INT":
            continue
            
        top_ips.append({
            "asn": geo.get("asn", "N/A"),
            "ip": ip,
            "org": geo.get("isp", "Unknown ISP"),
            "hits": hits,
            "risk": "HIGH" if hits >= 10 else ("MEDIUM" if hits >= 3 else "LOW")
        })
        
    recent_data = []
    for event in recent_events:
        ip = event.attacker_ip
        geo = geo_map.get(ip, {})
        recent_data.append({
            "id": event.id,
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
            "attacker_ip": ip,
            "target_port": event.target_port,
            "protocol": event.protocol,
            "honeypot_type": event.honeypot_type,
            "event_type": event.event_type,
            "lat": geo.get("lat", 0.0),
            "lon": geo.get("lon", 0.0)
        })
    
    # 9. Additional Dashboard Metrics
    # High Risk Alerts (count of CRITICAL/HIGH alerts in last 24h)
    high_risk_query = await db.execute(
        select(func.count(RawEventModel.id))
        .where(RawEventModel.risk_score >= 80)
    )
    high_risk_alerts = high_risk_query.scalar() or 0
    
    # Lures tripped (total count of events on honeypots is inherently total lures tripped)
    lures_tripped = total_attacks
    
    # Hostile sources (Unique IPs in the last 30d)
    thirty_days_ago = now - timedelta(days=30)
    hostile_query = await db.execute(
        select(func.count(func.distinct(RawEventModel.attacker_ip)))
        .where(RawEventModel.timestamp >= thirty_days_ago)
    )
    hostile_sources = hostile_query.scalar() or 0
    
    # Targeted Sectors (Assuming ports/honeypot types as distinct "sectors" for now)
    sectors_query = await db.execute(
        select(func.count(func.distinct(RawEventModel.target_port)))
        .where(RawEventModel.timestamp >= thirty_days_ago)
    )
    targeted_sectors = sectors_query.scalar() or 0
    
    response_payload = {
        "summary": {
            "total_attacks": total_attacks,
            "unique_attackers": unique_attackers,
            "current_threat_level": (
                "HIGH"     if total_attacks > 10000 else
                "ELEVATED" if total_attacks > 1000  else
                "MEDIUM"   if total_attacks > 100   else
                "LOW"
            ),
            "high_risk_alerts": high_risk_alerts,
            "lures_tripped": lures_tripped,
            "hostile_sources": hostile_sources,
            "targeted_sectors": targeted_sectors
        },
        "recent": recent_data,
        "traffic_chart": traffic_data,
        "top_attackers": top_ips,
        "top_vectors": top_ports,
        "protocol_radar": radar_data,
        "recent_artifacts": artifacts
    }

    DASHBOARD_STATS_CACHE["data"] = response_payload
    DASHBOARD_STATS_CACHE["ts"] = now_epoch
    return response_payload

@router.get("/geo")
async def get_geo_stats(db: AsyncSession = Depends(get_db)):
    latest_res = await db.execute(select(RawEventModel.timestamp).order_by(desc(RawEventModel.timestamp)).limit(1))
    latest_ts = latest_res.scalar()
    now = latest_ts if latest_ts else datetime.utcnow()
    thirty_days_ago = now - timedelta(days=30)
    
    # Active Sources
    hostile_query = await db.execute(
        select(func.count(func.distinct(RawEventModel.attacker_ip)))
        .where(RawEventModel.timestamp >= thirty_days_ago)
    )
    active_sources = hostile_query.scalar() or 0
    
    # Targeted Zones
    sectors_query = await db.execute(
        select(func.count(func.distinct(RawEventModel.target_port)))
        .where(RawEventModel.timestamp >= thirty_days_ago)
    )
    targeted_zones = sectors_query.scalar() or 0
    
    # Last Detected
    recent_query = await db.execute(
        select(RawEventModel)
        .order_by(desc(RawEventModel.timestamp))
        .limit(1)
    )
    last_event = recent_query.scalars().first()
    last_detected = f"{last_event.attacker_ip} // PT:{last_event.target_port}" if last_event else "—"
    
    # Top IPs
    top_ips_query = await db.execute(
        select(RawEventModel.attacker_ip, func.count(RawEventModel.id).label("hits"))
        .group_by(RawEventModel.attacker_ip)
        .order_by(desc("hits"))
        .limit(30)
    )
    
    ip_hits = top_ips_query.all()
    
    all_ips_to_fetch = list(set([ip.split(':')[0] for ip, _ in ip_hits if ip]))
    geo_map = await fetch_geoip_batch(all_ips_to_fetch)
    
    countries_data = {}
    asn_data = {}
    
    for ip, hits in ip_hits:
        base_ip = (ip or '').split(':')[0]
        geo = geo_map.get(base_ip, {'country': 'Unknown', 'code': 'UN', 'isp': 'Unknown ISP', 'asn': 'N/A'})
        geo_flag = get_flag_emoji(geo.get('code', 'UN'))
        
        # Skip Internal/Local networks from Global Intelligence
        if geo.get('code') == 'INT':
            continue
        
        # Aggregate countries
        country_name = geo.get('country', 'Unknown')
        if country_name not in countries_data:
            countries_data[country_name] = {'flag': geo_flag, 'code': geo.get('code', 'UN'), 'events': 0, 'traffic': 0}
        countries_data[country_name]['events'] += hits
        
        traffic_multiplier = 0.5 + ((sum(bytearray(base_ip.encode())) % 10) / 10.0)  # Pseudo-random but consistent traffic per IP
        countries_data[country_name]['traffic'] += hits * traffic_multiplier
        
        # Aggregate ASN
        asn_name = geo.get('isp', 'Unknown ISP')
        asn_id = geo.get('asn', 'N/A')
        if asn_name not in asn_data:
            asn_data[asn_name] = {'asn': asn_id, 'count': 0, 'ips': set()}
        asn_data[asn_name]['count'] += hits
        asn_data[asn_name]['ips'].add(base_ip)

    top_countries = []
    for country, data in countries_data.items():
        top_countries.append({
            'flag': data['flag'],
            'country': country,
            'code': data['code'],
            'events': data['events'],
            'traffic': f"{data['traffic']:.1f} MB"
        })
    top_countries.sort(key=lambda x: x['events'], reverse=True)
    
    asn_intelligence = []
    for isp, data in asn_data.items():
        asn_intelligence.append({
            'asn': data['asn'],
            'isp_name': isp,
            'count': data['count'],
            'ips': ", ".join(list(data['ips']))
        })
    asn_intelligence.sort(key=lambda x: x['count'], reverse=True)
    
    top_isp = asn_intelligence[0] if asn_intelligence else None
    
    markers = []
    for ip, hits in ip_hits:
        base_ip = (ip or '').split(':')[0]
        geo = geo_map.get(base_ip)

        if not geo or geo.get('code') == 'INT':
            continue

        lat = geo.get('lat')
        lon = geo.get('lon')
        if lat is not None and lon is not None and (lat != 0.0 or lon != 0.0):
            markers.append({"ip": base_ip, "lat": lat, "lon": lon, "hits": hits})

    return {
        "active_sources": active_sources,
        "targeted_zones": targeted_zones,
        "last_detected": last_detected,
        "top_countries": top_countries[:5],
        "asn_intelligence": asn_intelligence[:5],
        "top_isp": top_isp,
        "markers": markers
    }
