from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.db.database import get_db
from app.models.all_models import RawEventModel
from app.services.telemetry.collector import local_collector
from datetime import datetime, timedelta
import requests
import asyncio
import ipaddress
import time

from app.api.v1.dependencies import get_current_active_user

router = APIRouter(dependencies=[Depends(get_current_active_user)])

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

def _is_internal(ip: str) -> bool:
    """RFC1918 / loopback / link-local (incl. 172.16/12 lab containers) — never geolocated."""
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def fetch_geoip_batch_sync(ips):
    # filter out already cached and invalid
    ips_to_fetch = [ip for ip in ips if ip and ip not in GEOIP_CACHE and not _is_internal(ip)]
    
    if ips_to_fetch:
        try:
            # batch fetch up to 100 IPs
            url = "http://ip-api.com/batch"
            params = {"fields": "status,country,countryCode,region,regionName,city,isp,org,as,lat,lon,query"}
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
                            "city": res.get("city") or None,
                            "region": res.get("regionName") or None,
                            "isp": res.get("isp", "Unknown ISP"),
                            "asn": as_number,
                            "lat": res.get("lat", 0.0),
                            "lon": res.get("lon", 0.0)
                        }
                    elif req_ip:
                         GEOIP_CACHE[req_ip] = {"country": "Unknown", "code": "UN", "city": None, "region": None, "isp": "Unknown ISP", "lat": 0.0, "lon": 0.0}
        except Exception as e:
            print("GeoIP Fetch Error:", e)
            
    # RFC1918 / loopback addresses -> labelled Internal (no external lookup)
    for ip in ips:
        if ip and _is_internal(ip):
            GEOIP_CACHE[ip] = {"country": "Internal", "code": "INT", "city": None, "region": None,
                                "isp": "Local Network", "lat": None, "lon": None}

    return GEOIP_CACHE

async def fetch_geoip_batch(ips):
    return await asyncio.to_thread(fetch_geoip_batch_sync, ips)

def most_specific_location(geo: dict) -> str | None:
    """City if resolved, else region, else None — never a bare country name.

    A country alone ("United States") tells an analyst almost nothing; if the
    lookup couldn't resolve anything finer, the caller should omit the
    location rather than print a country as if it were specific.
    """
    if not geo:
        return None
    city = geo.get("city")
    region = geo.get("region")
    country = geo.get("country")
    if city and country:
        return f"{city}, {country}"
    if city:
        return city
    if region and country:
        return f"{region}, {country}"
    if region:
        return region
    return None


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

    port_map = {
        21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS", 80: "HTTP",
        110: "POP3", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        1433: "MSSQL", 1521: "Oracle", 2222: "SSH-ALT", 2223: "SSH-ALT",
        3306: "MySQL", 3389: "RDP", 5060: "SIP", 5432: "PostgreSQL", 5439: "Redshift",
        5900: "VNC", 6379: "Redis", 8022: "HTTP-ALT", 8023: "TELNET-ALT", 8080: "HTTP-ALT",
        8443: "HTTPS-ALT", 9200: "Elasticsearch", 27017: "MongoDB",
    }

    def _port_threat(c: int) -> str:
        return "HIGH" if c >= 50 else ("MEDIUM" if c >= 10 else "LOW")

    # Only ports that have actually been hit — no zero-count padding.
    top_ports = [
        {"port": port, "service": port_map.get(port, "UNKNOWN"), "threat": _port_threat(count), "count": count}
        for port, count in port_counts.items() if count > 0
    ]
    top_ports.sort(key=lambda x: x["count"], reverse=True)
    top_ports = top_ports[:15]
    
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

    # 8. Recent distinct payloads / interactions. Prefer a captured command or an
    #    uploaded-file reference over a bare event type, and report the real
    #    disposition from the risk score instead of a canned "QUARANTINED".
    recent_payloads_query = await db.execute(
        select(
            RawEventModel.event_type, RawEventModel.honeypot_type,
            RawEventModel.commands, RawEventModel.uploaded_files, RawEventModel.risk_score,
        )
        .where(RawEventModel.event_type != None)
        .order_by(desc(RawEventModel.timestamp))
        .limit(60)
    )

    def _disposition(score: float) -> str:
        s = score or 0
        if s >= 80:
            return "BLOCKED"
        if s >= 40:
            return "FLAGGED"
        return "LOGGED"

    seen = set()
    artifacts = []
    for evt_type, hp_type, cmds, files, score in recent_payloads_query.all():
        label = (files or cmds or evt_type or "").strip().splitlines()[0][:40] if (files or cmds or evt_type) else evt_type
        key = label or evt_type
        if key and key not in seen:
            seen.add(key)
            artifacts.append({
                "hash": "file" if files else ("cmd" if cmds else "evt"),
                "type": label or (evt_type or "")[:40],
                "sensor": hp_type or "SYSTEM",
                "status": _disposition(score),
            })
            if len(artifacts) >= 15:
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
        internal = geo.get("code") == "INT"
        recent_data.append({
            "id": event.id,
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
            "attacker_ip": ip,
            "target_port": event.target_port,
            "protocol": event.protocol,
            "honeypot_type": event.honeypot_type,
            "event_type": event.event_type,
            "internal": internal,
            # No real coordinates for LAN traffic — leave null so the map plots
            # only genuine external attackers instead of a fake pin.
            "lat": None if internal else geo.get("lat"),
            "lon": None if internal else geo.get("lon"),
        })
    
    # 9. Additional Dashboard Metrics
    # High Risk Alerts (events scored >= 80)
    high_risk_alerts = (await db.execute(
        select(func.count(RawEventModel.id)).where(RawEventModel.risk_score >= 80)
    )).scalar() or 0

    # Lures tripped = real attacker *interactions* (login attempts, commands,
    # uploads, scans) — not bare TCP connects, so it differs from TOTAL EVENTS.
    lures_tripped = (await db.execute(
        select(func.count(RawEventModel.id)).where(
            (RawEventModel.commands.isnot(None))
            | (RawEventModel.uploaded_files.isnot(None))
            | (RawEventModel.ports_scanned.isnot(None))
            | (RawEventModel.event_type.like("%login%"))
            | (RawEventModel.event_type.like("%command%"))
            | (RawEventModel.event_type.like("%download%"))
            | (RawEventModel.event_type.like("%auth%"))
        )
    )).scalar() or 0

    # Hostile sources (Unique IPs in the last 30d)
    thirty_days_ago = now - timedelta(days=30)
    hostile_sources = (await db.execute(
        select(func.count(func.distinct(RawEventModel.attacker_ip)))
        .where(RawEventModel.timestamp >= thirty_days_ago)
    )).scalar() or 0

    # Targeted "sectors" = distinct ports probed in the last 30d
    targeted_sectors = (await db.execute(
        select(func.count(func.distinct(RawEventModel.target_port)))
        .where(RawEventModel.timestamp >= thirty_days_ago)
    )).scalar() or 0

    # Distinct payloads = unique captured commands + unique uploaded-file refs.
    # Falls back to distinct event types if the honeypots aren't capturing bodies.
    uniq_cmds = (await db.execute(
        select(func.count(func.distinct(RawEventModel.commands)))
        .where(RawEventModel.commands.isnot(None))
    )).scalar() or 0
    uniq_files = (await db.execute(
        select(func.count(func.distinct(RawEventModel.uploaded_files)))
        .where(RawEventModel.uploaded_files.isnot(None))
    )).scalar() or 0
    unique_payloads = uniq_cmds + uniq_files
    if unique_payloads == 0:
        unique_payloads = (await db.execute(
            select(func.count(func.distinct(RawEventModel.event_type)))
            .where(RawEventModel.event_type.isnot(None))
        )).scalar() or 0

    # Events scored in the last 24h + how many carry a non-trivial risk score —
    # the honest read on the "analysis engine" that classifies every event.
    day_ago = now - timedelta(hours=24)
    scored_24h = (await db.execute(
        select(func.count(RawEventModel.id)).where(RawEventModel.timestamp >= day_ago)
    )).scalar() or 0
    classified_24h = (await db.execute(
        select(func.count(RawEventModel.id))
        .where(RawEventModel.timestamp >= day_ago, RawEventModel.risk_score > 0)
    )).scalar() or 0

    # "Novel" high-risk patterns: distinct captured commands scored >= 80 (things
    # the honeypot saw that warrant a human look). Real query, not a placeholder.
    novel_patterns = (await db.execute(
        select(func.count(func.distinct(RawEventModel.commands)))
        .where(RawEventModel.risk_score >= 80, RawEventModel.commands.isnot(None))
    )).scalar() or 0

    collector = local_collector.status()
    online_sensors = 0
    total_sensors = 0
    try:
        from app.services.container_status import sensor_container_states
        for st in sensor_container_states().values():
            if not st.get("available"):
                continue
            total_sensors += 1
            if st.get("running"):
                online_sensors += 1
    except Exception:
        pass

    latest_event_iso = latest_ts.isoformat() if latest_ts else None

    # Engine is "ACTIVE" only if the collector loop actually ran recently.
    engine_live = bool(collector.get("running"))
    last_run = collector.get("last_run_at")
    if last_run:
        try:
            age = (datetime.utcnow() - datetime.fromisoformat(last_run)).total_seconds()
            engine_live = engine_live and age < max(120, collector.get("interval_seconds", 30) * 4)
        except ValueError:
            pass

    system_block = {
        "analysis_engine": {
            "state": "ACTIVE" if engine_live else "OFFLINE",
            "events_ingested": collector.get("events_ingested", 0),
            "cycles": collector.get("cycles", 0),
            "last_run_at": collector.get("last_run_at"),
            "last_cycle_at": collector.get("last_cycle_at"),
            "classified_24h": classified_24h,
            "scored_24h": scored_24h,
            "classified_pct": round(100 * classified_24h / scored_24h, 1) if scored_24h else 0.0,
            "last_error": collector.get("last_error"),
        },
        "deception": {
            "state": "ACTIVE" if online_sensors > 0 else "DEGRADED",
            "sensors_online": online_sensors,
            "sensors_total": total_sensors,
        },
        "novel_patterns": novel_patterns,
        "last_event_at": latest_event_iso,
        "generated_in_ms": round((time.time() - now_epoch) * 1000, 1),
    }

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
            "targeted_sectors": targeted_sectors,
            "unique_payloads": unique_payloads
        },
        "system": system_block,
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
    
    # Top IPs — real captured-payload bytes per source, not a synthetic estimate
    top_ips_query = await db.execute(
        select(
            RawEventModel.attacker_ip,
            func.count(RawEventModel.id).label("hits"),
            func.coalesce(func.sum(func.length(RawEventModel.raw_payload)), 0).label("bytes"),
        )
        .group_by(RawEventModel.attacker_ip)
        .order_by(desc("hits"))
        .limit(30)
    )

    ip_hits = top_ips_query.all()

    all_ips_to_fetch = list(set([row.attacker_ip.split(':')[0] for row in ip_hits if row.attacker_ip]))
    geo_map = await fetch_geoip_batch(all_ips_to_fetch)

    locations_data = {}
    asn_data = {}

    for row in ip_hits:
        base_ip = (row.attacker_ip or '').split(':')[0]
        geo = geo_map.get(base_ip, {'country': 'Unknown', 'code': 'UN', 'isp': 'Unknown ISP', 'asn': 'N/A'})

        # Skip Internal/Local networks from Global Intelligence
        if geo.get('code') == 'INT':
            continue

        # Aggregate by the most specific place we could resolve — never a
        # bare country name. Sources that only resolved to a country are
        # left out of this list entirely rather than mislabeled as precise.
        loc_name = most_specific_location(geo)
        if loc_name:
            if loc_name not in locations_data:
                locations_data[loc_name] = {
                    'flag': get_flag_emoji(geo.get('code', 'UN')), 'code': geo.get('code', 'UN'),
                    'events': 0, 'bytes': 0,
                }
            locations_data[loc_name]['events'] += row.hits
            locations_data[loc_name]['bytes'] += int(row.bytes or 0)

        # Aggregate ASN
        asn_name = geo.get('isp', 'Unknown ISP')
        asn_id = geo.get('asn', 'N/A')
        if asn_name not in asn_data:
            asn_data[asn_name] = {'asn': asn_id, 'count': 0, 'ips': set()}
        asn_data[asn_name]['count'] += row.hits
        asn_data[asn_name]['ips'].add(base_ip)

    top_locations = []
    for name, data in locations_data.items():
        top_locations.append({
            'flag': data['flag'],
            'location': name,
            'code': data['code'],
            'events': data['events'],
            'traffic': f"{data['bytes'] / (1024 * 1024):.2f} MB",
        })
    top_locations.sort(key=lambda x: x['events'], reverse=True)

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
    for row in ip_hits:
        base_ip = (row.attacker_ip or '').split(':')[0]
        geo = geo_map.get(base_ip)

        if not geo or geo.get('code') == 'INT':
            continue

        lat = geo.get('lat')
        lon = geo.get('lon')
        if lat is not None and lon is not None and (lat != 0.0 or lon != 0.0):
            markers.append({
                "ip": base_ip, "lat": lat, "lon": lon, "hits": row.hits,
                "location": most_specific_location(geo),
            })

    return {
        "active_sources": active_sources,
        "targeted_zones": targeted_zones,
        "last_detected": last_detected,
        "top_locations": top_locations[:5],
        "asn_intelligence": asn_intelligence[:5],
        "top_isp": top_isp,
        "markers": markers
    }


# ── Attack flow (Overview diagram) ──────────────────────────────────────────
FLOW_CACHE = {"ts": 0.0, "data": None}
FLOW_CACHE_TTL_SECONDS = 20
FLOW_TOP_SOURCES = 5
FLOW_MAX_DETECTIONS = 5000


def build_flow(source_rows, detection_rows, event_sensor, incident_status, status_counts):
    """Pure aggregation for /dashboard/flow, kept apart from the queries so it can be checked.

    source_rows:      [(source_ip, sensor, events)]
    detection_rows:   [(attack_technique, attack_tactic, matched_event_ids, incident_id)]
    event_sensor:     {event_id: sensor} for the first matched event of each detection
    incident_status:  {incident_id: status}
    status_counts:    [(status, cases)]
    """
    from collections import Counter

    per_source, per_sensor = Counter(), Counter()
    for ip, sensor, n in source_rows:
        per_source[ip] += n
        per_sensor[sensor] += n
    top = [ip for ip, _ in per_source.most_common(FLOW_TOP_SOURCES)]
    top_set = set(top)
    others = len(per_source) - len(top)

    source_sensor = Counter()
    for ip, sensor, n in source_rows:
        source_sensor[(ip if ip in top_set else "others", sensor)] += n

    sensor_technique, technique_case = Counter(), Counter()
    per_technique, tactic = Counter(), {}
    for technique, tac, matched, incident_id in detection_rows:
        if not technique:
            continue
        per_technique[technique] += 1
        tactic.setdefault(technique, tac)
        first = matched[0] if isinstance(matched, list) and matched else None
        sensor = event_sensor.get(first)
        if sensor:  # a detection whose first event is no longer stored is counted but not linked
            sensor_technique[(sensor, technique)] += 1
        status = incident_status.get(incident_id)
        if status:
            technique_case[(technique, status)] += 1

    sources = [{"id": ip, "label": ip, "events": per_source[ip]} for ip in top]
    if others > 0:
        sources.append({
            "id": "others",
            "label": f"{others} other address{'es' if others != 1 else ''}",
            "events": sum(n for ip, n in per_source.items() if ip not in top_set),
        })
    links = lambda c: [{"from": a, "to": b, "value": n} for (a, b), n in c.most_common()]
    return {
        "sources": sources,
        "sensors": [{"id": s, "events": n} for s, n in per_sensor.most_common()],
        "techniques": [{"id": t, "tactic": tactic.get(t), "detections": n} for t, n in per_technique.most_common()],
        "cases": [{"id": s, "cases": n} for s, n in status_counts if s],
        "links": {
            "source_sensor": links(source_sensor),
            "sensor_technique": links(sensor_technique),
            "technique_case": links(technique_case),
        },
    }


def _flow_selfcheck():
    """python -m app.api.v1.endpoints.dashboard is not practical (imports the app), so this is
    called from the endpoint's module by hand:  python -c "...; _flow_selfcheck()"."""
    out = build_flow(
        [("a", "cowrie", 5), ("b", "cowrie", 2), ("b", "dionaea", 4)] + [(f"x{i}", "cowrie", 1) for i in range(6)],
        [("T1110", "Credential Access", ["e1", "e2"], "i1"), ("T1110", "Credential Access", ["e9"], "i2"),
         ("T1059", "Execution", [], None), (None, None, ["e1"], "i1")],
        {"e1": "cowrie"}, {"i1": "NEW", "i2": "RESOLVED"}, [("NEW", 1), ("RESOLVED", 1)],
    )
    assert [s["id"] for s in out["sources"]][:2] == ["b", "a"] and out["sources"][-1]["id"] == "others"
    assert out["sources"][-1]["events"] == 3 and out["sources"][-1]["label"] == "3 other addresses"
    assert {s["id"]: s["events"] for s in out["sensors"]} == {"cowrie": 13, "dionaea": 4}
    assert sum(l["value"] for l in out["links"]["source_sensor"]) == 17
    assert {t["id"]: t["detections"] for t in out["techniques"]} == {"T1110": 2, "T1059": 1}
    assert out["links"]["sensor_technique"] == [{"from": "cowrie", "to": "T1110", "value": 1}]
    assert sorted((l["to"], l["value"]) for l in out["links"]["technique_case"]) == [("NEW", 1), ("RESOLVED", 1)]
    return "flow self-check ok"


@router.get("/flow")
async def get_attack_flow(db: AsyncSession = Depends(get_db)):
    """Counts for the Overview flow diagram, all read straight from the database:
    events per source address and sensor, which sensor's events matched which ATT&CK
    technique (by each detection's first matched event), and the status of the cases
    those detections were filed under."""
    from app.models.all_models import NormalizedEventModel as E, Detection as D, Incident as I

    now = time.time()
    if FLOW_CACHE["data"] and now - FLOW_CACHE["ts"] < FLOW_CACHE_TTL_SECONDS:
        return FLOW_CACHE["data"]

    source_rows = (await db.execute(
        select(E.source_ip, E.sensor, func.count()).group_by(E.source_ip, E.sensor)
    )).all()
    detection_rows = (await db.execute(
        select(D.attack_technique, D.attack_tactic, D.matched_event_ids, D.incident_id)
        .order_by(desc(D.created_at)).limit(FLOW_MAX_DETECTIONS)
    )).all()

    first_ids = list({m[0] for _, _, m, _ in detection_rows if isinstance(m, list) and m})
    event_sensor = {}
    for i in range(0, len(first_ids), 500):
        rows = (await db.execute(select(E.event_id, E.sensor).where(E.event_id.in_(first_ids[i:i + 500])))).all()
        event_sensor.update({eid: sensor for eid, sensor in rows})

    incident_status = {iid: status for iid, status in (await db.execute(select(I.id, I.status))).all()}
    status_counts = (await db.execute(select(I.status, func.count()).group_by(I.status))).all()

    data = build_flow(
        [tuple(r) for r in source_rows], [tuple(r) for r in detection_rows],
        event_sensor, incident_status, [tuple(r) for r in status_counts],
    )
    data["generated_at"] = datetime.utcnow().isoformat() + "Z"
    FLOW_CACHE.update(ts=now, data=data)
    return data
