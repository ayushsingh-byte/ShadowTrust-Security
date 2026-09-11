"""Operational SOC report providers — executive summary, geo intel, credentials,
incident, forensic/DFIR, detection validation, malware.

Every figure is pulled live from the application database or an existing service
function over the requested time window. No value is synthesised in this module;
where a data source is empty the provider returns an explicit "no data" marker so
the template can say so honestly rather than drop the section.
"""
from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List

from sqlalchemy import and_, case, desc, distinct, func, or_, select

from app.models.all_models import (
    AttackerSession, CredentialAuditLog, Detection, Evidence, Incident,
    IncidentActivity, IncidentEvent, IncidentIOC, IOCObservation,
    NormalizedEventModel, RawEventModel, ScenarioRun,
)
from .base import (
    bar_items, clip, delta, fmt_ts, kpi, kpis, note, parse_window, pct,
    prev_window, sev, status, table, text,
)

_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _looks_ip(v: str | None) -> bool:
    if not v:
        return False
    try:
        ipaddress.ip_address(v.split(":")[0])
        return True
    except ValueError:
        return False


def _is_internal(v: str | None) -> bool:
    try:
        return ipaddress.ip_address((v or "").split(":")[0]).is_private
    except ValueError:
        return False


async def _scalar(db, stmt) -> int:
    return (await db.execute(stmt)).scalar() or 0


def _win(col, start, end):
    if start is None:
        return col <= end
    return and_(col >= start, col <= end)


# ── executive summary ────────────────────────────────────────────────────────
async def executive_summary(db, params, user) -> Dict[str, Any]:
    start, end = parse_window(params)
    p_start, p_end = prev_window(start, end)
    NE = NormalizedEventModel

    total = await _scalar(db, select(func.count(NE.event_id)).where(_win(NE.timestamp, start, end)))
    uniq = await _scalar(db, select(func.count(distinct(NE.source_ip))).where(_win(NE.timestamp, start, end)))
    interactions = await _scalar(db, select(func.count(NE.event_id)).where(
        _win(NE.timestamp, start, end), or_(NE.command.isnot(None), NE.username.isnot(None))))
    det_total = await _scalar(db, select(func.count(Detection.id)).where(_win(Detection.created_at, start, end)))
    inc_total = await _scalar(db, select(func.count(Incident.id)).where(_win(Incident.created_at, start, end)))
    inc_open = await _scalar(db, select(func.count(Incident.id)).where(
        Incident.status.notin_(["RESOLVED", "FALSE_POSITIVE"])))

    # trend vs previous equal window
    p_total = p_uniq = p_det = 0
    if p_start is not None:
        p_total = await _scalar(db, select(func.count(NE.event_id)).where(_win(NE.timestamp, p_start, p_end)))
        p_uniq = await _scalar(db, select(func.count(distinct(NE.source_ip))).where(_win(NE.timestamp, p_start, p_end)))
        p_det = await _scalar(db, select(func.count(Detection.id)).where(_win(Detection.created_at, p_start, p_end)))

    # severity breakdown (events)
    sev_rows = (await db.execute(
        select(NE.severity, func.count(NE.event_id)).where(_win(NE.timestamp, start, end)).group_by(NE.severity)
    )).all()
    sev_map = {(s or "INFO").upper(): c for s, c in sev_rows}
    severity_breakdown = [
        {"label": s, "count": sev_map.get(s, 0), "pct": pct(sev_map.get(s, 0), total)}
        for s in _SEV_ORDER if sev_map.get(s)
    ]

    # detection severity
    det_sev = (await db.execute(
        select(Detection.severity, func.count(Detection.id))
        .where(_win(Detection.created_at, start, end)).group_by(Detection.severity)
    )).all()
    detection_sev = [[sev(s), c] for s, c in sorted(det_sev, key=lambda r: _SEV_ORDER.index((r[0] or "LOW").upper())
                                                    if (r[0] or "LOW").upper() in _SEV_ORDER else 9)]

    # tactic breakdown from detections
    tac = (await db.execute(
        select(Detection.attack_tactic, func.count(Detection.id))
        .where(_win(Detection.created_at, start, end), Detection.attack_tactic.isnot(None))
        .group_by(Detection.attack_tactic).order_by(desc(func.count(Detection.id)))
    )).all()
    tactic_bars = bar_items([(t or "—", c) for t, c in tac])

    # top ports
    ports = (await db.execute(
        select(NE.destination_port, func.count(NE.event_id))
        .where(_win(NE.timestamp, start, end), NE.destination_port.isnot(None))
        .group_by(NE.destination_port).order_by(desc(func.count(NE.event_id))).limit(12)
    )).all()
    port_rows = [[p, _PORTS.get(p, "—"), c] for p, c in ports]

    # top threats — per source IP
    succ = func.sum(case((NE.authentication_result == "SUCCESS", 1), else_=0))
    tt = (await db.execute(
        select(NE.source_ip,
               func.count(NE.event_id).label("events"),
               func.count(distinct(NE.sensor)).label("sensors"),
               func.count(distinct(NE.destination_port)).label("ports"),
               succ.label("succ"),
               func.min(NE.timestamp).label("first"),
               func.max(NE.timestamp).label("last"))
        .where(_win(NE.timestamp, start, end))
        .group_by(NE.source_ip).order_by(desc("events")).limit(12)
    )).all()
    det_by_ip = dict((await db.execute(
        select(Detection.source_ip, func.count(Detection.id)).group_by(Detection.source_ip)
    )).all())
    top_threats = [[
        r.source_ip, r.events, r.sensors, r.ports, det_by_ip.get(r.source_ip, 0),
        int(r.succ or 0), fmt_ts(r.first), fmt_ts(r.last),
    ] for r in tt]

    # sensor health
    sh = (await db.execute(
        select(NE.sensor, func.count(NE.event_id), func.max(NE.timestamp))
        .where(_win(NE.timestamp, start, end)).group_by(NE.sensor).order_by(desc(func.count(NE.event_id)))
    )).all()
    latest_overall = max([r[2] for r in sh], default=None)
    sensor_health = []
    for s, c, last in sh:
        stale = latest_overall and last and (latest_overall - last).total_seconds() > 3600
        sensor_health.append([s, c, fmt_ts(last), status("partial" if stale else "pass")])

    # incidents
    incs = (await db.execute(select(Incident).order_by(desc(Incident.risk_score)).limit(10))).scalars().all()
    incident_rows = [[
        i.incident_key, clip(i.title, 58), sev(i.severity), i.status,
        f"{(i.risk_score or 0):.0f}", fmt_ts(i.first_seen),
    ] for i in incs]

    crit_high = sev_map.get("CRITICAL", 0) + sev_map.get("HIGH", 0)
    win_lbl = "all history" if start is None else f"{(end - start).days}d"
    narrative = [
        f"Over the last {win_lbl} the platform recorded {total:,} normalized sensor events from "
        f"{uniq} distinct source addresses; {interactions:,} of those were active interactions "
        f"(authentication attempts or shell commands) rather than bare connections.",
        f"The detection engine raised {det_total} detection(s) and {inc_total} incident(s) in the window "
        f"({inc_open} incident(s) currently open). {crit_high} event(s) were classed CRITICAL or HIGH.",
    ]
    if p_start is not None:
        move = "up" if total >= p_total else "down"
        narrative.append(
            f"Event volume is {move} {abs(total - p_total):,} ({pct(total - p_total, p_total):+.0f}%) versus the "
            f"preceding {win_lbl}, unique sources {uniq - p_uniq:+d}, detections {det_total - p_det:+d}.")
    if sensor_health:
        busiest = sh[0]
        narrative.append(f"Busiest sensor: {busiest[0]} ({busiest[1]:,} events). "
                         f"{len(sh)} sensor(s) reported telemetry in the window.")

    return {
        "title": "SOC Executive Summary",
        "subject": "Global — all sensors",
        "window_start": start, "window_end": end,
        "sources": ["normalized_events", "detections", "incidents"],
        "record_count": total,
        "kpi_band": [
            kpi("Sensor events", f"{total:,}", f"prev {p_total:,}" if p_start else None),
            kpi("Unique sources", uniq, f"prev {p_uniq}" if p_start else None),
            kpi("Detections", det_total, f"prev {p_det}" if p_start else None),
            kpi("Incidents open / total", f"{inc_open} / {inc_total}"),
            kpi("Critical + High events", crit_high),
        ],
        "narrative": narrative,
        "severity_breakdown": severity_breakdown,
        "detection_sev_rows": detection_sev,
        "tactic_bars": tactic_bars,
        "trend": [
            delta("Sensor events", total, p_total),
            delta("Unique sources", uniq, p_uniq),
            delta("Detections", det_total, p_det),
        ] if p_start is not None else [],
        "top_threats_rows": top_threats,
        "port_rows": port_rows,
        "sensor_health_rows": sensor_health,
        "incident_rows": incident_rows,
    }


# ── geo intelligence ─────────────────────────────────────────────────────────
async def geo_intel(db, params, user) -> Dict[str, Any]:
    from app.api.v1.endpoints.dashboard import fetch_geoip_batch, get_flag_emoji

    start, end = parse_window(params)
    RE = RawEventModel

    agg = (await db.execute(
        select(RE.attacker_ip,
               func.count(RE.id).label("hits"),
               func.count(distinct(RE.session_id)).label("sessions"),
               func.count(distinct(RE.target_port)).label("ports"),
               func.count(distinct(RE.honeypot_type)).label("sensors"),
               func.coalesce(func.sum(func.length(RE.raw_payload)), 0).label("bytes"),
               func.min(RE.timestamp).label("first"),
               func.max(RE.timestamp).label("last"))
        .where(_win(RE.timestamp, start, end))
        .group_by(RE.attacker_ip).order_by(desc("hits"))
    )).all()

    ext = [r for r in agg if _looks_ip(r.attacker_ip) and not _is_internal(r.attacker_ip)]
    internal = [r for r in agg if _looks_ip(r.attacker_ip) and _is_internal(r.attacker_ip)]
    other = [r for r in agg if not _looks_ip(r.attacker_ip)]

    geo_map: Dict[str, dict] = {}
    if ext:
        try:
            geo_map = await fetch_geoip_batch([r.attacker_ip.split(":")[0] for r in ext])
        except Exception:
            geo_map = {}

    countries: Dict[str, dict] = defaultdict(lambda: {"events": 0, "ips": set(), "bytes": 0, "code": "UN"})
    asns: Dict[str, dict] = defaultdict(lambda: {"events": 0, "ips": set(), "asn": "N/A"})
    ip_rows: List[list] = []
    for r in ext:
        base = r.attacker_ip.split(":")[0]
        g = geo_map.get(base, {})
        cname = g.get("country") or "Unresolved"
        countries[cname]["events"] += r.hits
        countries[cname]["ips"].add(base)
        countries[cname]["bytes"] += int(r.bytes or 0)
        countries[cname]["code"] = g.get("code", "UN")
        isp = g.get("isp") or "Unresolved ISP"
        asns[isp]["events"] += r.hits
        asns[isp]["ips"].add(base)
        asns[isp]["asn"] = g.get("asn", "N/A")
        ip_rows.append([
            base, g.get("code", "—"), g.get("isp", "—"), r.hits, r.sessions, r.ports,
            fmt_ts(r.first), fmt_ts(r.last),
        ])

    country_rows = sorted(
        [[get_flag_emoji(d["code"]), c, d["code"], d["events"], len(d["ips"]),
          f"{d['bytes'] / 1024:.1f} KB"] for c, d in countries.items()],
        key=lambda x: x[3], reverse=True)
    asn_rows = sorted(
        [[d["asn"], clip(isp, 40), d["events"], len(d["ips"]), clip(", ".join(sorted(d["ips"])), 48)]
         for isp, d in asns.items()],
        key=lambda x: x[2], reverse=True)
    country_bars = bar_items([[c[1], c[3]] for c in country_rows], limit=10)

    internal_rows = [[r.attacker_ip, r.hits, r.sessions, r.ports, r.sensors, fmt_ts(r.first), fmt_ts(r.last)]
                     for r in internal]
    other_rows = [[clip(r.attacker_ip, 40), r.hits, r.sessions, r.ports, fmt_ts(r.first), fmt_ts(r.last)]
                  for r in other]

    total_ext = sum(r.hits for r in ext)
    return {
        "title": "Geographic Threat Intelligence Report",
        "subject": "Global source distribution",
        "window_start": start, "window_end": end,
        "sources": ["raw_events", "ip-api.com geolocation"],
        "record_count": sum(r.hits for r in agg),
        "kpi_band": [
            kpi("External sources", len(ext), f"{total_ext:,} events"),
            kpi("Countries resolved", len([c for c in country_rows if c[2] not in ("UN", "—")])),
            kpi("Distinct ASNs / ISPs", len(asn_rows)),
            kpi("Internal sources", len(internal), f"{sum(r.hits for r in internal):,} events"),
            kpi("Non-IP identifiers", len(other)),
        ],
        "geo_resolved": bool(geo_map),
        "country_rows": country_rows,
        "asn_rows": asn_rows,
        "country_bars": country_bars,
        "ip_rows": sorted(ip_rows, key=lambda x: x[3], reverse=True),
        "internal_rows": internal_rows,
        "other_rows": other_rows,
    }


# ── credentials ──────────────────────────────────────────────────────────────
_COMMON_PW = {
    "123456", "12345678", "123456789", "12345", "1234", "111111", "1234567", "password",
    "admin", "root", "toor", "qwerty", "abc123", "letmein", "welcome", "changeme",
    "admin123", "password1", "test", "guest", "1q2w3e4r", "000000", "654321", "kali",
    "raspberry", "ubuntu", "oracle", "postgres", "user", "1234567890", "p@ssw0rd",
}


def _classify_pw(pw: str, uname: str = "") -> str:
    p = pw or ""
    low = p.lower()
    if not p:
        return "empty"
    if low in _COMMON_PW:
        return "default / common"
    if uname and low == uname.lower():
        return "equals username"
    if len(p) < 6:
        return "too short (<6)"
    if p.isdigit():
        return "digits only"
    if p.isalpha() and p == low:
        return "lowercase letters only"
    return "—"


async def credentials_report(db, params, user) -> Dict[str, Any]:
    start, end = parse_window(params)
    NE = NormalizedEventModel
    cred_filter = and_(_win(NE.timestamp, start, end), NE.username.isnot(None), NE.username != "")

    rows = (await db.execute(
        select(NE.timestamp, NE.sensor, NE.protocol, NE.destination_port, NE.username,
               NE.password, NE.authentication_result, NE.source_ip)
        .where(cred_filter).order_by(desc(NE.timestamp))
    )).all()

    total = len(rows)
    successes = sum(1 for r in rows if (r.authentication_result or "").upper() == "SUCCESS")
    failures = sum(1 for r in rows if (r.authentication_result or "").upper() == "FAILURE")

    cred_rows = [[
        fmt_ts(r.timestamp, "%Y-%m-%d %H:%M:%S"), r.sensor, (r.protocol or "—"), r.destination_port,
        r.username or "—", (r.password if r.password not in (None, "") else "∅"),
        status("pass" if (r.authentication_result or "").upper() == "SUCCESS"
               else ("fail" if (r.authentication_result or "").upper() == "FAILURE" else "none")),
        r.source_ip,
    ] for r in rows[:150]]

    # weak / default password analysis
    pw_counter = Counter((r.password or "") for r in rows)
    pw_user = defaultdict(set)
    for r in rows:
        pw_user[r.password or ""].add((r.username or "").lower())
    weak_rows = []
    weak_total = 0
    for pw, cnt in pw_counter.most_common():
        cls = _classify_pw(pw, next(iter(pw_user[pw])) if len(pw_user[pw]) == 1 else "")
        if cls != "—":
            weak_total += cnt
            weak_rows.append([pw or "∅", cnt, len(pw_user[pw]), cls])
    weak_rows = weak_rows[:40]

    # top usernames
    u_att = Counter((r.username or "") for r in rows)
    u_pw = defaultdict(set); u_ip = defaultdict(set); u_succ = Counter()
    for r in rows:
        u = r.username or ""
        u_pw[u].add(r.password or "")
        u_ip[u].add(r.source_ip)
        if (r.authentication_result or "").upper() == "SUCCESS":
            u_succ[u] += 1
    user_rows = [[u or "—", c, len(u_pw[u]), len(u_ip[u]), u_succ[u]] for u, c in u_att.most_common(20)]

    # top passwords
    p_user = defaultdict(set); p_succ = Counter()
    for r in rows:
        p = r.password or ""
        p_user[p].add(r.username or "")
        if (r.authentication_result or "").upper() == "SUCCESS":
            p_succ[p] += 1
    pass_rows = [[p or "∅", c, len(p_user[p]), p_succ[p]] for p, c in pw_counter.most_common(20)]

    # top source IPs
    ip_att = Counter(r.source_ip for r in rows)
    ip_u = defaultdict(set); ip_p = defaultdict(set); ip_succ = Counter()
    ip_first: Dict[str, datetime] = {}; ip_last: Dict[str, datetime] = {}
    for r in rows:
        ip = r.source_ip
        ip_u[ip].add(r.username or ""); ip_p[ip].add(r.password or "")
        if (r.authentication_result or "").upper() == "SUCCESS":
            ip_succ[ip] += 1
        if r.timestamp:
            ip_first[ip] = min(ip_first.get(ip, r.timestamp), r.timestamp)
            ip_last[ip] = max(ip_last.get(ip, r.timestamp), r.timestamp)
    iprows = [[ip, c, len(ip_u[ip]), len(ip_p[ip]), ip_succ[ip], fmt_ts(ip_first.get(ip)), fmt_ts(ip_last.get(ip))]
              for ip, c in ip_att.most_common(20)]

    # reuse stats
    pairs = Counter((r.username or "", r.password or "") for r in rows)
    pair_ips = defaultdict(set)
    for r in rows:
        pair_ips[(r.username or "", r.password or "")].add(r.source_ip)
    multi_ip_pairs = sum(1 for k, v in pair_ips.items() if len(v) > 1)
    succ_pairs = sorted({(r.username or "", r.password or "") for r in rows
                         if (r.authentication_result or "").upper() == "SUCCESS"})
    reuse_kv = [
        ("Distinct username/password pairs", len(pairs)),
        ("Pairs attempted from >1 source IP", multi_ip_pairs),
        ("Most-repeated pair", (lambda k: f"{k[0][0] or '∅'} / {k[0][1] or '∅'} ×{k[1]}")(pairs.most_common(1)[0]) if pairs else "—"),
        ("Overall success rate", f"{pct(successes, total):.1f}% ({successes}/{total})"),
        ("Distinct usernames / passwords", f"{len(u_att)} / {len(pw_counter)}"),
        ("Credential pairs that succeeded", ", ".join(f"{u or '∅'}/{p or '∅'}" for u, p in succ_pairs[:12]) or "none"),
    ]

    # issuance audit trail (internal credential delivery)
    audits = (await db.execute(
        select(CredentialAuditLog).order_by(desc(CredentialAuditLog.timestamp)).limit(50)
    )).scalars().all()
    audit_rows = [[
        fmt_ts(a.timestamp), a.username or "—", a.delivery_method or "—",
        a.issuer_name or a.issued_by or "—", f"{a.email_status}/{a.token_status}",
    ] for a in audits]

    return {
        "title": "Captured Credentials Report",
        "subject": "Honeypot credential harvest",
        "window_start": start, "window_end": end,
        "sources": ["normalized_events (auth attempts)", "credential_audit_log"],
        "record_count": total,
        "kpi_band": [
            kpi("Credential attempts", total),
            kpi("Successful logins", successes, f"{pct(successes, total):.0f}% of attempts"),
            kpi("Failed logins", failures),
            kpi("Weak / default", weak_total, f"{pct(weak_total, total):.0f}% of attempts"),
            kpi("Distinct source IPs", len(ip_att)),
        ],
        "cred_rows": cred_rows,
        "cred_shown": len(cred_rows),
        "weak_rows": weak_rows,
        "user_rows": user_rows,
        "pass_rows": pass_rows,
        "srcip_rows": iprows,
        "reuse_kv": reuse_kv,
        "audit_rows": audit_rows,
    }


# ── incident ─────────────────────────────────────────────────────────────────
async def incident_report(db, params, user) -> Dict[str, Any]:
    from app.services.timeline_builder import build_timeline

    iid = params.get("incident_id") or params.get("subject")
    inc = None
    if iid:
        inc = (await db.execute(select(Incident).where(
            or_(Incident.id == iid, Incident.incident_key == iid)))).scalars().first()
        if not inc:
            raise ValueError(f"incident {iid} not found")
    else:
        inc = (await db.execute(
            select(Incident).where(Incident.status != "FALSE_POSITIVE")
            .order_by(desc(Incident.risk_score), desc(Incident.last_seen)).limit(1)
        )).scalars().first()
        if not inc:
            raise ValueError("no incidents on record to report on")

    dets = (await db.execute(select(Detection).where(Detection.incident_id == inc.id)
                             .order_by(Detection.first_event_at))).scalars().all()
    evs = (await db.execute(select(Evidence).where(Evidence.incident_id == inc.id))).scalars().all()
    acts = (await db.execute(select(IncidentActivity).where(IncidentActivity.incident_id == inc.id)
                             .order_by(IncidentActivity.at))).scalars().all()
    iocs = (await db.execute(select(IncidentIOC).where(IncidentIOC.incident_id == inc.id))).scalars().all()
    ev_link = await _scalar(db, select(func.count(IncidentEvent.id)).where(IncidentEvent.incident_id == inc.id))
    try:
        timeline = await build_timeline(db, inc)
    except Exception:
        timeline = []

    # event-type breakdown across the incident window for its source IPs
    etype_rows = []
    ips = inc.source_ips or ([inc.correlation_key] if inc.correlation_key else [])
    if ips and inc.first_seen:
        NE = NormalizedEventModel
        et = (await db.execute(
            select(NE.sensor_event_type, func.count(NE.event_id))
            .where(NE.source_ip.in_(ips), _win(NE.timestamp, inc.first_seen, inc.last_seen or datetime.utcnow()))
            .group_by(NE.sensor_event_type).order_by(desc(func.count(NE.event_id))).limit(15)
        )).all()
        etype_rows = [[e or "—", c] for e, c in et]

    ttc = "—"
    if inc.first_seen:
        contained = next((a.at for a in acts if a.action == "STATUS_CHANGE"
                          and "CONTAIN" in (a.detail or "").upper()), None)
        if contained:
            ttc = str(contained - inc.first_seen)
    dur = str((inc.last_seen - inc.first_seen)) if (inc.first_seen and inc.last_seen) else "—"

    rb = inc.risk_breakdown or {}
    meta_kv = [
        ("Incident key", inc.incident_key),
        ("Title", inc.title or "—"),
        ("Severity / status", f"{inc.severity} · {inc.status}"),
        ("Risk score", f"{(inc.risk_score or 0):.0f}"),
        ("Confidence", f"{(inc.confidence or 0) * 100:.0f}%"),
        ("First / last seen", f"{fmt_ts(inc.first_seen)}  →  {fmt_ts(inc.last_seen)}"),
        ("Activity span", dur),
        ("Time to contain", ttc),
        ("Linked events", ev_link),
        ("Assigned analyst", inc.assigned_analyst or "unassigned"),
        ("Origin", "auto-created" if inc.auto_created else "manual"),
        ("Correlation key", inc.correlation_key or "—"),
    ]
    if rb:
        meta_kv.append(("Risk breakdown", clip("; ".join(f"{k}={v}" for k, v in rb.items()), 160)))

    tech_rows = [[t.get("id", "—"), t.get("tactic", "—"), clip(t.get("name", ""), 60)]
                 for t in (inc.attack_techniques or [])]
    det_rows = [[
        d.rule_name, d.attack_technique or "—", sev(d.severity),
        fmt_ts(d.first_event_at), f"{(d.confidence or 0) * 100:.0f}%", clip(d.reason, 70),
    ] for d in dets]
    timeline_rows = [[
        e.get("ts", "—"), e.get("source", "—"), e.get("event_type", "—"),
        sev(e.get("severity", "")), clip(e.get("reason", ""), 66),
    ] for e in timeline[:70]]
    ev_rows = [[
        e.type, ((e.sha256 or "")[:16] + "…") if e.sha256 else "—", e.source or "—",
        fmt_ts(e.acquired_at), clip(e.ref, 42),
    ] for e in evs]
    act_rows = [[fmt_ts(a.at), a.actor or "—", a.action or "—", clip(a.detail, 76)] for a in acts]
    ioc_rows = [[i.ioc_type, clip(i.ioc_value, 60), fmt_ts(i.first_seen)] for i in iocs]

    narrative = [
        f"Incident {inc.incident_key} ({inc.severity}, {inc.status}) covers activity from "
        f"{', '.join(ips) or 'unknown source'} between {fmt_ts(inc.first_seen)} and {fmt_ts(inc.last_seen)}.",
        f"It groups {len(dets)} detection(s) across {len({d.attack_technique for d in dets if d.attack_technique})} "
        f"ATT&CK technique(s), with {ev_link} linked telemetry event(s) and {len(evs)} evidence item(s) in the "
        f"chain of custody.",
    ]
    for r in (inc.detection_reasons or [])[:4]:
        narrative.append(r)

    return {
        "title": f"Incident Report — {inc.incident_key}",
        "subject": clip(inc.title, 90),
        "window_start": inc.first_seen, "window_end": inc.last_seen,
        "sources": ["incidents", "detections", "incident_events", "evidence", "incident_activity", "incident_iocs"],
        "record_count": len(dets),
        "kpi_band": [
            kpi("Severity", inc.severity),
            kpi("Risk score", f"{(inc.risk_score or 0):.0f}"),
            kpi("Status", inc.status),
            kpi("Detections", len(dets)),
            kpi("Linked events", ev_link),
        ],
        "narrative": narrative,
        "meta_kv": meta_kv,
        "related_kv": [
            ("Source IPs", ", ".join(ips) or "—"),
            ("Related users", ", ".join(inc.related_users or []) or "—"),
            ("Related sensors", ", ".join(inc.related_sensors or []) or "—"),
        ],
        "tech_rows": tech_rows,
        "det_rows": det_rows,
        "etype_rows": etype_rows,
        "timeline_rows": timeline_rows,
        "ev_rows": ev_rows,
        "act_rows": act_rows,
        "ioc_rows": ioc_rows,
        "auto_selected": not iid,
    }


# ── forensic / DFIR ─────────────────────────────────────────────────────────
async def forensic_dfir(db, params, user) -> Dict[str, Any]:
    from app.api.v1.endpoints.behavior import get_behavior_profile

    start, end = parse_window(params)
    src = params.get("source_ip")
    if not src:
        hot = (await db.execute(
            select(AttackerSession).order_by(
                case((AttackerSession.risk_level == "CRITICAL", 0),
                     (AttackerSession.risk_level == "HIGH", 1),
                     (AttackerSession.risk_level == "MEDIUM", 2), else_=3),
                desc(AttackerSession.total_events)).limit(1)
        )).scalars().first()
        src = hot.attacker_ip if hot else None

    profile = await get_behavior_profile(db=db)
    actor = profile.get("actor", {})
    kc = profile.get("killchain", {})
    gm = profile.get("graph_metrics", {})
    mitre = profile.get("mitre", []) or []

    RE = RawEventModel
    sess_q = select(AttackerSession)
    if src:
        sess_q = sess_q.where(AttackerSession.attacker_ip == src)
    sessions = (await db.execute(sess_q.order_by(desc(AttackerSession.first_seen)).limit(30))).scalars().all()

    ev_q = select(RE).where(_win(RE.timestamp, start, end))
    if src:
        ev_q = ev_q.where(RE.attacker_ip == src)
    events = (await db.execute(ev_q.order_by(desc(RE.timestamp)).limit(400))).scalars().all()

    subj_kv = []
    if src:
        agg = (await db.execute(
            select(func.count(RE.id), func.count(distinct(RE.session_id)),
                   func.count(distinct(RE.target_port)), func.count(distinct(RE.honeypot_type)),
                   func.min(RE.timestamp), func.max(RE.timestamp))
            .where(RE.attacker_ip == src)
        )).first()
        if agg and agg[0]:
            span = (agg[5] - agg[4]) if (agg[4] and agg[5]) else None
            subj_kv = [
                ("Subject", src),
                ("Total events (all time)", agg[0]),
                ("Distinct sessions", agg[1]),
                ("Distinct target ports", agg[2]),
                ("Sensors touched", agg[3]),
                ("First / last seen", f"{fmt_ts(agg[4])}  →  {fmt_ts(agg[5])}"),
                ("Active span", str(span) if span else "—"),
            ]

    sensor_rows = []
    if src:
        sr = (await db.execute(
            select(RE.honeypot_type, func.count(RE.id), func.max(RE.timestamp))
            .where(RE.attacker_ip == src).group_by(RE.honeypot_type).order_by(desc(func.count(RE.id)))
        )).all()
        sensor_rows = [[s or "—", c, fmt_ts(t)] for s, c, t in sr]

    port_rows = []
    if src:
        pr = (await db.execute(
            select(RE.target_port, func.count(RE.id)).where(RE.attacker_ip == src)
            .group_by(RE.target_port).order_by(desc(func.count(RE.id))).limit(15)
        )).all()
        port_rows = [[p, _PORTS.get(p, "—"), c] for p, c in pr]

    etype_rows = []
    if src:
        er = (await db.execute(
            select(RE.event_type, func.count(RE.id)).where(RE.attacker_ip == src)
            .group_by(RE.event_type).order_by(desc(func.count(RE.id))).limit(15)
        )).all()
        etype_rows = [[e or "—", c] for e, c in er]

    cmd_rows = [[fmt_ts(e.timestamp, "%Y-%m-%d %H:%M:%S"), e.attacker_ip, e.honeypot_type or "—",
                 clip((e.commands or "").strip().replace("\n", " ⏎ "), 92)]
                for e in events if e.commands][:150]
    file_rows = [[fmt_ts(e.timestamp), e.attacker_ip, clip(e.uploaded_files, 80)]
                 for e in events if e.uploaded_files][:60]
    scan_rows = [[fmt_ts(e.timestamp), e.attacker_ip, clip(e.ports_scanned, 80)]
                 for e in events if e.ports_scanned][:40]

    # auth attempts from normalized events
    auth_rows = []
    if src:
        NE = NormalizedEventModel
        ar = (await db.execute(
            select(NE.timestamp, NE.username, NE.password, NE.authentication_result, NE.destination_port)
            .where(NE.source_ip == src, NE.username.isnot(None)).order_by(desc(NE.timestamp)).limit(60)
        )).all()
        auth_rows = [[fmt_ts(t), u or "—", p or "∅",
                      status("pass" if (r or "").upper() == "SUCCESS" else "fail"), dp] for t, u, p, r, dp in ar]

    # detections + IOCs touching the subject
    det_rows = []
    ioc_rows = []
    if src:
        dr = (await db.execute(select(Detection).where(Detection.source_ip == src)
                               .order_by(desc(Detection.created_at)).limit(30))).scalars().all()
        det_rows = [[d.rule_name, d.attack_technique or "—", sev(d.severity), fmt_ts(d.first_event_at),
                     clip(d.reason, 70)] for d in dr]
        ir = (await db.execute(select(IOCObservation).where(
            or_(IOCObservation.value == src, IOCObservation.value == (src or "").split(":")[0]))
            .order_by(desc(IOCObservation.last_seen)).limit(30))).scalars().all()
        ioc_rows = [[i.type, clip(i.value, 46), i.hit_count, i.source or "—",
                     fmt_ts(i.first_seen), fmt_ts(i.last_seen)] for i in ir]

    session_rows = [[fmt_ts(s.first_seen), fmt_ts(s.last_seen), s.attacker_ip, s.geoip_country or "—",
                     s.total_events, s.risk_level or "—"] for s in sessions]
    traits_rows = [[k, v] for k, v in (actor.get("traits", {}) or {}).items()]
    mitre_rows = []
    for m in mitre:
        if isinstance(m, dict):
            mitre_rows.append([m.get("id") or m.get("technique") or "—", m.get("tactic", "—"),
                               clip(m.get("name") or m.get("description", ""), 60)])

    return {
        "title": "Digital Forensics & Incident Response Report",
        "subject": src or "All attacker sessions",
        "window_start": start, "window_end": end,
        "sources": ["attacker_sessions", "raw_events", "normalized_events", "detections",
                    "ioc_observations", "behavioral graph analysis"],
        "record_count": len(events),
        "kpi_band": [
            kpi("Behaviour class", actor.get("name", "unclassified"), f"{actor.get('confidence', 0)}% match"),
            kpi("Kill-chain stage", kc.get("stage_name", "unknown"), f"{kc.get('percent', 0)}% progressed"),
            kpi("Graph nodes / edges", f"{gm.get('nodes', 0)} / {gm.get('edges', 0)}"),
            kpi("Commands captured", len(cmd_rows)),
            kpi("Detections on subject", len(det_rows)),
        ],
        "assessment": [
            f"Closest behavioural cluster: {actor.get('name', 'unclassified')} "
            f"(match confidence {actor.get('confidence', 0)}%, derived from observed TTPs — not a formal attribution).",
            f"Kill-chain position: {kc.get('stage_name', 'unknown')} ({kc.get('percent', 0)}% progressed). "
            f"Interaction graph: {gm.get('nodes', 0)} nodes, {gm.get('edges', 0)} edges, "
            f"{gm.get('components', 0)} component(s), top betweenness {gm.get('top_betweenness', 0)}.",
        ],
        "subj_kv": subj_kv,
        "traits_rows": traits_rows,
        "session_rows": session_rows,
        "sensor_rows": sensor_rows,
        "port_rows": port_rows,
        "etype_rows": etype_rows,
        "auth_rows": auth_rows,
        "cmd_rows": cmd_rows,
        "file_rows": file_rows,
        "scan_rows": scan_rows,
        "det_rows": det_rows,
        "ioc_rows": ioc_rows,
        "mitre_rows": mitre_rows,
        "auto_selected": not params.get("source_ip"),
    }


# ── detection validation & coverage ─────────────────────────────────────────
async def detection_validation_report(db, params, user) -> Dict[str, Any]:
    from app.services.detection_validation import coverage_report

    start, end = parse_window(params)
    cov = await coverage_report(db)
    scen = cov.get("scenarios", [])

    passing = sum(1 for s in scen if s.get("last_result") == "PASS")
    failing = sum(1 for s in scen if s.get("last_result") in ("FAIL", "PARTIAL"))
    never = sum(1 for s in scen if not s.get("last_run_at"))

    scen_rows = []
    detect_bars = []
    exp_act_rows = []
    for s in scen:
        m = s.get("metrics") or {}
        dsr = m.get("detection_success_rate")
        acov = m.get("attack_coverage")
        scen_rows.append([
            s.get("scenario_id", "?"),
            status((s.get("last_result") or "none").lower()),
            f"{(dsr * 100):.0f}%" if dsr is not None else "—",
            f"{(acov * 100):.0f}%" if acov is not None else "—",
            (s.get("expected_severity") or "—"),
            (s.get("actual_severity") or "—"),
            fmt_ts(s.get("last_run_at")),
        ])
        detect_bars.append({"label": clip(s.get("scenario_id", "?"), 34),
                            "value": f"{(dsr * 100):.0f}%" if dsr is not None else "0%",
                            "pct": round((dsr or 0) * 100, 1)})
        exp = set(s.get("expected_detections") or [])
        act = set(s.get("actual_detections") or [])
        exp_act_rows.append([
            s.get("scenario_id", "?"),
            clip(", ".join(sorted(exp)) or "—", 46),
            clip(", ".join(sorted(act & exp)) or "—", 40),
            clip(", ".join(sorted(exp - act)) or "none", 40),
        ])

    # ATT&CK technique coverage
    tech_expected = defaultdict(set)
    tech_covered = defaultdict(set)
    for s in scen:
        for t in (s.get("expected_techniques") or []):
            tech_expected[t].add(s.get("scenario_id"))
            if s.get("last_result") == "PASS" and t in set(s.get("actual_techniques") or []):
                tech_covered[t].add(s.get("scenario_id"))
    tech_rows = [[t, clip(", ".join(sorted(sids)), 40),
                  status("pass" if tech_covered.get(t) else "fail"),
                  len(tech_covered.get(t, set()))]
                 for t, sids in sorted(tech_expected.items())]

    # live detection-rule inventory
    inv = (await db.execute(
        select(Detection.rule_id, Detection.rule_name, Detection.severity, Detection.attack_technique,
               Detection.attack_tactic, func.count(Detection.id), func.max(Detection.created_at),
               func.count(distinct(Detection.source_ip)))
        .group_by(Detection.rule_id, Detection.rule_name, Detection.severity,
                  Detection.attack_technique, Detection.attack_tactic)
        .order_by(desc(func.count(Detection.id)))
    )).all()
    inv_rows = [[rid, clip(rn, 44), sev(sv), tech or "—", tac or "—", cnt, fmt_ts(last), ips]
                for rid, rn, sv, tech, tac, cnt, last, ips in inv]

    # recent scenario runs
    runs = (await db.execute(
        select(ScenarioRun).order_by(desc(ScenarioRun.started_at)).limit(25)
    )).scalars().all()
    run_rows = [[
        r.scenario_id, r.mode, r.status, status((r.result or "none").lower()),
        fmt_ts(r.started_at, "%Y-%m-%d %H:%M:%S"),
        (str(r.finished_at - r.started_at) if (r.started_at and r.finished_at) else "—"),
        r.severity_seen or "—",
    ] for r in runs]

    return {
        "title": "Detection Validation & Coverage Report",
        "subject": "SOC control testing",
        "window_start": start, "window_end": end,
        "sources": ["scenario_runs", "detections", "scenarios/*.yaml", "detection_validation"],
        "record_count": len(scen),
        "kpi_band": [
            kpi("Scenarios", len(scen)),
            kpi("Passing", f"{passing} / {len(scen)}"),
            kpi("Failing / partial", failing),
            kpi("Never run", never),
            kpi("Overall detect rate", f"{cov.get('detection_success_rate', 0) * 100:.0f}%"),
            kpi("ATT&CK coverage", f"{cov.get('attack_coverage', 0) * 100:.0f}%"),
        ],
        "scen_rows": scen_rows,
        "detect_bars": detect_bars,
        "exp_act_rows": exp_act_rows,
        "tech_rows": tech_rows,
        "inv_rows": inv_rows,
        "run_rows": run_rows,
        "failed_scenarios": cov.get("failed_scenarios", []),
        "untested_scenarios": cov.get("untested_scenarios", []),
    }


# ── malware analysis ────────────────────────────────────────────────────────
async def malware_report(db, params, user) -> Dict[str, Any]:
    from app.api.v1.endpoints.malware import _get_full_report, MALWARE_HISTORY_FILE, APK_HISTORY_FILE

    sha = params.get("sha256") or params.get("subject")
    hist_entry = {}
    if not sha:
        entries: List[dict] = []
        for f in (MALWARE_HISTORY_FILE, APK_HISTORY_FILE):
            try:
                with open(f) as fh:
                    entries += json.load(fh)
            except Exception:
                pass
        entries = [e for e in entries if e.get("sha256")]
        entries.sort(key=lambda e: e.get("analyzed_at", ""), reverse=True)
        if not entries:
            raise ValueError("no malware analyses on file — upload a sample first")
        hist_entry = entries[0]
        sha = hist_entry["sha256"]

    r = _get_full_report(sha)
    if not r:
        raise ValueError(f"no analysis on file for {sha} — upload the sample first")

    static = r.get("static", {}) or {}
    details = static.get("details", {}) or {}
    strings = static.get("strings", {}) or {}
    yara = r.get("yara", {}) or {}
    secrets = r.get("secrets", {}) or {}
    av = r.get("av", {}) or {}
    sandbox = r.get("sandbox", {}) or {}
    apk = r.get("apk", {}) or {}
    clam = av.get("clamav", {}) or {}

    ident_kv = [
        ("SHA-256", sha),
        ("MD5", hist_entry.get("md5", "—")),
        ("SHA-1", hist_entry.get("sha1", "—")),
        ("Filename", r.get("filename") or static.get("filename", "—")),
        ("File type / format", f"{r.get('file_type', '—')} · {details.get('format', '—')}"),
        ("Size", f"{static.get('file_size', hist_entry.get('size_bytes', 0)):,} bytes"),
        ("Overall entropy", static.get("overall_entropy", details.get("overall_entropy", "—"))),
        ("Analyzed at", r.get("analyzed_at", "—")),
        ("Threat family", r.get("threat_family", "Unknown")),
        ("Score / risk", f"{r.get('score', '—')} · {r.get('risk_level', '—')}"),
    ]

    static_rows = [[k, clip(v, 90)] for k, v in details.items()
                   if not isinstance(v, (dict, list))]
    indicator_list = details.get("indicators", []) or []

    string_rows = []
    for cat in ("urls", "network", "suspicious", "crypto", "filesystem", "registry"):
        for s in (strings.get(cat, []) or [])[:25]:
            string_rows.append([cat, clip(s, 96)])

    yara_rows = [[m.get("rule", "?"), (m.get("meta", {}) or {}).get("family", "—"),
                  clip(", ".join(m.get("tags", [])), 46)] for m in (yara.get("matches", []) or [])]
    sec_rows = [[f.get("type", "?"), f.get("severity", "?"), clip(f.get("match", ""), 48),
                 clip(f.get("location", ""), 40)] for f in (secrets.get("findings", []) or [])[:80]]

    av_kv = [
        ("ClamAV available", clam.get("available")),
        ("ClamAV infected", clam.get("infected")),
        ("ClamAV signature", clam.get("signature") or "—"),
        ("ClamAV error", clam.get("error") or "—"),
        ("Overall AV verdict", av.get("verdict", "—")),
    ]
    sandbox_kv = [
        ("Source", sandbox.get("source", "—")),
        ("Available", sandbox.get("available")),
        ("Reason", clip(sandbox.get("reason", "—"), 150)),
        ("Threat family", sandbox.get("threat_family") or "—"),
        ("Score / risk", f"{sandbox.get('score', '—')} · {sandbox.get('risk_level', '—')}"),
        ("Signatures", len(sandbox.get("signatures", []) or [])),
        ("MITRE techniques", ", ".join((sandbox.get("mitre_techniques", {}) or {}).keys()) or "—"),
    ]
    sandbox_sig_rows = [[clip(s, 120)] for s in (sandbox.get("signatures", []) or [])[:30]]

    apk_kv = []
    if apk:
        for k, v in apk.items():
            if not isinstance(v, (dict, list)):
                apk_kv.append([k, clip(v, 90)])

    sources = ["static analyzer", "YARA", "ClamAV", "secret detector"]
    if apk:
        sources.append("MobSF / APK engine")
    if sandbox.get("available"):
        sources.append("CAPE sandbox")

    return {
        "title": "Malware Analysis Report",
        "subject": sha[:32],
        "sources": sources,
        "record_count": secrets.get("total", 0),
        "kpi_band": [
            kpi("File type", r.get("file_type", "—")),
            kpi("Threat family", r.get("threat_family", "Unknown")),
            kpi("Score", r.get("score", "—"), r.get("risk_level", "—")),
            kpi("AV verdict", av.get("verdict", "—")),
            kpi("YARA / secrets", f"{yara.get('count', 0)} / {secrets.get('total', 0)}"),
        ],
        "ident_kv": ident_kv,
        "static_rows": static_rows,
        "indicator_list": indicator_list,
        "string_rows": string_rows,
        "yara_rows": yara_rows,
        "yara_available": yara.get("available"),
        "sec_rows": sec_rows,
        "sec_summary": secrets.get("summary", {}),
        "av_kv": av_kv,
        "sandbox_kv": sandbox_kv,
        "sandbox_sig_rows": sandbox_sig_rows,
        "apk_kv": apk_kv,
        "auto_selected": not (params.get("sha256") or params.get("subject")),
    }


# common port map (kept local so providers don't depend on the dashboard module)
_PORTS = {
    21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 1433: "MSSQL", 1521: "Oracle",
    2222: "SSH-ALT", 2223: "SSH-ALT", 3306: "MySQL", 3389: "RDP", 5060: "SIP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8022: "HTTP-ALT", 8023: "TELNET-ALT", 8080: "HTTP-ALT",
    8443: "HTTPS-ALT", 9200: "Elasticsearch", 27017: "MongoDB", 0: "—",
}
