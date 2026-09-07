"""Operational SOC report providers — geo intel, executive summary, credentials,
incident, forensic/DFIR, detection validation, malware.

Every figure is pulled live from the application database or an existing service
function. No value is synthesised in this module.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

from sqlalchemy import func, select, desc

from app.models.all_models import (
    RawEventModel, Detection, Incident, IncidentEvent, IncidentActivity,
    Evidence, ScenarioRun, CredentialAuditLog, AttackerSession,
)
from .base import kpis, table, text, note, listing, sev, parse_window


# ── executive summary ────────────────────────────────────────────────────────
async def executive_summary(db, params, user) -> Dict[str, Any]:
    from app.api.v1.endpoints.dashboard import get_dashboard_stats
    stats = await get_dashboard_stats(db)
    s = stats.get("summary", {})
    sysd = stats.get("system", {})

    det_total = (await db.execute(select(func.count(Detection.id)))).scalar() or 0
    inc_total = (await db.execute(select(func.count(Incident.id)))).scalar() or 0
    inc_open = (await db.execute(
        select(func.count(Incident.id)).where(Incident.status.notin_(["RESOLVED", "FALSE_POSITIVE"]))
    )).scalar() or 0

    sev_rows = []
    for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        c = (await db.execute(select(func.count(Detection.id)).where(Detection.severity == lvl))).scalar() or 0
        if c:
            sev_rows.append([sev(lvl), c])

    top_inc = (await db.execute(select(Incident).order_by(desc(Incident.risk_score)).limit(8))).scalars().all()

    return {
        "title": "SOC Executive Summary",
        "subject": "Global — all sensors",
        "sources": ["raw_events", "detections", "incidents", "detection engine"],
        "sections": [
            text("Overview", [
                f"This summary covers {s.get('total_attacks', 0):,} honeypot events from "
                f"{s.get('unique_attackers', 0)} distinct source IPs. Current platform threat "
                f"level is {s.get('current_threat_level', 'UNKNOWN')}.",
                f"The detection engine has completed {sysd.get('analysis_engine', {}).get('cycles', 0)} "
                f"correlation cycles; {sysd.get('analysis_engine', {}).get('classified_pct', 0)}% of "
                f"events in the last 24h were classified.",
            ]),
            kpis(
                ("Total events", f"{s.get('total_attacks', 0):,}"),
                ("Unique attackers", s.get("unique_attackers", 0)),
                ("High-risk alerts", s.get("high_risk_alerts", 0)),
                ("Detections", det_total),
                ("Incidents (open / total)", f"{inc_open} / {inc_total}"),
                ("Sensors online", f"{sysd.get('deception', {}).get('sensors_online', 0)} / {sysd.get('deception', {}).get('sensors_total', 0)}"),
            ),
            table("Detections by severity", ["Severity", "Count"], sev_rows,
                  note="Source: detections table, grouped by severity."),
            table("Highest-risk incidents", ["Key", "Title", "Severity", "Risk", "Status", "First seen"],
                  [[i.incident_key, (i.title or "")[:70], sev(i.severity), f"{i.risk_score:.0f}", i.status,
                    i.first_seen.strftime("%Y-%m-%d %H:%M") if i.first_seen else "—"] for i in top_inc],
                  note="Source: incidents table, ordered by computed risk_score."),
        ],
        "record_count": s.get("total_attacks", 0),
    }


# ── geo intelligence ─────────────────────────────────────────────────────────
async def geo_intel(db, params, user) -> Dict[str, Any]:
    from app.api.v1.endpoints.dashboard import get_geo_stats
    g = await get_geo_stats(db)

    country_rows = [[c.get("flag", ""), c.get("country", "?"), c.get("code", "?"),
                     c.get("events", 0), c.get("traffic", "—")] for c in g.get("top_countries", [])]
    asn_rows = [[a.get("asn", "N/A"), a.get("isp_name", "?"), a.get("count", 0),
                 (a.get("ips", "") or "")[:60]] for a in g.get("asn_intelligence", [])]

    return {
        "title": "Geographic Threat Intelligence Report",
        "subject": "Global source distribution",
        "sources": ["raw_events", "ip-api.com geolocation", "dashboard/geo"],
        "sections": [
            kpis(
                ("Active sources", g.get("active_sources", 0)),
                ("Targeted zones", g.get("targeted_zones", 0)),
                ("Countries observed", len(g.get("top_countries", []))),
            ),
            table("Top source countries", ["", "Country", "ISO", "Events", "Traffic"], country_rows,
                  note="Traffic = summed raw_payload bytes per country. Geo via ip-api.com batch lookup."),
            table("ASN / ISP intelligence", ["ASN", "ISP", "Events", "Sample IPs"], asn_rows,
                  note="Source: geoip_data on raw_events."),
            note("Recommended actions: correlate the listed ASNs with event telemetry and "
                 "honeypot service fingerprints; apply throttling to the top offending "
                 "clusters; re-run this report after mitigation to validate drift."),
        ],
        "record_count": sum(c.get("events", 0) for c in g.get("top_countries", [])),
    }


# ── credentials ──────────────────────────────────────────────────────────────
async def credentials_report(db, params, user) -> Dict[str, Any]:
    from app.api.v1.endpoints.analytics import get_credentials_vault
    v = await get_credentials_vault(db)
    k = v.get("kpi", {})
    rows = [[r["timestamp"], r["target_protocol"], r["username"], r["password"],
             r["source_ip"], f"{r['risk_score']:.0f}"] for r in v.get("data", [])[:120]]

    audits = (await db.execute(
        select(CredentialAuditLog).order_by(desc(CredentialAuditLog.timestamp)).limit(50)
    )).scalars().all()
    audit_rows = [[a.timestamp.strftime("%Y-%m-%d %H:%M") if a.timestamp else "—",
                   a.username or "—", a.delivery_method or "—",
                   a.issuer_name or a.issued_by or "—",
                   f"{a.email_status}/{a.token_status}"] for a in audits]

    return {
        "title": "Captured Credentials Report",
        "subject": "Honeypot credential harvest",
        "sources": ["raw_events (login payloads)", "credential_audit_log"],
        "sections": [
            kpis(
                ("Root login attempts", k.get("root_attempts", 0)),
                ("Unique fingerprints", k.get("unique_fingerprints", 0)),
                ("Weak / default passwords", k.get("weak_passwords", 0)),
                ("Velocity (attempts/min)", k.get("velocity", 0)),
            ),
            table("Captured credential attempts", ["Time", "Proto", "Username", "Password", "Source IP", "Risk"],
                  rows, note="Source: parsed \"password\" payloads on raw_events (most recent 120)."),
            table("Credential issuance audit trail", ["Time", "Username", "Action", "Issued by", "Delivery"],
                  audit_rows, note="Source: credential_audit_log."),
        ],
        "record_count": len(v.get("data", [])),
    }


# ── incident ─────────────────────────────────────────────────────────────────
async def incident_report(db, params, user) -> Dict[str, Any]:
    from app.services.timeline_builder import build_timeline
    iid = params.get("incident_id") or params.get("subject")
    if not iid:
        raise ValueError("incident_id is required for an incident report")
    inc = (await db.execute(select(Incident).where(
        (Incident.id == iid) | (Incident.incident_key == iid)
    ))).scalars().first()
    if not inc:
        raise ValueError(f"incident {iid} not found")

    dets = (await db.execute(select(Detection).where(Detection.incident_id == inc.id)
                             .order_by(Detection.first_event_at))).scalars().all()
    evs = (await db.execute(select(Evidence).where(Evidence.incident_id == inc.id))).scalars().all()
    acts = (await db.execute(select(IncidentActivity).where(IncidentActivity.incident_id == inc.id)
                             .order_by(IncidentActivity.at))).scalars().all()
    ev_link = (await db.execute(select(func.count(IncidentEvent.id))
                                .where(IncidentEvent.incident_id == inc.id))).scalar() or 0
    try:
        timeline = await build_timeline(db, inc)
    except Exception:
        timeline = []

    ttc = None
    if inc.first_seen:
        contained = next((a.at for a in acts if a.action == "STATUS_CHANGE" and "CONTAIN" in (a.detail or "").upper()), None)
        if contained:
            ttc = str(contained - inc.first_seen)

    return {
        "title": f"Incident Report — {inc.incident_key}",
        "subject": (inc.title or "")[:90],
        "sources": ["incidents", "detections", "incident_events", "evidence", "incident_activity"],
        "window_start": inc.first_seen, "window_end": inc.last_seen,
        "sections": [
            kpis(
                ("Severity", inc.severity),
                ("Risk score", f"{inc.risk_score:.0f}"),
                ("Status", inc.status),
                ("Confidence", f"{(inc.confidence or 0) * 100:.0f}%"),
                ("Linked events", ev_link),
                ("Time to contain", ttc or "—"),
            ),
            text("Summary", [
                inc.title or "",
                "Source IPs: " + ", ".join(inc.source_ips or []) if inc.source_ips else "Source IPs: —",
            ] + (inc.detection_reasons or [])),
            table("Detections", ["Rule", "Technique", "Severity", "First event", "Reason"],
                  [[d.rule_name, d.attack_technique or "—", sev(d.severity),
                    d.first_event_at.strftime("%Y-%m-%d %H:%M") if d.first_event_at else "—",
                    (d.reason or "")[:80]] for d in dets],
                  note="Source: detections linked to this incident."),
            table("Timeline", ["Time", "Source", "Event", "Severity", "Detail"],
                  [[e.get("ts", "—"), e.get("source", "—"), e.get("event_type", "—"),
                    sev(e.get("severity", "")), (e.get("reason", "") or "")[:70]] for e in timeline[:60]],
                  note="Source: timeline_builder (detections + linked honeypot events)."),
            table("Evidence (chain of custody)", ["Type", "SHA-256", "Source", "Acquired", "Ref"],
                  [[e.type, (e.sha256 or "")[:16] + "…" if e.sha256 else "—", e.source or "—",
                    e.acquired_at.strftime("%Y-%m-%d %H:%M") if e.acquired_at else "—",
                    (e.ref or "")[:44]] for e in evs],
                  note="Source: evidence table. Integrity via /evidence/{id}/verify."),
            table("Analyst activity", ["Time", "Actor", "Action", "Detail"],
                  [[a.at.strftime("%Y-%m-%d %H:%M") if a.at else "—", a.actor or "—", a.action or "—",
                    (a.detail or "")[:80]] for a in acts],
                  note="Source: incident_activity audit trail."),
        ],
        "record_count": len(dets),
    }


# ── forensic / DFIR (per attacker session or source ip) ──────────────────────
async def forensic_dfir(db, params, user) -> Dict[str, Any]:
    from app.api.v1.endpoints.behavior import get_behavior_profile
    profile = await get_behavior_profile(db=db)

    src = params.get("source_ip")
    q = select(AttackerSession)
    if src:
        q = q.where(AttackerSession.attacker_ip == src)
    sessions = (await db.execute(q.order_by(desc(AttackerSession.first_seen)).limit(30))).scalars().all()

    ev_q = select(RawEventModel).order_by(desc(RawEventModel.timestamp))
    if src:
        ev_q = ev_q.where(RawEventModel.attacker_ip == src)
    events = (await db.execute(ev_q.limit(200))).scalars().all()

    cmd_rows = [[e.timestamp.strftime("%Y-%m-%d %H:%M:%S") if e.timestamp else "—",
                 e.attacker_ip, e.honeypot_type or "—", (e.commands or "")[:90]]
                for e in events if e.commands]

    actor = profile.get("actor", {})
    kc = profile.get("killchain", {})

    return {
        "title": "Digital Forensics & Incident Response Report",
        "subject": src or "All attacker sessions",
        "sources": ["attacker_sessions", "raw_events", "behavioral graph analysis"],
        "sections": [
            text("Behavioral assessment", [
                f"Closest behavioural cluster: {actor.get('name', 'unclassified')} "
                f"(match confidence {actor.get('confidence', 0)}%, derived from observed TTPs — "
                f"not a formal attribution).",
                f"Kill-chain position: {kc.get('stage_name', 'unknown')} ({kc.get('percent', 0)}% progressed).",
            ]),
            table("Observed traits", ["Dimension", "Assessment"],
                  [[k, v] for k, v in (actor.get("traits", {}) or {}).items()],
                  note="Source: behavioral graph analysis over the interaction graph."),
            table("Attacker sessions", ["First seen", "Last seen", "Source IP", "Country", "Events", "Risk"],
                  [[s.first_seen.strftime("%Y-%m-%d %H:%M") if s.first_seen else "—",
                    s.last_seen.strftime("%Y-%m-%d %H:%M") if s.last_seen else "—",
                    s.attacker_ip, s.geoip_country or "—", s.total_events, s.risk_level or "—"]
                   for s in sessions],
                  note="Source: attacker_sessions."),
            table("Command history", ["Time", "Source IP", "Sensor", "Command"], cmd_rows[:120],
                  note="Source: raw_events.commands (most recent 120 with a command payload)."),
        ],
        "record_count": len(events),
    }


# ── detection validation coverage ────────────────────────────────────────────
async def detection_validation_report(db, params, user) -> Dict[str, Any]:
    from app.services.detection_validation import coverage_report
    cov = await coverage_report(db)
    scen = cov.get("scenarios", [])

    rows = []
    for s in scen:
        m = s.get("metrics") or {}
        rows.append([s.get("scenario_id", "?"), s.get("last_result", "NONE"),
                     f"{m.get('detection_success_rate', 0) * 100:.0f}%",
                     f"{m.get('attack_coverage', 0) * 100:.0f}%",
                     ", ".join(m.get("missing_detections", []))[:40] or "—",
                     s.get("last_run_at", "—") or "—"])
    passing = sum(1 for s in scen if s.get("last_result") == "PASS")

    return {
        "title": "Detection Validation & Coverage Report",
        "subject": "SOC control testing",
        "sources": ["scenario_runs", "detections", "scenarios/*.yaml"],
        "sections": [
            kpis(
                ("Scenarios", len(scen)),
                ("Passing", f"{passing} / {len(scen)}"),
                ("Never run", sum(1 for s in scen if not s.get("last_run_at"))),
            ),
            table("Scenario results", ["Scenario", "Result", "Detect rate", "ATT&CK cov.", "Missing detections", "Last run"],
                  rows, note="Source: detection_validation.coverage_report — real grading against the last run."),
            note("A scenario fires the matching controlled attack at the local honeypots "
                 "(target hard-locked to 127.0.0.1), waits one detection cycle, then grades "
                 "the real detections produced. FAIL / PARTIAL rows are genuine coverage gaps."),
        ],
        "record_count": len(scen),
    }


# ── malware analysis (from the cached real pipeline report) ──────────────────
async def malware_report(db, params, user) -> Dict[str, Any]:
    from app.api.v1.endpoints.malware import _get_full_report
    sha = params.get("sha256") or params.get("subject")
    if not sha:
        raise ValueError("sha256 is required for a malware report")
    r = _get_full_report(sha)
    if not r:
        raise ValueError(f"no analysis on file for {sha} — upload the sample first")

    secrets = r.get("secrets", {})
    yara = r.get("yara", {})
    static = r.get("static", {})
    av = r.get("av", {})

    sec_rows = [[f.get("type", "?"), f.get("severity", "?"), (f.get("match", "") or "")[:50],
                 (f.get("location", "") or "")[:40]] for f in secrets.get("findings", [])[:80]]
    yara_rows = [[m.get("rule", "?"), (m.get("meta", {}) or {}).get("family", "—"),
                  ", ".join(m.get("tags", []))[:40]] for m in yara.get("matches", [])]

    return {
        "title": "Malware Analysis Report",
        "subject": sha[:32],
        "sources": ["static analyzer", "YARA", "ClamAV", "secret detector"] + (["MobSF"] if r.get("apk") else []),
        "sections": [
            kpis(
                ("File type", r.get("file_type", "—")),
                ("Threat family", r.get("threat_family", "Unknown")),
                ("Score", r.get("score", "—")),
                ("Risk level", r.get("risk_level", "—")),
                ("Secrets found", secrets.get("total", 0)),
                ("YARA matches", yara.get("count", 0)),
            ),
            text("File identity", [
                f"SHA-256: {sha}",
                f"Analyzed at: {r.get('analyzed_at', '—')}",
                f"ClamAV: {av.get('clamav', {}).get('signature') or ('clean' if av.get('clamav', {}).get('infected') is False else 'no verdict')}",
            ]),
            table("Static analysis", ["Property", "Value"],
                  [[k, str(v)[:80]] for k, v in static.items() if not isinstance(v, (dict, list))][:30],
                  note="Source: static_analyzer.py (real PE/ELF/script parsing)."),
            table("YARA signature matches", ["Rule", "Family", "Tags"], yara_rows,
                  note="Source: backend/yara_rules via yara-python."),
            table("Hardcoded secrets", ["Type", "Severity", "Match (redacted)", "Location"], sec_rows,
                  note="Source: secret_detector.py regex engine."),
        ],
        "record_count": secrets.get("total", 0),
    }
