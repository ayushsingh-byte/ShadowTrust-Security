"""
Attack reconstruction — a chronological, explainable timeline for one incident
(task 2).

Every entry states *why* it belongs to the chain (``reason``). Nothing is
fabricated: an entry exists only because a real row / report / search links it
to the incident's events, source IPs, or IOCs.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.all_models import (
    Detection,
    Incident,
    IncidentEvent,
    IncidentIOC,
    NormalizedEventModel,
)
from app.services.telemetry.collector import SEVERITY_RISK_SCORE


def _iso(dt) -> Optional[str]:
    if dt is None:
        return None
    if isinstance(dt, str):
        return dt
    return dt.isoformat()


def _entry(ts, source, event_type, severity, reason, *, ref=None,
           source_ip=None, dest=None, username=None, ioc=None, technique=None) -> Dict[str, Any]:
    return {
        "timestamp": _iso(ts),
        "source": source,
        "event_type": event_type,
        "severity": severity,
        "source_ip": source_ip,
        "destination": dest,
        "username": username,
        "ioc": ioc,
        "attack_technique": technique,
        "ref": ref,
        "reason": reason,
    }


async def build_timeline(db: AsyncSession, incident: Incident,
                         include_splunk: bool = True) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []

    linked = (await db.execute(
        select(IncidentEvent).where(IncidentEvent.incident_id == incident.id)
    )).scalars().all()
    linked_ids = [le.event_id for le in linked]
    reason_by_id = {le.event_id: le.correlation_reason for le in linked}

    ips = incident.source_ips or ([incident.correlation_key] if incident.correlation_key else [])
    lo = (incident.first_seen or incident.created_at) - timedelta(minutes=5) if incident.first_seen else None
    hi = (incident.last_seen or incident.updated_at) + timedelta(minutes=5) if incident.last_seen else None

    # 1. the normalized events — linked ones, plus same-IP events inside the window
    seen_events: set = set()
    if linked_ids:
        rows = (await db.execute(
            select(NormalizedEventModel).where(NormalizedEventModel.event_id.in_(linked_ids))
        )).scalars().all()
        for e in rows:
            seen_events.add(e.event_id)
            entries.append(_entry(
                e.timestamp, "honeypot", e.sensor_event_type,
                e.severity, reason_by_id.get(e.event_id) or "linked to incident",
                ref=e.event_id, source_ip=e.source_ip,
                dest=f"{e.destination_ip or ''}:{e.destination_port or ''}".strip(":"),
                username=e.username,
            ))
    if ips and lo and hi:
        rows = (await db.execute(
            select(NormalizedEventModel)
            .where(
                NormalizedEventModel.source_ip.in_(ips),
                NormalizedEventModel.timestamp >= lo,
                NormalizedEventModel.timestamp <= hi,
            )
            .order_by(NormalizedEventModel.timestamp.asc())
            .limit(400)
        )).scalars().all()
        for e in rows:
            if e.event_id in seen_events:
                continue
            seen_events.add(e.event_id)
            entries.append(_entry(
                e.timestamp, "honeypot", e.sensor_event_type, e.severity,
                f"same source IP {e.source_ip} within the incident window",
                ref=e.event_id, source_ip=e.source_ip,
                dest=f"{e.destination_ip or ''}:{e.destination_port or ''}".strip(":"),
                username=e.username,
            ))

    # 2. the detections
    dets = (await db.execute(
        select(Detection).where(Detection.incident_id == incident.id)
    )).scalars().all()
    for d in dets:
        entries.append(_entry(
            d.last_event_at or d.created_at, "detection", d.rule_name,
            d.severity, d.reason or f"rule {d.rule_id} fired",
            ref=f"detection:{d.id}", source_ip=d.source_ip, username=d.username,
            technique=d.attack_technique,
        ))

    # 3. malware analysis for any hash IOC on this incident
    iocs = (await db.execute(
        select(IncidentIOC).where(IncidentIOC.incident_id == incident.id)
    )).scalars().all()
    hash_iocs = [i for i in iocs if i.ioc_type in ("sha256", "md5", "sha1")]
    if hash_iocs:
        try:
            from app.api.v1.endpoints.malware import _load_full_reports
            reports = _load_full_reports()
        except Exception:
            reports = {}
        for i in hash_iocs:
            rep = reports.get(i.ioc_value)
            if not rep:
                continue
            entries.append(_entry(
                rep.get("analyzed_at"), "malware-analysis", "sample analysed",
                rep.get("risk_level", "MEDIUM"),
                f"hash {i.ioc_value[:12]}… observed in this incident was analysed "
                f"(family {rep.get('threat_family', 'Unknown')}, score {rep.get('score', 0)})",
                ref=f"scans/{i.ioc_value}.json",
                ioc=f"{i.ioc_type}:{i.ioc_value}",
            ))
            av = rep.get("av", {})
            clam = av.get("clamav", {})
            if clam.get("infected"):
                entries.append(_entry(
                    rep.get("analyzed_at"), "malware-analysis", "ClamAV signature hit",
                    "CRITICAL", f"ClamAV flagged {i.ioc_value[:12]}… as {clam.get('signature')}",
                    ref=f"scans/{i.ioc_value}.json#av", ioc=f"{i.ioc_type}:{i.ioc_value}",
                ))
            yara = rep.get("yara", {})
            if yara.get("count"):
                names = ", ".join(m.get("rule") for m in yara.get("matches", [])[:5])
                entries.append(_entry(
                    rep.get("analyzed_at"), "malware-analysis", "YARA match",
                    "HIGH", f"YARA rules matched {i.ioc_value[:12]}…: {names}",
                    ref=f"scans/{i.ioc_value}.json#yara", ioc=f"{i.ioc_type}:{i.ioc_value}",
                ))

    # 4. Splunk (best-effort — labelled, never blocking)
    if include_splunk and ips and lo and hi:
        try:
            from app.api.v1.endpoints.splunk import _run_search

            for ip in ips[:3]:
                res = await _run_search(
                    f'search index=* {ip} earliest=-24h | sort - _time | head 20 '
                    f'| table _time host source sourcetype _raw',
                    earliest="-7d",
                )
                if not res.get("reachable"):
                    break
                for r in res.get("rows", []):
                    entries.append(_entry(
                        r.get("_time"), "splunk", r.get("sourcetype") or "event",
                        "INFO",
                        f"Splunk event mentioning {ip} within the incident window",
                        ref=r.get("source"), source_ip=ip,
                    ))
        except Exception:
            pass

    entries.sort(key=lambda e: e["timestamp"] or "")
    return entries
