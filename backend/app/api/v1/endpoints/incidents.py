"""
Incident Management API (task 1) — the investigation workspace.

An incident is the unit an analyst works: it aggregates detections, events,
IOCs, ATT&CK techniques, evidence, a timeline, notes and an activity log, and
carries an explainable severity (``risk_breakdown``).

Incidents are created by the detection engine (correlation) and by analysts
manually. Status transitions and notes are audited.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import get_current_active_user, require_role
from app.db.database import get_db
from app.models.all_models import (
    AdminActivity,
    Detection,
    Evidence,
    Incident,
    IncidentActivity,
    IncidentEvent,
    IncidentIOC,
    NormalizedEventModel,
    User,
)
from app.services.timeline_builder import build_timeline

router = APIRouter()

_STATUSES = {"NEW", "TRIAGING", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"}
_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
_ANALYST_ROLES = ["ANALYST", "AUDITOR", "OVERSEER", "ADMIN"]

# the kinds ``extract_iocs`` emits, plus the two an analyst commonly adds by hand
_IOC_TYPES = {"ip", "domain", "url", "md5", "sha1", "sha256", "email", "filename"}
_TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
_MAX_LINK_EVENTS = 500


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _clean_techniques(raw: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Validate ``[{id,tactic,name}]`` and fill name/tactic from the ATT&CK catalog."""
    try:                                            # lazy: avoid an endpoint->endpoint import at module load
        from app.api.v1.endpoints.mitre import ATTACK_CATALOG
        catalog = {t["id"]: t for t in ATTACK_CATALOG}
    except Exception:
        catalog = {}

    out: List[Dict[str, Any]] = []
    seen: set = set()
    for item in raw or []:
        if not isinstance(item, dict):
            raise HTTPException(status_code=400, detail="each technique must be an object")
        tid = str(item.get("id", "")).strip().upper()
        if not _TECHNIQUE_ID.match(tid):
            raise HTTPException(status_code=400, detail=f"invalid ATT&CK technique id: {tid or '(empty)'}")
        if tid in seen:
            continue
        seen.add(tid)
        known = catalog.get(tid, {})
        out.append({
            "id": tid,
            "name": str(item.get("name") or known.get("name") or "")[:200],
            "tactic": str(item.get("tactic") or known.get("tactic") or "")[:100],
        })
    return out


async def _link_events(
    db: AsyncSession, inc: Incident, event_ids: List[str], reason: str,
) -> Dict[str, int]:
    """
    Link normalized events to an incident.

    Linking is what makes a manual incident investigable: ``build_timeline``
    resolves ``IncidentEvent.event_id`` against ``NormalizedEventModel``. We also
    widen ``first_seen``/``last_seen`` and the attribution lists, otherwise the
    timeline's same-source-IP sweep would only cover the moment of creation.
    """
    ids = [e for e in dict.fromkeys(event_ids) if e][:_MAX_LINK_EVENTS]
    if not ids:
        return {"linked": 0, "already_linked": 0, "not_found": 0}

    found = {e.event_id: e for e in (await db.execute(
        select(NormalizedEventModel).where(NormalizedEventModel.event_id.in_(ids))
    )).scalars().all()}
    already = set((await db.execute(
        select(IncidentEvent.event_id).where(IncidentEvent.incident_id == inc.id)
    )).scalars().all())

    ips = set(inc.source_ips or [])
    users = set(inc.related_users or [])
    sensors = set(inc.related_sensors or [])
    stamps: List[datetime] = []
    linked = dupes = 0

    for eid in ids:
        ev = found.get(eid)
        if ev is None:
            continue
        if eid in already:
            dupes += 1
            continue
        db.add(IncidentEvent(
            incident_id=inc.id, event_id=eid,
            source=ev.sensor or "honeypot", correlation_reason=reason,
        ))
        already.add(eid)
        linked += 1
        if ev.timestamp:
            stamps.append(ev.timestamp)
        if ev.source_ip:
            ips.add(ev.source_ip)
        if ev.username:
            users.add(ev.username)
        if ev.sensor:
            sensors.add(ev.sensor)

    if linked:
        inc.source_ips = sorted(ips)
        inc.related_users = sorted(users)
        inc.related_sensors = sorted(sensors)
    if stamps:
        lo, hi = min(stamps), max(stamps)
        if inc.first_seen is None or lo < inc.first_seen:
            inc.first_seen = lo
        if inc.last_seen is None or hi > inc.last_seen:
            inc.last_seen = hi

    return {"linked": linked, "already_linked": dupes, "not_found": len(ids) - linked - dupes}


def _incident_brief(inc: Incident) -> Dict[str, Any]:
    return {
        "id": inc.id,
        "incident_key": inc.incident_key,
        "title": inc.title,
        "severity": inc.severity,
        "status": inc.status,
        "confidence": inc.confidence,
        "risk_score": inc.risk_score,
        "first_seen": inc.first_seen.isoformat() if inc.first_seen else None,
        "last_seen": inc.last_seen.isoformat() if inc.last_seen else None,
        "source_ips": inc.source_ips or [],
        "attack_techniques": inc.attack_techniques or [],
        "assigned_analyst": inc.assigned_analyst,
        "auto_created": inc.auto_created,
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
    }


async def _audit(db: AsyncSession, request: Request, user: User, action: str, incident: Incident, detail: str):
    db.add(IncidentActivity(
        incident_id=incident.id, actor=user.email, action=action, detail=detail,
    ))
    db.add(AdminActivity(
        admin_id=getattr(user, "id", None),
        admin_username=user.email,
        action=f"INCIDENT_{action}",
        affected_user=incident.incident_key,
        ip_address=request.client.host if request.client else None,
        result="SUCCESS",
        details=detail[:2000],
    ))


@router.get("")
@router.get("/")
async def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    assignee: Optional[str] = None,
    ip: Optional[str] = None,
    limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_active_user),
):
    q = select(Incident).order_by(Incident.last_seen.desc(), Incident.created_at.desc())
    if status:
        q = q.where(Incident.status == status.upper())
    if severity:
        q = q.where(Incident.severity == severity.upper())
    if assignee:
        q = q.where(Incident.assigned_analyst == assignee)
    rows = (await db.execute(q.limit(limit))).scalars().all()
    if ip:
        rows = [r for r in rows if ip in (r.source_ips or [])]
    return {"incidents": [_incident_brief(r) for r in rows], "count": len(rows)}


@router.get("/stats")
async def incident_stats(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_active_user)):
    by_status: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    for status_val, n in (await db.execute(
        select(Incident.status, func.count(Incident.id)).group_by(Incident.status)
    )).all():
        by_status[status_val] = n
    for sev, n in (await db.execute(
        select(Incident.severity, func.count(Incident.id)).group_by(Incident.severity)
    )).all():
        by_severity[sev] = n
    open_count = sum(v for k, v in by_status.items() if k not in ("RESOLVED", "FALSE_POSITIVE"))
    total = (await db.execute(select(func.count(Incident.id)))).scalar() or 0
    return {"total": total, "open": open_count, "by_status": by_status, "by_severity": by_severity}


@router.get("/{incident_id}")
async def get_incident(incident_id: str, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_active_user)):
    inc = (await db.execute(
        select(Incident).where((Incident.id == incident_id) | (Incident.incident_key == incident_id))
    )).scalars().first()
    if not inc:
        raise HTTPException(status_code=404, detail="incident not found")

    detections = (await db.execute(
        select(Detection).where(Detection.incident_id == inc.id).order_by(Detection.created_at.asc())
    )).scalars().all()
    links = (await db.execute(
        select(IncidentEvent).where(IncidentEvent.incident_id == inc.id)
    )).scalars().all()
    iocs = (await db.execute(
        select(IncidentIOC).where(IncidentIOC.incident_id == inc.id)
    )).scalars().all()
    activity = (await db.execute(
        select(IncidentActivity).where(IncidentActivity.incident_id == inc.id).order_by(IncidentActivity.at.asc())
    )).scalars().all()
    evidence = (await db.execute(
        select(Evidence).where(Evidence.incident_id == inc.id).order_by(Evidence.created_at.asc())
    )).scalars().all()

    return {
        **_incident_brief(inc),
        "correlation_key": inc.correlation_key,
        "related_users": inc.related_users or [],
        "related_sensors": inc.related_sensors or [],
        "detection_reasons": inc.detection_reasons or [],
        "risk_breakdown": inc.risk_breakdown or {},
        "analyst_notes": inc.analyst_notes,
        "detections": [{
            "id": d.id, "rule_id": d.rule_id, "rule_name": d.rule_name,
            "rule_source": d.rule_source, "severity": d.severity, "confidence": d.confidence,
            "attack_technique": d.attack_technique, "attack_tactic": d.attack_tactic,
            "matched_event_ids": d.matched_event_ids or [],
            "match_conditions": d.match_conditions or {},
            "reason": d.reason, "source_ip": d.source_ip,
            "first_event_at": d.first_event_at.isoformat() if d.first_event_at else None,
            "last_event_at": d.last_event_at.isoformat() if d.last_event_at else None,
        } for d in detections],
        "linked_events": [{
            "event_id": le.event_id, "source": le.source,
            "correlation_reason": le.correlation_reason,
            "added_at": le.added_at.isoformat() if le.added_at else None,
        } for le in links],
        "iocs": [{"type": i.ioc_type, "value": i.ioc_value,
                  "first_seen": i.first_seen.isoformat() if i.first_seen else None} for i in iocs],
        "evidence": [{
            "id": e.id, "type": e.type, "sha256": e.sha256, "source": e.source,
            "ref": e.ref, "immutable": e.immutable,
            "acquired_at": e.acquired_at.isoformat() if e.acquired_at else None,
        } for e in evidence],
        "activity": [{
            "actor": a.actor, "action": a.action, "detail": a.detail,
            "at": a.at.isoformat() if a.at else None,
        } for a in activity],
    }


@router.get("/{incident_id}/timeline")
async def incident_timeline(
    incident_id: str,
    splunk: bool = True,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_active_user),
):
    inc = (await db.execute(
        select(Incident).where((Incident.id == incident_id) | (Incident.incident_key == incident_id))
    )).scalars().first()
    if not inc:
        raise HTTPException(status_code=404, detail="incident not found")
    timeline = await build_timeline(db, inc, include_splunk=splunk)
    return {"incident_key": inc.incident_key, "count": len(timeline), "timeline": timeline}


class IncidentPatch(BaseModel):
    status: Optional[str] = None
    assigned_analyst: Optional[str] = None
    title: Optional[str] = None
    severity: Optional[str] = None
    attack_techniques: Optional[List[Dict[str, Any]]] = None    # full replace: [{id,tactic,name}]


@router.patch("/{incident_id}")
async def patch_incident(
    incident_id: str,
    body: IncidentPatch,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role(_ANALYST_ROLES)),
):
    inc = (await db.execute(
        select(Incident).where((Incident.id == incident_id) | (Incident.incident_key == incident_id))
    )).scalars().first()
    if not inc:
        raise HTTPException(status_code=404, detail="incident not found")

    changes: List[str] = []
    if body.status is not None:
        new = body.status.upper()
        if new not in _STATUSES:
            raise HTTPException(status_code=400, detail=f"status must be one of {sorted(_STATUSES)}")
        if new != inc.status:
            changes.append(f"status {inc.status} -> {new}")
            inc.status = new
            await _audit(db, request, user, "STATUS_CHANGE", inc, f"{changes[-1]}")
    if body.assigned_analyst is not None:
        if body.assigned_analyst != inc.assigned_analyst:
            changes.append(f"assignee -> {body.assigned_analyst or 'unassigned'}")
            inc.assigned_analyst = body.assigned_analyst or None
            await _audit(db, request, user, "ASSIGN", inc, changes[-1])
    if body.title:
        inc.title = body.title[:500]
        changes.append("title updated")
    if body.severity is not None:
        sev = body.severity.upper()
        if sev not in _SEVERITIES:
            raise HTTPException(status_code=400, detail="invalid severity")
        if sev != inc.severity:
            changes.append(f"severity {inc.severity} -> {sev} (analyst override)")
            inc.severity = sev
            await _audit(db, request, user, "STATUS_CHANGE", inc, changes[-1])
    if body.attack_techniques is not None:
        cleaned = _clean_techniques(body.attack_techniques)
        before = {t.get("id") for t in (inc.attack_techniques or [])}
        after = {t["id"] for t in cleaned}
        if before != after:
            added = sorted(after - before)
            removed = sorted(before - after)
            bits = []
            if added:
                bits.append("added " + ", ".join(added))
            if removed:
                bits.append("removed " + ", ".join(removed))
            changes.append("techniques: " + "; ".join(bits))
            inc.attack_techniques = cleaned
            await _audit(db, request, user, "TECHNIQUES", inc, changes[-1])

    inc.updated_at = _now()
    await db.commit()
    return {"status": "success", "changes": changes, "incident": _incident_brief(inc)}


class LinkEventsBody(BaseModel):
    event_ids: List[str]
    reason: str = "linked by analyst"


@router.post("/{incident_id}/events")
async def link_events(
    incident_id: str,
    body: LinkEventsBody,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role(_ANALYST_ROLES)),
):
    """Attach normalized events to an existing incident — this is what feeds the timeline."""
    inc = (await db.execute(
        select(Incident).where((Incident.id == incident_id) | (Incident.incident_key == incident_id))
    )).scalars().first()
    if not inc:
        raise HTTPException(status_code=404, detail="incident not found")

    result = await _link_events(db, inc, body.event_ids, body.reason.strip()[:500] or "linked by analyst")
    if result["linked"]:
        inc.updated_at = _now()
        await _audit(db, request, user, "EVENTS_LINK", inc,
                     f"linked {result['linked']} event(s): {body.reason.strip()[:200]}")
    await db.commit()
    return {"status": "success", **result, "incident": _incident_brief(inc)}


class IOCBody(BaseModel):
    type: str
    value: str


@router.post("/{incident_id}/iocs")
async def add_ioc(
    incident_id: str,
    body: IOCBody,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role(_ANALYST_ROLES)),
):
    inc = (await db.execute(
        select(Incident).where((Incident.id == incident_id) | (Incident.incident_key == incident_id))
    )).scalars().first()
    if not inc:
        raise HTTPException(status_code=404, detail="incident not found")

    kind = body.type.strip().lower()
    if kind not in _IOC_TYPES:
        raise HTTPException(status_code=400, detail=f"type must be one of {sorted(_IOC_TYPES)}")
    value = body.value.strip()[:512]
    if not value:
        raise HTTPException(status_code=400, detail="value is required")

    existing = (await db.execute(
        select(IncidentIOC).where(IncidentIOC.incident_id == inc.id, IncidentIOC.ioc_value == value)
    )).scalars().first()
    if existing:
        return {"status": "success", "created": False, "detail": "already present"}

    db.add(IncidentIOC(incident_id=inc.id, ioc_type=kind, ioc_value=value))
    inc.updated_at = _now()
    await _audit(db, request, user, "IOC_ADD", inc, f"{kind}:{value}")
    await db.commit()
    return {"status": "success", "created": True, "ioc": {"type": kind, "value": value}}


@router.delete("/{incident_id}/iocs")
async def remove_ioc(
    incident_id: str,
    value: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role(_ANALYST_ROLES)),
):
    inc = (await db.execute(
        select(Incident).where((Incident.id == incident_id) | (Incident.incident_key == incident_id))
    )).scalars().first()
    if not inc:
        raise HTTPException(status_code=404, detail="incident not found")

    row = (await db.execute(
        select(IncidentIOC).where(IncidentIOC.incident_id == inc.id, IncidentIOC.ioc_value == value.strip())
    )).scalars().first()
    if not row:
        raise HTTPException(status_code=404, detail="ioc not found on this incident")

    await db.delete(row)
    inc.updated_at = _now()
    await _audit(db, request, user, "IOC_REMOVE", inc, f"{row.ioc_type}:{row.ioc_value}")
    await db.commit()
    return {"status": "success", "removed": value.strip()}


class NoteBody(BaseModel):
    text: str


@router.post("/{incident_id}/notes")
async def add_note(
    incident_id: str,
    body: NoteBody,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role(_ANALYST_ROLES)),
):
    inc = (await db.execute(
        select(Incident).where((Incident.id == incident_id) | (Incident.incident_key == incident_id))
    )).scalars().first()
    if not inc:
        raise HTTPException(status_code=404, detail="incident not found")
    stamp = _now().isoformat(timespec="seconds")
    line = f"[{stamp}] {user.email}: {body.text.strip()}"
    inc.analyst_notes = (inc.analyst_notes + "\n" if inc.analyst_notes else "") + line
    inc.updated_at = _now()
    await _audit(db, request, user, "NOTE", inc, body.text.strip()[:500])
    await db.commit()
    return {"status": "success", "note": line}


class CreateIncidentBody(BaseModel):
    title: str
    severity: str = "MEDIUM"
    source_ips: List[str] = []
    event_ids: List[str] = []
    reason: str = "manually created by analyst"
    attack_techniques: List[Dict[str, Any]] = []                # [{id,tactic,name}]
    iocs: List[Dict[str, str]] = []                             # [{type,value}]


@router.post("")
@router.post("/")
async def create_incident(
    body: CreateIncidentBody,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role(_ANALYST_ROLES)),
):
    sev = body.severity.upper()
    if sev not in _SEVERITIES:
        raise HTTPException(status_code=400, detail="invalid severity")
    n = (await db.execute(select(func.count(Incident.id)))).scalar() or 0
    now = _now()
    inc = Incident(
        incident_key=f"INC-{n + 1:06d}",
        correlation_key=(body.source_ips[0] if body.source_ips else f"manual-{now.timestamp():.0f}"),
        title=body.title[:500],
        severity=sev,
        status="NEW",
        first_seen=now,
        last_seen=now,
        source_ips=body.source_ips,
        detection_reasons=[body.reason],
        attack_techniques=_clean_techniques(body.attack_techniques),
        auto_created=False,
        confidence=0.5,
    )
    db.add(inc)
    await db.flush()

    # linking validates the ids and widens the window/attribution, so the
    # timeline has something to reconstruct from
    linked = await _link_events(db, inc, body.event_ids, "added by analyst on creation")

    for item in body.iocs:
        kind = str(item.get("type", "")).strip().lower()
        value = str(item.get("value", "")).strip()[:512]
        if kind not in _IOC_TYPES:
            raise HTTPException(status_code=400, detail=f"ioc type must be one of {sorted(_IOC_TYPES)}")
        if value:
            db.add(IncidentIOC(incident_id=inc.id, ioc_type=kind, ioc_value=value))

    await _audit(
        db, request, user, "CREATE", inc,
        f"manual incident: {body.title[:200]} "
        f"({linked['linked']} event(s), {len(inc.attack_techniques or [])} technique(s), {len(body.iocs)} ioc(s))",
    )
    await db.commit()
    return {"status": "success", "events": linked, "incident": _incident_brief(inc)}
