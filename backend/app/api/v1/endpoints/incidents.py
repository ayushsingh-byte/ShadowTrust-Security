"""
Incident Management API (task 1) — the investigation workspace.

An incident is the unit an analyst works: it aggregates detections, events,
IOCs, ATT&CK techniques, evidence, a timeline, notes and an activity log, and
carries an explainable severity (``risk_breakdown``).

Incidents are created by the detection engine (correlation) and by analysts
manually. Status transitions and notes are audited.
"""

from __future__ import annotations

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


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


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

    inc.updated_at = _now()
    await db.commit()
    return {"status": "success", "changes": changes, "incident": _incident_brief(inc)}


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
        auto_created=False,
        confidence=0.5,
    )
    db.add(inc)
    await db.flush()
    for eid in body.event_ids[:200]:
        db.add(IncidentEvent(incident_id=inc.id, event_id=eid, source="manual",
                             correlation_reason="added by analyst on creation"))
    await _audit(db, request, user, "CREATE", inc, f"manual incident: {body.title[:200]}")
    await db.commit()
    return {"status": "success", "incident": _incident_brief(inc)}
