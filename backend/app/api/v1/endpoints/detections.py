"""
Detection layer read API + rule management.

Detections are produced by the background detection engine
(``services/detection_engine.py``). This endpoint exposes them and lets an
admin list / reload the rule set. Rules themselves are read-only files under
``backend/detections/`` — there is no "create rule via API" surface.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import get_current_active_user, require_role
from app.db.database import get_db
from app.models.all_models import Detection, User
from app.services.detection_rules import load_rules

router = APIRouter()


def _rule_public(r) -> Dict[str, Any]:
    return {
        "id": r.id, "name": r.name, "description": r.description,
        "severity": r.severity, "confidence": r.confidence,
        "type": r.rule_type, "group_by": r.group_by,
        "timeframe_seconds": int(r.timeframe.total_seconds()),
        "threshold": r.threshold,
        "attack": {"technique": r.technique, "tactic": r.tactic},
        "selection": r.raw_selection,
        "source": "builtin",
    }


@router.get("/rules")
async def list_rules(_: User = Depends(get_current_active_user)):
    rules = load_rules()
    return {"count": len(rules), "rules": [_rule_public(r) for r in rules]}


@router.post("/rules/reload")
async def reload_rules(_: User = Depends(require_role(["ADMIN"]))):
    rules = load_rules(force=True)
    return {"status": "reloaded", "count": len(rules), "rule_ids": [r.id for r in rules]}


@router.get("")
@router.get("/")
async def list_detections(
    rule_id: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    incident_id: Optional[str] = None,
    limit: int = Query(200, le=1000),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_active_user),
):
    q = select(Detection).order_by(Detection.created_at.desc())
    if rule_id:
        q = q.where(Detection.rule_id == rule_id)
    if severity:
        q = q.where(Detection.severity == severity.upper())
    if source_ip:
        q = q.where(Detection.source_ip == source_ip)
    if incident_id:
        q = q.where(Detection.incident_id == incident_id)
    rows = (await db.execute(q.limit(limit))).scalars().all()
    return {
        "count": len(rows),
        "detections": [{
            "id": d.id, "rule_id": d.rule_id, "rule_name": d.rule_name,
            "rule_source": d.rule_source, "severity": d.severity, "confidence": d.confidence,
            "attack_technique": d.attack_technique, "attack_tactic": d.attack_tactic,
            "matched_event_ids": d.matched_event_ids or [],
            "match_conditions": d.match_conditions or {},
            "reason": d.reason, "source_ip": d.source_ip, "username": d.username,
            "incident_id": d.incident_id,
            "first_event_at": d.first_event_at.isoformat() if d.first_event_at else None,
            "last_event_at": d.last_event_at.isoformat() if d.last_event_at else None,
            "created_at": d.created_at.isoformat() if d.created_at else None,
        } for d in rows],
    }


@router.get("/stats")
async def detection_stats(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_active_user)):
    by_rule: Dict[str, int] = {}
    for rid, n in (await db.execute(
        select(Detection.rule_id, func.count(Detection.id)).group_by(Detection.rule_id)
    )).all():
        by_rule[rid] = n
    by_sev: Dict[str, int] = {}
    for sev, n in (await db.execute(
        select(Detection.severity, func.count(Detection.id)).group_by(Detection.severity)
    )).all():
        by_sev[sev] = n
    total = (await db.execute(select(func.count(Detection.id)))).scalar() or 0
    return {"total": total, "by_rule": by_rule, "by_severity": by_sev}
