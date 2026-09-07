"""
SOC testing / detection validation API (tasks 8 + 9).

Executes or evaluates a controlled attack scenario and grades the real
detection pipeline output against the scenario's expectations.

``execute`` mode fires local attack traffic — ADMIN only, target hard-locked
to 127.0.0.1.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import get_current_active_user, require_role
from app.db.database import get_db
from app.models.all_models import ScenarioRun, User
from app.services.detection_validation import (
    coverage_report,
    load_scenarios,
    run_scenario,
)

router = APIRouter()


@router.get("/scenarios")
async def list_scenarios(_: User = Depends(get_current_active_user)):
    scenarios = load_scenarios()
    return {
        "count": len(scenarios),
        "scenarios": [
            {
                "id": s["id"],
                "description": (s.get("description") or "").strip(),
                "target": s.get("target", "127.0.0.1"),
                "script_scenario": s.get("script_scenario"),
                "requires": s.get("requires"),
                "expected_telemetry": s.get("expected_telemetry", []),
                "expected_detections": s.get("expected_detections", []),
                "expected_techniques": s.get("expected_techniques", []),
                "expected_severity": s.get("expected_severity"),
                "expected_incident": s.get("expected_incident", False),
            }
            for s in scenarios.values()
        ],
    }


class RunBody(BaseModel):
    mode: str = "evaluate"          # evaluate | execute
    settle_seconds: Optional[int] = None


def _run_public(r: ScenarioRun) -> dict:
    return {
        "id": r.id,
        "scenario_id": r.scenario_id,
        "mode": r.mode,
        "status": r.status,
        "result": r.result,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
        "expected": r.expected,
        "observed": r.observed,
        "detections_seen": r.detections_seen,
        "techniques_seen": r.techniques_seen,
        "severity_seen": r.severity_seen,
        "metrics": r.metrics,
        "triggered_by": r.triggered_by,
    }


@router.post("/scenarios/{scenario_id}/run")
async def run(
    scenario_id: str,
    body: RunBody,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role(["ADMIN"])),
):
    if body.mode not in ("evaluate", "execute"):
        raise HTTPException(status_code=400, detail="mode must be 'evaluate' or 'execute'")
    try:
        result = await run_scenario(
            db, scenario_id, mode=body.mode,
            triggered_by=user.email, settle_seconds=body.settle_seconds,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"status": "complete", "run": _run_public(result)}


@router.get("/runs")
async def list_runs(
    scenario_id: Optional[str] = None,
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_active_user),
):
    q = select(ScenarioRun).order_by(ScenarioRun.started_at.desc())
    if scenario_id:
        q = q.where(ScenarioRun.scenario_id == scenario_id)
    rows = (await db.execute(q.limit(limit))).scalars().all()
    return {"count": len(rows), "runs": [_run_public(r) for r in rows]}


@router.get("/runs/{run_id}")
async def get_run(run_id: str, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_active_user)):
    r = (await db.execute(select(ScenarioRun).where(ScenarioRun.id == run_id))).scalars().first()
    if not r:
        raise HTTPException(status_code=404, detail="run not found")
    return _run_public(r)


@router.get("/coverage")
async def coverage(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_active_user)):
    return await coverage_report(db)
