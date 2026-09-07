"""
SOC 2 readiness + GRC API.

GET /compliance/controls           the SOC 2 control catalogue
GET /compliance/assessment         live readiness self-assessment (evidence + scoring)
GET /compliance/risk-register      automated risk register
GET /compliance/risk-register/export?fmt=csv|json
"""
from __future__ import annotations

import csv
import io
import json

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import get_current_active_user
from app.db.database import get_db
from app.models.all_models import User
from app.services.compliance.assessment import run_assessment
from app.services.compliance.framework import CATALOG
from app.services.compliance.risk_register import build_risks

router = APIRouter()


@router.get("/controls")
async def controls(user: User = Depends(get_current_active_user)):
    return {"framework": "AICPA SOC 2 Trust Services Criteria",
            "controls": [c._asdict() for c in CATALOG]}


@router.get("/assessment")
async def assessment(db: AsyncSession = Depends(get_db),
                     user: User = Depends(get_current_active_user)):
    return await run_assessment(db)


@router.get("/risk-register")
async def risk_register(db: AsyncSession = Depends(get_db),
                        user: User = Depends(get_current_active_user)):
    risks = await build_risks(db)
    return {
        "generated_at": (await run_assessment(db))["generated_at"] if False else None,
        "count": len(risks),
        "by_rating": {r: sum(1 for x in risks if x["rating"] == r) for r in ("Critical", "High", "Medium", "Low")},
        "risks": risks,
    }


@router.get("/risk-register/export")
async def risk_register_export(fmt: str = Query("csv"),
                               db: AsyncSession = Depends(get_db),
                               user: User = Depends(get_current_active_user)):
    risks = await build_risks(db)
    if fmt == "json":
        return Response(json.dumps(risks, indent=2), media_type="application/json",
                        headers={"Content-Disposition": 'attachment; filename="ShadowTrust-RiskRegister.json"'})
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=["id", "title", "source", "category", "likelihood",
                                        "impact", "score", "rating", "treatment", "owner", "status"])
    w.writeheader()
    for r in risks:
        w.writerow(r)
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="ShadowTrust-RiskRegister.csv"'})
