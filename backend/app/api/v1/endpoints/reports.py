"""
Report generation + registry API.

POST /reports/{type}          generate a report (PDF), persist it, return metadata
GET  /reports                 list generated reports (newest first)
GET  /reports/types           available report types
GET  /reports/{id}            one report's metadata
GET  /reports/{id}/download   stream the file with its download filename
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import get_current_active_user
from app.db.database import get_db
from app.models.all_models import GeneratedReport, User
from app.services.reporting import engine
from app.services.reporting.registry import REGISTRY, get as get_def

router = APIRouter()

REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "/app/reports"))
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


class GenerateBody(BaseModel):
    params: Dict[str, Any] = {}


def _brief(r: GeneratedReport) -> Dict[str, Any]:
    return {
        "id": r.id, "report_type": r.report_type, "title": r.title, "subject": r.subject,
        "fmt": r.fmt, "filename": r.filename, "sha256": r.sha256, "size_bytes": r.size_bytes,
        "generated_by": r.generated_by_email, "generated_at": r.generated_at.isoformat() if r.generated_at else None,
        "window_start": r.window_start.isoformat() if r.window_start else None,
        "window_end": r.window_end.isoformat() if r.window_end else None,
        "status": r.status, "error": r.error,
        "download_url": f"/api/v1/reports/{r.id}/download",
    }


@router.get("/types")
async def list_types(user: User = Depends(get_current_active_user)):
    is_admin = (user.role or "") in ("ADMIN", "SUPER_ADMIN")
    return [
        {"type": k, "title": v.title, "admin_only": v.admin_only}
        for k, v in REGISTRY.items() if is_admin or not v.admin_only
    ]


@router.get("")
@router.get("/")
async def list_reports(
    report_type: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    q = select(GeneratedReport).order_by(desc(GeneratedReport.generated_at)).limit(limit)
    if report_type:
        q = q.where(GeneratedReport.report_type == report_type)
    rows = (await db.execute(q)).scalars().all()
    return {"reports": [_brief(r) for r in rows]}


@router.post("/{report_type}")
async def generate(
    report_type: str,
    body: GenerateBody = GenerateBody(),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    try:
        rdef = get_def(report_type)
    except KeyError:
        raise HTTPException(404, f"unknown report type: {report_type}")

    is_admin = (user.role or "") in ("ADMIN", "SUPER_ADMIN")
    if rdef.admin_only and not is_admin:
        raise HTTPException(403, "this report requires an admin session")

    params = body.params or {}
    now = datetime.now(timezone.utc)
    report_id = str(uuid.uuid4())

    try:
        ctx = await rdef.builder(db, params, user)
    except ValueError as e:
        raise HTTPException(422, str(e))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(500, f"report data assembly failed: {e}")

    subject = ctx.get("subject") or params.get("subject") or "global"
    ctx.setdefault("title", rdef.title)
    ctx.update({
        "report_type": report_type,
        "document_id": report_id,
        "generated_by_email": user.email,
        "generated_by_id": user.id,
        "operator_local": now.astimezone().strftime("%Y-%m-%d %H:%M %Z") if now.astimezone().tzinfo else None,
        "disclaimer": ctx.get("disclaimer") or rdef.disclaimer or None,
    })

    try:
        pdf = engine.render_pdf(rdef.template, ctx)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(500, f"PDF rendering failed: {e}")

    sha = engine.sha256_bytes(pdf)
    fname = engine.report_filename(report_type, subject, now)
    fpath = REPORTS_DIR / fname
    fpath.write_bytes(pdf)

    row = GeneratedReport(
        id=report_id, report_type=report_type, title=ctx["title"], subject=str(subject)[:255], fmt="pdf",
        file_path=str(fpath), filename=fname, sha256=sha, size_bytes=len(pdf),
        generated_by_id=user.id, generated_by_email=user.email, generated_at=now.replace(tzinfo=None),
        params_json=params,
        window_start=ctx.get("window_start"), window_end=ctx.get("window_end"),
        status="ready",
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return _brief(row)


@router.get("/{report_id}")
async def get_report(report_id: str, db: AsyncSession = Depends(get_db),
                     user: User = Depends(get_current_active_user)):
    r = (await db.execute(select(GeneratedReport).where(GeneratedReport.id == report_id))).scalars().first()
    if not r:
        raise HTTPException(404, "report not found")
    return _brief(r)


@router.get("/{report_id}/download")
async def download(report_id: str, db: AsyncSession = Depends(get_db),
                   user: User = Depends(get_current_active_user)):
    r = (await db.execute(select(GeneratedReport).where(GeneratedReport.id == report_id))).scalars().first()
    if not r:
        raise HTTPException(404, "report not found")
    if not os.path.exists(r.file_path):
        raise HTTPException(410, "report file no longer on disk")
    return FileResponse(r.file_path, media_type="application/pdf", filename=r.filename)
