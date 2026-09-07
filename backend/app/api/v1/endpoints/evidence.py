"""
Evidence / chain-of-custody API (task 6).

  * list evidence for an incident, read one item
  * add analyst evidence (note / exported log / splunk result / file attachment)
  * verify integrity (recompute the content hash)
  * download the raw malware sample — ADMIN + clearance 3 only, streamed with a
    forced-download disposition and a defanged name. NEVER a static directory.
"""

from __future__ import annotations

import os
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import get_current_active_user, require_clearance, require_role
from app.db.database import get_db
from app.models.all_models import Evidence, Incident, User
from app.services.evidence_service import add_analyst_evidence, verify_evidence

router = APIRouter()

_ANALYST_ROLES = ["ANALYST", "AUDITOR", "OVERSEER", "ADMIN"]
_ANALYST_EVIDENCE_TYPES = {"analyst_note", "exported_log", "splunk_result", "attachment"}
_MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024


def _ev_public(e: Evidence) -> dict:
    return {
        "id": e.id, "incident_id": e.incident_id, "type": e.type,
        "sha256": e.sha256, "md5": e.md5, "sha1": e.sha1,
        "source": e.source, "ref": e.ref,
        "acquired_at": e.acquired_at.isoformat() if e.acquired_at else None,
        "created_at": e.created_at.isoformat() if e.created_at else None,
        "metadata": e.evidence_metadata or {},
        "content_hash": e.content_hash,
        "immutable": e.immutable,
        "added_by": e.added_by,
    }


async def _get_incident(db: AsyncSession, incident_id: str) -> Incident:
    inc = (await db.execute(
        select(Incident).where((Incident.id == incident_id) | (Incident.incident_key == incident_id))
    )).scalars().first()
    if not inc:
        raise HTTPException(status_code=404, detail="incident not found")
    return inc


@router.get("")
@router.get("/")
async def list_evidence(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_active_user),
):
    inc = await _get_incident(db, incident_id)
    rows = (await db.execute(
        select(Evidence).where(Evidence.incident_id == inc.id).order_by(Evidence.created_at.asc())
    )).scalars().all()
    return {"incident_key": inc.incident_key, "count": len(rows), "evidence": [_ev_public(e) for e in rows]}


@router.post("/incident/{incident_id}")
async def add_evidence(
    incident_id: str,
    request: Request,
    type: str = Form(...),
    text: Optional[str] = Form(None),
    ref: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role(_ANALYST_ROLES)),
):
    if type not in _ANALYST_EVIDENCE_TYPES:
        raise HTTPException(status_code=400, detail=f"type must be one of {sorted(_ANALYST_EVIDENCE_TYPES)}")
    inc = await _get_incident(db, incident_id)

    file_bytes = None
    filename = None
    if file is not None:
        file_bytes = b""
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            file_bytes += chunk
            if len(file_bytes) > _MAX_ATTACHMENT_BYTES:
                raise HTTPException(status_code=413, detail="attachment too large")
        filename = file.filename
        type = "attachment"

    if type in ("analyst_note", "exported_log", "splunk_result") and not text:
        raise HTTPException(status_code=400, detail="text is required for this evidence type")

    ev = await add_analyst_evidence(
        db, inc, etype=type, source="analyst",
        text=text, ref=ref, file_bytes=file_bytes, filename=filename,
        added_by=user.email,
    )
    await db.commit()
    return {"status": "success", "evidence": _ev_public(ev)}


@router.get("/{evidence_id}")
async def get_evidence(evidence_id: str, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_active_user)):
    ev = (await db.execute(select(Evidence).where(Evidence.id == evidence_id))).scalars().first()
    if not ev:
        raise HTTPException(status_code=404, detail="evidence not found")
    return _ev_public(ev)


@router.get("/{evidence_id}/verify")
async def verify(evidence_id: str, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_active_user)):
    ev = (await db.execute(select(Evidence).where(Evidence.id == evidence_id))).scalars().first()
    if not ev:
        raise HTTPException(status_code=404, detail="evidence not found")
    return verify_evidence(ev)


@router.get("/{evidence_id}/sample")
async def download_sample(
    evidence_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role(["ADMIN"])),
    __: User = Depends(require_clearance(3)),
):
    ev = (await db.execute(select(Evidence).where(Evidence.id == evidence_id))).scalars().first()
    if not ev or ev.type != "malware_sample" or not ev.sha256:
        raise HTTPException(status_code=404, detail="no downloadable sample for this evidence item")

    from app.api.v1.endpoints.malware import quarantine_path

    path = quarantine_path(ev.sha256)
    if not os.path.exists(path):
        raise HTTPException(status_code=410, detail="sample no longer in quarantine")

    def _stream():
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                yield chunk

    return StreamingResponse(
        _stream(),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{ev.sha256}.bin"',
            "X-Content-Type-Options": "nosniff",
            "X-Shadow-Trust-Warning": "live malware sample - handle in an isolated environment",
        },
    )
