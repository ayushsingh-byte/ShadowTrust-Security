"""
Evidence / chain-of-custody helpers (task 6).

Evidence items attach to an incident. Each carries a ``content_hash`` (SHA-256
of the evidence blob) so an analyst can verify integrity later. Items are
``immutable`` by default.

Raw malware samples are **never** exposed through a static directory — only via
the authenticated ``GET /evidence/{id}/sample`` endpoint.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.all_models import Evidence, Incident, IncidentActivity

EVIDENCE_DIR = os.path.abspath(os.getenv("EVIDENCE_DIR", "evidence"))
os.makedirs(EVIDENCE_DIR, exist_ok=True)


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _hash_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _hash_json(obj: Any) -> str:
    return _hash_bytes(json.dumps(obj, sort_keys=True, default=str).encode())


async def _has_evidence(db: AsyncSession, incident_id: str, etype: str, ref: str) -> bool:
    row = (await db.execute(
        select(Evidence).where(
            Evidence.incident_id == incident_id,
            Evidence.type == etype,
            Evidence.ref == ref,
        )
    )).scalars().first()
    return row is not None


async def attach_malware_evidence(db: AsyncSession, incident: Incident, sha256: str) -> List[Evidence]:
    """
    Create evidence items for a malware hash linked to an incident: the sample
    reference plus each section of its analysis report. Idempotent.
    """
    from app.api.v1.endpoints.malware import _load_full_reports, quarantine_path

    reports = _load_full_reports()
    report = reports.get(sha256)
    if not report:
        return []

    created: List[Evidence] = []
    qpath = None
    try:
        qpath = quarantine_path(sha256)
    except Exception:
        qpath = None

    items = [
        ("malware_sample", f"quarantine/{sha256}", {
            "present": bool(qpath and os.path.exists(qpath)),
            "size_bytes": os.path.getsize(qpath) if qpath and os.path.exists(qpath) else None,
            "file_type": report.get("file_type"),
        }, _hash_bytes((sha256 + str(report.get("file_type"))).encode())),
        ("static_report", f"scans/{sha256}.json#static", report.get("static", {}),
         _hash_json(report.get("static", {}))),
        ("sandbox_report", f"scans/{sha256}.json#sandbox", report.get("sandbox", {}),
         _hash_json(report.get("sandbox", {}))),
        ("yara_result", f"scans/{sha256}.json#yara", report.get("yara", {}),
         _hash_json(report.get("yara", {}))),
        ("clamav_result", f"scans/{sha256}.json#av.clamav", report.get("av", {}).get("clamav", {}),
         _hash_json(report.get("av", {}).get("clamav", {}))),
        ("virustotal_result", f"scans/{sha256}.json#av.virustotal", report.get("av", {}).get("virustotal", {}),
         _hash_json(report.get("av", {}).get("virustotal", {}))),
    ]

    for etype, ref, meta, content_hash in items:
        if await _has_evidence(db, incident.id, etype, ref):
            continue
        ev = Evidence(
            incident_id=incident.id,
            type=etype,
            sha256=sha256,
            md5=report.get("hashes", {}).get("md5") if isinstance(report.get("hashes"), dict) else None,
            source="malware-pipeline",
            ref=ref,
            acquired_at=_now(),
            evidence_metadata=meta if isinstance(meta, dict) else {"value": meta},
            content_hash=content_hash,
            immutable=True,
        )
        db.add(ev)
        created.append(ev)

    if created:
        db.add(IncidentActivity(
            incident_id=incident.id, actor="detection-engine", action="EVIDENCE_ADD",
            detail=f"auto-attached {len(created)} evidence item(s) for sample {sha256[:12]}…",
        ))
    return created


async def attach_event_evidence(db: AsyncSession, incident: Incident, event_id: str,
                                added_by: Optional[str] = None) -> Optional[Evidence]:
    ref = f"event:{event_id}"
    if await _has_evidence(db, incident.id, "honeypot_event", ref):
        return None
    ev = Evidence(
        incident_id=incident.id, type="honeypot_event", source="honeypot",
        ref=ref, acquired_at=_now(),
        content_hash=_hash_bytes(event_id.encode()),
        immutable=True, added_by=added_by,
    )
    db.add(ev)
    return ev


async def add_analyst_evidence(
    db: AsyncSession, incident: Incident, *, etype: str, source: str,
    text: Optional[str] = None, ref: Optional[str] = None,
    file_bytes: Optional[bytes] = None, filename: Optional[str] = None,
    added_by: Optional[str] = None,
) -> Evidence:
    """Analyst-supplied note, exported log, splunk result, or file attachment."""
    metadata: Dict[str, Any] = {}
    content_hash = None
    stored_ref = ref

    if file_bytes is not None:
        safe = "".join(c for c in (filename or "attachment") if c.isalnum() or c in "._- ")[:120] or "attachment"
        subdir = os.path.join(EVIDENCE_DIR, incident.id)
        os.makedirs(subdir, exist_ok=True)
        import uuid as _uuid
        disk = os.path.join(subdir, f"{_uuid.uuid4().hex}_{safe}")
        # containment: the resolved path must stay under EVIDENCE_DIR/<incident>
        if os.path.commonpath([os.path.realpath(disk), subdir]) != subdir:
            raise ValueError("attachment path escapes evidence dir")
        with open(disk, "wb") as fh:
            fh.write(file_bytes)
        content_hash = _hash_bytes(file_bytes)
        stored_ref = os.path.relpath(disk, os.getcwd())
        metadata = {"filename": safe, "size_bytes": len(file_bytes)}
    elif text is not None:
        content_hash = _hash_bytes(text.encode())
        metadata = {"text": text[:8000]}

    ev = Evidence(
        incident_id=incident.id, type=etype, source=source,
        ref=stored_ref, acquired_at=_now(),
        evidence_metadata=metadata, content_hash=content_hash,
        immutable=True, added_by=added_by,
    )
    db.add(ev)
    db.add(IncidentActivity(
        incident_id=incident.id, actor=added_by or "analyst", action="EVIDENCE_ADD",
        detail=f"{etype} added ({metadata.get('filename') or (text[:80] if text else stored_ref)})",
    ))
    return ev


def verify_evidence(ev: Evidence) -> Dict[str, Any]:
    """Recompute the content hash and compare with the stored one."""
    recomputed = None
    md = ev.evidence_metadata or {}
    if ev.type == "attachment" and ev.ref and os.path.exists(ev.ref):
        with open(ev.ref, "rb") as fh:
            recomputed = _hash_bytes(fh.read())
    elif "text" in md:
        recomputed = _hash_bytes(md["text"].encode())
    elif ev.ref and ev.ref.startswith("scans/"):
        try:
            from app.api.v1.endpoints.malware import _load_full_reports
            sha, _, section = ev.ref[len("scans/"):].partition(".json#")
            report = _load_full_reports().get(sha, {})
            obj = report
            for key in section.split("."):
                obj = obj.get(key, {}) if isinstance(obj, dict) else {}
            recomputed = _hash_json(obj)
        except Exception:
            recomputed = None

    return {
        "evidence_id": ev.id,
        "stored_hash": ev.content_hash,
        "recomputed_hash": recomputed,
        "verified": recomputed is not None and recomputed == ev.content_hash,
        "note": "hash recomputation not supported for this evidence type" if recomputed is None else None,
    }
