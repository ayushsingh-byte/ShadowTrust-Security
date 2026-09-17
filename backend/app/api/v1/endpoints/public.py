"""Unauthenticated, aggregate-only platform status for the sign-in page."""

import os
from datetime import datetime
from typing import Any, Dict

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.models.all_models import NormalizedEventModel
from app.services.aws_telemetry_service import telemetry_engine
from app.services.telemetry.collector import local_collector

router = APIRouter()


@router.get("/summary")
async def public_summary(db: AsyncSession = Depends(get_db)) -> Dict[str, Any]:
    """Two counters and whether ingestion is running — no per-event, per-IP or per-user detail."""
    events = (await db.execute(select(func.count(NormalizedEventModel.event_id)))).scalar() or 0
    attackers = (await db.execute(
        select(func.count(func.distinct(NormalizedEventModel.source_ip)))
    )).scalar() or 0

    if os.getenv("INFRA_PROVIDER", "local").strip().lower() == "aws":
        pipeline = {"running": bool(getattr(telemetry_engine, "is_running", False)), "mode": "s3"}
    else:
        pipeline = {"running": local_collector.is_running, "mode": local_collector.mode}

    return {
        "events_logged": events,
        "unique_attackers": attackers,
        "pipeline": pipeline,
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }


_status_cache: Dict[str, Any] = {"at": 0.0, "data": None}


@router.get("/status")
async def public_status() -> Dict[str, Any]:
    """
    Live service / sensor / pipeline state for the public status page.
    Names and up/down only (same safe view as /health, minus DB/schema detail).
    Cached 15s so an unauthenticated caller can't drive the container probes.
    """
    import time
    from app.health_page import _build_full_data, _safe_view

    now = time.monotonic()
    if _status_cache["data"] is None or now - _status_cache["at"] > 15:
        safe = _safe_view(await _build_full_data())
        _status_cache["data"] = {
            "generated_at": safe.get("generated_at"),
            "backend": {"status": (safe.get("backend") or {}).get("status"),
                        "uptime_seconds": (safe.get("backend") or {}).get("uptime_seconds")},
            "database": {"status": (safe.get("database") or {}).get("status")},
            "services": [s for s in safe.get("services", []) if s.get("status") != "stopped"],
            "sensors": [{"name": s.get("name"), "status": s.get("status"), "last_event": s.get("last_event")}
                        for s in safe.get("sensors", [])],
            "collector": {"running": (safe.get("collector") or {}).get("running"),
                          "last_cycle_at": (safe.get("collector") or {}).get("last_cycle_at")},
        }
        _status_cache["at"] = now
    return _status_cache["data"]
