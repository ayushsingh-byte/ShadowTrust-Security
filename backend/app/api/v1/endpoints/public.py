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
