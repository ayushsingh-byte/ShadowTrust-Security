from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, desc
from sqlalchemy.future import select
from typing import Dict, Any, List

from app.db.sqlite_db import get_db
from app.models.all_models import RawEventModel
from app.services.aws_telemetry_service import telemetry_engine

router = APIRouter()

@router.get("/recent")
async def get_recent_attacks(limit: int = 50, db: AsyncSession = Depends(get_db)):
    """Returns latest attack events perfectly synced to the SQLite index."""
    
    # Query Database for ground truth payloads
    result = await db.execute(
        select(RawEventModel).order_by(desc(RawEventModel.timestamp)).limit(limit)
    )
    events = result.scalars().all()
    return [{
        "id": e.id,
        "timestamp": e.timestamp.isoformat(),
        "source_ip": e.attacker_ip,
        "target_port": e.target_port,
        "honeypot_type": e.honeypot_type,
        "event_type": e.event_type
    } for e in events]

@router.get("/top-ips")
async def get_top_ips(limit: int = 10, db: AsyncSession = Depends(get_db)):
    """Returns most active attacker IPs."""
    result = await db.execute(
        select(RawEventModel.attacker_ip, func.count(RawEventModel.id).label('count'))
        .group_by(RawEventModel.attacker_ip)
        .order_by(desc('count'))
        .limit(limit)
    )
    return [{"ip": row.attacker_ip, "count": row.count} for row in result.all()]

@router.get("/by-port")
async def get_attacks_by_port(db: AsyncSession = Depends(get_db)):
    """Returns attack distribution by service/port."""
    result = await db.execute(
        select(RawEventModel.target_port, func.count(RawEventModel.id).label('count'))
        .group_by(RawEventModel.target_port)
        .order_by(desc('count'))
    )
    return [{"port": row.target_port, "count": row.count} for row in result.all() if row.target_port]

@router.get("/timeline")
async def get_attack_timeline(db: AsyncSession = Depends(get_db)):
    """Returns time-series attack activity (grouped by hour for simplicity)."""
    # SQLite datetime slice to get YYYY-MM-DD HH
    result = await db.execute(
        select(
            func.substr(RawEventModel.timestamp, 1, 13).label('hour'),
            func.count(RawEventModel.id).label('count')
        )
        .group_by('hour')
        .order_by(desc('hour'))
        .limit(24)
    )
    return [{"time": f"{row.hour}:00:00Z", "count": row.count} for row in result.all()]

@router.get("/categories")
async def get_attack_categories(db: AsyncSession = Depends(get_db)):
    """Returns ML-classified attack types."""
    # Since we mapped ml_category -> event_type during S3 ingestion
    result = await db.execute(
        select(RawEventModel.event_type, func.count(RawEventModel.id).label('count'))
        .group_by(RawEventModel.event_type)
        .order_by(desc('count'))
    )
    return [{"category": row.event_type, "count": row.count} for row in result.all()]
