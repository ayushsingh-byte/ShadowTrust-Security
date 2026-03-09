from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, desc
from sqlalchemy.future import select
from typing import Dict, Any, List

from app.db.sqlite_db import get_db
from app.models.all_models import RawEventModel

router = APIRouter()

@router.get("/status")
async def get_honeypot_status(db: AsyncSession = Depends(get_db)):
    """Shows activity per honeypot."""
    result = await db.execute(
        select(RawEventModel.honeypot_type, func.count(RawEventModel.id).label('count'))
        .group_by(RawEventModel.honeypot_type)
        .order_by(desc('count'))
    )
    return [{"honeypot": row.honeypot_type, "events": row.count} for row in result.all() if row.honeypot_type]
