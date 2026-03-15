from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from datetime import datetime, timedelta

from app.db.sqlite_db import get_db
from app.models.all_models import RawEventModel
from app.api.v1.dependencies import get_current_active_user, User
from app.ai_engine.gnn_profiler import TemporalGNNProfiler

router = APIRouter()

@router.get("/profile")
async def get_behavior_profile(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Fetches the latest chronological events and instantiates the Temporal GNN algorithmic model
    to synthesize behavioral threats, MITRE mappings, and graph network nodes.
    """
    # Grab the last 200 chronological events (within 30 days of the latest event)
    latest_res = await db.execute(select(RawEventModel.timestamp).order_by(desc(RawEventModel.timestamp)).limit(1))
    latest_ts = latest_res.scalar()
    now = latest_ts if latest_ts else datetime.utcnow()
    thirty_days_ago = now - timedelta(days=30)
    
    result = await db.execute(
        select(RawEventModel)
        .where(RawEventModel.timestamp >= thirty_days_ago)
        .order_by(desc(RawEventModel.timestamp))
        .limit(200)
    )
    # Reverse to process chronologically oldest to newest in the profiler window
    recent_events = sorted(result.scalars().all(), key=lambda x: x.timestamp)
    
    profiler = TemporalGNNProfiler(recent_events)
    profiler.construct_temporal_graph()
    profile_data = profiler.analyze_behavior()
    
    return profile_data
