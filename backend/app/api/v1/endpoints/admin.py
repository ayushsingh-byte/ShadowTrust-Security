from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import json
import datetime

from app.db.sqlite_db import get_db
from app.models.all_models import User, Node, Event, SystemSettings, AccessLog
from app.api.v1.dependencies import require_role

router = APIRouter()

@router.get("/backup")
async def system_backup(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["SUPER_ADMIN"]))
):
    """Export all system data as JSON."""
    try:
        # Fetch all tables
        result_users = await db.execute(select(User))
        users = result_users.scalars().all()
        
        result_nodes = await db.execute(select(Node))
        nodes = result_nodes.scalars().all()
        
        result_logs = await db.execute(select(Event).limit(500))
        logs = result_logs.scalars().all()
        
        backup_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "users": [{"id": u.id, "email": u.email, "role": u.role} for u in users],
            "nodes": [{"id": n.node_id, "name": n.name, "status": n.status} for n in nodes],
            "logs": [{"id": l.id, "type": l.type, "timestamp": str(l.timestamp)} for l in logs],
            "system_info": {"version": "v1.0", "deployment": "PROD-01 (SQLite)"}
        }
        
        return backup_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/settings")
async def get_settings(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["SUPER_ADMIN", "OVERSEER"]))
):
    """Get System Settings."""
    try:
        result = await db.execute(select(SystemSettings).where(SystemSettings.key == "sector_control"))
        settings = result.scalars().first()
        if settings:
            return settings.value
        
        # Default settings if none exist
        return {
            "education": {"enabled": False, "level": 1},
            "government": {"enabled": False, "level": 1},
            "financial": {"enabled": False, "level": 1}
        }
    except Exception as e:
        print(f"Error fetching settings: {e}")
        return {}

@router.post("/settings")
async def update_settings(
    settings_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["SUPER_ADMIN"]))
):
    """Update System Settings."""
    try:
        result = await db.execute(select(SystemSettings).where(SystemSettings.key == "sector_control"))
        settings = result.scalars().first()
        
        if settings:
            settings.value = settings_data
            settings.updated_at = datetime.datetime.utcnow()
        else:
            settings = SystemSettings(
                key="sector_control",
                value=settings_data
            )
            db.add(settings)
            
        await db.commit()
        return {"status": "updated", "data": settings_data}
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/reset")
async def reset_settings(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["SUPER_ADMIN"]))
):
    """Reset to defaults."""
    try:
        result = await db.execute(select(SystemSettings).where(SystemSettings.key == "sector_control"))
        settings = result.scalars().first()
        if settings:
            await db.delete(settings)
            await db.commit()
        return {"status": "reset", "message": "System settings restored to default."}
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
async def system_health(db: AsyncSession = Depends(get_db)):
    """Check system health status."""
    try:
         # Check DB connection
        try:
             await db.execute(select(User).limit(1))
             db_status = "ONLINE"
        except:
             db_status = "UNREACHABLE"
             
        return {
            "status": "HEALTHY" if db_status == "ONLINE" else "DEGRADED",
            "database": db_status,
            "api_version": "v1.0 (SQLite)",
            "timestamp": datetime.datetime.now().isoformat(),
            "services": {
                "auth": "ONLINE",
                "vm_controller": "ONLINE", # In real app, check VMService.ping()
                "mobsf_integration": "ONLINE"
            }
        }
    except Exception as e:
        return {"status": "CRITICAL", "error": str(e)}

@router.get("/logs/access")
async def get_access_logs(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["SUPER_ADMIN", "AUDITOR"]))
):
    """Get Access Control Logs."""
    try:
        # We query the AccessLog model directly.
        # SQLAlchemy handles the join if we configure relationship access,
        # but for simple serialization we can just return properties.
        result = await db.execute(select(AccessLog).order_by(AccessLog.timestamp.desc()).limit(100))
        logs = result.scalars().all()
        
        fmt_logs = []
        for l in logs:
            fmt_logs.append({
                "id": str(l.id),
                "admin_id": l.admin_id,
                "target_user_id": l.target_user_id,
                "action": l.action,
                "details": l.details,
                "timestamp": str(l.timestamp)
            })
            
        return fmt_logs

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

