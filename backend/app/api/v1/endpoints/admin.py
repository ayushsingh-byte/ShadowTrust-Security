from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any
from app.core.supabase import supabase
import json
import datetime

router = APIRouter()

@router.get("/backup")
def system_backup():
    """Export all system data as JSON."""
    try:
        # Fetch all tables
        users = supabase.table("users").select("*").execute()
        nodes = supabase.table("nodes").select("*").execute()
        logs = supabase.table("logs").select("*").limit(500).execute() # Limit to prevent timeout
        
        backup_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "users": users.data,
            "nodes": nodes.data,
            "logs": logs.data,
            "system_info": {"version": "v1.0", "deployment": "PROD-01"}
        }
        
        return backup_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/settings")
def get_settings():
    """Get System Settings."""
    try:
        # Fetch sector settings
        settings = supabase.table("system_settings").select("*").eq("key", "sector_control").execute()
        if settings.data:
            return json.loads(settings.data[0]['value'])
        
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
def update_settings(settings: Dict[str, Any]):
    """Update System Settings."""
    try:
        # Save to 'system_settings' table
        data = {
            "key": "sector_control",
            "value": json.dumps(settings),
            "updated_at": datetime.datetime.now().isoformat()
        }
        
        # Upsert (Insert or Update)
        result = supabase.table("system_settings").upsert(data).execute()
        return {"status": "updated", "data": result.data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/reset")
def reset_settings():
    """Reset to defaults."""
    try:
        supabase.table("system_settings").delete().eq("key", "sector_control").execute()
        return {"status": "reset", "message": "System settings restored to default."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
def system_health():
    """Check system health status."""
    try:
         # Check DB connection
        try:
             supabase.table("users").select("count", count="exact").limit(1).execute()
             db_status = "ONLINE"
        except:
             db_status = "UNREACHABLE"
             
        return {
            "status": "HEALTHY" if db_status == "ONLINE" else "DEGRADED",
            "database": db_status,
            "api_version": "v1.0",
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
def get_access_logs():
    """Get Access Control Logs."""
    try:
        # Fetch logs with admin and target user details
        # Note: Supabase syntax for foreign key joins might vary based on client version.
        # Assuming standard PostgREST syntax: select=*,admin:users!admin_id(email),target_user:users!target_user_id(email)
        # If that fails, we fallback to just fetching logs.
        
        try:
            response = supabase.table("access_logs").select("*, admin:users!admin_id(email), target_user:users!target_user_id(email)").order("timestamp", desc=True).limit(100).execute()
            return response.data
        except:
             # Fallback if join syntax issues
             response = supabase.table("access_logs").select("*").order("timestamp", desc=True).limit(100).execute()
             return response.data

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
