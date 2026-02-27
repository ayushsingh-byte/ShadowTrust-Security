from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from pydantic import BaseModel
from typing import Dict, Any, Optional

from app.services.session_manager import LabSessionManager

router = APIRouter()

class LabStartRequest(BaseModel):
    environment_type: str # 'kali', 'windows', 'windows-tools', 'honeypot'
    user_id: str
    ami_id: str
    instance_type: str
    subnet_id: str
    protocol: Optional[str] = 'rdp'
    security_group_id: Optional[str] = None
    aws_region: Optional[str] = 'ap-south-1'
    aws_access_key: Optional[str] = None
    aws_secret_key: Optional[str] = None

class LabResponse(BaseModel):
    status: str
    lab_id: str
    instance_id: str
    message: str

@router.post("/start", response_model=LabResponse)
async def start_lab(request: LabStartRequest, background_tasks: BackgroundTasks):
    """
    Initiates the AWS + Guacamole Lab provisioning sequence.
    Returns the lab_id immediately while the instance boots in the background.
    """
    manager = LabSessionManager(
        aws_region=request.aws_region,
        aws_access_key=request.aws_access_key,
        aws_secret_key=request.aws_secret_key
    )
    
    try:
        # Immediately start EC2 and create 'provisioning' DB record
        result = manager.start_lab_provisioning(
            user_id=request.user_id,
            environment_type=request.environment_type,
            ami_id=request.ami_id,
            instance_type=request.instance_type,
            subnet_id=request.subnet_id,
            security_group_id=request.security_group_id,
            protocol=request.protocol
        )
        
        # Dispatch background task to poll EC2 for Private IP and register with Guacamole Postgres
        background_tasks.add_task(
            manager.process_lab_readiness,
            lab_id=result["lab_id"],
            instance_id=result["instance_id"]
        )
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class LabStopRequest(BaseModel):
    lab_id: str
    instance_id: str
    guac_connection_id: Optional[int] = None
    aws_region: Optional[str] = 'ap-south-1'
    aws_access_key: Optional[str] = None
    aws_secret_key: Optional[str] = None

@router.post("/stop")
async def stop_lab(request: LabStopRequest):
    """
    Terminates the EC2 instance and removes the Guacamole connection geometry.
    """
    manager = LabSessionManager(
        aws_region=request.aws_region,
        aws_access_key=request.aws_access_key,
        aws_secret_key=request.aws_secret_key
    )
    
    try:
        success = manager.terminate_lab(
            lab_id=request.lab_id,
            instance_id=request.instance_id,
            guac_connection_id=request.guac_connection_id
        )
        
        if not success:
            raise Exception("AWS Orchestrator failed to terminate instance.")
            
        return {"status": "success", "message": f"Lab {request.lab_id} terminated."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/status/{lab_id}")
async def get_lab_status(lab_id: str):
    """
    Polls the Supabase database to track the async background worker.
    Returns status: provisioning | ready | error | stopped
    """
    from app.services.session_manager import GLOBAL_LAB_STATE
    
    # Check in-memory state first (Graceful degradation if Supabase DB is offline)
    if lab_id in GLOBAL_LAB_STATE:
        record = GLOBAL_LAB_STATE[lab_id]
        current_status = record.get("status", "UNKNOWN").upper()
        auth_token = None
        
        if current_status in ["READY", "RUNNING"]:
            try:
                import httpx
                resp = httpx.post(
                    "http://localhost:8080/guacamole/api/tokens",
                    data={"username": "guacadmin", "password": "guacadmin"},
                    timeout=3.0
                )
                if resp.status_code == 200:
                    auth_token = resp.json().get("authToken")
            except:
                pass

        return {
            "status": current_status,
            "state": record.get("status", "unknown").lower(),
            "instance_id": record.get("instance_id"),
            "guacamole_connection_id": record.get("guacamole_connection_id"),
            "auth_token": auth_token
        }

    from app.db.supabase_client import get_supabase
    db = get_supabase()
    
    try:
        res = db.table("vm_instances").select("*").eq("id", lab_id).execute()
        if not res.data:
            return {"status": "NOT_FOUND", "message": "Lab session not found"}
            
        record = res.data[0]
        status = record.get("status", "unknown").upper()
        auth_token = None
        
        if status in ["READY", "RUNNING"]:
            try:
                import httpx
                resp = httpx.post(
                    "http://localhost:8080/guacamole/api/tokens",
                    data={"username": "guacadmin", "password": "guacadmin"},
                    timeout=3.0
                )
                if resp.status_code == 200:
                    auth_token = resp.json().get("authToken")
            except:
                pass
        
        # In a full schema, we'd also pull the guac_connection_id explicitly.
        # For this prototype we're returning the raw status state to drive the UI.
        return {
            "status": status,
            "state": status.lower(),
            "instance_id": record.get("instance_id"),
            "guacamole_connection_id": record.get("guacamole_connection_id", "1"), # Mocked ID #1 if schema lacks column
            "auth_token": auth_token
        }
    except Exception as e:
        # Fallback if Supabase project is paused or offline (DNS Error)
        return {"status": "NOT_FOUND", "state": "unknown", "message": f"Database unreachable: {str(e)}"}
