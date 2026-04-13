import logging
from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from pydantic import BaseModel
from typing import Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.db.sqlite_db import get_db, AsyncSessionLocal
from app.models.all_models import User, VMInstance
from app.api.v1.dependencies import get_current_active_user
from app.services.session_manager import LabSessionManager, GLOBAL_LAB_STATE, save_local_state

logger = logging.getLogger(__name__)

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
async def start_lab(
    request: LabStartRequest, 
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user)
):
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
        result = await manager.start_lab_provisioning(
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
async def stop_lab(
    request: LabStopRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Terminates the EC2 instance and removes the Guacamole connection geometry.
    """
    manager = LabSessionManager(
        aws_region=request.aws_region,
        aws_access_key=request.aws_access_key,
        aws_secret_key=request.aws_secret_key
    )
    
    try:
        success = await manager.terminate_lab(
            lab_id=request.lab_id,
            instance_id=request.instance_id,
            guac_connection_id=request.guac_connection_id
        )
        
        if not success:
            raise Exception("AWS Orchestrator failed to terminate instance.")
            
        return {"status": "success", "message": f"Lab {request.lab_id} terminated."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

async def _get_guac_auth_token() -> Optional[str]:
    """
    Fetches a fresh Guacamole session token using the admin account.
    Uses async httpx so the FastAPI event loop is never blocked.
    Returns None silently if Guacamole is unreachable (Docker not running, etc.).
    """
    try:
        import httpx
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.post(
                "http://localhost:8080/guacamole/api/tokens",
                data={"username": "guacadmin", "password": "guacadmin"}
            )
            if resp.status_code == 200:
                return resp.json().get("authToken")
    except Exception:
        pass
    return None


@router.get("/status/{lab_id}")
async def get_lab_status(
    lab_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Polls the local state to track the async background worker.
    Returns: { status, instance_id, guacamole_connection_id, auth_token }
    """
    from app.services.session_manager import GLOBAL_LAB_STATE

    # ── In-memory state (most up-to-date) ────────────────────────────────────
    if lab_id in GLOBAL_LAB_STATE:
        record = GLOBAL_LAB_STATE[lab_id]
        current_status = record.get("status", "UNKNOWN").upper()
        auth_token = None

        if current_status in ["READY", "RUNNING"]:
            auth_token = await _get_guac_auth_token()

        return {
            "status": current_status,
            "state": current_status.lower(),
            "instance_id": record.get("instance_id"),
            "private_ip": record.get("private_ip"),
            "guacamole_connection_id": record.get("guacamole_connection_id"),
            "auth_token": auth_token
        }

    # ── SQLite fallback (survives server restarts) ────────────────────────────
    try:
        result = await db.execute(select(VMInstance).where(VMInstance.id == lab_id))
        record = result.scalars().first()
        if not record:
            return {"status": "NOT_FOUND", "message": "Lab session not found"}

        status = (record.status or "UNKNOWN").upper()
        auth_token = None
        guac_id = getattr(record, "guac_connection_id", None)

        if status in ["READY", "RUNNING"]:
            auth_token = await _get_guac_auth_token()

        return {
            "status": status,
            "state": status.lower(),
            "instance_id": record.instance_id,
            "private_ip": getattr(record, "private_ip", None),
            "guacamole_connection_id": guac_id,
            "auth_token": auth_token
        }
    except Exception as e:
        return {"status": "NOT_FOUND", "state": "unknown", "message": f"Database error: {str(e)}"}

@router.get("/cluster-metrics")
async def get_cluster_metrics(
    db: AsyncSession = Depends(get_db),
):
    """
    Returns actual live vCPU, RAM, and instances from AWS EC2.
    Runs the blocking EC2 call in a thread so the event loop stays free.
    """
    import asyncio
    from app.models.all_models import SystemConfig
    from sqlalchemy.future import select as sa_select

    # Load saved AWS credentials for the orchestrator
    result = await db.execute(
        sa_select(SystemConfig).where(
            SystemConfig.key.in_(["aws_access_key", "aws_secret_key", "aws_region"])
        )
    )
    cfg = {r.key: r.value for r in result.scalars().all()}
    aws_ak = cfg.get("aws_access_key", "")
    aws_sk = cfg.get("aws_secret_key", "")
    aws_region = cfg.get("aws_region", "ap-south-1")

    if not aws_ak or not aws_sk:
        return {"status": "success", "vcpu": 0, "ram": 0, "active_count": 0, "instances": []}

    def _fetch():
        manager = LabSessionManager(
            aws_region=aws_region,
            aws_access_key=aws_ak,
            aws_secret_key=aws_sk,
        )
        return manager.aws.get_cluster_metrics()

    try:
        metrics = await asyncio.to_thread(_fetch)
        return metrics
    except Exception as e:
        logger.warning(f"cluster-metrics fetch failed: {e}")
        return {"status": "success", "vcpu": 0, "ram": 0, "active_count": 0, "instances": []}


@router.post("/reattach/{lab_id}")
async def reattach_guacamole(
    lab_id: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user)
):
    """
    Re-registers a Guacamole connection for a READY lab that has no browser session.
    Called when a lab is READY but guacamole_connection_id is null (e.g. Guacamole was
    down when the EC2 instance first came online).
    """
    record = GLOBAL_LAB_STATE.get(lab_id)
    if not record:
        raise HTTPException(status_code=404, detail="Lab not found in active state")

    status = record.get("status", "").upper()
    private_ip = record.get("private_ip")

    if status not in ["READY", "RUNNING"]:
        raise HTTPException(status_code=400, detail=f"Lab is not READY (current: {status})")

    if not private_ip:
        raise HTTPException(status_code=400, detail="Lab has no IP address recorded — cannot create Guacamole connection")

    if record.get("guacamole_connection_id"):
        return {"status": "already_connected", "guacamole_connection_id": record["guacamole_connection_id"]}

    async def _reattach():
        manager = LabSessionManager()
        protocol   = record.get("protocol", "rdp")
        profile_id = record.get("profile_id", "")
        port       = "22" if protocol == "ssh" else "3389"

        if "kali" in profile_id:
            username, password = "kali", "kali"
        elif "malware" in profile_id:
            username, password = "Administrator", "N1oHa9gwwPqU8b?0E(K4Mv2&Y&iu&u85"
        else:
            username, password = "Administrator", "2aA.XlugId5KDkwu!pc5!@UygmmVkvov"

        guac_id = manager.guac.create_connection(
            lab_id=lab_id,
            private_ip=private_ip,
            protocol=protocol,
            port=port,
            username=username,
            password=password
        )
        if guac_id:
            GLOBAL_LAB_STATE[lab_id]["guacamole_connection_id"] = guac_id
            save_local_state(GLOBAL_LAB_STATE)
            logger.info(f"Reattached Guacamole connection #{guac_id} for lab {lab_id} at {private_ip}")
        else:
            logger.warning(f"Reattach failed for lab {lab_id} — Guacamole DB still unreachable")

    background_tasks.add_task(_reattach)
    return {"status": "reattaching", "message": "Guacamole connection is being re-registered. Poll /status in ~3 seconds."}
