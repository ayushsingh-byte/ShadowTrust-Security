import logging
from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from pydantic import BaseModel
from typing import Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.db.database import get_db, AsyncSessionLocal
from app.models.all_models import User, VMInstance
from app.api.v1.dependencies import get_current_active_user
from app.services.session_manager import LabSessionManager, GLOBAL_LAB_STATE, save_local_state
from app.services.providers import PROFILES, get_provider_name

logger = logging.getLogger(__name__)

router = APIRouter()


def _aws_credentials(request) -> Optional[dict]:
    """
    Collect AWS credentials from a request, if it carries any.

    Only consulted when INFRA_PROVIDER=aws; in local mode these are ignored
    entirely and the lab runs with no cloud credentials of any kind.
    """
    creds = {
        "aws_region": getattr(request, "aws_region", None),
        "aws_access_key": getattr(request, "aws_access_key", None),
        "aws_secret_key": getattr(request, "aws_secret_key", None),
        "security_group_id": getattr(request, "security_group_id", None),
    }
    return creds if any(creds.values()) else None


class LabStartRequest(BaseModel):
    environment_type: str                      # 'kali', 'windows', ...
    user_id: str
    profile: Optional[str] = "standard"        # 'light' | 'standard' | 'heavy'
    protocol: Optional[str] = "rdp"
    # AWS-only fields — ignored unless INFRA_PROVIDER=aws.
    security_group_id: Optional[str] = None
    aws_region: Optional[str] = None
    aws_access_key: Optional[str] = None
    aws_secret_key: Optional[str] = None

class LabResponse(BaseModel):
    status: str
    lab_id: str
    message: str
    provider: Optional[str] = None
    environment: Optional[str] = None
    profile: Optional[str] = None


@router.get("/profiles")
async def list_profiles():
    """
    Provider-independent resource tiers for the UI.

    The frontend renders whatever this returns, so no AWS instance types are
    ever hard-coded client-side.
    """
    return {
        "provider": get_provider_name(),
        "profiles": [
            {"id": p.id, "label": p.label, "cpu": p.cpu, "memory_gb": p.memory_gb}
            for p in PROFILES.values()
        ],
    }


@router.post("/start", response_model=LabResponse)
async def start_lab(
    request: LabStartRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user)
):
    """
    Initiates the lab provisioning sequence through the configured provider.
    Returns the lab_id immediately while the lab boots in the background.
    """
    manager = LabSessionManager(aws_credentials=_aws_credentials(request))

    try:
        result = await manager.start_lab_provisioning(
            user_id=request.user_id,
            environment_type=request.environment_type,
            profile=request.profile or "standard",
            protocol=request.protocol or "rdp",
        )

        # Dispatch background task to wait for readiness and register Guacamole
        background_tasks.add_task(
            manager.process_lab_readiness,
            lab_id=result["lab_id"],
        )

        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class LabStopRequest(BaseModel):
    lab_id: str
    guac_connection_id: Optional[int] = None
    # AWS-only fields — ignored unless INFRA_PROVIDER=aws.
    aws_region: Optional[str] = None
    aws_access_key: Optional[str] = None
    aws_secret_key: Optional[str] = None

@router.post("/stop")
async def stop_lab(
    request: LabStopRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Tears down the lab through the provider and removes its Guacamole connection.
    """
    manager = LabSessionManager(aws_credentials=_aws_credentials(request))

    try:
        success = await manager.terminate_lab(
            lab_id=request.lab_id,
            guac_connection_id=request.guac_connection_id
        )

        if not success:
            raise Exception("Provider failed to terminate the lab.")

        return {"status": "success", "message": f"Lab {request.lab_id} terminated."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

async def _get_guac_auth_token() -> Optional[str]:
    """
    Fetches a fresh Guacamole session token using the admin account.
    Uses async httpx so the FastAPI event loop is never blocked.
    Returns None silently if Guacamole is unreachable (Docker not running, etc.).

    Base URL: GUAC_API_URL (compose sets http://guacamole:8080/guacamole);
    native runs fall back to localhost:8080.
    """
    import os
    base = os.getenv("GUAC_API_URL", "http://localhost:8080/guacamole").rstrip("/")
    try:
        import httpx
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.post(
                f"{base}/api/tokens",
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
    Returns: { status, lab_id, host, guacamole_connection_id, auth_token }
    """
    from app.services.session_manager import GLOBAL_LAB_STATE

    # ── In-memory state (most up-to-date) ────────────────────────────────────
    if lab_id in GLOBAL_LAB_STATE:
        record = GLOBAL_LAB_STATE[lab_id]
        current_status = record.get("status", "UNKNOWN").upper()
        auth_token = None

        if current_status in ["READY", "RUNNING"]:
            auth_token = await _get_guac_auth_token()

        host = record.get("host") or record.get("private_ip")
        return {
            "status": current_status,
            "state": current_status.lower(),
            "lab_id": lab_id,
            "provider": record.get("provider"),
            "environment": record.get("environment"),
            "profile": record.get("profile"),
            "host": host,
            # Retained for existing frontend state files.
            "private_ip": host,
            "guacamole_connection_id": record.get("guacamole_connection_id"),
            "auth_token": auth_token
        }

    # ── Database fallback (survives server restarts) ─────────────────────────
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

        host = getattr(record, "private_ip", None)
        return {
            "status": status,
            "state": status.lower(),
            "lab_id": lab_id,
            "host": host,
            "private_ip": host,
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
    Live vCPU, RAM and lab inventory from the configured provider.

    In local mode this reads Docker; in AWS mode it reads EC2. The blocking
    provider call runs in a thread so the event loop stays free.
    """
    from app.models.all_models import SystemConfig
    from sqlalchemy.future import select as sa_select

    aws_credentials = None
    if get_provider_name() == "aws":
        # Load saved AWS credentials for the provider.
        result = await db.execute(
            sa_select(SystemConfig).where(
                SystemConfig.key.in_(["aws_access_key", "aws_secret_key", "aws_region"])
            )
        )
        cfg = {r.key: r.value for r in result.scalars().all()}
        if not cfg.get("aws_access_key") or not cfg.get("aws_secret_key"):
            return {"status": "success", "vcpu": 0, "ram": 0, "active_count": 0,
                    "labs": [], "instances": [], "provider": "aws", "region": cfg.get("aws_region", "ap-south-1"),
                    "message": "AWS credentials not configured"}
        aws_credentials = {
            "aws_access_key": cfg.get("aws_access_key"),
            "aws_secret_key": cfg.get("aws_secret_key"),
            "aws_region": cfg.get("aws_region", "ap-south-1"),
        }

    import psutil as _ps
    host = {
        "provider": get_provider_name(),
        "region": (aws_credentials or {}).get("aws_region") if get_provider_name() == "aws" else "local docker host",
        "host_vcpu": _ps.cpu_count() or 0,
        "host_ram_gb": round((_ps.virtual_memory().total or 0) / 1024**3, 1),
        "host_cpu_pct": _ps.cpu_percent(interval=0.2),
        "host_ram_pct": _ps.virtual_memory().percent,
    }
    try:
        manager = LabSessionManager(aws_credentials=aws_credentials)
        m = await manager.get_metrics()
        m.update(host)
        return m
    except Exception as e:
        logger.warning(f"cluster-metrics fetch failed: {e}")
        return {"status": "success", "vcpu": 0, "ram": 0,
                "active_count": 0, "labs": [], "instances": [], **host}


@router.post("/reattach/{lab_id}")
async def reattach_guacamole(
    lab_id: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user)
):
    """
    Re-registers a Guacamole connection for a READY lab that has no browser session.
    Called when a lab is READY but guacamole_connection_id is null (e.g. Guacamole was
    down when the lab first came online).
    """
    record = GLOBAL_LAB_STATE.get(lab_id)
    if not record:
        raise HTTPException(status_code=404, detail="Lab not found in active state")

    status = record.get("status", "").upper()
    host = record.get("host") or record.get("private_ip")

    if status not in ["READY", "RUNNING"]:
        raise HTTPException(status_code=400, detail=f"Lab is not READY (current: {status})")

    if not host:
        raise HTTPException(status_code=400, detail="Lab has no address recorded — cannot create Guacamole connection")

    if record.get("guacamole_connection_id"):
        return {"status": "already_connected", "guacamole_connection_id": record["guacamole_connection_id"]}

    async def _reattach():
        import asyncio

        manager  = LabSessionManager()
        protocol = record.get("protocol", "rdp")

        # Connection details (including credentials) come from the provider, so
        # no environment-specific passwords live in the application layer.
        connection = await asyncio.to_thread(manager.provider.get_connection, lab_id, protocol)
        if connection is None:
            logger.warning(f"Reattach failed for lab {lab_id} — provider returned no connection details")
            return

        guac_id = manager.guac.create_connection(
            lab_id=lab_id,
            private_ip=connection.host,
            protocol=connection.protocol,
            port=str(connection.port),
            username=connection.username,
            password=connection.password
        )
        if guac_id:
            GLOBAL_LAB_STATE[lab_id]["guacamole_connection_id"] = guac_id
            save_local_state(GLOBAL_LAB_STATE)
            logger.info(f"Reattached Guacamole connection #{guac_id} for lab {lab_id} at {connection.host}")
        else:
            logger.warning(f"Reattach failed for lab {lab_id} — Guacamole DB still unreachable")

    background_tasks.add_task(_reattach)
    return {"status": "reattaching", "message": "Guacamole connection is being re-registered. Poll /status in ~3 seconds."}
