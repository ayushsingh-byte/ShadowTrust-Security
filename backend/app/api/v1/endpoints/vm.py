from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from typing import Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.schemas.event import LabLaunchRequest, LabActionRequest, LabResponse
from app.db.database import get_db
from app.api.v1.dependencies import get_current_active_user
from app.models.all_models import User, VMInstance
from app.services.providers import (
    LabConfig,
    LabStatus,
    ProviderUnavailableError,
    UnsupportedEnvironmentError,
    get_lab_provider,
    get_provider_name,
)

router = APIRouter()


def _credentials(request) -> Dict[str, Any]:
    """AWS credentials from the request, used only when INFRA_PROVIDER=aws."""
    creds = {
        "aws_region": getattr(request, "aws_region", None),
        "aws_access_key": getattr(request, "aws_access_key", None),
        "aws_secret_key": getattr(request, "aws_secret_key", None),
    }
    return creds if any(creds.values()) else None


@router.post("/launch", response_model=LabResponse)
async def launch_lab(
    request: LabLaunchRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Launches a lab through the configured infrastructure provider.

    Which backend actually runs the lab (Docker locally, EC2 in AWS mode) is
    decided by INFRA_PROVIDER; this endpoint deals only in generic terms.
    """
    import asyncio

    provider = get_lab_provider(aws_credentials=_credentials(request))

    config = LabConfig(
        environment=request.environment,
        profile=request.profile,
        protocol=request.protocol,
        owner_id=current_user.id,
        labels={"lab_id": request.lab_id} if request.lab_id else {},
    )

    try:
        info = await asyncio.to_thread(provider.launch_lab, config)
    except UnsupportedEnvironmentError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except ProviderUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    try:
        new_vm = VMInstance(
            id=info.lab_id,
            instance_id=info.lab_id,
            status=LabStatus.PROVISIONING,
            session_id=current_user.id
        )
        db.add(new_vm)
        await db.commit()
    except Exception:
        await db.rollback()
        # Non-fatal: the lab is already running regardless of the audit record.
        pass

    return LabResponse(
        status="success",
        lab_id=info.lab_id,
        provider=provider.name,
        environment=info.environment,
        profile=info.profile,
        message="Lab is launching"
    )


@router.post("/{lab_id}/terminate", response_model=LabResponse)
async def terminate_lab(
    lab_id: str,
    request: LabActionRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Tears down a lab by its provider-independent lab_id."""
    import asyncio

    provider = get_lab_provider(aws_credentials=_credentials(request))

    try:
        success = await asyncio.to_thread(provider.terminate_lab, lab_id)
    except ProviderUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    if not success:
        raise HTTPException(status_code=500, detail="Failed to terminate lab.")

    try:
        result = await db.execute(select(VMInstance).where(VMInstance.id == lab_id))
        vm = result.scalars().first()
        if vm:
            vm.status = LabStatus.TERMINATED
            await db.commit()
    except Exception:
        pass

    return LabResponse(
        status="success",
        lab_id=lab_id,
        provider=provider.name,
        message="Termination initiated"
    )


@router.post("/{lab_id}/status", response_model=Dict[str, Any])
async def get_lab_status(
    lab_id: str,
    request: LabActionRequest,
    current_user: User = Depends(get_current_active_user)
):
    """Returns the normalised status of a lab."""
    import asyncio

    provider = get_lab_provider(aws_credentials=_credentials(request))

    try:
        info = await asyncio.to_thread(provider.get_lab_status, lab_id)
    except ProviderUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    if info.status == LabStatus.TERMINATED and info.message:
        raise HTTPException(status_code=404, detail=info.message)

    payload = info.to_dict()
    payload["provider"] = provider.name
    return payload


@router.get("/provider", response_model=Dict[str, Any])
async def describe_provider(current_user: User = Depends(get_current_active_user)):
    """Reports which provider is active and what it can run."""
    provider = get_lab_provider()
    return {
        "provider": get_provider_name(),
        "supported_environments": sorted(provider.supported_environments),
        "profiles": provider.describe_profiles(),
    }
