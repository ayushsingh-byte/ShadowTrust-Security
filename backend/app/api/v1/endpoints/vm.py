from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from typing import Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.schemas.event import VMLaunchRequest, VMResponse, VMTerminateRequest
from app.services.aws_orchestrator import AWSOrchestrator
from app.db.sqlite_db import get_db
from app.api.v1.dependencies import get_current_active_user
from app.models.all_models import User, VMInstance

router = APIRouter()

# Profiles are now dynamically passed from the frontend UI configuration hub.

@router.post("/launch", response_model=VMResponse)
async def launch_vm(
    request: VMLaunchRequest, 
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Launches an EC2 instance from a specified profile (AMI).
    The actual launch is handed off to the AWSOrchestrator.
    """
    orchestrator = AWSOrchestrator(
        region_name=request.aws_region or 'ap-south-1',
        aws_access_key=request.aws_access_key,
        aws_secret_key=request.aws_secret_key
    )
    
    # Normally this is an async operation, but boto3 is synchronous. 
    # For high concurrency, we'd use aiobotocore. For now, running sync.
    result = orchestrator.launch_analysis_vm(
        ami_id=request.ami_id,
        instance_type=request.instance_type,
        session_id=request.session_id,
        subnet_id=request.subnet_id,
        iam_profile_name=request.iam_profile_name,
        profile_id=request.profile_id
    )
    
    if result["status"] == "error":
        raise HTTPException(status_code=500, detail=result["message"])

    try:
        new_vm = VMInstance(
            id=request.session_id, # Or generate new UUID if session_id is string
            instance_id=result.get("instance_id"),
            status="PROVISIONING",
            session_id=current_user.id
        )
        db.add(new_vm)
        await db.commit()
    except Exception as e:
        await db.rollback()
        # Non-fatal log, instance is still launching in AWS
        pass
    
    return VMResponse(
        status="success",
        instance_id=result.get("instance_id"),
        message="VM is launching"
    )

@router.post("/{instance_id}/terminate", response_model=VMResponse)
async def terminate_vm(
    instance_id: str, 
    request: VMTerminateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Terminates an active VM by Instance ID."""
    orchestrator = AWSOrchestrator(
        region_name=request.aws_region or 'ap-south-1',
        aws_access_key=request.aws_access_key,
        aws_secret_key=request.aws_secret_key
    )
    success = orchestrator.terminate_vm(instance_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to terminate instance.")
    
    try:
        result = await db.execute(select(VMInstance).where(VMInstance.instance_id == instance_id))
        vm = result.scalars().first()
        if vm:
            vm.status = "TERMINATED"
            await db.commit()
    except:
        pass

    return VMResponse(status="success", instance_id=instance_id, message="Termination initiated")

@router.post("/{instance_id}/status", response_model=Dict[str, Any])
async def get_vm_status(
    instance_id: str, 
    request: VMTerminateRequest,
    current_user: User = Depends(get_current_active_user)
):
    """Returns status of a specific VM instance."""
    orchestrator = AWSOrchestrator(
        region_name=request.aws_region or 'ap-south-1',
        aws_access_key=request.aws_access_key,
        aws_secret_key=request.aws_secret_key
    )
    state = orchestrator.get_instance_status(instance_id)
    if not state:
        raise HTTPException(status_code=404, detail="Instance not found or error occurred.")
        
    return {
        "instance_id": instance_id,
        "state": state
    }
