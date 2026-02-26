from fastapi import APIRouter
from typing import Dict, Any

from app.schemas.event import SessionOpenRequest
from app.services.aws_orchestrator import AWSOrchestrator

router = APIRouter()

@router.post("/{instance_id}/open", response_model=Dict[str, Any])
async def open_ssm_session(instance_id: str, request: SessionOpenRequest):
    """
    Generates an AWS SSM browser session link.
    """
    orchestrator = AWSOrchestrator(
        region_name=request.aws_region or 'ap-south-1',
        aws_access_key=request.aws_access_key,
        aws_secret_key=request.aws_secret_key
    )
    url = orchestrator.generate_ssm_session_url(instance_id)
    return {
        "status": "success",
        "instance_id": instance_id,
        "session_url": url
    }
