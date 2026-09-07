from fastapi import APIRouter, HTTPException
from typing import Dict, Any

from app.schemas.event import LabActionRequest
from app.services.providers import (
    ProviderUnavailableError,
    get_lab_provider,
    get_provider_name,
)

router = APIRouter()


@router.post("/{lab_id}/open", response_model=Dict[str, Any])
async def open_lab_console(lab_id: str, request: LabActionRequest):
    """
    Returns an out-of-band management console link for a lab, when the provider
    offers one.

    In AWS mode this is an SSM Session Manager link. The local Docker provider
    has no separate console — labs are reached through the Guacamole browser
    session — so `session_url` comes back null and the caller falls back to the
    Guacamole workspace.
    """
    import asyncio

    creds = {
        "aws_region": request.aws_region,
        "aws_access_key": request.aws_access_key,
        "aws_secret_key": request.aws_secret_key,
    }
    provider = get_lab_provider(aws_credentials=creds if any(creds.values()) else None)

    try:
        url = await asyncio.to_thread(provider.get_console_url, lab_id)
    except ProviderUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    return {
        "status": "success",
        "lab_id": lab_id,
        "provider": get_provider_name(),
        "session_url": url,
        "message": (
            "Use the Guacamole workspace for this lab."
            if url is None else "Console link generated."
        ),
    }
