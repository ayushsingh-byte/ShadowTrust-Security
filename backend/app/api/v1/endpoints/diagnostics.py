"""
Authenticated admin diagnostics.

The detailed operator view — credentials, DB connection details, container
inventory, copy-paste attack commands — that used to live on the
unauthenticated /health page. Now ADMIN-only.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.api.v1.dependencies import require_role
from app.health_page import build_admin_diagnostics
from app.models.all_models import User
from app.services import data_admin, honeypot_triggers

router = APIRouter()


@router.get("/diagnostics")
async def admin_diagnostics(_: User = Depends(require_role(["ADMIN"]))):
    """Full status + credentials + telemetry-generation commands. ADMIN only."""
    return await build_admin_diagnostics()


@router.post("/diagnostics/trigger/{trigger_id}")
async def trigger_honeypot(trigger_id: str, _: User = Depends(require_role(["ADMIN"]))):
    """
    Fire one fixed, server-defined action at this operator's own honeypot lab
    (see app.services.honeypot_triggers). trigger_id only selects which
    predefined function runs — never raw client-supplied commands.
    """
    return await honeypot_triggers.run_trigger(trigger_id)


# ── Data lifecycle (see app.services.data_admin) ───────────────────────────
class PopulateBody(BaseModel):
    corpus_events: int = Field(20000, ge=0, le=60000)
    live_waves: int = Field(1, ge=0, le=3)


class ResetBody(BaseModel):
    confirm: str = ""


@router.get("/data")
async def data_status(_: User = Depends(require_role(["ADMIN"]))):
    """Current data inventory (rows per data table, files per data dir) + last job."""
    return {"inventory": await data_admin.inventory(), "job": data_admin.JOB}


@router.post("/data/populate")
async def data_populate(body: PopulateBody, _: User = Depends(require_role(["ADMIN"]))):
    if not body.corpus_events and not body.live_waves:
        raise HTTPException(status_code=400, detail="nothing to do: corpus_events and live_waves are both 0")
    return await data_admin.start("populate", corpus_events=body.corpus_events, waves=body.live_waves)


@router.post("/data/reset")
async def data_reset(body: ResetBody, _: User = Depends(require_role(["ADMIN"]))):
    """Wipe platform data (never accounts/access). Requires confirm == "RESET"."""
    if body.confirm != "RESET":
        raise HTTPException(status_code=400, detail='type RESET to confirm')
    return await data_admin.start("reset")
