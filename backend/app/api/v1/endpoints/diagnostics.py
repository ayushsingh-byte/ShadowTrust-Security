"""
Authenticated admin diagnostics.

The detailed operator view — credentials, DB connection details, container
inventory, copy-paste attack commands — that used to live on the
unauthenticated /health page. Now ADMIN-only.
"""

from fastapi import APIRouter, Depends

from app.api.v1.dependencies import require_role
from app.health_page import build_admin_diagnostics
from app.models.all_models import User

router = APIRouter()


@router.get("/diagnostics")
async def admin_diagnostics(_: User = Depends(require_role(["ADMIN"]))):
    """Full status + credentials + telemetry-generation commands. ADMIN only."""
    return await build_admin_diagnostics()
