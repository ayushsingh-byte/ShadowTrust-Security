"""
Credentials API — User Credential Management Endpoints
=======================================================
All routes are admin-only and require a valid JWT with role SUPER_ADMIN, ADMIN, or OVERSEER.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc
from pydantic import BaseModel
from typing import Optional, List
import math

from app.db.database import get_db
from app.api.v1.dependencies import get_current_user
from app.models.all_models import (
    User, CredentialAuditLog, AdminActivity, CredentialToken
)
from app.services.credential_service import (
    issue_credentials,
    validate_one_time_token,
    resend_credentials,
    generate_temp_password,
)

router = APIRouter()

ADMIN_ROLES = {"SUPER_ADMIN", "ADMIN", "OVERSEER"}

# ─── Dependency: require admin ────────────────────────────────────────────────

async def require_admin(current_user: User = Depends(get_current_user)):
    if current_user.role not in ADMIN_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges required"
        )
    return current_user

def _admin_display_name(user: User) -> str:
    name = f"{user.first_name or ''} {user.last_name or ''}".strip()
    return name if name else (user.username or user.email or "Administrator")


# ─── Request / Response Schemas ───────────────────────────────────────────────

class RecipientSchema(BaseModel):
    email: Optional[str] = None
    phone: Optional[str] = None
    delivery: Optional[List[str]] = None


class IssueCredentialsRequest(BaseModel):
    username: str
    new_password: Optional[str] = None        # Auto-generated if omitted
    email: Optional[str] = None
    phone: Optional[str] = None
    delivery: List[str] = ["email"]           # ["email", "whatsapp", "both"]
    message: Optional[str] = ""
    token_expires_hours: Optional[int] = 24
    force_password_change: Optional[bool] = True
    additional_recipients: Optional[List[RecipientSchema]] = []


# ─── POST /issue ──────────────────────────────────────────────────────────────

@router.post("/issue")
async def issue_credentials_endpoint(
    payload: IssueCredentialsRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Issue new credentials and send delivery notifications."""
    admin_ip   = request.client.host if request.client else "unknown"
    password   = payload.new_password or generate_temp_password()
    admin_name = _admin_display_name(admin)

    result = await issue_credentials(
        db,
        username=payload.username,
        new_password=password,
        email=payload.email,
        phone=payload.phone,
        delivery=payload.delivery,
        custom_message=payload.message or "",
        token_expires_hours=payload.token_expires_hours or 24,
        force_password_change=payload.force_password_change if payload.force_password_change is not None else True,
        admin_id=str(admin.id or "unknown"),
        admin_ip=admin_ip,
        admin_name=admin_name,
        additional_recipients=[r.dict() for r in (payload.additional_recipients or [])],
    )

    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Unknown error"))

    return result


# ─── GET /audit ───────────────────────────────────────────────────────────────

@router.get("/audit")
async def get_audit_trail(
    page: int = 1,
    limit: int = 25,
    search: str = "",
    filter_method: str = "",
    filter_status: str = "",
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Return paginated credential delivery audit log."""
    query = select(CredentialAuditLog).order_by(desc(CredentialAuditLog.timestamp))

    result = await db.execute(query)
    all_records = result.scalars().all()

    # Filter in Python for consistent case-insensitive matching
    filtered = []
    search_lower = search.lower()
    for r in all_records:
        if search_lower and not any(
            search_lower in (getattr(r, f) or "").lower()
            for f in ["username", "recipient_email", "recipient_phone", "issuer_name"]
        ):
            continue
        if filter_method and r.delivery_method != filter_method.upper():
            continue
        if filter_status:
            combined = f"{r.email_status}|{r.whatsapp_status}".upper()
            if filter_status.upper() not in combined:
                continue
        filtered.append(r)

    total = len(filtered)
    start = (page - 1) * limit
    page_records = filtered[start: start + limit]

    return {
        "total": total,
        "page": page,
        "pages": math.ceil(total / limit) if limit else 1,
        "records": [
            {
                "id": r.id,
                "username": r.username,
                "recipient_email": r.recipient_email,
                "recipient_phone": r.recipient_phone,
                "issuer_name": r.issuer_name,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "delivery_method": r.delivery_method,
                "email_status": r.email_status,
                "whatsapp_status": r.whatsapp_status,
                "token_status": r.token_status,
                "custom_message": r.custom_message,
                "admin_ip": r.admin_ip,
            }
            for r in page_records
        ],
    }


# ─── GET /audit/{audit_id} ────────────────────────────────────────────────────

@router.get("/audit/{audit_id}")
async def get_audit_detail(
    audit_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Return full details for a single audit event."""
    result = await db.execute(
        select(CredentialAuditLog).where(CredentialAuditLog.id == audit_id)
    )
    entry = result.scalars().first()
    if not entry:
        raise HTTPException(status_code=404, detail="Audit entry not found")

    return {
        "id": entry.id,
        "username": entry.username,
        "recipient_email": entry.recipient_email,
        "recipient_phone": entry.recipient_phone,
        "issued_by": entry.issued_by,
        "issuer_name": entry.issuer_name,
        "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
        "delivery_method": entry.delivery_method,
        "email_status": entry.email_status,
        "whatsapp_status": entry.whatsapp_status,
        "token_id": entry.token_id,
        "token_status": entry.token_status,
        "custom_message": entry.custom_message,
        "admin_ip": entry.admin_ip,
    }


# ─── POST /resend/{audit_id} ──────────────────────────────────────────────────

@router.post("/resend/{audit_id}")
async def resend_credentials_endpoint(
    audit_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Re-send credentials for a previous audit event."""
    admin_ip   = request.client.host if request.client else "unknown"
    admin_name = _admin_display_name(admin)

    result = await resend_credentials(
        db,
        audit_id=audit_id,
        admin_id=str(admin.id or "unknown"),
        admin_ip=admin_ip,
        admin_name=admin_name,
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


# ─── GET /token/{token} ───────────────────────────────────────────────────────

@router.get("/token/{token}")
async def validate_token(
    token: str,
    db: AsyncSession = Depends(get_db),
):
    """Public endpoint — validate a one-time login token."""
    return await validate_one_time_token(db, token)


# ─── GET /activity ────────────────────────────────────────────────────────────

@router.get("/activity")
async def get_admin_activity(
    page: int = 1,
    limit: int = 30,
    search: str = "",
    action_filter: str = "",
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Return paginated admin activity log."""
    result = await db.execute(
        select(AdminActivity).order_by(desc(AdminActivity.timestamp))
    )
    all_records = result.scalars().all()

    search_lower = search.lower()
    filtered = []
    for r in all_records:
        if search_lower and not any(
            search_lower in (getattr(r, f) or "").lower()
            for f in ["admin_username", "action", "affected_user", "ip_address"]
        ):
            continue
        if action_filter and r.action != action_filter.upper():
            continue
        filtered.append(r)

    total = len(filtered)
    start = (page - 1) * limit
    page_records = filtered[start: start + limit]

    return {
        "total": total,
        "page": page,
        "pages": math.ceil(total / limit) if limit else 1,
        "records": [
            {
                "id": r.id,
                "admin_id": r.admin_id,
                "admin_username": r.admin_username,
                "action": r.action,
                "affected_user": r.affected_user,
                "ip_address": r.ip_address,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "result": r.result,
                "details": r.details,
            }
            for r in page_records
        ],
    }


# ─── GET /generate-password ───────────────────────────────────────────────────

@router.get("/generate-password")
async def generate_password_endpoint(
    admin: User = Depends(require_admin),
):
    """Generate a secure temporary password (admin only)."""
    return {"password": generate_temp_password()}
