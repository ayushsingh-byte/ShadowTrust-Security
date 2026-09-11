from fastapi import APIRouter, HTTPException, Depends
from typing import List, Optional
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.db.database import get_db
from app.models.all_models import User, AccessLog
from app.services.auth_service import get_password_hash, generate_system_code, _send_auth_email, create_access_token
from app.api.v1.dependencies import get_current_active_user, require_role, require_clearance
from datetime import datetime

router = APIRouter()

# Schema for User Operations
class UserCreate(BaseModel):
    email: str
    password: str
    first_name: str
    last_name: str
    role: str = "ANALYST"
    clearance_level: int = 1

class UserUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role: Optional[str] = None
    clearance_level: Optional[int] = None
    status: Optional[str] = None

class UserOut(BaseModel):
    id: str
    email: str
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    department: Optional[str] = None
    role: Optional[str] = None
    clearance_level: Optional[int] = None
    requested_clearance_level: Optional[int] = None
    status: str
    last_login: Optional[str] = None

@router.get("/", response_model=List[UserOut])
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["SUPER_ADMIN", "OVERSEER"]))
):
    """List all users (Admin/Overseer only)."""
    try:
        result = await db.execute(select(User))
        users = result.scalars().all()
        # Format the datetime for response model
        fmt_users = []
        for u in users:
             fmt_users.append({
                 "id": u.id,
                 "email": u.email,
                 "username": u.username,
                 "first_name": u.first_name,
                 "last_name": u.last_name,
                 "department": u.department,
                 "role": u.role,
                 "clearance_level": u.clearance_level,
                 "requested_clearance_level": u.requested_clearance_level,
                 "status": u.status,
                 "last_login": str(u.last_login) if u.last_login else None
             })
        return fmt_users
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/me", response_model=UserOut)
async def get_me(current_user: User = Depends(get_current_active_user)):
    """Get current logged in user details."""
    return {
        "id": current_user.id,
        "email": current_user.email,
        "username": current_user.username,
        "first_name": current_user.first_name,
        "last_name": current_user.last_name,
        "department": current_user.department,
        "role": current_user.role,
        "clearance_level": current_user.clearance_level,
        "requested_clearance_level": current_user.requested_clearance_level,
        "status": current_user.status,
        "last_login": str(current_user.last_login) if current_user.last_login else None
    }


@router.get("/me/activity")
async def get_my_activity(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Counts and a recent timeline built only from records attributed to the signed-in user."""
    from sqlalchemy import desc, func, or_
    from app.models.all_models import AdminActivity, GeneratedReport, Incident, IncidentActivity

    identities = [value for value in (current_user.email, current_user.username) if value]
    closed_statuses = ("RESOLVED", "CLOSED", "FALSE_POSITIVE", "FALSE POSITIVE")

    async def count(query) -> int:
        return (await db.execute(query)).scalar() or 0

    counts = {
        "incidents_assigned": await count(
            select(func.count(Incident.id)).where(Incident.assigned_analyst.in_(identities))
        ),
        "incidents_resolved": await count(
            select(func.count(Incident.id)).where(
                Incident.assigned_analyst.in_(identities),
                func.upper(Incident.status).in_(closed_statuses),
            )
        ),
        "investigation_actions": await count(
            select(func.count(IncidentActivity.id)).where(IncidentActivity.actor.in_(identities))
        ),
        "reports_generated": await count(
            select(func.count(GeneratedReport.id)).where(GeneratedReport.generated_by_email == current_user.email)
        ),
        "admin_actions": await count(
            select(func.count(AdminActivity.id)).where(
                or_(AdminActivity.admin_id == current_user.id, AdminActivity.admin_username.in_(identities))
            )
        ),
    }

    timeline = []
    activity_rows = (await db.execute(
        select(IncidentActivity, Incident.incident_key)
        .join(Incident, Incident.id == IncidentActivity.incident_id, isouter=True)
        .where(IncidentActivity.actor.in_(identities))
        .order_by(desc(IncidentActivity.at)).limit(12)
    )).all()
    for activity, incident_key in activity_rows:
        timeline.append({"at": activity.at, "action": activity.action,
                         "target": incident_key or f"incident {activity.incident_id}",
                         "result": activity.detail})

    for report in (await db.execute(
        select(GeneratedReport).where(GeneratedReport.generated_by_email == current_user.email)
        .order_by(desc(GeneratedReport.generated_at)).limit(12)
    )).scalars():
        timeline.append({"at": report.generated_at, "action": "report generated",
                         "target": report.title or report.report_type, "result": report.status})

    for entry in (await db.execute(
        select(AdminActivity).where(
            or_(AdminActivity.admin_id == current_user.id, AdminActivity.admin_username.in_(identities))
        ).order_by(desc(AdminActivity.timestamp)).limit(12)
    )).scalars():
        timeline.append({"at": entry.timestamp, "action": entry.action,
                         "target": entry.affected_user, "result": entry.result})

    timeline = sorted((t for t in timeline if t["at"]), key=lambda t: t["at"], reverse=True)[:12]
    for item in timeline:
        item["at"] = item["at"].isoformat()

    return {
        "counts": counts,
        "timeline": timeline,
        "member_since": current_user.created_at.isoformat() if current_user.created_at else None,
        "last_login": current_user.last_login.isoformat() if current_user.last_login else None,
    }


@router.post("/", response_model=UserOut)
async def create_user(
    user: UserCreate, 
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["SUPER_ADMIN"]))
):
    """Create a new user with specific role and clearance (Admin only)."""
    try:
        # Check if user exists
        result = await db.execute(select(User).where(User.email == user.email))
        if result.scalars().first():
            raise HTTPException(status_code=400, detail="User already exists")

        hashed_pw = get_password_hash(user.password) 
        username = user.email.split('@')[0]

        new_user = User(
            username=username,
            email=user.email,
            password_hash=hashed_pw,
            first_name=user.first_name,
            last_name=user.last_name,
            role=user.role,
            clearance_level=user.clearance_level,
            status="ACTIVE" 
        )

        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)
             
        return {
            "id": new_user.id,
            "email": new_user.email,
            "username": new_user.username,
            "first_name": new_user.first_name,
            "last_name": new_user.last_name,
            "department": new_user.department,
            "role": new_user.role,
            "clearance_level": new_user.clearance_level,
            "requested_clearance_level": new_user.requested_clearance_level,
            "status": new_user.status,
            "last_login": None
        }

    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/{user_id}", response_model=UserOut)
async def update_user(
    user_id: str, 
    user_update: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["SUPER_ADMIN"]))
):
    """Update user details and access level."""
    try:
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalars().first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        update_data = user_update.dict(exclude_unset=True)
        if not update_data:
            raise HTTPException(status_code=400, detail="No fields to update")

        for key, value in update_data.items():
            setattr(user, key, value)
            
        await db.commit()
        await db.refresh(user)

        return {
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "department": user.department,
            "role": user.role,
            "clearance_level": user.clearance_level,
            "requested_clearance_level": user.requested_clearance_level,
            "status": user.status,
            "last_login": str(user.last_login) if user.last_login else None
        }
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/{user_id}")
async def delete_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["SUPER_ADMIN"]))
):
    """Delete a user."""
    try:
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalars().first()
        if not user:
             raise HTTPException(status_code=404, detail="User not found")
             
        await db.delete(user)
        await db.commit()
        
        return {"message": "User deleted successfully"}
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

# --- Access Control Endpoints ---

class UserApprove(BaseModel):
    role: str
    clearance_level: int

class UserDeny(BaseModel):
    reason: str

@router.get("/pending", response_model=List[UserOut])
async def list_pending_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["SUPER_ADMIN"]))
):
    """List users awaiting approval."""
    try:
        result = await db.execute(select(User).where(User.status == "PENDING"))
        pending_users = result.scalars().all()
        
        fmt_users = []
        for u in pending_users:
             fmt_users.append({
                 "id": u.id,
                 "email": u.email,
                 "username": u.username,
                 "first_name": u.first_name,
                 "last_name": u.last_name,
                 "department": u.department,
                 "role": u.role,
                 "clearance_level": u.clearance_level,
                 "requested_clearance_level": u.requested_clearance_level,
                 "status": u.status,
                 "last_login": str(u.last_login) if u.last_login else None
             })
        return fmt_users
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{user_id}/approve")
async def approve_user(
    user_id: str, 
    approval: UserApprove,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["SUPER_ADMIN"]))
):
    """Approve a pending user."""
    try:
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalars().first()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user.status = "ACTIVE"
        user.role = approval.role
        user.clearance_level = approval.clearance_level

        # 2. If promoted to an admin role, generate + email an access code
        system_code_generated = None
        ADMIN_ROLES = {"SUPER_ADMIN", "ADMIN", "OVERSEER"}
        if approval.role in ADMIN_ROLES:
            system_code_generated = generate_system_code()
            user.system_code = system_code_generated

        # 3. Log Action
        log_entry = AccessLog(
            admin_id=current_user.id,
            target_user_id=user.id,
            action="APPROVE",
            details=f"Role: {approval.role}, Level: {approval.clearance_level}"
        )
        db.add(log_entry)

        await db.commit()
        await db.refresh(user)

        # 4. Send approval email (with admin code if applicable)
        if system_code_generated:
            html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>body{{background:#f4f6f8;font-family:sans-serif;margin:0;padding:0}}
.w{{max-width:580px;margin:40px auto;background:#fff;border-radius:8px;overflow:hidden;border-top:4px solid #ff0055}}
.h{{padding:28px 30px;border-bottom:1px solid #eef0f2}}.h h1{{margin:0;color:#0f171e;font-size:22px}}
.h p{{margin:6px 0 0;color:#64748b;font-size:13px;text-transform:uppercase;letter-spacing:1px}}
.b{{padding:36px 30px}}.b p{{color:#334155;line-height:1.6;font-size:15px}}
.code-box{{background:#0f171e;color:#ff0055;font-family:monospace;font-size:2rem;font-weight:700;
text-align:center;padding:20px;border-radius:6px;letter-spacing:8px;margin:24px 0}}
.note{{background:#fff5f5;border:1px solid #fed7d7;border-radius:6px;padding:14px;
font-size:13px;color:#c53030;margin-top:24px}}
.f{{background:#0f171e;padding:20px;font-size:12px;color:#94a3b8;text-align:center}}</style></head>
<body><div class="w">
<div class="h"><h1>SOC SENTINEL</h1><p>Admin Access Approved</p></div>
<div class="b">
<p>Hello <strong>{user.first_name or user.username}</strong>,<br><br>
Your account has been approved with <strong>{approval.role}</strong> privileges (Clearance Level {approval.clearance_level}).<br>
You can now log into the system using your credentials along with the Admin Access Code below.</p>
<div class="code-box">{system_code_generated}</div>
<p>Use this code in the <strong>Admin Login</strong> page alongside your email and password.<br>
Navigate to: <a href="http://localhost:5500/frontend/admin_login.html" style="color:#00c6ff">Admin Login Page</a></p>
<div class="note"><strong>Security Notice:</strong> Keep this code confidential. Do not share it with anyone.
This code is your second factor for admin authentication.</div>
</div>
<div class="f">Shadow Trust Defense Systems &bull; {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}</div>
</div></body></html>"""
            _send_auth_email(user.email, "[Shadow Trust] Admin Access Approved — Your Access Code", html)
        else:
            # Regular user approval email
            html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>body{{background:#f4f6f8;font-family:sans-serif;margin:0;padding:0}}
.w{{max-width:580px;margin:40px auto;background:#fff;border-radius:8px;overflow:hidden;border-top:4px solid #00c6ff}}
.h{{padding:28px 30px;border-bottom:1px solid #eef0f2}}.h h1{{margin:0;color:#0f171e;font-size:22px}}
.h p{{margin:6px 0 0;color:#64748b;font-size:13px;text-transform:uppercase;letter-spacing:1px}}
.b{{padding:36px 30px}}.b p{{color:#334155;line-height:1.6;font-size:15px}}
.btn{{display:inline-block;background:#00c6ff;color:#0f171e;padding:13px 26px;border-radius:4px;
font-weight:700;text-decoration:none;font-size:15px;margin:24px 0}}
.f{{background:#0f171e;padding:20px;font-size:12px;color:#94a3b8;text-align:center}}</style></head>
<body><div class="w">
<div class="h"><h1>SOC SENTINEL</h1><p>Account Approved</p></div>
<div class="b">
<p>Hello <strong>{user.first_name or user.username}</strong>,<br><br>
Your account has been approved with role <strong>{approval.role}</strong> (Clearance Level {approval.clearance_level}).<br>
You can now sign in to the platform.</p>
<a href="http://localhost:5500/frontend/login.html" class="btn">Sign In Now</a>
</div>
<div class="f">Shadow Trust Defense Systems &bull; {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}</div>
</div></body></html>"""
            _send_auth_email(user.email, "[Shadow Trust] Your Account Has Been Approved", html)

        return {"status": "approved", "user": {
                 "id": user.id,
                 "email": user.email,
                 "username": user.username,
                 "first_name": user.first_name,
                 "last_name": user.last_name,
                 "department": user.department,
                 "role": user.role,
                 "clearance_level": user.clearance_level,
                 "requested_clearance_level": user.requested_clearance_level,
                 "status": user.status,
             }}
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{user_id}/regenerate-admin-code")
async def regenerate_admin_code(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["SUPER_ADMIN"]))
):
    """Generate (or regenerate) the 2FA hardware token for an admin user and email it."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    new_code = generate_system_code()
    user.system_code = new_code
    await db.commit()

    # Email the new code
    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>body{{background:#f4f6f8;font-family:sans-serif;margin:0;padding:0}}
.w{{max-width:580px;margin:40px auto;background:#fff;border-radius:8px;overflow:hidden;border-top:4px solid #ff0055}}
.h{{padding:28px 30px;border-bottom:1px solid #eef0f2}}.h h1{{margin:0;color:#0f171e;font-size:22px}}
.h p{{margin:6px 0 0;color:#64748b;font-size:13px;text-transform:uppercase;letter-spacing:1px}}
.b{{padding:36px 30px}}.b p{{color:#334155;line-height:1.6;font-size:15px}}
.code-box{{background:#0f171e;color:#ff0055;font-family:monospace;font-size:2rem;font-weight:700;
text-align:center;padding:20px;border-radius:6px;letter-spacing:8px;margin:24px 0}}
.note{{background:#fff5f5;border:1px solid #fed7d7;border-radius:6px;padding:14px;
font-size:13px;color:#c53030;margin-top:24px}}
.f{{background:#0f171e;padding:20px;font-size:12px;color:#94a3b8;text-align:center}}</style></head>
<body><div class="w">
<div class="h"><h1>SOC SENTINEL</h1><p>New 2FA Hardware Token</p></div>
<div class="b">
<p>Hello <strong>{user.first_name or user.username}</strong>,<br><br>
A new admin 2FA Hardware Token has been generated for your account by a Super Administrator.</p>
<div class="code-box">{new_code}</div>
<p>Use this token on the Admin Login page alongside your email and password.</p>
<div class="note"><strong>Security Notice:</strong> Your old token is now invalid. Keep this code confidential.</div>
</div>
<div class="f">Shadow Trust Defense Systems &bull; {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}</div>
</div></body></html>"""
    email_sent = _send_auth_email(user.email, "[Shadow Trust] Your New 2FA Hardware Token", html)

    return {
        "status": "success",
        "system_code": new_code,
        "email_sent": email_sent,
        "user_email": user.email
    }

@router.post("/{user_id}/deny")
async def deny_user(
    user_id: str, 
    denial: UserDeny,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["SUPER_ADMIN"]))
):
    """Deny (Delete) a pending user."""
    try:
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalars().first()
        
        if not user:
             raise HTTPException(status_code=404, detail="User not found")
        
        target_email = user.email

        # 2. Delete User (or could set status=REJECTED)
        await db.delete(user)

        # 3. Log Action
        log_entry = AccessLog(
            admin_id=current_user.id,
            target_user_id=None,
            action="DENY",
            details=f"User {target_email} denied. Reason: {denial.reason}"
        )
        db.add(log_entry)
        
        await db.commit()

        return {"status": "denied", "message": "User access denied and record removed."}
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
