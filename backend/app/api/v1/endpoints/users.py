from fastapi import APIRouter, HTTPException, Depends
from typing import List, Optional
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.db.sqlite_db import get_db
from app.models.all_models import User, AccessLog
from app.services.auth_service import get_password_hash
from app.api.v1.dependencies import get_current_active_user, require_role, require_clearance

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

        # 2. Log Action
        log_entry = AccessLog(
            admin_id=current_user.id,
            target_user_id=user.id,
            action="APPROVE",
            details=f"Role: {approval.role}, Level: {approval.clearance_level}"
        )
        db.add(log_entry)
        
        await db.commit()
        await db.refresh(user)

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
