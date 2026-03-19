from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.db.sqlite_db import get_db
from app.services.auth_service import auth_service, get_password_hash, create_access_token
from app.models.all_models import User, CredentialToken

router = APIRouter()

class UserRegister(BaseModel):
    username: str
    email: str
    password: str
    first_name: str = ""
    last_name: str = ""
    department: str = ""
    clearance_level: int = 1  # Requested clearance level (1, 2, or 3)

class UserLogin(BaseModel):
    email: str
    password: str

class OTPVerify(BaseModel):
    email: str
    otp: str

@router.post("/register")
async def register(user_in: UserRegister, db: AsyncSession = Depends(get_db)):
    return await auth_service.register_user(
        db,
        username=user_in.username,
        email=user_in.email,
        password=user_in.password,
        first_name=user_in.first_name,
        last_name=user_in.last_name,
        department=user_in.department,
        clearance_level=user_in.clearance_level
    )

from fastapi.security import OAuth2PasswordRequestForm

@router.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    return await auth_service.login(db, form_data.username, form_data.password)

@router.post("/verify-otp")
async def verify_otp(otp_in: OTPVerify, db: AsyncSession = Depends(get_db)):
    return await auth_service.verify_otp_and_token(db, otp_in.email, otp_in.otp)

@router.post("/forgot-password")
async def forgot_password(payload: dict, db: AsyncSession = Depends(get_db)):
    email = payload.get("email", "").strip()
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
    return await auth_service.forgot_password(db, email)

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

@router.post("/reset-password")
async def reset_password(req: ResetPasswordRequest, db: AsyncSession = Depends(get_db)):
    return await auth_service.reset_password(db, req.token, req.new_password)

class AdminLoginRequest(BaseModel):
    email: str
    password: str
    system_code: str

@router.post("/admin-login")
async def admin_login(req: AdminLoginRequest, db: AsyncSession = Depends(get_db)):
    return await auth_service.admin_login(db, req.email, req.password, req.system_code)

class ActivateAccountRequest(BaseModel):
    credential_token: str
    new_password: str

@router.post("/activate-account")
async def activate_account(req: ActivateAccountRequest, db: AsyncSession = Depends(get_db)):
    """
    Activates a user account via a credential token issued by an admin.
    Sets a new password and returns a JWT for immediate login.
    """
    if len(req.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")

    # Look up the token
    result = await db.execute(select(CredentialToken).where(CredentialToken.token == req.credential_token))
    token_obj = result.scalars().first()

    if not token_obj:
        raise HTTPException(status_code=400, detail="Invalid credential token.")
    if token_obj.used:
        raise HTTPException(status_code=400, detail="This credential token has already been used.")
    if datetime.utcnow() > token_obj.expires_at:
        raise HTTPException(status_code=400, detail="Credential token has expired.")

    # Find the user by username
    user_result = await db.execute(select(User).where(User.username == token_obj.username))
    user = user_result.scalars().first()
    if not user:
        # Try by email too
        user_result = await db.execute(select(User).where(User.email == token_obj.username))
        user = user_result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail=f"User '{token_obj.username}' not found.")

    # Update password and activate account
    user.password_hash = get_password_hash(req.new_password)
    if user.status == "PENDING":
        user.status = "ACTIVE"
    user.last_login = datetime.utcnow()

    # Mark token as used
    token_obj.used = True
    token_obj.used_at = datetime.utcnow()

    await db.commit()

    # Issue JWT
    access_token = create_access_token(
        data={"sub": user.email, "role": user.role, "clearance": user.clearance_level, "user_id": user.id}
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {"id": user.id, "email": user.email, "role": user.role, "status": user.status}
    }

@router.post("/dev-bypass")
async def dev_bypass(db: AsyncSession = Depends(get_db)):
    return await auth_service.dev_bypass_token(db)