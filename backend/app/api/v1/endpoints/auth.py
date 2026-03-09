from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.sqlite_db import get_db
from app.services.auth_service import auth_service

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

@router.post("/dev-bypass")
async def dev_bypass(db: AsyncSession = Depends(get_db)):
    return await auth_service.dev_bypass_token(db)