from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.sqlite_db import get_db
from app.services.auth_service import auth_service

router = APIRouter()

class UserRegister(BaseModel):
    email: str
    password: str
    full_name: str = ""

class UserLogin(BaseModel):
    email: str
    password: str

class OTPVerify(BaseModel):
    email: str
    otp: str

@router.post("/register")
async def register(user_in: UserRegister, db: AsyncSession = Depends(get_db)):
    return await auth_service.register_user(db, user_in.email, user_in.password, user_in.full_name)

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