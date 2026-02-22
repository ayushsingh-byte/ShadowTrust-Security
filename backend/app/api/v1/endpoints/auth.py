
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from app.services.auth_service import auth_service

router = APIRouter()

class UserRegister(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class OTPVerify(BaseModel):
    email: str
    otp: str

@router.post("/register")
def register(user_in: UserRegister):
    return auth_service.register_user(user_in.email, user_in.password)

@router.post("/login")
def login(user_in: UserLogin):
    return auth_service.login(user_in.email, user_in.password)

@router.post("/verify-otp")
def verify_otp(otp_in: OTPVerify):
    return auth_service.verify_otp_and_token(otp_in.email, otp_in.otp)