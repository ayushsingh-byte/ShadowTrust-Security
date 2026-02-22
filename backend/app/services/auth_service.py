
from datetime import datetime, timedelta
from typing import Optional
import random
import string
import jwt
from fastapi import HTTPException, status
from app.core.config import settings
from app.core.supabase import supabase
# In a real app, use a proper email library. For demo, we might mock or use a simple SMTP function.
# from app.utils.email import send_email

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

class AuthService:
    def register_user(self, email: str, password: str):
        # Check if user exists
        user = supabase.table("users").select("*").eq("email", email).execute()
        if user.data:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Create user (unapproved)
        # In a real app, hash password here!
        # For this demo, assuming password is sent hashed or we hash it now.
        # simple hash for demo:
        # pwd_hash = "hashed_" + password 
        
        new_user = {
            "email": email,
            "password_hash": password, # REPLACE WITH HASHING
            "role": "operative",
            "is_approved": False
        }
        res = supabase.table("users").insert(new_user).execute()
        return res.data[0]

    def login(self, email: str, password: str):
        user_res = supabase.table("users").select("*").eq("email", email).execute()
        if not user_res.data:
             raise HTTPException(status_code=400, detail="Invalid credentials")
        
        user = user_res.data[0]
        # Verify password (DEMO)
        if user["password_hash"] != password:
             raise HTTPException(status_code=400, detail="Invalid credentials")
             
        if not user.get("is_approved"):
            raise HTTPException(status_code=403, detail="Account pending approval by Admin")

        # Generate OTP
        otp = generate_otp()
        # Store OTP in DB or Cache (Skipping for brevity, assuming immediate verification or email send)
        # For this demo, we will return the OTP in the response for testing, 
        # BUT normally you send it via Email.
        
        return {"message": "OTP sent", "otp_debug": otp, "email": email}

    def verify_otp_and_token(self, email: str, otp: str):
        # Validate OTP (Mock implementation)
        # In real world, check against stored OTP
        if len(otp) != 6:
             raise HTTPException(status_code=400, detail="Invalid OTP")
             
        user_res = supabase.table("users").select("*").eq("email", email).execute()
        user = user_res.data[0]
        
        access_token = create_access_token(
            data={"sub": user["email"], "role": user["role"], "user_id": user["id"]}
        )
        return {"access_token": access_token, "token_type": "bearer"}

auth_service = AuthService()
