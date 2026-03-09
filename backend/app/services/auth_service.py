from datetime import datetime, timedelta
from typing import Optional
import random
import string
import jwt
import bcrypt
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.core.config import settings
from app.models.all_models import User

# Password Hashing setup with direct bcrypt
SECRET_KEY = settings.SECRET_KEY
ALGORITHM = getattr(settings, "ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = getattr(settings, "ACCESS_TOKEN_EXPIRE_MINUTES", 60)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False

def get_password_hash(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

class AuthService:
    async def register_user(self, db: AsyncSession, username: str, email: str, password: str,
                             first_name: str = "", last_name: str = "", department: str = "",
                             clearance_level: int = 1):
        # Check if user exists by email or username
        result = await db.execute(select(User).where(User.email == email))
        if result.scalars().first():
            raise HTTPException(status_code=400, detail="Email already registered")

        result = await db.execute(select(User).where(User.username == username))
        if result.scalars().first():
            raise HTTPException(status_code=400, detail="Username already taken")

        # Validate clearance level
        if clearance_level not in (1, 2, 3):
            raise HTTPException(status_code=400, detail="Clearance level must be 1, 2, or 3")

        # Map requested clearance level to a default role
        role_map = {1: "OPERATIVE", 2: "SPECIALIST", 3: "OVERSEER"}
        requested_role = role_map.get(clearance_level, "OPERATIVE")

        # Create user — PENDING until Admin approves
        new_user = User(
            username=username,
            email=email,
            password_hash=get_password_hash(password),
            first_name=first_name,
            last_name=last_name,
            department=department,
            role=requested_role,
            clearance_level=None,  # Not assigned until approved
            requested_clearance_level=clearance_level,
            status="PENDING",
        )

        db.add(new_user)
        try:
            await db.commit()
            await db.refresh(new_user)
        except Exception as e:
            await db.rollback()
            raise HTTPException(status_code=500, detail=str(e))

        return {
            "id": new_user.id,
            "email": new_user.email,
            "username": new_user.username,
            "requested_clearance_level": new_user.requested_clearance_level,
            "message": "Registration successful. Your account is pending admin approval."
        }

    async def login(self, db: AsyncSession, email: str, password: str):
        # Try to find user by email first, then by username
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalars().first()
        if not user:
            result = await db.execute(select(User).where(User.username == email))
            user = result.scalars().first()
        
        if not user or not verify_password(password, user.password_hash):
             raise HTTPException(status_code=401, detail="Invalid credentials")
             
        if user.status == "PENDING":
            raise HTTPException(status_code=403, detail="Account pending approval by Admin")
        elif user.status == "BLOCKED":
            raise HTTPException(status_code=403, detail="Account is blocked")

        # Update last login
        user.last_login = datetime.utcnow()
        await db.commit()

        # For this prototype we can skip the OTP for seamless UI behavior
        # But here is where we would generate and store it.
        # otp = generate_otp()
        # user.otp_code = otp
        # user.otp_expires_at = datetime.utcnow() + timedelta(minutes=10)
        # await db.commit()
        # return {"message": "OTP sent", "otp_debug": otp, "email": email}
        
        # Seamless login without OTP for fast testing:
        return await self.verify_otp_and_token(db, email, "SKIP_OTP")

    async def verify_otp_and_token(self, db: AsyncSession, email: str, otp: str):
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalars().first()
        
        if not user:
            raise HTTPException(status_code=400, detail="User not found")
        
        # Skipping OTP validation for the prototype per prior conversation defaults (Bypass Login)
        # if otp != "SKIP_OTP" and user.otp_code != otp:
        #    raise HTTPException(status_code=401, detail="Invalid OTP")
             
        access_token = create_access_token(
            data={"sub": user.email, "role": user.role, "clearance": user.clearance_level, "user_id": user.id}
        )
        return {
            "access_token": access_token, 
            "token_type": "bearer", 
            "user": {
                "id": user.id,
                "email": user.email,
                "role": user.role,
                "status": user.status
            }
        }

    async def dev_bypass_token(self, db: AsyncSession):
        # Create or fetch an admin user for dev bypass
        email = "admin@shadowtrust.com"
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalars().first()
        
        if not user:
            user = User(
                username="admin_bypass",
                email=email,
                password_hash=get_password_hash("password123"),
                role="SUPER_ADMIN",
                clearance_level=5,
                status="ACTIVE",
                first_name="Dev",
                last_name="Bypass"
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
        elif user.status != "ACTIVE" or user.role != "SUPER_ADMIN":
            user.status = "ACTIVE"
            user.role = "SUPER_ADMIN"
            user.clearance_level = 5
            await db.commit()
            
        access_token = create_access_token(
            data={"sub": user.email, "role": user.role, "clearance": user.clearance_level, "user_id": user.id}
        )
        return {
            "access_token": access_token, 
            "token_type": "bearer", 
            "user": {
                "id": user.id,
                "email": user.email,
                "role": user.role,
                "status": user.status
            }
        }

auth_service = AuthService()
