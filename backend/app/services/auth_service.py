from datetime import datetime, timedelta
from typing import Optional
import random
import string
import secrets
import jwt
import bcrypt
import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.core.config import settings
from app.models.all_models import User

# ─── Email Config (reads same .env as credential_service) ─────────────────────
_SMTP_HOST    = os.getenv("SMTP_HOST", "")
_SMTP_PORT    = int(os.getenv("SMTP_PORT", "587"))
_SMTP_USER    = os.getenv("SMTP_USER", "")
_SMTP_PASS    = os.getenv("SMTP_PASS", "")
_SMTP_FROM    = os.getenv("SMTP_FROM", _SMTP_USER)
_SMTP_ENABLED = bool(_SMTP_HOST and _SMTP_USER and _SMTP_PASS)
_PORTAL_URL   = os.getenv("PORTAL_BASE_URL", "http://localhost:5500")

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

def generate_system_code() -> str:
    """Generate a 6-char admin access code in XXX-XXX format (uppercase letters + digits)."""
    chars = string.ascii_uppercase + string.digits
    part1 = ''.join(random.choices(chars, k=3))
    part2 = ''.join(random.choices(chars, k=3))
    return f"{part1}-{part2}"

def _send_auth_email(to_email: str, subject: str, html_body: str) -> bool:
    """Send an auth-related email. Returns True on success, False otherwise."""
    if not _SMTP_ENABLED:
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = _SMTP_FROM
        msg["To"] = to_email
        msg.attach(MIMEText(html_body, "html"))
        with smtplib.SMTP(_SMTP_HOST, _SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(_SMTP_USER, _SMTP_PASS)
            server.sendmail(_SMTP_FROM, [to_email], msg.as_string())
        return True
    except Exception:
        return False

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

    async def forgot_password(self, db: AsyncSession, email: str):
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalars().first()
        # Always return success to avoid email enumeration
        if not user:
            return {"message": "If that email exists, a reset link has been sent."}

        # Generate a secure token, store in otp_code with 1-hour expiry
        token = secrets.token_urlsafe(32)
        user.otp_code = token
        user.otp_expires_at = datetime.utcnow() + timedelta(hours=1)
        await db.commit()

        reset_link = f"{_PORTAL_URL}/frontend/forgot_password.html?token={token}"
        html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>body{{background:#f4f6f8;font-family:sans-serif;margin:0;padding:0}}
.w{{max-width:580px;margin:40px auto;background:#fff;border-radius:8px;overflow:hidden;border-top:4px solid #00c6ff}}
.h{{padding:28px 30px;border-bottom:1px solid #eef0f2}}.h h1{{margin:0;color:#0f171e;font-size:22px}}
.h p{{margin:6px 0 0;color:#64748b;font-size:13px;text-transform:uppercase;letter-spacing:1px}}
.b{{padding:36px 30px}}.b p{{color:#334155;line-height:1.6;font-size:15px}}
.btn{{display:inline-block;background:#00c6ff;color:#0f171e;padding:13px 26px;border-radius:4px;
font-weight:700;text-decoration:none;font-size:15px;margin:24px 0}}
.note{{background:#fff5f5;border:1px solid #fed7d7;border-radius:6px;padding:14px;
font-size:13px;color:#c53030;margin-top:24px}}
.f{{background:#0f171e;padding:20px;font-size:12px;color:#94a3b8;text-align:center}}</style></head>
<body><div class="w"><div class="h"><h1>SOC SENTINEL</h1><p>Password Reset Request</p></div>
<div class="b"><p>We received a request to reset the password for your account.<br>
Click the button below to set a new password. This link expires in <strong>1 hour</strong>.</p>
<a href="{reset_link}" class="btn">Reset My Password</a>
<div class="note">If you did not request a password reset, ignore this email — your account is safe.</div>
</div><div class="f">Shadow Trust Defense Systems &bull; {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}</div>
</div></body></html>"""

        sent = _send_auth_email(user.email, "[Shadow Trust] Password Reset Link", html)
        return {"message": "If that email exists, a reset link has been sent.", "email_sent": sent}

    async def reset_password(self, db: AsyncSession, token: str, new_password: str):
        if len(new_password) < 8:
            raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")

        result = await db.execute(select(User).where(User.otp_code == token))
        user = result.scalars().first()
        if not user:
            raise HTTPException(status_code=400, detail="Invalid or expired reset token.")
        if not user.otp_expires_at or datetime.utcnow() > user.otp_expires_at.replace(tzinfo=None):
            raise HTTPException(status_code=400, detail="Reset token has expired. Please request a new one.")

        user.password_hash = get_password_hash(new_password)
        user.otp_code = None
        user.otp_expires_at = None
        await db.commit()
        return {"message": "Password reset successfully. You can now log in."}

    async def admin_login(self, db: AsyncSession, email: str, password: str, system_code: str):
        """Admin login: validates email + password + system_code."""
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalars().first()

        if not user or not verify_password(password, user.password_hash):
            raise HTTPException(status_code=401, detail="Invalid credentials")

        if user.status != "ACTIVE":
            raise HTTPException(status_code=403, detail="Account is not active")

        admin_roles = {"SUPER_ADMIN", "ADMIN", "OVERSEER"}
        if user.role not in admin_roles:
            raise HTTPException(status_code=403, detail="This account does not have admin privileges")

        # Validate system_code
        if not user.system_code:
            raise HTTPException(status_code=403, detail="No admin access code is set for this account. Contact a Super Admin.")

        if user.system_code.strip().upper() != system_code.strip().upper():
            raise HTTPException(status_code=401, detail="Invalid admin access code")

        user.last_login = datetime.utcnow()
        await db.commit()

        access_token = create_access_token(
            data={"sub": user.email, "role": user.role, "clearance": user.clearance_level, "user_id": user.id}
        )
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {"id": user.id, "email": user.email, "role": user.role, "status": user.status}
        }

    async def dev_bypass_token(self, db: AsyncSession):
        # Create or fetch an admin user for dev bypass
        email = "admin@gmail.com"
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
                last_name="Bypass",
                system_code=generate_system_code()
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
        else:
            changed = False
            if user.status != "ACTIVE" or user.role != "SUPER_ADMIN":
                user.status = "ACTIVE"
                user.role = "SUPER_ADMIN"
                user.clearance_level = 5
                changed = True
            if not user.system_code:
                user.system_code = generate_system_code()
                changed = True
            if changed:
                await db.commit()
            
        access_token = create_access_token(
            data={"sub": user.email, "role": user.role, "clearance": user.clearance_level, "user_id": user.id}
        )
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "system_code": user.system_code,   # exposed for dev convenience
            "user": {
                "id": user.id,
                "email": user.email,
                "role": user.role,
                "status": user.status
            }
        }

auth_service = AuthService()
