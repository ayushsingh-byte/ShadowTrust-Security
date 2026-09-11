import os

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import jwt

from app.core.config import settings
from app.db.database import get_db
from app.models.all_models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login")


def dev_bypass_enabled() -> bool:
    """
    The ``dev_bypass_token`` shortcut is honoured only when explicitly enabled
    (``DEV_BYPASS=1``) AND the app is running locally (``INFRA_PROVIDER=local``).
    Any production-like config is fail-closed.
    """
    return (
        os.getenv("DEV_BYPASS", "0").strip().lower() in ("1", "true", "yes")
        and os.getenv("INFRA_PROVIDER", "local").strip().lower() == "local"
    )

# The persisted account the dev-bypass shortcut signs in as (see AuthService.dev_bypass_token).
DEV_BYPASS_EMAIL = "admin@gmail.com"


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        if token == "dev_bypass_token":
            if not dev_bypass_enabled():
                raise credentials_exception
            # Resolve to the real database row, so the user has an id and serializes like any
            # other — an unsaved stand-in object made /users/me fail response validation.
            email = DEV_BYPASS_EMAIL
            if (await db.execute(select(User.id).where(User.email == email))).first() is None:
                from app.services.auth_service import auth_service
                await auth_service.dev_bypass_token(db)
        else:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            email = payload.get("sub")
        if email is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalars().first()
    
    if user is None:
        raise credentials_exception
    if user.status != "ACTIVE":
        raise HTTPException(status_code=400, detail="Inactive user")
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.status != "ACTIVE":
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def require_role(allowed_roles: list[str]):
    async def role_checker(current_user: User = Depends(get_current_active_user)):
        if current_user.role not in allowed_roles and current_user.role != "SUPER_ADMIN":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted. Required role in {allowed_roles}"
            )
        return current_user
    return role_checker

def require_clearance(min_level: int):
    async def clearance_checker(current_user: User = Depends(get_current_active_user)):
        if current_user.clearance_level < min_level and current_user.role != "SUPER_ADMIN":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted. Minimum clearance level {min_level} required"
            )
        return current_user
    return clearance_checker
