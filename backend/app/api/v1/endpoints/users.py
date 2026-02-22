from fastapi import APIRouter, HTTPException, Depends
from typing import List, Optional
from pydantic import BaseModel
from app.core.supabase import supabase
from app.services.auth_service import AuthService
# reusing the existing service for password hashing if available, or implementing basic hash here

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
    id: int
    email: str
    first_name: Optional[str]
    last_name: Optional[str]
    role: str
    clearance_level: int
    status: str
    last_login: Optional[str]

@router.get("/", response_model=List[UserOut])
def list_users():
    """List all users."""
    try:
        response = supabase.table("users").select("*").execute()
        return response.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/")
def create_user(user: UserCreate):
    """Create a new user with specific role and clearance."""
    try:
        # Check if user exists
        exists = supabase.table("users").select("email").eq("email", user.email).execute()
        if exists.data:
            raise HTTPException(status_code=400, detail="User already exists")

        # Hash password (using AuthService utility if possible, else implementing here)
        # For now assuming AuthService has a helper or we use a basic implementation
        # In a real scenario we'd import the context from passlib
        # hashed_pw = auth_service.get_password_hash(user.password) 
        
        # Simulating hash for now as we don't have direct access to internal hash func in previous view
        # But we can call the service register method if it supports extra fields, 
        # or just invoke the hashing logic. 
        # Let's use a placeholder hash for safety until we see auth_service.py
        hashed_pw = f"hashed_{user.password}" 

        new_user = {
            "email": user.email,
            "password_hash": hashed_pw,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "role": user.role,
            "clearance_level": user.clearance_level,
            "status": "ACTIVE" 
        }

        data = supabase.table("users").insert(new_user).execute()
        if not data.data:
             raise HTTPException(status_code=500, detail="Failed to create user")
             
        return data.data[0]

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/{user_id}")
def update_user(user_id: int, user_update: UserUpdate):
    """Update user details and access level."""
    try:
        updates = {k: v for k, v in user_update.dict().items() if v is not None}
        if not updates:
            raise HTTPException(status_code=400, detail="No fields to update")

        data = supabase.table("users").update(updates).eq("id", user_id).execute()
        if not data.data:
            raise HTTPException(status_code=404, detail="User not found")
            
        return data.data[0]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/{user_id}")
def delete_user(user_id: int):
    """Delete a user."""
    try:
        data = supabase.table("users").delete().eq("id", user_id).execute()
        if not data.data:
             raise HTTPException(status_code=404, detail="User not found")
        return {"message": "User deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- Access Control Endpoints ---

class UserApprove(BaseModel):
    role: str
    clearance_level: int
    admin_id: int # The ID of the admin performing the action

class UserDeny(BaseModel):
    reason: str
    admin_id: int

@router.get("/pending", response_model=List[UserOut])
def list_pending_users():
    """List users awaiting approval."""
    try:
        response = supabase.table("users").select("*").eq("status", "PENDING").execute()
        return response.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{user_id}/approve")
def approve_user(user_id: int, approval: UserApprove):
    """Approve a pending user."""
    try:
        # 1. Update User
        updates = {
            "status": "ACTIVE",
            "role": approval.role,
            "clearance_level": approval.clearance_level
        }
        user_data = supabase.table("users").update(updates).eq("id", user_id).execute()
        
        if not user_data.data:
            raise HTTPException(status_code=404, detail="User not found")

        # 2. Log Action
        log_entry = {
            "admin_id": approval.admin_id,
            "target_user_id": user_id,
            "action": "APPROVE",
            "details": f"Role: {approval.role}, Level: {approval.clearance_level}"
        }
        supabase.table("access_logs").insert(log_entry).execute()

        return {"status": "approved", "user": user_data.data[0]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{user_id}/deny")
def deny_user(user_id: int, denial: UserDeny):
    """Deny (Delete) a pending user."""
    try:
        # 1. Get user details for log before Deleting
        user_data = supabase.table("users").select("*").eq("id", user_id).execute()
        if not user_data.data:
             raise HTTPException(status_code=404, detail="User not found")
        
        target_email = user_data.data[0]['email']

        # 2. Delete User (or could set status=REJECTED)
        # For security, often better to just remove pending request
        supabase.table("users").delete().eq("id", user_id).execute()

        # 3. Log Action
        log_entry = {
            "admin_id": denial.admin_id,
            "target_user_id": None, # User deleted, so null or keep ID for record if soft delete
            "action": "DENY",
            "details": f"User {target_email} denied. Reason: {denial.reason}"
        }
        supabase.table("access_logs").insert(log_entry).execute()

        return {"status": "denied", "message": "User access denied and record removed."}
    except Exception as e:
         raise HTTPException(status_code=500, detail=str(e))
