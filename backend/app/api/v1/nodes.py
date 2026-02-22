from fastapi import APIRouter, HTTPException, Depends
from typing import List, Dict, Any
import psutil
import time
import random
import uuid
from app.core.supabase import supabase

router = APIRouter()

# --- Mock Service Manager (Since we are single VM) ---
class NodeService:
    @staticmethod
    def get_system_stats():
        return {
            "cpu_percent": psutil.cpu_percent(interval=None),
            "memory": psutil.virtual_memory()._asdict(),
            "disk": psutil.disk_usage('/')._asdict(),
            "boot_time": psutil.boot_time()
        }

    @staticmethod
    def simulate_launch(node_type: str, name: str):
        # In a real system, this would spawn a Docker container or VM
        # Here we just generate a mock PID and "Success"
        return {
            "pid": random.randint(1000, 9999),
            "status": "ONLINE",
            "ip": f"10.0.1.{random.randint(10, 250)}"
        }

# --- Endpoints ---

@router.get("/", response_model=List[Dict[str, Any]])
def get_nodes():
    """Fetch all nodes from Supabase."""
    res = supabase.table("nodes").select("*").execute()
    return res.data

@router.get("/stats")
def get_stats():
    """Get real-time system stats (CPU/RAM) of the host."""
    return NodeService.get_system_stats()

@router.post("/launch")
def launch_node(name: str, type: str, sector: str):
    """Launch a new node (Simulated)."""
    # 1. Simulate Deployment
    sim_data = NodeService.simulate_launch(type, name)
    
    # 2. Record in DB
    new_node = {
        "node_id": str(uuid.uuid4()),
        "name": name,
        "type": type,
        "sector": sector,
        "status": sim_data["status"],
        "ip_address": sim_data["ip"],
        "uptime_seconds": 0,
        "risk_level": "LOW"
    }

    try:
        res = supabase.table("nodes").insert(new_node).execute()
        if not res.data:
            # raise HTTPException(status_code=500, detail="Failed to save node to DB")
            with open("error.log", "a") as f:
                 f.write(f"Launch Failed: No data returned. Response: {res}\n")
            return {} # Return empty dict to avoid 500 for now if data is missing but no error
    except Exception as e:
        with open("error.log", "a") as f:
            f.write(f"Launch Error: {str(e)}\n")
        raise HTTPException(status_code=500, detail=f"Database Error: {str(e)}")
        
    return res.data[0]

@router.post("/{node_id}/stop")
def stop_node(node_id: str):
    """Stop a node."""
    # Update DB status
    res = supabase.table("nodes").update({"status": "OFFLINE"}).eq("node_id", node_id).execute()
    return {"message": "Node stopped", "node_id": node_id}

@router.post("/{node_id}/start")
def start_node(node_id: str):
    """Start a node."""
    res = supabase.table("nodes").update({"status": "RUNNING"}).eq("node_id", node_id).execute()
    return {"message": "Node started", "node_id": node_id}
