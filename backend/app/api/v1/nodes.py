from fastapi import APIRouter, HTTPException, Depends
from typing import List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, update
import psutil
import time
import random
import uuid

from app.db.sqlite_db import get_db, AsyncSessionLocal
from app.models.all_models import RawEventModel, Node
from app.api.v1.dependencies import get_current_active_user, User

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

@router.get("/")
async def get_nodes(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Fetch active nodes from local SQLite."""
    # Real statically defined nodes or dynamically added
    result = await db.execute(select(Node))
    nodes = result.scalars().all()
    
    nodes_data = []
    for n in nodes:
        nodes_data.append({
            "node_id": n.node_id,
            "name": n.name,
            "type": n.type,
            "sector": n.sector,
            "status": n.status,
            "ip_address": n.ip_address,
            "uptime_seconds": n.uptime_seconds,
            "risk_level": n.risk_level,
            "cpu_percent": random.randint(5, 30) if n.status == "ONLINE" else 0
        })
    
    # Aggregated virtual nodes from incoming logs
    distinct_nodes_query = await db.execute(
        select(RawEventModel.honeypot_type, func.max(RawEventModel.timestamp).label("last_seen"))
        .where(RawEventModel.honeypot_type != None)
        .group_by(RawEventModel.honeypot_type)
    )
    
    for hp_type, last_seen in distinct_nodes_query.all():
        node_type = hp_type.upper() if hp_type else "UNKNOWN"
        virtual_name = f"{node_type}-SENSOR-01"
        
        # Avoid duplicate mock virtual nodes if real nodes exist in DB
        if not any(nd["name"] == virtual_name for nd in nodes_data):
            nodes_data.append({
                "node_id": str(uuid.uuid4()),
                "name": virtual_name,
                "type": node_type,
                "sector": "EXTERNAL",
                "status": "ONLINE",
                "ip_address": "Locally Ingested",
                "uptime_seconds": 99999,
                "risk_level": "LOW",
                "cpu_percent": random.randint(5, 30) # Simulated load for the UI
            })
        
    return nodes_data

@router.get("/stats")
async def get_stats(current_user: User = Depends(get_current_active_user)):
    """Get real-time system stats (CPU/RAM) of the host."""
    return NodeService.get_system_stats()

@router.post("/launch")
async def launch_node(
    name: str, 
    type: str, 
    sector: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Launch a new node (Simulated)."""
    # 1. Simulate Deployment
    sim_data = NodeService.simulate_launch(type, name)
    
    # 2. Record in DB
    new_node = Node(
        node_id=str(uuid.uuid4()),
        name=name,
        type=type,
        sector=sector,
        status=sim_data["status"],
        ip_address=sim_data["ip"],
        uptime_seconds=0,
        risk_level="LOW"
    )

    try:
        db.add(new_node)
        await db.commit()
        await db.refresh(new_node)
        
        return {
            "node_id": new_node.node_id,
            "name": new_node.name,
            "type": new_node.type,
            "sector": new_node.sector,
            "status": new_node.status,
            "ip_address": new_node.ip_address,
            "uptime_seconds": new_node.uptime_seconds,
            "risk_level": new_node.risk_level
        }
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Database Error: {str(e)}")

@router.post("/{node_id}/stop")
async def stop_node(
    node_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Stop a node."""
    try:
        await db.execute(update(Node).where(Node.node_id == node_id).values(status="OFFLINE"))
        await db.commit()
        return {"message": "Node stopped", "node_id": node_id}
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{node_id}/start")
async def start_node(
    node_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Start a node."""
    try:
        await db.execute(update(Node).where(Node.node_id == node_id).values(status="RUNNING"))
        await db.commit()
        return {"message": "Node started", "node_id": node_id}
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
