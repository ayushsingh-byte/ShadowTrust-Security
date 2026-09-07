from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Dict, Any
from datetime import datetime, timedelta, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, update
import psutil
import time
import uuid

from app.db.database import get_db, AsyncSessionLocal
from app.models.all_models import RawEventModel, Node
from app.api.v1.dependencies import get_current_active_user, User
from app.services.container_status import sensor_container_states, SENSOR_CONTAINERS

router = APIRouter()

# --- Host system stats (real psutil readings) ---
class NodeService:
    @staticmethod
    def get_system_stats():
        process = psutil.Process()
        uptime_seconds = time.time() - process.create_time()
        net_io = psutil.net_io_counters()
        
        return {
            "cpu_percent": psutil.cpu_percent(interval=None),
            "memory": psutil.virtual_memory()._asdict(),
            "disk": psutil.disk_usage('/')._asdict(),
            "boot_time": process.create_time(),
            "uptime_seconds": uptime_seconds,
            "network": {
                "bytes_sent": net_io.bytes_sent,
                "bytes_recv": net_io.bytes_recv
            }
        }

# --- Endpoints ---

@router.get("/")
async def get_nodes(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Fetch active nodes from the database."""
    # Real statically defined nodes or dynamically added
    result = await db.execute(select(Node))
    nodes = result.scalars().all()
    
    # Real per-sensor activity load: events seen in the last 15 min, mapped to a
    # 0-100 "load" gauge. This is the honest signal for a honeypot grid — how
    # much an attacker is currently poking each sensor.
    since = datetime.utcnow() - timedelta(minutes=15)
    rate_rows = (await db.execute(
        select(RawEventModel.honeypot_type, func.count(RawEventModel.id))
        .where(RawEventModel.timestamp >= since)
        .group_by(RawEventModel.honeypot_type)
    )).all()
    load_by_type = {(t or "").upper(): c for t, c in rate_rows}
    # highest-risk event per sensor in the last 24h -> risk_level badge
    risk_since = datetime.utcnow() - timedelta(hours=24)
    risk_rows = (await db.execute(
        select(RawEventModel.honeypot_type, func.max(RawEventModel.risk_score))
        .where(RawEventModel.timestamp >= risk_since)
        .group_by(RawEventModel.honeypot_type)
    )).all()
    risk_by_type = {(t or "").upper(): (r or 0) for t, r in risk_rows}

    container_state = sensor_container_states()

    def _load(sensor_type: str) -> int:
        return min(100, int(load_by_type.get(sensor_type.upper(), 0)) * 6)

    def _risk_level(sensor_type: str) -> str:
        r = risk_by_type.get(sensor_type.upper(), 0)
        return "HIGH" if r >= 80 else ("MEDIUM" if r >= 40 else "LOW")

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
            "cpu_percent": _load(n.type or ""),
        })

    # Core honeypot sensors — status/uptime from the real container, load from
    # the real event rate. Falls back to event-recency if the Docker socket is
    # unavailable (so the grid still works outside compose).
    recent_seen = dict(
        (await db.execute(
            select(RawEventModel.honeypot_type, func.max(RawEventModel.timestamp))
            .where(RawEventModel.honeypot_type != None)
            .group_by(RawEventModel.honeypot_type)
        )).all()
    )
    recent_seen = {(k or "").upper(): v for k, v in recent_seen.items()}
    existing = {nd["name"] for nd in nodes_data}

    for sensor in SENSOR_CONTAINERS:
        virtual_name = f"{sensor}-SENSOR-01"
        if virtual_name in existing:
            continue
        st = container_state.get(sensor, {})
        if st.get("available"):
            online = bool(st.get("running"))
            uptime = int(st.get("uptime_seconds") or 0)
            status = "ONLINE" if online else "OFFLINE"
        else:
            last = recent_seen.get(sensor)
            if last is not None and last.tzinfo is not None:
                last = last.replace(tzinfo=None)
            online = last is not None and (datetime.utcnow() - last) < timedelta(minutes=30)
            uptime = 0
            status = "ONLINE" if online else "OFFLINE"
        nodes_data.append({
            "node_id": f"sensor-{sensor.lower()}",
            "name": virtual_name,
            "type": sensor,
            "sector": "EXTERNAL",
            "status": status,
            "ip_address": SENSOR_CONTAINERS[sensor],
            "uptime_seconds": uptime,
            "risk_level": _risk_level(sensor),
            "cpu_percent": _load(sensor) if online else 0,
        })

    return nodes_data

@router.get("/stats")
async def get_stats(current_user: User = Depends(get_current_active_user)):
    """Get real-time system stats (CPU/RAM) of the host."""
    return NodeService.get_system_stats()

class NodeLaunchRequest(BaseModel):
    name: str
    type: str
    sector: str


@router.post("/launch")
async def launch_node(
    req: NodeLaunchRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Honeypot sensors are fixed infrastructure services (cowrie / dionaea /
    honeytrap) defined in docker-compose.yml and deployed on the isolated
    honeynet_edge network. The application backend runs on the app network and
    deliberately cannot create or mutate edge-zone containers (see
    services/container_manager.py). To add a sensor, add a service to
    docker-compose.yml and `docker compose up -d`.
    """
    raise HTTPException(
        status_code=501,
        detail=("Sensor provisioning is not available from the dashboard. Honeypot "
                "sensors are compose-managed services on the isolated edge network. "
                "Add a service to docker-compose.yml to deploy another sensor."),
    )

@router.post("/{node_id}/stop")
async def stop_node(
    node_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Mark a registered node offline. Compose-managed sensors (node_id
    'sensor-*') are controlled through docker/compose, not here."""
    if node_id.startswith("sensor-"):
        raise HTTPException(status_code=409, detail=(
            "This is a compose-managed edge sensor. Stop it with "
            f"`docker compose stop {node_id.replace('sensor-', 'honeynet_')}` on the host."))
    res = await db.execute(select(Node).where(Node.node_id == node_id))
    node = res.scalars().first()
    if not node:
        raise HTTPException(status_code=404, detail="node not found")
    node.status = "OFFLINE"
    await db.commit()
    return {"message": "Node marked offline", "node_id": node_id, "status": "OFFLINE"}

@router.post("/{node_id}/start")
async def start_node(
    node_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Mark a registered node online. Compose-managed sensors (node_id
    'sensor-*') are controlled through docker/compose, not here."""
    if node_id.startswith("sensor-"):
        raise HTTPException(status_code=409, detail=(
            "This is a compose-managed edge sensor. Start it with "
            f"`docker compose start {node_id.replace('sensor-', 'honeynet_')}` on the host."))
    res = await db.execute(select(Node).where(Node.node_id == node_id))
    node = res.scalars().first()
    if not node:
        raise HTTPException(status_code=404, detail="node not found")
    node.status = "RUNNING"
    await db.commit()
    return {"message": "Node marked online", "node_id": node_id, "status": "RUNNING"}
