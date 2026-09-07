"""
Live honeynet API — normalized events, attacker profiles, sensor health.

Everything here reads normalized_events, so the dashboard never touches a
Cowrie- or Dionaea-specific field name. The older dashboard/geo/events
endpoints continue to read raw_events and are left alone.

Real-time delivery is Server-Sent Events rather than WebSockets: the stream is
one-directional (server -> browser), SSE reconnects automatically, it needs no
extra dependency, and it survives an nginx proxy with one buffering directive.
A WebSocket would add a handshake, a heartbeat protocol and a reconnect loop to
write, for no capability this dashboard uses.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.models.all_models import NormalizedEventModel
from app.services.event_bus import event_bus
from app.services.telemetry.collector import local_collector
from app.services.telemetry.normalize import KNOWN_SENSORS

router = APIRouter()

# A sensor with no event inside this window is reported as idle rather than
# online. Long enough that a quiet honeypot is not flapping, short enough that
# a dead sensor is noticed during a demo.
SENSOR_ACTIVE_WINDOW = timedelta(minutes=5)

# Heartbeat cadence for the SSE stream. Without periodic traffic an idle
# connection is closed by intermediate proxies, and the dashboard would go
# quiet without knowing it had been disconnected.
SSE_HEARTBEAT_SECONDS = 15.0


def _serialize(event: NormalizedEventModel) -> Dict[str, Any]:
    """Row -> the same JSON shape the SSE stream emits, so the dashboard has one parser."""
    return {
        "event_id": event.event_id,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "ingested_at": event.ingested_at.isoformat() if event.ingested_at else None,
        "sensor": event.sensor,
        "sensor_event_type": event.sensor_event_type,
        "source_ip": event.source_ip,
        "source_port": event.source_port,
        "destination_ip": event.destination_ip,
        "destination_port": event.destination_port,
        "protocol": event.protocol,
        "username": event.username,
        "authentication_result": event.authentication_result,
        "command": event.command,
        "session_id": event.session_id,
        "severity": event.severity,
        "metadata": event.event_metadata,
    }


@router.get("/stream")
async def stream_events(request: Request):
    """
    Server-Sent Events stream of normalized events.

    Emits three event types:
      * ``event``     — one normalized honeypot event
      * ``heartbeat`` — periodic keepalive so proxies hold the connection
      * ``ready``     — sent once on connect, so the UI can show "live"

    The client disconnect check matters: without it a closed browser tab leaves
    the generator parked on the queue forever, and the bus keeps a subscriber
    that will never be read.
    """

    async def generator():
        yield f"event: ready\ndata: {json.dumps({'status': 'connected'})}\n\n"

        subscription = event_bus.subscribe()
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(
                        subscription.__anext__(), timeout=SSE_HEARTBEAT_SECONDS
                    )
                    yield f"event: event\ndata: {json.dumps(event, default=str)}\n\n"
                except asyncio.TimeoutError:
                    payload = json.dumps({"ts": datetime.utcnow().isoformat()})
                    yield f"event: heartbeat\ndata: {payload}\n\n"
        finally:
            await subscription.aclose()

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            # Tells nginx not to buffer the stream; without it events arrive in
            # batches when the proxy's buffer fills instead of immediately.
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/overview")
async def get_overview(db: AsyncSession = Depends(get_db)) -> Dict[str, Any]:
    """Headline counters for the dashboard's overview strip."""
    total = (await db.execute(select(func.count(NormalizedEventModel.event_id)))).scalar() or 0
    unique_ips = (
        await db.execute(select(func.count(func.distinct(NormalizedEventModel.source_ip))))
    ).scalar() or 0
    sessions = (
        await db.execute(
            select(func.count(func.distinct(NormalizedEventModel.session_id))).where(
                NormalizedEventModel.session_id.isnot(None)
            )
        )
    ).scalar() or 0
    commands = (
        await db.execute(
            select(func.count(NormalizedEventModel.event_id)).where(
                NormalizedEventModel.command.isnot(None)
            )
        )
    ).scalar() or 0
    logins = (
        await db.execute(
            select(func.count(NormalizedEventModel.event_id)).where(
                NormalizedEventModel.authentication_result == "SUCCESS"
            )
        )
    ).scalar() or 0

    severity_rows = (
        await db.execute(
            select(NormalizedEventModel.severity, func.count(NormalizedEventModel.event_id))
            .group_by(NormalizedEventModel.severity)
        )
    ).all()

    sensor_rows = (
        await db.execute(
            select(
                NormalizedEventModel.sensor,
                func.count(NormalizedEventModel.event_id),
                func.max(NormalizedEventModel.timestamp),
            ).group_by(NormalizedEventModel.sensor)
        )
    ).all()

    now = datetime.utcnow()
    sensors_online = sum(
        1 for _s, _c, last in sensor_rows if last and (now - last) < SENSOR_ACTIVE_WINDOW
    )

    return {
        "total_events": total,
        "unique_source_ips": unique_ips,
        "active_sessions": sessions,
        "commands_executed": commands,
        "successful_logins": logins,
        "sensors_online": sensors_online,
        "sensors_known": len(KNOWN_SENSORS),
        "severity_breakdown": {sev or "INFO": count for sev, count in severity_rows},
        "collector": local_collector.status(),
    }


@router.get("/events")
async def get_events(
    limit: int = Query(default=100, le=1000),
    sensor: Optional[str] = None,
    source_ip: Optional[str] = None,
    severity: Optional[str] = None,
    session_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Recent normalized events, newest first, with optional filters."""
    query = select(NormalizedEventModel)

    if sensor:
        query = query.where(NormalizedEventModel.sensor == sensor.lower())
    if source_ip:
        query = query.where(NormalizedEventModel.source_ip == source_ip)
    if severity:
        query = query.where(NormalizedEventModel.severity == severity.upper())
    if session_id:
        query = query.where(NormalizedEventModel.session_id == session_id)

    query = query.order_by(desc(NormalizedEventModel.timestamp)).limit(limit)
    rows = (await db.execute(query)).scalars().all()
    return [_serialize(row) for row in rows]


@router.get("/attackers")
async def get_attackers(
    limit: int = Query(default=50, le=500),
    db: AsyncSession = Depends(get_db),
) -> List[Dict[str, Any]]:
    """
    One profile per source IP.

    Aggregated in SQL rather than by loading every event into Python, so this
    stays fast as the event table grows.
    """
    rows = (
        await db.execute(
            select(
                NormalizedEventModel.source_ip,
                func.count(NormalizedEventModel.event_id).label("event_count"),
                func.min(NormalizedEventModel.timestamp).label("first_seen"),
                func.max(NormalizedEventModel.timestamp).label("last_seen"),
                func.count(func.distinct(NormalizedEventModel.sensor)).label("sensor_count"),
                func.count(func.distinct(NormalizedEventModel.session_id)).label("session_count"),
            )
            .group_by(NormalizedEventModel.source_ip)
            .order_by(desc("last_seen"))
            .limit(limit)
        )
    ).all()

    profiles = []
    for row in rows:
        detail = (
            await db.execute(
                select(
                    NormalizedEventModel.sensor,
                    NormalizedEventModel.destination_port,
                    NormalizedEventModel.protocol,
                    NormalizedEventModel.username,
                    NormalizedEventModel.command,
                    NormalizedEventModel.severity,
                    NormalizedEventModel.authentication_result,
                ).where(NormalizedEventModel.source_ip == row.source_ip)
            )
        ).all()

        sensors, ports, protocols, usernames, commands = set(), set(), set(), set(), []
        worst = "INFO"
        severity_rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        successful_logins = 0

        for item in detail:
            if item.sensor:
                sensors.add(item.sensor)
            if item.destination_port:
                ports.add(item.destination_port)
            if item.protocol:
                protocols.add(item.protocol)
            if item.username:
                usernames.add(item.username)
            if item.command and item.command not in commands:
                commands.append(item.command)
            if item.authentication_result == "SUCCESS":
                successful_logins += 1
            if severity_rank.get(item.severity or "INFO", 0) > severity_rank.get(worst, 0):
                worst = item.severity

        profiles.append({
            "source_ip": row.source_ip,
            "event_count": row.event_count,
            "first_seen": row.first_seen.isoformat() if row.first_seen else None,
            "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            "sensors": sorted(sensors),
            "ports_targeted": sorted(ports),
            "protocols": sorted(protocols),
            "usernames_attempted": sorted(usernames),
            "commands": commands[:50],
            "session_count": row.session_count,
            "successful_logins": successful_logins,
            "severity": worst,
        })

    return profiles


@router.get("/attackers/{source_ip}")
async def get_attacker(source_ip: str, db: AsyncSession = Depends(get_db)) -> Dict[str, Any]:
    """Full profile plus chronological timeline for one source IP."""
    rows = (
        await db.execute(
            select(NormalizedEventModel)
            .where(NormalizedEventModel.source_ip == source_ip)
            .order_by(NormalizedEventModel.timestamp)
        )
    ).scalars().all()

    if not rows:
        return {"source_ip": source_ip, "found": False, "timeline": []}

    sensors, ports, usernames, sessions = set(), set(), set(), set()
    commands: List[str] = []
    for row in rows:
        if row.sensor:
            sensors.add(row.sensor)
        if row.destination_port:
            ports.add(row.destination_port)
        if row.username:
            usernames.add(row.username)
        if row.session_id:
            sessions.add(row.session_id)
        if row.command:
            commands.append(row.command)

    return {
        "source_ip": source_ip,
        "found": True,
        "event_count": len(rows),
        "first_seen": rows[0].timestamp.isoformat() if rows[0].timestamp else None,
        "last_seen": rows[-1].timestamp.isoformat() if rows[-1].timestamp else None,
        "sensors": sorted(sensors),
        "ports_targeted": sorted(ports),
        "usernames_attempted": sorted(usernames),
        "sessions": sorted(sessions),
        "commands": commands,
        "timeline": [_serialize(row) for row in rows],
    }


@router.get("/sensors")
async def get_sensors(db: AsyncSession = Depends(get_db)) -> List[Dict[str, Any]]:
    """
    Per-sensor health.

    Every known sensor is listed even with zero events, so a sensor that has
    never reported shows as offline rather than silently missing from the UI —
    the difference between "quiet" and "broken" matters during a demo.
    """
    rows = (
        await db.execute(
            select(
                NormalizedEventModel.sensor,
                func.count(NormalizedEventModel.event_id).label("event_count"),
                func.max(NormalizedEventModel.timestamp).label("last_event"),
                func.count(func.distinct(NormalizedEventModel.source_ip)).label("unique_ips"),
            ).group_by(NormalizedEventModel.sensor)
        )
    ).all()

    by_sensor = {row.sensor: row for row in rows}
    now = datetime.utcnow()

    sensors = []
    for name in list(KNOWN_SENSORS) + [s for s in by_sensor if s not in KNOWN_SENSORS]:
        row = by_sensor.get(name)
        if row is None:
            sensors.append({
                "sensor": name,
                "status": "NO_DATA",
                "event_count": 0,
                "unique_source_ips": 0,
                "last_event": None,
                "seconds_since_last_event": None,
            })
            continue

        age = (now - row.last_event).total_seconds() if row.last_event else None
        sensors.append({
            "sensor": name,
            "status": "ACTIVE" if age is not None and age < SENSOR_ACTIVE_WINDOW.total_seconds() else "IDLE",
            "event_count": row.event_count,
            "unique_source_ips": row.unique_ips,
            "last_event": row.last_event.isoformat() if row.last_event else None,
            "seconds_since_last_event": int(age) if age is not None else None,
        })

    return sensors


@router.get("/sessions/{session_id}")
async def get_session(session_id: str, db: AsyncSession = Depends(get_db)) -> Dict[str, Any]:
    """Chronological timeline for one attacker session."""
    rows = (
        await db.execute(
            select(NormalizedEventModel)
            .where(NormalizedEventModel.session_id == session_id)
            .order_by(NormalizedEventModel.timestamp)
        )
    ).scalars().all()

    if not rows:
        return {"session_id": session_id, "found": False, "timeline": []}

    return {
        "session_id": session_id,
        "found": True,
        "source_ip": rows[0].source_ip,
        "sensor": rows[0].sensor,
        "started_at": rows[0].timestamp.isoformat() if rows[0].timestamp else None,
        "ended_at": rows[-1].timestamp.isoformat() if rows[-1].timestamp else None,
        "event_count": len(rows),
        "commands": [row.command for row in rows if row.command],
        "timeline": [_serialize(row) for row in rows],
    }


@router.get("/collector")
async def get_collector_status() -> Dict[str, Any]:
    """Collector health, for the dashboard's pipeline indicator."""
    return local_collector.status()
