"""
Analysis Lab — disposable, egress-free sandbox shells (analysis_lab.html).

Every command an analyst types and every outbound connection the sandbox
attempts is captured and written as an ordinary telemetry event
(`normalized_events` + `raw_events`), so it flows through the **existing**
pipeline untouched:

    synthetic event  →  detection engine   (st-exec-003/004/005, st-recon-006)
                     →  behaviour profiler  (ai_engine/gnn_profiler)
                     →  incidents / MITRE analytics / Event Log / SSE

Events are tagged `honeypot_type="AnalysisShell"` /
`source_ip="analyst-shell:<email>"` so they are never confused with real
attacker telemetry.

The container itself: internal Docker network (no egress), no Docker socket, no
host mounts, `cap_drop=ALL` + `no-new-privileges`, non-root, 512 MB / 1 CPU /
128 PIDs, hard TTL + idle reap, one per user. Enforced in
`container_manager.validate_analysis_run`.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import AsyncSessionLocal
from app.models.all_models import (
    AnalysisSession,
    Incident,
    NormalizedEventModel,
    RawEventModel,
)
from app.services import container_manager
from app.services.event_bus import event_bus
from app.services.telemetry.collector import SEVERITY_RISK_SCORE
from app.services.telemetry.normalize import derive_severity

TTL_MIN = int(os.getenv("ANALYSIS_SHELL_TTL_MIN", "20"))
HARD_MAX_MIN = int(os.getenv("ANALYSIS_SHELL_HARD_MAX_MIN", "60"))
MAX_SESSIONS = int(os.getenv("ANALYSIS_SHELL_MAX_SESSIONS", "8"))
_START_TIMEOUT = 20

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|[\x00-\x08\x0b-\x1f\x7f]")
# `ss -tunH` line: "tcp ESTAB 0 0 172.19.0.5:44210 185.99.1.7:80"
_SS_PEER_RE = re.compile(r"\s(\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]+\]):(\d+)\s*$")
_PRIVATE_RE = re.compile(r"^(?:10\.|127\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|::1|fe80:)")


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _clean_command(raw: str) -> str:
    txt = _ANSI_RE.sub("", raw or "").strip()
    txt = txt.replace("\r", "").replace("\n", " ")
    return txt[:2000]


def source_tag(owner: str) -> str:
    return f"analyst-shell:{owner}"


# ── synthetic telemetry ───────────────────────────────────────────────────
async def _emit_event(
    db: AsyncSession,
    session: AnalysisSession,
    *,
    sensor_event_type: str,
    command: str,
    dst_ip: Optional[str] = None,
    dst_port: Optional[int] = None,
) -> None:
    session.seq = (session.seq or 0) + 1
    tag = session.source_tag
    ts = _now()
    event_id = hashlib.sha256(
        f"shell:{session.session_id}:{session.seq}:{command}".encode()
    ).hexdigest()

    severity = derive_severity(sensor_event_type, None, command if "command" in sensor_event_type else None)
    meta = {
        "analysis_session": session.session_id,
        "kind": "analysis-shell",
        "owner": session.owner,
    }

    db.add(NormalizedEventModel(
        event_id=event_id,
        timestamp=ts,
        ingested_at=ts,
        sensor="analysis-shell",
        sensor_event_type=sensor_event_type,
        source_ip=tag,
        destination_ip=dst_ip,
        destination_port=dst_port or 0,
        protocol="shell",
        command=command,
        severity=severity,
        raw_event=command,
        event_metadata=meta,
        session_id=session.session_id,
    ))
    db.add(RawEventModel(
        id=event_id,
        timestamp=ts,
        attacker_ip=tag,
        target_port=dst_port or 0,
        protocol="shell",
        honeypot_type="AnalysisShell",
        session_id=session.session_id,
        event_type=sensor_event_type,
        commands=command,
        risk_score=SEVERITY_RISK_SCORE.get(severity, 10.0),
        raw_payload=command,
        sync_status="LOCAL",
        signature=event_id,
    ))
    try:
        event_bus.publish_many([{
            "event_id": event_id, "timestamp": ts.isoformat(), "sensor": "analysis-shell",
            "sensor_event_type": sensor_event_type, "source_ip": tag, "command": command,
            "severity": severity, "destination_ip": dst_ip, "destination_port": dst_port,
        }])
    except Exception:
        pass


# ── session lifecycle ─────────────────────────────────────────────────────
async def start_session(db: AsyncSession, owner: str) -> AnalysisSession:
    # one active session per user
    existing = (await db.execute(
        select(AnalysisSession).where(
            AnalysisSession.owner == owner,
            AnalysisSession.status.in_(("starting", "running")),
        )
    )).scalars().all()
    for s in existing:
        await _teardown(db, s, reason="replaced by a new session")

    live = (await db.execute(
        select(func.count(AnalysisSession.id)).where(AnalysisSession.status == "running")
    )).scalar() or 0
    if live >= MAX_SESSIONS:
        raise RuntimeError(f"too many active analysis sessions ({live}/{MAX_SESSIONS}) — try again later")

    if not container_manager.available():
        raise RuntimeError("Docker is not reachable from the backend")

    import uuid
    session_id = uuid.uuid4().hex
    session = AnalysisSession(
        session_id=session_id,
        owner=owner,
        source_tag=source_tag(owner),
        status="starting",
        ttl_minutes=TTL_MIN,
        started_at=_now(),
        last_activity_at=_now(),
    )
    db.add(session)
    await db.flush()

    try:
        container = await _run_in_thread(container_manager.run_analysis_container, session_id, owner)
    except container_manager.ContainerPolicyError as exc:
        session.status = "error"
        await db.commit()
        raise RuntimeError(f"sandbox blocked by policy: {exc}")
    except Exception as exc:  # noqa: BLE001
        session.status = "error"
        await db.commit()
        msg = str(exc).lower()
        if "no such image" in msg or "not found" in msg:
            raise RuntimeError("analysis-shell image missing — run: make analysis-image")
        raise RuntimeError(f"failed to start sandbox: {exc}")

    session.container_name = container.name
    deadline = time.time() + _START_TIMEOUT
    while time.time() < deadline:
        try:
            container.reload()
            if container.status == "running":
                break
        except Exception:
            pass
        await _sleep(0.5)
    session.status = "running" if container.status == "running" else "error"
    await db.commit()
    return session


async def get_session(db: AsyncSession, session_id: str, owner: Optional[str] = None) -> Optional[AnalysisSession]:
    q = select(AnalysisSession).where(AnalysisSession.session_id == session_id)
    if owner:
        q = q.where(AnalysisSession.owner == owner)
    return (await db.execute(q)).scalars().first()


async def stop_session(db: AsyncSession, session_id: str, owner: Optional[str] = None) -> bool:
    s = await get_session(db, session_id, owner)
    if not s:
        return False
    await _teardown(db, s, reason="stopped by analyst")
    await db.commit()
    return True


async def _teardown(db: AsyncSession, s: AnalysisSession, reason: str = "") -> None:
    try:
        c = await _run_in_thread(container_manager.find_session_container, s.session_id)
        if c is not None:
            await _run_in_thread(container_manager.stop_and_remove_managed, c)
    except Exception:
        pass
    s.status = "stopped"
    s.stopped_at = _now()


async def record_command(db: AsyncSession, session: AnalysisSession, raw_line: str) -> Optional[str]:
    cmd = _clean_command(raw_line)
    if not cmd or cmd in (":", "clear", "exit"):
        return None
    await _emit_event(db, session, sensor_event_type="shell.command.input", command=cmd)
    session.command_count = (session.command_count or 0) + 1
    session.last_activity_at = _now()
    await _link_incident(db, session)
    await db.commit()
    return cmd


async def poll_connections(db: AsyncSession, session: AnalysisSession, seen: set) -> int:
    c = await _run_in_thread(container_manager.find_session_container, session.session_id)
    if c is None:
        return 0
    try:
        code, out = await _run_in_thread(
            container_manager.exec_in_managed, c, ["ss", "-tunH"]
        )
    except Exception:
        return 0
    text = out.decode("utf-8", "replace") if isinstance(out, (bytes, bytearray)) else str(out)
    new = 0
    for line in text.splitlines():
        m = _SS_PEER_RE.search(line.rstrip())
        if not m:
            continue
        ip = m.group(1).strip("[]")
        port = int(m.group(2))
        key = f"{ip}:{port}"
        if key in seen or ip.startswith(("0.0.0.0", "127.0.0.1")):
            continue
        seen.add(key)
        label = "connect" if _PRIVATE_RE.match(ip) else "connect (external)"
        await _emit_event(
            db, session,
            sensor_event_type="shell.connection.attempt",
            command=f"{label} {ip}:{port}",
            dst_ip=ip, dst_port=port,
        )
        session.connection_count = (session.connection_count or 0) + 1
        session.last_activity_at = _now()
        new += 1
    if new:
        await _link_incident(db, session)
        await db.commit()
    return new


async def _link_incident(db: AsyncSession, session: AnalysisSession) -> None:
    if session.incident_id:
        return
    inc = (await db.execute(
        select(Incident).where(Incident.correlation_key == session.source_tag)
        .order_by(Incident.created_at.desc())
    )).scalars().first()
    if inc:
        session.incident_id = inc.id


async def reap_stale(db: Optional[AsyncSession] = None) -> Dict[str, Any]:
    if db is None:
        async with AsyncSessionLocal() as s:
            return await reap_stale(s)
    now = _now()
    rows = (await db.execute(
        select(AnalysisSession).where(AnalysisSession.status.in_(("starting", "running")))
    )).scalars().all()
    reaped = 0
    for s in rows:
        idle = now - (s.last_activity_at or s.started_at)
        age = now - (s.started_at or now)
        if idle > timedelta(minutes=s.ttl_minutes or TTL_MIN) or age > timedelta(minutes=HARD_MAX_MIN):
            await _teardown(db, s, reason="idle/expired")
            reaped += 1
    if reaped:
        await db.commit()
    return {"reaped": reaped, "active": len(rows) - reaped}


# ── tiny async shims (keep the module import-light) ────────────────────────
async def _run_in_thread(fn, *args):
    import asyncio
    return await asyncio.to_thread(fn, *args)


async def _sleep(secs: float):
    import asyncio
    await asyncio.sleep(secs)
