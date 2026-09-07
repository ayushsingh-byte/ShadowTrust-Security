"""
Analysis Lab API (analysis_lab.html).

  POST /analysis-shell/start            spawn a disposable egress-free sandbox
  WS   /analysis-shell/{id}/pty?token=  interactive terminal; input is parsed for
                                        commands and fed to the behaviour pipeline
  GET  /analysis-shell/{id}             status + recent commands / connections
  GET  /analysis-shell/sessions         the caller's sessions
  POST /analysis-shell/{id}/stop        reap now

Any authenticated user may start one session. It is time-boxed, resource-capped,
has no network egress and no Docker socket (see services/analysis_shell.py).
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, Dict, Optional

import jwt
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import get_current_active_user
from app.core.config import settings
from app.db.database import AsyncSessionLocal, get_db
from app.models.all_models import AnalysisSession, NormalizedEventModel, User
from app.services import analysis_shell, container_manager

router = APIRouter()


def _public(s: AnalysisSession) -> Dict[str, Any]:
    return {
        "session_id": s.session_id,
        "owner": s.owner,
        "source_tag": s.source_tag,
        "container": s.container_name,
        "status": s.status,
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "last_activity_at": s.last_activity_at.isoformat() if s.last_activity_at else None,
        "command_count": s.command_count,
        "connection_count": s.connection_count,
        "ttl_minutes": s.ttl_minutes,
        "incident_id": s.incident_id,
    }


@router.post("/start")
async def start(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_active_user)):
    try:
        session = await analysis_shell.start_session(db, user.email)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return {"status": "started", "session": _public(session)}


@router.get("/sessions")
async def my_sessions(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_active_user)):
    rows = (await db.execute(
        select(AnalysisSession).where(AnalysisSession.owner == user.email)
        .order_by(desc(AnalysisSession.started_at)).limit(20)
    )).scalars().all()
    return {"sessions": [_public(r) for r in rows]}


@router.get("/{session_id}")
async def session_detail(session_id: str, db: AsyncSession = Depends(get_db),
                         user: User = Depends(get_current_active_user)):
    s = await analysis_shell.get_session(db, session_id, owner=user.email)
    if not s:
        raise HTTPException(status_code=404, detail="session not found")
    if not s.incident_id:
        await analysis_shell._link_incident(db, s)
        await db.commit()
    events = (await db.execute(
        select(NormalizedEventModel)
        .where(NormalizedEventModel.source_ip == s.source_tag,
               NormalizedEventModel.session_id == s.session_id)
        .order_by(desc(NormalizedEventModel.timestamp)).limit(60)
    )).scalars().all()
    return {
        **_public(s),
        "recent": [{
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "type": e.sensor_event_type, "command": e.command,
            "severity": e.severity,
            "destination": f"{e.destination_ip}:{e.destination_port}" if e.destination_ip else None,
        } for e in events],
    }


@router.post("/{session_id}/stop")
async def stop(session_id: str, db: AsyncSession = Depends(get_db),
               user: User = Depends(get_current_active_user)):
    ok = await analysis_shell.stop_session(db, session_id, owner=user.email)
    if not ok:
        raise HTTPException(status_code=404, detail="session not found")
    return {"status": "stopped"}


# ── WebSocket PTY ─────────────────────────────────────────────────────────
async def _user_from_token(token: str, db: AsyncSession) -> Optional[User]:
    if not token:
        return None
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email = payload.get("sub")
    except jwt.PyJWTError:
        return None
    if not email:
        return None
    u = (await db.execute(select(User).where(User.email == email))).scalars().first()
    return u if (u and u.status == "ACTIVE") else None


@router.websocket("/{session_id}/pty")
async def pty(websocket: WebSocket, session_id: str, token: str = ""):
    await websocket.accept()

    async with AsyncSessionLocal() as db:
        user = await _user_from_token(token, db)
        if user is None:
            await websocket.close(code=4401)
            return
        session = await analysis_shell.get_session(db, session_id, owner=user.email)
        if not session or session.status != "running":
            await websocket.close(code=4404)
            return

        container = await asyncio.to_thread(container_manager.find_session_container, session_id)
        if container is None:
            await websocket.close(code=4404)
            return
        try:
            _rc, raw = await asyncio.to_thread(container_manager.attach_shell, container)
        except container_manager.ContainerPolicyError:
            await websocket.close(code=4403)
            return
        sock = getattr(raw, "_sock", raw)
        sock.settimeout(1.0)

        await websocket.send_text("\r\n\x1b[38;5;79mShadow Trust analysis sandbox — no network egress, session is recorded.\x1b[0m\r\n")

        input_buf = ""
        stop = asyncio.Event()

        async def pump_out():
            try:
                while not stop.is_set():
                    try:
                        chunk = await asyncio.to_thread(sock.recv, 4096)
                    except (TimeoutError, OSError):
                        continue
                    if not chunk:
                        break
                    await websocket.send_bytes(chunk)
            except Exception:
                pass
            finally:
                stop.set()

        async def pump_in():
            nonlocal input_buf
            try:
                while not stop.is_set():
                    data = await websocket.receive_bytes()
                    await asyncio.to_thread(sock.sendall, data)
                    # passive command capture: echo the keystrokes, split on Enter
                    text = data.decode("utf-8", "replace")
                    for ch in text:
                        if ch in ("\r", "\n"):
                            line, input_buf = input_buf, ""
                            if line.strip():
                                async with AsyncSessionLocal() as db2:
                                    s2 = await analysis_shell.get_session(db2, session_id)
                                    if s2:
                                        await analysis_shell.record_command(db2, s2, line)
                        elif ch in ("\x7f", "\b"):
                            input_buf = input_buf[:-1]
                        elif ch == "\x03":       # Ctrl-C — drop the buffer
                            input_buf = ""
                        elif ch.isprintable():
                            input_buf += ch
                            if len(input_buf) > 4000:
                                input_buf = input_buf[-4000:]
            except WebSocketDisconnect:
                pass
            except Exception:
                pass
            finally:
                stop.set()

        try:
            await asyncio.gather(pump_out(), pump_in())
        finally:
            try:
                sock.close()
            except Exception:
                pass
            try:
                await websocket.close()
            except Exception:
                pass
