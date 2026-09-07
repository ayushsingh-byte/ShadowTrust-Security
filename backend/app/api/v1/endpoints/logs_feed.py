"""
Unified Logs feed — one categorised stream over every log source:

  honeypot   normalized_events (attacker telemetry)
  splunk     recent events from the ~/splunk-lab Splunk (via the splunk proxy)
  platform   `docker logs` for the stack containers + errors/warnings
  audit      AccessLog + AdminActivity DB tables  (admins only)

Each line is tagged by app.services.log_categorizer (category · severity · reason).
Mounted at /api/v1/logs alongside the honeypot-ingest route in logs.py.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import get_current_active_user
from app.db.database import get_db
from app.models.all_models import AccessLog, AdminActivity, NormalizedEventModel, User
from app.services.log_categorizer import categorize, severity_rank

router = APIRouter()

_ADMIN_ROLES = {"ADMIN", "SUPER_ADMIN"}
_PLATFORM_CONTAINERS = (
    "honeynet_backend", "honeynet_frontend", "honeynet_db", "honeynet_phpmyadmin",
    "honeynet_mobsf", "honeynet_clamav", "honeynet_cowrie", "honeynet_dionaea",
    "honeynet_honeytrap", "guacamole", "guacd", "guacamole_db", "splunk",
)
_ALL_SOURCES = ("honeypot", "splunk", "platform", "audit")
_HARD_CAP = 800


def _iso(dt) -> Optional[str]:
    if not dt:
        return None
    if isinstance(dt, str):
        return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _item(ts, source: str, origin: str, text: str, ref: Optional[str] = None) -> Dict[str, Any]:
    cat = categorize(text, source)
    return {
        "ts": _iso(ts),
        "source": source,
        "origin": origin,
        "text": (text or "").strip()[:1000],
        "category": cat["category"],
        "severity": cat["severity"],
        "reason": cat["reason"],
        "ref": ref,
    }


async def _honeypot_items(db: AsyncSession, limit: int, since: datetime) -> List[Dict[str, Any]]:
    rows = (
        await db.execute(
            select(NormalizedEventModel)
            .where(NormalizedEventModel.timestamp >= since)
            .order_by(desc(NormalizedEventModel.timestamp))
            .limit(limit)
        )
    ).scalars().all()
    out = []
    for e in rows:
        bits = [e.sensor_event_type or "event", f"src={e.source_ip}"]
        if e.destination_port:
            bits.append(f"dst_port={e.destination_port}")
        if e.username:
            bits.append(f"user={e.username}")
        if e.command:
            bits.append(f"cmd={e.command}")
        if e.authentication_result:
            bits.append(f"auth={e.authentication_result}")
        out.append(_item(e.timestamp, "honeypot", e.sensor or "sensor", " ".join(bits), ref=e.event_id))
    return out


async def _splunk_items(limit: int) -> List[Dict[str, Any]]:
    try:
        from app.api.v1.endpoints.splunk import _run_search
    except Exception:
        return []
    res = await _run_search(
        f"search index=* | sort - _time | head {min(limit, 300)} | table _time host source sourcetype _raw",
        earliest="-30d",
    )
    if not res.get("reachable"):
        return []
    out = []
    for r in res.get("rows", []):
        raw = r.get("_raw") or ""
        origin = r.get("sourcetype") or r.get("source") or "splunk"
        out.append(_item(r.get("_time"), "splunk", str(origin), raw, ref=r.get("source")))
    return out


def _platform_items_sync(limit_per: int) -> List[Dict[str, Any]]:
    try:
        import docker  # type: ignore

        client = docker.from_env()
    except Exception:
        return []
    out: List[Dict[str, Any]] = []
    names = set(_PLATFORM_CONTAINERS)
    for c in client.containers.list(all=True):
        labels = c.labels or {}
        is_lab = labels.get("shadowtrust.managed") == "true"
        if c.name not in names and not is_lab:
            continue
        try:
            raw = c.logs(tail=limit_per, timestamps=True).decode("utf-8", "replace")
        except Exception:
            continue
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            ts, _, msg = line.partition(" ")
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                dt, msg = None, line
            out.append(_item(dt, "platform", c.name, msg or line))
    # container chatter is high-volume and always "now" — keep it from burying
    # the honeypot / splunk / audit signal in the merged feed.
    out.sort(key=lambda i: (i["ts"] or ""), reverse=True)
    return out[:250]


async def _audit_items(db: AsyncSession, limit: int) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        acc = (
            await db.execute(select(AccessLog).order_by(desc(AccessLog.timestamp)).limit(limit))
        ).scalars().all()
        for a in acc:
            out.append(_item(
                a.timestamp, "audit", "access-control",
                f"{a.action or 'ACTION'} admin={a.admin_id} target={a.target_user_id} {a.details or ''}",
                ref=a.id,
            ))
    except Exception:
        pass
    try:
        adm = (
            await db.execute(select(AdminActivity).order_by(desc(AdminActivity.timestamp)).limit(limit))
        ).scalars().all()
        for a in adm:
            out.append(_item(
                a.timestamp, "audit", "admin-activity",
                f"{a.action or 'ACTION'} by={a.admin_username} affected={a.affected_user} "
                f"result={a.result} ip={a.ip_address} {a.details or ''}",
                ref=a.id,
            ))
    except Exception:
        pass
    return out


@router.get("/feed")
async def logs_feed(
    sources: str = Query("honeypot,splunk,platform,audit"),
    category: Optional[str] = None,
    severity: Optional[str] = None,
    q: Optional[str] = None,
    limit: int = Query(300, le=_HARD_CAP),
    hours: int = Query(72, le=24 * 30),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    wanted = {s.strip() for s in sources.split(",") if s.strip()} or set(_ALL_SOURCES)
    is_admin = (user.role or "") in _ADMIN_ROLES
    if not is_admin:
        wanted -= {"platform", "audit"}

    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    per = min(limit, 250)

    tasks = []
    if "honeypot" in wanted:
        tasks.append(_honeypot_items(db, per, since))
    if "splunk" in wanted:
        tasks.append(_splunk_items(per))
    if "audit" in wanted:
        tasks.append(_audit_items(db, per))
    gathered = await asyncio.gather(*tasks, return_exceptions=True) if tasks else []

    items: List[Dict[str, Any]] = []
    for g in gathered:
        if isinstance(g, list):
            items.extend(g)

    if "platform" in wanted:
        try:
            plat = await asyncio.to_thread(_platform_items_sync, 40)
        except Exception:
            plat = []
        # container chatter is constant and always "now" — if other sources are
        # in play, give platform only a slice of the budget so it can't bury them.
        if items and len(wanted) > 1:
            plat = plat[: max(60, limit // 4)]
        items.extend(plat)

    # filters
    if category:
        cats = {c.strip().lower() for c in category.split(",")}
        items = [i for i in items if i["category"] in cats]
    if severity:
        floor = severity_rank(severity.upper())
        items = [i for i in items if severity_rank(i["severity"]) >= floor]
    if q:
        ql = q.lower()
        items = [i for i in items if ql in i["text"].lower() or ql in i["origin"].lower()]

    items.sort(key=lambda i: (i["ts"] or ""), reverse=True)
    items = items[:limit]

    return {
        "items": items,
        "count": len(items),
        "sources": sorted(wanted),
        "is_admin": is_admin,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/summary")
async def logs_summary(
    hours: int = Query(72, le=24 * 30),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    data = await logs_feed(
        sources="honeypot,splunk,platform,audit",
        limit=_HARD_CAP, hours=hours, db=db, user=user,
    )
    by_cat: Dict[str, int] = {}
    by_sev: Dict[str, int] = {}
    by_src: Dict[str, int] = {}
    for i in data["items"]:
        by_cat[i["category"]] = by_cat.get(i["category"], 0) + 1
        by_sev[i["severity"]] = by_sev.get(i["severity"], 0) + 1
        by_src[i["source"]] = by_src.get(i["source"], 0) + 1
    return {
        "total": data["count"],
        "by_category": dict(sorted(by_cat.items(), key=lambda kv: -kv[1])),
        "by_severity": by_sev,
        "by_source": by_src,
        "is_admin": data["is_admin"],
    }
