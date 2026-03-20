"""
Sector Intelligence System
==========================
Manages monitored websites/IPs organised by sector (education, defence, etc.).
Each target gets a unique API key used by the JS tracking snippet.

Public endpoint  : POST /api/v1/sectors/events/ingest  (no auth — JS snippet)
Protected routes : everything else requires a valid JWT
"""

from __future__ import annotations

import uuid
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import get_current_active_user, require_clearance
from app.db.sqlite_db import get_db
from app.models.all_models import SectorEvent, SectorTarget, User

router = APIRouter()

# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

VALID_SECTORS = {
    "edu", "defence", "medicare", "commerce",
    "finance", "gov", "energy", "telecom", "transport",
}

ATTACK_COLORS = {
    "SQLi":       "#ff6b6b",
    "XSS":        "#ffd93d",
    "RCE":        "#ff4757",
    "BruteForce": "#00c6ff",
    "Scan":       "#a29bfe",
    "Other":      "#8892a4",
}

GEO_COLORS = ["#ff6b6b", "#00c6ff", "#ffd93d", "#a29bfe", "#00ff88", "#ff4757", "#74b9ff"]

IOC_ICONS = {
    "ip":     "fa-network-wired",
    "domain": "fa-globe",
    "hash":   "fa-fingerprint",
    "url":    "fa-link",
}


class TargetCreate(BaseModel):
    name: str
    url: Optional[str] = None
    ip: Optional[str] = None
    description: Optional[str] = None


class EventIngest(BaseModel):
    api_key: str
    attacker_ip: Optional[str] = None
    attack_type: Optional[str] = "Other"
    country: Optional[str] = None
    commands: Optional[List[str]] = None
    ioc_value: Optional[str] = None
    ioc_type: Optional[str] = None
    risk_score: Optional[float] = 0.0
    user_agent: Optional[str] = None
    request_path: Optional[str] = None
    raw_payload: Optional[str] = None


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _validate_sector(sector_key: str) -> str:
    key = sector_key.lower()
    if key not in VALID_SECTORS:
        raise HTTPException(status_code=404, detail=f"Unknown sector '{sector_key}'")
    return key


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("")
async def list_sectors(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Return all sectors with target count and total event count."""
    rows = await db.execute(
        select(
            SectorTarget.sector_key,
            func.count(SectorTarget.id).label("target_count"),
        )
        .where(SectorTarget.active == True)
        .group_by(SectorTarget.sector_key)
    )
    target_counts = {r.sector_key: r.target_count for r in rows}

    rows2 = await db.execute(
        select(
            SectorEvent.sector_key,
            func.count(SectorEvent.id).label("event_count"),
        ).group_by(SectorEvent.sector_key)
    )
    event_counts = {r.sector_key: r.event_count for r in rows2}

    result = []
    for key in sorted(VALID_SECTORS):
        result.append({
            "key": key,
            "targets": target_counts.get(key, 0),
            "total_events": event_counts.get(key, 0),
        })
    return result


@router.get("/{sector_key}/targets")
async def list_targets(
    sector_key: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    key = _validate_sector(sector_key)
    rows = await db.execute(
        select(SectorTarget).where(
            SectorTarget.sector_key == key,
            SectorTarget.active == True,
        )
    )
    targets = rows.scalars().all()
    return [
        {
            "id": t.id,
            "name": t.name,
            "url": t.url,
            "ip": t.ip,
            "description": t.description,
            "api_key": t.api_key,
            "added_at": t.added_at.isoformat() if t.added_at else None,
        }
        for t in targets
    ]


@router.post("/{sector_key}/targets", status_code=201)
async def add_target(
    sector_key: str,
    body: TargetCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Add a website / IP to a sector. Returns the generated API key for the JS snippet."""
    key = _validate_sector(sector_key)

    if not body.url and not body.ip:
        raise HTTPException(status_code=422, detail="Provide at least one of 'url' or 'ip'")

    target = SectorTarget(
        sector_key=key,
        name=body.name,
        url=body.url,
        ip=body.ip,
        description=body.description,
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)

    snippet_url = "http://localhost:8000/api/v1/sectors/events/ingest"
    js_snippet = (
        f'<script>\n'
        f'(function(){{\n'
        f'  var ST_KEY="{target.api_key}";\n'
        f'  var ST_URL="{snippet_url}";\n'
        f'  function stSend(t,x){{'
        f'fetch(ST_URL,{{method:"POST",headers:{{"Content-Type":"application/json"}},'
        f'body:JSON.stringify(Object.assign({{api_key:ST_KEY,attack_type:t,'
        f'user_agent:navigator.userAgent,request_path:window.location.pathname}},x||{{}}))}}).catch(function(){{}});}}\n'
        f'  var u=window.location.href;\n'
        f'  if(/<script|javascript:/i.test(u))stSend("XSS",{{ioc_value:u.slice(0,200),ioc_type:"url"}});\n'
        f'  if(/union\\s+select|select.*from|drop\\s+table/i.test(u))stSend("SQLi",{{ioc_value:u.slice(0,200),ioc_type:"url"}});\n'
        f'  window.ShadowTrust={{report:stSend}};\n'
        f'}})()\n'
        f'</script>'
    )

    return {
        "id": target.id,
        "sector_key": target.sector_key,
        "name": target.name,
        "url": target.url,
        "ip": target.ip,
        "api_key": target.api_key,
        "js_snippet": js_snippet,
        "message": "Target added. Embed the js_snippet in your site's <head> to start tracking.",
    }


@router.delete("/{sector_key}/targets/{target_id}", status_code=204)
async def remove_target(
    sector_key: str,
    target_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    key = _validate_sector(sector_key)
    row = await db.execute(
        select(SectorTarget).where(
            SectorTarget.id == target_id,
            SectorTarget.sector_key == key,
        )
    )
    target = row.scalars().first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    target.active = False
    await db.commit()


# ---------------------------------------------------------------------------
# Public ingest (called by JS snippet — no JWT required)
# ---------------------------------------------------------------------------

@router.post("/events/ingest", status_code=202)
async def ingest_event(
    body: EventIngest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Receive a security event from an embedded JS snippet."""
    row = await db.execute(
        select(SectorTarget).where(
            SectorTarget.api_key == body.api_key,
            SectorTarget.active == True,
        )
    )
    target = row.scalars().first()
    if not target:
        raise HTTPException(status_code=401, detail="Invalid API key")

    # Fall back to the request's remote address when attacker_ip is absent
    attacker_ip = body.attacker_ip or request.client.host or "0.0.0.0"

    event = SectorEvent(
        sector_key=target.sector_key,
        target_id=target.id,
        target_url=target.url or target.ip,
        attacker_ip=attacker_ip,
        country=body.country,
        attack_type=body.attack_type or "Other",
        commands=body.commands,
        ioc_value=body.ioc_value,
        ioc_type=body.ioc_type,
        risk_score=body.risk_score or 0.0,
        user_agent=body.user_agent,
        request_path=body.request_path,
        raw_payload=body.raw_payload,
    )
    db.add(event)
    await db.commit()
    return {"status": "accepted"}


# ---------------------------------------------------------------------------
# Stats (matches frontend updateDashboardUI expectations exactly)
# ---------------------------------------------------------------------------

@router.get("/{sector_key}/stats")
async def sector_stats(
    sector_key: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    key = _validate_sector(sector_key)

    rows = await db.execute(
        select(SectorEvent).where(SectorEvent.sector_key == key)
    )
    events: list[SectorEvent] = rows.scalars().all()

    total_attacks = len(events)
    unique_attackers = len({e.attacker_ip for e in events})

    # ── Top attackers ────────────────────────────────────────────────────────
    ip_counter: Counter = Counter(e.attacker_ip for e in events)
    country_map: dict[str, str] = {e.attacker_ip: (e.country or "??") for e in events}
    top_attackers = [
        {"ip": ip, "cn": country_map.get(ip, "??"), "count": cnt}
        for ip, cnt in ip_counter.most_common(5)
    ]

    # ── Geo origins ─────────────────────────────────────────────────────────
    country_counter: Counter = Counter(
        e.country or "Unknown" for e in events if e.country
    )
    total_geo = sum(country_counter.values()) or 1
    geo_origins = [
        {
            "country": country,
            "percent": round(cnt / total_geo * 100),
            "color": GEO_COLORS[i % len(GEO_COLORS)],
        }
        for i, (country, cnt) in enumerate(country_counter.most_common(6))
    ]

    # ── IOCs ─────────────────────────────────────────────────────────────────
    ioc_seen: dict[str, str] = {}
    for e in reversed(events):
        if e.ioc_value and e.ioc_value not in ioc_seen:
            ioc_seen[e.ioc_value] = e.ioc_type or "ip"
        if len(ioc_seen) >= 10:
            break
    iocs = [
        {"icon": IOC_ICONS.get(itype, "fa-exclamation-triangle"), "value": val}
        for val, itype in ioc_seen.items()
    ]

    # ── Captured commands ────────────────────────────────────────────────────
    captured_commands: list[str] = []
    seen_cmds: set[str] = set()
    for e in reversed(events):
        if e.commands:
            for cmd in (e.commands if isinstance(e.commands, list) else [e.commands]):
                if cmd not in seen_cmds:
                    seen_cmds.add(cmd)
                    captured_commands.append(cmd)
                if len(captured_commands) >= 10:
                    break
        if len(captured_commands) >= 10:
            break

    # ── Active alerts (risk_score > 6) ──────────────────────────────────────
    high_risk = [e for e in events if e.risk_score >= 7]
    active_alerts = []
    for e in sorted(high_risk, key=lambda x: x.risk_score, reverse=True)[:5]:
        sev = "high" if e.risk_score >= 8.5 else "med"
        active_alerts.append({
            "sev": sev,
            "title": f"{e.attack_type or 'Unknown'} from {e.attacker_ip}",
            "description": (
                f"Risk {e.risk_score:.1f} — "
                f"{e.target_url or 'unknown target'} "
                f"[{e.country or '??'}]"
            ),
        })

    # ── Attack breakdown (donut chart) ───────────────────────────────────────
    type_counter: Counter = Counter(e.attack_type or "Other" for e in events)
    breakdown_labels = list(type_counter.keys())
    breakdown_values = list(type_counter.values())
    breakdown_colors = [ATTACK_COLORS.get(lbl, "#8892a4") for lbl in breakdown_labels]

    # ── Timeline — last 24 h, 1 h buckets ────────────────────────────────────
    now = datetime.utcnow()
    buckets: dict[str, int] = defaultdict(int)
    for h in range(23, -1, -1):
        label = (now - timedelta(hours=h)).strftime("%H:00")
        buckets[label] = 0
    for e in events:
        if e.timestamp and e.timestamp >= now - timedelta(hours=24):
            label = e.timestamp.strftime("%H:00")
            buckets[label] += 1
    timeline_labels = list(buckets.keys())
    timeline_values = list(buckets.values())

    return {
        "attacks": total_attacks,
        "attackers": unique_attackers,
        "top_attackers": top_attackers,
        "geo_origins": geo_origins,
        "iocs": iocs,
        "captured_commands": captured_commands,
        "active_alerts": active_alerts,
        "attack_breakdown": {
            "labels": breakdown_labels,
            "values": breakdown_values,
            "colors": breakdown_colors,
        },
        "timeline": {
            "labels": timeline_labels,
            "values": timeline_values,
            "label": "Attacks/Hour",
        },
    }
