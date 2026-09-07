"""
Session engine
==============
Correlates raw honeypot events into coherent AttackerSession records: events
from the same source IP within SESSION_TIMEOUT_MINUTES of each other form one
session. Runs every 60s from main.py. Fully real — it reads raw_events and
writes session_id back plus an upserted attacker_sessions row.
"""
from datetime import datetime, timedelta

from sqlalchemy import select, update

from app.db.database import AsyncSessionLocal
from app.models.all_models import RawEventModel, AttackerSession


def _risk_level(max_score: float) -> str:
    if max_score >= 80:
        return "CRITICAL"
    if max_score >= 50:
        return "HIGH"
    if max_score >= 20:
        return "MEDIUM"
    return "LOW"


class SessionEngine:
    SESSION_TIMEOUT_MINUTES = 30

    @staticmethod
    async def process_unmapped_events():
        gap = timedelta(minutes=SessionEngine.SESSION_TIMEOUT_MINUTES)
        async with AsyncSessionLocal() as db:
            rows = (await db.execute(
                select(RawEventModel)
                .where(RawEventModel.session_id.is_(None))
                .where(RawEventModel.attacker_ip.isnot(None))
                .order_by(RawEventModel.attacker_ip, RawEventModel.timestamp)
                .limit(1000)
            )).scalars().all()
            if not rows:
                return

            by_ip: dict[str, list] = {}
            for evt in rows:
                by_ip.setdefault(evt.attacker_ip, []).append(evt)

            mapped = 0
            for ip, events in by_ip.items():
                events.sort(key=lambda e: e.timestamp or datetime.min)

                # continue the IP's most recent existing session if it is still open
                last_sess = (await db.execute(
                    select(AttackerSession)
                    .where(AttackerSession.attacker_ip == ip)
                    .order_by(AttackerSession.last_seen.desc())
                    .limit(1)
                )).scalars().first()

                current = None
                if last_sess and last_sess.last_seen:
                    ls = last_sess.last_seen.replace(tzinfo=None)
                    if events[0].timestamp and (events[0].timestamp - ls) <= gap:
                        current = last_sess

                for evt in events:
                    ts = evt.timestamp or datetime.utcnow()
                    if current is None or (
                        current.last_seen and (ts - current.last_seen.replace(tzinfo=None)) > gap
                    ):
                        sid = f"{ip}-{int(ts.timestamp())}"
                        geo = (evt.geoip_data or {}).get("country") if isinstance(evt.geoip_data, dict) else None
                        current = AttackerSession(
                            session_id=sid, attacker_ip=ip,
                            first_seen=ts, last_seen=ts,
                            risk_level=_risk_level(evt.risk_score or 0),
                            total_events=0, geoip_country=geo,
                        )
                        db.add(current)
                        await db.flush()

                    evt.session_id = current.session_id
                    current.last_seen = ts
                    current.total_events = (current.total_events or 0) + 1
                    current.risk_level = _risk_level(
                        max(evt.risk_score or 0,
                            {"LOW": 0, "MEDIUM": 20, "HIGH": 50, "CRITICAL": 80}.get(current.risk_level, 0))
                    )
                    mapped += 1

            await db.commit()
            if mapped:
                print(f"[SessionEngine] mapped {mapped} events into sessions across {len(by_ip)} IPs")
