"""
Detection + Correlation engine (tasks 1 · 3 · part of 7).

Runs as a background loop (``main.py`` lifespan, every DETECTION_ENGINE_INTERVAL
seconds). Extends — never replaces — the existing per-event risk scoring:

    normalized_events
      -> IOC extraction        (ioc_observations, dedup by type+value)
      -> detection rules       (detections rows: rule, matched events, reason,
                                confidence, severity, ATT&CK)
      -> correlation           (group by source_ip within a rolling window;
                                every link carries an explainable reason)
      -> incident create/update (incidents + incident_events + incident_iocs
                                + incident_activity; risk_breakdown explains
                                "why this severity")
      -> attacker_sessions     (finally populated, feeds the timeline)

Idempotent: a cursor in ``system_config['detection_cursor']`` plus a unique
``detections.dedupe_key`` mean re-processing the same events creates nothing new.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import AsyncSessionLocal
from app.models.all_models import (
    AttackerSession,
    Detection,
    Incident,
    IncidentActivity,
    IncidentEvent,
    IncidentIOC,
    IOCObservation,
    NormalizedEventModel,
    SystemConfig,
)
from app.services.detection_rules import (
    DetectionRule,
    load_rules,
    severity_rank,
)
from app.services.telemetry.collector import SEVERITY_RISK_SCORE

_CURSOR_KEY = "detection_cursor"
_INCIDENT_WINDOW = timedelta(hours=6)      # merge new activity into an open incident
_MAX_LOOKBACK = timedelta(hours=2)         # widest rule window we support
_OPEN_STATUSES = ("NEW", "TRIAGING", "INVESTIGATING", "CONTAINED")

_URL_RE = re.compile(r"https?://[^\s'\"<>|)]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
_SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
_SHA1_RE = re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)
_MD5_RE = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _as_naive(dt) -> Optional[datetime]:
    if dt is None:
        return None
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


# ── IOC extraction ─────────────────────────────────────────────────────────
def extract_iocs(event) -> List[Tuple[str, str]]:
    """Return ``[(type, value), ...]`` for one event. Deterministic, no network."""
    out: List[Tuple[str, str]] = []
    if event.source_ip and event.source_ip not in ("0.0.0.0", "127.0.0.1", "::1"):
        out.append(("ip", event.source_ip))
    if event.destination_ip and event.destination_ip not in ("0.0.0.0", "127.0.0.1"):
        out.append(("ip", event.destination_ip))
    if event.username:
        out.append(("username", str(event.username)[:120]))

    # URLs / domains: scan the command + payload + raw blob.
    url_blob = " ".join(filter(None, [event.command, event.payload, event.raw_event or ""]))[:8000]
    for m in _URL_RE.findall(url_blob):
        m = m.rstrip(".,;:)]}'\"")
        if not m:
            continue
        out.append(("url", m[:480]))
        host = re.sub(r"^https?://", "", m, flags=re.IGNORECASE).split("/")[0].split(":")[0]
        if _DOMAIN_RE.fullmatch(host or ""):
            out.append(("domain", host.lower()))

    # File hashes: ONLY from attacker-controlled command text + captured file
    # references — never the raw event blob, whose SSH kex/version material is
    # full of hex that looks like a hash but is not an IOC.
    hash_blob = " ".join(filter(None, [event.command, getattr(event, "payload", None)]))[:8000]
    for rx, kind in ((_SHA256_RE, "sha256"), (_SHA1_RE, "sha1"), (_MD5_RE, "md5")):
        for h in rx.findall(hash_blob):
            out.append((kind, h.lower()))

    # de-dupe, preserve order
    seen = set()
    uniq = []
    for pair in out:
        if pair not in seen:
            seen.add(pair)
            uniq.append(pair)
    return uniq


async def _upsert_iocs(db: AsyncSession, events: List[Any]) -> Dict[str, List[Tuple[str, str]]]:
    """Upsert observed IOCs; return ``{source_ip: [(type,value), ...]}``."""
    by_ip: Dict[str, List[Tuple[str, str]]] = {}
    pending: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for e in events:
        iocs = extract_iocs(e)
        by_ip.setdefault(e.source_ip, [])
        for pair in iocs:
            if pair not in by_ip[e.source_ip]:
                by_ip[e.source_ip].append(pair)
            slot = pending.setdefault(pair, {"event_ids": [], "sensors": set(), "ts": e.timestamp})
            slot["event_ids"].append(e.event_id)
            if e.sensor:
                slot["sensors"].add(e.sensor)
            slot["ts"] = max(slot["ts"] or e.timestamp, e.timestamp)

    for (kind, value), slot in pending.items():
        row = (await db.execute(
            select(IOCObservation).where(
                IOCObservation.type == kind, IOCObservation.value == value
            )
        )).scalars().first()
        ts = _as_naive(slot["ts"]) or _now()
        if row:
            row.last_seen = max(row.last_seen or ts, ts)
            row.hit_count = (row.hit_count or 0) + len(slot["event_ids"])
            merged = list(dict.fromkeys((row.event_ids or []) + slot["event_ids"]))[-200:]
            row.event_ids = merged
        else:
            db.add(IOCObservation(
                type=kind, value=value, first_seen=ts, last_seen=ts,
                hit_count=len(slot["event_ids"]),
                source="honeypot",
                event_ids=slot["event_ids"][:200],
                context={"sensors": sorted(slot["sensors"])},
            ))
    return by_ip


# ── Rule evaluation ────────────────────────────────────────────────────────
def _bucket(ts: datetime, timeframe: timedelta) -> int:
    step = max(int(timeframe.total_seconds()), 60)
    return int(_as_naive(ts).timestamp()) // step


def evaluate_rule(rule: DetectionRule, window_events: List[Any], since: datetime) -> List[Dict[str, Any]]:
    """
    Return candidate detections for one rule over ``window_events``.
    Only groups with at least one event newer than ``since`` are reported, so a
    stable historical burst is not re-detected every cycle.
    """
    since = _as_naive(since)
    groups: Dict[str, List[Any]] = {}
    for e in window_events:
        g = rule.group_key(e)
        if g is not None:
            groups.setdefault(g, []).append(e)

    results: List[Dict[str, Any]] = []
    horizon = _now() - rule.timeframe

    for group, evs in groups.items():
        evs.sort(key=lambda e: _as_naive(e.timestamp) or _now())
        recent = [e for e in evs if (_as_naive(e.timestamp) or _now()) >= horizon]
        if not recent:
            continue
        has_new = any((_as_naive(e.ingested_at) or _now()) > since for e in recent)
        if not has_new:
            continue

        if rule.rule_type == "sequence":
            matched = _match_sequence(rule, recent)
        else:
            hits = [e for e in recent if rule.event_matches(e, rule.conditions)]
            matched = hits if len(hits) >= rule.threshold else []

        if not matched:
            continue

        matched.sort(key=lambda e: _as_naive(e.timestamp) or _now())
        first_ts = _as_naive(matched[0].timestamp)
        last_ts = _as_naive(matched[-1].timestamp)
        username = next((m.username for m in matched if m.username), None)
        results.append({
            "rule": rule,
            "group": group,
            "matched": matched,
            "dedupe_key": f"{rule.id}:{group}:{_bucket(last_ts, rule.timeframe)}",
            "first_event_at": first_ts,
            "last_event_at": last_ts,
            "username": username,
            "reason": rule.reason_for(group, len(matched)),
        })
    return results


def _match_sequence(rule: DetectionRule, events: List[Any]) -> List[Any]:
    """Ordered-step match: every step's conditions must be satisfied by
    ``min_count`` events, each step strictly after the previous step's last hit."""
    events = sorted(events, key=lambda e: _as_naive(e.timestamp) or _now())
    idx = 0
    used: List[Any] = []
    for step in rule.steps:
        step_hits = []
        while idx < len(events) and len(step_hits) < step.min_count:
            e = events[idx]
            idx += 1
            if rule.event_matches(e, step.conditions):
                step_hits.append(e)
        if len(step_hits) < step.min_count:
            return []
        used.extend(step_hits)
    return used


# ── Incident correlation ───────────────────────────────────────────────────
def _incident_severity(detections: List[Detection], max_event_risk: float) -> str:
    ranks = [severity_rank(d.severity) for d in detections]
    if max_event_risk >= 80:
        ranks.append(4)
    elif max_event_risk >= 55:
        ranks.append(3)
    top = max(ranks) if ranks else 1
    return {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}[top]


def _incident_risk(detections: List[Detection], techniques: List[str],
                   max_event_risk: float, session_events: int,
                   malware_linked: bool) -> Tuple[float, Dict[str, Any]]:
    sev_component = max([severity_rank(d.severity) for d in detections] or [1]) * 18  # up to 72
    det_component = min(len(detections) * 6, 24)
    tech_component = min(len(set(techniques)) * 5, 20)
    event_component = min(max_event_risk * 0.15, 15)
    session_component = min(session_events * 0.2, 10)
    malware_component = 20 if malware_linked else 0
    score = min(100.0, sev_component + det_component + tech_component
                + event_component + session_component + malware_component)
    breakdown = {
        "severity_component": round(sev_component, 1),
        "detection_count": len(detections),
        "detection_component": det_component,
        "unique_techniques": len(set(techniques)),
        "technique_component": tech_component,
        "max_event_risk_score": round(max_event_risk, 1),
        "event_component": round(event_component, 1),
        "session_event_count": session_events,
        "session_component": round(session_component, 1),
        "malware_linked": malware_linked,
        "malware_component": malware_component,
        "total": round(score, 1),
    }
    return round(score, 1), breakdown


async def _next_incident_key(db: AsyncSession) -> str:
    n = (await db.execute(select(func.count(Incident.id)))).scalar() or 0
    return f"INC-{n + 1:06d}"


async def _malware_hash_linked(iocs: List[Tuple[str, str]]) -> bool:
    """True if any hash IOC has a stored analysis report under scans/."""
    import os
    hashes = [v for (t, v) in iocs if t in ("sha256", "md5", "sha1")]
    if not hashes:
        return False
    try:
        from app.api.v1.endpoints.malware import _load_full_reports
        reports = _load_full_reports()
    except Exception:
        return False
    return any(h in reports for h in hashes)


async def _correlate(
    db: AsyncSession,
    ip: str,
    new_detections: List[Detection],
    matched_events: Dict[str, Tuple[Any, str]],  # event_id -> (event, reason)
    iocs: List[Tuple[str, str]],
    max_event_risk: float,
    session_events: int,
) -> Optional[Incident]:
    if not new_detections and max_event_risk < 80:
        return None

    now = _now()
    incident = (await db.execute(
        select(Incident)
        .where(
            Incident.correlation_key == ip,
            Incident.status.in_(_OPEN_STATUSES),
            Incident.last_seen >= now - _INCIDENT_WINDOW,
        )
        .order_by(Incident.last_seen.desc())
    )).scalars().first()

    techniques = [d.attack_technique for d in new_detections if d.attack_technique]
    tech_objs = [
        {"id": d.attack_technique, "tactic": d.attack_tactic, "name": d.rule_name}
        for d in new_detections if d.attack_technique
    ]
    reasons = sorted({d.reason for d in new_detections if d.reason})
    sensors = sorted({e.sensor for (e, _r) in matched_events.values() if e.sensor})
    users = sorted({e.username for (e, _r) in matched_events.values() if e.username})
    malware_linked = await _malware_hash_linked(iocs)
    created = False

    if incident is None:
        incident = Incident(
            incident_key=await _next_incident_key(db),
            correlation_key=ip,
            title=_title_for(ip, new_detections, max_event_risk),
            status="NEW",
            first_seen=now,
            last_seen=now,
            source_ips=[ip],
            related_users=users,
            related_sensors=sensors,
            attack_techniques=tech_objs,
            detection_reasons=reasons,
            auto_created=True,
        )
        db.add(incident)
        await db.flush()
        created = True
    else:
        incident.last_seen = now
        incident.source_ips = sorted(set((incident.source_ips or []) + [ip]))
        incident.related_users = sorted(set((incident.related_users or []) + users))
        incident.related_sensors = sorted(set((incident.related_sensors or []) + sensors))
        _merge_techniques(incident, tech_objs)
        incident.detection_reasons = sorted(set((incident.detection_reasons or []) + reasons))

    # link detections
    all_incident_detections = list(new_detections)
    for d in new_detections:
        d.incident_id = incident.id
    prior = (await db.execute(
        select(Detection).where(Detection.incident_id == incident.id)
    )).scalars().all()
    all_incident_detections = list({d.id: d for d in (prior + new_detections)}.values())

    # link events (dedupe against what's already linked)
    linked = set((await db.execute(
        select(IncidentEvent.event_id).where(IncidentEvent.incident_id == incident.id)
    )).scalars().all())
    for eid, (ev, reason) in matched_events.items():
        if eid in linked:
            continue
        db.add(IncidentEvent(
            incident_id=incident.id, event_id=eid,
            source="honeypot", correlation_reason=reason,
        ))

    # link IOCs
    linked_iocs = set((await db.execute(
        select(IncidentIOC.ioc_value).where(IncidentIOC.incident_id == incident.id)
    )).scalars().all())
    for kind, value in iocs:
        if value in linked_iocs:
            continue
        db.add(IncidentIOC(incident_id=incident.id, ioc_type=kind, ioc_value=value))

    # auto-evidence for any linked malware hash that has an analysis report
    if malware_linked:
        try:
            from app.services.evidence_service import attach_malware_evidence
            for kind, value in iocs:
                if kind in ("sha256", "md5", "sha1"):
                    await attach_malware_evidence(db, incident, value)
        except Exception:
            pass

    # score
    all_techs = [t["id"] for t in (incident.attack_techniques or [])]
    incident.severity = _incident_severity(all_incident_detections, max_event_risk)
    incident.confidence = round(
        min(0.99, max([d.confidence for d in all_incident_detections] or [0.4])
            + 0.05 * (len(all_incident_detections) - 1)),
        2,
    )
    incident.risk_score, incident.risk_breakdown = _incident_risk(
        all_incident_detections, all_techs, max_event_risk, session_events, malware_linked
    )

    if created:
        db.add(IncidentActivity(
            incident_id=incident.id, actor="detection-engine", action="CREATE",
            detail=f"auto-created from {len(new_detections)} detection(s) on {ip}",
        ))
    return incident


def _title_for(ip: str, detections: List[Detection], max_event_risk: float) -> str:
    if detections:
        names = sorted({d.rule_name for d in detections})
        head = names[0] if len(names) == 1 else f"{names[0]} (+{len(names) - 1} more)"
        return f"{head} — {ip}"
    return f"High-risk activity — {ip}"


def _merge_techniques(incident: Incident, new_objs: List[Dict[str, Any]]) -> None:
    have = {t["id"] for t in (incident.attack_techniques or [])}
    merged = list(incident.attack_techniques or [])
    for obj in new_objs:
        if obj["id"] not in have:
            merged.append(obj)
            have.add(obj["id"])
    incident.attack_techniques = merged


# ── attacker_sessions ──────────────────────────────────────────────────────
async def _update_sessions(db: AsyncSession, by_ip: Dict[str, List[Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for ip, events in by_ip.items():
        if not ip:
            continue
        total = (await db.execute(
            select(func.count(NormalizedEventModel.event_id))
            .where(NormalizedEventModel.source_ip == ip)
        )).scalar() or 0
        counts[ip] = total
        first = (await db.execute(
            select(func.min(NormalizedEventModel.timestamp))
            .where(NormalizedEventModel.source_ip == ip)
        )).scalar()
        last = (await db.execute(
            select(func.max(NormalizedEventModel.timestamp))
            .where(NormalizedEventModel.source_ip == ip)
        )).scalar()
        max_risk = max([_event_risk(e) for e in events] or [0.0])
        risk_level = "HIGH" if max_risk >= 80 else "MEDIUM" if max_risk >= 40 else "LOW"

        row = (await db.execute(
            select(AttackerSession).where(AttackerSession.attacker_ip == ip)
            .order_by(AttackerSession.last_seen.desc())
        )).scalars().first()
        if row:
            row.last_seen = _as_naive(last) or row.last_seen
            row.total_events = total
            if severity_rank(risk_level) > severity_rank(row.risk_level or "LOW"):
                row.risk_level = risk_level
        else:
            db.add(AttackerSession(
                session_id=f"sess-{ip}",
                attacker_ip=ip,
                first_seen=_as_naive(first) or _now(),
                last_seen=_as_naive(last) or _now(),
                risk_level=risk_level,
                total_events=total,
            ))
    return counts


# ── The cycle ──────────────────────────────────────────────────────────────
async def run_cycle(db: Optional[AsyncSession] = None) -> Dict[str, Any]:
    if db is None:
        async with AsyncSessionLocal() as session:
            return await run_cycle(session)

    rules = load_rules()
    now = _now()

    cfg = (await db.execute(
        select(SystemConfig).where(SystemConfig.key == _CURSOR_KEY)
    )).scalars().first()
    cursor = _as_naive(cfg.value) if cfg and cfg.value else (now - timedelta(hours=1))

    new_events = (await db.execute(
        select(NormalizedEventModel)
        .where(NormalizedEventModel.ingested_at > cursor)
        .order_by(NormalizedEventModel.ingested_at.asc())
        .limit(3000)
    )).scalars().all()

    summary = {"new_events": len(new_events), "detections": 0, "incidents": 0}
    if not new_events:
        return summary

    touched_ips = {e.source_ip for e in new_events if e.source_ip}
    by_ip_new: Dict[str, List[Any]] = {}
    for e in new_events:
        by_ip_new.setdefault(e.source_ip, []).append(e)

    lookback = now - _MAX_LOOKBACK
    window_events = (await db.execute(
        select(NormalizedEventModel)
        .where(
            NormalizedEventModel.source_ip.in_(touched_ips),
            NormalizedEventModel.timestamp >= lookback,
        )
        .order_by(NormalizedEventModel.timestamp.asc())
        .limit(8000)
    )).scalars().all() if touched_ips else []

    ioc_by_ip = await _upsert_iocs(db, new_events)
    session_counts = await _update_sessions(db, by_ip_new)

    # evaluate every rule
    candidates: List[Dict[str, Any]] = []
    for rule in rules:
        candidates.extend(evaluate_rule(rule, window_events, cursor))

    existing_keys = set()
    if candidates:
        existing_keys = set((await db.execute(
            select(Detection.dedupe_key)
            .where(Detection.dedupe_key.in_([c["dedupe_key"] for c in candidates]))
        )).scalars().all())

    detections_by_ip: Dict[str, List[Detection]] = {}
    matched_by_ip: Dict[str, Dict[str, Tuple[Any, str]]] = {}

    for c in candidates:
        if c["dedupe_key"] in existing_keys:
            continue
        rule: DetectionRule = c["rule"]
        det = Detection(
            dedupe_key=c["dedupe_key"],
            rule_id=rule.id,
            rule_name=rule.name,
            rule_source="builtin",
            severity=rule.severity,
            confidence=rule.confidence,
            attack_technique=rule.technique,
            attack_tactic=rule.tactic,
            matched_event_ids=[e.event_id for e in c["matched"]][:200],
            match_conditions=rule.raw_selection,
            reason=c["reason"],
            source_ip=c["group"] if rule.group_by == "source_ip" else (c["matched"][0].source_ip if c["matched"] else None),
            username=c["username"],
            first_event_at=c["first_event_at"],
            last_event_at=c["last_event_at"],
        )
        db.add(det)
        summary["detections"] += 1
        ip = det.source_ip or c["group"]
        detections_by_ip.setdefault(ip, []).append(det)
        slot = matched_by_ip.setdefault(ip, {})
        for e in c["matched"]:
            slot[e.event_id] = (e, c["reason"])

    await db.flush()

    # correlation -> incidents
    all_ips = set(detections_by_ip) | {
        ip for ip, evs in by_ip_new.items()
        if any(_event_risk(e) >= 80 for e in evs)
    }
    for ip in all_ips:
        if not ip:
            continue
        dets = detections_by_ip.get(ip, [])
        matched = matched_by_ip.get(ip, {})
        # also pull in high-risk raw events for this ip as incident evidence
        for e in by_ip_new.get(ip, []):
            if _event_risk(e) >= 80 and e.event_id not in matched:
                matched[e.event_id] = (e, f"event risk_score {_event_risk(e):.0f} (>=80) on sensor {e.sensor}")
        max_risk = max([_event_risk(e) for e in by_ip_new.get(ip, [])] or [0.0])
        incident = await _correlate(
            db, ip, dets, matched, ioc_by_ip.get(ip, []),
            max_risk, session_counts.get(ip, 0),
        )
        if incident is not None:
            summary["incidents"] += 1

    # advance cursor
    new_cursor = max(_as_naive(e.ingested_at) or now for e in new_events)
    if cfg:
        cfg.value = new_cursor.isoformat()
    else:
        db.add(SystemConfig(key=_CURSOR_KEY, value=new_cursor.isoformat()))

    await db.commit()
    return summary


def _event_risk(event) -> float:
    """Per-event risk = the same severity->score map the rest of the app uses.
    Extends, does not replace, existing scoring."""
    return float(SEVERITY_RISK_SCORE.get(getattr(event, "severity", None), 10.0))
