from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from datetime import datetime, timedelta

from app.db.database import get_db
from app.models.all_models import RawEventModel
from app.ai_engine.gnn_profiler import TemporalGNNProfiler

router = APIRouter()

@router.get("/profile")
async def get_behavior_profile(
    session: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Fetches the latest chronological events and instantiates the Temporal GNN algorithmic model
    to synthesize behavioral threats, MITRE mappings, and graph network nodes.

    ``?session=<id>`` scopes the profile to one Analysis Lab sandbox session — used
    by analysis_lab.html for the live per-session flow. Without it, the global view.
    """
    # Grab the last 200 chronological events (within 30 days of the latest event)
    latest_res = await db.execute(select(RawEventModel.timestamp).order_by(desc(RawEventModel.timestamp)).limit(1))
    latest_ts = latest_res.scalar()
    now = latest_ts if latest_ts else datetime.utcnow()
    thirty_days_ago = now - timedelta(days=30)

    query = (
        select(RawEventModel)
        .where(RawEventModel.timestamp >= thirty_days_ago)
        .order_by(desc(RawEventModel.timestamp))
        .limit(300 if session else 200)
    )
    if session:
        query = query.where(RawEventModel.session_id == session)
    result = await db.execute(query)
    # Reverse to process chronologically oldest to newest in the profiler window
    recent_events = sorted(result.scalars().all(), key=lambda x: x.timestamp)
    
    profiler = TemporalGNNProfiler(recent_events)
    profiler.construct_temporal_graph()
    profile_data = profiler.analyze_behavior()
    
    return profile_data


@router.get("/stix")
async def export_stix_bundle(db: AsyncSession = Depends(get_db)):
    """
    Real STIX 2.1 bundle built from observed indicators + detections.

    Sources: ioc_observations (deduped indicators from telemetry), detections
    (attack-pattern + relationship objects). No placeholder objects.
    """
    import uuid as _uuid
    from app.models.all_models import IOCObservation, Detection

    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    objects = []

    identity_id = f"identity--{_uuid.uuid4()}"
    objects.append({
        "type": "identity", "spec_version": "2.1", "id": identity_id,
        "created": now, "modified": now,
        "name": "ShadowTrust Defense Grid", "identity_class": "system",
    })

    iocs = (await db.execute(select(IOCObservation).order_by(desc(IOCObservation.last_seen)).limit(500))).scalars().all()
    stix_type = {"ip": "ipv4-addr", "domain": "domain-name", "url": "url",
                 "sha256": "file:hashes.'SHA-256'", "md5": "file:hashes.MD5",
                 "sha1": "file:hashes.'SHA-1'", "username": "user-account:account_login"}
    for o in iocs:
        patt_field = stix_type.get(o.type)
        if not patt_field:
            continue
        val = str(o.value).replace("'", "\\'")
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": f"indicator--{_uuid.uuid4()}",
            "created_by_ref": identity_id,
            "created": (o.first_seen or datetime.utcnow()).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "modified": (o.last_seen or datetime.utcnow()).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "name": f"{o.type} observed on honeypot: {o.value}",
            "indicator_types": ["malicious-activity"],
            "pattern_type": "stix",
            "pattern": f"[{patt_field} = '{val}']",
            "valid_from": (o.first_seen or datetime.utcnow()).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "labels": [f"source:{o.source}", f"hits:{o.hit_count}"],
        })

    dets = (await db.execute(select(Detection).where(Detection.attack_technique.isnot(None))
            .order_by(desc(Detection.created_at)).limit(200))).scalars().all()
    seen_tech = {}
    for d in dets:
        tid = d.attack_technique
        if tid not in seen_tech:
            ap_id = f"attack-pattern--{_uuid.uuid4()}"
            seen_tech[tid] = ap_id
            objects.append({
                "type": "attack-pattern", "spec_version": "2.1", "id": ap_id,
                "created": now, "modified": now,
                "name": d.rule_name, "created_by_ref": identity_id,
                "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
            })

    bundle = {"type": "bundle", "id": f"bundle--{_uuid.uuid4()}", "objects": objects}
    return {
        "bundle": bundle,
        "counts": {"indicators": len(iocs), "attack_patterns": len(seen_tech), "objects": len(objects)},
    }
