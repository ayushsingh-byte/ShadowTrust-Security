import asyncio
import boto3
from botocore.config import Config as BotoConfig
import json
import uuid
import logging
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Set, Tuple
from collections import deque
from sqlalchemy.future import select
from sqlalchemy import update

from app.db.sqlite_db import AsyncSessionLocal
from app.models.all_models import SystemConfig, RawEventModel, S3SyncState

logger = logging.getLogger(__name__)

# Timeout applied to every boto3 client — prevents pipeline hanging on network issues
_BOTO_CFG = BotoConfig(
    connect_timeout=8,
    read_timeout=20,
    retries={"max_attempts": 1},
)


def _pipeline_s3_fetch(
    aws_ak: str, aws_sk: str, aws_region: str, s3_bucket: str,
    processed_state_by_key: dict
) -> Tuple[List[dict], Set[str]]:
    """
    Synchronous S3 list + download. Runs in thread pool via asyncio.to_thread()
    so it NEVER blocks the FastAPI / asyncio event loop.
    Returns (list of raw event dicts, set of touched S3 keys).
    """
    session = boto3.Session(
        aws_access_key_id=aws_ak,
        aws_secret_access_key=aws_sk,
        region_name=aws_region
    )
    s3 = session.client('s3', config=_BOTO_CFG)

    paginator = s3.get_paginator('list_objects_v2')
    all_files: list = []
    for page in paginator.paginate(Bucket=s3_bucket):
        if 'Contents' in page:
            all_files.extend(page['Contents'])

    if not all_files:
        return [], set()

    files = sorted(all_files, key=lambda x: x['LastModified'], reverse=True)
    candidate_files = []
    for f in files:
        key = f['Key']
        processed_at = processed_state_by_key.get(key)
        if processed_at is None:
            candidate_files.append(f)
            continue
        last_modified = f.get('LastModified')
        try:
            # Normalize to naive UTC for comparison — processed_at is stored as naive UTC,
            # but boto3 LastModified is timezone-aware. Stripping tzinfo makes comparison safe.
            lm = last_modified.replace(tzinfo=None) if (last_modified and last_modified.tzinfo) else last_modified
            if lm and lm > processed_at:
                candidate_files.append(f)
        except Exception:
            candidate_files.append(f)

    parsed_events: List[dict] = []
    touched_keys: Set[str] = set()

    for obj in candidate_files[:250]:
        key = obj['Key']
        if not key.endswith('.json') and not key.endswith('.log'):
            continue
        try:
            file_obj = s3.get_object(Bucket=s3_bucket, Key=key)
            content = file_obj['Body'].read().decode('utf-8', errors='ignore')
            touched_keys.add(key)
        except Exception as fetch_err:
            logger.warning(f"Could not fetch s3://{s3_bucket}/{key}: {fetch_err}")
            continue

        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                if isinstance(event, dict):
                    parsed_events.append(event)
            except Exception:
                continue

    return parsed_events, touched_keys


class UnifiedTelemetryService:
    def __init__(self):
        self.is_running = False
        self.processed_s3_keys: Set[str] = set()
        
        # In-memory FAST cache for dashboard endpoints
        self.recent_events_cache: deque = deque(maxlen=5000)
        
        # Deduplication cache
        self.recent_signatures: deque = deque(maxlen=1000)
        
        # Connection state
        self.aws_ak = None
        self.aws_sk = None
        self.aws_region = None
        self.s3_bucket = None

    async def get_config(self, db):
        result = await db.execute(select(SystemConfig))
        configs = result.scalars().all()
        config_map = {c.key: c.value for c in configs}
        
        self.aws_ak = config_map.get('aws_access_key')
        self.aws_sk = config_map.get('aws_secret_key')
        self.aws_region = config_map.get('aws_region', 'ap-south-1')
        self.s3_bucket = config_map.get('s3_bucket_3rd') or config_map.get('s3_bucket')

    def ml_categorize_attack(self, target_port: int, src_ip: str) -> str:
        """
        Lightweight Heuristic ML Categorization Layer
        """
        if target_port in [2222, 8022]:
            return "SSH_BRUTE_FORCE"
        elif target_port == 8023:
            return "TELNET_LOGIN_ATTEMPT"
        elif target_port in [445, 3306, 5060, 1433, 21]:
            return "MALWARE_PROBE"
        elif target_port == 0:
            return "UNKNOWN_ACTIVITY"
        else:
            return "PORT_SCAN"

    def identify_honeypot(self, target_port: int) -> str:
        if target_port == 2222: return "Cowrie"
        if target_port in [8022, 8023, 5900]: return "Honeytrap"
        if target_port in [445, 3306, 5060, 1433, 21, 80]: return "Dionaea"
        return "Unknown"

    async def run_pipeline(self):
        self.is_running = True
        logger.info("Starting Autonomous S3 Telemetry Pipeline...")

        while self.is_running:
            try:
                async with AsyncSessionLocal() as db:
                    await self.get_config(db)

                    if not self.aws_ak or not self.aws_sk or not self.s3_bucket:
                        logger.debug("S3 Poller sleeping: Missing AWS Credentials in SystemConfig.")
                        await asyncio.sleep(30)
                        continue

                    # Load already-processed file keys (async DB read)
                    processed_query = await db.execute(select(S3SyncState.file_key, S3SyncState.processed_at))
                    processed_state_by_key = {row.file_key: row.processed_at for row in processed_query}

                    # ── Run ALL blocking S3 work in a thread — keeps event loop free ──
                    try:
                        raw_events, touched_keys = await asyncio.to_thread(
                            _pipeline_s3_fetch,
                            self.aws_ak, self.aws_sk, self.aws_region,
                            self.s3_bucket, processed_state_by_key
                        )
                    except Exception as s3_err:
                        logger.error(f"S3 fetch failed: {s3_err}")
                        await asyncio.sleep(30)
                        continue

                    if not raw_events and not touched_keys:
                        await asyncio.sleep(30)
                        continue

                    # ── Parse events in async context (fast CPU work, no I/O) ─────────
                    for key in touched_keys:
                        self.processed_s3_keys.add(key)

                    db_events = []
                    for event in raw_events:
                        try:
                            timestamp_raw = event.get("timestamp", datetime.utcnow().isoformat())
                            try:
                                dt = datetime.fromisoformat(str(timestamp_raw).replace('Z', '+00:00'))
                                # Store as naive UTC for DB consistency
                                dt = dt.replace(tzinfo=None)
                            except Exception:
                                dt = datetime.utcnow()

                            src_ip = event.get("src_ip", event.get("peerIP", "0.0.0.0"))

                            port_raw = event.get("dst_port", event.get("dest_port", event.get("hostPort", 0)))
                            try:
                                target_port = int(port_raw) if port_raw else 0
                            except (ValueError, TypeError):
                                target_port = 0

                            event_type_raw = str(event.get("eventid", event.get("event", "connection")))
                            sensor_type = str(event.get("sensor", event.get("system", ""))).lower()

                            if "heartbeat" in event_type_raw.lower() or "heartbeat" in str(event.get("events", "")).lower():
                                continue

                            # Regex parse Dionaea plain-text connection strings
                            if "dionaea" in sensor_type or "dionaea" in event_type_raw.lower():
                                match = re.search(r'\[[0-9\.]+:(\d+)->([0-9\.]+):\d+\]', event_type_raw)
                                if match:
                                    target_port = target_port if target_port != 0 else int(match.group(1))
                                    src_ip = src_ip if src_ip != "0.0.0.0" else match.group(2)
                                if target_port == 0:
                                    target_port = 445
                            elif "honeytrap" in sensor_type or "honeytrap" in event_type_raw.lower():
                                if target_port == 0:
                                    target_port = 8022
                            elif "cowrie" in sensor_type or "cowrie" in event_type_raw.lower() or event.get("protocol") == "ssh":
                                if target_port == 0:
                                    target_port = 2222

                            if src_ip == "0.0.0.0":
                                continue

                            signature = f"{src_ip}:{target_port}:{dt.isoformat()}"
                            if signature in self.recent_signatures:
                                continue
                            self.recent_signatures.append(signature)

                            if "cowrie" in event_type_raw.lower() or "cowrie" in sensor_type:
                                honeypot_type = "Cowrie"
                            elif "dionaea" in event_type_raw.lower() or "dionaea" in sensor_type:
                                honeypot_type = "Dionaea"
                            elif "honeytrap" in event_type_raw.lower() or "honeytrap" in sensor_type:
                                honeypot_type = "Honeytrap"
                            else:
                                honeypot_type = event.get("system", self.identify_honeypot(target_port))

                            ml_category = self.ml_categorize_attack(target_port, src_ip)
                            evt_id = str(uuid.uuid4())

                            self.recent_events_cache.appendleft({
                                "id": evt_id,
                                "timestamp": dt.isoformat(),
                                "source_ip": src_ip,
                                "target_port": target_port,
                                "honeypot_type": honeypot_type,
                                "ml_category": ml_category,
                                "event_type": event_type_raw,
                            })

                            db_events.append(RawEventModel(
                                id=evt_id,
                                timestamp=dt,
                                attacker_ip=src_ip,
                                target_port=target_port,
                                protocol=event.get("protocol", "tcp"),
                                honeypot_type=honeypot_type,
                                session_id=event.get("session", str(uuid.uuid4())),
                                event_type=ml_category,
                                raw_payload=json.dumps(event),
                                sync_status="SYNCED",
                                signature=signature,
                            ))
                        except Exception:
                            continue

                    # ── Async DB writes ───────────────────────────────────────────────
                    if db_events or touched_keys:
                        now_utc = datetime.utcnow()
                        for key in touched_keys:
                            if key in processed_state_by_key:
                                await db.execute(
                                    update(S3SyncState)
                                    .where(S3SyncState.file_key == key)
                                    .values(processed_at=now_utc)
                                )
                            else:
                                db.add(S3SyncState(file_key=key, processed_at=now_utc))

                        if db_events:
                            db.add_all(db_events)

                        try:
                            await db.commit()
                            logger.info(f"Ingested {len(db_events)} AWS S3 events from {len(touched_keys)} files.")
                        except Exception:
                            await db.rollback()
                            # Fallback: insert one by one to skip duplicate signatures
                            for ev in db_events:
                                db.add(ev)
                                try:
                                    await db.commit()
                                except Exception:
                                    await db.rollback()

            except Exception as e:
                logger.error(f"S3 Telemetry Pipeline Error: {str(e)}")
                await asyncio.sleep(30)

            # Poll every 30 seconds to reduce background load.
            await asyncio.sleep(30)

telemetry_engine = UnifiedTelemetryService()
