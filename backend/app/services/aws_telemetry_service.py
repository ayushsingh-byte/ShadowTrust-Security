import asyncio
import boto3
import json
import uuid
import logging
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Set
from collections import deque
from sqlalchemy.future import select

from app.db.sqlite_db import AsyncSessionLocal
from app.models.all_models import SystemConfig, RawEventModel, S3SyncState

logger = logging.getLogger(__name__)

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
        self.s3_bucket = config_map.get('s3_bucket')

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
                        await asyncio.sleep(10)
                        continue
                        
                    # Initialize boto3 synchronously inside the loop for simplicity (could wrap in executor block)
                    session = boto3.Session(
                        aws_access_key_id=self.aws_ak,
                        aws_secret_access_key=self.aws_sk,
                        region_name=self.aws_region
                    )
                    s3 = session.client('s3')
                    
                    processed_query = await db.execute(select(S3SyncState.file_key))
                    processed_db_keys = set(processed_query.scalars().all())
                    
                    paginator = s3.get_paginator('list_objects_v2')
                    page_iterator = paginator.paginate(Bucket=self.s3_bucket)
                    
                    all_files = []
                    for page in page_iterator:
                        if 'Contents' in page:
                            all_files.extend(page['Contents'])
                    
                    if not all_files:
                        await asyncio.sleep(10)
                        continue
                        
                    db_events = []
                    db_states = []
                    
                    files = sorted(all_files, key=lambda x: x['LastModified'], reverse=True)
                    unprocessed_files = [f for f in files if f['Key'] not in processed_db_keys]
                    
                    for obj in unprocessed_files[:250]:
                        key = obj['Key']
                        
                        if not key.endswith('.json') and not key.endswith('.log'):
                            continue
                            
                        db_states.append(S3SyncState(file_key=key))
                        self.processed_s3_keys.add(key)
                        
                        # Download Object
                        file_obj = s3.get_object(Bucket=self.s3_bucket, Key=key)
                        content = file_obj['Body'].read().decode('utf-8', errors='ignore')
                        
                        for line in content.splitlines():
                            if not line.strip(): continue
                            try:
                                event = json.loads(line)
                                
                                # Extract structured fields
                                timestamp_raw = event.get("timestamp", datetime.utcnow().isoformat())
                                try:
                                    # handle typical ISO bounds
                                    dt = datetime.fromisoformat(timestamp_raw.replace('Z', '+00:00'))
                                except:
                                    dt = datetime.utcnow()
                                    
                                src_ip = event.get("src_ip", event.get("peerIP", "0.0.0.0"))
                                
                                port_raw = event.get("dst_port", event.get("dest_port", event.get("hostPort", 0)))
                                try:
                                    target_port = int(port_raw) if port_raw else 0
                                except ValueError:
                                    target_port = 0
                                    
                                event_type_raw = event.get("eventid", event.get("event", "connection"))
                                sensor_type = event.get("sensor", event.get("system", "")).lower()
                                
                                # Skip non-attack logs like Honeytrap internal heartbeats
                                if "heartbeat" in event_type_raw.lower() or "heartbeat" in str(event.get("events", "")).lower():
                                    continue
                                    
                                # Regex parse Dionaea plain-text connection strings
                                if "dionaea" in sensor_type or "dionaea" in event_type_raw.lower():
                                    match = re.search(r'\[[0-9\.]+:(\d+)->([0-9\.]+):\d+\]', event_type_raw)
                                    if match:
                                        target_port = target_port if target_port != 0 else int(match.group(1))
                                        src_ip = src_ip if src_ip != "0.0.0.0" else match.group(2)
                                    if target_port == 0:
                                        target_port = 445 # native dionaea fallback
                                        
                                # Honeytrap fallback
                                elif "honeytrap" in sensor_type or "honeytrap" in event_type_raw.lower():
                                    if target_port == 0:
                                        target_port = 8022
                                        
                                # Cowrie fallback
                                elif "cowrie" in sensor_type or "cowrie" in event_type_raw.lower() or event.get("protocol") == "ssh":
                                    if target_port == 0:
                                        target_port = 2222
                                        
                                # If it's literally just a debug string or 0.0.0.0, drop it securely
                                if src_ip == "0.0.0.0":
                                    continue
                                    
                                # Deduplication logic
                                signature = f"{src_ip}:{target_port}:{dt.isoformat()}"
                                if signature in self.recent_signatures:
                                    continue
                                self.recent_signatures.append(signature)

                                event_type = event_type_raw
                                if "cowrie" in event_type.lower():
                                    honeypot_type = "Cowrie"
                                elif "dionaea" in event_type.lower():
                                    honeypot_type = "Dionaea"
                                elif "honeytrap" in event_type.lower():
                                    honeypot_type = "Honeytrap"
                                else:
                                    honeypot_type = event.get("system", self.identify_honeypot(target_port))

                                ml_category = self.ml_categorize_attack(target_port, src_ip)
                                
                                evt_id = str(uuid.uuid4())
                                
                                # In-Memory Cache object for fast Dashboard APIs
                                cache_obj = {
                                    "id": evt_id,
                                    "timestamp": dt.isoformat(),
                                    "source_ip": src_ip,
                                    "target_port": target_port,
                                    "honeypot_type": honeypot_type,
                                    "ml_category": ml_category,
                                    "event_type": event_type,
                                }
                                self.recent_events_cache.appendleft(cache_obj)
                                
                                # SQLite Persistent DB object
                                new_event = RawEventModel(
                                    id=evt_id,
                                    timestamp=dt,
                                    attacker_ip=src_ip,
                                    target_port=target_port,
                                    protocol=event.get("protocol", "tcp"),
                                    honeypot_type=honeypot_type,
                                    session_id=event.get("session", str(uuid.uuid4())),
                                    event_type=ml_category,  # Overriding event_type with category for dashboard visibility
                                    raw_payload=json.dumps(event),
                                    sync_status="SYNCED",
                                    signature=signature
                                )
                                db_events.append(new_event)
                                
                            except Exception as parse_e:
                                # Skip malformed JSON
                                pass
                                
                    if db_events or db_states:
                        for event in db_events:
                            db.add(event)
                            try:
                                await db.commit()
                            except Exception:
                                await db.rollback()
                                
                        for state in db_states:
                            db.add(state)
                            try:
                                await db.commit()
                            except Exception:
                                await db.rollback()
                        logger.info(f"Ingested {len(db_events)} AWS S3 mapped events.")
                        
            except Exception as e:
                logger.error(f"S3 Telemetry Pipeline Error: {str(e)}")
                
            # Poll every 10 seconds
            await asyncio.sleep(10)

telemetry_engine = UnifiedTelemetryService()
