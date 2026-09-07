from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
import os
import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

# Timeout applied to every boto3 client — prevents buttons hanging forever
_BOTO_CFG = BotoConfig(
    connect_timeout=8,
    read_timeout=20,
    retries={"max_attempts": 1},
)
import logging
import json
import uuid
import re
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy import update

from app.db.database import get_db
from app.models.all_models import RawEventModel, SystemConfig, S3SyncState
from app.services.aws_telemetry_service import telemetry_engine

logger = logging.getLogger(__name__)

router = APIRouter()

class AWSTestRequest(BaseModel):
    aws_access_key: str
    aws_secret_key: str
    aws_region: Optional[str] = "ap-south-1"

class AWSDebugRequest(AWSTestRequest):
    s3_bucket: Optional[str] = None
    iam_profile: Optional[str] = None

class AWSS3PullRequest(AWSTestRequest):
    s3_bucket_3rd: str
    force_repull: bool = False  # if True, re-process files already in S3SyncState


async def _load_saved_aws_config(db: AsyncSession) -> Dict[str, str]:
    """Load persisted AWS config values from SystemConfig as a lightweight fallback."""
    result = await db.execute(
        select(SystemConfig).where(
            SystemConfig.key.in_(["aws_access_key", "aws_secret_key", "aws_region", "s3_bucket", "s3_bucket_3rd"])
        )
    )
    rows = result.scalars().all()
    return {row.key: (row.value or "") for row in rows}

class ConfigSaveRequest(BaseModel):
    aws_access_key: str
    aws_secret_key: str
    aws_region: str
    s3_bucket: str
    s3_bucket_3rd: Optional[str] = None
    subnet_id: Optional[str] = None
    security_group_id: Optional[str] = None
    iam_profile: Optional[str] = None
    ami_win_base: Optional[str] = None
    ami_kali_base: Optional[str] = None
    ami_win_mal: Optional[str] = None

@router.post("/config", response_model=Dict[str, str])
async def save_aws_config(request: ConfigSaveRequest, db: AsyncSession = Depends(get_db)):
    config_dict = request.dict()
    from sqlalchemy.future import select
    for key, value in config_dict.items():
        if value is not None:
            # Check if exists
            result = await db.execute(select(SystemConfig).where(SystemConfig.key == key))
            db_config = result.scalars().first()
            if db_config:
                db_config.value = str(value)
            else:
                db.add(SystemConfig(key=key, value=str(value)))
    
    await db.commit()
    return {"status": "success", "message": "Configuration saved to backend vault."}

@router.post("/test", response_model=Dict[str, Any])
async def test_aws_connection(request: AWSTestRequest):
    """
    Validates AWS Credentials by executing an STS GetCallerIdentity API call.
    Returns the associated Account ID and IAM ARN if successful.
    """
    # Reject obvious placeholder keys up front rather than waiting on an STS timeout.
    if "EXAMPLE" in request.aws_access_key or not request.aws_access_key.strip():
        raise HTTPException(status_code=400, detail=(
            "Placeholder AWS credentials. Enter a real access key / secret for an IAM "
            "principal with sts:GetCallerIdentity permission."))

    import asyncio

    def _sts_call():
        sts_client = boto3.client(
            'sts',
            region_name=request.aws_region,
            aws_access_key_id=request.aws_access_key,
            aws_secret_access_key=request.aws_secret_key,
            config=_BOTO_CFG,
        )
        return sts_client.get_caller_identity()

    try:
        # Run the blocking STS call in a thread so the event loop stays free
        response = await asyncio.to_thread(_sts_call)

        return {
            "status": "success",
            "message": "AWS Connection Established",
            "account": response.get("Account"),
            "arn": response.get("Arn")
        }

    except ClientError as e:
        logger.warning(f"AWS Validation Failed: {e}")
        error_code = e.response.get('Error', {}).get('Code', '')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        
        if error_code == 'RequestTimeTooSkewed':
            raise HTTPException(status_code=400, detail=(
                "AWS rejected the request: the host clock is skewed from AWS time. "
                "Fix the system clock (NTP) and retry."))
        raise HTTPException(status_code=400, detail=f"AWS credential check failed [{error_code}]: {error_message}")
    except Exception as e:
        logger.error(f"Unexpected AWS error: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error during AWS validation.")


@router.post("/debug", response_model=Dict[str, Any])
async def full_aws_diagnostic(request: AWSDebugRequest):
    """
    Executes a comprehensive battery of tests against the AWS environment.
    Tests: 1. STS Identify, 2. EC2 Describe access, 3. S3 Bucket access, 4. IAM Profile Validation.
    All blocking boto3 calls run in a thread so the event loop stays free.
    """
    import asyncio

    def _run_diagnostics():
        results = []
        try:
            session = boto3.Session(
                aws_access_key_id=request.aws_access_key,
                aws_secret_access_key=request.aws_secret_key,
                region_name=request.aws_region
            )
        except Exception as e:
            return {"status": "error", "message": f"Failed to initialize Boto3 session: {str(e)}", "results": results}

        # Test 1: STS
        try:
            sts = session.client('sts', config=_BOTO_CFG)
            sts_res = sts.get_caller_identity()
            results.append({"name": "STS Authentication", "status": "PASS", "info": f"Account: {sts_res.get('Account')}"})
        except Exception as e:
            results.append({"name": "STS Authentication", "status": "FAIL", "info": str(e)})
            return {"status": "failed", "results": results}

        # Test 2: EC2 Access
        try:
            ec2 = session.client('ec2', config=_BOTO_CFG)
            ec2.describe_instances(MaxResults=5)
            results.append({"name": "EC2 Describe Access", "status": "PASS", "info": "Can read EC2 inventory"})
        except Exception as e:
            results.append({"name": "EC2 Describe Access", "status": "FAIL", "info": str(e)})

        # Test 3: S3 Bucket Access
        if request.s3_bucket:
            try:
                s3 = session.client('s3', config=_BOTO_CFG)
                s3.head_bucket(Bucket=request.s3_bucket)
                results.append({"name": f"S3 Access ({request.s3_bucket})", "status": "PASS", "info": "Bucket found and accessible"})
            except Exception as e:
                results.append({"name": f"S3 Access ({request.s3_bucket})", "status": "FAIL", "info": str(e)})

        # Test 4: IAM Instance Profile Validation
        if request.iam_profile:
            try:
                iam = session.client('iam', config=_BOTO_CFG)
                iam.get_instance_profile(InstanceProfileName=request.iam_profile)
                results.append({"name": f"IAM Profile ({request.iam_profile})", "status": "PASS", "info": "Profile exists and is accessible"})
            except Exception as e:
                results.append({"name": f"IAM Profile ({request.iam_profile})", "status": "FAIL", "info": str(e)})

        overall_status = "error" if any(r["status"] == "FAIL" for r in results) else "success"
        return {"status": overall_status, "results": results, "region": request.aws_region}

    return await asyncio.to_thread(_run_diagnostics)

# Only skip true binary/non-log file types.
# Removed: .csv, .yml, .yaml, .log, .md, .rst, .py, .sh
# — honeypots commonly export logs in these formats.
_SKIP_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico',
    '.zip', '.tar', '.gz', '.bz2', '.tgz',
    '.pdf', '.docx', '.xlsx', '.mp4', '.mp3', '.exe', '.bin',
}

def _extract_src_ip(event: dict) -> str:
    """
    Extracts the attacker source IP from a honeypot event dict.
    Handles Cowrie (src_ip), Dionaea (peerIP / src_ip),
    Honeytrap (source.host / src.host), and generic fallbacks.
    """
    # Direct flat fields
    for field in ("src_ip", "peerIP", "remote_host", "remote_ip",
                  "attacker", "host", "ip", "client_ip", "sourceIP"):
        val = event.get(field)
        if val and val not in ("0.0.0.0", "::"):
            return str(val)

    # Nested Honeytrap-style: {"source": {"host": "..."}} or {"src": {"host": "..."}}
    for nested_key in ("source", "src", "origin", "peer"):
        nested = event.get(nested_key)
        if isinstance(nested, dict):
            for sub in ("host", "ip", "addr", "address"):
                val = nested.get(sub)
                if val and val not in ("0.0.0.0", "::"):
                    return str(val)

    return "0.0.0.0"


_ML_RISK_MAP = {
    "MALWARE_PROBE": 90.0,
    "SSH_BRUTE_FORCE": 85.0,
    "TELNET_LOGIN_ATTEMPT": 75.0,
    "PORT_SCAN": 40.0,
    "UNKNOWN_ACTIVITY": 20.0,
}


def _s3_fetch_and_parse(request: "AWSS3PullRequest", processed_state_by_key: Dict[str, datetime]):
    """
    Synchronous S3 list + download + parse.  Runs in a thread-pool executor so
    it never blocks the FastAPI / asyncio event loop.  Returns plain Python
    lists of ORM model instances ready to be bulk-inserted.
    """
    boto_session = boto3.Session(
        aws_access_key_id=request.aws_access_key,
        aws_secret_access_key=request.aws_secret_key,
        region_name=request.aws_region,
    )
    s3 = boto_session.client('s3', config=_BOTO_CFG)
    bucket_name = request.s3_bucket_3rd

    # List all objects in the bucket
    paginator = s3.get_paginator('list_objects_v2')
    all_files: list = []
    for page in paginator.paginate(Bucket=bucket_name):
        all_files.extend(page.get('Contents', []))

    if not all_files:
        return [], [], 0, 0

    files = sorted(all_files, key=lambda x: x['LastModified'], reverse=True)
    if request.force_repull:
        candidate_files = files
    else:
        candidate_files = []
        for obj in files:
            key = obj['Key']
            processed_at = processed_state_by_key.get(key)
            if processed_at is None:
                candidate_files.append(obj)
                continue

            last_modified = obj.get('LastModified')
            try:
                # Normalize to naive UTC — processed_at is naive UTC, boto3 LastModified is
                # timezone-aware UTC. Stripping tzinfo makes the comparison safe and avoids
                # a TypeError that would silently re-process all files every cycle.
                lm = last_modified.replace(tzinfo=None) if (last_modified and last_modified.tzinfo) else last_modified
                if lm and lm > processed_at:
                    candidate_files.append(obj)
            except Exception:
                # Fallback: process to avoid missing fresh data.
                candidate_files.append(obj)

    logs_processed = 0
    skipped_files  = 0
    db_events: list = []
    touched_keys = set()

    for obj in candidate_files[:1000]:
        key = obj['Key']

        if key.endswith('/'):
            continue

        _, ext = os.path.splitext(key.split('/')[-1].lower())
        if ext in _SKIP_EXTENSIONS:
            continue

        try:
            file_obj = s3.get_object(Bucket=bucket_name, Key=key)
            content  = file_obj['Body'].read().decode('utf-8', errors='ignore')
            touched_keys.add(key)
            telemetry_engine.processed_s3_keys.add(key)
        except Exception as fetch_err:
            logger.warning(f"Could not fetch s3://{bucket_name}/{key}: {fetch_err}")
            skipped_files += 1
            continue

        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except Exception:
                continue

            if not isinstance(event, dict):
                continue

            # ── Timestamp ────────────────────────────────────────────────
            timestamp_raw = event.get("timestamp", datetime.utcnow().isoformat())
            try:
                dt = datetime.fromisoformat(str(timestamp_raw).replace('Z', '+00:00'))
            except (ValueError, TypeError):
                dt = datetime.utcnow()

            src_ip = _extract_src_ip(event)

            # ── Destination port ─────────────────────────────────────────
            port_raw = event.get("dst_port",
                       event.get("dest_port",
                       event.get("hostPort",
                       event.get("port", 0))))
            if not port_raw:
                dest = event.get("destination", event.get("dst", {}))
                if isinstance(dest, dict):
                    port_raw = dest.get("port", 0)
            try:
                target_port = int(port_raw) if port_raw else 0
            except (ValueError, TypeError):
                target_port = 0

            event_type_raw = str(event.get("eventid", event.get("event", "connection")))
            sensor_type    = str(event.get("sensor", event.get("system", ""))).lower()

            if "heartbeat" in event_type_raw.lower():
                continue

            # ── Sensor-specific enrichment ────────────────────────────────
            if "dionaea" in sensor_type or "dionaea" in event_type_raw.lower():
                match = re.search(r'\[[0-9\.]+:(\d+)->([0-9\.]+):\d+\]', event_type_raw)
                if match:
                    target_port = target_port or int(match.group(1))
                    if src_ip == "0.0.0.0":
                        src_ip = match.group(2)
                target_port = target_port or 445
            elif "honeytrap" in sensor_type or "honeytrap" in event_type_raw.lower():
                target_port = target_port or 8022
            elif ("cowrie" in sensor_type or "cowrie" in event_type_raw.lower()
                  or event.get("protocol") == "ssh"):
                target_port = target_port or 2222

            if src_ip == "0.0.0.0":
                continue

            signature = f"{src_ip}:{target_port}:{dt.isoformat()}"

            evt_lower = event_type_raw.lower()
            if   "cowrie"    in evt_lower or "cowrie"    in sensor_type: honeypot_type = "Cowrie"
            elif "dionaea"   in evt_lower or "dionaea"   in sensor_type: honeypot_type = "Dionaea"
            elif "honeytrap" in evt_lower or "honeytrap" in sensor_type: honeypot_type = "Honeytrap"
            else: honeypot_type = event.get("system", telemetry_engine.identify_honeypot(target_port))

            ml_category = telemetry_engine.ml_categorize_attack(target_port, src_ip)
            evt_id      = str(uuid.uuid4())
            risk_score  = _ML_RISK_MAP.get(ml_category, 30.0)

            telemetry_engine.recent_events_cache.appendleft({
                "id": evt_id, "timestamp": dt.isoformat(),
                "source_ip": src_ip, "target_port": target_port,
                "honeypot_type": honeypot_type, "ml_category": ml_category,
                "event_type": event_type_raw,
            })

            db_events.append(RawEventModel(
                id=evt_id, timestamp=dt, attacker_ip=src_ip,
                target_port=target_port, protocol=event.get("protocol", "tcp"),
                honeypot_type=honeypot_type,
                session_id=event.get("session", str(uuid.uuid4())),
                event_type=ml_category,
                commands=str(event.get("input", "")),
                raw_payload=json.dumps(event),
                risk_score=risk_score,
                sync_status="SYNCED", signature=signature,
            ))
            logs_processed += 1

    return db_events, touched_keys, logs_processed, skipped_files


@router.post("/pull-s3-logs", response_model=Dict[str, Any])
async def pull_s3_logs(request: AWSS3PullRequest, db: AsyncSession = Depends(get_db)):
    """
    Pulls honeypot telemetry logs from S3 and ingests them into the database.
    All blocking S3/boto3 operations run in a thread-pool executor so the
    FastAPI event loop stays free for other requests (e.g. /aws/test).
    """
    import asyncio

    try:
        saved_cfg = await _load_saved_aws_config(db)
        effective_request = AWSS3PullRequest(
            aws_access_key=(request.aws_access_key or saved_cfg.get("aws_access_key", "")).strip(),
            aws_secret_key=(request.aws_secret_key or saved_cfg.get("aws_secret_key", "")).strip(),
            aws_region=(request.aws_region or saved_cfg.get("aws_region", "ap-south-1")).strip() or "ap-south-1",
            s3_bucket_3rd=(request.s3_bucket_3rd or saved_cfg.get("s3_bucket_3rd") or saved_cfg.get("s3_bucket") or "").strip(),
            force_repull=request.force_repull,
        )

        if not effective_request.aws_access_key or not effective_request.aws_secret_key or not effective_request.s3_bucket_3rd:
            raise HTTPException(
                status_code=400,
                detail="Missing AWS credentials or S3 bucket. Configure AWS first in AWS Connection page.",
            )

        # Load already-processed file keys (fast async DB read)
        processed_query = await db.execute(select(S3SyncState.file_key, S3SyncState.processed_at))
        processed_state_by_key = {row.file_key: row.processed_at for row in processed_query}

        # ── Run ALL blocking S3 work in a thread — keeps event loop free ──────
        try:
            db_events, touched_keys, logs_processed, skipped_files = await asyncio.to_thread(
                _s3_fetch_and_parse, effective_request, processed_state_by_key
            )
        except ClientError as ce:
            error_message = ce.response.get('Error', {}).get('Message', str(ce))
            raise HTTPException(status_code=400, detail=f"S3 Access Error: {error_message}")

        if not touched_keys and not db_events:
            return {"status": "success", "message": "No new or updated objects found in S3 bucket.", "inserted_count": 0}

        # ── Async DB writes ───────────────────────────────────────────────────
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
        try:
            await db.commit()
        except Exception:
            await db.rollback()

        if db_events:
            try:
                db.add_all(db_events)
                await db.commit()
            except Exception:
                await db.rollback()
                for ev in db_events:
                    try:
                        db.add(ev)
                        await db.commit()
                    except Exception:
                        await db.rollback()

        logger.info(f"S3 pull complete: {logs_processed} events ingested, {skipped_files} files skipped.")
        return {
            "status": "success",
            "message": f"Successfully ingested {logs_processed} events from {len(touched_keys)} files.",
            "inserted_count": logs_processed,
            "files_scanned": len(touched_keys),
            "files_skipped": skipped_files,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected S3 pull error: {e}")
        raise HTTPException(status_code=500, detail=f"Internal Server Error during S3 pull: {e}")
