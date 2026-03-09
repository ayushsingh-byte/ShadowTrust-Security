from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
import boto3
from botocore.exceptions import ClientError
import logging
import json
import uuid
import re
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.sqlite_db import get_db
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
    try:
        # Instantiate a temporary STS client with the provided credentials
        sts_client = boto3.client(
            'sts',
            region_name=request.aws_region,
            aws_access_key_id=request.aws_access_key,
            aws_secret_access_key=request.aws_secret_key
        )
        
        # Call STS to verify identity
        response = sts_client.get_caller_identity()
        
        return {
            "status": "success",
            "message": "AWS Connection Established",
            "account": response.get("Account"),
            "arn": response.get("Arn")
        }
        
    except ClientError as e:
        logger.warning(f"AWS Validation Failed: {e}")
        # Extract the specific AWS Error Message
        error_message = e.response.get('Error', {}).get('Message', str(e))
        raise HTTPException(status_code=400, detail=f"AWS Invalid/Unauthorized: {error_message}")
        
    except Exception as e:
        logger.error(f"Unexpected AWS error: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error during AWS validation.")


@router.post("/debug", response_model=Dict[str, Any])
async def full_aws_diagnostic(request: AWSDebugRequest):
    """
    Executes a comprehensive battery of tests against the AWS environment.
    Tests: 1. STS Identify, 2. EC2 Describe access, 3. S3 Bucket access, 4. IAM Profile Validation.
    Returns a unified diagnostic report.
    """
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
        sts = session.client('sts')
        sts_res = sts.get_caller_identity()
        results.append({"name": "STS Authentication", "status": "PASS", "info": f"Account: {sts_res.get('Account')}"})
    except Exception as e:
        results.append({"name": "STS Authentication", "status": "FAIL", "info": str(e)})
        return {"status": "failed", "results": results} # Stop here if auth fails entirely

    # Test 2: EC2 Access
    try:
        ec2 = session.client('ec2')
        ec2.describe_instances(MaxResults=5)
        results.append({"name": "EC2 Describe Access", "status": "PASS", "info": "Can read EC2 inventory"})
    except Exception as e:
        results.append({"name": "EC2 Describe Access", "status": "FAIL", "info": str(e)})

    # Test 3: S3 Bucket Access
    if request.s3_bucket:
        try:
            s3 = session.client('s3')
            s3.head_bucket(Bucket=request.s3_bucket)
            results.append({"name": f"S3 Access ({request.s3_bucket})", "status": "PASS", "info": "Bucket found and accessible"})
        except Exception as e:
            results.append({"name": f"S3 Access ({request.s3_bucket})", "status": "FAIL", "info": str(e)})

    # Test 4: IAM Instance Profile Validation
    if request.iam_profile:
        try:
            iam = session.client('iam')
            iam.get_instance_profile(InstanceProfileName=request.iam_profile)
            results.append({"name": f"IAM Profile ({request.iam_profile})", "status": "PASS", "info": "Profile exists and is accessible"})
        except Exception as e:
            results.append({"name": f"IAM Profile ({request.iam_profile})", "status": "FAIL", "info": str(e)})

    # Determine overall status
    overall_status = "error" if any(r["status"] == "FAIL" for r in results) else "success"
    
    return {
        "status": overall_status,
        "results": results,
        "region": request.aws_region
    }

@router.post("/pull-s3-logs", response_model=Dict[str, Any])
async def pull_s3_logs(request: AWSS3PullRequest, db: AsyncSession = Depends(get_db)):
    """
    Pulls logs from the 3rd EC2 S3 bucket and ingests them into SQLite.
    Expected logs are typically Cowrie/Dionaea JSON events.
    """
    try:
        session = boto3.Session(
            aws_access_key_id=request.aws_access_key,
            aws_secret_access_key=request.aws_secret_key,
            region_name=request.aws_region
        )
        s3 = session.client('s3')
        bucket_name = request.s3_bucket_3rd
        
        processed_query = await db.execute(select(S3SyncState.file_key))
        processed_db_keys = set(processed_query.scalars().all())
        
        paginator = s3.get_paginator('list_objects_v2')
        page_iterator = paginator.paginate(Bucket=bucket_name)
        
        all_files = []
        for page in page_iterator:
            if 'Contents' in page:
                all_files.extend(page['Contents'])
                
        if not all_files:
            return {"status": "success", "message": "No logs found in S3 bucket.", "inserted_count": 0}
            
        logs_processed = 0
        db_events = []
        db_states = []
        
        files = sorted(all_files, key=lambda x: x['LastModified'], reverse=True)
        unprocessed_files = [f for f in files if f['Key'] not in processed_db_keys]
        
        for obj in unprocessed_files[:1000]:
            key = obj['Key']
            if not key.endswith('.json') and not key.endswith('.log'):
                continue
                
            db_states.append(S3SyncState(file_key=key))
            telemetry_engine.processed_s3_keys.add(key)
                
            # Get the object
            file_obj = s3.get_object(Bucket=bucket_name, Key=key)
            content = file_obj['Body'].read().decode('utf-8', errors='ignore')
            
            # Simple line-by-line JSON parsing
            for line in content.splitlines():
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    
                    timestamp_raw = event.get("timestamp", datetime.utcnow().isoformat())
                    try:
                        dt = datetime.fromisoformat(timestamp_raw.replace('Z', '+00:00'))
                    except ValueError:
                        dt = datetime.utcnow()
                        
                    src_ip = event.get("src_ip", event.get("peerIP", "0.0.0.0"))
                    
                    port_raw = event.get("dst_port", event.get("dest_port", event.get("hostPort", 0)))
                    try:
                        target_port = int(port_raw) if port_raw else 0
                    except ValueError:
                        target_port = 0
                        
                    event_type_raw = event.get("eventid", event.get("event", "connection"))
                    sensor_type = event.get("sensor", event.get("system", "")).lower()
                    
                    if "heartbeat" in event_type_raw.lower() or "heartbeat" in str(event.get("events", "")).lower():
                        continue
                        
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
                    if signature in telemetry_engine.recent_signatures:
                        continue
                    telemetry_engine.recent_signatures.append(signature)

                    event_type = event_type_raw
                    if "cowrie" in event_type.lower():
                        honeypot_type = "Cowrie"
                    elif "dionaea" in event_type.lower():
                        honeypot_type = "Dionaea"
                    elif "honeytrap" in event_type.lower():
                        honeypot_type = "Honeytrap"
                    else:
                        honeypot_type = event.get("system", telemetry_engine.identify_honeypot(target_port))

                    ml_category = telemetry_engine.ml_categorize_attack(target_port, src_ip)
                    
                    evt_id = str(uuid.uuid4())
                    
                    cache_obj = {
                        "id": evt_id,
                        "timestamp": dt.isoformat(),
                        "source_ip": src_ip,
                        "target_port": target_port,
                        "honeypot_type": honeypot_type,
                        "ml_category": ml_category,
                        "event_type": event_type,
                    }
                    telemetry_engine.recent_events_cache.appendleft(cache_obj)

                    new_event = RawEventModel(
                        id=evt_id,
                        timestamp=dt,
                        attacker_ip=src_ip,
                        target_port=target_port,
                        protocol=event.get("protocol", "tcp"),
                        honeypot_type=honeypot_type,
                        session_id=event.get("session", str(uuid.uuid4())),
                        event_type=ml_category,
                        commands=str(event.get("input", "")),
                        raw_payload=json.dumps(event),
                        sync_status="SYNCED",
                        signature=signature
                    )
                    db_events.append(new_event)
                    logs_processed += 1
                except Exception:
                    pass # Skip malformed lines
        
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
            
        return {"status": "success", "message": f"Successfully pulled and ingested {logs_processed} events.", "inserted_count": logs_processed}
        
    except ClientError as e:
        logger.error(f"S3 Pull Failed: {e}")
        error_message = e.response.get('Error', {}).get('Message', str(e))
        raise HTTPException(status_code=400, detail=f"S3 Access Error: {error_message}")
    except Exception as e:
        logger.error(f"Unexpected S3 pull error: {e}")
        raise HTTPException(status_code=500, detail=f"Internal Server Error during S3 pull: {e}")
