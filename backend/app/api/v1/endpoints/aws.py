from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
import boto3
from botocore.exceptions import ClientError
import logging
import json
import uuid
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.sqlite_db import get_db
from app.models.all_models import RawEventModel

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
        
        # List objects in the bucket
        response = s3.list_objects_v2(Bucket=bucket_name)
        if 'Contents' not in response:
            return {"status": "success", "message": "No logs found in S3 bucket.", "inserted_count": 0}
            
        logs_processed = 0
        db_events = []
        
        for obj in response['Contents']:
            key = obj['Key']
            # Only process json or log files, skip folders
            if not key.endswith('.json') and not key.endswith('.log'):
                continue
                
            # Get the object
            file_obj = s3.get_object(Bucket=bucket_name, Key=key)
            content = file_obj['Body'].read().decode('utf-8', errors='ignore')
            
            # Simple line-by-line JSON parsing
            for line in content.splitlines():
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    evt_id = str(uuid.uuid4())
                    
                    
                    # Convert port values safely
                    target_port = 0
                    try:
                        port_raw = event.get("dest_port", event.get("hostPort", 0))
                        target_port = int(port_raw) if port_raw else 0
                    except ValueError:
                        target_port = 0

                    new_event = RawEventModel(
                        id=evt_id,
                        timestamp=datetime.utcnow(),
                        attacker_ip=event.get("src_ip", event.get("peerIP", "0.0.0.0")),
                        target_port=target_port,
                        protocol=event.get("protocol", "tcp"),
                        honeypot_type=event.get("system", event.get("honeypot", "s3-import")),
                        session_id=event.get("session", str(uuid.uuid4())),
                        event_type=event.get("eventid", event.get("id", "unknown")),
                        commands=str(event.get("input", "")),
                        raw_payload=json.dumps(event),
                        sync_status="PENDING"
                    )
                    db_events.append(new_event)
                    logs_processed += 1
                except json.JSONDecodeError:
                    pass # Skip malformed lines
        
        # Insert into DB
        if db_events:
            db.add_all(db_events)
            await db.commit()
            
        return {"status": "success", "message": f"Successfully pulled and ingested {logs_processed} events.", "inserted_count": logs_processed}
        
    except ClientError as e:
        logger.error(f"S3 Pull Failed: {e}")
        error_message = e.response.get('Error', {}).get('Message', str(e))
        raise HTTPException(status_code=400, detail=f"S3 Access Error: {error_message}")
    except Exception as e:
        logger.error(f"Unexpected S3 pull error: {e}")
        raise HTTPException(status_code=500, detail=f"Internal Server Error during S3 pull: {e}")
