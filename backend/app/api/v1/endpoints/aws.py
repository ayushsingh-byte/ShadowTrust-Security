from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
import boto3
from botocore.exceptions import ClientError
import logging

logger = logging.getLogger(__name__)

router = APIRouter()

class AWSTestRequest(BaseModel):
    aws_access_key: str
    aws_secret_key: str
    aws_region: Optional[str] = "ap-south-1"

class AWSDebugRequest(AWSTestRequest):
    s3_bucket: Optional[str] = None
    iam_profile: Optional[str] = None

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
