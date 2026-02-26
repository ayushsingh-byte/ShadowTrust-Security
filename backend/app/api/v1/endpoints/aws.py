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
        raise HTTPException(status_code=401, detail=f"AWS Invalid/Unauthorized: {error_message}")
        
    except Exception as e:
        logger.error(f"Unexpected AWS error: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error during AWS validation.")
