from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime

class RawEventSchema(BaseModel):
    id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    attacker_ip: str
    target_port: Optional[int] = None
    protocol: Optional[str] = None
    honeypot_type: Optional[str] = None
    session_id: Optional[str] = None
    event_type: str
    commands: Optional[str] = None
    uploaded_files: Optional[str] = None
    ports_scanned: Optional[str] = None
    geoip_data: Optional[Dict[str, Any]] = None
    risk_score: float = 0.0
    raw_payload: Optional[str] = None

class VMResponse(BaseModel):
    status: str
    instance_id: Optional[str] = None
    message: Optional[str] = None

class AWSCredentialsSchema(BaseModel):
    aws_access_key: Optional[str] = None
    aws_secret_key: Optional[str] = None
    aws_region: Optional[str] = None

class VMLaunchRequest(AWSCredentialsSchema):
    ami_id: str
    instance_type: str
    subnet_id: str
    iam_profile_name: str
    session_id: str
    profile_id: Optional[str] = "custom_vm"

class VMTerminateRequest(AWSCredentialsSchema):
    pass

class SessionOpenRequest(AWSCredentialsSchema):
    pass
