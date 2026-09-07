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

class AWSCredentialsSchema(BaseModel):
    """
    Optional AWS credentials.

    Only read when INFRA_PROVIDER=aws. In local mode every field stays null and
    no AWS configuration is required anywhere in the request path.
    """
    aws_access_key: Optional[str] = None
    aws_secret_key: Optional[str] = None
    aws_region: Optional[str] = None


class LabLaunchRequest(AWSCredentialsSchema):
    """Provider-independent lab launch request."""
    environment: str                        # 'kali', 'windows', ...
    profile: Optional[str] = "standard"     # 'light' | 'standard' | 'heavy'
    protocol: Optional[str] = "rdp"         # 'rdp' | 'ssh'
    lab_id: Optional[str] = None            # caller-supplied id, else generated


class LabActionRequest(AWSCredentialsSchema):
    """Request body for actions addressed by lab_id in the path."""
    pass


class LabResponse(BaseModel):
    status: str
    lab_id: Optional[str] = None
    provider: Optional[str] = None
    environment: Optional[str] = None
    profile: Optional[str] = None
    message: Optional[str] = None


# ── Backwards-compatible aliases ────────────────────────────────────────────
# Kept so any external caller still importing the old names keeps working.
VMResponse = LabResponse
VMLaunchRequest = LabLaunchRequest
VMTerminateRequest = LabActionRequest
SessionOpenRequest = LabActionRequest
