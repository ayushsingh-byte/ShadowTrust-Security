from sqlalchemy import Column, ForeignKey, Integer, String, Float, DateTime, Text, JSON, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.sqlite_db import Base
import uuid
from datetime import datetime

# Users
class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    first_name = Column(String)
    last_name = Column(String)
    department = Column(String)
    clearance_level = Column(Integer) # 1, 2, 3
    requested_clearance_level = Column(Integer) # 1, 2, 3 — what user requested at registration
    role = Column(String) # SUPER_ADMIN, ANALYST, AUDITOR, OPERATIVE, SPECIALIST, OVERSEER
    status = Column(String, default="PENDING") # ACTIVE, PENDING, BLOCKED
    otp_code = Column(String, nullable=True)
    otp_expires_at = Column(DateTime(timezone=True), nullable=True)
    system_code = Column(String, nullable=True) # Admin Access Code (XXX XXX)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True))

# Nodes
class Node(Base):
    __tablename__ = "nodes"

    node_id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    type = Column(String)
    sector = Column(String)
    ip_address = Column(String)
    os = Column(String)
    status = Column(String, default="OFFLINE") # ONLINE, OFFLINE
    uptime_seconds = Column(Integer, default=0)
    risk_level = Column(String, default="LOW")
    last_activity = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    metrics = relationship("NodeMetrics", back_populates="node", uselist=False, cascade="all, delete-orphan")
    events = relationship("Event", back_populates="node")
    alerts = relationship("Alert", back_populates="node")

class NodeMetrics(Base):
    __tablename__ = "node_metrics"

    node_id = Column(String, ForeignKey("nodes.node_id", ondelete="CASCADE"), primary_key=True)
    total_attacks_24h = Column(Integer, default=0)
    unique_attackers_24h = Column(Integer, default=0)
    top_attack_type = Column(String)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    node = relationship("Node", back_populates="metrics")

# Logs & Events
class Event(Base):
    __tablename__ = "events"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    node_id = Column(String, ForeignKey("nodes.node_id", ondelete="SET NULL"))
    src_ip = Column(String)
    type = Column(String)
    protocol = Column(String)
    payload = Column(Text)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    node = relationship("Node", back_populates="events")

class Attack(Base):
    __tablename__ = "attacks"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    log_id = Column(String, ForeignKey("events.id", ondelete="CASCADE"), nullable=True) # links to raw Event if available
    type = Column(String)
    severity = Column(String) # LOW, MEDIUM, HIGH, CRITICAL 
    mitre_tactic = Column(String, nullable=True)
    mitre_id = Column(String, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

class RawEventModel(Base):
    __tablename__ = "raw_events"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=datetime.utcnow)
    attacker_ip = Column(String, index=True, nullable=False)
    target_port = Column(Integer)
    protocol = Column(String)
    honeypot_type = Column(String)
    session_id = Column(String, index=True)
    event_type = Column(String)
    commands = Column(String, nullable=True)
    uploaded_files = Column(String, nullable=True)
    ports_scanned = Column(String, nullable=True)
    geoip_data = Column(JSON, nullable=True)
    risk_score = Column(Float, default=0.0)
    raw_payload = Column(String, nullable=True)
    sync_status = Column(String, default="PENDING", index=True)
    signature = Column(String, unique=True, index=True, nullable=True)

class S3SyncState(Base):
    __tablename__ = "s3_sync_state"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    file_key = Column(String, unique=True, index=True, nullable=False)
    processed_at = Column(DateTime(timezone=True), server_default=func.now())

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    node_id = Column(String, ForeignKey("nodes.node_id", ondelete="SET NULL"))
    title = Column(String, nullable=False)
    description = Column(String)
    severity = Column(String) # LOW, MEDIUM, HIGH, CRITICAL
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(String, default="NEW") # NEW, INVESTIGATING, RESOLVED

    node = relationship("Node", back_populates="alerts")

class CapturedPayload(Base):
    __tablename__ = "captured_payloads"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    node_id = Column(String, ForeignKey("nodes.node_id", ondelete="SET NULL"))
    command = Column(String)
    file_hash = Column(String)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

class IOC(Base):
    __tablename__ = "iocs"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    node_id = Column(String, ForeignKey("nodes.node_id", ondelete="SET NULL"))
    type = Column(String) # ip, domain, hash_md5, hash_sha256
    value = Column(String, nullable=False)
    detected_at = Column(DateTime(timezone=True), server_default=func.now())

class SystemSettings(Base):
    __tablename__ = "system_settings"

    key = Column(String, primary_key=True, index=True)
    value = Column(JSON, nullable=False) # JSON 
    updated_at = Column(DateTime(timezone=True), server_default=func.now())

class AccessLog(Base):
    __tablename__ = "access_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    admin_id = Column(String, ForeignKey("users.id"))
    target_user_id = Column(String, ForeignKey("users.id"))
    action = Column(String) # APPROVE, DENY, REVOKE, ELEVATE
    details = Column(String) # JSON or text details about role/level changes
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    admin = relationship("User", foreign_keys=[admin_id])
    target_user = relationship("User", foreign_keys=[target_user_id])

# Orchestration Additions
class VMProfile(Base):
    __tablename__ = "vm_profiles"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    profile_name = Column(String, nullable=False)
    ami_id = Column(String, nullable=False)
    instance_type = Column(String, nullable=False)
    launch_template_id = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class VMInstance(Base):
    __tablename__ = "vm_instances"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    instance_id = Column(String, unique=True, nullable=False)
    profile_id = Column(String, ForeignKey("vm_profiles.id"))
    status = Column(String, nullable=False)
    public_ip = Column(String)
    private_ip = Column(String)
    session_id = Column(String)
    launched_at = Column(DateTime(timezone=True), server_default=func.now())
    terminated_at = Column(DateTime(timezone=True))

class AttackerSession(Base):
    __tablename__ = "attacker_sessions"

    session_id = Column(String, primary_key=True)
    attacker_ip = Column(String, nullable=False)
    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False)
    risk_level = Column(String)
    total_events = Column(Integer, default=0)
    geoip_country = Column(String)

class StructuredEvent(Base):
    __tablename__ = "structured_events"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    raw_event_id = Column(String, unique=True, nullable=False)
    session_id = Column(String, ForeignKey("attacker_sessions.session_id"))
    timestamp = Column(DateTime(timezone=True), nullable=False)
    honeypot_type = Column(String)
    event_type = Column(String)
    details = Column(JSON)
class SystemConfig(Base):
    __tablename__ = "system_config"

    key = Column(String, primary_key=True)
    value = Column(String, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ─── Credential Management System ────────────────────────────────────────────

class CredentialToken(Base):
    """One-time login tokens issued alongside temporary credentials."""
    __tablename__ = "credential_tokens"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, nullable=True)          # target user ID (may be new/external)
    username = Column(String, nullable=False)
    token = Column(String, unique=True, index=True, nullable=False)
    issued_by = Column(String, ForeignKey("users.id"), nullable=True)  # admin who issued
    issued_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    used_at = Column(DateTime, nullable=True)
    force_password_change = Column(Boolean, default=True)


class CredentialAuditLog(Base):
    """Full audit trail for every credential delivery event."""
    __tablename__ = "credential_audit_log"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, nullable=False)
    recipient_email = Column(String, nullable=True)
    recipient_phone = Column(String, nullable=True)
    issued_by = Column(String, ForeignKey("users.id"), nullable=True)   # admin ID
    issuer_name = Column(String, nullable=True)                          # admin display name
    timestamp = Column(DateTime, default=datetime.utcnow)
    delivery_method = Column(String, nullable=False)   # EMAIL | WHATSAPP | BOTH
    email_status = Column(String, default="NOT_SENT")  # SENT | FAILED | NOT_SENT | SIMULATED
    whatsapp_status = Column(String, default="NOT_SENT")
    token_id = Column(String, ForeignKey("credential_tokens.id"), nullable=True)
    token_status = Column(String, default="GENERATED")  # GENERATED | USED | EXPIRED | NONE
    custom_message = Column(Text, nullable=True)
    admin_ip = Column(String, nullable=True)


class AdminActivity(Base):
    """Log of every administrative action for security auditing."""
    __tablename__ = "admin_activity_log"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    admin_id = Column(String, ForeignKey("users.id"), nullable=True)
    admin_username = Column(String, nullable=True)
    action = Column(String, nullable=False)   # ISSUE_CREDENTIALS | RESET_PASSWORD | RESEND | etc.
    affected_user = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    result = Column(String, default="SUCCESS")  # SUCCESS | FAILED | RATE_LIMITED
    details = Column(Text, nullable=True)        # JSON blob with extra context


# ─── Sector Intelligence System ───────────────────────────────────────────────

class SectorTarget(Base):
    """A website or IP address assigned to a sector for monitoring."""
    __tablename__ = "sector_targets"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    sector_key = Column(String, index=True, nullable=False)  # education, defence, medicare, etc.
    name = Column(String, nullable=False)
    url = Column(String, nullable=True)
    ip = Column(String, nullable=True)
    description = Column(String, nullable=True)
    api_key = Column(String, unique=True, index=True, nullable=False, default=lambda: str(uuid.uuid4()))
    active = Column(Boolean, default=True)
    added_at = Column(DateTime, default=datetime.utcnow)

    events = relationship("SectorEvent", back_populates="target", cascade="all, delete-orphan")


class SectorEvent(Base):
    """An attack/security event ingested from a sector target."""
    __tablename__ = "sector_events"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    sector_key = Column(String, index=True, nullable=False)
    target_id = Column(String, ForeignKey("sector_targets.id", ondelete="SET NULL"), nullable=True)
    target_url = Column(String, nullable=True)
    attacker_ip = Column(String, index=True, nullable=False)
    country = Column(String, nullable=True)
    attack_type = Column(String, nullable=True)  # SQLi, XSS, RCE, BruteForce, Scan, Other
    commands = Column(JSON, nullable=True)        # list of captured commands
    ioc_value = Column(String, nullable=True)
    ioc_type = Column(String, nullable=True)      # ip, domain, hash, url
    risk_score = Column(Float, default=0.0)
    user_agent = Column(String, nullable=True)
    request_path = Column(String, nullable=True)
    raw_payload = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    target = relationship("SectorTarget", back_populates="events")
