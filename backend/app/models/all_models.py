from sqlalchemy import Column, ForeignKey, Integer, String, Float, DateTime, Text, JSON
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
