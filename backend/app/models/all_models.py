from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, DateTime, Text, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base
import uuid

# Models
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True) # SQLite/PG compatible ID
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    first_name = Column(String)
    last_name = Column(String)
    department = Column(String)
    clearance_level = Column(Integer) # 1, 2, 3
    role = Column(String) # SUPER_ADMIN, ANALYST, etc.
    status = Column(String, default="PENDING")
    otp_code = Column(String, nullable=True)
    otp_expires_at = Column(DateTime(timezone=True), nullable=True)
    system_code = Column(String, nullable=True) # Admin Access Code (XXX XXX)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True))

class Node(Base):
    __tablename__ = "nodes"

    node_id = Column(String, primary_key=True, index=True)
    name = Column(String)
    type = Column(String)
    sector = Column(String)
    ip_address = Column(String)
    os = Column(String)
    status = Column(String, default="OFFLINE")
    uptime_seconds = Column(Integer, default=0)
    risk_level = Column(String, default="LOW")
    last_activity = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    metrics = relationship("NodeMetrics", back_populates="node", uselist=False, cascade="all, delete-orphan")
    events = relationship("Event", back_populates="node")
    alerts = relationship("Alert", back_populates="node")

class NodeMetrics(Base):
    __tablename__ = "node_metrics"

    node_id = Column(String, ForeignKey("nodes.node_id"), primary_key=True)
    total_attacks_24h = Column(Integer, default=0)
    unique_attackers_24h = Column(Integer, default=0)
    top_attack_type = Column(String)
    updated_at = Column(DateTime(timezone=True), server_default=func.now())

    node = relationship("Node", back_populates="metrics")

class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    node_id = Column(String, ForeignKey("nodes.node_id"))
    src_ip = Column(String)
    type = Column(String)
    protocol = Column(String)
    payload = Column(Text)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    node = relationship("Node", back_populates="events")

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    node_id = Column(String, ForeignKey("nodes.node_id"))
    title = Column(String)
    description = Column(String)
    severity = Column(String)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(String, default="NEW")

    node = relationship("Node", back_populates="alerts")

class SystemSettings(Base):
    __tablename__ = "system_settings"

    key = Column(String, primary_key=True, index=True)
    value = Column(String) # JSON string
    updated_at = Column(DateTime(timezone=True), server_default=func.now())

class AccessLog(Base):
    __tablename__ = "access_logs"

    id = Column(Integer, primary_key=True, index=True)
    admin_id = Column(Integer, ForeignKey("users.id"))
    target_user_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String) # APPROVE, DENY, REVOKE, ELEVATE
    details = Column(String) # JSON or text details about role/level changes
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    admin = relationship("User", foreign_keys=[admin_id])
    target_user = relationship("User", foreign_keys=[target_user_id])
