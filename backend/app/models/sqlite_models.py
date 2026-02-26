from sqlalchemy import Column, String, Integer, Float, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
import uuid

from app.db.sqlite_db import Base

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
