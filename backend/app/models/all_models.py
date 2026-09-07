from sqlalchemy import Column, ForeignKey, Integer, String, Float, DateTime, Text, JSON, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.database import Base
import uuid
from datetime import datetime

# Users
class User(Base):
    __tablename__ = "users"

    id = Column(String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(255), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    first_name = Column(String(255))
    last_name = Column(String(255))
    department = Column(String(255))
    clearance_level = Column(Integer) # 1, 2, 3
    requested_clearance_level = Column(Integer) # 1, 2, 3 — what user requested at registration
    role = Column(String(255)) # SUPER_ADMIN, ANALYST, AUDITOR, OPERATIVE, SPECIALIST, OVERSEER
    status = Column(String(255), default="PENDING") # ACTIVE, PENDING, BLOCKED
    otp_code = Column(String(255), nullable=True)
    otp_expires_at = Column(DateTime(timezone=True), nullable=True)
    system_code = Column(String(255), nullable=True) # Admin Access Code (XXX XXX)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True))

# Nodes
class Node(Base):
    __tablename__ = "nodes"

    node_id = Column(String(255), primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    type = Column(String(255))
    sector = Column(String(255))
    ip_address = Column(String(255))
    os = Column(String(255))
    status = Column(String(255), default="OFFLINE") # ONLINE, OFFLINE
    uptime_seconds = Column(Integer, default=0)
    risk_level = Column(String(255), default="LOW")
    last_activity = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    metrics = relationship("NodeMetrics", back_populates="node", uselist=False, cascade="all, delete-orphan")
    events = relationship("Event", back_populates="node")
    alerts = relationship("Alert", back_populates="node")

class NodeMetrics(Base):
    __tablename__ = "node_metrics"

    node_id = Column(String(255), ForeignKey("nodes.node_id", ondelete="CASCADE"), primary_key=True)
    total_attacks_24h = Column(Integer, default=0)
    unique_attackers_24h = Column(Integer, default=0)
    top_attack_type = Column(String(255))
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    node = relationship("Node", back_populates="metrics")

# Logs & Events
class Event(Base):
    __tablename__ = "events"

    id = Column(String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    node_id = Column(String(255), ForeignKey("nodes.node_id", ondelete="SET NULL"))
    src_ip = Column(String(255))
    type = Column(String(255))
    protocol = Column(String(255))
    payload = Column(Text)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    node = relationship("Node", back_populates="events")

class Attack(Base):
    __tablename__ = "attacks"

    id = Column(String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    log_id = Column(String(255), ForeignKey("events.id", ondelete="CASCADE"), nullable=True) # links to raw Event if available
    type = Column(String(255))
    severity = Column(String(255)) # LOW, MEDIUM, HIGH, CRITICAL 
    mitre_tactic = Column(String(255), nullable=True)
    mitre_id = Column(String(255), nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

class RawEventModel(Base):
    __tablename__ = "raw_events"

    id = Column(String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=datetime.utcnow)
    attacker_ip = Column(String(255), index=True, nullable=False)
    target_port = Column(Integer)
    protocol = Column(String(255))
    honeypot_type = Column(String(255))
    session_id = Column(String(255), index=True)
    event_type = Column(String(255))
    commands = Column(Text, nullable=True)
    uploaded_files = Column(Text, nullable=True)
    ports_scanned = Column(Text, nullable=True)
    geoip_data = Column(JSON, nullable=True)
    risk_score = Column(Float, default=0.0)
    raw_payload = Column(Text, nullable=True)
    sync_status = Column(String(255), default="PENDING", index=True)
    signature = Column(String(255), unique=True, index=True, nullable=True)

class S3SyncState(Base):
    __tablename__ = "s3_sync_state"

    id = Column(String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    file_key = Column(String(255), unique=True, index=True, nullable=False)
    processed_at = Column(DateTime(timezone=True), server_default=func.now())


class NormalizedEventModel(Base):
    """
    Sensor-agnostic event, produced by services/telemetry/normalize.py.

    Named ...Model to match RawEventModel and to stay distinct from the
    NormalizedEvent dataclass in the normalizer, which is the in-flight
    representation of the same record.

    This is what the dashboard reads. RawEventModel is kept alongside it as the
    verbatim record (see the raw_event column here plus the raw/ telemetry
    files on disk), so nothing is lost by normalizing.

    The primary key is a content hash of the source event, not a random UUID.
    That makes re-ingesting the same log line a primary-key collision instead
    of a duplicate row, which is the backstop behind the cursor-based dedup in
    IngestCursor.
    """

    __tablename__ = "normalized_events"

    event_id = Column(String(255), primary_key=True)
    timestamp = Column(DateTime, index=True, nullable=False)
    ingested_at = Column(DateTime, default=datetime.utcnow, index=True)

    sensor = Column(String(255), index=True, nullable=False)
    sensor_event_type = Column(String(255), index=True)

    source_ip = Column(String(255), index=True, nullable=False)
    source_port = Column(Integer, nullable=True)
    destination_ip = Column(String(255), nullable=True)
    destination_port = Column(Integer, index=True, nullable=True)
    protocol = Column(String(255), index=True)

    username = Column(String(255), nullable=True)
    password = Column(String(255), nullable=True)
    authentication_result = Column(String(255), index=True, nullable=True)

    command = Column(Text, nullable=True)
    payload = Column(Text, nullable=True)
    session_id = Column(String(255), index=True, nullable=True)

    severity = Column(String(255), index=True)
    raw_event = Column(Text, nullable=True)
    event_metadata = Column("metadata", JSON, nullable=True)


class IngestCursor(Base):
    """
    Per-file read position for the local telemetry collector.

    Replaces mtime-only tracking. Honeypot logs are append-only, so re-reading
    a whole file every time its mtime advanced meant re-emitting every previous
    line on every cycle — dedup then had to catch thousands of repeats, and the
    old ip:port:timestamp signature collapsed genuinely distinct events that
    happened in the same second.

    Storing the byte offset means each line is read exactly once. inode and
    size detect rotation and truncation: if either goes backwards the file was
    replaced, so the offset resets to 0 rather than skipping the new content.
    """

    __tablename__ = "ingest_cursors"

    source_key = Column(String(255), primary_key=True)
    inode = Column(String(255), nullable=True)
    size_bytes = Column(Integer, default=0)
    byte_offset = Column(Integer, default=0)
    events_ingested = Column(Integer, default=0)
    last_error = Column(String(255), nullable=True)
    processed_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    node_id = Column(String(255), ForeignKey("nodes.node_id", ondelete="SET NULL"))
    title = Column(String(255), nullable=False)
    description = Column(String(255))
    severity = Column(String(255)) # LOW, MEDIUM, HIGH, CRITICAL
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(String(255), default="NEW") # NEW, INVESTIGATING, RESOLVED

    node = relationship("Node", back_populates="alerts")

class CapturedPayload(Base):
    __tablename__ = "captured_payloads"
    
    id = Column(String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    node_id = Column(String(255), ForeignKey("nodes.node_id", ondelete="SET NULL"))
    command = Column(Text)
    file_hash = Column(String(255))
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

class IOC(Base):
    __tablename__ = "iocs"
    
    id = Column(String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    node_id = Column(String(255), ForeignKey("nodes.node_id", ondelete="SET NULL"))
    type = Column(String(255)) # ip, domain, hash_md5, hash_sha256
    value = Column(String(255), nullable=False)
    detected_at = Column(DateTime(timezone=True), server_default=func.now())

class SystemSettings(Base):
    __tablename__ = "system_settings"

    key = Column(String(255), primary_key=True, index=True)
    value = Column(JSON, nullable=False) # JSON 
    updated_at = Column(DateTime(timezone=True), server_default=func.now())

class AccessLog(Base):
    __tablename__ = "access_logs"

    id = Column(String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    admin_id = Column(String(255), ForeignKey("users.id"))
    target_user_id = Column(String(255), ForeignKey("users.id"))
    action = Column(String(255)) # APPROVE, DENY, REVOKE, ELEVATE
    details = Column(Text) # JSON or text details about role/level changes
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    admin = relationship("User", foreign_keys=[admin_id])
    target_user = relationship("User", foreign_keys=[target_user_id])

# Orchestration Additions
class VMProfile(Base):
    __tablename__ = "vm_profiles"

    id = Column(String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    profile_name = Column(String(255), nullable=False)
    ami_id = Column(String(255), nullable=False)
    instance_type = Column(String(255), nullable=False)
    launch_template_id = Column(String(255))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class VMInstance(Base):
    __tablename__ = "vm_instances"

    id = Column(String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    instance_id = Column(String(255), unique=True, nullable=False)
    profile_id = Column(String(255), ForeignKey("vm_profiles.id"))
    status = Column(String(255), nullable=False)
    public_ip = Column(String(255))
    private_ip = Column(String(255))
    session_id = Column(String(255))
    launched_at = Column(DateTime(timezone=True), server_default=func.now())
    terminated_at = Column(DateTime(timezone=True))

class AttackerSession(Base):
    __tablename__ = "attacker_sessions"

    session_id = Column(String(255), primary_key=True)
    attacker_ip = Column(String(255), nullable=False)
    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False)
    risk_level = Column(String(255))
    total_events = Column(Integer, default=0)
    geoip_country = Column(String(255))

class StructuredEvent(Base):
    __tablename__ = "structured_events"

    id = Column(String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    raw_event_id = Column(String(255), unique=True, nullable=False)
    session_id = Column(String(255), ForeignKey("attacker_sessions.session_id"))
    timestamp = Column(DateTime(timezone=True), nullable=False)
    honeypot_type = Column(String(255))
    event_type = Column(String(255))
    details = Column(JSON)
class SystemConfig(Base):
    __tablename__ = "system_config"

    key = Column(String(255), primary_key=True)
    value = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ─── Credential Management System ────────────────────────────────────────────

class CredentialToken(Base):
    """One-time login tokens issued alongside temporary credentials."""
    __tablename__ = "credential_tokens"

    id = Column(String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(255), nullable=True)          # target user ID (may be new/external)
    username = Column(String(255), nullable=False)
    token = Column(String(255), unique=True, index=True, nullable=False)
    issued_by = Column(String(255), ForeignKey("users.id"), nullable=True)  # admin who issued
    issued_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    used_at = Column(DateTime, nullable=True)
    force_password_change = Column(Boolean, default=True)


class CredentialAuditLog(Base):
    """Full audit trail for every credential delivery event."""
    __tablename__ = "credential_audit_log"

    id = Column(String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(255), nullable=False)
    recipient_email = Column(String(255), nullable=True)
    recipient_phone = Column(String(255), nullable=True)
    issued_by = Column(String(255), ForeignKey("users.id"), nullable=True)   # admin ID
    issuer_name = Column(String(255), nullable=True)                          # admin display name
    timestamp = Column(DateTime, default=datetime.utcnow)
    delivery_method = Column(String(255), nullable=False)   # EMAIL | WHATSAPP | BOTH
    email_status = Column(String(255), default="NOT_SENT")  # SENT | FAILED | NOT_SENT | NOT_CONFIGURED
    whatsapp_status = Column(String(255), default="NOT_SENT")
    token_id = Column(String(255), ForeignKey("credential_tokens.id"), nullable=True)
    token_status = Column(String(255), default="GENERATED")  # GENERATED | USED | EXPIRED | NONE
    custom_message = Column(Text, nullable=True)
    admin_ip = Column(String(255), nullable=True)


class AdminActivity(Base):
    """Log of every administrative action for security auditing."""
    __tablename__ = "admin_activity_log"

    id = Column(String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    admin_id = Column(String(255), ForeignKey("users.id"), nullable=True)
    admin_username = Column(String(255), nullable=True)
    action = Column(String(255), nullable=False)   # ISSUE_CREDENTIALS | RESET_PASSWORD | RESEND | etc.
    affected_user = Column(String(255), nullable=True)
    ip_address = Column(String(255), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    result = Column(String(255), default="SUCCESS")  # SUCCESS | FAILED | RATE_LIMITED
    details = Column(Text, nullable=True)        # JSON blob with extra context



# ═══════════════════════════════════════════════════════════════════════════════
#  SOC layer — Detection · Correlation · Incident · Evidence · Validation
#  (all NEW tables; created by Base.metadata.create_all. Events are referenced by
#   their event_id string, not a foreign key, so no existing-table migration.)
# ═══════════════════════════════════════════════════════════════════════════════

class IOCObservation(Base):
    """A single indicator seen in the telemetry, deduplicated by (type, value)."""
    __tablename__ = "ioc_observations"

    id = Column(String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    type = Column(String(32), index=True, nullable=False)   # ip|domain|url|sha256|md5|sha1|username
    value = Column(String(512), index=True, nullable=False)
    first_seen = Column(DateTime, default=datetime.utcnow, index=True)
    last_seen = Column(DateTime, default=datetime.utcnow, index=True)
    hit_count = Column(Integer, default=1)
    source = Column(String(64))                             # honeypot|malware|splunk|manual
    event_ids = Column(JSON)                                # list[str]
    context = Column(JSON)                                  # {sensors, ports, ...}


class Detection(Base):
    """The output of one detection rule firing over a set of events."""
    __tablename__ = "detections"

    id = Column(String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    dedupe_key = Column(String(255), unique=True, index=True)   # rule + group + window bucket
    rule_id = Column(String(128), index=True, nullable=False)
    rule_name = Column(String(255), nullable=False)
    rule_source = Column(String(32), default="builtin")         # builtin|sigma
    severity = Column(String(16), index=True)                   # LOW|MEDIUM|HIGH|CRITICAL
    confidence = Column(Float, default=0.5)
    attack_technique = Column(String(32), index=True)           # T####
    attack_tactic = Column(String(64))
    matched_event_ids = Column(JSON)                            # list[str]
    match_conditions = Column(JSON)                             # the rule's selection block
    reason = Column(Text)                                       # plain-English why
    source_ip = Column(String(255), index=True)
    username = Column(String(255))
    first_event_at = Column(DateTime, index=True)
    last_event_at = Column(DateTime, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    incident_id = Column(String(255), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)


class Incident(Base):
    """Correlated group of detections / high-risk events — the investigation unit."""
    __tablename__ = "incidents"

    id = Column(String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_key = Column(String(64), unique=True, index=True)   # human ref e.g. INC-000042
    correlation_key = Column(String(255), index=True)            # source_ip or session id
    title = Column(String(512), nullable=False)
    severity = Column(String(16), index=True, default="LOW")
    status = Column(String(32), index=True, default="NEW")       # NEW|TRIAGING|INVESTIGATING|CONTAINED|RESOLVED|FALSE_POSITIVE
    confidence = Column(Float, default=0.5)
    risk_score = Column(Float, default=0.0)
    risk_breakdown = Column(JSON)                                # explains the score
    first_seen = Column(DateTime, index=True)
    last_seen = Column(DateTime, index=True)
    source_ips = Column(JSON)                                    # list[str]
    related_users = Column(JSON)
    related_sensors = Column(JSON)
    attack_techniques = Column(JSON)                             # list[{id,tactic,name}]
    detection_reasons = Column(JSON)                             # list[str] — why it exists / why this severity
    assigned_analyst = Column(String(255), nullable=True)  # analyst email/handle, not an FK
    analyst_notes = Column(Text)
    auto_created = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class IncidentEvent(Base):
    __tablename__ = "incident_events"
    id = Column(String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(String(255), ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False)
    event_id = Column(String(255), index=True, nullable=False)
    source = Column(String(32))                                  # honeypot|splunk|endpoint
    added_at = Column(DateTime, default=datetime.utcnow)
    correlation_reason = Column(Text)


class IncidentIOC(Base):
    __tablename__ = "incident_iocs"
    id = Column(String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(String(255), ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False)
    ioc_type = Column(String(32), nullable=False)
    ioc_value = Column(String(512), nullable=False)
    first_seen = Column(DateTime, default=datetime.utcnow)


class IncidentActivity(Base):
    """Audit trail of every analyst touch on an incident."""
    __tablename__ = "incident_activity"
    id = Column(String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(String(255), ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False)
    actor = Column(String(255))
    action = Column(String(64))                                  # STATUS_CHANGE|ASSIGN|NOTE|EVIDENCE_ADD|CREATE
    detail = Column(Text)
    at = Column(DateTime, default=datetime.utcnow, index=True)


class Evidence(Base):
    """Chain-of-custody item attached to an incident."""
    __tablename__ = "evidence"
    id = Column(String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(String(255), ForeignKey("incidents.id", ondelete="CASCADE"), index=True, nullable=False)
    type = Column(String(48), nullable=False)
    # malware_sample|static_report|sandbox_report|clamav_result|virustotal_result|
    # yara_result|honeypot_event|splunk_result|attachment|analyst_note|exported_log
    sha256 = Column(String(64), index=True)
    md5 = Column(String(32))
    sha1 = Column(String(40))
    source = Column(String(64))
    ref = Column(String(1024))                                   # event_id | scans/<sha>.json#section | evidence/<id>/<file>
    acquired_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    evidence_metadata = Column(JSON)
    content_hash = Column(String(64))                            # sha256 of the evidence blob, for integrity checks
    immutable = Column(Boolean, default=True)
    added_by = Column(String(255), nullable=True)  # analyst email/handle, not an FK


class ScenarioRun(Base):
    """One execution/evaluation of a controlled attack scenario for SOC testing."""
    __tablename__ = "scenario_runs"
    id = Column(String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    scenario_id = Column(String(128), index=True, nullable=False)
    mode = Column(String(16), default="evaluate")               # execute|evaluate
    status = Column(String(16), default="running")              # running|complete|error
    started_at = Column(DateTime, default=datetime.utcnow, index=True)
    finished_at = Column(DateTime, nullable=True)
    expected = Column(JSON)
    observed = Column(JSON)
    result = Column(String(16))                                 # PASS|FAIL|PARTIAL
    detections_seen = Column(JSON)
    techniques_seen = Column(JSON)
    severity_seen = Column(String(16))
    metrics = Column(JSON)
    triggered_by = Column(String(255))


class AnalysisSession(Base):
    """One Analysis Lab sandbox shell session (analysis_lab.html)."""
    __tablename__ = "analysis_sessions"

    id = Column(String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String(255), unique=True, index=True, nullable=False)
    owner = Column(String(255), index=True)              # analyst email — not an FK
    source_tag = Column(String(255), index=True)         # "analyst-shell:<email>"
    container_name = Column(String(255))
    status = Column(String(16), default="starting")      # starting|running|stopped|error
    started_at = Column(DateTime, default=datetime.utcnow, index=True)
    last_activity_at = Column(DateTime, default=datetime.utcnow, index=True)
    stopped_at = Column(DateTime, nullable=True)
    command_count = Column(Integer, default=0)
    connection_count = Column(Integer, default=0)
    seq = Column(Integer, default=0)                     # monotonic event counter
    ttl_minutes = Column(Integer, default=20)
    incident_id = Column(String(255), nullable=True)     # back-filled if commands correlate


class GeneratedReport(Base):
    """One report produced by the PDF report engine (app/services/reporting).

    Every report/export button on the dashboard writes a row here so there is an
    auditable record of what was generated, by whom, over which data window.
    """
    __tablename__ = "generated_reports"

    id = Column(String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    report_type = Column(String(64), index=True, nullable=False)   # geo_intel|incident|forensic_dfir|...
    title = Column(String(255), nullable=False)
    subject = Column(String(255))                                  # incident id, "global", sha256, ...
    fmt = Column(String(8), default="pdf")                         # pdf|json|csv
    file_path = Column(String(512), nullable=False)                # absolute path under /app/reports
    filename = Column(String(255), nullable=False)                 # download name
    sha256 = Column(String(64), index=True)
    size_bytes = Column(Integer, default=0)
    generated_by_id = Column(String(255), index=True)
    generated_by_email = Column(String(255))
    generated_at = Column(DateTime, default=datetime.utcnow, index=True)
    params_json = Column(JSON)                                     # request params echoed back
    window_start = Column(DateTime, nullable=True)
    window_end = Column(DateTime, nullable=True)
    status = Column(String(16), default="ready")                   # ready|error
    error = Column(Text, nullable=True)
