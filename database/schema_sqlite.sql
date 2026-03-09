-- SQLite Schema

-- Users Table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    first_name TEXT,
    last_name TEXT,
    department TEXT,
    clearance_level INTEGER CHECK (clearance_level IN (1, 2, 3)),
    requested_clearance_level INTEGER CHECK (requested_clearance_level IN (1, 2, 3)),
    role TEXT CHECK (role IN ('SUPER_ADMIN', 'ANALYST', 'AUDITOR', 'OPERATIVE', 'SPECIALIST', 'OVERSEER')),
    status TEXT DEFAULT 'PENDING' CHECK (status IN ('ACTIVE', 'PENDING', 'BLOCKED')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME
);

-- Nodes (Honeypots) Table
CREATE TABLE IF NOT EXISTS nodes (
    node_id TEXT PRIMARY KEY, -- e.g., 'EDU-01'
    name TEXT NOT NULL,
    type TEXT,
    sector TEXT,
    ip_address TEXT,
    os TEXT,
    status TEXT DEFAULT 'OFFLINE' CHECK (status IN ('ONLINE', 'OFFLINE')),
    uptime_seconds INTEGER DEFAULT 0,
    risk_level TEXT DEFAULT 'LOW',
    last_activity DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Node Metrics Table
CREATE TABLE IF NOT EXISTS node_metrics (
    node_id TEXT PRIMARY KEY,
    total_attacks_24h INTEGER DEFAULT 0,
    unique_attackers_24h INTEGER DEFAULT 0,
    top_attack_type TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE CASCADE
);

-- Events (Logs) Table
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT,
    src_ip TEXT,
    type TEXT, -- e.g., CMD_EXEC, LOGIN_ATTEMPT
    protocol TEXT, -- e.g., SSH, HTTP
    payload TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE SET NULL
);

-- Alerts Table
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'NEW' CHECK (status IN ('NEW', 'INVESTIGATING', 'RESOLVED')),
    FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE SET NULL
);

-- Captured Payloads Table
CREATE TABLE IF NOT EXISTS captured_payloads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT,
    command TEXT,
    file_hash TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE SET NULL
);

-- IOCs (Indicators of Compromise) Table
CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT,
    type TEXT CHECK (type IN ('ip', 'domain', 'hash_md5', 'hash_sha256')),
    value TEXT NOT NULL,
    detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE SET NULL
);

-- System Settings Table
CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL, -- Storing JSON as TEXT in SQLite
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert Default Admin User (Password: admin123 - should be hashed in production)
INSERT OR IGNORE INTO users (username, email, password_hash, role, clearance_level, status, first_name, last_name)
VALUES ('admin', 'admin@honey.net', 'hashed_admin123', 'SUPER_ADMIN', 3, 'ACTIVE', 'Admin', 'User');

-- Insert Mock Data for Settings
INSERT OR IGNORE INTO system_settings (key, value)
VALUES 
    ('general', '{"systemName": "ShadowTrust-01", "adminEmail": "admin@honey.net", "maintenanceMode": false}'),
    ('security', '{"sessionTimeout": 30, "strictIpFiltering": true, "maxLoginAttempts": 5}'),
    ('honeynet', '{"simulationLevel": "high", "responseLatency": 50, "honeyPortRotation": true}');

-- High-Frequency Telemetry Ingestion Table (Master Prompt architecture)
CREATE TABLE IF NOT EXISTS raw_events (
    id TEXT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    attacker_ip TEXT NOT NULL,
    target_port INTEGER,
    protocol TEXT,
    honeypot_type TEXT,
    session_id TEXT,
    event_type TEXT,
    commands TEXT,
    uploaded_files TEXT,
    ports_scanned TEXT,
    geoip_data JSON,
    risk_score REAL DEFAULT 0.0,
    raw_payload TEXT,
    sync_status TEXT DEFAULT 'PENDING'
);

CREATE INDEX IF NOT EXISTS idx_raw_events_status ON raw_events(sync_status);
CREATE INDEX IF NOT EXISTS idx_raw_events_ip ON raw_events(attacker_ip);
CREATE INDEX IF NOT EXISTS idx_raw_events_session ON raw_events(session_id);
