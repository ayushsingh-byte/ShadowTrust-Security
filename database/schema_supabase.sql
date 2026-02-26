-- Supabase (PostgreSQL) Schema

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users Table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    first_name TEXT,
    last_name TEXT,
    department TEXT,
    clearance_level INTEGER CHECK (clearance_level IN (1, 2, 3)),
    role TEXT CHECK (role IN ('SUPER_ADMIN', 'ANALYST', 'AUDITOR', 'OPERATIVE', 'SPECIALIST', 'OVERSEER')),
    status TEXT DEFAULT 'PENDING' CHECK (status IN ('ACTIVE', 'PENDING', 'BLOCKED')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE
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
    last_activity TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Node Metrics Table
CREATE TABLE IF NOT EXISTS node_metrics (
    node_id TEXT PRIMARY KEY REFERENCES nodes(node_id) ON DELETE CASCADE,
    total_attacks_24h INTEGER DEFAULT 0,
    unique_attackers_24h INTEGER DEFAULT 0,
    top_attack_type TEXT,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Events (Logs) Table
CREATE TABLE IF NOT EXISTS events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    node_id TEXT REFERENCES nodes(node_id) ON DELETE SET NULL,
    src_ip TEXT,
    type TEXT, -- e.g., CMD_EXEC, LOGIN_ATTEMPT
    protocol TEXT, -- e.g., SSH, HTTP
    payload TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Alerts Table
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    node_id TEXT REFERENCES nodes(node_id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    status TEXT DEFAULT 'NEW' CHECK (status IN ('NEW', 'INVESTIGATING', 'RESOLVED'))
);

-- Captured Payloads Table
CREATE TABLE IF NOT EXISTS captured_payloads (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    node_id TEXT REFERENCES nodes(node_id) ON DELETE SET NULL,
    command TEXT,
    file_hash TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- IOCs (Indicators of Compromise) Table
CREATE TABLE IF NOT EXISTS iocs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    node_id TEXT REFERENCES nodes(node_id) ON DELETE SET NULL,
    type TEXT CHECK (type IN ('ip', 'domain', 'hash_md5', 'hash_sha256')),
    value TEXT NOT NULL,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- System Settings Table
CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL, -- Using JSONB for flexibility
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Insert Default Admin User (Password: admin123 - should be hashed in production)
INSERT INTO users (username, email, password_hash, role, clearance_level, status, first_name, last_name)
VALUES ('admin', 'admin@honey.net', 'hashed_admin123', 'SUPER_ADMIN', 3, 'ACTIVE', 'Admin', 'User')
ON CONFLICT (email) DO NOTHING;

-- Insert Mock Data for Settings
INSERT INTO system_settings (key, value)
VALUES 
    ('general', '{"systemName": "ShadowTrust-01", "adminEmail": "admin@honey.net", "maintenanceMode": false}'),
    ('security', '{"sessionTimeout": 30, "strictIpFiltering": true, "maxLoginAttempts": 5}'),
    ('honeynet', '{"simulationLevel": "high", "responseLatency": 50, "honeyPortRotation": true}')
ON CONFLICT (key) DO NOTHING;


-- ORCHESTRATION BACKEND ADDITIONS (VM & Session Management)

CREATE TABLE IF NOT EXISTS vm_profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    profile_name TEXT NOT NULL,
    ami_id TEXT NOT NULL,
    instance_type TEXT NOT NULL,
    launch_template_id TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vm_instances (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    instance_id TEXT UNIQUE NOT NULL,
    profile_id UUID REFERENCES vm_profiles(id),
    status TEXT NOT NULL,
    public_ip TEXT,
    private_ip TEXT,
    session_id TEXT,
    launched_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    terminated_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS attacker_sessions (
    session_id TEXT PRIMARY KEY,
    attacker_ip TEXT NOT NULL,
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    risk_level TEXT,
    total_events INTEGER DEFAULT 0,
    geoip_country TEXT
);

CREATE TABLE IF NOT EXISTS structured_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    raw_event_id TEXT UNIQUE NOT NULL,
    session_id TEXT REFERENCES attacker_sessions(session_id),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    honeypot_type TEXT,
    event_type TEXT,
    details JSONB
);
