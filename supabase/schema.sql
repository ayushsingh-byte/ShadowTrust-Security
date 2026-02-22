
-- EXTENSIONS
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. USERS TABLE (Merged)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    -- Roles requested: Operative, Specialist, Overseer, Super Admin
    role TEXT CHECK (role IN ('operative', 'specialist', 'overseer', 'super_admin')) DEFAULT 'operative',
    is_approved BOOLEAN DEFAULT FALSE, -- Maps to status=PENDING/ACTIVE logic
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Legacy fields preserved for future use
    username TEXT,
    first_name TEXT,
    last_name TEXT,
    department TEXT,
    last_login TIMESTAMP WITH TIME ZONE
);

-- 2. NODES (Legacy) - Keeping this for the Dashboard Node View
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

-- 3. RAW LOGS (New - For Log Collector)
CREATE TABLE IF NOT EXISTS logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_ip TEXT,
    payload TEXT,
    protocol TEXT,
    port INTEGER,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    raw_data JSONB
);

-- 4. PROCESSED ATTACKS (New - For AI Engine Output)
CREATE TABLE IF NOT EXISTS attacks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    log_id UUID REFERENCES logs(id),
    type TEXT, -- e.g. SQL_INJECTION, SSH_BRUTE_FORCE
    severity TEXT, -- LOW, MEDIUM, HIGH, CRITICAL
    mitre_tactic TEXT, -- e.g. Initial Access
    mitre_id TEXT, -- e.g. T1110
    processed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 5. ALERTS (Legacy - mapped to Attacks via logic if needed, or kept separate)
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    node_id TEXT REFERENCES nodes(node_id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    status TEXT DEFAULT 'NEW' CHECK (status IN ('NEW', 'INVESTIGATING', 'RESOLVED'))
);

-- 6. SYSTEM SETTINGS (Legacy)
CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ROW LEVEL SECURITY (Allow All for MVP)
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE attacks ENABLE ROW LEVEL SECURITY;
ALTER TABLE nodes ENABLE ROW LEVEL SECURITY;

-- 1. Drop existing policies to avoid "already exists" errors
DROP POLICY IF EXISTS "Allow All" ON users;
DROP POLICY IF EXISTS "Allow All" ON logs;
DROP POLICY IF EXISTS "Allow All" ON attacks;
DROP POLICY IF EXISTS "Allow All" ON nodes;

-- 2. Create policies
CREATE POLICY "Allow All" ON users FOR ALL USING (true);
CREATE POLICY "Allow All" ON logs FOR ALL USING (true);
CREATE POLICY "Allow All" ON attacks FOR ALL USING (true);
CREATE POLICY "Allow All" ON nodes FOR ALL USING (true);

-- 3. EXPLICIT GRANTS (Fix for 42501 Permission Denied)
GRANT USAGE ON SCHEMA public TO postgres, anon, authenticated, service_role;
GRANT ALL ON ALL TABLES IN SCHEMA public TO postgres, anon, authenticated, service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO postgres, anon, authenticated, service_role;
GRANT ALL ON ALL FUNCTIONS IN SCHEMA public TO postgres, anon, authenticated, service_role;

-- SEED DATA
-- Default Admin (password: admin123 - hashed)
INSERT INTO users (email, password_hash, role, is_approved)
VALUES ('admin@honey.net', 'hashed_admin123', 'super_admin', TRUE)
ON CONFLICT (email) DO NOTHING;
