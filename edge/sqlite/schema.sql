PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

-- Nodes (optional if each DB belongs to a single node)
CREATE TABLE IF NOT EXISTS nodes (
  node_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  region TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Sessions represent an attacker interaction window (e.g., SSH session)
CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  protocol TEXT NOT NULL,
  src_ip TEXT NOT NULL,
  src_port INTEGER,
  dst_ip TEXT,
  dst_port INTEGER,
  started_at TEXT NOT NULL,
  ended_at TEXT,
  user_agent TEXT,
  fingerprint TEXT,
  risk_score INTEGER NOT NULL DEFAULT 0,
  synced_at TEXT,
  FOREIGN KEY(node_id) REFERENCES nodes(node_id)
);

CREATE INDEX IF NOT EXISTS idx_sessions_node_time ON sessions(node_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_srcip_time ON sessions(src_ip, started_at DESC);

-- Attack events: high-volume log line / event record
CREATE TABLE IF NOT EXISTS attack_events (
  event_id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  session_id TEXT,
  ts TEXT NOT NULL,
  event_type TEXT NOT NULL,
  protocol TEXT,
  src_ip TEXT,
  src_port INTEGER,
  dst_ip TEXT,
  dst_port INTEGER,
  severity TEXT NOT NULL DEFAULT 'INFO',
  message TEXT,
  raw_json TEXT,
  risk_score INTEGER NOT NULL DEFAULT 0,
  geo_country TEXT,
  geo_city TEXT,
  synced_at TEXT,
  FOREIGN KEY(node_id) REFERENCES nodes(node_id),
  FOREIGN KEY(session_id) REFERENCES sessions(session_id)
);

CREATE INDEX IF NOT EXISTS idx_events_node_ts ON attack_events(node_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_srcip_ts ON attack_events(src_ip, ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_type_ts ON attack_events(event_type, ts DESC);

-- Commands captured (e.g., from SSH honeypot)
CREATE TABLE IF NOT EXISTS commands (
  command_id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  session_id TEXT,
  ts TEXT NOT NULL,
  command TEXT NOT NULL,
  risk_score INTEGER NOT NULL DEFAULT 0,
  synced_at TEXT,
  FOREIGN KEY(node_id) REFERENCES nodes(node_id),
  FOREIGN KEY(session_id) REFERENCES sessions(session_id)
);

CREATE INDEX IF NOT EXISTS idx_commands_node_ts ON commands(node_id, ts DESC);

-- Payloads (uploads, dropped files, extracted artifacts)
CREATE TABLE IF NOT EXISTS payloads (
  payload_id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  session_id TEXT,
  ts TEXT NOT NULL,
  sha256 TEXT,
  filename TEXT,
  size_bytes INTEGER,
  mime TEXT,
  storage_path TEXT,
  classification TEXT,
  risk_score INTEGER NOT NULL DEFAULT 0,
  synced_at TEXT,
  FOREIGN KEY(node_id) REFERENCES nodes(node_id),
  FOREIGN KEY(session_id) REFERENCES sessions(session_id)
);

CREATE INDEX IF NOT EXISTS idx_payloads_node_ts ON payloads(node_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_payloads_sha ON payloads(sha256);

-- Connections (high-speed connection metadata)
CREATE TABLE IF NOT EXISTS connections (
  conn_id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  ts TEXT NOT NULL,
  protocol TEXT NOT NULL,
  src_ip TEXT NOT NULL,
  src_port INTEGER,
  dst_ip TEXT,
  dst_port INTEGER,
  flags TEXT,
  bytes_in INTEGER DEFAULT 0,
  bytes_out INTEGER DEFAULT 0,
  duration_ms INTEGER,
  risk_score INTEGER NOT NULL DEFAULT 0,
  synced_at TEXT,
  FOREIGN KEY(node_id) REFERENCES nodes(node_id)
);

CREATE INDEX IF NOT EXISTS idx_conns_node_ts ON connections(node_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_conns_srcip_ts ON connections(src_ip, ts DESC);
