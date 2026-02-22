# Hybrid Edge + Cloud Honeypot Platform (Architecture)

## Goals
- **Edge reliability**: each honeypot node ingests raw telemetry locally into SQLite (works offline).
- **Cloud analytics**: Supabase Postgres stores only **summaries/aggregations/alerts**.
- **Security**: frontend never touches SQLite; all access goes through authenticated backend API.
- **Scalability**: support many nodes with a collector pattern and eventual sync.

## High-level diagram
```text
┌───────────────┐      raw telemetry       ┌────────────────────┐
│ Honeypot Node │ ───────────────────────▶ │ SQLite (local edge) │
│ (sensors)     │                          │ logs/sessions/etc.  │
└───────┬───────┘                          └─────────┬──────────┘
        │                                                     ▲
        │ collector pull/read (no direct FE access)            │
        ▼                                                     │
┌──────────────────────┐   authenticated queries   ┌──────────┴──────────┐
│ Node.js Backend API   │ ◀─────────────────────── │ Static Dashboard      │
│ (collector + auth)    │   Supabase Auth (JWT)    │ (HTML/CSS/JS)         │
└──────────┬───────────┘                           └──────────────────────┘
           │
           │ summarized/enriched events (async)
           ▼
┌──────────────────────┐
│ Worker / Queue Sync   │
│ (Node.js)             │
└──────────┬───────────┘
           │ service role
           ▼
┌────────────────────────────────────────────────────┐
│ Supabase (Auth + Postgres + RLS)                    │
│ analytics/alerts/aggregations/attacker_profiles      │
└────────────────────────────────────────────────────┘
```

## Components

### 1) Edge node
- Honeypot(s) write raw events into a local SQLite DB.
- Optional “node-agent” can normalize sensor output into the schema.

### 2) Backend API (Node.js)
- Single point of access for dashboard.
- Reads from one or more SQLite DBs (collector pattern).
- Verifies Supabase JWT and enforces roles.
- Adds **rate limiting** + **audit logging**.

### 3) Background sync worker
- Pulls “important” events from SQLite and pushes *summaries* to Supabase Postgres.
- Runs continuously; uses a queue if Redis is available.
- Must tolerate offline nodes; retries later.

### 4) Supabase
- Auth: login, JWT issuance.
- Postgres: analytics tables.
- RLS: admin/analyst/viewer.

## Data ownership

### SQLite (edge)
Stores **raw telemetry** only:
- logs/events
- sessions
- payloads
- commands
- connection metadata

### Supabase Postgres (cloud)
Stores **derived** data:
- aggregated stats (daily/hourly)
- alerts
- attacker profiles
- top ports/countries/protocols
- audit trail (optional)

## AuthN/AuthZ
- Frontend authenticates via Supabase Auth.
- Frontend sends `Authorization: Bearer <supabase_jwt>` to the Node.js API.
- API verifies JWT using Supabase JWKS.
- API authorizes by **role**: `admin`, `analyst`, `viewer`.

Recommended role source:
- Use `app_metadata.role` (set via Supabase Admin API / edge function) or
- Use a `profiles` table in Supabase with RLS.

## API endpoints (minimal)
- `GET /health`
- `GET /v1/nodes`
- `GET /v1/events?nodeId=&from=&to=&limit=`
- `GET /v1/sessions?nodeId=&from=&to=&limit=`
- `GET /v1/attackers/:ip`
- `GET /v1/alerts` (from Supabase)

## Enrichment
- GeoIP: local library (`geoip-lite`) or MaxMind DB.
- Fingerprinting: stable hash of attacker features.
- Risk score: heuristic based on ports, auth failures, payload indicators.

## Security requirements mapping
- **SQLite not public**: never serve `.sqlite` files; keep edge storage out of web root.
- **Authenticated node access**: all queries go through API with JWT.
- **Rate limiting**: per-IP + per-user.
- **Audit logs**: request-level logs with `user_id`, `role`, `nodeId`, route.

## Offline + sync later
- Node keeps ingesting to SQLite.
- Worker marks synced records with `synced_at` and can resume.
- If Supabase is unreachable, worker backs off and retries.

## Repo layout (proposed)
```text
edge/sqlite/schema.sql
services/api/...
services/worker/...
frontend/...
```
