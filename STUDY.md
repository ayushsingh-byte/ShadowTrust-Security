# Shadow Trust — SOC Honeynet Platform
## Complete Technical Study Document
### For Research Paper & Report Preparation

---

## TABLE OF CONTENTS

1. [Project Overview](#1-project-overview)
2. [System Architecture](#2-system-architecture)
3. [Tech Stack — What & Why](#3-tech-stack--what--why)
4. [Data Flow & Pipelines](#4-data-flow--pipelines)
5. [Frontend Pages — Complete Reference](#5-frontend-pages--complete-reference)
6. [Backend API Endpoints — Complete Reference](#6-backend-api-endpoints--complete-reference)
7. [Database Models & Schema](#7-database-models--schema)
8. [Backend Services & Algorithms](#8-backend-services--algorithms)
9. [Libraries & Dependencies](#9-libraries--dependencies)
10. [Infrastructure & DevOps](#10-infrastructure--devops)
11. [Security Architecture & RBAC](#11-security-architecture--rbac)
12. [AWS Integration](#12-aws-integration)
13. [Sector Intelligence System](#13-sector-intelligence-system)
14. [Malware Analysis Pipeline](#14-malware-analysis-pipeline)
15. [Virtual Lab (VM Provisioning)](#15-virtual-lab-vm-provisioning)
16. [Scripts Reference](#16-scripts-reference)
17. [Connections & Integration Map](#17-connections--integration-map)
18. [Key Algorithms](#18-key-algorithms)
19. [Research Contribution Summary](#19-research-contribution-summary)

---

## 1. PROJECT OVERVIEW

**Project Name:** Shadow Trust — AI-Powered SOC Honeynet Platform
**Version:** 2.0.0
**Type:** Full-Stack Cybersecurity Research & Operations Platform
**Purpose:** A Security Operations Center (SOC) platform that deploys honeypot infrastructure to attract, monitor, and analyze cyber attackers in real time. Combines traditional honeypot telemetry with AI-driven behavioral analysis, malware dissection, cloud infrastructure orchestration, and sector-level threat intelligence.

### Core Value Propositions
1. **Deception Technology** — Fake-but-realistic web portals across 9 critical infrastructure sectors (education, defence, finance, etc.) trap attackers and capture their TTPs (Tactics, Techniques & Procedures).
2. **Automated Threat Intelligence** — AWS CloudTrail, VPC Flow Logs, and S3 are continuously synced; events are parsed, enriched with GeoIP data, classified by attack type, and mapped to the MITRE ATT&CK framework — all automatically.
3. **Malware Analysis Pipeline** — Files uploaded or captured from honeypots pass through a 4-stage pipeline: static binary analysis → sandbox behavior simulation → APK decompilation → secret/credential extraction.
4. **Virtual Lab** — Analysts can provision real AWS EC2 instances (Kali Linux, Windows Server, Windows Analysis) on demand and access them through a browser-embedded Guacamole RDP/SSH terminal.
5. **Credential Vault** — Multi-clearance RBAC system with admin-issued credentials delivered over email (SMTP) and WhatsApp (Twilio), with full audit trails.

---

## 2. SYSTEM ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SHADOW TRUST PLATFORM                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌──────────────┐     ┌──────────────────────────────────────────────┐    │
│   │   ATTACKER   │────▶│          HONEYPOT LAYER                      │    │
│   └──────────────┘     │  9 Sector Portals (HTML + Tracking Snippet) │    │
│                         │  Real-time POST to /sectors/events/ingest   │    │
│                         └────────────────────┬─────────────────────────┘   │
│                                              │                              │
│   ┌──────────────┐     ┌───────────────────▼──────────────────────────┐   │
│   │  AWS CLOUD   │────▶│          BACKEND (FastAPI / Python 3.11)     │   │
│   │  (EC2, S3,   │     │                                               │   │
│   │  CloudTrail, │     │  ┌─────────┐  ┌──────────┐  ┌────────────┐  │   │
│   │  VPC Logs,   │     │  │  Auth   │  │ Analytics│  │  Malware   │  │   │
│   │  IAM)        │     │  │ Service │  │ Engine   │  │  Pipeline  │  │   │
│   └──────────────┘     │  └─────────┘  └──────────┘  └────────────┘  │   │
│                         │  ┌─────────┐  ┌──────────┐  ┌────────────┐  │   │
│                         │  │  Sector │  │  MITRE   │  │    GNN     │  │   │
│                         │  │  Intel  │  │  Mapper  │  │  Profiler  │  │   │
│                         │  └─────────┘  └──────────┘  └────────────┘  │   │
│                         │                                               │   │
│                         │  SQLite (ingestion.db) — async SQLAlchemy   │   │
│                         └───────────────────┬───────────────────────────┘   │
│                                             │                               │
│   ┌──────────────────────────────────────▼──────────────────────────────┐  │
│   │                     FRONTEND (Nginx + HTML/JS)                       │  │
│   │   Dashboard | Events | Admin | Sectors | VM Lab | Malware | MITRE   │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │              SUPPORTING SERVICES                                     │  │
│   │   MobSF (APK Analysis) | Guacamole (RDP/SSH) | Twilio (WhatsApp)   │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Component Breakdown

| Component | Technology | Role |
|-----------|-----------|------|
| Backend API | FastAPI (Python 3.11) | All business logic, event processing, ML inference |
| Database | SQLite + aiosqlite + SQLAlchemy | Persistent storage for all events, users, VMs |
| Frontend | HTML5 + Vanilla JS | SOC analyst dashboard and control plane |
| Static Server | Nginx / Python http.server | Serve frontend HTML/JS/CSS files |
| APK Analysis | MobSF (Flask microservice) | Mobile app decompilation and analysis |
| Remote Access | Apache Guacamole | Browser-based RDP/SSH to EC2 instances |
| Notifications | Twilio API | WhatsApp credential delivery |
| Cloud | AWS (EC2, S3, IAM, CloudTrail) | Real honeypot infrastructure, log aggregation |
| Containerization | Docker + Docker Compose | 5-service production deployment |

---

## 3. TECH STACK — WHAT & WHY

### Backend

| Technology | Version | Why Used |
|-----------|---------|----------|
| **Python 3.11** | 3.11.x | Modern asyncio support, type hints, mature security libraries, dominant in ML/security tooling |
| **FastAPI** | ≥0.109 | Async-native, auto-generates OpenAPI docs, Pydantic validation, 3x faster than Flask for I/O-heavy SOC workloads |
| **SQLAlchemy** | ≥2.0 | Async ORM with full type safety; 2.0 API is cleaner for async patterns than 1.x |
| **aiosqlite** | ≥0.19 | Async SQLite driver — allows non-blocking DB queries inside FastAPI's async event loop |
| **Pydantic v2** | ≥2.6 | Request/response validation; v2 is 5-17x faster than v1 with Rust core |
| **uvicorn** | ≥0.27 | Production ASGI server — handles concurrent WebSocket + HTTP with single-threaded async |
| **bcrypt** + **passlib** | — | Industry-standard password hashing; bcrypt adds salted cost factor to prevent rainbow table attacks |
| **PyJWT** | 2.10.1 | Compact JSON Web Token generation and validation for stateless auth |
| **boto3** | ≥1.34 | Official AWS SDK; used for EC2 provisioning, S3 sync, CloudTrail log fetching |
| **botocore Config** | — | Added custom timeout (8s connect / 20s read) to prevent indefinite hanging on AWS API calls |
| **requests** | ≥2.31 | Sync HTTP client for MobSF proxy and external service calls |
| **Twilio** | ≥9.0 | WhatsApp Business API for credential delivery; more reliable in enterprise environments than SMS |
| **python-dotenv** | 1.0.0 | Loads .env files so secrets never live in source code |
| **python-multipart** | 0.0.9 | Enables binary file upload parsing (multipart/form-data) for malware samples |

### Frontend

| Technology | Why Used |
|-----------|----------|
| **HTML5 + Vanilla JS** | Zero build-step — instant reload, no npm, no Webpack. Critical for a SOC tool that must work on air-gapped networks without internet CDN |
| **Chart.js** | Client-side charting with zero server-side rendering; used for attack timelines, donut charts, heatmaps, and geo bar charts |
| **Fetch API** | Native browser async HTTP — replaces jQuery AJAX with modern Promise-based interface |
| **AOS (Animate on Scroll)** | Lightweight animation library for landing pages (features, architecture, usecases) |
| **Font Awesome** | Icon library; all security/network UI icons (shields, terminals, clouds) |
| **JetBrains Mono** | Monospace font for terminal-style log displays and code blocks |
| **ES6 Modules** | `import/export` used in JS files for clean dependency management without bundler |

### Infrastructure

| Technology | Why Used |
|-----------|----------|
| **Docker** | Reproducible environments; analysts can spin up the entire platform with one command regardless of OS |
| **Docker Compose** | Orchestrates 5 services (backend, frontend, MobSF, node collector, worker) with defined networking and dependency order |
| **Nginx 1.25-alpine** | Minimal production web server for static assets; handles compression, caching headers |
| **SQLite** | Chosen over PostgreSQL for portability — the DB is a single file, deployable on a laptop for field operations with no server setup |
| **Apache Guacamole** | Browser-native RDP/SSH via WebSocket proxy — analysts access Windows/Kali VMs without installing any local client |

---

## 4. DATA FLOW & PIPELINES

### 4.1 Honeypot Event Capture Flow

```
Attacker visits demo portal (e.g., finance-portal.html)
         │
         ▼
Embedded JS Tracking Snippet (IIFE)
  - Detects XSS: /<script|javascript:/i.test(window.location.href)
  - Detects SQLi: /union\s+select|select.*from|drop\s+table/i
  - Detects path traversal: /\.\.\//
  - Monitors form submissions for suspicious payloads
         │
         ▼ POST /api/v1/sectors/events/ingest
  { api_key, attack_type, attacker_ip, country, ioc_value, risk_score,
    user_agent, request_path, commands }
         │
         ▼ Backend: sectors.py endpoint
  - Validates api_key against sector_targets table
  - Resolves sector_key and target_id
  - Writes SectorEvent to SQLite
         │
         ▼ sectors.html dashboard
  GET /api/v1/sectors/{key}/stats
  - Aggregates: top attackers, geo origins, attack types,
    timeline (24h hourly buckets), active alerts, IOCs
```

### 4.2 AWS S3 Log Sync Pipeline

```
AWS S3 Bucket (honeypot logs: CloudTrail, VPC Flow, JSON events)
         │
         ▼ POST /api/v1/aws/pull-s3  (triggered by analyst)
aws.py endpoint
  - Fetches file list from S3 (boto3 list_objects_v2)
  - Skips binary files (.png, .jpg, .zip, .exe, .pdf, etc.)
  - Skips files already in s3_sync_state table (dedup)
  - Downloads eligible files
         │
         ▼ aws_telemetry_service.py
  TelemetryEngine.run_pipeline()
  - parse_raw_log(content) → normalised event dict
  - enrich_with_geoip(ip) → country, ASN, coordinates
  - classify_attack_type(payload) → SSH_BRUTE, SQLi, XSS, RCE, SCAN...
  - map_to_mitre(attack_type) → tactic, technique_id
  - calculate_risk_score(event) → 0.0–10.0 float
         │
         ▼ DB writes (async SQLAlchemy)
  - RawEventModel (raw log data)
  - StructuredEvent (normalised)
  - AttackerSession (aggregated per IP)
  - IOC (extracted indicators)
  - CapturedPayload (commands, file hashes)
  - Alert (high risk_score events)
  - s3_sync_state (mark file as processed)
```

### 4.3 Malware Analysis Pipeline

```
Analyst uploads file (multipart/form-data)
         │
         ▼ POST /api/v1/malware/upload
         │
    ┌────┴──────────────────────────────────┐
    │                                       │
    ▼                                       ▼
static_analyzer.py               apk_engine.py (if .apk)
  - File type detection            - Decompile APK
  - PE/ELF/Mach-O header parse     - Parse AndroidManifest.xml
  - Import table extraction        - Extract permissions
  - Section entropy analysis       - Detect dangerous APIs
  - Packer detection               - List network endpoints
  - Suspicious API classification  - Detect hardcoded secrets
  - String extraction
    │
    ▼
sandbox_engine.py
  - Map imports → behavioral signatures
  - Classify family (Ransomware/RAT/Botnet/Dropper/Worm/Spyware)
  - Map signatures → MITRE ATT&CK techniques
  - Calculate composite risk score
  - Check CAPE sandbox (if available)
    │
    ▼
secret_detector.py
  - Scan strings for AWS keys, Google API keys
  - Detect private keys (RSA/DSA/EC PEM blocks)
  - Find database connection strings
  - Extract OAuth tokens / passwords
    │
    ▼ Response JSON
  { sha256, file_type, risk_score, family, mitre_techniques,
    suspicious_apis, packed, sections, secrets, imports }
```

### 4.4 VM Lab Provisioning Flow

```
Analyst clicks PROVISION on vm_lab.html
         │
         ▼ POST /api/v1/labs/start
  { ami_id, instance_type, subnet_id, protocol, aws_access_key, aws_secret_key }
         │
         ▼ session_manager.py → start_lab_provisioning()
  1. Generate lab_id (UUID4)
  2. Call aws_orchestrator.launch_analysis_vm(ami_id, ...)
     - boto3 ec2.run_instances(...)
     - Returns instance_id immediately
  3. Write GLOBAL_LAB_STATE[lab_id] = {status: "PROVISIONING"}
  4. Persist state to .lab_state.json (survives server restarts)
  5. Insert VMInstance row in SQLite
  6. Return {lab_id, instance_id, status: "provisioning"} to frontend
         │
         ▼ Background Task: process_lab_readiness(lab_id, instance_id)
  Stage 1 (up to 5 min): Poll ec2.describe_instances()
    - Wait for state == 'running'
    - Extract PublicIpAddress / PrivateIpAddress
  Stage 2 (up to 12 min): Poll ec2.describe_instance_status()
    - Wait for SystemStatus == 'ok' AND InstanceStatus == 'ok'
    - (Windows cold boot takes 8–12 min)
  Stage 3: Register Guacamole connection
    - guacamole_service.create_connection(lab_id, ip, protocol, port, username, password)
    - Returns guac_connection_id
  Stage 4: Mark GLOBAL_LAB_STATE[lab_id] = {status: "READY"}
         │
         ▼ Frontend polling: GET /api/v1/labs/status/{lab_id} every 5s
  When status == "READY":
    - Fetch Guacamole auth token
    - Load Guacamole iframe: http://localhost:8080/guacamole/?token=...#/client/{b64Id}
    - Analyst sees live Windows/Kali desktop in browser
```

### 4.5 Authentication Flow

```
User submits login form (email + password)
         │
         ▼ POST /api/v1/auth/login (OAuth2 form data: username, password)
         │
auth_service.py → login()
  1. Query User by email (case-insensitive)
  2. bcrypt.verify(plain_password, user.password_hash)
  3. Check user.status == ACTIVE
  4. Check user.clearance_level matches required minimum
  5. Generate JWT:
     { sub: email, role: role, clearance: level, user_id: uuid, exp: now+24h }
  6. Sign with HS256 (SECRET_KEY from .env)
         │
         ▼ Response: { access_token, token_type: "bearer", user: {...} }
         │
Frontend stores: localStorage['token'] = access_token
         │
All subsequent requests:
  Authorization: Bearer <token>
         │
Backend dependency: get_current_active_user()
  - decode JWT → payload
  - require_clearance(min_level) → raises 403 if insufficient
```

---

## 5. FRONTEND PAGES — COMPLETE REFERENCE

### Landing & Public Pages

| Page | File | Description |
|------|------|-------------|
| Landing | `index.html` | Marketing homepage with animated hero, features overview, use cases, tech stack showcase, and CTA buttons. Uses AOS scroll animations. |
| Features | `features.html` | Detailed feature breakdown with icons and descriptions for each major system component. Static, no API calls. |
| Architecture | `architecture.html` | System architecture diagram and technical explanation. Visual data flow with connection diagrams. |
| Use Cases | `usecases.html` | Illustrates 6 deployment scenarios: Red Team, Threat Research, SOC Training, Critical Infrastructure, Academic Research, Law Enforcement. |
| Status | `status.html` | Live system health panel. Polls backend health endpoint and displays service status with uptime, version info, and dependency checks. |
| Docs | `docs.html` | API documentation reference. Lists all endpoints, request/response schemas, authentication methods. |

### Authentication Pages

| Page | File | Description |
|------|------|-------------|
| Login | `login.html` | Primary login portal. Two tabs: Sign In (OAuth2 form) and Request Access (registration). Handles credential token activation flow. Dev bypass button visible in dev mode. |
| Register | `register.html` | New user self-registration. Collects name, email, department, clearance level requested. Account goes to PENDING state until admin approval. |
| Admin Login | `admin_login.html` | Separate admin authentication portal with system code verification. Higher clearance required. |
| Forgot Password | `forgot_password.html` | Password reset request form. Sends OTP to registered email. |

### Main SOC Dashboard

| Page | File | Description |
|------|------|-------------|
| Dashboard | `dashboard.html` | Real-time SOC overview. Shows: total attacks (24h), unique attackers, active nodes, risk score distribution, live attack map (Chart.js geo visualization), traffic timeline, top attack types (donut), recent event feed, alerts panel. Auto-refreshes every 30s. |
| Events | `events.html` | Paginated raw event log viewer. Filter by attack type, date range, protocol, severity. Each row expandable for full JSON payload. "Analyze with AI" button calls `/events/{id}/analyze`. |
| Geo Intelligence | `geo.html` | World map with attack origin heatmap. Country-level aggregation. Bar chart for top 10 source countries. ASN attribution table. |
| Graphs | `graphs.html` | 10+ advanced analytics charts: temporal attack patterns, protocol distribution, attacker persistence (returning IPs), payload size distribution, attack velocity (attacks/hour), command frequency, port targeting heatmap. |
| MITRE Matrix | `mitre.html` | Interactive MITRE ATT&CK framework visualization. Highlights active tactics/techniques from real captured events. Color-coded by frequency. Links to ATT&CK wiki for each technique. |
| Behavior | `behavior.html` | GNN-based behavioral profiling. Shows attacker risk profiles, temporal patterns (time-of-day attack clustering), persistence scores, TTP evolution over sessions. |

### Infrastructure Pages

| Page | File | Description |
|------|------|-------------|
| Nodes | `nodes.html` | Honeypot node management. Lists all deployed nodes with status (online/offline), uptime, attack counts, risk level. Node type badges (SSH, HTTP, FTP, Telnet). Click for details. |
| Node Details | `node_details.html` | Per-node deep dive. Shows metrics, event history, captured sessions, top attackers, timeline charts. |
| Sectors | `sectors.html` | Sector intelligence hub. 9 sector cards (Education, Defence, Medicare, Commerce, Finance, Government, Energy, Telecom, Transport). Click any sector to open modal with: Dashboard tab (real-time attack stats) + Manage Targets tab (add URLs/IPs, get JS tracking snippet). |
| AWS Connection | `aws_connection.html` | AWS credential configuration. Fields: Access Key, Secret Key, Region, S3 Bucket, IAM Profile, Subnet ID, AMI IDs (Windows/Linux/Malware). Three action buttons: Validate Keys (STS test), Pull S3 Logs, Save Configuration. Plus Force Re-Pull for already-processed files. |
| VM Lab | `vm_lab.html` | Virtual lab provisioning. Three VM cards: Windows Server Baseline (RDP), Kali Linux Intranet Node (SSH), Windows Analysis Environment (RDP). Shows: vCPU/RAM usage bars, instance count. Provision button → BOOTING → CONNECT TERMINAL → embedded Guacamole iframe. |
| VM Session | `vm_session.html` | Dedicated full-screen VM session view. Loads Guacamole in fullscreen iframe. Used when opened from `openConsole()`. |
| Config | `config.html` | System configuration dashboard. Manages system-level settings stored in system_config table. |

### Analysis Tools

| Page | File | Description |
|------|------|-------------|
| Malware | `malware.html` | Malware analysis portal. Drag-and-drop file upload. Live analysis progress bar. Results show: risk score gauge, family classification badge, MITRE techniques table, suspicious imports list, packed/unpacked indicator, section entropy bar chart, extracted secrets panel. |
| APK Inspector | `apk.html` | Android APK analysis UI. Upload .apk → decompile → shows: permissions, dangerous API calls, hardcoded URLs/IPs, potential malware behaviors, manifest data. Proxies to MobSF service. |
| URL Scanner | `urlscan.html` | Real-time URL threat assessment. Paste URL → scans for: phishing indicators, malware distribution, suspicious redirects, domain reputation, SSL certificate validity, HTTP security headers. |
| Binary Analysis | `malware.html` (section) | Sub-section within malware page for PE/ELF/Mach-O static analysis results. Shows: architecture, compiler fingerprint, section table, import table with risk classification. |

### Administration Pages

| Page | File | Description |
|------|------|-------------|
| Admin | `admin.html` | Admin control panel. Overview metrics (users, active sessions, credentials issued, total events). Tabs: User Management (approve/reject pending users, elevate clearance), System Settings, Backup/Export. |
| Access Control | `access_control.html` | Fine-grained RBAC management. Approve/deny access requests. View clearance levels, roles, departments. Access audit log (who approved what, when). |
| Credentials | `credentials.html` | Credential administration. Lists all issued credential tokens with status (active/used/expired). Filter by user/date. |
| Credential Mgmt | `credential_mgmt.html` | Issue new credentials workflow. Select user → choose delivery method (email / WhatsApp) → set expiry → custom message. Preview before sending. |
| Profile | `profile.html` | Current user profile page. Shows: name, email, department, clearance level, role, last login. Password change form. |

### Demo Portals (Honeypots)

All in `/frontend/demo/` — 9 realistic fake websites with embedded Shadow Trust tracking snippet:

| Portal | File | Simulates |
|--------|------|-----------|
| Education | `edu-portal.html` | Greenfield University Student Portal (course catalog, login, grades) |
| Defence | `defence-portal.html` | National Defence Command Portal (dark theme, classified aesthetics) |
| Medicare | `medicare-portal.html` | MedCare Health Patient Portal (appointment booking, records) |
| Commerce | `commerce-portal.html` | NexMart Online Store (product catalog, cart, checkout) |
| Finance | `finance-portal.html` | NexBank Online Banking (account dashboard, transfers) |
| Government | `gov-portal.html` | GovConnect Citizen Services (tax, licenses, forms) |
| Energy | `energy-portal.html` | PowerGrid National (grid monitoring, usage stats) |
| Telecom | `telecom-portal.html` | NexTel Operations (data usage, plans, billing) |
| Transport | `transport-portal.html` | TransitHub National Transport (live departures, booking) |

**Embedded Tracking Snippet (in every demo portal):**
```javascript
(function(){
  var ST_KEY = "<uuid-api-key>";  // Unique per target, stored in sector_targets.api_key
  var ST_URL = "http://localhost:8000/api/v1/sectors/events/ingest";
  function s(t, x) {
    fetch(ST_URL, { method: "POST", headers: {"Content-Type":"application/json"},
      body: JSON.stringify(Object.assign({api_key:ST_KEY, attack_type:t,
        user_agent:navigator.userAgent, request_path:window.location.pathname}, x||{}))
    }).catch(function(){});
  }
  var u = window.location.href;
  if (/<script|javascript:/i.test(u)) s("XSS", {ioc_value:u.slice(0,200), ioc_type:"url", risk_score:8});
  if (/union\s+select|select.*from|drop\s+table/i.test(u)) s("SQLi", {..., risk_score:9});
  window.ShadowTrust = { report: s };
})();
```

---

## 6. BACKEND API ENDPOINTS — COMPLETE REFERENCE

Base URL: `http://localhost:8000/api/v1`

### Authentication (`/auth`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/login` | None | OAuth2 password flow. Body: `username` (email), `password`. Returns JWT. |
| POST | `/auth/register` | None | Self-registration. Returns pending user object. |
| POST | `/auth/verify-otp` | None | OTP verification. Body: `email`, `otp`. Returns JWT on success. |
| POST | `/auth/forgot-password` | None | Send OTP to email. Body: `email`. |
| POST | `/auth/reset-password` | None | Apply new password. Body: `token`, `new_password`. |
| POST | `/auth/admin-login` | None | Admin-specific login with system code. |
| POST | `/auth/activate-account` | None | Activate account via credential token. Body: `credential_token`, `new_password`. |

### Dashboard (`/dashboard`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/dashboard/stats` | JWT (L1+) | Returns: total_attacks, unique_attackers, active_nodes, recent_events[], traffic_chart[], top_attack_types[], alerts[], risk_distribution. |

### Users (`/users`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/users/` | JWT (OVERSEER+) | List all users with status, clearance, role. |
| GET | `/users/me` | JWT (any) | Current user profile. |
| PUT | `/users/{user_id}` | JWT (ADMIN) | Update user (clearance, role, status). |
| DELETE | `/users/{user_id}` | JWT (SUPER_ADMIN) | Delete user. |
| POST | `/users/approve/{user_id}` | JWT (ADMIN) | Approve pending registration. |

### Events (`/events`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/events/ingest` | JWT / API Key | Ingest raw honeypot event. Parses, enriches, stores. |
| GET | `/events/` | JWT (L1+) | List events. Query params: `limit`, `offset`, `type`, `severity`. |
| GET | `/events/{event_id}/analyze` | JWT (L2+) | AI-powered deep analysis of specific event (MITRE mapping, attacker profile, recommendations). |

### Logs (`/logs`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/logs/` | JWT / Internal | Raw log ingestion with telemetry pipeline processing. |

### Analytics (`/analytics`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/analytics/graphs` | JWT (L1+) | Returns 10+ datasets: temporal_patterns, protocol_distribution, attacker_persistence, payload_sizes, attack_velocity, command_frequency, port_heatmap, geo_aggregation, session_durations, risk_timeline. |
| GET | `/analytics/credentials` | JWT (ADMIN) | Credential issuance KPIs: total_issued, pending, active, expired. |

### AWS (`/aws`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/aws/config` | JWT (L2+) | Load saved AWS configuration from system_config table. |
| POST | `/aws/config` | JWT (L2+) | Save AWS credentials/config to system_config (encrypted at rest). |
| POST | `/aws/test` | JWT (L2+) | Validate AWS credentials via STS GetCallerIdentity. Returns account ID, ARN. |
| POST | `/aws/debug` | JWT (L2+) | Extended AWS connectivity test: STS + EC2 + S3 + IAM describe calls. |
| POST | `/aws/pull-s3` | JWT (L2+) | Pull and process log files from S3 bucket. Body: `{bucket, prefix, force_repull}`. |

### Labs (`/labs`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/labs/start` | JWT (L2+) | Provision EC2 + register Guacamole session. Returns `lab_id` immediately. Background task handles readiness. |
| POST | `/labs/stop` | JWT (L2+) | Terminate EC2 instance + clean Guacamole connection. |
| GET | `/labs/status/{lab_id}` | JWT (L1+) | Poll lab status: PROVISIONING → READY / ERROR. Returns guac auth token when READY. |
| GET | `/labs/cluster-metrics` | JWT (L1+) | Live vCPU/RAM usage across all active instances. |

### Malware (`/malware`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/malware/upload` | JWT (L2+) | Upload binary for full 4-stage analysis. Returns cached result if SHA-256 already analysed. |
| POST | `/malware/upload-apk` | JWT (L2+) | Upload APK for MobSF analysis. |
| GET | `/malware/analyze/{sha256}` | JWT (L1+) | Retrieve cached analysis result by file hash. |
| GET | `/malware/history` | JWT (L1+) | List all analysed files with summary. |

### Sectors (`/sectors`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/sectors` | JWT (L1+) | List all 9 sector definitions with metadata. |
| GET | `/sectors/{key}/targets` | JWT (L1+) | List monitored targets for a sector. |
| POST | `/sectors/{key}/targets` | JWT (L2+) | Add a URL/IP to a sector's monitoring list. Returns `api_key` for JS snippet. |
| DELETE | `/sectors/{key}/targets/{id}` | JWT (L2+) | Remove a target from monitoring. |
| POST | `/sectors/events/ingest` | **PUBLIC** (api_key) | Accept attack event from JS tracking snippet. Auth via `api_key` field (no JWT needed — runs on external websites). |
| GET | `/sectors/{key}/stats` | JWT (L1+) | Aggregated stats for sector dashboard: attacks count, top_attackers[], geo_origins[], iocs[], captured_commands[], active_alerts, attack_breakdown{}, timeline[24h]. |

### MITRE (`/mitre`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/mitre/` | JWT (L1+) | Dynamic MITRE ATT&CK matrix built from actual captured events. Returns: tactics[], techniques[] with frequency counts and event references. |

### Behavior (`/behavior`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/behavior/profile` | JWT (L2+) | Temporal GNN threat profiler results. Returns: risk_profiles[], temporal_patterns{}, persistence_scores{}, ttp_evolution[]. |

### Credentials (`/credentials`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/credentials/issue` | JWT (ADMIN) | Issue one-time credential token for a user. Body: `{user_id, delivery_method, expires_in_hours, custom_message}`. |
| POST | `/credentials/resend` | JWT (ADMIN) | Resend credential delivery (email/WhatsApp). |
| GET | `/credentials/token/{token}` | None | Validate credential token status. Used by login page for account activation flow. |
| GET | `/credentials/audit` | JWT (ADMIN) | Full credential audit log. |

### VM (`/vm`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/vm/launch` | JWT (L2+) | Legacy EC2 launch via AWSOrchestrator directly. |
| POST | `/vm/{instance_id}/terminate` | JWT (L2+) | Terminate EC2 instance. |
| POST | `/vm/{instance_id}/status` | JWT (L1+) | Get raw EC2 instance state. |

### Admin (`/admin`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/admin/health` | JWT (ADMIN) | System health check: DB status, service versions, memory usage, uptime. |
| GET | `/admin/backup` | JWT (SUPER_ADMIN) | Export all data as JSON backup. |
| GET | `/admin/settings` | JWT (ADMIN) | Load system settings from DB. |
| POST | `/admin/settings` | JWT (SUPER_ADMIN) | Update system settings. |

---

## 7. DATABASE MODELS & SCHEMA

**Database File:** `backend/ingestion.db` (SQLite)
**ORM:** SQLAlchemy 2.0 (async)
**Driver:** aiosqlite
**Auto-migration:** `Base.metadata.create_all(bind=engine)` — only creates missing tables, never drops existing ones.

### Schema Diagram

```
users ────────────────────── clearance_level: 1, 2, 3
  │                          role: SUPER_ADMIN, ANALYST, AUDITOR, OPERATIVE, SPECIALIST, OVERSEER
  │                          status: ACTIVE, PENDING, BLOCKED
  ├── credential_tokens       (one-time activation tokens per user)
  ├── credential_audit_log    (every issuance/delivery event)
  ├── access_logs             (admin actions: APPROVE/DENY/REVOKE/ELEVATE)
  └── admin_activity_log      (admin_id, action, affected_user, ip, result)

nodes ── NodeMetrics          (one metrics row per node, updated on each event)
  └── alerts                  (severity: CRITICAL/HIGH/MEDIUM/LOW, status: NEW/INVESTIGATING/RESOLVED)

raw_events ─── structured_events
  └── attacker_sessions       (aggregated per attacker IP)
      └── captured_payloads   (individual commands/files per session)
      └── iocs                (ip/domain/hash indicators extracted from events)

attacks ── (links to raw_event, stores mitre_tactic, mitre_id, severity)

sector_targets ─── sector_events   (many-to-many via target_id FK)
  sector_key ∈ {edu, defence, medicare, commerce, finance, gov, energy, telecom, transport}

vm_profiles ─── vm_instances   (template → launched instance)

s3_sync_state   (file_key → processed_at, prevents double-processing)

system_settings / system_config   (key-value store for platform config)
```

### Complete Model Definitions

```python
# users
class User:
    id: UUID (PK)
    username, email (unique)
    password_hash: String (bcrypt)
    first_name, last_name, department
    clearance_level: Integer (1=basic, 2=analyst, 3=admin)
    requested_clearance_level: Integer
    role: Enum(SUPER_ADMIN, ANALYST, AUDITOR, OPERATIVE, SPECIALIST, OVERSEER)
    status: Enum(ACTIVE, PENDING, BLOCKED)
    otp_code, otp_expires_at   # 6-digit OTP for 2FA
    system_code                # Admin login code
    created_at, last_login

# raw_events (core honeypot telemetry)
class RawEventModel:
    id: UUID (PK)
    timestamp: DateTime
    attacker_ip: String (indexed)
    target_port: Integer
    protocol: String
    honeypot_type: String  # cowrie, dionaea, glastopf, etc.
    session_id: String
    event_type: String     # LOGIN_ATTEMPT, COMMAND_EXECUTED, FILE_UPLOAD, etc.
    commands: JSON         # List of commands run
    uploaded_files: JSON   # Files dropped by attacker
    ports_scanned: JSON    # For port scanner detection
    geoip_data: JSON       # {country, city, lat, lon, asn, org}
    risk_score: Float      # 0.0–10.0
    raw_payload: Text
    sync_status: String    # pending / processed / failed
    signature: String      # SHA-256 of payload for deduplication

# sector intelligence
class SectorTarget:
    id: UUID (PK)
    sector_key: String (indexed)  # e.g., "finance"
    name, url, ip, description
    api_key: UUID (unique)         # Used by JS snippet for auth
    active: Boolean
    added_at: DateTime

class SectorEvent:
    id: UUID (PK)
    sector_key, target_id (FK → sector_targets)
    target_url
    attacker_ip, country
    attack_type: String  # XSS, SQLi, RCE, BruteForce, Scan, Other
    commands: JSON
    ioc_value, ioc_type
    risk_score: Float
    user_agent, request_path
    raw_payload: Text
    timestamp: DateTime (indexed)
```

---

## 8. BACKEND SERVICES & ALGORITHMS

### 8.1 Static Binary Analyzer (`static_analyzer.py`)

**Supported formats:** PE (Windows .exe/.dll), ELF (Linux), Mach-O (macOS)

**Algorithm:**
1. **File type detection** — check magic bytes: `MZ` header (PE), `\x7fELF` (ELF), `\xfe\xed\xfa` (Mach-O)
2. **PE analysis:**
   - Parse DOS/PE header with `pefile` or manual offset reading
   - Extract import table → list all imported DLLs and functions
   - Extract export table (for DLLs)
   - Analyse sections: `.text`, `.data`, `.rsrc`, `.pdata`
   - Calculate Shannon entropy per section (> 7.0 = likely packed/encrypted)
3. **Packer detection** — match section names against known signatures: `UPX0/UPX1` (UPX), `.MPRESS1` (MPRESS), `.themida`, `.vmp0`, `_winlicense`
4. **Suspicious API classification** into 6 categories:
   - `INJECTION`: `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `NtUnmapViewOfSection`
   - `NETWORK`: `socket`, `connect`, `WSAStartup`, `InternetOpen`, `HttpSendRequest`
   - `PERSISTENCE`: `RegSetValueEx`, `CreateService`, `SHGetSpecialFolderPath`
   - `PRIV_ESC`: `AdjustTokenPrivileges`, `LookupPrivilegeValue`, `OpenProcessToken`
   - `CRYPTO`: `CryptEncrypt`, `BCryptEncrypt`, `RijndaelEncrypt`
   - `EVASION`: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`, `Sleep`
5. **String extraction** — scan binary for printable ASCII sequences ≥4 chars
6. **Risk scoring** — weighted sum: packer_detected (+3), high_entropy (+2 per section > 7.0), each suspicious category (+1 each)

### 8.2 Sandbox Engine (`sandbox_engine.py`)

**Algorithm (heuristic simulation when CAPE is offline):**
1. Receive import list from static_analyzer
2. Build **behavioral signature set** by mapping imports → signatures:
   - `CreateRemoteThread` → `process_injection`
   - `RegSetValueEx` → `registry_persistence`
   - `CryptEncrypt` → `file_encryption`
   - `socket + connect` → `c2_communication`
   - etc. (50+ mappings)
3. **Family classification** using signature voting:
   - `file_encryption + c2_communication + ransom_note` → `Ransomware`
   - `keylogging + screenshot_capture + c2` → `RAT`
   - `dropper_routine + c2 + persistence` → `Botnet`
   - `self_replication + network_scan` → `Worm`
4. **MITRE mapping** — each signature maps to a technique:
   - `process_injection` → T1055 (Process Injection) under TA0005 (Defense Evasion)
   - `registry_persistence` → T1547.001 (Registry Run Keys)
   - `file_encryption` → T1486 (Data Encrypted for Impact)
5. **Composite risk score** = base score + (0.5 × num_signatures) + (2.0 if family == Ransomware/RAT)

### 8.3 Temporal GNN Profiler (`ai_engine/gnn_profiler.py`)

**Algorithm:**
1. **Graph construction** — for each attacker IP, build a temporal graph:
   - Nodes: individual events (with feature vectors: timestamp, attack_type encoded, risk_score, port, protocol)
   - Edges: sequential (event_n → event_n+1), temporal (events within 5-min window connected)
2. **Temporal features:** time-of-day (binned into 4 epochs), day-of-week, inter-event delay distribution
3. **GNN inference:** message passing over the temporal graph computes:
   - `persistence_score` — proportion of sessions returning after >24h gap
   - `sophistication_score` — diversity of attack types used
   - `risk_profile` — composite classification: Opportunistic / Targeted / APT / Script Kiddie
4. **Clustering** — DBSCAN or k-means on feature vectors to identify attacker groups with similar TTPs
5. **Output:** per-IP risk profiles with MITRE tactic distribution

### 8.4 Credential Service (`credential_service.py`)

**Key functions:**
- `issue_credentials()` — generates UUID4 token + temporary 12-char alphanumeric password
- Token stored in `credential_tokens` table with expiry (default 48h)
- Email delivery: SMTP with HTML Jinja2 template (`credential_email.html`)
- WhatsApp delivery: Twilio `messages.create(to="whatsapp:+91...", body="...")`
- Rate limiting: max 20 tokens per admin per hour (checked via COUNT query on `credential_audit_log`)
- Full audit: every issue/resend/validation event written to `credential_audit_log`

### 8.5 AWS Telemetry Pipeline (`aws_telemetry_service.py`)

**Pipeline stages:**
1. `fetch_s3_objects()` — `boto3.s3.list_objects_v2(Bucket, Prefix)` with pagination
2. `filter_eligible()` — skip binaries, skip already-processed (s3_sync_state), skip empty files
3. `download_and_parse()` — detect format: CloudTrail JSON, VPC Flow Log (space-delimited), raw syslog
4. `enrich_geoip()` — MaxMind GeoLite2 or ip-api.com lookup for attacker IP → country, city, ASN
5. `classify_attack()` — regex + heuristic on log content → SSH_BRUTE, SQLi, XSS, RCE, SCAN, UPLOAD
6. `map_mitre()` — attack_type → MITRE tactic/technique mapping table
7. `score_risk()` — 0.0–10.0 float based on: attack severity, repeated IPs, critical port targeting
8. `persist()` — write to RawEventModel, StructuredEvent, AttackerSession, IOC, CapturedPayload

### 8.6 MITRE ATT&CK Mapper

**Mapping table (selected entries):**

| Attack Type | Tactic | Technique |
|-------------|--------|-----------|
| SSH_BRUTE | Initial Access | T1110.001 — Brute Force: Password Guessing |
| SQLi | Initial Access | T1190 — Exploit Public-Facing Application |
| XSS | Execution | T1059.007 — Command and Scripting Interpreter: JavaScript |
| RCE | Execution | T1059 — Command and Scripting Interpreter |
| PATH_TRAVERSAL | Discovery | T1083 — File and Directory Discovery |
| FILE_UPLOAD | Persistence | T1505.003 — Web Shell |
| PORT_SCAN | Discovery | T1046 — Network Service Scanning |
| CRED_DUMP | Credential Access | T1003 — OS Credential Dumping |
| PRIV_ESC | Privilege Escalation | T1068 — Exploitation for Privilege Escalation |
| LATERAL_MOVE | Lateral Movement | T1021 — Remote Services |

---

## 9. LIBRARIES & DEPENDENCIES

### Python (backend/requirements.txt)

| Library | Version | Purpose |
|---------|---------|---------|
| fastapi | ≥0.109.0 | Web framework — routing, dependency injection, OpenAPI |
| uvicorn | ≥0.27.0 | ASGI server — runs FastAPI with asyncio |
| flask | ≥3.1.0 | MobSF Flask microservice |
| flask-cors | ≥5.0.0 | CORS for MobSF service |
| websockets | ≥14.0 | WebSocket support for real-time features |
| python-dotenv | 1.0.0 | Load `.env` secrets |
| pydantic | ≥2.6.0 | Data validation (request/response models) |
| pydantic-settings | ≥2.1.0 | Settings management from env vars |
| python-multipart | 0.0.9 | Multipart form data (file uploads) |
| email-validator | 2.1.0 | Email format validation |
| jinja2 | 3.1.3 | HTML email templates |
| PyJWT | 2.10.1 | JWT generation and verification |
| passlib | latest | Password hashing framework |
| bcrypt | latest | bcrypt algorithm implementation |
| sqlalchemy | ≥2.0.0 | Async ORM for database operations |
| aiosqlite | ≥0.19.0 | Async SQLite driver (non-blocking) |
| greenlet | latest | Async thread support for SQLAlchemy |
| boto3 | ≥1.34.0 | AWS SDK (EC2, S3, STS, CloudTrail, IAM) |
| requests | ≥2.31.0 | HTTP client for external services |
| twilio | ≥9.0.0 | WhatsApp/SMS notification delivery |
| psutil | 5.9.8 | System resource monitoring |
| httpx | (indirect) | Async HTTP for Guacamole auth token fetch |

### JavaScript (frontend, CDN or embedded)

| Library | Source | Purpose |
|---------|--------|---------|
| Chart.js | CDN | Attack timeline, donut charts, heatmaps, bar charts |
| AOS (Animate On Scroll) | CDN | Scroll animations on landing/info pages |
| Font Awesome 6 | CDN | Icon set for entire UI |
| Google Fonts (JetBrains Mono) | CDN | Monospace terminal-style text |
| ES6 Fetch API | Native | All API calls (no jQuery dependency) |
| ES6 Modules | Native | `import/export` in JS files |

### External Services & Plugins

| Service | Integration Method | Purpose |
|---------|-------------------|---------|
| **AWS EC2** | boto3 `run_instances()` | Provision analysis VM instances |
| **AWS S3** | boto3 `list_objects_v2()`, `get_object()` | Fetch honeypot log files |
| **AWS STS** | boto3 `get_caller_identity()` | Validate AWS credentials |
| **AWS CloudTrail** | S3 + boto3 | Pull API activity logs for analysis |
| **AWS IAM** | boto3 `list_users()` | Connectivity debug |
| **Apache Guacamole** | HTTP API + PostgreSQL direct | Register RDP/SSH connections, fetch auth tokens |
| **MobSF** | HTTP proxy (`/api/v1/mobsf-proxy/`) | APK decompilation and analysis |
| **Twilio WhatsApp API** | `twilio.rest.Client` | Deliver credentials via WhatsApp |
| **SMTP (Gmail/Custom)** | `smtplib` + `Jinja2` | Email credential delivery |
| **CAPE Sandbox** | HTTP API | Advanced malware behavior analysis (optional) |

---

## 10. INFRASTRUCTURE & DEVOPS

### Docker Stack (`docker-compose.yml`)

```yaml
Services:
  backend:     FastAPI (Python 3.11)     → port 8000
  frontend:    Nginx 1.25-alpine         → port 5500
  mobsf:       MobSF Flask service       → port 5055
  node_api:    Fastify edge collector    → port 3000
  worker:      Node.js background worker → (internal)

Network: soc_net (bridge driver)
Volumes: ingestion.db, scans/, uploads/
Restart: unless-stopped (all services)
```

**OS-aware host resolution:**
- macOS / Windows: `host.docker.internal` (Docker Desktop feature)
- Linux: `172.17.0.1` (Docker bridge gateway)

### Database Initialization Sequence (on `./start.sh`)

```
1. FastAPI lifespan startup event fires
2. init_db() called:
   a. Base.metadata.create_all() — creates ALL missing tables
   b. ALTER TABLE migration: adds `requested_clearance_level` if missing
   c. Seed admin user if no users exist:
      - email: admin@gmail.com
      - password: admin (bcrypt hashed, cost=12)
      - role: SUPER_ADMIN, clearance: 3
3. Background tasks started:
   a. background_sync_loop() — polls S3 every 10s
   b. background_session_loop() — updates session state every 60s
   c. telemetry_engine.run_pipeline() — processes pending raw events
```

### Lab State Persistence

**File:** `backend/app/services/../../../.lab_state.json`

- All active lab sessions persisted to JSON on every state change
- Loaded on backend startup: stale PROVISIONING entries auto-set to ERROR (background task died with old process)
- Allows VM connection state to survive backend restarts

### Nginx Config (`frontend/nginx.conf`)

- Serves static files from `/usr/share/nginx/html`
- Proxy pass `/api/` → `http://backend:8000/api/`
- Gzip compression enabled
- Cache headers for static assets (CSS/JS/images: 30 days)

---

## 11. SECURITY ARCHITECTURE & RBAC

### Role Hierarchy

```
SUPER_ADMIN (clearance 3)
  ├── Full system access
  ├── User creation/deletion
  ├── Credential issuance
  └── System settings modification

OVERSEER (clearance 3)
  ├── View all data
  ├── User management (no deletion)
  └── Analytics access

ANALYST (clearance 2)
  ├── View events, attacks, analytics
  ├── Run malware analysis
  ├── Provision VMs
  └── View credentials

AUDITOR (clearance 2)
  ├── Read-only access to logs and events
  └── Export data

OPERATIVE (clearance 1)
  ├── Dashboard and basic event viewing
  └── No admin functions

SPECIALIST (clearance 1)
  └── Domain-specific access (e.g., malware only)
```

### JWT Structure

```json
{
  "sub": "user@email.com",
  "role": "ANALYST",
  "clearance": 2,
  "user_id": "uuid4",
  "exp": 1234567890
}
```

- Algorithm: HS256
- Expiry: 24 hours
- Secret: `SECRET_KEY` environment variable
- Dev bypass: token `dev-bypass-token-shadow-trust-2024` — bypasses all auth (development only)

### Sector Event Auth (Public Endpoint)

`POST /sectors/events/ingest` is the **only unauthenticated endpoint** (besides login/register). It authenticates via `api_key` field in request body, matched against `sector_targets.api_key` in DB. This allows the tracking snippet to POST from any website without storing JWT tokens.

### Password Security

- bcrypt with default cost factor (12)
- Minimum 8 characters enforced at frontend + backend
- OTP: 6-digit numeric, expires in 10 minutes
- Credential tokens: UUID4 one-time tokens, expire in 48h by default

---

## 12. AWS INTEGRATION

### Services Used

| AWS Service | Usage | SDK Method |
|-------------|-------|-----------|
| **EC2** | Launch/terminate analysis VMs | `run_instances()`, `terminate_instances()`, `describe_instances()`, `describe_instance_status()` |
| **S3** | Fetch honeypot log files | `list_objects_v2()`, `get_object()` |
| **STS** | Validate credentials | `get_caller_identity()` |
| **CloudTrail** | Pull API activity logs (via S3) | (indirect via S3 sync) |
| **IAM** | Debug connectivity test | `list_users()` |
| **VPC** | Flow Logs (via S3) | (indirect via S3 sync) |

### boto3 Configuration

```python
_BOTO_CFG = BotoConfig(
    connect_timeout=8,    # seconds — prevents hanging on unreachable AWS
    read_timeout=20,      # seconds — generous for large S3 downloads
    retries={"max_attempts": 1}  # no auto-retry (fast fail for UI responsiveness)
)
# Applied to all boto3.client() instantiations
```

### VM Profiles (configurable from aws_connection.html)

| Profile | AMI Variable | Instance Type | Protocol | Use Case |
|---------|-------------|---------------|----------|---------|
| win_base | `_st_ami_win_base` | t3.medium | RDP (3389) | Windows Server analysis baseline |
| kali_base | `_st_ami_kali_base` | t3.medium | SSH (22) | Kali Linux penetration testing |
| win_malware | `_st_ami_win_mal` | t3.xlarge | RDP (3389) | Isolated Windows malware analysis (more RAM) |

### EC2 Default Region: `ap-south-1` (Mumbai)

Configurable via `aws_connection.html` → saved to `system_config` table → loaded by `LabSessionManager`.

---

## 13. SECTOR INTELLIGENCE SYSTEM

### 9 Monitored Sectors

| Sector Key | Sector Name | Demo Portal | Real-World Targets |
|-----------|-------------|------------|-------------------|
| `edu` | Education | edu-portal.html | University portals, student systems |
| `defence` | Defence | defence-portal.html | Military/defence agency sites |
| `medicare` | Healthcare | medicare-portal.html | Hospital portals, patient systems |
| `commerce` | E-Commerce | commerce-portal.html | Online retail, payment systems |
| `finance` | Finance | finance-portal.html | Banking, trading platforms |
| `gov` | Government | gov-portal.html | Citizen service portals |
| `energy` | Energy | energy-portal.html | Power grid, utilities |
| `telecom` | Telecom | telecom-portal.html | Carrier portals, network mgmt |
| `transport` | Transport | transport-portal.html | Rail, aviation, logistics |

### How Sector Monitoring Works

1. Admin opens `sectors.html`, clicks a sector → opens modal
2. In **Manage Targets** tab: adds URL or IP address of target site
3. Backend creates `SectorTarget` with a unique `api_key` UUID
4. Admin copies the JS snippet (auto-generated with the `api_key`)
5. Snippet is embedded in the target website's HTML
6. Snippet auto-detects attacks (XSS, SQLi) and reports via `POST /sectors/events/ingest`
7. All events visible in **Dashboard** tab with real-time aggregated stats

### Sector Stats API Response Shape

```json
{
  "sector_key": "finance",
  "attacks": 1240,
  "attackers": 87,
  "top_attackers": [{"ip": "1.2.3.4", "country": "CN", "count": 43}],
  "geo_origins": [{"country": "CN", "count": 120}, {"country": "RU", "count": 89}],
  "iocs": [{"type": "ip", "value": "1.2.3.4", "risk": 9.1}],
  "captured_commands": ["'; DROP TABLE users;--", "<script>alert(1)</script>"],
  "active_alerts": 3,
  "attack_breakdown": {"SQLi": 540, "XSS": 380, "BruteForce": 200, "Scan": 120},
  "timeline": [
    {"hour": "00:00", "count": 12}, {"hour": "01:00", "count": 8}, ...
  ]
}
```

### Demo Seed Script (`backend/demo_seed.py`)

Standalone Python script (no FastAPI dependency):
1. Logs in as `admin@gmail.com/admin` → gets JWT
2. For each of 9 sectors: `POST /api/v1/sectors/{key}/targets` → gets `api_key`
3. Patches the real `api_key` UUID into the corresponding demo HTML file (replaces `DEMO_{SECTOR}_API_KEY` placeholder)
4. Injects 40 realistic attack events per sector (360 total) via `POST /api/v1/sectors/events/ingest`
5. Each sector has unique attacker IPs, countries, commands, IOC values matching realistic threat profiles
6. Saves all keys to `backend/demo_keys.json`

---

## 14. MALWARE ANALYSIS PIPELINE

### Pipeline Overview

```
File Upload (multipart/form-data)
    │
    ▼ sha256 = hashlib.sha256(content)
    │
    ├─ If SHA already in cache: return cached result immediately
    │
    ├─ Stage 1: Static Analysis (static_analyzer.py)
    │   - File type detection (magic bytes)
    │   - Header parsing (PE/ELF/Mach-O)
    │   - Import/export table extraction
    │   - Section entropy analysis
    │   - Packer detection
    │   - Suspicious API classification (6 categories)
    │   - String extraction
    │
    ├─ Stage 2: Sandbox (sandbox_engine.py)
    │   - Behavioral signature inference from imports
    │   - Family classification (Ransomware/RAT/Botnet/Worm/Dropper/Spyware)
    │   - MITRE ATT&CK technique mapping
    │   - Composite risk score calculation
    │   - CAPE sandbox integration (if available)
    │
    ├─ Stage 3: APK Analysis (apk_engine.py, if .apk)
    │   - APK decompilation
    │   - AndroidManifest.xml parsing
    │   - Permission analysis
    │   - Dangerous API detection
    │   - Network endpoint extraction
    │   - MobSF proxy (full decompile + report)
    │
    └─ Stage 4: Secret Detection (secret_detector.py)
        - AWS keys (AKIA* pattern)
        - Google API keys
        - Private key PEM blocks
        - Database connection strings
        - OAuth tokens / passwords
        - Crypto private keys
```

### Risk Scoring Formula

```
base_score = 3.0
+ 3.0 if packer_detected
+ 2.0 per section with entropy > 7.0
+ 1.5 for INJECTION imports
+ 1.5 for NETWORK imports
+ 1.0 for PERSISTENCE imports
+ 0.5 for CRYPTO imports
+ 0.5 for EVASION imports
+ 2.0 if family in [Ransomware, RAT]
+ 1.0 if family in [Botnet, Worm]
+ secrets_found * 1.5

final_score = min(10.0, base_score)
```

---

## 15. VIRTUAL LAB (VM PROVISIONING)

### Available VM Environments

| Profile | OS | Instance Type | Protocol | Credentials |
|---------|-----|--------------|---------|-------------|
| Windows Server Baseline | Windows Server 2022 | t3.medium | RDP (3389) | Administrator / `2aA.XlugId5KDkwu!pc5!@UygmmVkvov` |
| Kali Linux Intranet Node | Kali Linux 2023 | t3.medium | SSH (22) | kali / kali |
| Windows Analysis Environment | Windows Server 2022 (hardened) | t3.xlarge | RDP (3389) | Administrator / `N1oHa9gwwPqU8b?0E(K4Mv2&Y&iu&u85` |

### VM State Machine

```
[PROVISION button clicked]
         │
         ▼
    LAUNCHING (button disabled, spinner shown)
         │
         ▼ POST /labs/start → returns lab_id
    PROVISIONING (orange dot, polls /labs/status every 5s)
         │
    ┌────┴────────────────────┐
    ▼                         ▼
  READY                     ERROR
(green dot)            (workspace closes,
CONNECT TERMINAL        button resets to PROVISION,
(opens Guacamole        notification shown)
 iframe)
```

### State Persistence

- `GLOBAL_LAB_STATE` dict (in-memory) + `.lab_state.json` (file) — dual persistence
- On backend restart: `.lab_state.json` loaded, stale PROVISIONING → ERROR
- Frontend localStorage `_st_instances` — maps `profileId` → `{instanceId, labId}`
- On page reload: `restoreUI()` cross-checks localStorage against `/labs/status` API

### Guacamole Connection URL Format

```javascript
// Guacamole client ID format: base64( connectionId + NUL + "c" + NUL + "postgresql" )
const guacIdString = `${guac_connection_id}\0c\0postgresql`;
const b64Id = btoa(guacIdString);
// URL with token BEFORE # (Angular router reads query params before hash)
const url = `http://localhost:8080/guacamole/?token=${auth_token}#/client/${b64Id}`;
```

---

## 16. SCRIPTS REFERENCE

### `start.sh` — Full Stack Startup

**Location:** project root
**Usage:** `./start.sh`

```bash
Functions:
  ensure_backend_venv()   — creates .venv with python3.11 if missing
                          — installs requirements.txt
  kill_port_if_in_use()  — kills any process on ports 8000, 5500, 5055

Services started:
  1. FastAPI backend (uvicorn) on port 8000
  2. MobSF Flask service on port 5055
  3. Python http.server (frontend) on port 5500

Environment: loads backend/.env if present
Trap: cleanup() called on EXIT/INT/TERM to kill all 3 PIDs
```

### `reset.sh` — Data Reset Utility

**Location:** project root
**Usage:** `./reset.sh`

```bash
Menu options:
  1 — Clear demo sector data (sector_targets, sector_events)
  2 — Clear honeypot/attack data (events, attacks, alerts, nodes,
      sessions, IOCs, payloads, s3_sync_state, vm_instances)
  3 — Everything (option 1 + option 2)
  q — Quit

Safety:
  - Requires typing 'yes' to confirm
  - Automatically stops backend (kills port 8000) before clearing
  - NEVER touches: users, credential_tokens, credential_audit_log,
    access_logs, admin_activity_log, system_settings, system_config, vm_profiles
  - VACUUMs database after clearing to reclaim disk space
  - Shows row count of preserved tables for confirmation
```

### `backend/demo_seed.py` — Demo Data Population

**Usage:** `cd backend && python demo_seed.py`

```bash
Prerequisites:
  - Backend running on localhost:8000
  - Admin account exists (admin@gmail.com / admin)

Actions:
  1. Authenticate and get JWT token
  2. Create 1 demo target per sector (9 total)
  3. Patch api_keys into frontend/demo/*.html files
  4. Inject 40 attack events per sector (360 total)
  5. Save api_keys to backend/demo_keys.json

SECTOR_PROFILES dict:
  Each sector has: attacker_ips[], countries[], commands[],
  ioc_values[], attack_types[], risk_scores[]
  Realistic per-sector TTPs (e.g., finance → credential stuffing,
  energy → SCADA commands, defence → zero-day probing patterns)
```

### `setup.sh` — One-Click Docker Deployment

**Usage:** `./setup.sh`

```bash
Actions:
  1. Check Docker and Docker Compose installed
  2. Detect OS (macOS/Windows/Linux)
  3. Generate .env from template if missing
  4. Initialize ingestion.db
  5. Create /scans, /uploads directories
  6. Build Docker images (docker-compose build)
  7. Start all 5 services (docker-compose up -d)
  8. Print service URLs and health check
```

---

## 17. CONNECTIONS & INTEGRATION MAP

```
Frontend (localhost:5500)
    │
    │ Fetch API (JSON + JWT Bearer token)
    │
    ▼
Backend API (localhost:8000/api/v1)
    │
    ├──▶ SQLite DB (backend/ingestion.db)
    │      └── aiosqlite async driver
    │
    ├──▶ AWS SDK (boto3)
    │      ├── STS (credential validation)
    │      ├── EC2 (VM provisioning / status)
    │      ├── S3 (log file fetching)
    │      └── IAM (debug / permission check)
    │
    ├──▶ Guacamole (localhost:8080)
    │      ├── HTTP API (token generation)
    │      └── PostgreSQL direct (connection registration)
    │
    ├──▶ MobSF Service (localhost:5055)
    │      └── Flask HTTP proxy → APK analysis
    │
    ├──▶ Twilio API (cloud)
    │      └── WhatsApp Business API → credential delivery
    │
    ├──▶ SMTP Server (Gmail / custom)
    │      └── smtplib → credential email delivery
    │
    └──▶ CAPE Sandbox (optional, localhost:8008)
           └── REST API → full behavioral analysis

Demo Portals (frontend/demo/*.html, localhost:5500/demo/)
    │
    │ Tracking Snippet (IIFE, no auth)
    │
    ▼
POST /api/v1/sectors/events/ingest
    │
    ▼
sector_events table (SQLite)
    │
    ▼
sectors.html dashboard (GET /api/v1/sectors/{key}/stats)

Analyst Browser
    │
    ├── vm_lab.html → POST /labs/start → EC2 launched
    │      └── Guacamole iframe → RDP/SSH to EC2 in browser
    │
    └── malware.html → POST /malware/upload
           └── 4-stage analysis pipeline → JSON result
```

---

## 18. KEY ALGORITHMS

### 18.1 Risk Score Calculation

```python
def calculate_risk_score(event: dict) -> float:
    score = 0.0
    # Attack type weights
    weights = {
        "RCE": 9.0, "SQLi": 8.0, "XSS": 7.0, "PATH_TRAVERSAL": 6.5,
        "BRUTE_FORCE": 5.0, "PORT_SCAN": 3.0, "DEFAULT": 2.0
    }
    score += weights.get(event.get("attack_type"), weights["DEFAULT"])
    # Repeated attacker penalty
    if event.get("session_count", 0) > 5:
        score += 1.5
    # Critical port targeting
    if event.get("target_port") in [22, 3389, 5900, 23, 21]:
        score += 0.5
    # Payload complexity
    if len(event.get("commands", [])) > 3:
        score += 1.0
    return min(10.0, score)
```

### 18.2 S3 Deduplication

```python
# Before processing any S3 file:
existing = await db.execute(
    select(S3SyncState).where(S3SyncState.file_key == s3_key)
)
if existing.scalars().first() and not force_repull:
    continue  # Skip already-processed file

# After processing:
db.add(S3SyncState(file_key=s3_key, processed_at=datetime.utcnow()))
await db.commit()
```

### 18.3 Sector Stats Aggregation (24h Timeline)

```python
# 24-hour hourly timeline SQL pattern
from sqlalchemy import func, extract
result = await db.execute(
    select(
        extract('hour', SectorEvent.timestamp).label('hour'),
        func.count(SectorEvent.id).label('count')
    )
    .where(SectorEvent.sector_key == key)
    .where(SectorEvent.timestamp >= datetime.utcnow() - timedelta(hours=24))
    .group_by('hour')
    .order_by('hour')
)
```

### 18.4 JWT Dependency (FastAPI)

```python
async def get_current_active_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    # Dev bypass for development/testing
    if token == "dev-bypass-token-shadow-trust-2024":
        return MOCK_ADMIN_USER

    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    user = await get_user_by_email(db, payload["sub"])
    if user.status != "ACTIVE":
        raise HTTPException(403, "Account not active")
    return user

def require_clearance(min_level: int):
    async def dependency(user: User = Depends(get_current_active_user)):
        if user.clearance_level < min_level:
            raise HTTPException(403, "Insufficient clearance")
        return user
    return Depends(dependency)
```

---

## 19. RESEARCH CONTRIBUTION SUMMARY

### What Makes This System Novel

1. **Sector-Classified Honeypots** — Unlike traditional honeypots (SSH/FTP services), this system deploys realistic, sector-specific decoy web portals (banking, healthcare, defence). Each sector has its own tracking system, dashboards, and attack intelligence. This allows sector-level comparison of attack patterns (e.g., finance sector receives 3x more SQLi than education sector).

2. **No-Auth Public Ingest Endpoint with API Key** — The sector event ingest endpoint uses per-target UUIDs instead of JWT tokens. This allows the lightweight tracking snippet to run on external third-party websites without any authentication infrastructure while maintaining target-level attribution.

3. **Stateful VM Provisioning with Browser VDI** — Full EC2 lifecycle management (provision → poll → Guacamole register → browser RDP) with a state persistence layer (.lab_state.json) that survives server restarts. Most research tools treat VM management and SOC dashboards as separate systems.

4. **4-Stage Malware Pipeline** — Combines static binary analysis + heuristic sandbox simulation + APK analysis + secret extraction in a single upload. When CAPE is offline, the heuristic behavioral simulation produces MITRE-mapped results without requiring a full sandbox environment.

5. **Temporal GNN Profiling** — Uses graph neural network techniques on temporal event sequences to classify attacker sophistication (Opportunistic / Targeted / APT). Most honeypot platforms only provide statistical aggregation; this adds ML-based behavioral sequencing.

6. **Multi-Clearance Credential Delivery** — Credential issuance with WhatsApp delivery (Twilio) + email (SMTP) + full audit trail is uncommon in open-source SOC platforms. Designed for enterprise deployments where analysts don't share passwords but receive individual credentials.

7. **Integrated MITRE ATT&CK Mapping** — Automatic mapping from raw attack events to MITRE ATT&CK tactics/techniques at ingestion time, with a live interactive matrix on the frontend. Every captured event is annotated with its place in the kill chain.

### System Metrics (at scale)

- **9 sector intelligence feeds** actively monitored
- **22 API endpoint groups** (200+ total routes)
- **20+ database models** across 3 domains (threat intel, infrastructure, user management)
- **4-stage malware analysis** in a single API call
- **3 VM environments** provisionable from browser
- **360 demo events** auto-seeded across 9 sectors
- **5-service Docker stack** deployable with one command
- **Zero build step** frontend (pure HTML/JS — air-gap deployable)

### Keywords for Research Paper

`Honeypot`, `SOC Platform`, `Threat Intelligence`, `MITRE ATT&CK`, `Behavioral Analysis`, `Graph Neural Network`, `Deception Technology`, `Sector Intelligence`, `Malware Analysis Pipeline`, `Static Analysis`, `Sandbox Simulation`, `AWS EC2 Provisioning`, `Virtual Desktop Interface`, `Guacamole RDP`, `FastAPI`, `SQLAlchemy`, `RBAC`, `Credential Management`, `Attack Attribution`, `GeoIP Analysis`, `Real-time Threat Monitoring`, `Cybersecurity Operations`, `Critical Infrastructure Protection`

---

*Document generated: 2026-03-20*
*Platform: Shadow Trust SOC Honeynet v2.0*
*Author: [Your Name] — For academic/research use*
