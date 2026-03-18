# SentinelHive — Shadow Trust Platform
## Technical Documentation & Research Reference

> **Classification**: Internal Research Documentation
> **Version**: 1.0
> **Date**: 2026-03-17
> **Purpose**: Research Paper Reference, System Architecture Report, Technical Audit

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Overview & Goals](#2-system-overview--goals)
3. [High-Level Architecture](#3-high-level-architecture)
4. [AWS Cloud Architecture](#4-aws-cloud-architecture)
5. [Backend Architecture (FastAPI)](#5-backend-architecture-fastapi)
6. [API Reference (All Endpoints)](#6-api-reference-all-endpoints)
7. [Database Schema](#7-database-schema)
8. [Authentication & Authorization (RBAC)](#8-authentication--authorization-rbac)
9. [AI & ML Components](#9-ai--ml-components)
10. [Algorithms Used](#10-algorithms-used)
11. [Honeypot System](#11-honeypot-system)
12. [Malware Analysis Pipeline (4-Stage)](#12-malware-analysis-pipeline-4-stage)
13. [Threat Intelligence & Enrichment](#13-threat-intelligence--enrichment)
14. [Real-Time & Async Processing](#14-real-time--async-processing)
15. [Risk Scoring Engine](#15-risk-scoring-engine)
16. [Frontend Architecture](#16-frontend-architecture)
17. [Credential Management System](#17-credential-management-system)
18. [Third-Party Integrations](#18-third-party-integrations)
19. [Security Model](#19-security-model)
20. [Environment & Configuration](#20-environment--configuration)
21. [Identified Vulnerabilities & Gaps](#21-identified-vulnerabilities--gaps)
22. [Performance Characteristics](#22-performance-characteristics)
23. [Technology Stack Summary](#23-technology-stack-summary)
24. [Glossary](#24-glossary)

---

## 1. Executive Summary

**SentinelHive (Shadow Trust)** is a next-generation, hybrid edge-to-cloud Security Operations Center (SOC) platform built around a network of honeypots and AI-driven threat intelligence. It is designed to:

- **Deceive** adversaries using deployable honeypot nodes (Cowrie, Dionaea, Honeytrap)
- **Capture** attacker telemetry (credentials, payloads, commands, session data)
- **Analyze** threats using multi-stage AI pipelines (static, sandbox, APK, secret detection)
- **Orchestrate** dynamic cloud VMs (AWS EC2) for live malware detonation
- **Correlate** events to attacker sessions with behavioral profiling
- **Map** attacks to MITRE ATT&CK framework automatically
- **Notify** security teams via email (SMTP) and WhatsApp (Twilio)
- **Visualize** global threat data via a 25+ page web dashboard

The platform operates as a **full-stack Python/JavaScript application** with an async FastAPI backend, SQLite edge storage, optional Supabase PostgreSQL cloud sync, and AWS cloud orchestration via Boto3.

---

## 2. System Overview & Goals

| Property | Detail |
|----------|--------|
| **Project Name** | SentinelHive / Shadow Trust |
| **Type** | Hybrid Honeypot + Threat Intelligence Platform |
| **Primary Use** | SOC Operations, Threat Research, Malware Analysis |
| **Deployment Model** | Edge (on-prem honeypots) + Cloud (AWS EC2, S3, Supabase) |
| **Backend Language** | Python 3.10+ (FastAPI) |
| **Frontend** | Vanilla HTML5 / CSS3 / JavaScript (no framework) |
| **Database** | SQLite (edge) + Supabase PostgreSQL (cloud optional) |
| **AI/ML Approach** | Rule-based signature matching + behavioral heuristics |
| **Cloud Provider** | AWS (EC2, S3, IAM, SSM) |
| **Region** | ap-south-1 (Mumbai) |
| **API Style** | RESTful (JSON), JWT-authenticated |

### Core Objectives

1. **Deception Technology**: Lure real-world attackers into instrumented honeypots
2. **Telemetry Capture**: Log commands, credentials, payloads, session chains
3. **Multi-Stage Analysis**: Static binary, sandbox behavioral, APK mobile, secret detection
4. **MITRE ATT&CK Correlation**: Auto-map every event to ATT&CK tactics/techniques
5. **Dynamic Lab VMs**: On-demand EC2 analysis environments with JIT credential injection
6. **Credential Lifecycle Management**: Secure one-time token issuance, SMTP/WhatsApp delivery
7. **Audit Trail**: Full admin action logging, access control history

---

## 3. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         ATTACKER / INTERNET                              │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │
        ┌────────────────────────▼────────────────────────┐
        │              HONEYPOT NODES (Edge)               │
        │  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
        │  │  Cowrie  │  │ Dionaea  │  │  Honeytrap   │   │
        │  │ SSH/Telnet│  │ Malware  │  │ Multi-proto  │   │
        │  └────┬─────┘  └────┬─────┘  └──────┬───────┘   │
        └───────┼─────────────┼───────────────┼────────────┘
                │             │               │
                └─────────────┼───────────────┘
                              │  (Raw logs, captured payloads)
                              ▼
                    ┌─────────────────┐
                    │   AWS S3 Bucket  │
                    │ honeynet-telemetry│
                    │       -logs      │
                    └────────┬────────┘
                             │ (Boto3 async pull, 5-min cron)
                             ▼
        ┌────────────────────────────────────────────────┐
        │         FASTAPI BACKEND (Python 3.10+)          │
        │                                                  │
        │  ┌──────────┐ ┌───────────┐ ┌───────────────┐  │
        │  │  Auth &  │ │  Event    │ │   Malware     │  │
        │  │  RBAC    │ │ Ingestion │ │   Pipeline    │  │
        │  └──────────┘ └─────┬─────┘ └───────┬───────┘  │
        │                     │               │           │
        │  ┌──────────┐ ┌─────▼─────┐ ┌──────▼───────┐  │
        │  │   AWS    │ │  AI Engine│ │  URL Scanner  │  │
        │  │Orchestr. │ │(Classify) │ │  (Multi-eng.) │  │
        │  └──────────┘ └─────┬─────┘ └──────────────┘  │
        │                     │                           │
        │  ┌──────────────────▼──────────────────────┐   │
        │  │           SQLite (ingestion.db)           │   │
        │  │  RawEvent → StructuredEvent → Session     │   │
        │  └──────────────────┬──────────────────────┘   │
        └─────────────────────┼──────────────────────────┘
                              │ (optional async sync)
                              ▼
                   ┌──────────────────┐
                   │ Supabase (Cloud)  │
                   │  PostgreSQL DB    │
                   └──────────────────┘
                              │
              ┌───────────────┼──────────────────┐
              │               │                  │
              ▼               ▼                  ▼
     ┌──────────────┐ ┌──────────────┐  ┌──────────────┐
     │   FRONTEND   │ │  AWS EC2 VMs │  │  Notif. Layer │
     │ 25+ HTML     │ │ (Analysis    │  │  SMTP + Twilio│
     │  Dashboard   │ │  Lab VMs)    │  │  WhatsApp     │
     └──────────────┘ └──────────────┘  └──────────────┘
```

---

## 4. AWS Cloud Architecture

### Services Used

| AWS Service | Role in Platform |
|-------------|-----------------|
| **EC2** | Dynamic analysis VM launch/termination for malware sandboxing |
| **S3** | Honeypot telemetry storage (`honeynet-telemetry-logs` bucket) |
| **IAM** | Role attachment (`ShadowTrust-Analysis-Role`), JIT credential injection |
| **Systems Manager (SSM)** | Browser-based session manager console access to VMs |

### EC2 VM Architecture

```
AWS Cloud (ap-south-1 — Mumbai)
┌──────────────────────────────────────────────────────┐
│                                                        │
│  AMI Registry (VMProfile table)                        │
│  ┌──────────────────────────────────────────────────┐ │
│  │ ami-0dab019e2f90d9a3d │ Windows Default  │t3.med │ │
│  │ ami-026489f968e64588d │ Linux Default    │t2.med │ │
│  │ ami-083e29ace4dd6d300 │ Win Security Kit │t3.xlg │ │
│  └──────────────────────────────────────────────────┘ │
│                                                        │
│  On Launch (AWSOrchestrator.launch_analysis_vm()):     │
│  ┌──────────────────────────────────────────────────┐ │
│  │ 1. Creates EC2 from selected AMI                  │ │
│  │ 2. Tags: Name=ShadowTrust-{profile}-{session}     │ │
│  │         SessionID, ManagedBy=ShadowTrust           │ │
│  │ 3. Injects UserData script:                       │ │
│  │    - Enable password auth (Linux)                 │ │
│  │    - Set kali:kali default creds                  │ │
│  │    - Fix XRDP for remote desktop                  │ │
│  │ 4. Attaches IAM profile (ShadowTrust-Analysis)    │ │
│  │ 5. Returns instance_id → stored in VMInstance     │ │
│  └──────────────────────────────────────────────────┘ │
│                                                        │
│  JIT Credential Model:                                 │
│  - AWS keys passed in request body from frontend      │
│  - Never stored in backend database                   │
│  - Discarded after API call completes                 │
│                                                        │
└──────────────────────────────────────────────────────┘
```

### S3 Telemetry Ingestion Flow

```
Honeypot EC2 Node
    │  (5-min cron: aws s3 sync /honeynet-logs s3://honeynet-telemetry-logs/)
    ▼
S3 Bucket: honeynet-telemetry-logs
    │  (Boto3 list_objects_v2 + get_object — continuous background task)
    ▼
TelemetryEngine (Python)
    │  (Parse JSON/CSV logs per honeypot type)
    ▼
RawEventModel (SQLite)
    │  (S3SyncState tracks processed file_keys to avoid duplication)
    ▼
SyncManager → StructuredEvent → AttackerSession
```

---

## 5. Backend Architecture (FastAPI)

### Module Structure

```
backend/
├── main.py                         # FastAPI app, lifespan startup tasks
├── ingestion.db                    # SQLite edge database
├── requirements.txt
├── app/
│   ├── core/
│   │   ├── config.py               # Environment variable loading
│   │   ├── database.py             # SQLAlchemy async engine + session
│   │   └── security.py             # JWT encode/decode, bcrypt
│   ├── models/
│   │   └── models.py               # All ORM models (SQLAlchemy declarative)
│   ├── routes/
│   │   ├── auth.py                 # /auth/* endpoints
│   │   ├── events.py               # /events/* endpoints
│   │   ├── dashboard.py            # /dashboard/* endpoints
│   │   ├── analytics.py            # /analytics/* endpoints
│   │   ├── malware.py              # /malware/* endpoints
│   │   ├── honeypots.py            # /honeypots/* endpoints
│   │   ├── mitre.py                # /mitre/* endpoint
│   │   ├── vm.py                   # /vm/* endpoints
│   │   ├── admin.py                # /admin/* endpoints
│   │   ├── credentials.py          # /credentials/* endpoints
│   │   └── url_scan.py             # /url-scan/* endpoints
│   ├── services/
│   │   ├── ai_classifier.py        # Rule-based event classification
│   │   ├── static_analyzer.py      # Binary static analysis (PE/ELF/PDF)
│   │   ├── sandbox_engine.py       # CAPE sandbox + heuristic simulation
│   │   ├── apk_engine.py           # Android APK analysis
│   │   ├── secret_detector.py      # 50+ hardcoded secret patterns
│   │   ├── aws_orchestrator.py     # Boto3 EC2/S3/IAM orchestration
│   │   ├── credential_service.py   # Token issuance + SMTP/Twilio delivery
│   │   ├── geoip_service.py        # ip-api.com enrichment + caching
│   │   ├── sync_manager.py         # SQLite → StructuredEvent background task
│   │   └── session_engine.py       # Attacker session correlation
│   └── dependencies.py             # FastAPI dependency injection (auth guards)
└── mobsf_service/
    └── data/
        └── mobsf_history.db        # MobSF legacy analysis history
```

### Startup Lifecycle (FastAPI `lifespan`)

On server start, three background tasks launch:
1. **SyncManager** — every 10 seconds: normalize raw events into structured events
2. **SessionEngine** — every 60 seconds: correlate events into attacker sessions
3. **TelemetryEngine** — continuous: pull and index S3 telemetry files

---

## 6. API Reference (All Endpoints)

**Base URL**: `http://127.0.0.1:8000/api/v1`

### Authentication

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/auth/register` | None | Register new user (requests clearance level) |
| POST | `/auth/login` | None | Login → returns JWT (HS256, 60-min TTL) |
| POST | `/auth/verify-otp` | None | OTP verification step |
| POST | `/auth/dev-bypass` | None | Dev-only admin token bypass |

### Events

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/events/ingest` | Optional | High-throughput honeypot telemetry ingestion |
| GET | `/events/` | Required | Fetch raw events (limit=200) |
| GET | `/events/{id}/analyze` | Required | AI-powered event analysis + MITRE mapping |

### Dashboard & Analytics

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/dashboard/stats` | Required | Real-time metrics (attacks, attackers, traffic charts) |
| GET | `/dashboard/geo` | Required | Geolocation intelligence (country/ASN aggregation) |
| GET | `/analytics/graphs` | Required | 10 Chart.js widget datasets |
| GET | `/analytics/credentials` | Required | Credential vault KPIs |

### Malware Analysis

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/malware/upload` | Required | Trigger 4-stage analysis pipeline |
| GET | `/malware/report/{sha256}` | Required | Full cached intelligence report |
| GET | `/malware/secrets/{sha256}` | Required | Secret detection findings |
| GET | `/malware/apk-intel/{sha256}` | Required | APK-specific analysis section |
| GET | `/malware/static/{sha256}` | Required | Static analysis section |
| GET | `/malware/history` | Required | Analysis history (limit=30) |
| GET | `/malware/family-distribution` | Required | Threat family aggregation |
| POST | `/malware/launch-ida` | Required | Launch IDA Pro RE environment |
| POST | `/malware/analyze/apk` | Required | MobSF-backed APK analysis (legacy) |
| GET | `/malware/apk/history` | Required | APK analysis history |
| GET | `/malware/apk/stats` | Required | APK analysis statistics |

### Honeypots & MITRE

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/honeypots/status` | Required | Activity per honeypot type |
| GET | `/mitre/` | Required | Dynamic MITRE ATT&CK matrix with mapped techniques |

### VM Orchestration

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/vm/launch` | Required | Launch EC2 from AMI profile |
| POST | `/vm/{instance_id}/terminate` | Required | Terminate EC2 instance |
| POST | `/vm/{instance_id}/status` | Required | Get EC2 instance status |

### Administration

| Method | Endpoint | Auth | Role |
|--------|----------|------|------|
| GET | `/admin/backup` | Required | SUPER_ADMIN |
| GET | `/admin/settings` | Required | SUPER_ADMIN |
| POST | `/admin/settings` | Required | SUPER_ADMIN |
| POST | `/admin/reset` | Required | SUPER_ADMIN |
| GET | `/admin/health` | Required | Any |
| GET | `/admin/logs/access` | Required | SUPER_ADMIN / ADMIN |

### Credentials Management

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/credentials/issue` | Required | Issue temp credentials with one-time token |
| POST | `/credentials/resend` | Required | Resend via SMTP or Twilio WhatsApp |
| GET | `/credentials/history` | Required | Full audit trail |

### URL Scanning

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/url-scan/scan` | Required | Multi-engine URL threat analysis |

---

## 7. Database Schema

### Primary Storage: SQLite (`ingestion.db`)

```sql
-- User management
Users (
    id            UUID PK,
    username      VARCHAR UNIQUE,
    email         VARCHAR UNIQUE,
    password_hash VARCHAR,
    role          ENUM(SUPER_ADMIN, ANALYST, AUDITOR, OPERATIVE, SPECIALIST, OVERSEER),
    clearance_level        INT,
    requested_clearance_level INT,
    status        ENUM(PENDING, ACTIVE, SUSPENDED),
    otp_code      VARCHAR,
    otp_expires_at DATETIME,
    system_code   VARCHAR,
    created_at    DATETIME,
    last_login    DATETIME
)

-- Honeypot node registry
Nodes (
    node_id       UUID PK,
    name          VARCHAR,
    type          ENUM(cowrie, dionaea, honeytrap),
    sector        VARCHAR,
    ip_address    VARCHAR,
    os            VARCHAR,
    status        ENUM(ACTIVE, INACTIVE, COMPROMISED),
    uptime_seconds INT,
    risk_level    ENUM(LOW, MEDIUM, HIGH, CRITICAL),
    last_activity DATETIME,
    created_at    DATETIME
)

NodeMetrics (
    node_id              FK → Nodes,
    total_attacks_24h    INT,
    unique_attackers_24h INT,
    top_attack_type      VARCHAR
)

-- Raw telemetry (edge ingestion)
RawEventModel (
    id            INT PK AUTOINCREMENT,
    timestamp     DATETIME,
    attacker_ip   VARCHAR,
    target_port   INT,
    protocol      VARCHAR,
    honeypot_type VARCHAR,
    session_id    VARCHAR,
    event_type    VARCHAR,
    commands      TEXT,
    uploaded_files TEXT,
    ports_scanned TEXT,
    geoip_data    JSON,
    risk_score    FLOAT,
    raw_payload   TEXT,
    sync_status   ENUM(PENDING, SYNCED),
    signature     VARCHAR UNIQUE    -- dedup key
)

-- Normalized events
StructuredEvent (
    id            INT PK,
    raw_event_id  FK → RawEventModel UNIQUE,
    session_id    FK → AttackerSession,
    timestamp     DATETIME,
    honeypot_type VARCHAR,
    event_type    VARCHAR,
    details       JSON
)

-- Session correlation
AttackerSession (
    session_id    VARCHAR PK,
    attacker_ip   VARCHAR,
    first_seen    DATETIME,
    last_seen     DATETIME,
    risk_level    ENUM(LOW, MEDIUM, HIGH, CRITICAL),
    total_events  INT,
    geoip_country VARCHAR
)

-- Simplified events (legacy)
Events (
    id        UUID PK,
    node_id   FK → Nodes,
    src_ip    VARCHAR,
    type      VARCHAR,
    protocol  VARCHAR,
    payload   TEXT,
    timestamp DATETIME
)

-- Alerts
Alert (
    id          UUID PK,
    node_id     FK → Nodes,
    title       VARCHAR,
    description TEXT,
    severity    ENUM(LOW, MEDIUM, HIGH, CRITICAL),
    timestamp   DATETIME,
    status      ENUM(NEW, INVESTIGATING, RESOLVED)
)

-- Captured payloads & IOCs
CapturedPayload (id, node_id FK, command, file_hash, timestamp)
IOC (id, node_id FK, type ENUM(ip, domain, hash_md5, hash_sha256), value, detected_at)

-- Access control audit
AccessLog (
    id             INT PK,
    admin_id       FK → Users,
    target_user_id FK → Users,
    action         ENUM(APPROVE, DENY, REVOKE, ELEVATE),
    details        TEXT,
    timestamp      DATETIME
)

-- Credential tokens
CredentialToken (
    id                    INT PK,
    user_id               VARCHAR,
    username              VARCHAR,
    token                 VARCHAR UNIQUE,
    issued_by             FK → Users,
    issued_at             DATETIME,
    expires_at            DATETIME,
    used                  BOOLEAN,
    used_at               DATETIME,
    force_password_change BOOLEAN
)

-- Credential delivery audit
CredentialAuditLog (
    id               INT PK,
    username         VARCHAR,
    recipient_email  VARCHAR,
    recipient_phone  VARCHAR,
    issued_by        FK → Users,
    issuer_name      VARCHAR,
    timestamp        DATETIME,
    delivery_method  ENUM(EMAIL, WHATSAPP, BOTH),
    email_status     VARCHAR,
    whatsapp_status  VARCHAR,
    token_id         FK → CredentialToken,
    token_status     VARCHAR,
    custom_message   TEXT,
    admin_ip         VARCHAR
)

-- Admin activity log
AdminActivity (
    id             INT PK,
    admin_id       FK → Users,
    admin_username VARCHAR,
    action         VARCHAR,
    affected_user  VARCHAR,
    ip_address     VARCHAR,
    timestamp      DATETIME,
    result         ENUM(SUCCESS, FAILED, RATE_LIMITED),
    details        JSON
)

-- VM profiles & instances
VMProfile  (id, profile_name, ami_id, instance_type, launch_template_id, created_at)
VMInstance (id, instance_id UNIQUE, profile_id FK, status, public_ip, private_ip,
            session_id, launched_at, terminated_at)

-- S3 dedup tracking
S3SyncState (id, file_key UNIQUE, processed_at)

-- System settings
SystemSettings (key PK, value JSON, updated_at)
SystemConfig   (key PK, value VARCHAR, updated_at)
```

### Optional Cloud Storage: Supabase (PostgreSQL)

Used for cloud-synced summaries, alerts, and attacker profiles. Schema mirrors SQLite models. Sync is optional and one-directional (edge → cloud).

---

## 8. Authentication & Authorization (RBAC)

### JWT Token Specification

```
Algorithm  : HS256
Secret     : ENV SECRET_KEY
Expiration : 60 minutes
Claims     : { sub: email, role: str, clearance: int, user_id: uuid, exp: timestamp }
```

### Role Hierarchy

```
SUPER_ADMIN  (clearance 3)
    ├── Full system access
    ├── Credential issuance and revocation
    ├── User approval/suspension
    ├── System backup and settings
    └── Access log review

ADMIN        (clearance 3)
    ├── User management
    ├── Dashboard analytics
    └── Alert management

ANALYST      (clearance 2)
    ├── Full dashboard access
    ├── Event analysis and MITRE mapping
    └── Malware analysis

SPECIALIST   (clearance 2)
    ├── Advanced analytics
    └── URL/malware scanning

OVERSEER     (clearance 3)
    └── Administrative + monitoring

AUDITOR      (clearance 1)
    └── Audit logs, read-only access

OPERATIVE    (clearance 1)
    └── Basic event viewing
```

### Dependency Injection Guards

```python
get_current_user()           # Validates JWT from OAuth2 Bearer header
get_current_active_user()    # + requires status == ACTIVE
require_role([roles])        # Gate by role list
require_clearance(min_level) # Gate by clearance level integer
```

### Password Security

- Hashing: `bcrypt` (via `passlib`)
- No plaintext passwords stored anywhere

---

## 9. AI & ML Components

### 9.1 AIEngine — Rule-Based Classifier

**File**: `backend/app/services/ai_classifier.py`

Classifies raw event payloads using **regex signature matching** combined with **stateful behavioral heuristics**.

#### Signature Rules (Regex-Based)

| Attack Type | Pattern | MITRE Technique |
|-------------|---------|-----------------|
| SQL_INJECTION | `SELECT\|UNION\|INSERT\|DELETE\|DROP\|--\|#\|/\*` | T1190 |
| XSS | `<script\|javascript:\|onload=\|onerror=\|alert(` | T1059.007 |
| PATH_TRAVERSAL | `\.\./\|\.\.\\|/etc/passwd\|c:\\windows` | T1083 |
| COMMAND_INJECTION | `;\|\|\|` \| \`\|\$(\|\&\&` | T1059 |
| SSH_BRUTE_FORCE | `Failed password\|Invalid user\|authentication failure` | T1110 |

#### Behavioral Detection (Stateful, In-Memory)

| Behavior | Trigger Condition | MITRE |
|----------|------------------|-------|
| PORT_SCAN / NMAP_SCAN | > 5 distinct ports in 10-second window | T1595.001 |
| DDOS | > 20 requests in 5-second window | T1498 |
| BRUTE_FORCE | > 5 failed auth attempts in 60-second window | T1110 |

### 9.2 CAPESandboxEngine — Behavioral Sandbox

**File**: `backend/app/services/sandbox_engine.py`

Wraps the open-source **CAPE Sandbox** API with local heuristic simulation fallback.

#### Capabilities

- Behavioral signature matching against **80+ MITRE ATT&CK techniques**
- Threat family classification
- Suspicious Windows API call detection (6 categories)
- PE section entropy analysis
- Result caching: SHA-256 keyed FIFO cache (500 entries max)

#### Threat Family Signatures

| Family | Key Indicators |
|--------|---------------|
| Ransomware | `encrypt`, `.locked`, `bitcoin`, `ransom`, `CryptoLocker`, `monero` |
| RAT | `CreateRemoteThread`, `VirtualAllocEx`, `reverse_shell` |
| Botnet | `wget`, `curl`, `socket`, `connect`, `C2`, `bot_id` |
| Trojan | `/bin/bash`, `cmd.exe`, `powershell`, `svchost` |
| Spyware | `mimikatz`, `lsass`, `password`, `keylog`, `clipboard` |
| Rootkit | `NtSetSystemInformation`, `DKOM`, `driver`, `kernel32` |
| Worm | `WNetAddConnection`, `SMB`, `EternalBlue`, `spreader` |

#### Suspicious API Categories

| Category | Example APIs |
|----------|-------------|
| Injection | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` |
| Network | `socket`, `connect`, `WSAStartup`, `URLDownloadToFile` |
| Persistence | `RegSetValueEx`, `CreateServiceA`, `WritePrivateProfileString` |
| Privilege Escalation | `AdjustTokenPrivileges`, `OpenProcessToken`, `CreateProcessWithLogon` |
| Cryptography | `CryptEncrypt`, `CryptDecrypt`, `BCryptEncrypt` |
| Evasion | `IsDebuggerPresent`, `FindWindow`, `Sleep`, `GetTickCount` |

### 9.3 StaticAnalyzer — Binary Analysis

**File**: `backend/app/services/static_analyzer.py`

#### Supported File Types
- **PE** (Windows executables): `.exe`, `.dll`, `.sys`
- **ELF** (Linux binaries): No extension or `ELF` magic
- **PDF**: `.pdf`
- **Office**: `.doc`, `.docx`, `.xls`, `.xlsx`
- **Scripts**: `.py`, `.js`, `.sh`, `.ps1`

#### Analysis Components

1. **Architecture Detection**: x86, x86-64, ARM, ARM64, MIPS, PowerPC (from PE machine field or ELF header)
2. **Packer Detection**: UPX, MPRESS, Themida, VMProtect, ASPack, PECompact, NsPack, Obsidium
3. **Section Entropy** (Shannon Entropy):
   - Formula: `H = -Σ p(x) * log2(p(x))`
   - LOW: `H < 6.0` | MEDIUM: `H < 7.0` | HIGH: `H < 7.5` | CRITICAL: `H ≥ 7.5`
4. **Import/Export Table Parsing**: Categorized by API class (injection, network, persistence, etc.)
5. **String Extraction**: Regex minimum 6 chars, categorized by content type

### 9.4 APKEngine — Android Analysis

**File**: `backend/app/services/apk_engine.py`

#### Analysis Stages

1. **Manifest Parsing**: Binary XML extraction → permissions, components, intent filters
2. **Critical Permission Detection** (grouped by threat type):

| Category | Permissions |
|----------|------------|
| SMS/Call Abuse | `SEND_SMS`, `RECEIVE_SMS`, `READ_SMS`, `PROCESS_OUTGOING_CALLS` |
| Device Control | `BIND_DEVICE_ADMIN`, `INSTALL_PACKAGES` |
| Spyware | `RECORD_AUDIO`, `CAMERA`, `ACCESS_FINE_LOCATION` |
| Persistence | `RECEIVE_BOOT_COMPLETED` |

3. **DEX Code Scanning** (72 patterns across 12 categories):

| Category | Severity | Example Indicators |
|----------|----------|-------------------|
| DynamicDexLoading | CRITICAL | `DexClassLoader`, `PathClassLoader` |
| Reflection | HIGH | `java.lang.reflect`, `getMethod`, `invoke` |
| Runtime Execution | HIGH | `Runtime.getRuntime().exec()` |
| Cryptographic Ops | MEDIUM | `javax.crypto`, `AES`, `DES` |
| Device Identifiers | HIGH | `getDeviceId`, `getImei`, `getAndroidId` |
| SMS Sending | CRITICAL | `sendTextMessage`, `SmsManager` |
| WebView XSS | HIGH | `addJavascriptInterface`, `setJavaScriptEnabled` |
| Accessibility Abuse | CRITICAL | `AccessibilityService`, `performGlobalAction` |
| Device Admin | CRITICAL | `DevicePolicyManager`, `removeActiveAdmin` |

4. **APK Secret Detection** (13 patterns): Firebase, Twilio SID, JWT, DB URIs, hardcoded creds

### 9.5 SecretDetector

**File**: `backend/app/services/secret_detector.py`

Scans file content for **50+ hardcoded secret patterns**:

| Category | Patterns |
|----------|---------|
| Cloud Keys | Google API Key, Firebase FCM, AWS Access Key |
| SaaS Tokens | SendGrid, Stripe, Twilio, GitHub Token, Slack Token |
| Cryptographic | RSA/EC/OpenSSH/PGP Private Keys, AES/HMAC secrets |
| Auth Tokens | JWT tokens, Bearer tokens, Basic auth headers |
| Database URIs | MongoDB, PostgreSQL, MySQL, Redis, JDBC |
| Credentials | Hardcoded passwords, API keys, generic tokens |
| Network | IP-based URLs, Tor `.onion`, I2P `.i2p`, suspicious TLDs (`.tk`, `.ml`, `.ga`) |

**Severity Classification**: CRITICAL → HIGH → MEDIUM → LOW

---

## 10. Algorithms Used

| Algorithm | Purpose | File |
|-----------|---------|------|
| **HS256 (HMAC-SHA256)** | JWT token signing/verification | `core/security.py` |
| **bcrypt** | Password hashing (salted, adaptive cost) | `core/security.py` |
| **Shannon Entropy** | PE/ELF section packing detection | `static_analyzer.py` |
| **Regex Pattern Matching** | Attack signature detection (SQL injection, XSS, etc.) | `ai_classifier.py` |
| **Sliding Window (Time-Based)** | Behavioral detection (port scan, DDoS, brute force) | `ai_classifier.py` |
| **Levenshtein Distance** (implied) | Phishing domain homograph/IDN attack detection | `url_scan.py` |
| **Weighted Scoring** | URL risk scoring (0–100 scale, 23 keyword weights) | `url_scan.py` |
| **SHA-256 Hashing** | Malware deduplication, result cache keys | `sandbox_engine.py` |
| **LRU / FIFO Cache** | Malware result caching (500–1000 entry cap) | `sandbox_engine.py` |
| **RBAC Decision Tree** | Multi-level role and clearance authorization | `dependencies.py` |
| **UUID4** | One-time credential token generation | `credential_service.py` |
| **Token Bucket (Rate Limiting)** | Credential issuance rate limiting (20/admin/hr) | `credential_service.py` |
| **Batch Processing** | SQLite event normalization (100 events/batch) | `sync_manager.py` |
| **Session Correlation** | IP + time-window based attacker session grouping | `session_engine.py` |

---

## 11. Honeypot System

### Supported Honeypot Types

| Type | Protocol | Purpose |
|------|----------|---------|
| **Cowrie** | SSH (port 22), Telnet (port 23) | Captures brute-force attempts, shell commands, uploaded files, TTY sessions |
| **Dionaea** | HTTP, SMB, FTP, MSSQL, SIP | Malware capture honeypot; traps binaries, exploits, shellcode |
| **Honeytrap** | Multi-protocol | Low-interaction; monitors unexpected protocol connections |

### Port-Based Risk Classification

| Port | Service | Risk Level |
|------|---------|------------|
| 22 | SSH | HIGH — Brute Force vector |
| 23 | Telnet | HIGH |
| 80 / 443 | HTTP/HTTPS | CRITICAL — Web exploit vector |
| 445 | SMB | HIGH — Lateral movement vector |
| 3389 | RDP | HIGH — Remote access vector |
| 5060 | SIP/VoIP | MEDIUM |

### Attacker Session Lifecycle

```
First connection from IP → Create AttackerSession (first_seen, risk=LOW)
    ↓
Each event → append to session, update last_seen, total_events++
    ↓
Risk escalation: LOW → MEDIUM → HIGH → CRITICAL (based on event types)
    ↓
Session closed after inactivity timeout (configurable)
```

---

## 12. Malware Analysis Pipeline (4-Stage)

```
File Upload (POST /malware/upload)
        │
        ▼ SHA-256 Hash → Check cache (hit? return cached result)
        │
        ├──── Stage 1: StaticAnalyzer
        │     - Architecture, imports/exports, packer detection
        │     - Section entropy (Shannon), string extraction
        │     - API classification (6 categories)
        │     - Risk: LOW / MEDIUM / HIGH / CRITICAL
        │
        ├──── Stage 2: CAPESandboxEngine
        │     - Real: POST to CAPE_URL API (behavioral detonation)
        │     - Fallback: Local heuristic simulation
        │     - Outputs: family, MITRE tags, suspicious APIs, C2 IOCs
        │
        ├──── Stage 3: APKEngine  (APK files only)
        │     - Manifest permissions, DEX code patterns (72 checks)
        │     - APK secret detection (13 patterns)
        │     - Component exposure analysis
        │
        └──── Stage 4: SecretDetector  (all file types)
              - 50+ hardcoded secret patterns
              - Cloud keys, crypto keys, database URIs, tokens
              │
              ▼
        Aggregate Result → Store in MalwareReport table
        Cache by SHA-256 → Return to frontend
```

---

## 13. Threat Intelligence & Enrichment

### GeoIP Enrichment

- **Provider**: `ip-api.com` (batch API, free tier)
- **Fields**: country, country code, ISP, ASN, latitude, longitude
- **Caching**: Local in-memory cache to avoid rate limiting
- **Special Case**: RFC1918 private IPs → mapped to "INT" (internal)

### MITRE ATT&CK Mapping

Full ATT&CK matrix dynamically generated at `/mitre/`. Auto-populated from:
- Rule-based classifier results (event analysis)
- Sandbox behavioral signatures (80+ techniques)
- APK code pattern analysis

### URL Threat Intelligence

**Engine Components** (all local, no external dependency required):

1. **DNS Analysis**: A, MX, TXT, NS, CNAME resolution
2. **SSL/TLS Inspection**: Certificate validity, issuer, expiry, SANs
3. **HTTP Response Analysis**: Redirect chain, content-type, response codes
4. **Domain Age Estimation**: WHOIS-style heuristics
5. **Phishing Detection**: 23 weighted keywords (login, verify, account, update, bank, etc.)
6. **Multi-Engine Simulation**: 16 vendor results (VirusTotal-style)
7. **Homograph/IDN Attack Detection**: Unicode character substitution detection
8. **Scoring**: 0–100 scale; categories: Phishing, Credential Theft, Malware Distribution, Suspicious Domain, DGA

---

## 14. Real-Time & Async Processing

### Background Tasks (FastAPI Lifespan)

| Task | Interval | Function |
|------|----------|---------|
| **SyncManager** | 10 seconds | Pull PENDING RawEvents → normalize → StructuredEvent (100/batch) |
| **SessionEngine** | 60 seconds | Correlate unmapped StructuredEvents → AttackerSession records |
| **TelemetryEngine** | Continuous | S3 bucket polling → parse → RawEventModel (S3SyncState dedup) |

### Frontend Refresh

- **Dashboard**: `setInterval` polling (configurable interval)
- **Charts**: Chart.js re-render on new data
- **Geo Map**: Leaflet.js markers refreshed with each poll
- **WebSocket**: Architecture is WebSocket-ready but uses polling in current version

---

## 15. Risk Scoring Engine

### Score Calculation

```
risk_score = base_score + behavioral_bonus + secret_bonus

Where:
  base_score        = attack type severity weight
                      CRITICAL=90, HIGH=60, MEDIUM=35, LOW=10

  behavioral_bonus  = +20 if DDOS detected
                    + +15 if BRUTE_FORCE detected
                    + +10 if PORT_SCAN detected

  secret_bonus      = count_of_secrets × 5 points

  Final score       = min(100, risk_score)
```

### Risk Level Thresholds

| Level | Score Range | Color Code |
|-------|------------|------------|
| CRITICAL | ≥ 80 | Red |
| HIGH | ≥ 55 | Orange |
| MEDIUM | ≥ 30 | Yellow |
| LOW | < 30 | Green |

---

## 16. Frontend Architecture

### Overview

- **Framework**: None — pure Vanilla HTML5 / CSS3 / JavaScript
- **No build step**: All files served statically
- **Visualization**: Chart.js (graphs), Leaflet.js (geo map)
- **Icons**: Font Awesome
- **Design**: Neon/cyberpunk aesthetic, dark theme

### Page Inventory (25+ Pages)

| Category | Pages |
|----------|-------|
| **Command Center** | `dashboard.html`, `events.html` |
| **Grid Monitoring** | `nodes.html`, `sectors.html`, `geo.html` |
| **Intelligence** | `mitre.html`, `graphs.html`, `credentials.html`, `behavior.html`, `simulation.html` |
| **Analysis Tools** | `malware.html`, `urlscan.html`, `apk.html`, `vm_lab.html` |
| **Administration** | `admin.html`, `config.html`, `profile.html`, `aws_connection.html` |
| **Access Control** | `credential_mgmt.html`, `login.html` |

### API Client (`frontend/js/api.js`)

```javascript
class ApiService {
    baseUrl = 'http://127.0.0.1:8000/api/v1'   // Auto-detected for local dev

    get(endpoint)                     // Authenticated GET
    post(endpoint, data)              // Authenticated POST (JSON)
    upload(endpoint, formData)        // Authenticated POST (multipart)

    setToken(token)                   // → localStorage.access_token
    getToken()                        // ← localStorage.access_token
    clearToken()                      // Logout, clear token
}
```

### Authentication Flow (Browser)

```
1. User visits login.html
2. POST /auth/login → { access_token, token_type, role, clearance }
3. Store access_token in localStorage
4. All subsequent requests: Authorization: Bearer {token}
5. On 401 response → redirect to login.html
6. Logout: clear localStorage, redirect to login.html
```

---

## 17. Credential Management System

### Issuance Flow

```
Admin triggers POST /credentials/issue
    │
    ├─ Rate limit check: max 20 operations/admin/hour
    │  (via AdminActivity table count in rolling window)
    │
    ├─ Generate secure temp password (backend):
    │  - 12 chars: uppercase + lowercase + digits + special
    │  - All character classes guaranteed present
    │
    ├─ Create CredentialToken (UUID4, expiry configurable)
    │
    ├─ Send via delivery_method:
    │  ├─ EMAIL  → SMTP (TLS port 587)
    │  ├─ WHATSAPP → Twilio API
    │  └─ BOTH   → Both channels
    │
    ├─ Log to CredentialAuditLog (all fields including admin IP)
    └─ Log to AdminActivity
```

### Token Properties

- **Format**: UUID4 (`uuid.uuid4()`)
- **One-time use**: Invalidated after first use (`used = True`)
- **Configurable expiry**: Set at issuance time
- **Force password change**: Flag to require reset on first login

---

## 18. Third-Party Integrations

| Service | Purpose | Config Variables |
|---------|---------|-----------------|
| **AWS (Boto3)** | EC2 launch/terminate, S3 telemetry, IAM | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION` |
| **Supabase** | Cloud PostgreSQL sync (optional) | `SUPABASE_URL`, `SUPABASE_KEY` |
| **CAPE Sandbox** | Real malware behavioral analysis | `CAPE_URL`, `CAPE_API_KEY` |
| **MobSF** | Legacy Android APK analysis | `MOBSF_URL`, `MOBSF_API_KEY` |
| **ip-api.com** | GeoIP enrichment | None (public API, rate-limited) |
| **SMTP Server** | Credential email delivery | `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS` |
| **Twilio** | WhatsApp credential delivery | `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM` |

---

## 19. Security Model

### Strengths

| Control | Implementation |
|---------|---------------|
| Authentication | JWT HS256, 60-min TTL |
| Authorization | 7-role RBAC + 3-level clearance |
| Password Storage | bcrypt (salted, adaptive) |
| Rate Limiting | 20 ops/hr per admin on credential issuance |
| Audit Logging | Full trail: AdminActivity, CredentialAuditLog, AccessLog |
| AWS Credential Safety | JIT injection — never stored in backend DB |
| File Analysis | Malware scanned before processing |
| Secret Detection | 50+ patterns in uploaded files |
| Token Security | UUID4 one-time tokens with configurable expiry |

### Known Gaps (for remediation)

| Gap | Severity | Location |
|-----|----------|---------|
| Dev bypass endpoint without ENV guard | HIGH | `auth.py:113` |
| CORS allows all origins (`*`) | HIGH | `main.py` |
| OTP validation skipped in production | HIGH | `auth.py` |
| Default admin seeded with known bcrypt hash | MEDIUM | `main.py` seed |
| No API-level rate limiting (non-credential endpoints) | MEDIUM | All routes |
| JWT refresh token not implemented | MEDIUM | `auth.py` |
| SQLite not encrypted at rest | LOW | `ingestion.db` |
| Browser localStorage for JWT (XSS risk) | MEDIUM | `frontend/js/api.js` |
| Hardcoded API base URL in `credential_mgmt.html` | HIGH | `credential_mgmt.html:774` |
| User ID interpolated in onclick (potential XSS) | MEDIUM | `admin.js:260` |

---

## 20. Environment & Configuration

### Required Environment Variables

```env
# Core Security
SECRET_KEY=<random 256-bit secret>
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60

# AWS
AWS_ACCESS_KEY_ID=<key>
AWS_SECRET_ACCESS_KEY=<secret>
AWS_REGION=ap-south-1
AWS_BUCKET_NAME=honeynet-telemetry-logs

# Email (SMTP)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=<user>
SMTP_PASS=<app-password>
SMTP_FROM=<sender>

# WhatsApp (Twilio)
TWILIO_ACCOUNT_SID=<sid>
TWILIO_AUTH_TOKEN=<token>
TWILIO_FROM=+14155238886

# Analysis Backends
MOBSF_URL=http://<host>:8000
MOBSF_API_KEY=<key>
CAPE_URL=http://<host>
CAPE_API_KEY=<key>

# Portal
PORTAL_BASE_URL=http://localhost:8001
CRED_RATE_LIMIT=20
```

### Python Dependencies (Key)

```
fastapi>=0.109.0         # Async web framework
uvicorn>=0.27.0          # ASGI server
sqlalchemy>=2.0.0        # ORM (async)
aiosqlite>=0.19.0        # Async SQLite driver
PyJWT==2.10.1            # JWT tokens
bcrypt                   # Password hashing
boto3>=1.34.0            # AWS SDK
requests>=2.31.0         # HTTP client (for external APIs)
websockets>=14.0         # WebSocket support
flask>=3.1.0             # Legacy MobSF adapter
psutil==5.9.8            # System metrics
```

---

## 21. Identified Vulnerabilities & Gaps

*(Full list for security audit / remediation backlog)*

### Critical / Breaking

| # | File | Line | Issue |
|---|------|------|-------|
| 1 | `credential_mgmt.html` | 774 | Hard-coded `http://localhost:8000` — breaks in production |
| 2 | `admin.js` | 8–9 | No null checks on DOM elements — crash on missing elements |
| 3 | `credentials.html` | 543–546 | Unchecked `.kpi` property access — crash on API change |
| 4 | `events.html` | 238 | CSS class typo: `SOC-btn-sm` vs `soc-btn-sm` |

### High / Functional

| # | File | Line | Issue |
|---|------|------|-------|
| 5 | `credential_service.py` | 537–542 | Resend sends wrong password + `expires_hours: 0` |
| 6 | `credential_mgmt.html` | 1132 | Pagination onclick uses fragile function name string |
| 7 | `auth.js` | 113 | Dev bypass endpoint has no environment guard |
| 8 | `credentials.html` | 565 | Geo column always hardcoded as N/A |

### Medium / Quality

| # | File | Line | Issue |
|---|------|------|-------|
| 9 | `admin.js` | 260 | User ID interpolated in onclick — potential XSS |
| 10 | `sidebar.js` | 111–114 | Dead code — system group hide logic unreachable |
| 11 | `auth.js` | 154–159 | Fragile form parsing (relies on placeholder text) |
| 12 | `credential_mgmt.html` | 830 | Silent failure on password generation fallback |

### Low / Best Practice

| # | File | Line | Issue |
|---|------|------|-------|
| 13 | `requirements.txt` | 13 | `psutil==5.9.8` outdated (current: 6.x) |
| 14 | `requirements.txt` | 19 | `greenlet` has no version pin |

---

## 22. Performance Characteristics

### Throughput

| Component | Throughput |
|-----------|-----------|
| Event Ingestion | Batched 100 events/10s |
| Malware Analysis | Cached by SHA-256; re-analysis skipped for duplicates |
| GeoIP Lookups | Cached in-memory + batched API calls |
| Dashboard Queries | Pre-aggregated per analytics endpoint |
| S3 Telemetry Pull | Continuous, deduped via S3SyncState |

### Latency Estimates

| Operation | Estimated Latency |
|-----------|------------------|
| JWT Validation | < 1ms |
| Event Analysis (AI) | 100–500ms |
| Sandbox (CAPE real) | 5–60 seconds |
| Sandbox (Heuristic) | < 500ms |
| Static Analysis | 1–5 seconds |
| GeoIP (cached) | < 10ms |

---

## 23. Technology Stack Summary

| Layer | Technology |
|-------|-----------|
| **Backend Framework** | FastAPI 0.109+ (Python 3.10+) |
| **ASGI Server** | Uvicorn |
| **ORM** | SQLAlchemy 2.0 (async) |
| **Edge Database** | SQLite via aiosqlite |
| **Cloud Database** | Supabase (PostgreSQL) |
| **Authentication** | JWT HS256 via PyJWT |
| **Password Hashing** | bcrypt (passlib) |
| **Cloud SDK** | Boto3 (AWS) |
| **Frontend** | Vanilla HTML5 / CSS3 / JavaScript |
| **Charts** | Chart.js |
| **Maps** | Leaflet.js |
| **Icons** | Font Awesome |
| **Malware Sandbox** | CAPE (open-source) |
| **Mobile Analysis** | MobSF (legacy) |
| **Notifications** | SMTP + Twilio WhatsApp API |
| **GeoIP** | ip-api.com |
| **Honeypots** | Cowrie, Dionaea, Honeytrap |

---

## 24. Glossary

| Term | Definition |
|------|-----------|
| **Honeypot** | Decoy system designed to attract and trap attackers |
| **Telemetry** | Raw data streams from honeypot sensors |
| **IOC** | Indicator of Compromise — artifact of malicious activity |
| **MITRE ATT&CK** | Framework cataloguing adversary tactics and techniques |
| **TTPs** | Tactics, Techniques, and Procedures |
| **RBAC** | Role-Based Access Control |
| **JIT** | Just-In-Time — credentials created/injected at moment of need |
| **Shannon Entropy** | Measure of randomness/unpredictability in binary data |
| **CAPE** | Config And Payload Extraction sandbox (open-source) |
| **MobSF** | Mobile Security Framework — Android/iOS analysis tool |
| **APK** | Android Package — application binary for Android OS |
| **DEX** | Dalvik Executable — compiled bytecode for Android apps |
| **PE** | Portable Executable — Windows binary format |
| **ELF** | Executable and Linkable Format — Linux binary format |
| **ASN** | Autonomous System Number — network routing identifier |
| **IDN** | Internationalized Domain Name — supports Unicode characters |
| **DGA** | Domain Generation Algorithm — used by malware for C2 |
| **C2** | Command and Control — attacker's remote control infrastructure |
| **FIFO Cache** | First-In-First-Out cache eviction policy |
| **LRU Cache** | Least-Recently-Used cache eviction policy |
| **SSM** | AWS Systems Manager — remote instance management service |

---

*Document generated from source code analysis of SentinelHive v1.0 — Shadow Trust Platform.*
*For research paper use, bug reports, or architecture review.*
