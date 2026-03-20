<div align="center">

<img src="frontend/hero_image.png" alt="Shadow Trust" width="100%">

# 🛡️ Shadow Trust

### AI-Powered Security Operations Center & Threat Intelligence Platform

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![Supabase](https://img.shields.io/badge/Supabase-PostgreSQL-3ECF8E?style=flat-square&logo=supabase&logoColor=white)](https://supabase.com)
[![AWS](https://img.shields.io/badge/AWS-EC2%20%7C%20S3%20%7C%20IAM-FF9900?style=flat-square&logo=amazonaws&logoColor=white)](https://aws.amazon.com)
[![Node.js](https://img.shields.io/badge/Node.js-20-339933?style=flat-square&logo=nodedotjs&logoColor=white)](https://nodejs.org)
[![License](https://img.shields.io/badge/License-Private-red?style=flat-square)](.)

**Deceive. Capture. Analyze. Respond.**

[Features](#-features) · [Architecture](#-architecture) · [Quick Start](#-quick-start) · [Dashboard](#-dashboard-pages) · [API](#-api-endpoints) · [Configuration](#-configuration) · [Team Setup](#-team-setup)

</div>

---

## 📖 Overview

**Shadow Trust** is a next-generation, full-stack Security Operations Center platform built around a network of honeypots and AI-driven threat intelligence. It combines a **hybrid edge-to-cloud architecture** with real-time global threat monitoring, automated attack classification, malware analysis, and AWS cloud orchestration — all accessible through a 30+ page neon dark web dashboard.

<div align="center">
<img src="frontend/architecture_hero.png" alt="Architecture" width="100%">
</div>

> Built for red teams, blue teams, and SOC analysts who need real operational visibility — not just dashboards.

---

## ✨ Features

<img src="frontend/features_hero.png" alt="Features" width="100%">

### 🧠 AI & Detection
- **AI Attack Classifier** — Detects SQLi, XSS, Brute Force, RCE, Path Traversal, and anomalous payloads using heuristic rule-based classifiers and behavioral pattern matching
- **Session Correlation Engine** — Groups raw events into attacker sessions with full lifecycle tracking
- **Behavioral Profiling** — Builds persistent attacker profiles across sessions with risk scoring
- **MITRE ATT&CK Mapping** — Automatically maps captured attacks to MITRE ATT&CK techniques and tactics

### 🍯 Honeypot Network
- **Multi-Protocol Deception** — Supports Cowrie (SSH/Telnet), Dionaea (malware capture), and Honeytrap (multi-port)
- **Edge-First Telemetry** — Honeypots log locally to SQLite for full offline resilience, syncing to cloud when available
- **Node Orchestration** — Deploy, monitor, and manage honeypot nodes directly from the dashboard UI
- **Payload Capture** — Full capture of credentials, commands, binaries, and session interactions

### 🔬 Malware Analysis Pipeline (4-Stage)
1. **Static Analysis** — Binary metadata extraction, hash identification, string analysis
2. **Sandbox Detonation** — Controlled behavioral execution in isolated environments
3. **APK Analysis** — Mobile Android APK security scanning via MobSF integration
4. **Secret Detection** — Credential and API key extraction from captured payloads

### ☁️ Cloud & VM Orchestration
- **AWS EC2 On-Demand** — Launch and terminate isolated analysis VMs on demand via boto3
- **JIT Credentials** — Just-in-time credential injection via AWS Systems Manager
- **S3 Log Storage** — Automated telemetry archival to S3 with structured ingestion pipeline
- **Remote Desktop Access** — Apache Guacamole integration for browser-based VM access

### 🔐 Security & Access Control
- **JWT Authentication** — Stateless token-based auth with configurable expiry
- **RBAC System** — 6-tier role model with clearance levels (1–3)
- **Credential Management** — Encrypted storage with SMTP-delivered credential packages
- **Audit Logging** — Full API-level audit trail for compliance

### 📡 Integrations & Alerts
- **URL Scanner** — Multi-engine URL reputation analysis
- **Email Alerts** — SMTP/Gmail alert delivery with Jinja2 templating
- **WhatsApp Alerts** — Real-time threat notifications via Twilio
- **GeoIP Enrichment** — Attack origin mapping with country/ASN metadata
- **Supabase Realtime** — Live dashboard updates via PostgreSQL pub/sub

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SHADOW TRUST PLATFORM                     │
├──────────────┬──────────────┬──────────────┬────────────────┤
│   HONEYPOTS  │   BACKEND    │   FRONTEND   │   CLOUD        │
│              │              │              │                │
│  Cowrie      │  FastAPI     │  Nginx       │  AWS EC2       │
│  (SSH/Telnet)│  Python 3.11 │  HTML5/CSS3  │  AWS S3        │
│              │  Port: 8000  │  Port: 5500  │  AWS IAM/SSM   │
│  Dionaea     │              │              │                │
│  (Malware)   │  MobSF Svc   │  Vanilla JS  │  Supabase      │
│              │  Flask       │  Neon Dark   │  PostgreSQL    │
│  Honeytrap   │  Port: 5055  │  UI Theme    │  Realtime Sync │
│  (Multi-port)│              │              │                │
│              │  Node API    │              │  Guacamole     │
│  SQLite Edge │  Fastify     │              │  Remote Desktop│
│  (Offline)   │  Port: 3000  │              │                │
└──────────────┴──────────────┴──────────────┴────────────────┘
```

### Data Flow
```
Honeypot → SQLite (Edge) → FastAPI Backend → AI Classifier
                                           → Session Engine → Supabase
                                           → MITRE Mapper  → Dashboard
                                           → Alert System  → Email/WhatsApp
```

---

## 🚀 Quick Start

### Option A — Docker (Recommended, One Command)

**Prerequisites:** [Docker Desktop](https://docs.docker.com/get-docker/) installed and running.

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/Shadow-Trust.git
cd Shadow-Trust

# 2. Run the one-click setup wizard
./setup.sh
```

That's it. The wizard will:
- Detect your OS (macOS / Linux / Windows)
- Create all environment files automatically
- Build all Docker images
- Start all 5 services

**Access the platform:**

| Service | URL |
|---|---|
| 🖥️ Dashboard | http://localhost:5500 |
| 📚 API Docs (Swagger) | http://localhost:8000/docs |
| 🔬 MobSF Service | http://localhost:5055 |
| ⚡ Node API | http://localhost:3000 |

---

### Option B — Manual (Without Docker)

**Prerequisites:** Python 3.11+, Node.js 20+

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/Shadow-Trust.git
cd Shadow-Trust

# Run everything at once
./start.sh
```

Or start services individually:

```bash
# Backend
cd backend
python3.11 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# MobSF Service (separate terminal)
python -c "from mobsf_service.app import app; app.run(host='0.0.0.0', port=5055)"

# Node API (separate terminal)
cd services/api
npm install && npm run build && npm start

# Frontend (separate terminal)
cd frontend
python3 -m http.server 5500
```

---

## ⚙️ Configuration

All credentials are in `backend/.env` — already pre-filled for the team.

```env
# Core
SECRET_KEY=your-jwt-secret
ACCESS_TOKEN_EXPIRE_MINUTES=60

# Supabase (required)
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-service-role-key

# Email Alerts (optional)
SMTP_HOST=smtp.gmail.com
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-gmail-app-password

# WhatsApp Alerts (optional)
TWILIO_ACCOUNT_SID=ACxxxxxxxx
TWILIO_AUTH_TOKEN=your-token

# AWS (optional — for VM orchestration)
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_REGION=us-east-1
```

> ⚠️ This repo is **private**. Never make it public — the `.env` contains live credentials.

---

## 🎛️ Makefile Commands

```bash
make setup       # First-time setup wizard (same as ./setup.sh)
make up          # Start all containers (no rebuild)
make down        # Stop all containers
make restart     # Restart all containers
make rebuild     # Rebuild images + restart (after code changes)
make logs        # Tail logs from all containers
make logs-backend  # Tail backend logs only
make status      # Show container status
make shell-backend # Open bash inside the backend container
make clean       # Remove containers + local images
make nuke        # ⚠️ Remove everything including volumes (resets DBs)
```

---

## 📊 Dashboard Pages

Shadow Trust ships with **30+ dashboard pages**:

| Page | Route | Description |
|---|---|---|
| 🏠 Landing | `index.html` | Public landing / marketing page |
| 🔐 Login | `login.html` | Operator authentication |
| 📝 Register | `register.html` | New operator registration |
| 🗺️ Dashboard | `dashboard.html` | Main threat map command center |
| 📋 Events | `events.html` | Real-time attack event log |
| 🍯 Nodes | `nodes.html` | Honeypot node status & management |
| 🌍 Geo | `geo.html` | Geolocation attack origin mapping |
| 🧬 Behavior | `behavior.html` | Attacker behavioral profiling |
| ☣️ Malware | `malware.html` | Malware analysis pipeline |
| 📱 APK | `apk.html` | Android APK security scanner |
| 🎯 MITRE | `mitre.html` | MITRE ATT&CK framework mapping |
| 📈 Graphs | `graphs.html` | Attack trend analytics & charts |
| 🔑 Credentials | `credentials.html` | Captured credential viewer |
| 🗝️ Credential Mgmt | `credential_mgmt.html` | Secure credential management system |
| 🔗 URL Scan | `urlscan.html` | Multi-engine URL reputation analysis |
| 🖥️ VM Lab | `vm_lab.html` | AWS VM orchestration interface |
| 🖥️ VM Session | `vm_session.html` | Active VM session manager |
| ☁️ AWS | `aws_connection.html` | AWS connectivity & diagnostics |
| 👥 Admin | `admin.html` | User & role management panel |
| 🔒 Access Control | `access_control.html` | RBAC permissions management |
| 📐 Architecture | `architecture.html` | Live architecture diagram |
| ⚙️ Config | `config.html` | Platform configuration |
| 📊 Status | `status.html` | System health monitoring |
| 👤 Profile | `profile.html` | Operator profile |

---

## 🔌 API Endpoints

Full interactive docs at **http://localhost:8000/docs**

| Module | Base Path | Description |
|---|---|---|
| Auth | `/api/v1/auth` | Login, register, JWT refresh |
| Users | `/api/v1/users` | User CRUD, role assignment |
| Events | `/api/v1/events` | Attack event ingestion & query |
| Dashboard | `/api/v1/dashboard` | Aggregated threat metrics |
| Honeypots | `/api/v1/honeypots` | Node management |
| Attacks | `/api/v1/attacks` | Attack log & classification |
| Malware | `/api/v1/malware` | Malware analysis pipeline |
| MobSF | `/api/v1/mobsf` | APK analysis proxy |
| Behavior | `/api/v1/behavior` | Behavioral profiling |
| MITRE | `/api/v1/mitre` | ATT&CK mapping |
| Session | `/api/v1/session` | Session correlation |
| Analytics | `/api/v1/analytics` | Trend analytics |
| VM | `/api/v1/vm` | AWS EC2 orchestration |
| AWS | `/api/v1/aws` | AWS diagnostics |
| URL Scan | `/api/v1/urlscan` | URL reputation analysis |
| Credentials | `/api/v1/credentials` | Captured credential management |
| Admin | `/api/v1/admin` | Platform administration |
| Labs | `/api/v1/labs` | Research lab environments |
| Logs | `/api/v1/logs` | System logs |

---

## 🔐 Roles & Access Control

Shadow Trust uses a 6-tier RBAC model with clearance levels:

| Role | Clearance | Access |
|---|---|---|
| `super_admin` | 3 | Full platform access, user management, system config |
| `overseer` | 3 | All analytics, all nodes, read-only config |
| `auditor` | 2 | Compliance logs, audit trails, read-only |
| `analyst` | 2 | Events, malware, behavior, MITRE mapping |
| `specialist` | 2 | VM lab, APK analysis, URL scanning |
| `operative` | 1 | Dashboard, events, basic node view |

**First-time Super Admin setup:**
1. Register via `/register.html`
2. In your Supabase dashboard → `users` table → set `role` to `super_admin`

---

## 📁 Project Structure

```
Shadow-Trust/
│
├── backend/                    # Python FastAPI backend
│   ├── app/
│   │   ├── api/v1/endpoints/   # 19 API endpoint modules
│   │   ├── services/           # Business logic (AWS, malware, auth, alerts)
│   │   ├── ai_engine/          # Threat classifier & behavioral profiler
│   │   ├── worker/             # Background task workers
│   │   ├── db/                 # SQLite database layer
│   │   └── models/             # Pydantic schemas
│   ├── mobsf_service/          # MobSF APK analysis Flask proxy
│   ├── requirements.txt
│   └── .env                    # ← credentials (private repo only)
│
├── frontend/                   # Vanilla HTML5/CSS3/JS dashboard
│   ├── js/                     # API client, auth, page modules
│   ├── css/                    # Neon dark UI theme
│   ├── *.html                  # 30+ dashboard pages
│   └── nginx.conf              # Nginx config for Docker
│
├── services/
│   ├── api/                    # Node.js Fastify edge-collector API
│   └── worker/                 # Node.js Supabase background sync worker
│
├── database/
│   ├── schema_sqlite.sql       # Edge SQLite schema
│   └── schema_supabase.sql     # Cloud PostgreSQL schema
│
├── vm_scripts/                 # Honeypot node setup & log collector
├── scripts/                    # Seed data & testing utilities
├── guacamole/                  # Apache Guacamole remote desktop
│
├── docker-compose.yml          # Full stack orchestration
├── Dockerfile.backend          # FastAPI multi-stage build
├── Dockerfile.mobsf            # MobSF service build
├── Dockerfile.node             # Node.js multi-stage build (api + worker)
├── setup.sh                    # ← One-click setup wizard
├── Makefile                    # Developer convenience commands
└── start.sh                    # Local dev start (no Docker)
```

---

## 👥 Team Setup

Since credentials and databases are committed to this private repo, any teammate can be up and running in under 5 minutes:

```bash
git clone https://github.com/YOUR_USERNAME/Shadow-Trust.git
cd Shadow-Trust
./setup.sh
# Done. Open http://localhost:5500
```

**Keeping in sync:**
```bash
git pull          # Get latest code + any DB/config updates
make rebuild      # Rebuild images with new code
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend API | Python 3.11, FastAPI, Uvicorn |
| MobSF Proxy | Python, Flask |
| Edge API | Node.js 20, Fastify, TypeScript |
| Background Worker | Node.js, Supabase JS SDK |
| Frontend | HTML5, CSS3 (Neon Dark), Vanilla JavaScript |
| Web Server | Nginx 1.25 Alpine |
| Edge Database | SQLite + aiosqlite |
| Cloud Database | Supabase (PostgreSQL + Realtime) |
| Auth | JWT (PyJWT), Supabase Auth |
| Cloud | AWS EC2, S3, IAM, Systems Manager |
| Honeypots | Cowrie, Dionaea, Honeytrap |
| APK Analysis | MobSF |
| Alerts | SMTP (Gmail), Twilio WhatsApp |
| Containerization | Docker, Docker Compose |

---

## 📚 Additional Documentation

| Document | Description |
|---|---|
| `PROJECT_DOCUMENTATION.md` | Full technical reference — architecture, schemas, algorithms, API |
| `report.md` | Comprehensive project report with AWS data flow |
| `ARCHITECTURE.md` | High-level architecture diagrams |
| `AWS_CLOUD_ARCHITECTURE.md` | AWS integration deep-dive |
| `backend/app/` | Inline code documentation |
| `http://localhost:8000/docs` | Live interactive API documentation (Swagger UI) |

---

<div align="center">

**Shadow Trust** — Built for the next generation of Cyber Intelligence Operations.

*Private Repository — Keep Confidential*

</div>
