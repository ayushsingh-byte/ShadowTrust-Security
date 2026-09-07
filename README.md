<div align="center">

<img src="frontend/hero_image.png" alt="Shadow Trust" width="100%">

# 🛡️ Shadow Trust

### AI-Powered Security Operations Center & Threat Intelligence Platform

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![MariaDB](https://img.shields.io/badge/MariaDB-11-003545?style=flat-square&logo=mariadb&logoColor=white)](https://mariadb.org)
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
- **Edge-First Telemetry** — Honeypots log to newline-delimited JSON on disk; the backend tails those files from an exact byte offset, so a crash and restart re-reads without duplicating
- **Node Orchestration** — Deploy, monitor, and manage honeypot nodes directly from the dashboard UI
- **Payload Capture** — Full capture of credentials, commands, binaries, and session interactions

### 🔬 Malware Analysis Pipeline
Streamed to `backend/quarantine/<sha256>` (size-capped, magic-byte checked, never
web-served), then: **Static → YARA → Sandbox → APK → Secrets → ClamAV → VirusTotal → aggregate**.
1. **Static Analysis** — Binary metadata, hash identification, section entropy, string analysis
2. **YARA** — `backend/yara_rules/*.yar` (read-only); matched rule names + metadata feed the verdict
3. **Sandbox** — real CAPE if `CAPE_URL` is set, otherwise a deterministic simulation **explicitly labelled as such** (never passed off as a real detonation)
4. **APK Analysis** — Android APK scanning via an on-demand MobSF engine container
5. **Secret Detection** — Credential / API-key / C2-endpoint extraction
6. **ClamAV + VirusTotal** — offline signature scan + optional hash lookup; verdict = worst of all engines

### ☁️ Cloud & VM Orchestration
- **AWS EC2 On-Demand** — Launch and terminate isolated analysis VMs on demand via boto3
- **JIT Credentials** — Just-in-time credential injection via AWS Systems Manager
- **S3 Log Storage** — Automated telemetry archival to S3 with structured ingestion pipeline
- **Remote Desktop Access** — Apache Guacamole integration for browser-based VM access

### 🔐 Security & Access Control
- **JWT Authentication** — Stateless token-based auth with configurable expiry
- **RBAC System** — 6-tier role model with clearance levels (1–3); incident/detection/evidence writes are role-gated and audited
- **Credential Management** — Encrypted storage with SMTP-delivered credential packages
- **Audit Logging** — Full API-level audit trail (also a source in the unified Logs feed)
- **Fail-closed by default** — `/health` is off (`HEALTH_PAGE=0`) and never emits secrets even when on; the `dev_bypass_token` shortcut needs `DEV_BYPASS=1` + local mode; full operator detail is the authenticated `/api/v1/admin/diagnostics`
- **Docker socket chokepoint** — one module (`services/container_manager.py`) is the only code that touches `/var/run/docker.sock`, with a hard allow-list (images, network, no bind mounts, resource caps, managed-label-only lifecycle ops); no generic Docker endpoint exists
- **Honeypot isolation preserved** — sensors stay alone on `honeynet_edge`; the container manager never creates or mutates a honeypot container
- **Analysis Lab sandboxes** — internal Docker network (zero egress: no internet, no honeypots, no app), `cap_drop=ALL` + `no-new-privileges`, non-root, 512 MB / 1 CPU / 128 PIDs, no Docker socket, hard TTL + idle reap, one per user; command capture is passive stream-parsing in the backend (no in-container agent)

### 📡 Integrations & Alerts
- **URL Scanner** — Multi-engine URL reputation analysis
- **Email Alerts** — SMTP/Gmail alert delivery with Jinja2 templating
- **WhatsApp Alerts** — Real-time threat notifications via Twilio
- **GeoIP Enrichment** — Attack origin mapping with country/ASN metadata
- **Server-Sent Events** — Live dashboard updates streamed from the backend as telemetry lands

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SHADOW TRUST PLATFORM                     │
├──────────────┬──────────────┬──────────────┬────────────────┤
│   HONEYPOTS  │   BACKEND    │   FRONTEND   │   CLOUD        │
│              │              │              │                │
│  Cowrie      │  FastAPI     │  Nginx       │  MariaDB 11    │
│  (SSH/Telnet)│  Python 3.11 │  HTML5/CSS3  │  Port: 3307    │
│              │  Port: 8000  │  Port: 5500  │                │
│  Dionaea     │              │              │  phpMyAdmin    │
│  (Malware)   │  MobSF Svc   │  Vanilla JS  │  Port: 8081    │
│              │  Flask       │  Neon Dark   │                │
│  Honeytrap   │  Port: 5055  │  UI Theme    │  Guacamole     │
│  (Multi-port)│              │              │  Remote Desktop│
│              │  Node API    │              │                │
│  NDJSON logs │  Fastify     │              │  AWS EC2/S3    │
│  on disk     │  Port: 3000  │              │  (opt-in)      │
└──────────────┴──────────────┴──────────────┴────────────────┘
```

### Data Flow
```
Honeypot → NDJSON logs → FastAPI collector → normalize() (idempotent, event_id hash)
                                          → MariaDB (raw_events + normalized_events)
                                          → SSE event bus → Dashboard / Event Log

Detection & correlation loop (every ~20s, extends the risk layer — does not replace it):

  normalized_events
    → IOC extraction        (ioc_observations)
    → detection rules        backend/detections/*.yml  → detections rows
                             (rule id · matched events · match conditions ·
                              reason · confidence · severity · ATT&CK)
    → correlation            group by source_ip / session within a 6h window
    → incident create/update explainable risk_breakdown; auto-evidence for
                             linked malware hashes
    → Investigations page · attack-reconstruction timeline · Evidence ·
      ATT&CK analytics · Detection Validation
```

**Answering "what happened?"** — an incident (`incidents.html`) ties together every
detection, event, IOC, sensor, ATT&CK technique and evidence item for one attacker,
with a chronological timeline where each entry states *why* it belongs to the chain,
and a `risk_breakdown` that itemises the severity.

**Detection rules** are YAML files under `backend/detections/` (read-only at runtime).
Adding a rule = dropping a file — `threshold` and `sequence` (multi-event) types,
field/regex/window matching, ATT&CK mapping. `backend/yara_rules/` feeds the malware
pipeline the same way.

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
- Start all core services (db, phpMyAdmin, backend, frontend, 3 sensors)

**Access the platform:**

| Service | URL |
|---|---|
| 🖥️ Dashboard | http://localhost:5500 |
| 📚 API Docs (Swagger) | http://localhost:8000/docs |
| 🗄️ phpMyAdmin | http://localhost:8081  (server: `db`, user/pass: `shadowtrust`) |
| ❤️ Status page | http://localhost:8000/health  (all services, sensors, DB counts, logins, copy-paste attack commands — local only) |
| 🖥️ VM Lab (Guacamole) | http://localhost:8080/guacamole  (`guacadmin` / `guacadmin`) |
| 🔬 MobSF Service | http://localhost:5055  (APK analysis) |
| 🛡️ Splunk Blue Team | in-app page → `~/splunk-lab` container on http://localhost:8009  (`admin` / `ChangeMe123!`) |
| ⚡ Node API | http://localhost:3000  (`--profile extras`) |

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
# Database (always a container — there is no embedded DB)
docker compose up -d db phpmyadmin

# Backend
cd backend
python3.11 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export DATABASE_URL="mysql+aiomysql://shadowtrust:shadowtrust@127.0.0.1:3307/shadowtrust"
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

## 🏠 Local Mode vs AWS Mode

Shadow Trust runs **local-first**. A fresh checkout needs Docker and nothing else — no AWS account, no cloud credentials, no spend. AWS remains fully supported as an opt-in provider.

The whole platform switches on one variable:

```env
INFRA_PROVIDER=local   # default — Docker containers
INFRA_PROVIDER=aws     # EC2 instances + S3 telemetry
```

|  | Local mode (default) | AWS mode |
|---|---|---|
| Lab backend | Docker containers | EC2 instances |
| Telemetry | Watched directory | S3 bucket |
| Cost | None | EC2 + S3 charges |
| Credentials needed | None | AWS access key, secret, region |
| Remote desktop | Guacamole → container | Guacamole → instance |
| Windows labs | ⚠️ Linux host + KVM only | ✅ supported |

### Local mode — quick start

Guacamole and MobSF are part of the default stack now. One command:

```bash
make labs-up      # builds the Kali image if missing (slow first time), then: docker compose up -d
```

or plain `docker compose up -d` if the `shadowtrust/lab-kali` image is already built
(`make lab-image`). Then open **http://localhost:5500/vm_lab.html**, provision a
**Kali** lab, and its XFCE desktop (CLI + GUI) loads in the page via Guacamole.
No `.env` changes needed — `local` is the default.

**Windows labs**: set `LAB_WINDOWS_ENABLED=true`. They run `dockurr/windows`
(Windows in a KVM VM inside a container) and need a **Linux host with `/dev/kvm`** —
macOS cannot run them and the UI will say so.

Useful targets:

```bash
make labs-list      # show running lab containers
make labs-clean     # force-remove every lab container
make verify-local   # live end-to-end provider check (needs Docker)
make test           # backend test suite
```

### Telemetry in local mode

The Cowrie, Dionaea and Honeytrap containers in `docker-compose.yml` write newline-delimited JSON straight into the watched directory (`./telemetry/raw`, override with `TELEMETRY_DIR` — see `telemetry/README.md`). The collector tails it every `COLLECTOR_INTERVAL_SECONDS` (default 2s) and runs it through the same parser, normalizer and deduplicator the S3 path uses:

```
./telemetry/raw/
├── cowrie/cowrie.json
├── dionaea/dionaea.log
└── honeytrap/events.jsonl
```

Each file is read from the exact byte offset it left off at, not just when its mtime changes, and a content-hash primary key on `normalized_events` makes a full re-read after a crash a no-op rather than a duplicate. See **🍯 Local Honeynet** below for the full sensor → dashboard walkthrough.

### Switching to AWS mode

```env
INFRA_PROVIDER=aws
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=ap-south-1
AWS_SUBNET_ID=subnet-...
AWS_AMI_KALI=ami-...
AWS_AMI_WINDOWS=ami-...
```

Restart the backend. The existing EC2 and S3 code paths are unchanged — nothing was removed in the local-first refactor.

> ⚠️ AWS mode launches billable EC2 instances. The free tier covers only `t2.micro`/`t3.micro` (1 GB RAM), which is not enough for an XFCE or Windows desktop over RDP. Budget accordingly, and terminate labs when you are done.

### Resource profiles

Labs are sized with provider-independent tiers rather than EC2 instance types:

| Profile | vCPU | RAM | Local (Docker limits) | AWS (instance type) |
|---|---|---|---|---|
| `light` | 2 | 2 GB | `--cpus=2 --memory=2g` | `t3.small` |
| `standard` | 4 | 4 GB | `--cpus=4 --memory=4g` | `t3.medium` |
| `heavy` | 6 | 8 GB | `--cpus=6 --memory=8g` | `t3.xlarge` |

Override the AWS mapping with `AWS_INSTANCE_TYPE_LIGHT` / `_STANDARD` / `_HEAVY`.

### Architecture

```
                    Shadow Trust
                        │
              ┌─────────┴─────────┐
              │                   │
         LabProvider        TelemetrySource
              │                   │
       ┌──────┴──────┐      ┌─────┴─────┐
       │             │      │           │
     Docker         AWS   Local FS      S3
     Provider     Provider Source      Source
```

The application layer works only with `lab_id`, `profile`, `status` and `resources`. EC2 identifiers, AMIs and instance types never leave `AWSLabProvider`; container IDs never leave `DockerLabProvider`.

---

## 🍯 Local Honeynet

The honeynet is a separate two-machine demo from the VM Lab above: real Cowrie/Dionaea/Honeytrap containers on one machine, attacked over the network from a second, with every step of the real telemetry path visible on a live dashboard.

```
MacBook #2 (attacker)                    MacBook #1 (main — docker compose up -d)
──────────────────────                   ─────────────────────────────────────────
                                          ┌─ cowrie / dionaea / honeytrap  (honeynet_edge network)
 ssh, nmap, curl  ───────────────────────▶│      │ writes NDJSON
                                          │      ▼
                                          │  telemetry/raw/<sensor>/*.json
                                          │      │ tailed read-only
                                          │      ▼
                                          │  collector → normalizer → MariaDB   (honeynet_app network)
                                          │      │
                                          │      ├─▶ /api/v1/live/*        (REST — overview, events, attackers, sensors)
                                          │      └─▶ /api/v1/live/stream   (SSE — pushed the instant it's stored)
                                          │              │
                                          │              ▼
 http://<main-ip>:5500  ◀───────────────────────  nginx dashboard (Event Log page)
```

The two networks matter: `honeynet_edge` (sensors only) has no route to `honeynet_app` (backend, dashboard) — see the security model comment at the top of `docker-compose.yml`. A fully compromised honeypot can write misleading log lines; it cannot reach the API, the database, or the Docker socket.

### 1. Start it (MacBook #1)

```bash
docker compose up -d          # cowrie, dionaea, honeytrap, backend, frontend
docker compose ps             # confirm all are Up (db/backend show (healthy) once ready)
docker compose logs -f backend   # watch the collector's ingest cycles
```

Open the dashboard: **http://localhost:5500** (or `http://<main-ip>:5500` from the LAN). The **Event Log** page (`events.html`, in the sidebar's *Command Center* group) has live overview counters, an SSE-driven activity feed, per-sensor health, attacker profiles, and a filterable event log. **Tactical Overview** is the full dashboard.

### 2. Find the main machine's LAN IP

```bash
ipconfig getifaddr en0     # macOS, Wi-Fi — use en1/en0 as applicable
```

### 3. Attack it (MacBook #2 — terminal + network access only)

```bash
ssh -p 2222 root@<main-ip>                 # any password in sensors/cowrie/userdb.txt succeeds, e.g. "hunter2"
whoami; uname -a; ls -la; cat /etc/passwd  # Cowrie logs every command

nmap -sT -Pn -p 2222,2223,8022,8023,445,2121,1433 <main-ip>
curl http://<main-ip>:8022/
```

Or run the bundled scenarios, which drive the same real traffic (SSH session, brute force, port scan, HTTP probing, telnet) and refuse anything outside a private/loopback address:

```bash
./scripts/attack_scenarios.sh <main-ip> all
./scripts/attack_scenarios.sh <main-ip> ssh-session   # or: brute-force, port-scan, http-probe, telnet
```

`HONEYPOT_SSH_PORT=22 docker compose up -d` (in `.env`) if you want a bare `ssh root@<main-ip>` instead.

### 4. Watch it land (MacBook #1)

Within a couple of seconds the dashboard's activity feed shows the connection, the login attempt, and each command — no manual refresh. The same data is available directly:

```bash
curl http://localhost:8000/api/v1/live/overview
curl http://localhost:8000/api/v1/live/events?limit=20
curl http://localhost:8000/api/v1/live/attackers
curl -N http://localhost:8000/api/v1/live/stream     # raw SSE feed
```

### 5. Replay mode (no live sensors needed)

Writes through the identical pipeline (same files, same collector, same dedup) — useful for UI work, tests, or a demo without a second machine:

```bash
python3 scripts/replay_telemetry.py --sensor cowrie --rate 2 --seed 42
python3 scripts/replay_telemetry.py --scenario brute-force --sensor cowrie
python3 scripts/replay_telemetry.py --all-sensors --count 60 --rate 5
```

### 6. Tests

```bash
cd backend && source .venv/bin/activate
pip install -r requirements.txt   # first time only
pytest                            # parsers, dedup, ingestion, collector persistence, event bus, provider selection
```

### 7. Reset to a clean slate

```bash
./reset.sh   # option 2 (honeypot data) or 3 (everything) — offers to also truncate telemetry/raw/*.json
```

### 8. Stop

```bash
docker compose down          # keeps volumes/data
docker compose down -v       # also drops named volumes — wipes the MariaDB database (db_data)
```

### Sensor ports (host side, overridable in `.env`)

| Sensor | Port(s) | Protocol |
|---|---|---|
| Cowrie | 2222, 2223 | SSH, Telnet |
| Dionaea | 445, 2121, 1433 | SMB, FTP, MSSQL |
| Honeytrap | 8022, 8023 | HTTP-ish multi-port |

### Normalized event schema

Every sensor's dialect (`app/services/telemetry/normalize.py`) is converted to one shape before it reaches the dashboard or `normalized_events`:

```
event_id · timestamp · sensor · sensor_event_type · source_ip · source_port
destination_ip · destination_port · protocol · username · password
authentication_result · command · payload · session_id · severity
raw_event · metadata
```

`raw_event` keeps the original sensor JSON verbatim (also mirrored into `raw_events` for the pre-existing dashboard/analytics endpoints); nothing is discarded.

### Known limitations

- Dionaea's upstream image is amd64-only — on Apple Silicon it runs under emulation (slower, occasionally unstable).
- The `backend` container currently runs as root inside its own network-isolated, capability-default image (no Docker socket, no route from the honeypot network). The honeypots — the actual attacker-facing containers — already run with `cap_drop: ALL`, `no-new-privileges`, and memory/pid limits. Dropping backend to a non-root user is left as a follow-up rather than shipped unverified.
- `docker compose up -d` pulls public images (`cowrie/cowrie`, `dinotools/dionaea`, `honeytrap/honeytrap`) on first run — that one step needs internet access; nothing after it does.

---

## ⚙️ Configuration

All credentials are in `backend/.env` — already pre-filled for the team.

```env
# Core
SECRET_KEY=your-jwt-secret
ACCESS_TOKEN_EXPIRE_MINUTES=60

# Database (MariaDB — the compose backend overrides host to `db`)
DATABASE_URL=mysql+aiomysql://shadowtrust:shadowtrust@localhost:3307/shadowtrust

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
| 📋 Event Log | `events.html` | Live SSE feed, sensor health, attacker profiles, filterable event log |
| 📂 Investigations | `incidents.html` | Incident workspace — correlated detections, IOCs, ATT&CK, evidence, attack-reconstruction timeline, analyst notes/status. Every incident carries an explainable `risk_breakdown` |
| 🧪 Detection Validation | `validation.html` | SOC testing — run/evaluate controlled scenarios against the real detection pipeline; PASS/FAIL + detection-success / ATT&CK-coverage metrics |
| 📚 Logs | `logs.html` | Unified categorised feed — honeypot telemetry + Splunk events + container logs + audit trail, tagged by a heuristic category layer (auth/recon/exec/c2/malware/…) |
| 🛡️ Splunk Blue Team | `splunk.html` | SIEM console — KPIs, notable events, ad-hoc SPL search, **multi-file log upload** (drag `.log`/`.txt`/`.json`/`.csv`), **purge by source/age** (proxies the `~/splunk-lab` container) |
| 🍯 Nodes | `nodes.html` | Honeypot node status & management |
| 🌍 Geo | `geo.html` | Geolocation attack origin mapping |
| 🧬 Behavior | `behavior.html` | Attacker behavioral profiling |
| ☣️ Malware | `malware.html` | Static + sandbox + secrets pipeline, plus a **ClamAV** container scan and optional **VirusTotal** hash lookup — merged AV verdict banner (worst-of-three) |
| 📱 APK | `apk.html` | Android APK security scanner |
| 🖳 Analysis Lab | `analysis_lab.html` | Interactive terminal into a disposable, **egress-free** Linux sandbox. Every command + connection attempt is captured and fed through the pipeline — the behavioural flow graph, MITRE map and detections build in real time as you type |
| 🎯 MITRE | `mitre.html` | Live ATT&CK matrix — drag technique cards between tactics, set triage status (observed/investigating/mitigated/false-positive), pin, annotate, add techniques manually; overlay persists server-side |
| 📈 Graphs | `graphs.html` | Attack trend analytics & charts |
| 🔑 Credentials | `credentials.html` | Captured credential viewer |
| 🗝️ Credential Mgmt | `credential_mgmt.html` | Secure credential management system |
| 🔗 URL Scan | `urlscan.html` | Multi-engine URL reputation analysis |
| 🖥️ VM Lab | `vm_lab.html` | Provision Kali (local Docker) / Windows (AWS or Linux+KVM) desktops, in-page via Guacamole |
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
| MITRE | `/api/v1/mitre` | ATT&CK mapping + `/annotations` triage overlay + `/catalog` picker + `/analytics` (per-technique event/incident/confidence rollup) |
| Logs | `/api/v1/logs/feed` | Unified categorised log feed (`/summary` for KPI counts) |
| Splunk | `/api/v1/splunk` | Proxy to `~/splunk-lab` — `/search` `/upload` `/sources` `/purge` `/notable` |
| **Incidents** | `/api/v1/incidents` | Incident CRUD, `/{id}` full correlated view, `/{id}/timeline` attack reconstruction, `/{id}/notes`, `/stats` |
| **Detections** | `/api/v1/detections` | Detection rows, `/rules` (list bundled Sigma-style rules), `/rules/reload` (admin), `/stats` |
| **Evidence** | `/api/v1/evidence` | Chain of custody — `/{id}`, `/{id}/verify` (integrity), `/{id}/sample` (raw malware, ADMIN + clearance 3, streamed never static) |
| **SOC testing** | `/api/v1/soc-testing` | `/scenarios`, `/scenarios/{id}/run` (admin), `/runs`, `/coverage` |
| **Admin diag** | `/api/v1/admin/diagnostics` | The full operator status + credentials + attack commands that used to be on `/health` — now ADMIN-only |
| **Analysis Lab** | `/api/v1/analysis-shell` | `/start` (spawn sandbox), `WS /{id}/pty` (terminal), `/{id}` (captured commands/connections), `/{id}/stop`. Any authenticated user; time-boxed; container has no egress + no Docker socket |
| **Behavior** | `/api/v1/behavior/profile` | Adds `?session=<id>` to scope the profile to one Analysis Lab session |
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

A default super admin is seeded on first boot: **`admin@gmail.com` / `admin`** — change the
password immediately. To promote another account: register via `/register.html`, then in
phpMyAdmin (http://localhost:8081) open `shadowtrust` → `users` and set that row's `role`
to `SUPER_ADMIN` and `status` to `ACTIVE`.

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
│   │   ├── db/                 # SQLAlchemy async engine + MariaDB init
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
│   └── worker/                 # Node.js background worker (opt-in stub)
│
├── database/
│   ├── init/                   # SQL run on first MariaDB boot (creates test schema)
│   └── schema_*.sql            # historical reference schemas
│
├── vm_scripts/                 # Honeypot node setup & log collector
├── scripts/                    # Seed data & testing utilities
├── guacamole/init/initdb.sql   # Guacamole Postgres schema (mounted by docker-compose)
├── docker/lab-kali/            # Kali + XFCE + XRDP image for local VM Lab
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
| Background Worker | Node.js (opt-in, `--profile extras`) |
| Frontend | HTML5, CSS3 (Neon Dark), Vanilla JavaScript |
| Web Server | Nginx 1.25 Alpine |
| Database | MariaDB 11 (SQLAlchemy async + aiomysql) |
| DB Admin GUI | phpMyAdmin (http://localhost:8081) |
| Auth | JWT (PyJWT) |
| Cloud (opt-in) | AWS EC2, S3, IAM, Systems Manager |
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
