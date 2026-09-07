<div align="center">

<img src="frontend/hero_image.png" alt="Shadow Trust" width="100%">

# 🛡️ Shadow Trust

**Honeypot-driven Security Operations Center — deception, detection, investigation, and compliance in one stack.**

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![MariaDB](https://img.shields.io/badge/MariaDB-11-003545?style=flat-square&logo=mariadb&logoColor=white)](https://mariadb.org)
[![Tests](https://img.shields.io/badge/tests-133%20passing-3fb950?style=flat-square)](backend/tests)
[![License](https://img.shields.io/badge/License-Private-red?style=flat-square)](.)

[Overview](#overview) · [Quick start](#quick-start) · [Dashboard](#dashboard) · [Reports &amp; compliance](#reports--compliance) · [Architecture](#architecture) · [Configuration](#configuration) · [Team setup](#team-setup)

</div>

---

## Overview

Shadow Trust runs a small network of real honeypots (SSH/Telnet, SMB/FTP/MSSQL, HTTP), ingests everything they see, and turns that telemetry into detections, correlated incidents, attacker behavior profiles, MITRE ATT&CK coverage, and designed PDF reports — through a dark‑theme operator dashboard.

It is a **local‑first** platform: `docker compose up` on one machine brings up the whole thing, no cloud account required. An optional AWS mode adds S3 telemetry ingestion and EC2 lab VMs.

**Design principle — nothing fake.** Every number on every page traces to a real query or a real engine. Where a capability needs an external service that isn't configured (CAPE sandbox, VirusTotal, SMTP), the UI says *"not configured"* rather than showing simulated output.

> Built for people who want operational visibility from a honeynet — not a demo dashboard.

---

## Feature highlights

**Deception & capture**
- Three attack‑facing sensors (`cowrie`, `dionaea`, `honeytrap`) on an isolated Docker network — nothing bridges the edge network to the app network.
- Cursor‑based log collector tails sensor output every few seconds; raw events are normalized into a sensor‑agnostic schema and deduplicated by content hash.

**Detection & investigation**
- Rule engine over YAML detection rules (`backend/detections/*.yml`) with **Sigma** rule support; runs a correlation cycle every ~20 s.
- Detections roll up into **Incidents** with an explainable `risk_breakdown`, an attack‑reconstruction timeline, linked IOCs, ATT&CK techniques, evidence chain‑of‑custody, and an analyst audit trail.
- **Detection validation** — fire a controlled scenario (target hard‑locked to `127.0.0.1`) at the honeypots, wait one detection cycle, and grade the real detections it produced. PASS / PARTIAL / FAIL with detection‑rate and ATT&CK‑coverage metrics.
- **Behavior profiling** — builds the attacker interaction graph, computes real centrality (networkx), and classifies activity *style* (automated scanner, credential‑stuffing bot, hands‑on‑keyboard, …) from measured signals. No named‑APT attribution.

**Analysis tools**
- **Binary analysis** — static parsing + YARA + ClamAV + a 30‑pattern secret detector. Dynamic detonation via a real CAPE Sandbox when `CAPE_URL` is set.
- **APK inspector** — MobSF‑backed Android analysis.
- **URL scanner** — live DNS/SSL/HTTP probing, entropy & homograph checks, real WHOIS, real IP geolocation.
- **Analysis Lab** — an interactive terminal into a disposable, **egress‑free** Linux sandbox (`internal: true` network). Every command and outbound connection attempt is captured and fed through the pipeline; the behavior graph, ATT&CK map and detections build live as you type.
- **Virtual Lab** — provision disposable Kali (local Docker) or Windows (Linux+KVM / AWS EC2) desktops, streamed in‑page over Apache Guacamole.

**Reports & compliance** — see [below](#reports--compliance).

---

## Quick start

**Prerequisites:** Docker Desktop (or Docker Engine + Compose v2) and Git. Nothing else — no local Python or Node.

```bash
git clone https://github.com/ayushsingh-byte/ShadowTrust-Security.git
cd ShadowTrust-Security

cp backend/.env.example backend/.env
# set SECRET_KEY:  python3 -c "import secrets; print(secrets.token_hex(32))"

./setup.sh            # detects your OS, builds images, starts the stack
```

Then open **http://localhost:5500** and log in with the seeded account:

```
admin@gmail.com  /  admin        ← change this immediately (Profile page)
```

Generate some live telemetry so the dashboards fill:

```bash
./scripts/attack_scenarios.sh localhost all
# or, no live sensors needed:
python3 scripts/replay_telemetry.py --all-sensors --count 60 --rate 5
```

| Service | URL | Notes |
|---|---|---|
| Dashboard | http://localhost:5500 | main operator UI |
| API + Swagger | http://localhost:8000/docs | FastAPI backend |
| Operator status | http://localhost:8000/health | set `HEALTH_PAGE=1` — local only, prints seeded creds |
| phpMyAdmin | http://localhost:8081 | server `db`, `shadowtrust` / `shadowtrust` |
| MobSF | http://localhost:5055 | APK engine |
| Guacamole | http://localhost:8080/guacamole | Virtual Lab desktops (`guacadmin` / `guacadmin`) |

Full walkthrough (Windows notes, ports, troubleshooting): [`SETUP.md`](SETUP.md).

---

## Dashboard

The shared sidebar (`frontend/js/sidebar.js`) groups the app pages:

| Group | Pages |
|---|---|
| **Command Center** | Tactical Overview · Investigations · Event Log · Logs · **Reports** |
| **Grid Monitoring** | Honeypot Nodes · Splunk Blue Team · Geo Intelligence |
| **Intelligence** | MITRE Matrix · Detection Validation · Attack Analytics · Credentials Vault · Behavior Profiling · Analysis Lab |
| **Governance** | **GRC & SOC 2** |
| **Tools Suite** | Binary Analysis · URL Scanner · APK Inspector · Virtual Lab |
| **System** *(admin)* | Admin Access · Admin Console · Officer Profile |

Plus a public landing site (`index.html`, `architecture.html`, `docs.html`, `features.html`, `usecases.html`, `status.html`) and the auth pages (`login.html`, `admin_login.html`, `forgot_password.html`).

---

## Reports & compliance

**PDF report engine** (`backend/app/services/reporting/`, WeasyPrint + Jinja2). Every report is generated from live data and carries a **provenance block** on the cover — who generated it, when (UTC + operator TZ), the data window, the source systems queried, row counts, and the document SHA‑256. Files are stored server‑side and served only through an authenticated download endpoint; the **Reports** page lists every one that's been produced.

| Report | Source |
|---|---|
| Executive summary | dashboard stats, detections, incidents |
| Geographic threat intelligence | events + IP geolocation |
| Incident report | one incident — detections, timeline, evidence, analyst activity |
| DFIR / forensic | attacker sessions, command history, behavior analysis |
| Captured credentials | parsed login payloads + issuance audit trail |
| Detection validation & coverage | scenario runs graded against real detections |
| Malware analysis | static + YARA + ClamAV + secrets |
| **SOC 2 readiness self‑assessment** | see below |

**SOC 2 / GRC** (`backend/app/services/compliance/`). Maps the **49 Trust Services Criteria** (CC1–CC9, A1, C1, PI1, P1–P8) to **25 live evidence collectors** that query the running system — auth data, detection‑engine stats, incident MTTR, access logs, evidence‑integrity checks, pipeline counts, container config. Each control is scored `met` / `partial` / `gap`, or `manual` when it can't be evaluated from system data (never auto‑passed). Produces a live **GRC dashboard**, an automated **risk register** (derived from open incidents, coverage gaps, high‑risk sessions), CSV/JSON export, and a designed readiness PDF.

> This is an **internal readiness self‑assessment**, not a SOC 2 examination — a real attestation requires an independent licensed CPA firm. Use it to find and close gaps before engaging an auditor.

---

## Architecture

```
                 honeynet_edge (isolated)              honeynet_app
   ┌───────────────────────────────────┐   ┌──────────────────────────────────────┐
   │  cowrie   dionaea   honeytrap     │   │  backend (FastAPI)  ── MariaDB (db)   │
   │  SSH/telnet  SMB/FTP/MSSQL  HTTP  │   │     │  detection engine                │
   └───────────────┬───────────────────┘   │     │  session / correlation engine    │
                   │  log files             │     │  telemetry collector             │
                   ▼  (read-only mount)      │     │  report engine (WeasyPrint)      │
        telemetry/raw/<sensor>/  ───────────┼───▶ │  compliance / risk engine        │
                                            │                                        │
   frontend (nginx)  guacamole + guacd + pg │  mobsf   clamav   analysis sandbox     │
   phpmyadmin                               │  (Virtual Lab)     (egress-free)        │
   └────────────────────────────────────────┴────────────────────────────────────────┘
```

- The **edge** and **app** Docker networks never bridge — a compromised backend can't reach the honeypots and vice‑versa.
- Detection rules, YARA rules and scenario definitions are mounted **read‑only**.
- The Docker socket is mounted into the backend only to power the Virtual Lab / Analysis Lab; keep port 8000 off untrusted networks.

More detail: [`ARCHITECTURE.md`](ARCHITECTURE.md) · [`AWS_CLOUD_ARCHITECTURE.md`](AWS_CLOUD_ARCHITECTURE.md).

---

## Local mode vs AWS mode

| | Local (`INFRA_PROVIDER=local`) | AWS (`INFRA_PROVIDER=aws`) |
|---|---|---|
| Telemetry | collector tails `telemetry/raw/` | S3 pipeline poller |
| Virtual Lab | Kali as a local Docker container | Windows / Kali as EC2 instances |
| Cost | none | your AWS bill |

Local is the default and needs no configuration. Switch by setting `INFRA_PROVIDER=aws` and filling in credentials on the **AWS** page.

---

## Configuration

`backend/.env` (from `backend/.env.example`). Only `SECRET_KEY` is required.

```bash
SECRET_KEY="<32+ random chars>"          # required
DATABASE_URL="mysql+aiomysql://…"        # pre-filled; compose overrides host to `db`

# optional — features degrade gracefully when unset
SMTP_HOST / SMTP_USER / SMTP_PASS        # email credential delivery
TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN   # WhatsApp alerts
CAPE_URL                                 # dynamic malware sandbox
SPLUNK_API_URL / SPLUNK_WEB_URL          # Splunk Blue Team page (separate ~/splunk-lab stack)
```

Root `.env` (from `.env.example`, created by `setup.sh`) holds host port mappings and DB passwords.

**Local‑only conveniences** — off by default, enable in `.env`:

```bash
HEALTH_PAGE=1      # GET /health status page (unauthenticated, prints seeded creds)
DEV_BYPASS=1       # "Developer Bypass" button on the login page (needs INFRA_PROVIDER=local too)
```

> ⚠️ **Never commit `.env`.** The `.gitignore` excludes every `.env`; only `.env.example` files are tracked. Keep this repo private, and set `HEALTH_PAGE=0` / `DEV_BYPASS=0` anywhere it's reachable from an untrusted network.

---

## Make targets

```bash
make setup          # one-click setup wizard
make up / down      # start / stop the stack (data volumes preserved)
make rebuild        # rebuild images + restart (after code changes)
make logs-backend   # tail one service
make db-shell       # MariaDB prompt
make test           # backend test suite (needs the db container up)
make labs-up        # build the Kali image if missing, then start everything
make labs-clean     # force-remove every lab container
make nuke           # ⚠ destructive: containers + images + volumes
make help           # full list
```

---

## Tech stack

| Layer | Tech |
|---|---|
| Backend | Python 3.11, FastAPI, SQLAlchemy (async), aiomysql |
| Database | MariaDB 11 (phpMyAdmin at :8081) |
| Frontend | static HTML/JS/CSS served by nginx; Chart.js |
| Reports | WeasyPrint + Jinja2 |
| Detection | YAML rules + Sigma; networkx for graph analysis |
| Malware | pefile/static parsers, `yara-python`, ClamAV, MobSF, optional CAPE |
| Honeypots | cowrie, dionaea, honeytrap |
| Virtual Lab | Apache Guacamole + guacd + PostgreSQL; Kali/XFCE/XRDP image |
| Orchestration | Docker Compose; boto3 for AWS mode |

---

## Project structure

```
backend/
  app/
    api/v1/endpoints/     REST endpoints (auth, dashboard, incidents, detections,
                          reports, compliance, malware, labs, splunk, …)
    services/
      reporting/          PDF report engine + providers + templates
      compliance/         SOC 2 framework, evidence collectors, assessment, risk register
      telemetry/          collector + normalizer (local + S3 sources)
      detection_engine.py, session_engine.py, timeline_builder.py, …
    models/all_models.py  SQLAlchemy models (Detection, Incident, Evidence, GeneratedReport, …)
  detections/*.yml        detection rules
  scenarios/*.yml         controlled attack scenarios for detection validation
  yara_rules/             YARA signatures
  tests/                  133 tests

frontend/                 all dashboard pages + js/ + css/
docker/
  analysis-seed/          seeded "compromised host" filesystem for the Analysis Lab
  lab-kali/               Kali desktop image for the Virtual Lab
sensors/                  cowrie / dionaea / honeytrap config
scripts/                  attack_scenarios.sh, replay_telemetry.py, …
docker-compose.yml        the whole stack
setup.sh                  one-click setup
```

---

## Testing

```bash
docker compose up -d db          # tests need the database
make test                        # or: docker compose exec backend python -m pytest
```

133 tests cover the telemetry pipeline, detection engine, detection validation, timeline/evidence integrity, container‑manager policy, lab lifecycle, malware isolation and health hardening.

---

## Security notes

- Honeypot sensors are **meant** to be attacked — that's the point. The edge network isolation keeps that contained.
- `backend/quarantine/` (malware samples) and `backend/evidence/` (incident evidence) are never served by nginx and never committed.
- The seeded `admin@gmail.com / admin` account and the `/health` page are local conveniences — lock both down before exposing the platform.
- For a public deployment: put a reverse proxy in front, expose only 443, firewall port 8000, and consider a Docker‑socket proxy instead of the raw socket mount.

---

## Additional documentation

| Doc | Contents |
|---|---|
| [`SETUP.md`](SETUP.md) | full setup guide, Windows notes, troubleshooting |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | system architecture |
| [`AWS_CLOUD_ARCHITECTURE.md`](AWS_CLOUD_ARCHITECTURE.md) | AWS mode design |
| [`PROJECT_DOCUMENTATION.md`](PROJECT_DOCUMENTATION.md) · [`STUDY.md`](STUDY.md) | deep technical reference |

---

<div align="center">
<sub>Shadow Trust · SOC Honeynet · v2</sub>
</div>
