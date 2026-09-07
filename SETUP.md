# Shadow Trust — SOC Honeynet
## Complete Setup Guide (Fresh GitHub Clone)

> Follow this exactly, top to bottom. Takes ~10 minutes on a decent internet connection.

---

## WHAT YOU NEED BEFORE STARTING

| Requirement | Version | Download |
|-------------|---------|----------|
| **Docker Desktop** | Latest | https://www.docker.com/products/docker-desktop |
| **Git** | Any | https://git-scm.com |
| **A terminal** | — | Terminal (Mac/Linux) or Git Bash (Windows) |

> **Windows users:** Use Git Bash for all commands below, NOT Command Prompt or PowerShell.

> **That's it.** You do NOT need Python, Node.js, pip, or anything else installed locally. Docker handles everything.

---

## STEP 1 — Clone the Repository

```bash
git clone https://github.com/ayushsingh-byte/ShadowTrust.git
cd ShadowTrust
```

---

## STEP 2 — Create Your Environment File

The project needs a `backend/.env` file with credentials. A template is provided.

```bash
cp backend/.env.example backend/.env
```

Now open `backend/.env` in any text editor and fill in the values:

```
SECRET_KEY="any-long-random-string-you-make-up"
```

> Generate one instantly:
> ```bash
> python3 -c "import secrets; print(secrets.token_hex(32))"
> ```
> Copy the output and paste it as `SECRET_KEY`.

**The rest of the `.env` fields:**

| Field | Required? | What to put |
|-------|-----------|-------------|
| `SECRET_KEY` | ✅ YES | Any random 32+ char string (see above) |
| `DATABASE_URL` | ✅ Pre-filled | MariaDB URL. Default works out of the box; compose overrides the host to `db`. |
| `SMTP_HOST / SMTP_USER / SMTP_PASS` | ⚠️ Optional | Only needed for email credential delivery |
| `TWILIO_*` | ⚠️ Optional | Only needed for WhatsApp alerts |
| `AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY` | ⚠️ Optional | Only for AWS mode (S3 telemetry, Windows/EC2 labs) |
| `VIRUSTOTAL_API_KEY` | ⚠️ Optional | Malware Lab cross-checks file hashes against VirusTotal when set. Without it, ClamAV alone drives the AV verdict. Free key: virustotal.com → profile → API key |
| `SPLUNK_API_URL / SPLUNK_WEB_URL / SPLUNK_USER / SPLUNK_PASSWORD` | ⚠️ Pre-filled | Points the **Splunk Blue Team** page at the `~/splunk-lab` Splunk. Defaults assume `admin` / `ChangeMe123!` on `https://host.docker.internal:8089`. |

> **Minimum to get the platform running:** Only `SECRET_KEY` is required. Everything else is optional — you can use the dashboard, events, malware analysis, the admin panel without any external credentials.

### Malware engine (ClamAV)

The `clamav` container is part of the main compose file and starts automatically.
On first boot it downloads ~1.5 GB of signatures (~5 min) — until then the Malware
Lab still runs and the AV banner shows *"engine offline"*. Check readiness on the
`/health` page (ClamAV row) or with `docker compose logs clamav`.

---

## STEP 3 — Run Setup (One Command)

```bash
./setup.sh
```

**What this does automatically:**
- Checks Docker is installed and running
- Detects your OS (macOS / Linux / Windows) and sets the right Docker host
- Creates all required directories (`scans/`, `mobsf_service/data/`)
- Creates empty database files so Docker doesn't make them directories
- Builds all Docker images (takes 3–5 min first time, instant after)
- Starts all services in background

**You should see at the end:**
```
╔══════════════════════════════════════════════════════╗
║   Shadow Trust is running!                           ║
╚══════════════════════════════════════════════════════╝

  Open in your browser:
    Dashboard   →  http://localhost:5500
    API Docs    →  http://localhost:8000/docs
    MobSF Svc  →  http://localhost:5055
    Node API    →  http://localhost:3000
```

---

## STEP 4 — Open the Platform

Open your browser and go to:

```
http://localhost:5500
```

**Default login credentials (auto-seeded on first run):**
```
Email:    admin@gmail.com
Password: admin
```

> Change this password immediately after first login via Profile page.

---

## STEP 5 (Optional) — Generate live telemetry

Poke the honeypots so the dashboards fill with real data:

```bash
./scripts/attack_scenarios.sh localhost all      # brute-force, port-scan, HTTP probes
# or: python3 scripts/replay_telemetry.py --all-sensors --count 60 --rate 5
```

---

## STEP 6 — VM Lab (Browser RDP/SSH)

The VM Lab page (`vm_lab.html`) provisions disposable Kali desktops as local
Docker containers and shows them in the browser via Guacamole. Guacamole + the
Kali image are part of the default stack now:

```bash
make labs-up          # builds shadowtrust/lab-kali if missing (slow first run), then docker compose up -d
```

Open **http://localhost:5500/vm_lab.html**, click **PROVISION** on the *Kali
Linux* card, wait for `READY`, and the XFCE desktop loads in the page. In-VM
login: `kali / kali`.

- **Windows labs**: set `LAB_WINDOWS_ENABLED=true` in `.env`. Needs a **Linux
  host with `/dev/kvm`** — not possible on macOS.
- **AWS EC2 labs** (Windows on any host): set `INFRA_PROVIDER=aws` and fill in
  `aws_connection.html`.

> Guacamole: `http://localhost:8080/guacamole` (login `guacadmin / guacadmin`) —
> open it directly to watch live lab sessions.

---

## ALL SERVICES AT A GLANCE

| Service | URL | What it is |
|---------|-----|-----------|
| **Dashboard** | http://localhost:5500 | Main SOC analyst interface |
| **Backend API** | http://localhost:8000 | FastAPI backend |
| **API Docs** | http://localhost:8000/docs | Interactive Swagger UI |
| **MobSF** | http://localhost:5055 | APK analysis service |
| **Node Collector** | http://localhost:3000 | Edge honeypot collector |
| **Guacamole** | http://localhost:8080/guacamole | VM Lab remote desktop (guacadmin/guacadmin) |
| **Status page** | http://localhost:8000/health | Everything at a glance + logins |

---

## USEFUL COMMANDS

```bash
# Check all containers are running
docker compose ps

# View logs (all services)
docker compose logs -f

# View logs (specific service)
docker compose logs -f backend
docker compose logs -f frontend

# Stop everything
docker compose down

# Stop and remove all data (full reset)
docker compose down -v

# Rebuild after code changes
docker compose up --build -d

# Restart just the backend
docker compose restart backend
```

---

## RESETTING DATA

A reset script is included. It's interactive and **never touches your login credentials**.

```bash
./reset.sh
```

Menu options:
- `2` — Clear honeypot / attack event data
- `3` — Clear everything (keeps users and credentials)
- `q` — Quit

---

## TROUBLESHOOTING

### "Permission denied: ./setup.sh"
```bash
chmod +x setup.sh
./setup.sh
```

### "Docker daemon is not running"
Open Docker Desktop and wait for it to fully start (whale icon stops animating), then retry.

### "Port already in use" (8000, 5500, etc.)
Either stop whatever is using that port, or change the port in `.env`:
```bash
# Edit .env at project root:
BACKEND_PORT=8001
FRONTEND_PORT=5501
```
Then rerun `docker compose up -d`.

### Backend keeps restarting / unhealthy
Almost always means `backend/.env` is missing or has a bad `SECRET_KEY`. Check:
```bash
docker compose logs backend
```
If you see `SECRET_KEY` errors, re-check Step 2.

### Database connection errors on startup
The backend needs the `db` (MariaDB) container healthy first. `docker compose up`
handles the ordering, but if the backend logs show `Can't connect to MySQL server`:
```bash
docker compose up -d db          # start just the database
docker compose logs -f db        # wait for "ready for connections"
docker compose up -d             # then the rest
```
To wipe the database and start fresh: `docker compose down -v && docker compose up -d`.

### phpMyAdmin can't log in
Use server `db`, username `shadowtrust`, password `shadowtrust` (or whatever you set
for `MARIADB_USER` / `MARIADB_PASSWORD` in the root `.env` **before first boot** —
changing them afterwards needs `docker compose down -v`).

### Port 3307 (or 8081) already in use
Another MySQL/MariaDB (or app) owns it. Change `MARIADB_PORT` / `PHPMYADMIN_PORT` in
the root `.env` and re-run `docker compose up -d`.

### Login says "Failed to fetch"
Backend is not running. Check:
```bash
docker compose ps        # all containers should show "running"
docker compose logs backend   # look for errors
```

### VM Lab shows "FATAL ERROR: AWS Orchestrator failed"
- Make sure your AWS credentials are saved in `aws_connection.html`
- Click **VALIDATE KEYS** first to confirm credentials work
- The button resets to PROVISION automatically — click it again to launch

### Windows-specific: `./setup.sh` doesn't run
Use Git Bash (not PowerShell or CMD):
```bash
bash setup.sh
```

---

## PROJECT STRUCTURE (Quick Reference)

```
ShadowTrust/
├── backend/                  FastAPI backend (Python 3.11)
│   ├── app/
│   │   ├── api/v1/           All API endpoints
│   │   ├── models/           Database models (SQLAlchemy)
│   │   ├── services/         Business logic (malware, AWS, telemetry, labs...)
│   │   └── db/               SQLAlchemy async engine + MariaDB init
│   ├── .env.example          ← Template — copy to .env
│   ├── requirements.txt      Python dependencies
│
├── frontend/                 HTML/JS dashboard (served by Nginx)
│   ├── *.html                All pages
│   ├── js/                   JavaScript modules
│   └── nginx.conf            Nginx config
│
├── database/init/            SQL run on first MariaDB boot (creates test schema)
│
├── guacamole/init/initdb.sql   Guacamole Postgres schema (mounted by the main compose)
├── docker/lab-kali/          Kali + XFCE + XRDP image for local VM Lab containers
│
├── docker-compose.yml        Main service stack
├── Dockerfile.backend        Backend container build
├── Dockerfile.mobsf          MobSF container build
├── Dockerfile.node           Node.js services build
├── setup.sh                  ← ONE-CLICK SETUP (run this)
├── reset.sh                  Data reset utility
├── STUDY.md                  Full technical reference document
└── SETUP.md                  This file
```

---

## MINIMUM SETUP CHECKLIST

```
[ ] Docker Desktop installed and running
[ ] git clone <repo>
[ ] cp backend/.env.example backend/.env
[ ] Added SECRET_KEY to backend/.env
[ ] ./setup.sh  (ran successfully)
[ ] http://localhost:5500 opens in browser
[ ] Login with admin@gmail.com / admin works
```

**Optional extras:**
```
[ ] ./scripts/attack_scenarios.sh localhost all      (generate live telemetry)
[ ] make labs-up                                    (builds Kali image + starts everything)
[ ] AWS credentials added in aws_connection.html     (S3 logs + EC2 VMs)
```

---

*Shadow Trust SOC Honeynet v2.0 — Setup Guide*
