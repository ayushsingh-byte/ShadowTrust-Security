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
| `SUPABASE_URL` | ⚠️ Optional | Leave blank if not using Supabase |
| `SUPABASE_KEY` | ⚠️ Optional | Leave blank if not using Supabase |
| `SMTP_HOST / SMTP_USER / SMTP_PASS` | ⚠️ Optional | Only needed for email credential delivery |
| `TWILIO_*` | ⚠️ Optional | Only needed for WhatsApp alerts |
| `AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY` | ⚠️ Optional | Only needed for VM Lab and S3 log sync |

> **Minimum to get the platform running:** Only `SECRET_KEY` is required. Everything else is optional — you can use the dashboard, events, malware analysis, sector intelligence, admin panel without any external credentials.

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

## STEP 5 (Optional) — Load Demo Data

If you want the Sector dashboards to show live attack data immediately:

```bash
# In a new terminal tab, while the platform is running:
docker exec -it soc_backend python demo_seed.py
```

This adds 9 demo targets (one per sector) and injects 360 realistic attack events so dashboards show real charts immediately.

---

## STEP 6 (Optional) — Enable VM Lab (Browser RDP/SSH)

The Virtual Lab page lets you provision AWS EC2 instances and access them in the browser. This needs Guacamole running separately.

```bash
# In a new terminal tab:
cd guacamole
docker compose up -d
cd ..
```

Then open `http://localhost:5500/aws_connection.html` and fill in your AWS credentials.

> Guacamole runs on port `8080`. You can visit `http://localhost:8080/guacamole` directly (default login: `guacadmin / guacadmin`).

---

## ALL SERVICES AT A GLANCE

| Service | URL | What it is |
|---------|-----|-----------|
| **Dashboard** | http://localhost:5500 | Main SOC analyst interface |
| **Backend API** | http://localhost:8000 | FastAPI backend |
| **API Docs** | http://localhost:8000/docs | Interactive Swagger UI |
| **MobSF** | http://localhost:5055 | APK analysis service |
| **Node Collector** | http://localhost:3000 | Edge honeypot collector |
| **Guacamole** | http://localhost:8080/guacamole | VM browser terminal (Step 6 only) |

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
- `1` — Clear sector/demo data only
- `2` — Clear honeypot/attack event data only
- `3` — Clear everything (but keeps users and credentials)
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

### `ingestion.db` error / SQLite error on startup
```bash
# Stop containers first
docker compose down

# Create the DB files manually
touch backend/ingestion.db backend/honeynet.db

# Start again
docker compose up -d
```

### Login says "Failed to fetch"
Backend is not running. Check:
```bash
docker compose ps        # all containers should show "running"
docker compose logs backend   # look for errors
```

### Sectors dashboard shows no data
Run the seed script (Step 5) to populate demo data.

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
│   │   ├── services/         Business logic (malware, AWS, sectors...)
│   │   └── db/               SQLite setup and init
│   ├── .env.example          ← Template — copy to .env
│   ├── requirements.txt      Python dependencies
│   └── demo_seed.py          Demo data population script
│
├── frontend/                 HTML/JS dashboard (served by Nginx)
│   ├── *.html                All pages
│   ├── js/                   JavaScript modules
│   ├── demo/                 9 sector honeypot portals
│   └── nginx.conf            Nginx config
│
├── guacamole/                Guacamole VM terminal stack (optional)
│   ├── docker-compose.yml    Run separately for VM Lab feature
│   └── init/initdb.sql       Guacamole PostgreSQL schema
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
[ ] docker exec -it soc_backend python demo_seed.py  (sector demo data)
[ ] cd guacamole && docker compose up -d             (VM Lab terminal)
[ ] AWS credentials added in aws_connection.html     (S3 logs + EC2 VMs)
```

---

*Shadow Trust SOC Honeynet v2.0 — Setup Guide*
