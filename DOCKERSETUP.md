# DOCKERSETUP — rebuild every Docker image for Shadow Trust

Snapshot taken 2026-09-25 before all images were deleted to free disk space.
All images below are recreatable from this repo + Docker Hub. **Data lives in
volumes, not images — keep the volumes.**

---

## 1. Images that existed (19 images, ~17 GB)

| Image | Size | What it does | Source |
|---|---|---|---|
| `soc/backend:latest` | 689 MB | FastAPI backend + telemetry collector + detection engine (:8000) | built — `Dockerfile.backend` |
| `soc/mobsf:latest` | 348 MB | APK analysis proxy service for apk.html (:5055) | built — `Dockerfile.mobsf` |
| `shadowtrust/lab-kali:latest` | 1.42 GB | Kali + XFCE + XRDP desktop for VM Lab (vm_lab.html) | built — `docker/lab-kali/Dockerfile` |
| `shadowtrust/analysis-shell:latest` | 488 MB | Egress-free Debian sandbox for analysis_lab.html | built — `Dockerfile.analysis` |
| `st-attacker:latest` | 69 MB | Alpine attacker that drives real honeypot traffic | built — `scripts/attacker/Dockerfile` (by `scripts/populate_lab.sh`) |
| `cowrie/cowrie:latest` | 428 MB | SSH/Telnet honeypot (:2222) | pulled |
| `dinotools/dionaea:latest` | 266 MB | Malware-capture honeypot (:445, :21, :1433) | pulled |
| `honeytrap/honeytrap:latest` | 54 MB | Multi-port honeypot (:8022, :8023) | pulled |
| `mariadb:11` | 484 MB | Main app database (:3306) | pulled |
| `phpmyadmin:5` | 827 MB | DB web GUI (:8081) | pulled |
| `guacamole/guacd:latest` | 378 MB | Guacamole remote-desktop daemon (VM Lab) | pulled |
| `guacamole/guacamole:latest` | 1.12 GB | Guacamole web UI (:8080/guacamole) | pulled |
| `postgres:15` | 654 MB | Guacamole's DB (users, connections) | pulled |
| `nginx:1.25-alpine` | 77 MB | Frontend dashboard + API proxy (:5500) | pulled |
| `clamav/clamav-debian:latest` | 577 MB | Antivirus engine (malware scan) | pulled |
| `opensecurity/mobile-security-framework-mobsf:latest` | 3.37 GB | Real MobSF engine; spawned on demand by backend as container `shadowtrust-mobsf-engine` | pulled automatically by backend on first APK scan |
| `splunk/splunk:latest` | 6.52 GB | Splunk Blue Team page (web :8009, API :8089) | pulled — **compose lives outside repo**, see §4 |
| `debian:12-slim` | 138 MB | Base image for analysis-shell | pulled during build |
| `alpine:3.19` | 12 MB | Base image for st-attacker | pulled during build |

Not built at snapshot time (optional, `extras` profile): `soc/node-api`, `soc/worker` (`Dockerfile.node`).

---

## 2. Delete images safely (keeps data)

```bash
cd ~/Documents/ShadowTrust-Security-main
docker compose down                       # stop + remove containers (volumes kept)
(cd ~/splunk-lab && docker compose down)  # stop Splunk (volumes kept)
docker rm -f shadowtrust-mobsf-engine 2>/dev/null
docker image prune -a -f                  # delete ALL images
docker builder prune -a -f                # delete build cache (~8 GB)
```

**NEVER run these — they delete data permanently:**
`docker compose down -v` · `docker system prune --volumes` · `docker volume prune` · `make nuke`

Volumes to keep:

| Volume | Holds | Recreatable? |
|---|---|---|
| `honeynet_db_data` | MariaDB — all app data, users, incidents, events | **NO** — back up first (§5) |
| `honeynet_guac_pgdata` | Guacamole users + connections | re-initialised on fresh start |
| `honeynet_clamav_db` | ClamAV signatures (~1.5 GB) | yes, re-downloads (slow) |
| `splunk-lab_splunk-var`, `splunk-lab_splunk-etc` | Splunk indexes + config | **NO** — indexed data lost if deleted |

`telemetry/` and other repo files are on disk, not in Docker — unaffected.

---

## 3. Recreate everything (practical day)

Needs: Docker Desktop running + internet. First run ~15–30 min (Kali + Splunk are big).

```bash
docker desktop start                      # if daemon is down
cd ~/Documents/ShadowTrust-Security-main

# 1) Lab images not built by compose
make lab-image                            # shadowtrust/lab-kali   (slowest, 5–15 min)
make analysis-image                       # shadowtrust/analysis-shell

# 2) Main stack: pulls all Hub images + builds soc/backend, soc/mobsf, then starts
docker compose up -d --build
#   optional extras (node-api, worker):
#   docker compose --profile extras up -d --build

# 3) Splunk (separate compose, §4)
(cd ~/splunk-lab && docker compose up -d)

# 4) Check
docker compose ps
```

Shortcut for steps 1(kali)+2: `make labs-up`.

Auto-built on demand (no action needed):
- `st-attacker` → built by `scripts/populate_lab.sh` when you run it.
- MobSF engine → backend pulls `opensecurity/mobile-security-framework-mobsf` on first APK scan
  (pre-pull to avoid a 3.4 GB wait during demo: `docker pull opensecurity/mobile-security-framework-mobsf:latest`).
- ClamAV → downloads signatures on first start (few minutes before scans work).

---

## 4. Splunk compose (outside repo — `~/splunk-lab/docker-compose.yml`)

If that folder is gone, recreate it with exactly this:

```yaml
services:
  splunk:
    image: splunk/splunk:latest
    platform: linux/amd64
    container_name: splunk
    environment:
      SPLUNK_START_ARGS: --accept-license
      SPLUNK_GENERAL_TERMS: --accept-sgt-current-at-splunk-com
      SPLUNK_PASSWORD: ChangeMe123!
    ports:
      - "8009:8000"   # Web UI (8000 belongs to Shadow Trust backend)
      - "8089:8089"   # REST API — backend queries this
      - "8088:8088"   # HTTP Event Collector
      - "9997:9997"   # Forwarder receiving
    volumes:
      - splunk-var:/opt/splunk/var
      - splunk-etc:/opt/splunk/etc
      - /Users/ayushsingh/Downloads/BKH-Logs:/mnt/bkh-logs:ro

volumes:
  splunk-var:
  splunk-etc:
```

Backend connects via `.env`: `SPLUNK_API_URL=https://host.docker.internal:8089`,
`SPLUNK_WEB_URL=http://localhost:8009`, `SPLUNK_USER=admin`, `SPLUNK_PASSWORD=ChangeMe123!`.

---

## 5. Back up the database before deleting anything

```bash
docker compose up -d db && sleep 15
make db-dump                              # writes database/dump.sql
```

Restore into a fresh DB (only needed if `honeynet_db_data` was lost):

```bash
docker compose up -d db && sleep 15
docker exec -i honeynet_db mariadb -ushadowtrust -pshadowtrust shadowtrust < database/dump.sql
```

---

## 6. How everything connects

Networks (created automatically by `docker compose up`):

| Network | Members | Rule |
|---|---|---|
| `honeynet_edge` | cowrie, dionaea, honeytrap | honeypots isolated — no route to backend/db |
| `honeynet_app` | backend, db, phpmyadmin, frontend, mobsf, clamav | app tier |
| `shadowtrust_labnet` | backend, mobsf, guacd, guacamole, guacamole_db, Kali lab containers, MobSF engine | VM Lab / APK engine |
| `shadowtrust_analysis` | analysis-shell sandboxes | `internal: true` — no internet |
| `splunk-lab_default` | splunk | reached by backend via `host.docker.internal:8089` |

Honeypots write logs to `telemetry/raw/*` on disk → backend collector reads them → MariaDB.
Backend mounts `/var/run/docker.sock` to spawn Kali labs, analysis sandboxes and the MobSF engine.

URLs after startup:

| What | URL |
|---|---|
| Dashboard | http://localhost:5500 |
| Backend API | http://localhost:8000 |
| phpMyAdmin | http://localhost:8081 |
| Guacamole | http://localhost:8080/guacamole (guacadmin/guacadmin) |
| VM Lab | http://localhost:5500/vm_lab.html |
| MobSF service | http://localhost:5055 |
| Splunk | http://localhost:8009 (admin / ChangeMe123!) |
| Health test bench | http://localhost:8000/health (needs `HEALTH_PAGE` env flag on) |

Ports overridable in root `.env` (see `.env.example`).

---

## 7. Gotchas

- Many images use `:latest` → re-pull may fetch newer version than tested. If something breaks, pin the tag in `docker-compose.yml`.
- Splunk is `linux/amd64` → runs emulated on Apple Silicon, slow first boot (~3–5 min).
- Docker Desktop can drop mid-session → `docker desktop start`, then `docker compose up -d --force-recreate`.
- Dashboard empty after rebuild? Run `scripts/populate_lab.sh` to generate real honeypot traffic.
