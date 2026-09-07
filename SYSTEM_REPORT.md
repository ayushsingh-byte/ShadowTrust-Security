# Shadow Trust — Full System Report

*AI‑assisted SOC / honeynet / malware‑analysis platform. Runs entirely on one machine with Docker Compose. This document describes every moving part: the container topology, the data pipeline, the backend API, the database, and all 37 frontend pages.*

Generated 2026‑09‑07. Reflects the current codebase (post Phase‑6 + dashboard rework).

---

## 1. What it is (one paragraph)

Shadow Trust is a self‑hosted **deception + detection platform**. Three real honeypots (Cowrie, Dionaea, Honeytrap) sit on an isolated Docker network and absorb attacker traffic. A FastAPI backend tails their logs, normalizes every event into one schema, risk‑scores it, stores it in MariaDB, and serves it to a vanilla‑JS dashboard over a same‑origin nginx proxy. Bolted onto that core are analyst tools: a 6‑stage malware pipeline (static + YARA + sandbox + secrets + ClamAV + VirusTotal), a live editable MITRE ATT&CK matrix, a unified categorised log feed spanning honeypots + Splunk + container logs + audit trail, a browser‑delivered VM lab (Kali / Windows via Apache Guacamole), an APK analyzer (MobSF), and a URL reputation scanner. Everything is containerised; nothing needs the cloud.

---

## 2. Container topology (Docker Compose)

`docker-compose.yml` defines **14 services** across **3 networks**. Bring it up with `docker compose up -d --build` (or `./setup.sh`).

### 2.1 Services

| Service | Image | Container name | Host port | Purpose |
|---|---|---|---|---|
| **cowrie** | `cowrie/cowrie:latest` | `honeynet_cowrie` | 2222 (SSH), 2223 (Telnet) | SSH/Telnet honeypot. Richest telemetry — full session, credentials, every typed command. |
| **dionaea** | `dinotools/dionaea:latest` | `honeynet_dionaea` | 445 (SMB), 21 (FTP), 1433 (MSSQL) | Malware‑capture honeypot for service exploitation. |
| **honeytrap** | `honeytrap/honeytrap:latest` | `honeynet_honeytrap` | 8022 (HTTP), 8023 (alt) | Low‑interaction catch‑all listener. |
| **db** | `mariadb:11` | `honeynet_db` | 3307 → 3306 | Application database. (Host port is 3307 to avoid clashing with a local MySQL.) |
| **phpmyadmin** | `phpmyadmin:5` | `honeynet_phpmyadmin` | 8081 | Web GUI for the MariaDB above. |
| **backend** | `soc/backend:latest` (built from `backend/Dockerfile`) | `honeynet_backend` | 8000 | FastAPI app + telemetry collector + background loops. |
| **frontend** | `nginx:1.25-alpine` | `honeynet_frontend` | 5500 | Serves `frontend/` static files and reverse‑proxies `/api/` to the backend. |
| **guacd** | `guacamole/guacd:latest` | `guacd` | — | Guacamole proxy daemon (RDP/VNC/SSH → browser). |
| **guacamole_db** | `postgres:15` | `guacamole_db` | — | Postgres holding Guacamole connection definitions. |
| **guacamole** | `guacamole/guacamole:latest` | `guacamole` | 8080 | Guacamole web app; the VM Lab page embeds it in an iframe. |
| **mobsf** | `soc/mobsf:latest` (built) | `honeynet_mobsf` | 5055 | Flask shim that spawns a real MobSF engine container on demand for APK analysis. |
| **clamav** | `clamav/clamav-debian:latest` | `honeynet_clamav` | 3310 (internal) | Antivirus engine for the Malware Lab. First boot downloads ~1.5 GB of signatures. |
| **node_api** | `soc/node-api:latest` | `honeynet_node_api` | 3000 | Optional legacy Node service. **Off unless `--profile extras`.** |
| **worker** | `soc/worker:latest` | `honeynet_worker` | — | Optional legacy Node worker. **Off unless `--profile extras`.** |

Plus **lab containers** the backend spawns at runtime (`shadowtrust/lab-kali:latest`, etc.), labelled `shadowtrust.managed=true`, attached to `labnet`.

### 2.2 Networks

| Network | Members | Reason it exists |
|---|---|---|
| `honeynet_edge` | cowrie, dionaea, honeytrap | The honeypots sit here **alone**. The backend has no route to it, so a compromised sensor cannot reach the database or API. |
| `honeynet_app` | backend, frontend, db, phpmyadmin, mobsf, clamav, (node_api, worker) | The application plane. |
| `labnet` | guacd, guacamole, guacamole_db, backend, mobsf, spawned lab containers | Remote‑desktop plane. Backend joins it so it can register Guacamole connections and reach lab VMs. |

The honeypots never touch telemetry via the network — they write log files to a **shared bind mount** (`./telemetry/raw/<sensor>/`), which the backend mounts **read‑only**. That is the only channel between edge and app.

### 2.3 Volumes / bind mounts of note

- `./telemetry/raw` → sensor log files (sensors write, backend reads RO).
- `./backend/scans` → malware analysis report store (JSON per SHA‑256).
- `/var/run/docker.sock` → mounted into **backend** and **mobsf** so they can spawn/inspect containers (VM Lab, MobSF engine, sensor status checks).
- `db_data`, `guac_pgdata`, `clamav_db` → named volumes for persistence.
- `./database/init` → SQL run once on first MariaDB boot.
- `./frontend` → served live by nginx (edit a file, refresh, see it — no rebuild).

---

## 3. End‑to‑end data flow (the core loop)

```
   Attacker
      │  SSH / SMB / HTTP / …
      ▼
┌──────────────┐   writes JSON log lines
│  Honeypot    │───────────────┐
│ (cowrie/…)   │               ▼
└──────────────┘      ./telemetry/raw/<sensor>/*.json   (shared bind mount, RO to backend)
                                │
                                │  every 2 s  (COLLECTOR_INTERVAL_SECONDS)
                                ▼
                     ┌────────────────────────┐
                     │  LocalCollector        │   backend/app/services/telemetry/collector.py
                     │  - cursor per file     │   remembers byte offset in ingest_cursors table
                     │  - reads only new bytes│
                     └───────────┬────────────┘
                                 ▼
                     ┌────────────────────────┐
                     │  normalize()           │   telemetry/normalize.py — pure, stdlib‑only
                     │  cowrie/dionaea/…      │   → one common NormalizedEvent
                     │  parsers               │   deterministic event_id = hash(raw)  ⇒ idempotent
                     │  derive_severity()     │   INFO/LOW/MEDIUM/HIGH/CRITICAL by rules
                     │  drop loopback (opt‑in)│
                     └───────────┬────────────┘
                                 ▼
              ┌──────────────────┴───────────────────┐
              ▼                                      ▼
   INSERT IGNORE raw_events                INSERT IGNORE normalized_events
   (legacy wide table,                     (clean schema — everything new reads this)
    dashboards/analytics read it)
              │                                      │
              │  commit                              │  after commit only
              ▼                                      ▼
       MariaDB (honeynet_db)               event_bus.publish_many()   in‑process pub/sub
              │                                      │
              ▼                                      ▼
   REST endpoints (/dashboard, /mitre,     SSE  /api/v1/live/stream
   /logs, /attacks, /live/*, …)            (Event Log page, real‑time)
              │                                      │
              └──────────────┬───────────────────────┘
                             ▼
                   nginx  (same‑origin /api/ proxy, SSE‑aware)
                             ▼
                   Vanilla‑JS pages in frontend/
```

Key properties:

- **Idempotent ingest.** `event_id` is a SHA hash of the raw line. Re‑reading a rotated file or replaying after a crash inserts nothing new (`INSERT … IGNORE` + `ingest_cursors`).
- **Two event tables on purpose.** `raw_events` is the old wide table the dashboards/analytics still query; `normalized_events` is the clean schema. The collector writes both in one transaction so they never diverge.
- **Publish‑after‑commit.** The SSE stream never shows an event that isn't in the DB.
- **AWS mode swap.** If `INFRA_PROVIDER=aws`, the lifespan starts `telemetry_engine.run_pipeline()` (30 s S3 poll) **instead of** the local collector — same `normalize()` downstream. Local is the default and everything in this doc assumes local.

---

## 4. Backend (FastAPI)

`backend/app/` — async FastAPI, SQLAlchemy async + `aiomysql`, Pydantic. Entry `app/main.py`.

### 4.1 Lifespan / background tasks

On startup (`lifespan` in `main.py`):
1. `init_db()` — create tables, seed the default admin (`admin@gmail.com` / `admin`).
2. `background_sync_loop()` — every 10 s, `SyncManager.run_sync_cycle()` promotes normalized events into derived tables (alerts, IOCs) using their risk score.
3. `background_session_loop()` — stitches events into `attacker_sessions`.
4. Telemetry: `local_collector.run_forever()` (local) **or** `telemetry_engine.run_pipeline()` (aws).

On shutdown: cancel tasks, let `finally` blocks flush, `engine.dispose()` before the loop closes.

### 4.2 API routers

All mounted under `/api/v1` (`app/api/v1/api.py`). Grouped by concern:

**Core telemetry / dashboard**
| Prefix | File | Highlights |
|---|---|---|
| `/dashboard` | `endpoints/dashboard.py` | `GET /stats` — the big aggregate: totals, unique attackers, traffic‑by‑minute buckets, top attacker IPs (with GeoIP), exploit vectors by port, protocol radar, recent payloads, and a `system` block (analysis‑engine liveness, deception status, novel patterns). 15 s server cache. `GET /geo` — country/ASN breakdown. |
| `/live` | `endpoints/live.py` | `GET /stream` — **SSE** feed (the Event Log page). Also `/overview`, `/events`, `/attackers`, `/attackers/{ip}`, `/sensors`, `/sessions/{id}`, `/collector` (collector health snapshot). |
| `/events` | `endpoints/events.py` | `POST /ingest` (manual event injection), `GET /`, `GET /{id}/analyze`. |
| `/attacks` | `endpoints/attacks_api.py` | `/recent`, `/top-ips`, `/by-port`, `/timeline`, `/categories`. |
| `/nodes` | `nodes.py` | `GET /` — sensor list. Status + uptime come from the **real Docker container** (`services/container_status.py`); "load" is the real event rate in the last 15 min; `risk_level` is the max risk score in 24 h. `GET /stats` — host CPU/RAM/net from `psutil`. `POST /launch`, `/{id}/stop`, `/{id}/start`. |
| `/honeypots` | `endpoints/honeypots_api.py` | `GET /status`. |

**Logs & detection**
| Prefix | File | Highlights |
|---|---|---|
| `/logs` (feed) | `endpoints/logs_feed.py` | `GET /feed` — one categorised stream over **4 sources**: `honeypot` (normalized_events), `splunk` (proxied search), `platform` (`docker logs` of stack containers), `audit` (AccessLog + AdminActivity, admin‑only). Filters: `sources`, `category`, `severity`, `q`, `hours`, `limit`. `GET /summary` — counts by category / severity / source. Non‑admins silently lose `platform` + `audit`. |
| `/logs` (ingest) | `endpoints/logs.py` | `POST /` — raw honeypot line ingest (legacy path). |
| `/mitre` | `endpoints/mitre.py` | `GET /` — live ATT&CK matrix built from `raw_events` via a small rules engine (`map_to_mitre`). `GET /catalog` — ~40‑technique picker list. `GET /annotations` / `PUT /annotations` — the analyst overlay (status / note / pin / order / manual techniques), stored as one JSON blob in `system_config`. |
| `/analytics` | `endpoints/analytics.py` | `/graphs`, `/credentials` — chart data for the Attack Analytics page. |
| `/behavior` | `endpoints/behavior.py` | `/profile` — per‑attacker behavioural profiling. |

**Malware / URL / APK tools**
| Prefix | File | Highlights |
|---|---|---|
| `/malware` | `endpoints/malware.py` | `POST /upload` runs the **5‑stage pipeline** (§6.4). `GET /report/{sha256}`, `/secrets/{sha256}`, `/static/{sha256}`, `/apk-intel/{sha256}`, `/history`, `/family-distribution`. Reports cached as JSON under `backend/scans/`. |
| `/url-scan` | `endpoints/url_scan.py` | `POST /scan` — structural heuristics + live DNS + TLS cert + redirect‑chain analysis. |
| `/mobsf-proxy` | `endpoints/mobsf_proxy.py` | Reverse proxy to the spawned MobSF engine so the APK page can embed its UI. |

**VM lab / remote desktop**
| Prefix | File | Highlights |
|---|---|---|
| `/labs` | `endpoints/labs.py` | `GET /profiles`, `POST /start` (returns `lab_id` immediately, boots in a background task, then registers a Guacamole connection), `POST /stop`, `GET /status/{id}`, `/cluster-metrics`, `/reattach/{id}`. |
| `/vm` | `endpoints/vm.py` | `POST /launch`, `/{id}/terminate`, `/{id}/status`, `GET /provider`. Delegates to a **provider** (`services/providers/`): `docker_provider` (local Kali), `aws_provider` (EC2 Windows), selected by `INFRA_PROVIDER`. |
| `/session` | `endpoints/session.py` | `POST /{lab_id}/open` — mint the Guacamole iframe URL. |

**Splunk integration**
| Prefix | File | Highlights |
|---|---|---|
| `/splunk` | `endpoints/splunk.py` | Proxies the user's own Splunk (`~/splunk-lab`, mgmt API on `:8089`). `GET /health`, `/config`, `/kpis`, `/notable`; `POST /search` (oneshot SPL); `POST /ingest` (paste, one event/line); `POST /upload` (**multi‑file** `.log/.txt/.json/.csv`, auto sourcetype); `GET /sources` (`| tstats` for the purge picker); `POST /purge` (delete by source and/or age); `POST /delete` (delete by arbitrary SPL). Auto‑grants the Splunk user the `can_delete` role. |

**Auth / users / admin**
| Prefix | File | Highlights |
|---|---|---|
| `/auth` | `endpoints/auth.py` | `POST /register`, `/login` (OAuth2 password form → JWT), `/verify-otp`, `/forgot-password`, `/reset-password`, `/admin-login`, `/activate-account`, `/dev-bypass` (issues a SUPER_ADMIN token for local dev). |
| `/users` | `endpoints/users.py` | CRUD + approval workflow: `/pending`, `/{id}/approve`, `/{id}/deny`, `/{id}/regenerate-admin-code`, `GET /me`. |
| `/admin` | `endpoints/admin.py` | `/settings` (GET/POST), `/reset` (wipe data tables), `/backup`, `/health`, `/logs/access`. |
| `/credentials` | `endpoints/credentials_api.py` | Issue one‑time credential tokens, email them, audit trail. `/issue`, `/audit`, `/resend/{id}`, `/token/{t}`, `/activity`, `/generate-password`. |
| `/aws` | `endpoints/aws.py` | `/config`, `/test`, `/debug`, `/pull-s3-logs` — only relevant in AWS mode. |

### 4.3 Key services (`backend/app/services/`)

| File | Role |
|---|---|
| `telemetry/collector.py` | The `LocalCollector` — cursor‑based log tailer, the heart of local mode. Exposes `.status()` (running, cycles, `last_run_at`, events ingested, last error). |
| `telemetry/normalize.py` | Per‑sensor parsers + `derive_severity()` + deterministic `event_id`. Pure functions, heavily unit‑tested. |
| `telemetry/local_source.py` / `s3_source.py` / `factory.py` | Pluggable log sources (local dir vs S3), chosen by env. |
| `event_bus.py` | In‑process async pub/sub. Bounded per‑subscriber queue (~10 s of a busy honeypot); slow subscribers get dropped, not blocked. |
| `log_categorizer.py` | **Heuristic "category layer"** for the Logs page. Ordered regex `RULES`, first match wins → `{category, severity, reason}`. 15 categories (auth, recon, exec, c2, malware, lateral, exfil, persistence, privilege, defense‑evasion, system, network, audit, error, info). Zero dependencies, one editable file. |
| `av_scanner.py` | `clamav_scan(path)` — raw‑socket INSTREAM to `clamav:3310`. `virustotal_lookup(sha256)` — VT API v3 hash lookup (`x-apikey`). Both never raise; missing engine/key → `available: false`. |
| `static_analyzer.py` | PE/ELF/Mach‑O/PDF/DOCX/script static analysis — arch, imports, section entropy, packer indicators, suspicious API categories, strings. |
| `sandbox_engine.py` | CAPE proxy if `CAPE_URL` set, otherwise a deterministic heuristic simulation producing the same report schema. Cached by SHA‑256. |
| `secret_detector.py` | 30+ secret patterns (API keys, tokens, private keys, DB URLs, cloud creds, C2 endpoints). |
| `apk_engine.py` | Android APK analysis on the raw ZIP — manifest, permissions, exposed components, DEX scan. No external tools. |
| `url_scan_service.py` | Multi‑engine URL analysis — 50+ structural patterns, live DNS (A/MX/TXT/NS/CNAME), TLS cert inspection, HTTP redirect chain. |
| `container_status.py` | Real sensor container state via the Docker socket (running, health, `StartedAt` uptime). 8 s cache, no slow `stats()` calls. Feeds the dashboard + `/nodes`. |
| `guacamole_service.py` | Writes/removes connection rows directly in the Guacamole Postgres DB (`guacamole_connection` + `guacamole_connection_parameter`) so a lab VM shows up as an embeddable session. |
| `providers/` | `docker_provider` (spawn Kali container on `labnet`), `aws_provider` (EC2), `factory` picks by `INFRA_PROVIDER`. |
| `session_engine.py` / `session_manager.py` | Attacker‑session correlation + lab‑session lifecycle. |
| `sync_manager.py` | The 10 s promotion loop: normalized events → alerts / IOCs by risk. |
| `auth_service.py` | bcrypt hashing, JWT (`jwt.encode`, `SECRET_KEY`), OTP, system codes, registration/approval, credential emails. |

---

## 5. Database (MariaDB `shadowtrust`)

~30 tables. The ones that matter:

| Table | Written by | Read by |
|---|---|---|
| `raw_events` | collector (`INSERT IGNORE`) | dashboard, analytics, mitre, attacks |
| `normalized_events` | collector (`INSERT IGNORE`) | logs feed, live/*, behavior, sync_manager |
| `ingest_cursors` | collector | collector (byte offset per sensor file) |
| `alerts`, `iocs` | `sync_manager` | analytics, admin |
| `attacker_sessions`, `structured_events` | `session_engine` | behavior profiling |
| `users` | auth_service | everything auth‑gated |
| `system_config` | `PUT /mitre/annotations` (key `mitre_annotations`) | mitre page |
| `system_settings` | `/admin/settings` | admin console |
| `access_logs`, `admin_activity_log` | RBAC actions | audit source of the Logs page, admin |
| `credential_tokens`, `credential_audit_log` | `/credentials/*` | Credentials Vault |
| `vm_instances`, `vm_profiles` | vm/labs endpoints | VM Lab / VM Session pages |
| `nodes`, `node_metrics` | `/nodes/launch` (manual) | nodes page (virtual sensors are synthesised, not stored) |

`phpMyAdmin` on `:8081` is a direct GUI onto this DB.

---

## 6. Frontend

`frontend/` — **no framework**. Plain HTML + one shared JS module per concern, served by nginx.

### 6.1 Shared infrastructure

- **`js/api.js`** — `apiService` singleton. Auto‑resolves base URL (`http://127.0.0.1:8000/api/v1` when opened from `file:`/localhost dev, otherwise `/api/v1` via the nginx proxy). Methods: `get`, `post`, `put`, `delete`, `upload(endpoint, FormData)`. Attaches `Authorization: Bearer <token>` from `localStorage`. Auto‑redirects to `login.html` on 401.
- **`js/sidebar.js`** — the **single source of navigation** for all 17 app pages. Renders `#sidebar` from a `navGroups` array, verifies the session against `/users/me` (fail‑closed), and only shows the admin block for `ADMIN` / `SUPER_ADMIN`. The 3 admin pages (`admin.html`, `access_control.html`, `aws_connection.html`) carry their own separate sidebar.
- **nginx** (`frontend/nginx.conf`) — serves static files, proxies `/api/` to `backend:8000`, has a **dedicated SSE block** for `/api/v1/live/stream` (buffering off, 24 h read timeout), no‑cache headers on HTML/CSS/JS.

### 6.2 App pages (in sidebar)

**Command Center**
| Page | Backend it calls | What it shows |
|---|---|---|
| `dashboard.html` — *Tactical Overview* | `/dashboard/stats`, `/nodes/`, `/nodes/stats` | The command screen. 8 metric tiles (total events, unique attackers, unique payloads, system integrity, network flow, high‑risk alerts, uptime, active sensors), a micro‑metric strip (analysis engine %, threat level, deception sensors, novel patterns, defense matrix), a Leaflet world map with live attack markers, a stacked traffic‑volume chart (SSH/HTTP/malware per minute), a live honeypot feed, three tables (top attacker networks / recent payloads / exploit vectors by port), a protocol‑mix radar, and the sensor grid. **Every value is a real backend query** — the only client‑side effects are the clock and the local "console lockdown" screen guard. Chart.js + Leaflet (keyless OSM tiles, CSS‑darkened). |
| `events.html` — *Event Log* | `/live/stream` (SSE), `/live/overview`, `/live/attackers`, `/live/sensors` | Real‑time. Overview counters, an SSE‑driven activity feed, per‑sensor health strip, attacker profiles, a filterable event table, CSV export. |
| `logs.html` — *Logs* | `/logs/feed`, `/logs/summary` | The unified categorised feed. KPI row per category (click → filter), source toggles (honeypot / splunk / platform / audit), category + severity + text filters, CSV export, dense colour‑chipped table with the categoriser's `reason` as a tooltip. 8 s auto‑refresh. |

**Grid Monitoring**
| Page | Backend | What it shows |
|---|---|---|
| `nodes.html` — *Honeypot Nodes* | `/nodes/`, `/honeypots/status` | Sensor cards with real container status / uptime / event‑rate load, start/stop controls. |
| `node_details.html` — *Node Investigation* | `/live/sensors`, `/attacks/*` | Drill‑down for one sensor. |
| `splunk.html` — *Splunk Blue Team* | `/splunk/*` | SIEM console against the user's own Splunk: KPIs (events indexed, hosts, sourcetypes, indexes), notable events, ad‑hoc SPL search with CSV + "delete matches", a **drag‑and‑drop multi‑file uploader**, and a **Purge by source / age** card. |
| `geo.html` — *Geo Intelligence* | `/dashboard/geo` | Full‑page Leaflet map, top source countries, ASN intelligence, "generate SOC report". |

**Intelligence**
| Page | Backend | What it shows |
|---|---|---|
| `mitre.html` — *MITRE Matrix* | `/mitre/`, `/mitre/catalog`, `/mitre/annotations` | **Live + editable** ATT&CK matrix. 14 tactic columns as SortableJS lists; drag a technique card between tactics; per‑card triage status (`observed` / `investigating` / `mitigated` / `false-positive`), pin toggle, inline note; "+ add technique" picker (catalog search or free‑text `T####`). Debounced `PUT` on any change, 15 s poll that re‑merges live data without clobbering unsaved edits. Observed techniques come from the live feed; the overlay persists in `system_config`. |
| `graphs.html` — *Attack Analytics* | `/analytics/graphs`, `/analytics/credentials` | Trend charts (Chart.js). |
| `credentials.html` — *Credentials Vault* | `/credentials/activity`, `/analytics/credentials` | Captured attacker credentials from the honeypots. |
| `credential_mgmt.html` | `/credentials/issue`, `/credentials/audit`, `/credentials/resend/{id}` | Issue one‑time platform credentials to real users + audit trail (admin tool). |
| `behavior.html` — *Behavior Profiling* | `/behavior/profile` | Per‑attacker behavioural fingerprints. |

**Tools Suite**
| Page | Backend | What it shows |
|---|---|---|
| `malware.html` — *Binary Analysis* | `/malware/upload`, `/malware/history`, `/malware/family-distribution` | Drop a file → 5‑stage pipeline (§6.4). Risk ring + family, an **AV verdict banner** (ClamAV signature, VirusTotal N/total + permalink, which engine drove the verdict), pipeline step tracker, tabbed report (static / sandbox / network / MITRE / APK / secrets / signatures), scan history table, family‑distribution chart. |
| `urlscan.html` — *URL Scanner* | `/url-scan/scan` | Paste a URL → structural score, DNS records, TLS cert, redirect chain, verdict. |
| `apk.html` — *APK Inspector* | `/malware/analyze/apk`, `/mobsf-proxy/*` | Upload an APK → static analysis + embedded MobSF UI (engine spawned on demand). |
| `vm_lab.html` — *Virtual Lab* | `/labs/profiles`, `/labs/start`, `/labs/status/{id}`, `/session/{id}/open`, `/labs/stop` | Two cards: **Kali (local Docker)** and **Windows Analysis (AWS/KVM)**. Provision → the backend spawns a container/VM, waits for boot, registers a Guacamole connection → the desktop appears **in‑page in an iframe**. Terminate tears down the container and the Guacamole row. |
| `vm_session.html` — *Live OS Session* | `/vm/{id}/status` | Full‑screen view of one running lab session. |

**System**
| Page | Backend | Notes |
|---|---|---|
| `admin_login.html` / `login.html` / `register.html` / `forgot_password.html` | `/auth/*` | JWT auth. Registration is approval‑gated; login can require OTP. `register.html` currently just redirects. |
| `profile.html` — *Officer Profile* | `/users/me` | The logged‑in analyst's profile. |
| `admin.html` — *Global Admin Control* | `/admin/*`, `/users/*` | User management, pending approvals, system settings, data reset, access‑log viewer. Admin‑only, own sidebar. |
| `access_control.html` — *Access Control Console* | `/users/*` | RBAC / clearance management. |
| `aws_connection.html` — *AWS Infrastructure* | `/aws/*` | AWS credential test + S3 telemetry pull. Only meaningful in AWS mode. |
| `config.html` — *System Config* | static | Config reference page. |

### 6.3 Non‑sidebar / marketing / utility pages

`index.html` (landing), `features.html`, `usecases.html`, `docs.html`, `architecture.html` (static architecture diagram), `status.html`, `debug.html` (diagnostics), `mock_vdi.html`, `index_old.html`. The `/health` status page is served **by the backend** (`app/health_page.py`, `HEALTH_PAGE=1`), not nginx — it lists every container, every service URL, admin credentials, and copy‑paste attack commands. It is unauthenticated by design (local‑only) and disabled with `HEALTH_PAGE=0`.

### 6.4 Malware pipeline (`_run_pipeline` in `endpoints/malware.py`)

```
upload → multi-hash (md5/sha1/sha256) → dedup check (scans/<sha256>.json)
   │  (cache hit → return stored report)
   ▼
Stage 1  Static Analysis      static_analyzer.py   arch, imports, entropy, packer, suspicious APIs, strings
Stage 2  Sandbox / CAPE       sandbox_engine.py    real CAPE if CAPE_URL else deterministic heuristic sim
Stage 3  APK Intelligence     apk_engine.py        (APK files only) manifest, perms, components, DEX
Stage 4  Secret Detection     secret_detector.py   30+ hardcoded-secret patterns
Stage 5  Antivirus            av_scanner.py        ClamAV INSTREAM  +  VirusTotal hash lookup (if key)
   ▼
Aggregate:  final_score = min(100, sandbox_score + apk_risk/3 + secret_boost)
            if clamav.infected            → score = max(score, 95)
            elif virustotal.malicious ≥ 3 → score = max(score, 60 + malicious)
            verdict = worst of {static, sandbox, ClamAV, VT}
            threat_family from ClamAV signature or first VT name
   ▼
store scans/<sha256>.json  +  append history  →  return unified report
```

---

## 6b. SOC investigation layer (detection → correlation → incident → evidence)

Above the raw event stream sits a persisted analysis layer, driven by a background
loop (`services/detection_engine.py`, every ~20 s, cursor in `system_config`).
It **extends** the existing severity→`risk_score` mapping, it does not replace it.

```
normalized_events (cursor: only new rows)
  → IOC extraction          ip / domain / url / sha256|md5|sha1 / username
                            → ioc_observations (dedup by type+value)
  → detection rules         backend/detections/*.yml — READ-ONLY, YAML, no engine
                            change to add one. threshold + sequence types;
                            eq/contains/regex/in/gt field ops; timeframe + threshold
                            + group_by. → detections rows carrying {rule_id,
                            matched_event_ids, match_conditions, reason, confidence,
                            severity, ATT&CK id+tactic}
  → correlation             group by source_ip / session inside a 6 h window;
                            open incident matched → updated, else created (NEW).
                            Every link carries a plain-English correlation_reason.
  → incident                incidents + incident_events + incident_iocs +
                            incident_activity. severity = worst of the detections;
                            risk_breakdown itemises the score (severity + detection
                            count + technique count + max event risk + session span
                            + malware-linked) → answers "why this severity".
  → auto-evidence           a linked malware hash with a stored report spawns
                            Evidence rows (sample ref + static/sandbox/yara/clamav/vt
                            sections), each with a content_hash for integrity.
  → attacker_sessions       finally populated as a side effect (was a stub).
```

**Endpoints** (`/api/v1`): `incidents` (list · `{id}` full view · `{id}/timeline`
attack reconstruction · `{id}/notes` · `PATCH` status/assign · `stats`),
`detections` (`/rules`, `/rules/reload`, `/stats`), `evidence` (`{id}` · `{id}/verify`
· `{id}/sample` — ADMIN + clearance 3, streamed, never a static dir),
`mitre/analytics` (per-technique event/incident/confidence rollup),
`soc-testing` (`/scenarios`, `/scenarios/{id}/run` mode=evaluate|execute,
`/runs`, `/coverage`).

**Timeline** (`services/timeline_builder.py`) merges, chronologically and with a
`reason` on every entry: the incident's linked `normalized_events` + same-IP events
in the window, its `detections`, malware-report sections for any hash IOC, and
(best-effort, labelled) Splunk events for the source IP. **No fabricated links.**

**Detection validation** (`services/detection_validation.py`,
`backend/scenarios/*.yml`): `execute` fires `scripts/attack_scenarios.sh` with the
target **hard-locked to `127.0.0.1`** (ADMIN only), waits a detection cycle, then
grades the real `detections`/`incidents`/techniques against the scenario's
expectations → PASS/FAIL/PARTIAL + detection-success-rate / ATT&CK-coverage /
telemetry-coverage / false-positive metrics. `evaluate` grades without firing traffic.

**Frontend:** `incidents.html` (Command Center) — the investigation workspace;
`validation.html` (Intelligence) — the SOC test harness; `mitre.html` gains a
per-technique analytics panel (the live editable overlay is unchanged).

**New tables** (all created by `create_all`, no migration — events referenced by
`event_id` string): `detections`, `ioc_observations`, `incidents`, `incident_events`,
`incident_iocs`, `incident_activity`, `evidence`, `scenario_runs`.

---

## 6c. Analysis Lab — interactive sandbox wired into behaviour profiling

`analysis_lab.html` gives an analyst a real terminal into a **disposable Debian
container** so they can *drive* a behaviour instead of only observing attackers.

- **Container** (`Dockerfile.analysis`, `container_manager.run_analysis_container`):
  on `shadowtrust_analysis` — a Docker `internal: true` network, so **zero egress**
  (no internet, no honeypots, no app). `cap_drop=ALL` + `no-new-privileges`,
  non-root `analyst`, 512 MB / 1 CPU / 128 PIDs, **no Docker socket**, no host
  mounts. Hard TTL + idle reap (`background_analysis_reaper`), one per user.
- **Terminal**: `WS /api/v1/analysis-shell/{id}/pty?token=<jwt>` relays a PTY
  (`container_manager.attach_shell`). The backend also **passively parses the
  input stream** — buffer until Enter → that's the command line. No agent runs
  inside the container.
- **Capture → pipeline**: each command → a synthetic `normalized_events` +
  `raw_events` row (`sensor="analysis-shell"`, `source_ip="analyst-shell:<email>"`,
  `honeypot_type="AnalysisShell"`). Each new peer in `ss -tunH` (polled) →
  `shell.connection.attempt`. These are ordinary events, so with **no extra
  wiring** they flow to: the **detection engine** (`st-exec-003/004/005`,
  `st-recon-006` → a `Detection` + `Incident` scoped to the session tag), the
  **behaviour profiler** (`gnn_profiler` — a green SHELL node, commands chained in
  execution order, connection-attempt destination nodes, MITRE map), the Event
  Log / Logs feed / SSE.
- **Page**: xterm.js terminal on the left; on the right the live vis-network
  behavioural flow (`/behavior/profile?session=<id>`), a MITRE strip, the
  command/connection stream, and a detections/incident panel — all polling every
  3 s so the graph grows as you type. `behavior.html` (global view) also shows
  shell sessions.
- **Tables**: `analysis_sessions` (new).

---

## 7. Security model

- **Network isolation.** Honeypots are alone on `honeynet_edge`. A rooted sensor can reach nothing else — the only egress is a read‑only log bind mount. The Container Manager never creates or touches a honeypot container.
- **Docker socket chokepoint.** `services/container_manager.py` is the **only** module that calls `docker.from_env()`. It exposes a small allow‑listed surface — `validate_lab_run` (image ∈ allow‑list, network == labnet, no bind mounts, resource caps, `privileged`/extra caps rejected), `assert_managed` (lifecycle ops only on `shadowtrust.managed=true` containers), name‑allow‑listed read‑only status/logs. No generic "run arbitrary Docker" method or endpoint. The lab provider, sensor‑status reader, health page and logs feed all route through it.
- **Malware isolation.** Uploads stream to `backend/quarantine/<sha256>` — path built only from the hex hash (kills traversal), `os.path.realpath` containment assertion, hard size cap, magic‑byte type allow‑list, zip‑slip guard. `quarantine/` and `evidence/` are git‑ignored and **not** an nginx or `StaticFiles` mount. The raw sample is reachable only via `GET /evidence/{id}/sample` (ADMIN + clearance 3, forced‑download disposition). Static/YARA/secret/ClamAV analysis runs in‑process reading bytes — no Docker socket, no execution of the sample. The deterministic sandbox is labelled `is_simulation: true`.
- **AuthN.** bcrypt password hashes, JWT bearer tokens (`SECRET_KEY`, HS256), optional OTP on login, one‑time system codes for admin access. `dev_bypass_token` / `POST /auth/dev-bypass` are honoured **only** when `DEV_BYPASS=1` **and** `INFRA_PROVIDER=local` — fail‑closed otherwise.
- **AuthZ.** Roles: `SUPER_ADMIN`, `ANALYST`, `AUDITOR`, `OPERATIVE`, `SPECIALIST`, `OVERSEER` + numeric clearance levels 1–3. Incident/detection/evidence/soc‑testing writes are role‑gated (`require_role`) and audited. The Logs feed drops `platform` + `audit` sources for non‑admins in the endpoint, not just the UI.
- **Audit.** Every RBAC/admin action + incident status change / note writes `access_logs` + `admin_activity_log` + `incident_activity`, all of which are sources in the unified Logs page.
- **`/health` hardening.** Default `HEALTH_PAGE=0` → 404. When enabled it emits **only** service up/down, sensor status, collector `{running, cycles, last_run_at}`, event total — **no credentials, no DB details, no attack commands**. That full detail moved to `GET /api/v1/admin/diagnostics` (ADMIN role).
- **Guacamole.** `scripts/set_guac_password.sh` replaces the seeded `guacadmin/guacadmin` with a strong hash post‑boot; `setup.sh` and `/admin/diagnostics` prompt for it.
- **Defensive‑only tooling.** ClamAV / YARA / VirusTotal / MobSF are legitimate malware‑analysis tools. The VM lab and attack scripts are scoped to the local isolated lab (RFC1918/loopback only, enforced in the script and hard‑coded in the validation runner).

---

## 8. Environments

| | Local (default) | AWS |
|---|---|---|
| `INFRA_PROVIDER` | `local` | `aws` |
| Telemetry | `LocalCollector` tails `./telemetry/raw` every 2 s | `telemetry_engine` polls an S3 bucket every 30 s |
| Windows VM lab | Linux + KVM (`LAB_WINDOWS_ENABLED=1`) or unavailable | EC2 Windows instance |
| Kali VM lab | Docker container on `labnet` | Docker container on `labnet` |
| GeoIP | `ip-api.com` batch (cached) | same |
| Splunk | user's `~/splunk-lab` compose project on `:8089` | same |

Everything in this report is the **local** path.

---

## 9. Running it

```bash
# one-time
cp .env.example .env           # set SECRET_KEY at minimum
./setup.sh                     # checks Docker, creates dirs, builds, brings up the stack

# or manually
docker compose up -d --build

# URLs
http://localhost:5500          # dashboard (nginx)
http://localhost:8000/docs     # FastAPI OpenAPI
http://localhost:8000/health   # status page (HEALTH_PAGE=1)
http://localhost:8081          # phpMyAdmin
http://localhost:8080/guacamole# Guacamole (guacadmin/guacadmin)
http://localhost:5055          # MobSF shim

# generate real telemetry
./scripts/attack_scenarios.sh 127.0.0.1 brute-force     # 30 SSH login attempts at Cowrie
./scripts/attack_scenarios.sh 127.0.0.1 all             # every scenario

# tests
cd backend && .venv/bin/python -m pytest tests/ -q      # 68 tests
```

Optional env: `VIRUSTOTAL_API_KEY` (Malware Lab cross‑check), `SPLUNK_*` (Splunk page), `LAB_WINDOWS_ENABLED=1` (KVM Windows lab), `TELEMETRY_DROP_LOOPBACK=1` (ignore `127.0.0.1` source events).

---

## 10. TL;DR for another model

> Shadow Trust = Docker Compose stack. 3 honeypots on an isolated network write JSON logs to a shared read‑only mount. A FastAPI backend tails those files every 2 s, normalizes each event to one schema with a deterministic hash (idempotent), risk‑scores it by explainable rules, and stores it in MariaDB (two tables — legacy wide + clean). A vanilla‑JS frontend behind an nginx same‑origin proxy renders it: a real‑data tactical dashboard, a live SSE event log, a unified categorised log feed spanning honeypots + Splunk + container logs + audit trail, and a drag‑to‑triage MITRE ATT&CK matrix persisted server‑side. Analyst tools hang off the same backend: a 5‑stage malware pipeline ending in a ClamAV container + optional VirusTotal, a URL scanner, an APK analyzer backed by an on‑demand MobSF container, and a browser‑delivered Kali/Windows VM lab via Apache Guacamole (the backend writes connection rows straight into Guacamole's Postgres and embeds the desktop in an iframe). JWT + bcrypt + role/clearance RBAC, approval‑gated registration, full audit logging. Runs 100% locally; an `INFRA_PROVIDER=aws` switch swaps the log source to S3 and the Windows lab to EC2.
