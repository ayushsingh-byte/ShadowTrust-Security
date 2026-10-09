# ShadowTrust: practical viva guide

One file to revise from before the viva. Read sections 1 to 4 first, they are what the examiner will ask about most. Section 5 is one short entry per page.

Contents

1. The idea in one minute
2. The three honeypots: Cowrie, Dionaea, Honeytrap
3. Architecture
4. How one attack becomes a case (the pipeline)
5. Every page, what it is for and how it works
6. Running the live demo
7. Questions the examiner is likely to ask

---

## 1. The idea in one minute

ShadowTrust is a self-hosted deception and security operations platform.

- It runs **real honeypots** (fake servers that look vulnerable) on an isolated network.
- Anything that touches a honeypot is hostile by definition, because no real user has a reason to be there. So there are almost no false positives.
- Everything the honeypots record is **collected, normalised, checked against detection rules, correlated into cases, graded by severity and mapped to MITRE ATT&CK**.
- An analyst then works those cases in a web dashboard: timeline, evidence, credentials tried, attacker behaviour, reports, compliance.

Short version to say out loud: *"The honeypots are only the front door. The product is the pipeline behind them that turns raw attacker activity into a graded, explainable case."*

It is local first: `docker compose up -d` on one machine starts the whole thing. No cloud account is needed. AWS is optional.

---

## 2. The three honeypots

A **honeypot** is a decoy system. It pretends to be a real service, lets the attacker interact, and records everything. It has no real data and no real users.

Why three? Each one imitates different services, so together they cover the common ways an attacker gets in: remote login, file and database services, and web.

### Cowrie (SSH and Telnet)

| | |
|---|---|
| Pretends to be | A Linux server you can log in to over SSH or Telnet |
| Ports | 2222 (SSH), 2223 (Telnet) |
| Interaction level | Medium. It gives the attacker a fake shell with a fake filesystem |
| Records | Every username and password tried, whether the login "worked", every command typed, files the attacker tries to download |
| Log file | `telemetry/raw/cowrie/cowrie.json` |

How it behaves: a few obvious passwords are rejected (so a brute force looks real), then other passwords are accepted. The attacker thinks they are in. Commands like `whoami`, `cat /etc/passwd`, `wget http://...` return believable output, but nothing really runs. This is the richest sensor: it shows the full kill chain from password guessing to hands on keyboard.

### Dionaea (SMB, FTP, MSSQL, MySQL and more)

| | |
|---|---|
| Pretends to be | A Windows style server with many network services open |
| Ports | 445 (SMB), 21 (FTP, published on host as 2121), 1433 (MSSQL), plus 3306, 80, 135 and others inside the lab network |
| Interaction level | Low. It answers the protocol handshake, it does not give a shell |
| Records | Every connection (which port, from which IP), and logins sent to FTP, MySQL and MSSQL |
| Log file | `telemetry/raw/dionaea/dionaea.json` |

Dionaea was built to capture malware that spreads through services like SMB. In this project its main jobs are: showing **port scans** (one IP touching many ports) and capturing **service credentials** (a login to FTP or a database). The login is captured during the handshake, so the attacker never actually gets in.

### Honeytrap (HTTP and a second SSH banner)

| | |
|---|---|
| Pretends to be | An Apache web server, and an OpenSSH banner on a second port |
| Ports | 8022 (HTTP, answers as `Apache/2.4.52`), 8023 (SSH simulator) |
| Interaction level | Low. It accepts the request and logs it |
| Records | Each HTTP request: method, URL, user agent, source IP |
| Log file | `telemetry/raw/honeytrap/honeytrap.json` |

Honeytrap is how the platform sees **web attacks**: SQL injection strings, Log4Shell strings in a header, path traversal, script injection, scanner user agents such as sqlmap.

### Side by side

| Sensor | Catches | Example rule it feeds |
|---|---|---|
| Cowrie | Brute force, successful login, commands, payload download | `st-auth-001`, `st-cred-002`, `st-exec-003`, `st-exec-004` |
| Dionaea | Port scans, FTP / MySQL / MSSQL logins | `st-recon-006`, `st-cred-003` |
| Honeytrap | Malicious HTTP requests | `st-web-002` |

---

## 3. Architecture

### The containers

```
                    ATTACKER
                       |
        ===============|=================  honeynet_edge  (attacker facing, sensors only)
        |              |                |
   +---------+   +-----------+   +-----------+
   | Cowrie  |   |  Dionaea  |   | Honeytrap |
   | SSH/Tel |   | SMB/FTP/DB|   |   HTTP    |
   +----+----+   +-----+-----+   +-----+-----+
        |              |               |
        |   each sensor only WRITES a JSON log file
        v              v               v
   ./telemetry/raw/cowrie   /dionaea   /honeytrap        (folder on the host)
        |
        |   backend mounts the folder READ ONLY and tails the files
        v
        =================================  honeynet_app  (application, no route to sensors)
   +-------------------------------+      +-----------+
   | Backend (FastAPI, Python)     |<---->|  MariaDB  |
   |  collector -> normaliser      |      +-----------+
   |  detection + correlation      |      +-----------+
   |  REST API on :8000            |<---->|  ClamAV   |
   +---------------+---------------+      +-----------+
                   ^
                   |  /api proxied by nginx
   +---------------+---------------+
   | Frontend (nginx, HTML/CSS/JS) |  :5500  <---  analyst's browser
   +-------------------------------+
```

Other containers: **phpMyAdmin** (database GUI, :8081), **Guacamole + guacd + Postgres** (remote desktop in the browser for the Virtual Lab, :8080), **MobSF** (Android APK analysis, :5055), **Splunk** (optional SIEM for the blue team page).

### The four networks, and why

| Network | Who is on it | Purpose |
|---|---|---|
| `honeynet_edge` | Cowrie, Dionaea, Honeytrap | The only place an attacker can reach |
| `honeynet_app` | Backend, frontend, database, ClamAV, phpMyAdmin | The real application |
| `shadowtrust_labnet` | Backend, Guacamole, MobSF, lab containers | Virtual Lab desktops |
| `shadowtrust_analysis` | Only the disposable sandbox shells | `internal: true`, so no internet at all |

### The security model (say this, examiners like it)

> We assume the honeypots **will** be compromised. So no service is on both the edge network and the app network, and Docker does not route between them.

- A sensor has **no network path** to the backend, the database or the dashboard.
- The **only** way data leaves a sensor is the log file it writes.
- The backend mounts that folder **read only**.
- So the worst a fully hacked honeypot can do is write misleading log lines. It cannot call the API, reach the database, or reach Docker.
- Each sensor also runs with Linux capabilities dropped, `no-new-privileges`, and memory and process limits, so a fork bomb inside a honeypot cannot take down the host.

### Tech stack

| Layer | Technology |
|---|---|
| Sensors | Cowrie, Dionaea, Honeytrap (official Docker images) |
| Backend | Python, FastAPI (async), SQLAlchemy |
| Database | MariaDB 11 |
| Frontend | Plain HTML, CSS and JavaScript served by nginx. No framework |
| Analysis engines | ClamAV, YARA, MobSF, a secret detector, optional CAPE sandbox and VirusTotal |
| Remote desktop | Apache Guacamole |
| Auth | JWT (HS256, 60 minute token), bcrypt password hashes, role checks on the server |
| Packaging | Docker Compose |

---

## 4. How one attack becomes a case

This is the heart of the project. Five steps.

```
 sensor log line
   -> 1 COLLECT      backend tails the log file
   -> 2 NORMALISE    one common event shape for all sensors
   -> 3 DETECT       YAML rules look for patterns
   -> 4 CORRELATE    detections from one attacker merge into one case
   -> 5 GRADE + MAP  severity LOW..CRITICAL, MITRE ATT&CK technique
```

**1. Collect.** A collector inside the backend watches the three log files and reads only the new lines (it remembers its position in each file with a cursor). File change notifications wake it; polling is the fallback.

**2. Normalise.** Each honeypot writes a different JSON format. `normalize.py` converts all of them into one table, `normalized_events`, with the same columns: time, sensor, source IP, port, username, password, command, severity. The event id is a **hash of the raw line**, so reading the same line twice can never create a duplicate.

**3. Detect.** Rules live as YAML files in `backend/detections/`. Sigma format rules are supported too. The engine runs about every 20 seconds, and sooner when new events arrive.

| Rule | Name | Severity | MITRE |
|---|---|---|---|
| `st-recon-006` | Port / service scan | MEDIUM | T1046 Network Service Discovery |
| `st-auth-001` | SSH / Telnet brute force | HIGH | T1110 Brute Force |
| `st-cred-002` | Successful login after brute force | CRITICAL | T1110 |
| `st-cred-003` | Service credential capture | MEDIUM | T1110 |
| `st-exec-003` | Suspicious post-exploitation command | HIGH | T1059 Command and Scripting Interpreter |
| `st-exec-004` | Payload download / stager | HIGH | T1105 Ingress Tool Transfer |
| `st-exec-005` | Suspicious PowerShell | HIGH | T1059 |
| `st-web-002` | Web application attack | HIGH | T1190 Exploit Public-Facing Application |

Good detail to mention: the port scan rule counts **distinct ports** from one IP, not packets. Each detection has a dedupe key (rule + source + time bucket), so the same attack inside the same window does not raise the same alert twice.

**4. Correlate.** Detections from the **same source IP within 6 hours** are merged into one **incident** (a case). So brute force, then login, then commands, then a download becomes one story, not four separate alerts.

**5. Grade and map.** Each case gets a risk score out of 100, and the score is explainable. It is the sum of:

| Component | Meaning | Max |
|---|---|---|
| Severity | Worst rule or event seen | 72 |
| Detections | How many rules fired | 24 |
| Techniques | How many different ATT&CK techniques | 20 |
| Event risk | Worst single raw event | 10 |
| Session volume | How much activity | 6 |
| Malware | A captured hash is linked | 20 |

Then the band: under 28 LOW, 28 to 49 MEDIUM, 50 to 74 HIGH, 75 and above CRITICAL. Two guard rails stop everything turning red: a case with fewer than two detections cannot be graded above its strongest single signal, and raw events alone can never reach CRITICAL. A rule that is itself CRITICAL (login after brute force) always makes the case CRITICAL.

The Investigations page shows this breakdown under "why this severity". That is the answer to *"how do you decide severity?"*

---

## 5. Every page

All pages are in `frontend/`. Each one calls the backend API under `/api/v1/...` with the logged in user's JWT. Nothing on a page is hardcoded sample data.

### Operate

**Overview** (`dashboard.html`)
The landing page after sign in. Threat level, event and case counts, sensor health, an attack flow diagram (source to sensor to rule to case) and a world map of attacker locations. Reads `/dashboard/stats`, `/dashboard/flow`, `/dashboard/geo`, `/nodes`.

**Investigations** (`incidents.html`)
The main analyst page. A list of cases, each one a group of correlated detections. Opening a case shows the timeline rebuilt in order, the rules that fired, the risk breakdown, indicators (IPs, hashes, URLs), linked evidence, ATT&CK techniques and analyst notes. Status can be moved (new, triaging, investigating, contained, closed) and every change is logged.

**Event log** (`events.html`)
The raw feed: every event as it moves from sensor to collector to normaliser to the page. This is where you prove a detection came from real data. Uses a live stream so new events appear without a refresh.

**Logs** (`logs.html`)
All sources in one feed, with each line put in a category (authentication, network, command, malware and so on) by a log categoriser. Useful for a quick "what kind of activity is this".

**Reports** (`reports.html`)
Generates PDF reports on demand: SOC executive summary, geographic threat intelligence, captured credentials, incident report, DFIR report, detection validation and coverage, malware analysis. Each PDF is stored with its SHA-256 so it can be shown to be unchanged. Incident and DFIR reports are admin only.

### Sensors

**Honeypot nodes** (`nodes.html`)
Every sensor in the deployment: running or not, ports, event counts. Health comes from the real containers. **Sensor investigation** (`node_details.html`) is the drill down for one sensor: who is talking to it and what it recorded.

**Splunk blue team** (`splunk.html`)
A front end to a Splunk instance: run searches, upload log files, see notable events and KPIs, purge data. Shows the platform can feed a real SIEM, not only its own database.

**Geo intelligence** (`geo.html`)
Where attacks come from: city, country and ASN (the network owner) for each source IP, on a map. Sources that only resolve to a country are left out instead of being drawn at a made up point.

### Intelligence

**MITRE ATT&CK** (`mitre.html`)
The 14 ATT&CK tactics as columns. A technique is **triggered** when a detection rule has fired for it: the card turns red, shows the detection count and how long ago, and is tagged "new" for the first two minutes. A strip at the top lists every triggered technique, newest first; clicking one jumps to its card. Analysts can set a status, add a note, pin a card, drag it to another tactic, or add a technique by hand.

**Detection validation** (`validation.html`)
Answers "do the rules actually work?". It replays a known attack scenario against the honeypots, waits one detection cycle, then grades what the engine really produced: PASS, PARTIAL or FAIL, with coverage per technique. Scenarios cover brute force, credential attack, reconnaissance, suspicious command, malware download, web attack, PowerShell and exfiltration.

**Attack analytics** (`graphs.html`)
Charts drawn from stored events: most targeted ports, protocols, top source IPs, volume over time.

**Credential vault** (`credentials.html`)
Every username and password attackers tried, across SSH, Telnet, FTP, MySQL and MSSQL, with which ones were accepted. Shows which passwords are being guessed in the wild.

**Behaviour profiling** (`behavior.html`)
Groups attackers by **what they do**, not where they come from. It builds a graph of attacker to target interactions and classifies the style from measured signals, for example automated scanner, credential stuffing bot, or hands on keyboard. Rule based, not a trained model, so every label can be explained.

**Analysis lab** (`analysis_lab.html`)
A terminal in the browser connected to a disposable Linux sandbox with **no internet** (it sits on the internal only network). Every command typed and every outbound connection attempt is captured and pushed through the same detection pipeline, so you can watch a behaviour profile build live. Sandboxes expire on their own.

### Governance

**GRC and SOC 2** (`grc.html`)
Maps the platform's own evidence to SOC 2 Trust Services Criteria controls (CC1.1 onward). Shows a readiness score, each control's status, the evidence behind it, and a risk register. It is a live assessment computed from the system, not a static checklist.

### Tools

**Binary analysis** (`malware.html`)
Upload a file and it goes through a six stage pipeline: static parsing, YARA rules, sandbox detonation (only if a CAPE sandbox is configured), APK checks (if it is an APK), a secret detector, and ClamAV antivirus. Files are identified by SHA-256, quarantined, and a report is stored. A stage that could not run is shown as skipped, never faked.

**URL scanner** (`urlscan.html`)
Checks a link without opening it in your browser: DNS, TLS certificate, WHOIS, HTTP response, plus entropy and lookalike domain checks, and a safe preview.

**APK inspector** (`apk.html`)
Static analysis of Android apps through MobSF: manifest, permissions, network endpoints, embedded secrets.

**Virtual lab** (`vm_lab.html`, `vm_session.html`)
Launches a disposable Kali Linux desktop (and Windows where the host supports it) and streams it into the browser through Apache Guacamole. `vm_session.html` is the page that shows the running desktop.

### Administration (admin only, enforced on the server)

**Administration** (`admin.html`)
Users, services, sensors, settings, backups and diagnostics for the deployment.

**Access control** (`access_control.html`)
New accounts are requests, not instant access. An admin approves or rejects them here and sets what each person can do. Also shows the access log.

**Credential management** (`credential_mgmt.html`)
Issues one time credentials to new analysts.

**AWS connection** (`aws_connection.html`) and **System diagnostics** (`debug.html`)
Optional cloud mode: connect AWS keys to pull honeypot logs from S3 and launch EC2 lab machines. The diagnostics page tests those keys before anything is launched.

**Profile** (`profile.html`)
The signed in user's account, recent activity and permissions.

**Wallboard** (`wallboard.html`)
A full screen, read only view of live stats and cases for a SOC wall display.

### Sign in pages

`login.html` (sign in), `admin_login.html` (admin sign in), `register.html` (request access, needs admin approval), `forgot_password.html` (reset).

### Public site (no login)

`index.html` (landing page with the launch film), `features.html`, `usecases.html`, `architecture.html`, `docs.html` (setup guide), `status.html` (live service status from `/public/status`).

---

## 6. Running the live demo

Start the stack, then run the walkthrough:

```bash
docker compose up -d
./scripts/demo.sh            # press Enter to move between stages
./scripts/demo.sh --fast     # no waiting, for a quick check beforehand
```

Sign in at http://localhost:5500 and keep the browser next to the terminal.

| Stage | Attack | Sensor | Rules expected | Page to show |
|---|---|---|---|---|
| 1 Recon | Port sweep, then nmap | Dionaea | `st-recon-006` | Event log, MITRE (Discovery) |
| 2 Breach | 7 wrong SSH passwords, a working one, commands, two downloads | Cowrie | `st-auth-001`, `st-cred-002`, `st-exec-003`, `st-exec-004` | Investigations, Credential vault, Behaviour profiling |
| 3 Service creds | FTP, MySQL, MSSQL logins | Dionaea | `st-cred-003` | Credential vault |
| 4 Web attack | Injection, Log4Shell, traversal requests | Honeytrap | `st-web-002` | Event log, MITRE (Initial Access) |
| 5 Malware | Upload the standard antivirus test file | Backend pipeline | ClamAV and YARA result | Binary analysis |

Each terminal screen has the same panels, in pipeline order: **ATTACK** (what was sent), **CAPTURED** (events the sensors recorded), **DETECTED** (rules that fired), **CASE** (the incident and its risk score), **EXPLAIN** (what to say), **OPEN IN THE BROWSER** (what to show). CAPTURED, DETECTED and CASE are read from the database at that moment.

Two things to know before you present:

- A grey dot instead of a green tick means the rule is **already on record**. The engine does not raise the same alert twice inside its window. Reset the data (`./reset.sh`) or leave a gap before the real run so the examiner sees green ticks.
- The demo attackers run one after another and get the same lab IP, so all stages land in **one** case. That is correct behaviour (same source, one story), just be ready to say so.

---

## 7. Questions the examiner is likely to ask

**What is a honeypot and why use one?**
A decoy system with no real users. Any interaction is suspicious, so it gives high quality attack data with almost no false positives, and it shows attacker methods safely.

**Low interaction vs medium interaction?**
Low interaction (Dionaea, Honeytrap) only answers the protocol and logs it. Medium interaction (Cowrie) gives a fake shell so you also see what the attacker does after getting in. High interaction would be a real machine, which is riskier.

**What if the attacker takes over a honeypot?**
It is assumed. Sensors are on their own network with no route to the application. Their only output is a log file that the backend reads read only. Capabilities are dropped and resources limited.

**How do you avoid duplicate events?**
The event id is a hash of the raw log line, and it is the primary key. Re-reading a file cannot insert the same event twice. Detections have their own dedupe key.

**How is severity decided?**
A risk score out of 100 built from six components (section 4), turned into LOW, MEDIUM, HIGH or CRITICAL, with guard rails so one noisy signal cannot make a case CRITICAL. The breakdown is shown on the case.

**What is correlation here?**
Grouping detections from the same source IP within six hours into one incident, with a timeline.

**What is MITRE ATT&CK and how do you map to it?**
A public knowledge base of attacker tactics (the goal) and techniques (the method). Each detection rule carries its technique id, so when a rule fires the technique is marked triggered on the matrix.

**Is the data real or simulated?**
Real. The attacks in the demo are real network traffic against real honeypot containers, and every number on screen comes from a database query. Where an external service is not configured (CAPE, VirusTotal), the page says it is skipped.

**Is there machine learning?**
No. Detection is rule based (YAML and Sigma) and behaviour profiling is rule based on measured signals. The benefit is that every result can be explained.

**How is the dashboard secured?**
JWT login with bcrypt hashed passwords, tokens expire after 60 minutes, new accounts need admin approval, and role checks are done on the server, not only hidden in the UI.

**Why Docker?**
Isolation between sensors and application, the same setup on any machine with one command, and easy reset.

**Limitations?**
Honeypots only see attacks aimed at them, not attacks on real systems. A skilled attacker can fingerprint a known honeypot. Low interaction sensors do not show post-exploitation. It runs on a single host, not a distributed deployment.

**Future work?**
More sensors and protocols, distributed sensors in several locations, automated response (block an IP), and threat intelligence sharing.
