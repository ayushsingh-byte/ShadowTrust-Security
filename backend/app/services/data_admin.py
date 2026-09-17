"""
Platform data lifecycle — the ADMIN "populate data" / "reset data" buttons on
the /health test bench (POST /api/v1/admin/data/{populate,reset}).

Reset wipes *data only*: telemetry, detections, incidents, evidence, reports,
malware scans and the sensor log files the collector tails. Accounts, roles,
access / admin / credential audit logs, system settings, the node registry,
VM labs and Splunk are left untouched.

Populate goes through the same route as live traffic — nothing is written past
the collector:
  * corpus     scripts/seed_corpus.py appends a geolocatable historic corpus to
               the sensor log files (a presentation corpus — see that script).
  * live       scripts/attacker/actors/*.sh run in throwaway st-attacker
               containers on honeynet_edge and really attack the sensors, same
               as scripts/populate_lab.sh.

The backend mounts ./telemetry/raw read-only on purpose, so the two operations
that must write there (append corpus, truncate logs) run in a one-shot helper
container with only that directory mounted and no network. Every command is
fixed here; the request body only picks sizes from a bounded range.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from sqlalchemy import bindparam, text

from app.db.database import AsyncSessionLocal

EDGE_NET = os.getenv("HONEYNET_EDGE_NETWORK", "honeynet_edge")
ATTACKER_IMAGE = "st-attacker:latest"
HELPER_PY_IMAGE = os.getenv("DATA_HELPER_PY_IMAGE", "soc/backend:latest")
HELPER_SH_IMAGE = "alpine:3.19"
SCRIPTS_DIR = Path("/app/scripts")
ACTORS = ["mirai", "handson", "exfil", "recon", "web", "dionaea", "slowbrute"]
ACTOR_ENV = {
    "COWRIE": "honeynet_cowrie", "DIONAEA": "honeynet_dionaea", "HONEYTRAP": "honeynet_honeytrap",
    "SSH_P": "2222", "TELNET_P": "2223", "SMB_P": "445", "MSSQL_P": "1433", "FTP_P": "2121",
    "HTTP_P": "8022", "HTTP2_P": "8023", "FAIL_PW": "123456 password root toor 12345 admin 1234",
}

# Tables holding platform *data*. Anything not listed (users, access_logs,
# admin_activity_log, credential_*, system_settings/config, nodes, vm_*) is kept.
DATA_TABLES = [
    "normalized_events", "raw_events", "ingest_cursors", "events", "attacks", "alerts",
    "captured_payloads", "iocs", "ioc_observations", "node_metrics", "attacker_sessions",
    "structured_events", "s3_sync_state", "detections", "incident_events", "incident_iocs",
    "incident_activity", "evidence", "incidents", "scenario_runs", "analysis_sessions",
    "generated_reports",
]
DATA_SETTING_KEYS = ["mitre_annotations"]
DATA_DIRS = [
    Path(os.getenv("REPORTS_DIR", "/app/reports")),
    Path(os.path.abspath(os.getenv("EVIDENCE_DIR", "evidence"))),
    Path(os.path.abspath(os.getenv("QUARANTINE_DIR", "quarantine"))),
    Path(os.path.abspath("scans")),
]
TELEMETRY_DIR = Path(os.getenv("TELEMETRY_DIR", "/app/telemetry/raw"))
SENSOR_CONTAINERS = ["honeynet_cowrie", "honeynet_dionaea", "honeynet_honeytrap"]
LIVE_SENSOR_FILES = ["cowrie/cowrie.json", "cowrie/cowrie.log", "dionaea/dionaea.json",
                     "dionaea/dionaea.log", "dionaea/dionaea-errors.log", "honeytrap/honeytrap.json"]

_lock = asyncio.Lock()
JOB: Dict[str, Any] = {"kind": None, "status": "idle", "log": []}


def _log(msg: str) -> None:
    JOB["log"].append(f"{datetime.now(timezone.utc).strftime('%H:%M:%S')}  {msg}")
    del JOB["log"][:-300]


def _docker():
    import docker  # type: ignore
    return docker.from_env()


def _host_path(container_path: str) -> str:
    """Host source of one of this backend container's bind mounts."""
    me = _docker().containers.get(socket.gethostname())
    for m in me.attrs.get("Mounts", []):
        if m.get("Destination") == container_path:
            return m["Source"]
    raise RuntimeError(f"backend has no bind mount at {container_path}")


def _sensors(action: str) -> None:
    client = _docker()
    for name in SENSOR_CONTAINERS:
        try:
            getattr(client.containers.get(name), action)()
        except Exception as e:  # noqa: BLE001
            _log(f"  {action} {name}: {e.__class__.__name__}: {e}")


def _run_helper(image: str, command: List[str], volumes: Dict[str, Dict[str, str]], timeout: int = 600) -> str:
    client = _docker()
    c = client.containers.run(
        image, entrypoint=command[:1], command=command[1:], volumes=volumes,
        network_mode="none", user="0", detach=True,
        labels={"shadowtrust.data_admin": "helper"},
    )
    try:
        rc = c.wait(timeout=timeout).get("StatusCode", 1)
        out = c.logs().decode("utf-8", "replace")
        if rc != 0:
            raise RuntimeError(f"helper exited {rc}: {out[-400:]}")
        return out
    finally:
        try:
            c.remove(force=True)
        except Exception:
            pass


# ── inventory ───────────────────────────────────────────────────────────────
async def inventory() -> Dict[str, Any]:
    rows: Dict[str, int] = {}
    async with AsyncSessionLocal() as db:
        existing = {r[0] for r in (await db.execute(text(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()"
        ))).all()}
        for t in DATA_TABLES:
            if t in existing:
                rows[t] = (await db.execute(text(f"SELECT COUNT(*) FROM `{t}`"))).scalar() or 0
    files = {}
    for d in DATA_DIRS + [TELEMETRY_DIR]:
        if d.exists():
            fs = [p for p in d.rglob("*") if p.is_file()]
            files[str(d)] = {"files": len(fs), "bytes": sum(p.stat().st_size for p in fs)}
    return {"tables": rows, "total_rows": sum(rows.values()), "files": files}


# ── reset ───────────────────────────────────────────────────────────────────
async def _reset() -> None:
    _log("stopping analysis-lab sandboxes")
    from app.models.all_models import AnalysisSession
    from app.services import analysis_shell
    from sqlalchemy import select
    async with AsyncSessionLocal() as db:
        live = (await db.execute(select(AnalysisSession).where(
            AnalysisSession.status.in_(("starting", "running"))))).scalars().all()
        for s in live:
            await analysis_shell._teardown(db, s, reason="data reset")
        await db.commit()
    _log(f"  stopped {len(live)}")

    # Sensors keep their own file offsets (Cowrie's Twisted writer is not
    # O_APPEND), so stop them, empty the logs, and restart them after the wipe
    # so they reopen at offset 0 instead of writing past a hole.
    _log("stopping sensors: " + ", ".join(SENSOR_CONTAINERS))
    await asyncio.to_thread(_sensors, "stop")
    try:
        _log("emptying sensor logs (helper container, telemetry mount only)")
        src = await asyncio.to_thread(_host_path, str(TELEMETRY_DIR))
        keep = " ".join(f"! -path '/t/{f}'" for f in LIVE_SENSOR_FILES)
        await asyncio.to_thread(
            _run_helper, HELPER_SH_IMAGE,
            ["sh", "-c", f"find /t -type f {keep} -delete; "
                         "find /t -type f -exec sh -c ': > \"$1\"' _ {} \\;"],
            {src: {"bind": "/t", "mode": "rw"}},
        )
        await asyncio.sleep(5)      # let an in-flight collector cycle land before the wipe
        _log("wiping data tables")
        async with AsyncSessionLocal() as db:
            existing = {r[0] for r in (await db.execute(text(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()"
            ))).all()}
            await db.execute(text("SET FOREIGN_KEY_CHECKS=0"))
            try:
                for t in DATA_TABLES:
                    if t in existing:
                        await db.execute(text(f"TRUNCATE TABLE `{t}`"))
                await db.execute(
                    text("DELETE FROM system_settings WHERE `key` IN :k").bindparams(bindparam("k", expanding=True)),
                    {"k": DATA_SETTING_KEYS},
                )
            finally:
                await db.execute(text("SET FOREIGN_KEY_CHECKS=1"))
            await db.commit()

        _log("clearing reports / evidence / quarantine / scans")
        for d in DATA_DIRS:
            if not d.exists():
                continue
            for p in d.iterdir():
                if p.is_dir():
                    shutil.rmtree(p, ignore_errors=True)
                else:
                    p.unlink(missing_ok=True)
    finally:
        _log("starting sensors")
        await asyncio.to_thread(_sensors, "start")


# ── populate ────────────────────────────────────────────────────────────────
async def _seed_corpus(events: int) -> None:
    _log(f"writing {events} historic corpus events into sensor logs")
    t_src = await asyncio.to_thread(_host_path, str(TELEMETRY_DIR))
    s_src = await asyncio.to_thread(_host_path, str(SCRIPTS_DIR))
    out = await asyncio.to_thread(
        _run_helper, HELPER_PY_IMAGE,
        ["python3", "/s/seed_corpus.py", "--events", str(events), "--days", "30", "--telemetry-dir", "/t"],
        {t_src: {"bind": "/t", "mode": "rw"}, s_src: {"bind": "/s", "mode": "ro"}},
    )
    for line in out.strip().splitlines():
        _log("  " + line.strip())


def _ensure_attacker_image() -> None:
    client = _docker()
    try:
        client.images.get(ATTACKER_IMAGE)
    except Exception:
        _log("building st-attacker image (first run, needs internet for apk)")
        client.images.build(path=str(SCRIPTS_DIR / "attacker"), tag=ATTACKER_IMAGE, rm=True)


def _wave(n: int) -> None:
    client = _docker()
    started = []
    for a in ACTORS:
        script = (SCRIPTS_DIR / "attacker" / "actors" / f"{a}.sh").read_text()
        c = client.containers.run(
            ATTACKER_IMAGE, [script], network=EDGE_NET, environment=ACTOR_ENV, detach=True,
            name=f"st-atk-{a}-{int(time.time())}-{n}", labels={"shadowtrust.data_admin": "attacker"},
        )
        started.append((a, c))
        _log(f"  + {a} ({c.short_id})")
    deadline = time.time() + 180
    for a, c in started:
        try:
            c.wait(timeout=max(1, deadline - time.time()))
        except Exception:
            _log(f"  {a} still running at deadline — killed")
        finally:
            try:
                c.remove(force=True)
            except Exception:
                pass


async def _populate(corpus_events: int, waves: int) -> None:
    if corpus_events:
        await _seed_corpus(corpus_events)
    if waves:
        await asyncio.to_thread(_ensure_attacker_image)
        for w in range(1, waves + 1):
            _log(f"live attack wave {w}/{waves}: {len(ACTORS)} actors on {EDGE_NET}")
            await asyncio.to_thread(_wave, w)
            if w < waves:
                _log("  cooldown 25s (lets the detection engine correlate)")
                await asyncio.sleep(25)
    _log("waiting 20s for the collector + detection engine to catch up")
    await asyncio.sleep(20)


# ── job wrapper ─────────────────────────────────────────────────────────────
async def _run(kind: str, coro) -> None:
    try:
        await coro
        inv = await inventory()
        _log(f"done — {inv['total_rows']} data rows now")
        JOB["status"] = "done"
    except Exception as e:  # noqa: BLE001
        _log(f"FAILED: {e.__class__.__name__}: {e}")
        JOB["status"] = "failed"
    finally:
        JOB["finished_at"] = datetime.now(timezone.utc).isoformat()
        _lock.release()


async def start(kind: str, **kw) -> Dict[str, Any]:
    if _lock.locked():
        return {"ok": False, "error": f"a '{JOB['kind']}' job is already running", "job": JOB}
    await _lock.acquire()
    JOB.update(kind=kind, status="running", log=[], started_at=datetime.now(timezone.utc).isoformat(),
               finished_at=None, params=kw)
    coro = _reset() if kind == "reset" else _populate(**kw)
    asyncio.create_task(_run(kind, coro))
    return {"ok": True, "job": JOB}
