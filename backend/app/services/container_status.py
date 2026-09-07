"""
Real Docker container state for the honeypot sensors, read through the socket
that is already mounted into the backend (for the VM Lab feature).

Fast path only: `client.containers.list()` + parse `State` from the cached
`attrs`. No `stats()` calls — those stream for ~2 s each and would stall the
dashboard poll. "Load" for the UI is derived from event rate elsewhere.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Dict

from app.services import container_manager

# compose service name -> the container name it runs as
SENSOR_CONTAINERS: Dict[str, str] = {
    "COWRIE": "honeynet_cowrie",
    "DIONAEA": "honeynet_dionaea",
    "HONEYTRAP": "honeynet_honeytrap",
}

_CACHE: Dict[str, object] = {"ts": 0.0, "data": {}}
_TTL = 8.0


def _parse_started_at(raw: str) -> float:
    """Docker RFC3339Nano -> unix seconds. Returns 0.0 on failure."""
    if not raw or raw.startswith("0001-01-01"):
        return 0.0
    txt = raw.replace("Z", "+00:00")
    # trim nanoseconds to microseconds for fromisoformat
    if "." in txt:
        head, _, tail = txt.partition(".")
        frac = tail
        tz = ""
        for sign in ("+", "-"):
            if sign in tail:
                frac, _, tz = tail.partition(sign)
                tz = sign + tz
                break
        txt = f"{head}.{frac[:6]}{tz}"
    try:
        return datetime.fromisoformat(txt).timestamp()
    except ValueError:
        return 0.0


def sensor_container_states() -> Dict[str, dict]:
    """
    { "COWRIE": {"running": bool, "status": str, "health": str|None,
                 "uptime_seconds": int, "available": True}, ... }

    On any Docker error every sensor comes back {"available": False} and the
    caller should fall back to event-recency, not claim the sensor is down.
    """
    now = time.time()
    if now - float(_CACHE["ts"]) < _TTL and _CACHE["data"]:
        return dict(_CACHE["data"])  # type: ignore[arg-type]

    out: Dict[str, dict] = {}
    try:
        # Read-only status through the central chokepoint; no direct socket here.
        by_name = container_manager.read_stack_status(SENSOR_CONTAINERS.values())
        if not by_name and not container_manager.available():
            raise RuntimeError("docker unavailable")
        for sensor, cname in SENSOR_CONTAINERS.items():
            info = by_name.get(cname)
            if info is None:
                out[sensor] = {"available": True, "running": False, "status": "absent",
                               "health": None, "uptime_seconds": 0}
                continue
            started = _parse_started_at(info.get("started_at") or "")
            running = bool(info.get("running"))
            out[sensor] = {
                "available": True,
                "running": running,
                "status": info.get("status"),
                "health": info.get("health"),
                "uptime_seconds": int(now - started) if running and started else 0,
            }
    except Exception:  # noqa: BLE001 — socket missing / permission / API down
        return {s: {"available": False} for s in SENSOR_CONTAINERS}

    _CACHE["ts"] = now
    _CACHE["data"] = out
    return dict(out)
