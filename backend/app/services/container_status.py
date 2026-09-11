"""
Real Docker state and resource usage for the honeypot sensors, read through the
socket that is already mounted into the backend (for the VM Lab feature).

State (running, uptime) is a fast `containers.list()` read cached for a few
seconds. Resource usage comes from `container.stats()`, which blocks ~1-2 s per
call, so a background sampler reads it on an interval and requests are served
from memory.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Callable, Dict, Optional, Tuple

from app.services import container_manager

logger = logging.getLogger(__name__)

# compose service name -> the container name it runs as
SENSOR_CONTAINERS: Dict[str, str] = {
    "COWRIE": "honeynet_cowrie",
    "DIONAEA": "honeynet_dionaea",
    "HONEYTRAP": "honeynet_honeytrap",
}

_CACHE: Dict[str, object] = {"ts": 0.0, "data": {}}
_TTL = 8.0

METRICS_INTERVAL_SECONDS = 5.0
_METRICS: Dict[str, dict] = {}
# container name -> (sample time, cumulative rx bytes, cumulative tx bytes)
_PREV_NET: Dict[str, Tuple[float, int, int]] = {}


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


def _percent(part: float, whole: float) -> Optional[float]:
    return round(part / whole * 100.0, 1) if whole else None


def _sample(container_name: str) -> dict:
    """One resource reading for a container, in the same units `docker stats` shows. Never raises."""
    try:
        container = container_manager.get_client().containers.get(container_name)
        if container.status != "running":
            _PREV_NET.pop(container_name, None)
            return {"available": True, "running": False}
        stats = container.stats(stream=False)
    except Exception as exc:  # noqa: BLE001 — socket missing, container absent, API error
        return {"available": False, "error": str(exc)[:200]}

    cpu = stats.get("cpu_stats") or {}
    previous_cpu = stats.get("precpu_stats") or {}
    cpu_delta = (cpu.get("cpu_usage") or {}).get("total_usage", 0) - (previous_cpu.get("cpu_usage") or {}).get("total_usage", 0)
    system_delta = (cpu.get("system_cpu_usage") or 0) - (previous_cpu.get("system_cpu_usage") or 0)
    cpus = cpu.get("online_cpus") or len((cpu.get("cpu_usage") or {}).get("percpu_usage") or []) or 1
    cpu_percent = round(cpu_delta / system_delta * cpus * 100.0, 1) if system_delta > 0 and cpu_delta >= 0 else 0.0

    memory = stats.get("memory_stats") or {}
    detail = memory.get("stats") or {}
    # Reclaimable page cache is excluded, as `docker stats` does (cgroup v2: inactive_file, v1: cache).
    used = max(0, (memory.get("usage") or 0) - (detail.get("inactive_file", detail.get("cache", 0)) or 0))

    networks = stats.get("networks") or {}
    rx = sum(n.get("rx_bytes", 0) for n in networks.values())
    tx = sum(n.get("tx_bytes", 0) for n in networks.values())
    now = time.time()
    previous = _PREV_NET.get(container_name)
    _PREV_NET[container_name] = (now, rx, tx)
    rx_kbps = tx_kbps = None
    if previous and now > previous[0]:
        elapsed = now - previous[0]
        rx_kbps = round(max(0, rx - previous[1]) / elapsed / 1024, 2)
        tx_kbps = round(max(0, tx - previous[2]) / elapsed / 1024, 2)

    return {
        "available": True,
        "running": True,
        "cpu_percent": cpu_percent,
        "memory_percent": _percent(used, memory.get("limit") or 0),
        "memory_used_mb": round(used / 1048576, 1),
        "net_rx_kbps": rx_kbps,
        "net_tx_kbps": tx_kbps,
        "sampled_at": datetime.now(timezone.utc).isoformat(),
    }


async def run_metrics_sampler(
    publish: Callable[[dict], None], interval: float = METRICS_INTERVAL_SECONDS
) -> None:
    """Sample every sensor container forever, publishing each snapshot."""
    while True:
        try:
            names = list(SENSOR_CONTAINERS.items())
            readings = await asyncio.gather(*(asyncio.to_thread(_sample, cname) for _sensor, cname in names))
            snapshot = {sensor: reading for (sensor, _cname), reading in zip(names, readings)}
            _METRICS.clear()
            _METRICS.update(snapshot)
            publish(snapshot)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — keep sampling through transient Docker errors
            logger.warning(f"Container metrics sample failed: {exc}")
        await asyncio.sleep(interval)


def sensor_container_metrics() -> Dict[str, dict]:
    """Latest sample per sensor ({} until the sampler's first pass completes)."""
    return dict(_METRICS)
