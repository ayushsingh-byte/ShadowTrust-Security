"""
Splunk Blue Team — thin proxy over a local Splunk's REST API.

The Splunk container is its own compose project (~/splunk-lab). This module
talks to its management API (default https://host.docker.internal:8089) with
basic auth over a self-signed cert. Every call degrades to a
``{"reachable": false}`` shape when Splunk is down, so splunk.html never breaks.

Env:
  SPLUNK_API_URL   https://host.docker.internal:8089   (splunkd management port)
  SPLUNK_WEB_URL   http://localhost:8009               (browser link on the page)
  SPLUNK_USER      admin
  SPLUNK_PASSWORD  ChangeMe123!
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, Depends, File, UploadFile
from pydantic import BaseModel

from app.api.v1.dependencies import get_current_active_user
from app.models.all_models import User

router = APIRouter()

SPLUNK_API_URL = os.getenv("SPLUNK_API_URL", "https://host.docker.internal:8089").rstrip("/")
SPLUNK_WEB_URL = os.getenv("SPLUNK_WEB_URL", "http://localhost:8009").rstrip("/")
SPLUNK_USER = os.getenv("SPLUNK_USER", "admin")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "ChangeMe123!")

# Hard caps so a bad SPL can't hang a request or flood the browser.
_MAX_RESULTS = 500
_TIMEOUT = 45.0


async def _run_search(spl: str, earliest: str = "-24h", latest: str = "+5m") -> Dict[str, Any]:
    """
    Run a blocking oneshot search via /services/search/jobs/export.

    Returns {"reachable": bool, "rows": [...], "error": str|None, "count": int}.
    """
    if not spl.strip():
        return {"reachable": True, "rows": [], "count": 0, "error": "empty search"}

    # Splunk requires the search to start with `search` or a generating command.
    normalized = spl.strip()
    if not (normalized.startswith("|") or normalized.lower().startswith("search ")):
        normalized = f"search {normalized}"

    try:
        async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{SPLUNK_API_URL}/services/search/jobs/export",
                auth=(SPLUNK_USER, SPLUNK_PASSWORD),
                data={
                    "search": normalized,
                    "output_mode": "json",
                    "earliest_time": earliest,
                    "latest_time": ("+5m" if latest == "now" else latest),
                    "count": _MAX_RESULTS,
                },
            )
    except Exception as e:  # noqa: BLE001 — connection refused, DNS, timeout…
        return {"reachable": False, "rows": [], "count": 0, "error": f"{e.__class__.__name__}: {e}"}

    if resp.status_code == 401:
        return {"reachable": True, "rows": [], "count": 0, "error": "Splunk auth failed (check SPLUNK_USER/PASSWORD)"}
    if resp.status_code >= 400:
        return {"reachable": True, "rows": [], "count": 0, "error": f"Splunk HTTP {resp.status_code}: {resp.text[:200]}"}

    rows: List[Dict[str, Any]] = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        result = obj.get("result")
        if result:
            rows.append(result)
        if len(rows) >= _MAX_RESULTS:
            break
    return {"reachable": True, "rows": rows, "count": len(rows), "error": None}


@router.get("/config")
async def splunk_config(_: User = Depends(get_current_active_user)) -> Dict[str, Any]:
    """Non-secret info the page needs (the console link)."""
    return {"web_url": SPLUNK_WEB_URL, "api_url": SPLUNK_API_URL, "user": SPLUNK_USER}


@router.get("/health")
async def splunk_health(_: User = Depends(get_current_active_user)) -> Dict[str, Any]:
    try:
        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            resp = await client.get(
                f"{SPLUNK_API_URL}/services/server/info",
                auth=(SPLUNK_USER, SPLUNK_PASSWORD),
                params={"output_mode": "json"},
            )
        if resp.status_code == 401:
            return {"reachable": True, "authed": False, "error": "auth failed"}
        data = resp.json()
        entry = (data.get("entry") or [{}])[0].get("content", {})
        return {
            "reachable": True,
            "authed": True,
            "version": entry.get("version"),
            "server_name": entry.get("serverName"),
            "web_url": SPLUNK_WEB_URL,
        }
    except Exception as e:  # noqa: BLE001
        return {"reachable": False, "authed": False, "error": f"{e.__class__.__name__}", "web_url": SPLUNK_WEB_URL}


def _int(v: Any) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


@router.get("/kpis")
async def splunk_kpis(_: User = Depends(get_current_active_user)) -> Dict[str, Any]:
    """Headline numbers for the KPI row. Wide window — imported datasets are historical."""
    # One tstats grouped by index gives everything: total, per-index, index count.
    idx = await _run_search("| tstats count where index=* by index | sort - count", earliest="-5y")
    if not idx["reachable"]:
        return {"reachable": False, "error": idx["error"]}
    by_index = [{"index": r.get("index"), "count": _int(r.get("count"))} for r in idx["rows"]]

    hosts = await _run_search(
        "| tstats count where index=* by host | stats count as n, sum(count) as total", earliest="-5y"
    )
    st = await _run_search(
        "| tstats count where index=* by sourcetype | stats count as n", earliest="-5y"
    )
    hrow = (hosts["rows"] or [{}])[0]
    return {
        "reachable": True,
        "events_total": _int(hrow.get("total")) or sum(x["count"] for x in by_index),
        "hosts": _int(hrow.get("n")),
        "sourcetypes": _int((st["rows"] or [{}])[0].get("n")),
        "indexes": len(by_index),
        "by_index": by_index[:12],
    }


@router.get("/notable")
async def splunk_notable(limit: int = 25, _: User = Depends(get_current_active_user)) -> Dict[str, Any]:
    """
    Recent high-interest events across common blue-team signals:
    failed logons, blocked actions, Sysmon process creation, explicit severity=high.
    """
    limit = max(1, min(limit, 200))
    # Full-text match on common blue-team signals so this works regardless of how
    # the data was onboarded (structured fields OR raw text). Newest first.
    spl = (
        'search index=* ('
        '"4625" OR "4720" OR "4740" OR "1102" '
        'OR "Failed password" OR "authentication failure" OR "status=failed" '
        'OR "action=blocked" OR "action=denied" OR "Access Denied" '
        'OR "EventID\\": 1" OR "malware" OR "ProcessCreate"'
        ') '
        '| sort - _time '
        f'| head {limit} '
        '| eval signal=substr(_raw, 1, 200) '
        '| table _time sourcetype source signal'
    )
    res = await _run_search(spl, earliest="-5y")
    return {"reachable": res["reachable"], "error": res["error"], "rows": res["rows"], "count": res["count"]}


class SearchRequest(BaseModel):
    spl: str
    earliest: Optional[str] = "-24h"
    latest: Optional[str] = "now"


@router.post("/search")
async def splunk_search(body: SearchRequest, _: User = Depends(get_current_active_user)) -> Dict[str, Any]:
    return await _run_search(body.spl, body.earliest or "-24h", body.latest or "now")


# ── Add / remove logs ───────────────────────────────────────────────────────

class IngestRequest(BaseModel):
    data: str
    sourcetype: str = "shadowtrust:manual"
    index: str = "main"
    source: str = "shadowtrust-panel"
    host: str = "shadowtrust-panel"


@router.post("/ingest")
async def splunk_ingest(body: IngestRequest, _: User = Depends(get_current_active_user)) -> Dict[str, Any]:
    """
    Add log lines to Splunk via the simple receiver — one event per non-blank line.
    """
    lines = [ln for ln in body.data.replace("\r\n", "\n").split("\n") if ln.strip()]
    if not lines:
        return {"ok": False, "error": "no non-blank lines to ingest", "events": 0}
    if len(lines) > 20000:
        return {"ok": False, "error": "too many lines (max 20000 per call)", "events": 0}

    params = {
        "source": body.source[:200] or "shadowtrust-panel",
        "sourcetype": body.sourcetype[:200] or "shadowtrust:manual",
        "index": body.index[:80] or "main",
        "host": body.host[:200] or "shadowtrust-panel",
    }
    try:
        async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{SPLUNK_API_URL}/services/receivers/simple",
                auth=(SPLUNK_USER, SPLUNK_PASSWORD),
                params=params,
                content=("\n".join(lines) + "\n").encode(),
            )
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{e.__class__.__name__}: {e}", "events": 0}
    if resp.status_code >= 400:
        return {"ok": False, "error": f"Splunk HTTP {resp.status_code}: {resp.text[:200]}", "events": 0}
    return {"ok": True, "events": len(lines), "index": params["index"], "sourcetype": params["sourcetype"]}


_MAX_FILE_BYTES = 20 * 1024 * 1024
_MAX_FILE_LINES = 100_000


async def _send_lines(lines: List[str], *, source: str, sourcetype: str, index: str) -> Dict[str, Any]:
    if not lines:
        return {"ok": False, "events": 0, "error": "no non-blank lines"}
    body = ("\n".join(lines) + "\n").encode()
    try:
        async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{SPLUNK_API_URL}/services/receivers/simple",
                auth=(SPLUNK_USER, SPLUNK_PASSWORD),
                params={"source": source[:200], "sourcetype": sourcetype[:200],
                        "index": index[:80], "host": "shadowtrust-panel"},
                content=body,
            )
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "events": 0, "error": f"{e.__class__.__name__}: {e}"}
    if resp.status_code >= 400:
        return {"ok": False, "events": 0, "error": f"Splunk HTTP {resp.status_code}: {resp.text[:160]}"}
    return {"ok": True, "events": len(lines), "sourcetype": sourcetype}


@router.post("/upload")
async def splunk_upload(
    files: List[UploadFile] = File(...),
    _: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """
    Upload one or more log files (.log/.txt/.json/.csv/.jsonl…). Each file's
    non-blank lines are ingested as events with source=<filename>. Sourcetype is
    auto-detected: `_json` when the first line parses as JSON, else
    `shadowtrust:file`.
    """
    results: List[Dict[str, Any]] = []
    total = 0
    for f in files:
        name = (f.filename or "upload").split("/")[-1]
        raw = await f.read()
        if len(raw) > _MAX_FILE_BYTES:
            results.append({"name": name, "ok": False, "events": 0,
                            "error": f"file > {_MAX_FILE_BYTES // (1024*1024)} MB"})
            continue
        text = raw.decode("utf-8", errors="replace")
        lines = [ln for ln in text.replace("\r\n", "\n").split("\n") if ln.strip()]
        if len(lines) > _MAX_FILE_LINES:
            lines = lines[:_MAX_FILE_LINES]
        sourcetype = "shadowtrust:file"
        if lines:
            try:
                json.loads(lines[0])
                sourcetype = "_json"
            except ValueError:
                pass
        r = await _send_lines(lines, source=name, sourcetype=sourcetype, index="main")
        r["name"] = name
        results.append(r)
        total += r.get("events", 0)
    return {"ok": any(r.get("ok") for r in results), "total_events": total, "files": results}


@router.get("/sources")
async def splunk_sources(_: User = Depends(get_current_active_user)) -> Dict[str, Any]:
    """Every (index, source, sourcetype) with its event count and time span — for the purge UI."""
    res = await _run_search(
        "| tstats count, min(_time) as first, max(_time) as last where index=* by index, source, sourcetype "
        "| sort - count",
        earliest="-5y",
    )
    if not res["reachable"]:
        return {"reachable": False, "error": res["error"], "sources": []}
    out = []
    for r in res["rows"]:
        out.append({
            "index": r.get("index"),
            "source": r.get("source"),
            "sourcetype": r.get("sourcetype"),
            "count": _int(r.get("count")),
            "first": r.get("first"),
            "last": r.get("last"),
        })
    return {"reachable": True, "sources": out}


class PurgeRequest(BaseModel):
    index: str = "main"
    source: Optional[str] = None
    older_than_days: Optional[int] = None
    confirm: bool = False


@router.post("/purge")
async def splunk_purge(body: PurgeRequest, _: User = Depends(get_current_active_user)) -> Dict[str, Any]:
    """
    Delete data by source and/or age. Needs an index, confirm=true, and at least
    one of source / older_than_days (never an unscoped wipe).
    """
    if not body.confirm:
        return {"ok": False, "error": "set confirm=true"}
    idx = (body.index or "").strip()
    if not idx:
        return {"ok": False, "error": "index is required"}
    if not body.source and not body.older_than_days:
        return {"ok": False, "error": "specify a source and/or older_than_days"}

    parts = [f"search index={idx}"]
    if body.source:
        safe = body.source.replace('"', '')
        parts.append(f'source="{safe}"')
    latest = "now"
    if body.older_than_days and body.older_than_days > 0:
        latest = f"-{int(body.older_than_days)}d@d"
    spl = " ".join(parts) + " | delete"

    granted = await _ensure_can_delete()
    res = await _run_search(spl, earliest="0", latest=latest)
    if not res["reachable"] or res["error"]:
        return {"ok": False, "error": res["error"] or "unreachable"}
    total = 0
    for r in res["rows"]:
        try:
            total += int(float(r.get("deleted", 0)))
        except (TypeError, ValueError):
            pass
    if total == 0 and not res["rows"] and not granted:
        return {"ok": False, "error": "could not grant the Splunk user can_delete — add it in Splunk."}
    return {"ok": True, "deleted": total, "spl": spl, "latest": latest}


async def _ensure_can_delete() -> bool:
    """
    Give the Splunk user the built-in `can_delete` role (grants only
    delete_by_keyword). Returns True once the role is present.
    """
    try:
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            info = await client.get(
                f"{SPLUNK_API_URL}/services/authentication/users/{SPLUNK_USER}",
                auth=(SPLUNK_USER, SPLUNK_PASSWORD),
                params={"output_mode": "json"},
            )
            roles = []
            try:
                roles = info.json()["entry"][0]["content"].get("roles", []) or []
            except Exception:
                pass
            if "can_delete" in roles:
                return True
            new_roles = sorted(set(roles) | {"can_delete"})
            await client.post(
                f"{SPLUNK_API_URL}/services/authentication/users/{SPLUNK_USER}",
                auth=(SPLUNK_USER, SPLUNK_PASSWORD),
                data=[("roles", r) for r in new_roles],
            )
            check = await client.get(
                f"{SPLUNK_API_URL}/services/authentication/users/{SPLUNK_USER}",
                auth=(SPLUNK_USER, SPLUNK_PASSWORD),
                params={"output_mode": "json"},
            )
            return "can_delete" in (check.json()["entry"][0]["content"].get("roles", []) or [])
    except Exception:
        return False


class DeleteRequest(BaseModel):
    spl: str
    earliest: Optional[str] = "0"
    latest: Optional[str] = "now"
    confirm: bool = False


@router.post("/delete")
async def splunk_delete(body: DeleteRequest, _: User = Depends(get_current_active_user)) -> Dict[str, Any]:
    """
    Mark events matching an SPL as deleted (Splunk's `| delete`). Deleted events
    are hidden from all searches immediately; disk space is reclaimed later.
    Requires `confirm: true`.
    """
    if not body.confirm:
        return {"ok": False, "error": "set confirm=true to delete"}
    spl = body.spl.strip()
    if not spl:
        return {"ok": False, "error": "empty search"}
    if "| delete" in spl.lower():
        return {"ok": False, "error": "do not include `| delete` — it is appended automatically"}
    if not (spl.startswith("|") or spl.lower().startswith("search ")):
        spl = f"search {spl}"
    # Guard: refuse an unscoped delete of everything.
    if "index=" not in spl.lower() and "index =" not in spl.lower():
        return {"ok": False, "error": "refusing to delete without an explicit index= filter"}

    granted = await _ensure_can_delete()
    res = await _run_search(f"{spl} | delete", earliest=body.earliest or "0", latest=body.latest or "now")
    if not res["reachable"]:
        return {"ok": False, "error": res["error"]}
    if res["error"]:
        return {"ok": False, "error": res["error"]}
    # `| delete` returns a row with `deleted` / `errors` totals.
    total = 0
    for r in res["rows"]:
        try:
            total += int(float(r.get("deleted", 0)))
        except (TypeError, ValueError):
            pass
    if total == 0 and not res["rows"] and not granted:
        return {
            "ok": False,
            "error": "delete produced no result — the Splunk user could not be granted the "
            "can_delete role. Add it in Splunk (Settings → Users → admin → can_delete).",
        }
    return {"ok": True, "deleted": total, "rows": res["rows"]}
