"""Shared helpers for report context providers.

A provider is  async def build(db, params, user) -> dict  returning the full
template context: title, subject, sections[], plus optional window/sources/
record_count/disclaimer. engine.render_pdf() + the /reports endpoint add the
provenance fields (generated_by, timestamps, sha256).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional


def parse_window(params: Dict[str, Any]) -> tuple[Optional[datetime], Optional[datetime]]:
    """`days` (int) or explicit `start`/`end` ISO strings. None => all data."""
    end = datetime.utcnow()
    start = None
    if params.get("start"):
        start = datetime.fromisoformat(str(params["start"]).replace("Z", "+00:00")).replace(tzinfo=None)
    if params.get("end"):
        end = datetime.fromisoformat(str(params["end"]).replace("Z", "+00:00")).replace(tzinfo=None)
    days = params.get("days")
    if start is None and days:
        try:
            start = end - timedelta(days=int(days))
        except (TypeError, ValueError):
            start = None
    return start, end


def kpis(*pairs) -> Dict[str, Any]:
    return {"kind": "kpis", "items": [{"label": l, "value": v} for l, v in pairs]}


def table(heading: str, columns: list[str], rows: list[list], note: str | None = None) -> Dict[str, Any]:
    return {"kind": "table", "heading": heading, "columns": columns, "rows": rows, "note": note}


def text(heading: str | None, body) -> Dict[str, Any]:
    return {"kind": "text", "heading": heading, "body": body}


def note(body: str) -> Dict[str, Any]:
    return {"kind": "note", "body": body}


def listing(heading: str, items: list) -> Dict[str, Any]:
    return {"kind": "list", "heading": heading, "items": items}


def sev(text_: str) -> Dict[str, str]:
    return {"pill": "sev", "text": text_ or "—"}
