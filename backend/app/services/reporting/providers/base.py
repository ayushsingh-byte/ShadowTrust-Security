"""Shared helpers for report context providers.

A provider is  async def build(db, params, user) -> dict  returning the full
template context: title, subject, sections[] (legacy) or the per-type keys the
dedicated template reads, plus optional window/sources/record_count/disclaimer.
engine.render_pdf() + the /reports endpoint add the provenance fields
(generated_by, timestamps, sha256).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple


# ── time window ──────────────────────────────────────────────────────────────
def parse_window(params: Dict[str, Any]) -> Tuple[Optional[datetime], datetime]:
    """`window_days` / `days` (int) or explicit `start`/`end` ISO strings.

    Returns (start, end) as naive UTC datetimes. start is None only when the
    caller explicitly asks for all history (`window_days=0` / `all`).
    """
    end = datetime.utcnow()
    start: Optional[datetime] = None

    if params.get("start"):
        start = datetime.fromisoformat(str(params["start"]).replace("Z", "+00:00")).replace(tzinfo=None)
    if params.get("end"):
        end = datetime.fromisoformat(str(params["end"]).replace("Z", "+00:00")).replace(tzinfo=None)

    days = params.get("window_days", params.get("days"))
    if start is None:
        if days in (None, "", "all"):
            days = 30  # sensible default window for every report
        try:
            days = int(days)
        except (TypeError, ValueError):
            days = 30
        start = None if days <= 0 else (end - timedelta(days=days))
    return start, end


def prev_window(start: Optional[datetime], end: datetime) -> Tuple[Optional[datetime], Optional[datetime]]:
    """The equally-sized window immediately before [start, end]."""
    if start is None:
        return None, None
    span = end - start
    return start - span, start


# ── formatting ───────────────────────────────────────────────────────────────
def fmt_ts(v: Any, fmt: str = "%Y-%m-%d %H:%M") -> str:
    if not v:
        return "—"
    if isinstance(v, datetime):
        return v.strftime(fmt)
    return str(v)[:19].replace("T", " ")


def pct(n: Any, total: Any) -> float:
    try:
        n = float(n or 0); total = float(total or 0)
        return round(100 * n / total, 1) if total else 0.0
    except (TypeError, ValueError):
        return 0.0


def clip(s: Any, n: int) -> str:
    s = "" if s is None else str(s)
    return s if len(s) <= n else s[: n - 1] + "…"


# ── section / cell builders (legacy generic.html + new templates) ────────────
def kpis(*pairs) -> Dict[str, Any]:
    return {"kind": "kpis", "items": [{"label": l, "value": v} for l, v in pairs]}


def kpi(label: str, value: Any, sub: str | None = None) -> Dict[str, Any]:
    return {"label": label, "value": value, "sub": sub}


def table(heading: str, columns: list, rows: list, note: str | None = None) -> Dict[str, Any]:
    return {"kind": "table", "heading": heading, "columns": columns, "rows": rows, "note": note}


def text(heading: str | None, body) -> Dict[str, Any]:
    return {"kind": "text", "heading": heading, "body": body}


def note(body: str) -> Dict[str, Any]:
    return {"kind": "note", "body": body}


def listing(heading: str, items: list) -> Dict[str, Any]:
    return {"kind": "list", "heading": heading, "items": items}


def sev(text_: str) -> Dict[str, str]:
    return {"pill": "sev", "text": text_ or "—"}


def status(text_: str) -> Dict[str, str]:
    return {"pill": "status", "text": text_ or "—"}


# ── chart / trend helpers ────────────────────────────────────────────────────
def bar_items(pairs: Iterable[Tuple[Any, Any]], limit: int | None = None) -> List[Dict[str, Any]]:
    """pairs = [(label, value), ...] -> [{label, value, pct}] scaled to the max."""
    rows = [(str(l), float(v or 0)) for l, v in pairs]
    rows = [r for r in rows if r[1] > 0] or rows
    if limit:
        rows = rows[:limit]
    top = max((v for _, v in rows), default=0) or 1
    out = []
    for l, v in rows:
        out.append({"label": clip(l, 34), "value": (int(v) if v == int(v) else round(v, 1)),
                    "pct": round(100 * v / top, 1)})
    return out


def delta(label: str, current: int | float, previous: int | float) -> Dict[str, Any]:
    cur = current or 0
    prev = previous or 0
    diff = cur - prev
    if diff > 0:
        d = f"▲ +{diff}"
        direction = "up"
    elif diff < 0:
        d = f"▼ {diff}"
        direction = "down"
    else:
        d = "► 0"
        direction = "flat"
    if prev:
        d += f" ({pct(diff, prev):+.0f}%)"
    return {"label": label, "current": cur, "previous": prev, "delta": d, "dir": direction}
