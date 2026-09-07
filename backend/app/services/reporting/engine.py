"""
PDF report engine
=================
Renders Jinja2 HTML templates (templates/) to PDF with WeasyPrint.

Every report shares templates/base.html, which stamps a provenance block on the
cover — who generated it, when (UTC + operator TZ), the data window, the source
systems queried, row counts and the document SHA-256. Nothing in a report is
invented here: providers/ assemble the context purely from live DB / service
data, and this module only lays it out.
"""
from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from jinja2 import Environment, FileSystemLoader, select_autoescape

_BASE = Path(__file__).parent
_TEMPLATES = _BASE / "templates"

REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "/app/reports"))

_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES)),
    autoescape=select_autoescape(["html", "xml"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def _fmt_dt(value: Any, fmt: str = "%Y-%m-%d %H:%M:%S UTC") -> str:
    if value in (None, "", "-"):
        return "—"
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    if isinstance(value, datetime):
        return value.strftime(fmt)
    return str(value)


def _fmt_bytes(n: Any) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "—"
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(n) < 1024.0:
            return f"{n:,.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024.0
    return f"{n:,.1f} EB"


_env.filters["dt"] = _fmt_dt
_env.filters["bytes"] = _fmt_bytes


def slugify(text: str) -> str:
    text = re.sub(r"[^A-Za-z0-9]+", "-", str(text or "")).strip("-").lower()
    return text or "report"


def report_filename(report_type: str, subject: str, when: datetime, ext: str = "pdf") -> str:
    stamp = when.astimezone(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    parts = ["ShadowTrust", "".join(w.capitalize() for w in report_type.split("_"))]
    subj = slugify(subject)[:40].strip("-")
    if subj and subj not in ("report", "global"):
        parts.append(subj)
    parts.append(stamp)
    return "-".join(parts) + f".{ext}"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def render_pdf(template: str, context: Dict[str, Any]) -> bytes:
    """Render templates/<template> to PDF bytes."""
    from weasyprint import HTML  # imported here so a missing lib fails loudly at call time

    ctx = dict(context)
    ctx.setdefault("now_utc", datetime.now(timezone.utc))
    html = _env.get_template(template).render(**ctx)
    return HTML(string=html, base_url=str(_BASE)).write_pdf()
