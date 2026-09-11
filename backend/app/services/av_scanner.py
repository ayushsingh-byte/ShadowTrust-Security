"""
Real antivirus for the Malware Lab.

  * clamav_scan(path)      — stream the file to clamd (INSTREAM, :3310) for a
                             signature verdict. Fully offline once the DB is
                             downloaded. Absent container -> available: False.
  * virustotal_lookup(sha) — query the VirusTotal API v3 by hash. Needs
                             VIRUSTOTAL_API_KEY; free tier is 4 req/min / 500/day,
                             so results are cached by the caller.

Both return a plain dict and never raise — a missing engine must not break a
report, it just contributes nothing to the verdict.
"""

from __future__ import annotations

import os
import socket
import struct
from typing import Any, Dict

CLAMAV_HOST = os.getenv("CLAMAV_HOST", "clamav")
CLAMAV_PORT = int(os.getenv("CLAMAV_PORT", "3310"))
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

_CHUNK = 64 * 1024
_MAX_STREAM = 64 * 1024 * 1024  # clamd StreamMaxLength default


def clamav_scan(file_path: str) -> Dict[str, Any]:
    """
    Returns:
      {available: bool, infected: bool|None, signature: str|None, error: str|None}
    """
    out: Dict[str, Any] = {"available": False, "infected": None, "signature": None, "error": None}
    try:
        with socket.create_connection((CLAMAV_HOST, CLAMAV_PORT), timeout=8) as sock:
            sock.settimeout(60)
            sock.sendall(b"zINSTREAM\0")
            sent = 0
            with open(file_path, "rb") as fh:
                while True:
                    chunk = fh.read(_CHUNK)
                    if not chunk:
                        break
                    sent += len(chunk)
                    if sent > _MAX_STREAM:
                        out["error"] = "file larger than clamd StreamMaxLength"
                        break
                    sock.sendall(struct.pack("!L", len(chunk)) + chunk)
            sock.sendall(struct.pack("!L", 0))  # end of stream

            resp = b""
            while b"\0" not in resp and len(resp) < 4096:
                part = sock.recv(4096)
                if not part:
                    break
                resp += part
    except (OSError, socket.timeout) as e:
        out["error"] = f"clamd unreachable: {e.__class__.__name__}"
        return out

    text = resp.decode("utf-8", "replace").strip().strip("\0")
    out["available"] = True
    if text.endswith("OK"):
        out["infected"] = False
    elif "FOUND" in text:
        out["infected"] = True
        # "stream: Win.Test.EICAR_HDB-1 FOUND"
        try:
            out["signature"] = text.split(":", 1)[1].strip().rsplit(" ", 1)[0].strip()
        except Exception:
            out["signature"] = text
    else:
        out["error"] = text or "empty clamd response"
        out["available"] = not text.lower().startswith("error")
    return out


def _virustotal_query(sha256: str) -> Dict[str, Any]:
    """
    Hash lookup only (no file upload). Returns:
      {available, known, malicious, suspicious, harmless, undetected, total,
       names[], permalink, error}
    """
    out: Dict[str, Any] = {
        "available": bool(VIRUSTOTAL_API_KEY),
        "known": False, "malicious": 0, "suspicious": 0, "total": 0,
        "names": [], "permalink": None, "error": None,
    }
    if not VIRUSTOTAL_API_KEY:
        out["error"] = "no VIRUSTOTAL_API_KEY set"
        return out
    try:
        import requests

        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=15,
        )
    except Exception as e:  # noqa: BLE001
        out["error"] = f"{e.__class__.__name__}: {e}"
        return out

    out["permalink"] = f"https://www.virustotal.com/gui/file/{sha256}"
    if r.status_code == 404:
        out["error"] = "not seen by VirusTotal"
        return out
    if r.status_code == 429:
        out["error"] = "VirusTotal rate limit"
        return out
    if r.status_code != 200:
        out["error"] = f"VirusTotal HTTP {r.status_code}"
        return out

    try:
        attr = r.json()["data"]["attributes"]
        stats = attr.get("last_analysis_stats", {})
        out.update(
            known=True,
            malicious=int(stats.get("malicious", 0)),
            suspicious=int(stats.get("suspicious", 0)),
            harmless=int(stats.get("harmless", 0)),
            undetected=int(stats.get("undetected", 0)),
            total=sum(int(v) for v in stats.values() if isinstance(v, (int, float))),
        )
        results = attr.get("last_analysis_results", {})
        out["names"] = sorted({
            v.get("result") for v in results.values()
            if v.get("category") in ("malicious", "suspicious") and v.get("result")
        })[:10]
    except Exception as e:  # noqa: BLE001
        out["error"] = f"parse: {e}"
    return out


# Outcome of the most recent lookup, so the status check can report a rejected key
# without spending quota on a test request (free tier: 4 lookups/min, 500/day).
_VT_LAST: Dict[str, Any] = {"error": None}


def virustotal_lookup(sha256: str) -> Dict[str, Any]:
    result = _virustotal_query(sha256)
    _VT_LAST["error"] = result.get("error")
    return result


def virustotal_status() -> Dict[str, Any]:
    if not VIRUSTOTAL_API_KEY:
        return {"available": False, "detail": "no API key configured"}
    if str(_VT_LAST["error"] or "").startswith(("VirusTotal HTTP 401", "VirusTotal HTTP 403")):
        return {"available": False, "detail": "API key rejected by VirusTotal"}
    return {"available": True, "detail": "hash lookup on every new sample"}
