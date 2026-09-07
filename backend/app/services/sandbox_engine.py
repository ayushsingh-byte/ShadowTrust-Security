"""
CAPE Sandbox integration
========================
Dynamic malware detonation via a real CAPE Sandbox deployment.

Set ``CAPE_URL`` (and optionally ``CAPE_API_KEY``) to a reachable CAPE instance
to enable behavioural analysis. When it is not configured, ``analyze()`` returns
``{"available": False, ...}`` — the pipeline records that dynamic analysis was
not run rather than fabricating a report. Static analysis, YARA, ClamAV and
secret detection still run and carry the verdict.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

CAPE_URL = os.getenv("CAPE_URL", "").rstrip("/")
CAPE_API_KEY = os.getenv("CAPE_API_KEY", "")
CACHE_FILE = os.path.join("scans", "cape_cache.json")

MITRE_TECHNIQUES = {
    "T1059": "Command and Scripting Interpreter",
    "T1055": "Process Injection",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1071": "Application Layer Protocol (C2)",
    "T1547": "Boot or Logon Autostart Execution",
    "T1105": "Ingress Tool Transfer",
    "T1027": "Obfuscated Files or Information",
    "T1140": "Deobfuscate/Decode Files",
    "T1190": "Exploit Public-Facing Application",
    "T1486": "Data Encrypted for Impact (Ransomware)",
    "T1112": "Modify Registry",
    "T1070": "Indicator Removal on Host",
    "T1016": "System Network Configuration Discovery",
    "T1049": "System Network Connections Discovery",
    "T1021": "Remote Services (Lateral Movement)",
    "T1078": "Valid Accounts",
    "T1136": "Create Account",
    "T1566": "Phishing",
    "T1003": "OS Credential Dumping",
}


# ─── result cache (CAPE reports only) ───────────────────────────────────────────
def _load_cache() -> Dict[str, Any]:
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_cache(cache: Dict[str, Any]) -> None:
    os.makedirs("scans", exist_ok=True)
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)


def get_cached_result(sha256: str) -> Optional[Dict[str, Any]]:
    cached = _load_cache().get(sha256)
    if isinstance(cached, dict) and cached.get("source") == "CAPE_LIVE":
        return cached
    return None


def cache_result(sha256: str, result: Dict[str, Any]) -> None:
    if result.get("source") != "CAPE_LIVE":
        return  # only cache genuine detonations
    cache = _load_cache()
    cache[sha256] = result
    if len(cache) > 500:
        del cache[next(iter(cache))]
    _save_cache(cache)


UNAVAILABLE_RESULT = {
    "source": "UNAVAILABLE",
    "available": False,
    "reason": ("Dynamic sandbox detonation is not configured. Set CAPE_URL to a "
               "reachable CAPE Sandbox instance to enable behavioural analysis."),
    "threat_family": None,
    "score": None,
    "risk_level": None,
    "mitre_techniques": {},
    "signatures": [],
    "network_intel": {},
    "behavior_profile": {},
}


class CAPESandboxEngine:
    """Submits a sample to a real CAPE deployment and normalises the report."""

    def __init__(self, file_path: str, sha256: str, filename: str):
        self.file_path = file_path
        self.sha256 = sha256
        self.filename = filename

    def _call_real_cape(self) -> Optional[Dict[str, Any]]:
        try:
            import requests
            headers = {"Authorization": f"Token {CAPE_API_KEY}"} if CAPE_API_KEY else {}
            with open(self.file_path, "rb") as f:
                resp = requests.post(
                    f"{CAPE_URL}/apiv2/tasks/create/file/",
                    files={"file": (self.filename, f)}, headers=headers, timeout=30,
                )
            if resp.status_code != 200:
                return None
            body = resp.json()
            task_id = body.get("data", {}).get("task_id") or (body.get("task_ids") or [None])[0]
            if not task_id:
                return None
            import time
            for _ in range(18):  # up to ~90s
                time.sleep(5)
                r2 = requests.get(f"{CAPE_URL}/apiv2/tasks/report/{task_id}/", headers=headers, timeout=30)
                if r2.status_code == 200:
                    return self._parse_cape_report(r2.json())
        except Exception:
            return None
        return None

    def _parse_cape_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        signatures = report.get("signatures", [])
        behavior = report.get("behavior", {})
        network = report.get("network", {})
        malscore = report.get("malscore", 0) or 0

        mitre_map: Dict[str, str] = {}
        for sig in signatures:
            for ttp in sig.get("ttp", []):
                tid = ttp.get("ttp", "")
                if tid:
                    mitre_map[tid] = MITRE_TECHNIQUES.get(tid, sig.get("name", ""))

        return {
            "source": "CAPE_LIVE",
            "available": True,
            "threat_family": report.get("malfamily") or "Unknown",
            "score": int(malscore * 10),
            "risk_level": "CRITICAL" if malscore > 7 else "HIGH" if malscore > 4 else "MEDIUM",
            "mitre_techniques": mitre_map,
            "behavior_profile": {
                "network_activity": bool(network.get("tcp") or network.get("dns")),
                "file_modifications": len(behavior.get("summary", {}).get("files", [])),
                "registry_changes": len(behavior.get("summary", {}).get("keys", [])),
                "dropped_files": len(report.get("dropped", [])),
                "process_injections": len([s for s in signatures if "injection" in s.get("name", "").lower()]),
                "process_tree": behavior.get("processtree", []),
            },
            "network_intel": {
                "urls": [h.get("uri", "") for h in network.get("http", [])][:10],
                "c2_ips": [c.get("dst", "") for c in network.get("tcp", [])][:10],
                "dns_queries": [{"domain": d.get("request", ""), "type": d.get("type", "A")}
                                for d in network.get("dns", [])][:10],
            },
            "signatures": [{"name": s.get("name"), "severity": s.get("severity", 2)} for s in signatures[:15]],
        }

    def analyze(self) -> Dict[str, Any]:
        cached = get_cached_result(self.sha256)
        if cached:
            cached["from_cache"] = True
            return cached

        result = self._call_real_cape() if CAPE_URL else None
        if result is None:
            result = dict(UNAVAILABLE_RESULT)

        result["sha256"] = self.sha256
        result["filename"] = self.filename
        result["analyzed_at"] = datetime.now(timezone.utc).isoformat()
        result["from_cache"] = False
        cache_result(self.sha256, result)
        return result
