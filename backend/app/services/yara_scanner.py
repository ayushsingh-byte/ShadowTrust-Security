"""
YARA scanning for the malware pipeline (task 5).

  * rules live in ``backend/yara_rules/*.yar`` — mounted **read-only**, so an
    analysed sample can never rewrite them
  * ``yara-python`` is imported lazily; if it (or a rule) fails to compile the
    scanner returns ``available: False`` and the pipeline continues
  * compiled rules are cached in-process and recompiled when the directory
    mtime changes
  * results are cached by SHA-256 in the ``yara_results`` table by the caller
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

YARA_RULES_DIR = os.getenv("YARA_RULES_DIR", os.path.join(os.getcwd(), "yara_rules"))

_COMPILED: Dict[str, Any] = {"mtime": None, "rules": None, "error": None}


def _dir_mtime(path: str) -> float:
    try:
        files = [os.path.join(path, f) for f in os.listdir(path)
                 if f.endswith((".yar", ".yara"))]
        return max((os.path.getmtime(f) for f in files), default=0.0)
    except FileNotFoundError:
        return -1.0


def _compile(path: str):
    """(Re)compile all rule files. Returns (compiled_or_None, error_or_None)."""
    try:
        import yara  # type: ignore
    except Exception as exc:  # noqa: BLE001
        return None, f"yara-python unavailable: {exc}"

    filepaths = {}
    try:
        for f in sorted(os.listdir(path)):
            if f.endswith((".yar", ".yara")):
                filepaths[f] = os.path.join(path, f)
    except FileNotFoundError:
        return None, f"rules directory not found: {path}"

    if not filepaths:
        return None, "no .yar rule files present"

    try:
        return yara.compile(filepaths=filepaths), None
    except Exception as exc:  # noqa: BLE001 — a bad rule must not kill the pipeline
        return None, f"rule compile error: {exc}"


def _get_rules():
    mtime = _dir_mtime(YARA_RULES_DIR)
    if _COMPILED["mtime"] != mtime:
        rules, err = _compile(YARA_RULES_DIR)
        _COMPILED.update(mtime=mtime, rules=rules, error=err)
    return _COMPILED["rules"], _COMPILED["error"]


def yara_scan(file_path: str, sha256: str = "") -> Dict[str, Any]:
    """
    Returns:
      {available: bool, matches: [{rule, namespace, tags, meta}], count: int, error: str|None}
    Never raises.
    """
    out: Dict[str, Any] = {"available": False, "matches": [], "count": 0, "error": None}
    rules, err = _get_rules()
    if rules is None:
        out["error"] = err
        return out

    try:
        raw_matches = rules.match(file_path, timeout=30)
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"scan error: {exc}"
        out["available"] = True
        return out

    matches: List[Dict[str, Any]] = []
    for m in raw_matches:
        meta = dict(getattr(m, "meta", {}) or {})
        matches.append({
            "rule": m.rule,
            "namespace": getattr(m, "namespace", "default"),
            "tags": list(getattr(m, "tags", []) or []),
            "meta": meta,
        })

    out.update(available=True, matches=matches, count=len(matches))
    return out


def worst_severity(matches: List[Dict[str, Any]]) -> str:
    order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    top = 0
    for m in matches:
        sev = str(m.get("meta", {}).get("severity", "")).lower()
        top = max(top, order.get(sev, 0))
    return {0: "", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}[top]
