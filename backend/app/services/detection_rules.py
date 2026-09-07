"""
Detection rule loader + matcher (task 4 — the "Sigma-style" layer).

Rules are YAML files under ``backend/detections/`` — **read-only** at runtime
(the directory is bind-mounted ``:ro``). Adding a rule is dropping a file; the
engine never needs a code change.

Rule shape
----------
```yaml
id: st-auth-001                     # unique, stable
name: SSH / Telnet brute force
description: Repeated auth failures from one source within a window.
severity: HIGH                      # LOW | MEDIUM | HIGH | CRITICAL
confidence: 0.8                     # 0..1, optional (defaults by severity)
source: honeypot                    # informational
attack:
  technique: T1110
  tactic: Credential Access
type: threshold                     # threshold (default) | sequence
selection:                          # field -> match. field|op syntax:
  authentication_result: FAILURE    #   eq (default)
  sensor_event_type|contains: [login.failed, login]   # contains / regex / in / startswith / gt / lt / exists
timeframe: 10m                      # 30s / 10m / 2h / 1d
group_by: source_ip                 # source_ip (default) | session_id | username
threshold: 5                        # threshold rules: N matching events in the window
# sequence rules instead use:
# steps:
#   - { selection: {authentication_result: FAILURE}, min_count: 3 }
#   - { selection: {authentication_result: SUCCESS}, min_count: 1 }
```

Fields resolve against ``NormalizedEventModel`` columns first, then keys inside
the event ``metadata`` JSON.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Dict, List, Optional

DETECTIONS_DIR = os.getenv("DETECTIONS_DIR", os.path.join(os.getcwd(), "detections"))

_SEV_CONFIDENCE = {"LOW": 0.4, "MEDIUM": 0.6, "HIGH": 0.8, "CRITICAL": 0.9}
_SEV_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_VALID_SEVERITY = set(_SEV_ORDER)

_EVENT_COLUMNS = {
    "event_id", "timestamp", "sensor", "sensor_event_type", "source_ip",
    "source_port", "destination_ip", "destination_port", "protocol", "severity",
    "username", "password", "authentication_result", "command", "payload",
    "session_id", "raw_event",
}


def _parse_timeframe(text: str) -> timedelta:
    text = str(text or "10m").strip().lower()
    m = re.match(r"^(\d+)\s*(s|m|h|d)$", text)
    if not m:
        return timedelta(minutes=10)
    n, unit = int(m.group(1)), m.group(2)
    return {"s": timedelta(seconds=n), "m": timedelta(minutes=n),
            "h": timedelta(hours=n), "d": timedelta(days=n)}[unit]


@dataclass
class Condition:
    field: str
    op: str
    value: Any

    def matches(self, event_value: Any) -> bool:
        ev = event_value
        op, want = self.op, self.value
        if op == "exists":
            return (ev is not None) == bool(want)
        if ev is None:
            return False
        s = str(ev)
        if op == "eq":
            if isinstance(want, list):
                return any(str(w).lower() == s.lower() for w in want)
            return s.lower() == str(want).lower()
        if op == "in":
            return s.lower() in [str(w).lower() for w in (want or [])]
        if op == "contains":
            opts = want if isinstance(want, list) else [want]
            return any(str(w).lower() in s.lower() for w in opts)
        if op == "startswith":
            opts = want if isinstance(want, list) else [want]
            return any(s.lower().startswith(str(w).lower()) for w in opts)
        if op == "regex":
            opts = want if isinstance(want, list) else [want]
            return any(re.search(str(w), s, re.IGNORECASE) for w in opts)
        if op in ("gt", "lt", "gte", "lte"):
            try:
                a, b = float(ev), float(want)
            except (TypeError, ValueError):
                return False
            return {"gt": a > b, "lt": a < b, "gte": a >= b, "lte": a <= b}[op]
        return False


@dataclass
class Step:
    conditions: List[Condition]
    min_count: int = 1


@dataclass
class DetectionRule:
    id: str
    name: str
    severity: str
    confidence: float
    technique: Optional[str]
    tactic: Optional[str]
    rule_type: str                       # threshold | sequence
    group_by: str
    timeframe: timedelta
    threshold: int
    conditions: List[Condition] = field(default_factory=list)
    steps: List[Step] = field(default_factory=list)
    description: str = ""
    source: str = ""
    raw_selection: Dict[str, Any] = field(default_factory=dict)

    def event_field(self, event, name: str) -> Any:
        if name in _EVENT_COLUMNS and hasattr(event, name):
            return getattr(event, name)
        # normalized_events stores the sensor-specific blob under the ORM
        # attribute `event_metadata` (column name "metadata").
        meta = getattr(event, "event_metadata", None)
        if meta is None:
            meta = getattr(event, "metadata", None)
        if isinstance(meta, str):
            try:
                import json
                meta = json.loads(meta)
            except Exception:
                meta = {}
        if isinstance(meta, dict):
            return meta.get(name)
        return None

    def event_matches(self, event, conditions: List[Condition]) -> bool:
        return all(c.matches(self.event_field(event, c.field)) for c in conditions)

    def group_key(self, event) -> Optional[str]:
        val = self.event_field(event, self.group_by)
        return str(val) if val is not None else None

    def reason_for(self, group: str, n: int) -> str:
        window = _human_timedelta(self.timeframe)
        if self.rule_type == "sequence":
            return (f"rule {self.id} ({self.name}): matched the ordered step sequence "
                    f"for {self.group_by}={group} within {window}")
        return (f"rule {self.id} ({self.name}): {n} events matched "
                f"{self.raw_selection} for {self.group_by}={group} within {window} "
                f"(threshold {self.threshold})")


def _human_timedelta(td: timedelta) -> str:
    secs = int(td.total_seconds())
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if secs % size == 0 and secs >= size:
            return f"{secs // size}{unit}"
    return f"{secs}s"


def _parse_selection(selection: Dict[str, Any]) -> List[Condition]:
    conditions: List[Condition] = []
    for key, value in (selection or {}).items():
        if "|" in key:
            fld, op = key.split("|", 1)
        else:
            fld, op = key, "eq"
        conditions.append(Condition(field=fld.strip(), op=op.strip(), value=value))
    return conditions


def _parse_rule(doc: Dict[str, Any]) -> DetectionRule:
    sev = str(doc.get("severity", "MEDIUM")).upper()
    if sev not in _VALID_SEVERITY:
        sev = "MEDIUM"
    attack = doc.get("attack") or {}
    rule_type = str(doc.get("type", "threshold")).lower()
    steps: List[Step] = []
    conditions: List[Condition] = []
    if rule_type == "sequence":
        for s in doc.get("steps", []):
            steps.append(Step(
                conditions=_parse_selection(s.get("selection", {})),
                min_count=int(s.get("min_count", 1)),
            ))
    else:
        conditions = _parse_selection(doc.get("selection", {}))
    return DetectionRule(
        id=str(doc["id"]),
        name=str(doc.get("name", doc["id"])),
        severity=sev,
        confidence=float(doc.get("confidence", _SEV_CONFIDENCE[sev])),
        technique=(attack.get("technique") or None),
        tactic=(attack.get("tactic") or None),
        rule_type="sequence" if rule_type == "sequence" else "threshold",
        group_by=str(doc.get("group_by", "source_ip")),
        timeframe=_parse_timeframe(doc.get("timeframe", "10m")),
        threshold=int(doc.get("threshold", 1)),
        conditions=conditions,
        steps=steps,
        description=str(doc.get("description", "")),
        source=str(doc.get("source", "")),
        raw_selection=doc.get("selection", {}) if rule_type != "sequence" else {"steps": doc.get("steps", [])},
    )


_CACHE: Dict[str, Any] = {"mtime": None, "rules": []}


def load_rules(directory: Optional[str] = None, force: bool = False) -> List[DetectionRule]:
    """Load + cache all rule files. Recompiles when the directory mtime changes."""
    path = directory or DETECTIONS_DIR
    try:
        mtime = max(
            (os.path.getmtime(os.path.join(path, f)) for f in os.listdir(path)
             if f.endswith((".yml", ".yaml"))),
            default=0.0,
        )
    except FileNotFoundError:
        return []
    if not force and _CACHE["mtime"] == mtime and _CACHE["rules"]:
        return _CACHE["rules"]

    try:
        import yaml
    except ImportError:
        return []

    rules: List[DetectionRule] = []
    for fname in sorted(os.listdir(path)):
        if not fname.endswith((".yml", ".yaml")):
            continue
        try:
            with open(os.path.join(path, fname)) as fh:
                doc = yaml.safe_load(fh)
            if isinstance(doc, dict) and doc.get("id"):
                rules.append(_parse_rule(doc))
        except Exception:
            # A malformed rule file must not take the whole engine down.
            continue
    _CACHE["mtime"] = mtime
    _CACHE["rules"] = rules
    return rules


def severity_rank(sev: str) -> int:
    return _SEV_ORDER.get(str(sev).upper(), 0)
