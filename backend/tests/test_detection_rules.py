"""Detection rule loader + matcher — pure unit tests (no DB)."""

from datetime import datetime, timedelta

import pytest

from app.services import detection_rules
from app.services.detection_rules import (
    Condition,
    _parse_timeframe,
    load_rules,
)


class _Ev:
    """Minimal stand-in for a NormalizedEventModel row."""

    def __init__(self, **kw):
        self.event_id = kw.get("event_id", "e")
        self.timestamp = kw.get("timestamp", datetime.utcnow())
        self.ingested_at = kw.get("ingested_at", datetime.utcnow())
        self.sensor = kw.get("sensor", "cowrie")
        self.sensor_event_type = kw.get("sensor_event_type", "cowrie.login.failed")
        self.source_ip = kw.get("source_ip", "203.0.113.9")
        self.destination_ip = kw.get("destination_ip")
        self.destination_port = kw.get("destination_port", 2222)
        self.protocol = kw.get("protocol", "ssh")
        self.severity = kw.get("severity", "MEDIUM")
        self.username = kw.get("username")
        self.password = kw.get("password")
        self.authentication_result = kw.get("authentication_result", "FAILURE")
        self.command = kw.get("command")
        self.payload = kw.get("payload")
        self.session_id = kw.get("session_id")
        self.raw_event = kw.get("raw_event", "{}")
        self.event_metadata = kw.get("event_metadata", {})


def test_timeframe_parsing():
    assert _parse_timeframe("10m") == timedelta(minutes=10)
    assert _parse_timeframe("2h") == timedelta(hours=2)
    assert _parse_timeframe("30s") == timedelta(seconds=30)
    assert _parse_timeframe("garbage") == timedelta(minutes=10)


def test_condition_ops():
    assert Condition("x", "eq", "FAILURE").matches("failure")
    assert Condition("x", "in", ["a", "b"]).matches("B")
    assert Condition("x", "contains", ["login.failed"]).matches("cowrie.login.failed")
    assert Condition("x", "regex", [r"wget\s+http"]).matches("wget http://evil/x")
    assert Condition("x", "startswith", "T10").matches("T1059")
    assert Condition("x", "gt", 100).matches("450")
    assert not Condition("x", "gt", 100).matches("50")
    assert Condition("x", "exists", True).matches("anything")
    assert not Condition("x", "exists", True).matches(None)


def test_bundled_rules_load(tmp_path):
    rules = load_rules(str(tmp_path / "nope"), force=True)
    assert rules == []  # missing dir -> empty, not crash

    rules = load_rules("detections", force=True)
    ids = {r.id for r in rules}
    assert {"st-auth-001", "st-cred-002", "st-exec-004", "st-recon-006"} <= ids
    seq = next(r for r in rules if r.id == "st-cred-002")
    assert seq.rule_type == "sequence" and len(seq.steps) == 2


def test_threshold_rule_matches_field():
    rule = next(r for r in load_rules("detections", force=True) if r.id == "st-auth-001")
    fail = _Ev(authentication_result="FAILURE")
    ok = _Ev(authentication_result="SUCCESS")
    assert rule.event_matches(fail, rule.conditions)
    assert not rule.event_matches(ok, rule.conditions)
    assert rule.group_key(fail) == fail.source_ip


def test_metadata_field_resolution():
    rule = next(r for r in load_rules("detections", force=True) if r.id == "st-auth-001")
    ev = _Ev(event_metadata={"asn": "AS64500"})
    assert rule.event_field(ev, "asn") == "AS64500"
    assert rule.event_field(ev, "source_ip") == ev.source_ip
