"""Detection-validation grading math + scenario loading (no traffic)."""

from app.services import detection_validation as dv


def test_scenarios_load_and_are_local_only():
    scenarios = dv.load_scenarios("scenarios")
    assert "ssh-brute-force" in scenarios
    for s in scenarios.values():
        assert s.get("target", "127.0.0.1") in ("127.0.0.1", "localhost")


def test_local_target_is_hardcoded():
    assert dv.LOCAL_TARGET == "127.0.0.1"


def test_grade_pass():
    expected = {
        "expected_detections": ["st-auth-001"],
        "expected_techniques": ["T1110"],
        "expected_severity": "HIGH",
        "expected_incident": True,
    }
    observed = {
        "detections_seen": ["st-auth-001"],
        "techniques_seen": ["T1110"],
        "severity_seen": "HIGH",
        "incidents_touched": ["INC-000001"],
        "telemetry": True,
        "all_detection_rules_in_window": ["st-auth-001"],
    }
    g = dv._grade(expected, observed)
    assert g["result"] == "PASS"
    assert g["metrics"]["detection_success_rate"] == 1.0
    assert g["metrics"]["attack_coverage"] == 1.0
    assert g["metrics"]["telemetry_coverage"] == 1.0


def test_grade_fail_when_detection_missing():
    expected = {
        "expected_detections": ["st-exec-005"],
        "expected_techniques": ["T1059.001"],
        "expected_severity": "HIGH",
        "expected_incident": True,
    }
    observed = {
        "detections_seen": [],
        "techniques_seen": [],
        "severity_seen": None,
        "incidents_touched": [],
        "telemetry": False,
        "all_detection_rules_in_window": [],
    }
    g = dv._grade(expected, observed)
    assert g["result"] == "FAIL"
    assert g["metrics"]["telemetry_coverage"] == 0.0
    assert "st-exec-005" in g["metrics"]["missing_detections"]


def test_grade_partial():
    expected = {
        "expected_detections": ["st-auth-001", "st-cred-002"],
        "expected_techniques": ["T1110"],
        "expected_severity": "CRITICAL",
        "expected_incident": True,
    }
    observed = {
        "detections_seen": ["st-auth-001"],
        "techniques_seen": ["T1110"],
        "severity_seen": "HIGH",
        "incidents_touched": ["INC-1"],
        "telemetry": True,
        "all_detection_rules_in_window": ["st-auth-001"],
    }
    g = dv._grade(expected, observed)
    assert g["result"] == "PARTIAL"
    assert 0 < g["metrics"]["detection_success_rate"] < 1


def test_false_positive_detection_flagged():
    expected = {"expected_detections": ["st-auth-001"], "expected_techniques": [],
                "expected_severity": "", "expected_incident": False}
    observed = {
        "detections_seen": ["st-auth-001"],
        "techniques_seen": [],
        "severity_seen": "HIGH",
        "incidents_touched": [],
        "telemetry": True,
        "all_detection_rules_in_window": ["st-auth-001", "st-not-a-real-rule"],
    }
    g = dv._grade(expected, observed)
    assert "st-not-a-real-rule" in g["metrics"]["false_positive_rules"]
