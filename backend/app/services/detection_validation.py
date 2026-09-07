"""
Detection validation / SOC testing (tasks 8 + 9).

Runs (or evaluates) a controlled attack scenario and grades what the **real**
Shadow Trust detection pipeline produced against what the scenario expects.

Security: ``execute`` mode shells out to ``scripts/attack_scenarios.sh`` with the
target **hard-coded to 127.0.0.1** — the analyst never supplies a target. The
script additionally refuses anything outside RFC1918 / loopback.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.all_models import (
    Detection,
    Incident,
    NormalizedEventModel,
    ScenarioRun,
)
from app.services import detection_engine
from app.services.detection_rules import severity_rank

SCENARIOS_DIR = os.getenv("SCENARIOS_DIR", os.path.join(os.getcwd(), "scenarios"))
ATTACK_SCRIPT = os.getenv("ATTACK_SCENARIOS_SCRIPT", os.path.join(os.getcwd(), "scripts", "attack_scenarios.sh"))
LOCAL_TARGET = "127.0.0.1"  # never analyst-supplied


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def load_scenarios(directory: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    path = directory or SCENARIOS_DIR
    out: Dict[str, Dict[str, Any]] = {}
    try:
        import yaml
    except ImportError:
        return {}
    try:
        files = sorted(os.listdir(path))
    except FileNotFoundError:
        return {}
    for f in files:
        if not f.endswith((".yml", ".yaml")):
            continue
        try:
            with open(os.path.join(path, f)) as fh:
                doc = yaml.safe_load(fh)
            if isinstance(doc, dict) and doc.get("id"):
                doc.setdefault("expected_detections", [])
                doc.setdefault("expected_techniques", [])
                out[doc["id"]] = doc
        except Exception:
            continue
    return out


def _all_expected_rule_ids() -> set:
    return {rid for s in load_scenarios().values() for rid in s.get("expected_detections", [])}


async def _observe(db: AsyncSession, window_start: datetime, target_ip: str) -> Dict[str, Any]:
    """What the pipeline produced since ``window_start``."""
    dets = (await db.execute(
        select(Detection).where(Detection.created_at >= window_start)
    )).scalars().all()
    incs = (await db.execute(
        select(Incident).where(Incident.updated_at >= window_start)
    )).scalars().all()
    ev_count = (await db.execute(
        select(NormalizedEventModel).where(NormalizedEventModel.ingested_at >= window_start).limit(1)
    )).scalars().first()

    det_rules = sorted({d.rule_id for d in dets})
    techniques = sorted({d.attack_technique for d in dets if d.attack_technique})
    severities = [d.severity for d in dets]
    top_sev = max(severities, key=severity_rank) if severities else None

    return {
        "detections_seen": det_rules,
        "detection_rows": len(dets),
        "techniques_seen": techniques,
        "severity_seen": top_sev,
        "incidents_touched": [i.incident_key for i in incs],
        "telemetry": bool(ev_count),
        "all_detection_rules_in_window": det_rules,
    }


def _grade(expected: Dict[str, Any], observed: Dict[str, Any]) -> Dict[str, Any]:
    exp_rules = set(expected.get("expected_detections", []))
    exp_tech = set(expected.get("expected_techniques", []))
    exp_sev = (expected.get("expected_severity") or "").upper()
    exp_incident = bool(expected.get("expected_incident"))

    seen_rules = set(observed["detections_seen"])
    seen_tech = set(observed["techniques_seen"])

    rule_hits = exp_rules & seen_rules
    tech_hits = exp_tech & seen_tech
    missing_rules = sorted(exp_rules - seen_rules)
    missing_tech = sorted(exp_tech - seen_tech)

    sev_ok = (not exp_sev) or (
        observed["severity_seen"] is not None
        and severity_rank(observed["severity_seen"]) >= severity_rank(exp_sev)
    )
    incident_ok = (not exp_incident) or bool(observed["incidents_touched"])

    checks = []
    if exp_rules:
        checks.append(len(rule_hits) == len(exp_rules))
    if exp_tech:
        checks.append(len(tech_hits) == len(exp_tech))
    checks.append(sev_ok)
    checks.append(incident_ok)

    passed = all(checks)
    partial = any(checks) and not passed
    result = "PASS" if passed else ("PARTIAL" if partial else "FAIL")

    det_rate = (len(rule_hits) / len(exp_rules)) if exp_rules else (1.0 if seen_rules or not exp_rules else 0.0)
    attack_cov = (len(tech_hits) / len(exp_tech)) if exp_tech else 1.0

    fp_pool = _all_expected_rule_ids()
    false_positives = sorted(r for r in observed["all_detection_rules_in_window"] if r not in fp_pool)

    metrics = {
        "detection_success_rate": round(det_rate, 3),
        "attack_coverage": round(attack_cov, 3),
        "telemetry_coverage": 1.0 if observed["telemetry"] else 0.0,
        "severity_ok": sev_ok,
        "incident_ok": incident_ok,
        "missing_detections": missing_rules,
        "missing_techniques": missing_tech,
        "false_positive_rules": false_positives,
    }
    return {"result": result, "metrics": metrics}


async def _run_attack_script(script_scenario: str) -> Dict[str, Any]:
    if not os.path.exists(ATTACK_SCRIPT):
        return {"ran": False, "error": f"attack script not found at {ATTACK_SCRIPT}"}

    def _call():
        return subprocess.run(
            ["bash", ATTACK_SCRIPT, LOCAL_TARGET, script_scenario],  # target is fixed
            capture_output=True, text=True, timeout=240,
        )
    try:
        proc = await asyncio.to_thread(_call)
        return {"ran": True, "returncode": proc.returncode,
                "stdout_tail": proc.stdout[-2000:], "stderr_tail": proc.stderr[-1000:]}
    except subprocess.TimeoutExpired:
        return {"ran": True, "error": "attack script timed out"}
    except Exception as exc:  # noqa: BLE001
        return {"ran": False, "error": str(exc)}


async def run_scenario(
    db: AsyncSession,
    scenario_id: str,
    *,
    mode: str = "evaluate",
    triggered_by: Optional[str] = None,
    settle_seconds: Optional[int] = None,
) -> ScenarioRun:
    scenarios = load_scenarios()
    scenario = scenarios.get(scenario_id)
    if scenario is None:
        raise ValueError(f"unknown scenario '{scenario_id}'")

    mode = "execute" if mode == "execute" else "evaluate"
    run = ScenarioRun(
        scenario_id=scenario_id, mode=mode, status="running",
        expected={
            "expected_detections": scenario.get("expected_detections", []),
            "expected_techniques": scenario.get("expected_techniques", []),
            "expected_severity": scenario.get("expected_severity"),
            "expected_incident": scenario.get("expected_incident", False),
            "expected_telemetry": scenario.get("expected_telemetry", []),
        },
        triggered_by=triggered_by,
    )
    db.add(run)
    await db.flush()

    window_start = _now()
    exec_info: Dict[str, Any] = {}

    if mode == "execute":
        exec_info = await _run_attack_script(scenario.get("script_scenario", scenario_id))
        settle = settle_seconds if settle_seconds is not None else int(
            os.getenv("VALIDATION_SETTLE_SECONDS", "45")
        )
        await asyncio.sleep(settle)
        # force a detection cycle so we don't wait for the loop
        try:
            await detection_engine.run_cycle()
        except Exception:
            pass
    else:
        window_start = _now() - timedelta(minutes=int(os.getenv("VALIDATION_EVAL_WINDOW_MIN", "30")))

    observed = await _observe(db, window_start, LOCAL_TARGET)
    graded = _grade(scenario, observed)

    run.status = "complete"
    run.finished_at = _now()
    run.observed = {**observed, "execution": exec_info}
    run.result = graded["result"]
    run.detections_seen = observed["detections_seen"]
    run.techniques_seen = observed["techniques_seen"]
    run.severity_seen = observed["severity_seen"]
    run.metrics = graded["metrics"]

    await db.commit()
    return run


async def coverage_report(db: AsyncSession) -> Dict[str, Any]:
    scenarios = load_scenarios()
    runs = (await db.execute(
        select(ScenarioRun).order_by(ScenarioRun.started_at.desc()).limit(200)
    )).scalars().all()

    latest: Dict[str, ScenarioRun] = {}
    for r in runs:
        latest.setdefault(r.scenario_id, r)

    rows = []
    passes = 0
    all_expected_tech: set = set()
    covered_tech: set = set()
    for sid, sc in scenarios.items():
        run = latest.get(sid)
        all_expected_tech |= set(sc.get("expected_techniques", []))
        row = {
            "scenario_id": sid,
            "description": sc.get("description", "").strip(),
            "expected_detections": sc.get("expected_detections", []),
            "expected_techniques": sc.get("expected_techniques", []),
            "expected_severity": sc.get("expected_severity"),
            "last_result": run.result if run else None,
            "last_run_at": run.started_at.isoformat() if run else None,
            "actual_detections": run.detections_seen if run else None,
            "actual_techniques": run.techniques_seen if run else None,
            "actual_severity": run.severity_seen if run else None,
            "metrics": run.metrics if run else None,
        }
        rows.append(row)
        if run and run.result == "PASS":
            passes += 1
            covered_tech |= set(run.techniques_seen or [])

    scenario_count = len(scenarios) or 1
    return {
        "scenarios": rows,
        "detection_success_rate": round(passes / scenario_count, 3),
        "attack_coverage": round(len(covered_tech & all_expected_tech) / (len(all_expected_tech) or 1), 3),
        "scenarios_total": len(scenarios),
        "scenarios_passing": passes,
        "failed_scenarios": [r["scenario_id"] for r in rows if r["last_result"] in ("FAIL", "PARTIAL")],
        "untested_scenarios": [r["scenario_id"] for r in rows if r["last_result"] is None],
    }
