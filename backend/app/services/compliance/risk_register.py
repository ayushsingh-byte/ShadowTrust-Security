"""
Automated risk register.

Risks are derived from live system state — open incidents, control gaps, failed
control tests, high-risk attacker sessions — not entered by hand. Likelihood and
impact are computed from real counts/severities on a documented 1–5 scale.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List

from sqlalchemy import func, select

from app.models.all_models import Incident, ScenarioRun, AttackerSession, Detection

_SEV_IMPACT = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def _risk(rid, title, source, category, likelihood, impact, treatment, status="Open") -> Dict[str, Any]:
    likelihood = max(1, min(5, int(likelihood)))
    impact = max(1, min(5, int(impact)))
    return {
        "id": rid, "title": title, "source": source, "category": category,
        "likelihood": likelihood, "impact": impact, "score": likelihood * impact,
        "rating": "Critical" if likelihood * impact >= 20 else "High" if likelihood * impact >= 12
        else "Medium" if likelihood * impact >= 6 else "Low",
        "treatment": treatment, "owner": "unassigned", "status": status,
    }


async def build_risks(db) -> List[Dict[str, Any]]:
    risks: List[Dict[str, Any]] = []

    # 1. open incidents by severity
    open_inc = (await db.execute(select(Incident).where(
        Incident.status.notin_(["RESOLVED", "FALSE_POSITIVE"])
    ).order_by(Incident.risk_score.desc()))).scalars().all()
    for i in open_inc:
        recency = 5 if (i.last_seen and i.last_seen > datetime.utcnow() - timedelta(days=2)) else 3
        risks.append(_risk(
            f"RISK-INC-{i.incident_key}", f"Unresolved incident: {(i.title or '')[:70]}",
            f"incidents / {i.incident_key}", "Security incident",
            likelihood=recency, impact=_SEV_IMPACT.get((i.severity or "").upper(), 3),
            treatment="Complete triage, contain, and close the incident per the response process.",
            status=i.status,
        ))

    # 2. failed / never-run control tests
    from app.services.detection_validation import coverage_report
    cov = await coverage_report(db)
    for s in cov.get("scenarios", []):
        res = s.get("last_result")
        if res in ("FAIL", "PARTIAL") or not s.get("last_run_at"):
            missing = ", ".join((s.get("metrics") or {}).get("missing_detections", []))
            risks.append(_risk(
                f"RISK-COV-{s['scenario_id']}",
                f"Detection coverage gap: {s['scenario_id']}" + (f" (missing {missing})" if missing else ""),
                "detection_validation", "Detection coverage",
                likelihood=4 if res == "FAIL" else 3,
                impact=_SEV_IMPACT.get((s.get("expected_severity") or "MEDIUM").upper(), 3),
                treatment="Tune or add the missing detection rule; re-run the scenario to verify.",
                status="Open" if res != "PASS" else "Monitoring",
            ))

    # 3. high-risk attacker sessions not linked to an incident
    hot = (await db.execute(select(AttackerSession).where(
        AttackerSession.risk_level.in_(["HIGH", "CRITICAL"])
    ).order_by(AttackerSession.last_seen.desc()).limit(10))).scalars().all()
    for s in hot:
        risks.append(_risk(
            f"RISK-SESS-{s.session_id[:12]}",
            f"High-risk attacker session from {s.attacker_ip} ({s.geoip_country or 'unknown'})",
            "attacker_sessions", "Active threat",
            likelihood=4, impact=4,
            treatment="Investigate the session, block the source, and confirm no lateral movement.",
        ))

    # 4. control gaps from the readiness assessment
    from .assessment import run_assessment
    a = await run_assessment(db)
    for g in a.get("gaps", []):
        risks.append(_risk(
            f"RISK-CTRL-{g['id']}", f"SOC 2 control gap: {g['id']} {g['title']}",
            "SOC 2 readiness assessment", f"Compliance — {g['category']}",
            likelihood=3, impact=3,
            treatment=g.get("note") or "Implement the control and collect operating evidence.",
        ))

    risks.sort(key=lambda r: r["score"], reverse=True)
    return risks
