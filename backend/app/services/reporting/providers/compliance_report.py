"""SOC 2 readiness report provider — assembles the live assessment + risk
register into the report context. Every figure comes from
services.compliance.* which reads the live database."""
from __future__ import annotations

from typing import Any, Dict

from .base import kpis, table, text, note


async def soc2_readiness(db, params, user) -> Dict[str, Any]:
    from app.services.compliance.assessment import run_assessment
    from app.services.compliance.risk_register import build_risks

    a = await run_assessment(db)
    risks = await build_risks(db)
    c = a["counts"]

    cat_rows = [[cat, d["met"], d["partial"], d["gap"], d["manual"], d["total"]]
                for cat, d in a["by_category"].items()]

    control_rows = []
    for x in a["controls"]:
        ev = x["evidence"][0]["value"] if x["evidence"] else (x["note"] or "—")
        control_rows.append([x["id"], x["title"], {"pill": "status", "text": x["status"]},
                             (str(ev))[:70], (x["collector"] or "manual")])

    gap_rows = [[g["id"], g["title"], g["category"], (g.get("note") or "")[:80]] for g in a["gaps"]]
    partial_rows = [[p["id"], p["title"], p["category"], (p.get("note") or "")[:80]] for p in a["partials"]]

    risk_rows = [[r["id"], r["title"][:60], r["category"], r["likelihood"], r["impact"],
                  r["score"], r["rating"], r["status"]] for r in risks[:40]]

    return {
        "title": "SOC 2 Readiness Self-Assessment",
        "subject": "ShadowTrust Defense Grid platform",
        "disclaimer": ("This is an internal readiness self-assessment generated from live system "
                       "evidence. It is NOT a SOC 2 examination or attestation — those can only be "
                       "performed by an independent licensed CPA firm. Use this to find and close "
                       "gaps before engaging an auditor."),
        "sources": ["users", "detections", "incidents", "scenario_runs", "evidence",
                    "admin_activity_log", "access_logs", "raw/normalized events", "psutil", "container config"],
        "sections": [
            text("Scope & framework", [
                a["framework"] + ".",
                a["assessment_type"] + ".",
                f"{c['total']} criteria assessed: {c['met']} met, {c['partial']} partial, "
                f"{c['gap']} gap, {c['manual']} manual-attestation.",
            ]),
            kpis(
                ("Readiness (automatable controls)", f"{a['readiness_pct']}%"),
                ("Met", c["met"]),
                ("Partial", c["partial"]),
                ("Gaps", c["gap"]),
                ("Manual attestation", c["manual"]),
                ("Open risks", len(risks)),
            ),
            note("Readiness % scores only the controls that can be evaluated from system data "
                 "(met = 1.0, partial = 0.5, gap = 0). Manual-attestation controls are excluded "
                 "from the score and listed separately — they require a human sign-off."),
            table("Coverage by trust services category",
                  ["Category", "Met", "Partial", "Gap", "Manual", "Total"], cat_rows),
            table("Control-by-control assessment",
                  ["Control", "Title", "Status", "Primary evidence", "Collector"], control_rows,
                  note="Status is derived live: 'met' only when the cited query proves the control operates."),
            table("Gaps — remediate before an audit",
                  ["Control", "Title", "Category", "Remediation"], gap_rows,
                  note="These controls returned no operating evidence."),
            table("Partially-satisfied controls",
                  ["Control", "Title", "Category", "To reach 'met'"], partial_rows),
            text("Risk register (top 40 by score)", [
                "Risks are derived from open incidents, coverage gaps, high-risk sessions and "
                "control gaps. Likelihood × Impact on a 1–5 scale.",
            ]),
            table("Risk register", ["ID", "Risk", "Category", "L", "I", "Score", "Rating", "Status"],
                  risk_rows, note="Source: services/compliance/risk_register.py — full export at /compliance/risk-register/export."),
            text("Manual attestation required", [
                "The following criteria cannot be evaluated from system data and require documented "
                "management attestation: " +
                ", ".join(x["id"] for x in a["controls"] if x["status"] == "manual") + ".",
            ]),
        ],
        "record_count": c["total"],
    }
