"""SOC 2 readiness report provider — assembles the live assessment + risk
register into the report context. Every figure comes from
services.compliance.* which reads the live database."""
from __future__ import annotations

from collections import Counter
from typing import Any, Dict

from .base import clip, kpi, parse_window, pct, status


async def soc2_readiness(db, params, user) -> Dict[str, Any]:
    from app.services.compliance.assessment import run_assessment
    from app.services.compliance.risk_register import build_risks

    start, end = parse_window(params)
    a = await run_assessment(db)
    risks = await build_risks(db)
    c = a["counts"]
    controls = a["controls"]

    cat_rows = [[cat, d["met"], d["partial"], d["gap"], d["manual"], d["total"],
                 f"{pct(d['met'] + 0.5 * d['partial'], d['met'] + d['partial'] + d['gap']):.0f}%"]
                for cat, d in a["by_category"].items()]

    control_rows = []
    for x in controls:
        ev = x["evidence"][0]["value"] if x["evidence"] else (x["note"] or "—")
        metric = ""
        if x.get("metrics"):
            metric = clip("; ".join(f"{k}={v}" for k, v in x["metrics"].items()), 44)
        control_rows.append([
            x["id"], x["category"], clip(x["title"], 46), status(x["status"]),
            clip(str(ev), 60), x["collector"] or "manual", metric or "—",
        ])

    gap_rows = [[g["id"], clip(g["title"], 46), g["category"], clip(g.get("note") or "", 70)]
                for g in a["gaps"]]
    partial_rows = [[p["id"], clip(p["title"], 46), p["category"], clip(p.get("note") or "", 70)]
                    for p in a["partials"]]
    manual_rows = [[x["id"], x["category"], clip(x["title"], 50), clip(x.get("intent") or "", 70)]
                   for x in controls if x["status"] == "manual"]

    risk_rows = [[r["id"], clip(r["title"], 54), r["category"], r["likelihood"], r["impact"],
                  r["score"], r["rating"], r["status"]] for r in risks[:45]]
    rating_counter = Counter(r["rating"] for r in risks)
    rating_bars = [{"label": k, "value": v, "pct": round(100 * v / (len(risks) or 1), 1)}
                   for k, v in sorted(rating_counter.items(), key=lambda kv: -kv[1])]

    # collector coverage summary
    coll = Counter(x["collector"] or "manual" for x in controls)
    coll_met = Counter(x["collector"] or "manual" for x in controls if x["status"] == "met")
    collector_rows = [[name, n, coll_met.get(name, 0),
                       f"{pct(coll_met.get(name, 0), n):.0f}%"]
                      for name, n in coll.most_common()]

    return {
        "title": "SOC 2 Readiness Self-Assessment",
        "subject": "ShadowTrust Defense Grid platform",
        "window_start": start, "window_end": end,
        "disclaimer": ("This is an internal readiness self-assessment generated from live system "
                       "evidence. It is NOT a SOC 2 examination or attestation — those can only be "
                       "performed by an independent licensed CPA firm. Use this to find and close "
                       "gaps before engaging an auditor."),
        "sources": ["users", "detections", "incidents", "scenario_runs", "evidence",
                    "admin_activity_log", "access_logs", "raw/normalized events", "psutil", "container config"],
        "record_count": c["total"],
        "framework": a["framework"],
        "assessment_type": a["assessment_type"],
        "readiness_pct": a["readiness_pct"],
        "kpi_band": [
            kpi("Readiness", f"{a['readiness_pct']}%", "automatable controls"),
            kpi("Met", c["met"]),
            kpi("Partial", c["partial"]),
            kpi("Gaps", c["gap"]),
            kpi("Manual attestation", c["manual"]),
            kpi("Open risks", len(risks)),
        ],
        "counts": c,
        "cat_rows": cat_rows,
        "control_rows": control_rows,
        "gap_rows": gap_rows,
        "partial_rows": partial_rows,
        "manual_rows": manual_rows,
        "risk_rows": risk_rows,
        "rating_bars": rating_bars,
        "collector_rows": collector_rows,
    }
