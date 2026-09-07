"""Run every evidence collector, map results onto the SOC 2 control catalogue,
and score readiness. Pure aggregation — no data is invented here."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from .framework import CATALOG
from .evidence import COLLECTORS

_SCORE = {"met": 1.0, "partial": 0.5, "gap": 0.0}


async def run_assessment(db) -> Dict[str, Any]:
    controls = []
    cache: Dict[str, Any] = {}

    for c in CATALOG:
        if c.evidence is None:
            entry = {"status": "manual", "evidence": [], "metrics": {},
                     "note": "No system-derived evidence; requires manual attestation."}
        else:
            fn = COLLECTORS.get(c.evidence)
            if fn is None:
                entry = {"status": "gap", "evidence": [], "metrics": {},
                         "note": f"collector '{c.evidence}' not implemented"}
            else:
                if c.evidence not in cache:
                    try:
                        cache[c.evidence] = await fn(db)
                    except Exception as e:  # noqa: BLE001
                        cache[c.evidence] = {"status": "gap", "evidence": [],
                                             "metrics": {}, "note": f"collector error: {e}"}
                entry = cache[c.evidence]

        controls.append({
            "id": c.id, "category": c.category, "title": c.title, "intent": c.intent,
            "collector": c.evidence,
            "status": entry["status"],
            "evidence": entry.get("evidence", []),
            "metrics": entry.get("metrics", {}),
            "note": entry.get("note"),
        })

    # scoring — automatable controls only
    auto = [x for x in controls if x["status"] != "manual"]
    scored = sum(_SCORE.get(x["status"], 0.0) for x in auto)
    readiness = round(100 * scored / len(auto), 1) if auto else 0.0

    by_cat: Dict[str, Dict[str, int]] = {}
    for x in controls:
        d = by_cat.setdefault(x["category"], {"met": 0, "partial": 0, "gap": 0, "manual": 0, "total": 0})
        d[x["status"]] += 1
        d["total"] += 1

    gaps = [{"id": x["id"], "title": x["title"], "category": x["category"],
             "note": x["note"], "evidence": x["evidence"]}
            for x in controls if x["status"] == "gap"]
    partials = [{"id": x["id"], "title": x["title"], "category": x["category"], "note": x["note"]}
                for x in controls if x["status"] == "partial"]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "framework": "AICPA SOC 2 — Trust Services Criteria (2017, with 2022 revisions)",
        "assessment_type": "Internal readiness self-assessment — NOT an independent CPA attestation",
        "readiness_pct": readiness,
        "counts": {
            "met": sum(1 for x in controls if x["status"] == "met"),
            "partial": sum(1 for x in controls if x["status"] == "partial"),
            "gap": sum(1 for x in controls if x["status"] == "gap"),
            "manual": sum(1 for x in controls if x["status"] == "manual"),
            "total": len(controls),
        },
        "by_category": by_cat,
        "controls": controls,
        "gaps": gaps,
        "partials": partials,
    }
