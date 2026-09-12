"""Report-type registry: type -> (builder, template, title, admin_only)."""
from __future__ import annotations

from typing import Callable, Dict, NamedTuple

from .providers import soc_reports
from .providers import compliance_report


class ReportDef(NamedTuple):
    builder: Callable
    template: str
    title: str
    admin_only: bool = False
    disclaimer: str = ""


REGISTRY: Dict[str, ReportDef] = {
    "executive_summary": ReportDef(soc_reports.executive_summary, "executive_summary.html", "SOC Executive Summary"),
    "geo_intel": ReportDef(soc_reports.geo_intel, "geo_intel.html", "Geographic Threat Intelligence Report"),
    "credentials": ReportDef(soc_reports.credentials_report, "credentials.html", "Captured Credentials Report"),
    "incident": ReportDef(soc_reports.incident_report, "incident.html", "Incident Report", admin_only=True),
    "forensic_dfir": ReportDef(soc_reports.forensic_dfir, "forensic_dfir.html", "DFIR Report", admin_only=True),
    "detection_validation": ReportDef(soc_reports.detection_validation_report, "detection_validation.html", "Detection Validation & Coverage Report"),
    "malware": ReportDef(soc_reports.malware_report, "malware.html", "Malware Analysis Report"),
    "soc2_readiness": ReportDef(compliance_report.soc2_readiness, "soc2_readiness.html",
                                "SOC 2 Readiness Self-Assessment", admin_only=True),
}


def get(report_type: str) -> ReportDef:
    if report_type not in REGISTRY:
        raise KeyError(report_type)
    return REGISTRY[report_type]
