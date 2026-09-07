"""
SOC 2 Trust Services Criteria — control catalogue.

The descriptions below are ShadowTrust's own plain-language summary of each
criterion's intent (the official AICPA TSC text is copyrighted and is not
reproduced). `evidence` names the collector in evidence.py; ``None`` means the
control can only be satisfied by manual attestation and is reported as such.
"""
from __future__ import annotations

from typing import List, NamedTuple, Optional


class Control(NamedTuple):
    id: str
    category: str          # "Common Criteria (Security)" | "Availability" | ...
    title: str
    intent: str
    evidence: Optional[str]  # key in evidence.COLLECTORS, or None => manual


CATALOG: List[Control] = [
    # ── CC1 Control Environment ───────────────────────────────────────────────
    Control("CC1.1", "Common Criteria", "Integrity & ethical values",
            "The organisation demonstrates a commitment to integrity and ethical values through policy and tone.", None),
    Control("CC1.2", "Common Criteria", "Board oversight",
            "Those charged with governance oversee the design and operation of internal control.", None),
    Control("CC1.3", "Common Criteria", "Structure, authority & responsibility",
            "Management establishes reporting lines and appropriate authorities to meet objectives.", "org_roles"),
    Control("CC1.4", "Common Criteria", "Commitment to competence",
            "The organisation attracts, develops and retains competent individuals.", None),
    Control("CC1.5", "Common Criteria", "Accountability",
            "Individuals are held accountable for their internal-control responsibilities.", "admin_activity"),
    # ── CC2 Communication & Information ───────────────────────────────────────
    Control("CC2.1", "Common Criteria", "Quality information",
            "Relevant, quality information is generated and used to support internal control.", "monitoring_pipeline"),
    Control("CC2.2", "Common Criteria", "Internal communication",
            "Security objectives and responsibilities are communicated internally.", None),
    Control("CC2.3", "Common Criteria", "External communication",
            "Matters affecting internal control are communicated to external parties.", None),
    # ── CC3 Risk Assessment ──────────────────────────────────────────────────
    Control("CC3.1", "Common Criteria", "Objectives specified",
            "Objectives are specified with sufficient clarity to identify and assess risk.", None),
    Control("CC3.2", "Common Criteria", "Risk identification & analysis",
            "Risks to objectives are identified and analysed across the entity.", "risk_process"),
    Control("CC3.3", "Common Criteria", "Fraud risk",
            "The potential for fraud is considered in assessing risk.", None),
    Control("CC3.4", "Common Criteria", "Change risk",
            "Changes that could significantly affect internal control are identified and assessed.", "change_mgmt"),
    # ── CC4 Monitoring ───────────────────────────────────────────────────────
    Control("CC4.1", "Common Criteria", "Ongoing & separate evaluations",
            "Evaluations are performed to ascertain whether controls are present and functioning.", "control_testing"),
    Control("CC4.2", "Common Criteria", "Deficiencies evaluated & communicated",
            "Control deficiencies are evaluated and communicated to those responsible for corrective action.", "control_testing"),
    # ── CC5 Control Activities ───────────────────────────────────────────────
    Control("CC5.1", "Common Criteria", "Control selection & development",
            "Control activities are selected and developed to mitigate risk to acceptable levels.", "detection_controls"),
    Control("CC5.2", "Common Criteria", "Technology general controls",
            "General controls over technology are selected and developed.", "detection_controls"),
    Control("CC5.3", "Common Criteria", "Policies & procedures",
            "Control activities are deployed through policies that establish expectations and procedures.", None),
    # ── CC6 Logical & Physical Access ────────────────────────────────────────
    Control("CC6.1", "Common Criteria", "Logical access provisioning",
            "Logical access to data and systems is restricted through identification, authentication and authorisation.", "logical_access"),
    Control("CC6.2", "Common Criteria", "Registration & authorisation of users",
            "New internal and external users are registered and authorised before access is granted; access is removed when no longer required.", "user_lifecycle"),
    Control("CC6.3", "Common Criteria", "Role-based access & least privilege",
            "Access is granted based on role and least privilege and is reviewed periodically.", "rbac"),
    Control("CC6.6", "Common Criteria", "Boundary protection",
            "Security measures protect against threats from outside the system boundary.", "boundary"),
    Control("CC6.7", "Common Criteria", "Restricted transmission & movement of data",
            "Data in transit and the movement of credentials/information is restricted to authorised users and protected.", "data_transmission"),
    Control("CC6.8", "Common Criteria", "Malicious software prevention",
            "Controls prevent or detect the introduction of unauthorised or malicious software.", "malware_controls"),
    # ── CC7 System Operations ────────────────────────────────────────────────
    Control("CC7.1", "Common Criteria", "Vulnerability detection",
            "Configuration and vulnerability management identifies deviations from the hardened baseline.", "vuln_detection"),
    Control("CC7.2", "Common Criteria", "Security monitoring",
            "The system is monitored to detect anomalies and potential security events.", "monitoring_pipeline"),
    Control("CC7.3", "Common Criteria", "Security incident evaluation",
            "Detected events are evaluated to determine whether they constitute a security incident.", "incident_eval"),
    Control("CC7.4", "Common Criteria", "Incident response",
            "Identified incidents are contained, remediated and communicated through a defined response process.", "incident_response"),
    Control("CC7.5", "Common Criteria", "Recovery from incidents",
            "The organisation restores affected systems and preserves evidence following an incident.", "recovery"),
    # ── CC8 Change Management ────────────────────────────────────────────────
    Control("CC8.1", "Common Criteria", "Change management",
            "Changes to infrastructure, data and software are authorised, designed, tested and approved before implementation.", "change_mgmt"),
    # ── CC9 Risk Mitigation ─────────────────────────────────────────────────
    Control("CC9.1", "Common Criteria", "Risk mitigation activities",
            "The organisation identifies, selects and develops risk-mitigation activities for disruptions.", "risk_process"),
    Control("CC9.2", "Common Criteria", "Vendor & business-partner risk",
            "The organisation assesses and manages risks arising from vendors and business partners.", None),
    # ── Availability ────────────────────────────────────────────────────────
    Control("A1.1", "Availability", "Capacity management",
            "Current processing capacity is monitored against demand so that capacity can be managed.", "capacity"),
    Control("A1.2", "Availability", "Environmental & backup protection",
            "Backup processes and recovery infrastructure protect against availability failures.", "availability"),
    Control("A1.3", "Availability", "Recovery testing",
            "Recovery-plan procedures are tested to support system availability commitments.", None),
    # ── Confidentiality ────────────────────────────────────────────────────
    Control("C1.1", "Confidentiality", "Confidential information identified",
            "Information requiring confidential treatment is identified and maintained.", "data_classification"),
    Control("C1.2", "Confidentiality", "Confidential information disposed",
            "Confidential information is retained and disposed of in line with policy.", "data_retention"),
    # ── Processing Integrity ──────────────────────────────────────────────────
    Control("PI1.1", "Processing Integrity", "Processing definitions",
            "The organisation obtains/creates accurate definitions of processing to meet objectives.", None),
    Control("PI1.2", "Processing Integrity", "Inputs complete & accurate",
            "System inputs are processed completely, accurately and timely.", "pipeline_integrity"),
    Control("PI1.3", "Processing Integrity", "Processing complete & accurate",
            "Processing (normalisation, enrichment, correlation) is complete, accurate and authorised.", "pipeline_integrity"),
    Control("PI1.4", "Processing Integrity", "Outputs complete & accurate",
            "Outputs (detections, incidents, reports) are complete, accurate and distributed to authorised parties.", "output_integrity"),
    Control("PI1.5", "Processing Integrity", "Storage integrity",
            "Stored items are maintained completely, accurately and in a protected manner.", "storage_integrity"),
    # ── Privacy (P1–P8) ─────────────────────────────────────────────────────
    Control("P1.1", "Privacy", "Privacy notice", "Notice about privacy practices is provided to data subjects.", None),
    Control("P2.1", "Privacy", "Choice & consent", "Choices regarding personal information are communicated and consent obtained.", None),
    Control("P3.1", "Privacy", "Collection", "Personal information is collected consistently with objectives.", "pii_collection"),
    Control("P4.1", "Privacy", "Use, retention & disposal", "Personal information use, retention and disposal follow policy.", "data_retention"),
    Control("P5.1", "Privacy", "Access", "Data subjects can access and correct their personal information.", None),
    Control("P6.1", "Privacy", "Disclosure to third parties", "Personal information disclosure is limited to stated purposes.", None),
    Control("P7.1", "Privacy", "Quality", "Personal information is accurate and complete for its purposes.", None),
    Control("P8.1", "Privacy", "Monitoring & enforcement", "Privacy complaints and compliance are monitored and enforced.", None),
]


def by_category() -> dict:
    out: dict = {}
    for c in CATALOG:
        out.setdefault(c.category, []).append(c)
    return out
