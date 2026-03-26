"""
AVE Compliance Dashboard — Core compliance engine.

Provides real-time compliance posture assessment, regulatory mapping,
defence coverage analysis, and audit-ready reporting against the
AVE vulnerability taxonomy.
"""

from __future__ import annotations

import json
import statistics
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="NAIL AVE Compliance Dashboard",
    description="Real-time compliance posture against the AVE taxonomy and regulatory frameworks.",
    version="1.0.0",
    docs_url="/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

AVE_CATEGORIES = [
    "prompt_injection", "tool_abuse", "memory_poisoning", "identity_spoofing",
    "goal_hijacking", "knowledge_poisoning", "resource_exhaustion",
    "output_manipulation", "privilege_escalation", "trust_exploitation",
    "context_overflow", "model_denial_of_service", "data_exfiltration",
    "supply_chain", "model_poisoning", "multi_agent_coordination",
    "reward_hacking", "emergent_behavior",
]


class ControlStatus(str, Enum):
    COMPLIANT = "compliant"
    PARTIAL = "partial"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"


class ReportFormat(str, Enum):
    JSON = "json"
    PDF = "pdf"
    HTML = "html"


# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------


class ComplianceControl(BaseModel):
    control_id: str
    framework: str
    title: str
    description: str
    ave_categories: list[str]
    status: ControlStatus = ControlStatus.NON_COMPLIANT
    evidence: list[str] = Field(default_factory=list)
    last_assessed: str = ""
    weight: float = 1.0


class ComplianceFramework(BaseModel):
    framework_id: str
    name: str
    version: str
    controls: list[ComplianceControl]
    total_score: float = 0.0
    weight: float = 1.0


class ComplianceAssessment(BaseModel):
    assessment_id: str = Field(default_factory=lambda: f"assess-{uuid.uuid4().hex[:10]}")
    org_id: str = "default"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    overall_score: float = 0.0
    framework_scores: dict[str, float] = Field(default_factory=dict)
    category_coverage: dict[str, float] = Field(default_factory=dict)
    gaps: list[dict[str, Any]] = Field(default_factory=list)


class AuditEntry(BaseModel):
    entry_id: str = Field(default_factory=lambda: f"audit-{uuid.uuid4().hex[:10]}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    action: str
    actor: str = "system"
    details: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Regulatory mapping data
# ---------------------------------------------------------------------------


def _build_frameworks() -> dict[str, ComplianceFramework]:
    """Build compliance framework control mappings."""

    nist_controls = [
        ComplianceControl(
            control_id="NIST-MAP-1.1",
            framework="nist_ai_rmf",
            title="Identify AI System Context",
            description="Map AI system capabilities, limitations, and risk context.",
            ave_categories=["prompt_injection", "goal_hijacking", "trust_exploitation"],
            status=ControlStatus.COMPLIANT,
            weight=1.2,
        ),
        ComplianceControl(
            control_id="NIST-MAP-1.5",
            framework="nist_ai_rmf",
            title="Risk Identification for Third-Party AI",
            description="Assess risks from third-party AI components and models.",
            ave_categories=["supply_chain", "model_poisoning"],
            status=ControlStatus.PARTIAL,
            weight=1.0,
        ),
        ComplianceControl(
            control_id="NIST-GOV-1.1",
            framework="nist_ai_rmf",
            title="AI Risk Management Policies",
            description="Establish organisational policies for AI risk management.",
            ave_categories=AVE_CATEGORIES[:6],
            status=ControlStatus.COMPLIANT,
            weight=1.5,
        ),
        ComplianceControl(
            control_id="NIST-MEA-2.6",
            framework="nist_ai_rmf",
            title="Monitor AI System Behaviour",
            description="Continuously monitor deployed AI systems for anomalous behaviour.",
            ave_categories=["emergent_behavior", "reward_hacking", "goal_hijacking"],
            status=ControlStatus.PARTIAL,
            weight=1.3,
        ),
        ComplianceControl(
            control_id="NIST-MAN-4.1",
            framework="nist_ai_rmf",
            title="Incident Response for AI Systems",
            description="Establish incident response procedures specific to AI failures.",
            ave_categories=["resource_exhaustion", "model_denial_of_service", "data_exfiltration"],
            status=ControlStatus.NON_COMPLIANT,
            weight=1.4,
        ),
    ]

    eu_ai_controls = [
        ComplianceControl(
            control_id="EU-AI-ART-9",
            framework="eu_ai_act",
            title="Risk Management System",
            description="Implement continuous risk management system for high-risk AI.",
            ave_categories=AVE_CATEGORIES[:8],
            status=ControlStatus.COMPLIANT,
            weight=1.5,
        ),
        ComplianceControl(
            control_id="EU-AI-ART-10",
            framework="eu_ai_act",
            title="Data Governance",
            description="Ensure training data quality, relevance, and representativeness.",
            ave_categories=["model_poisoning", "knowledge_poisoning", "data_exfiltration"],
            status=ControlStatus.PARTIAL,
            weight=1.2,
        ),
        ComplianceControl(
            control_id="EU-AI-ART-13",
            framework="eu_ai_act",
            title="Transparency",
            description="Provide clear information on AI system capabilities and limitations.",
            ave_categories=["output_manipulation", "trust_exploitation", "identity_spoofing"],
            status=ControlStatus.COMPLIANT,
            weight=1.0,
        ),
        ComplianceControl(
            control_id="EU-AI-ART-14",
            framework="eu_ai_act",
            title="Human Oversight",
            description="Enable effective human oversight of AI system operation.",
            ave_categories=["goal_hijacking", "emergent_behavior", "multi_agent_coordination"],
            status=ControlStatus.PARTIAL,
            weight=1.3,
        ),
        ComplianceControl(
            control_id="EU-AI-ART-15",
            framework="eu_ai_act",
            title="Accuracy, Robustness, Cybersecurity",
            description="Ensure appropriate levels of accuracy, robustness, and cybersecurity.",
            ave_categories=["prompt_injection", "tool_abuse", "memory_poisoning", "privilege_escalation"],
            status=ControlStatus.NON_COMPLIANT,
            weight=1.4,
        ),
    ]

    iso_controls = [
        ComplianceControl(
            control_id="ISO-42001-6.1",
            framework="iso_42001",
            title="Actions to Address Risks",
            description="Determine and plan actions to address AI-specific risks.",
            ave_categories=AVE_CATEGORIES[:10],
            status=ControlStatus.PARTIAL,
            weight=1.3,
        ),
        ComplianceControl(
            control_id="ISO-42001-8.4",
            framework="iso_42001",
            title="AI System Impact Assessment",
            description="Conduct impact assessments for AI systems.",
            ave_categories=["emergent_behavior", "multi_agent_coordination", "goal_hijacking"],
            status=ControlStatus.COMPLIANT,
            weight=1.1,
        ),
        ComplianceControl(
            control_id="ISO-42001-A.5",
            framework="iso_42001",
            title="Data Management for AI",
            description="Manage data used in AI systems throughout its lifecycle.",
            ave_categories=["data_exfiltration", "model_poisoning", "knowledge_poisoning"],
            status=ControlStatus.PARTIAL,
            weight=1.0,
        ),
    ]

    owasp_controls = [
        ComplianceControl(
            control_id="OWASP-LLM-01",
            framework="owasp_llm_top10",
            title="Prompt Injection",
            description="Prevent direct and indirect prompt injection attacks.",
            ave_categories=["prompt_injection"],
            status=ControlStatus.COMPLIANT,
            weight=1.5,
        ),
        ComplianceControl(
            control_id="OWASP-LLM-02",
            framework="owasp_llm_top10",
            title="Insecure Output Handling",
            description="Validate and sanitise all LLM outputs.",
            ave_categories=["output_manipulation"],
            status=ControlStatus.PARTIAL,
            weight=1.2,
        ),
        ComplianceControl(
            control_id="OWASP-LLM-03",
            framework="owasp_llm_top10",
            title="Training Data Poisoning",
            description="Ensure integrity of training data pipeline.",
            ave_categories=["model_poisoning", "knowledge_poisoning"],
            status=ControlStatus.NON_COMPLIANT,
            weight=1.3,
        ),
        ComplianceControl(
            control_id="OWASP-LLM-05",
            framework="owasp_llm_top10",
            title="Supply Chain Vulnerabilities",
            description="Secure the AI/ML supply chain.",
            ave_categories=["supply_chain"],
            status=ControlStatus.PARTIAL,
            weight=1.1,
        ),
        ComplianceControl(
            control_id="OWASP-LLM-06",
            framework="owasp_llm_top10",
            title="Sensitive Information Disclosure",
            description="Prevent leakage of sensitive data through LLM interactions.",
            ave_categories=["data_exfiltration", "context_overflow"],
            status=ControlStatus.PARTIAL,
            weight=1.2,
        ),
    ]

    frameworks = {
        "nist_ai_rmf": ComplianceFramework(
            framework_id="nist_ai_rmf",
            name="NIST AI Risk Management Framework",
            version="1.0",
            controls=nist_controls,
            weight=1.2,
        ),
        "eu_ai_act": ComplianceFramework(
            framework_id="eu_ai_act",
            name="EU Artificial Intelligence Act",
            version="2024",
            controls=eu_ai_controls,
            weight=1.3,
        ),
        "iso_42001": ComplianceFramework(
            framework_id="iso_42001",
            name="ISO/IEC 42001 AI Management System",
            version="2023",
            controls=iso_controls,
            weight=1.0,
        ),
        "owasp_llm_top10": ComplianceFramework(
            framework_id="owasp_llm_top10",
            name="OWASP LLM Top 10",
            version="2025",
            controls=owasp_controls,
            weight=1.1,
        ),
    }

    # Compute framework scores
    for fw in frameworks.values():
        _score_framework(fw)

    return frameworks


def _score_framework(fw: ComplianceFramework) -> None:
    """Compute compliance score for a framework."""
    status_scores = {
        ControlStatus.COMPLIANT: 1.0,
        ControlStatus.PARTIAL: 0.5,
        ControlStatus.NON_COMPLIANT: 0.0,
        ControlStatus.NOT_APPLICABLE: None,
    }
    weighted_sum = 0.0
    weight_total = 0.0
    for ctrl in fw.controls:
        score = status_scores[ctrl.status]
        if score is not None:
            weighted_sum += score * ctrl.weight
            weight_total += ctrl.weight
    fw.total_score = round(weighted_sum / weight_total * 100, 1) if weight_total > 0 else 0


# ---------------------------------------------------------------------------
# In-memory stores
# ---------------------------------------------------------------------------

frameworks = _build_frameworks()
assessments: list[ComplianceAssessment] = []
audit_log: list[AuditEntry] = []

# Defence coverage simulation (production → query DOP)
defence_coverage: dict[str, float] = {
    "prompt_injection": 0.85,
    "tool_abuse": 0.72,
    "memory_poisoning": 0.60,
    "identity_spoofing": 0.55,
    "goal_hijacking": 0.68,
    "knowledge_poisoning": 0.50,
    "resource_exhaustion": 0.78,
    "output_manipulation": 0.65,
    "privilege_escalation": 0.70,
    "trust_exploitation": 0.58,
    "context_overflow": 0.62,
    "model_denial_of_service": 0.75,
    "data_exfiltration": 0.80,
    "supply_chain": 0.45,
    "model_poisoning": 0.40,
    "multi_agent_coordination": 0.35,
    "reward_hacking": 0.30,
    "emergent_behavior": 0.25,
}


# ---------------------------------------------------------------------------
# Compliance engine
# ---------------------------------------------------------------------------


def compute_overall_posture() -> ComplianceAssessment:
    """Run full compliance assessment."""
    framework_scores: dict[str, float] = {}
    weighted_sum = 0.0
    weight_total = 0.0

    for fid, fw in frameworks.items():
        _score_framework(fw)
        framework_scores[fid] = fw.total_score
        weighted_sum += fw.total_score * fw.weight
        weight_total += fw.weight

    overall = round(weighted_sum / weight_total, 1) if weight_total > 0 else 0

    # Identify gaps
    gaps = []
    for cat in AVE_CATEGORIES:
        coverage = defence_coverage.get(cat, 0)
        if coverage < 0.6:
            severity = "critical" if coverage < 0.3 else "high" if coverage < 0.5 else "medium"
            # Find affected controls
            affected = []
            for fw in frameworks.values():
                for ctrl in fw.controls:
                    if cat in ctrl.ave_categories and ctrl.status != ControlStatus.COMPLIANT:
                        affected.append(f"{ctrl.control_id}: {ctrl.title}")

            gaps.append({
                "category": cat,
                "defence_coverage": round(coverage, 2),
                "gap_severity": severity,
                "affected_controls": affected[:5],
                "remediation": [
                    f"Deploy {cat.replace('_', ' ')} detection guardrails",
                    f"Implement monitoring for {cat.replace('_', ' ')} patterns",
                    "Update security policies and incident response procedures",
                ],
            })

    gaps.sort(key=lambda g: g["defence_coverage"])

    assessment = ComplianceAssessment(
        overall_score=overall,
        framework_scores=framework_scores,
        category_coverage=dict(defence_coverage),
        gaps=gaps,
    )

    assessments.append(assessment)
    audit_log.append(AuditEntry(
        action="compliance_assessment",
        details={"assessment_id": assessment.assessment_id, "score": overall},
    ))

    return assessment


# ---------------------------------------------------------------------------
# API endpoints — Compliance posture
# ---------------------------------------------------------------------------


@app.get("/v1/compliance/posture")
async def compliance_posture() -> dict[str, Any]:
    """Get current overall compliance posture."""
    assessment = compute_overall_posture()
    return {
        "assessment": assessment.model_dump(),
        "summary": {
            "overall_score": assessment.overall_score,
            "frameworks_assessed": len(frameworks),
            "categories_covered": sum(
                1 for v in defence_coverage.values() if v >= 0.6
            ),
            "total_categories": len(AVE_CATEGORIES),
            "critical_gaps": sum(1 for g in assessment.gaps if g["gap_severity"] == "critical"),
        },
    }


@app.get("/v1/compliance/posture/{org_id}")
async def org_compliance_posture(org_id: str) -> dict[str, Any]:
    """Get compliance posture for a specific organisation."""
    assessment = compute_overall_posture()
    assessment.org_id = org_id
    return {
        "org_id": org_id,
        "assessment": assessment.model_dump(),
    }


# ---------------------------------------------------------------------------
# API endpoints — Framework mappings
# ---------------------------------------------------------------------------


@app.get("/v1/compliance/frameworks")
async def list_frameworks() -> dict[str, Any]:
    """List all supported compliance frameworks."""
    return {
        "frameworks": [
            {
                "framework_id": fw.framework_id,
                "name": fw.name,
                "version": fw.version,
                "control_count": len(fw.controls),
                "score": fw.total_score,
            }
            for fw in frameworks.values()
        ],
    }


@app.get("/v1/compliance/framework/{framework_id}/mapping")
async def framework_mapping(framework_id: str) -> dict[str, Any]:
    """Get AVE → framework control mapping."""
    fw = frameworks.get(framework_id)
    if not fw:
        raise HTTPException(status_code=404, detail=f"Framework {framework_id} not found")

    mapping: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ctrl in fw.controls:
        for cat in ctrl.ave_categories:
            mapping[cat].append({
                "control_id": ctrl.control_id,
                "title": ctrl.title,
                "status": ctrl.status.value,
                "weight": ctrl.weight,
            })

    return {
        "framework": fw.framework_id,
        "name": fw.name,
        "total_score": fw.total_score,
        "category_mappings": dict(mapping),
    }


# ---------------------------------------------------------------------------
# API endpoints — Gap analysis
# ---------------------------------------------------------------------------


@app.get("/v1/compliance/gaps")
async def compliance_gaps() -> dict[str, Any]:
    """Get all compliance gaps."""
    assessment = compute_overall_posture()
    return {
        "total_gaps": len(assessment.gaps),
        "gaps": assessment.gaps,
        "overall_coverage": round(
            statistics.mean(defence_coverage.values()), 2,
        ),
    }


@app.get("/v1/compliance/gaps/{category}")
async def category_gaps(category: str) -> dict[str, Any]:
    """Get gaps for a specific AVE category."""
    coverage = defence_coverage.get(category, 0)

    affected_controls = []
    for fw in frameworks.values():
        for ctrl in fw.controls:
            if category in ctrl.ave_categories:
                affected_controls.append({
                    "framework": fw.name,
                    "control_id": ctrl.control_id,
                    "title": ctrl.title,
                    "status": ctrl.status.value,
                    "description": ctrl.description,
                })

    return {
        "category": category,
        "defence_coverage": round(coverage, 2),
        "gap_severity": (
            "critical" if coverage < 0.3 else
            "high" if coverage < 0.5 else
            "medium" if coverage < 0.7 else
            "low"
        ),
        "affected_controls": affected_controls,
        "remediation_steps": [
            f"Deploy detection rules for {category.replace('_', ' ')}",
            f"Implement automated response for {category.replace('_', ' ')} incidents",
            "Review and update security policies",
            "Conduct tabletop exercise for this attack category",
            "Engage third-party assessment if coverage remains below 60%",
        ],
    }


# ---------------------------------------------------------------------------
# API endpoints — Assessment & reporting
# ---------------------------------------------------------------------------


@app.post("/v1/compliance/assess")
async def trigger_assessment(org_id: str = Query("default")) -> dict[str, Any]:
    """Trigger a new compliance assessment."""
    assessment = compute_overall_posture()
    assessment.org_id = org_id
    return {
        "assessment_id": assessment.assessment_id,
        "org_id": org_id,
        "overall_score": assessment.overall_score,
        "timestamp": assessment.timestamp,
    }


@app.get("/v1/compliance/reports")
async def list_reports() -> dict[str, Any]:
    """List previously generated assessments/reports."""
    return {
        "report_count": len(assessments),
        "reports": [
            {
                "assessment_id": a.assessment_id,
                "org_id": a.org_id,
                "overall_score": a.overall_score,
                "timestamp": a.timestamp,
            }
            for a in assessments[-20:]
        ],
    }


@app.post("/v1/compliance/reports/generate")
async def generate_report(
    org_id: str = Query("default"),
    format: ReportFormat = Query(ReportFormat.JSON),
) -> dict[str, Any]:
    """Generate a compliance report."""
    assessment = compute_overall_posture()
    assessment.org_id = org_id

    report = {
        "report_id": f"rpt-{uuid.uuid4().hex[:10]}",
        "format": format.value,
        "org_id": org_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "assessment": assessment.model_dump(),
        "framework_details": {
            fid: {
                "name": fw.name,
                "score": fw.total_score,
                "controls": [
                    {
                        "id": c.control_id,
                        "title": c.title,
                        "status": c.status.value,
                    }
                    for c in fw.controls
                ],
            }
            for fid, fw in frameworks.items()
        },
        "executive_summary": {
            "overall_compliance": f"{assessment.overall_score}%",
            "critical_gaps": sum(1 for g in assessment.gaps if g["gap_severity"] == "critical"),
            "high_gaps": sum(1 for g in assessment.gaps if g["gap_severity"] == "high"),
            "recommendation": (
                "Immediate action required on supply chain, model poisoning, "
                "and multi-agent coordination defences."
                if assessment.overall_score < 70 else
                "Good compliance posture. Focus on closing remaining gaps in "
                "emerging categories."
            ),
        },
    }

    audit_log.append(AuditEntry(
        action="report_generated",
        details={"report_id": report["report_id"], "format": format.value},
    ))

    return report


# ---------------------------------------------------------------------------
# API endpoints — Audit log
# ---------------------------------------------------------------------------


@app.get("/v1/compliance/audit-log")
async def get_audit_log(
    limit: int = Query(50, ge=1, le=500),
) -> dict[str, Any]:
    """Get compliance audit trail."""
    return {
        "total_entries": len(audit_log),
        "entries": [e.model_dump() for e in audit_log[-limit:]],
    }


# ---------------------------------------------------------------------------
# API endpoints — Trends
# ---------------------------------------------------------------------------


@app.get("/v1/compliance/trends")
async def compliance_trends() -> dict[str, Any]:
    """Historical compliance score trends."""
    # Generate trend data from assessment history
    if len(assessments) < 2:
        # Simulate historical trend
        now = datetime.now(timezone.utc)
        trend_data = []
        for i in range(12):
            date = now - timedelta(days=30 * (11 - i))
            score = 45 + i * 3.5 + (hash(str(i)) % 5)
            trend_data.append({
                "date": date.strftime("%Y-%m-%d"),
                "overall_score": round(min(100, score), 1),
            })
    else:
        trend_data = [
            {
                "date": a.timestamp[:10],
                "overall_score": a.overall_score,
            }
            for a in assessments[-12:]
        ]

    return {
        "data_points": len(trend_data),
        "trend": trend_data,
        "direction": (
            "improving" if len(trend_data) >= 2
            and trend_data[-1]["overall_score"] > trend_data[0]["overall_score"]
            else "stable"
        ),
    }


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "service": "compliance-dashboard"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8601)
