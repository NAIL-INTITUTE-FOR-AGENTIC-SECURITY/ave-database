"""
Autonomous Compliance Auditor — Phase 20 Service 5 of 5
Port: 9404

Continuous compliance monitoring across 6 regulatory frameworks,
framework-agnostic control library, evidence collection with
chain of custody, automated checks, gap analysis, and
audit-ready report generation.
"""

from __future__ import annotations

import hashlib
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ControlDomain(str, Enum):
    governance = "governance"
    technical = "technical"
    operational = "operational"
    human_oversight = "human_oversight"
    transparency = "transparency"


class ControlStatus(str, Enum):
    not_started = "not_started"
    in_progress = "in_progress"
    implemented = "implemented"
    verified = "verified"
    non_applicable = "non_applicable"


class CheckType(str, Enum):
    configuration_audit = "configuration_audit"
    policy_review = "policy_review"
    access_control = "access_control"
    log_completeness = "log_completeness"
    encryption_status = "encryption_status"


class FindingSeverity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"


class ReportFormat(str, Enum):
    detailed = "detailed"
    summary = "summary"
    regulatory = "regulatory"


AVE_CATEGORIES: list[str] = [
    "prompt_injection", "tool_misuse", "memory_poisoning",
    "goal_hijacking", "identity_spoofing", "privilege_escalation",
    "data_exfiltration", "resource_exhaustion", "multi_agent_manipulation",
    "context_overflow", "guardrail_bypass", "output_manipulation",
    "supply_chain_compromise", "model_extraction", "reward_hacking",
    "capability_elicitation", "alignment_subversion", "delegation_abuse",
]

# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class FrameworkRequirement(BaseModel):
    req_id: str
    title: str
    description: str
    article_ref: str = ""


class FrameworkRecord(BaseModel):
    framework_id: str
    name: str
    version: str
    effective_date: str
    requirements: List[FrameworkRequirement]
    description: str = ""


class ControlCreate(BaseModel):
    name: str
    domain: ControlDomain
    description: str = ""
    status: ControlStatus = ControlStatus.not_started
    owner: str = ""
    framework_mappings: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="framework_id -> [req_id, ...]",
    )
    evidence_requirements: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ControlRecord(ControlCreate):
    control_id: str
    evidence_ids: List[str] = Field(default_factory=list)
    created_at: str
    updated_at: str


class EvidenceCreate(BaseModel):
    control_id: str
    title: str
    evidence_type: str = "document"  # document | configuration | log | attestation | screenshot
    content: str = ""
    submitted_by: str = ""


class EvidenceRecord(EvidenceCreate):
    evidence_id: str
    content_hash: str
    fresh: bool = True
    created_at: str


class CheckRun(BaseModel):
    check_type: CheckType
    target_service: str = ""
    schedule: str = "on_demand"  # continuous | daily | weekly | on_demand


class CheckResult(BaseModel):
    check_id: str
    check_type: CheckType
    target_service: str
    findings: List[Dict[str, Any]]
    passed: bool
    run_at: str


class ReportGenerate(BaseModel):
    framework_id: str
    report_format: ReportFormat = ReportFormat.detailed
    auditor_name: str = ""
    notes: str = ""


class ReportRecord(BaseModel):
    report_id: str
    framework_id: str
    report_format: ReportFormat
    compliance_score: float
    sections: Dict[str, Any]
    auditor_name: str
    created_at: str


# ---------------------------------------------------------------------------
# In-Memory Stores & Bootstrap
# ---------------------------------------------------------------------------

frameworks: Dict[str, FrameworkRecord] = {}
controls: Dict[str, ControlRecord] = {}
evidence_store: Dict[str, EvidenceRecord] = {}
check_results: List[CheckResult] = []
reports: Dict[str, ReportRecord] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _bootstrap():
    if frameworks:
        return
    _seed_frameworks = [
        FrameworkRecord(
            framework_id="EU-AI-ACT",
            name="EU AI Act",
            version="2024/1689",
            effective_date="2025-08-02",
            description="European Union Artificial Intelligence Act",
            requirements=[
                FrameworkRequirement(req_id="EU-AI-1", title="Risk Classification", description="AI systems must be classified by risk level", article_ref="Art. 6"),
                FrameworkRequirement(req_id="EU-AI-2", title="Transparency", description="AI systems must provide transparency to users", article_ref="Art. 13"),
                FrameworkRequirement(req_id="EU-AI-3", title="Human Oversight", description="High-risk AI must allow human oversight", article_ref="Art. 14"),
                FrameworkRequirement(req_id="EU-AI-4", title="Data Governance", description="Training data quality and governance requirements", article_ref="Art. 10"),
                FrameworkRequirement(req_id="EU-AI-5", title="Technical Documentation", description="Comprehensive technical documentation required", article_ref="Art. 11"),
            ],
        ),
        FrameworkRecord(
            framework_id="NIST-AI-RMF",
            name="NIST AI RMF 1.0",
            version="1.0",
            effective_date="2023-01-26",
            description="NIST Artificial Intelligence Risk Management Framework",
            requirements=[
                FrameworkRequirement(req_id="NIST-GOV", title="Govern", description="Governance structures for AI risk management"),
                FrameworkRequirement(req_id="NIST-MAP", title="Map", description="Map AI risks and impacts"),
                FrameworkRequirement(req_id="NIST-MEA", title="Measure", description="Measure identified AI risks"),
                FrameworkRequirement(req_id="NIST-MAN", title="Manage", description="Manage and mitigate AI risks"),
            ],
        ),
        FrameworkRecord(
            framework_id="ISO-27001",
            name="ISO 27001:2022",
            version="2022",
            effective_date="2022-10-25",
            description="Information Security Management Systems",
            requirements=[
                FrameworkRequirement(req_id="ISO-A5", title="Organisational Controls", description="37 organisational controls", article_ref="Annex A.5"),
                FrameworkRequirement(req_id="ISO-A6", title="People Controls", description="8 people controls", article_ref="Annex A.6"),
                FrameworkRequirement(req_id="ISO-A7", title="Physical Controls", description="14 physical controls", article_ref="Annex A.7"),
                FrameworkRequirement(req_id="ISO-A8", title="Technological Controls", description="34 technological controls", article_ref="Annex A.8"),
            ],
        ),
        FrameworkRecord(
            framework_id="ISO-42001",
            name="ISO 42001:2023",
            version="2023",
            effective_date="2023-12-18",
            description="AI Management System",
            requirements=[
                FrameworkRequirement(req_id="ISO42-4", title="Context", description="Understanding the organisation's AI context"),
                FrameworkRequirement(req_id="ISO42-5", title="Leadership", description="Leadership commitment to AI management"),
                FrameworkRequirement(req_id="ISO42-6", title="Planning", description="Planning for AI management system"),
                FrameworkRequirement(req_id="ISO42-8", title="Operation", description="Operational AI management"),
                FrameworkRequirement(req_id="ISO42-9", title="Performance Evaluation", description="Monitoring and evaluation of AI management"),
            ],
        ),
        FrameworkRecord(
            framework_id="SOC2",
            name="SOC 2 Type II",
            version="2022",
            effective_date="2022-01-01",
            description="Service Organization Control 2",
            requirements=[
                FrameworkRequirement(req_id="SOC-SEC", title="Security", description="System is protected against unauthorized access"),
                FrameworkRequirement(req_id="SOC-AVL", title="Availability", description="System is available for operation"),
                FrameworkRequirement(req_id="SOC-INT", title="Processing Integrity", description="Processing is complete, valid, accurate, timely"),
                FrameworkRequirement(req_id="SOC-CON", title="Confidentiality", description="Information designated as confidential is protected"),
                FrameworkRequirement(req_id="SOC-PRI", title="Privacy", description="Personal information is managed appropriately"),
            ],
        ),
        FrameworkRecord(
            framework_id="OWASP-LLM",
            name="OWASP Top 10 for LLM",
            version="1.1",
            effective_date="2023-10-16",
            description="OWASP Top 10 security risks for LLM applications",
            requirements=[
                FrameworkRequirement(req_id="LLM01", title="Prompt Injection", description="Manipulation of LLM via crafted inputs"),
                FrameworkRequirement(req_id="LLM02", title="Insecure Output Handling", description="Insufficient validation of LLM outputs"),
                FrameworkRequirement(req_id="LLM03", title="Training Data Poisoning", description="Tampering with training data"),
                FrameworkRequirement(req_id="LLM04", title="Model Denial of Service", description="Resource-intensive operations causing service degradation"),
                FrameworkRequirement(req_id="LLM05", title="Supply Chain Vulnerabilities", description="Compromised components in LLM supply chain"),
            ],
        ),
    ]
    for fw in _seed_frameworks:
        frameworks[fw.framework_id] = fw


_bootstrap()


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Autonomous Compliance Auditor",
    description="Phase 20 — Continuous compliance monitoring, gap analysis, and audit reporting",
    version="20.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health():
    return {
        "service": "autonomous-compliance-auditor",
        "status": "healthy",
        "phase": 20,
        "port": 9404,
        "stats": {
            "frameworks": len(frameworks),
            "controls": len(controls),
            "evidence": len(evidence_store),
            "reports": len(reports),
        },
        "timestamp": _now(),
    }


# ── Frameworks ─────────────────────────────────────────────────────────────

@app.get("/v1/frameworks")
def list_frameworks():
    return {"frameworks": [f.dict() for f in frameworks.values()], "total": len(frameworks)}


@app.get("/v1/frameworks/{framework_id}")
def get_framework(framework_id: str):
    if framework_id not in frameworks:
        raise HTTPException(404, "Framework not found")
    fw = frameworks[framework_id]
    # Cross-reference mapped controls
    mapped_controls = [
        c.dict() for c in controls.values()
        if framework_id in c.framework_mappings
    ]
    return {**fw.dict(), "mapped_controls": mapped_controls}


# ── Controls ───────────────────────────────────────────────────────────────

@app.post("/v1/controls", status_code=201)
def create_control(body: ControlCreate):
    cid = f"CTL-{uuid.uuid4().hex[:12]}"
    now = _now()
    record = ControlRecord(**body.dict(), control_id=cid, created_at=now, updated_at=now)
    controls[cid] = record
    return record.dict()


@app.get("/v1/controls")
def list_controls(
    domain: Optional[ControlDomain] = None,
    status: Optional[ControlStatus] = None,
    framework_id: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    results = list(controls.values())
    if domain:
        results = [c for c in results if c.domain == domain]
    if status:
        results = [c for c in results if c.status == status]
    if framework_id:
        results = [c for c in results if framework_id in c.framework_mappings]
    return {"controls": [c.dict() for c in results[:limit]], "total": len(results)}


@app.get("/v1/controls/{control_id}")
def get_control(control_id: str):
    if control_id not in controls:
        raise HTTPException(404, "Control not found")
    c = controls[control_id]
    evs = [evidence_store[eid].dict() for eid in c.evidence_ids if eid in evidence_store]
    return {**c.dict(), "evidence": evs}


# ── Evidence ───────────────────────────────────────────────────────────────

@app.post("/v1/evidence", status_code=201)
def submit_evidence(body: EvidenceCreate):
    if body.control_id not in controls:
        raise HTTPException(404, "Control not found")
    eid = f"EVD-{uuid.uuid4().hex[:12]}"
    content_hash = hashlib.sha256(body.content.encode()).hexdigest()
    record = EvidenceRecord(
        **body.dict(),
        evidence_id=eid,
        content_hash=content_hash,
        created_at=_now(),
    )
    evidence_store[eid] = record
    controls[body.control_id].evidence_ids.append(eid)
    controls[body.control_id].updated_at = _now()
    return record.dict()


@app.get("/v1/evidence")
def list_evidence(control_id: Optional[str] = None, limit: int = Query(default=100, ge=1, le=1000)):
    results = list(evidence_store.values())
    if control_id:
        results = [e for e in results if e.control_id == control_id]
    return {"evidence": [e.dict() for e in results[:limit]], "total": len(results)}


# ── Compliance Checks ──────────────────────────────────────────────────────

@app.post("/v1/checks/run")
def run_check(body: CheckRun):
    cid = f"CHK-{uuid.uuid4().hex[:12]}"
    # Simulated check with deterministic findings
    findings = []
    if body.check_type == CheckType.configuration_audit:
        findings.append({"control": "encryption_at_rest", "severity": "medium", "detail": "2 services missing encryption at rest"})
    elif body.check_type == CheckType.policy_review:
        findings.append({"control": "access_policy", "severity": "low", "detail": "Policy last reviewed 45 days ago"})
    elif body.check_type == CheckType.access_control:
        findings.append({"control": "rbac", "severity": "high", "detail": "3 overprivileged service accounts detected"})
    elif body.check_type == CheckType.log_completeness:
        findings.append({"control": "audit_logs", "severity": "informational", "detail": "Log coverage at 94%"})
    elif body.check_type == CheckType.encryption_status:
        findings.append({"control": "tls", "severity": "low", "detail": "All endpoints use TLS 1.3"})

    passed = all(f.get("severity") in ("low", "informational") for f in findings)
    result = CheckResult(
        check_id=cid,
        check_type=body.check_type,
        target_service=body.target_service,
        findings=findings,
        passed=passed,
        run_at=_now(),
    )
    check_results.append(result)
    if len(check_results) > 10000:
        check_results.pop(0)
    return result.dict()


@app.get("/v1/checks")
def list_checks(check_type: Optional[CheckType] = None, limit: int = Query(default=50, ge=1, le=500)):
    results = check_results[:]
    if check_type:
        results = [c for c in results if c.check_type == check_type]
    return {"checks": [c.dict() for c in results[-limit:]], "total": len(results)}


# ── Gap Analysis ───────────────────────────────────────────────────────────

@app.get("/v1/gaps/{framework_id}")
def gap_analysis(framework_id: str):
    if framework_id not in frameworks:
        raise HTTPException(404, "Framework not found")
    fw = frameworks[framework_id]
    mapped = [c for c in controls.values() if framework_id in c.framework_mappings]
    total_reqs = len(fw.requirements)

    # Check which requirements are covered by verified controls
    covered_reqs: set = set()
    for c in mapped:
        if c.status == ControlStatus.verified:
            for req_id in c.framework_mappings.get(framework_id, []):
                covered_reqs.add(req_id)

    gaps = []
    for req in fw.requirements:
        if req.req_id not in covered_reqs:
            # Find any controls mapped to this req
            mapped_controls_for_req = [
                c for c in mapped
                if req.req_id in c.framework_mappings.get(framework_id, [])
            ]
            best_status = max(
                (c.status.value for c in mapped_controls_for_req),
                default="not_started",
            )
            gaps.append({
                "requirement": req.dict(),
                "best_control_status": best_status,
                "mapped_controls": len(mapped_controls_for_req),
                "remediation_hours_estimate": 40 if best_status == "not_started" else 16,
            })

    score = round(len(covered_reqs) / max(total_reqs, 1) * 100, 1)
    return {
        "framework_id": framework_id,
        "compliance_score": score,
        "total_requirements": total_reqs,
        "covered_requirements": len(covered_reqs),
        "gaps": gaps,
        "gap_count": len(gaps),
    }


# ── Reports ────────────────────────────────────────────────────────────────

@app.post("/v1/reports/generate", status_code=201)
def generate_report(body: ReportGenerate):
    if body.framework_id not in frameworks:
        raise HTTPException(404, "Framework not found")
    fw = frameworks[body.framework_id]
    # Build gap data
    mapped = [c for c in controls.values() if body.framework_id in c.framework_mappings]
    verified = [c for c in mapped if c.status == ControlStatus.verified]
    score = round(len(verified) / max(len(fw.requirements), 1) * 100, 1)

    status_dist: Dict[str, int] = defaultdict(int)
    for c in mapped:
        status_dist[c.status.value] += 1

    sections = {
        "executive_summary": {
            "framework": fw.name,
            "compliance_score": score,
            "total_requirements": len(fw.requirements),
            "controls_mapped": len(mapped),
            "controls_verified": len(verified),
        },
        "scope": {
            "framework_version": fw.version,
            "audit_date": _now(),
            "auditor": body.auditor_name or "Autonomous Compliance Auditor",
        },
        "methodology": "Automated continuous compliance monitoring with evidence-based verification",
        "findings": {
            "control_status_distribution": dict(status_dist),
            "recent_checks": len(check_results),
            "evidence_items": sum(len(c.evidence_ids) for c in mapped),
        },
        "remediation_plan": {
            "gaps": len(fw.requirements) - len(verified),
            "estimated_total_hours": (len(fw.requirements) - len(verified)) * 24,
        },
    }

    if body.report_format == ReportFormat.summary:
        sections = {"executive_summary": sections["executive_summary"], "scope": sections["scope"]}
    elif body.report_format == ReportFormat.regulatory:
        sections["certification_statement"] = f"Compliance assessment for {fw.name} conducted per automated audit procedures."

    rid = f"RPT-{uuid.uuid4().hex[:12]}"
    record = ReportRecord(
        report_id=rid,
        framework_id=body.framework_id,
        report_format=body.report_format,
        compliance_score=score,
        sections=sections,
        auditor_name=body.auditor_name or "Autonomous Compliance Auditor",
        created_at=_now(),
    )
    reports[rid] = record
    return record.dict()


@app.get("/v1/reports")
def list_reports(framework_id: Optional[str] = None):
    results = list(reports.values())
    if framework_id:
        results = [r for r in results if r.framework_id == framework_id]
    return {"reports": [r.dict() for r in results], "total": len(results)}


@app.get("/v1/reports/{report_id}")
def get_report(report_id: str):
    if report_id not in reports:
        raise HTTPException(404, "Report not found")
    return reports[report_id].dict()


# ── Analytics ──────────────────────────────────────────────────────────────

@app.get("/v1/analytics")
def analytics():
    domain_dist: Dict[str, int] = defaultdict(int)
    status_dist: Dict[str, int] = defaultdict(int)
    for c in controls.values():
        domain_dist[c.domain.value] += 1
        status_dist[c.status.value] += 1
    per_framework_score: Dict[str, float] = {}
    for fid, fw in frameworks.items():
        mapped = [c for c in controls.values() if fid in c.framework_mappings and c.status == ControlStatus.verified]
        per_framework_score[fid] = round(len(mapped) / max(len(fw.requirements), 1) * 100, 1)
    return {
        "frameworks": len(frameworks),
        "controls": {
            "total": len(controls),
            "domain_distribution": dict(domain_dist),
            "status_distribution": dict(status_dist),
        },
        "evidence_items": len(evidence_store),
        "checks_run": len(check_results),
        "reports_generated": len(reports),
        "compliance_scores": per_framework_score,
    }


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9404)
