"""
Inter-Agency Compliance Bridge — Phase 24 Service 5 of 5
Port: 9804

Automated compliance evidence sharing across regulatory boundaries with
audit trail federation, mutual recognition agreements, and cross-jurisdiction
equivalence mapping.
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

class AgencyDomain(str, Enum):
    data_protection = "data_protection"
    ai_safety = "ai_safety"
    financial_services = "financial_services"
    healthcare = "healthcare"
    critical_infrastructure = "critical_infrastructure"
    telecom = "telecom"
    energy = "energy"
    general = "general"


class AuthorityLevel(str, Enum):
    primary = "primary"
    secondary = "secondary"
    advisory = "advisory"


class ControlCategory(str, Enum):
    technical = "technical"
    administrative = "administrative"
    physical = "physical"
    procedural = "procedural"


class EvidenceType(str, Enum):
    audit_report = "audit_report"
    certification = "certification"
    test_result = "test_result"
    policy_document = "policy_document"
    incident_report = "incident_report"
    assessment = "assessment"
    attestation = "attestation"


class EvidenceClassification(str, Enum):
    public = "public"
    restricted = "restricted"
    confidential = "confidential"


class EvidenceStatus(str, Enum):
    submitted = "submitted"
    under_review = "under_review"
    accepted = "accepted"
    rejected = "rejected"
    expired = "expired"


class EquivalenceStrength(str, Enum):
    full = "full"
    partial = "partial"
    conditional = "conditional"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class AgencyCreate(BaseModel):
    name: str
    jurisdiction: str
    domain: AgencyDomain
    authority_level: AuthorityLevel = AuthorityLevel.primary
    contact_email: str = ""
    website: str = ""
    description: str = ""


class AgencyRecord(AgencyCreate):
    agency_id: str
    created_at: str


class FrameworkCreate(BaseModel):
    name: str
    agency_id: str
    version: str = "1.0"
    description: str = ""
    effective_date: str = ""


class FrameworkRecord(FrameworkCreate):
    framework_id: str
    requirements: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: str


class RequirementCreate(BaseModel):
    title: str
    description: str = ""
    control_category: ControlCategory = ControlCategory.technical
    identifier: str = ""  # e.g. "GDPR-Art5", "SOC2-CC6.1"


class EvidenceCreate(BaseModel):
    title: str
    evidence_type: EvidenceType
    classification: EvidenceClassification = EvidenceClassification.restricted
    description: str = ""
    submitting_organisation: str = ""
    target_agency_id: str = ""
    framework_id: str = ""
    content_hash: str = ""
    expires_at: str = ""


class EvidenceRecord(EvidenceCreate):
    evidence_id: str
    status: EvidenceStatus = EvidenceStatus.submitted
    reviewer_notes: str = ""
    reviewed_at: Optional[str] = None
    submitted_at: str
    updated_at: str


class EvidenceReview(BaseModel):
    decision: str = Field(..., regex="^(accepted|rejected)$")
    reviewer_notes: str = ""


class MRACreate(BaseModel):
    title: str
    agency_ids: List[str]
    framework_ids: List[str] = Field(default_factory=list)
    evidence_types: List[EvidenceType] = Field(default_factory=list)
    validity_period_days: int = Field(default=365, ge=30)
    description: str = ""


class MRARecord(MRACreate):
    mra_id: str
    active: bool = True
    created_at: str
    expires_at: str


class EquivalenceCreate(BaseModel):
    framework_a_id: str
    requirement_a_id: str
    framework_b_id: str
    requirement_b_id: str
    strength: EquivalenceStrength = EquivalenceStrength.full
    rationale: str = ""
    assessor: str = ""


class EquivalenceRecord(EquivalenceCreate):
    equivalence_id: str
    created_at: str


# ---------------------------------------------------------------------------
# In-Memory Stores
# ---------------------------------------------------------------------------

agencies: Dict[str, AgencyRecord] = {}
frameworks: Dict[str, FrameworkRecord] = {}
evidence: Dict[str, EvidenceRecord] = {}
mras: Dict[str, MRARecord] = {}
equivalences: Dict[str, EquivalenceRecord] = {}
audit_trail: List[Dict[str, Any]] = []
MAX_AUDIT = 10000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _audit(action: str, entity_type: str, entity_id: str, actor: str = "system", detail: str = ""):
    entry = {
        "audit_id": f"FA-{uuid.uuid4().hex[:8]}",
        "action": action,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "actor": actor,
        "detail": detail,
        "timestamp": _now(),
    }
    audit_trail.append(entry)
    if len(audit_trail) > MAX_AUDIT:
        audit_trail.pop(0)


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Inter-Agency Compliance Bridge",
    description="Phase 24 — Cross-regulatory evidence sharing with MRAs, equivalence mapping, compliance passports",
    version="24.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health():
    return {
        "service": "inter-agency-compliance-bridge",
        "status": "healthy",
        "phase": 24,
        "port": 9804,
        "stats": {
            "agencies": len(agencies),
            "frameworks": len(frameworks),
            "evidence_packages": len(evidence),
            "mras": len(mras),
            "equivalences": len(equivalences),
            "audit_entries": len(audit_trail),
        },
        "timestamp": _now(),
    }


# -- Agencies ----------------------------------------------------------------

@app.post("/v1/agencies", status_code=201)
def register_agency(body: AgencyCreate):
    aid = f"AGY-{uuid.uuid4().hex[:12]}"
    record = AgencyRecord(**body.dict(), agency_id=aid, created_at=_now())
    agencies[aid] = record
    _audit("agency_registered", "agency", aid, detail=body.name)
    return record.dict()


@app.get("/v1/agencies")
def list_agencies(
    domain: Optional[AgencyDomain] = None,
    jurisdiction: Optional[str] = None,
):
    results = list(agencies.values())
    if domain:
        results = [a for a in results if a.domain == domain]
    if jurisdiction:
        results = [a for a in results if a.jurisdiction == jurisdiction]
    return {"agencies": [a.dict() for a in results], "total": len(results)}


# -- Frameworks --------------------------------------------------------------

@app.post("/v1/frameworks", status_code=201)
def create_framework(body: FrameworkCreate):
    if body.agency_id not in agencies:
        raise HTTPException(404, "Agency not found")
    fid = f"FW-{uuid.uuid4().hex[:12]}"
    record = FrameworkRecord(**body.dict(), framework_id=fid, created_at=_now())
    frameworks[fid] = record
    _audit("framework_created", "framework", fid, detail=body.name)
    return record.dict()


@app.get("/v1/frameworks")
def list_frameworks(agency_id: Optional[str] = None):
    results = list(frameworks.values())
    if agency_id:
        results = [f for f in results if f.agency_id == agency_id]
    return {"frameworks": [f.dict() for f in results], "total": len(results)}


@app.post("/v1/frameworks/{fw_id}/requirements", status_code=201)
def add_requirement(fw_id: str, body: RequirementCreate):
    if fw_id not in frameworks:
        raise HTTPException(404, "Framework not found")
    req = {
        "requirement_id": f"REQ-{uuid.uuid4().hex[:8]}",
        **body.dict(),
        "added_at": _now(),
    }
    frameworks[fw_id].requirements.append(req)
    return req


# -- Evidence ----------------------------------------------------------------

@app.post("/v1/evidence", status_code=201)
def submit_evidence(body: EvidenceCreate):
    if body.target_agency_id and body.target_agency_id not in agencies:
        raise HTTPException(404, "Target agency not found")
    eid = f"EVD-{uuid.uuid4().hex[:12]}"
    if not body.content_hash:
        body.content_hash = hashlib.sha256(f"{body.title}{_now()}".encode()).hexdigest()
    now = _now()
    record = EvidenceRecord(**body.dict(), evidence_id=eid, submitted_at=now, updated_at=now)
    evidence[eid] = record
    _audit("evidence_submitted", "evidence", eid, body.submitting_organisation, f"To {body.target_agency_id}")
    return record.dict()


@app.get("/v1/evidence")
def list_evidence(
    submitting_organisation: Optional[str] = None,
    target_agency_id: Optional[str] = None,
    status: Optional[EvidenceStatus] = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    results = list(evidence.values())
    if submitting_organisation:
        results = [e for e in results if e.submitting_organisation == submitting_organisation]
    if target_agency_id:
        results = [e for e in results if e.target_agency_id == target_agency_id]
    if status:
        results = [e for e in results if e.status == status]
    results.sort(key=lambda e: e.submitted_at, reverse=True)
    return {"evidence": [e.dict() for e in results[:limit]], "total": len(results)}


@app.patch("/v1/evidence/{evd_id}/review")
def review_evidence(evd_id: str, body: EvidenceReview):
    if evd_id not in evidence:
        raise HTTPException(404, "Evidence not found")
    record = evidence[evd_id]
    record.status = EvidenceStatus.accepted if body.decision == "accepted" else EvidenceStatus.rejected
    record.reviewer_notes = body.reviewer_notes
    record.reviewed_at = _now()
    record.updated_at = _now()
    _audit(f"evidence_{body.decision}", "evidence", evd_id, detail=body.reviewer_notes)
    return record.dict()


# -- Mutual Recognition Agreements -------------------------------------------

@app.post("/v1/agreements", status_code=201)
def create_mra(body: MRACreate):
    for aid in body.agency_ids:
        if aid not in agencies:
            raise HTTPException(404, f"Agency {aid} not found")
    mid = f"MRA-{uuid.uuid4().hex[:12]}"
    now = _now()
    from datetime import timedelta
    expires = (datetime.now(timezone.utc) + timedelta(days=body.validity_period_days)).isoformat()
    record = MRARecord(**body.dict(), mra_id=mid, created_at=now, expires_at=expires)
    mras[mid] = record
    _audit("mra_created", "mra", mid, detail=f"Between {len(body.agency_ids)} agencies")
    return record.dict()


@app.get("/v1/agreements")
def list_mras(active_only: bool = False):
    results = list(mras.values())
    if active_only:
        results = [m for m in results if m.active]
    return {"agreements": [m.dict() for m in results], "total": len(results)}


# -- Equivalences ------------------------------------------------------------

@app.post("/v1/equivalences", status_code=201)
def create_equivalence(body: EquivalenceCreate):
    if body.framework_a_id not in frameworks:
        raise HTTPException(404, f"Framework {body.framework_a_id} not found")
    if body.framework_b_id not in frameworks:
        raise HTTPException(404, f"Framework {body.framework_b_id} not found")
    eqid = f"EQV-{uuid.uuid4().hex[:12]}"
    record = EquivalenceRecord(**body.dict(), equivalence_id=eqid, created_at=_now())
    equivalences[eqid] = record
    _audit("equivalence_mapped", "equivalence", eqid, body.assessor,
           f"{body.framework_a_id}:{body.requirement_a_id} ↔ {body.framework_b_id}:{body.requirement_b_id}")
    return record.dict()


@app.get("/v1/equivalences")
def list_equivalences(
    framework_id: Optional[str] = None,
    strength: Optional[EquivalenceStrength] = None,
):
    results = list(equivalences.values())
    if framework_id:
        results = [e for e in results if e.framework_a_id == framework_id or e.framework_b_id == framework_id]
    if strength:
        results = [e for e in results if e.strength == strength]
    return {"equivalences": [e.dict() for e in results], "total": len(results)}


# -- Compliance Passport -----------------------------------------------------

@app.get("/v1/passport/{org}")
def compliance_passport(org: str):
    """Generate a portable compliance passport for an organisation."""
    org_evidence = [e for e in evidence.values() if e.submitting_organisation == org and e.status == EvidenceStatus.accepted]

    # Group by agency
    by_agency: Dict[str, List[Dict]] = defaultdict(list)
    for ev in org_evidence:
        agency_name = agencies.get(ev.target_agency_id, AgencyRecord(
            agency_id="", name="Unknown", jurisdiction="", domain=AgencyDomain.general, created_at="",
        )).name
        by_agency[agency_name].append({
            "evidence_id": ev.evidence_id,
            "title": ev.title,
            "type": ev.evidence_type.value,
            "accepted_at": ev.reviewed_at,
        })

    # Find recognised equivalences
    recognised = []
    for eq in equivalences.values():
        recognised.append({
            "equivalence_id": eq.equivalence_id,
            "framework_a": eq.framework_a_id,
            "framework_b": eq.framework_b_id,
            "strength": eq.strength.value,
        })

    # Find applicable MRAs
    applicable_mras = []
    org_agencies = set(e.target_agency_id for e in org_evidence)
    for mra in mras.values():
        if mra.active and org_agencies & set(mra.agency_ids):
            applicable_mras.append({
                "mra_id": mra.mra_id,
                "title": mra.title,
                "expires_at": mra.expires_at,
            })

    return {
        "organisation": org,
        "generated_at": _now(),
        "accepted_evidence": {
            "total": len(org_evidence),
            "by_agency": {k: len(v) for k, v in by_agency.items()},
            "detail": dict(by_agency),
        },
        "mutual_recognition_agreements": applicable_mras,
        "equivalence_mappings": len(recognised),
        "compliance_score": min(100, len(org_evidence) * 15 + len(applicable_mras) * 10),
    }


# -- Audit Trail -------------------------------------------------------------

@app.get("/v1/audit-trail")
def get_audit_trail(
    entity_type: Optional[str] = None,
    actor: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    results = list(audit_trail)
    if entity_type:
        results = [a for a in results if a.get("entity_type") == entity_type]
    if actor:
        results = [a for a in results if a.get("actor") == actor]
    results = results[-limit:]
    results.reverse()
    return {"audit_trail": results, "total": len(results)}


# -- Analytics ----------------------------------------------------------------

@app.get("/v1/analytics")
def analytics():
    domain_dist: Dict[str, int] = defaultdict(int)
    for a in agencies.values():
        domain_dist[a.domain.value] += 1

    ev_status_dist: Dict[str, int] = defaultdict(int)
    ev_type_dist: Dict[str, int] = defaultdict(int)
    for e in evidence.values():
        ev_status_dist[e.status.value] += 1
        ev_type_dist[e.evidence_type.value] += 1

    strength_dist: Dict[str, int] = defaultdict(int)
    for eq in equivalences.values():
        strength_dist[eq.strength.value] += 1

    return {
        "agencies": {
            "total": len(agencies),
            "domain_distribution": dict(domain_dist),
        },
        "frameworks": {
            "total": len(frameworks),
            "total_requirements": sum(len(f.requirements) for f in frameworks.values()),
        },
        "evidence": {
            "total": len(evidence),
            "status_distribution": dict(ev_status_dist),
            "type_distribution": dict(ev_type_dist),
        },
        "agreements": {
            "total": len(mras),
            "active": sum(1 for m in mras.values() if m.active),
        },
        "equivalences": {
            "total": len(equivalences),
            "strength_distribution": dict(strength_dist),
        },
        "audit": {
            "total_entries": len(audit_trail),
        },
    }


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9804)
