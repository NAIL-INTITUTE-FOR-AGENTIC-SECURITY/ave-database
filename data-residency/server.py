"""
Sovereign Data Residency Engine — Phase 21 Service 2 of 5
Port: 9501

Jurisdiction-aware data governance enforcing residency requirements,
cross-border transfer controls, data localisation policies, and
regulatory compliance across global data sovereignty regimes.
"""

from __future__ import annotations

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

class SovereigntyLevel(str, Enum):
    full = "full"
    partial = "partial"
    advisory = "advisory"


class DataCategory(str, Enum):
    personal_data = "personal_data"
    financial = "financial"
    health = "health"
    biometric = "biometric"
    ai_training = "ai_training"
    telemetry = "telemetry"
    classified = "classified"


class TransferLegalBasis(str, Enum):
    adequacy_decision = "adequacy_decision"
    standard_contractual_clauses = "standard_contractual_clauses"
    binding_corporate_rules = "binding_corporate_rules"
    explicit_consent = "explicit_consent"
    derogation = "derogation"


class TransferStatus(str, Enum):
    pending = "pending"
    approved = "approved"
    denied = "denied"
    expired = "expired"


class ComplianceStatus(str, Enum):
    compliant = "compliant"
    non_compliant = "non_compliant"
    warning = "warning"
    unknown = "unknown"


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

class JurisdictionCreate(BaseModel):
    code: str  # ISO 3166-1 alpha-2 or region code
    name: str
    sovereignty_level: SovereigntyLevel = SovereigntyLevel.full
    governing_legislation: List[str] = Field(default_factory=list)
    restricted_categories: List[DataCategory] = Field(default_factory=list)
    allowed_transfer_destinations: List[str] = Field(default_factory=list)
    encryption_required: bool = True
    retention_max_days: int = Field(default=365 * 3, ge=1)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class JurisdictionRecord(JurisdictionCreate):
    jurisdiction_id: str
    created_at: str


class PolicyCreate(BaseModel):
    jurisdiction_id: str
    data_category: DataCategory
    allowed_regions: List[str] = Field(default_factory=list)
    encryption_at_rest: bool = True
    encryption_in_transit: bool = True
    local_processing_only: bool = False
    retention_days: int = Field(default=365, ge=1)
    description: str = ""


class PolicyRecord(PolicyCreate):
    policy_id: str
    created_at: str


class AssetCreate(BaseModel):
    name: str
    data_category: DataCategory
    owning_jurisdiction: str
    storage_region: str
    replication_regions: List[str] = Field(default_factory=list)
    size_gb: float = Field(default=0.0, ge=0)
    encrypted: bool = True
    description: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AssetRecord(AssetCreate):
    asset_id: str
    compliance_status: ComplianceStatus = ComplianceStatus.unknown
    violations: List[str] = Field(default_factory=list)
    created_at: str
    updated_at: str


class TransferRequest(BaseModel):
    asset_id: str
    source_jurisdiction: str
    destination_jurisdiction: str
    legal_basis: TransferLegalBasis
    purpose: str = ""
    requestor: str = ""
    impact_assessment: str = ""


class TransferRecord(TransferRequest):
    transfer_id: str
    status: TransferStatus = TransferStatus.pending
    reviewer: str = ""
    review_notes: str = ""
    created_at: str
    decided_at: Optional[str] = None


# ---------------------------------------------------------------------------
# In-Memory Stores & Bootstrap
# ---------------------------------------------------------------------------

jurisdictions: Dict[str, JurisdictionRecord] = {}
policies: Dict[str, PolicyRecord] = {}
assets: Dict[str, AssetRecord] = {}
transfers: Dict[str, TransferRecord] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _bootstrap():
    if jurisdictions:
        return
    seed = [
        JurisdictionCreate(code="EU", name="European Union", sovereignty_level=SovereigntyLevel.full,
                           governing_legislation=["GDPR", "EU AI Act", "Data Governance Act"],
                           restricted_categories=[DataCategory.personal_data, DataCategory.health, DataCategory.biometric],
                           allowed_transfer_destinations=["EU", "UK", "JP", "AU"],
                           encryption_required=True, retention_max_days=365 * 3),
        JurisdictionCreate(code="US", name="United States", sovereignty_level=SovereigntyLevel.partial,
                           governing_legislation=["CCPA", "HIPAA", "GLBA", "EO 14110"],
                           restricted_categories=[DataCategory.health, DataCategory.financial],
                           allowed_transfer_destinations=["US", "EU", "UK", "JP", "AU"],
                           encryption_required=True, retention_max_days=365 * 7),
        JurisdictionCreate(code="UK", name="United Kingdom", sovereignty_level=SovereigntyLevel.full,
                           governing_legislation=["UK GDPR", "Data Protection Act 2018"],
                           restricted_categories=[DataCategory.personal_data, DataCategory.health],
                           allowed_transfer_destinations=["UK", "EU", "US", "JP", "AU"],
                           encryption_required=True, retention_max_days=365 * 3),
        JurisdictionCreate(code="CN", name="China", sovereignty_level=SovereigntyLevel.full,
                           governing_legislation=["PIPL", "Data Security Law", "Cybersecurity Law"],
                           restricted_categories=[DataCategory.personal_data, DataCategory.ai_training, DataCategory.classified],
                           allowed_transfer_destinations=["CN"],
                           encryption_required=True, retention_max_days=365 * 5),
        JurisdictionCreate(code="JP", name="Japan", sovereignty_level=SovereigntyLevel.full,
                           governing_legislation=["APPI"],
                           restricted_categories=[DataCategory.personal_data],
                           allowed_transfer_destinations=["JP", "EU", "UK", "US", "AU"],
                           encryption_required=True, retention_max_days=365 * 3),
        JurisdictionCreate(code="AU", name="Australia", sovereignty_level=SovereigntyLevel.full,
                           governing_legislation=["Privacy Act 1988", "CDR"],
                           restricted_categories=[DataCategory.personal_data, DataCategory.health],
                           allowed_transfer_destinations=["AU", "EU", "UK", "US", "JP"],
                           encryption_required=True, retention_max_days=365 * 3),
        JurisdictionCreate(code="BR", name="Brazil", sovereignty_level=SovereigntyLevel.full,
                           governing_legislation=["LGPD"],
                           restricted_categories=[DataCategory.personal_data, DataCategory.health],
                           allowed_transfer_destinations=["BR", "EU"],
                           encryption_required=True, retention_max_days=365 * 5),
        JurisdictionCreate(code="IN", name="India", sovereignty_level=SovereigntyLevel.full,
                           governing_legislation=["DPDP Act 2023"],
                           restricted_categories=[DataCategory.personal_data, DataCategory.financial],
                           allowed_transfer_destinations=["IN"],
                           encryption_required=True, retention_max_days=365 * 5),
    ]
    for j in seed:
        jid = j.code
        jurisdictions[jid] = JurisdictionRecord(**j.dict(), jurisdiction_id=jid, created_at=_now())


_bootstrap()


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Sovereign Data Residency Engine",
    description="Phase 21 — Jurisdiction-aware data governance, residency enforcement, cross-border transfer controls",
    version="21.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health():
    return {
        "service": "sovereign-data-residency-engine",
        "status": "healthy",
        "phase": 21,
        "port": 9501,
        "stats": {
            "jurisdictions": len(jurisdictions),
            "policies": len(policies),
            "assets": len(assets),
            "transfers": len(transfers),
        },
        "timestamp": _now(),
    }


# ── Jurisdictions ──────────────────────────────────────────────────────────

@app.post("/v1/jurisdictions", status_code=201)
def create_jurisdiction(body: JurisdictionCreate):
    jid = body.code.upper()
    if jid in jurisdictions:
        raise HTTPException(409, f"Jurisdiction {jid} already exists")
    record = JurisdictionRecord(**body.dict(), jurisdiction_id=jid, created_at=_now())
    jurisdictions[jid] = record
    return record.dict()


@app.get("/v1/jurisdictions")
def list_jurisdictions():
    return {"jurisdictions": [j.dict() for j in jurisdictions.values()], "total": len(jurisdictions)}


@app.get("/v1/jurisdictions/{jid}")
def get_jurisdiction(jid: str):
    jid = jid.upper()
    if jid not in jurisdictions:
        raise HTTPException(404, "Jurisdiction not found")
    j = jurisdictions[jid]
    j_policies = [p.dict() for p in policies.values() if p.jurisdiction_id == jid]
    j_assets = [a.dict() for a in assets.values() if a.owning_jurisdiction == jid]
    return {**j.dict(), "policies": j_policies, "assets": j_assets}


# ── Policies ───────────────────────────────────────────────────────────────

@app.post("/v1/policies", status_code=201)
def create_policy(body: PolicyCreate):
    if body.jurisdiction_id not in jurisdictions:
        raise HTTPException(404, "Jurisdiction not found")
    pid = f"POL-{uuid.uuid4().hex[:12]}"
    record = PolicyRecord(**body.dict(), policy_id=pid, created_at=_now())
    policies[pid] = record
    return record.dict()


@app.get("/v1/policies")
def list_policies(jurisdiction_id: Optional[str] = None, data_category: Optional[DataCategory] = None):
    results = list(policies.values())
    if jurisdiction_id:
        results = [p for p in results if p.jurisdiction_id == jurisdiction_id.upper()]
    if data_category:
        results = [p for p in results if p.data_category == data_category]
    return {"policies": [p.dict() for p in results], "total": len(results)}


# ── Assets ─────────────────────────────────────────────────────────────────

@app.post("/v1/assets", status_code=201)
def register_asset(body: AssetCreate):
    aid = f"ASSET-{uuid.uuid4().hex[:12]}"
    now = _now()
    record = AssetRecord(**body.dict(), asset_id=aid, created_at=now, updated_at=now)
    # Run compliance check
    _check_asset_compliance(record)
    assets[aid] = record
    return record.dict()


@app.get("/v1/assets")
def list_assets(
    jurisdiction: Optional[str] = None,
    category: Optional[DataCategory] = None,
    compliance: Optional[ComplianceStatus] = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    results = list(assets.values())
    if jurisdiction:
        results = [a for a in results if a.owning_jurisdiction == jurisdiction.upper()]
    if category:
        results = [a for a in results if a.data_category == category]
    if compliance:
        results = [a for a in results if a.compliance_status == compliance]
    return {"assets": [a.dict() for a in results[:limit]], "total": len(results)}


@app.get("/v1/assets/{asset_id}")
def get_asset(asset_id: str):
    if asset_id not in assets:
        raise HTTPException(404, "Asset not found")
    return assets[asset_id].dict()


def _check_asset_compliance(asset: AssetRecord):
    """Automated residency violation detection."""
    violations = []
    j = jurisdictions.get(asset.owning_jurisdiction.upper())
    if not j:
        violations.append(f"Unknown jurisdiction: {asset.owning_jurisdiction}")
        asset.compliance_status = ComplianceStatus.non_compliant
        asset.violations = violations
        return

    # Check storage region allowed
    applicable_policies = [p for p in policies.values()
                           if p.jurisdiction_id == j.jurisdiction_id and p.data_category == asset.data_category]
    for pol in applicable_policies:
        if pol.allowed_regions and asset.storage_region not in pol.allowed_regions:
            violations.append(f"Storage region {asset.storage_region} not in allowed regions {pol.allowed_regions}")
        if pol.encryption_at_rest and not asset.encrypted:
            violations.append("Encryption at rest required but asset is unencrypted")
        if pol.local_processing_only and asset.replication_regions:
            violations.append("Local processing only — replication to other regions not allowed")

    # Check transfer destinations
    if j.allowed_transfer_destinations:
        for rep in asset.replication_regions:
            if rep not in j.allowed_transfer_destinations:
                violations.append(f"Replication to {rep} not in allowed destinations for {j.jurisdiction_id}")

    # Check restricted categories
    if asset.data_category in j.restricted_categories and not asset.encrypted:
        violations.append(f"Restricted category {asset.data_category.value} requires encryption")

    if violations:
        asset.compliance_status = ComplianceStatus.non_compliant
    else:
        asset.compliance_status = ComplianceStatus.compliant
    asset.violations = violations


# ── Transfers ──────────────────────────────────────────────────────────────

@app.post("/v1/transfers", status_code=201)
def request_transfer(body: TransferRequest):
    if body.asset_id not in assets:
        raise HTTPException(404, "Asset not found")
    tid = f"TXF-{uuid.uuid4().hex[:12]}"
    record = TransferRecord(**body.dict(), transfer_id=tid, created_at=_now())

    # Auto-check legality
    src_j = jurisdictions.get(body.source_jurisdiction.upper())
    if src_j and body.destination_jurisdiction.upper() not in src_j.allowed_transfer_destinations:
        record.status = TransferStatus.denied
        record.review_notes = f"Destination {body.destination_jurisdiction} not in allowed transfer destinations for {body.source_jurisdiction}"
        record.decided_at = _now()

    transfers[tid] = record
    return record.dict()


@app.get("/v1/transfers")
def list_transfers(status: Optional[TransferStatus] = None, limit: int = Query(default=100, ge=1, le=1000)):
    results = list(transfers.values())
    if status:
        results = [t for t in results if t.status == status]
    return {"transfers": [t.dict() for t in results[:limit]], "total": len(results)}


@app.patch("/v1/transfers/{tid}/approve")
def approve_transfer(tid: str, reviewer: str = "", notes: str = ""):
    if tid not in transfers:
        raise HTTPException(404, "Transfer not found")
    t = transfers[tid]
    if t.status != TransferStatus.pending:
        raise HTTPException(409, f"Transfer is {t.status.value}, not pending")
    t.status = TransferStatus.approved
    t.reviewer = reviewer
    t.review_notes = notes
    t.decided_at = _now()
    return t.dict()


@app.patch("/v1/transfers/{tid}/deny")
def deny_transfer(tid: str, reviewer: str = "", notes: str = ""):
    if tid not in transfers:
        raise HTTPException(404, "Transfer not found")
    t = transfers[tid]
    if t.status != TransferStatus.pending:
        raise HTTPException(409, f"Transfer is {t.status.value}, not pending")
    t.status = TransferStatus.denied
    t.reviewer = reviewer
    t.review_notes = notes
    t.decided_at = _now()
    return t.dict()


# ── Compliance ─────────────────────────────────────────────────────────────

@app.get("/v1/compliance/check")
def compliance_check(jurisdiction: Optional[str] = None):
    target_assets = list(assets.values())
    if jurisdiction:
        target_assets = [a for a in target_assets if a.owning_jurisdiction == jurisdiction.upper()]
    for a in target_assets:
        _check_asset_compliance(a)
        a.updated_at = _now()
    compliant = sum(1 for a in target_assets if a.compliance_status == ComplianceStatus.compliant)
    non_compliant = sum(1 for a in target_assets if a.compliance_status == ComplianceStatus.non_compliant)
    return {
        "total_assets_checked": len(target_assets),
        "compliant": compliant,
        "non_compliant": non_compliant,
        "compliance_rate": round(compliant / max(len(target_assets), 1) * 100, 1),
        "violations": [
            {"asset_id": a.asset_id, "violations": a.violations}
            for a in target_assets if a.violations
        ],
    }


# ── Analytics ──────────────────────────────────────────────────────────────

@app.get("/v1/analytics")
def analytics():
    cat_dist: Dict[str, int] = defaultdict(int)
    comp_dist: Dict[str, int] = defaultdict(int)
    for a in assets.values():
        cat_dist[a.data_category.value] += 1
        comp_dist[a.compliance_status.value] += 1
    transfer_dist: Dict[str, int] = defaultdict(int)
    for t in transfers.values():
        transfer_dist[t.status.value] += 1
    return {
        "jurisdictions": len(jurisdictions),
        "policies": len(policies),
        "assets": {
            "total": len(assets),
            "category_distribution": dict(cat_dist),
            "compliance_distribution": dict(comp_dist),
        },
        "transfers": {"total": len(transfers), "status_distribution": dict(transfer_dist)},
    }


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9501)
