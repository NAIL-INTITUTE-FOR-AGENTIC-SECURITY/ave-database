"""
Federated Threat Intelligence Hub — Phase 24 Service 1 of 5
Port: 9800

Cross-organisational threat sharing with privacy-preserving data exchange,
indicator federation, trust-tier access control, and Traffic Light Protocol
(TLP) enforcement.
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

class TrustTier(str, Enum):
    founder = "founder"
    partner = "partner"
    associate = "associate"
    observer = "observer"


class TLPLevel(str, Enum):
    RED = "TLP:RED"
    AMBER_STRICT = "TLP:AMBER+STRICT"
    AMBER = "TLP:AMBER"
    GREEN = "TLP:GREEN"
    CLEAR = "TLP:CLEAR"


TLP_ORDER = {
    "TLP:RED": 5, "TLP:AMBER+STRICT": 4, "TLP:AMBER": 3,
    "TLP:GREEN": 2, "TLP:CLEAR": 1,
}

TIER_MAX_TLP = {
    "founder": 5,       # all TLP levels
    "partner": 3,       # AMBER and below
    "associate": 2,     # GREEN and CLEAR
    "observer": 1,      # CLEAR only
}


class IndicatorType(str, Enum):
    ip = "ip"
    domain = "domain"
    hash = "hash"
    url = "url"
    email = "email"
    cve = "cve"
    ttps = "ttps"
    behaviour = "behaviour"


class IndicatorSeverity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"


class SightingType(str, Enum):
    confirmed = "confirmed"
    suspected = "suspected"
    false_positive = "false_positive"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class OrgCreate(BaseModel):
    name: str
    trust_tier: TrustTier = TrustTier.observer
    tlp_clearance: TLPLevel = TLPLevel.CLEAR
    sector: str = "general"
    contact_email: str = ""
    description: str = ""


class OrgRecord(OrgCreate):
    org_id: str
    created_at: str


class IndicatorCreate(BaseModel):
    indicator_type: IndicatorType
    value: str
    tlp: TLPLevel = TLPLevel.GREEN
    confidence: float = Field(default=50.0, ge=0, le=100)
    severity: IndicatorSeverity = IndicatorSeverity.medium
    source_org_id: str
    description: str = ""
    mitre_attack_ids: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    ttl_hours: int = Field(default=720, ge=1)
    hash_only: bool = False


class IndicatorRecord(BaseModel):
    indicator_id: str
    indicator_type: str
    value: str
    value_hash: str
    tlp: str
    confidence: float
    severity: str
    source_org_id: str
    description: str
    mitre_attack_ids: List[str]
    tags: List[str]
    ttl_hours: int
    sightings: List[Dict[str, Any]] = Field(default_factory=list)
    sighting_count: int = 0
    related_indicators: List[str] = Field(default_factory=list)
    created_at: str
    updated_at: str


class SightingCreate(BaseModel):
    sighting_type: SightingType
    reporter_org_id: str
    detail: str = ""


class AgreementCreate(BaseModel):
    org_a_id: str
    org_b_id: str
    indicator_types: List[IndicatorType] = Field(default_factory=list)
    tlp_ceiling: TLPLevel = TLPLevel.GREEN
    retention_days: int = Field(default=90, ge=1)
    description: str = ""


class AgreementRecord(AgreementCreate):
    agreement_id: str
    active: bool = True
    created_at: str


# ---------------------------------------------------------------------------
# In-Memory Stores
# ---------------------------------------------------------------------------

organisations: Dict[str, OrgRecord] = {}
indicators: Dict[str, IndicatorRecord] = {}
agreements: Dict[str, AgreementRecord] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _can_access_tlp(org: OrgRecord, tlp_value: str) -> bool:
    """Check if org's tier allows access to this TLP level."""
    org_max = TIER_MAX_TLP.get(org.trust_tier.value, 1)
    indicator_level = TLP_ORDER.get(tlp_value, 1)
    return org_max >= indicator_level


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Federated Threat Intelligence Hub",
    description="Phase 24 — Cross-org threat sharing with TLP enforcement and trust-tier access control",
    version="24.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health():
    tier_dist: Dict[str, int] = defaultdict(int)
    for o in organisations.values():
        tier_dist[o.trust_tier.value] += 1
    return {
        "service": "federated-threat-intelligence-hub",
        "status": "healthy",
        "phase": 24,
        "port": 9800,
        "stats": {
            "organisations": len(organisations),
            "indicators": len(indicators),
            "agreements": len(agreements),
            "tier_distribution": dict(tier_dist),
        },
        "timestamp": _now(),
    }


# -- Organisations -----------------------------------------------------------

@app.post("/v1/organisations", status_code=201)
def register_org(body: OrgCreate):
    oid = f"ORG-{uuid.uuid4().hex[:12]}"
    record = OrgRecord(**body.dict(), org_id=oid, created_at=_now())
    organisations[oid] = record
    return record.dict()


@app.get("/v1/organisations")
def list_orgs(
    trust_tier: Optional[TrustTier] = None,
    sector: Optional[str] = None,
):
    results = list(organisations.values())
    if trust_tier:
        results = [o for o in results if o.trust_tier == trust_tier]
    if sector:
        results = [o for o in results if o.sector == sector]
    return {"organisations": [o.dict() for o in results], "total": len(results)}


# -- Indicators --------------------------------------------------------------

@app.post("/v1/indicators", status_code=201)
def publish_indicator(body: IndicatorCreate):
    if body.source_org_id not in organisations:
        raise HTTPException(404, "Source organisation not found")
    iid = f"IOC-{uuid.uuid4().hex[:12]}"
    now = _now()
    stored_value = _hash(body.value) if body.hash_only else body.value
    record = IndicatorRecord(
        indicator_id=iid,
        indicator_type=body.indicator_type.value,
        value=stored_value,
        value_hash=_hash(body.value),
        tlp=body.tlp.value,
        confidence=body.confidence,
        severity=body.severity.value,
        source_org_id=body.source_org_id,
        description=body.description,
        mitre_attack_ids=body.mitre_attack_ids,
        tags=body.tags,
        ttl_hours=body.ttl_hours,
        created_at=now,
        updated_at=now,
    )
    indicators[iid] = record
    return record.dict()


@app.get("/v1/indicators")
def query_indicators(
    indicator_type: Optional[IndicatorType] = None,
    severity: Optional[IndicatorSeverity] = None,
    tlp: Optional[TLPLevel] = None,
    source_org_id: Optional[str] = None,
    tag: Optional[str] = None,
    search: Optional[str] = None,
    requesting_org_id: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    results = list(indicators.values())
    if indicator_type:
        results = [i for i in results if i.indicator_type == indicator_type.value]
    if severity:
        results = [i for i in results if i.severity == severity.value]
    if tlp:
        results = [i for i in results if i.tlp == tlp.value]
    if source_org_id:
        results = [i for i in results if i.source_org_id == source_org_id]
    if tag:
        results = [i for i in results if tag in i.tags]
    if search:
        q = search.lower()
        results = [i for i in results if q in i.description.lower() or q in i.value.lower()]
    # TLP gate
    if requesting_org_id and requesting_org_id in organisations:
        org = organisations[requesting_org_id]
        results = [i for i in results if _can_access_tlp(org, i.tlp)]
    results.sort(key=lambda i: i.created_at, reverse=True)
    return {"indicators": [i.dict() for i in results[:limit]], "total": len(results)}


@app.get("/v1/indicators/{ioc_id}")
def get_indicator(ioc_id: str):
    if ioc_id not in indicators:
        raise HTTPException(404, "Indicator not found")
    return indicators[ioc_id].dict()


@app.post("/v1/indicators/{ioc_id}/sightings", status_code=201)
def report_sighting(ioc_id: str, body: SightingCreate):
    if ioc_id not in indicators:
        raise HTTPException(404, "Indicator not found")
    if body.reporter_org_id not in organisations:
        raise HTTPException(404, "Reporter organisation not found")
    indicator = indicators[ioc_id]
    sighting = {
        "sighting_id": f"SIG-{uuid.uuid4().hex[:8]}",
        "sighting_type": body.sighting_type.value,
        "reporter_org_id": body.reporter_org_id,
        "detail": body.detail,
        "reported_at": _now(),
    }
    indicator.sightings.append(sighting)
    indicator.sighting_count = len(indicator.sightings)

    # Adjust confidence based on sighting type
    confirmed = sum(1 for s in indicator.sightings if s["sighting_type"] == "confirmed")
    false_pos = sum(1 for s in indicator.sightings if s["sighting_type"] == "false_positive")
    if confirmed > false_pos:
        indicator.confidence = min(100, indicator.confidence + 5)
    elif false_pos > confirmed:
        indicator.confidence = max(0, indicator.confidence - 10)
    indicator.updated_at = _now()
    return sighting


# -- Sharing Agreements ------------------------------------------------------

@app.post("/v1/agreements", status_code=201)
def create_agreement(body: AgreementCreate):
    if body.org_a_id not in organisations:
        raise HTTPException(404, f"Organisation {body.org_a_id} not found")
    if body.org_b_id not in organisations:
        raise HTTPException(404, f"Organisation {body.org_b_id} not found")
    aid = f"SA-{uuid.uuid4().hex[:12]}"
    record = AgreementRecord(**body.dict(), agreement_id=aid, created_at=_now())
    agreements[aid] = record
    return record.dict()


@app.get("/v1/agreements")
def list_agreements(org_id: Optional[str] = None, active_only: bool = False):
    results = list(agreements.values())
    if org_id:
        results = [a for a in results if a.org_a_id == org_id or a.org_b_id == org_id]
    if active_only:
        results = [a for a in results if a.active]
    return {"agreements": [a.dict() for a in results], "total": len(results)}


@app.delete("/v1/agreements/{agreement_id}")
def revoke_agreement(agreement_id: str):
    if agreement_id not in agreements:
        raise HTTPException(404, "Agreement not found")
    agreements[agreement_id].active = False
    return {"agreement_id": agreement_id, "active": False}


# -- Feed --------------------------------------------------------------------

@app.get("/v1/feed")
def indicator_feed(
    consumer_org_id: str,
    indicator_type: Optional[IndicatorType] = None,
    severity: Optional[IndicatorSeverity] = None,
    limit: int = Query(default=50, ge=1, le=500),
):
    if consumer_org_id not in organisations:
        raise HTTPException(404, "Consumer organisation not found")
    org = organisations[consumer_org_id]
    results = [i for i in indicators.values() if _can_access_tlp(org, i.tlp)]
    if indicator_type:
        results = [i for i in results if i.indicator_type == indicator_type.value]
    if severity:
        results = [i for i in results if i.severity == severity.value]
    results.sort(key=lambda i: i.created_at, reverse=True)
    return {"feed": [i.dict() for i in results[:limit]], "consumer_org": consumer_org_id, "total": len(results)}


# -- Analytics ----------------------------------------------------------------

@app.get("/v1/analytics")
def analytics():
    type_dist: Dict[str, int] = defaultdict(int)
    sev_dist: Dict[str, int] = defaultdict(int)
    tlp_dist: Dict[str, int] = defaultdict(int)
    src_dist: Dict[str, int] = defaultdict(int)
    for ind in indicators.values():
        type_dist[ind.indicator_type] += 1
        sev_dist[ind.severity] += 1
        tlp_dist[ind.tlp] += 1
        src_dist[ind.source_org_id] += 1

    tier_dist: Dict[str, int] = defaultdict(int)
    for o in organisations.values():
        tier_dist[o.trust_tier.value] += 1

    total_sightings = sum(i.sighting_count for i in indicators.values())
    confirmed_sightings = sum(
        1 for i in indicators.values()
        for s in i.sightings if s["sighting_type"] == "confirmed"
    )

    return {
        "organisations": {
            "total": len(organisations),
            "tier_distribution": dict(tier_dist),
        },
        "indicators": {
            "total": len(indicators),
            "type_distribution": dict(type_dist),
            "severity_distribution": dict(sev_dist),
            "tlp_distribution": dict(tlp_dist),
            "source_distribution": dict(src_dist),
        },
        "sightings": {
            "total": total_sightings,
            "confirmed": confirmed_sightings,
        },
        "agreements": {
            "total": len(agreements),
            "active": sum(1 for a in agreements.values() if a.active),
        },
    }


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9800)
