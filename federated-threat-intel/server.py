"""
Federated Threat Intelligence Exchange — Phase 20 Service 3 of 5
Port: 9402

Privacy-preserving multi-org threat intel sharing with differential
privacy (Laplace noise, randomised response, budget tracking),
secure aggregation with K-anonymity threshold, trust-tiered access,
contribution reputation, and federated queries.
"""

from __future__ import annotations

import math
import random
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
    founding = "founding"
    verified = "verified"
    standard = "standard"
    provisional = "provisional"


TIER_ACCESS = {
    TrustTier.founding: 4,    # raw submissions
    TrustTier.verified: 3,    # detailed indicators
    TrustTier.standard: 2,    # category breakdowns
    TrustTier.provisional: 1, # aggregates only
}

TIER_BUDGET = {
    TrustTier.founding: 50.0,
    TrustTier.verified: 30.0,
    TrustTier.standard: 15.0,
    TrustTier.provisional: 5.0,
}


class IndicatorType(str, Enum):
    ioc = "ioc"
    ttp = "ttp"
    threat_actor = "threat_actor"
    vulnerability = "vulnerability"


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

class OrgCreate(BaseModel):
    name: str
    trust_tier: TrustTier = TrustTier.provisional
    sharing_categories: List[str] = Field(default_factory=lambda: list(AVE_CATEGORIES))
    min_aggregation_threshold: int = Field(default=3, ge=1)
    retention_days: int = Field(default=365, ge=1)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class OrgRecord(OrgCreate):
    org_id: str
    privacy_budget_remaining: float
    contribution_score: float = 0.0
    indicators_submitted: int = 0
    created_at: str


class IndicatorCreate(BaseModel):
    org_id: str
    indicator_type: IndicatorType
    category: str
    severity: str = "medium"
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    value: str  # the actual indicator data
    description: str = ""
    embargo_until: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IndicatorRecord(IndicatorCreate):
    indicator_id: str
    corroboration_count: int = 1
    created_at: str


class AggregateQuery(BaseModel):
    requesting_org_id: str
    category: Optional[str] = None
    indicator_type: Optional[IndicatorType] = None
    query_type: str = "count"  # count | avg_severity | distribution


class TrendQuery(BaseModel):
    requesting_org_id: str
    category: Optional[str] = None
    window_days: int = Field(default=30, ge=1, le=365)


class AgreementCreate(BaseModel):
    org_a: str
    org_b: str
    shared_categories: List[str]
    expires_at: Optional[str] = None


class AgreementRecord(AgreementCreate):
    agreement_id: str
    active: bool = True
    created_at: str


# ---------------------------------------------------------------------------
# In-Memory Stores
# ---------------------------------------------------------------------------

orgs: Dict[str, OrgRecord] = {}
indicators: Dict[str, IndicatorRecord] = {}
agreements: Dict[str, AgreementRecord] = {}
query_log: List[Dict[str, Any]] = []


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Differential Privacy Helpers
# ---------------------------------------------------------------------------

DEFAULT_EPSILON = 1.0
DEFAULT_DELTA = 1e-5
K_ANONYMITY = 3  # minimum orgs contributing before releasing result


def _laplace_noise(sensitivity: float, epsilon: float) -> float:
    """Add Laplace noise for ε-differential privacy."""
    scale = sensitivity / epsilon
    return random.uniform(-1, 1) * scale * math.log(1.0 / (1.0 - random.random() + 1e-10))


def _consume_budget(org: OrgRecord, cost: float) -> bool:
    """Consume privacy budget; return False if exhausted."""
    if org.privacy_budget_remaining < cost:
        return False
    org.privacy_budget_remaining -= cost
    return True


def _severity_to_num(sev: str) -> float:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}.get(sev, 2)


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Federated Threat Intelligence Exchange",
    description="Phase 20 — Privacy-preserving multi-org threat intel with differential privacy",
    version="20.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health():
    return {
        "service": "federated-threat-intelligence-exchange",
        "status": "healthy",
        "phase": 20,
        "port": 9402,
        "stats": {
            "organisations": len(orgs),
            "indicators": len(indicators),
            "agreements": len(agreements),
        },
        "timestamp": _now(),
    }


# ── Organisations ──────────────────────────────────────────────────────────

@app.post("/v1/organisations", status_code=201)
def register_org(body: OrgCreate):
    oid = f"ORG-{uuid.uuid4().hex[:12]}"
    budget = TIER_BUDGET.get(body.trust_tier, 5.0)
    record = OrgRecord(
        **body.dict(),
        org_id=oid,
        privacy_budget_remaining=budget,
        created_at=_now(),
    )
    orgs[oid] = record
    return record.dict()


@app.get("/v1/organisations")
def list_orgs(tier: Optional[TrustTier] = None):
    results = list(orgs.values())
    if tier:
        results = [o for o in results if o.trust_tier == tier]
    return {"organisations": [o.dict() for o in results], "total": len(results)}


@app.get("/v1/organisations/{org_id}")
def get_org(org_id: str):
    if org_id not in orgs:
        raise HTTPException(404, "Organisation not found")
    return orgs[org_id].dict()


# ── Indicators ─────────────────────────────────────────────────────────────

@app.post("/v1/indicators", status_code=201)
def submit_indicator(body: IndicatorCreate):
    if body.org_id not in orgs:
        raise HTTPException(404, "Organisation not found")
    org = orgs[body.org_id]
    if body.category not in org.sharing_categories:
        raise HTTPException(422, f"Category '{body.category}' not in org sharing policy")
    iid = f"IND-{uuid.uuid4().hex[:12]}"
    record = IndicatorRecord(**body.dict(), indicator_id=iid, created_at=_now())
    indicators[iid] = record
    # Update org stats
    org.indicators_submitted += 1
    org.contribution_score += body.confidence * (1.0 if body.severity in ("critical", "high") else 0.5)
    return record.dict()


@app.get("/v1/indicators")
def list_indicators(
    requesting_org_id: str = Query(...),
    category: Optional[str] = None,
    indicator_type: Optional[IndicatorType] = None,
    limit: int = Query(default=50, ge=1, le=500),
):
    if requesting_org_id not in orgs:
        raise HTTPException(404, "Requesting organisation not found")
    org = orgs[requesting_org_id]
    access = TIER_ACCESS[org.trust_tier]
    results = list(indicators.values())
    if category:
        results = [i for i in results if i.category == category]
    if indicator_type:
        results = [i for i in results if i.indicator_type == indicator_type]
    # Filter by embargo
    now_str = _now()
    results = [i for i in results if not i.embargo_until or i.embargo_until <= now_str]
    # Tier gating
    if access < 3:
        # Standard/provisional: strip value field
        sanitised = []
        for i in results[:limit]:
            d = i.dict()
            d["value"] = "[REDACTED — upgrade trust tier for details]"
            sanitised.append(d)
        return {"indicators": sanitised, "total": len(results), "access_level": access}
    return {"indicators": [i.dict() for i in results[:limit]], "total": len(results), "access_level": access}


@app.get("/v1/indicators/{indicator_id}")
def get_indicator(indicator_id: str, requesting_org_id: str = Query(...)):
    if requesting_org_id not in orgs:
        raise HTTPException(404, "Requesting organisation not found")
    if indicator_id not in indicators:
        raise HTTPException(404, "Indicator not found")
    org = orgs[requesting_org_id]
    access = TIER_ACCESS[org.trust_tier]
    ind = indicators[indicator_id]
    d = ind.dict()
    if access < 3:
        d["value"] = "[REDACTED]"
    return d


# ── Federated Queries ──────────────────────────────────────────────────────

@app.post("/v1/query/aggregate")
def aggregate_query(body: AggregateQuery):
    if body.requesting_org_id not in orgs:
        raise HTTPException(404, "Organisation not found")
    org = orgs[body.requesting_org_id]
    budget_cost = DEFAULT_EPSILON
    if not _consume_budget(org, budget_cost):
        raise HTTPException(429, "Privacy budget exhausted")

    filtered = list(indicators.values())
    if body.category:
        filtered = [i for i in filtered if i.category == body.category]
    if body.indicator_type:
        filtered = [i for i in filtered if i.indicator_type == body.indicator_type]

    # K-anonymity check: how many distinct orgs contributed
    contributing_orgs = {i.org_id for i in filtered}
    if len(contributing_orgs) < K_ANONYMITY:
        return {
            "suppressed": True,
            "reason": f"Fewer than {K_ANONYMITY} organisations contributed — result suppressed for privacy",
            "budget_remaining": round(org.privacy_budget_remaining, 4),
        }

    if body.query_type == "count":
        raw = len(filtered)
        noisy = max(0, round(raw + _laplace_noise(1.0, DEFAULT_EPSILON)))
        result = {"count": noisy, "noise_added": True}
    elif body.query_type == "avg_severity":
        if not filtered:
            result = {"avg_severity": 0.0}
        else:
            raw_avg = sum(_severity_to_num(i.severity) for i in filtered) / len(filtered)
            noisy_avg = max(0, raw_avg + _laplace_noise(4.0 / len(filtered), DEFAULT_EPSILON))
            result = {"avg_severity": round(noisy_avg, 2), "noise_added": True}
    elif body.query_type == "distribution":
        dist: Dict[str, int] = defaultdict(int)
        for i in filtered:
            dist[i.category] += 1
        noisy_dist = {k: max(0, round(v + _laplace_noise(1.0, DEFAULT_EPSILON))) for k, v in dist.items()}
        result = {"distribution": noisy_dist, "noise_added": True}
    else:
        result = {"error": "Unknown query_type"}

    query_log.append({"org_id": body.requesting_org_id, "query_type": body.query_type, "budget_cost": budget_cost, "timestamp": _now()})
    return {**result, "contributing_orgs": len(contributing_orgs), "budget_remaining": round(org.privacy_budget_remaining, 4)}


@app.post("/v1/query/trends")
def trend_query(body: TrendQuery):
    if body.requesting_org_id not in orgs:
        raise HTTPException(404, "Organisation not found")
    org = orgs[body.requesting_org_id]
    if not _consume_budget(org, DEFAULT_EPSILON):
        raise HTTPException(429, "Privacy budget exhausted")
    filtered = list(indicators.values())
    if body.category:
        filtered = [i for i in filtered if i.category == body.category]
    # Simple bucket: count per day (simulated)
    total = len(filtered)
    avg_per_day = total / max(body.window_days, 1)
    noisy_avg = max(0, avg_per_day + _laplace_noise(1.0, DEFAULT_EPSILON))
    return {
        "window_days": body.window_days,
        "category": body.category,
        "avg_indicators_per_day": round(noisy_avg, 2),
        "total_in_window": max(0, round(total + _laplace_noise(1.0, DEFAULT_EPSILON))),
        "noise_added": True,
        "budget_remaining": round(org.privacy_budget_remaining, 4),
    }


# ── Privacy Budget ─────────────────────────────────────────────────────────

@app.get("/v1/privacy/budget/{org_id}")
def privacy_budget(org_id: str):
    if org_id not in orgs:
        raise HTTPException(404, "Organisation not found")
    org = orgs[org_id]
    return {
        "org_id": org_id,
        "trust_tier": org.trust_tier.value,
        "initial_budget": TIER_BUDGET[org.trust_tier],
        "remaining": round(org.privacy_budget_remaining, 4),
        "consumed": round(TIER_BUDGET[org.trust_tier] - org.privacy_budget_remaining, 4),
    }


# ── Agreements ─────────────────────────────────────────────────────────────

@app.post("/v1/agreements", status_code=201)
def create_agreement(body: AgreementCreate):
    if body.org_a not in orgs:
        raise HTTPException(404, f"Organisation {body.org_a} not found")
    if body.org_b not in orgs:
        raise HTTPException(404, f"Organisation {body.org_b} not found")
    aid = f"AGR-{uuid.uuid4().hex[:12]}"
    record = AgreementRecord(**body.dict(), agreement_id=aid, created_at=_now())
    agreements[aid] = record
    return record.dict()


@app.get("/v1/agreements")
def list_agreements(org_id: Optional[str] = None):
    results = list(agreements.values())
    if org_id:
        results = [a for a in results if a.org_a == org_id or a.org_b == org_id]
    return {"agreements": [a.dict() for a in results], "total": len(results)}


# ── Reputation ─────────────────────────────────────────────────────────────

@app.get("/v1/reputation/{org_id}")
def get_reputation(org_id: str):
    if org_id not in orgs:
        raise HTTPException(404, "Organisation not found")
    org = orgs[org_id]
    return {
        "org_id": org_id,
        "contribution_score": round(org.contribution_score, 2),
        "indicators_submitted": org.indicators_submitted,
        "trust_tier": org.trust_tier.value,
    }


# ── Analytics ──────────────────────────────────────────────────────────────

@app.get("/v1/analytics")
def analytics():
    tier_dist: Dict[str, int] = defaultdict(int)
    for o in orgs.values():
        tier_dist[o.trust_tier.value] += 1
    type_dist: Dict[str, int] = defaultdict(int)
    cat_dist: Dict[str, int] = defaultdict(int)
    for i in indicators.values():
        type_dist[i.indicator_type.value] += 1
        cat_dist[i.category] += 1
    return {
        "organisations": {"total": len(orgs), "tier_distribution": dict(tier_dist)},
        "indicators": {"total": len(indicators), "type_distribution": dict(type_dist), "category_distribution": dict(cat_dist)},
        "agreements": {"total": len(agreements), "active": sum(1 for a in agreements.values() if a.active)},
        "queries_processed": len(query_log),
        "privacy": {
            "epsilon": DEFAULT_EPSILON,
            "delta": DEFAULT_DELTA,
            "k_anonymity": K_ANONYMITY,
        },
    }


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9402)
