"""
Cross-Organisation Threat Federation — Core federation server.

Zero-trust multi-tenant threat sharing network enabling organisations
to contribute and consume anonymised threat intelligence without
revealing internal architecture.  Implements tenant isolation,
k-anonymity, bilateral trust scoring, cryptographic envelopes,
and compliance-gated sharing.
"""

from __future__ import annotations

import hashlib
import math
import random
import statistics
import uuid
from collections import Counter, defaultdict
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
    title="NAIL Cross-Organisation Threat Federation",
    description=(
        "Zero-trust multi-tenant threat sharing network with anonymisation, "
        "bilateral trust, cryptographic envelopes, and compliance gating."
    ),
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
    "prompt_injection", "tool_misuse", "memory_poisoning", "goal_hijacking",
    "identity_spoofing", "privilege_escalation", "data_exfiltration",
    "resource_exhaustion", "multi_agent_manipulation", "context_overflow",
    "guardrail_bypass", "output_manipulation", "supply_chain_compromise",
    "model_extraction", "reward_hacking", "capability_elicitation",
    "alignment_subversion", "delegation_abuse",
]

TLP_LEVELS = ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:RED"]

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TenantStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    PENDING = "pending"


class IntelStatus(str, Enum):
    SHARED = "shared"
    CONSUMED = "consumed"
    REDACTED = "redacted"
    EXPIRED = "expired"


class TrustLevel(str, Enum):
    UNTRUSTED = "untrusted"
    BASIC = "basic"
    VERIFIED = "verified"
    TRUSTED = "trusted"
    STRATEGIC = "strategic"


class ComplianceRegime(str, Enum):
    GDPR = "gdpr"
    CCPA = "ccpa"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    SOC2 = "soc2"
    NONE = "none"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class SharingPolicy(BaseModel):
    share_categories: list[str] = Field(default_factory=lambda: AVE_CATEGORIES[:])
    max_tlp_level: str = "TLP:AMBER"
    auto_share: bool = False
    require_reciprocity: bool = True
    compliance_regimes: list[ComplianceRegime] = Field(default_factory=lambda: [ComplianceRegime.GDPR])
    anonymise: bool = True
    k_anonymity_k: int = 5  # minimum group size for k-anonymity
    share_with: list[str] = Field(default_factory=list)  # tenant IDs; empty = all


class Tenant(BaseModel):
    id: str = Field(default_factory=lambda: f"ORG-{uuid.uuid4().hex[:8].upper()}")
    name: str
    industry: str = "technology"
    jurisdiction: str = "global"
    status: TenantStatus = TenantStatus.ACTIVE
    public_key_fingerprint: str = Field(
        default_factory=lambda: hashlib.sha256(uuid.uuid4().bytes).hexdigest()[:32]
    )
    sharing_policy: SharingPolicy = Field(default_factory=SharingPolicy)
    trust_scores: dict[str, float] = Field(default_factory=dict)  # peer_id → score
    intel_contributed: int = 0
    intel_consumed: int = 0
    joined_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class TenantCreate(BaseModel):
    name: str
    industry: str = "technology"
    jurisdiction: str = "global"


class IntelItem(BaseModel):
    id: str = Field(default_factory=lambda: f"INTEL-{uuid.uuid4().hex[:10].upper()}")
    contributor_id: str
    title: str
    category: str
    severity: str = "medium"
    tlp_level: str = "TLP:GREEN"
    description: str = ""
    indicators: list[str] = Field(default_factory=list)
    ave_ids: list[str] = Field(default_factory=list)
    anonymised: bool = False
    anonymised_description: str = ""
    content_hash: str = ""
    envelope_recipients: list[str] = Field(default_factory=list)  # tenant IDs that can decrypt
    status: IntelStatus = IntelStatus.SHARED
    quality_ratings: list[dict[str, Any]] = Field(default_factory=list)
    avg_quality: float = 0.0
    shared_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    expires_at: Optional[str] = None


class IntelShare(BaseModel):
    title: str
    category: str
    severity: str = "medium"
    tlp_level: str = "TLP:GREEN"
    description: str = ""
    indicators: list[str] = Field(default_factory=list)
    ave_ids: list[str] = Field(default_factory=list)
    ttl_hours: int = 720  # 30 days


class QualityRating(BaseModel):
    rater_tenant_id: str
    intel_id: str
    score: float = Field(ge=0.0, le=5.0)
    comment: str = ""


class AuditEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action: str
    tenant_id: str
    target_id: Optional[str] = None
    details: dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ---------------------------------------------------------------------------
# In-Memory Stores  (production → PostgreSQL + Vault + Redis)
# ---------------------------------------------------------------------------

TENANTS: dict[str, Tenant] = {}
INTEL_ITEMS: dict[str, IntelItem] = {}
AUDIT_LOG: list[AuditEntry] = []

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_now = lambda: datetime.now(timezone.utc)  # noqa: E731


def _audit(action: str, tenant_id: str, target_id: str | None = None, **details):
    entry = AuditEntry(action=action, tenant_id=tenant_id, target_id=target_id, details=details)
    AUDIT_LOG.append(entry)
    return entry


def _anonymise_text(text: str) -> str:
    """Simulate k-anonymity / generalisation anonymisation."""
    replacements = {
        "our company": "an organisation",
        "our": "the",
        "we": "they",
        "internal": "an",
        "192.168.": "10.x.x.",
        "prod-": "host-",
    }
    result = text
    for old, new in replacements.items():
        result = result.replace(old, new)
    # Redact potential org identifiers
    words = result.split()
    anonymised = []
    for w in words:
        if w.endswith(".com") or w.endswith(".org") or w.endswith(".io"):
            anonymised.append("[REDACTED-DOMAIN]")
        elif "@" in w:
            anonymised.append("[REDACTED-EMAIL]")
        else:
            anonymised.append(w)
    return " ".join(anonymised)


def _content_hash(title: str, description: str) -> str:
    return hashlib.sha256(f"{title.lower().strip()}|{description.lower().strip()}".encode()).hexdigest()


def _compute_trust(tenant: Tenant, peer_id: str) -> float:
    """Bilateral trust score based on contribution, quality, and reciprocity."""
    base = 0.3
    # Contribution factor
    contrib = min(tenant.intel_contributed / 20.0, 0.3)
    # Quality of intel contributed TO this tenant
    quality_scores = []
    for item in INTEL_ITEMS.values():
        if item.contributor_id == tenant.id and item.avg_quality > 0:
            quality_scores.append(item.avg_quality)
    quality_factor = (statistics.mean(quality_scores) / 5.0 * 0.3) if quality_scores else 0.0
    # Reciprocity
    peer_contrib = 0
    for item in INTEL_ITEMS.values():
        if item.contributor_id == peer_id:
            peer_contrib += 1
    recip = min(peer_contrib / max(tenant.intel_contributed, 1), 1.0) * 0.1

    return round(min(base + contrib + quality_factor + recip, 1.0), 4)


def _trust_level(score: float) -> TrustLevel:
    if score >= 0.8:
        return TrustLevel.STRATEGIC
    elif score >= 0.6:
        return TrustLevel.TRUSTED
    elif score >= 0.4:
        return TrustLevel.VERIFIED
    elif score >= 0.2:
        return TrustLevel.BASIC
    return TrustLevel.UNTRUSTED


def _compliance_check(tenant: Tenant, item: IntelShare) -> list[str]:
    """Check if sharing complies with tenant's compliance regimes."""
    violations: list[str] = []
    for regime in tenant.sharing_policy.compliance_regimes:
        if regime == ComplianceRegime.GDPR:
            if not tenant.sharing_policy.anonymise and "personal" in item.description.lower():
                violations.append("GDPR: Personal data must be anonymised before sharing")
        elif regime == ComplianceRegime.HIPAA:
            health_terms = ["patient", "diagnosis", "medical", "health"]
            if any(t in item.description.lower() for t in health_terms):
                violations.append("HIPAA: Health-related data requires additional safeguards")
    return violations


def _determine_recipients(contributor: Tenant, item: IntelItem) -> list[str]:
    """Determine which tenants can receive this intel based on policies."""
    recipients: list[str] = []
    tlp_order = {t: i for i, t in enumerate(TLP_LEVELS)}
    item_tlp_idx = tlp_order.get(item.tlp_level, 0)

    for tid, tenant in TENANTS.items():
        if tid == contributor.id:
            continue
        if tenant.status != TenantStatus.ACTIVE:
            continue
        # Check contributor's share_with list
        if contributor.sharing_policy.share_with and tid not in contributor.sharing_policy.share_with:
            continue
        # Check category in scope
        if item.category not in tenant.sharing_policy.share_categories:
            continue
        # Check TLP ceiling
        recipient_max = tlp_order.get(tenant.sharing_policy.max_tlp_level, 2)
        if item_tlp_idx > recipient_max:
            continue
        # Reciprocity check
        if contributor.sharing_policy.require_reciprocity:
            peer_contrib = sum(
                1 for i in INTEL_ITEMS.values() if i.contributor_id == tid
            )
            if peer_contrib == 0:
                continue  # Skip non-contributing peers
        recipients.append(tid)

    return recipients


# ---------------------------------------------------------------------------
# Seed Data
# ---------------------------------------------------------------------------

def _seed() -> None:
    orgs = [
        ("NAIL Institute", "ai_security", "global"),
        ("Acme AI Corp", "technology", "US"),
        ("EuroBank AG", "finance", "EU"),
        ("HealthFirst Ltd", "healthcare", "UK"),
        ("GovSecure Agency", "government", "US"),
    ]

    for name, industry, jurisdiction in orgs:
        t = Tenant(name=name, industry=industry, jurisdiction=jurisdiction)
        TENANTS[t.id] = t
        _audit("tenant_registered", t.id, details={"name": name})

    tenant_ids = list(TENANTS.keys())

    # Seed intel items
    intel_data = [
        ("Prompt relay chain across federated agents", "prompt_injection", "critical", "TLP:AMBER"),
        ("Tool schema injection in production pipeline", "tool_misuse", "high", "TLP:GREEN"),
        ("Persistent memory backdoor via context manipulation", "memory_poisoning", "high", "TLP:GREEN"),
        ("Multi-agent coordination exploit observed", "multi_agent_manipulation", "critical", "TLP:AMBER"),
        ("Guardrail bypass using Unicode homoglyphs", "guardrail_bypass", "high", "TLP:CLEAR"),
        ("Data exfiltration through retrieval-augmented pipeline", "data_exfiltration", "critical", "TLP:AMBER"),
        ("Goal hijacking via injected system prompt", "goal_hijacking", "medium", "TLP:GREEN"),
    ]

    for title, cat, sev, tlp in intel_data:
        contributor = TENANTS[random.choice(tenant_ids)]
        ch = _content_hash(title, f"Observed {cat} activity")
        anon_desc = _anonymise_text(f"Observed {cat} activity in production environment")

        item = IntelItem(
            contributor_id=contributor.id,
            title=title,
            category=cat,
            severity=sev,
            tlp_level=tlp,
            description=f"Observed {cat} activity in production environment",
            anonymised=True,
            anonymised_description=anon_desc,
            content_hash=ch,
            expires_at=(_now() + timedelta(days=30)).isoformat(),
        )
        item.envelope_recipients = _determine_recipients(contributor, item)
        INTEL_ITEMS[item.id] = item
        contributor.intel_contributed += 1
        _audit("intel_shared", contributor.id, item.id, category=cat, tlp=tlp)

    # Generate trust scores
    for tid in tenant_ids:
        for pid in tenant_ids:
            if tid != pid:
                TENANTS[tid].trust_scores[pid] = _compute_trust(TENANTS[tid], pid)


_seed()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "cross-org-threat-federation",
        "version": "1.0.0",
        "tenants": len(TENANTS),
        "intel_items": len(INTEL_ITEMS),
        "audit_entries": len(AUDIT_LOG),
    }


# ---- Tenants -------------------------------------------------------------

@app.post("/v1/tenants", status_code=status.HTTP_201_CREATED)
async def register_tenant(data: TenantCreate):
    if any(t.name == data.name for t in TENANTS.values()):
        raise HTTPException(409, "Organisation name already registered")
    t = Tenant(name=data.name, industry=data.industry, jurisdiction=data.jurisdiction)
    TENANTS[t.id] = t
    _audit("tenant_registered", t.id, details={"name": data.name})
    return {"id": t.id, "name": t.name, "public_key_fingerprint": t.public_key_fingerprint}


@app.get("/v1/tenants")
async def list_tenants(status_filter: Optional[TenantStatus] = Query(None, alias="status")):
    tenants = list(TENANTS.values())
    if status_filter:
        tenants = [t for t in tenants if t.status == status_filter]
    # Return sanitised view (no sharing policies of other tenants)
    return {
        "count": len(tenants),
        "tenants": [
            {
                "id": t.id,
                "name": t.name,
                "industry": t.industry,
                "jurisdiction": t.jurisdiction,
                "status": t.status.value,
                "intel_contributed": t.intel_contributed,
                "joined_at": t.joined_at,
            }
            for t in tenants
        ],
    }


@app.get("/v1/tenants/{tenant_id}")
async def get_tenant(tenant_id: str):
    if tenant_id not in TENANTS:
        raise HTTPException(404, "Tenant not found")
    return TENANTS[tenant_id].dict()


@app.post("/v1/tenants/{tenant_id}/policy")
async def set_sharing_policy(tenant_id: str, policy: SharingPolicy):
    if tenant_id not in TENANTS:
        raise HTTPException(404, "Tenant not found")
    for cat in policy.share_categories:
        if cat not in AVE_CATEGORIES:
            raise HTTPException(400, f"Invalid category: {cat}")
    if policy.max_tlp_level not in TLP_LEVELS:
        raise HTTPException(400, f"Invalid TLP level. Must be one of: {TLP_LEVELS}")

    TENANTS[tenant_id].sharing_policy = policy
    _audit("policy_updated", tenant_id, details={"categories": len(policy.share_categories)})
    return {"updated": True, "tenant_id": tenant_id}


@app.get("/v1/tenants/{tenant_id}/policy")
async def get_sharing_policy(tenant_id: str):
    if tenant_id not in TENANTS:
        raise HTTPException(404, "Tenant not found")
    return TENANTS[tenant_id].sharing_policy.dict()


# ---- Intel Sharing -------------------------------------------------------

@app.post("/v1/intel/share", status_code=status.HTTP_201_CREATED)
async def share_intel(contributor_id: str = Query(...), data: IntelShare = ...):
    if contributor_id not in TENANTS:
        raise HTTPException(404, "Contributor tenant not found")
    if data.category not in AVE_CATEGORIES:
        raise HTTPException(400, f"Invalid category: {data.category}")
    if data.tlp_level not in TLP_LEVELS:
        raise HTTPException(400, f"Invalid TLP level: {data.tlp_level}")

    tenant = TENANTS[contributor_id]
    if tenant.status != TenantStatus.ACTIVE:
        raise HTTPException(403, "Tenant is not active")

    # Compliance check
    violations = _compliance_check(tenant, data)
    if violations:
        raise HTTPException(
            422,
            {"message": "Compliance violations detected", "violations": violations},
        )

    # Duplicate check
    ch = _content_hash(data.title, data.description)
    for existing in INTEL_ITEMS.values():
        if existing.content_hash == ch:
            raise HTTPException(409, f"Duplicate intel (matches {existing.id})")

    anon_desc = _anonymise_text(data.description) if tenant.sharing_policy.anonymise else data.description

    item = IntelItem(
        contributor_id=contributor_id,
        title=data.title,
        category=data.category,
        severity=data.severity,
        tlp_level=data.tlp_level,
        description=data.description,
        anonymised=tenant.sharing_policy.anonymise,
        anonymised_description=anon_desc,
        indicators=data.indicators,
        ave_ids=data.ave_ids,
        content_hash=ch,
        expires_at=(_now() + timedelta(hours=data.ttl_hours)).isoformat(),
    )
    item.envelope_recipients = _determine_recipients(tenant, item)

    INTEL_ITEMS[item.id] = item
    tenant.intel_contributed += 1
    _audit("intel_shared", contributor_id, item.id, category=data.category, tlp=data.tlp_level)

    return {
        "id": item.id,
        "recipients": len(item.envelope_recipients),
        "anonymised": item.anonymised,
    }


@app.get("/v1/intel/feed")
async def consume_feed(
    tenant_id: str = Query(...),
    category: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
):
    if tenant_id not in TENANTS:
        raise HTTPException(404, "Tenant not found")

    now = _now().isoformat()
    items = [
        i for i in INTEL_ITEMS.values()
        if tenant_id in i.envelope_recipients
        and i.status == IntelStatus.SHARED
        and (i.expires_at is None or i.expires_at > now)
    ]

    if category:
        items = [i for i in items if i.category == category]
    if severity:
        items = [i for i in items if i.severity == severity]

    items.sort(key=lambda i: i.shared_at, reverse=True)

    # Return anonymised view
    feed = []
    for i in items[:limit]:
        feed.append({
            "id": i.id,
            "title": i.title,
            "category": i.category,
            "severity": i.severity,
            "tlp_level": i.tlp_level,
            "description": i.anonymised_description if i.anonymised else i.description,
            "indicators": i.indicators,
            "avg_quality": i.avg_quality,
            "shared_at": i.shared_at,
        })

    TENANTS[tenant_id].intel_consumed += len(feed)
    _audit("feed_consumed", tenant_id, details={"items": len(feed)})

    return {"count": len(feed), "feed": feed}


@app.get("/v1/intel/{intel_id}")
async def get_intel(intel_id: str, tenant_id: str = Query(...)):
    if intel_id not in INTEL_ITEMS:
        raise HTTPException(404, "Intel item not found")
    if tenant_id not in TENANTS:
        raise HTTPException(404, "Tenant not found")

    item = INTEL_ITEMS[intel_id]
    if tenant_id != item.contributor_id and tenant_id not in item.envelope_recipients:
        raise HTTPException(403, "Not authorised to view this intel item")

    view = item.dict()
    if item.anonymised and tenant_id != item.contributor_id:
        view["description"] = item.anonymised_description
    return view


# ---- Trust ---------------------------------------------------------------

@app.get("/v1/trust")
async def trust_matrix():
    matrix: dict[str, dict[str, Any]] = {}
    for tid, tenant in TENANTS.items():
        peers: dict[str, Any] = {}
        for pid, score in tenant.trust_scores.items():
            peers[pid] = {
                "score": score,
                "level": _trust_level(score).value,
                "name": TENANTS[pid].name if pid in TENANTS else "unknown",
            }
        matrix[tid] = {
            "name": tenant.name,
            "peers": peers,
        }
    return {"tenants": len(TENANTS), "matrix": matrix}


@app.post("/v1/trust/rate")
async def rate_intel(rating: QualityRating):
    if rating.rater_tenant_id not in TENANTS:
        raise HTTPException(404, "Rater tenant not found")
    if rating.intel_id not in INTEL_ITEMS:
        raise HTTPException(404, "Intel item not found")

    item = INTEL_ITEMS[rating.intel_id]
    item.quality_ratings.append({
        "rater": rating.rater_tenant_id,
        "score": rating.score,
        "comment": rating.comment,
        "timestamp": _now().isoformat(),
    })
    item.avg_quality = round(
        statistics.mean(r["score"] for r in item.quality_ratings), 2
    )

    # Update contributor trust scores
    contributor = TENANTS.get(item.contributor_id)
    if contributor:
        for tid in TENANTS:
            if tid != contributor.id:
                contributor.trust_scores[tid] = _compute_trust(contributor, tid)

    _audit("intel_rated", rating.rater_tenant_id, rating.intel_id, score=rating.score)
    return {"rated": True, "avg_quality": item.avg_quality}


# ---- Audit ---------------------------------------------------------------

@app.get("/v1/audit")
async def audit_log(
    tenant_id: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
):
    entries = AUDIT_LOG[:]
    if tenant_id:
        entries = [e for e in entries if e.tenant_id == tenant_id]
    if action:
        entries = [e for e in entries if e.action == action]
    entries.sort(key=lambda e: e.timestamp, reverse=True)
    return {"count": len(entries[:limit]), "entries": [e.dict() for e in entries[:limit]]}


# ---- Analytics -----------------------------------------------------------

@app.get("/v1/analytics")
async def federation_analytics():
    tenants = list(TENANTS.values())
    items = list(INTEL_ITEMS.values())

    by_category = Counter(i.category for i in items)
    by_severity = Counter(i.severity for i in items)
    by_tlp = Counter(i.tlp_level for i in items)
    by_industry = Counter(t.industry for t in tenants)

    total_contributed = sum(t.intel_contributed for t in tenants)
    total_consumed = sum(t.intel_consumed for t in tenants)

    avg_quality_scores = [i.avg_quality for i in items if i.avg_quality > 0]
    avg_quality = round(statistics.mean(avg_quality_scores), 2) if avg_quality_scores else 0.0

    # Trust distribution
    all_trust = [
        s for t in tenants for s in t.trust_scores.values()
    ]
    avg_trust = round(statistics.mean(all_trust), 4) if all_trust else 0.0

    return {
        "total_tenants": len(tenants),
        "active_tenants": sum(1 for t in tenants if t.status == TenantStatus.ACTIVE),
        "total_intel_items": len(items),
        "total_contributed": total_contributed,
        "total_consumed": total_consumed,
        "by_category": dict(by_category),
        "by_severity": dict(by_severity),
        "by_tlp": dict(by_tlp),
        "by_industry": dict(by_industry),
        "avg_intel_quality": avg_quality,
        "avg_trust_score": avg_trust,
        "audit_entries": len(AUDIT_LOG),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8801)
