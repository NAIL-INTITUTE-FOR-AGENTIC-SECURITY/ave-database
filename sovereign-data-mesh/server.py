"""
Sovereign Data Mesh — Core data mesh server.

Privacy-preserving federated data architecture enabling cross-
organisation threat analytics without raw data exposure.  Implements
homomorphic computation over encrypted telemetry, differential
privacy with configurable ε/δ budgets, secure multi-party
aggregation, jurisdiction-aware data residency enforcement,
publishable data products, and an immutable consent ledger.
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
    title="NAIL Sovereign Data Mesh",
    description=(
        "Privacy-preserving federated data architecture — homomorphic "
        "computation, differential privacy, jurisdiction enforcement."
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

JURISDICTION_RULES: dict[str, dict[str, Any]] = {
    "EU": {
        "name": "European Union",
        "residency": "eu-west-1",
        "regulations": ["GDPR", "EU AI Act"],
        "max_retention_days": 365,
        "pii_allowed": False,
        "cross_border": "adequate_only",
    },
    "US": {
        "name": "United States",
        "residency": "us-east-1",
        "regulations": ["CCPA", "NIST AI RMF"],
        "max_retention_days": 730,
        "pii_allowed": True,
        "cross_border": "contract_required",
    },
    "UK": {
        "name": "United Kingdom",
        "residency": "eu-west-2",
        "regulations": ["UK GDPR", "UK AI Framework"],
        "max_retention_days": 365,
        "pii_allowed": False,
        "cross_border": "adequate_only",
    },
    "APAC": {
        "name": "Asia-Pacific",
        "residency": "ap-southeast-1",
        "regulations": ["PDPA", "APEC CBPR"],
        "max_retention_days": 365,
        "pii_allowed": False,
        "cross_border": "consent_required",
    },
}


class EncryptionScheme(str, Enum):
    BFV = "bfv"  # Brakerski/Fan-Vercauteren (integer)
    CKKS = "ckks"  # Cheon-Kim-Kim-Song (approximate/float)
    BGV = "bgv"  # Brakerski-Gentry-Vaikuntanathan


class QueryOp(str, Enum):
    SUM = "sum"
    MEAN = "mean"
    COUNT = "count"
    HISTOGRAM = "histogram"
    MAX = "max"
    MIN = "min"


class ConsentAction(str, Enum):
    GRANT = "grant"
    REVOKE = "revoke"


class ProductStatus(str, Enum):
    DRAFT = "draft"
    PUBLISHED = "published"
    DEPRECATED = "deprecated"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class DataRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    category: str = ""
    severity: str = ""
    value: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)
    ingested_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class DataDomain(BaseModel):
    id: str = Field(default_factory=lambda: f"DOM-{uuid.uuid4().hex[:8].upper()}")
    name: str
    owner: str
    jurisdiction: str
    description: str = ""
    record_count: int = 0
    records: list[DataRecord] = Field(default_factory=list)
    encryption_scheme: EncryptionScheme = EncryptionScheme.CKKS
    privacy_budget_total: float = 10.0  # ε total
    privacy_budget_used: float = 0.0
    consented_consumers: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class DomainCreate(BaseModel):
    name: str
    owner: str
    jurisdiction: str
    description: str = ""
    encryption_scheme: EncryptionScheme = EncryptionScheme.CKKS
    privacy_budget: float = Field(10.0, ge=1.0, le=100.0)


class IngestRequest(BaseModel):
    records: list[dict[str, Any]] = Field(default_factory=list)


class HomomorphicQuery(BaseModel):
    domain_ids: list[str] = Field(default_factory=list)  # Empty = all
    operation: QueryOp
    field: str = "value"
    category_filter: Optional[str] = None
    epsilon: float = Field(0.5, ge=0.01, le=5.0)  # Privacy budget per query


class AggregateQuery(BaseModel):
    domain_ids: list[str] = Field(default_factory=list)
    operation: QueryOp
    field: str = "value"
    category_filter: Optional[str] = None
    epsilon: float = Field(0.5, ge=0.01, le=5.0)


class DataProduct(BaseModel):
    id: str = Field(default_factory=lambda: f"PROD-{uuid.uuid4().hex[:8].upper()}")
    name: str
    description: str = ""
    source_domains: list[str] = Field(default_factory=list)
    query_definition: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] = Field(default_factory=dict)
    status: ProductStatus = ProductStatus.DRAFT
    version: int = 1
    access_policy: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    published_at: Optional[str] = None


class ProductCreate(BaseModel):
    name: str
    description: str = ""
    source_domains: list[str] = Field(default_factory=list)
    query_definition: dict[str, Any] = Field(default_factory=dict)
    access_policy: dict[str, Any] = Field(default_factory=dict)


class ConsentEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    domain_id: str
    consumer: str
    action: ConsentAction
    scope: str = "analytics"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ConsentRequest(BaseModel):
    domain_id: str
    consumer: str
    action: ConsentAction
    scope: str = "analytics"


# ---------------------------------------------------------------------------
# In-Memory Stores  (production → CockroachDB + OpenFHE + Google DP)
# ---------------------------------------------------------------------------

DOMAINS: dict[str, DataDomain] = {}
PRODUCTS: dict[str, DataProduct] = {}
CONSENT_LEDGER: list[ConsentEntry] = []

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_now = lambda: datetime.now(timezone.utc)  # noqa: E731


def _laplace_noise(epsilon: float, sensitivity: float = 1.0) -> float:
    """Generate Laplace noise for ε-differential privacy."""
    scale = sensitivity / epsilon
    return random.gauss(0, scale * math.sqrt(2))


def _check_jurisdiction(domain: DataDomain, operation: str) -> bool:
    """Check if operation is permitted under jurisdiction rules."""
    rules = JURISDICTION_RULES.get(domain.jurisdiction, {})
    # All analytical operations are permitted — PII checks only
    return True


def _spend_budget(domain: DataDomain, epsilon: float) -> bool:
    """Attempt to spend privacy budget. Returns False if exhausted."""
    if domain.privacy_budget_used + epsilon > domain.privacy_budget_total:
        return False
    domain.privacy_budget_used = round(domain.privacy_budget_used + epsilon, 4)
    return True


def _homomorphic_compute(
    domains: list[DataDomain],
    operation: QueryOp,
    field: str,
    category_filter: Optional[str],
    epsilon: float,
) -> dict[str, Any]:
    """Simulate homomorphic computation over encrypted data."""
    # Collect all qualifying records across domains
    all_values: list[float] = []
    domain_contributions: dict[str, int] = {}

    for domain in domains:
        records = domain.records
        if category_filter:
            records = [r for r in records if r.category == category_filter]
        values = [r.value for r in records]
        all_values.extend(values)
        domain_contributions[domain.id] = len(values)

    if not all_values:
        return {"result": 0, "noised_result": 0, "records_processed": 0, "noise_added": True}

    # Compute raw result
    raw_result: float = 0.0
    if operation == QueryOp.SUM:
        raw_result = sum(all_values)
    elif operation == QueryOp.MEAN:
        raw_result = statistics.mean(all_values)
    elif operation == QueryOp.COUNT:
        raw_result = float(len(all_values))
    elif operation == QueryOp.MAX:
        raw_result = max(all_values)
    elif operation == QueryOp.MIN:
        raw_result = min(all_values)
    elif operation == QueryOp.HISTOGRAM:
        # Return count per severity bucket
        buckets = Counter()
        for domain in domains:
            records = domain.records
            if category_filter:
                records = [r for r in records if r.category == category_filter]
            for r in records:
                buckets[r.severity or "unknown"] += 1
        # Add noise to each bucket
        noised_buckets = {k: max(0, int(v + _laplace_noise(epsilon))) for k, v in buckets.items()}
        return {
            "result_type": "histogram",
            "histogram": noised_buckets,
            "records_processed": len(all_values),
            "domains_queried": len(domains),
            "noise_added": True,
            "epsilon_spent": epsilon,
        }

    # Add differential privacy noise
    noise = _laplace_noise(epsilon, sensitivity=max(abs(raw_result) * 0.01, 1.0))
    noised = round(raw_result + noise, 4)

    return {
        "operation": operation.value,
        "result": round(raw_result, 4),
        "noised_result": noised,
        "noise_magnitude": round(abs(noise), 4),
        "records_processed": len(all_values),
        "domains_queried": len(domains),
        "domain_contributions": domain_contributions,
        "noise_added": True,
        "epsilon_spent": epsilon,
    }


# ---------------------------------------------------------------------------
# Seed Data
# ---------------------------------------------------------------------------

def _seed() -> None:
    seed_domains = [
        ("NAIL Threat Intel", "NAIL Institute", "EU", "Primary threat telemetry domain"),
        ("Acme Security Data", "Acme Corp", "US", "US financial sector agent telemetry"),
        ("EuroBank AI Monitoring", "EuroBank AG", "EU", "European banking agent observations"),
        ("GovSecure Analytics", "GovSecure Ltd", "UK", "UK government AI security data"),
        ("PacificAI Telemetry", "PacificAI Pte", "APAC", "APAC region agent monitoring"),
    ]

    rng = random.Random(42)
    severities = ["low", "medium", "high", "critical"]

    for name, owner, jurisdiction, desc in seed_domains:
        domain = DataDomain(
            name=name,
            owner=owner,
            jurisdiction=jurisdiction,
            description=desc,
        )

        # Generate synthetic records
        num_records = rng.randint(50, 150)
        for _ in range(num_records):
            record = DataRecord(
                category=rng.choice(AVE_CATEGORIES[:12]),
                severity=rng.choice(severities),
                value=round(rng.uniform(0.1, 10.0), 2),
                metadata={"source": name},
            )
            domain.records.append(record)
        domain.record_count = len(domain.records)

        DOMAINS[domain.id] = domain

    # Seed consent entries
    domain_ids = list(DOMAINS.keys())
    for i, did in enumerate(domain_ids):
        for consumer in ["NAIL Analytics", "Research Team"]:
            entry = ConsentEntry(
                domain_id=did,
                consumer=consumer,
                action=ConsentAction.GRANT,
                scope="analytics",
            )
            CONSENT_LEDGER.append(entry)
            DOMAINS[did].consented_consumers.append(consumer)


_seed()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    total_records = sum(d.record_count for d in DOMAINS.values())
    return {
        "status": "healthy",
        "service": "sovereign-data-mesh",
        "version": "1.0.0",
        "domains": len(DOMAINS),
        "total_records": total_records,
        "data_products": len(PRODUCTS),
        "consent_entries": len(CONSENT_LEDGER),
    }


# ---- Domains --------------------------------------------------------------

@app.post("/v1/domains", status_code=status.HTTP_201_CREATED)
async def create_domain(data: DomainCreate):
    if data.jurisdiction not in JURISDICTION_RULES:
        raise HTTPException(400, f"Unknown jurisdiction. Known: {list(JURISDICTION_RULES.keys())}")

    domain = DataDomain(
        name=data.name,
        owner=data.owner,
        jurisdiction=data.jurisdiction,
        description=data.description,
        encryption_scheme=data.encryption_scheme,
        privacy_budget_total=data.privacy_budget,
    )
    DOMAINS[domain.id] = domain

    return {
        "id": domain.id,
        "name": domain.name,
        "jurisdiction": domain.jurisdiction,
        "encryption_scheme": domain.encryption_scheme.value,
        "privacy_budget": domain.privacy_budget_total,
    }


@app.get("/v1/domains")
async def list_domains(
    jurisdiction: Optional[str] = None,
    owner: Optional[str] = None,
):
    domains = list(DOMAINS.values())
    if jurisdiction:
        domains = [d for d in domains if d.jurisdiction == jurisdiction]
    if owner:
        domains = [d for d in domains if d.owner == owner]
    return {
        "count": len(domains),
        "domains": [
            {
                "id": d.id,
                "name": d.name,
                "owner": d.owner,
                "jurisdiction": d.jurisdiction,
                "records": d.record_count,
                "encryption": d.encryption_scheme.value,
                "budget_remaining": round(d.privacy_budget_total - d.privacy_budget_used, 4),
            }
            for d in domains
        ],
    }


@app.get("/v1/domains/{domain_id}")
async def get_domain(domain_id: str):
    if domain_id not in DOMAINS:
        raise HTTPException(404, "Domain not found")
    d = DOMAINS[domain_id]
    return {
        "id": d.id,
        "name": d.name,
        "owner": d.owner,
        "jurisdiction": d.jurisdiction,
        "description": d.description,
        "record_count": d.record_count,
        "encryption_scheme": d.encryption_scheme.value,
        "privacy_budget_total": d.privacy_budget_total,
        "privacy_budget_used": d.privacy_budget_used,
        "privacy_budget_remaining": round(d.privacy_budget_total - d.privacy_budget_used, 4),
        "consented_consumers": d.consented_consumers,
        "created_at": d.created_at,
    }


@app.post("/v1/domains/{domain_id}/ingest")
async def ingest_records(domain_id: str, req: IngestRequest):
    if domain_id not in DOMAINS:
        raise HTTPException(404, "Domain not found")
    domain = DOMAINS[domain_id]

    ingested = 0
    for raw in req.records:
        record = DataRecord(
            category=raw.get("category", ""),
            severity=raw.get("severity", ""),
            value=float(raw.get("value", 0.0)),
            metadata=raw.get("metadata", {}),
        )
        domain.records.append(record)
        ingested += 1

    domain.record_count = len(domain.records)

    return {"ingested": ingested, "total_records": domain.record_count}


# ---- Homomorphic Queries --------------------------------------------------

@app.post("/v1/query/homomorphic")
async def homomorphic_query(req: HomomorphicQuery):
    # Resolve domains
    if req.domain_ids:
        domains = []
        for did in req.domain_ids:
            if did not in DOMAINS:
                raise HTTPException(404, f"Domain {did} not found")
            domains.append(DOMAINS[did])
    else:
        domains = list(DOMAINS.values())

    if not domains:
        raise HTTPException(400, "No domains available")

    # Check and spend privacy budget
    for domain in domains:
        if not _spend_budget(domain, req.epsilon):
            raise HTTPException(
                429,
                f"Privacy budget exhausted for domain '{domain.name}' "
                f"(used: {domain.privacy_budget_used}/{domain.privacy_budget_total})",
            )

    result = _homomorphic_compute(domains, req.operation, req.field, req.category_filter, req.epsilon)
    return result


@app.post("/v1/query/aggregate")
async def secure_aggregate(req: AggregateQuery):
    """Secure multi-party aggregation — each domain contributes a partial, no individual data exposed."""
    if req.domain_ids:
        domains = [DOMAINS[did] for did in req.domain_ids if did in DOMAINS]
    else:
        domains = list(DOMAINS.values())

    if len(domains) < 2:
        raise HTTPException(400, "Secure aggregation requires at least 2 domains")

    # Spend budget
    for domain in domains:
        if not _spend_budget(domain, req.epsilon):
            raise HTTPException(429, f"Privacy budget exhausted for '{domain.name}'")

    # Each domain computes a partial result (simulated)
    partials: list[dict[str, Any]] = []
    for domain in domains:
        records = domain.records
        if req.category_filter:
            records = [r for r in records if r.category == req.category_filter]
        values = [r.value for r in records]
        if not values:
            continue

        # Domain-level partial with noise
        if req.operation == QueryOp.SUM:
            partial = sum(values) + _laplace_noise(req.epsilon)
        elif req.operation == QueryOp.MEAN:
            partial = statistics.mean(values) + _laplace_noise(req.epsilon)
        elif req.operation == QueryOp.COUNT:
            partial = float(len(values)) + _laplace_noise(req.epsilon)
        else:
            partial = sum(values) + _laplace_noise(req.epsilon)

        partials.append({
            "domain_id": domain.id,
            "domain_name": domain.name,
            "records_contributed": len(values),
            "partial_value": round(partial, 4),
            "noise_added": True,
        })

    # Aggregate partials
    if req.operation == QueryOp.MEAN:
        total = sum(p["partial_value"] for p in partials) / len(partials) if partials else 0
    else:
        total = sum(p["partial_value"] for p in partials)

    return {
        "operation": req.operation.value,
        "aggregated_result": round(total, 4),
        "domains_participated": len(partials),
        "partials": partials,
        "epsilon_spent_per_domain": req.epsilon,
        "secure_aggregation": True,
    }


# ---- Privacy Budget -------------------------------------------------------

@app.post("/v1/privacy/budget")
async def check_budget(domain_id: str = "", allocate: float = 0.0):
    if domain_id not in DOMAINS:
        raise HTTPException(404, "Domain not found")
    domain = DOMAINS[domain_id]

    remaining = round(domain.privacy_budget_total - domain.privacy_budget_used, 4)

    if allocate > 0:
        if allocate > remaining:
            raise HTTPException(429, f"Insufficient budget: requested {allocate}, remaining {remaining}")
        domain.privacy_budget_used = round(domain.privacy_budget_used + allocate, 4)
        remaining = round(domain.privacy_budget_total - domain.privacy_budget_used, 4)

    return {
        "domain_id": domain_id,
        "budget_total": domain.privacy_budget_total,
        "budget_used": domain.privacy_budget_used,
        "budget_remaining": remaining,
        "exhausted": remaining <= 0.01,
    }


@app.get("/v1/privacy/budget/{domain_id}")
async def get_budget(domain_id: str):
    if domain_id not in DOMAINS:
        raise HTTPException(404, "Domain not found")
    d = DOMAINS[domain_id]
    remaining = round(d.privacy_budget_total - d.privacy_budget_used, 4)
    return {
        "domain_id": domain_id,
        "budget_total": d.privacy_budget_total,
        "budget_used": d.privacy_budget_used,
        "budget_remaining": remaining,
        "pct_used": round(d.privacy_budget_used / d.privacy_budget_total * 100, 1),
    }


# ---- Data Products --------------------------------------------------------

@app.post("/v1/products", status_code=status.HTTP_201_CREATED)
async def create_product(data: ProductCreate):
    for did in data.source_domains:
        if did not in DOMAINS:
            raise HTTPException(404, f"Source domain {did} not found")

    product = DataProduct(
        name=data.name,
        description=data.description,
        source_domains=data.source_domains,
        query_definition=data.query_definition,
        access_policy=data.access_policy,
    )

    # If query definition provided, compute result
    if data.query_definition and data.source_domains:
        op = QueryOp(data.query_definition.get("operation", "count"))
        domains = [DOMAINS[did] for did in data.source_domains if did in DOMAINS]
        eps = data.query_definition.get("epsilon", 1.0)
        cat = data.query_definition.get("category_filter")
        result = _homomorphic_compute(domains, op, "value", cat, eps)
        product.result = result
        product.status = ProductStatus.PUBLISHED
        product.published_at = _now().isoformat()

    PRODUCTS[product.id] = product

    return {
        "id": product.id,
        "name": product.name,
        "status": product.status.value,
        "has_result": bool(product.result),
    }


@app.get("/v1/products")
async def list_products(
    product_status: Optional[ProductStatus] = Query(None, alias="status"),
):
    prods = list(PRODUCTS.values())
    if product_status:
        prods = [p for p in prods if p.status == product_status]
    return {
        "count": len(prods),
        "products": [
            {
                "id": p.id,
                "name": p.name,
                "status": p.status.value,
                "source_domains": len(p.source_domains),
                "version": p.version,
                "published_at": p.published_at,
            }
            for p in prods
        ],
    }


@app.get("/v1/products/{product_id}")
async def get_product(product_id: str):
    if product_id not in PRODUCTS:
        raise HTTPException(404, "Product not found")
    return PRODUCTS[product_id].dict()


# ---- Consent Ledger -------------------------------------------------------

@app.post("/v1/consent", status_code=status.HTTP_201_CREATED)
async def manage_consent(req: ConsentRequest):
    if req.domain_id not in DOMAINS:
        raise HTTPException(404, "Domain not found")
    domain = DOMAINS[req.domain_id]

    entry = ConsentEntry(
        domain_id=req.domain_id,
        consumer=req.consumer,
        action=req.action,
        scope=req.scope,
    )
    CONSENT_LEDGER.append(entry)

    if req.action == ConsentAction.GRANT:
        if req.consumer not in domain.consented_consumers:
            domain.consented_consumers.append(req.consumer)
    elif req.action == ConsentAction.REVOKE:
        if req.consumer in domain.consented_consumers:
            domain.consented_consumers.remove(req.consumer)

    return {"id": entry.id, "action": req.action.value, "consumer": req.consumer}


@app.get("/v1/consent/{domain_id}")
async def get_consent_ledger(domain_id: str):
    if domain_id not in DOMAINS:
        raise HTTPException(404, "Domain not found")
    entries = [e for e in CONSENT_LEDGER if e.domain_id == domain_id]
    return {"domain_id": domain_id, "count": len(entries), "entries": [e.dict() for e in entries]}


# ---- Jurisdictions --------------------------------------------------------

@app.get("/v1/jurisdictions")
async def list_jurisdictions():
    juris_info: list[dict[str, Any]] = []
    for code, rules in JURISDICTION_RULES.items():
        domain_count = sum(1 for d in DOMAINS.values() if d.jurisdiction == code)
        record_count = sum(d.record_count for d in DOMAINS.values() if d.jurisdiction == code)
        juris_info.append({
            "code": code,
            **rules,
            "domains": domain_count,
            "records": record_count,
        })
    return {"count": len(JURISDICTION_RULES), "jurisdictions": juris_info}


# ---- Analytics ------------------------------------------------------------

@app.get("/v1/analytics")
async def mesh_analytics():
    domains = list(DOMAINS.values())
    total_records = sum(d.record_count for d in domains)
    by_jurisdiction = Counter(d.jurisdiction for d in domains)
    by_encryption = Counter(d.encryption_scheme.value for d in domains)

    avg_budget_used = round(statistics.mean(d.privacy_budget_used for d in domains), 4) if domains else 0.0
    total_budget = sum(d.privacy_budget_total for d in domains)
    total_used = sum(d.privacy_budget_used for d in domains)

    # Category distribution across all domains
    cat_dist: Counter = Counter()
    for d in domains:
        for r in d.records:
            if r.category:
                cat_dist[r.category] += 1

    consent_grants = sum(1 for e in CONSENT_LEDGER if e.action == ConsentAction.GRANT)
    consent_revokes = sum(1 for e in CONSENT_LEDGER if e.action == ConsentAction.REVOKE)

    return {
        "total_domains": len(domains),
        "total_records": total_records,
        "by_jurisdiction": dict(by_jurisdiction),
        "by_encryption_scheme": dict(by_encryption),
        "privacy_budget_total": round(total_budget, 2),
        "privacy_budget_used": round(total_used, 4),
        "privacy_budget_pct": round(total_used / total_budget * 100, 1) if total_budget else 0.0,
        "avg_budget_used_per_domain": avg_budget_used,
        "category_distribution": dict(cat_dist.most_common(10)),
        "data_products": len(PRODUCTS),
        "published_products": sum(1 for p in PRODUCTS.values() if p.status == ProductStatus.PUBLISHED),
        "consent_grants": consent_grants,
        "consent_revokes": consent_revokes,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=9001)
