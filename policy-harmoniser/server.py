"""
Cross-Org Policy Harmoniser — Phase 24 Service 3 of 5
Port: 9802

Policy alignment engine that reconciles security policies across
organisational boundaries with conflict detection, resolution
strategies, and harmonised policy generation.
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

class PolicyDomain(str, Enum):
    access_control = "access_control"
    data_handling = "data_handling"
    incident_response = "incident_response"
    encryption = "encryption"
    retention = "retention"
    ai_governance = "ai_governance"
    network_security = "network_security"
    identity_management = "identity_management"


class EnforcementLevel(str, Enum):
    mandatory = "mandatory"
    recommended = "recommended"
    advisory = "advisory"
    informational = "informational"


ENFORCEMENT_WEIGHT = {"mandatory": 4, "recommended": 3, "advisory": 2, "informational": 1}


class RuleEffect(str, Enum):
    allow = "allow"
    deny = "deny"
    require = "require"
    restrict = "restrict"
    audit = "audit"


class ConflictType(str, Enum):
    direct_contradiction = "direct_contradiction"
    scope_overlap = "scope_overlap"
    precedence_ambiguity = "precedence_ambiguity"
    jurisdiction_clash = "jurisdiction_clash"
    enforcement_mismatch = "enforcement_mismatch"


class ResolutionStrategy(str, Enum):
    strictest_wins = "strictest_wins"
    most_permissive = "most_permissive"
    weighted_merge = "weighted_merge"
    manual_review = "manual_review"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class PolicyCreate(BaseModel):
    title: str
    organisation: str
    domain: PolicyDomain
    enforcement: EnforcementLevel = EnforcementLevel.mandatory
    jurisdictions: List[str] = Field(default_factory=list)
    description: str = ""
    version: str = "1.0.0"


class PolicyRecord(PolicyCreate):
    policy_id: str
    rules: List[Dict[str, Any]] = Field(default_factory=list)
    version_history: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: str
    updated_at: str


class RuleCreate(BaseModel):
    subject: str
    action: str
    resource: str
    condition: str = ""
    effect: RuleEffect = RuleEffect.require
    priority: int = Field(default=50, ge=1, le=100)
    description: str = ""


class HarmoniseRequest(BaseModel):
    organisations: List[str]
    domains: List[PolicyDomain] = Field(default_factory=list)
    strategy: ResolutionStrategy = ResolutionStrategy.strictest_wins
    description: str = ""


class SessionRecord(BaseModel):
    session_id: str
    organisations: List[str]
    domains: List[str]
    strategy: str
    description: str
    conflicts: List[Dict[str, Any]] = Field(default_factory=list)
    resolutions: List[Dict[str, Any]] = Field(default_factory=list)
    harmonised_rules: List[Dict[str, Any]] = Field(default_factory=list)
    gaps: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: str


# ---------------------------------------------------------------------------
# In-Memory Stores
# ---------------------------------------------------------------------------

policies: Dict[str, PolicyRecord] = {}
sessions: Dict[str, SessionRecord] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Conflict Detection & Resolution
# ---------------------------------------------------------------------------

def _detect_conflicts(policy_a: PolicyRecord, policy_b: PolicyRecord) -> List[Dict[str, Any]]:
    """Detect pairwise conflicts between two policies."""
    conflicts = []

    for ra in policy_a.rules:
        for rb in policy_b.rules:
            # Same resource + subject → potential conflict
            if ra.get("resource") == rb.get("resource") and ra.get("subject") == rb.get("subject"):
                # Direct contradiction: allow vs deny / require vs restrict
                if ({ra.get("effect"), rb.get("effect")} in
                    [{"allow", "deny"}, {"require", "restrict"}]):
                    conflicts.append({
                        "type": ConflictType.direct_contradiction.value,
                        "policy_a": policy_a.policy_id,
                        "policy_b": policy_b.policy_id,
                        "rule_a": ra,
                        "rule_b": rb,
                        "severity": 0.9,
                        "description": f"Direct contradiction on resource '{ra.get('resource')}': {ra.get('effect')} vs {rb.get('effect')}",
                    })
                # Enforcement mismatch
                elif ra.get("effect") == rb.get("effect") and policy_a.enforcement != policy_b.enforcement:
                    conflicts.append({
                        "type": ConflictType.enforcement_mismatch.value,
                        "policy_a": policy_a.policy_id,
                        "policy_b": policy_b.policy_id,
                        "rule_a": ra,
                        "rule_b": rb,
                        "severity": 0.4,
                        "description": f"Same effect but enforcement differs: {policy_a.enforcement.value} vs {policy_b.enforcement.value}",
                    })

    # Jurisdiction clash
    j_a = set(policy_a.jurisdictions)
    j_b = set(policy_b.jurisdictions)
    if j_a and j_b and j_a != j_b and j_a & j_b:
        conflicts.append({
            "type": ConflictType.jurisdiction_clash.value,
            "policy_a": policy_a.policy_id,
            "policy_b": policy_b.policy_id,
            "overlap": list(j_a & j_b),
            "severity": 0.5,
            "description": f"Overlapping jurisdictions with different policy scopes",
        })

    return conflicts


def _resolve_conflict(conflict: Dict[str, Any], strategy: ResolutionStrategy) -> Dict[str, Any]:
    """Apply resolution strategy to a conflict."""
    rule_a = conflict.get("rule_a", {})
    rule_b = conflict.get("rule_b", {})

    if strategy == ResolutionStrategy.strictest_wins:
        effect_order = {"deny": 5, "restrict": 4, "require": 3, "audit": 2, "allow": 1}
        winner = rule_a if effect_order.get(rule_a.get("effect"), 0) >= effect_order.get(rule_b.get("effect"), 0) else rule_b
        return {"strategy": strategy.value, "winner_rule": winner, "rationale": "Strictest effect prevails"}

    elif strategy == ResolutionStrategy.most_permissive:
        effect_order = {"allow": 5, "audit": 4, "require": 3, "restrict": 2, "deny": 1}
        winner = rule_a if effect_order.get(rule_a.get("effect"), 0) >= effect_order.get(rule_b.get("effect"), 0) else rule_b
        return {"strategy": strategy.value, "winner_rule": winner, "rationale": "Most permissive effect prevails"}

    elif strategy == ResolutionStrategy.weighted_merge:
        pri_a = rule_a.get("priority", 50)
        pri_b = rule_b.get("priority", 50)
        winner = rule_a if pri_a >= pri_b else rule_b
        return {"strategy": strategy.value, "winner_rule": winner, "rationale": f"Higher priority wins ({max(pri_a, pri_b)} vs {min(pri_a, pri_b)})"}

    else:  # manual_review
        return {"strategy": strategy.value, "winner_rule": None, "rationale": "Queued for manual review"}


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Cross-Org Policy Harmoniser",
    description="Phase 24 — Policy alignment with conflict detection, resolution strategies, and harmonised output",
    version="24.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health():
    return {
        "service": "cross-org-policy-harmoniser",
        "status": "healthy",
        "phase": 24,
        "port": 9802,
        "stats": {
            "policies": len(policies),
            "total_rules": sum(len(p.rules) for p in policies.values()),
            "harmonisation_sessions": len(sessions),
        },
        "timestamp": _now(),
    }


# -- Policies ----------------------------------------------------------------

@app.post("/v1/policies", status_code=201)
def create_policy(body: PolicyCreate):
    pid = f"POL-{uuid.uuid4().hex[:12]}"
    now = _now()
    record = PolicyRecord(**body.dict(), policy_id=pid, created_at=now, updated_at=now)
    record.version_history.append({"version": body.version, "changed_at": now})
    policies[pid] = record
    return record.dict()


@app.get("/v1/policies")
def list_policies(
    organisation: Optional[str] = None,
    domain: Optional[PolicyDomain] = None,
    enforcement: Optional[EnforcementLevel] = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    results = list(policies.values())
    if organisation:
        results = [p for p in results if p.organisation == organisation]
    if domain:
        results = [p for p in results if p.domain == domain]
    if enforcement:
        results = [p for p in results if p.enforcement == enforcement]
    return {"policies": [p.dict() for p in results[:limit]], "total": len(results)}


@app.get("/v1/policies/{policy_id}")
def get_policy(policy_id: str):
    if policy_id not in policies:
        raise HTTPException(404, "Policy not found")
    return policies[policy_id].dict()


@app.post("/v1/policies/{policy_id}/rules", status_code=201)
def add_rule(policy_id: str, body: RuleCreate):
    if policy_id not in policies:
        raise HTTPException(404, "Policy not found")
    rule = {"rule_id": f"RL-{uuid.uuid4().hex[:8]}", **body.dict(), "added_at": _now()}
    policies[policy_id].rules.append(rule)
    policies[policy_id].updated_at = _now()
    return rule


@app.get("/v1/policies/{policy_id}/rules")
def list_rules(policy_id: str):
    if policy_id not in policies:
        raise HTTPException(404, "Policy not found")
    return {"rules": policies[policy_id].rules, "total": len(policies[policy_id].rules)}


# -- Harmonisation -----------------------------------------------------------

@app.post("/v1/harmonise", status_code=201)
def harmonise(body: HarmoniseRequest):
    sid = f"HSESS-{uuid.uuid4().hex[:12]}"
    target_domains = [d.value for d in body.domains] if body.domains else [d.value for d in PolicyDomain]

    # Gather relevant policies
    relevant = [
        p for p in policies.values()
        if p.organisation in body.organisations and p.domain.value in target_domains
    ]

    # Pairwise conflict detection
    all_conflicts = []
    checked = set()
    for i, pa in enumerate(relevant):
        for j, pb in enumerate(relevant):
            if i >= j:
                continue
            if pa.organisation == pb.organisation:
                continue
            pair_key = tuple(sorted([pa.policy_id, pb.policy_id]))
            if pair_key in checked:
                continue
            checked.add(pair_key)
            conflicts = _detect_conflicts(pa, pb)
            all_conflicts.extend(conflicts)

    # Resolve conflicts
    all_resolutions = []
    for conflict in all_conflicts:
        resolution = _resolve_conflict(conflict, body.strategy)
        all_resolutions.append({**conflict, "resolution": resolution})

    # Build harmonised rule set
    harmonised = []
    used_rules = set()
    for res in all_resolutions:
        winner = res.get("resolution", {}).get("winner_rule")
        if winner and winner.get("rule_id"):
            harmonised.append({
                **winner,
                "provenance": "conflict_resolution",
                "strategy": body.strategy.value,
            })
            used_rules.add(winner.get("rule_id"))

    # Add non-conflicting rules
    for p in relevant:
        for rule in p.rules:
            if rule.get("rule_id") not in used_rules:
                harmonised.append({
                    **rule,
                    "provenance": p.organisation,
                    "policy_id": p.policy_id,
                })

    # Gap analysis
    domain_coverage: Dict[str, set] = defaultdict(set)
    for p in relevant:
        domain_coverage[p.domain.value].add(p.organisation)
    gaps = []
    for domain in target_domains:
        missing = set(body.organisations) - domain_coverage.get(domain, set())
        if missing:
            gaps.append({
                "domain": domain,
                "missing_organisations": list(missing),
                "recommendation": f"Organisations {', '.join(missing)} need policies for {domain}",
            })

    session = SessionRecord(
        session_id=sid,
        organisations=body.organisations,
        domains=target_domains,
        strategy=body.strategy.value,
        description=body.description,
        conflicts=all_conflicts,
        resolutions=all_resolutions,
        harmonised_rules=harmonised,
        gaps=gaps,
        created_at=_now(),
    )
    sessions[sid] = session
    return session.dict()


@app.get("/v1/sessions")
def list_sessions():
    return {"sessions": [s.dict() for s in sessions.values()], "total": len(sessions)}


@app.get("/v1/sessions/{session_id}")
def get_session(session_id: str):
    if session_id not in sessions:
        raise HTTPException(404, "Session not found")
    return sessions[session_id].dict()


@app.get("/v1/sessions/{session_id}/gaps")
def session_gaps(session_id: str):
    if session_id not in sessions:
        raise HTTPException(404, "Session not found")
    return {"session_id": session_id, "gaps": sessions[session_id].gaps}


# -- Analytics ----------------------------------------------------------------

@app.get("/v1/analytics")
def analytics():
    org_dist: Dict[str, int] = defaultdict(int)
    domain_dist: Dict[str, int] = defaultdict(int)
    enforcement_dist: Dict[str, int] = defaultdict(int)
    for p in policies.values():
        org_dist[p.organisation] += 1
        domain_dist[p.domain.value] += 1
        enforcement_dist[p.enforcement.value] += 1

    conflict_types: Dict[str, int] = defaultdict(int)
    for s in sessions.values():
        for c in s.conflicts:
            conflict_types[c.get("type", "unknown")] += 1

    return {
        "policies": {
            "total": len(policies),
            "organisation_distribution": dict(org_dist),
            "domain_distribution": dict(domain_dist),
            "enforcement_distribution": dict(enforcement_dist),
            "total_rules": sum(len(p.rules) for p in policies.values()),
        },
        "harmonisation": {
            "sessions": len(sessions),
            "total_conflicts_detected": sum(len(s.conflicts) for s in sessions.values()),
            "conflict_type_distribution": dict(conflict_types),
            "total_gaps_found": sum(len(s.gaps) for s in sessions.values()),
        },
    }


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9802)
