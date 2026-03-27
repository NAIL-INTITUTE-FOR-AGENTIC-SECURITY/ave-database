"""
Autonomous Policy Engine — Phase 19 Service 2 of 5
Port: 9301

Policy CRUD with versioned rules, rule synthesis from incidents,
conflict detection & resolution, impact simulation, progressive
enforcement, and compliance mapping.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class PolicyType(str, Enum):
    access_control = "access_control"
    rate_limit = "rate_limit"
    content_filter = "content_filter"
    isolation = "isolation"
    escalation = "escalation"
    compliance = "compliance"


class ConditionOperator(str, Enum):
    eq = "eq"
    neq = "neq"
    gt = "gt"
    gte = "gte"
    lt = "lt"
    lte = "lte"
    contains = "contains"
    regex = "regex"
    in_list = "in"


class ActionType(str, Enum):
    allow = "allow"
    deny = "deny"
    throttle = "throttle"
    quarantine = "quarantine"
    alert = "alert"
    escalate = "escalate"


class PriorityTier(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


PRIORITY_SCORES = {
    PriorityTier.critical: 1000,
    PriorityTier.high: 750,
    PriorityTier.medium: 500,
    PriorityTier.low: 250,
}


class PolicyStatus(str, Enum):
    draft = "draft"
    active = "active"
    shadow = "shadow"
    deprecated = "deprecated"
    archived = "archived"


class ConflictType(str, Enum):
    contradiction = "contradiction"
    subsumption = "subsumption"
    priority_inversion = "priority_inversion"
    scope_overlap = "scope_overlap"
    temporal_conflict = "temporal_conflict"
    circular_dependency = "circular_dependency"


class ResolutionStrategy(str, Enum):
    priority_wins = "priority_wins"
    most_restrictive = "most_restrictive"
    most_recent = "most_recent"
    manual_review = "manual_review"


class EnforcementPhase(str, Enum):
    shadow = "shadow"
    canary = "canary"
    partial = "partial"
    full = "full"


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

class Condition(BaseModel):
    field: str
    operator: ConditionOperator
    value: Any


class Action(BaseModel):
    action_type: ActionType
    parameters: Dict[str, Any] = Field(default_factory=dict)


class Rule(BaseModel):
    conditions: List[Condition]
    actions: List[Action]
    scope: Dict[str, Any] = Field(default_factory=dict)


class PolicyCreate(BaseModel):
    name: str
    policy_type: PolicyType
    priority: PriorityTier = PriorityTier.medium
    description: str = ""
    rules: List[Rule] = Field(default_factory=list)
    categories: List[str] = Field(default_factory=list)
    status: PolicyStatus = PolicyStatus.draft
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PolicyRecord(PolicyCreate):
    policy_id: str
    version: int = 1
    priority_score: int = 500
    created_at: str
    updated_at: str


class EvaluateRequest(BaseModel):
    context: Dict[str, Any]
    categories: Optional[List[str]] = None


class SynthesisRequest(BaseModel):
    incident_patterns: List[Dict[str, Any]]
    min_confidence: float = Field(default=0.7, ge=0.0, le=1.0)


class SynthesisCandidate(BaseModel):
    candidate_id: str
    proposed_policy: PolicyCreate
    confidence: float
    source_patterns: List[Dict[str, Any]]
    requires_approval: bool = True
    created_at: str


class SimulationRequest(BaseModel):
    policy_id: str
    test_contexts: List[Dict[str, Any]]
    mode: str = "what_if"  # what_if | shadow | rollback


class EnforcementConfig(BaseModel):
    policy_id: str
    phase: EnforcementPhase
    rollout_percentage: float = Field(default=0.0, ge=0.0, le=100.0)
    health_gate_threshold: float = Field(default=0.95, ge=0.0, le=1.0)
    kill_switch: bool = False


# ---------------------------------------------------------------------------
# In-Memory Stores
# ---------------------------------------------------------------------------

policies: Dict[str, PolicyRecord] = {}
synthesis_candidates: Dict[str, SynthesisCandidate] = {}
enforcement_configs: Dict[str, EnforcementConfig] = {}
evaluation_log: List[Dict[str, Any]] = []


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Policy Evaluation Helpers
# ---------------------------------------------------------------------------

def _evaluate_condition(cond: Condition, context: Dict[str, Any]) -> bool:
    val = context.get(cond.field)
    if val is None:
        return False
    op = cond.operator
    if op == ConditionOperator.eq:
        return val == cond.value
    if op == ConditionOperator.neq:
        return val != cond.value
    if op == ConditionOperator.gt:
        return val > cond.value
    if op == ConditionOperator.gte:
        return val >= cond.value
    if op == ConditionOperator.lt:
        return val < cond.value
    if op == ConditionOperator.lte:
        return val <= cond.value
    if op == ConditionOperator.contains:
        return cond.value in str(val)
    if op == ConditionOperator.in_list:
        return val in cond.value
    return False


def _evaluate_rule(rule: Rule, context: Dict[str, Any]) -> bool:
    return all(_evaluate_condition(c, context) for c in rule.conditions)


def _detect_conflicts_between(p1: PolicyRecord, p2: PolicyRecord) -> List[Dict[str, Any]]:
    conflicts = []
    # Simple heuristic: same category + contradictory actions
    shared_cats = set(p1.categories) & set(p2.categories)
    if not shared_cats:
        return conflicts
    for r1 in p1.rules:
        for r2 in p2.rules:
            a1_types = {a.action_type for a in r1.actions}
            a2_types = {a.action_type for a in r2.actions}
            if ActionType.allow in a1_types and ActionType.deny in a2_types:
                conflicts.append({
                    "type": ConflictType.contradiction.value,
                    "policy_a": p1.policy_id,
                    "policy_b": p2.policy_id,
                    "shared_categories": list(shared_cats),
                    "detail": "One policy allows while the other denies for overlapping categories",
                })
            if p1.priority_score == p2.priority_score and a1_types != a2_types:
                conflicts.append({
                    "type": ConflictType.priority_inversion.value,
                    "policy_a": p1.policy_id,
                    "policy_b": p2.policy_id,
                    "detail": "Equal priority with different actions — ambiguous resolution",
                })
    return conflicts


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Autonomous Policy Engine",
    description="Phase 19 — Policy lifecycle, synthesis, conflict resolution, simulation, and enforcement",
    version="19.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health():
    return {
        "service": "autonomous-policy-engine",
        "status": "healthy",
        "phase": 19,
        "port": 9301,
        "stats": {
            "policies": len(policies),
            "active": sum(1 for p in policies.values() if p.status == PolicyStatus.active),
            "candidates": len(synthesis_candidates),
        },
        "timestamp": _now(),
    }


# ── Policy CRUD ────────────────────────────────────────────────────────────

@app.post("/v1/policies", status_code=201)
def create_policy(body: PolicyCreate):
    pid = f"POL-{uuid.uuid4().hex[:12]}"
    now = _now()
    record = PolicyRecord(
        **body.dict(),
        policy_id=pid,
        priority_score=PRIORITY_SCORES.get(body.priority, 500),
        created_at=now,
        updated_at=now,
    )
    policies[pid] = record
    return record.dict()


@app.get("/v1/policies")
def list_policies(
    policy_type: Optional[PolicyType] = None,
    status: Optional[PolicyStatus] = None,
    priority: Optional[PriorityTier] = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    results = list(policies.values())
    if policy_type:
        results = [p for p in results if p.policy_type == policy_type]
    if status:
        results = [p for p in results if p.status == status]
    if priority:
        results = [p for p in results if p.priority == priority]
    results.sort(key=lambda p: p.priority_score, reverse=True)
    return {"policies": [p.dict() for p in results[:limit]], "total": len(results)}


@app.get("/v1/policies/{policy_id}")
def get_policy(policy_id: str):
    if policy_id not in policies:
        raise HTTPException(404, "Policy not found")
    return policies[policy_id].dict()


@app.delete("/v1/policies/{policy_id}")
def delete_policy(policy_id: str):
    if policy_id not in policies:
        raise HTTPException(404, "Policy not found")
    del policies[policy_id]
    enforcement_configs.pop(policy_id, None)
    return {"deleted": policy_id}


# ── Evaluation ─────────────────────────────────────────────────────────────

@app.post("/v1/policies/evaluate")
def evaluate_policies(body: EvaluateRequest):
    applicable = [
        p for p in policies.values()
        if p.status in (PolicyStatus.active, PolicyStatus.shadow)
    ]
    if body.categories:
        applicable = [p for p in applicable if set(p.categories) & set(body.categories)]
    applicable.sort(key=lambda p: p.priority_score, reverse=True)

    decisions: List[Dict[str, Any]] = []
    for p in applicable:
        for rule in p.rules:
            if _evaluate_rule(rule, body.context):
                decisions.append({
                    "policy_id": p.policy_id,
                    "policy_name": p.name,
                    "priority_score": p.priority_score,
                    "actions": [a.dict() for a in rule.actions],
                    "is_shadow": p.status == PolicyStatus.shadow,
                })
    # Log evaluation
    entry = {"context": body.context, "decisions": decisions, "timestamp": _now()}
    evaluation_log.append(entry)
    if len(evaluation_log) > 10000:
        evaluation_log.pop(0)
    return {"decisions": decisions, "policies_evaluated": len(applicable)}


# ── Synthesis ──────────────────────────────────────────────────────────────

@app.post("/v1/synthesis/generate")
def generate_candidates(body: SynthesisRequest):
    candidates = []
    for i, pattern in enumerate(body.incident_patterns):
        category = pattern.get("category", "unknown")
        severity = pattern.get("severity", "medium")
        confidence = pattern.get("confidence", 0.8)
        if confidence < body.min_confidence:
            continue
        # Synthesise a policy from the pattern
        action_type = ActionType.deny if severity in ("critical", "high") else ActionType.throttle
        proposed = PolicyCreate(
            name=f"Auto-synthesised: {category} defence",
            policy_type=PolicyType.content_filter,
            priority=PriorityTier.high if severity == "critical" else PriorityTier.medium,
            description=f"Auto-generated from incident pattern: {pattern.get('description', '')}",
            rules=[Rule(
                conditions=[Condition(field="category", operator=ConditionOperator.eq, value=category)],
                actions=[Action(action_type=action_type)],
            )],
            categories=[category],
            status=PolicyStatus.draft,
        )
        cid = f"CAND-{uuid.uuid4().hex[:12]}"
        candidate = SynthesisCandidate(
            candidate_id=cid,
            proposed_policy=proposed,
            confidence=confidence,
            source_patterns=[pattern],
            created_at=_now(),
        )
        synthesis_candidates[cid] = candidate
        candidates.append(candidate.dict())
    return {"candidates_generated": len(candidates), "candidates": candidates}


@app.get("/v1/synthesis/candidates")
def list_candidates():
    return {
        "candidates": [c.dict() for c in synthesis_candidates.values()],
        "total": len(synthesis_candidates),
    }


@app.post("/v1/synthesis/approve/{candidate_id}")
def approve_candidate(candidate_id: str):
    if candidate_id not in synthesis_candidates:
        raise HTTPException(404, "Candidate not found")
    candidate = synthesis_candidates.pop(candidate_id)
    proposed = candidate.proposed_policy
    proposed.status = PolicyStatus.shadow  # Start in shadow mode
    pid = f"POL-{uuid.uuid4().hex[:12]}"
    now = _now()
    record = PolicyRecord(
        **proposed.dict(),
        policy_id=pid,
        priority_score=PRIORITY_SCORES.get(proposed.priority, 500),
        created_at=now,
        updated_at=now,
    )
    policies[pid] = record
    return {"approved": True, "policy_id": pid, "policy": record.dict()}


# ── Conflict Detection ────────────────────────────────────────────────────

@app.get("/v1/conflicts")
def detect_conflicts():
    active = [p for p in policies.values() if p.status in (PolicyStatus.active, PolicyStatus.shadow)]
    all_conflicts = []
    for i, p1 in enumerate(active):
        for p2 in active[i + 1:]:
            c = _detect_conflicts_between(p1, p2)
            all_conflicts.extend(c)
    return {"conflict_count": len(all_conflicts), "conflicts": all_conflicts}


# ── Simulation ─────────────────────────────────────────────────────────────

@app.post("/v1/simulate")
def simulate(body: SimulationRequest):
    if body.policy_id not in policies:
        raise HTTPException(404, "Policy not found")
    policy = policies[body.policy_id]
    results = []
    for ctx in body.test_contexts:
        matched_rules = []
        for rule in policy.rules:
            if _evaluate_rule(rule, ctx):
                matched_rules.append({
                    "actions": [a.dict() for a in rule.actions],
                    "conditions_matched": len(rule.conditions),
                })
        results.append({
            "context": ctx,
            "matched": len(matched_rules) > 0,
            "rules_triggered": matched_rules,
        })
    match_rate = sum(1 for r in results if r["matched"]) / max(len(results), 1)
    return {
        "policy_id": body.policy_id,
        "mode": body.mode,
        "test_count": len(results),
        "match_rate": round(match_rate, 4),
        "results": results,
    }


# ── Enforcement ────────────────────────────────────────────────────────────

@app.post("/v1/enforcement")
def set_enforcement(body: EnforcementConfig):
    if body.policy_id not in policies:
        raise HTTPException(404, "Policy not found")
    # Auto-set rollout percentage per phase
    phase_rollout = {
        EnforcementPhase.shadow: 0.0,
        EnforcementPhase.canary: 5.0,
        EnforcementPhase.partial: 50.0,
        EnforcementPhase.full: 100.0,
    }
    if body.rollout_percentage == 0.0:
        body.rollout_percentage = phase_rollout.get(body.phase, 0.0)
    enforcement_configs[body.policy_id] = body
    return body.dict()


@app.get("/v1/enforcement")
def list_enforcement():
    return {
        "configs": {pid: c.dict() for pid, c in enforcement_configs.items()},
        "total": len(enforcement_configs),
    }


# ── Compliance Mapping ────────────────────────────────────────────────────

COMPLIANCE_FRAMEWORKS = {
    "eu_ai_act": {
        "name": "EU AI Act",
        "mappable_types": [PolicyType.content_filter, PolicyType.compliance, PolicyType.escalation],
        "required_controls": ["human_oversight", "transparency", "risk_assessment"],
    },
    "nist_ai_rmf": {
        "name": "NIST AI RMF",
        "mappable_types": [PolicyType.access_control, PolicyType.isolation, PolicyType.compliance],
        "required_controls": ["govern", "map", "measure", "manage"],
    },
    "iso_27001": {
        "name": "ISO 27001",
        "mappable_types": [PolicyType.access_control, PolicyType.rate_limit, PolicyType.isolation],
        "required_controls": ["access_control", "cryptography", "operations_security"],
    },
    "soc2": {
        "name": "SOC 2",
        "mappable_types": [PolicyType.access_control, PolicyType.rate_limit, PolicyType.compliance],
        "required_controls": ["security", "availability", "confidentiality"],
    },
}


@app.get("/v1/compliance")
def compliance_overview():
    report = {}
    for fw_id, fw in COMPLIANCE_FRAMEWORKS.items():
        mapped = [
            p.policy_id for p in policies.values()
            if p.policy_type in fw["mappable_types"] and p.status == PolicyStatus.active
        ]
        report[fw_id] = {
            "framework": fw["name"],
            "mapped_policies": len(mapped),
            "required_controls": fw["required_controls"],
            "coverage": round(len(mapped) / max(len(fw["required_controls"]), 1), 2),
        }
    return {"compliance": report}


# ── Analytics ──────────────────────────────────────────────────────────────

@app.get("/v1/analytics")
def analytics():
    status_dist: Dict[str, int] = defaultdict(int)
    type_dist: Dict[str, int] = defaultdict(int)
    priority_dist: Dict[str, int] = defaultdict(int)
    for p in policies.values():
        status_dist[p.status.value] += 1
        type_dist[p.policy_type.value] += 1
        priority_dist[p.priority.value] += 1
    return {
        "total_policies": len(policies),
        "status_distribution": dict(status_dist),
        "type_distribution": dict(type_dist),
        "priority_distribution": dict(priority_dist),
        "pending_candidates": len(synthesis_candidates),
        "enforcement_configs": len(enforcement_configs),
        "evaluation_log_size": len(evaluation_log),
    }


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9301)
