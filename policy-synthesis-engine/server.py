"""Policy Synthesis Engine — Phase 31 Service 1 · Port 9930"""

from __future__ import annotations
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum
import uuid, random

app = FastAPI(title="Policy Synthesis Engine", version="0.31.1")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Enums ────────────────────────────────────────────────────────────
class SourceType(str, Enum):
    incident_history = "incident_history"
    compliance_framework = "compliance_framework"
    threat_intelligence = "threat_intelligence"
    operational_pattern = "operational_pattern"
    industry_standard = "industry_standard"
    expert_input = "expert_input"

class ExtractionMode(str, Enum):
    pattern_matching = "pattern_matching"
    nlp_analysis = "nlp_analysis"
    statistical_inference = "statistical_inference"
    hybrid = "hybrid"

class PolicyState(str, Enum):
    draft = "draft"
    review = "review"
    approved = "approved"
    active = "active"
    deprecated = "deprecated"
    archived = "archived"

POL_TRANSITIONS = {
    "draft": ["review"],
    "review": ["approved", "draft"],
    "approved": ["active"],
    "active": ["deprecated"],
    "deprecated": ["archived"],
}

class RuleSeverity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

class ConflictResolution(str, Enum):
    priority_based = "priority_based"
    specificity = "specificity"
    temporal_latest = "temporal_latest"
    human_review = "human_review"

# ── Models ───────────────────────────────────────────────────────────
class SourceCreate(BaseModel):
    name: str
    source_type: SourceType
    reliability: float = Field(0.8, ge=0, le=1)
    domain: str = "general"
    description: str = ""

class PolicyCreate(BaseModel):
    name: str
    scope: str = "platform-wide"
    description: str = ""

class RuleCreate(BaseModel):
    title: str
    condition: str
    action: str
    severity: RuleSeverity = RuleSeverity.medium
    scope: str = "global"
    confidence: float = Field(0.7, ge=0, le=1)

class RefinementFeedback(BaseModel):
    rule_id: str
    effective: bool
    false_positive_rate: float = Field(0.1, ge=0, le=1)
    notes: str = ""

# ── Stores ───────────────────────────────────────────────────────────
sources: dict[str, dict] = {}
policies: dict[str, dict] = {}
requirements: list[dict] = []

def _now():
    return datetime.now(timezone.utc).isoformat()

# ── Health ───────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"service": "policy-synthesis-engine", "status": "healthy", "version": "0.31.1", "sources": len(sources), "policies": len(policies)}

# ── Sources ──────────────────────────────────────────────────────────
@app.post("/v1/sources", status_code=201)
def create_source(body: SourceCreate):
    sid = str(uuid.uuid4())
    rec = {"id": sid, **body.model_dump(), "extracted_rules": [], "created_at": _now()}
    sources[sid] = rec
    return rec

@app.get("/v1/sources")
def list_sources(source_type: Optional[SourceType] = None):
    out = list(sources.values())
    if source_type:
        out = [s for s in out if s["source_type"] == source_type]
    return [{k: v for k, v in s.items() if k != "extracted_rules"} for s in out]

# ── Extract ──────────────────────────────────────────────────────────
@app.post("/v1/sources/{sid}/extract")
def extract_rules(sid: str, mode: ExtractionMode = Query(ExtractionMode.hybrid)):
    if sid not in sources:
        raise HTTPException(404, "Source not found")
    src = sources[sid]
    # Simulate extraction
    mode_conf = {"pattern_matching": 0.7, "nlp_analysis": 0.75, "statistical_inference": 0.65, "hybrid": 0.82}
    count = random.randint(2, 6)
    rules = []
    actions = ["block", "alert", "monitor", "restrict", "quarantine", "escalate"]
    conditions = ["anomalous_traffic_detected", "credential_reuse_pattern", "privilege_escalation_attempt", "data_exfiltration_indicator", "policy_violation_threshold_exceeded", "unusual_access_pattern"]
    for _ in range(count):
        rules.append({
            "id": str(uuid.uuid4()),
            "title": f"Auto-extracted from {src['name']}",
            "condition": random.choice(conditions),
            "action": random.choice(actions),
            "severity": random.choice(list(RuleSeverity)).value,
            "scope": src["domain"],
            "confidence": round(mode_conf[mode] * src["reliability"] + random.uniform(-0.1, 0.1), 3),
            "extraction_mode": mode,
            "source_id": sid,
            "extracted_at": _now(),
        })
    src["extracted_rules"].extend(rules)
    return {"source_id": sid, "mode": mode, "rules_extracted": len(rules), "rules": rules}

# ── Policies ─────────────────────────────────────────────────────────
@app.post("/v1/policies", status_code=201)
def create_policy(body: PolicyCreate):
    pid = str(uuid.uuid4())
    rec = {"id": pid, **body.model_dump(), "state": "draft", "version": 1, "rules": [], "refinement_log": [], "created_at": _now()}
    policies[pid] = rec
    return rec

@app.get("/v1/policies")
def list_policies(state: Optional[PolicyState] = None):
    out = list(policies.values())
    if state:
        out = [p for p in out if p["state"] == state]
    return [{**{k: v for k, v in p.items() if k not in ("rules", "refinement_log")}, "rule_count": len(p["rules"])} for p in out]

@app.get("/v1/policies/{pid}")
def get_policy(pid: str):
    if pid not in policies:
        raise HTTPException(404, "Policy not found")
    return policies[pid]

@app.patch("/v1/policies/{pid}/advance")
def advance_policy(pid: str, target_state: PolicyState = Query(...)):
    if pid not in policies:
        raise HTTPException(404, "Policy not found")
    p = policies[pid]
    allowed = POL_TRANSITIONS.get(p["state"], [])
    if target_state not in allowed:
        raise HTTPException(400, f"Cannot transition from {p['state']} to {target_state}")
    p["state"] = target_state
    if target_state == "active":
        p["activated_at"] = _now()
    return p

# ── Rules ────────────────────────────────────────────────────────────
@app.post("/v1/policies/{pid}/rules")
def add_rule(pid: str, body: RuleCreate):
    if pid not in policies:
        raise HTTPException(404, "Policy not found")
    rid = str(uuid.uuid4())
    rule = {"id": rid, **body.model_dump(), "effective": True, "added_at": _now()}
    policies[pid]["rules"].append(rule)
    policies[pid]["version"] += 1
    return rule

# ── Refine ───────────────────────────────────────────────────────────
@app.post("/v1/policies/{pid}/refine")
def refine_policy(pid: str, body: RefinementFeedback):
    if pid not in policies:
        raise HTTPException(404, "Policy not found")
    p = policies[pid]
    rule = next((r for r in p["rules"] if r["id"] == body.rule_id), None)
    if not rule:
        raise HTTPException(404, "Rule not found in policy")

    action = "strengthened" if body.effective and body.false_positive_rate < 0.15 else "weakened" if body.false_positive_rate > 0.3 else "unchanged"
    if body.false_positive_rate > 0.5:
        action = "removed"
        rule["effective"] = False

    if action in ("strengthened", "weakened"):
        delta = 0.05 if action == "strengthened" else -0.05
        rule["confidence"] = round(max(0, min(1, rule["confidence"] + delta)), 3)

    log_entry = {"rule_id": body.rule_id, "feedback_effective": body.effective, "false_positive_rate": body.false_positive_rate, "action_taken": action, "notes": body.notes, "refined_at": _now()}
    p["refinement_log"].append(log_entry)
    p["version"] += 1
    return {"rule_id": body.rule_id, "action_taken": action, "new_confidence": rule["confidence"], "rule_active": rule["effective"]}

# ── Conflicts ────────────────────────────────────────────────────────
@app.get("/v1/conflicts")
def detect_conflicts():
    all_rules = []
    for pid, p in policies.items():
        for r in p["rules"]:
            if r["effective"]:
                all_rules.append({**r, "policy_id": pid, "policy_name": p["name"]})

    conflicts = []
    for i, r1 in enumerate(all_rules):
        for r2 in all_rules[i + 1:]:
            if r1["condition"] == r2["condition"] and r1["action"] != r2["action"] and (r1["scope"] == r2["scope"] or r1["scope"] == "global" or r2["scope"] == "global"):
                conflicts.append({
                    "rule_a": {"id": r1["id"], "policy": r1["policy_name"], "action": r1["action"], "severity": r1["severity"]},
                    "rule_b": {"id": r2["id"], "policy": r2["policy_name"], "action": r2["action"], "severity": r2["severity"]},
                    "conflicting_condition": r1["condition"],
                    "scope_overlap": r1["scope"] == r2["scope"] or "global" in (r1["scope"], r2["scope"]),
                })
    return {"conflicts_detected": len(conflicts), "conflicts": conflicts}

# ── Coverage ─────────────────────────────────────────────────────────
@app.get("/v1/coverage")
def coverage():
    # Gather all compliance requirements from sources
    compliance_sources = [s for s in sources.values() if s["source_type"] in ("compliance_framework", "industry_standard")]
    all_conditions = set()
    for p in policies.values():
        for r in p["rules"]:
            if r["effective"]:
                all_conditions.add(r["condition"])

    req_conditions = set()
    for src in compliance_sources:
        for r in src.get("extracted_rules", []):
            req_conditions.add(r["condition"])

    covered = all_conditions & req_conditions
    uncovered = req_conditions - all_conditions
    extra = all_conditions - req_conditions

    return {
        "required_conditions": len(req_conditions),
        "covered": len(covered),
        "uncovered": len(uncovered),
        "coverage_pct": round(len(covered) / max(len(req_conditions), 1) * 100, 1),
        "uncovered_conditions": list(uncovered),
        "extra_conditions": list(extra),
    }

# ── Simulate ─────────────────────────────────────────────────────────
@app.post("/v1/policies/{pid}/simulate")
def simulate(pid: str):
    if pid not in policies:
        raise HTTPException(404, "Policy not found")
    p = policies[pid]
    active_rules = [r for r in p["rules"] if r["effective"]]
    simulated_incidents = random.randint(50, 200)
    results = []
    total_tp, total_fp, total_fn = 0, 0, 0
    for r in active_rules:
        tp = int(simulated_incidents * r["confidence"] * 0.7)
        fp = int(simulated_incidents * (1 - r["confidence"]) * 0.3)
        fn = int(simulated_incidents * (1 - r["confidence"]) * 0.2)
        total_tp += tp; total_fp += fp; total_fn += fn
        results.append({"rule_id": r["id"], "title": r["title"], "true_positives": tp, "false_positives": fp, "false_negatives": fn})
    precision = round(total_tp / max(total_tp + total_fp, 1), 3)
    recall = round(total_tp / max(total_tp + total_fn, 1), 3)
    return {"policy_id": pid, "simulated_incidents": simulated_incidents, "rules_evaluated": len(active_rules), "precision": precision, "recall": recall, "f1": round(2 * precision * recall / max(precision + recall, 0.001), 3), "per_rule": results}

# ── Diff ─────────────────────────────────────────────────────────────
@app.get("/v1/policies/{pid}/diff/{other_pid}")
def diff(pid: str, other_pid: str):
    if pid not in policies:
        raise HTTPException(404, f"Policy {pid} not found")
    if other_pid not in policies:
        raise HTTPException(404, f"Policy {other_pid} not found")
    rules_a = {r["id"]: r for r in policies[pid]["rules"]}
    rules_b = {r["id"]: r for r in policies[other_pid]["rules"]}
    added = [r for rid, r in rules_b.items() if rid not in rules_a]
    removed = [r for rid, r in rules_a.items() if rid not in rules_b]
    common = set(rules_a.keys()) & set(rules_b.keys())
    modified = []
    for rid in common:
        if rules_a[rid]["action"] != rules_b[rid]["action"] or rules_a[rid]["severity"] != rules_b[rid]["severity"]:
            modified.append({"id": rid, "before": rules_a[rid], "after": rules_b[rid]})
    return {"policy_a": pid, "policy_b": other_pid, "added": len(added), "removed": len(removed), "modified": len(modified), "details": {"added": added, "removed": removed, "modified": modified}}

# ── Analytics ────────────────────────────────────────────────────────
@app.get("/v1/analytics")
def analytics():
    pl = list(policies.values())
    by_state = {}
    for p in pl:
        by_state[p["state"]] = by_state.get(p["state"], 0) + 1
    total_rules = sum(len(p["rules"]) for p in pl)
    active_rules = sum(sum(1 for r in p["rules"] if r["effective"]) for p in pl)
    total_refinements = sum(len(p["refinement_log"]) for p in pl)
    return {
        "total_sources": len(sources),
        "total_policies": len(pl),
        "by_state": by_state,
        "total_rules": total_rules,
        "active_rules": active_rules,
        "inactive_rules": total_rules - active_rules,
        "total_refinements": total_refinements,
        "total_extracted_rules": sum(len(s["extracted_rules"]) for s in sources.values()),
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9930)
