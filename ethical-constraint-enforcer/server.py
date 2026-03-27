"""Ethical Constraint Enforcer — Phase 31 Service 3 · Port 9932"""

from __future__ import annotations
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum
import uuid, random
from collections import Counter

app = FastAPI(title="Ethical Constraint Enforcer", version="0.31.3")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Enums ────────────────────────────────────────────────────────────
class ConstraintType(str, Enum):
    proportionality = "proportionality"
    non_discrimination = "non_discrimination"
    transparency = "transparency"
    privacy_preservation = "privacy_preservation"
    human_dignity = "human_dignity"
    minimal_harm = "minimal_harm"
    due_process = "due_process"

class ConstraintSeverity(str, Enum):
    advisory = "advisory"
    mandatory = "mandatory"
    absolute = "absolute"

class ProtectedAttribute(str, Enum):
    demographic = "demographic"
    geographic = "geographic"
    temporal = "temporal"
    behavioural = "behavioural"
    technological = "technological"
    economic = "economic"

# ── Models ───────────────────────────────────────────────────────────
class ConstraintCreate(BaseModel):
    name: str
    constraint_type: ConstraintType
    severity: ConstraintSeverity = ConstraintSeverity.mandatory
    scope: str = "all_decisions"
    threshold: float = Field(0.8, ge=0, le=1)
    description: str = ""

class DecisionEval(BaseModel):
    decision_type: str
    threat_severity: float = Field(0.5, ge=0, le=1)
    response_severity: float = Field(0.5, ge=0, le=1)
    affected_entities: int = Field(1, ge=0)
    attributes: dict = {}
    context: str = ""

class OverrideRequest(BaseModel):
    overrider_id: str
    justification: str
    constraint_id: str

# ── Stores ───────────────────────────────────────────────────────────
constraints: dict[str, dict] = {}
evaluations: dict[str, dict] = {}

def _now():
    return datetime.now(timezone.utc).isoformat()

# ── Evaluation Logic ─────────────────────────────────────────────────
def _check_constraint(constraint: dict, decision: dict) -> dict:
    ct = constraint["constraint_type"]
    passed = True
    detail = ""
    score = 100.0

    if ct == "proportionality":
        ratio = decision["response_severity"] / max(decision["threat_severity"], 0.01)
        passed = ratio <= 1.5
        score = max(0, 100 - (ratio - 1) * 100) if ratio > 1 else 100
        detail = f"Response/threat ratio: {ratio:.2f} (threshold: ≤ 1.5)"

    elif ct == "non_discrimination":
        # Check if attributes suggest disparate impact
        attrs = decision.get("attributes", {})
        has_protected = any(k in [pa.value for pa in ProtectedAttribute] for k in attrs)
        if has_protected:
            impact_score = random.uniform(0.6, 1.0)  # simulated
            passed = impact_score >= 0.8  # 80% rule
            score = impact_score * 100
            detail = f"Disparate impact score: {impact_score:.2f} (threshold: ≥ 0.80)"
        else:
            detail = "No protected attributes in decision"

    elif ct == "transparency":
        has_context = len(decision.get("context", "")) > 10
        passed = has_context
        score = 100 if has_context else 30
        detail = "Decision context provided" if has_context else "Insufficient decision context for transparency"

    elif ct == "privacy_preservation":
        affected = decision["affected_entities"]
        passed = affected <= 100
        score = max(0, 100 - affected * 0.5)
        detail = f"Affected entities: {affected} (threshold: ≤ 100)"

    elif ct == "human_dignity":
        response_sev = decision["response_severity"]
        passed = response_sev < 0.9
        score = max(0, (1 - response_sev) * 100)
        detail = f"Response severity: {response_sev:.2f} (dignity threshold: < 0.9)"

    elif ct == "minimal_harm":
        harm_est = decision["response_severity"] * decision["affected_entities"]
        max_harm = constraint["threshold"] * 100
        passed = harm_est <= max_harm
        score = max(0, 100 - harm_est / max(max_harm, 1) * 100)
        detail = f"Estimated harm: {harm_est:.1f} (max allowed: {max_harm:.1f})"

    elif ct == "due_process":
        passed = decision["threat_severity"] >= 0.3 or decision["response_severity"] < 0.3
        score = 100 if passed else 40
        detail = "Due process satisfied" if passed else "Low-threat decision with high-severity response requires due process review"

    return {
        "constraint_id": constraint["id"],
        "constraint_name": constraint["name"],
        "constraint_type": ct,
        "severity": constraint["severity"],
        "passed": passed,
        "score": round(score, 1),
        "detail": detail,
    }

# ── Health ───────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"service": "ethical-constraint-enforcer", "status": "healthy", "version": "0.31.3", "constraints": len(constraints), "evaluations": len(evaluations)}

# ── Constraints ──────────────────────────────────────────────────────
@app.post("/v1/constraints", status_code=201)
def create_constraint(body: ConstraintCreate):
    cid = str(uuid.uuid4())
    rec = {"id": cid, **body.model_dump(), "active": True, "created_at": _now()}
    constraints[cid] = rec
    return rec

@app.get("/v1/constraints")
def list_constraints(constraint_type: Optional[ConstraintType] = None, severity: Optional[ConstraintSeverity] = None):
    out = list(constraints.values())
    if constraint_type:
        out = [c for c in out if c["constraint_type"] == constraint_type]
    if severity:
        out = [c for c in out if c["severity"] == severity]
    return out

@app.get("/v1/constraints/{cid}")
def get_constraint(cid: str):
    if cid not in constraints:
        raise HTTPException(404, "Constraint not found")
    return constraints[cid]

# ── Evaluate ─────────────────────────────────────────────────────────
@app.post("/v1/evaluate", status_code=201)
def evaluate(body: DecisionEval):
    eid = str(uuid.uuid4())
    results = []
    for c in constraints.values():
        if c["active"]:
            results.append(_check_constraint(c, body.model_dump()))

    violations = [r for r in results if not r["passed"]]
    mandatory_violations = [v for v in violations if v["severity"] in ("mandatory", "absolute")]
    overall_score = round(sum(r["score"] for r in results) / max(len(results), 1), 1)
    blocked = any(v["severity"] == "absolute" for v in violations)

    rec = {
        "id": eid,
        **body.model_dump(),
        "results": results,
        "overall_score": overall_score,
        "total_constraints": len(results),
        "violations": len(violations),
        "mandatory_violations": len(mandatory_violations),
        "blocked": blocked,
        "overrides": [],
        "evaluated_at": _now(),
    }
    evaluations[eid] = rec
    return rec

@app.get("/v1/evaluations")
def list_evaluations(limit: int = Query(100, ge=1, le=1000)):
    return [{k: v for k, v in e.items() if k != "results"} for e in list(evaluations.values())[-limit:]]

@app.get("/v1/evaluations/{eid}")
def get_evaluation(eid: str):
    if eid not in evaluations:
        raise HTTPException(404, "Evaluation not found")
    return evaluations[eid]

# ── Override ─────────────────────────────────────────────────────────
@app.post("/v1/evaluations/{eid}/override")
def override(eid: str, body: OverrideRequest):
    if eid not in evaluations:
        raise HTTPException(404, "Evaluation not found")
    ev = evaluations[eid]
    violation = next((r for r in ev["results"] if r["constraint_id"] == body.constraint_id and not r["passed"]), None)
    if not violation:
        raise HTTPException(400, "No violation found for this constraint")
    if violation["severity"] == "absolute":
        raise HTTPException(403, "Absolute constraints cannot be overridden")

    override_rec = {
        "id": str(uuid.uuid4()),
        "constraint_id": body.constraint_id,
        "constraint_name": violation["constraint_name"],
        "overrider_id": body.overrider_id,
        "justification": body.justification,
        "original_score": violation["score"],
        "overridden_at": _now(),
    }
    ev["overrides"].append(override_rec)
    return override_rec

# ── Bias Scan ────────────────────────────────────────────────────────
@app.get("/v1/bias-scan")
def bias_scan():
    evl = list(evaluations.values())
    if len(evl) < 5:
        return {"message": "Insufficient evaluations for bias analysis", "evaluations_available": len(evl)}

    attr_groups: dict[str, list] = {}
    for ev in evl:
        for attr_key, attr_val in ev.get("attributes", {}).items():
            if attr_key in [pa.value for pa in ProtectedAttribute]:
                key = f"{attr_key}:{attr_val}"
                attr_groups.setdefault(key, []).append(ev)

    findings = []
    for group_key, group_evals in attr_groups.items():
        if len(group_evals) < 3:
            continue
        group_block_rate = sum(1 for e in group_evals if e["blocked"]) / len(group_evals)
        overall_block_rate = sum(1 for e in evl if e["blocked"]) / len(evl)
        if overall_block_rate > 0:
            impact_ratio = group_block_rate / overall_block_rate
            if impact_ratio > 1.25 or impact_ratio < 0.8:
                findings.append({
                    "protected_group": group_key,
                    "group_size": len(group_evals),
                    "group_block_rate": round(group_block_rate, 3),
                    "overall_block_rate": round(overall_block_rate, 3),
                    "impact_ratio": round(impact_ratio, 3),
                    "disparate_impact": impact_ratio < 0.8 or impact_ratio > 1.25,
                    "severity": "high" if abs(impact_ratio - 1) > 0.5 else "medium",
                })

    return {"evaluations_analysed": len(evl), "groups_analysed": len(attr_groups), "bias_findings": len(findings), "findings": findings}

# ── Fairness ─────────────────────────────────────────────────────────
@app.get("/v1/fairness")
def fairness():
    evl = list(evaluations.values())
    if not evl:
        return {"message": "No evaluations to compute fairness metrics"}

    total = len(evl)
    blocked = sum(1 for e in evl if e["blocked"])
    avg_score = round(sum(e["overall_score"] for e in evl) / total, 1)
    violation_rate = round(sum(e["violations"] for e in evl) / max(sum(e["total_constraints"] for e in evl), 1), 3)

    return {
        "total_evaluations": total,
        "demographic_parity": round(1 - abs(blocked / total - 0.5) * 2, 3) if total > 0 else 1.0,
        "equal_opportunity": round(avg_score / 100, 3),
        "predictive_equality": round(1 - violation_rate, 3),
        "individual_fairness": round(sum(1 for e in evl if e["overall_score"] >= 60) / total, 3),
        "avg_ethical_score": avg_score,
        "block_rate": round(blocked / total, 3),
        "override_rate": round(sum(1 for e in evl if e["overrides"]) / total, 3),
    }

# ── Violations ───────────────────────────────────────────────────────
@app.get("/v1/violations")
def violations():
    all_violations = []
    for ev in evaluations.values():
        for r in ev["results"]:
            if not r["passed"]:
                all_violations.append({**r, "evaluation_id": ev["id"], "decision_type": ev["decision_type"], "evaluated_at": ev["evaluated_at"]})

    by_type = Counter(v["constraint_type"] for v in all_violations)
    by_severity = Counter(v["severity"] for v in all_violations)

    # Detect systematic patterns
    systematic = [ct for ct, count in by_type.items() if count >= 5]

    return {
        "total_violations": len(all_violations),
        "by_constraint_type": dict(by_type),
        "by_severity": dict(by_severity),
        "systematic_violations": systematic,
        "recent_violations": all_violations[-20:],
    }

# ── Analytics ────────────────────────────────────────────────────────
@app.get("/v1/analytics")
def analytics():
    evl = list(evaluations.values())
    return {
        "total_constraints": len(constraints),
        "active_constraints": sum(1 for c in constraints.values() if c["active"]),
        "total_evaluations": len(evl),
        "blocked_decisions": sum(1 for e in evl if e["blocked"]),
        "total_violations": sum(e["violations"] for e in evl),
        "total_overrides": sum(len(e["overrides"]) for e in evl),
        "avg_ethical_score": round(sum(e["overall_score"] for e in evl) / max(len(evl), 1), 1),
        "by_constraint_type": dict(Counter(c["constraint_type"] for c in constraints.values())),
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9932)
