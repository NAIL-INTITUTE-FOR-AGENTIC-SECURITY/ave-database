"""Decision Accountability Tracker — Phase 31 Service 5 · Port 9934"""

from __future__ import annotations
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum
import uuid, random
from collections import Counter

app = FastAPI(title="Decision Accountability Tracker", version="0.31.5")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Enums ────────────────────────────────────────────────────────────
class DecisionType(str, Enum):
    threat_blocked = "threat_blocked"
    access_denied = "access_denied"
    alert_escalated = "alert_escalated"
    policy_enforced = "policy_enforced"
    quarantine_applied = "quarantine_applied"
    privilege_revoked = "privilege_revoked"
    investigation_triggered = "investigation_triggered"
    response_automated = "response_automated"

class StepType(str, Enum):
    data_ingestion = "data_ingestion"
    feature_extraction = "feature_extraction"
    model_inference = "model_inference"
    rule_evaluation = "rule_evaluation"
    threshold_check = "threshold_check"
    aggregation = "aggregation"
    final_determination = "final_determination"

class ContestState(str, Enum):
    filed = "filed"
    reviewing = "reviewing"
    investigated = "investigated"
    upheld = "upheld"
    overturned = "overturned"

CONTEST_TRANSITIONS = {
    "filed": ["reviewing"],
    "reviewing": ["investigated"],
    "investigated": ["upheld", "overturned"],
}

class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

# ── Models ───────────────────────────────────────────────────────────
class DecisionCreate(BaseModel):
    decision_type: DecisionType
    severity: Severity = Severity.medium
    affected_entities: list[str] = []
    outcome: str = ""
    context: str = ""

class StepCreate(BaseModel):
    step_type: StepType
    inputs: dict = {}
    outputs: dict = {}
    confidence: float = Field(0.8, ge=0, le=1)
    model_reference: str = ""

class ContestCreate(BaseModel):
    decision_id: str
    contestant_id: str
    grounds: str
    evidence: str = ""

# ── Stores ───────────────────────────────────────────────────────────
decisions: dict[str, dict] = {}
contestations: dict[str, dict] = {}

def _now():
    return datetime.now(timezone.utc).isoformat()

# ── Health ───────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"service": "decision-accountability-tracker", "status": "healthy", "version": "0.31.5", "decisions": len(decisions), "contestations": len(contestations)}

# ── Decisions ────────────────────────────────────────────────────────
@app.post("/v1/decisions", status_code=201)
def create_decision(body: DecisionCreate):
    did = str(uuid.uuid4())
    rec = {
        "id": did,
        **body.model_dump(),
        "reasoning_chain": [],
        "notifications": [],
        "created_at": _now(),
    }
    decisions[did] = rec
    return rec

@app.get("/v1/decisions")
def list_decisions(decision_type: Optional[DecisionType] = None, severity: Optional[Severity] = None, limit: int = Query(100, ge=1, le=1000)):
    out = list(decisions.values())
    if decision_type:
        out = [d for d in out if d["decision_type"] == decision_type]
    if severity:
        out = [d for d in out if d["severity"] == severity]
    return [{**{k: v for k, v in d.items() if k not in ("reasoning_chain", "notifications")}, "chain_length": len(d["reasoning_chain"])} for d in out[-limit:]]

@app.get("/v1/decisions/{did}")
def get_decision(did: str):
    if did not in decisions:
        raise HTTPException(404, "Decision not found")
    return decisions[did]

# ── Reasoning Steps ──────────────────────────────────────────────────
@app.post("/v1/decisions/{did}/steps")
def add_step(did: str, body: StepCreate):
    if did not in decisions:
        raise HTTPException(404, "Decision not found")
    step_num = len(decisions[did]["reasoning_chain"]) + 1
    step = {"id": str(uuid.uuid4()), "step_number": step_num, **body.model_dump(), "added_at": _now()}
    decisions[did]["reasoning_chain"].append(step)
    return step

# ── Explainability ───────────────────────────────────────────────────
@app.get("/v1/decisions/{did}/explain")
def explain(did: str):
    if did not in decisions:
        raise HTTPException(404, "Decision not found")
    d = decisions[did]
    chain = d["reasoning_chain"]

    if not chain:
        return {"decision_id": did, "explanation": "No reasoning chain recorded", "confidence": 0}

    # Build plain-language explanation
    steps_summary = []
    for s in chain:
        if s["step_type"] == "data_ingestion":
            steps_summary.append(f"Ingested data: {s.get('inputs', {}).get('source', 'various sources')}")
        elif s["step_type"] == "feature_extraction":
            steps_summary.append(f"Extracted {len(s.get('outputs', {}))} features from raw data")
        elif s["step_type"] == "model_inference":
            steps_summary.append(f"Model '{s.get('model_reference', 'unnamed')}' inferred with {s['confidence']:.0%} confidence")
        elif s["step_type"] == "rule_evaluation":
            steps_summary.append(f"Evaluated rules against inputs")
        elif s["step_type"] == "threshold_check":
            steps_summary.append(f"Checked thresholds: {'passed' if s['confidence'] > 0.5 else 'below threshold'}")
        elif s["step_type"] == "aggregation":
            steps_summary.append(f"Aggregated signals from {len(s.get('inputs', {}))} sources")
        elif s["step_type"] == "final_determination":
            steps_summary.append(f"Final determination: {d['decision_type']} (severity: {d['severity']})")

    avg_confidence = round(sum(s["confidence"] for s in chain) / len(chain), 3)
    key_factors = [s for s in chain if s["confidence"] > 0.7]

    return {
        "decision_id": did,
        "decision_type": d["decision_type"],
        "severity": d["severity"],
        "summary": f"Decision '{d['decision_type']}' was made through {len(chain)} reasoning steps with average confidence {avg_confidence:.1%}.",
        "steps_explained": steps_summary,
        "key_factors": [{"step": s["step_number"], "type": s["step_type"], "confidence": s["confidence"], "model": s.get("model_reference", "")} for s in key_factors],
        "overall_confidence": avg_confidence,
        "chain_completeness": "complete" if any(s["step_type"] == "final_determination" for s in chain) else "partial",
        "affected_entities": d["affected_entities"],
    }

# ── Counterfactual ───────────────────────────────────────────────────
@app.get("/v1/decisions/{did}/counterfactual")
def counterfactual(did: str):
    if did not in decisions:
        raise HTTPException(404, "Decision not found")
    d = decisions[did]
    chain = d["reasoning_chain"]

    if not chain:
        return {"decision_id": did, "message": "No reasoning chain for counterfactual analysis"}

    scenarios = []
    for s in chain:
        if s["step_type"] in ("model_inference", "threshold_check", "rule_evaluation"):
            # Perturb confidence
            alt_confidence = max(0, min(1, s["confidence"] + random.choice([-0.2, -0.15, 0.1, 0.15])))
            would_change = (s["confidence"] > 0.5) != (alt_confidence > 0.5)
            scenarios.append({
                "step_number": s["step_number"],
                "step_type": s["step_type"],
                "original_confidence": s["confidence"],
                "alternative_confidence": round(alt_confidence, 3),
                "would_change_outcome": would_change,
                "sensitivity": "high" if would_change else "low",
                "description": f"If step {s['step_number']} ({s['step_type']}) had confidence {alt_confidence:.1%} instead of {s['confidence']:.1%}, outcome would {'change' if would_change else 'remain the same'}",
            })

    sensitive_steps = sum(1 for sc in scenarios if sc["sensitivity"] == "high")
    return {
        "decision_id": did,
        "total_scenarios": len(scenarios),
        "sensitive_steps": sensitive_steps,
        "decision_robustness": "fragile" if sensitive_steps > len(scenarios) * 0.4 else "robust",
        "scenarios": scenarios,
    }

# ── Contestations ───────────────────────────────────────────────────
@app.post("/v1/contestations", status_code=201)
def file_contestation(body: ContestCreate):
    if body.decision_id not in decisions:
        raise HTTPException(404, "Decision not found")
    cid = str(uuid.uuid4())
    rec = {
        "id": cid,
        **body.model_dump(),
        "decision_type": decisions[body.decision_id]["decision_type"],
        "state": "filed",
        "reviewer_id": None,
        "resolution_rationale": None,
        "filed_at": _now(),
        "resolved_at": None,
    }
    contestations[cid] = rec
    return rec

@app.get("/v1/contestations")
def list_contestations(state: Optional[ContestState] = None):
    out = list(contestations.values())
    if state:
        out = [c for c in out if c["state"] == state]
    return out

@app.get("/v1/contestations/{cid}")
def get_contestation(cid: str):
    if cid not in contestations:
        raise HTTPException(404, "Contestation not found")
    return contestations[cid]

@app.patch("/v1/contestations/{cid}/advance")
def advance_contestation(cid: str, target_state: ContestState = Query(...), reviewer_id: str = Query(""), rationale: str = Query("")):
    if cid not in contestations:
        raise HTTPException(404, "Contestation not found")
    c = contestations[cid]
    allowed = CONTEST_TRANSITIONS.get(c["state"], [])
    if target_state not in allowed:
        raise HTTPException(400, f"Cannot transition from {c['state']} to {target_state}")

    c["state"] = target_state
    if reviewer_id:
        c["reviewer_id"] = reviewer_id
    if target_state in ("upheld", "overturned"):
        if not rationale:
            raise HTTPException(400, "Resolution rationale is required")
        c["resolution_rationale"] = rationale
        c["resolved_at"] = _now()
    return c

# ── Impact ───────────────────────────────────────────────────────────
@app.get("/v1/decisions/{did}/impact")
def impact(did: str):
    if did not in decisions:
        raise HTTPException(404, "Decision not found")
    d = decisions[did]
    related_contests = [c for c in contestations.values() if c["decision_id"] == did]
    overturned = sum(1 for c in related_contests if c["state"] == "overturned")

    return {
        "decision_id": did,
        "decision_type": d["decision_type"],
        "severity": d["severity"],
        "affected_entity_count": len(d["affected_entities"]),
        "affected_entities": d["affected_entities"],
        "contestations_filed": len(related_contests),
        "overturned": overturned,
        "reversal_rate": round(overturned / max(len(related_contests), 1), 3) if related_contests else 0,
        "chain_length": len(d["reasoning_chain"]),
    }

# ── Patterns ─────────────────────────────────────────────────────────
@app.get("/v1/patterns")
def patterns():
    dl = list(decisions.values())
    by_type = Counter(d["decision_type"] for d in dl)
    by_severity = Counter(d["severity"] for d in dl)

    # Average chain length per type
    chain_by_type = {}
    for d in dl:
        dt = d["decision_type"]
        if dt not in chain_by_type:
            chain_by_type[dt] = []
        chain_by_type[dt].append(len(d["reasoning_chain"]))
    avg_chain = {k: round(sum(v) / len(v), 1) for k, v in chain_by_type.items()}

    # Model usage frequency
    model_usage = Counter()
    for d in dl:
        for s in d["reasoning_chain"]:
            if s.get("model_reference"):
                model_usage[s["model_reference"]] += 1

    return {
        "total_decisions": len(dl),
        "by_type": dict(by_type),
        "by_severity": dict(by_severity),
        "avg_chain_length_by_type": avg_chain,
        "model_usage": dict(model_usage.most_common(10)),
        "avg_overall_chain_length": round(sum(len(d["reasoning_chain"]) for d in dl) / max(len(dl), 1), 1),
    }

# ── Analytics ────────────────────────────────────────────────────────
@app.get("/v1/analytics")
def analytics():
    dl = list(decisions.values())
    cl = list(contestations.values())
    by_type = Counter(d["decision_type"] for d in dl)
    by_contest_state = Counter(c["state"] for c in cl)
    overturned = sum(1 for c in cl if c["state"] == "overturned")
    upheld = sum(1 for c in cl if c["state"] == "upheld")

    total_steps = sum(len(d["reasoning_chain"]) for d in dl)
    decisions_with_chain = sum(1 for d in dl if d["reasoning_chain"])

    return {
        "total_decisions": len(dl),
        "by_decision_type": dict(by_type),
        "total_reasoning_steps": total_steps,
        "decisions_with_chain": decisions_with_chain,
        "explainability_coverage": round(decisions_with_chain / max(len(dl), 1), 3),
        "avg_chain_length": round(total_steps / max(len(dl), 1), 1),
        "total_contestations": len(cl),
        "by_contestation_state": dict(by_contest_state),
        "overturn_rate": round(overturned / max(overturned + upheld, 1), 3),
        "total_affected_entities": sum(len(d["affected_entities"]) for d in dl),
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9934)
