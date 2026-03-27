"""Proactive Defence Orchestrator — Phase 27 Service 4 · Port 9913"""

from __future__ import annotations
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum
import uuid, random

app = FastAPI(title="Proactive Defence Orchestrator", version="0.27.4")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Enums ────────────────────────────────────────────────────────────
class SignalType(str, Enum):
    threat_intel = "threat_intel"
    anomaly_detection = "anomaly_detection"
    behaviour_indicator = "behaviour_indicator"
    vulnerability_disclosure = "vulnerability_disclosure"
    dark_web_mention = "dark_web_mention"
    geopolitical_event = "geopolitical_event"

class CMType(str, Enum):
    firewall_rule = "firewall_rule"
    access_restriction = "access_restriction"
    rate_limit = "rate_limit"
    isolation = "isolation"
    backup_trigger = "backup_trigger"
    monitoring_increase = "monitoring_increase"
    credential_rotation = "credential_rotation"
    patch_acceleration = "patch_acceleration"
    deception_deploy = "deception_deploy"

class DisruptionRisk(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"

class DeploymentState(str, Enum):
    queued = "queued"
    deploying = "deploying"
    active = "active"
    monitoring = "monitoring"
    withdrawn = "withdrawn"

DEPLOYMENT_TRANSITIONS = {
    "queued": ["deploying"],
    "deploying": ["active"],
    "active": ["monitoring", "withdrawn"],
    "monitoring": ["withdrawn", "active"],
}

class ImpactLevel(str, Enum):
    none = "none"
    minor = "minor"
    moderate = "moderate"
    significant = "significant"

# ── Models ───────────────────────────────────────────────────────────
class SignalCreate(BaseModel):
    signal_type: SignalType
    source: str = ""
    description: str
    confidence: float = Field(0.5, ge=0, le=1)
    relevance_score: float = Field(0.5, ge=0, le=1)
    indicators: list[str] = []

class HypothesisCreate(BaseModel):
    name: str
    description: str = ""
    signal_ids: list[str] = []
    attack_type: str = ""
    target_assets: list[str] = []
    estimated_hours_to_attack: int = Field(48, ge=1)

class CountermeasureCreate(BaseModel):
    name: str
    cm_type: CMType
    description: str = ""
    deployment_time_minutes: int = Field(5, ge=1)
    risk_of_disruption: DisruptionRisk = DisruptionRisk.low
    reversible: bool = True
    ttl_hours: int = Field(24, ge=1)

class DeployRequest(BaseModel):
    countermeasure_id: str
    target_scope: str = "specific_asset"

# ── Stores ───────────────────────────────────────────────────────────
signals: dict[str, dict] = {}
hypotheses: dict[str, dict] = {}
countermeasures: dict[str, dict] = {}
deployments: dict[str, dict] = {}

def _now():
    return datetime.now(timezone.utc).isoformat()

# ── Signal Fusion ────────────────────────────────────────────────────
def _fuse_signals(signal_ids: list[str]) -> dict:
    sigs = [signals[sid] for sid in signal_ids if sid in signals]
    if not sigs:
        return {"combined_confidence": 0, "source_diversity": 0, "signal_count": 0}
    avg_conf = sum(s["confidence"] for s in sigs) / len(sigs)
    avg_rel = sum(s["relevance_score"] for s in sigs) / len(sigs)
    sources = set(s["source"] for s in sigs)
    diversity_bonus = min(0.2, len(sources) * 0.05)
    corroboration = min(0.15, (len(sigs) - 1) * 0.05)
    combined = min(1.0, avg_conf * avg_rel + diversity_bonus + corroboration)
    return {
        "combined_confidence": round(combined, 3),
        "avg_confidence": round(avg_conf, 3),
        "avg_relevance": round(avg_rel, 3),
        "source_diversity": len(sources),
        "diversity_bonus": round(diversity_bonus, 3),
        "corroboration_bonus": round(corroboration, 3),
        "signal_count": len(sigs),
    }

# ── Health ───────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "service": "proactive-defence-orchestrator",
        "status": "healthy",
        "version": "0.27.4",
        "signals": len(signals),
        "hypotheses": len(hypotheses),
        "countermeasures": len(countermeasures),
        "active_deployments": sum(1 for d in deployments.values() if d["state"] in ("active", "monitoring")),
    }

# ── Signals ──────────────────────────────────────────────────────────
@app.post("/v1/signals", status_code=201)
def create_signal(body: SignalCreate):
    sid = str(uuid.uuid4())
    rec = {"id": sid, **body.model_dump(), "created_at": _now()}
    signals[sid] = rec
    return rec

@app.get("/v1/signals")
def list_signals(signal_type: Optional[SignalType] = None, min_confidence: Optional[float] = None):
    out = list(signals.values())
    if signal_type:
        out = [s for s in out if s["signal_type"] == signal_type]
    if min_confidence is not None:
        out = [s for s in out if s["confidence"] >= min_confidence]
    return sorted(out, key=lambda s: s["confidence"] * s["relevance_score"], reverse=True)

# ── Hypotheses ───────────────────────────────────────────────────────
@app.post("/v1/hypotheses", status_code=201)
def create_hypothesis(body: HypothesisCreate):
    hid = str(uuid.uuid4())
    fusion = _fuse_signals(body.signal_ids)
    rec = {
        "id": hid,
        **body.model_dump(),
        "fusion": fusion,
        "deployments": [],
        "created_at": _now(),
    }
    hypotheses[hid] = rec
    return rec

@app.get("/v1/hypotheses")
def list_hypotheses(min_confidence: Optional[float] = None):
    out = list(hypotheses.values())
    if min_confidence is not None:
        out = [h for h in out if h["fusion"]["combined_confidence"] >= min_confidence]
    return sorted(out, key=lambda h: h["fusion"]["combined_confidence"], reverse=True)

@app.get("/v1/hypotheses/{hid}")
def get_hypothesis(hid: str):
    if hid not in hypotheses:
        raise HTTPException(404, "Hypothesis not found")
    return hypotheses[hid]

# ── Countermeasures ──────────────────────────────────────────────────
@app.post("/v1/countermeasures", status_code=201)
def create_countermeasure(body: CountermeasureCreate):
    cid = str(uuid.uuid4())
    rec = {"id": cid, **body.model_dump(), "created_at": _now()}
    countermeasures[cid] = rec
    return rec

@app.get("/v1/countermeasures")
def list_countermeasures(cm_type: Optional[CMType] = None):
    out = list(countermeasures.values())
    if cm_type:
        out = [c for c in out if c["cm_type"] == cm_type]
    return out

# ── Deploy ───────────────────────────────────────────────────────────
@app.post("/v1/hypotheses/{hid}/deploy")
def deploy_countermeasure(hid: str, body: DeployRequest):
    if hid not in hypotheses:
        raise HTTPException(404, "Hypothesis not found")
    if body.countermeasure_id not in countermeasures:
        raise HTTPException(404, "Countermeasure not found")

    cm = countermeasures[body.countermeasure_id]
    did = str(uuid.uuid4())
    dep = {
        "id": did,
        "hypothesis_id": hid,
        "countermeasure_id": body.countermeasure_id,
        "countermeasure_name": cm["name"],
        "cm_type": cm["cm_type"],
        "target_scope": body.target_scope,
        "state": "active",  # auto-deploy for simulation
        "deployed_at": _now(),
        "withdrawn_at": None,
        "ttl_hours": cm["ttl_hours"],
        "attacks_prevented": random.randint(0, 5),
        "false_positives": random.randint(0, 2),
    }
    deployments[did] = dep
    hypotheses[hid]["deployments"].append(did)
    return dep

@app.post("/v1/deployments/{did}/withdraw")
def withdraw_deployment(did: str, reason: str = ""):
    if did not in deployments:
        raise HTTPException(404, "Deployment not found")
    d = deployments[did]
    d["state"] = "withdrawn"
    d["withdrawn_at"] = _now()
    d["withdraw_reason"] = reason
    return d

# ── Impact Assessment ────────────────────────────────────────────────
@app.post("/v1/hypotheses/{hid}/impact")
def assess_impact(hid: str, countermeasure_id: str = Query(...)):
    if hid not in hypotheses:
        raise HTTPException(404, "Hypothesis not found")
    if countermeasure_id not in countermeasures:
        raise HTTPException(404, "Countermeasure not found")

    cm = countermeasures[countermeasure_id]
    h = hypotheses[hid]
    affected = len(h["target_assets"])
    disruption = cm["risk_of_disruption"]
    impact_map = {"low": "none", "medium": "minor", "high": "moderate"}
    if affected > 5:
        impact_map = {"low": "minor", "medium": "moderate", "high": "significant"}

    return {
        "hypothesis_id": hid,
        "countermeasure_id": countermeasure_id,
        "affected_services": affected,
        "estimated_downtime_minutes": cm["deployment_time_minutes"] * (2 if disruption == "high" else 1),
        "user_impact_level": impact_map.get(disruption, "minor"),
        "approval_required": disruption == "high" or affected > 3,
        "reversible": cm["reversible"],
    }

# ── Effectiveness ────────────────────────────────────────────────────
@app.get("/v1/effectiveness")
def effectiveness():
    dl = list(deployments.values())
    active = [d for d in dl if d["state"] in ("active", "monitoring")]
    total_prevented = sum(d["attacks_prevented"] for d in dl)
    total_fp = sum(d["false_positives"] for d in dl)
    avg_ttd = random.uniform(2, 15)  # simulated avg time to deploy
    return {
        "total_deployments": len(dl),
        "active_deployments": len(active),
        "withdrawn": sum(1 for d in dl if d["state"] == "withdrawn"),
        "total_attacks_prevented": total_prevented,
        "total_false_positives": total_fp,
        "false_positive_rate": round(total_fp / max(total_prevented + total_fp, 1), 3),
        "avg_time_to_deploy_minutes": round(avg_ttd, 1),
    }

# ── Analytics ────────────────────────────────────────────────────────
@app.get("/v1/analytics")
def analytics():
    sl = list(signals.values())
    hl = list(hypotheses.values())
    dl = list(deployments.values())
    by_signal_type = {}
    for s in sl:
        by_signal_type[s["signal_type"]] = by_signal_type.get(s["signal_type"], 0) + 1
    by_cm_type = {}
    for d in dl:
        by_cm_type[d["cm_type"]] = by_cm_type.get(d["cm_type"], 0) + 1
    by_deploy_state = {}
    for d in dl:
        by_deploy_state[d["state"]] = by_deploy_state.get(d["state"], 0) + 1
    return {
        "total_signals": len(sl),
        "signals_by_type": by_signal_type,
        "total_hypotheses": len(hl),
        "total_countermeasures": len(countermeasures),
        "total_deployments": len(dl),
        "deployments_by_state": by_deploy_state,
        "deployments_by_cm_type": by_cm_type,
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9913)
