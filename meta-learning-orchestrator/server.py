"""Meta-Learning Orchestrator — Phase 29 Service 1 · Port 9920"""

from __future__ import annotations
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum
import uuid, random, math

app = FastAPI(title="Meta-Learning Orchestrator", version="0.29.1")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Enums ────────────────────────────────────────────────────────────
class ComponentType(str, Enum):
    classifier = "classifier"
    detector = "detector"
    recommender = "recommender"
    generator = "generator"
    embedder = "embedder"
    ranker = "ranker"
    agent = "agent"

class ParamType(str, Enum):
    float_type = "float"
    int_type = "int"
    bool_type = "bool"
    categorical = "categorical"

class Strategy(str, Enum):
    grid_search = "grid_search"
    random_search = "random_search"
    bayesian_optimisation = "bayesian_optimisation"
    evolutionary = "evolutionary"
    bandit = "bandit"
    transfer_learning = "transfer_learning"

class MetricType(str, Enum):
    accuracy = "accuracy"
    latency_p99 = "latency_p99"
    throughput = "throughput"
    false_positive_rate = "false_positive_rate"
    false_negative_rate = "false_negative_rate"
    resource_usage = "resource_usage"
    drift_score = "drift_score"
    user_satisfaction = "user_satisfaction"

# ── Models ───────────────────────────────────────────────────────────
class ComponentCreate(BaseModel):
    name: str
    component_type: ComponentType
    version: str = "1.0.0"
    description: str = ""

class ConfigParam(BaseModel):
    name: str
    param_type: ParamType
    current_value: float | int | bool | str = 0.5
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    choices: list[str] = []
    sensitivity: float = Field(0.5, ge=0, le=1)

class SignalRecord(BaseModel):
    metric_type: MetricType
    value: float
    context: str = ""

class TrialCreate(BaseModel):
    component_id: str
    strategy: Strategy
    target_metric: MetricType = MetricType.accuracy
    iterations: int = Field(10, ge=1, le=100)

# ── Stores ───────────────────────────────────────────────────────────
components: dict[str, dict] = {}
trials: dict[str, dict] = {}

def _now():
    return datetime.now(timezone.utc).isoformat()

# ── Health ───────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "service": "meta-learning-orchestrator",
        "status": "healthy",
        "version": "0.29.1",
        "components": len(components),
        "trials": len(trials),
    }

# ── Components ───────────────────────────────────────────────────────
@app.post("/v1/components", status_code=201)
def create_component(body: ComponentCreate):
    cid = str(uuid.uuid4())
    rec = {
        "id": cid,
        **body.model_dump(),
        "configs": [],
        "signals": [],
        "config_versions": [],
        "created_at": _now(),
    }
    components[cid] = rec
    return rec

@app.get("/v1/components")
def list_components(component_type: Optional[ComponentType] = None):
    out = list(components.values())
    if component_type:
        out = [c for c in out if c["component_type"] == component_type]
    enriched = []
    for c in out:
        latest_signals = {}
        for s in c["signals"][-20:]:
            latest_signals[s["metric_type"]] = s["value"]
        enriched.append({**{k: v for k, v in c.items() if k != "signals"}, "latest_metrics": latest_signals, "signal_count": len(c["signals"])})
    return enriched

@app.get("/v1/components/{cid}")
def get_component(cid: str):
    if cid not in components:
        raise HTTPException(404, "Component not found")
    c = components[cid]
    latest = {}
    for s in c["signals"][-20:]:
        latest[s["metric_type"]] = s["value"]
    return {**c, "latest_metrics": latest}

# ── Configs ──────────────────────────────────────────────────────────
@app.post("/v1/components/{cid}/configs")
def add_config(cid: str, body: ConfigParam):
    if cid not in components:
        raise HTTPException(404, "Component not found")
    entry = {"id": str(uuid.uuid4()), **body.model_dump(), "added_at": _now()}
    components[cid]["configs"].append(entry)
    components[cid]["config_versions"].append({"configs": [e.copy() for e in components[cid]["configs"]], "version": len(components[cid]["config_versions"]) + 1, "saved_at": _now()})
    return entry

# ── Signals ──────────────────────────────────────────────────────────
@app.post("/v1/components/{cid}/signals")
def record_signal(cid: str, body: SignalRecord):
    if cid not in components:
        raise HTTPException(404, "Component not found")
    entry = {"id": str(uuid.uuid4()), **body.model_dump(), "recorded_at": _now()}
    components[cid]["signals"].append(entry)
    return entry

# ── Trials ───────────────────────────────────────────────────────────
@app.post("/v1/trials", status_code=201)
def run_trial(body: TrialCreate):
    if body.component_id not in components:
        raise HTTPException(404, "Component not found")
    comp = components[body.component_id]
    tid = str(uuid.uuid4())

    # Simulate trial iterations
    baseline_signals = [s for s in comp["signals"] if s["metric_type"] == body.target_metric]
    baseline_val = baseline_signals[-1]["value"] if baseline_signals else 0.5

    iterations = []
    best_val = baseline_val
    best_config_delta = {}
    for i in range(body.iterations):
        # Simulate config perturbation
        delta = random.uniform(-0.05, 0.08)
        val = max(0, min(1, baseline_val + delta + random.gauss(0, 0.02)))
        improved = val > best_val
        if improved:
            best_val = val
            best_config_delta = {p["name"]: round(random.uniform(-0.1, 0.1), 4) for p in comp["configs"][:3]}
        iterations.append({"iteration": i + 1, "value": round(val, 4), "improved": improved})

    improvement_pct = round((best_val - baseline_val) / max(baseline_val, 0.001) * 100, 2)
    significant = abs(improvement_pct) > 2  # 2% threshold

    rec = {
        "id": tid,
        "component_id": body.component_id,
        "component_name": comp["name"],
        "strategy": body.strategy,
        "target_metric": body.target_metric,
        "baseline_value": round(baseline_val, 4),
        "best_value": round(best_val, 4),
        "improvement_pct": improvement_pct,
        "statistically_significant": significant,
        "best_config_delta": best_config_delta,
        "iterations": iterations,
        "total_iterations": body.iterations,
        "created_at": _now(),
    }
    trials[tid] = rec
    return rec

@app.get("/v1/trials")
def list_trials(strategy: Optional[Strategy] = None, component_id: Optional[str] = None):
    out = list(trials.values())
    if strategy:
        out = [t for t in out if t["strategy"] == strategy]
    if component_id:
        out = [t for t in out if t["component_id"] == component_id]
    return [{k: v for k, v in t.items() if k != "iterations"} for t in out]

@app.get("/v1/trials/{tid}")
def get_trial(tid: str):
    if tid not in trials:
        raise HTTPException(404, "Trial not found")
    return trials[tid]

# ── Recommendations ──────────────────────────────────────────────────
@app.get("/v1/components/{cid}/recommendations")
def recommendations(cid: str):
    if cid not in components:
        raise HTTPException(404, "Component not found")
    comp = components[cid]
    comp_trials = [t for t in trials.values() if t["component_id"] == cid and t["statistically_significant"]]

    if not comp_trials:
        return {"component_id": cid, "recommendations": [], "message": "No significant trials yet — run more trials"}

    best = max(comp_trials, key=lambda t: t["improvement_pct"])
    recs = []
    for param_name, delta in best["best_config_delta"].items():
        current = next((p for p in comp["configs"] if p["name"] == param_name), None)
        if current:
            recs.append({
                "parameter": param_name,
                "current_value": current["current_value"],
                "recommended_delta": delta,
                "estimated_improvement_pct": round(best["improvement_pct"] * abs(delta) / max(sum(abs(d) for d in best["best_config_delta"].values()), 0.01), 2),
                "confidence": round(min(0.95, 0.5 + len(comp_trials) * 0.05), 3),
            })

    return {
        "component_id": cid,
        "best_strategy": best["strategy"],
        "total_improvement_pct": best["improvement_pct"],
        "recommendations": recs,
        "trials_analysed": len(comp_trials),
    }

# ── Strategy Affinity ────────────────────────────────────────────────
@app.get("/v1/strategy-affinity")
def strategy_affinity():
    matrix: dict[str, dict[str, dict]] = {}
    for t in trials.values():
        ct = components.get(t["component_id"], {}).get("component_type", "unknown")
        if ct not in matrix:
            matrix[ct] = {}
        strat = t["strategy"]
        if strat not in matrix[ct]:
            matrix[ct][strat] = {"trials": 0, "avg_improvement": 0, "significant_count": 0}
        m = matrix[ct][strat]
        m["trials"] += 1
        m["avg_improvement"] = round((m["avg_improvement"] * (m["trials"] - 1) + t["improvement_pct"]) / m["trials"], 2)
        if t["statistically_significant"]:
            m["significant_count"] += 1

    # Find best strategy per component type
    best_per_type = {}
    for ct, strategies in matrix.items():
        best = max(strategies.items(), key=lambda x: x[1]["avg_improvement"], default=(None, None))
        if best[0]:
            best_per_type[ct] = best[0]

    return {"affinity_matrix": matrix, "best_strategy_per_type": best_per_type}

# ── Analytics ────────────────────────────────────────────────────────
@app.get("/v1/analytics")
def analytics():
    tl = list(trials.values())
    by_strategy = {}
    for t in tl:
        by_strategy[t["strategy"]] = by_strategy.get(t["strategy"], 0) + 1
    significant = [t for t in tl if t["statistically_significant"]]
    avg_improvement = round(sum(t["improvement_pct"] for t in significant) / max(len(significant), 1), 2)
    return {
        "total_components": len(components),
        "total_trials": len(tl),
        "by_strategy": by_strategy,
        "significant_trials": len(significant),
        "significance_rate": round(len(significant) / max(len(tl), 1), 3),
        "avg_improvement_pct": avg_improvement,
        "total_signals_recorded": sum(len(c["signals"]) for c in components.values()),
        "total_config_versions": sum(len(c["config_versions"]) for c in components.values()),
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9920)
