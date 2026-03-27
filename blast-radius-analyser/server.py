"""Blast Radius Analyser — Phase 28 Service 3 · Port 9917"""

from __future__ import annotations
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum
import uuid, random
from collections import deque

app = FastAPI(title="Blast Radius Analyser", version="0.28.3")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Enums ────────────────────────────────────────────────────────────
class ComponentType(str, Enum):
    service = "service"
    database = "database"
    cache = "cache"
    queue = "queue"
    gateway = "gateway"
    storage = "storage"
    model_server = "model_server"

class FailureMode(str, Enum):
    crash = "crash"
    degradation = "degradation"
    latency_spike = "latency_spike"
    data_loss = "data_loss"
    byzantine = "byzantine"

FAILURE_PROPAGATION = {"crash": 0.9, "degradation": 0.5, "latency_spike": 0.4, "data_loss": 0.7, "byzantine": 0.6}

class DependencyType(str, Enum):
    data = "data"
    control = "control"
    health = "health"

class ContainmentStrategy(str, Enum):
    circuit_breaker = "circuit_breaker"
    bulkhead = "bulkhead"
    timeout = "timeout"
    fallback = "fallback"

# ── Models ───────────────────────────────────────────────────────────
class ComponentCreate(BaseModel):
    name: str
    component_type: ComponentType
    criticality: int = Field(5, ge=1, le=10)
    health_status: str = Field("healthy", pattern="^(healthy|degraded|unhealthy)$")

class DependencyCreate(BaseModel):
    from_component_id: str
    to_component_id: str
    dependency_type: DependencyType = DependencyType.data
    coupling_strength: float = Field(0.5, ge=0, le=1)

class SimulationRequest(BaseModel):
    origin_component_id: str
    failure_mode: FailureMode
    severity: float = Field(0.7, ge=0, le=1)
    dampening_factor: float = Field(0.3, ge=0, le=1)

class WhatIfRequest(BaseModel):
    origin_component_id: str
    failure_mode: FailureMode
    severity: float = Field(0.7, ge=0, le=1)
    proposed_containment: dict[str, ContainmentStrategy] = {}

# ── Stores ───────────────────────────────────────────────────────────
components: dict[str, dict] = {}
dependencies: dict[str, dict] = {}
simulations: dict[str, dict] = {}

def _now():
    return datetime.now(timezone.utc).isoformat()

# ── Propagation Engine ───────────────────────────────────────────────
def _build_adj() -> dict[str, list[dict]]:
    adj: dict[str, list[dict]] = {cid: [] for cid in components}
    for d in dependencies.values():
        if d["from_component_id"] in adj:
            adj[d["from_component_id"]].append(d)
    return adj

def _propagate(origin: str, failure_mode: str, severity: float, dampening: float, containment_ids: set[str] | None = None) -> dict:
    """BFS propagation with dampening."""
    adj = _build_adj()
    containment_ids = containment_ids or set()

    visited: dict[str, dict] = {}
    queue: deque[tuple[str, float, int]] = deque()
    queue.append((origin, severity, 0))
    cascade_path: list[dict] = []

    while queue:
        cid, impact, depth = queue.popleft()
        if cid in visited:
            continue
        if cid in containment_ids and cid != origin:
            cascade_path.append({"component_id": cid, "name": components.get(cid, {}).get("name", "?"), "impact": 0, "depth": depth, "contained": True})
            continue

        comp = components.get(cid, {})
        visited[cid] = {"component_id": cid, "name": comp.get("name", "?"), "criticality": comp.get("criticality", 5), "impact": round(impact, 3), "depth": depth}
        cascade_path.append(visited[cid])

        for edge in adj.get(cid, []):
            target = edge["to_component_id"]
            if target not in visited:
                prop_prob = FAILURE_PROPAGATION.get(failure_mode, 0.5) * edge["coupling_strength"]
                new_impact = impact * prop_prob * (1 - dampening)
                if new_impact > 0.05:  # threshold
                    queue.append((target, new_impact, depth + 1))

    affected = [v for v in visited.values() if v["component_id"] != origin]
    max_depth = max((v["depth"] for v in visited.values()), default=0)
    total_criticality = sum(v["criticality"] * v["impact"] for v in affected)
    blast_score = round(len(affected) * total_criticality * max_depth / max(len(components), 1) * 100, 1)

    return {
        "origin": origin,
        "origin_name": components.get(origin, {}).get("name", "?"),
        "failure_mode": failure_mode,
        "severity": severity,
        "affected_components": len(affected),
        "total_components": len(components),
        "cascade_depth": max_depth,
        "blast_radius_score": min(1000, blast_score),
        "cascade_path": cascade_path,
        "amplification_points": [v["component_id"] for v in affected if len(adj.get(v["component_id"], [])) > 2],
    }

# ── Health ───────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "service": "blast-radius-analyser",
        "status": "healthy",
        "version": "0.28.3",
        "components": len(components),
        "dependencies": len(dependencies),
        "simulations": len(simulations),
    }

# ── Components ───────────────────────────────────────────────────────
@app.post("/v1/components", status_code=201)
def create_component(body: ComponentCreate):
    cid = str(uuid.uuid4())
    rec = {"id": cid, **body.model_dump(), "created_at": _now()}
    components[cid] = rec
    return rec

@app.get("/v1/components")
def list_components(component_type: Optional[ComponentType] = None):
    out = list(components.values())
    if component_type:
        out = [c for c in out if c["component_type"] == component_type]
    return out

@app.get("/v1/components/{cid}")
def get_component(cid: str):
    if cid not in components:
        raise HTTPException(404, "Component not found")
    c = components[cid]
    deps_out = [d for d in dependencies.values() if d["from_component_id"] == cid]
    deps_in = [d for d in dependencies.values() if d["to_component_id"] == cid]
    return {**c, "outgoing_dependencies": len(deps_out), "incoming_dependencies": len(deps_in)}

# ── Dependencies ─────────────────────────────────────────────────────
@app.post("/v1/dependencies", status_code=201)
def add_dependency(body: DependencyCreate):
    if body.from_component_id not in components:
        raise HTTPException(404, f"Component {body.from_component_id} not found")
    if body.to_component_id not in components:
        raise HTTPException(404, f"Component {body.to_component_id} not found")
    did = str(uuid.uuid4())
    rec = {"id": did, **body.model_dump(), "created_at": _now()}
    dependencies[did] = rec
    return rec

@app.get("/v1/dependencies")
def list_dependencies():
    return list(dependencies.values())

# ── Graph ────────────────────────────────────────────────────────────
@app.get("/v1/graph")
def get_graph():
    nodes = [{"id": c["id"], "name": c["name"], "type": c["component_type"], "criticality": c["criticality"]} for c in components.values()]
    edges = [{"from": d["from_component_id"], "to": d["to_component_id"], "type": d["dependency_type"], "coupling": d["coupling_strength"]} for d in dependencies.values()]
    return {"nodes": nodes, "edges": edges, "node_count": len(nodes), "edge_count": len(edges)}

# ── Simulate ─────────────────────────────────────────────────────────
@app.post("/v1/simulate", status_code=201)
def simulate(body: SimulationRequest):
    if body.origin_component_id not in components:
        raise HTTPException(404, "Origin component not found")
    result = _propagate(body.origin_component_id, body.failure_mode, body.severity, body.dampening_factor)
    sid = str(uuid.uuid4())
    sim = {"id": sid, **result, "dampening_factor": body.dampening_factor, "simulated_at": _now()}
    simulations[sid] = sim
    return sim

@app.get("/v1/simulations")
def list_simulations(limit: int = Query(20, ge=1)):
    return sorted(simulations.values(), key=lambda s: s["blast_radius_score"], reverse=True)[:limit]

@app.get("/v1/simulations/{sid}")
def get_simulation(sid: str):
    if sid not in simulations:
        raise HTTPException(404, "Simulation not found")
    return simulations[sid]

# ── What-If ──────────────────────────────────────────────────────────
@app.post("/v1/what-if")
def what_if(body: WhatIfRequest):
    if body.origin_component_id not in components:
        raise HTTPException(404, "Origin component not found")

    # Without containment
    baseline = _propagate(body.origin_component_id, body.failure_mode, body.severity, 0.3)

    # With containment — treated as isolation points
    contained = _propagate(body.origin_component_id, body.failure_mode, body.severity, 0.3, set(body.proposed_containment.keys()))

    return {
        "baseline": {"affected": baseline["affected_components"], "blast_score": baseline["blast_radius_score"], "cascade_depth": baseline["cascade_depth"]},
        "with_containment": {"affected": contained["affected_components"], "blast_score": contained["blast_radius_score"], "cascade_depth": contained["cascade_depth"]},
        "reduction": {
            "affected_reduction": baseline["affected_components"] - contained["affected_components"],
            "score_reduction": round(baseline["blast_radius_score"] - contained["blast_radius_score"], 1),
            "depth_reduction": baseline["cascade_depth"] - contained["cascade_depth"],
            "effectiveness_pct": round((1 - contained["blast_radius_score"] / max(baseline["blast_radius_score"], 0.01)) * 100, 1),
        },
        "containment_applied": {cid: strat for cid, strat in body.proposed_containment.items()},
    }

# ── Containment Recommendations ──────────────────────────────────────
@app.get("/v1/containment-recommendations")
def containment_recommendations():
    adj = _build_adj()
    recs = []
    for cid, comp in components.items():
        outgoing = adj.get(cid, [])
        incoming = [d for d in dependencies.values() if d["to_component_id"] == cid]
        fan_out = len(outgoing)
        fan_in = len(incoming)
        avg_coupling = sum(d["coupling_strength"] for d in outgoing) / max(fan_out, 1)

        if fan_out >= 3 or (comp["criticality"] >= 7 and avg_coupling > 0.6):
            best_strategy = "circuit_breaker" if fan_out >= 4 else "bulkhead" if avg_coupling > 0.7 else "timeout"
            risk_reduction = round(min(50, fan_out * avg_coupling * 15), 1)
            recs.append({
                "component_id": cid,
                "component_name": comp["name"],
                "strategy": best_strategy,
                "reason": f"High fan-out ({fan_out}) with avg coupling {avg_coupling:.2f}",
                "estimated_risk_reduction_pct": risk_reduction,
                "effort_hours": {"circuit_breaker": 8, "bulkhead": 12, "timeout": 4, "fallback": 6}.get(best_strategy, 8),
                "priority": round(risk_reduction / max({"circuit_breaker": 8, "bulkhead": 12, "timeout": 4, "fallback": 6}.get(best_strategy, 8), 1), 2),
            })
    return sorted(recs, key=lambda r: r["priority"], reverse=True)

# ── Analytics ────────────────────────────────────────────────────────
@app.get("/v1/analytics")
def analytics():
    sl = list(simulations.values())
    by_failure = {}
    for s in sl:
        by_failure[s["failure_mode"]] = by_failure.get(s["failure_mode"], 0) + 1
    avg_blast = round(sum(s["blast_radius_score"] for s in sl) / max(len(sl), 1), 1)
    avg_depth = round(sum(s["cascade_depth"] for s in sl) / max(len(sl), 1), 1)

    # Most vulnerable components (appear most in cascade paths)
    vuln_count: dict[str, int] = {}
    for s in sl:
        for step in s.get("cascade_path", []):
            cid = step["component_id"]
            if cid != s["origin"]:
                vuln_count[cid] = vuln_count.get(cid, 0) + 1
    top_vulnerable = sorted(vuln_count.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "total_components": len(components),
        "total_dependencies": len(dependencies),
        "total_simulations": len(sl),
        "by_failure_mode": by_failure,
        "avg_blast_radius_score": avg_blast,
        "avg_cascade_depth": avg_depth,
        "max_blast_radius_score": max((s["blast_radius_score"] for s in sl), default=0),
        "most_vulnerable_components": [{"component_id": cid, "name": components.get(cid, {}).get("name", "?"), "times_affected": cnt} for cid, cnt in top_vulnerable],
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9917)
