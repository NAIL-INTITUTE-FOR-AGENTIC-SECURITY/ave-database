"""Feedback Loop Analyser — Phase 29 Service 2 · Port 9921"""

from __future__ import annotations
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum
import uuid, random

app = FastAPI(title="Feedback Loop Analyser", version="0.29.2")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Enums ────────────────────────────────────────────────────────────
class NodeType(str, Enum):
    sensor = "sensor"
    processor = "processor"
    decision_engine = "decision_engine"
    actuator = "actuator"
    data_store = "data_store"
    human_operator = "human_operator"

class LoopType(str, Enum):
    positive_reinforcing = "positive_reinforcing"
    negative_stabilising = "negative_stabilising"
    mixed = "mixed"
    unknown = "unknown"

class DampenType(str, Enum):
    rate_limiter = "rate_limiter"
    gain_cap = "gain_cap"
    delay_injection = "delay_injection"
    circuit_break = "circuit_break"

# ── Models ───────────────────────────────────────────────────────────
class NodeCreate(BaseModel):
    name: str
    node_type: NodeType
    throughput_baseline: float = Field(100, ge=0)
    criticality: int = Field(5, ge=1, le=10)

class EdgeCreate(BaseModel):
    from_node_id: str
    to_node_id: str
    signal_gain: float = Field(1.0, ge=0)
    delay_ms: float = Field(10, ge=0)

class DampenRequest(BaseModel):
    dampen_type: DampenType
    parameter: float = Field(0.5, ge=0, le=1)

# ── Stores ───────────────────────────────────────────────────────────
nodes: dict[str, dict] = {}
edges: dict[str, dict] = {}
loops: dict[str, dict] = {}

def _now():
    return datetime.now(timezone.utc).isoformat()

# ── Loop Detection (DFS cycle finding) ───────────────────────────────
def _build_adj() -> dict[str, list[dict]]:
    adj: dict[str, list[dict]] = {nid: [] for nid in nodes}
    for e in edges.values():
        if e["from_node_id"] in adj:
            adj[e["from_node_id"]].append(e)
    return adj

def _find_cycles() -> list[list[str]]:
    adj = _build_adj()
    visited: set[str] = set()
    on_stack: set[str] = set()
    stack_path: list[str] = []
    found_cycles: list[list[str]] = []

    def dfs(node: str):
        visited.add(node)
        on_stack.add(node)
        stack_path.append(node)
        for edge in adj.get(node, []):
            target = edge["to_node_id"]
            if target not in visited:
                dfs(target)
            elif target in on_stack:
                idx = stack_path.index(target)
                cycle = stack_path[idx:] + [target]
                found_cycles.append(cycle)
        stack_path.pop()
        on_stack.discard(node)

    for nid in nodes:
        if nid not in visited:
            dfs(nid)
    return found_cycles

def _analyse_loop(cycle_nodes: list[str]) -> dict:
    """Analyse a detected loop."""
    adj = _build_adj()
    total_gain = 1.0
    total_delay = 0.0
    hop_details = []

    for i in range(len(cycle_nodes) - 1):
        src, dst = cycle_nodes[i], cycle_nodes[i + 1]
        edge = next((e for e in adj.get(src, []) if e["to_node_id"] == dst), None)
        gain = edge["signal_gain"] if edge else 1.0
        delay = edge["delay_ms"] if edge else 0
        total_gain *= gain
        total_delay += delay
        hop_details.append({
            "from": src, "to": dst,
            "from_name": nodes.get(src, {}).get("name", "?"),
            "to_name": nodes.get(dst, {}).get("name", "?"),
            "gain": gain, "delay_ms": delay,
        })

    # Classify
    if total_gain > 1.05:
        loop_type = "positive_reinforcing"
    elif total_gain < 0.95:
        loop_type = "negative_stabilising"
    elif 0.95 <= total_gain <= 1.05:
        loop_type = "mixed"
    else:
        loop_type = "unknown"

    runaway_risk = total_gain > 1.2
    avg_criticality = sum(nodes.get(n, {}).get("criticality", 5) for n in cycle_nodes[:-1]) / max(len(cycle_nodes) - 1, 1)
    stability = max(0, min(100, round(100 - (total_gain - 1) * 200 - (10 - avg_criticality) * 3, 1)))

    return {
        "loop_type": loop_type,
        "loop_length": len(cycle_nodes) - 1,
        "cumulative_gain": round(total_gain, 4),
        "total_delay_ms": round(total_delay, 1),
        "runaway_risk": runaway_risk,
        "stability_score": stability,
        "avg_criticality": round(avg_criticality, 1),
        "hops": hop_details,
    }

# ── Health ───────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "service": "feedback-loop-analyser",
        "status": "healthy",
        "version": "0.29.2",
        "nodes": len(nodes),
        "edges": len(edges),
        "loops_detected": len(loops),
    }

# ── Nodes ────────────────────────────────────────────────────────────
@app.post("/v1/nodes", status_code=201)
def create_node(body: NodeCreate):
    nid = str(uuid.uuid4())
    rec = {"id": nid, **body.model_dump(), "created_at": _now()}
    nodes[nid] = rec
    return rec

@app.get("/v1/nodes")
def list_nodes(node_type: Optional[NodeType] = None):
    out = list(nodes.values())
    if node_type:
        out = [n for n in out if n["node_type"] == node_type]
    return out

# ── Edges ────────────────────────────────────────────────────────────
@app.post("/v1/edges", status_code=201)
def create_edge(body: EdgeCreate):
    if body.from_node_id not in nodes:
        raise HTTPException(404, f"Node {body.from_node_id} not found")
    if body.to_node_id not in nodes:
        raise HTTPException(404, f"Node {body.to_node_id} not found")
    eid = str(uuid.uuid4())
    rec = {"id": eid, **body.model_dump(), "created_at": _now()}
    edges[eid] = rec
    return rec

@app.get("/v1/edges")
def list_edges():
    return list(edges.values())

# ── Detect Loops ─────────────────────────────────────────────────────
@app.post("/v1/detect-loops")
def detect_loops():
    cycles = _find_cycles()
    new_loops = []
    for cycle in cycles:
        cycle_key = "→".join(cycle)
        # Avoid duplicates
        if any(l.get("cycle_key") == cycle_key for l in loops.values()):
            continue
        lid = str(uuid.uuid4())
        analysis = _analyse_loop(cycle)
        rec = {
            "id": lid,
            "cycle_key": cycle_key,
            "node_ids": cycle,
            **analysis,
            "dampening_controls": [],
            "detected_at": _now(),
        }
        loops[lid] = rec
        new_loops.append(rec)
    return {"new_loops_detected": len(new_loops), "total_loops": len(loops), "loops": new_loops}

@app.get("/v1/loops")
def list_loops(loop_type: Optional[LoopType] = None):
    out = list(loops.values())
    if loop_type:
        out = [l for l in out if l["loop_type"] == loop_type]
    return sorted(out, key=lambda l: l["stability_score"])

@app.get("/v1/loops/{lid}")
def get_loop(lid: str):
    if lid not in loops:
        raise HTTPException(404, "Loop not found")
    return loops[lid]

# ── Trace ────────────────────────────────────────────────────────────
@app.post("/v1/loops/{lid}/trace")
def trace_loop(lid: str, initial_amplitude: float = Query(1.0, ge=0.01)):
    if lid not in loops:
        raise HTTPException(404, "Loop not found")
    lp = loops[lid]
    trace = []
    amplitude = initial_amplitude
    for hop in lp["hops"]:
        amplitude *= hop["gain"]
        # Apply dampening if present
        for dc in lp["dampening_controls"]:
            if dc["applied_at_hop_from"] == hop["from"]:
                if dc["dampen_type"] == "gain_cap":
                    amplitude = min(amplitude, dc["parameter"] * initial_amplitude * 2)
                elif dc["dampen_type"] == "rate_limiter":
                    amplitude *= (1 - dc["parameter"] * 0.5)
        trace.append({
            "from": hop["from_name"],
            "to": hop["to_name"],
            "gain": hop["gain"],
            "amplitude_after": round(amplitude, 4),
            "delay_ms": hop["delay_ms"],
        })
    return {
        "loop_id": lid,
        "initial_amplitude": initial_amplitude,
        "final_amplitude": round(amplitude, 4),
        "amplification_factor": round(amplitude / initial_amplitude, 4),
        "runaway": amplitude > initial_amplitude * 1.5,
        "trace": trace,
    }

# ── Dampen ───────────────────────────────────────────────────────────
@app.post("/v1/loops/{lid}/dampen")
def dampen_loop(lid: str, body: DampenRequest, at_node_id: str = Query(...)):
    if lid not in loops:
        raise HTTPException(404, "Loop not found")
    if at_node_id not in nodes:
        raise HTTPException(404, "Node not found")
    lp = loops[lid]
    control = {
        "id": str(uuid.uuid4()),
        "dampen_type": body.dampen_type,
        "parameter": body.parameter,
        "applied_at_hop_from": at_node_id,
        "applied_at": _now(),
    }
    lp["dampening_controls"].append(control)
    # Recalculate stability
    dampening_factor = sum(dc["parameter"] * 0.15 for dc in lp["dampening_controls"])
    lp["stability_score"] = min(100, round(lp["stability_score"] + dampening_factor * 100, 1))
    lp["runaway_risk"] = lp["stability_score"] < 40
    return {"control": control, "updated_stability": lp["stability_score"], "runaway_risk": lp["runaway_risk"]}

# ── Simulate ─────────────────────────────────────────────────────────
@app.post("/v1/loops/{lid}/simulate")
def simulate_dampening(lid: str, body: DampenRequest, at_node_id: str = Query(...)):
    if lid not in loops:
        raise HTTPException(404, "Loop not found")
    lp = loops[lid]
    current_stability = lp["stability_score"]
    dampening_boost = body.parameter * 15
    simulated_stability = min(100, round(current_stability + dampening_boost, 1))
    return {
        "loop_id": lid,
        "dampen_type": body.dampen_type,
        "at_node": at_node_id,
        "current_stability": current_stability,
        "simulated_stability": simulated_stability,
        "improvement": round(simulated_stability - current_stability, 1),
        "would_resolve_runaway": simulated_stability >= 60,
    }

# ── Stability Overview ───────────────────────────────────────────────
@app.get("/v1/stability-overview")
def stability_overview():
    ll = list(loops.values())
    if not ll:
        return {"message": "No loops detected", "total_loops": 0}

    stable = sum(1 for l in ll if l["stability_score"] >= 70)
    at_risk = sum(1 for l in ll if 40 <= l["stability_score"] < 70)
    critical = sum(1 for l in ll if l["stability_score"] < 40)
    avg_stability = round(sum(l["stability_score"] for l in ll) / len(ll), 1)
    runaway_count = sum(1 for l in ll if l["runaway_risk"])

    return {
        "total_loops": len(ll),
        "stable": stable,
        "at_risk": at_risk,
        "critical": critical,
        "avg_stability_score": avg_stability,
        "runaway_risks": runaway_count,
        "dampening_coverage": round(sum(1 for l in ll if l["dampening_controls"]) / len(ll), 3),
        "by_type": {lt: sum(1 for l in ll if l["loop_type"] == lt) for lt in set(l["loop_type"] for l in ll)},
    }

# ── Analytics ────────────────────────────────────────────────────────
@app.get("/v1/analytics")
def analytics():
    ll = list(loops.values())
    by_type = {}
    for l in ll:
        by_type[l["loop_type"]] = by_type.get(l["loop_type"], 0) + 1
    total_dampening = sum(len(l["dampening_controls"]) for l in ll)
    return {
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "total_loops": len(ll),
        "by_loop_type": by_type,
        "avg_loop_length": round(sum(l["loop_length"] for l in ll) / max(len(ll), 1), 1),
        "avg_cumulative_gain": round(sum(l["cumulative_gain"] for l in ll) / max(len(ll), 1), 4),
        "total_dampening_controls": total_dampening,
        "runaway_risks": sum(1 for l in ll if l["runaway_risk"]),
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9921)
