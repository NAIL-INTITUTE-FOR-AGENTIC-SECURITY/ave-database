"""
Global Edge Mesh Coordinator — Phase 21 Service 1 of 5
Port: 9500

Distributed edge-node orchestration with geo-aware routing,
latency-optimised task placement, cross-region consistency,
and partition-tolerant coordination.
"""

from __future__ import annotations

import math
import random
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

class NodeState(str, Enum):
    initialising = "initialising"
    healthy = "healthy"
    degraded = "degraded"
    draining = "draining"
    offline = "offline"


class RoutingStrategy(str, Enum):
    latency_optimised = "latency_optimised"
    geo_fenced = "geo_fenced"
    cost_optimised = "cost_optimised"
    resilience_first = "resilience_first"


class TaskType(str, Enum):
    inference = "inference"
    aggregation = "aggregation"
    replication = "replication"
    cache_warm = "cache_warm"
    health_probe = "health_probe"
    custom = "custom"


class TaskState(str, Enum):
    pending = "pending"
    placed = "placed"
    running = "running"
    completed = "completed"
    failed = "failed"


class ConsistencyModel(str, Enum):
    eventual = "eventual"
    bounded_staleness = "bounded_staleness"
    strong = "strong"


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

class NodeCreate(BaseModel):
    name: str
    region: str
    zone: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    capacity_cpu: float = Field(default=100.0, ge=0)
    capacity_memory_gb: float = Field(default=64.0, ge=0)
    capacity_gpu: int = Field(default=0, ge=0)
    bandwidth_gbps: float = Field(default=10.0, ge=0)
    cost_per_hour: float = Field(default=1.0, ge=0)
    tags: Dict[str, str] = Field(default_factory=dict)


class NodeRecord(NodeCreate):
    node_id: str
    state: NodeState = NodeState.initialising
    used_cpu: float = 0.0
    used_memory_gb: float = 0.0
    used_gpu: int = 0
    task_count: int = 0
    last_heartbeat: str = ""
    created_at: str
    updated_at: str


class RoutingRequest(BaseModel):
    client_latitude: float = 0.0
    client_longitude: float = 0.0
    strategy: RoutingStrategy = RoutingStrategy.latency_optimised
    required_region: Optional[str] = None
    min_cpu: float = 0.0
    min_memory_gb: float = 0.0
    min_gpu: int = 0


class TaskCreate(BaseModel):
    task_type: TaskType
    payload: Dict[str, Any] = Field(default_factory=dict)
    required_cpu: float = Field(default=1.0, ge=0)
    required_memory_gb: float = Field(default=0.5, ge=0)
    required_gpu: int = Field(default=0, ge=0)
    affinity_region: Optional[str] = None
    anti_affinity_nodes: List[str] = Field(default_factory=list)
    deadline_seconds: Optional[int] = None
    priority: int = Field(default=5, ge=1, le=10)


class TaskRecord(TaskCreate):
    task_id: str
    state: TaskState = TaskState.pending
    assigned_node: Optional[str] = None
    created_at: str
    completed_at: Optional[str] = None


class ConsistencyWrite(BaseModel):
    partition: str
    key: str
    value: Any
    consistency: ConsistencyModel = ConsistencyModel.eventual


class ConsistencyRead(BaseModel):
    partition: str
    key: str
    consistency: ConsistencyModel = ConsistencyModel.eventual


# ---------------------------------------------------------------------------
# In-Memory Stores
# ---------------------------------------------------------------------------

nodes: Dict[str, NodeRecord] = {}
tasks: Dict[str, TaskRecord] = {}
data_store: Dict[str, Dict[str, Any]] = defaultdict(dict)  # partition -> {key: {value, version, replicas}}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Distance in km between two lat/lon points."""
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2) ** 2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def _healthy_nodes() -> List[NodeRecord]:
    return [n for n in nodes.values() if n.state in (NodeState.healthy, NodeState.degraded)]


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Global Edge Mesh Coordinator",
    description="Phase 21 — Geo-aware edge orchestration, task placement, cross-region consistency",
    version="21.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health():
    return {
        "service": "global-edge-mesh-coordinator",
        "status": "healthy",
        "phase": 21,
        "port": 9500,
        "stats": {
            "nodes": len(nodes),
            "healthy_nodes": len(_healthy_nodes()),
            "tasks": len(tasks),
            "regions": len(set(n.region for n in nodes.values())),
        },
        "timestamp": _now(),
    }


# ── Nodes ──────────────────────────────────────────────────────────────────

@app.post("/v1/nodes", status_code=201)
def register_node(body: NodeCreate):
    nid = f"EDGE-{uuid.uuid4().hex[:12]}"
    now = _now()
    record = NodeRecord(
        **body.dict(), node_id=nid, state=NodeState.healthy,
        last_heartbeat=now, created_at=now, updated_at=now,
    )
    nodes[nid] = record
    return record.dict()


@app.get("/v1/nodes")
def list_nodes(
    region: Optional[str] = None,
    zone: Optional[str] = None,
    state: Optional[NodeState] = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    results = list(nodes.values())
    if region:
        results = [n for n in results if n.region == region]
    if zone:
        results = [n for n in results if n.zone == zone]
    if state:
        results = [n for n in results if n.state == state]
    return {"nodes": [n.dict() for n in results[:limit]], "total": len(results)}


@app.get("/v1/nodes/{node_id}")
def get_node(node_id: str):
    if node_id not in nodes:
        raise HTTPException(404, "Node not found")
    n = nodes[node_id]
    node_tasks = [t.dict() for t in tasks.values() if t.assigned_node == node_id]
    return {**n.dict(), "tasks": node_tasks}


@app.patch("/v1/nodes/{node_id}/heartbeat")
def heartbeat(node_id: str):
    if node_id not in nodes:
        raise HTTPException(404, "Node not found")
    nodes[node_id].last_heartbeat = _now()
    nodes[node_id].updated_at = _now()
    if nodes[node_id].state == NodeState.initialising:
        nodes[node_id].state = NodeState.healthy
    return {"node_id": node_id, "state": nodes[node_id].state.value, "heartbeat": nodes[node_id].last_heartbeat}


@app.delete("/v1/nodes/{node_id}")
def drain_node(node_id: str):
    if node_id not in nodes:
        raise HTTPException(404, "Node not found")
    nodes[node_id].state = NodeState.draining
    nodes[node_id].updated_at = _now()
    # Reassign tasks
    reassigned = 0
    for t in tasks.values():
        if t.assigned_node == node_id and t.state in (TaskState.pending, TaskState.placed):
            t.assigned_node = None
            t.state = TaskState.pending
            reassigned += 1
    return {"drained": node_id, "tasks_reassigned": reassigned}


# ── Routing ────────────────────────────────────────────────────────────────

@app.post("/v1/routing/resolve")
def resolve_route(body: RoutingRequest):
    candidates = _healthy_nodes()
    if not candidates:
        raise HTTPException(503, "No healthy nodes available")

    # Filter by requirements
    if body.required_region:
        candidates = [n for n in candidates if n.region == body.required_region]
    candidates = [n for n in candidates if (n.capacity_cpu - n.used_cpu) >= body.min_cpu]
    candidates = [n for n in candidates if (n.capacity_memory_gb - n.used_memory_gb) >= body.min_memory_gb]
    candidates = [n for n in candidates if (n.capacity_gpu - n.used_gpu) >= body.min_gpu]

    if not candidates:
        raise HTTPException(503, "No nodes meet requirements")

    scored: List[tuple] = []
    for n in candidates:
        dist = _haversine(body.client_latitude, body.client_longitude, n.latitude, n.longitude)
        headroom = (n.capacity_cpu - n.used_cpu) / max(n.capacity_cpu, 1)

        if body.strategy == RoutingStrategy.latency_optimised:
            score = -dist  # Closest wins
        elif body.strategy == RoutingStrategy.geo_fenced:
            score = -dist if body.required_region and n.region == body.required_region else -1e9
        elif body.strategy == RoutingStrategy.cost_optimised:
            score = -n.cost_per_hour
        elif body.strategy == RoutingStrategy.resilience_first:
            score = headroom * 100 - dist * 0.01  # Prefer headroom, break ties by distance
        else:
            score = -dist
        scored.append((score, n))

    scored.sort(key=lambda x: x[0], reverse=True)
    best = scored[0][1]
    return {
        "selected_node": best.node_id,
        "region": best.region,
        "zone": best.zone,
        "distance_km": round(_haversine(body.client_latitude, body.client_longitude, best.latitude, best.longitude), 2),
        "strategy": body.strategy.value,
        "candidates_evaluated": len(scored),
    }


# ── Tasks ──────────────────────────────────────────────────────────────────

@app.post("/v1/tasks", status_code=201)
def submit_task(body: TaskCreate):
    tid = f"TASK-{uuid.uuid4().hex[:12]}"
    record = TaskRecord(**body.dict(), task_id=tid, created_at=_now())

    # Auto-place
    candidates = _healthy_nodes()
    if body.affinity_region:
        preferred = [n for n in candidates if n.region == body.affinity_region]
        if preferred:
            candidates = preferred
    candidates = [n for n in candidates if n.node_id not in body.anti_affinity_nodes]
    candidates = [n for n in candidates if (n.capacity_cpu - n.used_cpu) >= body.required_cpu]
    candidates = [n for n in candidates if (n.capacity_memory_gb - n.used_memory_gb) >= body.required_memory_gb]
    candidates = [n for n in candidates if (n.capacity_gpu - n.used_gpu) >= body.required_gpu]

    if candidates:
        best = min(candidates, key=lambda n: n.task_count)
        record.assigned_node = best.node_id
        record.state = TaskState.placed
        best.used_cpu += body.required_cpu
        best.used_memory_gb += body.required_memory_gb
        best.used_gpu += body.required_gpu
        best.task_count += 1

    tasks[tid] = record
    return record.dict()


@app.get("/v1/tasks")
def list_tasks(state: Optional[TaskState] = None, limit: int = Query(default=100, ge=1, le=1000)):
    results = list(tasks.values())
    if state:
        results = [t for t in results if t.state == state]
    return {"tasks": [t.dict() for t in results[:limit]], "total": len(results)}


@app.get("/v1/tasks/{task_id}")
def get_task(task_id: str):
    if task_id not in tasks:
        raise HTTPException(404, "Task not found")
    return tasks[task_id].dict()


# ── Consistency ────────────────────────────────────────────────────────────

@app.post("/v1/consistency/write")
def consistency_write(body: ConsistencyWrite):
    partition = data_store[body.partition]
    existing = partition.get(body.key, {})
    version = existing.get("version", 0) + 1
    healthy = _healthy_nodes()

    if body.consistency == ConsistencyModel.strong:
        quorum = max(len(healthy) // 2 + 1, 1)
    elif body.consistency == ConsistencyModel.bounded_staleness:
        quorum = max(len(healthy) // 3 + 1, 1)
    else:
        quorum = 1

    replicas = [n.node_id for n in healthy[:quorum]]
    partition[body.key] = {"value": body.value, "version": version, "replicas": replicas, "written_at": _now()}
    return {
        "partition": body.partition,
        "key": body.key,
        "version": version,
        "consistency": body.consistency.value,
        "replicas": len(replicas),
    }


@app.get("/v1/consistency/read")
def consistency_read(partition: str, key: str, consistency: ConsistencyModel = ConsistencyModel.eventual):
    if partition not in data_store or key not in data_store[partition]:
        raise HTTPException(404, "Key not found")
    entry = data_store[partition][key]
    return {
        "partition": partition,
        "key": key,
        "value": entry["value"],
        "version": entry["version"],
        "consistency": consistency.value,
        "replicas": entry.get("replicas", []),
    }


# ── Topology ───────────────────────────────────────────────────────────────

@app.get("/v1/topology")
def topology():
    regions: Dict[str, Dict] = defaultdict(lambda: {"nodes": 0, "healthy": 0, "zones": set(), "total_cpu": 0.0, "used_cpu": 0.0})
    for n in nodes.values():
        r = regions[n.region]
        r["nodes"] += 1
        if n.state in (NodeState.healthy, NodeState.degraded):
            r["healthy"] += 1
        r["zones"].add(n.zone)
        r["total_cpu"] += n.capacity_cpu
        r["used_cpu"] += n.used_cpu
    # Serialise sets
    for r in regions.values():
        r["zones"] = list(r["zones"])
        r["utilisation"] = round(r["used_cpu"] / max(r["total_cpu"], 1) * 100, 1)
    return {"regions": dict(regions), "total_nodes": len(nodes), "total_regions": len(regions)}


# ── Analytics ──────────────────────────────────────────────────────────────

@app.get("/v1/analytics")
def analytics():
    state_dist: Dict[str, int] = defaultdict(int)
    for n in nodes.values():
        state_dist[n.state.value] += 1
    task_dist: Dict[str, int] = defaultdict(int)
    for t in tasks.values():
        task_dist[t.state.value] += 1
    region_set = set(n.region for n in nodes.values())
    total_cpu = sum(n.capacity_cpu for n in nodes.values())
    used_cpu = sum(n.used_cpu for n in nodes.values())
    return {
        "nodes": {"total": len(nodes), "state_distribution": dict(state_dist)},
        "regions": len(region_set),
        "tasks": {"total": len(tasks), "state_distribution": dict(task_dist)},
        "utilisation": {
            "cpu_percent": round(used_cpu / max(total_cpu, 1) * 100, 1),
        },
        "data_partitions": len(data_store),
    }


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9500)
