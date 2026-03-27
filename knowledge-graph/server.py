"""
Knowledge Graph Engine — Phase 19 Service 1 of 5
Port: 9300

Typed node/edge registry, multi-hop graph queries, inference
engine (transitive closure, gap analysis, impact propagation,
similarity), ontology management, and analytics.
"""

from __future__ import annotations

import math
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class NodeType(str, Enum):
    threat = "threat"
    defence = "defence"
    incident = "incident"
    agent = "agent"
    standard = "standard"
    vulnerability = "vulnerability"
    organisation = "organisation"
    technique = "technique"


class EdgeType(str, Enum):
    causes = "causes"
    mitigates = "mitigates"
    exploits = "exploits"
    detects = "detects"
    relates_to = "relates_to"
    escalates_to = "escalates_to"
    depends_on = "depends_on"
    belongs_to = "belongs_to"
    implements = "implements"
    violates = "violates"
    precedes = "precedes"
    co_occurs_with = "co_occurs_with"


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
    node_type: NodeType
    name: str
    description: str = ""
    category: Optional[str] = None
    severity: Optional[str] = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)


class NodeRecord(NodeCreate):
    node_id: str
    created_at: str
    updated_at: str
    version: int = 1


class EdgeCreate(BaseModel):
    edge_type: EdgeType
    source_id: str
    target_id: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EdgeRecord(EdgeCreate):
    edge_id: str
    created_at: str


class PathQuery(BaseModel):
    source_id: str
    target_id: str
    max_depth: int = Field(default=5, ge=1, le=10)
    edge_types: Optional[List[EdgeType]] = None


class NeighbourQuery(BaseModel):
    node_id: str
    depth: int = Field(default=1, ge=1, le=10)
    node_types: Optional[List[NodeType]] = None
    edge_types: Optional[List[EdgeType]] = None


class SubgraphQuery(BaseModel):
    node_types: Optional[List[NodeType]] = None
    categories: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    max_nodes: int = Field(default=200, ge=1, le=5000)


class ImpactRequest(BaseModel):
    source_id: str
    decay: float = Field(default=0.8, ge=0.0, le=1.0)
    max_depth: int = Field(default=5, ge=1, le=10)
    edge_types: Optional[List[EdgeType]] = None


# ---------------------------------------------------------------------------
# In-Memory Graph Store
# ---------------------------------------------------------------------------

nodes: Dict[str, NodeRecord] = {}
edges: Dict[str, EdgeRecord] = {}
# adjacency: node_id -> list[(edge_id, neighbour_id)]
adj_out: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
adj_in: Dict[str, List[Tuple[str, str]]] = defaultdict(list)

# Ontology edge constraints: edge_type -> list of (source_type, target_type)
ONTOLOGY_CONSTRAINTS: Dict[EdgeType, List[Tuple[NodeType, NodeType]]] = {
    EdgeType.causes: [(NodeType.threat, NodeType.incident), (NodeType.vulnerability, NodeType.incident)],
    EdgeType.mitigates: [(NodeType.defence, NodeType.threat), (NodeType.defence, NodeType.vulnerability)],
    EdgeType.exploits: [(NodeType.technique, NodeType.vulnerability), (NodeType.agent, NodeType.vulnerability)],
    EdgeType.detects: [(NodeType.defence, NodeType.threat), (NodeType.agent, NodeType.threat)],
    EdgeType.relates_to: [],  # any-to-any
    EdgeType.escalates_to: [(NodeType.threat, NodeType.threat), (NodeType.incident, NodeType.incident)],
    EdgeType.depends_on: [],  # any-to-any
    EdgeType.belongs_to: [(NodeType.agent, NodeType.organisation), (NodeType.standard, NodeType.organisation)],
    EdgeType.implements: [(NodeType.defence, NodeType.standard)],
    EdgeType.violates: [(NodeType.threat, NodeType.standard), (NodeType.incident, NodeType.standard)],
    EdgeType.precedes: [(NodeType.technique, NodeType.technique), (NodeType.incident, NodeType.incident)],
    EdgeType.co_occurs_with: [],  # any-to-any
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _prefix(nt: NodeType) -> str:
    prefixes = {
        NodeType.threat: "THREAT",
        NodeType.defence: "DEF",
        NodeType.incident: "INC",
        NodeType.agent: "AGENT",
        NodeType.standard: "STD",
        NodeType.vulnerability: "VULN",
        NodeType.organisation: "ORG",
        NodeType.technique: "TECH",
    }
    return prefixes.get(nt, "NODE")


# ---------------------------------------------------------------------------
# Helpers — graph algorithms
# ---------------------------------------------------------------------------

def _bfs_shortest_path(
    src: str, dst: str, max_depth: int, allowed_edges: Optional[Set[EdgeType]] = None
) -> Optional[List[str]]:
    """BFS shortest path returning list of node IDs."""
    if src not in nodes or dst not in nodes:
        return None
    visited: Set[str] = {src}
    queue: deque[Tuple[str, List[str]]] = deque([(src, [src])])
    while queue:
        current, path = queue.popleft()
        if len(path) - 1 >= max_depth:
            continue
        for edge_id, neighbour in adj_out.get(current, []):
            if allowed_edges:
                e = edges[edge_id]
                if e.edge_type not in allowed_edges:
                    continue
            if neighbour == dst:
                return path + [neighbour]
            if neighbour not in visited:
                visited.add(neighbour)
                queue.append((neighbour, path + [neighbour]))
    return None


def _all_paths(
    src: str, dst: str, max_depth: int, allowed_edges: Optional[Set[EdgeType]] = None
) -> List[List[str]]:
    """DFS all simple paths up to max_depth."""
    results: List[List[str]] = []

    def _dfs(current: str, path: List[str], visited: Set[str]):
        if len(path) - 1 >= max_depth:
            return
        for edge_id, neighbour in adj_out.get(current, []):
            if allowed_edges:
                e = edges[edge_id]
                if e.edge_type not in allowed_edges:
                    continue
            if neighbour in visited:
                continue
            new_path = path + [neighbour]
            if neighbour == dst:
                results.append(new_path)
            else:
                _dfs(neighbour, new_path, visited | {neighbour})

    _dfs(src, [src], {src})
    return results


def _neighbourhood(
    node_id: str,
    depth: int,
    node_types: Optional[Set[NodeType]] = None,
    edge_types: Optional[Set[EdgeType]] = None,
) -> Dict[str, int]:
    """Return {node_id: hop_distance} within depth hops."""
    visited: Dict[str, int] = {node_id: 0}
    queue: deque[Tuple[str, int]] = deque([(node_id, 0)])
    while queue:
        current, d = queue.popleft()
        if d >= depth:
            continue
        for edge_id, neighbour in adj_out.get(current, []) + adj_in.get(current, []):
            if edge_types:
                if edges[edge_id].edge_type not in edge_types:
                    continue
            if neighbour in visited:
                continue
            if node_types:
                n = nodes.get(neighbour)
                if n and n.node_type not in node_types:
                    continue
            visited[neighbour] = d + 1
            queue.append((neighbour, d + 1))
    return visited


def _jaccard_similarity(a_id: str, b_id: str) -> float:
    """Jaccard similarity of one-hop neighbours."""
    n_a = {nid for _, nid in adj_out.get(a_id, []) + adj_in.get(a_id, [])}
    n_b = {nid for _, nid in adj_out.get(b_id, []) + adj_in.get(b_id, [])}
    if not n_a and not n_b:
        return 0.0
    return len(n_a & n_b) / len(n_a | n_b)


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Knowledge Graph Engine",
    description="Phase 19 — Typed node/edge graph with query, inference, and ontology management",
    version="19.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health():
    return {
        "service": "knowledge-graph-engine",
        "status": "healthy",
        "phase": 19,
        "port": 9300,
        "stats": {"nodes": len(nodes), "edges": len(edges)},
        "timestamp": _now(),
    }


# ── Nodes ──────────────────────────────────────────────────────────────────

@app.post("/v1/nodes", status_code=201)
def create_node(body: NodeCreate):
    nid = f"{_prefix(body.node_type)}-{uuid.uuid4().hex[:12]}"
    now = _now()
    record = NodeRecord(**body.dict(), node_id=nid, created_at=now, updated_at=now)
    nodes[nid] = record
    return record.dict()


@app.get("/v1/nodes")
def list_nodes(
    node_type: Optional[NodeType] = None,
    category: Optional[str] = None,
    tag: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    results = list(nodes.values())
    if node_type:
        results = [n for n in results if n.node_type == node_type]
    if category:
        results = [n for n in results if n.category == category]
    if tag:
        results = [n for n in results if tag in n.tags]
    return {"nodes": [n.dict() for n in results[:limit]], "total": len(results)}


@app.get("/v1/nodes/{node_id}")
def get_node(node_id: str):
    if node_id not in nodes:
        raise HTTPException(404, "Node not found")
    n = nodes[node_id]
    out_edges = [edges[eid].dict() for eid, _ in adj_out.get(node_id, [])]
    in_edges = [edges[eid].dict() for eid, _ in adj_in.get(node_id, [])]
    return {**n.dict(), "outgoing_edges": out_edges, "incoming_edges": in_edges}


@app.delete("/v1/nodes/{node_id}")
def delete_node(node_id: str):
    if node_id not in nodes:
        raise HTTPException(404, "Node not found")
    # Remove incident edges
    for eid, _ in adj_out.pop(node_id, []):
        edges.pop(eid, None)
    for eid, _ in adj_in.pop(node_id, []):
        edges.pop(eid, None)
    # Clean references in other adj lists
    for k in list(adj_out.keys()):
        adj_out[k] = [(eid, nid) for eid, nid in adj_out[k] if nid != node_id]
    for k in list(adj_in.keys()):
        adj_in[k] = [(eid, nid) for eid, nid in adj_in[k] if nid != node_id]
    del nodes[node_id]
    return {"deleted": node_id}


# ── Edges ──────────────────────────────────────────────────────────────────

@app.post("/v1/edges", status_code=201)
def create_edge(body: EdgeCreate):
    if body.source_id not in nodes:
        raise HTTPException(404, f"Source node {body.source_id} not found")
    if body.target_id not in nodes:
        raise HTTPException(404, f"Target node {body.target_id} not found")
    # Ontology constraint check
    constraints = ONTOLOGY_CONSTRAINTS.get(body.edge_type, [])
    if constraints:
        src_type = nodes[body.source_id].node_type
        tgt_type = nodes[body.target_id].node_type
        if (src_type, tgt_type) not in constraints:
            raise HTTPException(
                422,
                f"Edge type '{body.edge_type}' not allowed between {src_type} and {tgt_type}",
            )
    eid = f"EDGE-{uuid.uuid4().hex[:12]}"
    record = EdgeRecord(**body.dict(), edge_id=eid, created_at=_now())
    edges[eid] = record
    adj_out[body.source_id].append((eid, body.target_id))
    adj_in[body.target_id].append((eid, body.source_id))
    return record.dict()


@app.get("/v1/edges")
def list_edges(
    edge_type: Optional[EdgeType] = None,
    source_id: Optional[str] = None,
    target_id: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    results = list(edges.values())
    if edge_type:
        results = [e for e in results if e.edge_type == edge_type]
    if source_id:
        results = [e for e in results if e.source_id == source_id]
    if target_id:
        results = [e for e in results if e.target_id == target_id]
    return {"edges": [e.dict() for e in results[:limit]], "total": len(results)}


@app.delete("/v1/edges/{edge_id}")
def delete_edge(edge_id: str):
    if edge_id not in edges:
        raise HTTPException(404, "Edge not found")
    e = edges.pop(edge_id)
    adj_out[e.source_id] = [(eid, nid) for eid, nid in adj_out[e.source_id] if eid != edge_id]
    adj_in[e.target_id] = [(eid, nid) for eid, nid in adj_in[e.target_id] if eid != edge_id]
    return {"deleted": edge_id}


# ── Query Engine ───────────────────────────────────────────────────────────

@app.post("/v1/query/paths")
def query_paths(body: PathQuery):
    allowed = set(body.edge_types) if body.edge_types else None
    shortest = _bfs_shortest_path(body.source_id, body.target_id, body.max_depth, allowed)
    all_p = _all_paths(body.source_id, body.target_id, body.max_depth, allowed)
    return {
        "source": body.source_id,
        "target": body.target_id,
        "shortest_path": shortest,
        "all_paths": all_p[:50],
        "path_count": len(all_p),
    }


@app.post("/v1/query/neighbours")
def query_neighbours(body: NeighbourQuery):
    if body.node_id not in nodes:
        raise HTTPException(404, "Node not found")
    nt = set(body.node_types) if body.node_types else None
    et = set(body.edge_types) if body.edge_types else None
    hood = _neighbourhood(body.node_id, body.depth, nt, et)
    neighbour_nodes = []
    for nid, dist in hood.items():
        if nid == body.node_id:
            continue
        n = nodes[nid]
        neighbour_nodes.append({**n.dict(), "distance": dist})
    return {"center": body.node_id, "depth": body.depth, "neighbours": neighbour_nodes, "count": len(neighbour_nodes)}


@app.post("/v1/query/subgraph")
def query_subgraph(body: SubgraphQuery):
    selected: List[NodeRecord] = []
    for n in nodes.values():
        if body.node_types and n.node_type not in body.node_types:
            continue
        if body.categories and n.category not in body.categories:
            continue
        if body.tags and not set(body.tags) & set(n.tags):
            continue
        selected.append(n)
        if len(selected) >= body.max_nodes:
            break
    selected_ids = {n.node_id for n in selected}
    sub_edges = [
        e.dict() for e in edges.values()
        if e.source_id in selected_ids and e.target_id in selected_ids
    ]
    return {"nodes": [n.dict() for n in selected], "edges": sub_edges, "node_count": len(selected), "edge_count": len(sub_edges)}


# ── Inference ──────────────────────────────────────────────────────────────

@app.get("/v1/inference/transitive/{node_id}")
def transitive_closure(node_id: str, max_depth: int = Query(default=5, ge=1, le=10)):
    if node_id not in nodes:
        raise HTTPException(404, "Node not found")
    visited: Dict[str, int] = {}
    queue: deque[Tuple[str, int]] = deque([(node_id, 0)])
    while queue:
        current, depth = queue.popleft()
        if current in visited:
            continue
        visited[current] = depth
        if depth >= max_depth:
            continue
        for _, neighbour in adj_out.get(current, []):
            if neighbour not in visited:
                queue.append((neighbour, depth + 1))
    reachable = [
        {**nodes[nid].dict(), "hop_distance": d}
        for nid, d in visited.items()
        if nid != node_id and nid in nodes
    ]
    return {"source": node_id, "reachable_count": len(reachable), "reachable": reachable}


@app.get("/v1/inference/gaps")
def defence_gaps():
    """Threats/vulnerabilities with no mitigating defence edge."""
    gaps = []
    for n in nodes.values():
        if n.node_type not in (NodeType.threat, NodeType.vulnerability):
            continue
        has_mitigation = any(
            edges[eid].edge_type == EdgeType.mitigates
            for eid, _ in adj_in.get(n.node_id, [])
        )
        if not has_mitigation:
            gaps.append(n.dict())
    return {"unmitigated_count": len(gaps), "gaps": gaps}


@app.post("/v1/inference/impact")
def impact_propagation(body: ImpactRequest):
    if body.source_id not in nodes:
        raise HTTPException(404, "Node not found")
    allowed = set(body.edge_types) if body.edge_types else None
    impacts: Dict[str, float] = {}
    queue: deque[Tuple[str, float, int]] = deque([(body.source_id, 1.0, 0)])
    visited: Set[str] = set()
    while queue:
        current, strength, depth = queue.popleft()
        if current in visited or depth > body.max_depth:
            continue
        visited.add(current)
        if current != body.source_id:
            impacts[current] = round(strength, 6)
        for edge_id, neighbour in adj_out.get(current, []):
            e = edges[edge_id]
            if allowed and e.edge_type not in allowed:
                continue
            new_strength = strength * body.decay * e.confidence
            if new_strength > 0.001 and neighbour not in visited:
                queue.append((neighbour, new_strength, depth + 1))
    ranked = sorted(impacts.items(), key=lambda x: x[1], reverse=True)
    return {
        "source": body.source_id,
        "decay": body.decay,
        "impacted_nodes": [
            {**nodes[nid].dict(), "impact_score": score}
            for nid, score in ranked if nid in nodes
        ],
    }


@app.get("/v1/inference/similar/{node_id}")
def similar_nodes(node_id: str, top_k: int = Query(default=10, ge=1, le=50)):
    if node_id not in nodes:
        raise HTTPException(404, "Node not found")
    scores = []
    for nid in nodes:
        if nid == node_id:
            continue
        sim = _jaccard_similarity(node_id, nid)
        if sim > 0:
            scores.append((nid, sim))
    scores.sort(key=lambda x: x[1], reverse=True)
    return {
        "source": node_id,
        "similar": [
            {**nodes[nid].dict(), "similarity": round(s, 4)}
            for nid, s in scores[:top_k] if nid in nodes
        ],
    }


# ── Ontology ───────────────────────────────────────────────────────────────

@app.get("/v1/ontology")
def get_ontology():
    schema = {}
    for et, constraints in ONTOLOGY_CONSTRAINTS.items():
        schema[et.value] = {
            "allowed_pairs": [
                {"source_type": s.value, "target_type": t.value} for s, t in constraints
            ] if constraints else "any-to-any",
        }
    return {
        "node_types": [nt.value for nt in NodeType],
        "edge_types": [et.value for et in EdgeType],
        "constraints": schema,
        "ave_categories": AVE_CATEGORIES,
    }


# ── Analytics ──────────────────────────────────────────────────────────────

@app.get("/v1/analytics")
def analytics():
    type_counts: Dict[str, int] = defaultdict(int)
    for n in nodes.values():
        type_counts[n.node_type.value] += 1
    edge_type_counts: Dict[str, int] = defaultdict(int)
    for e in edges.values():
        edge_type_counts[e.edge_type.value] += 1
    # Degree distribution
    degrees: Dict[str, int] = defaultdict(int)
    for nid in nodes:
        degrees[nid] = len(adj_out.get(nid, [])) + len(adj_in.get(nid, []))
    top_hubs = sorted(degrees.items(), key=lambda x: x[1], reverse=True)[:10]
    # Connected components
    visited_cc: Set[str] = set()
    components = 0
    for nid in nodes:
        if nid in visited_cc:
            continue
        components += 1
        stack = [nid]
        while stack:
            cur = stack.pop()
            if cur in visited_cc:
                continue
            visited_cc.add(cur)
            for _, nb in adj_out.get(cur, []) + adj_in.get(cur, []):
                if nb not in visited_cc:
                    stack.append(nb)
    # Isolated nodes
    isolated = [nid for nid, d in degrees.items() if d == 0]

    return {
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "node_type_distribution": dict(type_counts),
        "edge_type_distribution": dict(edge_type_counts),
        "connected_components": components,
        "isolated_nodes": len(isolated),
        "top_hubs": [
            {"node_id": nid, "name": nodes[nid].name, "degree": d}
            for nid, d in top_hubs if nid in nodes
        ],
        "avg_degree": round(sum(degrees.values()) / max(len(degrees), 1), 2),
    }


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9300)
