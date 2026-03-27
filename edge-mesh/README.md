# Global Edge Mesh Coordinator

> **Phase 21 — Service 1 of 5 · Port `9500`**

Distributed edge-node orchestration with geo-aware routing, latency-optimised
task placement, cross-region consistency, and partition-tolerant coordination.

---

## Key Capabilities

| Capability | Detail |
|------------|--------|
| **Edge Node Registry** | Register nodes with region/zone/coordinates, 5 states (`initialising` → `healthy` → `degraded` → `draining` → `offline`), capacity tracking (CPU/memory/GPU/bandwidth), automatic heartbeat liveness |
| **Geo-Aware Routing** | 4 routing strategies — `latency_optimised` (nearest healthy), `geo_fenced` (jurisdiction-constrained), `cost_optimised` (cheapest path), `resilience_first` (cross-region redundancy) — with Haversine distance scoring |
| **Task Placement** | 6 task types (`inference` / `aggregation` / `replication` / `cache_warm` / `health_probe` / `custom`), affinity/anti-affinity constraints, resource reservation, deadline-aware scheduling |
| **Cross-Region Consistency** | 3 consistency models — `eventual` (async replication), `bounded_staleness` (max lag window), `strong` (quorum write) — configurable per data partition |
| **Partition Tolerance** | Split-brain detection via quorum membership, automatic leader re-election per region, partition healing with conflict-resolution merge |
| **Topology Analytics** | Region/zone distribution, node health heatmap, task placement density, routing strategy effectiveness, cross-region latency matrix |

## AVE Integration

All 18 AVE vulnerability categories are tracked for edge-specific threat
assessment — e.g. `data_exfiltration` at edge egress points,
`resource_exhaustion` via edge node flooding, `identity_spoofing` at
cross-region handoffs.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health |
| `POST` | `/v1/nodes` | Register edge node |
| `GET` | `/v1/nodes` | List nodes (filter by region, zone, state) |
| `GET` | `/v1/nodes/{node_id}` | Node detail |
| `PATCH` | `/v1/nodes/{node_id}/heartbeat` | Heartbeat update |
| `DELETE` | `/v1/nodes/{node_id}` | Drain & decommission node |
| `POST` | `/v1/routing/resolve` | Resolve best node for a request |
| `POST` | `/v1/tasks` | Submit task for placement |
| `GET` | `/v1/tasks` | List tasks |
| `GET` | `/v1/tasks/{task_id}` | Task detail |
| `POST` | `/v1/consistency/write` | Write with consistency model |
| `GET` | `/v1/consistency/read` | Read with consistency model |
| `GET` | `/v1/topology` | Topology overview |
| `GET` | `/v1/analytics` | Comprehensive analytics |

## Running

```bash
pip install fastapi uvicorn pydantic
uvicorn server:app --host 0.0.0.0 --port 9500
```

> **Note:** In-memory stores for development. Production deployments should
> back node registry and task state with a distributed store (etcd / CockroachDB).
