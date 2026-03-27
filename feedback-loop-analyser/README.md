# 🔄 Feedback Loop Analyser

**Phase 29 · Service 2 · Port 9921**

Tracks and optimises positive/negative feedback loops across the security platform to prevent runaway amplification and ensure system stability.

## Capabilities

| Capability | Detail |
|---|---|
| **Node Registry** | 6 node types: `sensor`, `processor`, `decision_engine`, `actuator`, `data_store`, `human_operator` with throughput baseline |
| **Loop Detection** | Automatically traces signal paths through connected nodes to identify feedback loops (cycles in the directed graph) |
| **Loop Classification** | 4 loop types: `positive_reinforcing`, `negative_stabilising`, `mixed`, `unknown` with amplification factor measurement |
| **Signal Tracing** | Inject tracer signals and observe propagation path, delay, and amplitude change at each hop |
| **Amplification Analysis** | Measures gain/attenuation at each node in the loop; flags runaway risk when cumulative gain > 1.0 |
| **Dampening Controls** | 4 dampening types: `rate_limiter`, `gain_cap`, `delay_injection`, `circuit_break` with configurable parameters |
| **Stability Score** | Per-loop stability 0-100 based on amplification factor, loop length, node criticality, and dampening coverage |
| **Health Monitoring** | Continuous loop health tracking with alerts when stability score drops below threshold |
| **What-If Simulation** | Test effect of adding/removing dampening controls on loop stability |
| **Analytics** | Total loops, stability distribution, runaway risks, dampening coverage, most active loops |

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/v1/nodes` | Register a node |
| `GET` | `/v1/nodes` | List nodes |
| `POST` | `/v1/edges` | Connect nodes (directed signal path) |
| `GET` | `/v1/edges` | List edges |
| `POST` | `/v1/detect-loops` | Detect all feedback loops in the graph |
| `GET` | `/v1/loops` | List detected loops |
| `GET` | `/v1/loops/{lid}` | Get loop detail with amplification analysis |
| `POST` | `/v1/loops/{lid}/trace` | Inject tracer signal into loop |
| `POST` | `/v1/loops/{lid}/dampen` | Apply dampening control |
| `POST` | `/v1/loops/{lid}/simulate` | Simulate dampening effect |
| `GET` | `/v1/stability-overview` | Fleet-wide stability overview |
| `GET` | `/v1/analytics` | Feedback loop analytics |
