# 💥 Blast Radius Analyser

**Phase 28 · Service 3 · Port 9917**

Failure propagation modelling that predicts cascading impact of component failures across interconnected systems with containment recommendations.

## Capabilities

| Capability | Detail |
|---|---|
| **Component Registry** | 7 component types: `service`, `database`, `cache`, `queue`, `gateway`, `storage`, `model_server` with criticality 1-10 and health status |
| **Dependency Graph** | Directed dependency edges with coupling strength 0-1 (loose→tight), failure propagation probability, and data/control/health dependency types |
| **Failure Simulation** | 5 failure modes: `crash`, `degradation`, `latency_spike`, `data_loss`, `byzantine` with configurable severity 0-1 |
| **Propagation Engine** | BFS/weighted propagation through dependency graph calculating cascade probability at each hop with dampening factor |
| **Impact Scoring** | Composite blast radius score: affected_components × avg_criticality × cascade_depth × coupling_strength (0-1000 scale) |
| **Cascade Depth** | Track maximum propagation depth from failure origin; identify amplification points where impact multiplies |
| **Containment Zones** | Auto-identified isolation boundaries: components that, if hardened, would prevent further propagation |
| **Containment Recommendations** | 4 strategy types: `circuit_breaker`, `bulkhead`, `timeout`, `fallback` with effort estimate and risk reduction |
| **What-If Analysis** | Test failure scenarios before they happen; compare blast radius with and without proposed containment |
| **Analytics** | Most vulnerable components, highest-impact failure points, containment coverage, dependency complexity |

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/v1/components` | Register component |
| `GET` | `/v1/components` | List components |
| `GET` | `/v1/components/{cid}` | Get component detail |
| `POST` | `/v1/dependencies` | Add dependency edge |
| `GET` | `/v1/dependencies` | List all dependencies |
| `GET` | `/v1/graph` | Get full dependency graph |
| `POST` | `/v1/simulate` | Simulate failure and compute blast radius |
| `GET` | `/v1/simulations` | List past simulations |
| `GET` | `/v1/simulations/{sid}` | Get simulation detail with cascade path |
| `POST` | `/v1/what-if` | Compare blast radius with/without containment |
| `GET` | `/v1/containment-recommendations` | Get containment strategy recommendations |
| `GET` | `/v1/analytics` | Blast radius analytics |
