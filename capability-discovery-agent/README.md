# 🔍 Capability Discovery Agent

**Phase 29 · Service 3 · Port 9922**

Autonomous agent that explores system capabilities, identifies emergent behaviours, and maps the full capability space of deployed AI systems.

## Capabilities

| Capability | Detail |
|---|---|
| **System Registry** | 6 system types: `llm`, `classifier`, `detector`, `generator`, `multi_agent`, `pipeline` with declared capabilities and version |
| **Probe Library** | 8 probe types: `boundary_test`, `adversarial_input`, `capability_elicitation`, `stress_test`, `cross_domain`, `composition_test`, `edge_case`, `emergent_behaviour` |
| **Discovery Campaigns** | 5 states: `planned` → `probing` → `analysing` → `reporting` → `archived` with target system + probe selection |
| **Capability Map** | Discovered capabilities categorised: `declared` (documented), `undeclared` (found but not documented), `emergent` (unexpected), `degraded` (below spec) |
| **Behaviour Classification** | 5 behaviour types: `expected`, `enhanced`, `degraded`, `unexpected`, `dangerous` with confidence score |
| **Boundary Mapping** | Identifies operational boundaries: input ranges, load limits, context windows, accuracy thresholds |
| **Emergent Detection** | Flags capabilities that arise from component interaction but weren't individually designed |
| **Risk Assessment** | Undeclared/emergent capabilities scored for security risk: benign, monitor, restrict, block |
| **Capability Diff** | Compare capability maps across versions to detect capability drift |
| **Analytics** | Systems explored, capabilities discovered, emergent count, risk distribution |

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/v1/systems` | Register AI system |
| `GET` | `/v1/systems` | List systems |
| `GET` | `/v1/systems/{sid}` | Get system with capability map |
| `POST` | `/v1/campaigns` | Create discovery campaign |
| `GET` | `/v1/campaigns` | List campaigns |
| `GET` | `/v1/campaigns/{cid}` | Get campaign detail |
| `PATCH` | `/v1/campaigns/{cid}/advance` | Advance campaign state |
| `POST` | `/v1/campaigns/{cid}/probe` | Execute a probe (simulated) |
| `GET` | `/v1/systems/{sid}/capabilities` | Get full capability map |
| `GET` | `/v1/systems/{sid}/boundaries` | Get operational boundaries |
| `GET` | `/v1/systems/{sid}/diff` | Capability diff vs previous version |
| `GET` | `/v1/analytics` | Discovery analytics |
