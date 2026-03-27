# 🧪 Chaos Experiment Engine

**Phase 28 · Service 1 · Port 9915**

Controlled fault injection framework that systematically tests system resilience through chaos engineering experiments with blast radius containment and automated rollback.

## Capabilities

| Capability | Detail |
|---|---|
| **Target Registry** | 6 target types: `service`, `database`, `network`, `compute`, `storage`, `ai_pipeline` with health baseline + criticality rating |
| **Experiment Library** | 8 fault types: `latency_injection`, `cpu_stress`, `memory_pressure`, `disk_fill`, `network_partition`, `process_kill`, `dependency_failure`, `data_corruption` |
| **Blast Radius Control** | 3 containment levels: `single_instance`, `service_subset`, `full_service` with max-impact-percentage and automatic abort thresholds |
| **Experiment Lifecycle** | 7 states: `designed` → `approved` → `preparing` → `running` → `observing` → `analysing` → `completed` / `aborted` with enforced transitions |
| **Safety Guards** | Pre-flight checks (health, capacity, time-window), mandatory rollback plan, automatic abort on threshold breach, cool-down enforcement between experiments |
| **Observation Engine** | Real-time metric collection during experiment: error_rate, latency_p99, recovery_time, cascade_depth with baseline comparison |
| **Rollback Controller** | 3 rollback strategies: `automatic`, `manual`, `progressive` with verification steps and state-consistency checks |
| **Results & Findings** | Experiment outcomes: `passed` (system resilient), `degraded` (partial failure), `failed` (cascading failure) with severity + recommendations |
| **Steady State Hypothesis** | Define expected behaviour pre-experiment, validate post-experiment, measure deviation |
| **Analytics** | Experiment history, pass/fail rates by target type, MTTR improvements, resilience trends |

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/v1/targets` | Register target system |
| `GET` | `/v1/targets` | List targets |
| `POST` | `/v1/experiments` | Design an experiment |
| `GET` | `/v1/experiments` | List experiments |
| `GET` | `/v1/experiments/{eid}` | Get experiment detail |
| `PATCH` | `/v1/experiments/{eid}/advance` | Advance experiment state |
| `POST` | `/v1/experiments/{eid}/run` | Execute experiment (simulated) |
| `POST` | `/v1/experiments/{eid}/abort` | Abort running experiment |
| `POST` | `/v1/experiments/{eid}/rollback` | Trigger rollback |
| `GET` | `/v1/experiments/{eid}/observations` | Get experiment observations |
| `GET` | `/v1/safety-status` | Current safety guard status |
| `GET` | `/v1/analytics` | Experiment analytics |
