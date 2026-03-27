# 🔄 Recovery Orchestrator

**Phase 28 · Service 2 · Port 9916**

Intelligent disaster recovery that coordinates multi-system restoration with dependency-aware sequencing, state verification, and progressive confidence building.

## Capabilities

| Capability | Detail |
|---|---|
| **System Registry** | 6 system types: `application`, `database`, `cache`, `message_queue`, `load_balancer`, `ai_service` with dependency graph + recovery priority 1-10 |
| **Recovery Plans** | Pre-defined restoration blueprints with ordered steps, dependency chains, estimated durations, and verification checkpoints |
| **Disaster Scenarios** | 7 types: `region_outage`, `database_corruption`, `network_partition`, `ransomware`, `cascading_failure`, `data_centre_loss`, `key_compromise` |
| **Recovery Execution** | 6 states: `initiated` → `assessing` → `sequencing` → `restoring` → `verifying` → `completed` / `failed` with parallel + sequential step orchestration |
| **Dependency Sequencing** | Topological sort of system dependencies ensuring correct restoration order; detects circular dependencies |
| **State Verification** | 3 verification types: `health_check`, `data_integrity`, `functional_test` run after each system restoration with pass/fail/degraded results |
| **Confidence Scoring** | Progressive confidence 0-100 that increases as systems restore + verify; confidence gates can halt recovery if score drops |
| **RTO/RPO Tracking** | Recovery Time Objective and Recovery Point Objective tracking per system with breach alerts |
| **Communication Log** | Timestamped status updates for stakeholder notification during recovery |
| **Analytics** | Recovery history, avg RTO achievement, success rates by scenario, dependency bottlenecks |

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/v1/systems` | Register recoverable system |
| `GET` | `/v1/systems` | List systems with dependency info |
| `GET` | `/v1/systems/{sid}` | Get system detail |
| `POST` | `/v1/plans` | Create recovery plan |
| `GET` | `/v1/plans` | List recovery plans |
| `POST` | `/v1/recoveries` | Initiate a recovery |
| `GET` | `/v1/recoveries` | List recoveries |
| `GET` | `/v1/recoveries/{rid}` | Get recovery detail with progress |
| `PATCH` | `/v1/recoveries/{rid}/advance` | Advance recovery phase |
| `POST` | `/v1/recoveries/{rid}/verify/{sid}` | Verify a restored system |
| `GET` | `/v1/recoveries/{rid}/sequence` | Get dependency-ordered restoration sequence |
| `GET` | `/v1/recoveries/{rid}/confidence` | Get confidence score timeline |
| `GET` | `/v1/analytics` | Recovery analytics |
