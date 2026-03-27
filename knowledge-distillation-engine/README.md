# 🧬 Knowledge Distillation Engine

**Phase 29 · Service 5 · Port 9924**

Extracts and compresses learned knowledge from complex models into efficient deployable forms while preserving security-critical decision boundaries.

## Capabilities

| Capability | Detail |
|---|---|
| **Teacher Registry** | Source (teacher) models: 6 types (`large_llm`, `ensemble`, `deep_classifier`, `transformer`, `graph_neural_net`, `multi_modal`) with parameter count + accuracy baseline |
| **Student Registry** | Target (student) models with architecture constraints: max_parameters, max_latency_ms, target_platform (edge/cloud/mobile) |
| **Distillation Jobs** | 5 states: `configured` → `distilling` → `evaluating` → `validated` → `deployed` / `rejected` |
| **Distillation Methods** | 5 methods: `logit_matching`, `feature_mimicry`, `attention_transfer`, `contrastive`, `progressive` with configurable temperature + alpha |
| **Quality Gates** | Minimum accuracy retention %, maximum latency, security boundary preservation score — all must pass |
| **Security Boundary Check** | Validates that critical decision boundaries (allow/deny, safe/unsafe) are preserved with configurable tolerance |
| **Compression Metrics** | Parameter reduction ratio, latency speedup, accuracy retention, memory reduction, security boundary fidelity |
| **A/B Validation** | Side-by-side teacher vs student evaluation on held-out security-critical test sets |
| **Deployment Readiness** | Automated readiness assessment: accuracy gate + latency gate + security gate + resource gate |
| **Analytics** | Jobs completed, avg compression ratio, accuracy retention, security boundary preservation rates |

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/v1/teachers` | Register teacher model |
| `GET` | `/v1/teachers` | List teacher models |
| `POST` | `/v1/students` | Register student model spec |
| `GET` | `/v1/students` | List student models |
| `POST` | `/v1/jobs` | Create distillation job |
| `GET` | `/v1/jobs` | List jobs |
| `GET` | `/v1/jobs/{jid}` | Get job detail |
| `PATCH` | `/v1/jobs/{jid}/advance` | Advance job state |
| `POST` | `/v1/jobs/{jid}/run` | Execute distillation (simulated) |
| `GET` | `/v1/jobs/{jid}/quality-gates` | Check quality gate results |
| `GET` | `/v1/jobs/{jid}/comparison` | Teacher vs student A/B comparison |
| `GET` | `/v1/analytics` | Distillation analytics |
