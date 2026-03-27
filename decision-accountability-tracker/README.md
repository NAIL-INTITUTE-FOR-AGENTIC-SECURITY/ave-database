# Decision Accountability Tracker

**Phase 31 · Service 5 of 5 · Port 9934**

Traces every automated security decision back through its reasoning chain, enabling full explainability and contestability.

## Quick Start

```bash
pip install fastapi uvicorn
uvicorn server:app --host 0.0.0.0 --port 9934
```

## Capabilities

| Capability | Description |
|---|---|
| Decision Registry | Record automated decisions (8 types: threat_blocked / access_denied / alert_escalated / policy_enforced / quarantine_applied / privilege_revoked / investigation_triggered / response_automated) with severity, affected entities, and outcome |
| Reasoning Chain | Each decision links to an ordered chain of reasoning steps (7 step types: data_ingestion / feature_extraction / model_inference / rule_evaluation / threshold_check / aggregation / final_determination) with inputs, outputs, confidence, and model references |
| Explainability Reports | Generate human-readable explanations from reasoning chains: plain-language summary, key factors, confidence breakdown, alternative outcomes considered |
| Contestation Workflow | 5-state contestation lifecycle (filed → reviewing → investigated → upheld / overturned) with evidence submission, reviewer assignment, and resolution rationale |
| Impact Assessment | Track decision impacts: affected_entity_count, severity_distribution, reversal_rate, downstream_effects |
| Decision Patterns | Analyse decision patterns over time: frequency, type distribution, severity trends, model drift indicators |
| Counterfactual Analysis | For any decision, generate "what-if" scenarios: what would have happened with different inputs or thresholds |
| Stakeholder Notification | Track who was notified of decisions and when; ensure accountability chain completeness |
| Analytics | Decisions by type, contestation rate, overturn rate, avg reasoning chain length, explainability coverage |

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/v1/decisions` | Record decision |
| `GET` | `/v1/decisions` | List decisions (filter by type, severity) |
| `GET` | `/v1/decisions/{id}` | Decision detail with reasoning chain |
| `POST` | `/v1/decisions/{id}/steps` | Add reasoning step |
| `GET` | `/v1/decisions/{id}/explain` | Generate explainability report |
| `GET` | `/v1/decisions/{id}/counterfactual` | Counterfactual analysis |
| `POST` | `/v1/contestations` | File contestation |
| `GET` | `/v1/contestations` | List contestations |
| `GET` | `/v1/contestations/{id}` | Contestation detail |
| `PATCH` | `/v1/contestations/{id}/advance` | Advance contestation state |
| `GET` | `/v1/decisions/{id}/impact` | Decision impact assessment |
| `GET` | `/v1/patterns` | Decision pattern analysis |
| `GET` | `/v1/analytics` | Accountability analytics |

## Design Notes

- In-memory stores — production would use immutable decision ledger
- Reasoning chains are ordered sequences; each step references its inputs and outputs
- Contestation workflow requires mandatory resolution rationale
- Counterfactual analysis perturbs key reasoning step inputs to estimate alternative outcomes
