# Ethical Constraint Enforcer

**Phase 31 · Service 3 of 5 · Port 9932**

Runtime enforcement of ethical boundaries and fairness constraints on AI security decisions, preventing bias amplification and ensuring proportional responses.

## Quick Start

```bash
pip install fastapi uvicorn
uvicorn server:app --host 0.0.0.0 --port 9932
```

## Capabilities

| Capability | Description |
|---|---|
| Constraint Registry | Define ethical constraints (7 types: proportionality / non_discrimination / transparency / privacy_preservation / human_dignity / minimal_harm / due_process) with severity (advisory / mandatory / absolute), scope, and threshold parameters |
| Decision Evaluation | Submit AI decisions for ethical evaluation against all active constraints; returns pass/fail per constraint with violation details and overall ethical score 0-100 |
| Bias Detection | Analyse decision patterns for statistical bias across protected attributes (6 attributes: demographic / geographic / temporal / behavioural / technological / economic); flags disparate impact exceeding 80% rule threshold |
| Proportionality Check | Evaluate whether response severity matches threat severity using configurable proportionality matrices; flag disproportionate responses |
| Fairness Metrics | Track 4 fairness metrics per decision category: demographic_parity / equal_opportunity / predictive_equality / individual_fairness with rolling window calculation |
| Override Mechanism | Allow human override of constraint violations with mandatory justification, escalation notification, and full audit logging |
| Constraint Conflict Resolution | Detect when constraints conflict (e.g., transparency vs privacy) and apply priority ordering or human escalation |
| Violation History | Track violation patterns over time; detect systematic constraint violations indicating model or process issues |
| Analytics | Decisions evaluated, violation rate, bias detections, override frequency, fairness metric trends |

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/v1/constraints` | Define ethical constraint |
| `GET` | `/v1/constraints` | List constraints (filter by type, severity) |
| `GET` | `/v1/constraints/{id}` | Constraint detail |
| `POST` | `/v1/evaluate` | Evaluate decision against constraints |
| `GET` | `/v1/evaluations` | List evaluations |
| `GET` | `/v1/evaluations/{id}` | Evaluation detail |
| `POST` | `/v1/evaluations/{id}/override` | Override constraint violation |
| `GET` | `/v1/bias-scan` | Run bias detection across recent decisions |
| `GET` | `/v1/fairness` | Fairness metrics dashboard |
| `GET` | `/v1/violations` | Violation history and patterns |
| `GET` | `/v1/analytics` | Ethical enforcement analytics |

## Design Notes

- In-memory stores — production would use persistent database with encryption at rest
- Bias detection uses 80% rule (four-fifths rule) for disparate impact analysis
- Proportionality check uses threat-response severity matrix
- All overrides are immutably logged with justification requirement
