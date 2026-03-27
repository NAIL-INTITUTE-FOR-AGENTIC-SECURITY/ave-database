# Security Debt Tracker

**Phase 27 — Service 5 of 5 · Port `9914`**

Quantifies accumulated security debt across systems, prioritises reduction
efforts, tracks debt velocity, forecasts risk exposure growth, and provides
executive-level security posture reporting.

---

## Key Capabilities

| Capability | Detail |
|-----------|--------|
| **System Registry** | Register systems with system_type (application/infrastructure/data_store/network/iot/ai_model), criticality (mission_critical/business_critical/operational/support), owner, tech_stack |
| **Debt Item Ingestion** | Create debt items: debt_type (unpatched_vuln/outdated_dependency/missing_encryption/weak_auth/no_mfa/insufficient_logging/missing_backup/deprecated_protocol/hardcoded_secret/no_rate_limit), estimated_effort_hours, risk_weight 1-10 |
| **Debt Scoring** | Per-system debt score: sum of (risk_weight × age_multiplier × criticality_factor) for open items; age_multiplier increases 10% per 30 days; overall portfolio score |
| **Debt Velocity** | Track debt accumulation vs reduction rate: new_debt_per_week, resolved_per_week, net_velocity (positive=growing, negative=shrinking), weeks_to_zero at current velocity |
| **Interest Calculation** | Security "interest" — increased risk exposure from unaddressed debt: interest_rate based on debt type severity, compounding with age; total_interest = cumulative additional risk |
| **Prioritisation** | Ranked reduction backlog: sort by risk_weight × age_multiplier × criticality / effort_hours (best ROI first); "quick wins" filter (effort <4h, risk_weight >5) |
| **Sprint Planning** | Generate debt reduction sprints: input capacity_hours → output recommended items to resolve, expected debt_score_reduction, estimated risk_reduction |
| **Forecasting** | Project debt trajectory at current velocity: 30/60/90-day debt score forecast; breach_risk_threshold alerting |
| **Executive Dashboard** | Portfolio-level view: total debt score, velocity trend, top-5 riskiest systems, debt age distribution, reduction progress |
| **Analytics** | Debt by type/system/age, velocity trends, resolution rates, effort distribution, ROI of past reductions |

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health + stats |
| `POST` | `/v1/systems` | Register system |
| `GET` | `/v1/systems` | List systems |
| `GET` | `/v1/systems/{id}` | Get system detail + debt score |
| `POST` | `/v1/debt-items` | Create debt item |
| `GET` | `/v1/debt-items` | List debt items (filter by type/system/severity) |
| `PATCH` | `/v1/debt-items/{id}/resolve` | Mark item resolved |
| `GET` | `/v1/velocity` | Debt velocity metrics |
| `GET` | `/v1/prioritised` | Prioritised reduction backlog |
| `POST` | `/v1/sprint-plan` | Generate sprint plan |
| `GET` | `/v1/forecast` | Debt trajectory forecast |
| `GET` | `/v1/executive-dashboard` | Executive summary |
| `GET` | `/v1/analytics` | Comprehensive analytics |

## Running Locally

```bash
pip install fastapi uvicorn pydantic
uvicorn server:app --host 0.0.0.0 --port 9914 --reload
```

> **Production note:** Replace in-memory stores with time-series database for velocity tracking; integrate with JIRA/Linear for sprint planning sync.
