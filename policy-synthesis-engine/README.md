# Policy Synthesis Engine

**Phase 31 · Service 1 of 5 · Port 9930**

Automatically generates and refines security policies from observed patterns, compliance requirements, and incident history across the platform.

## Quick Start

```bash
pip install fastapi uvicorn
uvicorn server:app --host 0.0.0.0 --port 9930
```

## Capabilities

| Capability | Description |
|---|---|
| Source Registry | Register policy sources (6 types: incident_history / compliance_framework / threat_intelligence / operational_pattern / industry_standard / expert_input) with reliability 0-1, freshness, and domain tag |
| Rule Extraction | Extract policy rules from sources with configurable extraction modes (pattern_matching / nlp_analysis / statistical_inference / hybrid); each rule has severity, applicability scope, and confidence |
| Policy Document Lifecycle | 6-state lifecycle (draft → review → approved → active → deprecated → archived) with version tracking and approval chain |
| Conflict Detection | Detect contradicting rules across policies (scope overlap + opposite actions); 4 resolution strategies (priority_based / specificity / temporal_latest / human_review) |
| Policy Refinement | Iterative refinement from feedback: effectiveness signals trigger rule strengthening/weakening/removal with audit trail |
| Coverage Analysis | Map policies against compliance requirements; identify gaps where no active rule addresses a requirement |
| Impact Simulation | Simulate policy changes against historical incident data; estimate false positive/negative impact before activation |
| Policy Diff | Compare two policy versions showing added/removed/modified rules |
| Analytics | Policies by state, rules per policy, coverage gaps, conflict rate, refinement velocity |

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/v1/sources` | Register policy source |
| `GET` | `/v1/sources` | List sources |
| `POST` | `/v1/sources/{id}/extract` | Extract rules from source |
| `POST` | `/v1/policies` | Create policy document |
| `GET` | `/v1/policies` | List policies (filter by state) |
| `GET` | `/v1/policies/{id}` | Policy detail with rules |
| `PATCH` | `/v1/policies/{id}/advance` | Advance policy state |
| `POST` | `/v1/policies/{id}/rules` | Add rule to policy |
| `POST` | `/v1/policies/{id}/refine` | Submit refinement feedback |
| `GET` | `/v1/conflicts` | Detect cross-policy conflicts |
| `GET` | `/v1/coverage` | Coverage analysis against requirements |
| `POST` | `/v1/policies/{id}/simulate` | Impact simulation |
| `GET` | `/v1/policies/{id}/diff/{other_id}` | Policy diff |
| `GET` | `/v1/analytics` | Synthesis analytics |

## Design Notes

- In-memory stores — production would use versioned document database
- Rule extraction is simulated — real deployment uses NLP/ML pipelines
- Conflict detection uses scope overlap analysis with action comparison
- Coverage analysis requires compliance requirements to be registered as sources
