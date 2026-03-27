# Shared Defence Playbook Library

**Phase 24 — Service 4 of 5 · Port `9803`**

Community-curated playbook repository with version control,
effectiveness ratings, organisation-specific customisation, and
step-by-step execution tracking.

---

## Key Capabilities

| Capability | Detail |
|-----------|--------|
| **Playbook Registry** | Create playbooks with category (incident_response/threat_hunting/vulnerability_management/compliance_audit/data_protection/access_review/forensic_analysis/recovery), target AVE categories, estimated duration, required roles |
| **Playbook Lifecycle** | 6-state workflow: draft → review → approved → published → deprecated → archived |
| **Step Definitions** | Ordered execution steps with step_type (manual/automated/decision/notification/escalation), instructions, expected_duration_minutes, required_role, success_criteria |
| **Version Control** | Full version history per playbook; semantic versioning with changelog; diff between versions; rollback to any version |
| **Effectiveness Ratings** | 5-star rating system with written reviews; aggregated effectiveness score; review count tracking |
| **Organisation Customisation** | Fork published playbooks into org-specific variants with custom steps/parameters while maintaining upstream linkage; pull upstream updates |
| **Execution Tracking** | Start playbook execution instance; track step completion with actual_duration/outcome/notes; 4 execution states (in_progress/completed/aborted/failed) |
| **Tagging & Search** | Tag-based organisation; full-text search across title/description/steps; filter by category/state/AVE-category/min-rating |
| **Analytics** | Playbook volume by category/state, avg effectiveness, execution completion rates, most-used playbooks, avg execution time vs estimated |

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health + stats |
| `POST` | `/v1/playbooks` | Create playbook |
| `GET` | `/v1/playbooks` | List/search playbooks |
| `GET` | `/v1/playbooks/{id}` | Get playbook detail with steps |
| `PATCH` | `/v1/playbooks/{id}/advance` | Advance lifecycle state |
| `POST` | `/v1/playbooks/{id}/steps` | Add step to playbook |
| `GET` | `/v1/playbooks/{id}/steps` | List steps |
| `POST` | `/v1/playbooks/{id}/reviews` | Submit effectiveness review |
| `GET` | `/v1/playbooks/{id}/reviews` | Get reviews |
| `POST` | `/v1/playbooks/{id}/fork` | Fork playbook for org customisation |
| `POST` | `/v1/playbooks/{id}/execute` | Start execution instance |
| `POST` | `/v1/executions/{id}/steps/{step}/complete` | Complete execution step |
| `GET` | `/v1/executions` | List executions |
| `GET` | `/v1/analytics` | Comprehensive analytics |

## Running Locally

```bash
pip install fastapi uvicorn pydantic
uvicorn server:app --host 0.0.0.0 --port 9803 --reload
```

> **Production note:** Replace in-memory stores with versioned document store (e.g. MongoDB with change streams) and add RBAC middleware.
