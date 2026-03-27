# 🎓 Incident Learning Engine

**Phase 28 · Service 5 · Port 9919**

Post-incident analysis system that extracts lessons, identifies systemic patterns, and generates preventive recommendations from incident history.

## Capabilities

| Capability | Detail |
|---|---|
| **Incident Registry** | 6 incident types: `outage`, `data_breach`, `performance_degradation`, `security_compromise`, `data_loss`, `cascading_failure` with 4 severities (critical/major/minor/cosmetic) |
| **Timeline Builder** | Ordered event sequence per incident: detection → triage → containment → mitigation → resolution → post-mortem with timestamps and actors |
| **Root Cause Analysis** | 8 root cause categories: `code_defect`, `config_error`, `capacity_limit`, `dependency_failure`, `human_error`, `security_exploit`, `data_corruption`, `infrastructure_fault` |
| **Lesson Extraction** | Structured lessons with category (process/technical/cultural/communication), impact assessment, and actionable recommendations |
| **Pattern Detection** | Cross-incident pattern recognition: recurring root causes, frequently affected systems, time-based patterns (day/hour), seasonal trends |
| **Action Item Tracking** | 5 states: `identified` → `assigned` → `in_progress` → `completed` → `verified` with owner, due date, and completion rate tracking |
| **Blameless Post-Mortem** | Structured post-mortem template: timeline, impact, root causes, contributing factors, lessons, action items — no individual blame |
| **Preventive Recommendations** | Auto-generated based on patterns: if same root cause appears 3+ times, flag systemic issue with remediation priority |
| **Incident Similarity** | Find similar past incidents using root cause + affected systems + incident type matching for faster resolution |
| **Analytics** | MTTR trends, incident frequency, pattern prevalence, action item completion rates, lessons per category |

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/v1/incidents` | Create incident record |
| `GET` | `/v1/incidents` | List incidents |
| `GET` | `/v1/incidents/{iid}` | Get incident detail |
| `POST` | `/v1/incidents/{iid}/timeline` | Add timeline event |
| `POST` | `/v1/incidents/{iid}/root-causes` | Record root cause |
| `POST` | `/v1/incidents/{iid}/lessons` | Extract a lesson |
| `POST` | `/v1/incidents/{iid}/actions` | Create action item |
| `PATCH` | `/v1/actions/{aid}/advance` | Advance action item state |
| `GET` | `/v1/incidents/{iid}/post-mortem` | Generate post-mortem report |
| `GET` | `/v1/incidents/{iid}/similar` | Find similar incidents |
| `GET` | `/v1/patterns` | Detected cross-incident patterns |
| `GET` | `/v1/preventive-recommendations` | Auto-generated preventive recommendations |
| `GET` | `/v1/analytics` | Incident learning analytics |
