# 🚨 Autonomous Incident Commander

> AI incident commander with full OODA loop — Observe, Orient,
> Decide, Act — for automated triage, escalation, containment,
> eradication, and recovery across multi-cloud agent deployments.

**Port:** `9002`

## Overview

The Autonomous Incident Commander manages the full incident lifecycle
from detection to post-incident review.  It continuously observes
threat telemetry, orients by correlating signals against the 18 AVE
categories, decides on response actions through a risk-weighted
decision engine, and acts via automated playbooks — all with
configurable human-on-the-loop oversight for high-severity events.

## Key Capabilities

| Capability | Detail |
|-----------|--------|
| **OODA Loop Engine** | Continuous Observe → Orient → Decide → Act cycle with configurable cadence |
| **Incident Lifecycle** | 7 states: detected → triaged → escalated → contained → eradicated → recovered → closed |
| **Automated Triage** | Severity + category classification with priority scoring |
| **Escalation Engine** | Rule-based escalation with SLA timers and notification routing |
| **Containment Playbooks** | 6 containment strategies (isolate agent, block pattern, rate limit, sandbox, revoke creds, network fence) |
| **Eradication & Recovery** | Root cause removal + system restoration + verification checks |
| **Human-on-the-Loop** | Mandatory human approval for critical/high-severity actions |
| **Post-Incident Review** | Automated timeline reconstruction, lessons learned, MTTR tracking |
| **Multi-Cloud Support** | Incident correlation across AWS, Azure, GCP, on-prem deployments |

## Incident Lifecycle

```
Detection → Triage → Escalation → Containment → Eradication → Recovery → Closure
    ↑                                                                    ↓
    └──────────────── Post-Incident Review ← Lessons Learned ←──────────┘
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health + active incidents |
| `POST` | `/v1/incidents` | Report / create a new incident |
| `GET` | `/v1/incidents` | List incidents with status/severity/category filters |
| `GET` | `/v1/incidents/{incident_id}` | Get full incident detail + timeline |
| `POST` | `/v1/incidents/{incident_id}/triage` | Auto-triage an incident |
| `POST` | `/v1/incidents/{incident_id}/escalate` | Escalate to next tier |
| `POST` | `/v1/incidents/{incident_id}/contain` | Execute containment playbook |
| `POST` | `/v1/incidents/{incident_id}/eradicate` | Run eradication procedures |
| `POST` | `/v1/incidents/{incident_id}/recover` | Execute recovery and verify |
| `POST` | `/v1/incidents/{incident_id}/close` | Close with resolution notes |
| `POST` | `/v1/incidents/{incident_id}/approve` | Human approval for pending actions |
| `GET` | `/v1/incidents/{incident_id}/timeline` | Full event timeline |
| `POST` | `/v1/ooda/cycle` | Trigger one OODA cycle manually |
| `GET` | `/v1/playbooks` | List containment playbooks |
| `GET` | `/v1/analytics` | MTTR, MTTD, incident trends, resolution rates |

## Production Notes

- OODA engine — production runs as continuous background task with configurable interval
- Escalation — production integrates PagerDuty / Opsgenie / Slack / Teams
- Containment — production executes via Kubernetes API, cloud provider APIs
- Audit trail — production uses immutable event store (EventStoreDB / Kafka)

## Quick Start

```bash
pip install fastapi uvicorn pydantic
uvicorn server:app --host 0.0.0.0 --port 9002
# Docs → http://localhost:9002/docs
```
