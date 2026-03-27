# Autonomous Incident Commander

> **Phase 21 — Service 4 of 5 · Port `9503`**

AI-driven incident response orchestrator with playbook execution,
escalation chains, war-room coordination, real-time status tracking,
and automated post-mortem generation.

---

## Key Capabilities

| Capability | Detail |
|------------|--------|
| **Incident Lifecycle** | 7-state machine (`detected` → `triaged` → `escalated` → `mitigating` → `contained` → `resolved` → `post_mortem`), 4 severity levels (P1 critical / P2 high / P3 medium / P4 low), 8 incident types mapping to AVE categories |
| **Playbook Engine** | Structured playbooks with ordered steps (`investigate` / `isolate` / `mitigate` / `verify` / `communicate` / `escalate`), conditional branching, timeout gates, automated and manual step types, per-step assignment |
| **Escalation Chains** | Multi-tier escalation (`on_call` → `team_lead` → `director` → `ciso` → `ceo`), configurable SLA timers per severity, automatic escalation on timeout, acknowledgement tracking |
| **War Room** | Real-time coordination space per incident with message timeline, participant roster, role assignments (commander/investigator/communicator/scribe), pinned decisions, action items |
| **Status Board** | Live incident dashboard with MTTR/MTTD tracking, active incident count by severity, responder workload, SLA compliance, timeline visualisation |
| **Post-Mortem Generator** | Automated post-mortem with timeline reconstruction, root cause analysis template, contributing factors, remediation items with owners + deadlines, lessons learned, blameless retrospective format |

## AVE Integration

8 incident types directly map to AVE categories — `prompt_injection_incident`,
`data_exfiltration_incident`, `privilege_escalation_incident`,
`multi_agent_compromise`, `supply_chain_incident`, `model_extraction_incident`,
`guardrail_bypass_incident`, `alignment_subversion_incident`.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health |
| `POST` | `/v1/incidents` | Declare incident |
| `GET` | `/v1/incidents` | List incidents |
| `GET` | `/v1/incidents/{inc_id}` | Incident detail |
| `PATCH` | `/v1/incidents/{inc_id}/advance` | Advance to next state |
| `POST` | `/v1/playbooks` | Create playbook |
| `GET` | `/v1/playbooks` | List playbooks |
| `POST` | `/v1/incidents/{inc_id}/execute` | Execute playbook step |
| `POST` | `/v1/escalation-chains` | Create escalation chain |
| `GET` | `/v1/escalation-chains` | List chains |
| `POST` | `/v1/incidents/{inc_id}/escalate` | Trigger escalation |
| `POST` | `/v1/incidents/{inc_id}/warroom` | Post war-room message |
| `GET` | `/v1/incidents/{inc_id}/warroom` | Get war-room timeline |
| `POST` | `/v1/incidents/{inc_id}/postmortem` | Generate post-mortem |
| `GET` | `/v1/status-board` | Live status board |
| `GET` | `/v1/analytics` | Comprehensive analytics |

## Running

```bash
pip install fastapi uvicorn pydantic
uvicorn server:app --host 0.0.0.0 --port 9503
```

> **Note:** In-memory stores for development. Production should use
> persistent event sourcing with PagerDuty/Opsgenie integration.
