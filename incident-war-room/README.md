# Collaborative Incident War Room

**Phase 24 — Service 2 of 5 · Port `9801`**

Real-time multi-stakeholder incident coordination with role-based channels,
evidence sharing, timeline reconstruction, and cross-organisation
collaboration.

---

## Key Capabilities

| Capability | Detail |
|-----------|--------|
| **Incident Creation** | Create incidents with severity (P1-critical/P2-high/P3-medium/P4-low), type (security_breach/data_leak/system_outage/policy_violation/supply_chain/other), affected systems, lead organisation |
| **Incident Lifecycle** | 7-state workflow: declared → triaging → investigating → containing → remediating → resolved → post_mortem |
| **Role-Based Channels** | Per-incident channels with 5 participant roles (commander/analyst/responder/observer/liaison); role gates message visibility |
| **Multi-Org Participants** | Add participants from different organisations with role assignment; organisation-level access control |
| **Evidence Locker** | Attach evidence items (log_file/screenshot/memory_dump/network_capture/config_snapshot/forensic_image/other) with SHA-256 integrity hash, classification level, chain-of-custody tracking |
| **Timeline Reconstruction** | Ordered event timeline per incident with event_type (detection/escalation/action/communication/evidence/resolution), timestamps, attribution |
| **Message Board** | Channel-scoped messages with sender/role/organisation, markdown content, optional evidence references |
| **Status Updates** | Broadcast status updates with next_steps and ETA tracking |
| **Post-Mortem Generation** | Auto-generate post-mortem from timeline + evidence + status updates with root_cause/impact_summary/lessons_learned/action_items |
| **Analytics** | Incident volume by severity/type/state, MTTR tracking, participant distribution, evidence counts |

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health + stats |
| `POST` | `/v1/incidents` | Declare new incident |
| `GET` | `/v1/incidents` | List incidents (filter by severity/state/type) |
| `GET` | `/v1/incidents/{id}` | Get incident detail |
| `PATCH` | `/v1/incidents/{id}/advance` | Advance lifecycle state |
| `POST` | `/v1/incidents/{id}/participants` | Add participant |
| `POST` | `/v1/incidents/{id}/evidence` | Submit evidence |
| `GET` | `/v1/incidents/{id}/evidence` | List evidence items |
| `POST` | `/v1/incidents/{id}/timeline` | Add timeline event |
| `GET` | `/v1/incidents/{id}/timeline` | Get full timeline |
| `POST` | `/v1/incidents/{id}/messages` | Post message to channel |
| `GET` | `/v1/incidents/{id}/messages` | Read channel messages |
| `POST` | `/v1/incidents/{id}/status` | Post status update |
| `POST` | `/v1/incidents/{id}/post-mortem` | Generate post-mortem |
| `GET` | `/v1/analytics` | Comprehensive analytics |

## Running Locally

```bash
pip install fastapi uvicorn pydantic
uvicorn server:app --host 0.0.0.0 --port 9801 --reload
```

> **Production note:** Replace in-memory stores with event-sourced database + WebSocket channels for real-time collaboration.
