# Governance Audit Trail

**Phase 31 · Service 2 of 5 · Port 9931**

Immutable audit logging for all AI decision-making with provenance tracking, accountability chains, and regulatory compliance evidence generation.

## Quick Start

```bash
pip install fastapi uvicorn
uvicorn server:app --host 0.0.0.0 --port 9931
```

## Capabilities

| Capability | Description |
|---|---|
| Actor Registry | Register decision-making actors (6 types: ai_agent / human_operator / automated_pipeline / hybrid_team / external_system / governance_bot) with role, clearance level 1-5, and accountability chain reference |
| Event Logging | Append-only audit events (8 categories: decision_made / policy_applied / override_executed / escalation_triggered / access_granted / access_denied / configuration_changed / anomaly_detected) with actor, timestamp, payload hash, and parent event chain |
| Immutability Verification | SHA-256 hash chain linking each event to its predecessor; chain integrity verification endpoint detecting any tampered or missing entries |
| Provenance Tracking | Trace any decision back through its full provenance chain: triggering event → data inputs → model used → reasoning steps → final decision → outcome |
| Accountability Chains | Link actors to their decisions with delegation tracking; identify who approved, who executed, and who was accountable at each step |
| Compliance Evidence | Generate regulatory evidence packages for specific time ranges or decision categories; includes event timeline, actor attestations, and chain verification proof |
| Retention Policies | Configurable retention windows per event category; auto-archive events past retention while preserving hash chain integrity |
| Search & Filter | Full-text search across events with filters by actor, category, time range, and severity |
| Analytics | Events by category, actor activity, chain integrity status, evidence packages generated, retention compliance |

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/v1/actors` | Register actor |
| `GET` | `/v1/actors` | List actors |
| `GET` | `/v1/actors/{id}` | Actor detail with activity summary |
| `POST` | `/v1/events` | Log audit event (append-only) |
| `GET` | `/v1/events` | Search events (filter by category, actor, time) |
| `GET` | `/v1/events/{id}` | Event detail with hash verification |
| `GET` | `/v1/events/{id}/provenance` | Full provenance chain |
| `GET` | `/v1/chain/verify` | Verify hash chain integrity |
| `POST` | `/v1/evidence` | Generate compliance evidence package |
| `GET` | `/v1/evidence` | List evidence packages |
| `GET` | `/v1/analytics` | Audit trail analytics |

## Design Notes

- In-memory append-only log — production would use immutable ledger (blockchain/WORM storage)
- SHA-256 chain: each event hash = SHA-256(payload + previous_hash)
- Events cannot be modified or deleted, only appended
- Evidence packages are snapshots with cryptographic chain verification
