# Sovereign Data Residency Engine

> **Phase 21 — Service 2 of 5 · Port `9501`**

Jurisdiction-aware data governance enforcing residency requirements,
cross-border transfer controls, data localisation policies, and
regulatory compliance across global data sovereignty regimes.

---

## Key Capabilities

| Capability | Detail |
|------------|--------|
| **Jurisdiction Registry** | 8 seed jurisdictions (EU/US/UK/CN/JP/AU/BR/IN) with sovereignty level (`full` / `partial` / `advisory`), governing legislation references, data categories subject to residency |
| **Residency Policies** | Per-jurisdiction rules mapping data categories (`personal_data` / `financial` / `health` / `biometric` / `ai_training` / `telemetry` / `classified`) to allowed storage regions, retention periods, and encryption requirements |
| **Transfer Controls** | Cross-border transfer request/approval workflow with 5 legal bases (`adequacy_decision` / `standard_contractual_clauses` / `binding_corporate_rules` / `explicit_consent` / `derogation`), impact assessment, and audit logging |
| **Data Asset Registry** | Track data assets with classification, owning jurisdiction, current storage location, replication targets, and residency compliance status |
| **Compliance Checking** | Automated residency violation detection — asset location vs. policy requirements, transfer legality validation, retention period enforcement |
| **Localisation Policies** | Enforce data-at-rest encryption standards, mandate local processing requirements, restrict cross-border analytics on sensitive categories |

## AVE Integration

18 AVE categories inform residency threat modelling — `data_exfiltration`
triggers cross-border transfer blocks, `supply_chain_compromise` flags
third-party storage risks, `privilege_escalation` monitors jurisdiction-hopping.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health |
| `POST` | `/v1/jurisdictions` | Register jurisdiction |
| `GET` | `/v1/jurisdictions` | List jurisdictions |
| `GET` | `/v1/jurisdictions/{jid}` | Jurisdiction detail |
| `POST` | `/v1/policies` | Create residency policy |
| `GET` | `/v1/policies` | List policies |
| `POST` | `/v1/assets` | Register data asset |
| `GET` | `/v1/assets` | List assets |
| `GET` | `/v1/assets/{asset_id}` | Asset detail |
| `POST` | `/v1/transfers` | Request cross-border transfer |
| `GET` | `/v1/transfers` | List transfers |
| `PATCH` | `/v1/transfers/{tid}/approve` | Approve transfer |
| `PATCH` | `/v1/transfers/{tid}/deny` | Deny transfer |
| `GET` | `/v1/compliance/check` | Run compliance check |
| `GET` | `/v1/analytics` | Comprehensive analytics |

## Running

```bash
pip install fastapi uvicorn pydantic
uvicorn server:app --host 0.0.0.0 --port 9501
```

> **Note:** In-memory stores for development. Production should integrate
> with legal/policy databases and real geographic storage APIs.
