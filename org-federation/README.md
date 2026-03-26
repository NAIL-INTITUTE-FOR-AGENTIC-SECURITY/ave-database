# 🔗 Cross-Organisation Threat Federation

> Zero-trust multi-tenant threat sharing network enabling organisations to
> contribute and consume anonymised threat intelligence without revealing
> internal architecture.

**Phase 14 · Item 2 · Port 8801**

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                  CROSS-ORGANISATION THREAT FEDERATION                     │
├──────────┬──────────┬──────────┬──────────┬──────────┬─────────────────────┤
│ Tenant   │ Anonym-  │ Trust    │ Sharing  │ Consume  │ Audit              │
│ Manager  │ isation  │ Broker   │ Policy   │ Engine   │ Trail              │
│          │ Engine   │          │ Engine   │          │                    │
├──────────┴──────────┴──────────┴──────────┴──────────┴─────────────────────┤
│                       ZERO-TRUST FABRIC                                   │
├──────────┬──────────┬──────────┬──────────┬──────────┬─────────────────────┤
│ mTLS     │ Token    │ Data     │ Rate     │ Crypto   │ Compliance         │
│ Channels │ Exchange │ Classif. │ Limit    │ Envelope │ Check              │
└──────────┴──────────┴──────────┴──────────┴──────────┴─────────────────────┘
```

## Key Features

1. **Zero-Trust Multi-Tenant** — Every org is a tenant with cryptographic identity; no implicit trust
2. **Data Anonymisation** — K-anonymity, entity generalisation, timestamp fuzzing before sharing
3. **Sharing Policies** — Per-tenant rules: what categories to share, at what TLP level, with whom
4. **Trust Broker** — Bilateral trust scores built from contribution quality and reciprocity
5. **Cryptographic Envelopes** — Intel items encrypted per-recipient; only authorised tenants can decrypt
6. **Compliance Gating** — Auto-checks sharing against GDPR, sector-specific data-sharing rules
7. **Consumption Engine** — Ingests federated intel, deduplicates, enriches with local context
8. **Full Audit Trail** — Every share, consume, and trust change is immutably logged

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health |
| `POST` | `/v1/tenants` | Register an organisation |
| `GET` | `/v1/tenants` | List tenants |
| `GET` | `/v1/tenants/{id}` | Tenant details |
| `POST` | `/v1/tenants/{id}/policy` | Set sharing policy |
| `GET` | `/v1/tenants/{id}/policy` | Get sharing policy |
| `POST` | `/v1/intel/share` | Share an intelligence item |
| `GET` | `/v1/intel/feed` | Consume federated intel feed |
| `GET` | `/v1/intel/{id}` | Intel item details |
| `GET` | `/v1/trust` | Trust matrix between tenants |
| `POST` | `/v1/trust/rate` | Rate received intel quality |
| `GET` | `/v1/audit` | Federation audit log |
| `GET` | `/v1/analytics` | Federation analytics |

## Running

```bash
pip install fastapi uvicorn pydantic
uvicorn server:app --host 0.0.0.0 --port 8801 --reload
```

Docs at http://localhost:8801/docs
