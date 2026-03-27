# 🔐 Sovereign Data Mesh

> Privacy-preserving federated data architecture with homomorphic
> computation over encrypted threat telemetry, enabling cross-
> organisation analytics without raw data exposure.

**Port:** `9001`

## Overview

The Sovereign Data Mesh enables organisations to collaborate on threat
intelligence analytics without ever exposing raw data.  Each
participant retains full sovereignty over their data while contributing
to collective insights through homomorphic encryption, differential
privacy, secure multi-party computation, and jurisdiction-aware data
residency enforcement.

## Key Capabilities

| Capability | Detail |
|-----------|--------|
| **Data Domains** | Isolated, owner-controlled data domains per organisation |
| **Homomorphic Queries** | Compute aggregations over encrypted data (sum, mean, count, histogram) |
| **Differential Privacy** | Laplace/Gaussian noise injection with configurable ε/δ budgets |
| **Secure Aggregation** | Multi-party aggregation without revealing individual contributions |
| **Jurisdiction Enforcement** | Data residency rules per jurisdiction (EU/US/UK/APAC) |
| **Data Products** | Publishable, versioned analytical products with access policies |
| **Consent Ledger** | Immutable record of consent grants and revocations |
| **Privacy Budget Tracker** | Per-domain ε budget consumption with exhaustion alerting |

## Architecture

```
Org-A Domain ─┐
Org-B Domain ─┼→ Secure Aggregation Layer → Homomorphic Query Engine
Org-C Domain ─┘           ↓                          ↓
                  Differential Privacy          Data Products
                       Engine                       ↓
                          └──────→ Jurisdiction Enforcer → Consumer
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health + domain count |
| `POST` | `/v1/domains` | Register a new data domain |
| `GET` | `/v1/domains` | List domains with jurisdiction/owner filters |
| `GET` | `/v1/domains/{domain_id}` | Get domain detail |
| `POST` | `/v1/domains/{domain_id}/ingest` | Ingest records into a domain |
| `POST` | `/v1/query/homomorphic` | Execute homomorphic query across domains |
| `POST` | `/v1/query/aggregate` | Secure multi-party aggregation |
| `POST` | `/v1/privacy/budget` | Check/allocate privacy budget |
| `GET` | `/v1/privacy/budget/{domain_id}` | Get remaining ε budget for domain |
| `POST` | `/v1/products` | Publish a data product |
| `GET` | `/v1/products` | List published data products |
| `GET` | `/v1/products/{product_id}` | Get data product detail |
| `POST` | `/v1/consent` | Grant or revoke data consent |
| `GET` | `/v1/consent/{domain_id}` | Get consent ledger for domain |
| `GET` | `/v1/jurisdictions` | List jurisdiction residency rules |
| `GET` | `/v1/analytics` | Mesh-wide analytics and privacy metrics |

## Production Notes

- Homomorphic encryption — production uses Microsoft SEAL / OpenFHE (BFV/CKKS)
- Differential privacy — production uses Google DP library with formal guarantees
- Data residency — production enforces via geo-fenced storage + network policies
- Consent ledger — production uses append-only blockchain or immutable DB

## Quick Start

```bash
pip install fastapi uvicorn pydantic
uvicorn server:app --host 0.0.0.0 --port 9001
# Docs → http://localhost:9001/docs
```
