# Federated Threat Intelligence Hub

**Phase 24 — Service 1 of 5 · Port `9800`**

Cross-organisational threat sharing with privacy-preserving data exchange,
indicator federation, trust-tier access control, and Traffic Light Protocol
(TLP) enforcement.

---

## Key Capabilities

| Capability | Detail |
|-----------|--------|
| **Organisation Registry** | Onboard partner organisations with trust tier (founder/partner/associate/observer), TLP clearance level (RED/AMBER+STRICT/AMBER/GREEN/CLEAR), sector classification, point-of-contact |
| **Threat Indicator Federation** | Share IOCs (ip/domain/hash/url/email/cve/ttps/behaviour) with TLP markings, confidence 0-100, severity (critical/high/medium/low/informational), source attribution, MITRE ATT&CK mapping |
| **Trust-Tier Access Control** | 4-tier model (founder=all TLP / partner=AMBER+below / associate=GREEN+CLEAR / observer=CLEAR only); automatic filtering based on recipient clearance |
| **Privacy-Preserving Exchange** | Indicator anonymisation with k-anonymity simulation; optional hash-only sharing mode (SHA-256 of raw values); provenance tracking without revealing internals |
| **Sharing Agreements** | Bilateral org-to-org agreements with scope (indicator_types + TLP ceiling + retention_days), revocable, audit-logged |
| **Feed Subscriptions** | Subscribe to filtered indicator feeds by type/severity/TLP/source_org; paginated retrieval |
| **Sighting Reports** | Confirm or dispute indicators with sighting_type (confirmed/suspected/false_positive), sighting count aggregation |
| **Indicator Enrichment** | Tag-based enrichment, related indicator linking, TTL-based expiry |
| **Analytics** | Indicator volume by type/severity/TLP/source, trust-tier distribution, sharing agreement coverage, sighting confirmation rates |

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health + stats |
| `POST` | `/v1/organisations` | Register partner organisation |
| `GET` | `/v1/organisations` | List organisations (filter by tier/sector) |
| `POST` | `/v1/indicators` | Publish threat indicator |
| `GET` | `/v1/indicators` | Query indicators (type/severity/TLP/source/text) |
| `GET` | `/v1/indicators/{id}` | Get indicator detail |
| `POST` | `/v1/indicators/{id}/sightings` | Report sighting |
| `POST` | `/v1/agreements` | Create sharing agreement |
| `GET` | `/v1/agreements` | List agreements |
| `DELETE` | `/v1/agreements/{id}` | Revoke agreement |
| `GET` | `/v1/feed` | Filtered indicator feed for a consumer org |
| `GET` | `/v1/analytics` | Comprehensive analytics |

## Data Flow

```
Org A publishes indicator (TLP:AMBER, confidence 85)
  → TLP gate checks recipient clearance
    → Org B (partner tier, AMBER clearance) ✓ receives
    → Org C (observer tier, CLEAR clearance) ✗ filtered out
  → Org B reports sighting (confirmed)
    → Confidence auto-adjusted upward
```

## Running Locally

```bash
pip install fastapi uvicorn pydantic
uvicorn server:app --host 0.0.0.0 --port 9800 --reload
```

> **Production note:** Replace in-memory stores with federated database (CockroachDB/YugabyteDB) and add mTLS for inter-org communication.
