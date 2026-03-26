# Federated Threat Intelligence Network

Decentralised peer-to-peer intelligence sharing between NAIL chapters, ISACs, and partner organisations with privacy-preserving protocols and cryptographic trust.

## Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                  Federated Intelligence Network                    │
│                                                                    │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐           │
│  │  NAIL Node  │◄──►│  NAIL Node  │◄──►│  ISAC Node  │           │
│  │  (Chapter)  │    │  (Chapter)  │    │  (Partner)  │           │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘           │
│         │                  │                  │                   │
│  ┌──────┴──────────────────┴──────────────────┴──────────────┐   │
│  │                    Federation Protocol                     │   │
│  │                                                            │   │
│  │  ┌──────────────┐  ┌────────────┐  ┌──────────────────┐  │   │
│  │  │ Gossip Proto │  │   Trust    │  │  Privacy Engine  │  │   │
│  │  │ (Discovery)  │  │  Scoring   │  │  (Differential   │  │   │
│  │  │              │  │  & Certs   │  │   Privacy + HE)  │  │   │
│  │  └──────────────┘  └────────────┘  └──────────────────┘  │   │
│  │                                                            │   │
│  │  ┌──────────────┐  ┌────────────┐  ┌──────────────────┐  │   │
│  │  │ Intel Store  │  │  Conflict  │  │  Rate Limiter    │  │   │
│  │  │ & Dedup      │  │  Resolver  │  │  & Quota Mgmt    │  │   │
│  │  └──────────────┘  └────────────┘  └──────────────────┘  │   │
│  └────────────────────────────────────────────────────────────┘   │
│                                                                    │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │                    Federation API (FastAPI)                 │   │
│  │                                                             │   │
│  │  Peer Mgmt │ Intel Sharing │ Trust │ Analytics │ Admin     │   │
│  └────────────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────────┘
```

## Core Protocols

### 1. Gossip-Based Peer Discovery
- Each node maintains a partial peer view (max 50 peers)
- Periodic heartbeat exchange (every 60s) with random peer subset
- Failure detection via exponential timeout with 3-strike removal
- Geographic and organisational affinity weighting

### 2. Trust Scoring System
- **Identity verification**: X.509 certificate chain validation
- **Reputation score**: 0.0–1.0 based on intelligence quality history
- **Contribution score**: Volume and timeliness of shared intelligence
- **Penalty decay**: Reputation penalties decay over 90 days
- **Minimum trust threshold**: 0.3 for intelligence reception, 0.5 for relay

### 3. Privacy-Preserving Intelligence Sharing
- **Differential privacy**: ε-differential privacy (ε=1.0) for aggregated statistics
- **Selective disclosure**: Nodes choose which intel categories to share
- **Redaction engine**: Auto-redact sensitive identifiers before sharing
- **Confidentiality levels**: TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:RED

### 4. Intelligence Deduplication & Conflict Resolution
- Content-hash based deduplication (SHA-256)
- Vector clock for causal ordering of concurrent updates
- Conflict resolution: highest-trust-source wins, with merge for complementary data

## Intelligence Format

Shared intelligence uses AVE-compatible STIX 2.1 bundles with extensions:

```json
{
  "type": "bundle",
  "id": "bundle--<uuid>",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--<uuid>",
      "name": "Novel prompt injection via tool chaining",
      "pattern": "[ave:category = 'prompt_injection']",
      "valid_from": "2026-03-20T00:00:00Z",
      "confidence": 85,
      "x_nail_tlp": "TLP:GREEN",
      "x_nail_ave_categories": ["prompt_injection", "tool_abuse"],
      "x_nail_source_node": "node-chapter-nyc",
      "x_nail_trust_score": 0.82
    }
  ]
}
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/v1/federation/status` | Network status and topology |
| `GET` | `/v1/federation/peers` | Connected peers list |
| `POST` | `/v1/federation/peers/register` | Register a new peer node |
| `DELETE` | `/v1/federation/peers/{peer_id}` | Remove a peer |
| `POST` | `/v1/federation/intel/share` | Share intelligence with network |
| `GET` | `/v1/federation/intel/feed` | Receive intelligence feed |
| `GET` | `/v1/federation/intel/{intel_id}` | Get specific intelligence item |
| `GET` | `/v1/federation/trust/{peer_id}` | Get trust score for a peer |
| `POST` | `/v1/federation/trust/{peer_id}/rate` | Rate intelligence quality |
| `GET` | `/v1/federation/analytics` | Network analytics and metrics |

## Running

```bash
cd federated-intel
pip install fastapi uvicorn pydantic
uvicorn server:app --port 8602
```
