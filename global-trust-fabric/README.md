# 🌐 Global Trust Fabric

> Decentralised identity and trust infrastructure for AI agents
> with verifiable credentials, reputation portability, cross-
> organisation trust delegation, and revocation propagation.

**Port:** `9004`

## Overview

The Global Trust Fabric provides a decentralised identity layer for
autonomous AI agents operating across organisational boundaries.
Every agent receives a verifiable credential anchored to a DID
(Decentralised Identifier).  Reputation scores are portable across
the NAIL federation, trust can be delegated with scoped permissions,
and revocations propagate in near-real-time to all relying parties.

## Key Capabilities

| Capability | Detail |
|-----------|--------|
| **Agent Identity (DID)** | W3C DID-compatible decentralised identifiers for every agent |
| **Verifiable Credentials** | Issuer-signed credentials (role, clearance, certification) with expiry |
| **Reputation System** | Portable reputation score (0-100) aggregated from behaviour across orgs |
| **Trust Delegation** | Scoped trust grants with depth limits, category restrictions, time bounds |
| **Revocation Registry** | Near-real-time credential/delegation revocation with propagation |
| **Trust Path Resolution** | Multi-hop trust chain verification with shortest-path discovery |
| **Cross-Org Federation** | Trust bridging between organisations with bilateral agreements |
| **Audit Trail** | Immutable log of identity events, delegations, verifications |

## Architecture

```
Agent A ──credential──→ Verifier
   ↕ delegation              ↓
Agent B            Trust Path Resolver → Reputation Aggregator
   ↕ delegation              ↓
Agent C         Revocation Registry → Propagation Engine
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health + identity stats |
| `POST` | `/v1/identities` | Register a new agent identity (DID) |
| `GET` | `/v1/identities` | List identities with org/role/status filters |
| `GET` | `/v1/identities/{did}` | Get identity detail |
| `POST` | `/v1/credentials/issue` | Issue a verifiable credential |
| `POST` | `/v1/credentials/verify` | Verify a credential's authenticity + status |
| `GET` | `/v1/credentials` | List credentials with holder/issuer/type filters |
| `POST` | `/v1/credentials/{cred_id}/revoke` | Revoke a credential |
| `POST` | `/v1/delegations` | Create a scoped trust delegation |
| `GET` | `/v1/delegations` | List delegations with grantor/grantee filters |
| `POST` | `/v1/delegations/{del_id}/revoke` | Revoke a delegation |
| `POST` | `/v1/trust/resolve` | Resolve trust path between two agents |
| `GET` | `/v1/reputation/{did}` | Get portable reputation score |
| `POST` | `/v1/reputation/{did}/update` | Submit reputation event |
| `GET` | `/v1/revocations` | Get revocation registry feed |
| `GET` | `/v1/analytics` | Trust fabric metrics and topology |

## Production Notes

- DIDs — production anchored to did:web or did:ion (Sidetree on Bitcoin/Ethereum)
- Credentials — production uses W3C Verifiable Credentials + JSON-LD + BBS+ signatures
- Revocation — production uses StatusList2021 or accumulator-based revocation
- Reputation — production uses weighted moving average with decay + Byzantine-tolerant aggregation
- Storage — production uses CockroachDB + IPFS for credential storage

## Quick Start

```bash
pip install fastapi uvicorn pydantic
uvicorn server:app --host 0.0.0.0 --port 9004
# Docs → http://localhost:9004/docs
```
