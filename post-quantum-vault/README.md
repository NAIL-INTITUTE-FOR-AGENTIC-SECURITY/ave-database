# Post-Quantum Cryptographic Vault

> Phase 20 · Service 1 of 5 · Port **9400**

Quantum-resistant key management system with lattice-based and hash-based cryptographic primitives, key lifecycle management, encryption/decryption operations, digital signatures, key rotation, and crypto-agility for seamless algorithm migration.

## Core Capabilities

### 1. Algorithm Registry

- **4 PQC algorithm families**: lattice (CRYSTALS-Kyber/Dilithium), hash-based (SPHINCS+), code-based (Classic McEliece), hybrid (PQC + classical composite)
- Per-algorithm metadata: NIST security level (1–5), key sizes, signature sizes, performance profiles
- Algorithm status tracking: recommended, acceptable, deprecated, broken
- Crypto-agility: hot-swap algorithms without re-keying downstream consumers

### 2. Key Lifecycle Management

- Key generation with algorithm selection and purpose binding (encryption, signing, key_exchange, authentication)
- 6-state key lifecycle: generated → active → suspended → rotating → retired → destroyed
- Automatic key rotation with configurable intervals and overlap windows
- Key escrow with M-of-N threshold recovery (Shamir secret sharing simulation)
- Hardware Security Module (HSM) readiness flags per key

### 3. Cryptographic Operations

- **Encrypt/Decrypt**: symmetric envelope encryption with PQC-wrapped data encryption keys
- **Sign/Verify**: digital signatures with algorithm-specific parameters
- **Key encapsulation**: KEM operations for key exchange
- Authenticated encryption with associated data (AEAD) envelope
- Operation audit log with caller identity, algorithm used, and timestamp

### 4. Key Rotation Engine

- Policy-driven rotation schedules (time-based, usage-count, compromise-triggered)
- Zero-downtime rotation with dual-active key windows
- Cascading rotation for dependent keys
- Post-rotation verification ensuring old ciphertext still decryptable during grace period

### 5. Crypto-Agility & Migration

- Algorithm migration plans: map old algorithm → new algorithm with timeline
- Bulk re-encryption orchestration for stored data
- Compatibility matrix tracking which services use which algorithms
- Deprecation warnings with enforcement deadlines

### 6. Compliance & Audit

- NIST SP 800-208 alignment for stateful hash-based signatures
- CNSA 2.0 timeline tracking
- Full audit trail: every key operation logged with immutable sequence numbers
- Key inventory reporting by algorithm, status, purpose, and age

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/algorithms` | List supported PQC algorithms |
| POST | `/v1/keys` | Generate a new key |
| GET | `/v1/keys` | List/search keys |
| GET | `/v1/keys/{key_id}` | Get key metadata (never raw material) |
| DELETE | `/v1/keys/{key_id}` | Destroy a key |
| POST | `/v1/keys/{key_id}/rotate` | Trigger key rotation |
| POST | `/v1/operations/encrypt` | Encrypt data |
| POST | `/v1/operations/decrypt` | Decrypt data |
| POST | `/v1/operations/sign` | Sign data |
| POST | `/v1/operations/verify` | Verify signature |
| GET | `/v1/rotation/policies` | List rotation policies |
| POST | `/v1/rotation/policies` | Create rotation policy |
| GET | `/v1/migration/plans` | List migration plans |
| POST | `/v1/migration/plans` | Create migration plan |
| GET | `/v1/audit` | Query audit log |
| GET | `/v1/analytics` | Vault-wide analytics |
| GET | `/health` | Health check |

## Design Decisions

- **Simulated cryptography** — Real PQC algorithms require `liboqs`; this service simulates the API surface and key management logic with placeholder byte operations
- **Key material never exposed** — GET endpoints return metadata only; raw key bytes are internal
- **Envelope encryption** — Data encrypted with ephemeral symmetric key, symmetric key wrapped with PQC public key
