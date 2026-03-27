"""
Post-Quantum Cryptographic Vault — Phase 20 Service 1 of 5
Port: 9400

Simulated PQC key management with lattice/hash-based/code-based/hybrid
algorithm registry, key lifecycle, envelope encryption, signing,
key rotation, crypto-agility migration, and compliance audit trail.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class AlgorithmFamily(str, Enum):
    lattice = "lattice"
    hash_based = "hash_based"
    code_based = "code_based"
    hybrid = "hybrid"


class AlgorithmStatus(str, Enum):
    recommended = "recommended"
    acceptable = "acceptable"
    deprecated = "deprecated"
    broken = "broken"


class KeyPurpose(str, Enum):
    encryption = "encryption"
    signing = "signing"
    key_exchange = "key_exchange"
    authentication = "authentication"


class KeyState(str, Enum):
    generated = "generated"
    active = "active"
    suspended = "suspended"
    rotating = "rotating"
    retired = "retired"
    destroyed = "destroyed"


AVE_CATEGORIES: list[str] = [
    "prompt_injection", "tool_misuse", "memory_poisoning",
    "goal_hijacking", "identity_spoofing", "privilege_escalation",
    "data_exfiltration", "resource_exhaustion", "multi_agent_manipulation",
    "context_overflow", "guardrail_bypass", "output_manipulation",
    "supply_chain_compromise", "model_extraction", "reward_hacking",
    "capability_elicitation", "alignment_subversion", "delegation_abuse",
]

# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class AlgorithmRecord(BaseModel):
    algorithm_id: str
    name: str
    family: AlgorithmFamily
    nist_level: int = Field(ge=1, le=5)
    key_size_bits: int
    signature_size_bytes: Optional[int] = None
    status: AlgorithmStatus
    description: str = ""


class KeyCreate(BaseModel):
    algorithm_id: str
    purpose: KeyPurpose
    label: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)
    hsm_backed: bool = False


class KeyRecord(BaseModel):
    key_id: str
    algorithm_id: str
    purpose: KeyPurpose
    label: str
    state: KeyState
    version: int = 1
    fingerprint: str  # SHA-256 of simulated key material
    hsm_backed: bool
    metadata: Dict[str, Any]
    created_at: str
    rotated_at: Optional[str] = None
    expires_at: Optional[str] = None


class EncryptRequest(BaseModel):
    key_id: str
    plaintext: str
    aad: Optional[str] = None  # additional authenticated data


class DecryptRequest(BaseModel):
    key_id: str
    ciphertext: str
    nonce: str
    aad: Optional[str] = None


class SignRequest(BaseModel):
    key_id: str
    message: str


class VerifyRequest(BaseModel):
    key_id: str
    message: str
    signature: str


class RotationPolicy(BaseModel):
    policy_id: Optional[str] = None
    key_id: str
    interval_days: int = Field(default=90, ge=1)
    max_usages: Optional[int] = None
    on_compromise: bool = True


class MigrationPlan(BaseModel):
    plan_id: Optional[str] = None
    from_algorithm: str
    to_algorithm: str
    affected_key_ids: List[str] = Field(default_factory=list)
    deadline: Optional[str] = None
    status: str = "planned"  # planned | in_progress | completed


# ---------------------------------------------------------------------------
# In-Memory Stores
# ---------------------------------------------------------------------------

ALGORITHMS: Dict[str, AlgorithmRecord] = {}
keys: Dict[str, KeyRecord] = {}
_key_material: Dict[str, bytes] = {}  # key_id -> simulated raw bytes (never exposed via API)
rotation_policies: Dict[str, RotationPolicy] = {}
migration_plans: Dict[str, MigrationPlan] = {}
audit_log: List[Dict[str, Any]] = []
operation_counter: Dict[str, int] = defaultdict(int)  # key_id -> usage count


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _audit(action: str, details: Dict[str, Any]):
    entry = {"seq": len(audit_log) + 1, "action": action, **details, "timestamp": _now()}
    audit_log.append(entry)
    if len(audit_log) > 50000:
        audit_log.pop(0)


# ---------------------------------------------------------------------------
# Bootstrap Algorithms
# ---------------------------------------------------------------------------

_SEED_ALGORITHMS = [
    AlgorithmRecord(algorithm_id="KYBER-768", name="CRYSTALS-Kyber-768", family=AlgorithmFamily.lattice, nist_level=3, key_size_bits=2400, status=AlgorithmStatus.recommended, description="Lattice-based KEM, NIST FIPS 203"),
    AlgorithmRecord(algorithm_id="DILITHIUM-3", name="CRYSTALS-Dilithium-3", family=AlgorithmFamily.lattice, nist_level=3, key_size_bits=3936, signature_size_bytes=3293, status=AlgorithmStatus.recommended, description="Lattice-based signature, NIST FIPS 204"),
    AlgorithmRecord(algorithm_id="SPHINCS-256", name="SPHINCS+-SHA2-256f", family=AlgorithmFamily.hash_based, nist_level=5, key_size_bits=512, signature_size_bytes=29792, status=AlgorithmStatus.recommended, description="Stateless hash-based signature, NIST FIPS 205"),
    AlgorithmRecord(algorithm_id="MCELIECE-460896", name="Classic McEliece 460896", family=AlgorithmFamily.code_based, nist_level=5, key_size_bits=524160, status=AlgorithmStatus.acceptable, description="Code-based KEM, large keys"),
    AlgorithmRecord(algorithm_id="HYBRID-KYBER-X25519", name="Hybrid Kyber-768 + X25519", family=AlgorithmFamily.hybrid, nist_level=3, key_size_bits=2656, status=AlgorithmStatus.recommended, description="Composite PQC + classical for transitional security"),
]


def _bootstrap():
    if ALGORITHMS:
        return
    for a in _SEED_ALGORITHMS:
        ALGORITHMS[a.algorithm_id] = a


# ---------------------------------------------------------------------------
# Simulated Crypto Helpers
# ---------------------------------------------------------------------------

def _generate_key_material(algo: AlgorithmRecord) -> bytes:
    return os.urandom(algo.key_size_bits // 8)


def _fingerprint(material: bytes) -> str:
    return hashlib.sha256(material).hexdigest()


def _sim_encrypt(material: bytes, plaintext: str) -> tuple[str, str]:
    nonce = os.urandom(12).hex()
    # XOR-based simulation (NOT real encryption)
    pt_bytes = plaintext.encode()
    key_stream = hashlib.sha256(material + bytes.fromhex(nonce)).digest()
    ct = bytes(b ^ key_stream[i % len(key_stream)] for i, b in enumerate(pt_bytes))
    return ct.hex(), nonce


def _sim_decrypt(material: bytes, ciphertext_hex: str, nonce: str) -> str:
    ct = bytes.fromhex(ciphertext_hex)
    key_stream = hashlib.sha256(material + bytes.fromhex(nonce)).digest()
    pt = bytes(b ^ key_stream[i % len(key_stream)] for i, b in enumerate(ct))
    return pt.decode(errors="replace")


def _sim_sign(material: bytes, message: str) -> str:
    return hashlib.sha256(material + message.encode()).hexdigest()


def _sim_verify(material: bytes, message: str, signature: str) -> bool:
    expected = hashlib.sha256(material + message.encode()).hexdigest()
    return expected == signature


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Post-Quantum Cryptographic Vault",
    description="Phase 20 — PQC key management, encryption, signing, rotation, crypto-agility",
    version="20.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_bootstrap()


@app.get("/health")
def health():
    return {
        "service": "post-quantum-cryptographic-vault",
        "status": "healthy",
        "phase": 20,
        "port": 9400,
        "stats": {
            "algorithms": len(ALGORITHMS),
            "keys": len(keys),
            "active_keys": sum(1 for k in keys.values() if k.state == KeyState.active),
        },
        "timestamp": _now(),
    }


# ── Algorithms ─────────────────────────────────────────────────────────────

@app.get("/v1/algorithms")
def list_algorithms(family: Optional[AlgorithmFamily] = None, status: Optional[AlgorithmStatus] = None):
    results = list(ALGORITHMS.values())
    if family:
        results = [a for a in results if a.family == family]
    if status:
        results = [a for a in results if a.status == status]
    return {"algorithms": [a.dict() for a in results], "total": len(results)}


# ── Keys ───────────────────────────────────────────────────────────────────

@app.post("/v1/keys", status_code=201)
def generate_key(body: KeyCreate):
    if body.algorithm_id not in ALGORITHMS:
        raise HTTPException(404, "Algorithm not found")
    algo = ALGORITHMS[body.algorithm_id]
    if algo.status in (AlgorithmStatus.deprecated, AlgorithmStatus.broken):
        raise HTTPException(422, f"Algorithm {body.algorithm_id} is {algo.status.value}")
    kid = f"KEY-{uuid.uuid4().hex[:16]}"
    material = _generate_key_material(algo)
    _key_material[kid] = material
    record = KeyRecord(
        key_id=kid,
        algorithm_id=body.algorithm_id,
        purpose=body.purpose,
        label=body.label,
        state=KeyState.active,
        fingerprint=_fingerprint(material),
        hsm_backed=body.hsm_backed,
        metadata=body.metadata,
        created_at=_now(),
    )
    keys[kid] = record
    _audit("key_generated", {"key_id": kid, "algorithm": body.algorithm_id, "purpose": body.purpose.value})
    return record.dict()


@app.get("/v1/keys")
def list_keys(
    purpose: Optional[KeyPurpose] = None,
    state: Optional[KeyState] = None,
    algorithm_id: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    results = list(keys.values())
    if purpose:
        results = [k for k in results if k.purpose == purpose]
    if state:
        results = [k for k in results if k.state == state]
    if algorithm_id:
        results = [k for k in results if k.algorithm_id == algorithm_id]
    return {"keys": [k.dict() for k in results[:limit]], "total": len(results)}


@app.get("/v1/keys/{key_id}")
def get_key(key_id: str):
    if key_id not in keys:
        raise HTTPException(404, "Key not found")
    return keys[key_id].dict()


@app.delete("/v1/keys/{key_id}")
def destroy_key(key_id: str):
    if key_id not in keys:
        raise HTTPException(404, "Key not found")
    keys[key_id].state = KeyState.destroyed
    _key_material.pop(key_id, None)
    _audit("key_destroyed", {"key_id": key_id})
    return {"destroyed": key_id}


@app.post("/v1/keys/{key_id}/rotate")
def rotate_key(key_id: str):
    if key_id not in keys:
        raise HTTPException(404, "Key not found")
    k = keys[key_id]
    if k.state not in (KeyState.active, KeyState.suspended):
        raise HTTPException(422, f"Cannot rotate key in state {k.state.value}")
    algo = ALGORITHMS[k.algorithm_id]
    new_material = _generate_key_material(algo)
    _key_material[key_id] = new_material
    k.fingerprint = _fingerprint(new_material)
    k.version += 1
    k.rotated_at = _now()
    k.state = KeyState.active
    _audit("key_rotated", {"key_id": key_id, "new_version": k.version})
    return k.dict()


# ── Operations ─────────────────────────────────────────────────────────────

@app.post("/v1/operations/encrypt")
def encrypt(body: EncryptRequest):
    if body.key_id not in keys or body.key_id not in _key_material:
        raise HTTPException(404, "Key not found or destroyed")
    k = keys[body.key_id]
    if k.state != KeyState.active:
        raise HTTPException(422, f"Key is {k.state.value}")
    if k.purpose not in (KeyPurpose.encryption, KeyPurpose.key_exchange):
        raise HTTPException(422, "Key purpose does not support encryption")
    ct, nonce = _sim_encrypt(_key_material[body.key_id], body.plaintext)
    operation_counter[body.key_id] += 1
    _audit("encrypt", {"key_id": body.key_id, "plaintext_len": len(body.plaintext)})
    return {"ciphertext": ct, "nonce": nonce, "algorithm": k.algorithm_id, "key_version": k.version}


@app.post("/v1/operations/decrypt")
def decrypt(body: DecryptRequest):
    if body.key_id not in keys or body.key_id not in _key_material:
        raise HTTPException(404, "Key not found or destroyed")
    k = keys[body.key_id]
    if k.state not in (KeyState.active, KeyState.suspended):
        raise HTTPException(422, f"Key is {k.state.value}")
    pt = _sim_decrypt(_key_material[body.key_id], body.ciphertext, body.nonce)
    operation_counter[body.key_id] += 1
    _audit("decrypt", {"key_id": body.key_id})
    return {"plaintext": pt, "algorithm": k.algorithm_id, "key_version": k.version}


@app.post("/v1/operations/sign")
def sign(body: SignRequest):
    if body.key_id not in keys or body.key_id not in _key_material:
        raise HTTPException(404, "Key not found or destroyed")
    k = keys[body.key_id]
    if k.state != KeyState.active:
        raise HTTPException(422, f"Key is {k.state.value}")
    if k.purpose not in (KeyPurpose.signing, KeyPurpose.authentication):
        raise HTTPException(422, "Key purpose does not support signing")
    sig = _sim_sign(_key_material[body.key_id], body.message)
    operation_counter[body.key_id] += 1
    _audit("sign", {"key_id": body.key_id, "message_len": len(body.message)})
    return {"signature": sig, "algorithm": k.algorithm_id, "key_version": k.version}


@app.post("/v1/operations/verify")
def verify(body: VerifyRequest):
    if body.key_id not in keys or body.key_id not in _key_material:
        raise HTTPException(404, "Key not found or destroyed")
    k = keys[body.key_id]
    valid = _sim_verify(_key_material[body.key_id], body.message, body.signature)
    _audit("verify", {"key_id": body.key_id, "valid": valid})
    return {"valid": valid, "algorithm": k.algorithm_id, "key_version": k.version}


# ── Rotation Policies ──────────────────────────────────────────────────────

@app.post("/v1/rotation/policies", status_code=201)
def create_rotation_policy(body: RotationPolicy):
    if body.key_id not in keys:
        raise HTTPException(404, "Key not found")
    pid = f"RPOL-{uuid.uuid4().hex[:12]}"
    body.policy_id = pid
    rotation_policies[pid] = body
    return body.dict()


@app.get("/v1/rotation/policies")
def list_rotation_policies():
    return {"policies": [p.dict() for p in rotation_policies.values()], "total": len(rotation_policies)}


# ── Migration Plans ────────────────────────────────────────────────────────

@app.post("/v1/migration/plans", status_code=201)
def create_migration_plan(body: MigrationPlan):
    if body.from_algorithm not in ALGORITHMS:
        raise HTTPException(404, f"Source algorithm {body.from_algorithm} not found")
    if body.to_algorithm not in ALGORITHMS:
        raise HTTPException(404, f"Target algorithm {body.to_algorithm} not found")
    mid = f"MIG-{uuid.uuid4().hex[:12]}"
    body.plan_id = mid
    if not body.affected_key_ids:
        body.affected_key_ids = [
            k.key_id for k in keys.values()
            if k.algorithm_id == body.from_algorithm and k.state == KeyState.active
        ]
    migration_plans[mid] = body
    _audit("migration_plan_created", {"plan_id": mid, "from": body.from_algorithm, "to": body.to_algorithm})
    return body.dict()


@app.get("/v1/migration/plans")
def list_migration_plans():
    return {"plans": [p.dict() for p in migration_plans.values()], "total": len(migration_plans)}


# ── Audit ──────────────────────────────────────────────────────────────────

@app.get("/v1/audit")
def get_audit(action: Optional[str] = None, key_id: Optional[str] = None, limit: int = Query(default=100, ge=1, le=5000)):
    results = audit_log[:]
    if action:
        results = [e for e in results if e.get("action") == action]
    if key_id:
        results = [e for e in results if e.get("key_id") == key_id]
    return {"entries": results[-limit:], "total": len(results)}


# ── Analytics ──────────────────────────────────────────────────────────────

@app.get("/v1/analytics")
def analytics():
    state_dist: Dict[str, int] = defaultdict(int)
    algo_dist: Dict[str, int] = defaultdict(int)
    purpose_dist: Dict[str, int] = defaultdict(int)
    for k in keys.values():
        state_dist[k.state.value] += 1
        algo_dist[k.algorithm_id] += 1
        purpose_dist[k.purpose.value] += 1
    return {
        "total_keys": len(keys),
        "state_distribution": dict(state_dist),
        "algorithm_distribution": dict(algo_dist),
        "purpose_distribution": dict(purpose_dist),
        "total_operations": sum(operation_counter.values()),
        "rotation_policies": len(rotation_policies),
        "migration_plans": len(migration_plans),
        "audit_entries": len(audit_log),
    }


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9400)
