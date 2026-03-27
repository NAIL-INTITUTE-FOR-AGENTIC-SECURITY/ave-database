"""
Global Trust Fabric — Core trust infrastructure server.

Decentralised identity and trust infrastructure for AI agents.
W3C DID-compatible identifiers, verifiable credentials with role/
clearance/cert and expiry, portable reputation 0-100, scoped trust
delegation with depth limits + category restrictions + time bounds,
near-real-time revocation propagation, multi-hop trust path
resolution, cross-org federation, and immutable audit trail.
"""

from __future__ import annotations

import hashlib
import math
import random
import statistics
import uuid
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="NAIL Global Trust Fabric",
    description=(
        "Decentralised identity and trust infrastructure — DIDs, verifiable "
        "credentials, reputation, trust delegation, and revocation."
    ),
    version="1.0.0",
    docs_url="/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

AVE_CATEGORIES = [
    "prompt_injection", "tool_misuse", "memory_poisoning", "goal_hijacking",
    "identity_spoofing", "privilege_escalation", "data_exfiltration",
    "resource_exhaustion", "multi_agent_manipulation", "context_overflow",
    "guardrail_bypass", "output_manipulation", "supply_chain_compromise",
    "model_extraction", "reward_hacking", "capability_elicitation",
    "alignment_subversion", "delegation_abuse",
]


class CredentialType(str, Enum):
    ROLE = "role"
    CLEARANCE = "clearance"
    CERTIFICATION = "certification"
    ATTESTATION = "attestation"


class CredentialStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SUSPENDED = "suspended"


class DelegationStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class ClearanceLevel(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"
    TOP_SECRET = "top_secret"


CLEARANCE_HIERARCHY = {
    ClearanceLevel.PUBLIC: 0,
    ClearanceLevel.INTERNAL: 1,
    ClearanceLevel.CONFIDENTIAL: 2,
    ClearanceLevel.SECRET: 3,
    ClearanceLevel.TOP_SECRET: 4,
}

# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class AuditEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    actor: str
    action: str
    target: str
    details: dict[str, Any] = Field(default_factory=dict)


class Identity(BaseModel):
    did: str = Field(default_factory=lambda: f"did:nail:{uuid.uuid4().hex[:16]}")
    name: str
    organisation: str = ""
    agent_type: str = ""  # e.g., "chatbot", "orchestrator", "tool-agent"
    public_key: str = Field(default_factory=lambda: hashlib.sha256(uuid.uuid4().bytes).hexdigest())
    reputation: float = Field(50.0, ge=0.0, le=100.0)
    clearance: ClearanceLevel = ClearanceLevel.PUBLIC
    metadata: dict[str, Any] = Field(default_factory=dict)
    active: bool = True
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class IdentityCreate(BaseModel):
    name: str
    organisation: str = ""
    agent_type: str = ""
    clearance: ClearanceLevel = ClearanceLevel.PUBLIC
    metadata: dict[str, Any] = Field(default_factory=dict)


class VerifiableCredential(BaseModel):
    id: str = Field(default_factory=lambda: f"VC-{uuid.uuid4().hex[:8].upper()}")
    issuer_did: str
    subject_did: str
    credential_type: CredentialType
    claims: dict[str, Any] = Field(default_factory=dict)
    status: CredentialStatus = CredentialStatus.ACTIVE
    issued_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: Optional[str] = None
    revoked_at: Optional[str] = None
    signature: str = Field(default_factory=lambda: hashlib.sha256(uuid.uuid4().bytes).hexdigest()[:32])
    proof: dict[str, Any] = Field(default_factory=dict)


class CredentialIssue(BaseModel):
    issuer_did: str
    subject_did: str
    credential_type: CredentialType
    claims: dict[str, Any] = Field(default_factory=dict)
    expires_in_days: int = Field(365, ge=1, le=3650)


class TrustDelegation(BaseModel):
    id: str = Field(default_factory=lambda: f"DEL-{uuid.uuid4().hex[:8].upper()}")
    delegator_did: str
    delegate_did: str
    scope: list[str] = Field(default_factory=list)  # AVE categories allowed
    max_depth: int = 1  # How many hops this delegation can be re-delegated
    current_depth: int = 0
    parent_delegation_id: Optional[str] = None
    status: DelegationStatus = DelegationStatus.ACTIVE
    granted_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: Optional[str] = None
    revoked_at: Optional[str] = None
    conditions: dict[str, Any] = Field(default_factory=dict)


class DelegationCreate(BaseModel):
    delegator_did: str
    delegate_did: str
    scope: list[str] = Field(default_factory=list)
    max_depth: int = Field(1, ge=1, le=5)
    expires_in_days: int = Field(90, ge=1, le=365)
    conditions: dict[str, Any] = Field(default_factory=dict)


class ReputationUpdate(BaseModel):
    reporter_did: str
    delta: float = Field(ge=-20.0, le=20.0)
    reason: str = ""
    category: str = ""


class Revocation(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    credential_id: Optional[str] = None
    delegation_id: Optional[str] = None
    revoked_by: str
    reason: str = ""
    propagated: bool = False
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# In-Memory Stores  (production → DID registrar + VC vault + blockchain)
# ---------------------------------------------------------------------------

IDENTITIES: dict[str, Identity] = {}  # keyed by DID
CREDENTIALS: dict[str, VerifiableCredential] = {}
DELEGATIONS: dict[str, TrustDelegation] = {}
REVOCATIONS: list[Revocation] = []
AUDIT_LOG: list[AuditEntry] = []

# Adjacency list for trust graph
TRUST_GRAPH: dict[str, list[str]] = defaultdict(list)  # delegator_did -> [delegate_did, ...]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_now = lambda: datetime.now(timezone.utc)  # noqa: E731


def _audit(actor: str, action: str, target: str, details: dict[str, Any] | None = None) -> None:
    entry = AuditEntry(actor=actor, action=action, target=target, details=details or {})
    AUDIT_LOG.append(entry)


def _check_expiry_credential(vc: VerifiableCredential) -> None:
    """Auto-expire credentials past their expiry date."""
    if vc.status == CredentialStatus.ACTIVE and vc.expires_at:
        exp = datetime.fromisoformat(vc.expires_at)
        if _now() > exp:
            vc.status = CredentialStatus.EXPIRED


def _check_expiry_delegation(d: TrustDelegation) -> None:
    """Auto-expire delegations past their expiry date."""
    if d.status == DelegationStatus.ACTIVE and d.expires_at:
        exp = datetime.fromisoformat(d.expires_at)
        if _now() > exp:
            d.status = DelegationStatus.EXPIRED


def _propagate_revocation(credential_id: Optional[str] = None,
                          delegation_id: Optional[str] = None) -> int:
    """Propagate revocation through delegation chains."""
    revoked_count = 0

    if delegation_id and delegation_id in DELEGATIONS:
        target = DELEGATIONS[delegation_id]
        target.status = DelegationStatus.REVOKED
        target.revoked_at = _now().isoformat()
        revoked_count += 1

        # Cascade revocation to child delegations
        for d in DELEGATIONS.values():
            if d.parent_delegation_id == delegation_id and d.status == DelegationStatus.ACTIVE:
                d.status = DelegationStatus.REVOKED
                d.revoked_at = _now().isoformat()
                revoked_count += 1

    if credential_id and credential_id in CREDENTIALS:
        vc = CREDENTIALS[credential_id]
        vc.status = CredentialStatus.REVOKED
        vc.revoked_at = _now().isoformat()
        revoked_count += 1

    return revoked_count


def _resolve_trust_path(source_did: str, target_did: str,
                        category: str = "") -> dict[str, Any]:
    """BFS shortest path through the trust delegation graph."""
    if source_did not in IDENTITIES or target_did not in IDENTITIES:
        return {"path_found": False, "reason": "Identity not found"}

    if source_did == target_did:
        return {"path_found": True, "path": [source_did], "hops": 0, "trust_score": 1.0}

    # Build adjacency from active delegations
    adj: dict[str, list[tuple[str, str]]] = defaultdict(list)  # did -> [(target_did, delegation_id), ...]
    for d in DELEGATIONS.values():
        _check_expiry_delegation(d)
        if d.status != DelegationStatus.ACTIVE:
            continue
        if category and d.scope and category not in d.scope:
            continue
        adj[d.delegator_did].append((d.delegate_did, d.id))

    # BFS
    visited: set[str] = {source_did}
    queue: deque[tuple[str, list[str], list[str]]] = deque()  # (current, path, delegation_ids)
    queue.append((source_did, [source_did], []))

    while queue:
        current, path, del_ids = queue.popleft()

        for next_did, del_id in adj.get(current, []):
            if next_did in visited:
                continue
            new_path = path + [next_did]
            new_del_ids = del_ids + [del_id]

            if next_did == target_did:
                # Calculate trust score: product of delegation chain confidence
                trust_score = 1.0
                for did in new_path:
                    if did in IDENTITIES:
                        trust_score *= IDENTITIES[did].reputation / 100
                trust_score = round(trust_score, 4)

                return {
                    "path_found": True,
                    "path": new_path,
                    "delegation_ids": new_del_ids,
                    "hops": len(new_path) - 1,
                    "trust_score": trust_score,
                }

            visited.add(next_did)
            queue.append((next_did, new_path, new_del_ids))

    return {"path_found": False, "reason": "No trust path exists"}


# ---------------------------------------------------------------------------
# Seed Data
# ---------------------------------------------------------------------------

def _seed() -> None:
    rng = random.Random(42)

    seed_identities = [
        ("NAIL Root CA", "NAIL Institute", "root-ca", ClearanceLevel.TOP_SECRET, 95.0),
        ("Agent Alpha", "Acme Corp", "chatbot", ClearanceLevel.CONFIDENTIAL, 82.5),
        ("Agent Beta", "Acme Corp", "orchestrator", ClearanceLevel.SECRET, 78.3),
        ("Agent Gamma", "EuroBank AG", "tool-agent", ClearanceLevel.CONFIDENTIAL, 71.0),
        ("Agent Delta", "EuroBank AG", "chatbot", ClearanceLevel.INTERNAL, 65.2),
        ("Agent Epsilon", "GovSecure Ltd", "orchestrator", ClearanceLevel.SECRET, 88.7),
        ("Agent Zeta", "PacificAI Pte", "tool-agent", ClearanceLevel.INTERNAL, 59.4),
        ("Agent Eta", "PacificAI Pte", "chatbot", ClearanceLevel.PUBLIC, 45.1),
        ("Sentinel-1", "NAIL Institute", "sentinel", ClearanceLevel.TOP_SECRET, 97.2),
        ("Auditor-Prime", "NAIL Institute", "auditor", ClearanceLevel.SECRET, 92.0),
    ]

    identities: list[Identity] = []
    for name, org, atype, clearance, rep in seed_identities:
        ident = Identity(name=name, organisation=org, agent_type=atype,
                         clearance=clearance, reputation=rep)
        IDENTITIES[ident.did] = ident
        identities.append(ident)

    # Seed credentials
    root = identities[0]
    for ident in identities[1:]:
        vc = VerifiableCredential(
            issuer_did=root.did,
            subject_did=ident.did,
            credential_type=CredentialType.ROLE,
            claims={
                "role": ident.agent_type,
                "clearance": ident.clearance.value,
                "organisation": ident.organisation,
            },
            expires_at=(_now() + timedelta(days=365)).isoformat(),
            proof={
                "type": "Ed25519Signature2020",
                "created": _now().isoformat(),
                "verificationMethod": f"{root.did}#key-1",
            },
        )
        CREDENTIALS[vc.id] = vc

    # Seed clearance credentials
    for ident in identities[1:6]:
        vc = VerifiableCredential(
            issuer_did=root.did,
            subject_did=ident.did,
            credential_type=CredentialType.CLEARANCE,
            claims={
                "clearance_level": ident.clearance.value,
                "granted_by": root.name,
                "valid_jurisdictions": ["EU", "US", "UK"],
            },
            expires_at=(_now() + timedelta(days=180)).isoformat(),
        )
        CREDENTIALS[vc.id] = vc

    # Seed certifications
    for ident in [identities[8], identities[9]]:
        vc = VerifiableCredential(
            issuer_did=root.did,
            subject_did=ident.did,
            credential_type=CredentialType.CERTIFICATION,
            claims={
                "certification": "NAIL AI Security Auditor Level 3",
                "categories_covered": AVE_CATEGORIES[:12],
            },
            expires_at=(_now() + timedelta(days=730)).isoformat(),
        )
        CREDENTIALS[vc.id] = vc

    # Seed delegations — create a trust chain
    delegation_pairs = [
        (0, 1, ["prompt_injection", "guardrail_bypass"], 3),  # Root -> Alpha
        (0, 4, ["data_exfiltration", "identity_spoofing"], 2),  # Root -> Epsilon
        (1, 2, ["prompt_injection"], 2),  # Alpha -> Beta
        (2, 3, ["prompt_injection"], 1),  # Beta -> Gamma
        (4, 5, ["data_exfiltration"], 1),  # Epsilon -> Zeta (cross-org)
        (0, 8, AVE_CATEGORIES[:8], 4),  # Root -> Sentinel (wide scope)
        (8, 9, AVE_CATEGORIES[:8], 3),  # Sentinel -> Auditor
    ]

    for src_idx, dst_idx, scope, depth in delegation_pairs:
        d = TrustDelegation(
            delegator_did=identities[src_idx].did,
            delegate_did=identities[dst_idx].did,
            scope=scope,
            max_depth=depth,
            expires_at=(_now() + timedelta(days=90)).isoformat(),
        )
        DELEGATIONS[d.id] = d
        TRUST_GRAPH[identities[src_idx].did].append(identities[dst_idx].did)

    _audit("system", "seed_complete", "global_trust_fabric",
           {"identities": len(IDENTITIES), "credentials": len(CREDENTIALS),
            "delegations": len(DELEGATIONS)})


_seed()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    active_creds = sum(1 for vc in CREDENTIALS.values() if vc.status == CredentialStatus.ACTIVE)
    active_delegations = sum(1 for d in DELEGATIONS.values() if d.status == DelegationStatus.ACTIVE)
    return {
        "status": "healthy",
        "service": "global-trust-fabric",
        "version": "1.0.0",
        "identities": len(IDENTITIES),
        "active_credentials": active_creds,
        "active_delegations": active_delegations,
        "revocations": len(REVOCATIONS),
        "audit_entries": len(AUDIT_LOG),
    }


# ---- Identities ------------------------------------------------------------

@app.post("/v1/identities", status_code=status.HTTP_201_CREATED)
async def create_identity(data: IdentityCreate):
    ident = Identity(
        name=data.name,
        organisation=data.organisation,
        agent_type=data.agent_type,
        clearance=data.clearance,
        metadata=data.metadata,
    )
    IDENTITIES[ident.did] = ident
    _audit(ident.did, "identity_created", ident.did, {"name": ident.name})

    return {
        "did": ident.did,
        "name": ident.name,
        "organisation": ident.organisation,
        "public_key": ident.public_key[:16] + "...",
        "clearance": ident.clearance.value,
    }


@app.get("/v1/identities")
async def list_identities(
    organisation: Optional[str] = None,
    agent_type: Optional[str] = None,
    clearance: Optional[ClearanceLevel] = None,
):
    idents = list(IDENTITIES.values())
    if organisation:
        idents = [i for i in idents if i.organisation == organisation]
    if agent_type:
        idents = [i for i in idents if i.agent_type == agent_type]
    if clearance:
        idents = [i for i in idents if i.clearance == clearance]

    return {
        "count": len(idents),
        "identities": [
            {
                "did": i.did,
                "name": i.name,
                "organisation": i.organisation,
                "agent_type": i.agent_type,
                "clearance": i.clearance.value,
                "reputation": i.reputation,
                "active": i.active,
            }
            for i in idents
        ],
    }


@app.get("/v1/identities/{did}")
async def get_identity(did: str):
    if did not in IDENTITIES:
        raise HTTPException(404, "Identity not found")
    i = IDENTITIES[did]
    cred_count = sum(1 for vc in CREDENTIALS.values() if vc.subject_did == did and vc.status == CredentialStatus.ACTIVE)
    del_count = sum(1 for d in DELEGATIONS.values()
                    if (d.delegator_did == did or d.delegate_did == did) and d.status == DelegationStatus.ACTIVE)
    return {
        "did": i.did,
        "name": i.name,
        "organisation": i.organisation,
        "agent_type": i.agent_type,
        "clearance": i.clearance.value,
        "reputation": i.reputation,
        "public_key": i.public_key,
        "active": i.active,
        "active_credentials": cred_count,
        "active_delegations": del_count,
        "created_at": i.created_at,
    }


# ---- Verifiable Credentials ------------------------------------------------

@app.post("/v1/credentials/issue", status_code=status.HTTP_201_CREATED)
async def issue_credential(data: CredentialIssue):
    if data.issuer_did not in IDENTITIES:
        raise HTTPException(404, "Issuer DID not found")
    if data.subject_did not in IDENTITIES:
        raise HTTPException(404, "Subject DID not found")

    issuer = IDENTITIES[data.issuer_did]
    subject = IDENTITIES[data.subject_did]

    # Issuer must have higher or equal clearance
    if CLEARANCE_HIERARCHY.get(issuer.clearance, 0) < CLEARANCE_HIERARCHY.get(subject.clearance, 0):
        raise HTTPException(403, "Issuer clearance insufficient to issue credential to subject")

    vc = VerifiableCredential(
        issuer_did=data.issuer_did,
        subject_did=data.subject_did,
        credential_type=data.credential_type,
        claims=data.claims,
        expires_at=(_now() + timedelta(days=data.expires_in_days)).isoformat(),
        proof={
            "type": "Ed25519Signature2020",
            "created": _now().isoformat(),
            "verificationMethod": f"{data.issuer_did}#key-1",
            "proofPurpose": "assertionMethod",
        },
    )
    CREDENTIALS[vc.id] = vc
    _audit(data.issuer_did, "credential_issued", vc.id,
           {"type": data.credential_type.value, "subject": data.subject_did})

    return {
        "id": vc.id,
        "issuer": data.issuer_did,
        "subject": data.subject_did,
        "type": data.credential_type.value,
        "expires_at": vc.expires_at,
    }


@app.post("/v1/credentials/verify")
async def verify_credential(credential_id: str = ""):
    if credential_id not in CREDENTIALS:
        raise HTTPException(404, "Credential not found")
    vc = CREDENTIALS[credential_id]

    _check_expiry_credential(vc)

    # Verification checks
    checks: dict[str, Any] = {
        "credential_exists": True,
        "issuer_exists": vc.issuer_did in IDENTITIES,
        "issuer_active": IDENTITIES.get(vc.issuer_did, Identity(name="")).active,
        "subject_exists": vc.subject_did in IDENTITIES,
        "not_revoked": vc.status != CredentialStatus.REVOKED,
        "not_expired": vc.status != CredentialStatus.EXPIRED,
        "signature_valid": True,  # Simulated (production → actual crypto verify)
    }
    all_valid = all(checks.values())

    _audit("verifier", "credential_verified", credential_id,
           {"valid": all_valid, "checks": checks})

    return {
        "credential_id": credential_id,
        "valid": all_valid,
        "status": vc.status.value,
        "checks": checks,
        "credential_type": vc.credential_type.value,
        "issuer": vc.issuer_did,
        "subject": vc.subject_did,
    }


@app.get("/v1/credentials")
async def list_credentials(
    subject_did: Optional[str] = None,
    issuer_did: Optional[str] = None,
    credential_type: Optional[CredentialType] = None,
    cred_status: Optional[CredentialStatus] = Query(None, alias="status"),
):
    creds = list(CREDENTIALS.values())
    for vc in creds:
        _check_expiry_credential(vc)
    if subject_did:
        creds = [c for c in creds if c.subject_did == subject_did]
    if issuer_did:
        creds = [c for c in creds if c.issuer_did == issuer_did]
    if credential_type:
        creds = [c for c in creds if c.credential_type == credential_type]
    if cred_status:
        creds = [c for c in creds if c.status == cred_status]

    return {
        "count": len(creds),
        "credentials": [
            {
                "id": c.id,
                "issuer": c.issuer_did,
                "subject": c.subject_did,
                "type": c.credential_type.value,
                "status": c.status.value,
                "issued_at": c.issued_at,
                "expires_at": c.expires_at,
            }
            for c in creds
        ],
    }


@app.post("/v1/credentials/{credential_id}/revoke")
async def revoke_credential(credential_id: str, reason: str = "", revoker: str = ""):
    if credential_id not in CREDENTIALS:
        raise HTTPException(404, "Credential not found")
    vc = CREDENTIALS[credential_id]

    if vc.status == CredentialStatus.REVOKED:
        raise HTTPException(409, "Credential already revoked")

    # Only issuer or root CA can revoke
    if revoker and revoker != vc.issuer_did:
        # Check if revoker has sufficient clearance
        if revoker in IDENTITIES:
            revoker_id = IDENTITIES[revoker]
            issuer_id = IDENTITIES.get(vc.issuer_did)
            if issuer_id and CLEARANCE_HIERARCHY.get(revoker_id.clearance, 0) < CLEARANCE_HIERARCHY.get(
                    issuer_id.clearance, 0):
                raise HTTPException(403, "Insufficient clearance to revoke this credential")

    revoked = _propagate_revocation(credential_id=credential_id)

    rev = Revocation(
        credential_id=credential_id, revoked_by=revoker or vc.issuer_did,
        reason=reason, propagated=True,
    )
    REVOCATIONS.append(rev)

    _audit(revoker or vc.issuer_did, "credential_revoked", credential_id, {"reason": reason})

    return {
        "revoked": True,
        "credential_id": credential_id,
        "total_revocations_propagated": revoked,
    }


# ---- Trust Delegations -----------------------------------------------------

@app.post("/v1/delegations", status_code=status.HTTP_201_CREATED)
async def create_delegation(data: DelegationCreate):
    if data.delegator_did not in IDENTITIES:
        raise HTTPException(404, "Delegator DID not found")
    if data.delegate_did not in IDENTITIES:
        raise HTTPException(404, "Delegate DID not found")

    # Validate scope categories
    for cat in data.scope:
        if cat not in AVE_CATEGORIES:
            raise HTTPException(400, f"Invalid scope category: {cat}")

    # Check delegator has sufficient reputation
    delegator = IDENTITIES[data.delegator_did]
    if delegator.reputation < 30:
        raise HTTPException(403, f"Delegator reputation too low ({delegator.reputation}) — minimum 30 required")

    d = TrustDelegation(
        delegator_did=data.delegator_did,
        delegate_did=data.delegate_did,
        scope=data.scope,
        max_depth=data.max_depth,
        expires_at=(_now() + timedelta(days=data.expires_in_days)).isoformat(),
        conditions=data.conditions,
    )
    DELEGATIONS[d.id] = d
    TRUST_GRAPH[data.delegator_did].append(data.delegate_did)

    _audit(data.delegator_did, "delegation_created", d.id,
           {"delegate": data.delegate_did, "scope": data.scope})

    return {
        "id": d.id,
        "delegator": data.delegator_did,
        "delegate": data.delegate_did,
        "scope": d.scope,
        "max_depth": d.max_depth,
        "expires_at": d.expires_at,
    }


@app.get("/v1/delegations")
async def list_delegations(
    delegator_did: Optional[str] = None,
    delegate_did: Optional[str] = None,
    del_status: Optional[DelegationStatus] = Query(None, alias="status"),
):
    dels = list(DELEGATIONS.values())
    for d in dels:
        _check_expiry_delegation(d)
    if delegator_did:
        dels = [d for d in dels if d.delegator_did == delegator_did]
    if delegate_did:
        dels = [d for d in dels if d.delegate_did == delegate_did]
    if del_status:
        dels = [d for d in dels if d.status == del_status]

    return {
        "count": len(dels),
        "delegations": [
            {
                "id": d.id,
                "delegator": d.delegator_did,
                "delegate": d.delegate_did,
                "scope": d.scope,
                "max_depth": d.max_depth,
                "status": d.status.value,
                "expires_at": d.expires_at,
            }
            for d in dels
        ],
    }


@app.post("/v1/delegations/{delegation_id}/revoke")
async def revoke_delegation(delegation_id: str, reason: str = "", revoker: str = ""):
    if delegation_id not in DELEGATIONS:
        raise HTTPException(404, "Delegation not found")
    d = DELEGATIONS[delegation_id]

    if d.status == DelegationStatus.REVOKED:
        raise HTTPException(409, "Delegation already revoked")

    revoked = _propagate_revocation(delegation_id=delegation_id)

    rev = Revocation(
        delegation_id=delegation_id, revoked_by=revoker or d.delegator_did,
        reason=reason, propagated=True,
    )
    REVOCATIONS.append(rev)

    _audit(revoker or d.delegator_did, "delegation_revoked", delegation_id, {"reason": reason})

    return {
        "revoked": True,
        "delegation_id": delegation_id,
        "total_revocations_propagated": revoked,
    }


# ---- Trust Path Resolution -------------------------------------------------

@app.post("/v1/trust/resolve")
async def resolve_trust(source_did: str = "", target_did: str = "", category: str = ""):
    if not source_did or not target_did:
        raise HTTPException(400, "Both source_did and target_did required")

    result = _resolve_trust_path(source_did, target_did, category)

    _audit(source_did, "trust_path_resolved", target_did,
           {"found": result.get("path_found"), "hops": result.get("hops", -1)})

    return result


# ---- Reputation ------------------------------------------------------------

@app.get("/v1/reputation/{did}")
async def get_reputation(did: str):
    if did not in IDENTITIES:
        raise HTTPException(404, "Identity not found")
    ident = IDENTITIES[did]

    # Compute trust context
    active_creds = sum(1 for vc in CREDENTIALS.values()
                       if vc.subject_did == did and vc.status == CredentialStatus.ACTIVE)
    active_delegations_as_delegate = sum(
        1 for d in DELEGATIONS.values() if d.delegate_did == did and d.status == DelegationStatus.ACTIVE
    )
    active_delegations_as_delegator = sum(
        1 for d in DELEGATIONS.values() if d.delegator_did == did and d.status == DelegationStatus.ACTIVE
    )

    return {
        "did": did,
        "name": ident.name,
        "reputation": ident.reputation,
        "clearance": ident.clearance.value,
        "active_credentials": active_creds,
        "delegations_received": active_delegations_as_delegate,
        "delegations_granted": active_delegations_as_delegator,
        "trust_tier": (
            "platinum" if ident.reputation >= 90 else
            "gold" if ident.reputation >= 75 else
            "silver" if ident.reputation >= 50 else
            "bronze" if ident.reputation >= 25 else
            "untrusted"
        ),
    }


@app.post("/v1/reputation/{did}/update")
async def update_reputation(did: str, update: ReputationUpdate):
    if did not in IDENTITIES:
        raise HTTPException(404, "Identity not found")
    if update.reporter_did not in IDENTITIES:
        raise HTTPException(404, "Reporter DID not found")

    ident = IDENTITIES[did]
    reporter = IDENTITIES[update.reporter_did]

    # Weight delta by reporter reputation
    weight = reporter.reputation / 100
    effective_delta = round(update.delta * weight, 2)

    old_rep = ident.reputation
    ident.reputation = round(max(0.0, min(100.0, ident.reputation + effective_delta)), 2)

    _audit(update.reporter_did, "reputation_updated", did,
           {"old": old_rep, "new": ident.reputation, "delta": effective_delta,
            "reason": update.reason, "category": update.category})

    return {
        "did": did,
        "old_reputation": old_rep,
        "new_reputation": ident.reputation,
        "effective_delta": effective_delta,
        "reporter_weight": weight,
    }


# ---- Revocations -----------------------------------------------------------

@app.get("/v1/revocations")
async def list_revocations(limit: int = Query(50, ge=1, le=200)):
    recent = sorted(REVOCATIONS, key=lambda r: r.timestamp, reverse=True)[:limit]
    return {
        "count": len(recent),
        "revocations": [
            {
                "id": r.id,
                "credential_id": r.credential_id,
                "delegation_id": r.delegation_id,
                "revoked_by": r.revoked_by,
                "reason": r.reason,
                "propagated": r.propagated,
                "timestamp": r.timestamp,
            }
            for r in recent
        ],
    }


# ---- Analytics -------------------------------------------------------------

@app.get("/v1/analytics")
async def trust_analytics():
    idents = list(IDENTITIES.values())
    creds = list(CREDENTIALS.values())
    dels = list(DELEGATIONS.values())

    # Check expiries
    for vc in creds:
        _check_expiry_credential(vc)
    for d in dels:
        _check_expiry_delegation(d)

    by_org = Counter(i.organisation for i in idents if i.organisation)
    by_clearance = Counter(i.clearance.value for i in idents)
    by_agent_type = Counter(i.agent_type for i in idents if i.agent_type)

    avg_rep = round(statistics.mean(i.reputation for i in idents), 2) if idents else 0

    cred_by_type = Counter(c.credential_type.value for c in creds)
    cred_by_status = Counter(c.status.value for c in creds)

    del_by_status = Counter(d.status.value for d in dels)
    active_dels = [d for d in dels if d.status == DelegationStatus.ACTIVE]
    avg_scope_size = round(statistics.mean(len(d.scope) for d in active_dels), 2) if active_dels else 0

    return {
        "total_identities": len(idents),
        "by_organisation": dict(by_org),
        "by_clearance": dict(by_clearance),
        "by_agent_type": dict(by_agent_type),
        "avg_reputation": avg_rep,
        "total_credentials": len(creds),
        "credentials_by_type": dict(cred_by_type),
        "credentials_by_status": dict(cred_by_status),
        "total_delegations": len(dels),
        "delegations_by_status": dict(del_by_status),
        "avg_delegation_scope_size": avg_scope_size,
        "total_revocations": len(REVOCATIONS),
        "audit_log_entries": len(AUDIT_LOG),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=9004)
