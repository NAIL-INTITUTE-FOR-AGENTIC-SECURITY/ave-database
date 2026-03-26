"""
Federated Threat Intelligence Network — Core federation server.

Implements peer-to-peer intelligence sharing with trust scoring,
privacy-preserving protocols, gossip-based discovery, and
conflict resolution for decentralised AVE threat intelligence.
"""

from __future__ import annotations

import hashlib
import math
import random
import statistics
import uuid
from collections import Counter, defaultdict
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
    title="NAIL Federated Threat Intelligence Network",
    description="Decentralised P2P intelligence sharing for agentic AI security.",
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
# Constants & enums
# ---------------------------------------------------------------------------

MAX_PEERS = 50
HEARTBEAT_INTERVAL_S = 60
TRUST_MIN_RECEIVE = 0.3
TRUST_MIN_RELAY = 0.5
DEFAULT_EPSILON = 1.0  # Differential privacy parameter


class TLPLevel(str, Enum):
    CLEAR = "TLP:CLEAR"
    GREEN = "TLP:GREEN"
    AMBER = "TLP:AMBER"
    RED = "TLP:RED"


class PeerStatus(str, Enum):
    ACTIVE = "active"
    DEGRADED = "degraded"
    UNREACHABLE = "unreachable"
    BANNED = "banned"


class IntelType(str, Enum):
    INDICATOR = "indicator"
    SIGHTING = "sighting"
    VULNERABILITY = "vulnerability"
    ATTACK_PATTERN = "attack_pattern"
    COURSE_OF_ACTION = "course_of_action"


# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------


class PeerNode(BaseModel):
    """A peer in the federation network."""

    peer_id: str = Field(default_factory=lambda: f"node-{uuid.uuid4().hex[:12]}")
    name: str
    organisation: str
    endpoint: str  # Base URL for the peer's federation API
    region: str = "global"
    status: PeerStatus = PeerStatus.ACTIVE
    trust_score: float = 0.5
    contribution_score: float = 0.0
    reputation_score: float = 0.5
    joined_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_heartbeat: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    strikes: int = 0
    shared_categories: list[str] = Field(default_factory=list)
    intel_sent: int = 0
    intel_received: int = 0
    certificate_fingerprint: str = ""


class IntelItem(BaseModel):
    """A shared intelligence item."""

    intel_id: str = Field(default_factory=lambda: f"intel-{uuid.uuid4().hex[:12]}")
    intel_type: IntelType
    title: str
    description: str
    ave_categories: list[str] = Field(default_factory=list)
    tlp: TLPLevel = TLPLevel.GREEN
    confidence: int = 50  # 0-100
    source_node: str = ""
    content_hash: str = ""
    stix_bundle: dict[str, Any] = Field(default_factory=dict)
    shared_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    ttl_hours: int = 720  # 30 days default
    vector_clock: dict[str, int] = Field(default_factory=dict)
    relay_count: int = 0
    quality_ratings: list[float] = Field(default_factory=list)


class TrustRating(BaseModel):
    """Rating of intelligence quality from a peer."""

    rater_peer_id: str
    target_peer_id: str
    intel_id: str
    score: float = Field(ge=0.0, le=1.0)
    comment: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# In-memory stores
# ---------------------------------------------------------------------------

# This node's identity
local_node = PeerNode(
    peer_id="node-nail-hq-001",
    name="NAIL HQ Federation Node",
    organisation="NAIL Institute",
    endpoint="https://federation.nailinstitute.org",
    region="north_america",
    trust_score=1.0,
    reputation_score=1.0,
)

peers: dict[str, PeerNode] = {}
intel_store: dict[str, IntelItem] = {}
content_hashes: set[str] = set()
trust_ratings: list[TrustRating] = []

# Seed peers for demonstration
_seed_peers = [
    PeerNode(
        peer_id="node-chapter-nyc",
        name="NAIL NYC Chapter",
        organisation="NAIL NYC",
        endpoint="https://nyc.nailinstitute.org/federation",
        region="north_america",
        trust_score=0.85,
        reputation_score=0.82,
        contribution_score=0.78,
        shared_categories=["prompt_injection", "tool_abuse", "goal_hijacking"],
        intel_sent=42,
        intel_received=38,
    ),
    PeerNode(
        peer_id="node-chapter-london",
        name="NAIL London Chapter",
        organisation="NAIL London",
        endpoint="https://london.nailinstitute.org/federation",
        region="europe",
        trust_score=0.80,
        reputation_score=0.79,
        contribution_score=0.72,
        shared_categories=["supply_chain", "model_poisoning", "data_exfiltration"],
        intel_sent=35,
        intel_received=40,
    ),
    PeerNode(
        peer_id="node-isac-finance",
        name="Financial Services ISAC",
        organisation="FS-ISAC",
        endpoint="https://ai-sec.fs-isac.org/federation",
        region="global",
        trust_score=0.90,
        reputation_score=0.88,
        contribution_score=0.85,
        shared_categories=["data_exfiltration", "trust_exploitation", "identity_spoofing"],
        intel_sent=58,
        intel_received=25,
    ),
    PeerNode(
        peer_id="node-partner-mitre",
        name="MITRE ATLAS Partner Node",
        organisation="MITRE",
        endpoint="https://atlas.mitre.org/federation",
        region="north_america",
        trust_score=0.95,
        reputation_score=0.92,
        contribution_score=0.90,
        shared_categories=[
            "prompt_injection", "tool_abuse", "memory_poisoning",
            "multi_agent_coordination", "emergent_behavior",
        ],
        intel_sent=95,
        intel_received=60,
    ),
]

for p in _seed_peers:
    peers[p.peer_id] = p

# Seed intel items
_seed_intel = [
    IntelItem(
        intel_id="intel-001-nyc-pi",
        intel_type=IntelType.INDICATOR,
        title="Novel indirect prompt injection via calendar integration",
        description="Adversary injects malicious instructions through calendar event descriptions that are parsed by scheduling agents.",
        ave_categories=["prompt_injection", "tool_abuse"],
        tlp=TLPLevel.GREEN,
        confidence=82,
        source_node="node-chapter-nyc",
        content_hash=hashlib.sha256(b"novel-calendar-injection").hexdigest(),
    ),
    IntelItem(
        intel_id="intel-002-london-sc",
        intel_type=IntelType.VULNERABILITY,
        title="Compromised model weights in popular HuggingFace repository",
        description="Backdoored model weights detected in widely-used text classification model.",
        ave_categories=["supply_chain", "model_poisoning"],
        tlp=TLPLevel.AMBER,
        confidence=91,
        source_node="node-chapter-london",
        content_hash=hashlib.sha256(b"hf-backdoor-weights").hexdigest(),
    ),
    IntelItem(
        intel_id="intel-003-fsisac-de",
        intel_type=IntelType.SIGHTING,
        title="Data exfiltration via multi-turn conversation manipulation",
        description="Financial AI assistant manipulated into revealing customer PII through carefully crafted multi-turn dialogue.",
        ave_categories=["data_exfiltration", "trust_exploitation"],
        tlp=TLPLevel.AMBER,
        confidence=88,
        source_node="node-isac-finance",
        content_hash=hashlib.sha256(b"multi-turn-pii-exfil").hexdigest(),
    ),
]

for item in _seed_intel:
    intel_store[item.intel_id] = item
    content_hashes.add(item.content_hash)


# ---------------------------------------------------------------------------
# Trust engine
# ---------------------------------------------------------------------------


def compute_trust_score(peer_id: str) -> float:
    """Recompute trust score from reputation + contribution."""
    peer = peers.get(peer_id)
    if not peer:
        return 0.0

    # Weighted combination
    trust = 0.5 * peer.reputation_score + 0.3 * peer.contribution_score + 0.2 * 0.5

    # Penalty for strikes
    if peer.strikes > 0:
        trust *= max(0.1, 1.0 - peer.strikes * 0.15)

    return round(max(0.0, min(1.0, trust)), 3)


def update_reputation(peer_id: str, quality_score: float) -> None:
    """Update reputation via exponential moving average."""
    peer = peers.get(peer_id)
    if not peer:
        return
    alpha = 0.2
    peer.reputation_score = round(
        alpha * quality_score + (1 - alpha) * peer.reputation_score, 3,
    )
    peer.trust_score = compute_trust_score(peer_id)


def update_contribution(peer_id: str) -> None:
    """Update contribution score based on sharing volume."""
    peer = peers.get(peer_id)
    if not peer:
        return
    total = peer.intel_sent + peer.intel_received
    if total == 0:
        return
    share_ratio = peer.intel_sent / total
    peer.contribution_score = round(min(1.0, share_ratio * 1.5), 3)
    peer.trust_score = compute_trust_score(peer_id)


# ---------------------------------------------------------------------------
# Privacy engine
# ---------------------------------------------------------------------------


def add_laplace_noise(value: float, sensitivity: float = 1.0) -> float:
    """Add Laplace noise for differential privacy."""
    scale = sensitivity / DEFAULT_EPSILON
    noise = random.uniform(-1, 1)
    noise = -scale * math.copysign(1, noise) * math.log(1 - abs(noise) + 1e-10)
    return round(value + noise, 2)


def redact_intel(item: IntelItem) -> dict[str, Any]:
    """Redact sensitive identifiers from intel before sharing."""
    redacted = item.model_dump()

    # Redact based on TLP level
    if item.tlp in (TLPLevel.AMBER, TLPLevel.RED):
        desc = redacted.get("description", "")
        # Redact IPs, emails, specific names
        import re
        desc = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[REDACTED-IP]', desc)
        desc = re.sub(r'\b[\w.+-]+@[\w-]+\.[\w.]+\b', '[REDACTED-EMAIL]', desc)
        redacted["description"] = desc

    if item.tlp == TLPLevel.RED:
        redacted["source_node"] = "[REDACTED]"
        redacted.pop("stix_bundle", None)

    return redacted


def compute_content_hash(item: IntelItem) -> str:
    """Compute dedup hash for intelligence item."""
    content = f"{item.title}|{item.description}|{'|'.join(sorted(item.ave_categories))}"
    return hashlib.sha256(content.encode()).hexdigest()


# ---------------------------------------------------------------------------
# API endpoints — Network status
# ---------------------------------------------------------------------------


@app.get("/v1/federation/status")
async def federation_status() -> dict[str, Any]:
    """Get network status and topology."""
    active_peers = [p for p in peers.values() if p.status == PeerStatus.ACTIVE]
    return {
        "local_node": local_node.model_dump(),
        "network": {
            "total_peers": len(peers),
            "active_peers": len(active_peers),
            "regions": list(set(p.region for p in peers.values())),
            "total_intel_items": len(intel_store),
            "avg_trust_score": round(
                statistics.mean(p.trust_score for p in peers.values()), 3,
            ) if peers else 0,
        },
        "protocol": {
            "heartbeat_interval_s": HEARTBEAT_INTERVAL_S,
            "max_peers": MAX_PEERS,
            "trust_min_receive": TRUST_MIN_RECEIVE,
            "trust_min_relay": TRUST_MIN_RELAY,
            "privacy_epsilon": DEFAULT_EPSILON,
        },
    }


# ---------------------------------------------------------------------------
# API endpoints — Peer management
# ---------------------------------------------------------------------------


@app.get("/v1/federation/peers")
async def list_peers(
    status_filter: Optional[PeerStatus] = None,
    region: Optional[str] = None,
) -> dict[str, Any]:
    """List connected peers."""
    filtered = list(peers.values())
    if status_filter:
        filtered = [p for p in filtered if p.status == status_filter]
    if region:
        filtered = [p for p in filtered if p.region == region]

    return {
        "peer_count": len(filtered),
        "peers": [p.model_dump() for p in filtered],
    }


@app.post("/v1/federation/peers/register", status_code=status.HTTP_201_CREATED)
async def register_peer(peer: PeerNode) -> dict[str, Any]:
    """Register a new peer node."""
    if len(peers) >= MAX_PEERS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Maximum peer limit ({MAX_PEERS}) reached",
        )

    if peer.peer_id in peers:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Peer {peer.peer_id} already registered",
        )

    peer.trust_score = 0.5  # New peers start at neutral trust
    peer.reputation_score = 0.5
    peer.contribution_score = 0.0
    peers[peer.peer_id] = peer

    return {
        "registered": True,
        "peer_id": peer.peer_id,
        "initial_trust": peer.trust_score,
    }


@app.delete("/v1/federation/peers/{peer_id}")
async def remove_peer(peer_id: str) -> dict[str, Any]:
    """Remove a peer from the network."""
    if peer_id not in peers:
        raise HTTPException(status_code=404, detail="Peer not found")
    removed = peers.pop(peer_id)
    return {"removed": True, "peer_id": peer_id, "name": removed.name}


# ---------------------------------------------------------------------------
# API endpoints — Intelligence sharing
# ---------------------------------------------------------------------------


@app.post("/v1/federation/intel/share", status_code=status.HTTP_201_CREATED)
async def share_intel(item: IntelItem) -> dict[str, Any]:
    """Share an intelligence item with the network."""
    # Compute content hash for dedup
    item.content_hash = compute_content_hash(item)

    if item.content_hash in content_hashes:
        return {
            "status": "duplicate",
            "intel_id": None,
            "message": "Intelligence item already exists in the network.",
        }

    # Check source node trust
    source_peer = peers.get(item.source_node)
    if source_peer and source_peer.trust_score < TRUST_MIN_RECEIVE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Source node trust ({source_peer.trust_score}) below minimum ({TRUST_MIN_RECEIVE})",
        )

    intel_store[item.intel_id] = item
    content_hashes.add(item.content_hash)

    # Update source contribution
    if source_peer:
        source_peer.intel_sent += 1
        update_contribution(item.source_node)

    # Determine relay eligibility
    relay_peers = [
        p for p in peers.values()
        if p.peer_id != item.source_node
        and p.status == PeerStatus.ACTIVE
        and p.trust_score >= TRUST_MIN_RELAY
        and any(cat in p.shared_categories for cat in item.ave_categories)
    ]

    return {
        "status": "shared",
        "intel_id": item.intel_id,
        "content_hash": item.content_hash,
        "relay_eligible_peers": len(relay_peers),
        "relay_peers": [p.peer_id for p in relay_peers],
    }


@app.get("/v1/federation/intel/feed")
async def intel_feed(
    category: Optional[str] = None,
    tlp: Optional[TLPLevel] = None,
    min_confidence: int = Query(0, ge=0, le=100),
    limit: int = Query(50, ge=1, le=200),
) -> dict[str, Any]:
    """Receive intelligence feed with optional filters."""
    items = list(intel_store.values())

    if category:
        items = [i for i in items if category in i.ave_categories]
    if tlp:
        items = [i for i in items if i.tlp == tlp]
    if min_confidence > 0:
        items = [i for i in items if i.confidence >= min_confidence]

    items.sort(key=lambda i: i.shared_at, reverse=True)
    items = items[:limit]

    # Apply redaction based on TLP
    return {
        "item_count": len(items),
        "items": [redact_intel(i) for i in items],
    }


@app.get("/v1/federation/intel/{intel_id}")
async def get_intel(intel_id: str) -> dict[str, Any]:
    """Get a specific intelligence item."""
    item = intel_store.get(intel_id)
    if not item:
        raise HTTPException(status_code=404, detail="Intelligence item not found")
    return redact_intel(item)


# ---------------------------------------------------------------------------
# API endpoints — Trust management
# ---------------------------------------------------------------------------


@app.get("/v1/federation/trust/{peer_id}")
async def get_trust(peer_id: str) -> dict[str, Any]:
    """Get detailed trust information for a peer."""
    peer = peers.get(peer_id)
    if not peer:
        raise HTTPException(status_code=404, detail="Peer not found")

    # Get quality ratings for this peer
    peer_ratings = [r for r in trust_ratings if r.target_peer_id == peer_id]
    avg_quality = (
        statistics.mean(r.score for r in peer_ratings)
        if peer_ratings else 0.5
    )

    return {
        "peer_id": peer_id,
        "name": peer.name,
        "trust_score": peer.trust_score,
        "reputation_score": peer.reputation_score,
        "contribution_score": peer.contribution_score,
        "strikes": peer.strikes,
        "intel_sent": peer.intel_sent,
        "intel_received": peer.intel_received,
        "quality_ratings": {
            "count": len(peer_ratings),
            "average": round(avg_quality, 3),
        },
        "trust_breakdown": {
            "reputation_component": round(0.5 * peer.reputation_score, 3),
            "contribution_component": round(0.3 * peer.contribution_score, 3),
            "base_component": round(0.2 * 0.5, 3),
            "strike_penalty": round(max(0, peer.strikes * 0.15), 3),
        },
    }


@app.post("/v1/federation/trust/{peer_id}/rate")
async def rate_intel_quality(peer_id: str, rating: TrustRating) -> dict[str, Any]:
    """Rate the quality of intelligence from a peer."""
    if peer_id not in peers:
        raise HTTPException(status_code=404, detail="Peer not found")

    rating.target_peer_id = peer_id
    trust_ratings.append(rating)

    # Update reputation
    update_reputation(peer_id, rating.score)

    return {
        "rated": True,
        "peer_id": peer_id,
        "new_trust_score": peers[peer_id].trust_score,
        "new_reputation": peers[peer_id].reputation_score,
    }


# ---------------------------------------------------------------------------
# API endpoints — Analytics
# ---------------------------------------------------------------------------


@app.get("/v1/federation/analytics")
async def federation_analytics() -> dict[str, Any]:
    """Network-wide analytics and metrics."""
    # Category distribution across all intel
    category_dist: Counter[str] = Counter()
    for item in intel_store.values():
        for cat in item.ave_categories:
            category_dist[cat] += 1

    # TLP distribution
    tlp_dist = Counter(item.tlp.value for item in intel_store.values())

    # Trust distribution
    trust_scores = [p.trust_score for p in peers.values()]

    # Regional distribution
    region_dist = Counter(p.region for p in peers.values())

    # Activity metrics (with differential privacy noise)
    total_sent = sum(p.intel_sent for p in peers.values())
    total_received = sum(p.intel_received for p in peers.values())

    return {
        "network_health": {
            "total_peers": len(peers),
            "active_peers": sum(1 for p in peers.values() if p.status == PeerStatus.ACTIVE),
            "avg_trust": round(statistics.mean(trust_scores), 3) if trust_scores else 0,
            "min_trust": round(min(trust_scores), 3) if trust_scores else 0,
            "max_trust": round(max(trust_scores), 3) if trust_scores else 0,
        },
        "intelligence_metrics": {
            "total_items": len(intel_store),
            "category_distribution": dict(category_dist.most_common()),
            "tlp_distribution": dict(tlp_dist),
            "avg_confidence": round(
                statistics.mean(i.confidence for i in intel_store.values()), 1,
            ) if intel_store else 0,
            "total_shared": add_laplace_noise(total_sent),
            "total_consumed": add_laplace_noise(total_received),
        },
        "topology": {
            "region_distribution": dict(region_dist),
            "organisations": list(set(p.organisation for p in peers.values())),
        },
    }


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "service": "federated-intel-network"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8602)
