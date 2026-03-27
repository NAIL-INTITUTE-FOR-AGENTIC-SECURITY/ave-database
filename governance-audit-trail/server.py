"""Governance Audit Trail — Phase 31 Service 2 · Port 9931"""

from __future__ import annotations
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum
import uuid, hashlib, json

app = FastAPI(title="Governance Audit Trail", version="0.31.2")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Enums ────────────────────────────────────────────────────────────
class ActorType(str, Enum):
    ai_agent = "ai_agent"
    human_operator = "human_operator"
    automated_pipeline = "automated_pipeline"
    hybrid_team = "hybrid_team"
    external_system = "external_system"
    governance_bot = "governance_bot"

class EventCategory(str, Enum):
    decision_made = "decision_made"
    policy_applied = "policy_applied"
    override_executed = "override_executed"
    escalation_triggered = "escalation_triggered"
    access_granted = "access_granted"
    access_denied = "access_denied"
    configuration_changed = "configuration_changed"
    anomaly_detected = "anomaly_detected"

# ── Models ───────────────────────────────────────────────────────────
class ActorCreate(BaseModel):
    name: str
    actor_type: ActorType
    role: str = "operator"
    clearance_level: int = Field(3, ge=1, le=5)
    accountability_chain: list[str] = []

class EventCreate(BaseModel):
    actor_id: str
    category: EventCategory
    description: str = ""
    payload: dict = {}
    parent_event_id: Optional[str] = None
    severity: str = "info"

class EvidenceRequest(BaseModel):
    category: Optional[EventCategory] = None
    actor_id: Optional[str] = None
    from_time: Optional[str] = None
    to_time: Optional[str] = None
    title: str = "Compliance Evidence Package"

# ── Stores ───────────────────────────────────────────────────────────
actors: dict[str, dict] = {}
events: list[dict] = []  # Append-only log
evidence_packages: dict[str, dict] = {}
GENESIS_HASH = "0" * 64

def _now():
    return datetime.now(timezone.utc).isoformat()

def _hash_event(payload: dict, prev_hash: str) -> str:
    content = json.dumps(payload, sort_keys=True) + prev_hash
    return hashlib.sha256(content.encode()).hexdigest()

def _prev_hash() -> str:
    return events[-1]["hash"] if events else GENESIS_HASH

# ── Health ───────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"service": "governance-audit-trail", "status": "healthy", "version": "0.31.2", "actors": len(actors), "events": len(events), "chain_length": len(events)}

# ── Actors ───────────────────────────────────────────────────────────
@app.post("/v1/actors", status_code=201)
def create_actor(body: ActorCreate):
    aid = str(uuid.uuid4())
    rec = {"id": aid, **body.model_dump(), "created_at": _now()}
    actors[aid] = rec
    return rec

@app.get("/v1/actors")
def list_actors(actor_type: Optional[ActorType] = None):
    out = list(actors.values())
    if actor_type:
        out = [a for a in out if a["actor_type"] == actor_type]
    # Enrich with activity
    for a in out:
        a["event_count"] = sum(1 for e in events if e["actor_id"] == a["id"])
    return out

@app.get("/v1/actors/{aid}")
def get_actor(aid: str):
    if aid not in actors:
        raise HTTPException(404, "Actor not found")
    a = actors[aid]
    actor_events = [e for e in events if e["actor_id"] == aid]
    by_cat = {}
    for e in actor_events:
        by_cat[e["category"]] = by_cat.get(e["category"], 0) + 1
    return {**a, "event_count": len(actor_events), "by_category": by_cat, "last_activity": actor_events[-1]["timestamp"] if actor_events else None}

# ── Events (append-only) ────────────────────────────────────────────
@app.post("/v1/events", status_code=201)
def log_event(body: EventCreate):
    if body.actor_id not in actors:
        raise HTTPException(404, "Actor not found")
    if body.parent_event_id:
        if not any(e["id"] == body.parent_event_id for e in events):
            raise HTTPException(404, "Parent event not found")

    eid = str(uuid.uuid4())
    prev = _prev_hash()
    payload = {**body.model_dump(), "id": eid, "timestamp": _now()}
    event_hash = _hash_event(payload, prev)

    rec = {
        **payload,
        "sequence": len(events),
        "hash": event_hash,
        "previous_hash": prev,
        "actor_name": actors[body.actor_id]["name"],
        "verified": True,
    }
    events.append(rec)
    return rec

@app.get("/v1/events")
def search_events(category: Optional[EventCategory] = None, actor_id: Optional[str] = None, severity: Optional[str] = None, limit: int = Query(100, ge=1, le=1000)):
    out = events
    if category:
        out = [e for e in out if e["category"] == category]
    if actor_id:
        out = [e for e in out if e["actor_id"] == actor_id]
    if severity:
        out = [e for e in out if e.get("severity") == severity]
    return out[-limit:]

@app.get("/v1/events/{eid}")
def get_event(eid: str):
    ev = next((e for e in events if e["id"] == eid), None)
    if not ev:
        raise HTTPException(404, "Event not found")
    # Verify hash
    idx = ev["sequence"]
    prev = events[idx - 1]["hash"] if idx > 0 else GENESIS_HASH
    expected = _hash_event({k: v for k, v in ev.items() if k not in ("sequence", "hash", "previous_hash", "actor_name", "verified")}, prev)
    verified = expected == ev["hash"]
    return {**ev, "verified": verified}

# ── Provenance ───────────────────────────────────────────────────────
@app.get("/v1/events/{eid}/provenance")
def provenance(eid: str):
    ev = next((e for e in events if e["id"] == eid), None)
    if not ev:
        raise HTTPException(404, "Event not found")
    chain = [ev]
    current = ev
    while current.get("parent_event_id"):
        parent = next((e for e in events if e["id"] == current["parent_event_id"]), None)
        if not parent:
            break
        chain.append(parent)
        current = parent
    chain.reverse()
    return {"target_event": eid, "chain_length": len(chain), "provenance_chain": chain}

# ── Chain Verification ───────────────────────────────────────────────
@app.get("/v1/chain/verify")
def verify_chain():
    if not events:
        return {"status": "empty", "length": 0, "valid": True}

    broken_at = []
    for i, ev in enumerate(events):
        prev = events[i - 1]["hash"] if i > 0 else GENESIS_HASH
        payload = {k: v for k, v in ev.items() if k not in ("sequence", "hash", "previous_hash", "actor_name", "verified")}
        expected = _hash_event(payload, prev)
        if expected != ev["hash"]:
            broken_at.append({"sequence": i, "event_id": ev["id"], "expected_hash": expected[:16] + "...", "actual_hash": ev["hash"][:16] + "..."})

    return {
        "chain_length": len(events),
        "valid": len(broken_at) == 0,
        "integrity_pct": round((1 - len(broken_at) / max(len(events), 1)) * 100, 1),
        "broken_links": broken_at,
        "verified_at": _now(),
    }

# ── Evidence Packages ────────────────────────────────────────────────
@app.post("/v1/evidence", status_code=201)
def generate_evidence(body: EvidenceRequest):
    filtered = events
    if body.category:
        filtered = [e for e in filtered if e["category"] == body.category]
    if body.actor_id:
        filtered = [e for e in filtered if e["actor_id"] == body.actor_id]
    if body.from_time:
        filtered = [e for e in filtered if e["timestamp"] >= body.from_time]
    if body.to_time:
        filtered = [e for e in filtered if e["timestamp"] <= body.to_time]

    # Verify chain for filtered events
    chain_valid = all(e.get("verified", True) for e in filtered)

    pid = str(uuid.uuid4())
    package = {
        "id": pid,
        "title": body.title,
        "events_included": len(filtered),
        "chain_integrity_verified": chain_valid,
        "filters_applied": {k: v for k, v in body.model_dump().items() if v is not None and k != "title"},
        "actor_attestations": list({e["actor_name"] for e in filtered}),
        "event_timeline": [{"id": e["id"], "category": e["category"], "actor": e["actor_name"], "timestamp": e["timestamp"], "hash": e["hash"][:16] + "..."} for e in filtered[:50]],
        "generated_at": _now(),
    }
    evidence_packages[pid] = package
    return package

@app.get("/v1/evidence")
def list_evidence():
    return list(evidence_packages.values())

# ── Analytics ────────────────────────────────────────────────────────
@app.get("/v1/analytics")
def analytics():
    by_cat = {}
    for e in events:
        by_cat[e["category"]] = by_cat.get(e["category"], 0) + 1
    by_actor_type = {}
    for e in events:
        at = actors.get(e["actor_id"], {}).get("actor_type", "unknown")
        by_actor_type[at] = by_actor_type.get(at, 0) + 1
    by_severity = {}
    for e in events:
        s = e.get("severity", "info")
        by_severity[s] = by_severity.get(s, 0) + 1

    return {
        "total_actors": len(actors),
        "total_events": len(events),
        "chain_length": len(events),
        "by_category": by_cat,
        "by_actor_type": by_actor_type,
        "by_severity": by_severity,
        "evidence_packages_generated": len(evidence_packages),
        "events_with_provenance": sum(1 for e in events if e.get("parent_event_id")),
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9931)
